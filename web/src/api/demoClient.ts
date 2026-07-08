import {
  buildLinks,
  extractIndicators,
  normalizeVt,
  type CyfirmaSearch,
  type EnrichRequest,
  type Intel471Malware,
  type Intel471Search,
  type NormalizedResult,
  type ParsedIndicator,
  type RfActorProfile,
  type RfMalwareProfile,
  type RfRuleSearchParams,
  type RfRuleSearchResult,
  type RfSandboxIntel,
  type ShodanContext,
  type ShodanInternetDb,
  type ShodanMonitorResult,
  type ShodanScanRequest,
  type ShodanScanStatus,
  type SocPrimeQueryOptions,
  type SocPrimeQueryResult,
  type SocPrimeRuleSearchParams,
  type SocPrimeRuleSearchResult,
  type ThreatVisionAdversary,
  type UrlscanResult,
  type UrlscanSubmission,
} from '@vteeee/shared';
import { FIXTURE_MAP } from '../fixtures/samples';
import { sleep, type EnrichClient, type EnrichHandlers } from './client';

/** Serves bundled sample fixtures and simulates streaming/progress. No network. */
export class DemoClient implements EnrichClient {
  readonly mode = 'demo' as const;

  async enrich(req: EnrichRequest, h: EnrichHandlers): Promise<void> {
    const total = req.indicators.length;
    let done = 0;
    const started = Date.now();
    h.onProgress({ done, total, inflight: total ? 1 : 0, rateLimitedUntil: null });

    for (const ind of req.indicators) {
      if (h.signal?.aborted) break;
      await sleep(160, h.signal);
      if (h.signal?.aborted) break;

      const fx = FIXTURE_MAP.get(ind.value.toLowerCase());
      const links = await buildLinks(ind.type, ind.value);
      let result: NormalizedResult;
      if (fx) {
        result = normalizeVt({
          input: ind.input,
          value: ind.value,
          type: ind.type,
          status: fx.status,
          data: fx.attributes ? { attributes: fx.attributes } : undefined,
          links,
          includeRaw: true,
        });
        if (fx.shodan) result.shodan = fx.shodan;
        if (fx.maxmind) result.maxmind = fx.maxmind;
        if (fx.domaintools) result.domaintools = fx.domaintools;
        if (fx.dnslytics) result.dnslytics = fx.dnslytics;
        if (fx.intel471) result.intel471 = fx.intel471;
        if (fx.cyfirma) result.cyfirma = fx.cyfirma;
        if (fx.threatvision) result.threatvision = fx.threatvision;
        if (fx.recordedfuture) result.recordedfuture = fx.recordedfuture;
        if (fx.abuseipdb) result.abuseipdb = fx.abuseipdb;
      } else {
        result = normalizeVt({
          input: ind.input,
          value: ind.value,
          type: ind.type,
          status: 'not_found',
          links,
          errorMessage: 'Demo mode — no sample data for this indicator. Configure a proxy in Settings for live results.',
        });
      }
      h.onResult(result);
      done++;
      h.onProgress({ done, total, inflight: done < total ? 1 : 0, rateLimitedUntil: null });
    }
    h.onDone({ done, total, elapsedMs: Date.now() - started });
  }

  /** In demo mode the regex extractor stands in for Claude smart-parse. */
  async smartParse(text: string): Promise<ParsedIndicator[]> {
    await sleep(250);
    return extractIndicators(text).indicators;
  }

  /** Sample Intel 471 Global Search counts + drill-down items (demo). */
  async intel471Search(): Promise<Intel471Search> {
    await sleep(300);
    return {
      reports: 35,
      posts: 132,
      actors: 41,
      entities: 13,
      news: 1,
      credentials: 1,
      dataLeakPosts: 1,
      events: 0,
      items: {
        reports: [
          { title: 'SOCKS proxy service provider actor Insorg adds 500 front-end proxies', url: 'https://titan.intel471.com/report/inforep/example' },
          { title: 'Bulletproof hosting actor advertises new proxy inventory' },
        ],
        actors: [{ title: 'Insorg' }, { title: 'MrBlonde' }],
        posts: [{ title: 'Selling fresh SOCKS5 proxies, US/EU, low latency…' }],
        news: [{ title: 'Proxy abuse trends in credential-stuffing campaigns' }],
      },
    };
  }

  /** Sample Intel 471 malware family details (demo). */
  async intel471Malware(uid: string, family?: string): Promise<Intel471Malware> {
    await sleep(300);
    return {
      family: family || 'orcus',
      uid: uid || '6e6ca74063416138a3fbf03dd2e189a6',
      aka: ['Schnorchel', 'Snorkel'],
      summary: 'Orcus is a popular remote access trojan (RAT) written in C#, sold since 2016; supports plugins, audio/video capture and credential theft.',
      reports: [
        'Orcus RAT operators expand plugin marketplace',
        'Commodity RAT orcus bundled in phishing campaign targeting finance',
      ],
      reportCount: 7,
      mitreTactics: ['command_and_control', 'collection'],
      girs: ['1.1.3'],
      activeFrom: '2022-08-18T01:39:08.000Z',
      activeTill: '2026-06-29T18:22:27.000Z',
      portalUrl: `https://titan.intel471.com/malware/${uid || '6e6ca74063416138a3fbf03dd2e189a6'}`,
    };
  }

  /** Sample ThreatVision adversary profile (demo). */
  async threatvisionAdversary(name: string): Promise<ThreatVisionAdversary> {
    await sleep(300);
    return {
      name: name || 'Amoeba',
      aliases: ['Winnti', 'APT41', 'Barium', 'Wicked Panda', 'Earth Baku'],
      originCountries: ['China'],
      targetedCountries: ['Taiwan', 'Japan', 'South Korea', 'United States of America', 'Hong Kong'],
      targetedIndustries: ['Government', 'Semiconductor', 'Telecommunication', 'Healthcare', 'Gaming'],
      overview:
        'A China-nexus adversary widely tracked as "Winnti," named after one of its most infamous RATs; assessed to have strong ties to China\'s MSS.',
    };
  }

  /** Sample SOC Prime Uncoder AI IOC → SIEM query (demo). */
  async socprimeQuery(text: string, opts: SocPrimeQueryOptions): Promise<SocPrimeQueryResult> {
    await sleep(400);
    const iocs = text
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 6);
    const quoted = iocs.map((i) => `"${i}"`).join(', ');
    let q: string;
    if (opts.siemType.startsWith('ala'))
      q = `union *\n| where DestinationIp in (${quoted}) or RemoteUrl has_any (${quoted})`;
    else if (opts.siemType === 'qradar') q = `SELECT * FROM events WHERE destinationip IN (${quoted}) LAST 7 DAYS`;
    else q = `search (${iocs.map((i) => `dest="${i}" OR url="${i}"`).join(' OR ')})`;
    return { queries: [q], iocCount: iocs.length, raw: { demo: true } };
  }

  /** Sample SOC Prime detection-rule search (demo). */
  async socprimeRules(params: SocPrimeRuleSearchParams): Promise<SocPrimeRuleSearchResult> {
    await sleep(400);
    const who = params.actor || params.tool || params.query || 'suspicious activity';
    return {
      total: 2,
      rules: [
        {
          id: 'demo-rule-1',
          name: `Possible ${who} — Suspicious PowerShell Download Cradle`,
          description: `Detects behavior associated with ${who}: PowerShell downloading and executing a remote payload.`,
          level: 'high',
          status: 'stable',
          author: 'SOC Prime Team',
          techniques: ['T1059.001', 'T1105'],
          tactics: ['Execution', 'Command and Control'],
          actors: params.actor ? [params.actor] : [],
          translation:
            params.siemType === 'ala'
              ? 'DeviceProcessEvents\n| where FileName =~ "powershell.exe"\n| where ProcessCommandLine has_any ("DownloadString","IEX")'
              : 'index=* source="WinEventLog:*" (Image="*\\\\powershell.exe" AND (CommandLine="*DownloadString*" OR CommandLine="*IEX*"))',
          url: 'https://tdm.socprime.com/tdm/info/demo-rule-1',
        },
        {
          id: 'demo-rule-2',
          name: `${who} — Rundll32 Executing from Temp`,
          description: 'Detects rundll32 launching a DLL from a temporary directory.',
          level: 'medium',
          status: 'test',
          author: 'Threat Bounty',
          techniques: ['T1218.011'],
          tactics: ['Defense Evasion'],
          translation:
            params.siemType === 'ala'
              ? 'DeviceProcessEvents | where FileName =~ "rundll32.exe" and ProcessCommandLine has "\\\\Temp\\\\"'
              : 'index=* Image="*\\\\rundll32.exe" CommandLine="*\\\\Temp\\\\*"',
          url: 'https://tdm.socprime.com/tdm/info/demo-rule-2',
        },
      ],
    };
  }

  /** Sample Recorded Future threat-actor profile (demo). */
  async rfActor(name: string): Promise<RfActorProfile> {
    await sleep(300);
    return {
      name: name || 'BlueDelta',
      id: 'S9Gvql',
      aliases: ['Fancy Bear', 'Sofacy', 'Sednit', 'Forest Blizzard'],
      commonNames: ['APT28'],
      categories: ['Nation State Sponsored', 'Russia Nation State Sponsored'],
      intelCard: 'https://app.recordedfuture.com/portal/intelligence-card/S9Gvql',
    };
  }

  /** Sample Recorded Future malware profile (demo). */
  async rfMalware(ref: { id?: string; name?: string }): Promise<RfMalwareProfile> {
    await sleep(300);
    return {
      name: ref.name || 'X-Agent',
      id: ref.id || 'K5GvlA',
      categories: ['Backdoor', 'Remote Access Trojan'],
      relatedActors: ['BlueDelta', 'APT28'],
      firstSeen: '2015-02-11T00:00:00.000Z',
      lastSeen: new Date().toISOString(),
      intelCard: `https://app.recordedfuture.com/portal/intelligence-card/${ref.id || 'K5GvlA'}`,
    };
  }

  /** Sample Recorded Future sandbox summary (demo). */
  async rfSandbox(hash: string): Promise<RfSandboxIntel> {
    await sleep(300);
    return {
      hash: hash.length === 64 ? hash : '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
      riskScore: 89,
      sandboxScore: 8,
      tags: ['trojan', 'family:redline', 'stealer'],
      fileExtensions: ['.exe'],
      universalReport: 'https://app.recordedfuture.com/portal/intelligence-card/hash:demo/sandbox-report',
      intelligenceCard: 'https://app.recordedfuture.com/portal/intelligence-card/hash:demo',
      total: 3,
    };
  }

  /** Sample Recorded Future detection-rule search (demo). */
  async rfRules(params: RfRuleSearchParams): Promise<RfRuleSearchResult> {
    await sleep(400);
    const type = params.types?.[0] ?? 'sigma';
    return {
      total: 1,
      rules: [
        {
          id: 'doc:demo1',
          title: `Possible X-Agent C2 beacon (${type})`,
          type,
          description: 'Detects the HTTP beacon pattern used by X-Agent implants.',
          created: '2024-05-01T00:00:00.000Z',
          updated: '2025-11-12T00:00:00.000Z',
          fileName: 'xagent_c2_http.yml',
          entities: ['X-Agent', 'BlueDelta'],
          content:
            'title: Possible X-Agent C2 beacon\nstatus: experimental\nlogsource:\n  category: proxy\ndetection:\n  selection:\n    c-uri|contains: "/watchcom/"\n  condition: selection\nlevel: high',
        },
      ],
    };
  }

  /** Sample urlscan.io submission (demo) — returns a fake uuid to "poll". */
  async urlscanSubmit(): Promise<UrlscanSubmission> {
    await sleep(300);
    const uuid = 'demo00000000-4000-8000-000000urlscan';
    return {
      uuid,
      resultUrl: `https://urlscan.io/result/${uuid}/`,
      visibility: 'unlisted',
      message: 'Demo — submission simulated (no real scan)',
    };
  }

  /** Sample urlscan.io result (demo) — a canned phishing "魚拓". */
  async urlscanResult(uuid: string): Promise<UrlscanResult> {
    await sleep(600);
    return {
      uuid,
      resultUrl: `https://urlscan.io/result/${uuid}/`,
      url: 'http://phishy-malware-example.com/login.php',
      finalUrl: 'http://phishy-malware-example.com/account/verify',
      title: 'Sign in to your account',
      ip: '185.220.101.1',
      asn: 'AS201814',
      asnName: 'BADHOST-AS',
      country: 'RU',
      server: 'nginx',
      status: 200,
      malicious: true,
      score: 87,
      brands: ['Microsoft'],
      tags: ['phishing', 'credential-harvesting'],
      contactedDomains: ['phishy-malware-example.com', 'cdn.badhost.example', 'track.evil.example'],
      contactedIps: ['185.220.101.1', '93.184.216.34'],
    };
  }

  /** Sample Shodan InternetDB (demo) — current known ports/CVEs, no active scan. */
  async shodanInternetDb(ip: string): Promise<ShodanInternetDb> {
    await sleep(350);
    return {
      found: true,
      ip,
      ports: [22, 80, 443, 8080],
      vulns: ['CVE-2021-44228', 'CVE-2019-0708'],
      cpes: ['cpe:/a:nginx:nginx', 'cpe:/a:openbsd:openssh'],
      hostnames: ['host.demo.example'],
      tags: ['cloud'],
    };
  }

  /** Sample Shodan re-scan request (demo) — no real scan, no credits consumed. */
  async shodanScan(): Promise<ShodanScanRequest> {
    await sleep(400);
    return { id: 'DEMOSCAN1A2B3C', count: 1, creditsLeft: 100 };
  }

  /** Sample Shodan scan status (demo) — reports DONE so the flow auto-refreshes. */
  async shodanScanStatus(id: string): Promise<ShodanScanStatus> {
    await sleep(400);
    return { id, status: 'DONE', count: 1 };
  }

  /** Sample Shodan Monitor list (demo) — one pre-monitored IP so the page isn't empty. */
  async shodanMonitorList(): Promise<ShodanMonitorResult> {
    await sleep(250);
    return {
      entries: [
        { id: 'demo-alert-1', ip: '185.220.101.1', name: 'vteeee:185.220.101.1', size: 1, triggers: ['malware', 'new_service'] },
      ],
    };
  }

  /** Sample Shodan Monitor add (demo). */
  async shodanMonitorAdd(ip: string): Promise<ShodanMonitorResult> {
    await sleep(250);
    return { ok: true, entries: [{ id: `demo-${ip}`, ip, name: `vteeee:${ip}`, size: 1 }] };
  }

  /** Sample Shodan Monitor remove (demo). */
  async shodanMonitorRemove(ip: string): Promise<ShodanMonitorResult> {
    await sleep(250);
    return { ok: true, removed: ip };
  }

  /** Sample fresh Shodan host banners (demo). */
  async shodanHost(): Promise<ShodanContext> {
    await sleep(500);
    return {
      found: true,
      org: 'Demo Cloud Networks',
      isp: 'Demo Cloud Networks',
      asn: 'AS13335',
      country: 'United States',
      city: 'Ashburn',
      ports: [22, 80, 443],
      services: [
        { port: 22, transport: 'tcp', product: 'OpenSSH', version: '8.9', module: 'ssh' },
        { port: 443, transport: 'tcp', product: 'nginx', module: 'https' },
      ],
      vulns: ['CVE-2021-44228'],
      tags: ['cloud'],
      hostnames: ['host.demo.example'],
      lastUpdate: new Date().toISOString(),
    };
  }

  /** Sample CYFIRMA Threat-Actor deep-dive (demo). */
  async cyfirmaSearch(name: string): Promise<CyfirmaSearch> {
    await sleep(300);
    return {
      actor: name || 'Fancy Bear',
      aliases: ['APT28', 'Sofacy', 'Strontium', 'Sednit'],
      description: 'Russian state-sponsored group affiliated with military intelligence.',
      motivation: 'Espionage',
      campaigns: ['vision2025', 'credential-harvest-eu'],
      malware: ['emotet', 'x-agent'],
      vulnerabilities: ['CVE-2023-23397', 'CVE-2020-0688'],
      relatedIocs: ['192.243.56.76', 'evil-c2.example'],
    };
  }
}
