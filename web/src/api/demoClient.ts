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
        if (fx.domaintools) result.domaintools = fx.domaintools;
        if (fx.dnslytics) result.dnslytics = fx.dnslytics;
        if (fx.intel471) result.intel471 = fx.intel471;
        if (fx.cyfirma) result.cyfirma = fx.cyfirma;
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
