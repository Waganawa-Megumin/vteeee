import { describe, it, expect, vi, afterEach } from 'vitest';
import type { EnrichEvent } from '@vteeee/shared';
import { mapIrisEnrich, mapIrisInvestigateReverseIp } from '../domaintoolsFetch';
import { mapDnslyticsIp, mapDnslyticsHostingHistory } from '../dnslyticsFetch';
import { mapIntel471Ioc, mapIntel471Indicator, mapIntel471Search } from '../intel471Fetch';
import { runEnrich } from '../enrich';
import type { ProxyEnv } from '../types';

const env: ProxyEnv = {
  vtApiKey: 'vt',
  domaintoolsApiUsername: 'u',
  domaintoolsApiKey: 'k',
  domaintoolsRpm: 600,
  dnslyticsApiKey: 'd',
  dnslyticsRpm: 600,
  intel471ApiUser: 'e@x.com',
  intel471ApiKey: 'k',
  intel471Rpm: 600,
  allowedOrigins: ['*'],
  defaultRpm: 600,
  maxRpm: 1000,
  xTool: 'vteeee',
  maxBatch: 1000,
  dailyCap: 0,
  parseDailyCap: 0,
};

function resp(status: number, body: unknown): Response {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status });
}

const ENRICH_RESULT = {
  domain: 'evil.com',
  domain_risk: { risk_score: 88, components: [{ name: 'phishing', risk_score: 88 }, { name: 'proximity', risk_score: 40 }] },
  create_date: { value: '2024-01-02' },
  first_seen: { value: '2024-01-03T00:00:00Z' },
  registrar: { value: 'NameCheap, Inc.' },
  ip: [{ address: { value: '193.0.2.10' }, asn: [{ value: 51167 }], isp: { value: 'Contabo' } }],
  name_server: [{ host: { value: 'dns1.reg.com' } }],
  mx: [{ host: { value: 'mx.evil.com' } }],
  ssl_info: [{ issuer_common_name: { value: "Let's Encrypt R3" }, not_after: { value: 20260919 } }],
  website_response: 200,
  server_type: { value: 'nginx' },
  website_title: { value: 'Login' },
  tags: ['phishing'],
};

const INVESTIGATE = {
  results_count: 3,
  total_count: 1500,
  results: [
    { domain: 'a.com', domain_risk: { risk_score: 10 } },
    { domain: 'b.com', domain_risk: { risk_score: 80 } },
    { domain: 'c.com' },
  ],
};

// Real DNSLytics IPInfo shape: { status, data: { asinfo, shortname, ptr, ndomains, blocklist, geoinfo } }.
const DNSL_IP = {
  status: 'succeed',
  data: {
    question: '8.8.8.8',
    typeinfo: 'ipinfo',
    asinfo: { asn: 15169, cidr: '8.8.8.0/24', shortname: 'GOOGLE' },
    shortname: 'GOOGLE',
    ptr: 'dns.google',
    ndomains: 1234,
    domains: ['dns.google', 'google-public-dns-a.google.com'],
    blocklist: { dnsbl: false, openproxy: false, adulthosting: false, mthreats: false },
    geoinfo: { country_code: 'US', country_name: 'United States' },
  },
};

// Real DNSLytics HostingHistory shape.
const DNSL_HH = {
  status: 'succeed',
  data: {
    question: 'evil.com',
    typeinfo: 'hostinghistory',
    ipv4: [{ ip: '193.0.2.10', updatedate: '2024-05-01' }, { ip: '5.45.109.92', updatedate: '2023-01-01' }],
    ipv6: [{ ip: '2400:cb00::1', updatedate: '2024-04-01' }],
    dns: [{ dns: 'ns1.reg.com', updatedate: '2024-05-01' }, { dns: 'ns1.reg.com', updatedate: '2023-01-01' }],
    mx: [{ mx: 'mx.evil.com', updatedate: '2024-05-01' }],
    spf: [{ record: 'v=spf1 -all', updatedate: '2024-05-01' }],
  },
};

const I471_IOC = {
  iocTotalCount: 4724,
  iocs: [
    {
      lastUpdated: 1600336264566,
      ispName: 'A-COM',
      links: {
        actorTotalCount: 0,
        reportTotalCount: 1,
        reports: [
          {
            subject: 'SOCKS proxy service provider actor Insorg adds 500 front-end proxies',
            portalReportUrl: 'https://titan.intel471.com/report/inforep/77ac9c8ec3009a1d3b8366a38cdbb55f',
            admiraltyCode: 'B3',
          },
        ],
      },
      activeFrom: 1522874107000,
      ispCountryCode: 'RU',
      activeTill: 1522874107000,
      uid: '10f35fc08ec94dfb3dcc1c4a49547dee',
      type: 'IPAddress',
      value: '188.130.163.218',
    },
  ],
};

const I471_INDICATORS = {
  indicatorTotalCount: 1,
  indicators: [
    {
      data: {
        uid: '03966eb21fe3b33e026f3363b9f012af',
        threat: { type: 'malware', uid: '29f5', data: { malware_family_profile_uid: '29f5', family: 'redline' } },
        expiration: 1617937719000,
        confidence: 'high',
        context: { description: 'redline controller URL' },
        mitre_tactics: 'command_and_control',
        indicator_type: 'url',
        indicator_data: { url: 'http://45.67.231.78:3214' },
        intel_requirements: ['1.1.5', '1.1.6'],
      },
      last_updated: 1615345743440,
      uid: '03966eb21fe3b33e026f3363b9f012af',
      activity: { first: 1615345265000, last: 1615345719000 },
    },
  ],
};

const I471_SEARCH = {
  indicatorTotalCount: 0,
  cveReportsTotalCount: 0,
  iocTotalCount: 0,
  eventTotalCount: 0,
  postTotalCount: 132,
  reportTotalCount: 35,
  entityTotalCount: 13,
  newsTotalCount: 1,
  malwareReportTotalCount: 0,
  actorTotalCount: 41,
  credentials_total_count: 1,
  credential_sets_total_count: 1,
  breach_alerts_total_count: 0,
  data_leak_post_total_count: 1,
};

afterEach(() => vi.unstubAllGlobals());

describe('DomainTools mappers', () => {
  it('mapIrisEnrich maps risk, registration, infra, SSL and tags', () => {
    const c = mapIrisEnrich(ENRICH_RESULT);
    expect(c).toMatchObject({ found: true, mode: 'enrich', riskScore: 88, registrar: 'NameCheap, Inc.' });
    expect(c.riskComponents).toHaveLength(2);
    expect(c.created).toBe('2024-01-02');
    expect(c.ips).toEqual(['193.0.2.10']);
    expect(c.asns).toEqual([51167]);
    expect(c.nameServers).toEqual(['dns1.reg.com']);
    expect(c.mailServers).toEqual(['mx.evil.com']);
    expect(c.sslIssuer).toBe("Let's Encrypt R3");
    expect(c.sslNotAfter).toBe('2026-09-19'); // YYYYMMDD int → ISO date
    expect(c.tags).toEqual(['phishing']);
  });

  it('mapIrisInvestigateReverseIp counts + samples hosted domains, riskiest first', () => {
    const c = mapIrisInvestigateReverseIp(INVESTIGATE);
    expect(c).toMatchObject({ found: true, mode: 'reverse-ip', hostedDomainCount: 1500 });
    expect(c.sampleDomains?.[0]?.domain).toBe('b.com'); // highest risk first
    expect(c.sampleDomains).toHaveLength(3);
  });
});

describe('DNSLytics IPInfo mapper', () => {
  it('reads nested asinfo/geoinfo/ptr/ndomains from the real schema', () => {
    const c = mapDnslyticsIp(DNSL_IP);
    expect(c).toMatchObject({
      found: true,
      kind: 'ip',
      asn: 15169,
      org: 'GOOGLE',
      network: '8.8.8.0/24',
      country: 'United States',
      hostname: 'dns.google',
      domainsOnIp: 1234,
    });
    expect(c.hostedDomains).toEqual(['dns.google', 'google-public-dns-a.google.com']);
    expect(c.threat).toBeUndefined(); // all blocklist flags false → no threat
  });
  it('summarizes blocklist flags into a threat string', () => {
    const c = mapDnslyticsIp({ status: 'succeed', data: { blocklist: { dnsbl: true, openproxy: true } } });
    expect(c.threat).toBe('DNSBL, open proxy');
  });
  it('accepts the inner object without the { data } envelope', () => {
    expect(mapDnslyticsIp(DNSL_IP.data).asn).toBe(15169);
  });
});

describe('DNSLytics HostingHistory mapper', () => {
  it('collects A/AAAA/NS/MX/SPF history, deduped and most-recent first', () => {
    const c = mapDnslyticsHostingHistory(DNSL_HH);
    expect(c).toMatchObject({ found: true, kind: 'domain' });
    expect(c.ips).toEqual(['193.0.2.10', '2400:cb00::1', '5.45.109.92']); // by updatedate desc
    expect(c.nameServers).toEqual(['ns1.reg.com']); // deduped
    expect(c.mailServers).toEqual(['mx.evil.com']);
    expect(c.spf).toEqual(['v=spf1 -all']);
  });
});

describe('Intel 471 mappers', () => {
  it('mapIntel471Ioc maps the matching record (type/active/ISP/links/reports)', () => {
    const c = mapIntel471Ioc(I471_IOC, '188.130.163.218');
    expect(c).toMatchObject({ found: true, totalCount: 4724, type: 'IPAddress', isp: 'A-COM', ispCountryCode: 'RU' });
    expect(c.reports).toBe(1);
    expect(c.actors).toBe(0);
    expect(c.reportTitles?.[0]).toMatch(/SOCKS proxy/);
    expect(c.portalUrl).toContain('titan.intel471.com');
    expect(c.activeFrom).toBe(new Date(1522874107000).toISOString());
  });
  it('mapIntel471Ioc returns found:false for an empty result set', () => {
    expect(mapIntel471Ioc({ iocTotalCount: 0, iocs: [] }, 'x')).toMatchObject({ found: false, totalCount: 0 });
  });
  it('mapIntel471Indicator maps malware family/confidence/threat/context/mitre/GIR', () => {
    const c = mapIntel471Indicator(I471_INDICATORS, 'http://45.67.231.78:3214');
    expect(c).toMatchObject({
      found: true,
      indicatorCount: 1,
      malwareFamily: 'redline',
      confidence: 'high',
      threatType: 'malware',
      context: 'redline controller URL',
      mitreTactics: 'command_and_control',
    });
    expect(c.girs).toEqual(['1.1.5', '1.1.6']);
    expect(c.activeFrom).toBe(new Date(1615345265000).toISOString());
  });
  it('mapIntel471Search maps cross-entity counts (camelCase + snake_case)', () => {
    const s = mapIntel471Search(I471_SEARCH);
    expect(s).toMatchObject({
      reports: 35,
      posts: 132,
      actors: 41,
      entities: 13,
      news: 1,
      credentials: 1,
      credentialSets: 1,
      dataLeakPosts: 1,
    });
  });
});

function stubFetch() {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      if (url.includes('iris-enrich')) return resp(200, { response: { results: [ENRICH_RESULT] } });
      if (url.includes('iris-investigate') && url.includes('ip=')) return resp(200, { response: INVESTIGATE });
      if (url.includes('iris-investigate')) return resp(200, { response: { results: [ENRICH_RESULT] } });
      if (url.includes('dnslytics') && url.includes('/ipinfo/')) return resp(200, DNSL_IP);
      if (url.includes('dnslytics') && url.includes('/hostinghistory/')) return resp(200, DNSL_HH);
      if (url.includes('intel471.com') && url.includes('/indicators')) return resp(200, I471_INDICATORS);
      if (url.includes('intel471.com') && url.includes('/iocs')) return resp(200, I471_IOC);
      if (url.includes('/ip_addresses/') || url.includes('/domains/') || url.includes('/urls'))
        return resp(200, { data: { attributes: { last_analysis_stats: { harmless: 9 } } } });
      return resp(404, '{}');
    }),
  );
}

async function collect(indicators: { type: any; value: string; input: string }[], options?: any) {
  const events: EnrichEvent[] = [];
  for await (const ev of runEnrich({ indicators, options }, env)) events.push(ev);
  return events.flatMap((e) => (e.event === 'result' ? [e.result] : []));
}

describe('runEnrich routing by IOC type', () => {
  it('domains → DomainTools Enrich + DNSLytics HostingHistory; IPs → DNSLytics IP + DomainTools reverse', async () => {
    stubFetch();
    const results = await collect([
      { type: 'domain', value: 'evil.com', input: 'evil.com' },
      { type: 'ipv4', value: '9.9.9.9', input: '9.9.9.9' },
    ]);
    const dom = results.find((r) => r.value === 'evil.com');
    const ip = results.find((r) => r.value === '9.9.9.9');
    expect(dom?.domaintools).toMatchObject({ found: true, mode: 'enrich', riskScore: 88 });
    expect(dom?.dnslytics).toMatchObject({ found: true, kind: 'domain' }); // HostingHistory
    expect(dom?.dnslytics?.ips).toContain('193.0.2.10');
    expect(ip?.dnslytics).toMatchObject({ found: true, kind: 'ip', asn: 15169 });
    expect(ip?.domaintools).toMatchObject({ found: true, mode: 'reverse-ip' });
    // Intel 471 applies to every IOC type, merging Malware Intel (indicators) + IOC feed.
    expect(dom?.intel471?.found).toBe(true);
    expect(dom?.intel471?.malwareFamily).toBe('redline'); // from /indicators
    expect(ip?.intel471?.found).toBe(true);
  });

  it("treats a URL's host as a domain", async () => {
    stubFetch();
    const [r] = await collect([{ type: 'url', value: 'http://evil.com/login', input: 'http://evil.com/login' }]);
    expect(r.domaintools).toMatchObject({ mode: 'enrich', found: true });
    expect(r.dnslytics).toMatchObject({ kind: 'domain', found: true });
  });

  it('falls back to Iris Enrich for domains when Investigate returns 403', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.includes('iris-investigate')) return resp(403, { error: { code: 403, message: 'no access' } });
        if (url.includes('iris-enrich')) return resp(200, { response: { results: [ENRICH_RESULT] } });
        if (url.includes('dnslytics')) return resp(200, DNSL_HH);
        return resp(200, { data: { attributes: {} } });
      }),
    );
    const [r] = await collect([{ type: 'domain', value: 'evil.com', input: 'evil.com' }]);
    expect(r.domaintools).toMatchObject({ found: true, mode: 'enrich', riskScore: 88 });
  });

  it('client opt-out (options) skips a provider even when configured', async () => {
    stubFetch();
    const [r] = await collect(
      [{ type: 'domain', value: 'evil.com', input: 'evil.com' }],
      { domaintools: false, dnslytics: false },
    );
    expect(r.domaintools).toBeUndefined();
    expect(r.dnslytics).toBeUndefined();
  });
});
