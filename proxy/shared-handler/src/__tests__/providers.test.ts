import { describe, it, expect, vi, afterEach } from 'vitest';
import type { EnrichEvent } from '@vteeee/shared';
import { mapIrisEnrich, mapIrisInvestigateReverseIp } from '../domaintoolsFetch';
import { mapDnslyticsIp, mapDnslyticsHostingHistory } from '../dnslyticsFetch';
import { runEnrich } from '../enrich';
import type { ProxyEnv } from '../types';

const env: ProxyEnv = {
  vtApiKey: 'vt',
  domaintoolsApiUsername: 'u',
  domaintoolsApiKey: 'k',
  domaintoolsRpm: 600,
  dnslyticsApiKey: 'd',
  dnslyticsRpm: 600,
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

function stubFetch() {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      if (url.includes('iris-enrich')) return resp(200, { response: { results: [ENRICH_RESULT] } });
      if (url.includes('iris-investigate') && url.includes('ip=')) return resp(200, { response: INVESTIGATE });
      if (url.includes('iris-investigate')) return resp(200, { response: { results: [ENRICH_RESULT] } });
      if (url.includes('dnslytics') && url.includes('/ipinfo/')) return resp(200, DNSL_IP);
      if (url.includes('dnslytics') && url.includes('/hostinghistory/')) return resp(200, DNSL_HH);
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
