import { describe, it, expect, vi, afterEach } from 'vitest';
import type { EnrichEvent } from '@vteeee/shared';
import { mapIrisEnrich, mapIrisInvestigateReverseIp } from '../domaintoolsFetch';
import { mapDnslyticsIp, mapDnslyticsHostingHistory } from '../dnslyticsFetch';
import {
  mapIntel471Ioc,
  mapIntel471Indicator,
  mapIntel471Search,
  mapIntel471MalwareReports,
  mapIntel471Family,
} from '../intel471Fetch';
import { mapRiskDossier, mapStixSearch, mapThreatActor } from '../cyfirmaFetch';
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
  cyfirmaApiKey: 'c',
  cyfirmaRpm: 600,
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

// Intel 471 /malwareReports?malwareFamilyProfileUid= (subjects + activity + GIR/MITRE).
const I471_MALWARE_REPORTS = {
  malwareReportTotalCount: 7,
  malwareReports: [
    {
      uid: 'r1',
      subject: 'Orcus RAT operators expand plugin marketplace',
      data: { threat: { data: { family: 'orcus', mitre_tactics: 'command_and_control' } }, malware_report_data: {} },
      classification: { intelRequirements: ['1.1.3'] },
      activity: { first: 1660784348000, last: 1751221347000 },
      last_updated: 1751221347000,
    },
    {
      uid: 'r2',
      subject: 'Commodity RAT orcus bundled in phishing campaign',
      data: { threat: { data: { family: 'orcus', mitre_tactics: 'collection' } } },
      classification: { intelRequirements: ['1.1.3', '2.4'] },
      activity: { first: 1670000000000, last: 1700000000000 },
    },
  ],
};

// Intel 471 /malwareFamilies?malwareFamily= (family profile: aka + summary).
const I471_MALWARE_FAMILIES = {
  malware_family_total_count: 1,
  malware_families: [
    {
      uid: '6e6ca74063416138a3fbf03dd2e189a6',
      name: 'orcus',
      aliases: ['Schnorchel', 'Snorkel'],
      description: 'Orcus is a popular RAT written in C#.',
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

// CYFIRMA Risk Dossier — real multi-entry shape: indicator entry + CAMPAIGN entry (TA in details) +
// IOC entry whose iocAttribute.sha is an array of OBJECTS ({key,value,…}), not strings.
const CYF_DOSSIER = {
  title: 'This view summarizes the risk dossier for the selected indicator for your organisation.',
  riskViewScores: { riskScore: 8, externalThreatScore: 8, riskScoreTrend: 'EQUAL', externalThreatScoreTrend: 'EQUAL' },
  riskDossierDetails: [
    {
      story: 'This IP address <span class="active-txt cp IP">158.255.7.61</span> is malicious in nature. Additional Information for the IP address.',
      description: null,
      impact: null,
      riskScore: 8,
      type: 'IP ADDRESS',
      action: 'Block the IP address.',
      details: { 'ASN Owner': 'Hostkey B.v.', ASN: '50867', Organization: 'Hostkey B.v.', 'Country Name': 'Russia' },
      iocAttribute: { md5: [], sha: [], ips: [], domain: [], hostname: [], url: [], file: [], ssl: [], mutex: [], emails: [], cves: [], exploits: [], coRelation: {} },
    },
    {
      story: '<span class="active-txt cp Campaign">bn34unit</span> campaign associated with IP Address <span class="active-txt cp IP">158.255.7.61</span>.',
      description: 'The campaign is believed to have been launched on 26 March 2021. Motivation: Stealing of sensitive information',
      impact: null,
      riskScore: 10,
      type: 'CAMPAIGN',
      action: 'Please refer to our campaign details page to find the recommendations.',
      details: { 'Threat Actor': '<span class="active-txt cp TA">Emissary Panda</span>', industry: 'Trading Companies & Distributors,IT Services' },
      iocAttribute: { md5: [], sha: [], ips: [], domain: [], hostname: [], url: [], file: [], ssl: [], mutex: [], emails: [], cves: [], exploits: [], coRelation: {} },
    },
    {
      story: 'These are the latest IOCs related to <span class="active-txt cp IP">158.255.7.61</span>.',
      description: null,
      impact: null,
      riskScore: null,
      type: 'IOC',
      action: 'Block these IOCs.',
      details: {},
      iocAttribute: {
        md5: [],
        sha: [
          { id: null, key: 'SHA', value: '4ae4df2bdb0428cace1085e4cc200ef1133affded57ee41fdc75fe5c9a9421ef', tags: [] },
          { id: null, key: 'SHA', value: '67d8f6ed6fe28fc2f62550dcdac4807b39531ac2750706e4d36c8113c3f267ed', tags: [] },
        ],
        ips: [],
        domain: [],
        hostname: [],
        url: [],
        file: [],
        ssl: [],
        mutex: [],
        emails: [],
        cves: [],
        exploits: [],
        coRelation: {},
      },
    },
  ],
};

// CYFIRMA STIX 2.1 IOC search — real shape: indicator + relationship + malware object.
const CYF_STIX = [
  {
    type: 'indicator',
    spec_version: '2.1',
    id: 'indicator--8e2e2d2b',
    name: 'Poison Ivy Malware',
    description: 'This file is part of Poison Ivy',
    pattern: "[ file:hashes.'SHA-256' = '4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877' ]",
    valid_from: '2016-01-01T00:00:00Z',
  },
  { type: 'relationship', spec_version: '2.1', id: 'relationship--1', relationship_type: 'indicates', source_ref: 'indicator--8e2e2d2b', target_ref: 'malware--31b9' },
  { type: 'malware', spec_version: '2.1', id: 'malware--31b9', name: 'Poison Ivy', malware_types: ['trojan'] },
];

// CYFIRMA Threat Actor search bundle — real shape (aliases/primary_motivation, malware, campaign, vulnerability).
const CYF_ACTOR = [
  {
    aliases: ['Tsar Team'],
    primary_motivation: 'Financial, Reputation damage,BRONZE BUTLER',
    type: 'threat-actor',
    spec_version: '2.1',
    id: 'threat-actor--5bfb529f',
    name: 'Fancy Bear',
    description: '',
  },
  { source_ref: 'malware--5c8a10e2', target_ref: 'threat-actor--5bfb529f', relationship_type: 'targets', type: 'relationship', spec_version: '2.1', id: 'relationship--1' },
  { is_family: false, malware_types: ['malware'], type: 'malware', spec_version: '2.1', id: 'malware--5c8a10e2', name: 'BRONZE BUTLER', description: 'Agent.btz' },
  { type: 'campaign', spec_version: '2.1', id: 'campaign--5f43a3f2', name: 'vision2025', description: '' },
  {
    type: 'vulnerability',
    spec_version: '2.1',
    id: 'vulnerability--5e7ba49d',
    name: 'CVE-2003-0845',
    description: 'Unknown vulnerability in the HSQLDB component in JBoss 3.2.1 and 3.0.8 ...',
    external_references: [{ source_name: 'cve', external_id: 'CVE-2003-0845' }],
  },
];

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
  it('mapIntel471Indicator captures the malware family profile UID (→ Titan /malware/{uid})', () => {
    const c = mapIntel471Indicator(I471_INDICATORS, 'http://45.67.231.78:3214');
    expect(c.malwareFamilyUid).toBe('29f5');
  });
  it('mapIntel471MalwareReports maps subjects, count, MITRE, GIR and the activity window', () => {
    const m = mapIntel471MalwareReports(I471_MALWARE_REPORTS);
    expect(m.reportCount).toBe(7);
    expect(m.reports).toEqual([
      'Orcus RAT operators expand plugin marketplace',
      'Commodity RAT orcus bundled in phishing campaign',
    ]);
    expect(m.mitreTactics).toEqual(expect.arrayContaining(['command_and_control', 'collection']));
    expect(m.girs).toEqual(expect.arrayContaining(['1.1.3', '2.4']));
    expect(m.activeFrom).toBe(new Date(1660784348000).toISOString()); // min first
    expect(m.activeTill).toBe(new Date(1751221347000).toISOString()); // max last
  });
  it('mapIntel471Family picks the profile by UID and maps aka + summary', () => {
    const f = mapIntel471Family(I471_MALWARE_FAMILIES, '6e6ca74063416138a3fbf03dd2e189a6', 'orcus');
    expect(f.family).toBe('orcus');
    expect(f.aka).toEqual(['Schnorchel', 'Snorkel']);
    expect(f.summary).toContain('RAT');
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

describe('CYFIRMA mappers', () => {
  it('mapRiskDossier maps scores, action, ASN/org/country from the primary entry and strips story HTML', () => {
    const c = mapRiskDossier(CYF_DOSSIER);
    expect(c).toMatchObject({
      found: true,
      riskScore: 8,
      externalThreatScore: 8,
      riskScoreTrend: 'EQUAL',
      indicatorType: 'IP ADDRESS',
      indicatorRiskScore: 8,
      action: 'Block the IP address.', // from the IP entry, not the CAMPAIGN/IOC entries
      asn: '50867',
      asnOwner: 'Hostkey B.v.',
      organization: 'Hostkey B.v.',
      country: 'Russia',
    });
    expect(c.story).toBe('This IP address 158.255.7.61 is malicious in nature. Additional Information for the IP address.');
  });

  it('mapRiskDossier harvests attribution (TA/campaign) from HTML spans across all entries', () => {
    const c = mapRiskDossier(CYF_DOSSIER);
    expect(c.campaigns).toEqual(['bn34unit']); // <span class="... cp Campaign">
    expect(c.threatActors).toEqual(['Emissary Panda']); // details["Threat Actor"] span
  });

  it('mapRiskDossier reads object-form iocAttribute buckets (sha[].value) as related hashes', () => {
    const c = mapRiskDossier(CYF_DOSSIER);
    expect(c.related?.hashes).toEqual([
      '4ae4df2bdb0428cace1085e4cc200ef1133affded57ee41fdc75fe5c9a9421ef',
      '67d8f6ed6fe28fc2f62550dcdac4807b39531ac2750706e4d36c8113c3f267ed',
    ]);
    expect(c.relatedCount).toBe(2);
  });

  it('mapRiskDossier accepts the V2 array-only shape and returns found:false when empty', () => {
    expect(mapRiskDossier([{ type: 'DOMAIN', story: 'x', action: 'Block this IOC.', iocAttribute: {} }])).toMatchObject({
      found: true,
      indicatorType: 'DOMAIN',
      action: 'Block this IOC.',
    });
    expect(mapRiskDossier({ riskViewScores: {}, riskDossierDetails: [] })).toMatchObject({ found: false });
  });

  it('mapStixSearch maps the STIX indicator name/description + related malware object', () => {
    const c = mapStixSearch(CYF_STIX);
    expect(c).toMatchObject({ found: true, indicatorName: 'Poison Ivy Malware' });
    expect(c.description).toContain('Poison Ivy');
    expect(c.malware).toEqual(['Poison Ivy']);
    expect(c.threatActors).toBeUndefined(); // this search bundle has no threat-actor object
  });

  it('mapThreatActor maps aliases/motivation/campaigns/malware/targeted CVEs', () => {
    const s = mapThreatActor(CYF_ACTOR);
    expect(s.actor).toBe('Fancy Bear');
    expect(s.aliases).toEqual(['Tsar Team']);
    expect(s.motivation).toContain('Financial');
    expect(s.campaigns).toEqual(['vision2025']);
    expect(s.malware).toEqual(['BRONZE BUTLER']);
    expect(s.vulnerabilities).toEqual(['CVE-2003-0845']);
    expect(s.description).toBeUndefined(); // empty description is not surfaced
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
      if (url.includes('decyfir') && url.includes('/risk-dossier')) return resp(200, CYF_DOSSIER);
      if (url.includes('decyfir') && url.includes('/threatioc/stix/v2.1/search')) return resp(200, CYF_STIX);
      if (url.includes('decyfir') && url.includes('/threatactor')) return resp(200, CYF_ACTOR);
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
    // CYFIRMA applies to every IOC type, merging Risk Dossier + STIX 2.1 search.
    expect(dom?.cyfirma?.found).toBe(true);
    expect(dom?.cyfirma?.action).toBe('Block the IP address.'); // from /risk-dossier
    expect(dom?.cyfirma?.threatActors).toContain('Emissary Panda'); // harvested from dossier spans
    expect(dom?.cyfirma?.malware).toContain('Poison Ivy'); // from STIX search
    expect(ip?.cyfirma?.found).toBe(true);
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
      { domaintools: false, dnslytics: false, cyfirma: false },
    );
    expect(r.domaintools).toBeUndefined();
    expect(r.dnslytics).toBeUndefined();
    expect(r.cyfirma).toBeUndefined();
  });
});
