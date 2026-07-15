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
import { mapTvIp, mapTvDomain, mapTvSample, mapTvAdversary } from '../threatvisionFetch';
import { mapSocprimeQuery, mapSocprimeRules } from '../socprimeFetch';
import { mapMaxmind, maxmindLookup } from '../maxmindFetch';
import {
  mapRfLookup,
  mapRfActor,
  mapRfMalware,
  mapRfSandbox,
  mapRfRules,
  rfLookup,
} from '../recordedfutureFetch';
import { runEnrich } from '../enrich';
import type { ProxyEnv } from '../types';

const env: ProxyEnv = {
  vtApiKey: 'vt',
  maxmindAccountId: 'mm',
  maxmindLicenseKey: 'mmk',
  maxmindRpm: 600,
  recordedfutureApiKey: 'rf',
  recordedfutureRpm: 600,
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
  threatvisionClientId: 'tv-id',
  threatvisionClientSecret: 'tv-sec',
  threatvisionRpm: 600,
  allowedOrigins: ['*'],
  defaultRpm: 600,
  maxRpm: 1000,
  xTool: 'vteeee',
  maxBatch: 1000,
  dailyCap: 0,
  parseDailyCap: 0,
  urlscanDailyCap: 0,
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
  // count=5 also returns the top item arrays for drill-down:
  reports: [
    { subject: 'SOCKS proxy provider Insorg adds 500 front-end proxies', portalReportUrl: 'https://titan.intel471.com/report/inforep/abc' },
    { subject: 'Bulletproof hosting actor advertises proxy inventory' },
  ],
  actors: [{ handle: 'Insorg' }, { handle: 'MrBlonde' }],
  posts: [{ message: '   Selling fresh SOCKS5 proxies,\n US/EU low latency   ' }],
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

// TeamT5 ThreatVision — IP detail (§6.3), domain detail (§7.3), samples search (§3.4b), adversary (§12.4).
const TV_IP = {
  success: true,
  id: '167.179.85.233',
  analysis_status: true,
  risk_level: 'medium',
  risk_score: 70,
  risk_types: ['ce'],
  adversaries: ['Amoeba'],
  attributes: [{ name: 'Malware C2', first_seen: '2023-12-19T05:37:32.633Z', last_seen: '2023-12-19T05:37:32.633Z' }],
  ip_sharing: [{ name: 'Hosting', first_seen: '2023-12-27T11:13:49.394Z', last_seen: '2023-12-27T11:13:49.394Z' }],
  services: [],
  country: 'Japan',
  city: 'Ōi',
  region: 'Saitama',
  last_update_at: '2023-12-27T11:13:54.578Z',
  summary: { whois: true, related_adversaries: 1, related_reports: 6, related_samples: 1, dns_records: 7, osint: 0 },
};

const TV_DOMAIN = {
  success: true,
  id: 'lomeptos.com',
  analysis_status: true,
  risk_level: 'high',
  risk_score: 75,
  adversaries: [],
  attributes: [],
  services: [],
  registrar: 'OwnRegistrar, Inc.',
  last_update_at: '2023-12-27T11:19:27.727Z',
  summary: { whois: true, related_adversaries: 0, related_reports: 0, related_samples: 0, dns_records: 41, osint: 1 },
};

const TV_SAMPLE_SEARCH = {
  success: true,
  samples: [
    {
      sha256: 'b4e11a083c5dc3b69d0866f80193d10e96dbe611961f5f108cbe78dc8c93c2be',
      md5: 'f233991c8b0da42504e1af7e859bf292',
      size: 46592,
      first_seen: 1632405027,
      adversaries: ['Huapi'],
      malwares: ['Bifrost'],
      filename: 'f233991c8b0da42504e1af7e859bf292.virus',
      risk_level: 'high',
      has_network_activity: false,
      url: 'https://api.threatvision.org/api/v2/samples/b4e11a083c5dc3b69d0866f80193d10e96dbe611961f5f108cbe78dc8c93c2be',
    },
  ],
};

// MaxMind GeoIP2 Insights web-service response (subset of the real /geoip/v2.1/insights/{ip} shape).
const MAXMIND_INSIGHTS = {
  continent: { code: 'NA', geoname_id: 6255149, names: { en: 'North America' } },
  country: { confidence: 99, geoname_id: 6252001, is_in_european_union: false, iso_code: 'US', names: { en: 'United States' } },
  registered_country: { geoname_id: 6252001, iso_code: 'US', names: { en: 'United States' } },
  city: { confidence: 50, geoname_id: 5375480, names: { en: 'Mountain View' } },
  subdivisions: [{ confidence: 40, geoname_id: 5332921, iso_code: 'CA', names: { en: 'California' } }],
  postal: { code: '94043', confidence: 20 },
  location: {
    accuracy_radius: 50,
    latitude: 37.386,
    longitude: -122.0838,
    time_zone: 'America/Los_Angeles',
    average_income: 128321,
    population_density: 2495,
  },
  traits: {
    autonomous_system_number: 15169,
    autonomous_system_organization: 'GOOGLE',
    connection_type: 'Corporate',
    domain: 'google.com',
    ip_address: '9.9.9.9',
    isp: 'Google LLC',
    organization: 'Google LLC',
    network: '9.9.9.0/24',
    mobile_country_code: '310',
    mobile_network_code: '004',
    static_ip_score: 0.34,
    user_count: 2,
    user_type: 'hosting',
    is_hosting_provider: true,
    is_anonymous_vpn: false,
    anonymizer_confidence: 0,
  },
};

// Recorded Future Connect API lookup (subset of /v2/{type}/{id}?fields=... response).
const RF_IP_LOOKUP = {
  data: {
    risk: {
      score: 92,
      criticality: 4,
      criticalityLabel: 'Very Malicious',
      riskString: '9/79',
      riskSummary: '9 of 79 Risk Rules currently observed',
      evidenceDetails: [
        {
          rule: 'Actively Communicating C&C Server',
          criticality: 4,
          criticalityLabel: 'Very Malicious',
          evidenceString: 'Recorded Future network traffic analysis identified active C2 communication.',
          timestamp: '2025-01-10T14:51:38.462Z',
        },
        {
          rule: 'Current Tor Node',
          criticality: 2,
          criticalityLabel: 'Suspicious',
          evidenceString: 'This IP is a current Tor exit node.',
          timestamp: '2025-01-09T00:00:00.000Z',
        },
      ],
    },
    timestamps: { firstSeen: '2019-08-14T00:00:00.000Z', lastSeen: '2025-01-10T00:00:00.000Z' },
    threatLists: [{ name: 'Tor Exit Nodes' }, { name: 'C&C Servers' }],
    relatedEntities: [
      {
        type: 'RelatedThreatActor',
        entities: [
          { count: 12, entity: { id: 'S9Gvql', name: 'BlueDelta', type: 'Organization' } },
          { count: 3, entity: { id: 'PD_NyL', name: 'UAC-0056' } },
        ],
      },
      { type: 'RelatedMalware', entities: [{ count: 7, entity: { id: 'K5GvlA', name: 'X-Agent' } }] },
    ],
    riskMapping: [{ rule: 'Actively Communicating C&C Server', categories: [{ framework: 'MITRE', name: 'T1071' }] }],
    location: { asn: 'AS60729', organization: 'Zwiebelfreunde e.V.', location: { country: 'Germany', city: 'Frankfurt' } },
    aiInsights: { text: 'Active C2 attributed to BlueDelta.' },
    intelCard: 'https://app.recordedfuture.com/live/sc/entity/ip%3A185.220.101.1',
  },
};

const RF_ACTOR = {
  data: [
    {
      id: 'S9Gvql',
      type: 'Organization',
      attributes: {
        name: 'BlueDelta',
        common_names: ['APT28'],
        alias: ['Fancy Bear', 'Sofacy'],
        categories: [{ id: 'PD_NyL', name: 'Nation State Sponsored' }],
      },
    },
  ],
};

const RF_MALWARE = {
  data: {
    entity: { id: 'K5GvlA', name: 'X-Agent' },
    timestamps: { firstSeen: '2015-02-11T00:00:00.000Z', lastSeen: '2025-01-01T00:00:00.000Z' },
    relatedEntities: [
      { type: 'RelatedMalwareCategory', entities: [{ entity: { name: 'Backdoor' } }] },
      { type: 'RelatedThreatActor', entities: [{ count: 5, entity: { name: 'BlueDelta' } }] },
    ],
  },
};

const RF_SANDBOX = {
  data: [
    {
      name: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
      count: 10,
      risk_score: 89,
      sandbox_score: 8,
      file_extensions: ['.exe'],
      tags: ['trojan', 'family:redline'],
      links: { universal_report: 'https://app.recordedfuture.com/portal/x/sandbox-report', intelligence_card: 'https://app.recordedfuture.com/portal/x' },
    },
  ],
  counts: { returned: 1, total: 3 },
};

const RF_RULES = {
  result: [
    {
      id: 'doc:1',
      title: 'X-Agent C2 beacon',
      type: 'sigma',
      description: 'Detects the HTTP beacon pattern used by X-Agent.',
      created: '2024-05-01',
      updated: '2025-11-12',
      rules: [{ content: 'title: X-Agent C2 beacon\nlevel: high', file_name: 'xagent.yml', entities: [{ name: 'X-Agent' }] }],
    },
  ],
  counts: { total: 1 },
};

const TV_ADVERSARY = {
  success: true,
  adversaries: [
    {
      name: 'Polaris',
      aliases: ['Mustang Panda', 'HoneyMyte', 'Earth Preta'],
      origin_countries: ['China'],
      targeted_countries: ['South Korea', 'Japan', null, 'Taiwan'],
      targeted_industries: ['Media', 'Government'],
      overview: 'The Polaris group has been active since at least 2011.',
      last_updated_at: 1695916800,
    },
  ],
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
  it('mapIntel471Search extracts top drill-down items (title + Titan url, whitespace collapsed)', () => {
    const s = mapIntel471Search(I471_SEARCH);
    expect(s.items?.reports?.[0]).toEqual({
      title: 'SOCKS proxy provider Insorg adds 500 front-end proxies',
      url: 'https://titan.intel471.com/report/inforep/abc',
    });
    expect(s.items?.reports?.[1]).toEqual({ title: 'Bulletproof hosting actor advertises proxy inventory' });
    expect(s.items?.actors?.map((a) => a.title)).toEqual(['Insorg', 'MrBlonde']);
    expect(s.items?.posts?.[0]?.title).toBe('Selling fresh SOCKS5 proxies, US/EU low latency'); // collapsed
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

describe('ThreatVision mappers', () => {
  it('mapTvIp maps risk, adversaries, attributes (+ ip_sharing), geo and summary counts', () => {
    const c = mapTvIp(TV_IP);
    expect(c).toMatchObject({ found: true, kind: 'ip', riskLevel: 'medium', riskScore: 70, country: 'Japan' });
    expect(c.riskTypes).toEqual(['ce']);
    expect(c.adversaries).toEqual(['Amoeba']);
    expect(c.attributes).toEqual(['Malware C2', 'Hosting']); // attributes[].name + ip_sharing[].name
    expect(c.relatedReports).toBe(6);
    expect(c.dnsRecords).toBe(7);
  });
  it('mapTvIp returns found:false when the IP is not yet analyzed', () => {
    expect(mapTvIp({ success: true, analysis_status: false, message: 'Analyzing' })).toMatchObject({
      found: false,
      kind: 'ip',
    });
  });
  it('mapTvDomain maps risk + registrar (no geo) + summary', () => {
    const c = mapTvDomain(TV_DOMAIN);
    expect(c).toMatchObject({ found: true, kind: 'domain', riskLevel: 'high', riskScore: 75, registrar: 'OwnRegistrar, Inc.' });
    expect(c.dnsRecords).toBe(41);
  });
  it('mapTvSample picks the matching sample → risk + adversary + malware family (0 AAP path)', () => {
    const c = mapTvSample(TV_SAMPLE_SEARCH, 'b4e11a083c5dc3b69d0866f80193d10e96dbe611961f5f108cbe78dc8c93c2be');
    expect(c).toMatchObject({ found: true, kind: 'sample', riskLevel: 'high', md5: 'f233991c8b0da42504e1af7e859bf292' });
    expect(c.adversaries).toEqual(['Huapi']);
    expect(c.malwareFamilies).toEqual(['Bifrost']);
    expect(c.hasNetworkActivity).toBe(false);
    expect(c.firstSeen).toBe(new Date(1632405027 * 1000).toISOString());
  });
  it('mapTvAdversary maps aliases/origin/targets, dropping nulls from targeted_countries', () => {
    const a = mapTvAdversary(TV_ADVERSARY);
    expect(a.name).toBe('Polaris');
    expect(a.aliases).toContain('Mustang Panda');
    expect(a.originCountries).toEqual(['China']);
    expect(a.targetedCountries).toEqual(['South Korea', 'Japan', 'Taiwan']); // null filtered out
    expect(a.targetedIndustries).toEqual(['Media', 'Government']);
    expect(a.overview).toContain('Polaris');
  });
});

describe('MaxMind GeoIP mapper + lookup', () => {
  it('mapMaxmind maps Insights place/network/anonymizer/demographics fields', () => {
    const c = mapMaxmind(MAXMIND_INSIGHTS);
    expect(c).toMatchObject({
      found: true,
      continent: 'North America',
      country: 'United States',
      countryCode: 'US',
      countryConfidence: 99,
      city: 'Mountain View',
      cityConfidence: 50,
      subdivision: 'California',
      subdivisionCode: 'CA',
      postal: '94043',
      latitude: 37.386,
      longitude: -122.0838,
      accuracyRadius: 50,
      timeZone: 'America/Los_Angeles',
      averageIncome: 128321,
      populationDensity: 2495,
      network: '9.9.9.0/24',
      asn: 15169,
      asnOrganization: 'GOOGLE',
      isp: 'Google LLC',
      domain: 'google.com',
      connectionType: 'Corporate',
      mobileCountryCode: '310',
      mobileNetworkCode: '004',
      staticIpScore: 0.34,
      userCount: 2,
      userType: 'hosting',
    });
    expect(c.subdivisions).toEqual(['California']);
    expect(c.anonymizerType).toEqual(['Hosting']); // derived from is_hosting_provider
    expect(c.isHostingProvider).toBe(true);
  });

  it('mapMaxmind returns found:false for an empty / non-object response', () => {
    expect(mapMaxmind({})).toMatchObject({ found: false });
    expect(mapMaxmind(null)).toMatchObject({ found: false });
  });

  it('maxmindLookup treats reserved/private IPs as found:false, not an error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => resp(400, { code: 'IP_ADDRESS_RESERVED', error: 'reserved IP' })),
    );
    const c = await maxmindLookup('192.168.0.1', env);
    expect(c).toMatchObject({ found: false });
    expect(c?.error).toBeUndefined(); // a private IP is simply "no geolocation", not a failure
  });

  it('maxmindLookup surfaces a 401 (bad account ID / license key) as an error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => resp(401, { code: 'AUTHORIZATION_INVALID', error: 'bad key' })),
    );
    const c = await maxmindLookup('9.9.9.9', env);
    expect(c?.found).toBe(false);
    expect(c?.error).toMatch(/401/);
  });

  it('maxmindLookup returns undefined when no MaxMind credentials are configured', async () => {
    const c = await maxmindLookup('9.9.9.9', { ...env, maxmindAccountId: undefined, maxmindLicenseKey: undefined });
    expect(c).toBeUndefined();
  });
});

describe('Recorded Future mappers + lookup', () => {
  it('mapRfLookup maps risk, evidence (+MITRE), related actors/malware, threat lists, location, AI', () => {
    const c = mapRfLookup(RF_IP_LOOKUP);
    expect(c).toMatchObject({
      found: true,
      riskScore: 92,
      criticality: 4,
      criticalityLabel: 'Very Malicious',
      riskString: '9/79',
    });
    expect(c.evidence?.[0]).toMatchObject({ rule: 'Actively Communicating C&C Server', criticality: 4 });
    expect(c.evidence?.[0]?.mitre).toEqual(['T1071']); // from riskMapping, joined by rule
    expect(c.threatLists).toEqual(['Tor Exit Nodes', 'C&C Servers']);
    expect(c.relatedActors?.[0]).toMatchObject({ id: 'S9Gvql', name: 'BlueDelta', count: 12 }); // most-referenced first
    expect(c.relatedMalware?.[0]).toMatchObject({ id: 'K5GvlA', name: 'X-Agent' });
    expect(c.mitre).toContain('T1071');
    expect(c.asn).toBe('AS60729');
    expect(c.country).toBe('Germany');
    expect(c.aiInsights).toContain('BlueDelta');
    expect(c.intelCard).toContain('recordedfuture.com');
  });
  it('mapRfLookup returns found:false for an empty response', () => {
    expect(mapRfLookup({})).toMatchObject({ found: false });
    expect(mapRfLookup({ data: {} })).toMatchObject({ found: false });
  });
  it('mapRfActor picks the name-matching actor + aliases/common names/categories + intel card', () => {
    const a = mapRfActor(RF_ACTOR, 'BlueDelta');
    expect(a).toMatchObject({ id: 'S9Gvql', name: 'BlueDelta' });
    expect(a.commonNames).toContain('APT28');
    expect(a.aliases).toContain('Fancy Bear');
    expect(a.categories).toContain('Nation State Sponsored');
    expect(a.intelCard).toContain('S9Gvql');
  });
  it('mapRfMalware maps categories + related actors + timestamps + intel card', () => {
    const m = mapRfMalware(RF_MALWARE, 'X-Agent');
    expect(m).toMatchObject({ id: 'K5GvlA', name: 'X-Agent' });
    expect(m.categories).toContain('Backdoor');
    expect(m.relatedActors).toContain('BlueDelta');
    expect(m.intelCard).toContain('K5GvlA');
  });
  it('mapRfSandbox maps the first hit (scores/tags/report link/total)', () => {
    const s = mapRfSandbox(RF_SANDBOX);
    expect(s).toMatchObject({ riskScore: 89, sandboxScore: 8, total: 3 });
    expect(s.tags).toContain('family:redline');
    expect(s.universalReport).toContain('sandbox-report');
  });
  it('mapRfRules maps rule docs (type/title/content/entities + total)', () => {
    const res = mapRfRules(RF_RULES);
    expect(res.total).toBe(1);
    expect(res.rules?.[0]).toMatchObject({ id: 'doc:1', title: 'X-Agent C2 beacon', type: 'sigma', fileName: 'xagent.yml' });
    expect(res.rules?.[0]?.content).toContain('X-Agent');
    expect(res.rules?.[0]?.entities).toEqual(['X-Agent']);
  });
  it('rfLookup treats a 404 as found:false (not in RF), not an error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => resp(404, {})));
    const c = await rfLookup('domain', 'nope.example', env);
    expect(c).toMatchObject({ found: false });
    expect(c?.error).toBeUndefined();
  });
  it('rfLookup surfaces a 403 (subscription lacks the API) as an error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => resp(403, { message: 'no access' })));
    const c = await rfLookup('ipv4', '1.2.3.4', env);
    expect(c?.found).toBe(false);
    expect(c?.error).toMatch(/403/);
  });
  it('rfLookup returns undefined when no RF token is configured', async () => {
    expect(await rfLookup('ipv4', '1.2.3.4', { ...env, recordedfutureApiKey: undefined })).toBeUndefined();
  });
});

describe('SOC Prime Uncoder mapper', () => {
  it('mapSocprimeQuery reads {queries:[{query,iocs_count}]}', () => {
    const r = mapSocprimeQuery({ queries: [{ query: 'index=* dst IN (1.1.1.1)', iocs_count: 3 }], iocs_count: 3 });
    expect(r.queries).toEqual(['index=* dst IN (1.1.1.1)']);
    expect(r.iocCount).toBe(3);
    expect(r.raw).toBeDefined();
  });
  it('mapSocprimeQuery accepts a bare string, an array of strings, and {result}', () => {
    expect(mapSocprimeQuery('search dst=1.1.1.1').queries).toEqual(['search dst=1.1.1.1']);
    expect(mapSocprimeQuery(['q1', 'q2']).queries).toEqual(['q1', 'q2']);
    expect(mapSocprimeQuery({ result: 'q3' }).queries).toEqual(['q3']);
  });
  it('mapSocprimeQuery returns no queries (but keeps raw) for an unrecognized shape', () => {
    const r = mapSocprimeQuery({ status: 'ok', unrelated: 1 });
    expect(r.queries).toBeUndefined();
    expect(r.raw).toEqual({ status: 'ok', unrelated: 1 });
  });

  it('mapSocprimeRules maps nested case/sigma/tags fields + techniques/tactics + total', () => {
    const res = mapSocprimeRules({
      total: 42,
      rules: [
        {
          case: { id: 'abc123', name: 'Suspicious PowerShell Download' },
          description: 'Detects a PowerShell download cradle.',
          sigma: { level: 'high', status: 'stable', text: 'index=* powershell DownloadString' },
          tags: {
            author: ['SOC Prime Team'],
            actor: ['APT28'],
            technique: [{ id: 'T1059.001', name: 'PowerShell', tactics: ['Execution'] }],
          },
          translation: 'index=* Image="*powershell.exe" CommandLine="*DownloadString*"',
        },
      ],
    });
    expect(res.total).toBe(42);
    const r = res.rules?.[0];
    expect(r).toMatchObject({ id: 'abc123', name: 'Suspicious PowerShell Download', level: 'high', status: 'stable', author: 'SOC Prime Team' });
    expect(r?.techniques).toEqual(['T1059.001']);
    expect(r?.tactics).toEqual(['Execution']);
    expect(r?.actors).toEqual(['APT28']);
    expect(r?.translation).toContain('DownloadString');
    expect(r?.url).toBe('https://tdm.socprime.com/tdm/info/abc123');
  });
  it('mapSocprimeRules accepts a bare array response', () => {
    const res = mapSocprimeRules([{ case: { id: 'x', name: 'Rule X' }, sigma: { level: 'low' } }]);
    expect(res.rules?.[0]).toMatchObject({ id: 'x', name: 'Rule X', level: 'low' });
    expect(res.total).toBe(1);
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
      // ThreatVision (before the VT catch-all: its domain path also contains "/domains/").
      if (url.includes('threatvision.org') && url.includes('/oauth/token')) return resp(200, { access_token: 'tv-tok', expires_in: 3600 });
      if (url.includes('threatvision.org') && url.includes('/network/ips/')) return resp(200, TV_IP);
      if (url.includes('threatvision.org') && url.includes('/network/domains/')) return resp(200, TV_DOMAIN);
      if (url.includes('threatvision.org') && url.includes('/samples/search')) return resp(200, TV_SAMPLE_SEARCH);
      if (url.includes('threatvision.org') && url.includes('/adversaries/search')) return resp(200, TV_ADVERSARY);
      // MaxMind GeoIP (before the VT catch-all): https://geoip.maxmind.com/geoip/v2.1/insights/{ip}
      if (url.includes('geoip.maxmind.com')) return resp(200, MAXMIND_INSIGHTS);
      // Recorded Future Connect lookup (all IOC types): https://api.recordedfuture.com/v2/{type}/{id}
      if (url.includes('api.recordedfuture.com/v2/')) return resp(200, RF_IP_LOOKUP);
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
    // MaxMind GeoIP applies to IPs only (geolocation + Insights traits).
    expect(ip?.maxmind).toMatchObject({ found: true, country: 'United States', city: 'Mountain View', asn: 15169 });
    expect(dom?.maxmind).toBeUndefined(); // not an IP → no MaxMind lookup
    // Recorded Future applies to every IOC type (Connect risk + related actors/malware pivots).
    expect(ip?.recordedfuture).toMatchObject({ found: true, riskScore: 92, criticalityLabel: 'Very Malicious' });
    expect(ip?.recordedfuture?.relatedActors?.[0]?.name).toBe('BlueDelta');
    expect(dom?.recordedfuture?.found).toBe(true);
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
    // ThreatVision: IPs → ips detail (1 AAP), domains → domains detail (1 AAP).
    expect(ip?.threatvision).toMatchObject({ found: true, kind: 'ip', riskLevel: 'medium' });
    expect(ip?.threatvision?.adversaries).toEqual(['Amoeba']);
    expect(dom?.threatvision).toMatchObject({ found: true, kind: 'domain', registrar: 'OwnRegistrar, Inc.' });
  });

  it('hashes → ThreatVision sample attribution (adversary + malware family) via search', async () => {
    stubFetch();
    const [r] = await collect([
      {
        type: 'sha256',
        value: 'b4e11a083c5dc3b69d0866f80193d10e96dbe611961f5f108cbe78dc8c93c2be',
        input: 'b4e11a083c5dc3b69d0866f80193d10e96dbe611961f5f108cbe78dc8c93c2be',
      },
    ]);
    expect(r.threatvision).toMatchObject({ found: true, kind: 'sample', riskLevel: 'high' });
    expect(r.threatvision?.adversaries).toEqual(['Huapi']);
    expect(r.threatvision?.malwareFamilies).toEqual(['Bifrost']);
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
      { domaintools: false, dnslytics: false, cyfirma: false, threatvision: false },
    );
    expect(r.domaintools).toBeUndefined();
    expect(r.dnslytics).toBeUndefined();
    expect(r.cyfirma).toBeUndefined();
    expect(r.threatvision).toBeUndefined();
  });
});
