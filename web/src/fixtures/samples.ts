import type { IocType, ResultStatus } from '@vteeee/shared';

export interface Fixture {
  value: string;
  type: IocType;
  status: ResultStatus;
  /** VT-style `data.attributes` (omitted for not_found). */
  attributes?: Record<string, unknown>;
}

const day = 86400;
const now = Math.floor(Date.now() / 1000);

/** Safe, realistic sample data covering every IOC type × verdict, incl. EICAR. */
export const FIXTURES: Fixture[] = [
  {
    value: '1.1.1.1',
    type: 'ipv4',
    status: 'success',
    attributes: {
      last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 78, undetected: 8, timeout: 0 },
      reputation: 3,
      total_votes: { harmless: 120, malicious: 6 },
      country: 'AU',
      asn: 13335,
      as_owner: 'CLOUDFLARENET',
      network: '1.1.1.0/24',
      regional_internet_registry: 'APNIC',
      tags: [],
      last_analysis_date: now - 2 * day,
    },
  },
  {
    value: '185.220.101.1',
    type: 'ipv4',
    status: 'success',
    attributes: {
      last_analysis_stats: { malicious: 14, suspicious: 2, harmless: 40, undetected: 14, timeout: 0 },
      reputation: -38,
      total_votes: { harmless: 1, malicious: 22 },
      country: 'DE',
      asn: 60729,
      as_owner: 'Zwiebelfreunde e.V. (Tor exit)',
      network: '185.220.100.0/22',
      regional_internet_registry: 'RIPE NCC',
      tags: ['tor', 'malicious'],
      last_analysis_date: now - 1 * day,
      gti_assessment: {
        verdict: { value: 'VERDICT_MALICIOUS' },
        severity: { value: 'SEVERITY_HIGH' },
        threat_score: { value: 85 },
      },
    },
  },
  {
    value: '2001:4860:4860::8888',
    type: 'ipv6',
    status: 'success',
    attributes: {
      last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 70, undetected: 16, timeout: 0 },
      reputation: 0,
      total_votes: { harmless: 30, malicious: 0 },
      country: 'US',
      asn: 15169,
      as_owner: 'GOOGLE',
      network: '2001:4860::/32',
      regional_internet_registry: 'ARIN',
      tags: [],
      last_analysis_date: now - 5 * day,
    },
  },
  {
    value: 'google.com',
    type: 'domain',
    status: 'success',
    attributes: {
      last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 84, undetected: 6, timeout: 0 },
      reputation: 95,
      total_votes: { harmless: 540, malicious: 12 },
      registrar: 'MarkMonitor Inc.',
      creation_date: 874296000,
      categories: { Forcepoint: 'search engines and portals', BitDefender: 'searchengines' },
      popularity_ranks: { Majestic: { rank: 1 }, 'Cisco Umbrella': { rank: 1 } },
      tags: [],
      last_analysis_date: now - 3 * day,
    },
  },
  {
    value: 'phishy-malware-example.com',
    type: 'domain',
    status: 'success',
    attributes: {
      last_analysis_stats: { malicious: 9, suspicious: 3, harmless: 40, undetected: 18, timeout: 0 },
      reputation: -22,
      total_votes: { harmless: 0, malicious: 14 },
      registrar: 'NameCheap, Inc.',
      creation_date: now - 20 * day,
      categories: { BitDefender: 'phishing', 'Forcepoint ThreatSeeker': 'malicious websites' },
      tags: ['phishing'],
      last_analysis_date: now - 1 * day,
      gti_assessment: {
        verdict: { value: 'VERDICT_MALICIOUS' },
        severity: { value: 'SEVERITY_MEDIUM' },
        threat_score: { value: 72 },
      },
    },
  },
  {
    value: 'never-scanned-vteeee-7f3a9.com',
    type: 'domain',
    status: 'not_found',
  },
  {
    value: 'https://www.google.com/',
    type: 'url',
    status: 'success',
    attributes: {
      last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 70, undetected: 20, timeout: 0 },
      reputation: 0,
      total_votes: { harmless: 40, malicious: 1 },
      title: 'Google',
      last_final_url: 'https://www.google.com/',
      last_http_response_code: 200,
      categories: { Forcepoint: 'search engines and portals' },
      tags: [],
      last_analysis_date: now - 4 * day,
    },
  },
  {
    value: 'http://phishy-malware-example.com/login.php',
    type: 'url',
    status: 'success',
    attributes: {
      last_analysis_stats: { malicious: 11, suspicious: 2, harmless: 50, undetected: 17, timeout: 0 },
      reputation: -30,
      total_votes: { harmless: 0, malicious: 9 },
      title: 'Account verification required',
      last_final_url: 'http://phishy-malware-example.com/login.php',
      last_http_response_code: 200,
      categories: { BitDefender: 'phishing' },
      threat_names: ['Phishing.Generic'],
      tags: ['phishing'],
      last_analysis_date: now - 1 * day,
      gti_assessment: {
        verdict: { value: 'VERDICT_MALICIOUS' },
        severity: { value: 'SEVERITY_HIGH' },
        threat_score: { value: 80 },
      },
    },
  },
  {
    value: 'http://never-seen-vteeee-7f3a9.net/payload',
    type: 'url',
    status: 'not_found',
  },
  {
    value: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
    type: 'sha256',
    status: 'success',
    attributes: {
      last_analysis_stats: {
        malicious: 63,
        suspicious: 0,
        harmless: 0,
        undetected: 5,
        timeout: 0,
        'type-unsupported': 2,
      },
      reputation: -90,
      total_votes: { harmless: 2, malicious: 380 },
      meaningful_name: 'eicar.com',
      names: ['eicar.com', 'eicar.com.txt', 'eicar_test_file'],
      type_description: 'EICAR virus test files',
      type_tag: 'text',
      size: 68,
      md5: '44d88612fea8a8f36de82e1278abb02f',
      sha1: '3395856ce81f2b7382dee72602f798b642f14140',
      sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
      popular_threat_classification: {
        suggested_threat_label: 'virus.eicar/test',
        popular_threat_category: [{ value: 'virus' }],
        popular_threat_name: [{ value: 'eicar' }],
      },
      tags: ['eicar', 'via-tor'],
      last_analysis_date: now - 6 * day,
      gti_assessment: {
        verdict: { value: 'VERDICT_MALICIOUS' },
        severity: { value: 'SEVERITY_LOW' },
        threat_score: { value: 30 },
      },
    },
  },
  {
    value: '44d88612fea8a8f36de82e1278abb02f',
    type: 'md5',
    status: 'success',
    attributes: {
      last_analysis_stats: { malicious: 63, suspicious: 0, harmless: 0, undetected: 5, timeout: 0 },
      reputation: -90,
      meaningful_name: 'eicar.com',
      type_description: 'EICAR virus test files',
      size: 68,
      md5: '44d88612fea8a8f36de82e1278abb02f',
      sha1: '3395856ce81f2b7382dee72602f798b642f14140',
      sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
      popular_threat_classification: {
        suggested_threat_label: 'virus.eicar/test',
        popular_threat_category: [{ value: 'virus' }],
      },
      tags: ['eicar'],
      last_analysis_date: now - 6 * day,
    },
  },
  {
    value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    type: 'sha256',
    status: 'success',
    attributes: {
      last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 70, timeout: 0 },
      reputation: 0,
      meaningful_name: 'empty',
      type_description: 'empty file',
      size: 0,
      tags: [],
      last_analysis_date: now - 30 * day,
    },
  },
  {
    value: 'aaaabbbbccccddddeeeeffff00001111aaaabbbbccccddddeeeeffff00001111',
    type: 'sha256',
    status: 'not_found',
  },
];

export const FIXTURE_MAP: Map<string, Fixture> = new Map(
  FIXTURES.map((f) => [f.value.toLowerCase(), f]),
);

/** A messy, mostly-defanged sample so first-time users can hit "Parse" immediately. */
export const DEMO_INPUT = `# Paste IPs / domains / URLs / hashes — defanged is fine. One per line or CSV.
1[.]1[.]1[.]1
185.220.101.1
2001:4860:4860::8888
google[.]com, 2024-05-01, search
hxxps://www[.]google[.]com/
phishy-malware-example[.]com
hxxp://phishy-malware-example[.]com/login.php
never-scanned-vteeee-7f3a9[.]com
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
44d88612fea8a8f36de82e1278abb02f
192.168.1.10`;
