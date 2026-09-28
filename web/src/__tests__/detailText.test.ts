import { describe, it, expect } from 'vitest';
import type { NormalizedResult } from '@vteeee/shared';
import { resultToText, type CaptureForText } from '../lib/detailText';

// Regression guard for the "screen vs PDF/Copy-text differ" report: resultToText (the single source
// for both "Copy text" and "Export PDF") must carry the same data the on-screen detail panel shows.
// Fixture mirrors the 114.156.155.90 report from the bug screenshot.
const r = {
  value: '114.156.155.90',
  type: 'ipv4',
  status: 'success',
  verdict: 'undetected',
  links: { gui: 'https://www.virustotal.com/gui/ip-address/114.156.155.90' },
  ip: { country: 'JP', asn: 4713, asOwner: 'NTT DOCOMO BUSINESS,Inc.', network: '114.144.0.0/12', rir: 'APNIC' },
  shodan: {
    found: true,
    org: 'Open Computer Network',
    isp: 'NTT Communications Corporation',
    city: 'Nagasaki',
    country: 'Japan',
    asn: 'AS4713',
    ports: [541, 10443],
    hostnames: ['p442026-ipngnfx01sinnagasak.nagasaki.ocn.ne.jp'],
    services: [
      { port: 541, product: 'Fortinet FortiGate' },
      { port: 10443, product: 'Fortinet FortiGate-60F' },
    ],
  },
  cyfirma: {
    found: true,
    riskScore: 5,
    externalThreatScore: 7,
    indicatorRiskScore: 2,
    indicatorType: 'IP ADDRESS',
    story: 'This IP address 114.156.155.90 is not malicious in nature.',
    country: 'Japan',
    organization: 'NTT DOCOMO Business, Inc.',
  },
  abuseipdb: {
    found: true,
    abuseConfidenceScore: 0,
    totalReports: 0,
    numDistinctUsers: 0,
    usageType: 'Fixed Line ISP',
    hostnames: ['p442026-ipngnfx01sinnagasak.nagasaki.ocn.ne.jp'],
    isp: 'Open Computer Network',
    domain: 'ocn.ne.jp',
    countryName: 'Japan',
    countryCode: 'JP',
  },
  threatvision: {
    found: true,
    kind: 'ip',
    riskLevel: 'low',
    riskScore: 0,
    dnsRecords: 2,
    city: 'Nagasaki',
    region: 'Nagasaki',
    country: 'Japan',
    lastUpdate: '2026-09-28T00:00:00Z',
  },
} as unknown as NormalizedResult;

describe('resultToText — parity with the on-screen detail panel', () => {
  const text = resultToText(r);

  it('Shodan includes Services (Fortinet FortiGate) and Hostnames', () => {
    expect(text).toContain('Services: 541 Fortinet FortiGate, 10443 Fortinet FortiGate-60F');
    expect(text).toContain('Hostnames: p442026-ipngnfx01sinnagasak.nagasaki.ocn.ne.jp');
  });

  it('CYFIRMA shows both org/external risk scores, indicator type and organization (not just 2/10)', () => {
    expect(text).toContain('Risk scores: risk 5/10 · ext threat 7/10');
    expect(text).toContain('Indicator risk: 2/10');
    expect(text).toContain('Indicator: IP ADDRESS');
    expect(text).toContain('Organization: NTT DOCOMO Business, Inc.');
  });

  it('ThreatVision includes Related intel and Updated', () => {
    expect(text).toContain('Related intel: 2 DNS');
    expect(text).toMatch(/Updated: .+/);
  });

  it('AbuseIPDB includes Hostnames', () => {
    // The AbuseIPDB section (after its heading) carries the hostname too.
    const abuse = text.slice(text.indexOf('## AbuseIPDB'));
    expect(abuse).toContain('Hostnames: p442026-ipngnfx01sinnagasak.nagasaki.ocn.ne.jp');
  });
});

describe('resultToText — urlscan 魚拓 capture section', () => {
  const captures: CaptureForText[] = [
    {
      target: 'https://114.156.155.90:541',
      history: [
        {
          at: Date.parse('2026-09-28T12:07:38Z'),
          by: 'admin',
          visibility: 'unlisted',
          result: {
            finalUrl: 'https://114.156.155.90:541/',
            malicious: false,
            score: 0,
            contactedDomains: ['114.156.155.90'],
            resultUrl: 'https://urlscan.io/result/abc-123/',
          },
        },
      ],
    },
  ];

  it('is absent when no captures are passed (prior behavior preserved)', () => {
    expect(resultToText(r)).not.toContain('Web capture (urlscan');
  });

  it('renders the capture target, final URL, verdict and urlscan result link when captures are passed', () => {
    const text = resultToText(r, captures);
    expect(text).toContain('## Web capture (urlscan · 魚拓)');
    expect(text).toContain('Target: https://114.156.155.90:541');
    expect(text).toContain('Final URL: https://114.156.155.90:541/');
    expect(text).toContain('Verdict: no verdict · score 0');
    expect(text).toContain('Contacted domains: 114.156.155.90');
    expect(text).toContain('Result: https://urlscan.io/result/abc-123/');
  });
});
