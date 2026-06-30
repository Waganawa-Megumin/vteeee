import { describe, it, expect } from 'vitest';
import { normalizeVt, deriveVerdict } from '../vt-normalize';

describe('deriveVerdict', () => {
  it('prefers GTI verdict when present', () => {
    expect(
      deriveVerdict({ malicious: 0, suspicious: 0, harmless: 80, undetected: 0, timeout: 0, total: 80 }, {
        verdict: 'VERDICT_MALICIOUS',
        severity: 'SEVERITY_HIGH',
        threatScore: 90,
      }),
    ).toBe('malicious');
  });

  it('derives from stats without GTI', () => {
    expect(
      deriveVerdict({ malicious: 5, suspicious: 1, harmless: 60, undetected: 4, timeout: 0, total: 70 }),
    ).toBe('malicious');
    expect(
      deriveVerdict({ malicious: 0, suspicious: 0, harmless: 70, undetected: 4, timeout: 0, total: 74 }),
    ).toBe('harmless');
  });

  it('returns unknown for no stats', () => {
    expect(deriveVerdict(null)).toBe('unknown');
  });
});

describe('normalizeVt', () => {
  it('normalizes a malicious IP object with GTI', () => {
    const r = normalizeVt({
      input: '185.220.101.1',
      value: '185.220.101.1',
      type: 'ipv4',
      status: 'success',
      links: { gui: 'https://www.virustotal.com/gui/ip-address/185.220.101.1' },
      data: {
        attributes: {
          last_analysis_stats: { malicious: 12, suspicious: 1, harmless: 50, undetected: 7, timeout: 0 },
          reputation: -40,
          total_votes: { harmless: 0, malicious: 9 },
          country: 'DE',
          asn: 12345,
          as_owner: 'Example AS',
          tags: ['tor'],
          gti_assessment: {
            verdict: { value: 'VERDICT_MALICIOUS' },
            severity: { value: 'SEVERITY_HIGH' },
            threat_score: { value: 88 },
          },
        },
      },
    });
    expect(r.verdict).toBe('malicious');
    expect(r.detection).toMatchObject({ malicious: 12, total: 70 });
    expect(r.reputation).toBe(-40);
    expect(r.ip).toMatchObject({ country: 'DE', asn: 12345, asOwner: 'Example AS' });
    expect(r.gti).toMatchObject({ verdict: 'VERDICT_MALICIOUS', severity: 'SEVERITY_HIGH', threatScore: 88 });
    // VT has no first/last submission for IPs.
    expect(r.firstSeen).toBeNull();
    expect(r.lastSeen).toBeNull();
    expect(r.timesSubmitted).toBeNull();
  });

  it('maps first/last seen + times submitted for files and URLs', () => {
    const r = normalizeVt({
      input: 'http://x/',
      value: 'http://x/',
      type: 'url',
      status: 'success',
      links: { gui: 'x' },
      data: {
        attributes: {
          first_submission_date: 1577836800, // 2020-01-01T00:00:00Z
          last_submission_date: 1717200000, // 2024-06-01T00:00:00Z
          times_submitted: 42,
        },
      },
    });
    expect(r.firstSeen).toBe(new Date(1577836800 * 1000).toISOString());
    expect(r.lastSeen).toBe(new Date(1717200000 * 1000).toISOString());
    expect(r.timesSubmitted).toBe(42);
  });

  it('handles a not_found result', () => {
    const r = normalizeVt({
      input: 'never-seen.example',
      value: 'never-seen.example',
      type: 'domain',
      status: 'not_found',
      links: { gui: 'https://www.virustotal.com/gui/domain/never-seen.example' },
    });
    expect(r.status).toBe('not_found');
    expect(r.verdict).toBe('unknown');
    expect(r.detection).toBeNull();
  });

  it('maps file popular_threat_classification', () => {
    const r = normalizeVt({
      input: 'eicar',
      value: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
      type: 'sha256',
      status: 'success',
      links: { gui: 'x' },
      data: {
        attributes: {
          last_analysis_stats: { malicious: 63, suspicious: 0, harmless: 0, undetected: 5, timeout: 0 },
          meaningful_name: 'eicar.com',
          type_description: 'EICAR virus test files',
          popular_threat_classification: {
            suggested_threat_label: 'virus.eicar/test',
            popular_threat_category: [{ value: 'virus' }],
          },
        },
      },
    });
    expect(r.verdict).toBe('malicious');
    expect(r.file).toMatchObject({ threatLabel: 'virus.eicar/test', threatCategories: ['virus'] });
  });
});
