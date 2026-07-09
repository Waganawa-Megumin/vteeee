import { describe, it, expect } from 'vitest';
import { fallbackSummary, type CampaignDigest } from '../campaignSummary';

const base: CampaignDigest = {
  name: 'APT-Test',
  iocCount: 5,
  withIntel: 4,
  malicious: 2,
  suspicious: 1,
  highAbuse: 1,
  distinctCves: 3,
  autoCount: 5,
  byType: [
    ['ipv4', 3],
    ['domain', 2],
  ],
  topCountries: [
    ['RU', 3],
    ['CN', 2],
  ],
  topCves: [['CVE-2024-0001', 2]],
  groups: [['c2', 3]],
  recentChanges: [{ value: '1.2.3.4', changes: ['verdict→malicious', '+2 CVE'] }],
  spanDays: 10,
  totalSnapshots: 12,
};

describe('fallbackSummary', () => {
  it('folds name, counts, top countries and recent changes into one line', () => {
    const s = fallbackSummary(base);
    expect(s).toContain('APT-Test');
    expect(s).toContain('5 IOCs');
    expect(s).toContain('malicious 2');
    expect(s).toContain('RU(3)');
    expect(s).toContain('1.2.3.4');
    expect(s.split('\n')).toHaveLength(1); // single ticker line
  });

  it('handles an empty campaign without throwing', () => {
    const s = fallbackSummary({
      ...base,
      iocCount: 0,
      withIntel: 0,
      malicious: 0,
      suspicious: 0,
      highAbuse: 0,
      distinctCves: 0,
      byType: [],
      topCountries: [],
      topCves: [],
      groups: [],
      recentChanges: [],
      totalSnapshots: 0,
    });
    expect(s).toContain('APT-Test');
    expect(s).toContain('0 IOCs');
  });
});
