import { describe, it, expect } from 'vitest';
import type { CampaignDigest } from '@vteeee/shared';
import { summarizeCampaign } from '../campaignSummary';
import type { ProxyEnv } from '../types';

const digest: CampaignDigest = {
  name: 'X-Campaign',
  iocCount: 1,
  withIntel: 1,
  malicious: 1,
  suspicious: 0,
  highAbuse: 0,
  distinctCves: 0,
  autoCount: 1,
  byType: [['ipv4', 1]],
  topCountries: [['RU', 1]],
  topCves: [],
  groups: [],
  recentChanges: [],
  spanDays: 0,
  totalSnapshots: 1,
};

describe('summarizeCampaign', () => {
  it('returns the deterministic fallback (no Claude call) when no ANTHROPIC key is configured', async () => {
    const env = {} as ProxyEnv;
    const r = await summarizeCampaign(digest, env);
    expect(r.text).toContain('X-Campaign');
    expect(r.text).toContain('1 IOCs');
    expect(r.model).toBeUndefined();
  });
});
