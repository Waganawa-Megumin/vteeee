import { describe, it, expect } from 'vitest';
import { putSharedCampaigns, getSharedCampaigns } from '../campaignStore';
import { putSharedMonitorProjects, getSharedMonitorProjects } from '../monitorProjectStore';
import type { Storage } from '../types';

function memStore(): Storage {
  const m = new Map<string, string>();
  return { get: async (k) => m.get(k) ?? null, put: async (k, v) => void m.set(k, v) };
}

describe('shared-store PUT sanitize (persistent UI-DoS guard)', () => {
  it('campaigns: coerces name-less entries + drops garbage, keeps valid', async () => {
    const store = memStore();
    await putSharedCampaigns(store, {
      c1: { id: 'c1', iocs: {} }, // no name
      c2: 'garbage', // dropped
      c3: { id: 'c3', name: 'Real', iocs: {} }, // valid
      c4: null, // dropped
    });
    const back = (await getSharedCampaigns(store)) as Record<string, { name?: string }>;
    expect(back.c1?.name).toMatch(/^\(unnamed/);
    expect(back.c2).toBeUndefined();
    expect(back.c3?.name).toBe('Real');
    expect(back.c4).toBeUndefined();
  });

  it('monitor-projects: same coercion/drop', async () => {
    const store = memStore();
    await putSharedMonitorProjects(store, { p1: { id: 'p1' }, p2: { id: 'p2', name: 'PJ' }, p3: 7 });
    const back = (await getSharedMonitorProjects(store)) as Record<string, { name?: string }>;
    expect(back.p1?.name).toMatch(/^\(unnamed/);
    expect(back.p2?.name).toBe('PJ');
    expect(back.p3).toBeUndefined();
  });

  it('non-object payload becomes an empty object (no crash)', async () => {
    const store = memStore();
    await putSharedCampaigns(store, [1, 2, 3]);
    expect(await getSharedCampaigns(store)).toEqual({});
  });
});
