import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the Claude-backed assessment functions so the batch test needs no network.
const campaignMock = vi.fn();
const monitorMock = vi.fn();
vi.mock('../campaignAssessment', () => ({ assessCampaign: (...a: unknown[]) => campaignMock(...a) }));
vi.mock('../monitorAssessment', () => ({ assessMonitors: (...a: unknown[]) => monitorMock(...a) }));

import { runScheduledAssessments } from '../scheduledAssessments';
import type { ProxyEnv, Storage } from '../types';

function memStore(initial: Record<string, string> = {}): Storage & { data: Record<string, string> } {
  const data: Record<string, string> = { ...initial };
  return {
    data,
    get: async (k: string) => (k in data ? data[k] : null),
    put: async (k: string, v: string) => {
      data[k] = v;
    },
  };
}

const env = { anthropicApiKey: 'x', scheduledAssess: true, allowedOrigins: ['*'], defaultRpm: 4, maxRpm: 1000, maxBatch: 1000 } as unknown as ProxyEnv;
const DAY = 86_400_000;
const HOUR = 3_600_000;
const now = Date.now();

const monitorsBlob = JSON.stringify({ '1.1.1.1': { ip: '1.1.1.1', addedAt: now - 5 * DAY, autoEnrich: true } });
const campaignsBlob = JSON.stringify({
  c1: { id: 'c1', name: 'C1', tlp: 'AMBER', iocs: { '2.2.2.2': { value: '2.2.2.2', type: 'ipv4' } } },
});

describe('runScheduledAssessments (daily batch)', () => {
  beforeEach(() => {
    campaignMock.mockReset();
    monitorMock.mockReset();
  });

  it('generates + appends an IP-Mon report and a per-campaign report, tagged by:auto', async () => {
    monitorMock.mockResolvedValue({ text: 'IP-MON REPORT', model: 'claude-haiku-4-5' });
    campaignMock.mockResolvedValue({ text: 'CTI REPORT', model: 'claude-haiku-4-5' });
    const store = memStore({ monitors: monitorsBlob, campaigns: campaignsBlob });

    const r = await runScheduledAssessments(store, env);

    expect(r).toEqual({ ipMon: true, campaigns: 1, skipped: 0 });
    const ma = JSON.parse(store.data['monitor-assessments']) as { text: string; by?: string; at: number }[];
    expect(ma[0].text).toBe('IP-MON REPORT');
    expect(ma[0].by).toBe('auto');
    const camps = JSON.parse(store.data['campaigns']) as Record<string, { assessment?: { text: string; by?: string }; assessments?: unknown[] }>;
    expect(camps.c1.assessment?.text).toBe('CTI REPORT');
    expect(camps.c1.assessment?.by).toBe('auto');
    expect(camps.c1.assessments).toHaveLength(1);
  });

  it('skips targets whose newest report is fresh (<20h) — once per day', async () => {
    const store = memStore({
      monitors: monitorsBlob,
      'monitor-assessments': JSON.stringify([{ text: 'old', at: now - HOUR, by: 'auto' }]),
      campaigns: JSON.stringify({
        c1: { name: 'C1', iocs: { '2.2.2.2': { value: '2.2.2.2', type: 'ipv4' } }, assessments: [{ text: 'old', at: now - HOUR }] },
      }),
    });

    const r = await runScheduledAssessments(store, env);

    expect(r.ipMon).toBe(false);
    expect(r.campaigns).toBe(0);
    expect(r.skipped).toBe(1); // IP-Mon fresh → skipped
    expect(monitorMock).not.toHaveBeenCalled();
    expect(campaignMock).not.toHaveBeenCalled();
  });

  it('re-generates once the newest report is ≳20h old, preserving the timeline', async () => {
    monitorMock.mockResolvedValue({ text: 'FRESH IP-MON', model: 'm' });
    campaignMock.mockResolvedValue({ text: 'FRESH CTI', model: 'm' });
    const store = memStore({
      monitors: monitorsBlob,
      'monitor-assessments': JSON.stringify([{ text: 'yesterday', at: now - 25 * HOUR, by: 'auto' }]),
      campaigns: JSON.stringify({
        c1: { name: 'C1', tlp: 'AMBER', iocs: { '2.2.2.2': { value: '2.2.2.2', type: 'ipv4' } }, assessments: [{ text: 'yesterday', at: now - 25 * HOUR }] },
      }),
    });

    const r = await runScheduledAssessments(store, env);

    expect(r.ipMon).toBe(true);
    expect(r.campaigns).toBe(1);
    const ma = JSON.parse(store.data['monitor-assessments']) as { text: string; at: number }[];
    expect(ma).toHaveLength(2); // new + preserved
    expect(ma[0].text).toBe('FRESH IP-MON');
    const camps = JSON.parse(store.data['campaigns']) as Record<string, { assessments: { text: string }[] }>;
    expect(camps.c1.assessments).toHaveLength(2);
    expect(camps.c1.assessments[0].text).toBe('FRESH CTI');
  });

  it('does not append when the assessment errors (Claude unavailable)', async () => {
    monitorMock.mockResolvedValue({ text: '', error: 'no key' });
    campaignMock.mockResolvedValue({ text: '', error: 'Claude API error 500' });
    const store = memStore({ monitors: monitorsBlob, campaigns: campaignsBlob });

    const r = await runScheduledAssessments(store, env);

    expect(r.ipMon).toBe(false);
    expect(r.campaigns).toBe(0);
    expect(store.data['monitor-assessments']).toBeUndefined();
  });

  it('is a no-op when disabled or unconfigured', async () => {
    const store = memStore({ monitors: monitorsBlob, campaigns: campaignsBlob });
    expect(await runScheduledAssessments(store, { ...env, scheduledAssess: false } as ProxyEnv)).toEqual({ ipMon: false, campaigns: 0, skipped: 0 });
    expect(await runScheduledAssessments(store, { ...env, anthropicApiKey: undefined } as ProxyEnv)).toEqual({ ipMon: false, campaigns: 0, skipped: 0 });
    expect(monitorMock).not.toHaveBeenCalled();
    expect(campaignMock).not.toHaveBeenCalled();
  });

  it('skips empty campaigns (no IOCs)', async () => {
    monitorMock.mockResolvedValue({ text: 'IP', model: 'm' });
    campaignMock.mockResolvedValue({ text: 'CTI', model: 'm' });
    const store = memStore({ campaigns: JSON.stringify({ empty: { name: 'Empty', iocs: {} } }) });

    const r = await runScheduledAssessments(store, env);

    expect(r.campaigns).toBe(0);
    expect(campaignMock).not.toHaveBeenCalled();
  });
});
