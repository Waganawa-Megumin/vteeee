import { describe, it, expect, vi } from 'vitest';

// Mock the enrich pipeline so the scheduler test needs no network: yield one synthetic result per IP.
vi.mock('../enrich', () => ({
  runEnrich: async function* (req: { indicators: { value: string }[] }) {
    const ip = req.indicators[0].value;
    yield {
      event: 'result',
      result: {
        input: ip,
        value: ip,
        type: 'ipv4',
        status: 'success',
        verdict: ip === '1.1.1.1' ? 'malicious' : 'harmless',
        detection: { malicious: ip === '1.1.1.1' ? 9 : 0, suspicious: 0, harmless: 1, undetected: 80, timeout: 0, total: 90 },
        reputation: 0,
        totalVotes: null,
        lastAnalysisDate: null,
        tags: [],
        links: { gui: '#' },
      },
    };
    yield { event: 'done', done: 1, total: 1, elapsedMs: 1 };
  },
}));

import { runScheduledAutoEnrich } from '../monitorAutoEnrich';
import type { ProxyEnv, Storage } from '../types';

function memStore(initial: unknown): Storage & { snapshot: () => Record<string, unknown> } {
  let blob = JSON.stringify(initial);
  return {
    get: async (k: string) => (k === 'monitors' ? blob : null),
    put: async (k: string, v: string) => {
      if (k === 'monitors') blob = v;
    },
    snapshot: () => JSON.parse(blob) as Record<string, unknown>,
  };
}

const env = { xTool: 'vteeee', allowedOrigins: ['*'], defaultRpm: 4, maxRpm: 1000, maxBatch: 1000 } as unknown as ProxyEnv;
const DAY = 86_400_000;
const HOUR = 3_600_000;

describe('server-side scheduled auto re-enrich', () => {
  it('enriches only due, opted-in IPs and appends a snapshot; leaves others untouched', async () => {
    const now = Date.now();
    const store = memStore({
      '1.1.1.1': { ip: '1.1.1.1', addedAt: now - 5 * DAY, autoEnrich: true, lastEnrichAt: now - 2 * DAY }, // due
      '2.2.2.2': { ip: '2.2.2.2', addedAt: now - 5 * DAY, autoEnrich: true, lastEnrichAt: now - 1 * HOUR }, // enriched 1h ago → not due
      '3.3.3.3': { ip: '3.3.3.3', addedAt: now - 5 * DAY, autoEnrich: false }, // not opted in
    });

    const r = await runScheduledAutoEnrich(store, env);

    expect(r.due).toBe(1);
    expect(r.enriched).toBe(1);
    const saved = store.snapshot() as Record<string, { history?: { by?: string }[]; lastEnrichAt?: number; result?: unknown }>;
    // The due IP got a snapshot recorded by the server ("auto") + a refreshed lastEnrichAt + a result.
    expect(saved['1.1.1.1'].history?.length).toBe(1);
    expect(saved['1.1.1.1'].history?.[0].by).toBe('auto');
    expect(saved['1.1.1.1'].lastEnrichAt).toBeGreaterThan(now - DAY);
    expect(saved['1.1.1.1'].result).toBeTruthy();
    // The recently-enriched and the not-opted-in entries are left alone.
    expect(saved['2.2.2.2'].history).toBeUndefined();
    expect(saved['3.3.3.3'].history).toBeUndefined();
  });

  it('does nothing when no IP is due', async () => {
    const now = Date.now();
    const store = memStore({
      'x': { ip: '9.9.9.9', addedAt: now - 5 * DAY, autoEnrich: true, lastEnrichAt: now - 1 * HOUR },
    });
    const r = await runScheduledAutoEnrich(store, env);
    expect(r).toEqual({ due: 0, enriched: 0, changed: 0 });
  });
});
