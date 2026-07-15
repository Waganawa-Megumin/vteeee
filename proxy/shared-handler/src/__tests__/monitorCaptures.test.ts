import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock urlscan network calls + make sleep instant so the bounded poll loop runs synchronously in tests.
const submitMock = vi.fn();
const resultMock = vi.fn();
vi.mock('../urlscanFetch', () => ({
  urlscanSubmit: (...a: unknown[]) => submitMock(...a),
  urlscanResult: (...a: unknown[]) => resultMock(...a),
}));
vi.mock('../util', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../util')>();
  return { ...actual, sleep: () => Promise.resolve() };
});

import { runScheduledCaptures } from '../monitorAutoEnrich';
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

const baseEnv = {
  urlscanApiKey: 'x',
  urlscanDailyCap: 0,
  allowedOrigins: ['*'],
  defaultRpm: 4,
  maxRpm: 1000,
  maxBatch: 1000,
} as unknown as ProxyEnv;
const DAY = 86_400_000;
const HOUR = 3_600_000;

describe('server-side scheduled auto 魚拓 (runScheduledCaptures)', () => {
  beforeEach(() => {
    submitMock.mockReset();
    resultMock.mockReset();
  });

  it('captures a stale/missing auto IP and stores a slimmed by:auto entry', async () => {
    const now = Date.now();
    const store = memStore({
      monitors: JSON.stringify({ '1.1.1.1': { ip: '1.1.1.1', autoEnrich: true, addedAt: now - 5 * DAY } }),
    });
    submitMock.mockResolvedValue({ uuid: 'u1', visibility: 'unlisted' });
    resultMock.mockResolvedValue({ uuid: 'u1', url: 'https://1.1.1.1', malicious: false, raw: { heavy: true } });

    const r = await runScheduledCaptures(store, baseEnv);

    expect(r).toEqual({ due: 1, captured: 1, pending: 0 });
    expect(submitMock).toHaveBeenCalledWith('https://1.1.1.1', baseEnv);
    const caps = JSON.parse(store.data['captures']) as Record<string, { uuid: string; by?: string; result: { raw?: unknown } }[]>;
    expect(caps['https://1.1.1.1']).toHaveLength(1);
    expect(caps['https://1.1.1.1'][0].uuid).toBe('u1');
    expect(caps['https://1.1.1.1'][0].by).toBe('auto');
    expect(caps['https://1.1.1.1'][0].result.raw).toBeUndefined(); // slimmed before persisting
  });

  it('skips a target captured within the ~20h window (no submit, no write)', async () => {
    const now = Date.now();
    const store = memStore({
      monitors: JSON.stringify({ '1.1.1.1': { ip: '1.1.1.1', autoEnrich: true } }),
      captures: JSON.stringify({ 'https://1.1.1.1': [{ uuid: 'old', at: now - HOUR, by: 'auto', result: {} }] }),
    });

    const r = await runScheduledCaptures(store, baseEnv);

    expect(r.due).toBe(0);
    expect(r.captured).toBe(0);
    expect(submitMock).not.toHaveBeenCalled();
  });

  it('resolves CP-Mon auto IOC targets (url/domain as-is, IP → https)', async () => {
    const store = memStore({
      campaigns: JSON.stringify({
        c1: {
          iocs: {
            'http://evil.test/p': { value: 'http://evil.test/p', type: 'url', autoEnrich: true },
            'bad.example': { value: 'bad.example', type: 'domain', autoEnrich: true },
            '9.9.9.9': { value: '9.9.9.9', type: 'ipv4', autoEnrich: true },
            'skip.example': { value: 'skip.example', type: 'domain', autoEnrich: false },
          },
        },
      }),
    });
    submitMock.mockImplementation((t: string) => Promise.resolve({ uuid: `u:${t}`, visibility: 'unlisted' }));
    resultMock.mockImplementation((uuid: string) => Promise.resolve({ uuid, url: 'x' }));

    const r = await runScheduledCaptures(store, baseEnv);

    expect(r.captured).toBe(3);
    const targets = submitMock.mock.calls.map((c) => c[0]).sort();
    expect(targets).toEqual(['bad.example', 'http://evil.test/p', 'https://9.9.9.9']);
  });

  it('respects the shared daily urlscan cap (stops submitting once hit)', async () => {
    const store = memStore({
      monitors: JSON.stringify({
        '1.1.1.1': { ip: '1.1.1.1', autoEnrich: true },
        '2.2.2.2': { ip: '2.2.2.2', autoEnrich: true },
      }),
    });
    submitMock.mockImplementation((t: string) => Promise.resolve({ uuid: `u:${t}`, visibility: 'unlisted' }));
    resultMock.mockImplementation((uuid: string) => Promise.resolve({ uuid, url: 'x' }));

    const r = await runScheduledCaptures(store, { ...baseEnv, urlscanDailyCap: 1 } as ProxyEnv);

    expect(submitMock).toHaveBeenCalledTimes(1); // cap = 1 → only one submission
    expect(r.captured).toBe(1);
  });

  it('does not write when every submission stays pending (urlscan still rendering)', async () => {
    const store = memStore({
      monitors: JSON.stringify({ '1.1.1.1': { ip: '1.1.1.1', autoEnrich: true } }),
    });
    submitMock.mockResolvedValue({ uuid: 'u1', visibility: 'unlisted' });
    resultMock.mockResolvedValue({ pending: true, uuid: 'u1' });

    const r = await runScheduledCaptures(store, baseEnv);

    expect(r.captured).toBe(0);
    expect(r.pending).toBe(1);
    expect(store.data['captures']).toBeUndefined(); // nothing captured → no KV write
  });

  it('no-ops when urlscan is not configured', async () => {
    const store = memStore({ monitors: JSON.stringify({ '1.1.1.1': { ip: '1.1.1.1', autoEnrich: true } }) });
    const r = await runScheduledCaptures(store, { ...baseEnv, urlscanApiKey: undefined } as ProxyEnv);
    expect(r).toEqual({ due: 0, captured: 0, pending: 0 });
    expect(submitMock).not.toHaveBeenCalled();
  });

  it('does NOT re-submit a dead/unresolvable target on the next run (throttles failures by attempt)', async () => {
    const store = memStore({ monitors: JSON.stringify({ '1.1.1.1': { ip: '1.1.1.1', autoEnrich: true } }) });
    submitMock.mockResolvedValue({ uuid: 'u1', visibility: 'unlisted' });
    resultMock.mockResolvedValue({ uuid: 'u1', error: 'urlscan: bad request (unresolvable or blacklisted target?)' });

    const r1 = await runScheduledCaptures(store, baseEnv);
    expect(r1.captured).toBe(0); // never renders → no success history written
    expect(submitMock).toHaveBeenCalledTimes(1);
    expect(store.data['captures']).toBeUndefined();
    expect(JSON.parse(store.data['capture-attempts'])['https://1.1.1.1']).toBeGreaterThan(0); // attempt recorded

    submitMock.mockClear();
    const r2 = await runScheduledCaptures(store, baseEnv); // immediate 2nd run
    expect(r2.due).toBe(0); // attempt is fresh (<20h) → not due
    expect(submitMock).not.toHaveBeenCalled(); // ← the fix: no every-run re-魚拓 of a dead target
  });

  it('takes due targets oldest-attempt first so dead targets cannot starve live ones under the cap', async () => {
    const now = Date.now();
    const store = memStore({
      monitors: JSON.stringify({
        '1.1.1.1': { ip: '1.1.1.1', autoEnrich: true },
        '2.2.2.2': { ip: '2.2.2.2', autoEnrich: true },
      }),
      'capture-attempts': JSON.stringify({ 'https://1.1.1.1': now - 30 * HOUR, 'https://2.2.2.2': now - 25 * HOUR }),
    });
    submitMock.mockImplementation((t: string) => Promise.resolve({ uuid: `u:${t}`, visibility: 'unlisted' }));
    resultMock.mockImplementation((uuid: string) => Promise.resolve({ uuid, url: 'x' }));

    // Both are due (>20h) but the cap allows only one — the OLDER (30h) must win.
    await runScheduledCaptures(store, { ...baseEnv, urlscanDailyCap: 1 } as ProxyEnv);
    expect(submitMock).toHaveBeenCalledTimes(1);
    expect(submitMock.mock.calls[0][0]).toBe('https://1.1.1.1');
  });

  it('prunes attempt records for targets that are no longer auto-enabled', async () => {
    const now = Date.now();
    const store = memStore({
      monitors: JSON.stringify({ '2.2.2.2': { ip: '2.2.2.2', autoEnrich: true } }),
      'capture-attempts': JSON.stringify({ 'https://9.9.9.9': now - HOUR, 'https://2.2.2.2': now - HOUR }),
    });

    await runScheduledCaptures(store, baseEnv);

    const attempts = JSON.parse(store.data['capture-attempts']) as Record<string, number>;
    expect(attempts['https://9.9.9.9']).toBeUndefined(); // no longer a target → pruned
    expect(attempts['https://2.2.2.2']).toBeDefined(); // still a target → kept
    expect(submitMock).not.toHaveBeenCalled(); // 2.2.2.2 attempted 1h ago → not due
  });
});
