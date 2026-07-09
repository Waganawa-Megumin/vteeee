import { describe, expect, it } from 'vitest';
import type { NormalizedResult } from '@vteeee/shared';

// store.ts persists to localStorage at import time; the vitest env is `node`, so shim it first.
const _mem = new Map<string, string>();
(globalThis as unknown as { localStorage: Storage }).localStorage = {
  get length() {
    return _mem.size;
  },
  clear: () => _mem.clear(),
  getItem: (k: string) => (_mem.has(k) ? _mem.get(k)! : null),
  key: (i: number) => Array.from(_mem.keys())[i] ?? null,
  removeItem: (k: string) => void _mem.delete(k),
  setItem: (k: string, v: string) => void _mem.set(k, String(v)),
};

const { appendSnapshot, downsampleHistory } = await import('../state/store');
type Snap = { at: number; by?: string; result: NormalizedResult };

const DAY = 86_400_000;
const NOW = 1_800_000_000_000;

/** A snapshot `daysAgo` old, with `mal` malicious detections so its state-signature is distinct. */
function snap(daysAgo: number, mal = daysAgo): Snap {
  return {
    at: NOW - daysAgo * DAY,
    by: 't',
    result: {
      input: '1.1.1.1',
      value: '1.1.1.1',
      type: 'ipv4',
      status: 'success',
      verdict: 'malicious',
      detection: { malicious: mal, suspicious: 0, harmless: 0, undetected: 90 - mal, timeout: 0, total: 90 },
      reputation: 0,
      totalVotes: null,
      lastAnalysisDate: null,
      tags: [],
      links: { gui: '#' },
    } as unknown as NormalizedResult,
  };
}
const ageDays = (s: Snap) => (NOW - s.at) / DAY;

describe('enrichment history downsampling (avoids unbounded log growth)', () => {
  it('keeps recent daily detail but thins old points, staying bounded', () => {
    const all: Snap[] = [];
    for (let d = 0; d <= 6; d++) all.push(snap(d)); // last week — one per day
    for (let d = 7; d <= 13; d++) all.push(snap(d)); // week 2
    for (let d = 14; d <= 27; d++) all.push(snap(d)); // weeks 3–4
    for (let d = 28; d <= 41; d++) all.push(snap(d)); // weeks 5–6
    for (let d = 42; d <= 250; d++) all.push(snap(d)); // 200+ old points

    const out = downsampleHistory(all, NOW);

    // Hard bound regardless of how many raw points went in (>220 here).
    expect(all.length).toBeGreaterThan(220);
    expect(out.length).toBeLessThanOrEqual(40);
    // The last week keeps one point per day (daily detail).
    expect(out.filter((s) => ageDays(s) < 7).length).toBe(7);
    // The 200+ ancient points collapse to ~monthly — a handful, not hundreds.
    expect(out.filter((s) => ageDays(s) >= 42).length).toBeLessThanOrEqual(9);
    // Ascending order, unique timestamps.
    for (let i = 1; i < out.length; i++) expect(out[i].at).toBeGreaterThan(out[i - 1].at);
  });

  it('does not grow when the state is unchanged, but records real changes on new days', () => {
    const T0 = NOW - 10 * DAY;
    const h1 = appendSnapshot(undefined, { at: T0, by: 'x', result: snap(0, 3).result }, T0);
    expect(h1.length).toBe(1);
    // Same metrics a day later → same signature → no new point.
    const h2 = appendSnapshot(h1, { at: T0 + DAY, by: 'x', result: snap(0, 3).result }, T0 + DAY);
    expect(h2.length).toBe(1);
    // A real change two days later → the timeline grows.
    const h3 = appendSnapshot(h2, { at: T0 + 2 * DAY, by: 'x', result: snap(0, 9).result }, T0 + 2 * DAY);
    expect(h3.length).toBe(2);
  });
});
