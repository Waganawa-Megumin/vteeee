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

const { appendSnapshot, downsampleHistory, autoEnrichInterval } = await import('../state/store');
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

describe('enrichment history = change-point timeline (never age-deletes data)', () => {
  it('keeps EVERY change point regardless of age (old points are not thrown away)', () => {
    const all: Snap[] = [];
    for (let d = 0; d <= 250; d++) all.push(snap(d)); // 251 distinct-state points across ~8 months

    const out = downsampleHistory(all, NOW);

    // Every distinct change point survives — no age-based deletion.
    expect(out.length).toBe(251);
    // Old change points (a point ~200 days old) are still present, not collapsed away.
    expect(out.some((s) => ageDays(s) >= 200)).toBe(true);
    // Ascending order, unique timestamps.
    for (let i = 1; i < out.length; i++) expect(out[i].at).toBeGreaterThan(out[i - 1].at);
  });

  it('collapses consecutive identical states but keeps real changes (lossless)', () => {
    const same = Array.from({ length: 10 }, (_, i) => snap(20 - i, 5)); // days 20..11, same state
    const changed = snap(10, 9); // day 10 — a real change
    const out = downsampleHistory([...same, changed], NOW);
    expect(out.length).toBe(2); // onset of the run + the change, not 11 points
  });

  it('caps at a high safety bound (keeps the newest points)', () => {
    const many = Array.from({ length: 500 }, (_, i) => snap(500 - i, i)); // 500 distinct states
    const out = downsampleHistory(many, NOW);
    expect(out.length).toBe(400);
    expect(ageDays(out[out.length - 1])).toBeLessThan(ageDays(out[0])); // newest kept, ascending
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

  it('auto-enrich cadence lengthens with monitoring age (daily → monthly)', () => {
    expect(autoEnrichInterval(1 * DAY)).toBe(DAY); // week 1 → daily
    expect(autoEnrichInterval(10 * DAY)).toBe(1.5 * DAY); // week 2
    expect(autoEnrichInterval(20 * DAY)).toBe(7 * DAY); // weeks 3–4 → weekly
    expect(autoEnrichInterval(35 * DAY)).toBe(14 * DAY); // weeks 5–6
    expect(autoEnrichInterval(90 * DAY)).toBe(30 * DAY); // older → monthly
    // Monotonically non-decreasing with age.
    let prev = 0;
    for (let d = 0; d <= 120; d += 3) {
      const iv = autoEnrichInterval(d * DAY);
      expect(iv).toBeGreaterThanOrEqual(prev);
      prev = iv;
    }
  });
});
