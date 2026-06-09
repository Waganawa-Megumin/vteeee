import { describe, it, expect } from 'vitest';
import { consumeDailyQuota } from '../quota';
import type { Storage } from '../types';

function memStore(): Storage {
  const m = new Map<string, string>();
  return {
    get: async (k) => m.get(k) ?? null,
    put: async (k, v) => {
      m.set(k, v);
    },
  };
}

describe('consumeDailyQuota', () => {
  it('reserves up to the cap, then rejects', async () => {
    const s = memStore();
    expect(await consumeDailyQuota(s, 'vt', 5, 3)).toBe(true); // 3/5
    expect(await consumeDailyQuota(s, 'vt', 5, 2)).toBe(true); // 5/5
    expect(await consumeDailyQuota(s, 'vt', 5, 1)).toBe(false); // would be 6
  });

  it('treats cap <= 0 as unlimited', async () => {
    const s = memStore();
    expect(await consumeDailyQuota(s, 'parse', 0, 9999)).toBe(true);
  });

  it('keeps separate counters per prefix', async () => {
    const s = memStore();
    expect(await consumeDailyQuota(s, 'vt', 2, 2)).toBe(true);
    expect(await consumeDailyQuota(s, 'parse', 2, 2)).toBe(true);
    expect(await consumeDailyQuota(s, 'vt', 2, 1)).toBe(false);
  });
});
