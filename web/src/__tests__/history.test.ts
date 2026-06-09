import { describe, it, expect } from 'vitest';
import type { HistoryRecord } from '@vteeee/shared';
import { prune } from '../lib/history';

const now = Date.now();
function mk(id: string, ageDays: number): HistoryRecord {
  return {
    id,
    createdAt: now - ageDays * 86_400_000,
    mode: 'demo',
    input: 'x',
    stats: { total: 1, unique: 1, duplicates: 0, unknown: 0, private: 0, enrichable: 1 },
    results: [],
  };
}

describe('history prune', () => {
  it('drops entries older than the retention window', () => {
    const out = prune([mk('a', 1), mk('b', 40), mk('c', 10)], 30, now);
    expect(out.map((x) => x.id)).toEqual(['a', 'c']); // 40d-old removed
  });

  it('sorts newest first', () => {
    const out = prune([mk('old', 5), mk('new', 1)], 30, now);
    expect(out[0].id).toBe('new');
  });

  it('keeps everything when retention is large', () => {
    expect(prune([mk('a', 100), mk('b', 200)], 3650, now)).toHaveLength(2);
  });
});
