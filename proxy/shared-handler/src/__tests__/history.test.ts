import { describe, it, expect } from 'vitest';
import type { HistoryRecord, NormalizedResult, Verdict } from '@vteeee/shared';
import { historyRoute, kvHistoryBackend, summarize, type KVLike } from '../history';

function mockKV(): KVLike {
  const m = new Map<string, { value: string; metadata?: unknown }>();
  return {
    async put(k, v, opts) {
      m.set(k, { value: v, metadata: opts?.metadata });
    },
    async get(k) {
      return m.get(k)?.value ?? null;
    },
    async list(opts) {
      const prefix = opts?.prefix ?? '';
      return {
        keys: [...m.entries()]
          .filter(([n]) => n.startsWith(prefix))
          .map(([name, e]) => ({ name, metadata: e.metadata })),
        list_complete: true,
      };
    },
    async delete(k) {
      m.delete(k);
    },
  };
}

function res(verdict: Verdict): NormalizedResult {
  return {
    input: 'x',
    value: 'v' + Math.random(),
    type: 'ipv4',
    status: 'success',
    verdict,
    detection: null,
    reputation: null,
    totalVotes: null,
    lastAnalysisDate: null,
    firstSeen: null,
    lastSeen: null,
    timesSubmitted: null,
    tags: [],
    links: { gui: '' },
  };
}
function rec(id: string, verdicts: Verdict[]): HistoryRecord {
  return {
    id,
    createdAt: Date.now(),
    mode: 'live',
    input: '1.1.1.1',
    stats: { total: verdicts.length, unique: verdicts.length, duplicates: 0, unknown: 0, private: 0, enrichable: verdicts.length },
    results: verdicts.map(res),
  };
}

describe('summarize', () => {
  it('counts verdicts', () => {
    const s = summarize(rec('a', ['malicious', 'malicious', 'harmless', 'suspicious']));
    expect(s.malicious).toBe(2);
    expect(s.suspicious).toBe(1);
    expect(s.total).toBe(4);
  });
});

describe('kvHistoryBackend', () => {
  it('supports save/list/get/update/del/clear', async () => {
    const b = kvHistoryBackend(mockKV());
    await b.save(rec('a', ['malicious']), 3600);
    await b.save(rec('b', ['harmless']), 3600);
    expect((await b.list(10)).length).toBe(2);
    expect((await b.get('a'))?.id).toBe('a');
    await b.update('a', { tags: ['c2'], note: 'n' }, 30);
    expect((await b.get('a'))?.tags).toEqual(['c2']);
    await b.del('b');
    expect(await b.get('b')).toBeNull();
    await b.clear();
    expect((await b.list(10)).length).toBe(0);
  });
});

describe('historyRoute', () => {
  it('POST then GET list', async () => {
    const b = kvHistoryBackend(mockKV());
    const post = await historyRoute('POST', null, { results: [], input: 'x', mode: 'live' }, b, {
      retentionDays: 30,
    });
    expect(post.status).toBe(200);
    const list = await historyRoute('GET', null, undefined, b, { retentionDays: 30 });
    expect((list.body as { entries: unknown[] }).entries.length).toBe(1);
  });

  it('skips POST when retention is 0', async () => {
    const b = kvHistoryBackend(mockKV());
    const r = await historyRoute('POST', null, { results: [] }, b, { retentionDays: 0 });
    expect(r.body).toEqual({ skipped: true });
  });

  it('scopes by owner; admin sees all (with IP)', async () => {
    const b = kvHistoryBackend(mockKV());
    await historyRoute('POST', null, { results: [] }, b, {
      retentionDays: 30,
      user: 'alice',
      ip: '1.2.3.4',
    });
    const bob = await historyRoute('GET', null, undefined, b, { retentionDays: 30, user: 'bob' });
    expect((bob.body as { entries: unknown[] }).entries.length).toBe(0);

    const alice = await historyRoute('GET', null, undefined, b, { retentionDays: 30, user: 'alice' });
    const aliceEntries = (alice.body as { entries: { ip?: string }[] }).entries;
    expect(aliceEntries.length).toBe(1);
    expect(aliceEntries[0].ip).toBe('1.2.3.4');

    const admin = await historyRoute('GET', null, undefined, b, {
      retentionDays: 30,
      user: 'bob',
      adminView: true,
    });
    expect((admin.body as { entries: unknown[] }).entries.length).toBe(1);
  });
});
