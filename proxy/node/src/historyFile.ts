import fs from 'node:fs';
import path from 'node:path';
import type { HistoryRecord } from '@vteeee/shared';
import { summarize, type HistoryBackend } from '@vteeee/proxy-core';

interface Stored extends HistoryRecord {
  expiresAt: number;
}

// Bound the file so it can't grow without limit — the whole store is read+written synchronously on
// every op (single Node thread), so an unbounded file would block the event loop (incl. /health,
// /api/enrich) for time proportional to its size. Newest records win; oversized results are truncated.
const MAX_RECORDS = 5000;
const MAX_RESULTS_PER_RECORD = 2000;

/** Simple JSON-file history backend for the Node proxy (keeps full results, incl. raw). */
export function fileHistoryBackend(dir: string): HistoryBackend {
  const file = path.join(dir, 'history.json');

  const read = (): Stored[] => {
    try {
      const rows = JSON.parse(fs.readFileSync(file, 'utf8')) as Stored[];
      return Array.isArray(rows) ? rows.filter((r) => r.expiresAt > Date.now()) : [];
    } catch {
      return [];
    }
  };
  const write = (rows: Stored[]) => fs.writeFileSync(file, JSON.stringify(rows));
  const strip = (r: Stored): HistoryRecord => {
    const { expiresAt: _e, ...rec } = r;
    void _e;
    return rec;
  };

  return {
    async save(rec, ttl) {
      const capped =
        rec.results.length > MAX_RESULTS_PER_RECORD ? { ...rec, results: rec.results.slice(0, MAX_RESULTS_PER_RECORD) } : rec;
      let rows = read().filter((r) => r.id !== rec.id);
      rows.push({ ...capped, expiresAt: Date.now() + Math.max(60, ttl) * 1000 });
      // Keep only the newest MAX_RECORDS so the file (and each sync read/write) stays bounded.
      if (rows.length > MAX_RECORDS) rows = rows.sort((a, b) => b.createdAt - a.createdAt).slice(0, MAX_RECORDS);
      write(rows);
    },
    async list(limit) {
      return read()
        .sort((a, b) => b.createdAt - a.createdAt)
        .slice(0, limit)
        .map(summarize);
    },
    async get(id) {
      const r = read().find((x) => x.id === id);
      return r ? strip(r) : null;
    },
    async update(id, patch, _retentionDays) {
      void _retentionDays;
      const rows = read();
      const r = rows.find((x) => x.id === id);
      if (!r) return null;
      if (patch.tags) r.tags = patch.tags.slice(0, 32);
      if (patch.note !== undefined) r.note = patch.note.slice(0, 4000);
      write(rows);
      return summarize(r);
    },
    async del(id) {
      write(read().filter((x) => x.id !== id));
    },
    async clear() {
      write([]);
    },
  };
}
