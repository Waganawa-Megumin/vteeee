import type { HistoryRecord, HistorySummary, NormalizedResult } from '@vteeee/shared';

const KEY = 'vteeee.history';
const MAX_ENTRIES = 50;
const SIZE_BUDGET = 4_000_000; // ~4MB of JSON in localStorage

/** Common interface for local (localStorage) and shared (proxy/KV) history. */
export interface HistorySource {
  /** true when backed by the proxy/KV (shared across the team). */
  shared: boolean;
  list(): Promise<HistorySummary[]>;
  get(id: string): Promise<HistoryRecord | null>;
  update(id: string, patch: { tags?: string[]; note?: string }): Promise<void>;
  del(id: string): Promise<void>;
  clear(): Promise<void>;
}

function read(): HistoryRecord[] {
  try {
    const raw = localStorage.getItem(KEY);
    const arr = raw ? (JSON.parse(raw) as HistoryRecord[]) : [];
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

function write(entries: HistoryRecord[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(entries));
  } catch {
    let e = entries.slice();
    while (e.length > 1) {
      e = e.slice(0, e.length - 1);
      try {
        localStorage.setItem(KEY, JSON.stringify(e));
        return;
      } catch {
        /* keep dropping */
      }
    }
  }
}

function stripRaw(results: NormalizedResult[]): NormalizedResult[] {
  return results.map((r) => {
    if (r.raw === undefined) return r;
    const { raw: _o, ...rest } = r;
    void _o;
    return rest;
  });
}

export function summarizeLocal(rec: HistoryRecord): HistorySummary {
  let malicious = 0;
  let suspicious = 0;
  for (const r of rec.results) {
    if (r.verdict === 'malicious') malicious++;
    else if (r.verdict === 'suspicious') suspicious++;
  }
  return {
    id: rec.id,
    createdAt: rec.createdAt,
    mode: rec.mode,
    total: rec.results.length,
    malicious,
    suspicious,
    inputPreview: rec.input.replace(/\s+/g, ' ').trim().slice(0, 90),
    tags: rec.tags,
    note: rec.note ? rec.note.slice(0, 160) : undefined,
  };
}

/** Pure: filter by retention window, sort newest-first, cap count + size. */
export function prune(entries: HistoryRecord[], retentionDays: number, now = Date.now()): HistoryRecord[] {
  const cutoff = now - retentionDays * 86_400_000;
  let e = entries
    .filter((x) => x.createdAt >= cutoff)
    .sort((a, b) => b.createdAt - a.createdAt)
    .slice(0, MAX_ENTRIES);
  while (e.length > 1 && JSON.stringify(e).length > SIZE_BUDGET) e = e.slice(0, e.length - 1);
  return e;
}

/** Save to localStorage (raw stripped to respect the ~5MB quota). */
export function saveLocal(rec: HistoryRecord, retentionDays: number): void {
  if (retentionDays <= 0) return;
  const stored: HistoryRecord = { ...rec, results: stripRaw(rec.results) };
  write(prune([stored, ...read().filter((r) => r.id !== rec.id)], retentionDays));
}

export function localHistorySource(retentionDays: number): HistorySource {
  return {
    shared: false,
    async list() {
      const e = prune(read(), retentionDays);
      write(e); // purge expired on read
      return e.map(summarizeLocal);
    },
    async get(id) {
      return read().find((r) => r.id === id) ?? null;
    },
    async update(id, patch) {
      const e = read();
      const r = e.find((x) => x.id === id);
      if (!r) return;
      if (patch.tags) r.tags = patch.tags;
      if (patch.note !== undefined) r.note = patch.note;
      write(prune(e, retentionDays));
    },
    async del(id) {
      write(read().filter((r) => r.id !== id));
    },
    async clear() {
      try {
        localStorage.removeItem(KEY);
      } catch {
        /* ignore */
      }
    },
  };
}
