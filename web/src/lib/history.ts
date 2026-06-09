import type { ExtractStats, NormalizedResult } from '@vteeee/shared';

const KEY = 'vteeee.history';
const MAX_ENTRIES = 50;
const SIZE_BUDGET = 3_000_000; // ~3MB of JSON in localStorage

export interface HistoryEntry {
  id: string;
  createdAt: number; // epoch ms
  mode: 'demo' | 'live';
  input: string;
  stats: ExtractStats;
  results: NormalizedResult[]; // stored without the heavy `raw` blob
}

function read(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw) as HistoryEntry[];
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

function write(entries: HistoryEntry[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(entries));
  } catch {
    // Quota exceeded — drop oldest entries until it fits.
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

function stripRaw(r: NormalizedResult): NormalizedResult {
  if (r.raw === undefined) return r;
  const { raw: _omit, ...rest } = r;
  void _omit;
  return rest;
}

/** Pure: filter by retention window, sort newest-first, cap count + size. */
export function prune(entries: HistoryEntry[], retentionDays: number, now = Date.now()): HistoryEntry[] {
  const cutoff = now - retentionDays * 86_400_000;
  let e = entries
    .filter((x) => x.createdAt >= cutoff)
    .sort((a, b) => b.createdAt - a.createdAt)
    .slice(0, MAX_ENTRIES);
  while (e.length > 1 && JSON.stringify(e).length > SIZE_BUDGET) e = e.slice(0, e.length - 1);
  return e;
}

export function loadHistory(retentionDays: number): HistoryEntry[] {
  const pruned = prune(read(), retentionDays);
  write(pruned); // purge expired on read
  return pruned;
}

export function addHistory(
  entry: Omit<HistoryEntry, 'id' | 'createdAt' | 'results'> & { results: NormalizedResult[] },
  retentionDays: number,
): HistoryEntry[] {
  if (retentionDays <= 0) return read(); // history disabled
  const full: HistoryEntry = {
    id: Math.random().toString(36).slice(2) + Date.now().toString(36),
    createdAt: Date.now(),
    mode: entry.mode,
    input: entry.input,
    stats: entry.stats,
    results: entry.results.map(stripRaw),
  };
  const next = prune([full, ...read()], retentionDays);
  write(next);
  return next;
}

export function deleteHistory(id: string, retentionDays: number): HistoryEntry[] {
  const next = prune(
    read().filter((x) => x.id !== id),
    retentionDays,
  );
  write(next);
  return next;
}

export function clearHistory(): void {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}
