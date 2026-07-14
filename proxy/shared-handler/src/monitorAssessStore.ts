import type { Storage } from './types';

// Shared IP-MON monitoring reports: a time-series (newest first) of Claude-written monitoring digests
// for the team's Shodan Monitor watchlist. Lives as one JSON array blob in the proxy KV/file store so
// every analyst on the same proxy sees the same report history (continuous monitoring — the changes over
// time are the point). Shape is opaque here — the web app owns it and does the non-destructive
// read-merge-write (union by `at`) on PUT.
const KEY = 'monitor-assessments';

export async function getSharedMonitorAssessments(store: Storage): Promise<unknown> {
  const raw = await store.get(KEY);
  if (!raw) return [];
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

export async function putSharedMonitorAssessments(store: Storage, data: unknown): Promise<void> {
  await store.put(KEY, JSON.stringify(Array.isArray(data) ? data : []));
}
