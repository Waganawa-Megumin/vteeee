import type { Storage } from './types';

// Shared urlscan 魚拓 history: per target (URL / domain / https://<ip>) a list of completed captures
// (uuid + timestamp + who + the urlscan result). Lives as one JSON blob in the proxy KV/file store so
// every analyst on the same proxy sees the same 魚拓 timeline instead of re-capturing. Shape is opaque
// here — the web app owns it and does the non-destructive read-merge-write on PUT.
const KEY = 'captures';

export async function getSharedCaptures(store: Storage): Promise<unknown> {
  const raw = await store.get(KEY);
  if (!raw) return {};
  try {
    const v = JSON.parse(raw);
    return v && typeof v === 'object' ? v : {};
  } catch {
    return {};
  }
}

export async function putSharedCaptures(store: Storage, data: unknown): Promise<void> {
  await store.put(KEY, JSON.stringify(data && typeof data === 'object' ? data : {}));
}
