import type { Storage } from './types';

// Shared IP-Mon PROJECTS (PJ) registry: keyed by project id → { id, name, createdAt, updatedAt }. Lives
// as one JSON object blob in the proxy KV/file store so the whole team sees the same project names
// (including empty ones registered up front). Each monitored IP carries its project id in the monitors
// blob; this registry just names/orders the projects. Shape is opaque here — the web app owns it and
// does the non-destructive read-merge-write (union by id, newest updatedAt wins) on PUT.
const KEY = 'monitor-projects';

export async function getSharedMonitorProjects(store: Storage): Promise<unknown> {
  const raw = await store.get(KEY);
  if (!raw) return {};
  try {
    const v = JSON.parse(raw);
    return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
  } catch {
    return {};
  }
}

export async function putSharedMonitorProjects(store: Storage, data: unknown): Promise<void> {
  await store.put(KEY, JSON.stringify(data && typeof data === 'object' && !Array.isArray(data) ? data : {}));
}
