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

/** Drop non-object entries and guarantee a string `name` on each project (same UI-DoS guard as campaigns:
 *  the PJ pickers sort by name, so a name-less shared entry would crash them). Coerces, never rejects. */
function sanitize(data: unknown): Record<string, unknown> {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return {};
  const out: Record<string, unknown> = {};
  for (const [id, v] of Object.entries(data as Record<string, unknown>)) {
    if (!v || typeof v !== 'object' || Array.isArray(v)) continue;
    const p = v as Record<string, unknown>;
    out[id] = { ...p, name: typeof p.name === 'string' && p.name.trim() ? p.name : `(unnamed ${id})` };
  }
  return out;
}

export async function putSharedMonitorProjects(store: Storage, data: unknown): Promise<void> {
  const next = JSON.stringify(sanitize(data));
  // Skip the KV WRITE when unchanged (writes are the scarce free-tier quota; reads are cheap).
  if ((await store.get(KEY)) === next) return;
  await store.put(KEY, next);
}
