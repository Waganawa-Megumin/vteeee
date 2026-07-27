import type { Storage } from './types';

// The shared CP-Mon campaigns (attack-campaign-organised IOC watchlists + their enrichment timelines)
// live as one JSON blob in the proxy's KV/file store, so every analyst on the same proxy sees the same
// campaigns and intel instead of re-enriching. Shape is opaque here — the web app owns it.
const KEY = 'campaigns';

export async function getSharedCampaigns(store: Storage): Promise<unknown> {
  const raw = await store.get(KEY);
  if (!raw) return {};
  try {
    const v = JSON.parse(raw);
    return v && typeof v === 'object' ? v : {};
  } catch {
    return {};
  }
}

/** Drop non-object entries and guarantee a string `name` on each campaign, so a poisoned PUT can't store
 *  a name-less/typeless entry that crashes every teammate's UI on next sync (name-sort → TypeError).
 *  Coerces rather than rejects the whole payload, so a legit write never fails. */
function sanitize(data: unknown): Record<string, unknown> {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return {};
  const out: Record<string, unknown> = {};
  for (const [id, v] of Object.entries(data as Record<string, unknown>)) {
    if (!v || typeof v !== 'object' || Array.isArray(v)) continue;
    const c = v as Record<string, unknown>;
    out[id] = { ...c, name: typeof c.name === 'string' && c.name.trim() ? c.name : `(unnamed ${id})` };
  }
  return out;
}

export async function putSharedCampaigns(store: Storage, data: unknown): Promise<void> {
  const next = JSON.stringify(sanitize(data));
  // Skip the KV WRITE when unchanged (writes are the scarce free-tier quota; reads are cheap).
  if ((await store.get(KEY)) === next) return;
  await store.put(KEY, next);
}
