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

export async function putSharedCampaigns(store: Storage, data: unknown): Promise<void> {
  const next = JSON.stringify(data && typeof data === 'object' ? data : {});
  // Skip the KV WRITE when unchanged (writes are the scarce free-tier quota; reads are cheap).
  if ((await store.get(KEY)) === next) return;
  await store.put(KEY, next);
}
