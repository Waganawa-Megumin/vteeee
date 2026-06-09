import type { Storage } from './types';

/**
 * Best-effort daily quota guard backed by the store (Cloudflare KV or Node file).
 * Reserves `n` units against a per-day counter; returns false if it would exceed `cap`.
 * `cap <= 0` means unlimited. Note: the store is eventually consistent, so this is a
 * cost-control guard, not a hard transactional limit.
 */
export async function consumeDailyQuota(
  store: Storage,
  prefix: string,
  cap: number,
  n: number,
): Promise<boolean> {
  if (!cap || cap <= 0) return true;
  const key = `quota:${prefix}:${new Date().toISOString().slice(0, 10)}`;
  const current = Number((await store.get(key)) ?? '0') || 0;
  if (current + n > cap) return false;
  await store.put(key, String(current + n));
  return true;
}
