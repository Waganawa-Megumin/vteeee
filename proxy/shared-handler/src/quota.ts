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
  try {
    const current = Number((await store.get(key)) ?? '0') || 0;
    if (current + n > cap) return false;
    await store.put(key, String(current + n));
    return true;
  } catch {
    // FAIL OPEN. This is a best-effort cost guard, not a hard limit — if the store is unavailable
    // (most notably: the Cloudflare KV *write* budget is exhausted, which makes store.put throw), the
    // feature must still work. Failing closed here is what surfaced as an HTTP 500 on the Claude
    // assessment (its parse-quota counter write threw and propagated to the worker's 500 handler).
    return true;
  }
}
