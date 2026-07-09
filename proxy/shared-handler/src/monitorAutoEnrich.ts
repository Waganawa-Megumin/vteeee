import type { EnrichableType, EnrichRequest, EnrichSnapshot, NormalizedResult } from '@vteeee/shared';
import { appendSnapshot } from '@vteeee/shared';
import { runEnrich } from './enrich';
import { getSharedMonitors, putSharedMonitors } from './monitorStore';
import type { ProxyEnv, Storage } from './types';

/** Loose view of the web app's MonitorEntry — the cron only touches the fields it needs; the shape is
 *  owned by the web app (see web/src/state/store.ts). */
interface WatchEntry {
  ip: string;
  addedAt?: number;
  updatedAt?: number;
  lastEnrichAt?: number;
  autoEnrich?: boolean;
  result?: NormalizedResult;
  history?: EnrichSnapshot[];
}

const HOUR = 3_600_000;
// Enrich an opted-in IP only if it hasn't been enriched in ~20h, so a once-a-day cron guarantees the
// user's "毎日かならず1回" without double-enriching when the client-side scheduler already ran.
const DUE_MS = 20 * HOUR;
// Cap per run so a large watchlist + the provider fan-out can't blow the scheduled-worker time budget;
// the oldest-enriched are done first, so over successive days everything is covered.
const MAX_PER_RUN = 40;

/**
 * Server-side auto re-enrichment. Reads the shared watchlist, re-enriches every IP opted into
 * `autoEnrich` that is due, appends a point-in-time snapshot to its timeline (same downsampling as the
 * web app, via the shared helper), and writes the blob back so every client picks it up on next sync.
 * Idempotent-ish: `lastEnrichAt` gates re-runs; unchanged results don't grow the timeline.
 */
export async function runScheduledAutoEnrich(
  store: Storage,
  env: ProxyEnv,
): Promise<{ due: number; enriched: number; changed: number }> {
  const blob = (await getSharedMonitors(store)) as Record<string, WatchEntry>;
  if (!blob || typeof blob !== 'object') return { due: 0, enriched: 0, changed: 0 };
  const now = Date.now();
  const due = Object.values(blob)
    .filter(
      (e): e is WatchEntry =>
        !!e && typeof e.ip === 'string' && !!e.autoEnrich && now - (e.lastEnrichAt ?? e.addedAt ?? 0) >= DUE_MS,
    )
    .sort((a, b) => (a.lastEnrichAt ?? a.addedAt ?? 0) - (b.lastEnrichAt ?? b.addedAt ?? 0));

  let enriched = 0;
  let changed = 0;
  for (const e of due.slice(0, MAX_PER_RUN)) {
    const type: EnrichableType = e.ip.includes(':') ? 'ipv6' : 'ipv4';
    const req: EnrichRequest = { indicators: [{ value: e.ip, type, input: e.ip }], options: { includeRaw: false } };
    let result: NormalizedResult | undefined;
    try {
      for await (const ev of runEnrich(req, env)) {
        if (ev.event === 'result') result = ev.result;
      }
    } catch {
      continue; // provider/quota error — leave the previous snapshot, try again next run
    }
    if (!result || result.status !== 'success') continue;
    enriched++;
    const before = e.history?.length ?? 0;
    e.history = appendSnapshot(e.history, { at: now, by: 'auto', result }, now);
    if ((e.history?.length ?? 0) !== before) changed++;
    e.result = result;
    e.lastEnrichAt = now;
    e.updatedAt = now;
  }
  if (enriched) await putSharedMonitors(store, blob);
  return { due: due.length, enriched, changed };
}
