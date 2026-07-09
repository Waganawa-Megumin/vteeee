import type { EnrichableType, EnrichRequest, EnrichSnapshot, NormalizedResult } from '@vteeee/shared';
import { appendSnapshot } from '@vteeee/shared';
import { runEnrich } from './enrich';
import { getSharedMonitors, putSharedMonitors } from './monitorStore';
import { getSharedCampaigns, putSharedCampaigns } from './campaignStore';
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

/** Loose view of the web app's CampaignIoc / Campaign — the cron only touches what it needs. */
interface CampaignIocLike {
  value: string;
  type: EnrichableType;
  addedAt?: number;
  updatedAt?: number;
  lastEnrichAt?: number;
  autoEnrich?: boolean;
  result?: NormalizedResult;
  history?: EnrichSnapshot[];
}
interface CampaignLike {
  updatedAt?: number;
  iocs?: Record<string, CampaignIocLike>;
}

/** Same as the watchlist auto-enrich, but for CP-Mon campaign IOCs (any type). Re-enriches every
 *  opted-in, due IOC across all campaigns, appends a snapshot, and writes the campaigns blob back. */
export async function runScheduledCampaignEnrich(
  store: Storage,
  env: ProxyEnv,
): Promise<{ due: number; enriched: number; changed: number }> {
  const blob = (await getSharedCampaigns(store)) as Record<string, CampaignLike>;
  if (!blob || typeof blob !== 'object') return { due: 0, enriched: 0, changed: 0 };
  const now = Date.now();
  const dueList: { c: CampaignLike; ioc: CampaignIocLike }[] = [];
  for (const c of Object.values(blob)) {
    if (!c?.iocs) continue;
    for (const ioc of Object.values(c.iocs)) {
      if (ioc?.autoEnrich && typeof ioc.value === 'string' && now - (ioc.lastEnrichAt ?? ioc.addedAt ?? 0) >= DUE_MS)
        dueList.push({ c, ioc });
    }
  }
  dueList.sort((a, b) => (a.ioc.lastEnrichAt ?? a.ioc.addedAt ?? 0) - (b.ioc.lastEnrichAt ?? b.ioc.addedAt ?? 0));

  let enriched = 0;
  let changed = 0;
  for (const { c, ioc } of dueList.slice(0, MAX_PER_RUN)) {
    const req: EnrichRequest = {
      indicators: [{ value: ioc.value, type: ioc.type, input: ioc.value }],
      options: { includeRaw: false },
    };
    let result: NormalizedResult | undefined;
    try {
      for await (const ev of runEnrich(req, env)) {
        if (ev.event === 'result') result = ev.result;
      }
    } catch {
      continue;
    }
    if (!result || result.status !== 'success') continue;
    enriched++;
    const before = ioc.history?.length ?? 0;
    ioc.history = appendSnapshot(ioc.history, { at: now, by: 'auto', result }, now);
    if ((ioc.history?.length ?? 0) !== before) changed++;
    ioc.result = result;
    ioc.lastEnrichAt = now;
    ioc.updatedAt = now;
    c.updatedAt = now;
  }
  if (enriched) await putSharedCampaigns(store, blob);
  return { due: dueList.length, enriched, changed };
}

/** Run both the IP-Mon watchlist and the CP-Mon campaign auto-enrich in one pass (cron entry point). */
export async function runAllScheduledEnrich(
  store: Storage,
  env: ProxyEnv,
): Promise<{ monitors: { due: number; enriched: number; changed: number }; campaigns: { due: number; enriched: number; changed: number } }> {
  const monitors = await runScheduledAutoEnrich(store, env);
  const campaigns = await runScheduledCampaignEnrich(store, env);
  return { monitors, campaigns };
}
