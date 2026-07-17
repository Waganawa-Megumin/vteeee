import type { EnrichableType, EnrichRequest, EnrichSnapshot, NormalizedResult, UrlscanResult } from '@vteeee/shared';
import { appendSnapshot } from '@vteeee/shared';
import { runEnrich } from './enrich';
import { getSharedMonitors, putSharedMonitors } from './monitorStore';
import { getSharedCampaigns, putSharedCampaigns } from './campaignStore';
import { getSharedCaptures, putSharedCaptures } from './captureStore';
import { urlscanSubmit, urlscanResult } from './urlscanFetch';
import { consumeDailyQuota } from './quota';
import { runScheduledAssessments } from './scheduledAssessments';
import { sleep } from './util';
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

// ---- Server-side auto 魚拓 (urlscan capture) ----------------------------------------------------
// Auto-魚拓 is a STANDING (定常) feature, so the daily cron is its single authority: it captures each
// auto target ONCE per day server-side and writes the shared blob, giving every device the identical
// timeline without N open browsers each firing their own submission (the Cloudflare KV / urlscan-quota
// burn we're removing). Intentional Re-魚拓 of a hand-picked target still runs client-side on demand.

/** One shared capture entry (mirrors the web app's WebCaptureEntry; `result` is a slimmed UrlscanResult). */
interface SharedCaptureEntry {
  uuid: string;
  at: number;
  by?: string;
  visibility?: string;
  result: UrlscanResult;
}

const CAP_DUE_MS = 20 * HOUR; // recapture a target only when its newest 魚拓 is ≳20h old (≈1回/日)
const CAP_MAX_PER_RUN = 12; // bound submissions per cron so a big watchlist can't burst urlscan/quota
const CAP_HISTORY_MAX = 20; // keep newest-N per target (matches the web app cap)
const CAP_RENDER_WAIT_MS = 15_000; // urlscan renders async (~30–60s) — wait once before polling
const CAP_POLL_ROUNDS = 6; // then poll all still-pending uuids in rounds (bounds total wall-clock)
const CAP_POLL_GAP_MS = 10_000;

/** Strip the heavy `raw` blob + clamp lists before persisting a capture result (mirrors the web app). */
function slimResult(r: UrlscanResult): UrlscanResult {
  const { raw: _raw, ...rest } = r;
  return { ...rest, contactedDomains: rest.contactedDomains?.slice(0, 40), contactedIps: rest.contactedIps?.slice(0, 40) };
}

/** Union two capture-history lists by uuid, newest first, capped (mirrors the web app merge). */
function mergeEntries(a: SharedCaptureEntry[] = [], b: SharedCaptureEntry[] = []): SharedCaptureEntry[] {
  const byUuid = new Map<string, SharedCaptureEntry>();
  for (const e of [...a, ...b]) {
    if (!e || !e.uuid) continue;
    const prev = byUuid.get(e.uuid);
    if (!prev || (e.at ?? 0) >= (prev.at ?? 0)) byUuid.set(e.uuid, e);
  }
  return [...byUuid.values()].sort((x, y) => (y.at ?? 0) - (x.at ?? 0)).slice(0, CAP_HISTORY_MAX);
}

// Server-internal auto-魚拓 ATTEMPT log: target → last attempt (ms). A dead/unresolvable target (no
// site or DNS → the 魚拓 can never succeed → no history entry is ever written) would otherwise stay
// perpetually "due" and be re-submitted on every run, wasting urlscan submissions and — under the
// per-run cap — starving live targets that never get their turn. Throttling on the last ATTEMPT (not
// just successes) backs a failure off to ~a day, exactly like a success. Not exposed via any route —
// only the cron reads/writes it.
const CAPTURE_ATTEMPTS_KEY = 'capture-attempts';
async function getCaptureAttempts(store: Storage): Promise<Record<string, number>> {
  const raw = await store.get(CAPTURE_ATTEMPTS_KEY);
  if (!raw) return {};
  try {
    const v = JSON.parse(raw);
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, number>) : {};
  } catch {
    return {};
  }
}
async function putCaptureAttempts(store: Storage, data: Record<string, number>): Promise<void> {
  const next = JSON.stringify(data);
  if ((await store.get(CAPTURE_ATTEMPTS_KEY)) === next) return; // skip the KV write when unchanged
  await store.put(CAPTURE_ATTEMPTS_KEY, next);
}

/** The web-capturable target for an IP (IPv6 bracketed) / a campaign IOC (URL/domain as-is, IP → https). */
function ipTarget(ip: string): string {
  return ip.includes(':') ? `https://[${ip}]` : `https://${ip}`;
}
function iocTarget(value: string, type: EnrichableType): string | null {
  if (type === 'url' || type === 'domain') return value;
  if (type === 'ipv4') return `https://${value}`;
  if (type === 'ipv6') return `https://[${value}]`;
  return null;
}

/**
 * Server-side auto 魚拓 for every auto-enabled, web-capturable target (IP-Mon auto IPs + CP-Mon auto
 * IOCs). Runs on the daily cron so it fires ONCE regardless of how many devices are open. A target is
 * due when its last ATTEMPT (a success in the shared `captures` blob, OR a recorded failed/pending
 * attempt) is ≳20h old — so a dead/unresolvable target (no site/DNS → 魚拓 can never succeed) retries
 * at most ~once a day like everything else, instead of every run. Due targets are taken oldest-attempt
 * first so dead ones can't monopolise the per-run cap and starve live targets. Submits a urlscan
 * (gated by the shared `urlscanDailyCap`), waits, polls in bounded rounds, and appends completed
 * captures to the shared blob (each written once, only if changed). Never throws.
 */
export async function runScheduledCaptures(
  store: Storage,
  env: ProxyEnv,
): Promise<{ due: number; captured: number; pending: number }> {
  if (!env.urlscanApiKey) return { due: 0, captured: 0, pending: 0 };

  // 1) Collect the auto targets from the shared watchlist + campaigns.
  const targets = new Set<string>();
  const monitors = (await getSharedMonitors(store)) as Record<string, WatchEntry>;
  if (monitors && typeof monitors === 'object') {
    for (const e of Object.values(monitors)) if (e?.autoEnrich && typeof e.ip === 'string') targets.add(ipTarget(e.ip));
  }
  const campaigns = (await getSharedCampaigns(store)) as Record<string, CampaignLike>;
  if (campaigns && typeof campaigns === 'object') {
    for (const c of Object.values(campaigns)) {
      if (!c?.iocs) continue;
      for (const ioc of Object.values(c.iocs)) {
        if (!ioc?.autoEnrich || typeof ioc.value !== 'string') continue;
        const t = iocTarget(ioc.value, ioc.type);
        if (t) targets.add(t);
      }
    }
  }
  if (!targets.size) return { due: 0, captured: 0, pending: 0 };

  // 2) A target's "last touch" is the newer of its most recent successful capture and its last recorded
  //    attempt (which we stamp for FAILURES too, below). Due = last touch ≳20h ago; oldest first so a
  //    pile of dead targets can't crowd out live ones under the per-run cap (never-touched → 0 → first).
  const caps = (await getSharedCaptures(store)) as Record<string, SharedCaptureEntry[]>;
  const blob: Record<string, SharedCaptureEntry[]> = caps && typeof caps === 'object' ? caps : {};
  const attempts = await getCaptureAttempts(store);
  const now = Date.now();
  const lastTouch = (t: string): number => {
    const hist = blob[t];
    const newest = Array.isArray(hist) && hist.length ? Math.max(...hist.map((h) => h?.at ?? 0)) : 0;
    return Math.max(newest, attempts[t] ?? 0);
  };
  const due = [...targets].filter((t) => now - lastTouch(t) >= CAP_DUE_MS).sort((a, b) => lastTouch(a) - lastTouch(b));

  // Prune attempt records for targets that are no longer auto-enabled, so the log can't grow unbounded.
  let attemptsChanged = false;
  for (const k of Object.keys(attempts))
    if (!targets.has(k)) {
      delete attempts[k];
      attemptsChanged = true;
    }
  if (!due.length) {
    if (attemptsChanged) await putCaptureAttempts(store, attempts);
    return { due: 0, captured: 0, pending: 0 };
  }

  // 3) Submit — each gated by the shared daily urlscan cap (0 = unlimited). Record the ATTEMPT for every
  //    target we submit BEFORE knowing the outcome, so a failure/pending throttles it ~a day just like a
  //    success (this is what stops dead targets repeating). Stop as soon as the cap bites.
  const submitted: { target: string; uuid: string; visibility?: string }[] = [];
  for (const t of due.slice(0, CAP_MAX_PER_RUN)) {
    if (!(await consumeDailyQuota(store, 'urlscan', env.urlscanDailyCap, 1))) break;
    attempts[t] = now;
    attemptsChanged = true;
    const sub = await urlscanSubmit(t, env);
    if (sub && !('error' in sub) && sub.uuid) submitted.push({ target: t, uuid: sub.uuid, visibility: sub.visibility });
  }
  if (attemptsChanged) await putCaptureAttempts(store, attempts);
  if (!submitted.length) return { due: due.length, captured: 0, pending: 0 };

  // 4) urlscan renders asynchronously — wait once, then poll all still-pending uuids in bounded rounds
  //    so wall-clock stays capped no matter how many were submitted.
  await sleep(CAP_RENDER_WAIT_MS);
  const remaining = new Map(submitted.map((s) => [s.uuid, s]));
  let captured = 0;
  for (let round = 0; round < CAP_POLL_ROUNDS && remaining.size; round++) {
    for (const [uuid, s] of [...remaining]) {
      const r = await urlscanResult(uuid, env);
      if (!r) {
        remaining.delete(uuid); // urlscan not configured — nothing to do
        continue;
      }
      if (r.pending) continue; // still rendering — retry next round
      remaining.delete(uuid);
      if (r.error) continue; // hard error (dead/blacklisted target) — drop, retry next day
      blob[s.target] = mergeEntries([{ uuid, at: Date.now(), by: 'auto', visibility: s.visibility, result: slimResult(r) }], blob[s.target] ?? []);
      captured++;
    }
    if (remaining.size && round < CAP_POLL_ROUNDS - 1) await sleep(CAP_POLL_GAP_MS);
  }
  if (captured) await putSharedCaptures(store, blob);
  return { due: due.length, captured, pending: remaining.size };
}

/** Run the IP-Mon watchlist + CP-Mon campaign auto-enrich AND the server-side auto 魚拓 in one pass
 *  (cron entry point). Each standing auto operation fires once per day server-side, so every device
 *  converges to the identical shared state without any browser needing to be open. */
export async function runAllScheduledEnrich(
  store: Storage,
  env: ProxyEnv,
): Promise<{
  monitors: { due: number; enriched: number; changed: number };
  campaigns: { due: number; enriched: number; changed: number };
  captures: { due: number; captured: number; pending: number };
  assessments: { ipMon: boolean; campaigns: number; skipped: number };
}> {
  const monitors = await runScheduledAutoEnrich(store, env);
  const campaigns = await runScheduledCampaignEnrich(store, env);
  const captures = await runScheduledCaptures(store, env);
  // Assessments run LAST so the CP-Mon / IP-Mon reports reflect the freshly-enriched data from this run.
  const assessments = await runScheduledAssessments(store, env);
  return { monitors, campaigns, captures, assessments };
}
