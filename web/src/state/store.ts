import { create } from 'zustand';
import {
  extractIndicators,
  type AppSettings,
  type CyfirmaSearch,
  type EnrichableType,
  type EnrichOptions,
  type ExtractStats,
  type HistoryRecord,
  type Intel471Malware,
  type Intel471Search,
  type NormalizedResult,
  type ParsedIndicator,
  type ProxyHealth,
  type RfActorProfile,
  type RfMalwareProfile,
  type RfRuleSearchParams,
  type RfRuleSearchResult,
  type RfSandboxIntel,
  type Session,
  type ShodanContext,
  type ShodanInternetDb,
  type ShodanScanRequest,
  type ShodanScanStatus,
  type UrlscanResult,
  type UrlscanSubmission,
  type SocPrimeQueryOptions,
  type SocPrimeQueryResult,
  type SocPrimeRuleSearchParams,
  type SocPrimeRuleSearchResult,
  type ThreatVisionAdversary,
  type UserRecord,
  appendSnapshot,
  downsampleHistory,
  autoEnrichInterval,
  fallbackSummary,
  type CampaignDigest,
  type EnrichSnapshot,
} from '@vteeee/shared';
// Re-export the shared timeline helpers/type so existing importers (components, tests) keep working.
export { appendSnapshot, downsampleHistory, autoEnrichInterval, type EnrichSnapshot };
import {
  consumeConnectLink,
  loadSettings,
  loadUsers,
  resolveMode,
  saveSettings,
  saveUsers,
  type Mode,
} from '../config';
import { authenticate, persistSession, restoreSession } from '../auth/session';
import { makeClient, type EnrichClient } from '../api/client';
import { saveHistory } from '../lib/historySource';
import { requestPersistentStorage } from '../lib/durable';
import {
  loadCampaigns,
  loadCampaignsBackup,
  saveCampaigns,
  slimCampaign,
  mergeCampaign,
  mergeCampaigns,
  mergeAssessments,
  type Campaign,
  type CampaignAssessment,
  type IocSide,
  type TlpLevel,
} from './campaigns';
export type { Campaign, CampaignIoc, IocSide, TlpLevel } from './campaigns';
import { abuseOf, countryOf, detOf, diffParts, rfOf } from '../lib/enrichTrend';

export const indKey = (i: { type: string; value: string }) => `${i.type}|${i.value}`;

let abortController: AbortController | null = null;

// ---- Background scan jobs (Shodan re-scan) ----
// Live re-scans are tracked in the store, not in the detail panel, so they keep running (and finish
// with a notification) even after the panel is closed. Persisted to localStorage so the history
// survives navigation; a full page reload can't resume the poll loop, so in-flight jobs become
// `interrupted` on boot and can be re-checked.
export type ScanPhase = 'submitting' | 'scanning' | 'fetching' | 'done' | 'timeout' | 'error' | 'interrupted';
export interface ScanJob {
  ip: string;
  kind: 'shodan';
  phase: ScanPhase;
  /** Shodan scan status: QUEUE / PROCESSING / DONE. */
  status?: string;
  msg?: string;
  startedAt: number;
  updatedAt: number;
  creditsLeft?: number;
  host?: ShodanContext;
  error?: string;
  /** Whether the finished result has been viewed (drives the header "new result" badge). */
  seen: boolean;
  /** Guards against a superseded poll loop writing stale updates. */
  token?: number;
}

const ACTIVE_PHASES: ScanPhase[] = ['submitting', 'scanning', 'fetching'];
export const isActiveScan = (j: ScanJob): boolean => ACTIVE_PHASES.includes(j.phase);

const SCANJOBS_KEY = 'vteeee.scanJobs';
function loadScanJobs(): Record<string, ScanJob> {
  try {
    const raw = localStorage.getItem(SCANJOBS_KEY);
    if (!raw) return {};
    const jobs = JSON.parse(raw) as Record<string, ScanJob>;
    for (const k of Object.keys(jobs)) {
      // The poll loop can't survive a full reload → park it so the user can re-check the host.
      if (jobs[k] && ACTIVE_PHASES.includes(jobs[k].phase)) {
        jobs[k] = { ...jobs[k], phase: 'interrupted', msg: 'Interrupted by a page reload — re-check the host.', token: undefined };
      }
    }
    return jobs;
  } catch {
    return {};
  }
}
function saveScanJobs(jobs: Record<string, ScanJob>): void {
  try {
    localStorage.setItem(SCANJOBS_KEY, JSON.stringify(jobs));
  } catch {
    /* storage full / disabled — in-memory tracking still works */
  }
}

// urlscan web captures (魚拓) are tracked in the store too, keyed by target — so a capture keeps running
// (and stays viewable) after the detail panel is closed, and a bulk capture can run many at once.
// Every completed capture is kept in `history` (newest-first, never overwritten) and shared team-wide via
// the proxy, so an analyst can pick a past 魚拓 ("過去") and always take a fresh one.
export interface WebCaptureEntry {
  /** urlscan scan uuid — the snapshot's identity (also its result page). */
  uuid: string;
  /** When this capture completed (ms). */
  at: number;
  /** Who ran it (username), when known. */
  by?: string;
  visibility?: string;
  result: UrlscanResult;
}
const CAP_HISTORY_MAX = 20;
export interface WebCaptureJob {
  target: string;
  phase: 'submitting' | 'running' | 'done' | 'error' | 'stalled' | 'interrupted';
  uuid?: string;
  visibility?: string;
  msg?: string;
  startedAt: number;
  updatedAt: number;
  result?: UrlscanResult;
  error?: string;
  /** Whether a finished capture has been viewed (drives "new" badges). */
  seen: boolean;
  /** Guard token so a superseded poll loop can't clobber a newer capture. */
  token?: number;
  /** All completed captures for this target, newest first (never overwritten). */
  history: WebCaptureEntry[];
  /** Hidden from the 🎣 tracker log (via Clear/✕) — the capture + history are kept, just not shown there. */
  dismissed?: boolean;
}
const CAP_ACTIVE: WebCaptureJob['phase'][] = ['submitting', 'running'];
export const isActiveCapture = (j: WebCaptureJob): boolean => CAP_ACTIVE.includes(j.phase);
/** Strip heavy/volatile fields before persisting or sharing a capture result. */
function slimCaptureResult(r: UrlscanResult): UrlscanResult {
  const { raw: _raw, ...rest } = r;
  return {
    ...rest,
    contactedDomains: rest.contactedDomains?.slice(0, 40),
    contactedIps: rest.contactedIps?.slice(0, 40),
  };
}
/** Merge two capture-history lists for the same target: union by uuid, newest first, capped. */
function mergeCaptureEntries(a: WebCaptureEntry[] = [], b: WebCaptureEntry[] = []): WebCaptureEntry[] {
  const byUuid = new Map<string, WebCaptureEntry>();
  for (const e of [...a, ...b]) {
    if (!e || !e.uuid) continue;
    const prev = byUuid.get(e.uuid);
    if (!prev || (e.at ?? 0) >= (prev.at ?? 0)) byUuid.set(e.uuid, e);
  }
  return [...byUuid.values()].sort((x, y) => (y.at ?? 0) - (x.at ?? 0)).slice(0, CAP_HISTORY_MAX);
}
const WEBCAP_KEY = 'vteeee.webCaptures';
function loadWebCaptures(): Record<string, WebCaptureJob> {
  try {
    const raw = localStorage.getItem(WEBCAP_KEY);
    if (!raw) return {};
    const jobs = JSON.parse(raw) as Record<string, WebCaptureJob>;
    for (const k of Object.keys(jobs)) {
      const j = jobs[k];
      if (!j) continue;
      // Migrate pre-history jobs: seed history from the last result so nothing is lost.
      if (!Array.isArray(j.history)) {
        j.history =
          j.result && (j.result.uuid ?? j.uuid)
            ? [{ uuid: (j.result.uuid ?? j.uuid)!, at: j.updatedAt ?? Date.now(), visibility: j.visibility, result: j.result }]
            : [];
      }
      if (CAP_ACTIVE.includes(j.phase)) {
        jobs[k] = { ...j, phase: 'interrupted', msg: 'ページ再読込で中断 — 「再確認」で続行できます。', token: undefined };
      }
    }
    return jobs;
  } catch {
    return {};
  }
}
function saveWebCaptures(jobs: Record<string, WebCaptureJob>): void {
  try {
    localStorage.setItem(WEBCAP_KEY, JSON.stringify(jobs));
  } catch {
    /* storage full / disabled */
  }
}
function maybeRequestNotify(): void {
  try {
    if (typeof Notification !== 'undefined' && Notification.permission === 'default') void Notification.requestPermission();
  } catch {
    /* ignore */
  }
}
// Users can mute OS notifications from the 🔔 bell while still keeping the in-app log.
const NOTIF_MUTE_KEY = 'vteeee.notifyMuted';
function notifyMuted(): boolean {
  try {
    return localStorage.getItem(NOTIF_MUTE_KEY) === '1';
  } catch {
    return false;
  }
}
function browserNotify(title: string, body: string, tag: string): void {
  try {
    if (notifyMuted()) return;
    if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
      new Notification(title, { body, tag });
    }
  } catch {
    /* ignore */
  }
}

// ---- Notification log (🔔) ----
// A persisted, in-app activity log of "something finished while you were elsewhere" events — bulk
// re-enrich / bulk 魚拓 completions plus individual background-job finishes. The 🔔 bell shows it, so a
// completion is never lost just because you navigated to another page (or missed the OS notification).
export type NotifKind = 'capture' | 'reenrich' | 'scan' | 'info' | 'auto';
export interface NotifItem {
  id: string;
  at: number;
  title: string;
  body?: string;
  kind: NotifKind;
  read: boolean;
}
const NOTIF_KEY = 'vteeee.notifications';
const NOTIF_MAX = 60;
function loadNotifs(): NotifItem[] {
  try {
    const raw = localStorage.getItem(NOTIF_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw) as NotifItem[];
    return Array.isArray(arr) ? arr.slice(0, NOTIF_MAX) : [];
  } catch {
    return [];
  }
}
function saveNotifs(items: NotifItem[]): void {
  try {
    localStorage.setItem(NOTIF_KEY, JSON.stringify(items.slice(0, NOTIF_MAX)));
  } catch {
    /* storage full / disabled */
  }
}

// ---- Shodan Monitor watchlist ----
// IPs registered to Shodan Monitor (server-side alerts) PLUS the last vteeee enrichment snapshot, so
// you can come back the next day and see the intel, not just the raw Shodan monitor. Shodan is the
// source of truth for which IPs are monitored; the enrichment snapshots are cached in localStorage.
export interface MonitorEntry {
  ip: string;
  addedAt: number;
  updatedAt: number;
  /** Shodan alert id. */
  alertId?: string;
  /** Present on Shodan's server-side alert list (the authoritative "is monitored" flag). */
  live?: boolean;
  /** Enabled Shodan trigger names for this alert (malware / new_service / …). */
  triggers?: string[];
  /** Last vteeee enrichment snapshot (raw VT attributes stripped to keep localStorage small). */
  result?: NormalizedResult;
  /** Timeline of enrichment snapshots (deduped by state) — the past is kept, not overwritten. */
  history?: EnrichSnapshot[];
  /** A re-enrich is in flight. */
  enriching?: boolean;
  error?: string;
  note?: string;
  /** Project (PJ) id this IP belongs to — the top-level watchlist partition (empty = 未分類). Shared. */
  project?: string;
  /** Analyst-assigned group label for organising the watchlist (arbitrary name; empty = ungrouped). */
  group?: string;
  /** Auto re-enrich this IP on a cadence aligned to its age (client-side, while vteeee is open). */
  autoEnrich?: boolean;
  /** When this IP was last enriched (auto OR manual) — drives the auto-enrich "due" check. */
  lastEnrichAt?: number;
  /** Shodan state when monitoring began — the reference the "monitoring result" diffs against. */
  baseline?: { ports?: number[]; vulns?: string[]; lastUpdate?: string };
  /** Latest Shodan re-observation vs. the baseline — this IS the "what did monitoring find" result. */
  check?: {
    at: number;
    found: boolean;
    ports?: number[];
    vulns?: string[];
    lastUpdate?: string;
    newPorts: number[];
    gonePorts: number[];
    newVulns: string[];
    changed: boolean;
    error?: string;
  };
  /** A monitor check is in flight. */
  checking?: boolean;
}

const MONITORS_KEY = 'vteeee.monitors';
function stripRaw(r?: NormalizedResult): NormalizedResult | undefined {
  if (!r) return undefined;
  const { raw: _raw, ...rest } = r as NormalizedResult & { raw?: unknown };
  return rest as NormalizedResult;
}
function stripSnap(s: EnrichSnapshot): EnrichSnapshot {
  return { at: s.at, by: s.by, result: stripRaw(s.result) as NormalizedResult };
}
/** If an entry has a current result but no timeline yet (existing watches predate history tracking),
 *  seed that result as the first point so the NEXT enrich has a baseline to diff against. */
function seedHistory(cur: MonitorEntry): EnrichSnapshot[] | undefined {
  if (cur.history && cur.history.length) return cur.history;
  if (cur.result) return [{ at: cur.lastEnrichAt ?? cur.updatedAt ?? cur.addedAt, result: cur.result }];
  return undefined;
}
/** Trim an entry for persistence/sharing: strip raw VT payloads from the latest result AND every snapshot. */
function slimEntry(v: MonitorEntry): MonitorEntry {
  return {
    ...v,
    result: stripRaw(v.result),
    history: v.history?.map(stripSnap),
    enriching: false,
    checking: false,
  };
}
function loadMonitors(): Record<string, MonitorEntry> {
  try {
    const raw = localStorage.getItem(MONITORS_KEY);
    return raw ? (JSON.parse(raw) as Record<string, MonitorEntry>) : {};
  } catch {
    return {};
  }
}
function saveMonitors(m: Record<string, MonitorEntry>): void {
  try {
    const slim: Record<string, MonitorEntry> = {};
    for (const [k, v] of Object.entries(m)) slim[k] = slimEntry(v);
    localStorage.setItem(MONITORS_KEY, JSON.stringify(slim));
  } catch {
    /* storage full/disabled — in-memory watchlist still works */
  }
}

// --- IP-Mon PROJECTS (PJ) — top-level watchlist partitions (like CP-Mon campaigns). ------------------
/** A named IP-Mon project. Each monitored IP carries its `project` id; this registry names/orders them. */
export interface MonitorProject {
  id: string;
  name: string;
  createdAt: number;
  updatedAt: number;
}
const MONITOR_PROJECTS_KEY = 'vteeee.monitorProjects';
/** Fixed id of the auto-migration bucket, so every browser converges to the SAME default PJ (no dupes). */
export const DEFAULT_PROJECT_ID = '__default_pj__';
const PROJECTS_MIGRATED_KEY = 'vteeee.monitorProjectsMigrated';
function loadMonitorProjects(): Record<string, MonitorProject> {
  try {
    const raw = localStorage.getItem(MONITOR_PROJECTS_KEY);
    const v = raw ? (JSON.parse(raw) as Record<string, MonitorProject>) : {};
    return v && typeof v === 'object' ? v : {};
  } catch {
    return {};
  }
}
function saveMonitorProjects(p: Record<string, MonitorProject>): void {
  try {
    localStorage.setItem(MONITOR_PROJECTS_KEY, JSON.stringify(p));
  } catch {
    /* storage full/disabled — in-memory registry still works */
  }
}
/** Union two project registries by id; the newer `updatedAt` wins (so a rename propagates). */
function mergeMonitorProjects(
  a: Record<string, MonitorProject>,
  b: Record<string, MonitorProject>,
): Record<string, MonitorProject> {
  const out: Record<string, MonitorProject> = { ...a };
  for (const [id, p] of Object.entries(b)) {
    if (!p || typeof p.id !== 'string') continue;
    const cur = out[id];
    if (!cur || (p.updatedAt ?? 0) >= (cur.updatedAt ?? 0)) out[id] = p;
  }
  return out;
}
/** Fetch the team's shared PJ registry. null when sharing is off. */
async function fetchSharedMonitorProjects(settings: AppSettings): Promise<Record<string, MonitorProject> | null> {
  if (!monitorSharingOn(settings)) return null;
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/monitor-projects`, { headers: monitorAuth(settings), cache: 'no-store' });
    if (!res.ok) return null;
    const j = await res.json();
    return j && typeof j === 'object' && !Array.isArray(j) ? (j as Record<string, MonitorProject>) : {};
  } catch {
    return null;
  }
}
/** Non-destructive read-merge-write of the PJ registry into the shared blob (union by id). Best-effort. */
async function pushSharedMonitorProjects(settings: AppSettings, projects: Record<string, MonitorProject>): Promise<void> {
  if (!monitorSharingOn(settings)) return;
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/monitor-projects`, { headers: monitorAuth(settings), cache: 'no-store' });
    const j = res.ok ? await res.json() : {};
    const remote = (j && typeof j === 'object' && !Array.isArray(j) ? j : {}) as Record<string, MonitorProject>;
    await fetch(`${base}/api/monitor-projects`, {
      method: 'PUT',
      headers: { ...monitorAuth(settings), 'content-type': 'application/json' },
      body: JSON.stringify(mergeMonitorProjects(remote, projects)),
    });
  } catch {
    /* offline — local copy keeps it; a later refresh reconciles */
  }
}
/** Read-modify-write DELETE of one PJ id from the shared registry (union can't remove). Best-effort. */
async function deleteSharedMonitorProject(settings: AppSettings, id: string): Promise<void> {
  if (!monitorSharingOn(settings)) return;
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/monitor-projects`, { headers: monitorAuth(settings), cache: 'no-store' });
    const j = res.ok ? await res.json() : {};
    const remote = (j && typeof j === 'object' && !Array.isArray(j) ? j : {}) as Record<string, MonitorProject>;
    delete remote[id];
    await fetch(`${base}/api/monitor-projects`, {
      method: 'PUT',
      headers: { ...monitorAuth(settings), 'content-type': 'application/json' },
      body: JSON.stringify(remote),
    });
  } catch {
    /* offline */
  }
}
// IP-Mon group display order (a local display preference — analogous to a campaign's groupOrder).
const MON_GROUP_ORDER_KEY = 'vteeee.monitorGroupOrder';
function loadMonitorGroupOrder(): string[] {
  try {
    const raw = localStorage.getItem(MON_GROUP_ORDER_KEY);
    const a = raw ? (JSON.parse(raw) as unknown) : [];
    return Array.isArray(a) ? a.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}
function saveMonitorGroupOrder(order: string[]): void {
  try {
    localStorage.setItem(MON_GROUP_ORDER_KEY, JSON.stringify(order));
  } catch {
    /* ignore */
  }
}

/** Run a full vteeee enrichment for ONE indicator (any type) and return the normalized result. */
async function enrichOne(
  settings: AppSettings,
  value: string,
  type: EnrichableType,
): Promise<NormalizedResult | undefined> {
  const client = await makeClient(settings);
  let out: NormalizedResult | undefined;
  const options: EnrichOptions = {
    rpm: settings.rpm,
    concurrency: 1,
    includeRaw: false,
    gti: settings.gti,
    submitUnknown: false,
    shodan: settings.shodan ?? true,
    maxmind: settings.maxmind ?? true,
    domaintools: settings.domaintools ?? true,
    dnslytics: settings.dnslytics ?? true,
    intel471: settings.intel471 ?? true,
    cyfirma: settings.cyfirma ?? true,
    threatvision: settings.threatvision ?? true,
    recordedfuture: settings.recordedfuture ?? true,
    abuseipdb: settings.abuseipdb ?? true,
  };
  await client.enrich(
    { indicators: [{ value, type, input: value }], options },
    { onResult: (r) => (out = r), onProgress: () => {}, onDone: () => {}, onError: () => {} },
  );
  return out;
}
/** Run a full vteeee enrichment for ONE IP (monitor snapshots). */
async function enrichOneIp(settings: AppSettings, ip: string): Promise<NormalizedResult | undefined> {
  return enrichOne(settings, ip, ip.includes(':') ? 'ipv6' : 'ipv4');
}

// ---- Shared watchlist sync (proxy KV) ----
// Default-on in Live mode: the watchlist + snapshots are shared across the team so nobody re-enriches
// what someone already monitored. Set shareMonitors:false to keep it to this browser.
const monitorSharingOn = (settings: AppSettings): boolean =>
  Boolean(settings.proxyBaseUrl) && settings.shareMonitors !== false;
function monitorAuth(settings: AppSettings): Record<string, string> {
  const h: Record<string, string> = {};
  if (settings.accessToken) h['Authorization'] = `Bearer ${settings.accessToken}`;
  return h;
}
async function fetchSharedMonitors(settings: AppSettings): Promise<Record<string, MonitorEntry> | null> {
  if (!monitorSharingOn(settings)) return null;
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/monitor`, { headers: monitorAuth(settings), cache: 'no-store' });
    if (!res.ok) return null;
    const j = await res.json();
    return j && typeof j === 'object' ? (j as Record<string, MonitorEntry>) : {};
  } catch {
    return null;
  }
}
/** Merge a local + shared copy of the same IP, preferring whichever side actually has intel. */
function mergeEntry(local: MonitorEntry | undefined, shared: MonitorEntry | undefined): MonitorEntry {
  const a = (local ?? {}) as Partial<MonitorEntry>;
  const b = (shared ?? {}) as Partial<MonitorEntry>;
  const check = a.check && b.check ? ((b.check.at ?? 0) >= (a.check.at ?? 0) ? b.check : a.check) : (b.check ?? a.check);
  // Union both sides' enrichment timelines so nobody's snapshots are lost; the newest drives "current".
  const history = downsampleHistory([...(a.history ?? []), ...(b.history ?? [])], Date.now());
  const latest = history.length ? history[history.length - 1].result : undefined;
  return {
    ...a,
    ...b,
    ip: (b.ip ?? a.ip) as string,
    result: latest ?? b.result ?? a.result, // newest snapshot wins; else whichever side has one
    history: history.length ? history : undefined,
    project: b.project ?? a.project, // PJ assignment — prefer the shared (latest-pushed) side, else local
    group: b.group ?? a.group, // group label — prefer the shared (latest-pushed) side, else local
    autoEnrich: b.autoEnrich ?? a.autoEnrich,
    lastEnrichAt: Math.max(a.lastEnrichAt ?? 0, b.lastEnrichAt ?? 0) || undefined,
    baseline: b.baseline ?? a.baseline,
    check,
    triggers: b.triggers ?? a.triggers,
    alertId: b.alertId ?? a.alertId,
    addedAt: Math.min(a.addedAt ?? Number.MAX_SAFE_INTEGER, b.addedAt ?? Number.MAX_SAFE_INTEGER),
    updatedAt: Math.max(a.updatedAt ?? 0, b.updatedAt ?? 0),
    enriching: false,
    checking: false,
  };
}

/** Replace the whole shared blob (raw stripped) — used to upload local-only snapshots to the team. */
async function putSharedMonitorsAll(settings: AppSettings, map: Record<string, MonitorEntry>): Promise<void> {
  if (!monitorSharingOn(settings)) return;
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  const slim: Record<string, MonitorEntry> = {};
  for (const [k, v] of Object.entries(map)) slim[k] = slimEntry(v);
  try {
    await fetch(`${base}/api/monitor`, {
      method: 'PUT',
      headers: { ...monitorAuth(settings), 'content-type': 'application/json' },
      body: JSON.stringify(slim),
    });
  } catch {
    /* offline */
  }
}

/** Read-modify-write ONE entry into the shared blob (set, or delete when entry is null) so a stale
 *  client can't clobber the whole team list. Best-effort. */
async function pushSharedMonitorEntry(settings: AppSettings, ip: string, entry: MonitorEntry | null): Promise<void> {
  if (!monitorSharingOn(settings)) return;
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/monitor`, { headers: monitorAuth(settings), cache: 'no-store' });
    const j = res.ok ? await res.json() : {};
    const map = (j && typeof j === 'object' ? j : {}) as Record<string, MonitorEntry>;
    if (entry) map[ip] = slimEntry(entry);
    else delete map[ip];
    await fetch(`${base}/api/monitor`, {
      method: 'PUT',
      headers: { ...monitorAuth(settings), 'content-type': 'application/json' },
      body: JSON.stringify(map),
    });
  } catch {
    /* offline — the local copy keeps it; a later refresh reconciles */
  }
}

// ---- Shared campaigns sync (proxy KV) ----
// CP-Mon is an all-shared model too (avoid redundant enrichment): campaigns + their IOC timelines sync
// via the proxy KV under the same on/off flag as the watchlist.
/** Fetch the shared campaigns with the HTTP status, so the UI can tell 404 (proxy too old) from 401
 *  (token) from a network/CORS error from "genuinely empty" — instead of one vague "sync failed". */
async function fetchCampaignsStatus(
  settings: AppSettings,
): Promise<{ data: Record<string, Campaign> | null; status: number; netError: boolean }> {
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/campaigns`, { headers: monitorAuth(settings), cache: 'no-store' });
    if (!res.ok) return { data: null, status: res.status, netError: false };
    const j = await res.json();
    return { data: (j && typeof j === 'object' ? (j as Record<string, Campaign>) : {}), status: res.status, netError: false };
  } catch {
    return { data: null, status: 0, netError: true };
  }
}
/** Publish local campaigns NON-destructively: re-read the shared blob, UNION it with local (per-field,
 *  per-IOC newest-wins via mergeCampaigns), and write the union back. A stale/empty client therefore can
 *  never wipe campaigns another browser created — it uploads what it has and keeps everything it doesn't. */
async function putSharedCampaignsAll(settings: AppSettings, map: Record<string, Campaign>): Promise<void> {
  if (!monitorSharingOn(settings)) return;
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/campaigns`, { headers: monitorAuth(settings), cache: 'no-store' });
    const j = res.ok ? await res.json() : {};
    const remote = (j && typeof j === 'object' ? j : {}) as Record<string, Campaign>;
    const merged = mergeCampaigns(map, remote);
    const slim: Record<string, Campaign> = {};
    for (const [k, v] of Object.entries(merged)) slim[k] = slimCampaign(v);
    await fetch(`${base}/api/campaigns`, {
      method: 'PUT',
      headers: { ...monitorAuth(settings), 'content-type': 'application/json' },
      body: JSON.stringify(slim),
    });
  } catch {
    /* offline — local copy keeps everything; a later refresh reconciles */
  }
}
/** Read-modify-write ONE campaign into the shared blob (set, or delete when null). Best-effort. */
async function pushSharedCampaign(settings: AppSettings, id: string, campaign: Campaign | null): Promise<void> {
  if (!monitorSharingOn(settings)) return;
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/campaigns`, { headers: monitorAuth(settings), cache: 'no-store' });
    const j = res.ok ? await res.json() : {};
    const map = (j && typeof j === 'object' ? j : {}) as Record<string, Campaign>;
    // Merge our copy with whatever's already shared so a concurrent edit on the SAME campaign (e.g. a
    // teammate adding IOCs) isn't clobbered; delete removes it (best-effort — no tombstone).
    if (campaign) map[id] = slimCampaign(mergeCampaign(map[id], campaign));
    else delete map[id];
    await fetch(`${base}/api/campaigns`, {
      method: 'PUT',
      headers: { ...monitorAuth(settings), 'content-type': 'application/json' },
      body: JSON.stringify(map),
    });
  } catch {
    /* offline — local copy keeps it; a later refresh reconciles */
  }
}

// ---- Shared 魚拓 capture history sync (proxy KV, key 'captures') ----
// Executed captures are shared team-wide so everyone sees the same 魚拓 timeline. The blob is
// Record<target, WebCaptureEntry[]>; the proxy is dumb storage and the merge (union by uuid) happens
// client-side on every write, so a stale client can never wipe another analyst's captures.
async function fetchSharedCaptures(settings: AppSettings): Promise<Record<string, WebCaptureEntry[]> | null> {
  if (!monitorSharingOn(settings)) return null;
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/captures`, { headers: monitorAuth(settings), cache: 'no-store' });
    if (!res.ok) return null;
    const j = await res.json();
    return j && typeof j === 'object' ? (j as Record<string, WebCaptureEntry[]>) : {};
  } catch {
    return null;
  }
}
/** Read-modify-write ONE target's capture history into the shared blob (union by uuid). Best-effort. */
async function pushSharedCapture(settings: AppSettings, target: string, history: WebCaptureEntry[]): Promise<void> {
  if (!monitorSharingOn(settings)) return;
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/captures`, { headers: monitorAuth(settings), cache: 'no-store' });
    const j = res.ok ? await res.json() : {};
    const map = (j && typeof j === 'object' ? j : {}) as Record<string, WebCaptureEntry[]>;
    map[target] = mergeCaptureEntries(history, map[target] ?? []);
    await fetch(`${base}/api/captures`, {
      method: 'PUT',
      headers: { ...monitorAuth(settings), 'content-type': 'application/json' },
      body: JSON.stringify(map),
    });
  } catch {
    /* offline — local copy keeps it; a later refresh reconciles */
  }
}

/** Fetch the team's shared IP-Mon monitoring-report history (time-series). null when sharing is off. */
async function fetchSharedMonitorAssessments(settings: AppSettings): Promise<CampaignAssessment[] | null> {
  if (!monitorSharingOn(settings)) return null;
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/monitor-assessments`, { headers: monitorAuth(settings), cache: 'no-store' });
    if (!res.ok) return null;
    const j = await res.json();
    return Array.isArray(j) ? (j as CampaignAssessment[]) : [];
  } catch {
    return null;
  }
}
/** Non-destructive read-merge-write of the report history into the shared blob (union by `at`). Best-effort. */
async function pushSharedMonitorAssessments(settings: AppSettings, list: CampaignAssessment[]): Promise<void> {
  if (!monitorSharingOn(settings)) return;
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/monitor-assessments`, { headers: monitorAuth(settings), cache: 'no-store' });
    const j = res.ok ? await res.json() : [];
    const remote = Array.isArray(j) ? (j as CampaignAssessment[]) : [];
    await fetch(`${base}/api/monitor-assessments`, {
      method: 'PUT',
      headers: { ...monitorAuth(settings), 'content-type': 'application/json' },
      body: JSON.stringify(mergeAssessments(list, remote)),
    });
  } catch {
    /* offline — local copy keeps it; a later refresh reconciles */
  }
}

/** Build the compact digest the summarizer consumes (aggregates + short change strings only). */
function buildCampaignDigest(c: Campaign): CampaignDigest {
  const iocs = Object.values(c.iocs);
  const byType = new Map<string, number>();
  const byCountry = new Map<string, number>();
  const byCve = new Map<string, number>();
  const byGroup = new Map<string, number>();
  let totalSnapshots = 0;
  let minAt = Number.MAX_SAFE_INTEGER;
  let maxAt = 0;
  const recentChanges: { value: string; changes: string[] }[] = [];
  for (const i of iocs) {
    byType.set(i.type, (byType.get(i.type) ?? 0) + 1);
    if (i.group) byGroup.set(i.group, (byGroup.get(i.group) ?? 0) + 1);
    const r = i.result;
    if (r) {
      const cc = countryOf(r);
      if (cc) byCountry.set(cc, (byCountry.get(cc) ?? 0) + 1);
      for (const v of r.shodan?.vulns ?? []) byCve.set(v, (byCve.get(v) ?? 0) + 1);
    }
    const h = i.history?.length ? [...i.history].sort((a, b) => a.at - b.at) : [];
    totalSnapshots += h.length;
    if (h.length) {
      minAt = Math.min(minAt, h[0].at);
      maxAt = Math.max(maxAt, h[h.length - 1].at);
    }
    if (h.length >= 2) {
      const changes = diffParts(h[h.length - 1].result, h[h.length - 2].result);
      if (changes.length) recentChanges.push({ value: i.value, changes });
    }
  }
  const top = (m: Map<string, number>, n: number): [string, number][] =>
    [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  return {
    name: c.name,
    iocCount: iocs.length,
    withIntel: iocs.filter((i) => i.result).length,
    malicious: iocs.filter((i) => i.result?.verdict === 'malicious').length,
    suspicious: iocs.filter((i) => i.result?.verdict === 'suspicious').length,
    highAbuse: iocs.filter((i) => (i.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75).length,
    distinctCves: byCve.size,
    autoCount: iocs.filter((i) => i.autoEnrich).length,
    byType: top(byType, 8),
    topCountries: top(byCountry, 6),
    topCves: top(byCve, 6),
    groups: top(byGroup, 12),
    recentChanges: recentChanges.slice(0, 12),
    spanDays: maxAt > minAt && minAt !== Number.MAX_SAFE_INTEGER ? Math.round((maxAt - minAt) / 86_400_000) : 0,
    totalSnapshots,
  };
}

/** Ask the proxy's Claude to write the key message; falls back to the deterministic summary offline. */
async function fetchCampaignSummary(settings: AppSettings, digest: CampaignDigest): Promise<string> {
  if (!monitorSharingOn(settings)) return fallbackSummary(digest);
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/campaign-summary`, {
      method: 'POST',
      headers: { ...monitorAuth(settings), 'content-type': 'application/json' },
      body: JSON.stringify(digest),
    });
    if (!res.ok) return fallbackSummary(digest);
    const j = (await res.json()) as { text?: string };
    return j.text?.trim() || fallbackSummary(digest);
  } catch {
    return fallbackSummary(digest);
  }
}

/** Rich, privacy-safe digest for the CTI assessment: per-IOC intel highlights + timeline changes so
 *  Claude has the context to reason (attribution, TTPs, infra), not just aggregates. Capped for cost. */
function buildAssessmentDigest(c: Campaign): unknown {
  const iocs = Object.values(c.iocs);
  const brief = (i: (typeof iocs)[number]) => {
    const r = i.result;
    const h = i.history?.length ? [...i.history].sort((a, b) => a.at - b.at) : [];
    const changes = h.length >= 2 ? diffParts(h[h.length - 1].result, h[h.length - 2].result) : [];
    return {
      value: i.value,
      type: i.type,
      group: i.group,
      verdict: r?.verdict,
      country: r ? countryOf(r) || undefined : undefined,
      org: r?.maxmind?.organization ?? r?.shodan?.org ?? r?.ip?.asOwner ?? undefined,
      asn: r?.maxmind?.asn ?? r?.ip?.asn ?? undefined,
      det: r ? detOf(r) : undefined,
      abuse: r ? abuseOf(r) ?? undefined : undefined,
      rf: r ? rfOf(r) ?? undefined : undefined,
      ports: r?.shodan?.ports?.slice(0, 12),
      cves: r?.shodan?.vulns?.slice(0, 12),
      threat: r?.file?.threatLabel ?? r?.gti?.verdict ?? undefined,
      firstDays: h.length ? Math.round((Date.now() - h[0].at) / 86_400_000) : undefined,
      recentChange: changes.length ? changes.join(' · ') : undefined,
    };
  };
  const cap = 50;
  const attack = iocs.filter((i) => (i.side ?? 'attack') === 'attack').slice(0, cap).map(brief);
  const target = iocs.filter((i) => i.side === 'target').slice(0, cap).map(brief);
  const byType = new Map<string, number>();
  const byCountry = new Map<string, number>();
  const byCve = new Map<string, number>();
  const byGroup = new Map<string, number>();
  let minAt = Number.MAX_SAFE_INTEGER;
  let maxAt = 0;
  let totalSnapshots = 0;
  const recentChanges: { value: string; changes: string }[] = [];
  for (const i of iocs) {
    byType.set(i.type, (byType.get(i.type) ?? 0) + 1);
    if (i.group) byGroup.set(i.group, (byGroup.get(i.group) ?? 0) + 1);
    const r = i.result;
    if (r) {
      const cc = countryOf(r);
      if (cc) byCountry.set(cc, (byCountry.get(cc) ?? 0) + 1);
      for (const v of r.shodan?.vulns ?? []) byCve.set(v, (byCve.get(v) ?? 0) + 1);
    }
    const h = i.history?.length ? [...i.history].sort((a, b) => a.at - b.at) : [];
    totalSnapshots += h.length;
    if (h.length) {
      minAt = Math.min(minAt, h[0].at);
      maxAt = Math.max(maxAt, h[h.length - 1].at);
      if (h.length >= 2) {
        const ch = diffParts(h[h.length - 1].result, h[h.length - 2].result);
        if (ch.length) recentChanges.push({ value: i.value, changes: ch.join(' · ') });
      }
    }
  }
  const top = (m: Map<string, number>, n: number) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  return {
    name: c.name,
    tlp: c.tlp ?? 'AMBER',
    // Free-text analyst context/background (empty → omitted). Claude weighs it as reporting context.
    analystNote: c.note && c.note.trim() ? c.note.trim().slice(0, 4000) : undefined,
    admiralty:
      c.admiraltyReliability || c.admiraltyCredibility
        ? `${c.admiraltyReliability ?? '?'}${c.admiraltyCredibility ?? '?'}`
        : undefined,
    iocCount: iocs.length,
    spanDays: maxAt > minAt && minAt !== Number.MAX_SAFE_INTEGER ? Math.round((maxAt - minAt) / 86_400_000) : 0,
    totalSnapshots,
    stats: {
      withIntel: iocs.filter((i) => i.result).length,
      malicious: iocs.filter((i) => i.result?.verdict === 'malicious').length,
      suspicious: iocs.filter((i) => i.result?.verdict === 'suspicious').length,
      highAbuse: iocs.filter((i) => (i.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75).length,
      distinctCves: byCve.size,
    },
    bySide: { attack: attack.length, target: target.length },
    byType: top(byType, 8),
    topCountries: top(byCountry, 10),
    topCves: top(byCve, 12),
    groups: top(byGroup, 20),
    attack,
    target,
    recentChanges: recentChanges.slice(0, 20),
  };
}

/** Ask the proxy's Claude for a full CTI assessment report. Returns '' if unavailable (caller handles). */
async function fetchCampaignAssessment(settings: AppSettings, digest: unknown): Promise<string> {
  if (!monitorSharingOn(settings)) {
    return 'アセスメントレポートの生成には Claude（プロキシ接続）が必要です。Settings でプロキシURL＋アクセストークンを設定し、プロキシに ANTHROPIC_API_KEY を登録してください。';
  }
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/campaign-assessment`, {
      method: 'POST',
      headers: { ...monitorAuth(settings), 'content-type': 'application/json' },
      body: JSON.stringify(digest),
    });
    if (!res.ok) {
      // Surface the server's error message instead of a bare status — a 500 alone hides the cause.
      let detail = '';
      try {
        const j = (await res.json()) as { error?: string };
        if (j?.error) detail = ` — ${String(j.error).slice(0, 300)}`;
      } catch {
        /* non-JSON error body */
      }
      return `アセスメント生成に失敗しました（HTTP ${res.status}${detail}）。`;
    }
    const j = (await res.json()) as { text?: string; error?: string };
    return j.text?.trim() || j.error || 'アセスメントを生成できませんでした。';
  } catch {
    return 'アセスメント生成に失敗しました（ネットワーク）。';
  }
}

// --- IP-Mon monitoring report (Claude) — digest, fetch, and local time-series persistence. ----------
const MONITOR_ASSESS_KEY = 'vteeee.monitorAssessments';
function loadMonitorAssessments(): CampaignAssessment[] {
  try {
    const raw = localStorage.getItem(MONITOR_ASSESS_KEY);
    const a = raw ? (JSON.parse(raw) as CampaignAssessment[]) : [];
    return Array.isArray(a) ? a : [];
  } catch {
    return [];
  }
}
function saveMonitorAssessments(a: CampaignAssessment[]): void {
  try {
    localStorage.setItem(MONITOR_ASSESS_KEY, JSON.stringify(a));
  } catch {
    // Quota — keep the most recent dozen so the time-series survives without blocking the write.
    try {
      localStorage.setItem(MONITOR_ASSESS_KEY, JSON.stringify(a.slice(0, 12)));
    } catch {
      /* give up silently — the in-memory history still holds this session */
    }
  }
}

/**
 * Privacy-safe, IP-MON-framed digest for the monitoring report: per-group hosts + surface changes
 * (Shodan check baseline diff), risk/threat drift (enrichment history change-points), scan timing/
 * coverage and geo/ASN spread — so Claude can objectively describe how the WATCHLIST is moving and
 * whether the monitoring is healthy, grounded in specific IPs. The watchlist mixes IPs of many
 * backgrounds (no single intent/campaign). Capped for cost.
 */
function buildMonitorDigest(monitors: Record<string, MonitorEntry>, groupOrder: string[], tlp: TlpLevel): unknown {
  const list = Object.values(monitors);
  const now = Date.now();
  const day = 86_400_000;
  const UNGROUPED = 'Ungrouped';
  const groupOf = (e: MonitorEntry) => (e.group && e.group.trim() ? e.group : UNGROUPED);
  const top = (m: Map<string, number>, n: number) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);

  const host = (e: MonitorEntry) => {
    const r = e.result;
    const hAsc = e.history?.length ? [...e.history].sort((a, b) => a.at - b.at) : [];
    return {
      ip: e.ip,
      verdict: r?.verdict,
      country: r ? countryOf(r) || undefined : undefined,
      org: r?.shodan?.org ?? r?.maxmind?.organization ?? r?.ip?.asOwner ?? undefined,
      asn: r?.maxmind?.asn ?? r?.ip?.asn ?? undefined,
      abuse: r?.abuseipdb?.abuseConfidenceScore ?? undefined,
      rf: r?.recordedfuture?.riskScore ?? undefined,
      det: r?.detection ? `${detOf(r)}/${r.detection.total ?? 0}` : undefined,
      ports: r?.shodan?.ports?.slice(0, 16),
      cves: r?.shodan?.vulns?.slice(0, 12),
      hostnames: r?.shodan?.hostnames?.slice(0, 3),
      live: e.live || undefined,
      triggers: e.triggers?.length ? e.triggers : undefined,
      auto: e.autoEnrich || undefined,
      firstSeenDays: Math.round((now - (hAsc.length ? hAsc[0].at : e.addedAt)) / day),
      snapshots: hAsc.length || undefined,
      daysSinceEnrich: e.lastEnrichAt ? Math.round((now - e.lastEnrichAt) / day) : undefined,
      daysSinceCheck: e.check?.at ? Math.round((now - e.check.at) / day) : undefined,
    };
  };

  // Group order: analyst order first (present groups), then any remaining alphabetically, Ungrouped last.
  const present = [...new Set(list.map(groupOf))];
  const ordered = [
    ...groupOrder.filter((g) => present.includes(g) && g !== UNGROUPED),
    ...present.filter((g) => !groupOrder.includes(g) && g !== UNGROUPED).sort((a, b) => a.localeCompare(b)),
    ...(present.includes(UNGROUPED) ? [UNGROUPED] : []),
  ];

  const groups = ordered.map((g) => {
    const es = list.filter((e) => groupOf(e) === g);
    const surfaceChanges: { ip: string; at: number; newPorts?: number[]; gonePorts?: number[]; newCves?: string[] }[] = [];
    const riskThreatChanges: { ip: string; at: number; changes: string }[] = [];
    const byCountry = new Map<string, number>();
    const byOrg = new Map<string, number>();
    const byCve = new Map<string, number>();
    for (const e of es) {
      const r = e.result;
      if (r) {
        const cc = countryOf(r);
        if (cc) byCountry.set(cc, (byCountry.get(cc) ?? 0) + 1);
        const org = r.shodan?.org ?? r.maxmind?.organization ?? r.ip?.asOwner;
        if (org) byOrg.set(org, (byOrg.get(org) ?? 0) + 1);
        for (const v of r.shodan?.vulns ?? []) byCve.set(v, (byCve.get(v) ?? 0) + 1);
      }
      if (e.check?.changed) {
        surfaceChanges.push({
          ip: e.ip,
          at: e.check.at,
          newPorts: e.check.newPorts?.length ? e.check.newPorts.slice(0, 8) : undefined,
          gonePorts: e.check.gonePorts?.length ? e.check.gonePorts.slice(0, 8) : undefined,
          newCves: e.check.newVulns?.length ? e.check.newVulns.slice(0, 6) : undefined,
        });
      }
      const hAsc = e.history?.length ? [...e.history].sort((a, b) => a.at - b.at) : [];
      if (hAsc.length >= 2) {
        const changes = diffParts(hAsc[hAsc.length - 1].result, hAsc[hAsc.length - 2].result);
        if (changes.length) riskThreatChanges.push({ ip: e.ip, at: hAsc[hAsc.length - 1].at, changes: changes.join(' · ') });
      }
    }
    return {
      name: g,
      ipCount: es.length,
      live: es.filter((e) => e.live).length,
      malicious: es.filter((e) => e.result?.verdict === 'malicious').length,
      suspicious: es.filter((e) => e.result?.verdict === 'suspicious').length,
      highAbuse: es.filter((e) => (e.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75).length,
      changedSinceBaseline: es.filter((e) => e.check?.changed).length,
      autoOn: es.filter((e) => e.autoEnrich).length,
      topCountries: top(byCountry, 6),
      topOrgs: top(byOrg, 5),
      topCves: top(byCve, 8),
      surfaceChanges: surfaceChanges.slice(0, 20),
      riskThreatChanges: riskThreatChanges.slice(0, 20),
      hosts: es.slice(0, 30).map(host),
    };
  });

  const checkAts = list.map((e) => e.check?.at).filter((x): x is number => typeof x === 'number');
  const enrichAts = list.map((e) => e.lastEnrichAt).filter((x): x is number => typeof x === 'number');
  const staleEnrich = list.filter((e) => !e.lastEnrichAt || now - e.lastEnrichAt > 14 * day).map((e) => e.ip);
  const neverChecked = list.filter((e) => !e.check?.at).map((e) => e.ip);
  const byCountryAll = new Map<string, number>();
  for (const e of list) {
    const r = e.result;
    if (r) {
      const cc = countryOf(r);
      if (cc) byCountryAll.set(cc, (byCountryAll.get(cc) ?? 0) + 1);
    }
  }
  const spanStart = Math.min(...list.map((e) => (e.history?.length ? e.history[0].at : e.addedAt)));

  return {
    kind: 'ip-mon',
    tlp,
    totals: {
      monitored: list.length,
      live: list.filter((e) => e.live).length,
      withIntel: list.filter((e) => e.result).length,
      malicious: list.filter((e) => e.result?.verdict === 'malicious').length,
      suspicious: list.filter((e) => e.result?.verdict === 'suspicious').length,
      highAbuse: list.filter((e) => (e.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75).length,
      changedSinceBaseline: list.filter((e) => e.check?.changed).length,
      countries: byCountryAll.size,
      autoOn: list.filter((e) => e.autoEnrich).length,
      groups: ordered.length,
    },
    monitoringWindowDays: Number.isFinite(spanStart) ? Math.round((now - spanStart) / day) : 0,
    scanActivity: {
      lastCheckAt: checkAts.length ? Math.max(...checkAts) : undefined,
      lastEnrichAt: enrichAts.length ? Math.max(...enrichAts) : undefined,
      checkedCount: checkAts.length,
      staleEnrichCount: staleEnrich.length,
      staleEnrich: staleEnrich.slice(0, 20),
      neverCheckedCount: neverChecked.length,
      neverChecked: neverChecked.slice(0, 20),
    },
    geo: { topCountries: top(byCountryAll, 12) },
    groups,
    generatedAt: now,
  };
}

/** Ask the proxy's Claude for an IP-Mon operational report. `ok` is false for a message-only result
 *  (Claude unavailable / HTTP / network) so the caller can surface it WITHOUT saving it to history. */
async function fetchMonitorAssessment(
  settings: AppSettings,
  digest: unknown,
): Promise<{ ok: boolean; text: string; model?: string }> {
  if (!monitorSharingOn(settings)) {
    return {
      ok: false,
      text: 'IP-MONモニタリング・ダイジェストの生成には Claude（プロキシ接続）が必要です。Settings でプロキシURL＋アクセストークンを設定し、プロキシに ANTHROPIC_API_KEY を登録してください。',
    };
  }
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/monitor-assessment`, {
      method: 'POST',
      headers: { ...monitorAuth(settings), 'content-type': 'application/json' },
      body: JSON.stringify(digest),
    });
    if (!res.ok) {
      let detail = '';
      try {
        const j = (await res.json()) as { error?: string };
        if (j?.error) detail = ` — ${String(j.error).slice(0, 300)}`;
      } catch {
        /* non-JSON error body */
      }
      return { ok: false, text: `レポート生成に失敗しました（HTTP ${res.status}${detail}）。` };
    }
    const j = (await res.json()) as { text?: string; model?: string; error?: string };
    const text = j.text?.trim();
    if (text) return { ok: true, text, model: j.model };
    return { ok: false, text: j.error || 'レポートを生成できませんでした。' };
  } catch {
    return { ok: false, text: 'レポート生成に失敗しました（ネットワーク）。' };
  }
}

interface State {
  booted: boolean;
  session: Session | null;
  users: UserRecord[];
  settings: AppSettings;
  mode: Mode;
  /** Integrations reported by the proxy /health (live mode). null = demo / not yet checked. */
  health: ProxyHealth | null;

  rawInput: string;
  parsed: ParsedIndicator[];
  stats: ExtractStats | null;
  includeMap: Record<string, boolean>;
  parsing: boolean;

  results: Record<string, NormalizedResult>;
  order: string[];
  /** The order the detail panel's ‹ / › navigation steps through — the table's currently VISIBLE
   *  (sorted + filtered) row order, set by ResultsTable. Falls back to `order` when empty. */
  navOrder: string[];
  progress: { done: number; total: number; inflight: number; rateLimitedUntil: number | null } | null;
  running: boolean;
  error: string | null;
  selected: string | null;
  view: 'app' | 'admin' | 'monitor' | 'monitor-projects' | 'monitor-assessment' | 'analysis' | 'campaigns' | 'campaign' | 'campaign-analysis';
  /** IP whose enrichment-analysis page is open (view === 'analysis'). */
  analysisIp: string | null;
  /** Campaign IOC whose enrichment-analysis page is open (view === 'campaign-analysis'). */
  analysisCampaign: { id: string; value: string } | null;
  /** Which CP-Mon tab is active — kept in the store so it survives the Analysis round-trip. */
  campaignTab: 'dashboard' | 'attack' | 'target' | 'assessment';
  /** Switch the active CP-Mon tab. */
  setCampaignTab: (t: 'dashboard' | 'attack' | 'target' | 'assessment') => void;

  /** IP-Mon monitoring reports (Claude), newest first — continuous monitoring time-series. */
  monitorAssessments: CampaignAssessment[];
  /** Generate a fresh IP-Mon monitoring digest from the current watchlist (appends to the history). */
  assessMonitors: () => Promise<void>;
  /** Pull the team's shared IP-Mon report history and merge it into the local time-series (sharing on). */
  refreshMonitorAssessments: () => Promise<void>;
  /** A report generation is in flight (drives the button spinner). */
  monitorAssessing: boolean;
  /** Last generation error (Claude unavailable / network) — shown on the page; not saved to history. */
  monitorAssessError: string | null;
  /** Open the full-page IP-Mon monitoring report. */
  openMonitorAssessment: () => void;

  /** CP-Mon campaigns (attack-campaign-organised IOC watchlists), keyed by campaign id. */
  campaigns: Record<string, Campaign>;
  /** Selected campaign (view === 'campaign'). */
  campaignId: string | null;
  /** Last campaign-sync outcome (shown on the overview so a failed sync isn't mistaken for "empty"). */
  campaignsSyncNote: string | null;

  boot: () => Promise<void>;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;

  setRawInput: (s: string) => void;
  parse: () => void;
  smartParse: () => Promise<void>;
  toggleInclude: (key: string) => void;
  setAllIncluded: (included: boolean) => void;

  enrich: () => Promise<void>;
  stop: () => void;
  clearResults: () => void;
  select: (value: string | null) => void;
  /** Set the ‹ / › navigation order (the table's visible row order). */
  setNavOrder: (values: string[]) => void;
  /** Merge one result into the table (if absent) and open its detail — used by the monitor page. */
  showResult: (r: NormalizedResult) => void;
  restore: (results: NormalizedResult[], input: string) => void;

  setView: (v: 'app' | 'admin' | 'monitor' | 'monitor-projects' | 'monitor-assessment' | 'analysis' | 'campaigns' | 'campaign' | 'campaign-analysis') => void;
  /** Open the full-page enrichment analysis for one monitored IP. */
  openAnalysis: (ip: string) => void;
  /** Open the full-page enrichment analysis for one campaign IOC (its history timeline). */
  openCampaignAnalysis: (id: string, value: string) => void;
  applySettings: (s: AppSettings) => void;
  applyUsers: (u: UserRecord[]) => void;
  refreshHealth: () => Promise<void>;
  intel471Search: (ioc: string, type: EnrichableType) => Promise<Intel471Search>;
  intel471Malware: (uid: string, family?: string) => Promise<Intel471Malware>;
  cyfirmaSearch: (name: string) => Promise<CyfirmaSearch>;
  threatvisionAdversary: (name: string) => Promise<ThreatVisionAdversary>;
  socprimeQuery: (text: string, opts: SocPrimeQueryOptions) => Promise<SocPrimeQueryResult>;
  socprimeRules: (params: SocPrimeRuleSearchParams) => Promise<SocPrimeRuleSearchResult>;
  rfActor: (name: string) => Promise<RfActorProfile>;
  rfMalware: (ref: { id?: string; name?: string }) => Promise<RfMalwareProfile>;
  rfSandbox: (hash: string) => Promise<RfSandboxIntel>;
  rfRules: (params: RfRuleSearchParams) => Promise<RfRuleSearchResult>;
  urlscanSubmit: (url: string, visibility?: string) => Promise<UrlscanSubmission>;
  urlscanResult: (uuid: string) => Promise<UrlscanResult>;
  shodanInternetDb: (ip: string) => Promise<ShodanInternetDb>;
  shodanScan: (ip: string) => Promise<ShodanScanRequest>;
  shodanScanStatus: (id: string) => Promise<ShodanScanStatus>;
  shodanHost: (ip: string) => Promise<ShodanContext>;

  /** Background Shodan re-scan jobs, keyed by IP — survive closing the detail panel. */
  scanJobs: Record<string, ScanJob>;
  /** Kick a Shodan re-scan that polls to completion in the store (not the panel) + notifies. */
  startShodanRescan: (ip: string) => Promise<void>;
  /** Re-fetch the host banners for an IP (after a timeout / interrupted scan). */
  recheckShodanHost: (ip: string) => Promise<void>;
  /** Mark a finished scan's result as viewed (clears the header badge). */
  markScanSeen: (ip: string) => void;
  /** Remove one scan job from the tracker. */
  dismissScan: (ip: string) => void;
  /** Remove all finished scan jobs (keeps still-running ones). */
  clearFinishedScans: () => void;

  /** Background urlscan web captures (魚拓), keyed by target (URL/domain) — survive closing the detail panel. */
  webCaptures: Record<string, WebCaptureJob>;
  /** Kick a urlscan capture that submits + polls to completion in the store (not the panel). No-op if already active. */
  startWebCapture: (target: string, visibility?: string, opts?: { silent?: boolean; auto?: boolean }) => Promise<void>;
  /** Bulk 魚拓 a set of targets (staggered submits); logs ONE completion notification when the batch settles. */
  startWebCaptureBatch: (targets: string[], visibility?: string, label?: string) => Promise<void>;
  /** Mark a finished capture's result as viewed (clears "new" badges). */
  markCaptureSeen: (target: string) => void;
  /** Remove one capture job from the tracker. */
  dismissWebCapture: (target: string) => void;
  /** Remove all finished capture jobs (keeps still-running ones). */
  clearFinishedWebCaptures: () => void;
  /** Pull the shared 魚拓 histories (proxy KV) and merge them into local captures (team-wide sharing). */
  refreshCaptures: () => Promise<void>;

  /** In-app notification log (🔔) — completion events that survive navigating away. Newest first. */
  notifications: NotifItem[];
  /** Append a notification to the log AND fire an OS notification (unless muted). */
  notify: (n: { title: string; body?: string; kind: NotifKind }) => void;
  /** Mark all log entries read (clears the bell's unread badge). */
  markNotifsRead: () => void;
  /** Empty the notification log. */
  clearNotifs: () => void;

  /** Shodan Monitor watchlist (IPs + last vteeee enrichment snapshot), keyed by IP. */
  monitors: Record<string, MonitorEntry>;
  /** Register an IP to Shodan Monitor and snapshot its current enrichment. */
  addMonitor: (ip: string, result?: NormalizedResult, project?: string) => Promise<void>;
  /** Remove an IP from Shodan Monitor + the watchlist. */
  removeMonitor: (ip: string) => Promise<void>;
  /** Reconcile the watchlist against Shodan's server-side alert list. */
  refreshMonitors: () => Promise<void>;
  /** Re-run vteeee enrichment for a monitored IP and refresh its snapshot. */
  reEnrichMonitor: (ip: string) => Promise<void>;
  /** Re-observe a monitored IP on Shodan and diff it vs. the baseline (the "monitoring result"). */
  checkMonitor: (ip: string) => Promise<void>;
  /** Scan the monitoring GAPS now: Shodan re-check every IP with no/stale scan info, and re-enrich the
   *  ones with no/stale enrichment. Sequential (throttled). Returns how many IPs it scanned. */
  scanStaleMonitors: (staleDays?: number) => Promise<number>;
  /** True while scanStaleMonitors is draining the gap list (drives the report button state). */
  scanningGaps: boolean;
  /** Assign (or clear, when group is blank/undefined) a group label on the given monitored IPs. */
  setMonitorGroup: (ips: string[], group: string | undefined) => Promise<void>;

  // ---- IP-Mon PROJECTS (PJ) — top-level watchlist partitions (team-shared, like campaigns) ----
  /** Registered projects, keyed by id. */
  monitorProjects: Record<string, MonitorProject>;
  /** The PJ currently open in the scoped IP-Mon view: a project id, '__none__' (未分類), or null (All IPs). */
  monitorProjectId: string | null;
  /** Create a PJ (returns its id) + share. */
  createMonitorProject: (name: string) => Promise<string>;
  /** Rename a PJ + share. */
  renameMonitorProject: (id: string, name: string) => Promise<void>;
  /** Delete a PJ (its IPs fall back to 未分類 — they are NOT removed) + share. */
  deleteMonitorProject: (id: string) => Promise<void>;
  /** Assign the given IPs to a PJ (undefined = 未分類) + share. */
  setMonitorProject: (ips: string[], project: string | undefined) => Promise<void>;
  /** Pull the team's shared PJ registry and merge it in. */
  refreshMonitorProjects: () => Promise<void>;
  /** Open the PJ list/dashboard page. */
  openMonitorProjects: () => void;
  /** Open the scoped IP-Mon view for a PJ (id), 未分類 ('__none__'), or All (null). */
  openMonitorProject: (id: string | null) => void;
  /** One-time: move existing project-less watches into a single default PJ (renameable later). */
  migrateMonitorsToDefaultProject: () => void;
  /** IP-Mon group display order (local preference); groups not listed fall back to alphabetical. */
  monitorGroupOrder: string[];
  /** Move an IP-Mon group up/down in the display order. */
  reorderMonitorGroup: (group: string, dir: 'up' | 'down') => void;
  /** Turn the age-tiered auto re-enrich on/off for the given monitored IPs. */
  setAutoEnrich: (ips: string[], on: boolean) => Promise<void>;
  /** Run one pass of auto re-enrichment for any monitored IP that is "due" (called on an interval). */
  runAutoEnrichDue: () => Promise<void>;

  // ---- CP-Mon (campaigns) ----
  /** Create a campaign and return its id. */
  createCampaign: (name: string) => Promise<string>;
  renameCampaign: (id: string, name: string) => Promise<void>;
  removeCampaign: (id: string) => Promise<void>;
  /** Open the CP-Mon overview (list of campaigns). */
  openCampaigns: () => void;
  /** Open one campaign's detail page. */
  openCampaign: (id: string) => void;
  /** Add IOCs (any type) to a campaign, optionally under a group + side (attack/target), and enrich. */
  addCampaignIocs: (
    id: string,
    iocs: { value: string; type: EnrichableType }[],
    group?: string,
    side?: IocSide,
  ) => Promise<void>;
  /** Assign (or clear) a group label on IOCs within a campaign. */
  setCampaignIocGroup: (id: string, values: string[], group: string | undefined) => Promise<void>;
  /** Move IOCs between attack / target sides of the campaign. */
  setCampaignIocSide: (id: string, values: string[], side: IocSide) => Promise<void>;
  /** Set the campaign's TLP handling marking. */
  setCampaignTlp: (id: string, tlp: TlpLevel) => Promise<void>;
  /** Set the campaign's free-text analyst context / background note (shared; fed into the assessment). */
  setCampaignNote: (id: string, note: string) => Promise<void>;
  /** Set the campaign's Admiralty Code (source reliability A–F, info credibility 1–6). */
  setCampaignAdmiralty: (id: string, reliability: string, credibility: string) => Promise<void>;
  /** Move a group up/down in the campaign's display order. */
  reorderCampaignGroup: (id: string, group: string, dir: 'up' | 'down') => Promise<void>;
  /** Remove IOCs from a campaign. */
  removeCampaignIocs: (id: string, values: string[]) => Promise<void>;
  /** Re-enrich one IOC in a campaign (appends a timeline snapshot). */
  reEnrichCampaignIoc: (id: string, value: string) => Promise<void>;
  /** Re-enrich many campaign IOCs in one go (sequential; used for bulk / "un-enriched only"). */
  reEnrichCampaignIocs: (id: string, values: string[]) => Promise<void>;
  /** Turn auto re-enrich on/off for IOCs in a campaign. */
  setCampaignIocAuto: (id: string, values: string[], on: boolean) => Promise<void>;
  /** Pull the shared campaigns (KV) + two-way merge. */
  refreshCampaigns: () => Promise<void>;
  /** Merge an imported campaigns map (from a JSON backup / another device) into local + shared. */
  importCampaigns: (incoming: Record<string, Campaign>) => Promise<number>;
  /** Restore from the on-device backup taken before the last overwrite (recover an accidental wipe). */
  restoreCampaignsBackup: () => number;
  /** (Re)generate the campaign's Claude key-message summary (電光掲示板); shared with the campaign. */
  summarizeCampaign: (id: string) => Promise<void>;
  /** Generate a Claude CTI assessment report (context-based insight); shared with the campaign. */
  assessCampaign: (id: string) => Promise<void>;
}

function defaultIncludes(parsed: ParsedIndicator[]): Record<string, boolean> {
  const m: Record<string, boolean> = {};
  for (const i of parsed) m[indKey(i)] = i.type !== 'unknown' && !i.private;
  return m;
}

export const useStore = create<State>((set, get) => {
  // Patch a scan job with a token guard so a superseded poll loop can't clobber a newer one.
  const writeJob = (ip: string, token: number, started: number, patch: Partial<ScanJob>): void => {
    set((s) => {
      const cur = s.scanJobs[ip];
      // Block a superseded run's async writes — but let a fresh Re-check CLAIM a settled/parked job
      // (done/timeout/interrupted), whose stale token would otherwise reject the new run's first write.
      if (cur && cur.token != null && cur.token !== token && isActiveScan(cur)) return {};
      const m: Partial<ScanJob> = { ...cur, ...patch };
      const next: ScanJob = {
        ip,
        kind: 'shodan',
        phase: m.phase ?? 'submitting',
        status: m.status,
        msg: m.msg,
        startedAt: m.startedAt ?? started,
        updatedAt: Date.now(),
        creditsLeft: m.creditsLeft,
        host: m.host,
        error: m.error,
        seen: m.seen ?? false,
        token,
      };
      const scanJobs = { ...s.scanJobs, [ip]: next };
      saveScanJobs(scanJobs);
      return { scanJobs };
    });
  };

  // Patch a web-capture job with a token guard (same pattern as writeJob) so a superseded poll loop
  // can't clobber a newer capture of the same target.
  const writeCap = (target: string, token: number, started: number, patch: Partial<WebCaptureJob>): void => {
    set((s) => {
      const cur = s.webCaptures[target];
      // Block a superseded run's async writes — but let a fresh Re-check / Re-魚拓 CLAIM a settled/parked
      // job (done/stalled/interrupted), whose stale token would otherwise reject the new run's first write.
      if (cur && cur.token != null && cur.token !== token && isActiveCapture(cur)) return {};
      const m: Partial<WebCaptureJob> = { ...cur, ...patch };
      const next: WebCaptureJob = {
        target,
        phase: m.phase ?? 'submitting',
        uuid: m.uuid,
        visibility: m.visibility,
        msg: m.msg,
        startedAt: m.startedAt ?? started,
        updatedAt: Date.now(),
        result: m.result,
        error: m.error,
        seen: m.seen ?? false,
        token,
        history: m.history ?? cur?.history ?? [],
        // A fresh submit/run un-hides the target in the tracker; other patches keep the current flag.
        dismissed: m.phase === 'submitting' || m.phase === 'running' ? false : (m.dismissed ?? cur?.dismissed),
      };
      const webCaptures = { ...s.webCaptures, [target]: next };
      saveWebCaptures(webCaptures);
      return { webCaptures };
    });
  };

  return {
  booted: false,
  session: null,
  users: [],
  settings: { proxyBaseUrl: null, rpm: 4, concurrency: 1, gti: false, submitUnknown: false, shodan: true, maxmind: true, domaintools: true, dnslytics: true, intel471: true, cyfirma: true, threatvision: true, recordedfuture: true, abuseipdb: true, tlp: 'AMBER', urlscanVisibility: 'unlisted', shareMonitors: true },
  mode: 'demo',
  health: null,
  scanJobs: loadScanJobs(),
  webCaptures: loadWebCaptures(),
  notifications: loadNotifs(),
  monitors: loadMonitors(),
  monitorGroupOrder: loadMonitorGroupOrder(),
  scanningGaps: false,
  monitorProjects: loadMonitorProjects(),
  monitorProjectId: null,

  rawInput: '',
  parsed: [],
  stats: null,
  includeMap: {},
  parsing: false,

  results: {},
  order: [],
  navOrder: [],
  progress: null,
  running: false,
  error: null,
  selected: null,
  view: 'app',
  analysisIp: null,
  analysisCampaign: null,
  campaignTab: 'dashboard',
  monitorAssessments: loadMonitorAssessments(),
  monitorAssessing: false,
  monitorAssessError: null,
  campaigns: loadCampaigns(),
  campaignId: null,
  campaignsSyncNote: null,

  async boot() {
    void requestPersistentStorage(); // ask the browser not to evict our storage
    const [users, loaded] = await Promise.all([loadUsers(), loadSettings()]);
    // A "connect another device" link (#connect=…) auto-applies the proxy URL + token so this device
    // becomes Live and can see the shared watchlist; land on IP-Mon so the sync is immediately visible.
    const imported = consumeConnectLink(loaded);
    const settings = imported ?? loaded;
    set({
      users,
      settings,
      mode: resolveMode(settings),
      session: restoreSession(),
      booted: true,
      ...(imported ? { view: 'monitor' as const } : {}),
    });
    void get().refreshHealth();
    void get().refreshCaptures(); // pull the team's shared 魚拓 history (best-effort)
    void get().refreshMonitorAssessments(); // pull the team's shared IP-Mon report history (best-effort)
    void get().refreshMonitorProjects(); // pull the team's shared IP-Mon PJ registry (best-effort)
  },

  async login(username, password) {
    const session = await authenticate(get().users, username, password);
    if (!session) return false;
    persistSession(session);
    set({ session });
    return true;
  },

  logout() {
    persistSession(null);
    set({ session: null, view: 'app' });
  },

  setRawInput(s) {
    set({ rawInput: s });
  },

  parse() {
    const { indicators, stats } = extractIndicators(get().rawInput);
    set({ parsed: indicators, stats, includeMap: defaultIncludes(indicators) });
  },

  async smartParse() {
    set({ parsing: true, error: null });
    try {
      const client = await makeClient(get().settings);
      const indicators = await client.smartParse(get().rawInput);
      set({
        parsed: indicators,
        stats: {
          total: indicators.length,
          unique: indicators.length,
          duplicates: 0,
          unknown: indicators.filter((i) => i.type === 'unknown').length,
          private: indicators.filter((i) => i.private).length,
          enrichable: indicators.filter((i) => i.type !== 'unknown' && !i.private).length,
        },
        includeMap: defaultIncludes(indicators),
      });
    } catch (e) {
      set({ error: `Smart parse failed: ${(e as Error).message}` });
    } finally {
      set({ parsing: false });
    }
  },

  toggleInclude(key) {
    set((s) => ({ includeMap: { ...s.includeMap, [key]: !s.includeMap[key] } }));
  },

  setAllIncluded(included) {
    set((s) => {
      const m: Record<string, boolean> = {};
      for (const i of s.parsed) m[indKey(i)] = included && i.type !== 'unknown';
      return { includeMap: m };
    });
  },

  async enrich() {
    const { parsed, includeMap, settings } = get();
    const indicators = parsed
      .filter((i) => i.type !== 'unknown' && includeMap[indKey(i)])
      .map((i) => ({ value: i.value, type: i.type as EnrichableType, input: i.input }));
    if (!indicators.length) {
      set({ error: 'No indicators selected for enrichment.' });
      return;
    }

    let client: EnrichClient;
    try {
      client = await makeClient(settings);
    } catch (e) {
      set({ error: (e as Error).message });
      return;
    }

    abortController = new AbortController();
    const options: EnrichOptions = {
      rpm: settings.rpm,
      concurrency: settings.concurrency,
      includeRaw: true,
      gti: settings.gti,
      submitUnknown: settings.submitUnknown,
      shodan: settings.shodan ?? true,
      maxmind: settings.maxmind ?? true,
      domaintools: settings.domaintools ?? true,
      dnslytics: settings.dnslytics ?? true,
      intel471: settings.intel471 ?? true,
      cyfirma: settings.cyfirma ?? true,
      threatvision: settings.threatvision ?? true,
      recordedfuture: settings.recordedfuture ?? true,
      abuseipdb: settings.abuseipdb ?? true,
    };
    set({
      running: true,
      error: null,
      results: {},
      order: [],
      selected: null,
      progress: { done: 0, total: indicators.length, inflight: 0, rateLimitedUntil: null },
    });

    await client.enrich(
      { indicators, options },
      {
        signal: abortController.signal,
        onProgress: (p) => set({ progress: p }),
        onResult: (r) =>
          set((s) => ({
            results: { ...s.results, [r.value]: r },
            order: s.order.includes(r.value) ? s.order : [...s.order, r.value],
          })),
        onDone: () => {
          set({ running: false });
          const s = get();
          const out = s.order.map((v) => s.results[v]).filter(Boolean);
          if (out.length) {
            const rec: HistoryRecord = {
              id: Math.random().toString(36).slice(2) + Date.now().toString(36),
              createdAt: Date.now(),
              mode: s.mode,
              input: s.rawInput,
              stats:
                s.stats ?? {
                  total: out.length,
                  unique: out.length,
                  duplicates: 0,
                  unknown: 0,
                  private: 0,
                  enrichable: out.length,
                },
              results: out,
            };
            void saveHistory(rec, s.settings, s.session);
          }

          // If the batch re-investigated any IP that's already on the watchlist, refresh its saved
          // snapshot and share it — so re-checking a monitored IP from the MAIN search (on any device)
          // updates the team watchlist exactly like IP-Mon's "Re-enrich". Only successful enrichments
          // overwrite the snapshot (a not_found/error must not wipe a good one). Shared per-entry and
          // sequentially so concurrent finishes don't clobber the shared blob.
          const monitoredHits = out.filter(
            (r) =>
              (r.type === 'ipv4' || r.type === 'ipv6') &&
              r.status === 'success' &&
              s.monitors[r.value],
          );
          if (monitoredHits.length) {
            const by = s.session?.username;
            const at = Date.now();
            set((st) => {
              const monitors = { ...st.monitors };
              for (const r of monitoredHits) {
                const cur = monitors[r.value];
                if (cur)
                  monitors[r.value] = {
                    ...cur,
                    result: r,
                    history: appendSnapshot(seedHistory(cur), { at, by, result: r }, at),
                    updatedAt: at,
                    lastEnrichAt: at,
                  };
              }
              saveMonitors(monitors);
              return { monitors };
            });
            void (async () => {
              const st = get();
              for (const r of monitoredHits) {
                await pushSharedMonitorEntry(st.settings, r.value, st.monitors[r.value] ?? null);
              }
            })();
          }
        },
        onError: (m) => set({ error: m, running: false }),
      },
    );
  },

  stop() {
    abortController?.abort();
    set({ running: false });
  },

  clearResults() {
    set({ results: {}, order: [], progress: null, selected: null });
  },

  select(value) {
    set({ selected: value });
  },

  setNavOrder(values) {
    set({ navOrder: values });
  },

  showResult(r) {
    // Open its detail as an overlay WITHOUT changing the view (so opening from IP-Mon/CP-Mon keeps you
    // there). Make the result available to the detail panel via `results[value]`, but do NOT add it to
    // `order` — otherwise IP-Mon/CP-Mon IOCs you merely opened would pile up in the main search table.
    // Past searches are recoverable from History; the main table only shows what was actually searched.
    set((s) => ({
      results: { ...s.results, [r.value]: r },
      selected: r.value,
    }));
  },

  restore(results, input) {
    const map: Record<string, NormalizedResult> = {};
    const order: string[] = [];
    for (const r of results) {
      if (!map[r.value]) order.push(r.value);
      map[r.value] = r;
    }
    set({ results: map, order, selected: null, progress: null, running: false, view: 'app', rawInput: input });
  },

  setView(v) {
    set({ view: v });
  },

  openAnalysis(ip) {
    set({ analysisIp: ip, view: 'analysis' });
  },

  openCampaignAnalysis(id, value) {
    set({ analysisCampaign: { id, value }, view: 'campaign-analysis' });
  },

  applySettings(s) {
    saveSettings(s);
    set({ settings: s, mode: resolveMode(s) });
    void get().refreshHealth();
  },

  applyUsers(u) {
    saveUsers(u);
    set({ users: u });
  },

  async refreshHealth() {
    const base = get().settings.proxyBaseUrl?.replace(/\/$/, '');
    if (!base) {
      set({ health: null }); // demo mode — no proxy to query
      return;
    }
    try {
      const res = await fetch(`${base}/health`, { cache: 'no-store' });
      if (!res.ok) {
        set({ health: { ok: false, vtKey: false, claude: false, shodan: false, maxmind: false, domaintools: false, dnslytics: false, intel471: false, cyfirma: false, threatvision: false, socprime: false, recordedfuture: false, urlscan: false, abuseipdb: false } });
        return;
      }
      const h = (await res.json()) as Partial<ProxyHealth>;
      set({
        health: {
          ok: Boolean(h.ok),
          vtKey: Boolean(h.vtKey),
          claude: Boolean(h.claude),
          shodan: Boolean(h.shodan),
          maxmind: Boolean(h.maxmind),
          domaintools: Boolean(h.domaintools),
          dnslytics: Boolean(h.dnslytics),
          intel471: Boolean(h.intel471),
          cyfirma: Boolean(h.cyfirma),
          threatvision: Boolean(h.threatvision),
          socprime: Boolean(h.socprime),
          recordedfuture: Boolean(h.recordedfuture),
          urlscan: Boolean(h.urlscan),
          abuseipdb: Boolean(h.abuseipdb),
        },
      });
    } catch {
      set({ health: { ok: false, vtKey: false, claude: false, shodan: false, maxmind: false, domaintools: false, dnslytics: false, intel471: false, cyfirma: false, threatvision: false, socprime: false, recordedfuture: false, urlscan: false, abuseipdb: false } });
    }
  },

  async intel471Search(ioc, type) {
    try {
      const client = await makeClient(get().settings);
      return await client.intel471Search(ioc, type);
    } catch (e) {
      return { error: (e as Error).message };
    }
  },

  async intel471Malware(uid, family) {
    try {
      const client = await makeClient(get().settings);
      return await client.intel471Malware(uid, family);
    } catch (e) {
      return { error: (e as Error).message };
    }
  },

  async cyfirmaSearch(name) {
    try {
      const client = await makeClient(get().settings);
      return await client.cyfirmaSearch(name);
    } catch (e) {
      return { error: (e as Error).message };
    }
  },

  async threatvisionAdversary(name) {
    try {
      const client = await makeClient(get().settings);
      return await client.threatvisionAdversary(name);
    } catch (e) {
      return { error: (e as Error).message };
    }
  },

  async socprimeQuery(text, opts) {
    try {
      const client = await makeClient(get().settings);
      return await client.socprimeQuery(text, opts);
    } catch (e) {
      return { error: (e as Error).message };
    }
  },

  async socprimeRules(params) {
    try {
      const client = await makeClient(get().settings);
      return await client.socprimeRules(params);
    } catch (e) {
      return { error: (e as Error).message };
    }
  },

  async rfActor(name) {
    try {
      const client = await makeClient(get().settings);
      return await client.rfActor(name);
    } catch (e) {
      return { error: (e as Error).message };
    }
  },

  async rfMalware(ref) {
    try {
      const client = await makeClient(get().settings);
      return await client.rfMalware(ref);
    } catch (e) {
      return { error: (e as Error).message };
    }
  },

  async rfSandbox(hash) {
    try {
      const client = await makeClient(get().settings);
      return await client.rfSandbox(hash);
    } catch (e) {
      return { error: (e as Error).message };
    }
  },

  async rfRules(params) {
    try {
      const client = await makeClient(get().settings);
      return await client.rfRules(params);
    } catch (e) {
      return { error: (e as Error).message };
    }
  },

  async urlscanSubmit(url, visibility) {
    try {
      const client = await makeClient(get().settings);
      return await client.urlscanSubmit(url, visibility);
    } catch (e) {
      return { error: (e as Error).message };
    }
  },

  async urlscanResult(uuid) {
    try {
      const client = await makeClient(get().settings);
      return await client.urlscanResult(uuid);
    } catch (e) {
      return { uuid, error: (e as Error).message };
    }
  },

  async shodanInternetDb(ip) {
    try {
      const client = await makeClient(get().settings);
      return await client.shodanInternetDb(ip);
    } catch (e) {
      return { found: false, error: (e as Error).message };
    }
  },

  async shodanScan(ip) {
    try {
      const client = await makeClient(get().settings);
      return await client.shodanScan(ip);
    } catch (e) {
      return { error: (e as Error).message };
    }
  },

  async shodanScanStatus(id) {
    try {
      const client = await makeClient(get().settings);
      return await client.shodanScanStatus(id);
    } catch (e) {
      return { id, error: (e as Error).message };
    }
  },

  async shodanHost(ip) {
    try {
      const client = await makeClient(get().settings);
      return await client.shodanHost(ip);
    } catch (e) {
      return { found: false, error: (e as Error).message };
    }
  },

  async startShodanRescan(ip) {
    const existing = get().scanJobs[ip];
    if (existing && isActiveScan(existing)) return; // a scan for this IP is already running
    const token = Date.now() + Math.random();
    const started = Date.now();
    const alive = () => get().scanJobs[ip]?.token === token;
    const wait = (ms: number) => new Promise((res) => setTimeout(res, ms));
    maybeRequestNotify(); // the button click is a user gesture, so we may ask for notification permission
    writeJob(ip, token, started, {
      phase: 'submitting',
      msg: 'Requesting a Shodan re-scan…',
      status: undefined,
      host: undefined,
      error: undefined,
      seen: false,
    });
    let client: EnrichClient;
    try {
      client = await makeClient(get().settings);
    } catch (e) {
      writeJob(ip, token, started, { phase: 'error', msg: (e as Error).message });
      return;
    }

    // Baseline: the host record's current lastUpdate. We treat the scan as complete when this
    // CHANGES (plain string compare, so Shodan's timezone-ambiguous timestamps don't matter). This is
    // far more reliable than waiting for the scan-status endpoint to report DONE — on-demand scans
    // frequently sit in QUEUE/PROCESSING for many minutes, which is why the old 2-min DONE-wait never
    // succeeded.
    let baseline: string | undefined;
    try {
      baseline = (await client.shodanHost(ip)).lastUpdate;
    } catch {
      /* ignore — treat as no baseline */
    }
    if (!alive()) return;

    const req = await client.shodanScan(ip);
    if (!alive()) return;
    if (req.error || !req.id) {
      writeJob(ip, token, started, { phase: 'error', msg: req.error ?? 'Shodan did not accept the scan (no id returned)' });
      return;
    }
    const credits = req.creditsLeft;
    const id = req.id;

    // On-demand scans can take many minutes — poll (in the background) for up to ~15 min.
    const deadline = started + 15 * 60 * 1000;
    let iter = 0;
    let lastHostCheck = 0;
    while (Date.now() < deadline) {
      const secs = Math.round((Date.now() - started) / 1000);
      writeJob(ip, token, started, {
        phase: 'scanning',
        creditsLeft: credits,
        msg: `Scanning… ${secs}s (Shodan on-demand scans can take several minutes)`,
      });
      await wait(iter < 6 ? 8000 : 15000); // quick for the first ~48s, then every 15s
      iter++;
      if (!alive()) return;

      // Progress only — the scan-status endpoint is unreliable, so a failure here is non-fatal.
      let statusDone = false;
      try {
        const st = await client.shodanScanStatus(id);
        if (!alive()) return;
        const s = (st.status ?? '').toUpperCase();
        statusDone = s === 'DONE';
        writeJob(ip, token, started, {
          phase: 'scanning',
          status: s || undefined,
          creditsLeft: credits,
          msg: `Scanning… ${Math.round((Date.now() - started) / 1000)}s${s ? ` · ${s}` : ''}`,
        });
      } catch {
        /* keep going — the host-change check below is authoritative */
      }

      // Authoritative completion: has the host record actually been refreshed? Check on DONE, and
      // otherwise every ~40s (host lookups cost a query credit, so we don't hammer it).
      if (statusDone || Date.now() - lastHostCheck > 40000) {
        lastHostCheck = Date.now();
        writeJob(ip, token, started, {
          phase: 'fetching',
          creditsLeft: credits,
          msg: `Checking for fresh banners… ${Math.round((Date.now() - started) / 1000)}s`,
        });
        const host = await client.shodanHost(ip);
        if (!alive()) return;
        if (host.found && host.lastUpdate && host.lastUpdate !== baseline) {
          writeJob(ip, token, started, { phase: 'done', creditsLeft: credits, host, seen: false, msg: undefined });
          get().notify({ title: 'Shodan re-scan complete', body: `${ip}${host.ports?.length ? ` · ports ${host.ports.slice(0, 8).join(', ')}` : ''}`, kind: 'scan' });
          return;
        }
      }
    }
    writeJob(ip, token, started, {
      phase: 'timeout',
      creditsLeft: credits,
      msg: 'Shodan has not refreshed this host within ~15 min — the scan may still be queued. Re-check later.',
    });
    get().notify({ title: 'Shodan re-scan still pending', body: `${ip} — not refreshed yet; re-check later.`, kind: 'scan' });
  },

  async recheckShodanHost(ip) {
    const token = Date.now() + Math.random();
    const started = get().scanJobs[ip]?.startedAt ?? Date.now();
    writeJob(ip, token, started, { phase: 'fetching', msg: 'Fetching the latest Shodan banners…', error: undefined });
    let client: EnrichClient;
    try {
      client = await makeClient(get().settings);
    } catch (e) {
      writeJob(ip, token, started, { phase: 'error', msg: (e as Error).message });
      return;
    }
    const host = await client.shodanHost(ip);
    if (get().scanJobs[ip]?.token !== token) return;
    if (host.error) {
      writeJob(ip, token, started, { phase: 'error', msg: host.error });
    } else {
      writeJob(ip, token, started, { phase: 'done', host, seen: false, msg: undefined });
      get().notify({ title: 'Shodan banners updated', body: `${ip}${host.ports?.length ? ` · ports ${host.ports.slice(0, 8).join(', ')}` : ''}`, kind: 'scan' });
    }
  },

  markScanSeen(ip) {
    set((s) => {
      const cur = s.scanJobs[ip];
      if (!cur || cur.seen) return {};
      const scanJobs = { ...s.scanJobs, [ip]: { ...cur, seen: true } };
      saveScanJobs(scanJobs);
      return { scanJobs };
    });
  },

  dismissScan(ip) {
    set((s) => {
      if (!s.scanJobs[ip]) return {};
      const scanJobs = { ...s.scanJobs };
      delete scanJobs[ip];
      saveScanJobs(scanJobs);
      return { scanJobs };
    });
  },

  clearFinishedScans() {
    set((s) => {
      const scanJobs: Record<string, ScanJob> = {};
      for (const [k, v] of Object.entries(s.scanJobs)) if (isActiveScan(v)) scanJobs[k] = v;
      saveScanJobs(scanJobs);
      return { scanJobs };
    });
  },

  async startWebCapture(target, visibility, opts) {
    const existing = get().webCaptures[target];
    if (existing && isActiveCapture(existing)) return; // a capture for this target is already running
    const silent = opts?.silent ?? false; // a bulk batch fires ONE summary instead of per-item notifs
    const token = Date.now() + Math.random();
    const started = existing?.startedAt ?? Date.now();
    const vis = visibility ?? get().settings.urlscanVisibility ?? 'unlisted';
    const alive = () => get().webCaptures[target]?.token === token;
    const wait = (ms: number) => new Promise((res) => setTimeout(res, ms));
    // Resume path: a stalled / interrupted job already has a uuid — never re-submit (that wastes a
    // scan and orphans the original), just keep polling for the same uuid's result. A fresh Re-魚拓
    // (done / error / no job) always submits anew.
    const resumable = Boolean(existing && (existing.phase === 'stalled' || existing.phase === 'interrupted') && existing.uuid);
    // Claim the target synchronously — BEFORE the async client import — so the tap gives instant feedback
    // (live dot, the Re-check button flips) even on mobile or right after a reload, when the client chunk
    // isn't cached yet and makeClient() takes a moment. Without this the tap looks dead until it resolves.
    writeCap(
      target,
      token,
      started,
      resumable
        ? { phase: 'running', visibility: vis, msg: 'urlscan の結果を再確認中…', error: undefined, seen: false }
        : { phase: 'submitting', visibility: vis, msg: '魚拓を準備中…', uuid: undefined, result: undefined, error: undefined, seen: false },
    );
    maybeRequestNotify(); // the button click is a user gesture, so we may ask for notification permission

    let client: EnrichClient;
    try {
      client = await makeClient(get().settings);
    } catch (e) {
      if (!alive()) return;
      writeCap(target, token, started, { phase: 'error', error: (e as Error).message, msg: (e as Error).message });
      return;
    }
    if (!alive()) return; // a newer run claimed this target while the client chunk loaded

    let uuid = resumable ? existing?.uuid : undefined;
    if (!uuid) {
      writeCap(target, token, started, {
        phase: 'submitting',
        visibility: vis,
        msg: 'urlscan に魚拓を送信中…',
        uuid: undefined,
        result: undefined,
        error: undefined,
        seen: false,
      });
      const sub = await client.urlscanSubmit(target, vis);
      if (!alive()) return;
      if (sub.error || !sub.uuid) {
        writeCap(target, token, started, {
          phase: 'error',
          error: sub.error ?? 'urlscan did not return a scan id',
          msg: sub.error ?? 'urlscan が受け付けませんでした',
        });
        return;
      }
      uuid = sub.uuid;
      writeCap(target, token, started, { phase: 'running', uuid, visibility: sub.visibility ?? vis, msg: 'urlscan でレンダリング中…' });
    } else {
      writeCap(target, token, started, { phase: 'running', uuid, msg: 'urlscan の結果を確認中…', error: undefined });
    }

    // Poll the result until it materializes. urlscan queues scans — a busy/slow site can take over a
    // minute, and the result 404s / reports `pending` until it's ready — so poll patiently, then park
    // in `stalled` (re-runnable — it resumes THIS uuid, never re-submits).
    for (let i = 0; i < 30; i++) {
      await wait(i === 0 ? 5000 : 4000);
      if (!alive()) return;
      const elapsed = Math.round((Date.now() - started) / 1000);
      writeCap(target, token, started, { phase: 'running', uuid, msg: `urlscan でレンダリング中… ${elapsed}s` });
      const result = await client.urlscanResult(uuid);
      if (!alive()) return;
      if (result.error) {
        writeCap(target, token, started, { phase: 'error', uuid, error: result.error, msg: result.error, result });
        return;
      }
      if (!result.pending) {
        // Append to this target's history (never overwrite) and share the snapshot team-wide.
        const slim = slimCaptureResult(result);
        // Auto-魚拓 is system-initiated — tag it as ⚡auto in the execution log (vs a person's username).
        const capBy = opts?.auto ? '⚡auto' : get().session?.username;
        const entry: WebCaptureEntry = { uuid: uuid!, at: Date.now(), by: capBy, visibility: vis, result: slim };
        const history = mergeCaptureEntries([entry], get().webCaptures[target]?.history ?? []);
        writeCap(target, token, started, { phase: 'done', uuid, result: slim, history, seen: false, msg: undefined, error: undefined });
        if (!silent) get().notify({ title: '魚拓が完了しました', body: `${target}${result.malicious ? ' · ⚠ malicious' : ''}`, kind: 'capture' });
        void pushSharedCapture(get().settings, target, history);
        return;
      }
    }
    writeCap(target, token, started, {
      phase: 'stalled',
      uuid,
      msg: `urlscan がまだレンダリング中です（~${Math.round((Date.now() - started) / 1000)}s）— 混雑/低速サイトは時間がかかります。「再確認」で続行できます。`,
    });
    if (!silent) get().notify({ title: '魚拓がまだ保留中です', body: `${target} — まだ完了していません。後で再確認してください。`, kind: 'capture' });
  },

  async startWebCaptureBatch(targets, visibility, label) {
    const uniq = [...new Set(targets)].filter(Boolean);
    if (!uniq.length) return;
    const wait = (ms: number) => new Promise((res) => setTimeout(res, ms));
    // Kick each capture (each runs its own background poll in the store). Stagger the SUBMITS a little
    // so urlscan's submission rate limit isn't tripped; run them silently so we can fire ONE summary.
    const proms: Promise<void>[] = [];
    for (const t of uniq) {
      proms.push(get().startWebCapture(t, visibility, { silent: true }));
      await wait(1500);
    }
    await Promise.all(proms);
    // Summarize the batch from the store's final state and log ONE completion notification — naming the
    // actual targets (which are malicious / pending) and the source (campaign · side) so it's actionable.
    const caps = get().webCaptures;
    const short = (t: string) => t.replace(/^https?:\/\//, '');
    const sample = (arr: string[]) =>
      arr.length ? ` [${arr.slice(0, 3).map(short).join(', ')}${arr.length > 3 ? ` …他${arr.length - 3}` : ''}]` : '';
    const done = uniq.filter((t) => caps[t]?.phase === 'done');
    const malT = done.filter((t) => caps[t]?.result?.malicious);
    const pendingT = uniq.filter((t) => {
      const p = caps[t]?.phase;
      return p === 'stalled' || p === 'error' || p === 'interrupted';
    });
    get().notify({
      title: `一括魚拓 完了${label ? `：${label}` : ''}`,
      body:
        `${done.length}/${uniq.length} 件完了` +
        (malT.length ? ` · ⚠悪性 ${malT.length}${sample(malT)}` : '') +
        (pendingT.length ? ` · 保留/失敗 ${pendingT.length}${sample(pendingT)}` : ''),
      kind: 'capture',
    });
  },

  notify(n) {
    set((s) => {
      const item: NotifItem = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        at: Date.now(),
        title: n.title,
        body: n.body,
        kind: n.kind,
        read: false,
      };
      const notifications = [item, ...s.notifications].slice(0, NOTIF_MAX);
      saveNotifs(notifications);
      return { notifications };
    });
    browserNotify(n.title, n.body ?? '', `vteeee-notif-${n.kind}`);
  },

  markNotifsRead() {
    set((s) => {
      if (!s.notifications.some((n) => !n.read)) return {};
      const notifications = s.notifications.map((n) => (n.read ? n : { ...n, read: true }));
      saveNotifs(notifications);
      return { notifications };
    });
  },

  clearNotifs() {
    set(() => {
      saveNotifs([]);
      return { notifications: [] };
    });
  },

  markCaptureSeen(target) {
    set((s) => {
      const cur = s.webCaptures[target];
      if (!cur || cur.seen) return {};
      const webCaptures = { ...s.webCaptures, [target]: { ...cur, seen: true } };
      saveWebCaptures(webCaptures);
      return { webCaptures };
    });
  },

  dismissWebCapture(target) {
    // Hide from the tracker log ONLY — the capture + its 魚拓 history are kept (per-row 済/過去 + Tr分析).
    set((s) => {
      const cur = s.webCaptures[target];
      if (!cur || cur.dismissed) return {};
      const webCaptures = { ...s.webCaptures, [target]: { ...cur, dismissed: true } };
      saveWebCaptures(webCaptures);
      return { webCaptures };
    });
  },

  clearFinishedWebCaptures() {
    // "Clear finished" is a LOG action: it hides finished entries from the tracker but never deletes
    // the 魚拓 URLs/history (those stay on the rows, the shared timeline and Tr-Analysis).
    set((s) => {
      const webCaptures = { ...s.webCaptures };
      let changed = false;
      for (const [k, v] of Object.entries(s.webCaptures)) {
        if (!isActiveCapture(v) && !v.dismissed) {
          webCaptures[k] = { ...v, dismissed: true };
          changed = true;
        }
      }
      if (!changed) return {};
      saveWebCaptures(webCaptures);
      return { webCaptures };
    });
  },

  async refreshCaptures() {
    const remote = await fetchSharedCaptures(get().settings);
    if (!remote) return;
    set((s) => {
      const webCaptures = { ...s.webCaptures };
      for (const [target, remoteHist] of Object.entries(remote)) {
        if (!Array.isArray(remoteHist) || !remoteHist.length) continue;
        const cur = webCaptures[target];
        const history = mergeCaptureEntries(cur?.history ?? [], remoteHist);
        if (!history.length) continue;
        if (cur) {
          // Don't disturb an in-flight capture — just merge the history. For an idle/finished job,
          // surface the latest snapshot (keep an error/stalled/interrupted affordance intact).
          const keepPhase =
            isActiveCapture(cur) || cur.phase === 'error' || cur.phase === 'stalled' || cur.phase === 'interrupted';
          webCaptures[target] = {
            ...cur,
            history,
            ...(keepPhase ? {} : { phase: 'done', result: history[0].result, uuid: history[0].uuid }),
          };
        } else {
          const latest = history[0];
          webCaptures[target] = {
            target,
            phase: 'done',
            uuid: latest.uuid,
            visibility: latest.visibility,
            msg: undefined,
            startedAt: latest.at,
            updatedAt: latest.at,
            result: latest.result,
            error: undefined,
            seen: true, // pulled from the shared timeline — not a "new" local completion
            history,
          };
        }
      }
      saveWebCaptures(webCaptures);
      return { webCaptures };
    });
  },

  async addMonitor(ip, result, project) {
    const now = Date.now();
    const by = get().session?.username;
    const openPj = get().monitorProjectId;
    // Explicit project wins; else keep any existing assignment; else inherit the open PJ (a real id).
    const proj = project ?? get().monitors[ip]?.project ?? (openPj && openPj !== '__none__' ? openPj : undefined);
    set((s) => {
      const cur = s.monitors[ip];
      const monitors = {
        ...s.monitors,
        [ip]: {
          ip,
          project: proj,
          addedAt: cur?.addedAt ?? now,
          updatedAt: now,
          result: result ?? cur?.result,
          history: result ? appendSnapshot(cur?.history, { at: now, by, result }, now) : cur?.history,
          lastEnrichAt: result ? now : cur?.lastEnrichAt,
          live: cur?.live,
          alertId: cur?.alertId,
          triggers: cur?.triggers,
          baseline:
            cur?.baseline ??
            (result?.shodan
              ? { ports: result.shodan.ports ?? [], vulns: result.shodan.vulns ?? [], lastUpdate: result.shodan.lastUpdate }
              : undefined),
          check: cur?.check,
          note: 'Registering with Shodan Monitor…',
          error: undefined,
        } as MonitorEntry,
      };
      saveMonitors(monitors);
      return { monitors };
    });
    let res;
    try {
      const client = await makeClient(get().settings);
      res = await client.shodanMonitorAdd(ip);
    } catch (e) {
      res = { error: (e as Error).message };
    }
    set((s) => {
      const cur = s.monitors[ip];
      if (!cur) return {};
      const e = res.entries?.[0];
      const monitors = {
        ...s.monitors,
        [ip]: {
          ...cur,
          live: res.error ? false : true,
          alertId: e?.id ?? cur.alertId,
          triggers: e?.triggers ?? cur.triggers,
          note: undefined,
          error: res.error,
          updatedAt: Date.now(),
        },
      };
      saveMonitors(monitors);
      return { monitors };
    });
    void pushSharedMonitorEntry(get().settings, ip, get().monitors[ip] ?? null);
  },

  async removeMonitor(ip) {
    try {
      const client = await makeClient(get().settings);
      await client.shodanMonitorRemove(ip);
    } catch {
      /* best effort — still drop it locally */
    }
    set((s) => {
      if (!s.monitors[ip]) return {};
      const monitors = { ...s.monitors };
      delete monitors[ip];
      saveMonitors(monitors);
      return { monitors };
    });
    void pushSharedMonitorEntry(get().settings, ip, null);
  },

  async refreshMonitors() {
    const demo = get().mode === 'demo';
    // Pull the team-shared watchlist (KV) — this is what gives an analyst the admin's snapshots.
    const shared = await fetchSharedMonitors(get().settings);
    let list: ReadonlyArray<{ ip?: string; id?: string; triggers?: string[] }> | null = null;
    try {
      const client = await makeClient(get().settings);
      const res = await client.shodanMonitorList();
      if (!res.error) list = res.entries ?? [];
    } catch {
      /* Shodan Monitor list unavailable — still merge the shared snapshots below */
    }
    set((s) => {
      // Two-way merge: union local + shared, keeping the snapshot from whichever side has one.
      const keys = new Set([...Object.keys(s.monitors), ...Object.keys(shared ?? {})]);
      const monitors: Record<string, MonitorEntry> = {};
      for (const ip of keys) monitors[ip] = mergeEntry(s.monitors[ip], shared?.[ip]);
      if (list) {
        const serverIps = new Set(list.map((e) => e.ip).filter(Boolean) as string[]);
        for (const e of list) {
          if (!e.ip) continue;
          const cur = monitors[e.ip];
          monitors[e.ip] = {
            ...(cur ?? { ip: e.ip, addedAt: Date.now() }),
            ip: e.ip,
            updatedAt: Date.now(),
            alertId: e.id ?? cur?.alertId,
            live: true,
            triggers: e.triggers ?? cur?.triggers,
            note: undefined,
            error: undefined,
          } as MonitorEntry;
        }
        // In live mode, an entry no longer on Shodan's list isn't actually monitored anymore.
        if (!demo) for (const [k, v] of Object.entries(monitors)) if (!serverIps.has(k)) monitors[k] = { ...v, live: false };
      }
      saveMonitors(monitors);
      return { monitors };
    });
    // Upload the merged view so local-only snapshots (e.g. added before sharing existed) reach the team.
    if (shared !== null) void putSharedMonitorsAll(get().settings, get().monitors);
  },

  async reEnrichMonitor(ip) {
    set((s) => {
      const cur = s.monitors[ip];
      if (!cur) return {};
      return { monitors: { ...s.monitors, [ip]: { ...cur, enriching: true } } };
    });
    let result: NormalizedResult | undefined;
    try {
      result = await enrichOneIp(get().settings, ip);
    } catch {
      /* leave the previous snapshot */
    }
    const by = get().session?.username;
    const at = Date.now();
    set((s) => {
      const cur = s.monitors[ip];
      if (!cur) return {};
      // Append to the timeline (deduped by state) instead of throwing the previous enrichment away.
      // Seed the pre-existing snapshot first so a forced re-enrich always has a "vs previous" baseline.
      const history = result ? appendSnapshot(seedHistory(cur), { at, by, result }, at) : cur.history;
      const monitors = {
        ...s.monitors,
        [ip]: { ...cur, enriching: false, result: result ?? cur.result, history, updatedAt: at, lastEnrichAt: at },
      };
      saveMonitors(monitors);
      return { monitors };
    });
    void pushSharedMonitorEntry(get().settings, ip, get().monitors[ip] ?? null);
  },

  async checkMonitor(ip) {
    set((s) => {
      const cur = s.monitors[ip];
      if (!cur) return {};
      return { monitors: { ...s.monitors, [ip]: { ...cur, checking: true } } };
    });
    let host: ShodanContext;
    try {
      const client = await makeClient(get().settings);
      host = await client.shodanHost(ip);
    } catch (e) {
      host = { found: false, error: (e as Error).message };
    }
    set((s) => {
      const cur = s.monitors[ip];
      if (!cur) return {};
      // Establish a baseline on first check if we never captured one (e.g. added without enrichment).
      const baseline = cur.baseline ?? { ports: host.ports ?? [], vulns: host.vulns ?? [], lastUpdate: host.lastUpdate };
      const basePorts = new Set(baseline.ports ?? []);
      const baseVulns = new Set(baseline.vulns ?? []);
      const curPorts = host.ports ?? [];
      const curPortSet = new Set(curPorts);
      const curVulns = host.vulns ?? [];
      const newPorts = curPorts.filter((p) => !basePorts.has(p));
      const gonePorts = [...basePorts].filter((p) => !curPortSet.has(p));
      const newVulns = curVulns.filter((v) => !baseVulns.has(v));
      const changed = newPorts.length > 0 || gonePorts.length > 0 || newVulns.length > 0;
      const check = {
        at: Date.now(),
        found: host.found,
        ports: curPorts,
        vulns: curVulns,
        lastUpdate: host.lastUpdate,
        newPorts,
        gonePorts,
        newVulns,
        changed,
        error: host.error,
      };
      const monitors = { ...s.monitors, [ip]: { ...cur, baseline, check, checking: false } };
      saveMonitors(monitors);
      return { monitors };
    });
    void pushSharedMonitorEntry(get().settings, ip, get().monitors[ip] ?? null);
  },

  async setMonitorGroup(ips, group) {
    const g = group && group.trim() ? group.trim() : undefined;
    const now = Date.now();
    set((s) => {
      const monitors = { ...s.monitors };
      for (const ip of ips) {
        const cur = monitors[ip];
        if (cur) monitors[ip] = { ...cur, group: g, updatedAt: now };
      }
      saveMonitors(monitors);
      return { monitors };
    });
    // Share each changed entry sequentially (per-entry read-modify-write) so the group assignment
    // propagates to the team without concurrent writes clobbering the shared blob.
    const st = get();
    for (const ip of ips) {
      const e = st.monitors[ip];
      if (e) await pushSharedMonitorEntry(st.settings, ip, e);
    }
  },

  // ---- IP-Mon PROJECTS (PJ) ----
  async createMonitorProject(name) {
    const nm = name.trim() || '無題のPJ';
    const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    const now = Date.now();
    const project: MonitorProject = { id, name: nm, createdAt: now, updatedAt: now };
    set((s) => {
      const monitorProjects = { ...s.monitorProjects, [id]: project };
      saveMonitorProjects(monitorProjects);
      return { monitorProjects };
    });
    void pushSharedMonitorProjects(get().settings, get().monitorProjects);
    return id;
  },

  async renameMonitorProject(id, name) {
    const nm = name.trim();
    if (!nm) return;
    const now = Date.now();
    set((s) => {
      const cur = s.monitorProjects[id];
      if (!cur) return {};
      const monitorProjects = { ...s.monitorProjects, [id]: { ...cur, name: nm, updatedAt: now } };
      saveMonitorProjects(monitorProjects);
      return { monitorProjects };
    });
    void pushSharedMonitorProjects(get().settings, get().monitorProjects);
  },

  async deleteMonitorProject(id) {
    const now = Date.now();
    const affected: string[] = [];
    set((s) => {
      // The PJ's IPs are NOT removed from monitoring — they fall back to 未分類.
      const monitors = { ...s.monitors };
      for (const [ip, e] of Object.entries(monitors)) {
        if (e.project === id) {
          monitors[ip] = { ...e, project: undefined, updatedAt: now };
          affected.push(ip);
        }
      }
      const monitorProjects = { ...s.monitorProjects };
      delete monitorProjects[id];
      saveMonitors(monitors);
      saveMonitorProjects(monitorProjects);
      return { monitors, monitorProjects, monitorProjectId: s.monitorProjectId === id ? null : s.monitorProjectId };
    });
    await deleteSharedMonitorProject(get().settings, id);
    const st = get();
    for (const ip of affected) {
      const e = st.monitors[ip];
      if (e) await pushSharedMonitorEntry(st.settings, ip, e);
    }
  },

  async setMonitorProject(ips, project) {
    const p = project && project.trim() ? project : undefined; // an id, or undefined = 未分類
    const now = Date.now();
    set((s) => {
      const monitors = { ...s.monitors };
      for (const ip of ips) {
        const cur = monitors[ip];
        if (cur) monitors[ip] = { ...cur, project: p, updatedAt: now };
      }
      saveMonitors(monitors);
      return { monitors };
    });
    const st = get();
    for (const ip of ips) {
      const e = st.monitors[ip];
      if (e) await pushSharedMonitorEntry(st.settings, ip, e);
    }
  },

  async refreshMonitorProjects() {
    const shared = await fetchSharedMonitorProjects(get().settings);
    if (!shared) return;
    set((s) => {
      const monitorProjects = mergeMonitorProjects(s.monitorProjects, shared);
      saveMonitorProjects(monitorProjects);
      return { monitorProjects };
    });
  },

  openMonitorProjects() {
    set({ view: 'monitor-projects' });
  },

  openMonitorProject(id) {
    set({ monitorProjectId: id, view: 'monitor' });
  },

  migrateMonitorsToDefaultProject() {
    try {
      if (localStorage.getItem(PROJECTS_MIGRATED_KEY)) return;
    } catch {
      /* ignore */
    }
    const unassigned = Object.values(get().monitors).filter((e) => !e.project);
    if (!unassigned.length) {
      try {
        localStorage.setItem(PROJECTS_MIGRATED_KEY, '1');
      } catch {
        /* ignore */
      }
      return;
    }
    const now = Date.now();
    set((s) => {
      const monitorProjects = { ...s.monitorProjects };
      // Fixed id ⇒ every browser converges on the SAME default PJ (no duplicates). Don't overwrite a
      // teammate's rename: only create it if absent.
      if (!monitorProjects[DEFAULT_PROJECT_ID])
        monitorProjects[DEFAULT_PROJECT_ID] = {
          id: DEFAULT_PROJECT_ID,
          name: '既定PJ（あとでリネーム）',
          createdAt: now,
          updatedAt: now,
        };
      const monitors = { ...s.monitors };
      for (const [ip, e] of Object.entries(monitors)) if (!e.project) monitors[ip] = { ...e, project: DEFAULT_PROJECT_ID, updatedAt: now };
      saveMonitors(monitors);
      saveMonitorProjects(monitorProjects);
      return { monitors, monitorProjects };
    });
    try {
      localStorage.setItem(PROJECTS_MIGRATED_KEY, '1');
    } catch {
      /* ignore */
    }
    void pushSharedMonitorProjects(get().settings, get().monitorProjects);
    void putSharedMonitorsAll(get().settings, get().monitors);
  },

  reorderMonitorGroup(group, dir) {
    set((s) => {
      const present = [...new Set(Object.values(s.monitors).map((e) => e.group).filter((x): x is string => !!x))];
      const base = s.monitorGroupOrder.filter((g) => present.includes(g));
      for (const g of [...present].sort((a, b) => a.localeCompare(b))) if (!base.includes(g)) base.push(g);
      const i = base.indexOf(group);
      const j = dir === 'up' ? i - 1 : i + 1;
      if (i < 0 || j < 0 || j >= base.length) return {};
      [base[i], base[j]] = [base[j], base[i]];
      saveMonitorGroupOrder(base);
      return { monitorGroupOrder: base };
    });
  },

  async setAutoEnrich(ips, on) {
    set((s) => {
      const monitors = { ...s.monitors };
      for (const ip of ips) {
        const cur = monitors[ip];
        if (cur) monitors[ip] = { ...cur, autoEnrich: on };
      }
      saveMonitors(monitors);
      return { monitors };
    });
    const st = get();
    for (const ip of ips) {
      const e = st.monitors[ip];
      if (e) await pushSharedMonitorEntry(st.settings, ip, e);
    }
  },

  async scanStaleMonitors(staleDays = 14) {
    if (get().scanningGaps) return 0;
    const STALE = staleDays * 86_400_000;
    const now = Date.now();
    // Gap set: no scan (check) or stale check, and/or no enrichment or stale enrichment.
    const gap = Object.values(get().monitors).filter(
      (e) => !e.check || now - e.check.at > STALE || !e.result || now - (e.lastEnrichAt ?? 0) > STALE,
    );
    if (!gap.length) return 0;
    set({ scanningGaps: true });
    try {
      // Sequential ⇒ naturally throttled so a big watchlist doesn't burst Shodan / the enrichers.
      for (const g of gap) {
        const cur = get().monitors[g.ip];
        if (!cur) continue;
        const checkGap = !cur.check || now - cur.check.at > STALE;
        const enrichGap = !cur.result || now - (cur.lastEnrichAt ?? 0) > STALE;
        if (checkGap && !cur.checking) await get().checkMonitor(g.ip);
        if (enrichGap && !get().monitors[g.ip]?.enriching) await get().reEnrichMonitor(g.ip);
      }
    } finally {
      set({ scanningGaps: false });
    }
    return gap.length;
  },

  async runAutoEnrichDue() {
    const s = get();
    // Client-side scheduler: only meaningful against a real proxy, and only for opted-in items. Runs
    // every ~5 min while vteeee is open (live mode). What it does — and when — is documented in Docs → ⚡自動処理.
    if (s.mode !== 'live') return;
    const now = Date.now();
    const ipEnrich: string[] = []; // IP-Mon IPs re-enriched this pass
    const ipScan: string[] = []; // IP-Mon IPs Shodan-checked this pass

    // When the watchlist is TEAM-SHARED, the daily server-side cron is the single authority for ALL
    // standing auto work — re-enrich, Shodan check, AND 魚拓 — doing each ONCE (not once-per-open-device)
    // and writing shared KV minimally. So each open device skipping that work here avoids N× duplicate
    // API calls + KV writes (the cause of the Cloudflare KV free-tier alarms). Local-only setups (no
    // sharing) still run everything client-side below.
    const deferToServer = monitorSharingOn(s.settings);

    // In shared mode this device is a READER, not a writer: pull the freshest cron-written shared state
    // (the 魚拓 timeline + report history) every pass so every device converges to the IDENTICAL state
    // without doing — or duplicating — the work. We deliberately DON'T re-pull shared monitors/campaigns
    // here: those are pulled on their page mounts, and that path re-stamps updatedAt, which would push
    // redundant KV writes — the very thing this whole change removes.
    if (deferToServer) {
      void get().refreshCaptures();
      void get().refreshMonitorAssessments();
    }

    if (!deferToServer) {
      // 1) Auto re-enrich due monitored IPs (capped per pass so a large watchlist doesn't burst the API).
      const due = Object.values(s.monitors)
        .filter(
          (e) =>
            e.autoEnrich &&
            !e.enriching &&
            now - (e.lastEnrichAt ?? e.addedAt) >= autoEnrichInterval(now - e.addedAt),
        )
        .sort((a, b) => (a.lastEnrichAt ?? a.addedAt) - (b.lastEnrichAt ?? b.addedAt));
      for (const e of due.slice(0, 4)) {
        await get().reEnrichMonitor(e.ip);
        ipEnrich.push(e.ip);
      }

      // 1b) Auto Shodan re-scan (check) for auto IPs whose monitoring result is MISSING or stale.
      const checkDue = Object.values(get().monitors)
        .filter(
          (e) =>
            e.autoEnrich &&
            !e.checking &&
            (!e.check || now - e.check.at >= autoEnrichInterval(now - e.addedAt)),
        )
        .sort((a, b) => (a.check?.at ?? 0) - (b.check?.at ?? 0));
      for (const e of checkDue.slice(0, 4)) {
        await get().checkMonitor(e.ip);
        ipScan.push(e.ip);
      }
    }

    // 2) Auto re-魚拓: keep a fresh urlscan capture for every auto-enabled, web-capturable target —
    // IP-Mon IPs (https://<ip>) and CP-Mon auto IOCs (URL/domain as-is, IP → https). Like enrich/scan
    // above, this is SERVER-MANAGED in team-shared mode: the daily cron captures each target ONCE and
    // writes the shared 魚拓 blob, so every device converges to the identical timeline without N open
    // browsers each firing a submission (wasteful urlscan-quota / KV burn). Local-only setups still run
    // it client-side. Throttled to ~daily, a few per pass, silent (they land in history tagged ⚡auto).
    // Intentional Re-魚拓 of a hand-picked target (startWebCapture from the UI) is unaffected by this.
    const capIp: string[] = [];
    const capCp: string[] = [];
    if (!deferToServer) {
      const AUTO_CAP_MS = 20 * 3_600_000;
      const monTargets = new Set<string>();
      const campTargets = new Set<string>();
      for (const e of Object.values(s.monitors)) {
        if (e.autoEnrich) monTargets.add(e.ip.includes(':') ? `https://[${e.ip}]` : `https://${e.ip}`);
      }
      for (const c of Object.values(s.campaigns)) {
        for (const i of Object.values(c.iocs)) {
          if (!i.autoEnrich) continue;
          const t =
            i.type === 'url' || i.type === 'domain'
              ? i.value
              : i.type === 'ipv4'
                ? `https://${i.value}`
                : i.type === 'ipv6'
                  ? `https://[${i.value}]`
                  : null;
          if (t) campTargets.add(t);
        }
      }
      const caps = get().webCaptures;
      const capDue = [...new Set([...monTargets, ...campTargets])]
        .filter((t) => {
          const j = caps[t];
          if (j && isActiveCapture(j)) return false;
          // Throttle by the last ATTEMPT (updatedAt), not just the last SUCCESSFUL capture (history[0].at):
          // a failing target (dead/nonexistent domain, error/stalled/interrupted) writes no history entry,
          // so keying off history alone made it look perpetually due and retry every ~5-min pass. Using the
          // attempt time backs failures off to ~daily too (≈1回/日), and cuts the notification spam.
          const lastAttempt = Math.max(j?.history?.[0]?.at ?? 0, j?.updatedAt ?? 0);
          return now - lastAttempt >= AUTO_CAP_MS;
        })
        .slice(0, 3);
      for (const t of capDue) {
        void get().startWebCapture(t, undefined, { silent: true, auto: true });
        (monTargets.has(t) ? capIp : capCp).push(t);
      }
    }

    // Record the pass in the notification LOG (naming what ran, by side) so auto activity is auditable.
    // Enrich/scan complete here; 魚拓 are started (each lands in the 実行ログ tagged ⚡auto as it finishes).
    if (ipEnrich.length + ipScan.length + capIp.length + capCp.length > 0) {
      const sample = (arr: string[]) => {
        const c = arr.map((x) => x.replace(/^https?:\/\//, '').replace(/^\[|\]$/g, ''));
        return c.length ? ` [${c.slice(0, 3).join(', ')}${c.length > 3 ? ` …他${c.length - 3}` : ''}]` : '';
      };
      const ipParts = [
        ipEnrich.length ? `エンリッチ ${ipEnrich.length}件${sample(ipEnrich)}` : '',
        ipScan.length ? `Shodanスキャン ${ipScan.length}件${sample(ipScan)}` : '',
        capIp.length ? `魚拓 ${capIp.length}件開始${sample(capIp)}` : '',
      ].filter(Boolean);
      const parts = [
        ipParts.length ? `IP-MON: ${ipParts.join(' · ')}` : '',
        capCp.length ? `CP-MON: 魚拓 ${capCp.length}件開始${sample(capCp)}` : '',
      ].filter(Boolean);
      get().notify({ title: '⚡ 自動処理を実行しました', body: parts.join(' ／ '), kind: 'auto' });
    }
  },

  // ---- CP-Mon (campaigns) ----
  async createCampaign(name) {
    const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    const now = Date.now();
    const campaign: Campaign = {
      id,
      name: name.trim() || 'Untitled campaign',
      createdAt: now,
      updatedAt: now,
      iocs: {},
    };
    set((s) => {
      const campaigns = { ...s.campaigns, [id]: campaign };
      saveCampaigns(campaigns);
      return { campaigns };
    });
    void pushSharedCampaign(get().settings, id, campaign);
    return id;
  },

  async renameCampaign(id, name) {
    const nm = name.trim();
    if (!nm) return;
    set((s) => {
      const cur = s.campaigns[id];
      if (!cur) return {};
      const campaigns = { ...s.campaigns, [id]: { ...cur, name: nm, updatedAt: Date.now() } };
      saveCampaigns(campaigns);
      return { campaigns };
    });
    void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
  },

  async removeCampaign(id) {
    set((s) => {
      if (!s.campaigns[id]) return {};
      const campaigns = { ...s.campaigns };
      delete campaigns[id];
      saveCampaigns(campaigns);
      return { campaigns, ...(s.campaignId === id ? { campaignId: null, view: 'campaigns' as const } : {}) };
    });
    void pushSharedCampaign(get().settings, id, null);
  },

  openCampaigns() {
    set({ view: 'campaigns', campaignId: null });
    void get().refreshCampaigns();
  },

  openCampaign(id) {
    // Opening a campaign fresh starts on the Dashboard; the Analysis round-trip (setView) keeps the tab.
    set({ view: 'campaign', campaignId: id, campaignTab: 'dashboard' });
  },

  setCampaignTab(t) {
    set({ campaignTab: t });
  },

  async addCampaignIocs(id, iocs, group, side) {
    const now = Date.now();
    const by = get().session?.username;
    const g = group && group.trim() ? group.trim() : undefined;
    set((s) => {
      const cur = s.campaigns[id];
      if (!cur) return {};
      const nextIocs = { ...cur.iocs };
      for (const { value, type } of iocs) {
        const ex = nextIocs[value];
        nextIocs[value] = ex
          ? { ...ex, group: g ?? ex.group, side: side ?? ex.side, updatedAt: now }
          : { value, type, side: side ?? 'attack', group: g, addedAt: now, updatedAt: now, addedBy: by, autoEnrich: true };
      }
      const campaigns = { ...s.campaigns, [id]: { ...cur, iocs: nextIocs, updatedAt: now } };
      saveCampaigns(campaigns);
      return { campaigns };
    });
    void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
    // Enrich the newly-added IOCs (sequential to respect the free-tier rate limit), then reconcile
    // once so the fully-enriched campaign is guaranteed shared.
    for (const { value } of iocs) await get().reEnrichCampaignIoc(id, value);
    await get().refreshCampaigns();
  },

  async setCampaignTlp(id, tlp) {
    const now = Date.now();
    set((s) => {
      const cur = s.campaigns[id];
      if (!cur) return {};
      const campaigns = { ...s.campaigns, [id]: { ...cur, tlp, updatedAt: now } };
      saveCampaigns(campaigns);
      return { campaigns };
    });
    void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
  },

  async setCampaignNote(id, note) {
    const now = Date.now();
    const n = note.trim() ? note : undefined;
    set((s) => {
      const cur = s.campaigns[id];
      if (!cur) return {};
      const campaigns = { ...s.campaigns, [id]: { ...cur, note: n, updatedAt: now } };
      saveCampaigns(campaigns);
      return { campaigns };
    });
    void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
  },

  async setCampaignAdmiralty(id, reliability, credibility) {
    const now = Date.now();
    set((s) => {
      const cur = s.campaigns[id];
      if (!cur) return {};
      const campaigns = {
        ...s.campaigns,
        [id]: {
          ...cur,
          admiraltyReliability: reliability || undefined,
          admiraltyCredibility: credibility || undefined,
          updatedAt: now,
        },
      };
      saveCampaigns(campaigns);
      return { campaigns };
    });
    void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
  },

  async setCampaignIocSide(id, values, side) {
    const now = Date.now();
    set((s) => {
      const cur = s.campaigns[id];
      if (!cur) return {};
      const nextIocs = { ...cur.iocs };
      for (const v of values) if (nextIocs[v]) nextIocs[v] = { ...nextIocs[v], side, updatedAt: now };
      const campaigns = { ...s.campaigns, [id]: { ...cur, iocs: nextIocs, updatedAt: now } };
      saveCampaigns(campaigns);
      return { campaigns };
    });
    void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
  },

  async reorderCampaignGroup(id, group, dir) {
    const now = Date.now();
    set((s) => {
      const cur = s.campaigns[id];
      if (!cur) return {};
      // Seed the order from the current group set (alphabetical) if none saved yet.
      const present = [...new Set(Object.values(cur.iocs).map((i) => i.group).filter((x): x is string => !!x))];
      const base = (cur.groupOrder ?? []).filter((g) => present.includes(g));
      for (const g of present.sort((a, b) => a.localeCompare(b))) if (!base.includes(g)) base.push(g);
      const i = base.indexOf(group);
      const j = dir === 'up' ? i - 1 : i + 1;
      if (i < 0 || j < 0 || j >= base.length) return {};
      [base[i], base[j]] = [base[j], base[i]];
      const campaigns = { ...s.campaigns, [id]: { ...cur, groupOrder: base, updatedAt: now } };
      saveCampaigns(campaigns);
      return { campaigns };
    });
    void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
  },

  async assessCampaign(id) {
    const cur = get().campaigns[id];
    if (!cur) return;
    const text = await fetchCampaignAssessment(get().settings, buildAssessmentDigest(cur));
    const at = Date.now();
    const by = get().session?.username;
    set((s) => {
      const c = s.campaigns[id];
      if (!c) return {};
      const entry: CampaignAssessment = { text, at, by, tlp: c.tlp ?? 'AMBER' };
      // Prepend to the history (fold any legacy single assessment in) — never overwrite past reports.
      const assessments = mergeAssessments([entry], [...(c.assessments ?? []), ...(c.assessment ? [c.assessment] : [])]);
      const campaigns = {
        ...s.campaigns,
        [id]: { ...c, assessment: assessments[0], assessments, updatedAt: at },
      };
      saveCampaigns(campaigns);
      return { campaigns };
    });
    void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
  },

  async assessMonitors() {
    const st = get();
    // Scope the report to the open PJ (id / '__none__' / null = all).
    const pj = st.monitorProjectId;
    const scoped =
      pj === null
        ? st.monitors
        : Object.fromEntries(
            Object.entries(st.monitors).filter(([, e]) =>
              pj === '__none__' ? !e.project || !st.monitorProjects[e.project] : e.project === pj,
            ),
          );
    if (!Object.keys(scoped).length) return;
    const digest = buildMonitorDigest(scoped, st.monitorGroupOrder, st.settings.tlp ?? 'AMBER');
    set({ monitorAssessing: true, monitorAssessError: null });
    try {
      const { ok, text, model } = await fetchMonitorAssessment(get().settings, digest);
      if (!ok) {
        // Claude unavailable / network — surface the message, don't pollute the time-series.
        set({ monitorAssessing: false, monitorAssessError: text });
        return;
      }
      const at = Date.now();
      const by = get().session?.username;
      set((s) => {
        const entry: CampaignAssessment = { text, at, by, model, tlp: s.settings.tlp ?? 'AMBER' };
        // Prepend to the history — continuous monitoring, never overwrite past reports.
        const monitorAssessments = mergeAssessments([entry], s.monitorAssessments);
        saveMonitorAssessments(monitorAssessments);
        return { monitorAssessments, monitorAssessing: false, monitorAssessError: null };
      });
      // Share the report time-series team-wide (always-on when the proxy is connected & sharing is on).
      void pushSharedMonitorAssessments(get().settings, get().monitorAssessments);
    } catch {
      set({ monitorAssessing: false, monitorAssessError: 'レポート生成に失敗しました。' });
    }
  },

  async refreshMonitorAssessments() {
    const shared = await fetchSharedMonitorAssessments(get().settings);
    if (!shared || !shared.length) return;
    set((s) => {
      const monitorAssessments = mergeAssessments(shared, s.monitorAssessments);
      saveMonitorAssessments(monitorAssessments);
      return { monitorAssessments };
    });
  },

  openMonitorAssessment() {
    set({ view: 'monitor-assessment' });
  },

  async setCampaignIocGroup(id, values, group) {
    const g = group && group.trim() ? group.trim() : undefined;
    const now = Date.now();
    set((s) => {
      const cur = s.campaigns[id];
      if (!cur) return {};
      const nextIocs = { ...cur.iocs };
      for (const v of values) if (nextIocs[v]) nextIocs[v] = { ...nextIocs[v], group: g, updatedAt: now };
      const campaigns = { ...s.campaigns, [id]: { ...cur, iocs: nextIocs, updatedAt: now } };
      saveCampaigns(campaigns);
      return { campaigns };
    });
    void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
  },

  async removeCampaignIocs(id, values) {
    set((s) => {
      const cur = s.campaigns[id];
      if (!cur) return {};
      const nextIocs = { ...cur.iocs };
      for (const v of values) delete nextIocs[v];
      const campaigns = { ...s.campaigns, [id]: { ...cur, iocs: nextIocs, updatedAt: Date.now() } };
      saveCampaigns(campaigns);
      return { campaigns };
    });
    void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
  },

  async reEnrichCampaignIoc(id, value) {
    const cur0 = get().campaigns[id]?.iocs[value];
    if (!cur0) return;
    set((s) => {
      const c = s.campaigns[id];
      if (!c?.iocs[value]) return {};
      const iocs = { ...c.iocs, [value]: { ...c.iocs[value], enriching: true } };
      return { campaigns: { ...s.campaigns, [id]: { ...c, iocs } } };
    });
    let result: NormalizedResult | undefined;
    try {
      result = await enrichOne(get().settings, value, cur0.type);
    } catch {
      /* leave the previous snapshot */
    }
    const by = get().session?.username;
    const at = Date.now();
    set((s) => {
      const c = s.campaigns[id];
      const ioc = c?.iocs[value];
      if (!c || !ioc) return {};
      // Seed the pre-existing result as the first point so the next enrich always has a baseline.
      const seed = ioc.history?.length
        ? ioc.history
        : ioc.result
          ? [{ at: ioc.lastEnrichAt ?? ioc.updatedAt, result: ioc.result }]
          : undefined;
      const history = result ? appendSnapshot(seed, { at, by, result }, at) : ioc.history;
      const iocs = {
        ...c.iocs,
        [value]: { ...ioc, enriching: false, result: result ?? ioc.result, history, updatedAt: at, lastEnrichAt: at },
      };
      const campaigns = { ...s.campaigns, [id]: { ...c, iocs, updatedAt: at } };
      saveCampaigns(campaigns);
      return { campaigns };
    });
    void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
  },

  async reEnrichCampaignIocs(id, values) {
    // Sequential to respect the free-tier rate limit; each row shows its own "enriching…" state.
    // Each reEnrichCampaignIoc already pushes its fresh result; a final two-way sync reconciles the
    // whole batch so the enriched campaign is guaranteed shared (and teammates' changes pulled in).
    for (const v of values) await get().reEnrichCampaignIoc(id, v);
    await get().refreshCampaigns();
    if (values.length > 1) {
      const name = get().campaigns[id]?.name;
      get().notify({
        title: '一括 Re-enrich が完了しました',
        body: `${name ? `${name} · ` : ''}${values.length} 件のエンリッチを更新`,
        kind: 'reenrich',
      });
    }
  },

  async setCampaignIocAuto(id, values, on) {
    const now = Date.now();
    set((s) => {
      const c = s.campaigns[id];
      if (!c) return {};
      const iocs = { ...c.iocs };
      for (const v of values) if (iocs[v]) iocs[v] = { ...iocs[v], autoEnrich: on };
      const campaigns = { ...s.campaigns, [id]: { ...c, iocs, updatedAt: now } };
      saveCampaigns(campaigns);
      return { campaigns };
    });
    void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
  },

  async refreshCampaigns() {
    const settings = get().settings;
    if (!monitorSharingOn(settings)) {
      set({ campaignsSyncNote: '共有OFF/プロキシ未接続 — この端末のみ表示中（Settings で接続すると共有されます）' });
      return;
    }
    const r = await fetchCampaignsStatus(settings);
    const shared = r.data;
    let note: string;
    if (r.netError) {
      note = '⚠ プロキシに到達できません（ネットワーク/CORS）。データは消えていません。プロキシURL・接続を確認して再試行してください。';
    } else if (r.status === 404) {
      note =
        '⚠ このプロキシに /api/campaigns がありません（CP-Mon 未対応の古いデプロイ）。GitHub Actions の「Deploy Proxy」で最新版を再デプロイしてください。※未対応の間、Campaign はこの端末のローカルのみで、サーバ共有されていません。';
    } else if (r.status === 401 || r.status === 403) {
      note = '⚠ 認証エラー（アクセストークン）。Settings のトークンを確認してください。データは消えていません。';
    } else if (r.status >= 400) {
      note = `⚠ 同期に失敗（HTTP ${r.status}）。データは消えていません。少し待って再試行してください。`;
    } else {
      note = `同期OK · サーバに ${Object.keys(shared ?? {}).length} 件`;
    }
    set((s) => {
      const campaigns = mergeCampaigns(s.campaigns, shared);
      saveCampaigns(campaigns);
      return { campaigns, campaignsSyncNote: note };
    });
    if (shared !== null) void putSharedCampaignsAll(settings, get().campaigns);
  },

  async importCampaigns(incoming) {
    const ids = Object.keys(incoming ?? {});
    if (!ids.length) return 0;
    set((s) => {
      const campaigns = mergeCampaigns(s.campaigns, incoming);
      saveCampaigns(campaigns);
      return { campaigns };
    });
    // Re-share every imported campaign (non-destructive merge into the KV).
    for (const id of ids) void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
    return ids.length;
  },

  restoreCampaignsBackup() {
    const bak = loadCampaignsBackup();
    if (!bak) return 0;
    set((s) => {
      const campaigns = mergeCampaigns(s.campaigns, bak);
      saveCampaigns(campaigns);
      return { campaigns };
    });
    for (const id of Object.keys(bak)) void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
    return Object.keys(bak).length;
  },

  async summarizeCampaign(id) {
    const cur = get().campaigns[id];
    if (!cur) return;
    const text = await fetchCampaignSummary(get().settings, buildCampaignDigest(cur));
    const at = Date.now();
    const by = get().session?.username;
    set((s) => {
      const c = s.campaigns[id];
      if (!c) return {};
      const campaigns = { ...s.campaigns, [id]: { ...c, summary: { text, at, by }, updatedAt: at } };
      saveCampaigns(campaigns);
      return { campaigns };
    });
    void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
  },
  };
});
