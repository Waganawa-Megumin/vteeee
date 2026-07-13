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
  type Campaign,
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
function maybeRequestNotify(): void {
  try {
    if (typeof Notification !== 'undefined' && Notification.permission === 'default') void Notification.requestPermission();
  } catch {
    /* ignore */
  }
}
function browserNotify(title: string, body: string, tag: string): void {
  try {
    if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
      new Notification(title, { body, tag });
    }
  } catch {
    /* ignore */
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
async function fetchSharedCampaigns(settings: AppSettings): Promise<Record<string, Campaign> | null> {
  if (!monitorSharingOn(settings)) return null;
  const base = settings.proxyBaseUrl!.replace(/\/$/, '');
  try {
    const res = await fetch(`${base}/api/campaigns`, { headers: monitorAuth(settings), cache: 'no-store' });
    if (!res.ok) return null;
    const j = await res.json();
    return j && typeof j === 'object' ? (j as Record<string, Campaign>) : {};
  } catch {
    return null;
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
    if (!res.ok) return `アセスメント生成に失敗しました（HTTP ${res.status}）。`;
    const j = (await res.json()) as { text?: string; error?: string };
    return j.text?.trim() || j.error || 'アセスメントを生成できませんでした。';
  } catch {
    return 'アセスメント生成に失敗しました（ネットワーク）。';
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
  view: 'app' | 'admin' | 'monitor' | 'analysis' | 'campaigns' | 'campaign';
  /** IP whose enrichment-analysis page is open (view === 'analysis'). */
  analysisIp: string | null;

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

  setView: (v: 'app' | 'admin' | 'monitor' | 'analysis' | 'campaigns' | 'campaign') => void;
  /** Open the full-page enrichment analysis for one monitored IP. */
  openAnalysis: (ip: string) => void;
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

  /** Shodan Monitor watchlist (IPs + last vteeee enrichment snapshot), keyed by IP. */
  monitors: Record<string, MonitorEntry>;
  /** Register an IP to Shodan Monitor and snapshot its current enrichment. */
  addMonitor: (ip: string, result?: NormalizedResult) => Promise<void>;
  /** Remove an IP from Shodan Monitor + the watchlist. */
  removeMonitor: (ip: string) => Promise<void>;
  /** Reconcile the watchlist against Shodan's server-side alert list. */
  refreshMonitors: () => Promise<void>;
  /** Re-run vteeee enrichment for a monitored IP and refresh its snapshot. */
  reEnrichMonitor: (ip: string) => Promise<void>;
  /** Re-observe a monitored IP on Shodan and diff it vs. the baseline (the "monitoring result"). */
  checkMonitor: (ip: string) => Promise<void>;
  /** Assign (or clear, when group is blank/undefined) a group label on the given monitored IPs. */
  setMonitorGroup: (ips: string[], group: string | undefined) => Promise<void>;
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
      if (cur && cur.token != null && cur.token !== token) return {};
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

  return {
  booted: false,
  session: null,
  users: [],
  settings: { proxyBaseUrl: null, rpm: 4, concurrency: 1, gti: false, submitUnknown: false, shodan: true, maxmind: true, domaintools: true, dnslytics: true, intel471: true, cyfirma: true, threatvision: true, recordedfuture: true, abuseipdb: true, tlp: 'AMBER', urlscanVisibility: 'unlisted', shareMonitors: true },
  mode: 'demo',
  health: null,
  scanJobs: loadScanJobs(),
  monitors: loadMonitors(),

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
    // Merge the snapshot in and open its detail as an overlay WITHOUT changing the view — so opening
    // from the IP-Mon dashboard keeps you on IP-Mon (closing the detail returns you there).
    set((s) => ({
      results: { ...s.results, [r.value]: r },
      order: s.order.includes(r.value) ? s.order : [...s.order, r.value],
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
          browserNotify('Shodan re-scan complete', `${ip}${host.ports?.length ? ` · ports ${host.ports.slice(0, 8).join(', ')}` : ''}`, `vteeee-shodan-${ip}`);
          return;
        }
      }
    }
    writeJob(ip, token, started, {
      phase: 'timeout',
      creditsLeft: credits,
      msg: 'Shodan has not refreshed this host within ~15 min — the scan may still be queued. Re-check later.',
    });
    browserNotify('Shodan re-scan still pending', `${ip} — not refreshed yet; re-check later.`, `vteeee-shodan-${ip}`);
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
      browserNotify('Shodan banners updated', `${ip}${host.ports?.length ? ` · ports ${host.ports.slice(0, 8).join(', ')}` : ''}`, `vteeee-shodan-${ip}`);
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

  async addMonitor(ip, result) {
    const now = Date.now();
    const by = get().session?.username;
    set((s) => {
      const cur = s.monitors[ip];
      const monitors = {
        ...s.monitors,
        [ip]: {
          ip,
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

  async runAutoEnrichDue() {
    const s = get();
    // Client-side scheduler: only meaningful against a real proxy, and only for opted-in IPs.
    if (s.mode !== 'live') return;
    const now = Date.now();
    const due = Object.values(s.monitors)
      .filter(
        (e) =>
          e.autoEnrich &&
          !e.enriching &&
          now - (e.lastEnrichAt ?? e.addedAt) >= autoEnrichInterval(now - e.addedAt),
      )
      .sort((a, b) => (a.lastEnrichAt ?? a.addedAt) - (b.lastEnrichAt ?? b.addedAt));
    if (!due.length) return;
    // Cap per pass so a large watchlist doesn't burst the API; the rest run on the next tick.
    for (const e of due.slice(0, 4)) {
      await get().reEnrichMonitor(e.ip);
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
    set({ view: 'campaign', campaignId: id });
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
    // Enrich the newly-added IOCs (sequential to respect the free-tier rate limit).
    for (const { value } of iocs) await get().reEnrichCampaignIoc(id, value);
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
      const campaigns = {
        ...s.campaigns,
        [id]: { ...c, assessment: { text, at, by, tlp: c.tlp ?? 'AMBER' }, updatedAt: at },
      };
      saveCampaigns(campaigns);
      return { campaigns };
    });
    void pushSharedCampaign(get().settings, id, get().campaigns[id] ?? null);
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
    for (const v of values) await get().reEnrichCampaignIoc(id, v);
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
    const shared = await fetchSharedCampaigns(settings);
    set((s) => {
      const campaigns = mergeCampaigns(s.campaigns, shared);
      saveCampaigns(campaigns);
      // Distinguish "sync failed / not connected" from "genuinely no campaigns yet".
      const note = !monitorSharingOn(settings)
        ? '共有OFF/プロキシ未接続 — この端末のみ表示中（Settings で接続すると共有されます）'
        : shared === null
          ? '⚠ 同期に失敗しました（通信/認証エラー）。データは消えていません。少し待って再試行してください。'
          : `同期OK · 共有 ${Object.keys(shared).length} 件`;
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
