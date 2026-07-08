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
} from '@vteeee/shared';
import { loadSettings, loadUsers, resolveMode, saveSettings, saveUsers, type Mode } from '../config';
import { authenticate, persistSession, restoreSession } from '../auth/session';
import { makeClient, type EnrichClient } from '../api/client';
import { saveHistory } from '../lib/historySource';
import { requestPersistentStorage } from '../lib/durable';

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
  progress: { done: number; total: number; inflight: number; rateLimitedUntil: number | null } | null;
  running: boolean;
  error: string | null;
  selected: string | null;
  view: 'app' | 'admin';

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
  restore: (results: NormalizedResult[], input: string) => void;

  setView: (v: 'app' | 'admin') => void;
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
  settings: { proxyBaseUrl: null, rpm: 4, concurrency: 1, gti: false, submitUnknown: false, shodan: true, maxmind: true, domaintools: true, dnslytics: true, intel471: true, cyfirma: true, threatvision: true, recordedfuture: true, abuseipdb: true, tlp: 'AMBER', urlscanVisibility: 'unlisted' },
  mode: 'demo',
  health: null,
  scanJobs: loadScanJobs(),

  rawInput: '',
  parsed: [],
  stats: null,
  includeMap: {},
  parsing: false,

  results: {},
  order: [],
  progress: null,
  running: false,
  error: null,
  selected: null,
  view: 'app',

  async boot() {
    void requestPersistentStorage(); // ask the browser not to evict our storage
    const [users, settings] = await Promise.all([loadUsers(), loadSettings()]);
    set({
      users,
      settings,
      mode: resolveMode(settings),
      session: restoreSession(),
      booted: true,
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
  };
});
