import { create } from 'zustand';
import {
  extractIndicators,
  type AppSettings,
  type EnrichableType,
  type EnrichOptions,
  type ExtractStats,
  type HistoryRecord,
  type NormalizedResult,
  type ParsedIndicator,
  type ProxyHealth,
  type Session,
  type UserRecord,
} from '@vteeee/shared';
import { loadSettings, loadUsers, resolveMode, saveSettings, saveUsers, type Mode } from '../config';
import { authenticate, persistSession, restoreSession } from '../auth/session';
import { makeClient, type EnrichClient } from '../api/client';
import { saveHistory } from '../lib/historySource';
import { requestPersistentStorage } from '../lib/durable';

export const indKey = (i: { type: string; value: string }) => `${i.type}|${i.value}`;

let abortController: AbortController | null = null;

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
}

function defaultIncludes(parsed: ParsedIndicator[]): Record<string, boolean> {
  const m: Record<string, boolean> = {};
  for (const i of parsed) m[indKey(i)] = i.type !== 'unknown' && !i.private;
  return m;
}

export const useStore = create<State>((set, get) => ({
  booted: false,
  session: null,
  users: [],
  settings: { proxyBaseUrl: null, rpm: 4, concurrency: 1, gti: false, submitUnknown: false, shodan: true, domaintools: true, dnslytics: true },
  mode: 'demo',
  health: null,

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
      domaintools: settings.domaintools ?? true,
      dnslytics: settings.dnslytics ?? true,
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
        set({ health: { ok: false, vtKey: false, claude: false, shodan: false, domaintools: false, dnslytics: false } });
        return;
      }
      const h = (await res.json()) as Partial<ProxyHealth>;
      set({
        health: {
          ok: Boolean(h.ok),
          vtKey: Boolean(h.vtKey),
          claude: Boolean(h.claude),
          shodan: Boolean(h.shodan),
          domaintools: Boolean(h.domaintools),
          dnslytics: Boolean(h.dnslytics),
        },
      });
    } catch {
      set({ health: { ok: false, vtKey: false, claude: false, shodan: false, domaintools: false, dnslytics: false } });
    }
  },
}));
