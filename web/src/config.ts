import type { AppSettings, SettingsConfig, UserRecord, UsersConfig } from '@vteeee/shared';
import { idbSet, rehydrateFromIdb } from './lib/durable';

const LS_USERS = 'vteeee.users';
const LS_SETTINGS = 'vteeee.settings';

const BASE = import.meta.env.BASE_URL; // '/vteeee/' on Pages, '/' in dev

export const DEFAULT_SETTINGS: AppSettings = {
  proxyBaseUrl: null,
  rpm: 4,
  concurrency: 1,
  gti: false,
  submitUnknown: false,
  shodan: true,
  maxmind: true,
  domaintools: true,
  dnslytics: true,
  intel471: true,
  cyfirma: true,
  threatvision: true,
  recordedfuture: true,
  abuseipdb: true,
  historyRetentionDays: 30,
  tlp: 'AMBER',
  urlscanVisibility: 'unlisted',
  shareMonitors: true,
};

async function fetchJson<T>(path: string): Promise<T | null> {
  try {
    const res = await fetch(`${BASE}${path}`, { cache: 'no-cache' });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

export async function loadUsers(): Promise<UserRecord[]> {
  const ls = localStorage.getItem(LS_USERS) ?? (await rehydrateFromIdb(LS_USERS));
  if (ls) {
    try {
      return (JSON.parse(ls) as UsersConfig).users;
    } catch {
      /* fall through to baseline */
    }
  }
  const base = await fetchJson<UsersConfig>('config/users.json');
  return base?.users ?? [];
}

export function saveUsers(users: UserRecord[]): void {
  const cfg: UsersConfig = { version: 1, users };
  const json = JSON.stringify(cfg);
  localStorage.setItem(LS_USERS, json);
  void idbSet(LS_USERS, json); // durable mirror (survives a localStorage eviction)
}

export async function loadSettings(): Promise<AppSettings> {
  // Built-in default proxy URL (set at build via VITE_API_BASE_URL). Applied
  // whenever no proxy URL is stored, so the connection never "disappears" after
  // a localStorage eviction or on a fresh device.
  const envProxy = (import.meta.env.VITE_API_BASE_URL as string | undefined) || undefined;
  const ls = localStorage.getItem(LS_SETTINGS) ?? (await rehydrateFromIdb(LS_SETTINGS));
  if (ls) {
    try {
      const s = { ...DEFAULT_SETTINGS, ...(JSON.parse(ls) as SettingsConfig).settings };
      if (!s.proxyBaseUrl && envProxy) s.proxyBaseUrl = envProxy;
      return s;
    } catch {
      /* fall through to baseline */
    }
  }
  const base = await fetchJson<SettingsConfig>('config/settings.json');
  const merged: AppSettings = { ...DEFAULT_SETTINGS, ...(base?.settings ?? {}) };
  if (!merged.proxyBaseUrl && envProxy) merged.proxyBaseUrl = envProxy;
  return merged;
}

export function saveSettings(settings: AppSettings): void {
  const cfg: SettingsConfig = { version: 1, settings };
  const json = JSON.stringify(cfg);
  localStorage.setItem(LS_SETTINGS, json);
  void idbSet(LS_SETTINGS, json); // durable mirror (survives a localStorage eviction)
}

export type Mode = 'demo' | 'live';

export function resolveMode(settings: AppSettings): Mode {
  return settings.proxyBaseUrl ? 'live' : 'demo';
}

// --- "Connect another device" link -------------------------------------------------------------
// Proxy URL + tokens live only in this browser's localStorage, so a teammate/another device starts
// unconfigured (demo) and can't see the shared watchlist. A setup link carries JUST the connection
// (proxy URL + tokens + share flag) in the URL *hash* — which browsers never send to any server — so
// the admin can open it on their other device (or hand it to a trusted teammate) to auto-configure.
const CONNECT_FIELDS = ['proxyBaseUrl', 'accessToken', 'adminToken', 'shareMonitors'] as const;

function b64urlEncode(s: string): string {
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s: string): string {
  return atob(s.replace(/-/g, '+').replace(/_/g, '/'));
}

/** A shareable URL that carries this browser's proxy connection in the hash (never sent to a server). */
export function buildConnectLink(settings: AppSettings): string {
  const blob: Record<string, unknown> = {};
  for (const k of CONNECT_FIELDS) if (settings[k] != null) blob[k] = settings[k];
  const data = b64urlEncode(JSON.stringify(blob));
  return `${location.origin}${location.pathname}#connect=${data}`;
}

/** If the URL hash carries a connect blob, merge it into `base`, persist, strip the hash, return merged. */
export function consumeConnectLink(base: AppSettings): AppSettings | null {
  try {
    const m = (location.hash || '').match(/[#&]connect=([^&]+)/);
    if (!m) return null;
    const patch = JSON.parse(b64urlDecode(m[1])) as Partial<AppSettings>;
    const clean: Partial<AppSettings> = {};
    for (const k of CONNECT_FIELDS) if (k in patch) (clean as Record<string, unknown>)[k] = patch[k];
    if (Object.keys(clean).length === 0) return null;
    const merged: AppSettings = { ...base, ...clean };
    saveSettings(merged);
    // Strip the hash so the access token isn't left sitting in the address bar / history.
    try {
      history.replaceState(null, '', location.pathname + location.search);
    } catch {
      /* ignore */
    }
    return merged;
  } catch {
    return null;
  }
}
