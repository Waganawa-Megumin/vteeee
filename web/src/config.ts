import type { AppSettings, SettingsConfig, UserRecord, UsersConfig } from '@vteeee/shared';

const LS_USERS = 'vteeee.users';
const LS_SETTINGS = 'vteeee.settings';

const BASE = import.meta.env.BASE_URL; // '/vteeee/' on Pages, '/' in dev

export const DEFAULT_SETTINGS: AppSettings = {
  proxyBaseUrl: null,
  rpm: 4,
  concurrency: 1,
  gti: false,
  submitUnknown: false,
  historyRetentionDays: 30,
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
  const ls = localStorage.getItem(LS_USERS);
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
  localStorage.setItem(LS_USERS, JSON.stringify(cfg));
}

export async function loadSettings(): Promise<AppSettings> {
  const ls = localStorage.getItem(LS_SETTINGS);
  if (ls) {
    try {
      return { ...DEFAULT_SETTINGS, ...(JSON.parse(ls) as SettingsConfig).settings };
    } catch {
      /* fall through to baseline */
    }
  }
  const base = await fetchJson<SettingsConfig>('config/settings.json');
  const merged: AppSettings = { ...DEFAULT_SETTINGS, ...(base?.settings ?? {}) };
  const envProxy = import.meta.env.VITE_API_BASE_URL as string | undefined;
  if (!merged.proxyBaseUrl && envProxy) merged.proxyBaseUrl = envProxy;
  return merged;
}

export function saveSettings(settings: AppSettings): void {
  const cfg: SettingsConfig = { version: 1, settings };
  localStorage.setItem(LS_SETTINGS, JSON.stringify(cfg));
}

export type Mode = 'demo' | 'live';

export function resolveMode(settings: AppSettings): Mode {
  return settings.proxyBaseUrl ? 'live' : 'demo';
}
