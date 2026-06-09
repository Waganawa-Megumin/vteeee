import type { AppSettings, SettingsConfig, UserRecord, UsersConfig } from '@vteeee/shared';
import type { Storage } from './types';

const USERS_KEY = 'users';
const SETTINGS_KEY = 'settings';

const DEFAULT_SETTINGS: AppSettings = {
  proxyBaseUrl: null,
  rpm: 4,
  concurrency: 1,
  gti: false,
  submitUnknown: false,
};

export async function getUsers(store: Storage): Promise<UsersConfig> {
  const s = await store.get(USERS_KEY);
  if (!s) return { version: 1, users: [] };
  try {
    return JSON.parse(s) as UsersConfig;
  } catch {
    return { version: 1, users: [] };
  }
}

export async function putUsers(store: Storage, users: UserRecord[]): Promise<void> {
  const cfg: UsersConfig = { version: 1, users };
  await store.put(USERS_KEY, JSON.stringify(cfg));
}

export async function getSettings(store: Storage): Promise<SettingsConfig> {
  const s = await store.get(SETTINGS_KEY);
  if (!s) return { version: 1, settings: DEFAULT_SETTINGS };
  try {
    return JSON.parse(s) as SettingsConfig;
  } catch {
    return { version: 1, settings: DEFAULT_SETTINGS };
  }
}

export async function putSettings(store: Storage, settings: AppSettings): Promise<void> {
  // Never persist runtime-only secrets to shared storage.
  const { accessToken: _a, adminToken: _b, ...shared } = settings;
  void _a;
  void _b;
  const cfg: SettingsConfig = { version: 1, settings: shared };
  await store.put(SETTINGS_KEY, JSON.stringify(cfg));
}
