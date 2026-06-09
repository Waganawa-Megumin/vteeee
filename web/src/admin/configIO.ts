import type { AppSettings, SettingsConfig, UserRecord, UsersConfig } from '@vteeee/shared';

function download(name: string, content: string): void {
  const blob = new Blob([content], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportUsers(users: UserRecord[]): void {
  const cfg: UsersConfig = { version: 1, users };
  download('users.json', JSON.stringify(cfg, null, 2) + '\n');
}

export function exportSettings(settings: AppSettings): void {
  // Never export runtime-only secrets.
  const { accessToken: _a, adminToken: _b, ...shared } = settings;
  void _a;
  void _b;
  const cfg: SettingsConfig = { version: 1, settings: shared };
  download('settings.json', JSON.stringify(cfg, null, 2) + '\n');
}

export async function importJsonFile<T>(file: File): Promise<T> {
  return JSON.parse(await file.text()) as T;
}
