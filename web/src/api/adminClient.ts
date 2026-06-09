import type { AppSettings, UserRecord } from '@vteeee/shared';

/**
 * Live-mode admin sync against the proxy (Cloudflare KV / Node store).
 * Writes require the admin token. In demo mode these are not used — admin data
 * lives in localStorage with JSON export/import instead.
 */
export class AdminClient {
  private base: string;
  private adminToken?: string | null;

  constructor(settings: AppSettings) {
    this.base = (settings.proxyBaseUrl ?? '').replace(/\/$/, '');
    this.adminToken = settings.adminToken;
  }

  private headers(): HeadersInit {
    const h: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.adminToken) h['Authorization'] = `Bearer ${this.adminToken}`;
    return h;
  }

  async getUsers(): Promise<UserRecord[]> {
    const res = await fetch(`${this.base}/api/admin/users`, { headers: this.headers() });
    if (!res.ok) throw new Error(`getUsers ${res.status}`);
    return ((await res.json()) as { users: UserRecord[] }).users;
  }

  async putUsers(users: UserRecord[]): Promise<void> {
    const res = await fetch(`${this.base}/api/admin/users`, {
      method: 'PUT',
      headers: this.headers(),
      body: JSON.stringify({ users }),
    });
    if (!res.ok) throw new Error(`putUsers ${res.status}`);
  }

  async putSettings(settings: AppSettings): Promise<void> {
    // Never sync runtime-only secrets to shared storage.
    const { accessToken: _a, adminToken: _b, ...shared } = settings;
    void _a;
    void _b;
    const res = await fetch(`${this.base}/api/admin/settings`, {
      method: 'PUT',
      headers: this.headers(),
      body: JSON.stringify({ settings: shared }),
    });
    if (!res.ok) throw new Error(`putSettings ${res.status}`);
  }
}
