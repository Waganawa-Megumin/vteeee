import type { ShodanMonitorEntry, ShodanMonitorResult } from '@vteeee/shared';
import type { ProxyEnv } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

// Shodan Monitor is built on network Alerts. Each watched IP gets its own alert named `vteeee:<ip>`
// so add/remove is a clean create/delete (Shodan has no reliable "edit the IP list" endpoint), and
// listing = the alerts whose name starts with `vteeee:`. Requires a Shodan membership+ key.
//   List    GET    /shodan/alert/info
//   Create  POST   /shodan/alert         { name, filters: { ip: [ip] } }
//   Delete  DELETE /shodan/alert/{id}
const ALERT_API = 'https://api.shodan.io/shodan/alert';
const PREFIX = 'vteeee:';

const str = (v: any): string | undefined => (typeof v === 'string' && v ? v : undefined);

function mapAlert(a: any): ShodanMonitorEntry {
  const ips: unknown = a?.filters?.ip;
  return {
    id: str(a?.id),
    ip: Array.isArray(ips) ? str(ips[0]) : undefined,
    name: str(a?.name),
    created: str(a?.created),
    size: typeof a?.size === 'number' ? a.size : Array.isArray(ips) ? ips.length : undefined,
    triggers: a?.triggers && typeof a.triggers === 'object' ? Object.keys(a.triggers) : undefined,
  };
}

async function alertError(res: Response): Promise<string> {
  let detail = '';
  try {
    detail = str(((await res.json()) as any)?.error) ?? '';
  } catch {
    /* non-JSON */
  }
  if (res.status === 401) return 'Shodan: invalid API key';
  if (res.status === 403) return 'Shodan Monitor: your plan does not include network monitoring (membership+ required)';
  if (res.status === 429) return 'Shodan: rate limited';
  return `Shodan Monitor error ${res.status}${detail ? ` — ${detail}` : ''}`;
}

/** Raw list of the caller's Shodan alerts. Never throws; returns [] on failure (see caller). */
async function fetchAllAlerts(env: ProxyEnv, signal?: AbortSignal): Promise<any[]> {
  const res = await fetch(`${ALERT_API}/info?key=${encodeURIComponent(env.shodanApiKey ?? '')}`, {
    headers: { accept: 'application/json' },
    signal,
  });
  if (!res.ok) throw new Error(await alertError(res));
  const j = (await res.json()) as any;
  return Array.isArray(j) ? j : Array.isArray(j?.matches) ? j.matches : [];
}

/** List the vteeee-managed monitor entries. Never throws. */
export async function shodanMonitorList(env: ProxyEnv, signal?: AbortSignal): Promise<ShodanMonitorResult> {
  if (!env.shodanApiKey) return { error: 'Shodan not configured' };
  try {
    const all = await fetchAllAlerts(env, signal);
    const entries = all
      .filter((a) => typeof a?.name === 'string' && a.name.startsWith(PREFIX))
      .map(mapAlert)
      .filter((e) => e.ip);
    return { entries };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

/** Add an IP to Shodan Monitor (idempotent — reuses an existing `vteeee:<ip>` alert). Never throws. */
export async function shodanMonitorAdd(
  ip: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<ShodanMonitorResult> {
  if (!env.shodanApiKey) return { error: 'Shodan not configured' };
  const name = `${PREFIX}${ip}`;
  try {
    const all = await fetchAllAlerts(env, signal);
    const existing = all.find((a) => a?.name === name);
    if (existing) return { entries: [mapAlert(existing)], ok: true };
    const res = await fetch(`${ALERT_API}?key=${encodeURIComponent(env.shodanApiKey)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ name, filters: { ip: [ip] } }),
      signal,
    });
    if (!res.ok) return { error: await alertError(res) };
    return { entries: [mapAlert(await res.json())], ok: true };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

/** Remove an IP from Shodan Monitor (deletes its `vteeee:<ip>` alert). Never throws. */
export async function shodanMonitorRemove(
  ip: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<ShodanMonitorResult> {
  if (!env.shodanApiKey) return { error: 'Shodan not configured' };
  const name = `${PREFIX}${ip}`;
  try {
    const all = await fetchAllAlerts(env, signal);
    const target = all.find((a) => a?.name === name);
    if (!target?.id) return { ok: true, removed: ip }; // already gone
    const res = await fetch(`${ALERT_API}/${encodeURIComponent(target.id)}?key=${encodeURIComponent(env.shodanApiKey)}`, {
      method: 'DELETE',
      headers: { accept: 'application/json' },
      signal,
    });
    if (!res.ok) return { error: await alertError(res) };
    return { ok: true, removed: ip };
  } catch (e) {
    return { error: (e as Error).message };
  }
}
