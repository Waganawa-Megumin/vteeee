import type { ShodanContext, ShodanInternetDb, ShodanScanRequest, ShodanService } from '@vteeee/shared';
import type { ProxyEnv } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

const SHODAN_HOST_API = 'https://api.shodan.io/shodan/host';
const SHODAN_SCAN_API = 'https://api.shodan.io/shodan/scan';
/** Free, key-less "current known state" endpoint — no active scan, no credits. */
const INTERNETDB_API = 'https://internetdb.shodan.io';

function uniqSorted(nums: unknown): number[] {
  if (!Array.isArray(nums)) return [];
  return [...new Set(nums.filter((n): n is number => typeof n === 'number'))].sort((a, b) => a - b);
}

function uniqStrings(arr: unknown): string[] {
  if (!Array.isArray(arr)) return [];
  return [...new Set(arr.filter((s): s is string => typeof s === 'string' && s.length > 0))];
}

/** Collect CVE ids from the top-level `vulns` array and each service's `vulns` map. */
function collectVulns(host: any): string[] {
  const out = new Set<string>();
  const add = (v: unknown) => {
    if (Array.isArray(v)) {
      for (const c of v) if (typeof c === 'string') out.add(c);
    } else if (v && typeof v === 'object') {
      // Per-service `vulns` is a map keyed by CVE id.
      for (const c of Object.keys(v)) out.add(c);
    }
  };
  add(host?.vulns);
  if (Array.isArray(host?.data)) for (const svc of host.data) add(svc?.vulns);
  return [...out].sort();
}

function toServices(data: unknown): ShodanService[] {
  if (!Array.isArray(data)) return [];
  return data
    .map((d: any): ShodanService | null => {
      if (typeof d?.port !== 'number') return null;
      const svc: ShodanService = { port: d.port };
      if (typeof d.transport === 'string') svc.transport = d.transport;
      if (typeof d.product === 'string') svc.product = d.product;
      if (typeof d.version === 'string' && d.version) svc.version = String(d.version);
      const mod = d?._shodan?.module;
      if (typeof mod === 'string') svc.module = mod;
      return svc;
    })
    .filter((s): s is ShodanService => s !== null)
    .sort((a, b) => a.port - b.port)
    .slice(0, 64);
}

/** Map a raw Shodan `/shodan/host/{ip}` response into our ShodanContext shape. */
export function mapShodanHost(host: any): ShodanContext {
  const ctx: ShodanContext = { found: true };
  if (typeof host?.org === 'string') ctx.org = host.org;
  if (typeof host?.isp === 'string') ctx.isp = host.isp;
  if (typeof host?.os === 'string' && host.os) ctx.os = host.os;
  if (typeof host?.country_name === 'string') ctx.country = host.country_name;
  if (typeof host?.city === 'string') ctx.city = host.city;
  if (typeof host?.asn === 'string') ctx.asn = host.asn;
  const hostnames = uniqStrings(host?.hostnames);
  if (hostnames.length) ctx.hostnames = hostnames;
  const ports = uniqSorted(host?.ports);
  if (ports.length) ctx.ports = ports;
  const tags = uniqStrings(host?.tags);
  if (tags.length) ctx.tags = tags;
  const vulns = collectVulns(host);
  if (vulns.length) ctx.vulns = vulns;
  const services = toServices(host?.data);
  if (services.length) ctx.services = services;
  if (typeof host?.last_update === 'string') ctx.lastUpdate = host.last_update;
  return ctx;
}

/**
 * Look up a single IP in Shodan. Supplementary enrichment — never throws and never
 * aborts the batch: failures (bad key, rate limit, network) come back as
 * `{ found: false, error }`. Returns `undefined` if Shodan is disabled or aborted.
 */
export async function shodanHostLookup(
  ip: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<ShodanContext | undefined> {
  if (!env.shodanApiKey) return undefined;
  if (signal?.aborted) return undefined;

  const url = `${SHODAN_HOST_API}/${encodeURIComponent(ip)}?key=${encodeURIComponent(
    env.shodanApiKey,
  )}&minify=false`;

  let res: Response;
  try {
    res = await fetch(url, { headers: { accept: 'application/json' }, signal });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return undefined;
    return { found: false, error: `Shodan unreachable: ${(e as Error).message}` };
  }

  // 404 = host simply isn't in Shodan's dataset (common, and free of charge).
  if (res.status === 404) return { found: false };
  if (res.status === 401) return { found: false, error: 'Shodan: invalid API key' };
  if (res.status === 429) return { found: false, error: 'Shodan: rate limited' };
  if (!res.ok) return { found: false, error: `Shodan error ${res.status}` };

  try {
    return mapShodanHost(await res.json());
  } catch {
    return { found: false, error: 'Shodan: malformed response' };
  }
}

/** Map a raw InternetDB response (`{ip,ports,cpes,hostnames,tags,vulns}`) to our shape (pure). */
export function mapInternetDb(json: any, ip: string): ShodanInternetDb {
  const out: ShodanInternetDb = { found: true, ip: typeof json?.ip === 'string' ? json.ip : ip };
  const ports = uniqSorted(json?.ports);
  if (ports.length) out.ports = ports;
  const vulns = uniqStrings(json?.vulns);
  if (vulns.length) out.vulns = vulns.sort();
  const cpes = uniqStrings(json?.cpes);
  if (cpes.length) out.cpes = cpes;
  const hostnames = uniqStrings(json?.hostnames);
  if (hostnames.length) out.hostnames = hostnames;
  const tags = uniqStrings(json?.tags);
  if (tags.length) out.tags = tags;
  return out;
}

/**
 * Shodan InternetDB — current *known* open ports / CVEs / hostnames for an IP. Free, no key, no
 * active scan (nothing is sent to the target). Never throws. 404 → `{ found: false }` (not in the set).
 */
export async function shodanInternetDb(ip: string, signal?: AbortSignal): Promise<ShodanInternetDb | undefined> {
  if (signal?.aborted) return undefined;
  let res: Response;
  try {
    res = await fetch(`${INTERNETDB_API}/${encodeURIComponent(ip)}`, {
      headers: { accept: 'application/json' },
      signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return undefined;
    return { found: false, error: `InternetDB unreachable: ${(e as Error).message}` };
  }
  if (res.status === 404) return { found: false };
  if (res.status === 429) return { found: false, error: 'InternetDB: rate limited' };
  if (!res.ok) return { found: false, error: `InternetDB error ${res.status}` };
  try {
    return mapInternetDb(await res.json(), ip);
  } catch {
    return { found: false, error: 'InternetDB: malformed response' };
  }
}

/**
 * Request an on-demand Shodan re-scan of an IP (`POST /shodan/scan`). This asks Shodan's own scanners
 * to observe the host again — fresh banners appear in the host dataset shortly after (re-fetch the
 * host to see them). Consumes scan credits. Never throws; needs a Shodan key.
 */
export async function shodanScanRequest(
  ip: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<ShodanScanRequest | undefined> {
  if (!env.shodanApiKey) return undefined;
  if (signal?.aborted) return undefined;
  let res: Response;
  try {
    res = await fetch(`${SHODAN_SCAN_API}?key=${encodeURIComponent(env.shodanApiKey)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: `ips=${encodeURIComponent(ip)}`,
      signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return undefined;
    return { error: `Shodan unreachable: ${(e as Error).message}` };
  }
  if (res.status === 401) return { error: 'Shodan: invalid API key' };
  if (res.status === 403) return { error: 'Shodan: no scan credits / plan does not allow on-demand scans' };
  if (res.status === 429) return { error: 'Shodan: rate limited' };
  if (!res.ok) {
    let detail = '';
    try {
      detail = ((await res.json()) as any)?.error ?? '';
    } catch {
      /* ignore */
    }
    return { error: `Shodan scan error ${res.status}${detail ? ` — ${detail}` : ''}` };
  }
  try {
    const j = (await res.json()) as any;
    return {
      id: typeof j?.id === 'string' ? j.id : undefined,
      count: typeof j?.count === 'number' ? j.count : undefined,
      creditsLeft: typeof j?.credits_left === 'number' ? j.credits_left : undefined,
    };
  } catch {
    return { error: 'Shodan: malformed scan response' };
  }
}
