import type { ShodanContext, ShodanService } from '@vteeee/shared';
import type { ProxyEnv } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

const SHODAN_HOST_API = 'https://api.shodan.io/shodan/host';

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
