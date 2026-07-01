import type { DnslyticsContext } from '@vteeee/shared';
import type { ProxyEnv } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

const DEFAULT_BASE = 'https://api.dnslytics.net/v1';

/**
 * DNSLytics response shapes vary by plan/version, and the docs are unreachable from
 * this environment, so these getters read a broad set of candidate keys (and unwrap
 * a `data`/`response` envelope). The raw payload is always kept for the detail panel.
 */
function root(json: any): any {
  return json?.data ?? json?.response ?? json ?? {};
}

function pickStr(o: any, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = o?.[k];
    if (typeof v === 'string' && v.length > 0) return v;
    if (typeof v === 'number') return String(v);
  }
  return undefined;
}

function pickNum(o: any, keys: string[]): number | undefined {
  for (const k of keys) {
    const v = o?.[k];
    if (typeof v === 'number' && Number.isFinite(v)) return v;
    if (typeof v === 'string' && v.trim() && Number.isFinite(Number(v))) return Number(v);
  }
  return undefined;
}

/** Summarize the DNSLytics `blocklist` flags into a short threat string (undefined when clean). */
function blocklistSummary(bl: any): string | undefined {
  if (!bl || typeof bl !== 'object') return undefined;
  const flags: string[] = [];
  if (bl.dnsbl) flags.push('DNSBL');
  if (bl.openproxy) flags.push('open proxy');
  if (bl.adulthosting) flags.push('adult hosting');
  if (bl.mthreats) flags.push('malware/threats');
  return flags.length ? flags.join(', ') : undefined;
}

/**
 * Map a DNSLytics IPInfo payload into our context shape. Shape (verified against a real
 * response): `{ status, data: { asinfo:{asn,cidr,shortname}, shortname, ptr, ndomains,
 * blocklist:{dnsbl,openproxy,...}, geoinfo:{country_name,country_code} } }`.
 */
export function mapDnslyticsIp(json: any): DnslyticsContext {
  const o = root(json); // unwraps the { data: … } envelope
  const as = o?.asinfo ?? {};
  const geo = o?.geoinfo ?? {};
  const ctx: DnslyticsContext = { found: true, kind: 'ip' };
  ctx.asn = pickNum(as, ['asn']) ?? pickNum(o, ['asn', 'as', 'as_number']);
  ctx.org = pickStr(o, ['shortname', 'org', 'as_org', 'organization']) ?? pickStr(as, ['shortname']);
  ctx.network = pickStr(as, ['cidr', 'prefix']) ?? pickStr(o, ['network', 'cidr', 'prefix', 'route']);
  ctx.country = pickStr(geo, ['country_name', 'country_code']) ?? pickStr(o, ['country', 'countryname', 'country_code']);
  const city = pickStr(geo, ['city']) ?? pickStr(o, ['city']);
  if (city) ctx.city = city;
  const ptr = pickStr(o, ['ptr', 'hostname', 'reverse', 'rdns', 'host']);
  if (ptr) ctx.hostname = ptr;
  ctx.domainsOnIp = pickNum(o, ['ndomains', 'domainscount', 'numdomains', 'hosted_domains']);
  // IPInfo returns a `domains` sample inline — surface it (avoids a separate ReverseIP credit).
  if (Array.isArray(o?.domains)) {
    const sample = o.domains.filter((d: any): d is string => typeof d === 'string' && d.length > 0).slice(0, 12);
    if (sample.length) ctx.hostedDomains = sample;
  }
  ctx.threat = blocklistSummary(o?.blocklist) ?? pickStr(o, ['threat', 'threatlevel', 'reputation']);
  const tags = Array.isArray(o?.tags) ? o.tags.filter((t: any) => typeof t === 'string') : [];
  if (tags.length) ctx.tags = tags;
  ctx.raw = o;
  return ctx;
}

/** Dedupe a list of history records by key, keeping the most recent (by `updatedate`) first. */
function recentUnique(recs: unknown, keyOf: (r: any) => unknown): string[] {
  if (!Array.isArray(recs)) return [];
  const sorted = [...recs].sort((a, b) =>
    String(b?.updatedate ?? b?.lastseen ?? '').localeCompare(String(a?.updatedate ?? a?.lastseen ?? '')),
  );
  const seen = new Set<string>();
  const out: string[] = [];
  for (const r of sorted) {
    const k = keyOf(r);
    if (typeof k === 'string' && k.length > 0 && !seen.has(k)) {
      seen.add(k);
      out.push(k);
    }
  }
  return out;
}

/**
 * Map a DNSLytics HostingHistory payload (IP/DNS history for a domain) into our context shape.
 * Verified shape: `{ status, data: { ipv4:[{ip,updatedate}], ipv6:[…], dns:[{dns,updatedate}],
 * mx:[{mx,updatedate}], spf:[{record,updatedate}] } }`.
 */
export function mapDnslyticsHostingHistory(json: any): DnslyticsContext {
  const o = root(json);
  const ctx: DnslyticsContext = { found: true, kind: 'domain' };
  const ips = recentUnique([...(Array.isArray(o?.ipv4) ? o.ipv4 : []), ...(Array.isArray(o?.ipv6) ? o.ipv6 : [])], (r) => r?.ip).slice(0, 12);
  if (ips.length) ctx.ips = ips;
  // NS records come under `dns` in the example (or `ns` per the field list).
  const ns = recentUnique([...(Array.isArray(o?.dns) ? o.dns : []), ...(Array.isArray(o?.ns) ? o.ns : [])], (r) => r?.dns ?? r?.ns ?? r?.host).slice(0, 12);
  if (ns.length) ctx.nameServers = ns;
  const mx = recentUnique(o?.mx, (r) => r?.mx ?? r?.host).slice(0, 12);
  if (mx.length) ctx.mailServers = mx;
  const spf = recentUnique(o?.spf, (r) => r?.record ?? r?.spf).slice(0, 4);
  if (spf.length) ctx.spf = spf;
  ctx.raw = o;
  return ctx;
}

function baseUrl(env: ProxyEnv): string {
  return (env.dnslyticsBaseUrl || DEFAULT_BASE).replace(/\/$/, '');
}

async function dnslFetch(url: string, signal?: AbortSignal): Promise<any | { __error: string } | { __notFound: true }> {
  let res: Response;
  try {
    res = await fetch(url, { headers: { accept: 'application/json' }, signal });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return { __error: 'aborted' };
    return { __error: `DNSLytics unreachable: ${(e as Error).message}` };
  }
  if (res.status === 404) return { __notFound: true };
  if (res.status === 401 || res.status === 403) return { __error: 'DNSLytics: invalid API key' };
  if (res.status === 429) return { __error: 'DNSLytics: rate limited' };
  if (!res.ok) return { __error: `DNSLytics error ${res.status}` };
  try {
    return await res.json();
  } catch {
    return { __error: 'DNSLytics: malformed response' };
  }
}

/** DNSLytics IPInfo for a single IP. */
export async function dnslyticsIpInfo(
  ip: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<DnslyticsContext | undefined> {
  if (!env.dnslyticsApiKey) return undefined;
  if (signal?.aborted) return undefined;
  const url = `${baseUrl(env)}/ipinfo/${encodeURIComponent(ip)}?apikey=${encodeURIComponent(env.dnslyticsApiKey)}`;
  const json = await dnslFetch(url, signal);
  if (json?.__error) return { found: false, kind: 'ip', error: json.__error };
  if (json?.__notFound) return { found: false, kind: 'ip' };
  // DNSLytics wraps results in `{ status: 'succeed', data: … }`.
  if (json?.status && json.status !== 'succeed') return { found: false, kind: 'ip' };
  return mapDnslyticsIp(json);
}

/** DNSLytics HostingHistory for a single domain (IP/DNS history: A/AAAA/MX/NS/SPF). */
export async function dnslyticsHostingHistory(
  domain: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<DnslyticsContext | undefined> {
  if (!env.dnslyticsApiKey) return undefined;
  if (signal?.aborted) return undefined;
  const url = `${baseUrl(env)}/hostinghistory/${encodeURIComponent(domain)}?apikey=${encodeURIComponent(
    env.dnslyticsApiKey,
  )}`;
  const json = await dnslFetch(url, signal);
  if (json?.__error) return { found: false, kind: 'domain', error: json.__error };
  if (json?.__notFound) return { found: false, kind: 'domain' };
  if (json?.status && json.status !== 'succeed') return { found: false, kind: 'domain' };
  return mapDnslyticsHostingHistory(json);
}
