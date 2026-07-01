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

/** Normalize an array of host-like entries (strings or {host}/{name}/{nameserver}) to strings. */
function hostList(o: any, keys: string[]): string[] {
  for (const k of keys) {
    const v = o?.[k];
    if (Array.isArray(v) && v.length) {
      const out = v
        .map((e) => (typeof e === 'string' ? e : e?.host ?? e?.name ?? e?.nameserver ?? e?.value ?? e?.hostname))
        .filter((s: any): s is string => typeof s === 'string' && s.length > 0);
      if (out.length) return [...new Set(out)];
    }
  }
  return [];
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

/** Map a DNSLytics DomainInfo payload into our context shape (tolerant to key naming). */
export function mapDnslyticsDomain(json: any): DnslyticsContext {
  const o = root(json);
  const ctx: DnslyticsContext = { found: true, kind: 'domain' };
  ctx.registrar = pickStr(o, ['registrar', 'registrarname']);
  ctx.created = pickStr(o, ['created', 'createddate', 'create_date', 'registered', 'creationdate']);
  ctx.updated = pickStr(o, ['updated', 'updateddate', 'changed', 'lastupdated']);
  ctx.expires = pickStr(o, ['expires', 'expiresdate', 'expiration', 'expiry', 'expirationdate']);
  const ns = hostList(o, ['nameservers', 'ns', 'nameserver']);
  if (ns.length) ctx.nameServers = ns;
  const mx = hostList(o, ['mx', 'mailservers', 'mailserver']);
  if (mx.length) ctx.mailServers = mx;
  ctx.provider = pickStr(o, ['provider', 'hoster', 'hosting', 'hostingprovider']);
  ctx.popularity = pickNum(o, ['rank', 'popularity', 'globalrank', 'alexarank']);
  ctx.threat = pickStr(o, ['threat', 'threatlevel', 'reputation']);
  const tags = Array.isArray(o?.tags) ? o.tags.filter((t: any) => typeof t === 'string') : [];
  if (tags.length) ctx.tags = tags;
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

/** DNSLytics DomainInfo for a single domain. */
export async function dnslyticsDomainInfo(
  domain: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<DnslyticsContext | undefined> {
  if (!env.dnslyticsApiKey) return undefined;
  if (signal?.aborted) return undefined;
  const url = `${baseUrl(env)}/domaininfo/${encodeURIComponent(domain)}?apikey=${encodeURIComponent(
    env.dnslyticsApiKey,
  )}`;
  const json = await dnslFetch(url, signal);
  if (json?.__error) return { found: false, kind: 'domain', error: json.__error };
  if (json?.__notFound) return { found: false, kind: 'domain' };
  return mapDnslyticsDomain(json);
}
