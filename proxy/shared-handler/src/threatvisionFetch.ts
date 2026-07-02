import type { EnrichableType, ThreatVisionAdversary, ThreatVisionContext } from '@vteeee/shared';
import type { ProxyEnv } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

const DEFAULT_BASE = 'https://api.threatvision.org';

function baseUrl(env: ProxyEnv): string {
  return (env.threatvisionBaseUrl || DEFAULT_BASE).replace(/\/$/, '');
}

/** ISO date from a Unix-seconds timestamp. */
function isoSec(sec: unknown): string | undefined {
  return typeof sec === 'number' && sec > 0 ? new Date(sec * 1000).toISOString() : undefined;
}

/** Collect names from an array of strings or `{name}` objects, dropping nulls + dupes. */
function names(v: unknown, limit = 12): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: string[] = [];
  for (const x of v) {
    if (typeof x === 'string' && x.trim()) out.push(x.trim());
    else if (x && typeof x === 'object' && typeof (x as any).name === 'string' && (x as any).name.trim())
      out.push((x as any).name.trim());
  }
  const uniq = Array.from(new Set(out)).slice(0, limit);
  return uniq.length ? uniq : undefined;
}

/** Plain non-empty strings (drops the nulls the API is documented to mix into arrays). */
function strs(v: unknown, limit = 30): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out = Array.from(new Set(v.filter((x): x is string => typeof x === 'string' && x.trim().length > 0))).slice(0, limit);
  return out.length ? out : undefined;
}

function num(v: unknown): number | undefined {
  return typeof v === 'number' ? v : undefined;
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() ? v : undefined;
}

function mapSummary(json: any, ctx: ThreatVisionContext): void {
  const s = json?.summary;
  if (!s || typeof s !== 'object') return;
  if (typeof s.related_reports === 'number') ctx.relatedReports = s.related_reports;
  if (typeof s.related_samples === 'number') ctx.relatedSamples = s.related_samples;
  if (typeof s.related_adversaries === 'number') ctx.relatedAdversaries = s.related_adversaries;
  if (typeof s.dns_records === 'number') ctx.dnsRecords = s.dns_records;
  if (typeof s.osint === 'number') ctx.osint = s.osint;
}

/** Map `GET /network/ips/:address` to our context. */
export function mapTvIp(json: any): ThreatVisionContext {
  if (!json || typeof json !== 'object') return { found: false, kind: 'ip' };
  if (json.analysis_status === false)
    return { found: false, kind: 'ip', error: str(json.message) ?? 'not analyzed yet' };
  const ctx: ThreatVisionContext = { found: false, kind: 'ip' };
  ctx.riskLevel = str(json.risk_level);
  ctx.riskScore = num(json.risk_score);
  ctx.riskTypes = strs(json.risk_types);
  ctx.adversaries = names(json.adversaries);
  // Behavioural attributes + sharing tags (e.g. "Malware C2", "Hosting").
  const attr = [...(names(json.attributes) ?? []), ...(names(json.ip_sharing) ?? [])];
  if (attr.length) ctx.attributes = Array.from(new Set(attr)).slice(0, 12);
  ctx.country = str(json.country);
  ctx.city = str(json.city);
  ctx.region = str(json.region);
  ctx.lastUpdate = str(json.last_update_at);
  mapSummary(json, ctx);
  ctx.found = Boolean(
    ctx.riskLevel || ctx.riskScore != null || ctx.adversaries || ctx.attributes || ctx.country || json.summary,
  );
  ctx.raw = json;
  return ctx;
}

/** Map `GET /network/domains/:fqdn` to our context (registrar instead of geo). */
export function mapTvDomain(json: any): ThreatVisionContext {
  if (!json || typeof json !== 'object') return { found: false, kind: 'domain' };
  if (json.analysis_status === false)
    return { found: false, kind: 'domain', error: str(json.message) ?? 'not analyzed yet' };
  const ctx: ThreatVisionContext = { found: false, kind: 'domain' };
  ctx.riskLevel = str(json.risk_level);
  ctx.riskScore = num(json.risk_score);
  ctx.riskTypes = strs(json.risk_types);
  ctx.adversaries = names(json.adversaries);
  ctx.attributes = names(json.attributes);
  ctx.registrar = str(json.registrar);
  ctx.lastUpdate = str(json.last_update_at);
  mapSummary(json, ctx);
  ctx.found = Boolean(
    ctx.riskLevel || ctx.riskScore != null || ctx.adversaries || ctx.registrar || json.summary,
  );
  ctx.raw = json;
  return ctx;
}

/** Map `GET /samples/search?query=` to our context, picking the sample matching `value`. */
export function mapTvSample(json: any, value: string): ThreatVisionContext {
  const list: any[] = Array.isArray(json?.samples) ? json.samples : [];
  const v = value.toLowerCase();
  const item =
    list.find((s) => typeof s?.sha256 === 'string' && s.sha256.toLowerCase() === v) ??
    list.find((s) => typeof s?.md5 === 'string' && s.md5.toLowerCase() === v) ??
    list[0];
  if (!item || typeof item !== 'object') return { found: false, kind: 'sample' };
  const ctx: ThreatVisionContext = { found: true, kind: 'sample' };
  ctx.riskLevel = str(item.risk_level);
  ctx.sha256 = str(item.sha256);
  ctx.md5 = str(item.md5);
  ctx.size = num(item.size);
  ctx.firstSeen = isoSec(item.first_seen);
  if (typeof item.has_network_activity === 'boolean') ctx.hasNetworkActivity = item.has_network_activity;
  ctx.adversaries = names(item.adversaries);
  ctx.malwareFamilies = names(item.malwares);
  ctx.raw = item;
  return ctx;
}

/** Map `GET /adversaries/search?query=` to the on-demand adversary profile (first match). */
export function mapTvAdversary(json: any): ThreatVisionAdversary {
  const a = Array.isArray(json?.adversaries) ? json.adversaries[0] : undefined;
  if (!a || typeof a !== 'object') return {};
  const out: ThreatVisionAdversary = {};
  out.name = str(a.name);
  out.aliases = strs(a.aliases);
  out.originCountries = strs(a.origin_countries);
  out.targetedCountries = strs(a.targeted_countries); // strs drops the documented nulls
  out.targetedIndustries = strs(a.targeted_industries);
  out.overview = str(a.overview);
  return out;
}

// --- OAuth2 client-credentials token, cached per isolate (tokens last ~1 year). ---
let tokenCache: { token: string; exp: number } | null = null;

async function getToken(env: ProxyEnv, signal?: AbortSignal): Promise<string | undefined> {
  if (env.threatvisionAccessToken) return env.threatvisionAccessToken;
  if (!env.threatvisionClientId || !env.threatvisionClientSecret) return undefined;
  const now = Date.now();
  if (tokenCache && tokenCache.exp > now + 60_000) return tokenCache.token;
  let res: Response;
  try {
    res = await fetch(`${baseUrl(env)}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: env.threatvisionClientId,
        client_secret: env.threatvisionClientSecret,
      }).toString(),
      signal,
    });
  } catch {
    return undefined;
  }
  if (!res.ok) return undefined;
  try {
    const j: any = await res.json();
    if (typeof j?.access_token === 'string') {
      const ttl = (typeof j.expires_in === 'number' && j.expires_in > 0 ? j.expires_in : 3600) * 1000;
      tokenCache = { token: j.access_token, exp: now + ttl };
      return j.access_token;
    }
  } catch {
    /* ignore */
  }
  return undefined;
}

async function tvFetch(path: string, env: ProxyEnv, signal?: AbortSignal): Promise<{ json?: any; __error?: string }> {
  const token = await getToken(env, signal);
  if (!token) return { __error: 'ThreatVision: missing/invalid credentials' };
  let res: Response;
  try {
    res = await fetch(`${baseUrl(env)}${path}`, {
      headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
      signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return { __error: 'aborted' };
    return { __error: `ThreatVision unreachable: ${(e as Error).message}` };
  }
  if (res.status === 401 || res.status === 403) return { __error: `ThreatVision ${res.status} — check credentials / entitlement` };
  if (res.status === 429) return { __error: 'ThreatVision: rate limited' };
  if (res.status === 404) return { json: null };
  if (!res.ok) return { __error: `ThreatVision error ${res.status}` };
  try {
    return { json: await res.json() };
  } catch {
    return { __error: 'ThreatVision: malformed response' };
  }
}

function configured(env: ProxyEnv): boolean {
  return Boolean(env.threatvisionAccessToken || (env.threatvisionClientId && env.threatvisionClientSecret));
}

/** IP detail (1 AAP). */
export async function threatvisionIp(value: string, env: ProxyEnv, signal?: AbortSignal): Promise<ThreatVisionContext | undefined> {
  if (!configured(env)) return undefined;
  if (signal?.aborted) return undefined;
  const r = await tvFetch(`/api/v2/network/ips/${encodeURIComponent(value)}`, env, signal);
  if (r.__error) return { found: false, kind: 'ip', error: r.__error };
  return mapTvIp(r.json);
}

/** Domain detail (1 AAP). */
export async function threatvisionDomain(value: string, env: ProxyEnv, signal?: AbortSignal): Promise<ThreatVisionContext | undefined> {
  if (!configured(env)) return undefined;
  if (signal?.aborted) return undefined;
  const r = await tvFetch(`/api/v2/network/domains/${encodeURIComponent(value)}`, env, signal);
  if (r.__error) return { found: false, kind: 'domain', error: r.__error };
  return mapTvDomain(r.json);
}

/** Sample attribution via search (0 AAP) — risk + adversary + malware family for a hash. */
export async function threatvisionSample(value: string, env: ProxyEnv, signal?: AbortSignal): Promise<ThreatVisionContext | undefined> {
  if (!configured(env)) return undefined;
  if (signal?.aborted) return undefined;
  const r = await tvFetch(`/api/v2/samples/search?query=${encodeURIComponent(value)}`, env, signal);
  if (r.__error) return { found: false, kind: 'sample', error: r.__error };
  return mapTvSample(r.json, value);
}

/** Route a single indicator to the right ThreatVision endpoint. */
export async function threatvisionLookup(
  value: string,
  type: EnrichableType,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<ThreatVisionContext | undefined> {
  if (type === 'ipv4' || type === 'ipv6') return threatvisionIp(value, env, signal);
  if (type === 'domain') return threatvisionDomain(value, env, signal);
  if (type === 'md5' || type === 'sha1' || type === 'sha256') return threatvisionSample(value, env, signal);
  return undefined;
}

/** On-demand adversary (APT group) profile by name — 0 AAP. */
export async function threatvisionAdversary(
  name: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<ThreatVisionAdversary | undefined> {
  if (!configured(env)) return undefined;
  const r = await tvFetch(`/api/v2/adversaries/search?query=${encodeURIComponent(name)}`, env, signal);
  if (r.__error) return { error: r.__error };
  const out = mapTvAdversary(r.json);
  if (!out.name) out.name = name;
  return out;
}
