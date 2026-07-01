import type { DomainToolsContext } from '@vteeee/shared';
import type { ProxyEnv } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

const IRIS_ENRICH = 'https://api.domaintools.com/v1/iris-enrich/';
const IRIS_INVESTIGATE = 'https://api.domaintools.com/v1/iris-investigate/';

/** Most Iris values are wrapped as `{ value: X }`; some are plain. Unwrap either. */
function val(x: any): any {
  if (x && typeof x === 'object' && 'value' in x) return x.value;
  return x;
}

function strs(arr: any, pick: (o: any) => any): string[] {
  if (!Array.isArray(arr)) return [];
  return [...new Set(arr.map((o) => val(pick(o))).filter((s): s is string => typeof s === 'string' && s.length > 0))];
}

function nums(arr: unknown): number[] {
  if (!Array.isArray(arr)) return [];
  return [...new Set(arr.map((n) => val(n)).filter((n): n is number => typeof n === 'number'))];
}

/** Iris `not_after` etc. come as an int YYYYMMDD (e.g. 20260919). Render as an ISO date. */
function ymdToIso(v: unknown): string | undefined {
  const n = typeof v === 'number' ? v : Number(v);
  if (!Number.isFinite(n) || n < 19000101) return undefined;
  const s = String(n);
  if (s.length !== 8) return undefined;
  return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}`;
}

/** Map one Iris Enrich `results[]` entry (a domain) into our context shape. */
export function mapIrisEnrich(r: any): DomainToolsContext {
  const ctx: DomainToolsContext = { found: true, mode: 'enrich' };
  const risk = r?.domain_risk;
  if (typeof risk?.risk_score === 'number') ctx.riskScore = risk.risk_score;
  if (Array.isArray(risk?.components)) {
    const comps = risk.components
      .filter((c: any) => c && typeof c.name === 'string')
      .map((c: any) => ({ name: c.name, riskScore: typeof c.risk_score === 'number' ? c.risk_score : 0 }));
    if (comps.length) ctx.riskComponents = comps;
  }
  const created = val(r?.create_date);
  if (typeof created === 'string' && created) ctx.created = created;
  const firstSeen = val(r?.first_seen);
  if (typeof firstSeen === 'string' && firstSeen) ctx.firstSeen = firstSeen;
  const registrar = val(r?.registrar);
  if (typeof registrar === 'string' && registrar) ctx.registrar = registrar;

  const ips = strs(r?.ip, (o) => o?.address);
  if (ips.length) ctx.ips = ips;
  const asns = Array.isArray(r?.ip) ? nums(r.ip.flatMap((o: any) => o?.asn ?? [])) : [];
  if (asns.length) ctx.asns = asns;
  const ns = strs(r?.name_server, (o) => o?.host);
  if (ns.length) ctx.nameServers = ns;
  const mx = strs(r?.mx, (o) => o?.host);
  if (mx.length) ctx.mailServers = mx;

  const ssl = Array.isArray(r?.ssl_info) ? r.ssl_info[0] : undefined;
  const issuer = val(ssl?.issuer_common_name);
  if (typeof issuer === 'string' && issuer) ctx.sslIssuer = issuer;
  const notAfter = ymdToIso(ssl?.not_after?.value ?? ssl?.not_after);
  if (notAfter) ctx.sslNotAfter = notAfter;

  if (typeof r?.website_response === 'number') ctx.websiteResponse = r.website_response;
  const server = val(r?.server_type);
  if (typeof server === 'string' && server) ctx.serverType = server;
  const title = val(r?.website_title);
  if (typeof title === 'string' && title) ctx.websiteTitle = title;
  const tags = Array.isArray(r?.tags) ? r.tags.map((t: any) => val(t)).filter((t: any) => typeof t === 'string' && t) : [];
  if (tags.length) ctx.tags = tags;

  ctx.raw = r;
  return ctx;
}

/** Map an Iris Investigate reverse-IP response (domains hosted on an IP) into our context shape. */
export function mapIrisInvestigateReverseIp(resp: any): DomainToolsContext {
  const results: any[] = Array.isArray(resp?.results) ? resp.results : [];
  // >10,000 matches returns HTTP 200 with response.error.code 413 + limit_exceeded.
  const limited = resp?.limit_exceeded === true || resp?.error?.code === 413;
  const totalRaw =
    typeof resp?.total_count === 'number'
      ? resp.total_count
      : typeof resp?.results_count === 'number'
        ? resp.results_count
        : results.length;
  const total = limited && !totalRaw ? 10000 : totalRaw;
  const sample = results
    .map((r) => ({
      domain: typeof r?.domain === 'string' ? r.domain : String(val(r?.domain) ?? ''),
      // Risk can be top-level (risk_score) or nested (domain_risk.risk_score).
      riskScore:
        typeof r?.domain_risk?.risk_score === 'number'
          ? r.domain_risk.risk_score
          : typeof r?.risk_score === 'number'
            ? r.risk_score
            : undefined,
    }))
    .filter((d) => d.domain)
    .sort((a, b) => (b.riskScore ?? -1) - (a.riskScore ?? -1))
    .slice(0, 12);
  return {
    found: total > 0 || limited,
    mode: 'reverse-ip',
    hostedDomainCount: total,
    sampleDomains: sample.length ? sample : undefined,
    raw: { total_count: total, results_count: resp?.results_count, limited, sample },
  };
}

/**
 * Fetch an Iris endpoint. Tries Header auth (`X-Api-Key`, DomainTools' recommended scheme)
 * first, and falls back to open-key (`api_username` + `api_key`) if the account rejects the
 * header (401). Splits 401 (bad key) from 403 (endpoint not in the account's subscription).
 */
async function irisFetch(base: string, query: string, env: ProxyEnv, signal?: AbortSignal): Promise<any> {
  const enc = encodeURIComponent;
  const attempt = async (headerAuth: boolean): Promise<Response | { __error: string }> => {
    const url = headerAuth
      ? `${base}?${query}`
      : `${base}?${query}&api_username=${enc(env.domaintoolsApiUsername ?? '')}&api_key=${enc(env.domaintoolsApiKey ?? '')}`;
    try {
      const headers: Record<string, string> = { accept: 'application/json' };
      if (headerAuth) headers['X-Api-Key'] = env.domaintoolsApiKey ?? '';
      return await fetch(url, { headers, signal });
    } catch (e) {
      if ((e as Error).name === 'AbortError') return { __error: 'aborted' };
      return { __error: `DomainTools unreachable: ${(e as Error).message}` };
    }
  };

  let res = await attempt(true);
  if ('__error' in res) return res;
  if (res.status === 401) {
    const fallback = await attempt(false); // header rejected — try open-key
    if ('__error' in fallback) return fallback;
    res = fallback;
  }

  if (res.status === 404) return { __notFound: true };
  if (res.status === 401)
    return { __error: 'DomainTools 401 — invalid API key/username (check DOMAINTOOLS_API_KEY & _USERNAME)' };
  if (res.status === 403)
    return { __error: 'DomainTools 403 — account lacks access to this endpoint (Enrich / Investigate subscription)' };
  if (res.status === 429 || res.status === 503) return { __error: 'DomainTools: rate limited' };
  // 200 and 206 (partial) both carry usable data.
  if (!res.ok && res.status !== 206) return { __error: `DomainTools error ${res.status}` };
  try {
    return await res.json();
  } catch {
    return { __error: 'DomainTools: malformed response' };
  }
}

/**
 * DomainTools forward lookup for a single domain. Tries Iris Investigate `?domain=` first
 * (the commonly-provisioned product) and falls back to Iris Enrich on 403. Both return
 * `response.results[0]` in the same shape, so one mapper handles either.
 */
export async function domaintoolsEnrichDomain(
  domain: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<DomainToolsContext | undefined> {
  if (!env.domaintoolsApiUsername || !env.domaintoolsApiKey) return undefined;
  if (signal?.aborted) return undefined;
  const q = `domain=${encodeURIComponent(domain)}`;
  // Iris Investigate is the more commonly-provisioned product and returns the same domain
  // profile, so try it first; fall back to Iris Enrich (the batch product) on 403.
  let json = await irisFetch(IRIS_INVESTIGATE, q, env, signal);
  if (typeof json?.__error === 'string' && json.__error.includes('403')) {
    json = await irisFetch(IRIS_ENRICH, q, env, signal);
  }
  if (json?.__error) return { found: false, mode: 'enrich', error: json.__error };
  if (json?.__notFound) return { found: false, mode: 'enrich' };
  const result = json?.response?.results?.[0];
  if (!result) return { found: false, mode: 'enrich' };
  return mapIrisEnrich(result);
}

/** DomainTools Iris Investigate reverse-IP lookup (domains hosted on an IP). */
export async function domaintoolsReverseIp(
  ip: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<DomainToolsContext | undefined> {
  if (!env.domaintoolsApiUsername || !env.domaintoolsApiKey) return undefined;
  if (signal?.aborted) return undefined;
  const json = await irisFetch(IRIS_INVESTIGATE, `ip=${encodeURIComponent(ip)}`, env, signal);
  if (json?.__error) return { found: false, mode: 'reverse-ip', error: json.__error };
  if (json?.__notFound) return { found: false, mode: 'reverse-ip' };
  return mapIrisInvestigateReverseIp(json?.response ?? {});
}
