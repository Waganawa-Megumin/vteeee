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
  const total =
    typeof resp?.total_count === 'number'
      ? resp.total_count
      : typeof resp?.results_count === 'number'
        ? resp.results_count
        : results.length;
  const sample = results
    .map((r) => ({
      domain: typeof r?.domain === 'string' ? r.domain : String(val(r?.domain) ?? ''),
      riskScore: typeof r?.domain_risk?.risk_score === 'number' ? r.domain_risk.risk_score : undefined,
    }))
    .filter((d) => d.domain)
    .sort((a, b) => (b.riskScore ?? -1) - (a.riskScore ?? -1))
    .slice(0, 12);
  return {
    found: total > 0,
    mode: 'reverse-ip',
    hostedDomainCount: total,
    sampleDomains: sample.length ? sample : undefined,
    raw: { total_count: total, results_count: resp?.results_count, sample },
  };
}

async function irisFetch(url: string, signal?: AbortSignal): Promise<any | { __error: string }> {
  let res: Response;
  try {
    res = await fetch(url, { headers: { accept: 'application/json' }, signal });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return { __error: 'aborted' };
    return { __error: `DomainTools unreachable: ${(e as Error).message}` };
  }
  if (res.status === 404) return { __notFound: true };
  if (res.status === 401 || res.status === 403) return { __error: 'DomainTools: auth/permission error' };
  if (res.status === 429 || res.status === 503) return { __error: 'DomainTools: rate limited' };
  // 200 and 206 (partial) both carry usable data.
  if (!res.ok && res.status !== 206) return { __error: `DomainTools error ${res.status}` };
  try {
    return await res.json();
  } catch {
    return { __error: 'DomainTools: malformed response' };
  }
}

function creds(env: ProxyEnv): string {
  return `api_username=${encodeURIComponent(env.domaintoolsApiUsername ?? '')}&api_key=${encodeURIComponent(
    env.domaintoolsApiKey ?? '',
  )}`;
}

/** DomainTools Iris Enrich for a single domain (forward lookup). */
export async function domaintoolsEnrichDomain(
  domain: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<DomainToolsContext | undefined> {
  if (!env.domaintoolsApiUsername || !env.domaintoolsApiKey) return undefined;
  if (signal?.aborted) return undefined;
  const json = await irisFetch(`${IRIS_ENRICH}?domain=${encodeURIComponent(domain)}&${creds(env)}`, signal);
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
  const json = await irisFetch(`${IRIS_INVESTIGATE}?ip=${encodeURIComponent(ip)}&${creds(env)}`, signal);
  if (json?.__error) return { found: false, mode: 'reverse-ip', error: json.__error };
  if (json?.__notFound) return { found: false, mode: 'reverse-ip' };
  return mapIrisInvestigateReverseIp(json?.response ?? {});
}
