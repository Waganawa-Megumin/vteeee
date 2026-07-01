import type {
  EnrichableType,
  Intel471Context,
  Intel471Malware,
  Intel471Search,
  Intel471SearchItem,
} from '@vteeee/shared';
import type { ProxyEnv } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

const DEFAULT_BASE = 'https://api.intel471.com/v1';

/** Our IOC type → Intel 471 `iocType` request value (adversary IOC feed). */
const IOC_TYPE: Partial<Record<EnrichableType, string>> = {
  ipv4: 'IpAddress',
  ipv6: 'IpAddress',
  domain: 'MaliciousDomain',
  url: 'MaliciousURL',
  md5: 'MD5',
  sha1: 'SHA1',
  sha256: 'SHA256',
};

/** Our IOC type → Intel 471 `indicatorType` (Malware Intelligence indicators; lowercase). */
const INDICATOR_TYPE: Partial<Record<EnrichableType, string>> = {
  ipv4: 'ipv4',
  ipv6: 'ipv6',
  domain: 'domain',
  url: 'url',
  md5: 'file',
  sha1: 'file',
  sha256: 'file',
};

/** ASCII → base64 (works in both Workers and Node without btoa/Buffer typings). */
function base64(input: string): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let out = '';
  for (let i = 0; i < input.length; i += 3) {
    const a = input.charCodeAt(i);
    const b = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    const c = i + 2 < input.length ? input.charCodeAt(i + 2) : 0;
    out += chars[a >> 2];
    out += chars[((a & 3) << 4) | (b >> 4)];
    out += i + 1 < input.length ? chars[((b & 15) << 2) | (c >> 6)] : '=';
    out += i + 2 < input.length ? chars[c & 63] : '=';
  }
  return out;
}

function isoMs(ms: unknown): string | undefined {
  return typeof ms === 'number' && ms > 0 ? new Date(ms).toISOString() : undefined;
}

/** Map an Intel 471 `/iocs` response to our context, picking the record matching `value`. */
export function mapIntel471Ioc(json: any, value: string): Intel471Context {
  const iocs: any[] = Array.isArray(json?.iocs) ? json.iocs : [];
  const total = typeof json?.iocTotalCount === 'number' ? json.iocTotalCount : iocs.length;
  // `ioc=` does substring matching — prefer the record whose value matches exactly.
  const item =
    iocs.find((i) => typeof i?.value === 'string' && i.value.toLowerCase() === value.toLowerCase()) ?? iocs[0];
  if (!item) return { found: false, totalCount: total };

  const links = item.links ?? {};
  const ctx: Intel471Context = { found: true, totalCount: total };
  if (typeof item.type === 'string') ctx.type = item.type;
  ctx.activeFrom = isoMs(item.activeFrom);
  ctx.activeTill = isoMs(item.activeTill);
  ctx.lastUpdated = isoMs(item.lastUpdated);
  if (typeof item.ispName === 'string' && item.ispName) ctx.isp = item.ispName;
  if (typeof item.ispCountryCode === 'string' && item.ispCountryCode) ctx.ispCountryCode = item.ispCountryCode;
  if (typeof links.reportTotalCount === 'number') ctx.reports = links.reportTotalCount;
  if (typeof links.actorTotalCount === 'number') ctx.actors = links.actorTotalCount;
  if (typeof links.malwareReportTotalCount === 'number') ctx.malwareReports = links.malwareReportTotalCount;
  if (typeof links.eventTotalCount === 'number') ctx.events = links.eventTotalCount;

  const reports = Array.isArray(links.reports) ? links.reports : [];
  const titles = reports.map((r: any) => r?.subject).filter((s: any): s is string => typeof s === 'string').slice(0, 3);
  if (titles.length) ctx.reportTitles = titles;
  const portal = reports.find((r: any) => typeof r?.portalReportUrl === 'string')?.portalReportUrl;
  if (portal) ctx.portalUrl = portal;

  ctx.raw = item;
  return ctx;
}

/** Map an Intel 471 `/indicators` (Malware Intelligence) response, picking the record matching `value`. */
export function mapIntel471Indicator(json: any, value: string): Intel471Context {
  const list: any[] = Array.isArray(json?.indicators) ? json.indicators : [];
  const total = typeof json?.indicatorTotalCount === 'number' ? json.indicatorTotalCount : list.length;
  const v = value.toLowerCase();
  // `indicator=` is a free-text search; keep the record whose indicator_data actually contains the value.
  const item =
    list.find((i) => JSON.stringify(i?.data?.indicator_data ?? '').toLowerCase().includes(v)) ?? list[0];
  if (!item) return { found: false, indicatorCount: total };

  const data = item.data ?? {};
  const threat = data.threat ?? {};
  const ctx: Intel471Context = { found: true, indicatorCount: total };
  const family = threat?.data?.family;
  if (typeof family === 'string' && family) ctx.malwareFamily = family;
  const famUid = threat?.data?.malware_family_profile_uid;
  if (typeof famUid === 'string' && famUid) ctx.malwareFamilyUid = famUid;
  if (typeof data.confidence === 'string' && data.confidence) ctx.confidence = data.confidence;
  if (typeof threat.type === 'string' && threat.type) ctx.threatType = threat.type;
  const desc = data.context?.description;
  if (typeof desc === 'string' && desc) ctx.context = desc;
  if (typeof data.mitre_tactics === 'string' && data.mitre_tactics) ctx.mitreTactics = data.mitre_tactics;
  if (Array.isArray(data.intel_requirements) && data.intel_requirements.length) ctx.girs = data.intel_requirements.filter((g: any) => typeof g === 'string');
  ctx.activeFrom = isoMs(item.activity?.first);
  ctx.activeTill = isoMs(item.activity?.last);
  ctx.lastUpdated = isoMs(item.last_updated);
  ctx.raw = item;
  return ctx;
}

/** Collapse whitespace + cap a string for use as a result title. */
function snippet(s: unknown): string | undefined {
  if (typeof s !== 'string') return undefined;
  const t = s.replace(/\s+/g, ' ').trim();
  if (!t) return undefined;
  return t.length > 120 ? `${t.slice(0, 117)}…` : t;
}

/** Best-effort human title for a Global Search result item (shape varies by collection). */
function searchItemTitle(i: any): string | undefined {
  if (typeof i === 'string') return snippet(i);
  if (!i || typeof i !== 'object') return undefined;
  const direct =
    i.subject ?? i.title ?? i.name ?? i.handle ?? i.value ?? i.login ?? i.email ?? i.threat?.data?.family ??
    i.data?.threat?.data?.family ?? i.message ?? i.text;
  const s = snippet(direct);
  if (s) return s;
  const idata = i.data?.indicator_data;
  if (idata && typeof idata === 'object') {
    return snippet(
      Object.values(idata)
        .filter((v): v is string => typeof v === 'string')
        .join(' '),
    );
  }
  return undefined;
}

/** Deep link into the Titan portal for a result item, when present. */
function searchItemUrl(i: any): string | undefined {
  const u = i?.portalReportUrl ?? i?.portalPostUrl ?? i?.portalActorUrl ?? i?.portal_url ?? i?.url;
  return typeof u === 'string' && u ? u : undefined;
}

/** Map an Intel 471 `/search` response to cross-entity counts + top items per category. */
export function mapIntel471Search(json: any): Intel471Search {
  const n = (...keys: string[]): number | undefined => {
    for (const k of keys) if (typeof json?.[k] === 'number') return json[k];
    return undefined;
  };
  const out: Intel471Search = {
    reports: n('reportTotalCount'),
    malwareReports: n('malwareReportTotalCount'),
    actors: n('actorTotalCount'),
    entities: n('entityTotalCount'),
    events: n('eventTotalCount'),
    posts: n('postTotalCount'),
    news: n('newsTotalCount'),
    iocs: n('iocTotalCount'),
    indicators: n('indicatorTotalCount'),
    credentials: n('credentials_total_count', 'credentialsTotalCount'),
    credentialSets: n('credential_sets_total_count', 'credentialSetsTotalCount'),
    dataLeakPosts: n('data_leak_post_total_count', 'dataLeakPostTotalCount'),
    breachAlerts: n('breach_alerts_total_count', 'breachAlertsTotalCount'),
    cveReports: n('cveReportsTotalCount'),
  };
  const items: NonNullable<Intel471Search['items']> = {};
  const keys = [
    'reports',
    'malwareReports',
    'actors',
    'entities',
    'events',
    'posts',
    'news',
    'iocs',
    'indicators',
    'credentials',
    'cveReports',
  ] as const;
  for (const k of keys) {
    const arr: any[] = Array.isArray(json?.[k]) ? json[k] : [];
    const list: Intel471SearchItem[] = [];
    for (const it of arr) {
      const title = searchItemTitle(it);
      if (!title) continue;
      const url = searchItemUrl(it);
      list.push(url ? { title, url } : { title });
      if (list.length >= 5) break;
    }
    if (list.length) items[k] = list;
  }
  if (Object.keys(items).length) out.items = items;
  return out;
}

function authHeader(env: ProxyEnv): string {
  return `Basic ${base64(`${env.intel471ApiUser ?? ''}:${env.intel471ApiKey ?? ''}`)}`;
}

function baseUrl(env: ProxyEnv): string {
  return (env.intel471BaseUrl || DEFAULT_BASE).replace(/\/$/, '');
}

async function i471Fetch(url: string, env: ProxyEnv, signal?: AbortSignal): Promise<{ json?: any; __error?: string }> {
  let res: Response;
  try {
    res = await fetch(url, { headers: { accept: 'application/json', authorization: authHeader(env) }, signal });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return { __error: 'aborted' };
    return { __error: `Intel471 unreachable: ${(e as Error).message}` };
  }
  if (res.status === 401) return { __error: 'Intel471 401 — check API email + key' };
  if (res.status === 403) return { __error: 'Intel471 403 — no access to this endpoint' };
  if (res.status === 429) return { __error: 'Intel471: rate limited' };
  if (res.status === 412) return { __error: 'Intel471 412 — bad query parameters' };
  if (!res.ok) return { __error: `Intel471 error ${res.status}` };
  try {
    return { json: await res.json() };
  } catch {
    return { __error: 'Intel471: malformed response' };
  }
}

/** Intel 471 IOC lookup for a single indicator. */
export async function intel471IocLookup(
  value: string,
  type: EnrichableType,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<Intel471Context | undefined> {
  if (!env.intel471ApiUser || !env.intel471ApiKey) return undefined;
  if (signal?.aborted) return undefined;
  const iocType = IOC_TYPE[type];
  const url = `${baseUrl(env)}/iocs?ioc=${encodeURIComponent(value)}${
    iocType ? `&iocType=${iocType}` : ''
  }&count=20&sort=latest`;
  const r = await i471Fetch(url, env, signal);
  if (r.__error) return { found: false, error: r.__error };
  return mapIntel471Ioc(r.json, value);
}

/** Intel 471 Malware Intelligence `/indicators` lookup for one value. */
export async function intel471Indicators(
  value: string,
  type: EnrichableType,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<Intel471Context | undefined> {
  if (!env.intel471ApiUser || !env.intel471ApiKey) return undefined;
  if (signal?.aborted) return undefined;
  const indicatorType = INDICATOR_TYPE[type];
  const url = `${baseUrl(env)}/indicators?indicator=${encodeURIComponent(value)}${
    indicatorType ? `&indicatorType=${indicatorType}` : ''
  }&count=10&sort=latest`;
  const r = await i471Fetch(url, env, signal);
  if (r.__error) return { found: false, error: r.__error };
  return mapIntel471Indicator(r.json, value);
}

/**
 * Combined Intel 471 lookup: Malware Intelligence indicators + adversary IOC feed (run together),
 * merged into one context. Covers hashes/URLs that live in the indicators dataset (not just /iocs).
 */
export async function intel471Lookup(
  value: string,
  type: EnrichableType,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<Intel471Context | undefined> {
  if (!env.intel471ApiUser || !env.intel471ApiKey) return undefined;
  const [ind, ioc] = await Promise.all([
    intel471Indicators(value, type, env, signal),
    intel471IocLookup(value, type, env, signal),
  ]);
  const found = Boolean(ind?.found || ioc?.found);
  if (!found) {
    const err = ind?.error ?? ioc?.error;
    return err ? { found: false, error: err } : { found: false };
  }
  const merged: Intel471Context = { found: true };
  if (ind?.found) {
    merged.indicatorCount = ind.indicatorCount;
    merged.malwareFamily = ind.malwareFamily;
    merged.malwareFamilyUid = ind.malwareFamilyUid;
    merged.confidence = ind.confidence;
    merged.threatType = ind.threatType;
    merged.context = ind.context;
    merged.mitreTactics = ind.mitreTactics;
    merged.girs = ind.girs;
  }
  if (ioc?.found) {
    merged.totalCount = ioc.totalCount;
    merged.type = ioc.type;
    merged.isp = ioc.isp;
    merged.ispCountryCode = ioc.ispCountryCode;
    merged.reports = ioc.reports;
    merged.actors = ioc.actors;
    merged.malwareReports = ioc.malwareReports;
    merged.events = ioc.events;
    merged.reportTitles = ioc.reportTitles;
    merged.portalUrl = ioc.portalUrl;
  }
  merged.activeFrom = ind?.activeFrom ?? ioc?.activeFrom;
  merged.activeTill = ind?.activeTill ?? ioc?.activeTill;
  merged.lastUpdated = ind?.lastUpdated ?? ioc?.lastUpdated;
  merged.raw = { indicator: ind?.raw, ioc: ioc?.raw };
  return merged;
}

/**
 * Intel 471 Global Search — cross-entity counts for a value (on-demand). Uses `text=` (the
 * GUI's free-text search, which spans every entity type: indicators, events, reports, actors,
 * posts, credentials, …) rather than `ioc=` (which only matches the adversary IOC dataset).
 * The `*TotalCount` fields come independently of the item arrays, so `count=1` keeps the payload
 * small (count=0 is rejected with 412).
 */
export async function intel471GlobalSearch(
  value: string,
  _type: EnrichableType,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<Intel471Search | undefined> {
  if (!env.intel471ApiUser || !env.intel471ApiKey) return undefined;
  // count=5 → the response carries the top items per category (not just counts) for drill-down.
  const url = `${baseUrl(env)}/search?text=${encodeURIComponent(value)}&count=5`;
  const r = await i471Fetch(url, env, signal);
  if (r.__error) return { error: r.__error };
  return mapIntel471Search(r.json);
}

/** GUI deep link for a malware family profile (matches the Titan URL the analyst sees). */
const TITAN_MALWARE_URL = 'https://titan.intel471.com/malware/';

/** Map `GET /malwareReports` (searched by family) to report subjects + activity window + MITRE/GIR. */
export function mapIntel471MalwareReports(json: any): Partial<Intel471Malware> {
  const list: any[] = Array.isArray(json?.malwareReports) ? json.malwareReports : [];
  const out: Partial<Intel471Malware> = {};
  const total = typeof json?.malwareReportTotalCount === 'number' ? json.malwareReportTotalCount : list.length;
  if (total) out.reportCount = total;
  const subjects = list.map((r) => r?.subject).filter((s: any): s is string => typeof s === 'string' && s.trim().length > 0);
  if (subjects.length) out.reports = subjects.slice(0, 8);
  const tactics = new Set<string>();
  const girs = new Set<string>();
  let first = Infinity;
  let last = 0;
  for (const r of list) {
    const t = r?.data?.threat?.data?.mitre_tactics ?? r?.data?.malware_report_data?.mitre_tactics;
    if (typeof t === 'string' && t) tactics.add(t);
    else if (Array.isArray(t)) for (const x of t) if (typeof x === 'string') tactics.add(x);
    const ir = r?.classification?.intelRequirements;
    if (Array.isArray(ir)) for (const g of ir) if (typeof g === 'string') girs.add(g);
    const f = r?.activity?.first;
    const l = r?.activity?.last;
    if (typeof f === 'number' && f > 0) first = Math.min(first, f);
    if (typeof l === 'number' && l > 0) last = Math.max(last, l);
  }
  if (tactics.size) out.mitreTactics = [...tactics].slice(0, 12);
  if (girs.size) out.girs = [...girs].slice(0, 12);
  if (first !== Infinity) out.activeFrom = new Date(first).toISOString();
  if (last > 0) out.activeTill = new Date(last).toISOString();
  return out;
}

/** Map `GET /malwareFamilies` to the family profile's aka/summary (loose schema → defensive). */
export function mapIntel471Family(json: any, uid: string, family?: string): Partial<Intel471Malware> {
  const list: any[] = Array.isArray(json?.malware_families) ? json.malware_families : [];
  const pick =
    list.find((f) => f && typeof f === 'object' && JSON.stringify(f).includes(uid)) ??
    (family
      ? list.find((f) => typeof f?.name === 'string' && f.name.toLowerCase() === family.toLowerCase())
      : undefined) ??
    list[0];
  const out: Partial<Intel471Malware> = {};
  if (!pick || typeof pick !== 'object') return out;
  const name = pick.name ?? pick.malware_family ?? pick.generic_name;
  if (typeof name === 'string' && name) out.family = name;
  const aka = pick.aliases ?? pick.aka ?? pick.names ?? pick.alternative_names;
  if (Array.isArray(aka)) {
    const a = aka.filter((x: any): x is string => typeof x === 'string' && x.trim().length > 0);
    if (a.length) out.aka = Array.from(new Set(a)).slice(0, 20);
  }
  const summary = pick.description ?? pick.summary ?? pick.overview ?? pick.profile;
  if (typeof summary === 'string' && summary.trim()) out.summary = summary.trim();
  return out;
}

/**
 * On-demand Intel 471 malware family details (clicking the malware-family chip): the family's recent
 * malware reports (by `malwareFamilyProfileUid`) + the family profile (aka/summary), run together and
 * deep-linked to the Titan malware page. Never throws; failures surface via `error`.
 */
export async function intel471MalwareProfile(
  uid: string,
  env: ProxyEnv,
  signal?: AbortSignal,
  family?: string,
): Promise<Intel471Malware | undefined> {
  if (!env.intel471ApiUser || !env.intel471ApiKey) return undefined;
  if (!uid) return { error: 'no malware family profile uid' };
  const portalUrl = `${TITAN_MALWARE_URL}${uid}`;
  const reportsUrl = `${baseUrl(env)}/malwareReports?malwareFamilyProfileUid=${encodeURIComponent(uid)}&count=10&sort=latest`;
  const famUrl = family ? `${baseUrl(env)}/malwareFamilies?malwareFamily=${encodeURIComponent(family)}&count=5` : undefined;
  const [reportsR, famR] = await Promise.all([
    i471Fetch(reportsUrl, env, signal),
    famUrl ? i471Fetch(famUrl, env, signal) : Promise.resolve({ json: undefined } as { json?: any; __error?: string }),
  ]);
  const out: Intel471Malware = { uid, portalUrl };
  if (family) out.family = family;
  if (reportsR.__error && !famR?.json) return { ...out, error: reportsR.__error };
  if (reportsR.json) Object.assign(out, mapIntel471MalwareReports(reportsR.json));
  if (famR?.json) {
    const fam = mapIntel471Family(famR.json, uid, family);
    out.aka = fam.aka ?? out.aka;
    out.summary = fam.summary ?? out.summary;
    if (fam.family) out.family = fam.family;
  }
  out.family = out.family ?? family;
  out.raw = { malwareReports: reportsR.json, malwareFamilies: famR?.json };
  return out;
}
