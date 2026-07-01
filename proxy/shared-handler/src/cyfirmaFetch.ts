import type { CyfirmaContext, CyfirmaRelated, CyfirmaSearch, EnrichableType } from '@vteeee/shared';
import type { ProxyEnv } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

const DEFAULT_BASE = 'https://decyfir.cyfirma.com/core/api-ua';

/** Our IOC type → CYFIRMA `indicatorType` enum (MD5/SHA/IP/DOMAIN/HOSTNAME/URL/EMAIL/CVE/EXPLOIT/MUTEX). */
const INDICATOR_TYPE: Partial<Record<EnrichableType, string>> = {
  ipv4: 'IP',
  ipv6: 'IP',
  domain: 'DOMAIN',
  url: 'URL',
  md5: 'MD5',
  sha1: 'SHA',
  sha256: 'SHA',
};

function uniq(list: string[]): string[] {
  return Array.from(new Set(list));
}

/** Collect a bounded array of non-empty strings (defensive against nulls / non-arrays). */
function strs(v: unknown, limit = 8): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out = uniq(v.filter((x): x is string => typeof x === 'string' && x.trim().length > 0)).slice(0, limit);
  return out.length ? out : undefined;
}

/** Strip HTML tags + decode the few entities CYFIRMA's `story` field uses, collapse whitespace. */
function stripHtml(v: unknown): string | undefined {
  if (typeof v !== 'string' || !v) return undefined;
  const s = v
    .replace(/<[^>]*>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/\s+/g, ' ')
    .trim();
  return s || undefined;
}

/** Pull the observable value out of a STIX pattern, e.g. `[ file:hashes.'SHA-256' = '4bac…' ]` → `4bac…`. */
function iocFromPattern(pattern: unknown): string | undefined {
  if (typeof pattern !== 'string') return undefined;
  const m = pattern.match(/=\s*'([^']+)'/);
  return m ? m[1] : undefined;
}

/** riskDossierDetails[].type values that describe an *associated* entity rather than the indicator itself. */
const ATTRIBUTION_TYPES = new Set(['CAMPAIGN', 'THREAT ACTOR', 'MALWARE', 'IOC']);

/**
 * Harvest entity names from DeCYFIR's HTML spans, e.g.
 * `<span class="active-txt cp TA">Emissary Panda</span>` → threat actor "Emissary Panda".
 * Only TA / Campaign / Malware are collected (the indicator's own `cp IP`/`cp Domain` span is skipped).
 */
function harvestSpans(text: unknown, buckets: { ta: string[]; camp: string[]; mal: string[] }): void {
  if (typeof text !== 'string' || text.indexOf('<span') < 0) return;
  const re = /<span[^>]*\bcp\s+(TA|Campaign|Malware)\b[^>]*>([^<]+)<\/span>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const token = m[1].toUpperCase();
    const name = stripHtml(m[2]);
    if (!name) continue;
    if (token === 'TA') buckets.ta.push(name);
    else if (token === 'CAMPAIGN') buckets.camp.push(name);
    else buckets.mal.push(name);
  }
}

/** iocAttribute buckets hold strings OR objects `{key,value,…}`; pull the value out of either form. */
function iocValues(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const x of v) {
    if (typeof x === 'string' && x.trim()) out.push(x.trim());
    else if (x && typeof x === 'object' && typeof (x as any).value === 'string' && (x as any).value.trim())
      out.push((x as any).value.trim());
  }
  return out;
}

/**
 * Map a Risk Dossier (`/risk-dossier`) response to our context (pure; raw is attached by the fetcher).
 * `riskDossierDetails` is a multi-entry array: one entry for the indicator itself (scores/story/action/
 * ASN·org·country) plus separate entries for associated campaigns / threat actors / malware / related IOCs.
 * We take the indicator entry as primary, then harvest attribution + correlated infra across *all* entries.
 * Also accepts the V2 shape (`/risk-dossier/v2/ioc`) which returns the details array directly.
 */
export function mapRiskDossier(json: any): CyfirmaContext {
  if (!json || typeof json !== 'object') return { found: false };
  const scores = json.riskViewScores ?? {};
  const details: any[] = Array.isArray(json.riskDossierDetails)
    ? json.riskDossierDetails
    : Array.isArray(json) // V2 returns the details array directly
      ? json
      : [];
  if (!details.length) return { found: false };

  // Primary = the first entry that isn't an associated-entity entry (falls back to the first entry).
  const primary = details.find((d) => d && !ATTRIBUTION_TYPES.has(String(d.type ?? '').toUpperCase())) ?? details[0];
  const ctx: CyfirmaContext = { found: true };

  if (typeof scores.riskScore === 'number') ctx.riskScore = scores.riskScore;
  if (typeof scores.externalThreatScore === 'number') ctx.externalThreatScore = scores.externalThreatScore;
  if (typeof scores.riskScoreTrend === 'string') ctx.riskScoreTrend = scores.riskScoreTrend;
  if (typeof scores.externalThreatScoreTrend === 'string')
    ctx.externalThreatScoreTrend = scores.externalThreatScoreTrend;

  if (primary) {
    if (typeof primary.type === 'string' && primary.type) ctx.indicatorType = primary.type;
    if (typeof primary.riskScore === 'number') ctx.indicatorRiskScore = primary.riskScore;
    const story = stripHtml(primary.story);
    if (story) ctx.story = story;
    if (typeof primary.impact === 'string' && primary.impact) ctx.impact = primary.impact;
    if (typeof primary.action === 'string' && primary.action) ctx.action = primary.action;
    const det = primary.details ?? {};
    const pick = (k: string): string | undefined =>
      typeof det[k] === 'string' && det[k] ? stripHtml(det[k]) : undefined;
    ctx.asn = pick('ASN');
    ctx.asnOwner = pick('ASN Owner');
    ctx.organization = pick('Organization');
    ctx.country = pick('Country Name') ?? pick('Country');
  }

  // Harvest attribution (TA/campaign/malware) + correlated infra from every detail entry.
  const buckets = { ta: [] as string[], camp: [] as string[], mal: [] as string[] };
  const relAll: Record<keyof CyfirmaRelated, string[]> = {
    ips: [],
    domains: [],
    hostnames: [],
    urls: [],
    hashes: [],
    emails: [],
    cves: [],
    exploits: [],
  };
  for (const d of details) {
    if (!d || typeof d !== 'object') continue;
    harvestSpans(d.story, buckets);
    const det = d.details ?? {};
    for (const val of Object.values(det)) harvestSpans(val, buckets);
    const ta = det['Threat Actor'];
    if (typeof ta === 'string') {
      const n = stripHtml(ta);
      if (n) buckets.ta.push(n);
    }
    const ia = d.iocAttribute ?? {};
    relAll.ips.push(...iocValues(ia.ips));
    relAll.domains.push(...iocValues(ia.domain));
    relAll.hostnames.push(...iocValues(ia.hostname));
    relAll.urls.push(...iocValues(ia.url));
    relAll.emails.push(...iocValues(ia.emails));
    relAll.cves.push(...iocValues(ia.cves));
    relAll.exploits.push(...iocValues(ia.exploits));
    relAll.hashes.push(...iocValues(ia.md5), ...iocValues(ia.sha), ...iocValues(ia.file));
  }

  const ta = uniq(buckets.ta);
  if (ta.length) ctx.threatActors = ta.slice(0, 10);
  const camp = uniq(buckets.camp);
  if (camp.length) ctx.campaigns = camp.slice(0, 10);
  const mal = uniq(buckets.mal);
  if (mal.length) ctx.malware = mal.slice(0, 10);

  const related: CyfirmaRelated = {};
  let total = 0;
  for (const key of Object.keys(relAll) as (keyof CyfirmaRelated)[]) {
    const vals = uniq(relAll[key]);
    total += vals.length;
    if (vals.length) related[key] = vals.slice(0, 8);
  }
  if (Object.keys(related).length) ctx.related = related;
  if (total > 0) ctx.relatedCount = total;
  return ctx;
}

/** Map a STIX 2.1 IOC search (`/threatioc/stix/v2.1/search`) bundle to attribution context (pure). */
export function mapStixSearch(json: any): CyfirmaContext {
  const arr: any[] = Array.isArray(json) ? json : Array.isArray(json?.objects) ? json.objects : [];
  const ctx: CyfirmaContext = { found: arr.length > 0 };
  const actors: string[] = [];
  const campaigns: string[] = [];
  const malware: string[] = [];
  for (const o of arr) {
    if (!o || typeof o !== 'object') continue;
    const name =
      typeof o.name === 'string' && o.name ? o.name : typeof o.title === 'string' && o.title ? o.title : undefined;
    switch (o.type) {
      case 'indicator':
        if (!ctx.indicatorName && name) ctx.indicatorName = name;
        if (!ctx.description && typeof o.description === 'string' && o.description) ctx.description = o.description;
        break;
      case 'threat-actor':
      case 'intrusion-set':
        if (name) actors.push(name);
        break;
      case 'campaign':
        if (name) campaigns.push(name);
        break;
      case 'malware':
        if (name) malware.push(name);
        break;
    }
  }
  if (actors.length) ctx.threatActors = uniq(actors).slice(0, 10);
  if (campaigns.length) ctx.campaigns = uniq(campaigns).slice(0, 10);
  if (malware.length) ctx.malware = uniq(malware).slice(0, 10);
  return ctx;
}

/** Map a Threat Actor (`/threatactor/stix/v2.1`) bundle to the on-demand deep-dive shape (pure). */
export function mapThreatActor(json: any): CyfirmaSearch {
  const arr: any[] = Array.isArray(json) ? json : Array.isArray(json?.objects) ? json.objects : [];
  const out: CyfirmaSearch = {};
  const campaigns: string[] = [];
  const malware: string[] = [];
  const vulns: string[] = [];
  const iocs: string[] = [];
  for (const o of arr) {
    if (!o || typeof o !== 'object') continue;
    const name =
      typeof o.name === 'string' && o.name ? o.name : typeof o.title === 'string' && o.title ? o.title : undefined;
    switch (o.type) {
      case 'threat-actor':
      case 'intrusion-set':
        if (!out.actor && name) out.actor = name;
        if (!out.aliases) {
          const a = strs(o.aliases, 24);
          if (a) out.aliases = a;
        }
        if (!out.description && typeof o.description === 'string' && o.description) out.description = o.description;
        if (!out.motivation) {
          if (typeof o.primary_motivation === 'string' && o.primary_motivation) out.motivation = o.primary_motivation;
          else {
            const m = o.motivations?.[0]?.value?.value;
            if (typeof m === 'string' && m) out.motivation = m;
          }
        }
        break;
      case 'campaign':
        if (name) campaigns.push(name);
        break;
      case 'malware':
        if (name) malware.push(name);
        break;
      case 'vulnerability': {
        const cve =
          typeof o.name === 'string'
            ? o.name
            : (Array.isArray(o.external_references) ? o.external_references : []).find(
                (r: any) => typeof r?.external_id === 'string',
              )?.external_id;
        if (typeof cve === 'string' && cve) vulns.push(cve);
        break;
      }
      case 'indicator': {
        const p = iocFromPattern(o.pattern) ?? (typeof o.name === 'string' ? o.name : undefined);
        if (p) iocs.push(p);
        break;
      }
    }
  }
  // "List" form (§9.2 first sample) has no STIX `type` field: title + motivations[] on the first object.
  if (!out.actor && arr[0] && typeof arr[0] === 'object' && typeof arr[0].title === 'string') out.actor = arr[0].title;
  if (campaigns.length) out.campaigns = uniq(campaigns).slice(0, 15);
  if (malware.length) out.malware = uniq(malware).slice(0, 15);
  if (vulns.length) out.vulnerabilities = uniq(vulns).slice(0, 15);
  if (iocs.length) out.relatedIocs = uniq(iocs).slice(0, 15);
  return out;
}

function baseUrl(env: ProxyEnv): string {
  return (env.cyfirmaBaseUrl || DEFAULT_BASE).replace(/\/$/, '');
}

/** GET a DeCYFIR JSON endpoint. Auth is the `key=` query param (no header). */
async function decyfirFetch(
  path: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<{ json?: any; __error?: string }> {
  const sep = path.includes('?') ? '&' : '?';
  const url = `${baseUrl(env)}${path}${sep}key=${encodeURIComponent(env.cyfirmaApiKey ?? '')}`;
  let res: Response;
  try {
    res = await fetch(url, { headers: { accept: 'application/json' }, signal });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return { __error: 'aborted' };
    return { __error: `CYFIRMA unreachable: ${(e as Error).message}` };
  }
  if (res.status === 401 || res.status === 403) return { __error: `CYFIRMA ${res.status} — check API key / entitlement` };
  if (res.status === 429) return { __error: 'CYFIRMA: rate limited' };
  if (res.status === 204) return { json: null };
  if (!res.ok) return { __error: `CYFIRMA error ${res.status}` };
  try {
    return { json: await res.json() };
  } catch {
    return { __error: 'CYFIRMA: malformed response' };
  }
}

/** Risk Dossier for a single indicator. */
export async function cyfirmaRiskDossier(
  value: string,
  type: EnrichableType,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<CyfirmaContext | undefined> {
  if (!env.cyfirmaApiKey) return undefined;
  if (signal?.aborted) return undefined;
  const it = INDICATOR_TYPE[type];
  if (!it) return { found: false };
  const path = `/risk-dossier?indicatorType=${it}&value=${encodeURIComponent(value)}`;
  const r = await decyfirFetch(path, env, signal);
  if (r.__error) return { found: false, error: r.__error };
  const ctx = mapRiskDossier(r.json);
  ctx.raw = r.json;
  return ctx;
}

/** STIX 2.1 IOC search (associated threat actors / campaigns / malware) for a single indicator. */
export async function cyfirmaStixSearch(
  value: string,
  type: EnrichableType,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<CyfirmaContext | undefined> {
  if (!env.cyfirmaApiKey) return undefined;
  if (signal?.aborted) return undefined;
  const it = INDICATOR_TYPE[type];
  if (!it) return { found: false };
  const path = `/threatioc/stix/v2.1/search?indicatorType=${it}&value=${encodeURIComponent(value)}`;
  const r = await decyfirFetch(path, env, signal);
  if (r.__error) return { found: false, error: r.__error };
  const ctx = mapStixSearch(r.json);
  ctx.raw = r.json;
  return ctx;
}

/**
 * Combined CYFIRMA DeCYFIR lookup: Risk Dossier (scores + narrative + recommended action +
 * correlated infrastructure) and the STIX 2.1 IOC search (threat-actor / campaign / malware
 * attribution) run together and merged into one context. Covers "attack-infra side" (related
 * hosts) and "target side" (attribution) for a single indicator.
 */
export async function cyfirmaLookup(
  value: string,
  type: EnrichableType,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<CyfirmaContext | undefined> {
  if (!env.cyfirmaApiKey) return undefined;
  const [dossier, stix] = await Promise.all([
    cyfirmaRiskDossier(value, type, env, signal),
    cyfirmaStixSearch(value, type, env, signal),
  ]);
  const found = Boolean(dossier?.found || stix?.found);
  if (!found) {
    const err = dossier?.error ?? stix?.error;
    return err ? { found: false, error: err } : { found: false };
  }
  const mergeList = (a?: string[], b?: string[]): string[] | undefined => {
    const u = uniq([...(a ?? []), ...(b ?? [])]);
    return u.length ? u.slice(0, 12) : undefined;
  };
  const merged: CyfirmaContext = { found: true };
  if (dossier?.found) {
    merged.riskScore = dossier.riskScore;
    merged.externalThreatScore = dossier.externalThreatScore;
    merged.riskScoreTrend = dossier.riskScoreTrend;
    merged.externalThreatScoreTrend = dossier.externalThreatScoreTrend;
    merged.indicatorType = dossier.indicatorType;
    merged.indicatorRiskScore = dossier.indicatorRiskScore;
    merged.story = dossier.story;
    merged.impact = dossier.impact;
    merged.action = dossier.action;
    merged.asn = dossier.asn;
    merged.asnOwner = dossier.asnOwner;
    merged.organization = dossier.organization;
    merged.country = dossier.country;
    merged.related = dossier.related;
    merged.relatedCount = dossier.relatedCount;
  }
  if (stix?.found) {
    merged.indicatorName = stix.indicatorName;
    merged.description = stix.description;
  }
  // Attribution comes from both the dossier (span-encoded) and the STIX search — union them.
  merged.threatActors = mergeList(dossier?.threatActors, stix?.threatActors);
  merged.campaigns = mergeList(dossier?.campaigns, stix?.campaigns);
  merged.malware = mergeList(dossier?.malware, stix?.malware);
  merged.raw = { dossier: dossier?.raw, stix: stix?.raw };
  return merged;
}

/**
 * CYFIRMA Threat-Actor deep-dive (on-demand) — search the threat-actor collection by name and
 * return the actor's aliases, campaigns, malware and targeted CVEs. Pivots from an attributed
 * indicator into the actor's broader attack-infrastructure + targeting picture.
 */
export async function cyfirmaActorSearch(
  name: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<CyfirmaSearch | undefined> {
  if (!env.cyfirmaApiKey) return undefined;
  const path = `/threatactor/stix/v2.1?name=${encodeURIComponent(name)}`;
  const r = await decyfirFetch(path, env, signal);
  if (r.__error) return { error: r.__error };
  const out = mapThreatActor(r.json);
  if (!out.actor) out.actor = name;
  return out;
}
