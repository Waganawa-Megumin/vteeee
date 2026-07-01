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

function len(v: unknown): number {
  return Array.isArray(v) ? v.length : 0;
}

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

/** Map a Risk Dossier (`/riskdossier`) response to our context (pure; raw is attached by the fetcher). */
export function mapRiskDossier(json: any): CyfirmaContext {
  if (!json || typeof json !== 'object') return { found: false };
  const scores = json.riskViewScores ?? {};
  const details: any[] = Array.isArray(json.riskDossierDetails) ? json.riskDossierDetails : [];
  const d0 = details[0];
  const ctx: CyfirmaContext = { found: Boolean(d0) };
  if (typeof scores.riskScore === 'number') ctx.riskScore = scores.riskScore;
  if (typeof scores.externalThreatScore === 'number') ctx.externalThreatScore = scores.externalThreatScore;
  if (typeof scores.riskScoreTrend === 'string') ctx.riskScoreTrend = scores.riskScoreTrend;
  if (typeof scores.externalThreatScoreTrend === 'string')
    ctx.externalThreatScoreTrend = scores.externalThreatScoreTrend;
  if (!d0) return ctx;

  if (typeof d0.type === 'string' && d0.type) ctx.indicatorType = d0.type;
  if (typeof d0.riskScore === 'number') ctx.indicatorRiskScore = d0.riskScore;
  const story = stripHtml(d0.story);
  if (story) ctx.story = story;
  if (typeof d0.impact === 'string' && d0.impact) ctx.impact = d0.impact;
  if (typeof d0.action === 'string' && d0.action) ctx.action = d0.action;

  const det = d0.details ?? {};
  const pick = (k: string): string | undefined =>
    typeof det[k] === 'string' && det[k] ? det[k] : undefined;
  ctx.asn = pick('ASN');
  ctx.asnOwner = pick('ASN Owner');
  ctx.organization = pick('Organization');
  ctx.country = pick('Country Name') ?? pick('Country');

  const ia = d0.iocAttribute ?? {};
  const related: CyfirmaRelated = {};
  const put = (key: keyof CyfirmaRelated, v: unknown) => {
    const s = strs(v);
    if (s) related[key] = s;
  };
  put('ips', ia.ips);
  put('domains', ia.domain);
  put('hostnames', ia.hostname);
  put('urls', ia.url);
  put('emails', ia.emails);
  put('cves', ia.cves);
  put('exploits', ia.exploits);
  const hashes = strs([
    ...(Array.isArray(ia.md5) ? ia.md5 : []),
    ...(Array.isArray(ia.sha) ? ia.sha : []),
    ...(Array.isArray(ia.file) ? ia.file : []),
  ]);
  if (hashes) related.hashes = hashes;
  if (Object.keys(related).length) ctx.related = related;

  const total =
    len(ia.ips) +
    len(ia.domain) +
    len(ia.hostname) +
    len(ia.url) +
    len(ia.emails) +
    len(ia.cves) +
    len(ia.exploits) +
    len(ia.md5) +
    len(ia.sha) +
    len(ia.file) +
    len(ia.mutex) +
    len(ia.ssl);
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
  const path = `/riskdossier?indicatorType=${it}&value=${encodeURIComponent(value)}`;
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
    merged.threatActors = stix.threatActors;
    merged.campaigns = stix.campaigns;
    merged.malware = stix.malware;
    merged.indicatorName = stix.indicatorName;
    merged.description = stix.description;
  }
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
