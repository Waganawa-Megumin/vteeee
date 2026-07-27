import type {
  EnrichableType,
  RecordedFutureContext,
  RfActorProfile,
  RfDetectionRule,
  RfEvidence,
  RfMalwareProfile,
  RfRelatedEntity,
  RfRuleSearchParams,
  RfRuleSearchResult,
  RfSandboxIntel,
} from '@vteeee/shared';
import type { ProxyEnv } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

// All Recorded Future product APIs hang off one host; each product has its own path prefix.
//   Connect API            /v2         (per-IOC enrichment: risk, evidence, related entities)
//   Threat API             /threat     (actor search — on-demand actor profile)
//   Malware Intelligence   /malware-intelligence (read-only sandbox queries; nothing is uploaded)
//   Detection Rule API     /detection-rule       (Sigma / YARA / Snort rule search)
const DEFAULT_BASE = 'https://api.recordedfuture.com';

const str = (v: any): string | undefined => (typeof v === 'string' && v ? v : undefined);
const num = (v: any): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);

function base(env: ProxyEnv): string {
  return (env.recordedfutureBaseUrl || DEFAULT_BASE).replace(/\/$/, '');
}

function headers(env: ProxyEnv, json = false): Record<string, string> {
  const h: Record<string, string> = {
    'X-RFToken': env.recordedfutureApiKey ?? '',
    accept: 'application/json',
    'user-agent': 'vteeee',
  };
  if (json) h['content-type'] = 'application/json';
  return h;
}

/** vteeee IOC type → Connect API entity path segment. */
export function rfPathType(type: EnrichableType): 'ip' | 'domain' | 'url' | 'hash' {
  if (type === 'ipv4' || type === 'ipv6') return 'ip';
  if (type === 'domain') return 'domain';
  if (type === 'url') return 'url';
  return 'hash';
}

/** Collect the entities of one relatedEntities group (e.g. RelatedThreatActor), most-referenced first. */
function relatedGroup(related: any, groupType: string, limit = 8): RfRelatedEntity[] | undefined {
  if (!Array.isArray(related)) return undefined;
  const group = related.find((g: any) => g?.type === groupType);
  if (!Array.isArray(group?.entities)) return undefined;
  const out: RfRelatedEntity[] = group.entities
    .map((e: any) => ({
      id: str(e?.entity?.id),
      name: str(e?.entity?.name) ?? '',
      count: num(e?.count),
    }))
    .filter((e: RfRelatedEntity) => e.name);
  out.sort((a, b) => (b.count ?? 0) - (a.count ?? 0));
  return out.length ? out.slice(0, limit) : undefined;
}

/** Map a Connect API lookup (`{data:{risk,...}}`) to our context (pure, tolerant). */
export function mapRfLookup(json: any): RecordedFutureContext {
  const ctx: RecordedFutureContext = { found: false };
  const d = json?.data;
  if (!d || typeof d !== 'object') return ctx;

  const risk = d.risk ?? {};
  ctx.riskScore = num(risk.score);
  ctx.criticality = num(risk.criticality);
  ctx.criticalityLabel = str(risk.criticalityLabel);
  ctx.riskString = str(risk.riskString);
  ctx.riskSummary = str(risk.riskSummary);

  // riskMapping (rule → MITRE ATT&CK identifiers), aggregated + attached per rule below.
  const mitreByRule = new Map<string, string[]>();
  if (Array.isArray(d.riskMapping)) {
    for (const m of d.riskMapping) {
      const rule = str(m?.rule);
      const ids = Array.isArray(m?.categories)
        ? m.categories
            .filter((c: any) => (str(c?.framework) ?? 'MITRE').toUpperCase().includes('MITRE'))
            .map((c: any) => str(c?.name))
            .filter(Boolean)
        : [];
      if (rule && ids.length) mitreByRule.set(rule, ids as string[]);
    }
  }

  if (Array.isArray(risk.evidenceDetails) && risk.evidenceDetails.length) {
    const ev: RfEvidence[] = risk.evidenceDetails
      .map((e: any) => {
        const rule = str(e?.rule) ?? '';
        const item: RfEvidence = { rule };
        item.criticality = num(e?.criticality);
        item.criticalityLabel = str(e?.criticalityLabel);
        item.evidence = str(e?.evidenceString);
        item.timestamp = str(e?.timestamp);
        const mitre = mitreByRule.get(rule);
        if (mitre) item.mitre = mitre;
        return item;
      })
      .filter((e: RfEvidence) => e.rule);
    ev.sort((a, b) => (b.criticality ?? 0) - (a.criticality ?? 0));
    if (ev.length) ctx.evidence = ev.slice(0, 12);
  }
  const allMitre = Array.from(new Set([...mitreByRule.values()].flat()));
  if (allMitre.length) ctx.mitre = allMitre.slice(0, 16);

  ctx.firstSeen = str(d.timestamps?.firstSeen);
  ctx.lastSeen = str(d.timestamps?.lastSeen);

  if (Array.isArray(d.threatLists) && d.threatLists.length) {
    const lists = d.threatLists
      .map((t: any) => str(t?.name) ?? str(t))
      .filter(Boolean) as string[];
    if (lists.length) ctx.threatLists = lists.slice(0, 10);
  }

  ctx.relatedActors = relatedGroup(d.relatedEntities, 'RelatedThreatActor');
  ctx.relatedMalware = relatedGroup(d.relatedEntities, 'RelatedMalware');

  // IP-only location block.
  const loc = d.location ?? {};
  ctx.asn = str(loc.asn);
  ctx.organization = str(loc.organization);
  ctx.country = str(loc.location?.country);
  ctx.city = str(loc.location?.city);

  const ai = d.aiInsights;
  ctx.aiInsights = str(ai?.text) ?? str(ai?.comment) ?? (typeof ai === 'string' ? ai : undefined);
  ctx.intelCard = str(d.intelCard);

  ctx.found = ctx.riskScore != null || Boolean(ctx.evidence?.length || ctx.firstSeen || ctx.intelCard);
  ctx.raw = json;
  return ctx;
}

/** Shared error → context helper for non-OK Connect responses. */
async function rfError(res: Response): Promise<string> {
  let detail = '';
  try {
    detail = (await res.text()).replace(/\s+/g, ' ').trim().slice(0, 300);
  } catch {
    /* unreadable body */
  }
  if (res.status === 401) return 'Recorded Future 401 — invalid/expired API token';
  if (res.status === 403)
    return `Recorded Future 403 — the token's subscription does not include this API${detail ? ` (${detail})` : ''}`;
  if (res.status === 429) return 'Recorded Future: rate limited';
  return `Recorded Future error ${res.status}${detail ? ` — ${detail}` : ''}`;
}

const CORE_FIELDS = 'risk,intelCard,timestamps,relatedEntities,threatLists';
const EXTRA_FIELDS = ',aiInsights,riskMapping';

/** Connect API per-IOC lookup. Never throws. 404 → found:false (not in RF). */
export async function rfLookup(
  type: EnrichableType,
  value: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<RecordedFutureContext | undefined> {
  if (!env.recordedfutureApiKey) return undefined;
  if (signal?.aborted) return undefined;
  const seg = rfPathType(type);
  const fields = (seg === 'ip' ? `${CORE_FIELDS},location` : CORE_FIELDS) + EXTRA_FIELDS;
  const call = async (f: string): Promise<Response> =>
    fetch(`${base(env)}/v2/${seg}/${encodeURIComponent(value)}?fields=${encodeURIComponent(f)}`, {
      headers: headers(env),
      signal,
    });
  let res: Response;
  try {
    res = await call(fields);
    // Older subscriptions may reject the newer aiInsights/riskMapping fields — retry with the core set.
    if (res.status === 400) res = await call(seg === 'ip' ? `${CORE_FIELDS},location` : CORE_FIELDS);
  } catch (e) {
    if ((e as Error).name === 'AbortError') return undefined;
    return { found: false, error: `Recorded Future unreachable: ${(e as Error).message}` };
  }
  if (res.status === 404) return { found: false }; // not in RF — a clean miss, not an error
  if (!res.ok) return { found: false, error: await rfError(res) };
  try {
    return mapRfLookup(await res.json());
  } catch {
    return { found: false, error: 'Recorded Future: malformed response' };
  }
}

/** Map a Threat API actor-search response to the best-matching profile. */
export function mapRfActor(json: any, name: string): RfActorProfile {
  const list: any[] = Array.isArray(json?.data) ? json.data : [];
  if (!list.length) return { name, error: 'No Recorded Future threat-actor profile found.' };
  const lower = name.toLowerCase();
  const score = (a: any): number => {
    const attrs = a?.attributes ?? {};
    const names = [
      str(attrs.name),
      ...(Array.isArray(attrs.common_names) ? attrs.common_names : []),
      ...(Array.isArray(attrs.alias) ? attrs.alias : []),
    ].filter(Boolean) as string[];
    return names.some((n) => n.toLowerCase() === lower) ? 1 : 0;
  };
  const bestMatch = [...list].sort((a, b) => score(b) - score(a))[0];
  const attrs = bestMatch?.attributes ?? {};
  const p: RfActorProfile = { raw: json };
  p.id = str(bestMatch?.id);
  p.name = str(attrs.name) ?? name;
  if (Array.isArray(attrs.alias) && attrs.alias.length) p.aliases = attrs.alias.filter(Boolean).slice(0, 12);
  if (Array.isArray(attrs.common_names) && attrs.common_names.length)
    p.commonNames = attrs.common_names.filter(Boolean).slice(0, 12);
  if (Array.isArray(attrs.categories)) {
    const cats = attrs.categories.map((c: any) => str(c?.name)).filter(Boolean) as string[];
    if (cats.length) p.categories = cats.slice(0, 8);
  }
  if (p.id) p.intelCard = `https://app.recordedfuture.com/portal/intelligence-card/${p.id}`;
  return p;
}

/** Threat API: actor profile by name (on demand, from an actor chip). Never throws. */
export async function rfActorSearch(
  name: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<RfActorProfile | undefined> {
  if (!env.recordedfutureApiKey) return undefined;
  let res: Response;
  try {
    res = await fetch(`${base(env)}/threat/actor/search`, {
      method: 'POST',
      headers: headers(env, true),
      body: JSON.stringify({ name, limit: 10 }),
      signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return { name, error: 'aborted' };
    return { name, error: `Recorded Future unreachable: ${(e as Error).message}` };
  }
  if (!res.ok) return { name, error: await rfError(res) };
  try {
    return mapRfActor(await res.json(), name);
  } catch {
    return { name, error: 'Recorded Future: malformed response' };
  }
}

/** Map a Connect malware lookup (`{data:{...}}`) or search result row to a profile. */
export function mapRfMalware(json: any, fallbackName?: string): RfMalwareProfile {
  // Accept both a lookup ({data:{...}}) and a search ({data:{results:[{...}]}}).
  const d = Array.isArray(json?.data?.results) ? json.data.results[0] : json?.data;
  if (!d || typeof d !== 'object')
    return { name: fallbackName, error: 'No Recorded Future malware profile found.', raw: json };
  const p: RfMalwareProfile = { raw: json };
  p.id = str(d.entity?.id) ?? str(d.id);
  p.name = str(d.entity?.name) ?? str(d.name) ?? fallbackName;
  const cats = relatedGroup(d.relatedEntities, 'RelatedMalwareCategory');
  if (cats) p.categories = cats.map((c) => c.name);
  const actors = relatedGroup(d.relatedEntities, 'RelatedThreatActor');
  if (actors) p.relatedActors = actors.map((a) => a.name);
  p.firstSeen = str(d.timestamps?.firstSeen);
  p.lastSeen = str(d.timestamps?.lastSeen);
  p.intelCard =
    str(d.intelCard) ?? (p.id ? `https://app.recordedfuture.com/portal/intelligence-card/${p.id}` : undefined);
  return p;
}

const MALWARE_FIELDS = 'entity,intelCard,timestamps,relatedEntities';

/** Connect API: malware profile by RF entity id (preferred) or free-text name. Never throws. */
export async function rfMalwareLookup(
  { id, name }: { id?: string; name?: string },
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<RfMalwareProfile | undefined> {
  if (!env.recordedfutureApiKey) return undefined;
  const url = id
    ? `${base(env)}/v2/malware/${encodeURIComponent(id)}?fields=${MALWARE_FIELDS}`
    : `${base(env)}/v2/malware/search?freetext=${encodeURIComponent(name ?? '')}&limit=1&fields=${MALWARE_FIELDS}`;
  let res: Response;
  try {
    res = await fetch(url, { headers: headers(env), signal });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return { name, error: 'aborted' };
    return { name, error: `Recorded Future unreachable: ${(e as Error).message}` };
  }
  if (res.status === 404) return { name, error: 'No Recorded Future malware profile found.' };
  if (!res.ok) return { name, error: await rfError(res) };
  try {
    return mapRfMalware(await res.json(), name);
  } catch {
    return { name, error: 'Recorded Future: malformed response' };
  }
}

/** Map a Malware Intelligence query response (first hit) to a sandbox summary. */
export function mapRfSandbox(json: any): RfSandboxIntel {
  const rows: any[] = Array.isArray(json?.data) ? json.data : [];
  if (!rows.length) return { error: 'No Recorded Future sandbox data for this hash.', raw: json };
  const r = rows[0];
  const out: RfSandboxIntel = { raw: json };
  out.hash = str(r.name);
  out.riskScore = num(r.risk_score);
  out.sandboxScore = num(r.sandbox_score);
  if (Array.isArray(r.tags) && r.tags.length) out.tags = r.tags.filter(Boolean).slice(0, 16);
  if (Array.isArray(r.file_extensions) && r.file_extensions.length)
    out.fileExtensions = r.file_extensions.filter(Boolean).slice(0, 8);
  out.universalReport = str(r.links?.universal_report);
  out.intelligenceCard = str(r.links?.intelligence_card);
  out.total = num(json?.counts?.total);
  return out;
}

/**
 * Malware Intelligence: sandbox summary for one hash (read-only `POST /v1/query` — this
 * QUERIES RF's dataset; no sample or data is ever submitted). Never throws.
 */
export async function rfSandboxIntel(
  hash: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<RfSandboxIntel | undefined> {
  if (!env.recordedfutureApiKey) return undefined;
  // Reject anything but a bare hex hash BEFORE it's interpolated into the RF query DSL — otherwise a
  // crafted `hash` (e.g. `x" OR sandbox_score > 0 OR "`) would inject query logic under the server RF key.
  const h = hash.trim().toLowerCase();
  if (!/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(h)) return undefined;
  const algo = h.length === 32 ? 'md5' : h.length === 40 ? 'sha1' : 'sha256';
  const body = {
    query: `sample.${algo} == "${h}"`,
    field: 'sha256',
    sandbox_score: true,
    links: true,
    page: 0,
  };
  let res: Response;
  try {
    res = await fetch(`${base(env)}/malware-intelligence/v1/query`, {
      method: 'POST',
      headers: headers(env, true),
      body: JSON.stringify(body),
      signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return { error: 'aborted' };
    return { error: `Recorded Future unreachable: ${(e as Error).message}` };
  }
  if (!res.ok) return { error: await rfError(res) };
  try {
    return mapRfSandbox(await res.json());
  } catch {
    return { error: 'Recorded Future: malformed response' };
  }
}

/** Map a Detection Rule API search response defensively (shape is loosely specified). */
export function mapRfRules(json: any): RfRuleSearchResult {
  const arr: any[] = Array.isArray(json?.result)
    ? json.result
    : Array.isArray(json?.results)
      ? json.results
      : Array.isArray(json?.data?.results)
        ? json.data.results
        : Array.isArray(json?.data)
          ? json.data
          : [];
  const rules: RfDetectionRule[] = [];
  for (const doc of arr) {
    if (!doc || typeof doc !== 'object') continue;
    const baseRule: RfDetectionRule = {};
    baseRule.id = str(doc.id);
    baseRule.title = str(doc.title) ?? str(doc.name);
    baseRule.type = str(doc.type);
    baseRule.description = str(doc.description);
    baseRule.created = str(doc.created);
    baseRule.updated = str(doc.updated);
    const bodies: any[] = Array.isArray(doc.rules) ? doc.rules : [doc];
    for (const b of bodies) {
      const content = str(b?.content) ?? str(b?.rule);
      const entities = Array.isArray(b?.entities)
        ? (b.entities.map((e: any) => str(e?.name) ?? str(e)).filter(Boolean) as string[])
        : undefined;
      rules.push({
        ...baseRule,
        content,
        fileName: str(b?.file_name),
        entities: entities?.length ? entities.slice(0, 8) : undefined,
      });
    }
  }
  const out: RfRuleSearchResult = { raw: json };
  if (rules.length) out.rules = rules.slice(0, 20);
  const total = num(json?.counts?.total) ?? num(json?.total);
  out.total = total ?? rules.length;
  return out;
}

/** Detection Rule API: search Sigma / YARA / Snort rules by entity ids and/or title. Never throws. */
export async function rfDetectionRules(
  params: RfRuleSearchParams,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<RfRuleSearchResult | undefined> {
  if (!env.recordedfutureApiKey) return undefined;
  const filter: Record<string, unknown> = {};
  if (params.types?.length) filter.types = params.types;
  if (params.title) filter.title = params.title;
  if (params.entities?.length) filter.entities = params.entities;
  const body = { filter, limit: Math.min(Math.max(params.limit ?? 10, 1), 50) };
  let res: Response;
  try {
    res = await fetch(`${base(env)}/detection-rule/search`, {
      method: 'POST',
      headers: headers(env, true),
      body: JSON.stringify(body),
      signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return { error: 'aborted' };
    return { error: `Recorded Future unreachable: ${(e as Error).message}` };
  }
  if (res.status === 404) return { rules: [], total: 0 };
  if (!res.ok) return { error: await rfError(res) };
  try {
    return mapRfRules(await res.json());
  } catch {
    return { error: 'Recorded Future: malformed response' };
  }
}
