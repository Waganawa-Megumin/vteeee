import type {
  SocPrimeQueryOptions,
  SocPrimeQueryResult,
  SocPrimeRule,
  SocPrimeRuleSearchParams,
  SocPrimeRuleSearchResult,
} from '@vteeee/shared';
import type { ProxyEnv } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

const DEFAULT_BASE = 'https://api.tdm.socprime.com';
// Cloudflare Workers send a default outbound User-Agent that some WAFs block; a direct curl (which
// works from a normal IP) sends its own. Set an explicit UA so a UA-based filter isn't the blocker.
const USER_AGENT = 'curl/8.7.1';

function baseUrl(env: ProxyEnv): string {
  return (env.socprimeBaseUrl || DEFAULT_BASE).replace(/\/$/, '');
}

/**
 * Build an error string that includes SOC Prime's ACTUAL response body — turns a guessed 401/403
 * hint into the platform's real reason (scope not saved vs. a subscription plan that doesn't include
 * API access vs. IP allow-list). Reads the body once (only call on a non-ok, non-404/429 response).
 */
async function socprimeErr(res: Response, scope: string): Promise<string> {
  let detail = '';
  try {
    detail = (await res.text()).replace(/\s+/g, ' ').trim().slice(0, 400);
  } catch {
    /* body unreadable */
  }
  const tail = detail ? ` — SOC Prime says: ${detail}` : ' (no response body)';
  if (res.status === 401) return `SOC Prime 401 — invalid/expired API key.${tail}`;
  if (res.status === 403)
    return (
      `SOC Prime 403 — the key authenticated but is not authorized. Confirm the “${scope}” product-API ` +
      `scope is enabled AND saved on the key, and that your subscription plan includes API access ` +
      `(the UI checkbox can be on while the plan still blocks the API). Allowed IPs must be empty for a ` +
      `Cloudflare Worker.${tail}`
    );
  return `SOC Prime error ${res.status}${tail}`;
}

/**
 * Pull generated query string(s) out of the (loosely-specified) Uncoder response. Handles the
 * likely shapes — a bare string, `{queries:[...]}`, an array of `{query}` objects, `{result}` —
 * and falls back to a pretty-printed blob so nothing is silently lost.
 */
export function mapSocprimeQuery(json: any): SocPrimeQueryResult {
  const out: SocPrimeQueryResult = { raw: json };
  const queries: string[] = [];
  let iocCount: number | undefined;

  const addQuery = (v: unknown): void => {
    if (typeof v === 'string' && v.trim()) queries.push(v);
    else if (v && typeof v === 'object') {
      const q = (v as any).query ?? (v as any).text ?? (v as any).result;
      if (typeof q === 'string' && q.trim()) queries.push(q);
      const n = (v as any).iocs_count ?? (v as any).ioc_count ?? (v as any).count;
      if (typeof n === 'number') iocCount = (iocCount ?? 0) + n;
    }
  };

  if (typeof json === 'string') {
    if (json.trim()) queries.push(json);
  } else if (Array.isArray(json)) {
    json.forEach(addQuery);
  } else if (json && typeof json === 'object') {
    const list = json.queries ?? json.results ?? json.data;
    if (Array.isArray(list)) list.forEach(addQuery);
    else addQuery(json); // single {query:...}/{result:...}
    if (typeof json.iocs_count === 'number') iocCount = json.iocs_count;
    else if (typeof json.ioc_count === 'number') iocCount = json.ioc_count;
  }

  if (queries.length) out.queries = queries;
  if (iocCount != null) out.iocCount = iocCount;
  return out;
}

/**
 * SOC Prime Uncoder AI: generate SIEM hunting query(ies) from a block of IOCs.
 * On-demand only (a results-toolbar action) — never part of batch enrichment. Never throws.
 */
export async function socprimeGenerateQuery(
  text: string,
  opts: SocPrimeQueryOptions,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<SocPrimeQueryResult | undefined> {
  if (!env.socprimeApiKey) return undefined;
  if (!text.trim()) return { error: 'no IOCs provided' };
  const body: Record<string, unknown> = {
    text,
    siem_type: opts.siemType,
    // Our indicators are already refanged, but keep defang rules on so pasted-in text also works,
    // and drop private/reserved IPs (not useful in a hunting query).
    ioc_parsing_rules: ['replace_dots', 'replace_hxxp', 'remove_private_and_reserved_ips'],
  };
  if (opts.iocsPerQuery) body.iocs_per_query = Math.min(Math.max(opts.iocsPerQuery, 25), 300);
  if (opts.includeSourceIp) body.include_source_ip = true;
  if (opts.includeIocTypes && opts.includeIocTypes.length) body.include_ioc_types = opts.includeIocTypes;

  let res: Response;
  try {
    res = await fetch(`${baseUrl(env)}/v1/uncoder/ioc/generate-query`, {
      method: 'POST',
      headers: {
        client_secret_id: env.socprimeApiKey,
        'content-type': 'application/json',
        accept: 'application/json',
        'user-agent': USER_AGENT,
      },
      body: JSON.stringify(body),
      signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return { error: 'aborted' };
    return { error: `SOC Prime unreachable: ${(e as Error).message}` };
  }
  if (res.status === 429) return { error: 'SOC Prime: rate limited (30 req / 10s)' };
  if (!res.ok) return { error: await socprimeErr(res, 'Uncoder AI') };
  let txt: string;
  try {
    txt = await res.text();
  } catch {
    return { error: 'SOC Prime: malformed response' };
  }
  if (!txt.trim()) return { error: 'SOC Prime: empty response' };
  try {
    return mapSocprimeQuery(JSON.parse(txt));
  } catch {
    return { queries: [txt] }; // some formats return a bare text/plain query
  }
}

/** Collect a bounded list of non-empty strings from a value that may be a string, array, or nested. */
function strList(v: unknown, limit = 12): string[] | undefined {
  const out: string[] = [];
  const push = (x: unknown): void => {
    if (typeof x === 'string' && x.trim()) out.push(x.trim());
    else if (x && typeof x === 'object') {
      const n = (x as any).name ?? (x as any).id ?? (x as any).value;
      if (typeof n === 'string' && n.trim()) out.push(n.trim());
    }
  };
  if (Array.isArray(v)) v.forEach(push);
  else if (v != null) push(v);
  const uniq = Array.from(new Set(out)).slice(0, limit);
  return uniq.length ? uniq : undefined;
}

/** Map one rule object from the (loosely-specified) search response into our shape. */
function mapRule(o: any): SocPrimeRule | undefined {
  if (!o || typeof o !== 'object') return undefined;
  const tags = o.tags ?? {};
  const sigma = o.sigma ?? {};
  const caseObj = o.case ?? {};
  const r: SocPrimeRule = {};
  const id = caseObj.id ?? o.case_id ?? o.id ?? o.rule_id;
  if (typeof id === 'string' && id) r.id = id;
  const name = caseObj.name ?? o.case_name ?? o.name ?? o.title;
  if (typeof name === 'string' && name) r.name = name;
  if (typeof o.description === 'string' && o.description) r.description = o.description;
  const level = sigma.level ?? o.level ?? o.severity;
  if (typeof level === 'string' && level) r.level = level;
  const status = sigma.status ?? o.status;
  if (typeof status === 'string' && status) r.status = status;
  const author = strList(tags.author ?? sigma.author ?? o.author, 4);
  if (author) r.author = author.join(', ');
  // MITRE techniques: tags.technique may be [{id,name,tactics}] or ids/names.
  const techIds: string[] = [];
  const tactics: string[] = [];
  const techniqueRaw = tags.technique ?? o.technique ?? tags['technique.id'];
  if (Array.isArray(techniqueRaw)) {
    for (const t of techniqueRaw) {
      if (typeof t === 'string') techIds.push(t);
      else if (t && typeof t === 'object') {
        const tid = t.id ?? t.name;
        if (typeof tid === 'string') techIds.push(tid);
        const tac = t.tactics ?? t.tactic;
        if (Array.isArray(tac)) for (const x of tac) if (typeof x === 'string') tactics.push(x);
        else if (typeof tac === 'string') tactics.push(tac);
      }
    }
  } else if (typeof techniqueRaw === 'string') techIds.push(techniqueRaw);
  const techniques = strList(techIds);
  if (techniques) r.techniques = techniques;
  const tac2 = strList(tactics.length ? tactics : (tags['technique.tactics'] ?? tags.tactic));
  if (tac2) r.tactics = tac2;
  const actors = strList(tags.actor ?? o.actor);
  if (actors) r.actors = actors;
  // Translated rule body for the requested SIEM format (field name varies).
  const tr = o.translation ?? o.siem_text ?? o.text ?? sigma.text ?? o.rule ?? o.query;
  if (typeof tr === 'string' && tr.trim()) r.translation = tr;
  if (r.id) r.url = `https://tdm.socprime.com/tdm/info/${r.id}`;
  return r;
}

/** Map a `/v1/search-sigmas` response (array or {rules|sigmas|results|data:[...]}) defensively. */
export function mapSocprimeRules(json: any): SocPrimeRuleSearchResult {
  const arr: any[] = Array.isArray(json)
    ? json
    : Array.isArray(json?.rules)
      ? json.rules
      : Array.isArray(json?.sigmas)
        ? json.sigmas
        : Array.isArray(json?.results)
          ? json.results
          : Array.isArray(json?.data)
            ? json.data
            : [];
  const rules = arr.map(mapRule).filter((r): r is SocPrimeRule => Boolean(r));
  const out: SocPrimeRuleSearchResult = { raw: json };
  if (rules.length) out.rules = rules;
  const total = json?.total ?? json?.total_count ?? json?.count;
  out.total = typeof total === 'number' ? total : rules.length;
  return out;
}

/**
 * SOC Prime detection-rule search (`GET /v1/search-sigmas`). Filters are passed as request headers
 * (per the API spec). On-demand only. Never throws.
 */
export async function socprimeSearchRules(
  params: SocPrimeRuleSearchParams,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<SocPrimeRuleSearchResult | undefined> {
  if (!env.socprimeApiKey) return undefined;
  if (!params.siemType) return { error: 'siemType required' };
  const headers: Record<string, string> = {
    client_secret_id: env.socprimeApiKey,
    client_siem_type: params.siemType,
    accept: 'application/json',
    'user-agent': USER_AGENT,
  };
  if (params.query) headers.client_query_string = params.query;
  if (params.actor) headers.client_tags_actor = params.actor;
  if (params.tool) headers.client_tags_tool = params.tool;
  if (params.techniqueId) headers.tags_technique_id = params.techniqueId;
  if (params.sigmaLevel) headers.sigma_level = params.sigmaLevel;
  if (params.sigmaType) headers.client_sigma_type = params.sigmaType;
  headers.page_size = String(Math.min(Math.max(params.pageSize ?? 25, 1), 50));
  if (params.pageNumber && params.pageNumber > 1) headers.page_number = String(params.pageNumber);

  let res: Response;
  try {
    res = await fetch(`${baseUrl(env)}/v1/search-sigmas`, { headers, signal });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return { error: 'aborted' };
    return { error: `SOC Prime unreachable: ${(e as Error).message}` };
  }
  if (res.status === 404) return { rules: [], total: 0 };
  if (res.status === 429) return { error: 'SOC Prime: rate limited (30 req / 10s)' };
  if (!res.ok) return { error: await socprimeErr(res, 'Threat Detection Marketplace') };
  try {
    return mapSocprimeRules(await res.json());
  } catch {
    return { error: 'SOC Prime: malformed response' };
  }
}
