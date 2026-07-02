import type { SocPrimeQueryOptions, SocPrimeQueryResult } from '@vteeee/shared';
import type { ProxyEnv } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

const DEFAULT_BASE = 'https://api.tdm.socprime.com';

function baseUrl(env: ProxyEnv): string {
  return (env.socprimeBaseUrl || DEFAULT_BASE).replace(/\/$/, '');
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
      },
      body: JSON.stringify(body),
      signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return { error: 'aborted' };
    return { error: `SOC Prime unreachable: ${(e as Error).message}` };
  }
  if (res.status === 401 || res.status === 403)
    return { error: `SOC Prime ${res.status} — check API key / Uncoder AI permission` };
  if (res.status === 429) return { error: 'SOC Prime: rate limited (30 req / 10s)' };
  if (!res.ok) return { error: `SOC Prime error ${res.status}` };
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
