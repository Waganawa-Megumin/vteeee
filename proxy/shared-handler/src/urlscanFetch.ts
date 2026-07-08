import type { UrlscanResult, UrlscanSubmission } from '@vteeee/shared';
import type { ProxyEnv } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

// urlscan.io — submit a URL, it renders the page from ITS OWN sandbox (the analyst's / proxy's
// egress never touches the target) and returns a screenshot + resolved IPs + every network contact
// + a malicious verdict. A CTI "web魚拓". Submissions default to `unlisted` (not shown publicly).
//   Submit   POST /api/v1/scan/            → { uuid, result, api }
//   Result   GET  /api/v1/result/{uuid}/   → full analysis (404 while still processing)
const DEFAULT_BASE = 'https://urlscan.io';

const str = (v: any): string | undefined => (typeof v === 'string' && v ? v : undefined);
const num = (v: any): number | undefined => {
  const n = typeof v === 'string' ? Number(v) : v;
  return typeof n === 'number' && Number.isFinite(n) ? n : undefined;
};

function base(env: ProxyEnv): string {
  return (env.urlscanBaseUrl || DEFAULT_BASE).replace(/\/$/, '');
}

function headers(env: ProxyEnv, json = false): Record<string, string> {
  const h: Record<string, string> = {
    'API-Key': env.urlscanApiKey ?? '',
    accept: 'application/json',
  };
  if (json) h['content-type'] = 'application/json';
  return h;
}

/** Normalize a requested visibility to a urlscan-accepted value; default unlisted. */
function normVisibility(v?: string): 'public' | 'unlisted' | 'private' {
  return v === 'public' || v === 'private' ? v : 'unlisted';
}

/** Pull a human-readable error out of a urlscan error body (message/description). */
async function urlscanError(res: Response): Promise<string> {
  let msg = '';
  try {
    const body = (await res.json()) as any;
    msg = str(body?.message) ?? str(body?.description) ?? '';
  } catch {
    /* non-JSON body */
  }
  if (res.status === 401) return 'urlscan: invalid API key';
  if (res.status === 429) return `urlscan: rate/quota limited${msg ? ` — ${msg}` : ''}`;
  if (res.status === 400) return `urlscan: ${msg || 'bad request (unresolvable or blacklisted target?)'}`;
  return `urlscan error ${res.status}${msg ? ` — ${msg}` : ''}`;
}

/**
 * Submit a URL/domain for scanning. Never throws. Returns the scan ids so the client can poll the
 * result endpoint. `visibility` overrides the proxy default for this one scan.
 */
export async function urlscanSubmit(
  target: string,
  env: ProxyEnv,
  visibility?: string,
  signal?: AbortSignal,
): Promise<UrlscanSubmission | undefined> {
  if (!env.urlscanApiKey) return undefined;
  if (signal?.aborted) return undefined;
  // urlscan wants a fetchable URL; bare domains get a scheme.
  const url = /^[a-z][a-z0-9+.-]*:\/\//i.test(target) ? target : `http://${target}`;
  // OPSEC: never expose a scan to urlscan's PUBLIC feed/search unless the operator explicitly opted
  // in on the proxy (URLSCAN_ALLOW_PUBLIC). Free tier's safe maximum is `unlisted` (not public-searchable).
  const requested = normVisibility(visibility || env.urlscanVisibility);
  const vis = requested === 'public' && !env.urlscanAllowPublic ? 'unlisted' : requested;
  // Body carries only the URL + visibility. Tags are OFF by default: urlscan tags are searchable, so
  // a fixed tag would let anyone enumerate/cluster every scan this tool makes. Only added if configured.
  const body: Record<string, unknown> = { url, visibility: vis };
  const tags = (env.urlscanTags ?? '')
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean);
  if (tags.length) body.tags = tags;
  let res: Response;
  try {
    res = await fetch(`${base(env)}/api/v1/scan/`, {
      method: 'POST',
      headers: headers(env, true),
      body: JSON.stringify(body),
      signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return { error: 'aborted' };
    return { error: `urlscan unreachable: ${(e as Error).message}` };
  }
  if (!res.ok) return { error: await urlscanError(res) };
  try {
    const j = (await res.json()) as any;
    const uuid = str(j?.uuid);
    return {
      uuid,
      resultUrl: str(j?.result) ?? (uuid ? `${base(env)}/result/${uuid}/` : undefined),
      apiUrl: str(j?.api),
      screenshotUrl: uuid ? `${base(env)}/screenshots/${uuid}.png` : undefined,
      visibility: str(j?.visibility) ?? vis,
      message: str(j?.message),
    };
  } catch {
    return { error: 'urlscan: malformed submission response' };
  }
}

/** Map a urlscan result document (`GET /api/v1/result/{uuid}/`) to our shape (pure, tolerant). */
export function mapUrlscanResult(json: any, fallbackBase = DEFAULT_BASE): UrlscanResult {
  const task = json?.task ?? {};
  const page = json?.page ?? {};
  const lists = json?.lists ?? {};
  const overall = json?.verdicts?.overall ?? {};
  const uuid = str(task.uuid);
  const out: UrlscanResult = { raw: json };
  out.uuid = uuid;
  out.screenshotUrl = str(task.screenshotURL) ?? (uuid ? `${fallbackBase}/screenshots/${uuid}.png` : undefined);
  out.resultUrl = str(task.reportURL) ?? (uuid ? `${fallbackBase}/result/${uuid}/` : undefined);
  out.url = str(task.url) ?? str(page.url);
  out.finalUrl = str(page.url);
  out.title = str(page.title);
  out.ip = str(page.ip);
  out.asn = str(page.asn);
  out.asnName = str(page.asnname);
  out.country = str(page.country);
  out.server = str(page.server);
  out.status = num(page.status);
  out.malicious = typeof overall.malicious === 'boolean' ? overall.malicious : undefined;
  out.score = num(overall.score);
  if (Array.isArray(overall.brands) && overall.brands.length) {
    const brands = overall.brands.map((b: any) => str(b?.name) ?? str(b)).filter(Boolean) as string[];
    if (brands.length) out.brands = brands.slice(0, 8);
  }
  if (Array.isArray(overall.tags) && overall.tags.length)
    out.tags = overall.tags.filter((t: any) => typeof t === 'string').slice(0, 12);
  if (Array.isArray(lists.domains) && lists.domains.length)
    out.contactedDomains = lists.domains.filter((d: any) => typeof d === 'string').slice(0, 40);
  if (Array.isArray(lists.ips) && lists.ips.length)
    out.contactedIps = lists.ips.filter((i: any) => typeof i === 'string').slice(0, 40);
  return out;
}

/**
 * Fetch a scan result by uuid. Never throws. While urlscan is still rendering the page it returns
 * 404 → we surface `{ pending: true }` so the client polls again. API key is sent so `private`
 * results are readable.
 */
export async function urlscanResult(
  uuid: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<UrlscanResult | undefined> {
  if (!env.urlscanApiKey) return undefined;
  if (signal?.aborted) return undefined;
  let res: Response;
  try {
    res = await fetch(`${base(env)}/api/v1/result/${encodeURIComponent(uuid)}/`, {
      headers: headers(env),
      signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return { pending: true, uuid };
    return { uuid, error: `urlscan unreachable: ${(e as Error).message}` };
  }
  // 404 = the scan result isn't materialized yet — keep polling.
  if (res.status === 404) return { pending: true, uuid };
  if (!res.ok) return { uuid, error: await urlscanError(res) };
  try {
    return mapUrlscanResult(await res.json(), base(env));
  } catch {
    return { uuid, error: 'urlscan: malformed result' };
  }
}
