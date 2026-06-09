import { apiPath, type EnrichableType, type ResultStatus } from '@vteeee/shared';
import { FatalError, RateLimitError, type ProxyEnv } from './types';

export interface VtLookup {
  status: ResultStatus;
  /** VT `data` object (has `.attributes`) on success. */
  data?: { attributes?: Record<string, unknown> };
}

/** Single VirusTotal v3 GET lookup. 404 -> not_found; 429 -> RateLimitError; 401/403 -> FatalError. */
export async function vtLookup(
  type: EnrichableType,
  value: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<VtLookup> {
  const res = await fetch(apiPath(type, value), {
    headers: {
      'x-apikey': env.vtApiKey,
      // Required for GTI to return gti_assessment.
      'x-tool': env.xTool ?? 'vteeee',
      accept: 'application/json',
    },
    signal,
  });

  if (res.status === 404) return { status: 'not_found' };
  if (res.status === 429) {
    const ra = res.headers.get('retry-after');
    const retryAfterMs = ra ? Number(ra) * 1000 : undefined;
    throw new RateLimitError(Number.isFinite(retryAfterMs) ? retryAfterMs : undefined);
  }
  if (res.status === 401 || res.status === 403) {
    throw new FatalError(`VirusTotal auth error ${res.status} — check VT_API_KEY`);
  }
  if (!res.ok) throw new Error(`VirusTotal error ${res.status}`);

  const json = (await res.json()) as { data?: { attributes?: Record<string, unknown> } };
  return { status: 'success', data: json.data };
}
