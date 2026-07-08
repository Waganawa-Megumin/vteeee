import type { AbuseIpdbContext, AbuseReport } from '@vteeee/shared';
import type { ProxyEnv } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

// AbuseIPDB APIv2 — community IP abuse reporting. IP-only (v4/v6). Auth via the `Key` header.
// We use CHECK (read-only); the report/bulk-report/clear-address (POST/mutation) endpoints are
// intentionally NOT wired. AbuseIPDB sends no CORS headers → this must run server-side (the proxy).
const DEFAULT_BASE = 'https://api.abuseipdb.com/api/v2';
const DEFAULT_MAX_AGE = 90;

const str = (v: any): string | undefined => (typeof v === 'string' && v ? v : undefined);
const num = (v: any): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);

/** AbuseIPDB report category ids → human labels (the API returns numeric ids in `categories`). */
const CATEGORY_LABELS: Record<number, string> = {
  1: 'DNS Compromise',
  2: 'DNS Poisoning',
  3: 'Fraud Orders',
  4: 'DDoS Attack',
  5: 'FTP Brute-Force',
  6: 'Ping of Death',
  7: 'Phishing',
  8: 'Fraud VoIP',
  9: 'Open Proxy',
  10: 'Web Spam',
  11: 'Email Spam',
  12: 'Blog Spam',
  13: 'VPN IP',
  14: 'Port Scan',
  15: 'Hacking',
  16: 'SQL Injection',
  17: 'Spoofing',
  18: 'Brute-Force',
  19: 'Bad Web Bot',
  20: 'Exploited Host',
  21: 'Web App Attack',
  22: 'SSH',
  23: 'IoT Targeted',
};

function label(id: unknown): string | undefined {
  return typeof id === 'number' ? (CATEGORY_LABELS[id] ?? `Category ${id}`) : undefined;
}

function base(env: ProxyEnv): string {
  return (env.abuseipdbBaseUrl || DEFAULT_BASE).replace(/\/$/, '');
}

/** Map a raw CHECK response (`{ data: {...} }`) to our context (pure, tolerant). */
export function mapAbuseIpdb(json: any): AbuseIpdbContext {
  const d = json?.data;
  if (!d || typeof d !== 'object') return { found: false, error: 'AbuseIPDB: empty response' };
  const ctx: AbuseIpdbContext = { found: true, raw: json };
  ctx.abuseConfidenceScore = num(d.abuseConfidenceScore);
  ctx.totalReports = num(d.totalReports);
  ctx.numDistinctUsers = num(d.numDistinctUsers);
  ctx.lastReportedAt = str(d.lastReportedAt);
  ctx.countryCode = str(d.countryCode);
  ctx.countryName = str(d.countryName);
  ctx.usageType = str(d.usageType);
  ctx.isp = str(d.isp);
  ctx.domain = str(d.domain);
  if (Array.isArray(d.hostnames)) {
    const h = d.hostnames.filter((x: any) => typeof x === 'string' && x);
    if (h.length) ctx.hostnames = h.slice(0, 10);
  }
  if (typeof d.isTor === 'boolean') ctx.isTor = d.isTor;
  if (typeof d.isWhitelisted === 'boolean') ctx.isWhitelisted = d.isWhitelisted;
  ctx.ipVersion = num(d.ipVersion);

  // Reports (present only with the `verbose` flag). Keep a recent sample + the distinct categories.
  if (Array.isArray(d.reports) && d.reports.length) {
    const catCounts = new Map<string, number>();
    const reports: AbuseReport[] = [];
    for (const rep of d.reports) {
      const cats = Array.isArray(rep?.categories)
        ? (rep.categories.map(label).filter(Boolean) as string[])
        : [];
      for (const c of cats) catCounts.set(c, (catCounts.get(c) ?? 0) + 1);
      if (reports.length < 6) {
        reports.push({
          reportedAt: str(rep?.reportedAt),
          comment: str(rep?.comment)?.slice(0, 300),
          categories: cats.length ? [...new Set(cats)] : undefined,
          reporterCountryCode: str(rep?.reporterCountryCode),
        });
      }
    }
    if (reports.length) ctx.reports = reports;
    if (catCounts.size) {
      ctx.categories = [...catCounts.entries()].sort((a, b) => b[1] - a[1]).map(([c]) => c).slice(0, 12);
    }
  }
  return ctx;
}

/** Pull a human error out of an AbuseIPDB error body (`{ errors: [{ detail, status }] }`). */
async function abuseError(res: Response): Promise<string> {
  let detail = '';
  try {
    const body = (await res.json()) as any;
    detail = str(body?.errors?.[0]?.detail) ?? '';
  } catch {
    /* non-JSON */
  }
  if (res.status === 401) return 'AbuseIPDB 401 — invalid API key';
  if (res.status === 403) return 'AbuseIPDB 403 — forbidden (key/plan)';
  if (res.status === 429) return `AbuseIPDB: daily rate limit reached${detail ? ` (${detail})` : ''}`;
  if (res.status === 422) return `AbuseIPDB 422 — ${detail || 'invalid parameter'}`;
  return `AbuseIPDB error ${res.status}${detail ? ` — ${detail}` : ''}`;
}

/** CHECK an IP (verbose). Never throws. Returns `{ found:false, error }` on failure. */
export async function abuseipdbCheck(
  ip: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<AbuseIpdbContext | undefined> {
  if (!env.abuseipdbApiKey) return undefined;
  if (signal?.aborted) return undefined;
  const maxAge = Math.min(Math.max(env.abuseipdbMaxAgeDays ?? DEFAULT_MAX_AGE, 1), 365);
  const url = `${base(env)}/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=${maxAge}&verbose`;
  let res: Response;
  try {
    res = await fetch(url, {
      headers: { Key: env.abuseipdbApiKey, accept: 'application/json' },
      signal,
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return undefined;
    return { found: false, error: `AbuseIPDB unreachable: ${(e as Error).message}` };
  }
  if (!res.ok) return { found: false, error: await abuseError(res) };
  try {
    return mapAbuseIpdb(await res.json());
  } catch {
    return { found: false, error: 'AbuseIPDB: malformed response' };
  }
}
