import type { NormalizedResult } from '@vteeee/shared';

/** Best-effort country across the enrichers. */
export function countryOf(r: NormalizedResult): string {
  return r.maxmind?.countryCode ?? r.abuseipdb?.countryCode ?? r.shodan?.country ?? r.ip?.country ?? '';
}

// Numeric series extractors used by trends / sparklines.
export const detOf = (r: NormalizedResult) => (r.detection?.malicious ?? 0) + (r.detection?.suspicious ?? 0);
export const abuseOf = (r: NormalizedResult) => r.abuseipdb?.abuseConfidenceScore ?? null;
export const rfOf = (r: NormalizedResult) => r.recordedfuture?.riskScore ?? null;
export const portsOf = (r: NormalizedResult) => r.shodan?.ports?.length ?? 0;
export const cvesOf = (r: NormalizedResult) => r.shodan?.vulns?.length ?? 0;

/** Human-readable "what changed" between two enrichment snapshots (cur vs prev). */
export function diffParts(cur: NormalizedResult, prev: NormalizedResult): string[] {
  const parts: string[] = [];
  if (prev.verdict !== cur.verdict) parts.push(`verdict ${prev.verdict}→${cur.verdict}`);
  if (detOf(prev) !== detOf(cur) || (prev.detection?.total ?? 0) !== (cur.detection?.total ?? 0))
    parts.push(`det ${detOf(prev)}/${prev.detection?.total ?? 0}→${detOf(cur)}/${cur.detection?.total ?? 0}`);
  if (abuseOf(prev) !== abuseOf(cur)) parts.push(`abuse ${abuseOf(prev) ?? '—'}→${abuseOf(cur) ?? '—'}`);
  if (rfOf(prev) !== rfOf(cur)) parts.push(`RF ${rfOf(prev) ?? '—'}→${rfOf(cur) ?? '—'}`);
  const setD = (prevArr: (number | string)[] | undefined, curArr: (number | string)[] | undefined, label: string) => {
    const p = new Set(prevArr ?? []);
    const c = new Set(curArr ?? []);
    const add = [...c].filter((x) => !p.has(x));
    const gone = [...p].filter((x) => !c.has(x));
    if (add.length) parts.push(`+${label} ${add.slice(0, 5).join(',')}${add.length > 5 ? '…' : ''}`);
    if (gone.length) parts.push(`−${label} ${gone.slice(0, 5).join(',')}${gone.length > 5 ? '…' : ''}`);
  };
  setD(prev.shodan?.ports, cur.shodan?.ports, 'ports');
  setD(prev.shodan?.vulns, cur.shodan?.vulns, 'CVE');
  if (countryOf(prev) !== countryOf(cur)) parts.push(`country ${countryOf(prev) || '—'}→${countryOf(cur) || '—'}`);
  return parts;
}
