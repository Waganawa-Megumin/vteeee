import type { NormalizedResult } from './types';

/** One point-in-time enrichment snapshot in a monitored IP's timeline. `by` records who enriched it
 *  (or 'auto' for the server-side scheduler). Shared by the web app and the proxy cron so the append /
 *  downsample behaviour is identical no matter which side records a point. */
export interface EnrichSnapshot {
  at: number;
  by?: string;
  result: NormalizedResult;
}

const MAX_HISTORY = 400; // safety backstop only — every change point is kept; Tr-Analysis thins the DISPLAY

/** Compact signature of the triage-relevant fields. Two snapshots with the same signature represent
 *  the "same state", so consecutive duplicates are collapsed — the timeline stays meaningful & small. */
export function snapSig(r: NormalizedResult): string {
  const d = r.detection;
  return [
    r.verdict,
    r.status,
    d ? `${d.malicious}/${d.suspicious}/${d.harmless}/${d.total}` : '-',
    r.reputation ?? '-',
    r.gti?.verdict ?? '-',
    r.gti?.severity ?? '-',
    r.gti?.threatScore ?? '-',
    r.abuseipdb?.abuseConfidenceScore ?? '-',
    r.abuseipdb?.totalReports ?? '-',
    r.recordedfuture?.riskScore ?? '-',
    (r.shodan?.ports ?? []).join(','),
    (r.shodan?.vulns ?? []).join(','),
    r.maxmind?.countryCode ?? r.abuseipdb?.countryCode ?? r.shodan?.country ?? r.ip?.country ?? '-',
    (r.tags ?? []).join(','),
  ].join('|');
}

/**
 * Normalise snapshots into a CHANGE-POINT timeline: unique by time, then keep only points where the
 * triage state actually changed (consecutive identical snapshots collapse to their onset — lossless).
 * There is NO age-based deletion, so a change from a year ago is preserved just like yesterday's; the
 * only bound is a high safety cap. Tr-Analysis thins the DISPLAY (collapsing old periods) instead of
 * throwing data away.
 */
export function downsampleHistory(list: EnrichSnapshot[], _now: number): EnrichSnapshot[] {
  const byAt = new Map<number, EnrichSnapshot>();
  for (const s of list) if (s && s.result && !byAt.has(s.at)) byAt.set(s.at, s);
  const sorted = [...byAt.values()].sort((a, b) => a.at - b.at);
  const out: EnrichSnapshot[] = [];
  let lastSig: string | null = null;
  for (const s of sorted) {
    const sig = snapSig(s.result);
    if (sig !== lastSig) {
      out.push(s);
      lastSig = sig;
    }
  }
  return out.slice(-MAX_HISTORY);
}

/** Append a snapshot only if it's a real change vs the newest one, then re-downsample by age. */
export function appendSnapshot(
  history: EnrichSnapshot[] | undefined,
  snap: EnrichSnapshot,
  now: number,
): EnrichSnapshot[] {
  const prev = history ?? [];
  const last = prev[prev.length - 1];
  if (last && snapSig(last.result) === snapSig(snap.result)) return prev;
  return downsampleHistory([...prev, snap], now);
}

/** Auto-enrich cadence, aligned to the history tiers so it captures ~1 point per downsample bucket:
 *  week 1 daily · week 2 ≈ 1.5d · weeks 3–4 weekly · weeks 5–6 biweekly · older monthly (定点観測). */
export function autoEnrichInterval(ageMs: number): number {
  const day = 86_400_000;
  const ageDays = ageMs / day;
  if (ageDays < 7) return day;
  if (ageDays < 14) return 1.5 * day;
  if (ageDays < 28) return 7 * day;
  if (ageDays < 42) return 14 * day;
  return 30 * day;
}
