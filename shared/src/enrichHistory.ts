import type { NormalizedResult } from './types';

/** One point-in-time enrichment snapshot in a monitored IP's timeline. `by` records who enriched it
 *  (or 'auto' for the server-side scheduler). Shared by the web app and the proxy cron so the append /
 *  downsample behaviour is identical no matter which side records a point. */
export interface EnrichSnapshot {
  at: number;
  by?: string;
  result: NormalizedResult;
}

const MAX_HISTORY = 40; // hard backstop after age-based downsampling

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

/** Age-based bucket key so the timeline can't grow without bound however often an IP is re-enriched:
 *  recent is fine-grained, older is progressively coarser. Tiers ≈ ≤1wk daily · 2wk ~5pts · 3–4wk ~2 ·
 *  5–6wk ~1 · older monthly. */
function ageBucket(at: number, now: number): string {
  const day = 86_400_000;
  const ageDays = (now - at) / day;
  if (ageDays < 7) return 'd' + Math.floor(at / day);
  if (ageDays < 14) return 'a' + Math.floor(at / (1.4 * day));
  if (ageDays < 28) return 'b' + Math.floor(at / (7 * day));
  if (ageDays < 42) return 'c' + Math.floor(at / (14 * day));
  return 'm' + Math.floor(at / (30 * day));
}

/** Normalise snapshots into a bounded timeline: unique by time, thinned to the newest per age bucket,
 *  consecutive same-state runs collapsed to their onset, hard-capped. */
export function downsampleHistory(list: EnrichSnapshot[], now: number): EnrichSnapshot[] {
  const byAt = new Map<number, EnrichSnapshot>();
  for (const s of list) if (s && s.result && !byAt.has(s.at)) byAt.set(s.at, s);
  const sorted = [...byAt.values()].sort((a, b) => a.at - b.at);
  const seen = new Set<string>();
  const kept: EnrichSnapshot[] = [];
  for (let i = sorted.length - 1; i >= 0; i--) {
    const bk = ageBucket(sorted[i].at, now);
    if (!seen.has(bk)) {
      seen.add(bk);
      kept.push(sorted[i]);
    }
  }
  kept.reverse();
  const out: EnrichSnapshot[] = [];
  let lastSig: string | null = null;
  for (const s of kept) {
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
