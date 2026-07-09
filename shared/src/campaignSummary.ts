/**
 * A compact, privacy-safe digest of a CP-Mon campaign, built on the client and sent to the proxy for
 * Claude to turn into a one-line key message (電光掲示板). Only aggregates + short change strings — never
 * raw enrichment payloads — so it stays small and cheap.
 */
export interface CampaignDigest {
  name: string;
  iocCount: number;
  withIntel: number;
  malicious: number;
  suspicious: number;
  highAbuse: number;
  distinctCves: number;
  autoCount: number;
  /** [type, count] e.g. [["ipv4", 8], ["domain", 3]] */
  byType: [string, number][];
  /** [countryCodeOrName, count], most-common first */
  topCountries: [string, number][];
  /** [cve, count], most-common first */
  topCves: [string, number][];
  /** [groupName, count] */
  groups: [string, number][];
  /** Per-IOC "vs previous" change strings — the 情報推移 (how the picture has shifted). */
  recentChanges: { value: string; changes: string[] }[];
  /** Days spanned by the earliest→latest snapshot across the campaign. */
  spanDays: number;
  totalSnapshots: number;
}

/**
 * Deterministic one-line summary, no LLM required. Used verbatim when no Claude key is configured
 * (proxy) or no proxy is connected (client), so the marquee always has something meaningful to show.
 */
export function fallbackSummary(d: CampaignDigest): string {
  const parts: string[] = [`🎯 ${d.name}`];
  const head: string[] = [`${d.iocCount} IOCs`];
  if (d.withIntel) head.push(`intel ${d.withIntel}`);
  if (d.malicious) head.push(`🔴 malicious ${d.malicious}`);
  if (d.suspicious) head.push(`🟠 suspicious ${d.suspicious}`);
  if (d.highAbuse) head.push(`abuse≥75 ${d.highAbuse}`);
  if (d.distinctCves) head.push(`CVE ${d.distinctCves}`);
  parts.push(head.join(' · '));
  if (d.topCountries.length) {
    parts.push(`主要国 ${d.topCountries.slice(0, 3).map(([c, n]) => `${c}(${n})`).join(' ')}`);
  }
  if (d.recentChanges.length) {
    const chg = d.recentChanges
      .slice(0, 3)
      .map((r) => `${r.value}: ${r.changes.slice(0, 2).join('/')}`)
      .join(' ／ ');
    parts.push(`直近の変化 ▲ ${chg}`);
  } else if (d.totalSnapshots > d.iocCount) {
    parts.push('直近の大きな変化なし');
  }
  return parts.join(' ｜ ');
}
