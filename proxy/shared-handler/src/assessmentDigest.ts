import type { EnrichableType, EnrichSnapshot, NormalizedResult } from '@vteeee/shared';

// Server-side ports of the web client's assessment digest builders (web/src/state/store.ts +
// web/src/lib/enrichTrend.ts), so the daily cron can generate the SAME CP-Mon / IP-Mon reports without
// a browser open. Kept as a faithful copy against loose input shapes; the web keeps its own copy for the
// on-demand path (a future cleanup could hoist both into @vteeee/shared and dedupe).

// ---- enrichTrend helpers (pure, isomorphic) -----------------------------------------------------
/** Best-effort country across the enrichers. */
export function countryOf(r: NormalizedResult): string {
  return r.maxmind?.countryCode ?? r.abuseipdb?.countryCode ?? r.shodan?.country ?? r.ip?.country ?? '';
}
const detOf = (r: NormalizedResult): number => (r.detection?.malicious ?? 0) + (r.detection?.suspicious ?? 0);
const abuseOf = (r: NormalizedResult): number | null => r.abuseipdb?.abuseConfidenceScore ?? null;
const rfOf = (r: NormalizedResult): number | null => r.recordedfuture?.riskScore ?? null;

/** Human-readable "what changed" between two enrichment snapshots (cur vs prev). */
function diffParts(cur: NormalizedResult, prev: NormalizedResult): string[] {
  const parts: string[] = [];
  if (prev.verdict !== cur.verdict) parts.push(`verdict ${prev.verdict}→${cur.verdict}`);
  if (detOf(prev) !== detOf(cur) || (prev.detection?.total ?? 0) !== (cur.detection?.total ?? 0))
    parts.push(`det ${detOf(prev)}/${prev.detection?.total ?? 0}→${detOf(cur)}/${cur.detection?.total ?? 0}`);
  if (abuseOf(prev) !== abuseOf(cur)) parts.push(`abuse ${abuseOf(prev) ?? '—'}→${abuseOf(cur) ?? '—'}`);
  if (rfOf(prev) !== rfOf(cur)) parts.push(`RF ${rfOf(prev) ?? '—'}→${rfOf(cur) ?? '—'}`);
  const setD = (prevArr: (number | string)[] | undefined, curArr: (number | string)[] | undefined, label: string): void => {
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

// ---- CP-Mon (campaign) digest -------------------------------------------------------------------
interface IocLike {
  value: string;
  type: EnrichableType;
  group?: string;
  side?: 'attack' | 'target';
  result?: NormalizedResult;
  history?: EnrichSnapshot[];
}
export interface CampaignLike {
  name?: string;
  tlp?: string;
  note?: string;
  admiraltyReliability?: string;
  admiraltyCredibility?: string;
  iocs?: Record<string, IocLike>;
}

/** Faithful port of the web app's buildAssessmentDigest(campaign). */
export function buildCampaignDigest(c: CampaignLike): unknown {
  const iocs = Object.values(c.iocs ?? {});
  const brief = (i: IocLike): unknown => {
    const r = i.result;
    const h = i.history?.length ? [...i.history].sort((a, b) => a.at - b.at) : [];
    const changes = h.length >= 2 ? diffParts(h[h.length - 1].result, h[h.length - 2].result) : [];
    return {
      value: i.value,
      type: i.type,
      group: i.group,
      verdict: r?.verdict,
      country: r ? countryOf(r) || undefined : undefined,
      org: r?.maxmind?.organization ?? r?.shodan?.org ?? r?.ip?.asOwner ?? undefined,
      asn: r?.maxmind?.asn ?? r?.ip?.asn ?? undefined,
      det: r ? detOf(r) : undefined,
      abuse: r ? abuseOf(r) ?? undefined : undefined,
      rf: r ? rfOf(r) ?? undefined : undefined,
      ports: r?.shodan?.ports?.slice(0, 12),
      cves: r?.shodan?.vulns?.slice(0, 12),
      threat: r?.file?.threatLabel ?? r?.gti?.verdict ?? undefined,
      firstDays: h.length ? Math.round((Date.now() - h[0].at) / 86_400_000) : undefined,
      recentChange: changes.length ? changes.join(' · ') : undefined,
    };
  };
  const cap = 50;
  const attack = iocs.filter((i) => (i.side ?? 'attack') === 'attack').slice(0, cap).map(brief);
  const target = iocs.filter((i) => i.side === 'target').slice(0, cap).map(brief);
  const byType = new Map<string, number>();
  const byCountry = new Map<string, number>();
  const byCve = new Map<string, number>();
  const byGroup = new Map<string, number>();
  let minAt = Number.MAX_SAFE_INTEGER;
  let maxAt = 0;
  let totalSnapshots = 0;
  const recentChanges: { value: string; changes: string }[] = [];
  for (const i of iocs) {
    byType.set(i.type, (byType.get(i.type) ?? 0) + 1);
    if (i.group) byGroup.set(i.group, (byGroup.get(i.group) ?? 0) + 1);
    const r = i.result;
    if (r) {
      const cc = countryOf(r);
      if (cc) byCountry.set(cc, (byCountry.get(cc) ?? 0) + 1);
      for (const v of r.shodan?.vulns ?? []) byCve.set(v, (byCve.get(v) ?? 0) + 1);
    }
    const h = i.history?.length ? [...i.history].sort((a, b) => a.at - b.at) : [];
    totalSnapshots += h.length;
    if (h.length) {
      minAt = Math.min(minAt, h[0].at);
      maxAt = Math.max(maxAt, h[h.length - 1].at);
      if (h.length >= 2) {
        const ch = diffParts(h[h.length - 1].result, h[h.length - 2].result);
        if (ch.length) recentChanges.push({ value: i.value, changes: ch.join(' · ') });
      }
    }
  }
  const top = (m: Map<string, number>, n: number): [string, number][] =>
    [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  return {
    name: c.name,
    tlp: c.tlp ?? 'AMBER',
    analystNote: c.note && c.note.trim() ? c.note.trim().slice(0, 4000) : undefined,
    admiralty:
      c.admiraltyReliability || c.admiraltyCredibility
        ? `${c.admiraltyReliability ?? '?'}${c.admiraltyCredibility ?? '?'}`
        : undefined,
    iocCount: iocs.length,
    spanDays: maxAt > minAt && minAt !== Number.MAX_SAFE_INTEGER ? Math.round((maxAt - minAt) / 86_400_000) : 0,
    totalSnapshots,
    stats: {
      withIntel: iocs.filter((i) => i.result).length,
      malicious: iocs.filter((i) => i.result?.verdict === 'malicious').length,
      suspicious: iocs.filter((i) => i.result?.verdict === 'suspicious').length,
      highAbuse: iocs.filter((i) => (i.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75).length,
      distinctCves: byCve.size,
    },
    bySide: { attack: attack.length, target: target.length },
    byType: top(byType, 8),
    topCountries: top(byCountry, 10),
    topCves: top(byCve, 12),
    groups: top(byGroup, 20),
    attack,
    target,
    recentChanges: recentChanges.slice(0, 20),
  };
}

// ---- IP-Mon (monitor) digest --------------------------------------------------------------------
interface CheckLike {
  at: number;
  changed?: boolean;
  newPorts?: number[];
  gonePorts?: number[];
  newVulns?: string[];
}
export interface MonitorLike {
  ip: string;
  group?: string;
  result?: NormalizedResult;
  history?: EnrichSnapshot[];
  addedAt: number;
  lastEnrichAt?: number;
  check?: CheckLike;
  live?: boolean;
  triggers?: string[];
  autoEnrich?: boolean;
}

/** Faithful port of the web app's buildMonitorDigest(monitors, groupOrder, tlp). */
export function buildMonitorDigest(monitors: Record<string, MonitorLike>, groupOrder: string[], tlp: string): unknown {
  const list = Object.values(monitors);
  const now = Date.now();
  const day = 86_400_000;
  const UNGROUPED = 'Ungrouped';
  const groupOf = (e: MonitorLike): string => (e.group && e.group.trim() ? e.group : UNGROUPED);
  const top = (m: Map<string, number>, n: number): [string, number][] =>
    [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);

  const host = (e: MonitorLike): unknown => {
    const r = e.result;
    const hAsc = e.history?.length ? [...e.history].sort((a, b) => a.at - b.at) : [];
    return {
      ip: e.ip,
      verdict: r?.verdict,
      country: r ? countryOf(r) || undefined : undefined,
      org: r?.shodan?.org ?? r?.maxmind?.organization ?? r?.ip?.asOwner ?? undefined,
      asn: r?.maxmind?.asn ?? r?.ip?.asn ?? undefined,
      abuse: r?.abuseipdb?.abuseConfidenceScore ?? undefined,
      rf: r?.recordedfuture?.riskScore ?? undefined,
      det: r?.detection ? `${detOf(r)}/${r.detection.total ?? 0}` : undefined,
      ports: r?.shodan?.ports?.slice(0, 16),
      cves: r?.shodan?.vulns?.slice(0, 12),
      hostnames: r?.shodan?.hostnames?.slice(0, 3),
      live: e.live || undefined,
      triggers: e.triggers?.length ? e.triggers : undefined,
      auto: e.autoEnrich || undefined,
      firstSeenDays: Math.round((now - (hAsc.length ? hAsc[0].at : e.addedAt)) / day),
      snapshots: hAsc.length || undefined,
      daysSinceEnrich: e.lastEnrichAt ? Math.round((now - e.lastEnrichAt) / day) : undefined,
      daysSinceCheck: e.check?.at ? Math.round((now - e.check.at) / day) : undefined,
    };
  };

  const present = [...new Set(list.map(groupOf))];
  const ordered = [
    ...groupOrder.filter((g) => present.includes(g) && g !== UNGROUPED),
    ...present.filter((g) => !groupOrder.includes(g) && g !== UNGROUPED).sort((a, b) => a.localeCompare(b)),
    ...(present.includes(UNGROUPED) ? [UNGROUPED] : []),
  ];

  const groups = ordered.map((g) => {
    const es = list.filter((e) => groupOf(e) === g);
    const surfaceChanges: { ip: string; at: number; newPorts?: number[]; gonePorts?: number[]; newCves?: string[] }[] = [];
    const riskThreatChanges: { ip: string; at: number; changes: string }[] = [];
    const byCountry = new Map<string, number>();
    const byOrg = new Map<string, number>();
    const byCve = new Map<string, number>();
    for (const e of es) {
      const r = e.result;
      if (r) {
        const cc = countryOf(r);
        if (cc) byCountry.set(cc, (byCountry.get(cc) ?? 0) + 1);
        const org = r.shodan?.org ?? r.maxmind?.organization ?? r.ip?.asOwner;
        if (org) byOrg.set(org, (byOrg.get(org) ?? 0) + 1);
        for (const v of r.shodan?.vulns ?? []) byCve.set(v, (byCve.get(v) ?? 0) + 1);
      }
      if (e.check?.changed) {
        surfaceChanges.push({
          ip: e.ip,
          at: e.check.at,
          newPorts: e.check.newPorts?.length ? e.check.newPorts.slice(0, 8) : undefined,
          gonePorts: e.check.gonePorts?.length ? e.check.gonePorts.slice(0, 8) : undefined,
          newCves: e.check.newVulns?.length ? e.check.newVulns.slice(0, 6) : undefined,
        });
      }
      const hAsc = e.history?.length ? [...e.history].sort((a, b) => a.at - b.at) : [];
      if (hAsc.length >= 2) {
        const changes = diffParts(hAsc[hAsc.length - 1].result, hAsc[hAsc.length - 2].result);
        if (changes.length) riskThreatChanges.push({ ip: e.ip, at: hAsc[hAsc.length - 1].at, changes: changes.join(' · ') });
      }
    }
    return {
      name: g,
      ipCount: es.length,
      live: es.filter((e) => e.live).length,
      malicious: es.filter((e) => e.result?.verdict === 'malicious').length,
      suspicious: es.filter((e) => e.result?.verdict === 'suspicious').length,
      highAbuse: es.filter((e) => (e.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75).length,
      changedSinceBaseline: es.filter((e) => e.check?.changed).length,
      autoOn: es.filter((e) => e.autoEnrich).length,
      topCountries: top(byCountry, 6),
      topOrgs: top(byOrg, 5),
      topCves: top(byCve, 8),
      surfaceChanges: surfaceChanges.slice(0, 20),
      riskThreatChanges: riskThreatChanges.slice(0, 20),
      hosts: es.slice(0, 30).map(host),
    };
  });

  const checkAts = list.map((e) => e.check?.at).filter((x): x is number => typeof x === 'number');
  const enrichAts = list.map((e) => e.lastEnrichAt).filter((x): x is number => typeof x === 'number');
  const staleEnrich = list.filter((e) => !e.lastEnrichAt || now - e.lastEnrichAt > 14 * day).map((e) => e.ip);
  const neverChecked = list.filter((e) => !e.check?.at).map((e) => e.ip);
  const byCountryAll = new Map<string, number>();
  for (const e of list) {
    const r = e.result;
    if (r) {
      const cc = countryOf(r);
      if (cc) byCountryAll.set(cc, (byCountryAll.get(cc) ?? 0) + 1);
    }
  }
  const spanStart = Math.min(...list.map((e) => (e.history?.length ? e.history[0].at : e.addedAt)));

  return {
    kind: 'ip-mon',
    tlp,
    totals: {
      monitored: list.length,
      live: list.filter((e) => e.live).length,
      withIntel: list.filter((e) => e.result).length,
      malicious: list.filter((e) => e.result?.verdict === 'malicious').length,
      suspicious: list.filter((e) => e.result?.verdict === 'suspicious').length,
      highAbuse: list.filter((e) => (e.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75).length,
      changedSinceBaseline: list.filter((e) => e.check?.changed).length,
      countries: byCountryAll.size,
      autoOn: list.filter((e) => e.autoEnrich).length,
      groups: ordered.length,
    },
    monitoringWindowDays: Number.isFinite(spanStart) ? Math.round((now - spanStart) / day) : 0,
    scanActivity: {
      lastCheckAt: checkAts.length ? Math.max(...checkAts) : undefined,
      lastEnrichAt: enrichAts.length ? Math.max(...enrichAts) : undefined,
      checkedCount: checkAts.length,
      staleEnrichCount: staleEnrich.length,
      staleEnrich: staleEnrich.slice(0, 20),
      neverCheckedCount: neverChecked.length,
      neverChecked: neverChecked.slice(0, 20),
    },
    geo: { topCountries: top(byCountryAll, 12) },
    groups,
    generatedAt: now,
  };
}
