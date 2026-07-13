import type { EnrichableType, EnrichSnapshot, NormalizedResult } from '@vteeee/shared';
import { downsampleHistory } from '@vteeee/shared';

/** One indicator tracked under a campaign. Reuses the IP-Mon enrichment timeline machinery
 *  (result + history via EnrichSnapshot) but for ANY IOC type and without Shodan-alert fields. */
/** Which side of the campaign an IOC belongs to: attacker infrastructure vs. targeted/victim assets. */
export type IocSide = 'attack' | 'target';

export interface CampaignIoc {
  value: string;
  type: EnrichableType;
  /** attack = attacker infrastructure (C2, malware, phishing); target = victim-side asset. Default attack. */
  side?: IocSide;
  /** Analyst-assigned group label within the campaign (arbitrary; empty = ungrouped). */
  group?: string;
  addedAt: number;
  updatedAt: number;
  addedBy?: string;
  /** Server-side + client-side auto re-enrich (default on — CP-Mon's whole point is continuous intel). */
  autoEnrich?: boolean;
  lastEnrichAt?: number;
  result?: NormalizedResult;
  history?: EnrichSnapshot[];
  enriching?: boolean;
  error?: string;
  note?: string;
}

/** A Claude-written (or deterministic-fallback) key-message summary of the campaign — the whole
 *  picture incl. how the enrichment has shifted (情報推移). Shown as the 電光掲示板 marquee up top. */
export interface CampaignSummary {
  text: string;
  at: number;
  by?: string;
  model?: string;
}

/** Traffic Light Protocol handling marking for the campaign / its assessment. */
export type TlpLevel = 'CLEAR' | 'GREEN' | 'AMBER' | 'AMBER+STRICT' | 'RED';
export const TLP_LEVELS: TlpLevel[] = ['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED'];

/** Admiralty Code (NATO source-evaluation system): source reliability A–F + info credibility 1–6. */
export const ADMIRALTY_RELIABILITY: [string, string][] = [
  ['A', '完全に信頼できる (Completely reliable)'],
  ['B', '通常信頼できる (Usually reliable)'],
  ['C', 'かなり信頼できる (Fairly reliable)'],
  ['D', '通常は信頼できない (Not usually reliable)'],
  ['E', '信頼できない (Unreliable)'],
  ['F', '信頼性を判定できない (Cannot be judged)'],
];
export const ADMIRALTY_CREDIBILITY: [string, string][] = [
  ['1', '確認済み・他の独立ソースで裏付け (Confirmed)'],
  ['2', 'おそらく真 (Probably true)'],
  ['3', '真の可能性あり (Possibly true)'],
  ['4', '疑わしい (Doubtful)'],
  ['5', 'ありそうにない (Improbable)'],
  ['6', '真偽を判定できない (Cannot be judged)'],
];

/** A Claude-written CTI assessment report (markdown) — context-based insight, not a data dump. */
export interface CampaignAssessment {
  text: string;
  at: number;
  by?: string;
  model?: string;
  /** TLP the report was generated under (snapshotted so the report carries its own marking). */
  tlp?: TlpLevel;
}

export interface Campaign {
  id: string;
  name: string;
  createdAt: number;
  updatedAt: number;
  note?: string;
  iocs: Record<string, CampaignIoc>;
  /** Analyst-defined display order of group names (groups not listed fall back to alphabetical). */
  groupOrder?: string[];
  /** Traffic Light Protocol marking (analyst-set; defaults to AMBER when unset). */
  tlp?: TlpLevel;
  /** Admiralty Code — source reliability (A–F). */
  admiraltyReliability?: string;
  /** Admiralty Code — information credibility (1–6). */
  admiraltyCredibility?: string;
  /** Latest overall summary (shared with the campaign so the whole team sees the same key message). */
  summary?: CampaignSummary;
  /** Latest Claude CTI assessment report (shared). */
  assessment?: CampaignAssessment;
}

export const CAMPAIGNS_KEY = 'vteeee.campaigns';

function stripRaw(r?: NormalizedResult): NormalizedResult | undefined {
  if (!r) return undefined;
  const { raw: _raw, ...rest } = r as NormalizedResult & { raw?: unknown };
  return rest as NormalizedResult;
}
function slimIoc(i: CampaignIoc): CampaignIoc {
  return {
    ...i,
    result: stripRaw(i.result),
    history: i.history?.map((s) => ({ at: s.at, by: s.by, result: stripRaw(s.result) as NormalizedResult })),
    enriching: false,
  };
}
/** Trim a campaign for persistence/sharing (raw VT payloads stripped from every IOC + snapshot). */
export function slimCampaign(c: Campaign): Campaign {
  const iocs: Record<string, CampaignIoc> = {};
  for (const [k, v] of Object.entries(c.iocs)) iocs[k] = slimIoc(v);
  return { ...c, iocs };
}

const CAMPAIGNS_BAK = `${CAMPAIGNS_KEY}.bak`;

export function loadCampaigns(): Record<string, Campaign> {
  try {
    const raw = localStorage.getItem(CAMPAIGNS_KEY);
    return raw ? (JSON.parse(raw) as Record<string, Campaign>) : {};
  } catch {
    // Corrupt JSON — preserve it under a side key rather than silently losing it.
    try {
      const raw = localStorage.getItem(CAMPAIGNS_KEY);
      if (raw) localStorage.setItem(`${CAMPAIGNS_KEY}.corrupt`, raw);
    } catch {
      /* ignore */
    }
    return {};
  }
}
export function saveCampaigns(m: Record<string, Campaign>): void {
  try {
    const slim: Record<string, Campaign> = {};
    for (const [k, v] of Object.entries(m)) slim[k] = slimCampaign(v);
    const next = JSON.stringify(slim);
    // One-slot backup: keep the previous NON-EMPTY value before overwriting, so an accidental wipe
    // (e.g. saving {} over real data) stays recoverable via loadCampaignsBackup().
    const prev = localStorage.getItem(CAMPAIGNS_KEY);
    if (prev && prev !== next && prev !== '{}' && Object.keys(m).length === 0) {
      localStorage.setItem(CAMPAIGNS_BAK, prev);
    } else if (prev && prev !== '{}' && Object.keys(m).length) {
      localStorage.setItem(CAMPAIGNS_BAK, prev);
    }
    localStorage.setItem(CAMPAIGNS_KEY, next);
  } catch {
    /* storage full/disabled — in-memory campaigns still work */
  }
}
/** The last non-empty persisted campaigns snapshot (for recovery after an accidental wipe). */
export function loadCampaignsBackup(): Record<string, Campaign> | null {
  try {
    const raw = localStorage.getItem(CAMPAIGNS_BAK);
    const m = raw ? (JSON.parse(raw) as Record<string, Campaign>) : null;
    return m && Object.keys(m).length ? m : null;
  } catch {
    return null;
  }
}

/** Merge a local + shared copy of one IOC, unioning enrichment timelines (nobody's snapshots lost). */
export function mergeIoc(a: CampaignIoc | undefined, b: CampaignIoc | undefined): CampaignIoc {
  const A = (a ?? {}) as Partial<CampaignIoc>;
  const B = (b ?? {}) as Partial<CampaignIoc>;
  const history = downsampleHistory([...(A.history ?? []), ...(B.history ?? [])], Date.now());
  const latest = history.length ? history[history.length - 1].result : undefined;
  return {
    value: (B.value ?? A.value) as string,
    type: (B.type ?? A.type) as EnrichableType,
    side: B.side ?? A.side,
    group: B.group ?? A.group,
    addedAt: Math.min(A.addedAt ?? Number.MAX_SAFE_INTEGER, B.addedAt ?? Number.MAX_SAFE_INTEGER),
    updatedAt: Math.max(A.updatedAt ?? 0, B.updatedAt ?? 0),
    addedBy: A.addedBy ?? B.addedBy,
    autoEnrich: B.autoEnrich ?? A.autoEnrich,
    lastEnrichAt: Math.max(A.lastEnrichAt ?? 0, B.lastEnrichAt ?? 0) || undefined,
    result: latest ?? B.result ?? A.result,
    history: history.length ? history : undefined,
    note: B.note ?? A.note,
  };
}

/** Merge two copies of a campaign (union IOCs; prefer the more-recently-updated name/note). */
export function mergeCampaign(a: Campaign | undefined, b: Campaign | undefined): Campaign {
  const base = (b ?? a)!;
  const newerB = (b?.updatedAt ?? 0) >= (a?.updatedAt ?? 0);
  const iocs: Record<string, CampaignIoc> = {};
  const keys = new Set([...Object.keys(a?.iocs ?? {}), ...Object.keys(b?.iocs ?? {})]);
  for (const k of keys) iocs[k] = mergeIoc(a?.iocs?.[k], b?.iocs?.[k]);
  // Keep whichever summary/assessment was generated most recently (travels with the shared campaign).
  const summary = (b?.summary?.at ?? 0) >= (a?.summary?.at ?? 0) ? b?.summary ?? a?.summary : a?.summary ?? b?.summary;
  const assessment =
    (b?.assessment?.at ?? 0) >= (a?.assessment?.at ?? 0) ? b?.assessment ?? a?.assessment : a?.assessment ?? b?.assessment;
  return {
    id: base.id,
    name: (newerB ? b?.name : a?.name) ?? base.name,
    createdAt: Math.min(a?.createdAt ?? Number.MAX_SAFE_INTEGER, b?.createdAt ?? Number.MAX_SAFE_INTEGER),
    updatedAt: Math.max(a?.updatedAt ?? 0, b?.updatedAt ?? 0),
    note: (newerB ? b?.note : a?.note) ?? base.note,
    tlp: (newerB ? b?.tlp : a?.tlp) ?? base.tlp,
    admiraltyReliability: (newerB ? b?.admiraltyReliability : a?.admiraltyReliability) ?? base.admiraltyReliability,
    admiraltyCredibility: (newerB ? b?.admiraltyCredibility : a?.admiraltyCredibility) ?? base.admiraltyCredibility,
    groupOrder: (newerB ? b?.groupOrder : a?.groupOrder) ?? base.groupOrder,
    iocs,
    summary,
    assessment,
  };
}

export function mergeCampaigns(
  local: Record<string, Campaign>,
  shared: Record<string, Campaign> | null,
): Record<string, Campaign> {
  const out: Record<string, Campaign> = {};
  const keys = new Set([...Object.keys(local), ...Object.keys(shared ?? {})]);
  for (const id of keys) out[id] = mergeCampaign(local[id], shared?.[id]);
  return out;
}
