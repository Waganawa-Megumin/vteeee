import type { EnrichableType, EnrichSnapshot, NormalizedResult } from '@vteeee/shared';
import { downsampleHistory } from '@vteeee/shared';

/** One indicator tracked under a campaign. Reuses the IP-Mon enrichment timeline machinery
 *  (result + history via EnrichSnapshot) but for ANY IOC type and without Shodan-alert fields. */
export interface CampaignIoc {
  value: string;
  type: EnrichableType;
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

export interface Campaign {
  id: string;
  name: string;
  createdAt: number;
  updatedAt: number;
  note?: string;
  iocs: Record<string, CampaignIoc>;
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

export function loadCampaigns(): Record<string, Campaign> {
  try {
    const raw = localStorage.getItem(CAMPAIGNS_KEY);
    return raw ? (JSON.parse(raw) as Record<string, Campaign>) : {};
  } catch {
    return {};
  }
}
export function saveCampaigns(m: Record<string, Campaign>): void {
  try {
    const slim: Record<string, Campaign> = {};
    for (const [k, v] of Object.entries(m)) slim[k] = slimCampaign(v);
    localStorage.setItem(CAMPAIGNS_KEY, JSON.stringify(slim));
  } catch {
    /* storage full/disabled — in-memory campaigns still work */
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
  return {
    id: base.id,
    name: (newerB ? b?.name : a?.name) ?? base.name,
    createdAt: Math.min(a?.createdAt ?? Number.MAX_SAFE_INTEGER, b?.createdAt ?? Number.MAX_SAFE_INTEGER),
    updatedAt: Math.max(a?.updatedAt ?? 0, b?.updatedAt ?? 0),
    note: (newerB ? b?.note : a?.note) ?? base.note,
    iocs,
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
