import type {
  DetectionStats,
  GtiAssessment,
  IocType,
  NormalizedResult,
  ResultStatus,
  Verdict,
} from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

function toStats(s: any): DetectionStats | null {
  if (!s || typeof s !== 'object') return null;
  const malicious = s.malicious ?? 0;
  const suspicious = s.suspicious ?? 0;
  const harmless = s.harmless ?? 0;
  const undetected = s.undetected ?? 0;
  const timeout = s.timeout ?? 0;
  const total = malicious + suspicious + harmless + undetected + timeout;
  return { malicious, suspicious, harmless, undetected, timeout, total };
}

function toGti(g: any): GtiAssessment | undefined {
  if (!g || typeof g !== 'object') return undefined;
  const verdict = g.verdict?.value;
  if (!verdict) return undefined;
  return {
    verdict,
    severity: g.severity?.value ?? null,
    threatScore: typeof g.threat_score?.value === 'number' ? g.threat_score.value : null,
  };
}

/** Unified verdict: GTI assessment wins, otherwise derive from analysis stats. */
export function deriveVerdict(stats: DetectionStats | null, gti?: GtiAssessment): Verdict {
  if (gti) {
    switch (gti.verdict) {
      case 'VERDICT_MALICIOUS':
        return 'malicious';
      case 'VERDICT_SUSPICIOUS':
        return 'suspicious';
      case 'VERDICT_BENIGN':
        return 'harmless';
      case 'VERDICT_UNDETECTED':
        return 'undetected';
    }
  }
  if (!stats) return 'unknown';
  if (stats.malicious > 0) return 'malicious';
  if (stats.suspicious > 0) return 'suspicious';
  if (stats.harmless > 0) return 'harmless';
  if (stats.undetected > 0) return 'undetected';
  return 'unknown';
}

function isoDate(epochSeconds: unknown): string | null {
  if (typeof epochSeconds !== 'number') return null;
  return new Date(epochSeconds * 1000).toISOString();
}

export interface NormalizeInput {
  input: string;
  value: string;
  type: IocType;
  /** The VT `data` object (with `.attributes`), or undefined for not_found/error. */
  data?: any;
  status: ResultStatus;
  links: { gui: string; apiId?: string };
  includeRaw?: boolean;
  errorMessage?: string;
}

/** Convert a raw VirusTotal v3 object into the unified NormalizedResult shape. */
export function normalizeVt(inp: NormalizeInput): NormalizedResult {
  const { input, value, type, status, links } = inp;
  const attr = inp.data?.attributes;

  const base: NormalizedResult = {
    input,
    value,
    type,
    status,
    errorMessage: inp.errorMessage,
    verdict: 'unknown',
    detection: null,
    reputation: null,
    totalVotes: null,
    lastAnalysisDate: null,
    firstSeen: null,
    lastSeen: null,
    timesSubmitted: null,
    tags: [],
    links,
  };

  if (status !== 'success' || !attr) {
    return base;
  }

  const detection = toStats(attr.last_analysis_stats);
  const gti = toGti(attr.gti_assessment);

  const result: NormalizedResult = {
    ...base,
    verdict: deriveVerdict(detection, gti),
    detection,
    reputation: typeof attr.reputation === 'number' ? attr.reputation : null,
    totalVotes: attr.total_votes
      ? { harmless: attr.total_votes.harmless ?? 0, malicious: attr.total_votes.malicious ?? 0 }
      : null,
    lastAnalysisDate: isoDate(attr.last_analysis_date),
    // first/last_submission_date are present on VT file & URL objects (not IP/domain).
    firstSeen: isoDate(attr.first_submission_date),
    lastSeen: isoDate(attr.last_submission_date),
    timesSubmitted: typeof attr.times_submitted === 'number' ? attr.times_submitted : null,
    tags: Array.isArray(attr.tags) ? attr.tags : [],
    gti,
    raw: inp.includeRaw ? attr : undefined,
  };

  if (type === 'ipv4' || type === 'ipv6') {
    result.ip = {
      country: attr.country,
      asn: attr.asn,
      asOwner: attr.as_owner,
      network: attr.network,
      rir: attr.regional_internet_registry,
    };
  } else if (type === 'domain') {
    result.domain = {
      registrar: attr.registrar,
      creationDate: isoDate(attr.creation_date) ?? undefined,
      categories: attr.categories,
      popularityRanks: attr.popularity_ranks,
    };
  } else if (type === 'url') {
    result.url = {
      finalUrl: attr.last_final_url,
      title: attr.title,
      httpResponseCode: attr.last_http_response_code,
      categories: attr.categories,
    };
  } else {
    // file hash
    const ptc = attr.popular_threat_classification;
    result.file = {
      md5: attr.md5,
      sha1: attr.sha1,
      sha256: attr.sha256,
      size: attr.size,
      typeDescription: attr.type_description,
      meaningfulName: attr.meaningful_name,
      threatLabel: ptc?.suggested_threat_label,
      threatCategories: Array.isArray(ptc?.popular_threat_category)
        ? ptc.popular_threat_category.map((c: any) => c.value).filter(Boolean)
        : undefined,
    };
  }

  return result;
}
