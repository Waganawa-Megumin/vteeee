/** Indicator types we recognize. `unknown` = could not be classified. */
export type IocType =
  | 'ipv4'
  | 'ipv6'
  | 'domain'
  | 'url'
  | 'md5'
  | 'sha1'
  | 'sha256'
  | 'unknown';

/** Types that can actually be enriched via VirusTotal. */
export type EnrichableType = Exclude<IocType, 'unknown'>;

export type ResultStatus = 'success' | 'not_found' | 'rate_limited' | 'error';

export type Verdict = 'malicious' | 'suspicious' | 'harmless' | 'undetected' | 'unknown';

export type ExcludeReason = 'private' | 'unknown' | 'duplicate' | null;

/** A single parsed/classified indicator from the input. */
export interface ParsedIndicator {
  /** Original raw token, as it appeared in the input. */
  input: string;
  /** Normalized / refanged value used for lookups. */
  value: string;
  type: IocType;
  /** RFC1918 / loopback / link-local / reserved / *.local etc. */
  private?: boolean;
  /** Why a token is excluded from enrichment by default (null = included). */
  excludedReason?: ExcludeReason;
  /** Confidence 0..1 (regex path = 1; Claude smart-parse may be lower). */
  confidence?: number;
}

export interface ExtractStats {
  total: number;
  unique: number;
  duplicates: number;
  unknown: number;
  private: number;
  enrichable: number;
}

export interface ExtractResult {
  indicators: ParsedIndicator[];
  stats: ExtractStats;
}

export interface DetectionStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout: number;
  total: number;
}

export interface GtiAssessment {
  /** e.g. VERDICT_MALICIOUS */
  verdict: string;
  /** e.g. SEVERITY_HIGH (may be absent for benign) */
  severity: string | null;
  /** 0..100 */
  threatScore: number | null;
}

/** The single shape the results table & detail panel consume, for all IOC types. */
export interface NormalizedResult {
  input: string;
  value: string;
  type: IocType;
  status: ResultStatus;
  errorMessage?: string;

  verdict: Verdict;
  detection: DetectionStats | null;
  reputation: number | null;
  totalVotes: { harmless: number; malicious: number } | null;
  lastAnalysisDate: string | null;
  tags: string[];

  gti?: GtiAssessment;

  ip?: { country?: string; asn?: number; asOwner?: string; network?: string; rir?: string };
  domain?: {
    registrar?: string;
    creationDate?: string;
    categories?: Record<string, string>;
    popularityRanks?: Record<string, { rank: number }>;
  };
  url?: { finalUrl?: string; title?: string; httpResponseCode?: number; categories?: Record<string, string> };
  file?: {
    md5?: string;
    sha1?: string;
    sha256?: string;
    size?: number;
    typeDescription?: string;
    meaningfulName?: string;
    threatLabel?: string;
    threatCategories?: string[];
  };

  links: { gui: string; apiId?: string };
  /** Full VT attributes for the detail panel (live mode; omitted in compact mode). */
  raw?: unknown;
}

export interface EnrichOptions {
  rpm?: number;
  concurrency?: number;
  includeRaw?: boolean;
  gti?: boolean;
  submitUnknown?: boolean;
}

export interface EnrichRequest {
  indicators: { value: string; type: EnrichableType; input: string }[];
  options?: EnrichOptions;
}

/** NDJSON stream events emitted by POST /api/enrich. */
export type EnrichEvent =
  | { event: 'progress'; done: number; total: number; inflight: number; rateLimitedUntil: number | null }
  | { event: 'result'; result: NormalizedResult }
  | { event: 'done'; done: number; total: number; elapsedMs: number }
  | { event: 'error'; message: string };

export interface ParseRequest {
  text: string;
  maxIndicators?: number;
}

export interface ParseResponse {
  indicators: ParsedIndicator[];
  model?: string;
  usage?: { input_tokens: number; output_tokens: number };
}

// ---- Auth / admin ----

export type Role = 'admin' | 'viewer';

export interface UserRecord {
  username: string;
  /** base64 PBKDF2 salt */
  salt: string;
  /** base64 PBKDF2 derived key (SHA-256, 256 bits) */
  hash: string;
  iterations: number;
  role: Role;
}

export interface UsersConfig {
  version: number;
  users: UserRecord[];
}

export interface AppSettings {
  /** When set, the app runs in Live mode against this proxy. */
  proxyBaseUrl: string | null;
  rpm: number;
  concurrency: number;
  gti: boolean;
  submitUnknown: boolean;
  /** Days to keep local search history (per browser). 0 = disabled. Default 30. */
  historyRetentionDays?: number;
  /** Documentation-only note shown in the admin UI. */
  allowedOriginsNote?: string;
  /**
   * Runtime-only secrets for talking to the proxy (stored in localStorage, never
   * in the committed baseline settings.json or in exports). On a static site these
   * are as exposed as the soft login gate; the real protection is keeping the
   * proxy URL + tokens off the public internet.
   */
  accessToken?: string | null;
  adminToken?: string | null;
}

export interface SettingsConfig {
  version: number;
  settings: AppSettings;
}

/** A signed-in session (stored client-side in sessionStorage). */
export interface Session {
  username: string;
  role: Role;
  token: string;
  /** epoch ms */
  expiresAt: number;
}
