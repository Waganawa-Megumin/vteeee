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

/** A single open service Shodan observed on the host. */
export interface ShodanService {
  port: number;
  /** 'tcp' | 'udp' */
  transport?: string;
  /** Detected product, e.g. 'nginx', 'OpenSSH'. */
  product?: string;
  version?: string;
  /** Shodan module / protocol, e.g. 'http', 'ssh'. */
  module?: string;
}

/**
 * Shodan host OSINT context (IP indicators only). `found: false` means the host
 * is not in Shodan's dataset, or the lookup was unavailable (see `error`).
 */
export interface ShodanContext {
  found: boolean;
  org?: string;
  isp?: string;
  os?: string;
  country?: string;
  city?: string;
  /** e.g. 'AS13335'. */
  asn?: string;
  hostnames?: string[];
  /** Open ports, ascending. */
  ports?: number[];
  /** Shodan tags, e.g. 'cdn', 'tor', 'self-signed'. */
  tags?: string[];
  /** Known CVEs across all services, e.g. ['CVE-2021-44228']. */
  vulns?: string[];
  services?: ShodanService[];
  /** ISO date Shodan last saw the host. */
  lastUpdate?: string;
  /** Set when the lookup itself failed (bad key / rate-limited / network). */
  error?: string;
}

/** One component of a DomainTools risk score (e.g. proximity, phishing, malware, spam). */
export interface DomainToolsRiskComponent {
  name: string;
  riskScore: number;
}

/**
 * DomainTools Iris context.
 * - `mode: 'enrich'` — forward lookup for a DOMAIN (Iris Enrich).
 * - `mode: 'reverse-ip'` — Iris Investigate reverse lookup for an IP (domains hosted on it).
 * `found: false` = not in the dataset / lookup unavailable (see `error`).
 */
export interface DomainToolsContext {
  found: boolean;
  mode: 'enrich' | 'reverse-ip';
  /** 0..100 overall risk (domain / representative). */
  riskScore?: number;
  riskComponents?: DomainToolsRiskComponent[];
  // --- domain (enrich) ---
  created?: string;
  firstSeen?: string;
  registrar?: string;
  ips?: string[];
  asns?: number[];
  nameServers?: string[];
  mailServers?: string[];
  sslIssuer?: string;
  sslNotAfter?: string;
  websiteResponse?: number;
  serverType?: string;
  websiteTitle?: string;
  tags?: string[];
  // --- reverse IP (investigate) ---
  /** Number of domains DomainTools sees hosted on this IP. */
  hostedDomainCount?: number;
  /** A sample of domains hosted on the IP, most-risky first. */
  sampleDomains?: { domain: string; riskScore?: number }[];
  /** Set when the lookup itself failed (bad key / rate-limited / network). */
  error?: string;
  /** Raw provider payload for the detail panel (never lost even if a field is unmapped). */
  raw?: unknown;
}

/**
 * DNSLytics context.
 * - `kind: 'ip'` — from the IPInfo endpoint.
 * - `kind: 'domain'` — from the DomainInfo endpoint.
 * `found: false` = not in the dataset / lookup unavailable (see `error`).
 */
export interface DnslyticsContext {
  found: boolean;
  kind: 'ip' | 'domain';
  // --- ip ---
  asn?: number;
  org?: string;
  isp?: string;
  network?: string;
  country?: string;
  city?: string;
  /** Reverse DNS / PTR host. */
  hostname?: string;
  /** Number of domains DNSLytics sees hosted on this IP. */
  domainsOnIp?: number;
  /** A sample of domains hosted on the IP (IPInfo returns a sample inline; no extra ReverseIP call needed). */
  hostedDomains?: string[];
  // --- domain (HostingHistory: current + past A/AAAA/MX/NS/SPF, most-recent first) ---
  /** A/AAAA addresses seen for the domain (recent first). */
  ips?: string[];
  nameServers?: string[];
  mailServers?: string[];
  /** SPF record strings seen for the domain. */
  spf?: string[];
  // --- shared ---
  tags?: string[];
  /** Threat / blocklist signal when the provider returns one. */
  threat?: string;
  error?: string;
  raw?: unknown;
}

/**
 * Intel 471 (Titan) IOC context — from `GET /iocs?ioc=&iocType=`. Applies to all IOC types
 * (IP / domain / URL / hash). `found: false` = no matching IOC record (or lookup failed).
 * Field mapping is tolerant + keeps `raw`, pending a populated sample response.
 */
export interface Intel471Context {
  found: boolean;
  /** iocTotalCount — how many IOC records Intel 471 has for this value. */
  totalCount?: number;
  /** Intel 471 IOC type as returned (e.g. "IPAddress", "MaliciousDomain"). */
  type?: string;
  activeFrom?: string;
  activeTill?: string;
  lastUpdated?: string;
  /** ISP name / country (present for IP IOCs). */
  isp?: string;
  ispCountryCode?: string;
  /** Counts of linked intel objects (links.*TotalCount). */
  reports?: number;
  actors?: number;
  malwareReports?: number;
  events?: number;
  /** Subjects of the top linked reports. */
  reportTitles?: string[];
  /** Portal URL of the top linked report (deep link into Titan). */
  portalUrl?: string;
  error?: string;
  raw?: unknown;
}

/**
 * Intel 471 Global Search cross-entity counts — from `GET /search?ioc=`. Fetched on demand
 * (a button in the detail panel), not during batch enrichment. Only non-zero counts are shown.
 */
export interface Intel471Search {
  reports?: number;
  malwareReports?: number;
  actors?: number;
  entities?: number;
  events?: number;
  posts?: number;
  news?: number;
  iocs?: number;
  indicators?: number;
  credentials?: number;
  credentialSets?: number;
  dataLeakPosts?: number;
  breachAlerts?: number;
  cveReports?: number;
  error?: string;
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
  /** VT `first_submission_date` — when VT first received this file/URL. null for IP/domain (VT has none). */
  firstSeen: string | null;
  /** VT `last_submission_date` — when VT last received this file/URL. */
  lastSeen: string | null;
  /** VT `times_submitted` — how many times this file/URL was submitted to VT. */
  timesSubmitted: number | null;
  /** VT `last_modification_date` — when VT last modified this record (all types). */
  lastModified: string | null;
  tags: string[];

  gti?: GtiAssessment;

  /** Shodan OSINT context (IP indicators only; present in live mode when a Shodan key is configured). */
  shodan?: ShodanContext;

  /** DomainTools Iris context (domains via Enrich; IPs via Investigate reverse lookup). */
  domaintools?: DomainToolsContext;

  /** DNSLytics context (IPs via IPInfo, domains via DomainInfo). */
  dnslytics?: DnslyticsContext;

  /** Intel 471 (Titan) IOC context — all IOC types. */
  intel471?: Intel471Context;

  ip?: {
    country?: string;
    asn?: number;
    asOwner?: string;
    network?: string;
    rir?: string;
    /** VT `whois_date` — when VT last fetched the WHOIS record. */
    whoisDate?: string;
  };
  domain?: {
    registrar?: string;
    creationDate?: string;
    categories?: Record<string, string>;
    popularityRanks?: Record<string, { rank: number }>;
    /** VT `last_dns_records_date` — when VT last retrieved the DNS records. */
    lastDnsRecordsDate?: string;
    /** VT `expiration_date` — domain registration expiry (WHOIS). */
    expiration?: string;
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
  /** Request Shodan OSINT on IPs (default true). Ignored if the proxy has no Shodan key. */
  shodan?: boolean;
  /** Request DomainTools Iris (domains + reverse-IP). Ignored if the proxy has no DomainTools key. */
  domaintools?: boolean;
  /** Request DNSLytics (IP + domain). Ignored if the proxy has no DNSLytics key. */
  dnslytics?: boolean;
  /** Request Intel 471 IOC lookups. Ignored if the proxy has no Intel 471 credentials. */
  intel471?: boolean;
}

/** What the proxy `GET /health` reports — which integrations are configured server-side. */
export interface ProxyHealth {
  ok: boolean;
  /** VirusTotal / GTI key present (base, required). */
  vtKey: boolean;
  /** Anthropic key present (optional — Claude smart-parse). */
  claude: boolean;
  /** Shodan key present (optional — IP OSINT). */
  shodan: boolean;
  /** DomainTools Iris credentials present (optional — domain/IP intel). */
  domaintools: boolean;
  /** DNSLytics key present (optional — IP/domain intel). */
  dnslytics: boolean;
  /** Intel 471 (Titan) credentials present (optional — IOC intel). */
  intel471: boolean;
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

export type Role = 'admin' | 'user';

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
  /** Request Shodan OSINT enrichment for IPs (default true; only used if the proxy has a Shodan key). */
  shodan?: boolean;
  /** Request DomainTools Iris enrichment (default true; only used if the proxy has DomainTools creds). */
  domaintools?: boolean;
  /** Request DNSLytics enrichment (default true; only used if the proxy has a DNSLytics key). */
  dnslytics?: boolean;
  /** Request Intel 471 IOC enrichment (default true; only used if the proxy has Intel 471 creds). */
  intel471?: boolean;
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

// ---- Search history ----

/** A saved search (local in demo mode, or shared via the proxy/KV in live mode). */
export interface HistoryRecord {
  id: string;
  createdAt: number; // epoch ms
  mode: 'demo' | 'live';
  input: string;
  stats: ExtractStats;
  /** Full results. In KV the raw VT attributes are kept; in localStorage they are stripped. */
  results: NormalizedResult[];
  tags?: string[];
  note?: string;
  /** Who ran it (login username, client-asserted) and the source IP (server-derived). */
  owner?: string;
  ip?: string;
}

/** Lightweight list item (stored as KV metadata; no need to fetch each record to list). */
export interface HistorySummary {
  id: string;
  createdAt: number;
  mode: 'demo' | 'live';
  total: number;
  malicious: number;
  suspicious: number;
  inputPreview: string;
  tags?: string[];
  note?: string;
  owner?: string;
  ip?: string;
}
