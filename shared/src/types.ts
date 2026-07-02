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
  activeFrom?: string;
  activeTill?: string;
  lastUpdated?: string;

  // --- Malware Intelligence (/indicators) ---
  /** Number of matching indicators. */
  indicatorCount?: number;
  /** Malware family (threat.data.family), e.g. "orcus", "redline". */
  malwareFamily?: string;
  /** Malware family profile UID (threat.data.malware_family_profile_uid) → Titan /malware/{uid}. */
  malwareFamilyUid?: string;
  /** Confidence: high / medium / low. */
  confidence?: string;
  /** Threat type (threat.type), e.g. "malware". */
  threatType?: string;
  /** Human context (context.description), e.g. "redline controller URL". */
  context?: string;
  /** MITRE tactic (mitre_tactics), e.g. "command_and_control". */
  mitreTactics?: string;
  /** General Intel Requirements (intel_requirements). */
  girs?: string[];

  // --- Adversary IOC feed (/iocs) ---
  /** iocTotalCount — how many IOC records Intel 471 has for this value. */
  totalCount?: number;
  /** Intel 471 IOC type as returned (e.g. "IPAddress", "MaliciousDomain"). */
  type?: string;
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

/** A single top result within a Global Search category (for drill-down). */
export interface Intel471SearchItem {
  /** Short human title (report subject, actor handle, post snippet, IOC value, …). */
  title: string;
  /** Deep link into the Titan portal, when the item exposes one. */
  url?: string;
}

/**
 * Intel 471 Global Search — from `GET /search?text=&count=5`. Fetched on demand (a button in the
 * detail panel). Returns cross-entity counts plus the top items per category so each hit can be
 * expanded to show details (and deep-linked into Titan). Only non-zero counts are shown.
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
  /** Top items per category (same /search call), keyed by the response array name. */
  items?: {
    reports?: Intel471SearchItem[];
    malwareReports?: Intel471SearchItem[];
    actors?: Intel471SearchItem[];
    entities?: Intel471SearchItem[];
    events?: Intel471SearchItem[];
    posts?: Intel471SearchItem[];
    news?: Intel471SearchItem[];
    iocs?: Intel471SearchItem[];
    indicators?: Intel471SearchItem[];
    credentials?: Intel471SearchItem[];
    cveReports?: Intel471SearchItem[];
  };
  error?: string;
}

/**
 * Intel 471 malware family details — fetched on demand (by clicking the malware-family chip in the
 * detail panel) from `GET /malwareFamilies` (profile: aka/summary) + `GET /malwareReports?
 * malwareFamilyProfileUid=` (recent analysis reports). Mirrors CYFIRMA's actor deep-dive.
 */
export interface Intel471Malware {
  family?: string;
  uid?: string;
  /** aka / alias names for the family. */
  aka?: string[];
  /** Free-text overview/summary from the family profile, when present. */
  summary?: string;
  /** Recent malware-report subjects (titles) for this family. */
  reports?: string[];
  /** Total malware reports Intel 471 has for the family. */
  reportCount?: number;
  /** MITRE ATT&CK tactics seen across the family's reports/profile. */
  mitreTactics?: string[];
  /** General Intel Requirements referenced by the reports. */
  girs?: string[];
  /** Activity window across the family's reports. */
  activeFrom?: string;
  activeTill?: string;
  /** Deep link to the Titan malware profile page. */
  portalUrl?: string;
  error?: string;
  raw?: unknown;
}

/**
 * Correlated infrastructure / victim attributes CYFIRMA links to an indicator
 * (from the Risk Dossier `iocAttribute`). Samples, not exhaustive lists — these are
 * the "attack-infrastructure side" pivots (related hosts) and target-side signals (emails/CVEs).
 */
export interface CyfirmaRelated {
  ips?: string[];
  domains?: string[];
  hostnames?: string[];
  urls?: string[];
  hashes?: string[];
  emails?: string[];
  cves?: string[];
  exploits?: string[];
}

/**
 * CYFIRMA DeCYFIR context — merged from the Risk Dossier (`/riskdossier`) and the STIX 2.1
 * IOC search (`/threatioc/stix/v2.1/search`). Applies to all IOC types. `found: false` = no
 * DeCYFIR record (or lookup failed). Mapping is tolerant + keeps `raw` (no live egress to verify).
 */
export interface CyfirmaContext {
  found: boolean;

  // --- Risk Dossier: organisation-level scores (0–10 scale) ---
  /** riskViewScores.riskScore — your organisation's risk from this indicator (0–10). */
  riskScore?: number;
  /** riskViewScores.externalThreatScore — external threat level (0–10). */
  externalThreatScore?: number;
  /** UP / DOWN / EQUAL. */
  riskScoreTrend?: string;
  externalThreatScoreTrend?: string;

  // --- Risk Dossier: per-indicator detail ---
  /** riskDossierDetails[].type, e.g. "IP ADDRESS", "DOMAIN". */
  indicatorType?: string;
  /** riskDossierDetails[].riskScore for this specific indicator (0–10). */
  indicatorRiskScore?: number;
  /** Narrative (HTML stripped). */
  story?: string;
  /** Impact statement. */
  impact?: string;
  /** Recommended action, e.g. "Block the IP address." */
  action?: string;
  /** details.* (infrastructure ownership). */
  asn?: string;
  asnOwner?: string;
  organization?: string;
  country?: string;
  /** Correlated infrastructure / victim attributes (attack-infra + target side). */
  related?: CyfirmaRelated;
  /** Total related attributes across every bucket (for a quick "N linked" chip). */
  relatedCount?: number;

  // --- STIX 2.1 IOC search: attribution ---
  /** Associated threat actors / intrusion sets (by name). */
  threatActors?: string[];
  /** Associated campaigns (by name). */
  campaigns?: string[];
  /** Associated malware families (by name). */
  malware?: string[];
  /** STIX indicator name, e.g. "Poison Ivy Malware". */
  indicatorName?: string;
  /** STIX indicator description. */
  description?: string;

  error?: string;
  raw?: unknown;
}

/**
 * CYFIRMA Threat-Actor deep-dive — from `GET /threatactor/stix/v2.1?name=`. Fetched on demand
 * (a button in the detail panel) to pivot from an indicator's attributed actor into that actor's
 * campaigns, malware and targeted CVEs (attack-infra + target-side view).
 */
export interface CyfirmaSearch {
  /** Resolved actor name/title. */
  actor?: string;
  aliases?: string[];
  description?: string;
  /** primary_motivation, e.g. "Espionage". */
  motivation?: string;
  campaigns?: string[];
  malware?: string[];
  /** CVEs the actor is seen targeting. */
  vulnerabilities?: string[];
  /** Sample of related IOCs surfaced in the actor bundle. */
  relatedIocs?: string[];
  error?: string;
}

/**
 * TeamT5 ThreatVision context — APT-attribution-focused CTI. Per-IOC:
 * - `kind: 'ip'` / `'domain'` — from the network detail endpoint (risk + adversaries + attributes).
 * - `kind: 'sample'` — from the samples search (0 AAP; risk + adversary + malware-family attribution).
 * `found: false` = not in ThreatVision / not yet analyzed (see `error`).
 */
export interface ThreatVisionContext {
  found: boolean;
  kind: 'ip' | 'domain' | 'sample';
  /** high / medium / low. */
  riskLevel?: string;
  /** 0..100. */
  riskScore?: number;
  /** Risk type codes, e.g. ["ce"]. */
  riskTypes?: string[];
  /** Attributed APT / adversary groups (TeamT5's differentiator). */
  adversaries?: string[];
  /** Malware families (samples). */
  malwareFamilies?: string[];
  /** Behavioural attributes / sharing tags for IP·domain, e.g. "Malware C2", "Hosting". */
  attributes?: string[];
  // --- ip ---
  country?: string;
  city?: string;
  region?: string;
  // --- domain ---
  registrar?: string;
  // --- sample ---
  md5?: string;
  sha256?: string;
  firstSeen?: string;
  size?: number;
  hasNetworkActivity?: boolean;
  // --- summary counts (ip/domain) ---
  relatedReports?: number;
  relatedSamples?: number;
  relatedAdversaries?: number;
  dnsRecords?: number;
  osint?: number;
  /** ISO 8601 last-updated for the IP/domain record. */
  lastUpdate?: string;
  error?: string;
  raw?: unknown;
}

/**
 * TeamT5 ThreatVision adversary (APT group) profile — fetched on demand by clicking an adversary
 * chip in the detail panel. Origin + targeting is the "attack-infra / target-side" pivot.
 */
export interface ThreatVisionAdversary {
  name?: string;
  aliases?: string[];
  originCountries?: string[];
  targetedCountries?: string[];
  targetedIndustries?: string[];
  overview?: string;
  error?: string;
}

/** Options for SOC Prime Uncoder AI IOC → SIEM query generation. */
export interface SocPrimeQueryOptions {
  /** Target SIEM/query format (Uncoder `siem_type`), e.g. `splunk`, `ala`, `qradar`. */
  siemType: string;
  /** IOCs per generated query (25–300). Default 25. */
  iocsPerQuery?: number;
  /** Also match source IPs (in addition to destination). */
  includeSourceIp?: boolean;
  /** Restrict to these IOC types: domain / url / hash / ip. */
  includeIocTypes?: string[];
}

/**
 * Result of SOC Prime Uncoder AI IOC → query generation (`POST /v1/uncoder/ioc/generate-query`).
 * Generated hunting query(ies) for the requested SIEM format. Fetched on demand (a results-toolbar
 * action), not during enrichment. Response shape is mapped defensively + `raw` is kept.
 */
export interface SocPrimeQueryResult {
  /** One or more generated query strings (usually one; more if IOCs exceed `iocsPerQuery`). */
  queries?: string[];
  /** Total IOCs SOC Prime used to build the query, when reported. */
  iocCount?: number;
  error?: string;
  raw?: unknown;
}

/** Filters for SOC Prime detection-rule search (`GET /v1/search-sigmas`). */
export interface SocPrimeRuleSearchParams {
  /** Target platform for the returned translation (client_siem_type), e.g. `splunk`, `ala`. */
  siemType: string;
  /** Free-text / Lucene query over rule name, description, body, tags (client_query_string). */
  query?: string;
  /** ATT&CK group / adversary name (client_tags_actor). */
  actor?: string;
  /** ATT&CK tool or malware name (client_tags_tool). */
  tool?: string;
  /** ATT&CK technique ID, e.g. T1055 (tags_technique_id). */
  techniqueId?: string;
  /** Severity: low / medium / high / critical (sigma_level). */
  sigmaLevel?: string;
  /** Sigma type: "IOC Sigma" / "Threat Hunting Sigma" / "Compliance" (client_sigma_type). */
  sigmaType?: string;
  /** Results per page (max 50). */
  pageSize?: number;
  /** 1-based page number. */
  pageNumber?: number;
}

/** One SOC Prime Sigma detection rule (from rule search), mapped defensively. */
export interface SocPrimeRule {
  id?: string;
  name?: string;
  description?: string;
  /** sigma.level — low / medium / high / critical. */
  level?: string;
  /** sigma.status — stable / test / experimental. */
  status?: string;
  author?: string;
  /** MITRE ATT&CK technique IDs/names. */
  techniques?: string[];
  /** MITRE ATT&CK tactics. */
  tactics?: string[];
  /** Attributed ATT&CK groups / adversaries. */
  actors?: string[];
  /** The rule translated into the requested SIEM format. */
  translation?: string;
  /** Deep link to the rule on the SOC Prime platform, when derivable. */
  url?: string;
}

/**
 * SOC Prime detection-rule search result (`GET /v1/search-sigmas`). Fetched on demand from the
 * "Detection rules" dialog. Response shape is mapped defensively + `raw` is kept.
 */
export interface SocPrimeRuleSearchResult {
  rules?: SocPrimeRule[];
  total?: number;
  error?: string;
  raw?: unknown;
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

  /** CYFIRMA DeCYFIR context (Risk Dossier + STIX 2.1 search) — all IOC types. */
  cyfirma?: CyfirmaContext;

  /** TeamT5 ThreatVision context (IP/domain detail, or sample attribution) — all IOC types. */
  threatvision?: ThreatVisionContext;

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
  /** Request CYFIRMA DeCYFIR lookups. Ignored if the proxy has no CYFIRMA key. */
  cyfirma?: boolean;
  /** Request TeamT5 ThreatVision lookups. Ignored if the proxy has no ThreatVision credentials. */
  threatvision?: boolean;
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
  /** CYFIRMA DeCYFIR key present (optional — risk dossier + STIX attribution). */
  cyfirma: boolean;
  /** TeamT5 ThreatVision credentials present (optional — APT attribution CTI). */
  threatvision: boolean;
  /** SOC Prime (TDM) API key present (optional — Uncoder AI IOC → SIEM query generation). */
  socprime: boolean;
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
  /** Request CYFIRMA DeCYFIR enrichment (default true; only used if the proxy has a CYFIRMA key). */
  cyfirma?: boolean;
  /** Request TeamT5 ThreatVision enrichment (default true; only used if the proxy has ThreatVision creds). */
  threatvision?: boolean;
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
