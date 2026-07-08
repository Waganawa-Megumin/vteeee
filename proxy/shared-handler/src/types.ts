/** Runtime-agnostic configuration assembled by each adapter (Node / Cloudflare). */
export interface ProxyEnv {
  vtApiKey: string;
  anthropicApiKey?: string;
  /** Shodan API key. When set, IP indicators are enriched with Shodan OSINT context. */
  shodanApiKey?: string;
  /** Per-minute cap on Shodan host lookups (free plan ≈ 1/s). Default 60. */
  shodanRpm?: number;
  /** MaxMind GeoIP account ID + license key (HTTP Basic auth). When both set, IPs get geolocation + map. */
  maxmindAccountId?: string;
  maxmindLicenseKey?: string;
  /** GeoIP web-service base URL. Default https://geoip.maxmind.com (paid). GeoLite2 = https://geolite.info. */
  maxmindBaseUrl?: string;
  /** Edition: `insights` (default — richest) / `city` / `country`. Needs a matching MaxMind license. */
  maxmindEdition?: string;
  /** Per-minute cap on MaxMind lookups. Default 60. */
  maxmindRpm?: number;
  /** DomainTools API username + key. When both set, domains use Iris Enrich and IPs use Iris Investigate (reverse). */
  domaintoolsApiUsername?: string;
  domaintoolsApiKey?: string;
  /** Per-minute cap on DomainTools lookups (Investigate is low-rate). Default 30. */
  domaintoolsRpm?: number;
  /** DNSLytics API key. When set, IPs use IPInfo and domains use DomainInfo. */
  dnslyticsApiKey?: string;
  /** DNSLytics API base URL. Default https://api.dnslytics.net/v1 (override if your endpoint differs). */
  dnslyticsBaseUrl?: string;
  /** Per-minute cap on DNSLytics lookups. Default 60. */
  dnslyticsRpm?: number;
  /** Intel 471 (Titan) BasicAuth: API email (login) + API key (password). */
  intel471ApiUser?: string;
  intel471ApiKey?: string;
  /** Intel 471 API base URL. Default https://api.intel471.com/v1. */
  intel471BaseUrl?: string;
  /** Per-minute cap on Intel 471 lookups. Default 60. */
  intel471Rpm?: number;
  /** CYFIRMA DeCYFIR API key (passed as the `key=` query param). When set, all IOC types get DeCYFIR context. */
  cyfirmaApiKey?: string;
  /** CYFIRMA DeCYFIR API base URL. Default https://decyfir.cyfirma.com/core/api-ua. */
  cyfirmaBaseUrl?: string;
  /** Per-minute cap on CYFIRMA lookups. Default 30. */
  cyfirmaRpm?: number;
  /** TeamT5 ThreatVision OAuth2 client credentials (exchanged for an access token). */
  threatvisionClientId?: string;
  threatvisionClientSecret?: string;
  /** Pre-obtained ThreatVision access token (alternative to client id/secret). */
  threatvisionAccessToken?: string;
  /** ThreatVision API base URL. Default https://api.threatvision.org. */
  threatvisionBaseUrl?: string;
  /** Per-minute cap on ThreatVision lookups. Default 30. NOTE: IP/domain detail cost 1 AAP each. */
  threatvisionRpm?: number;
  /** Recorded Future API token (sent as `X-RFToken`). Powers Connect enrichment + Threat/MalwareIntel/DetectionRule pivots. */
  recordedfutureApiKey?: string;
  /** Recorded Future API base URL. Default https://api.recordedfuture.com. */
  recordedfutureBaseUrl?: string;
  /** Per-minute cap on Recorded Future lookups. Default 30. */
  recordedfutureRpm?: number;
  /** SOC Prime (TDM) personal API key — sent as the `client_secret_id` header. Powers on-demand IOC → SIEM query generation. */
  socprimeApiKey?: string;
  /** SOC Prime API base URL. Default https://api.tdm.socprime.com. */
  socprimeBaseUrl?: string;
  /** Shared token required on /api/* (enrich, parse). */
  accessToken?: string;
  /** Token required to write users/settings via /api/admin/*. */
  adminToken?: string;
  /** Exact origins allowed by CORS (e.g. https://you.github.io, http://localhost:5173). */
  allowedOrigins: string[];
  defaultRpm: number;
  maxRpm: number;
  claudeModel?: string;
  /** Sent as the `x-tool` header so VT/GTI returns gti_assessment. */
  xTool?: string;
  /** Hard ceiling on indicators accepted in a single /api/enrich request. */
  maxBatch: number;
  /** Max VT lookups per day (0 = unlimited). Best-effort via the store. */
  dailyCap: number;
  /** Max Claude smart-parse calls per day (0 = unlimited). */
  parseDailyCap: number;
}

/** Minimal KV-like store for users/settings (Node file store or Cloudflare KV). */
export interface Storage {
  get(key: string): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
}

/** Bad API key / forbidden — abort the whole batch. */
export class FatalError extends Error {}

/** VT returned 429 — retry with backoff. */
export class RateLimitError extends Error {
  constructor(public retryAfterMs?: number) {
    super('rate limited');
  }
}
