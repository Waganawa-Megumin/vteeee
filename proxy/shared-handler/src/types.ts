/** Runtime-agnostic configuration assembled by each adapter (Node / Cloudflare). */
export interface ProxyEnv {
  vtApiKey: string;
  anthropicApiKey?: string;
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
