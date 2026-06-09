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
  /** Optional daily-quota guard; returns false when exhausted. */
  consumeQuota?: () => boolean;
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
