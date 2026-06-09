import { checkToken, parseBearer } from '@vteeee/shared';
import type { ProxyEnv } from './types';

/** CORS headers for a given request origin against the allowlist. */
export function corsHeaders(origin: string | null, allowed: string[]): Record<string, string> {
  const ok = !!origin && (allowed.includes('*') || allowed.includes(origin));
  return {
    'Access-Control-Allow-Origin': ok ? origin! : allowed[0] ?? 'null',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

export function originAllowed(origin: string | null, allowed: string[]): boolean {
  return !!origin && (allowed.includes('*') || allowed.includes(origin));
}

/** /api/* requires the shared access token. */
export function checkAccess(authHeader: string | null | undefined, env: ProxyEnv): boolean {
  // If no access token is configured, the proxy is open (discouraged; document it).
  if (!env.accessToken) return true;
  return checkToken(parseBearer(authHeader), env.accessToken);
}

/** /api/admin/* writes require the admin token. */
export function checkAdmin(authHeader: string | null | undefined, env: ProxyEnv): boolean {
  return checkToken(parseBearer(authHeader), env.adminToken);
}
