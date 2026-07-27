import { checkToken, parseBearer } from '@vteeee/shared';
import type { ProxyEnv } from './types';

/** CORS headers for a given request origin against the allowlist. */
export function corsHeaders(origin: string | null, allowed: string[]): Record<string, string> {
  const ok = !!origin && (allowed.includes('*') || allowed.includes(origin));
  return {
    'Access-Control-Allow-Origin': ok ? origin! : allowed[0] ?? 'null',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Vteeee-User,X-Vteeee-Admin',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

export function originAllowed(origin: string | null, allowed: string[]): boolean {
  return !!origin && (allowed.includes('*') || allowed.includes(origin));
}

/** /api/* requires the shared access token. */
export function checkAccess(authHeader: string | null | undefined, env: ProxyEnv): boolean {
  // Fail CLOSED when no access token is configured: /api/* is denied unless the operator EXPLICITLY
  // opts into an open proxy via ALLOW_ANONYMOUS=true (e.g. local dev or an intentionally-public demo).
  // Previously this failed open, so a missing/empty ACCESS_TOKEN silently exposed the proxy + its keys.
  if (!env.accessToken) return env.allowAnonymous === true;
  return checkToken(parseBearer(authHeader), env.accessToken);
}

/** /api/admin/* writes require the admin token. */
export function checkAdmin(authHeader: string | null | undefined, env: ProxyEnv): boolean {
  return checkToken(parseBearer(authHeader), env.adminToken);
}

/** Check a raw token value (e.g. the X-Vteeee-Admin header) against the admin token. */
export function checkAdminToken(token: string | null | undefined, env: ProxyEnv): boolean {
  return checkToken(token ?? null, env.adminToken);
}
