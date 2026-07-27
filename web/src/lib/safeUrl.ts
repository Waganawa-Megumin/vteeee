// URL guards for values that originate in the SHARED store (captures/results) and get rendered as
// <img src> / <a href> / window.open. A poisoned entry (written via PUT /api/captures by any token
// holder) must not make an analyst's browser beacon an attacker host — that would leak their IP/UA/
// Referer and break vteeee's core OPSEC promise (the analyst's egress never touches investigated infra).

const URLSCAN_HOSTS = new Set(['urlscan.io', 'www.urlscan.io']);

/**
 * A urlscan asset URL (screenshot / result page) that's safe to fetch/render: https + a urlscan.io host.
 * Anything else (attacker host, javascript:, data:, http) → undefined, so the caller renders nothing.
 */
export function safeUrlscanAsset(raw: unknown): string | undefined {
  if (typeof raw !== 'string' || !raw) return undefined;
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' && URLSCAN_HOSTS.has(u.hostname) ? u.toString() : undefined;
  } catch {
    return undefined;
  }
}

/**
 * A general external link (provider portals, GUI deep-links): scheme-restricted to http/https only.
 * Blocks javascript:/data:/file: — closes the "trusted-looking label, hostile scheme" phishing surface.
 */
export function safeHttpUrl(raw: unknown): string | undefined {
  if (typeof raw !== 'string' || !raw) return undefined;
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : undefined;
  } catch {
    return undefined;
  }
}
