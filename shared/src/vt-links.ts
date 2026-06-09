import type { EnrichableType, IocType } from './types';

const GUI = 'https://www.virustotal.com/gui';
const API = 'https://www.virustotal.com/api/v3';

/** url-safe base64 (no padding), UTF-8 safe. This is the id for GET /api/v3/urls/{id}. */
export function urlApiId(url: string): string {
  const bytes = new TextEncoder().encode(url);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Lowercase hex SHA-256 of a string. The GUI uses this as the /gui/url/{id}. */
export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Build the VirusTotal GUI deep-link for an indicator. For URLs, pass the SHA-256. */
export function guiLink(type: IocType, value: string, urlSha?: string): string {
  switch (type) {
    case 'ipv4':
    case 'ipv6':
      return `${GUI}/ip-address/${encodeURIComponent(value)}`;
    case 'domain':
      return `${GUI}/domain/${encodeURIComponent(value)}`;
    case 'url':
      return urlSha ? `${GUI}/url/${urlSha}` : `${GUI}/search?query=${encodeURIComponent(value)}`;
    case 'md5':
    case 'sha1':
    case 'sha256':
      return `${GUI}/file/${value}`;
    default:
      return `${GUI}/search?query=${encodeURIComponent(value)}`;
  }
}

/** Build the VirusTotal API v3 path (without base) for a GET lookup. */
export function apiPath(type: EnrichableType, value: string): string {
  switch (type) {
    case 'ipv4':
    case 'ipv6':
      return `${API}/ip_addresses/${encodeURIComponent(value)}`;
    case 'domain':
      return `${API}/domains/${encodeURIComponent(value)}`;
    case 'url':
      return `${API}/urls/${urlApiId(value)}`;
    case 'md5':
    case 'sha1':
    case 'sha256':
      return `${API}/files/${value}`;
  }
}

/** Resolve both links (GUI + API id) for a result. Async because URL GUI links need a SHA-256. */
export async function buildLinks(
  type: IocType,
  value: string,
): Promise<{ gui: string; apiId?: string }> {
  if (type === 'url') {
    const sha = await sha256Hex(value);
    return { gui: guiLink('url', value, sha), apiId: urlApiId(value) };
  }
  return { gui: guiLink(type, value) };
}
