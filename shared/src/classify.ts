import type { IocType } from './types';
import { refang, stripToken } from './defang';

const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const MD5_RE = /^[a-f0-9]{32}$/i;
const SHA1_RE = /^[a-f0-9]{40}$/i;
const SHA256_RE = /^[a-f0-9]{64}$/i;
const DOMAIN_RE = /^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$/i;
const EMAIL_RE = /^[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,63}$/i;

// Comprehensive IPv6 matcher (covers ::, embedded IPv4, fe80 zone id).
const IPV6_RE =
  /^(([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:)|fe80:(:[0-9a-f]{0,4}){0,4}%[0-9a-z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-f]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/i;

export interface Classification {
  type: IocType;
  value: string;
  isPrivate: boolean;
}

/** Convert a (possibly internationalized) host to its ASCII/punycode form, lowercased. */
export function toPunycodeHost(host: string): string {
  if (/^[\x00-\x7f]*$/.test(host)) return host.toLowerCase();
  try {
    return new URL('http://' + host).hostname;
  } catch {
    return host.toLowerCase();
  }
}

function isPrivateIpv4(ip: string): boolean {
  const o = ip.split('.').map(Number);
  if (o.length !== 4 || o.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const [a, b] = o;
  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127) || // CGNAT
    a >= 224 // multicast / reserved
  );
}

function isPrivateIpv6(ip: string): boolean {
  const v = ip.toLowerCase();
  return (
    v === '::1' ||
    v === '::' ||
    v.startsWith('fc') ||
    v.startsWith('fd') || // unique local fc00::/7
    v.startsWith('fe80') || // link local
    v.startsWith('::ffff:') // IPv4-mapped (often internal)
  );
}

function isPrivateHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (h === 'localhost') return true;
  return /\.(local|internal|localhost|lan|home|corp|intranet|test|example|invalid)$/.test(h);
}

/** Lowercase scheme + host of a URL, punycode the host, preserve path/query/fragment verbatim. */
function normalizeUrl(u: string): { value: string; host: string } {
  const m = u.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)([/?#].*)?$/);
  if (!m) return { value: u, host: '' };
  const scheme = m[1].toLowerCase();
  const authority = m[2];
  const rest = m[3] ?? '';
  const at = authority.lastIndexOf('@');
  const userinfo = at >= 0 ? authority.slice(0, at + 1) : '';
  const hostport = at >= 0 ? authority.slice(at + 1) : authority;
  const pm = hostport.match(/^(\[[^\]]+\]|[^:]+)(:\d+)?$/);
  const rawHost = pm ? pm[1] : hostport;
  const port = pm && pm[2] ? pm[2] : '';
  const host = rawHost.startsWith('[') ? rawHost.toLowerCase() : toPunycodeHost(rawHost);
  return { value: `${scheme}://${userinfo}${host}${port}${rest}`, host };
}

function classifyUrl(u: string): Classification {
  const { value, host } = normalizeUrl(u);
  const bare = host.replace(/^\[|\]$/g, '');
  const isPrivate = IPV4_RE.test(bare)
    ? isPrivateIpv4(bare)
    : IPV6_RE.test(bare)
      ? isPrivateIpv6(bare)
      : isPrivateHost(bare);
  return { type: 'url', value, isPrivate };
}

/**
 * Classify a single token (already line-refanged) into an indicator type and
 * its normalized value. The token is stripped of wrappers/trailing punctuation first.
 */
export function classify(raw: string): Classification {
  // Refang first so single defanged tokens (e.g. "evil[.]com", "1[.]1[.]1[.]1")
  // classify correctly even when called directly (not via extract()).
  const trimmed = refang(raw).trim();
  if (!trimmed) return { type: 'unknown', value: '', isPrivate: false };

  // Bracketed IPv6, optionally with a port: [::1]  or  [2001:db8::1]:443
  // (checked before stripToken, which would remove the surrounding brackets).
  const v6b = trimmed.match(/^\[([0-9a-f:.]+)\](?::\d+)?$/i);
  if (v6b && IPV6_RE.test(v6b[1])) {
    const v = v6b[1].toLowerCase();
    return { type: 'ipv6', value: v, isPrivate: isPrivateIpv6(v) };
  }

  const t = stripToken(trimmed);
  if (!t) return { type: 'unknown', value: '', isPrivate: false };

  // URL with an explicit scheme.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) return classifyUrl(t);

  // Email -> unknown (VirusTotal does not enrich raw email addresses).
  if (EMAIL_RE.test(t)) return { type: 'unknown', value: t.toLowerCase(), isPrivate: false };

  // Schemeless URL: host followed by a non-empty path / query / fragment.
  const pathIdx = t.search(/[/?#]/);
  if (pathIdx > 0) {
    const hostport = t.slice(0, pathIdx);
    const rest = t.slice(pathIdx);
    const host = hostport.split(':')[0];
    if (DOMAIN_RE.test(host) || IPV4_RE.test(host)) {
      if (rest === '/') {
        // Bare host with a trailing slash -> treat as the host itself.
        return classifyBareHost(host);
      }
      return classifyUrl('http://' + t);
    }
  }

  // IPv6 (checked before stripping :port, since v6 addresses contain colons).
  if (IPV6_RE.test(t)) {
    const v = t.toLowerCase();
    return { type: 'ipv6', value: v, isPrivate: isPrivateIpv6(v) };
  }

  // Strip a trailing :port and trailing dot for host/ip/hash classification.
  const bare = t.replace(/:\d+$/, '').replace(/\.$/, '');
  return classifyBareHost(bare);
}

function classifyBareHost(t: string): Classification {
  if (IPV4_RE.test(t)) return { type: 'ipv4', value: t, isPrivate: isPrivateIpv4(t) };
  if (IPV6_RE.test(t)) {
    const v = t.toLowerCase();
    return { type: 'ipv6', value: v, isPrivate: isPrivateIpv6(v) };
  }
  if (SHA256_RE.test(t)) return { type: 'sha256', value: t.toLowerCase(), isPrivate: false };
  if (SHA1_RE.test(t)) return { type: 'sha1', value: t.toLowerCase(), isPrivate: false };
  if (MD5_RE.test(t)) return { type: 'md5', value: t.toLowerCase(), isPrivate: false };

  const host = toPunycodeHost(t);
  if (DOMAIN_RE.test(host)) {
    return { type: 'domain', value: host, isPrivate: isPrivateHost(host) };
  }
  return { type: 'unknown', value: t, isPrivate: false };
}
