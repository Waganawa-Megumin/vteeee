import type { MaxmindConfidenceFactor, MaxmindContext } from '@vteeee/shared';
import type { ProxyEnv } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

const DEFAULT_BASE = 'https://geoip.maxmind.com';
const DEFAULT_EDITION = 'insights';

/** ASCII → base64 (works in both Workers and Node without btoa/Buffer typings). */
function base64(input: string): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let out = '';
  for (let i = 0; i < input.length; i += 3) {
    const a = input.charCodeAt(i);
    const b = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    const c = i + 2 < input.length ? input.charCodeAt(i + 2) : 0;
    out += chars[a >> 2];
    out += chars[((a & 3) << 4) | (b >> 4)];
    out += i + 1 < input.length ? chars[((b & 15) << 2) | (c >> 6)] : '=';
    out += i + 2 < input.length ? chars[c & 63] : '=';
  }
  return out;
}

/** English localized name from a MaxMind `{names:{en:...}}` object. */
function enName(o: any): string | undefined {
  const n = o?.names?.en;
  return typeof n === 'string' && n ? n : undefined;
}
const str = (v: any): string | undefined => (typeof v === 'string' && v ? v : undefined);
const num = (v: any): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
const flag = (v: any): boolean | undefined => (v === true ? true : undefined);

/** Map a GeoIP2 City / Insights response to our context (pure, tolerant of missing fields). */
export function mapMaxmind(json: any): MaxmindContext {
  const ctx: MaxmindContext = { found: false };
  if (!json || typeof json !== 'object') return ctx;
  const loc = json.location ?? {};
  const traits = json.traits ?? {};
  const subs: any[] = Array.isArray(json.subdivisions) ? json.subdivisions : [];

  // --- Place names ---
  ctx.continent = enName(json.continent);
  ctx.continentCode = str(json.continent?.code);
  ctx.country = enName(json.country);
  ctx.countryCode = str(json.country?.iso_code);
  ctx.countryConfidence = num(json.country?.confidence);
  ctx.countryInEu = flag(json.country?.is_in_european_union);
  ctx.registeredCountry = enName(json.registered_country);
  ctx.registeredCountryCode = str(json.registered_country?.iso_code);
  ctx.registeredCountryInEu = flag(json.registered_country?.is_in_european_union);
  ctx.representedCountry = enName(json.represented_country);
  ctx.representedCountryCode = str(json.represented_country?.iso_code);
  const subNames = subs.map(enName).filter((s): s is string => Boolean(s));
  if (subNames.length) ctx.subdivisions = subNames;
  const mostSpecific = subs[subs.length - 1];
  ctx.subdivision = enName(mostSpecific);
  ctx.subdivisionCode = str(mostSpecific?.iso_code);
  ctx.city = enName(json.city);
  ctx.cityConfidence = num(json.city?.confidence);
  ctx.postal = str(json.postal?.code);
  ctx.postalConfidence = num(json.postal?.confidence);

  // --- Coordinates (approximate) ---
  ctx.latitude = num(loc.latitude);
  ctx.longitude = num(loc.longitude);
  ctx.accuracyRadius = num(loc.accuracy_radius);
  ctx.timeZone = str(loc.time_zone);
  ctx.averageIncome = num(loc.average_income);
  ctx.populationDensity = num(loc.population_density);

  // --- Network / operator ---
  ctx.network = str(traits.network);
  ctx.connectionType = str(traits.connection_type);
  ctx.mobileCountryCode = str(traits.mobile_country_code);
  ctx.mobileNetworkCode = str(traits.mobile_network_code);
  ctx.isp = str(traits.isp);
  ctx.organization = str(traits.organization);
  ctx.asn = num(traits.autonomous_system_number);
  ctx.asnOrganization = str(traits.autonomous_system_organization);
  ctx.domain = str(traits.domain);

  // --- Anonymizer / VPN (Anonymous Plus, in Insights) ---
  ctx.isAnonymous = flag(traits.is_anonymous ?? traits.is_anonymous_proxy);
  ctx.isAnonymousVpn = flag(traits.is_anonymous_vpn);
  ctx.isHostingProvider = flag(traits.is_hosting_provider);
  ctx.isPublicProxy = flag(traits.is_public_proxy);
  ctx.isResidentialProxy = flag(traits.is_residential_proxy);
  ctx.isTorExitNode = flag(traits.is_tor_exit_node);
  const anonTypes: string[] = [];
  if (ctx.isAnonymousVpn) anonTypes.push('VPN');
  if (ctx.isHostingProvider) anonTypes.push('Hosting');
  if (ctx.isPublicProxy) anonTypes.push('Public Proxy');
  if (ctx.isResidentialProxy) anonTypes.push('Residential Proxy');
  if (ctx.isTorExitNode) anonTypes.push('Tor');
  if (!anonTypes.length && flag(traits.is_anonymous_proxy)) anonTypes.push('Anonymous Proxy');
  if (anonTypes.length) ctx.anonymizerType = anonTypes;
  ctx.anonymizerConfidence = num(traits.anonymizer_confidence);
  ctx.providerName = str(traits.provider_name);
  ctx.networkLastSeen = str(traits.network_last_seen);

  // --- Risk / usage signals ---
  ctx.staticIpScore = num(traits.static_ip_score);
  ctx.ipRisk = num(traits.ip_risk ?? traits.user_risk);
  ctx.userCount = num(traits.user_count);
  ctx.userType = str(traits.user_type);
  const cf = traits.confidence_factors;
  if (Array.isArray(cf)) {
    const factors: MaxmindConfidenceFactor[] = cf
      .map((f: any) => ({ factor: str(f?.factor) ?? '', influence: num(f?.influence) }))
      .filter((f) => f.factor);
    if (factors.length) ctx.confidenceFactors = factors;
  }

  ctx.found = Boolean(
    ctx.country || ctx.city || ctx.latitude != null || ctx.network || ctx.asn != null || ctx.isp,
  );
  ctx.raw = json;
  return ctx;
}

function baseUrl(env: ProxyEnv): string {
  return (env.maxmindBaseUrl || DEFAULT_BASE).replace(/\/$/, '');
}

/** MaxMind GeoIP geolocation lookup for a single IP. Never throws. */
export async function maxmindLookup(
  ip: string,
  env: ProxyEnv,
  signal?: AbortSignal,
): Promise<MaxmindContext | undefined> {
  if (!env.maxmindAccountId || !env.maxmindLicenseKey) return undefined;
  if (signal?.aborted) return undefined;
  const edition = env.maxmindEdition || DEFAULT_EDITION;
  const url = `${baseUrl(env)}/geoip/v2.1/${edition}/${encodeURIComponent(ip)}`;
  const auth = `Basic ${base64(`${env.maxmindAccountId}:${env.maxmindLicenseKey}`)}`;
  let res: Response;
  try {
    res = await fetch(url, { headers: { authorization: auth, accept: 'application/json' }, signal });
  } catch (e) {
    if ((e as Error).name === 'AbortError') return undefined;
    return { found: false, error: `MaxMind unreachable: ${(e as Error).message}` };
  }
  if (res.status === 401) return { found: false, error: 'MaxMind 401 — invalid account ID / license key' };
  if (res.status === 402) return { found: false, error: 'MaxMind 402 — out of queries (credit exhausted)' };
  if (res.status === 429) return { found: false, error: 'MaxMind: rate limited' };
  let json: any;
  try {
    json = await res.json();
  } catch {
    return { found: false, error: `MaxMind error ${res.status}` };
  }
  if (!res.ok) {
    const code = typeof json?.code === 'string' ? json.code : '';
    // Reserved/private or not-in-DB IPs aren't errors — just no geolocation.
    if (code === 'IP_ADDRESS_NOT_FOUND' || code === 'IP_ADDRESS_RESERVED') return { found: false };
    return { found: false, error: json?.error ? `MaxMind: ${json.error}` : `MaxMind error ${res.status}` };
  }
  return mapMaxmind(json);
}
