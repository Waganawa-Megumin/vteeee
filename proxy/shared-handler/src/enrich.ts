import {
  buildLinks,
  normalizeVt,
  type CyfirmaContext,
  type DnslyticsContext,
  type DomainToolsContext,
  type EnrichEvent,
  type EnrichRequest,
  type Intel471Context,
  type MaxmindContext,
  type NormalizedResult,
  type ResultStatus,
  type ShodanContext,
  type ThreatVisionContext,
} from '@vteeee/shared';
import { FatalError, RateLimitError, type ProxyEnv } from './types';
import { RateLimiter } from './rateLimiter';
import { vtLookup } from './vtFetch';
import { shodanHostLookup } from './shodanFetch';
import { maxmindLookup } from './maxmindFetch';
import { domaintoolsEnrichDomain, domaintoolsReverseIp } from './domaintoolsFetch';
import { dnslyticsHostingHistory, dnslyticsIpInfo } from './dnslyticsFetch';
import { intel471Lookup } from './intel471Fetch';
import { cyfirmaLookup } from './cyfirmaFetch';
import { threatvisionLookup } from './threatvisionFetch';
import { AsyncQueue, backoffMs, clamp, sleep } from './util';

const MAX_RL_RETRIES = 3;
const MAX_TRANSIENT_RETRIES = 2;
const DEFAULT_SHODAN_RPM = 60;
const DEFAULT_MAXMIND_RPM = 60;
const DEFAULT_DOMAINTOOLS_RPM = 30;
const DEFAULT_DNSLYTICS_RPM = 60;
const DEFAULT_INTEL471_RPM = 60;
const DEFAULT_CYFIRMA_RPM = 30;
const DEFAULT_THREATVISION_RPM = 30;

/** Hostname from a URL indicator (for treating a URL's host as a domain). null if not parseable. */
function hostFromUrl(u: string): string | null {
  try {
    return new URL(u).hostname || null;
  } catch {
    return null;
  }
}

/** True if `host` is an IPv4/IPv6 literal (so domain-only enrichers should skip it). */
function isIpLiteral(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

interface LookupOutcome {
  status: ResultStatus;
  data?: { attributes?: Record<string, unknown> };
  errorMessage?: string;
}

/** Stream enrichment results as NDJSON events. Drives a worker pool under one rate limiter. */
export async function* runEnrich(
  req: EnrichRequest,
  env: ProxyEnv,
  signal?: AbortSignal,
): AsyncGenerator<EnrichEvent> {
  const rpm = clamp(req.options?.rpm ?? env.defaultRpm, 1, env.maxRpm);
  const concurrency = clamp(req.options?.concurrency ?? 1, 1, 20);
  const includeRaw = req.options?.includeRaw ?? true;
  const limiter = new RateLimiter(rpm);
  // Shodan has its own quota/rate budget, so it runs under a separate limiter.
  // Gated by both the server key and the client's opt-out (options.shodan === false).
  const shodanEnabled = Boolean(env.shodanApiKey) && req.options?.shodan !== false;
  const shodanLimiter = shodanEnabled
    ? new RateLimiter(clamp(env.shodanRpm ?? DEFAULT_SHODAN_RPM, 1, 600))
    : null;
  // MaxMind GeoIP geolocation (IPs) under its own limiter.
  const maxmindEnabled =
    Boolean(env.maxmindAccountId && env.maxmindLicenseKey) && req.options?.maxmind !== false;
  const maxmindLimiter = maxmindEnabled
    ? new RateLimiter(clamp(env.maxmindRpm ?? DEFAULT_MAXMIND_RPM, 1, 600))
    : null;
  // DomainTools (domains → Iris Enrich, IPs → Iris Investigate reverse) under its own limiter.
  const dtEnabled =
    Boolean(env.domaintoolsApiUsername && env.domaintoolsApiKey) && req.options?.domaintools !== false;
  const dtLimiter = dtEnabled
    ? new RateLimiter(clamp(env.domaintoolsRpm ?? DEFAULT_DOMAINTOOLS_RPM, 1, 600))
    : null;
  // DNSLytics (IPs → IPInfo, domains → DomainInfo) under its own limiter.
  const dnslEnabled = Boolean(env.dnslyticsApiKey) && req.options?.dnslytics !== false;
  const dnslLimiter = dnslEnabled
    ? new RateLimiter(clamp(env.dnslyticsRpm ?? DEFAULT_DNSLYTICS_RPM, 1, 600))
    : null;
  // Intel 471 IOC lookups (all IOC types) under its own limiter.
  const i471Enabled =
    Boolean(env.intel471ApiUser && env.intel471ApiKey) && req.options?.intel471 !== false;
  const i471Limiter = i471Enabled
    ? new RateLimiter(clamp(env.intel471Rpm ?? DEFAULT_INTEL471_RPM, 1, 600))
    : null;
  // CYFIRMA DeCYFIR lookups (all IOC types) under its own limiter.
  const cyfirmaEnabled = Boolean(env.cyfirmaApiKey) && req.options?.cyfirma !== false;
  const cyfirmaLimiter = cyfirmaEnabled
    ? new RateLimiter(clamp(env.cyfirmaRpm ?? DEFAULT_CYFIRMA_RPM, 1, 600))
    : null;
  // TeamT5 ThreatVision lookups (IP/domain detail = 1 AAP each; sample search = 0 AAP) under its own limiter.
  const tvEnabled =
    Boolean(env.threatvisionAccessToken || (env.threatvisionClientId && env.threatvisionClientSecret)) &&
    req.options?.threatvision !== false;
  const tvLimiter = tvEnabled
    ? new RateLimiter(clamp(env.threatvisionRpm ?? DEFAULT_THREATVISION_RPM, 1, 600))
    : null;
  const queue = new AsyncQueue<EnrichEvent>();
  const tasks = [...req.indicators];
  const total = tasks.length;
  const start = Date.now();

  let done = 0;
  let inflight = 0;
  let rateLimitedUntil: number | null = null;
  let fatal = false;

  const progress = (): EnrichEvent => ({ event: 'progress', done, total, inflight, rateLimitedUntil });

  async function lookupWithRetry(ind: EnrichRequest['indicators'][number]): Promise<LookupOutcome> {
    let rlAttempt = 0;
    let trAttempt = 0;
    for (;;) {
      if (signal?.aborted) return { status: 'error', errorMessage: 'aborted' };
      try {
        await limiter.acquire(signal);
        const r = await vtLookup(ind.type, ind.value, env, signal);
        rateLimitedUntil = null;
        return { status: r.status, data: r.data };
      } catch (e) {
        if (e instanceof FatalError) throw e;
        if (e instanceof RateLimitError) {
          if (rlAttempt >= MAX_RL_RETRIES) return { status: 'rate_limited', errorMessage: 'rate limited' };
          const waitMs = e.retryAfterMs ?? backoffMs(rlAttempt);
          rateLimitedUntil = Date.now() + waitMs;
          queue.push(progress());
          await sleep(waitMs, signal);
          rlAttempt++;
          continue;
        }
        if ((e as Error).name === 'AbortError') return { status: 'error', errorMessage: 'aborted' };
        if (trAttempt >= MAX_TRANSIENT_RETRIES) {
          return { status: 'error', errorMessage: (e as Error).message };
        }
        await sleep(backoffMs(trAttempt), signal);
        trAttempt++;
      }
    }
  }

  /** Supplementary OSINT for IPs. Never throws; failures surface as an error note on the row. */
  async function enrichShodan(value: string): Promise<ShodanContext | undefined> {
    if (!shodanLimiter) return undefined;
    try {
      await shodanLimiter.acquire(signal);
      return await shodanHostLookup(value, env, signal);
    } catch (e) {
      if ((e as Error).name === 'AbortError') return undefined;
      return { found: false, error: (e as Error).message };
    }
  }

  /** MaxMind GeoIP geolocation for IPs. Never throws. */
  async function enrichMaxmind(value: string): Promise<MaxmindContext | undefined> {
    if (!maxmindLimiter) return undefined;
    try {
      await maxmindLimiter.acquire(signal);
      return await maxmindLookup(value, env, signal);
    } catch (e) {
      if ((e as Error).name === 'AbortError') return undefined;
      return { found: false, error: (e as Error).message };
    }
  }

  /** DomainTools for a domain (Enrich) or IP (Investigate reverse). Never throws. */
  async function enrichDomaintools(
    kind: 'domain' | 'ip',
    value: string,
  ): Promise<DomainToolsContext | undefined> {
    if (!dtLimiter) return undefined;
    try {
      await dtLimiter.acquire(signal);
      return kind === 'domain'
        ? await domaintoolsEnrichDomain(value, env, signal)
        : await domaintoolsReverseIp(value, env, signal);
    } catch (e) {
      if ((e as Error).name === 'AbortError') return undefined;
      return { found: false, mode: kind === 'domain' ? 'enrich' : 'reverse-ip', error: (e as Error).message };
    }
  }

  /** DNSLytics for a domain (DomainInfo) or IP (IPInfo). Never throws. */
  async function enrichDnslytics(
    kind: 'domain' | 'ip',
    value: string,
  ): Promise<DnslyticsContext | undefined> {
    if (!dnslLimiter) return undefined;
    try {
      await dnslLimiter.acquire(signal);
      return kind === 'domain'
        ? await dnslyticsHostingHistory(value, env, signal)
        : await dnslyticsIpInfo(value, env, signal);
    } catch (e) {
      if ((e as Error).name === 'AbortError') return undefined;
      return { found: false, kind, error: (e as Error).message };
    }
  }

  /** Intel 471 IOC lookup (all types). Never throws. */
  async function enrichIntel471(value: string, type: EnrichRequest['indicators'][number]['type']): Promise<Intel471Context | undefined> {
    if (!i471Limiter) return undefined;
    try {
      await i471Limiter.acquire(signal);
      return await intel471Lookup(value, type, env, signal);
    } catch (e) {
      if ((e as Error).name === 'AbortError') return undefined;
      return { found: false, error: (e as Error).message };
    }
  }

  /** CYFIRMA DeCYFIR lookup (all types). Never throws. */
  async function enrichCyfirma(value: string, type: EnrichRequest['indicators'][number]['type']): Promise<CyfirmaContext | undefined> {
    if (!cyfirmaLimiter) return undefined;
    try {
      await cyfirmaLimiter.acquire(signal);
      return await cyfirmaLookup(value, type, env, signal);
    } catch (e) {
      if ((e as Error).name === 'AbortError') return undefined;
      return { found: false, error: (e as Error).message };
    }
  }

  /** TeamT5 ThreatVision lookup (IP / domain / hash). Never throws. */
  async function enrichThreatVision(
    value: string,
    type: EnrichRequest['indicators'][number]['type'],
    kind: ThreatVisionContext['kind'],
  ): Promise<ThreatVisionContext | undefined> {
    if (!tvLimiter) return undefined;
    try {
      await tvLimiter.acquire(signal);
      return await threatvisionLookup(value, type, env, signal);
    } catch (e) {
      if ((e as Error).name === 'AbortError') return undefined;
      return { found: false, kind, error: (e as Error).message };
    }
  }

  /** Attach all provider context to a normalized result, routing by IOC type. */
  async function attachContext(ind: EnrichRequest['indicators'][number], result: NormalizedResult): Promise<void> {
    const isIp = ind.type === 'ipv4' || ind.type === 'ipv6';
    // A URL's host is treated as a domain (unless it's an IP literal).
    const urlHost = ind.type === 'url' ? hostFromUrl(ind.value) : null;
    const domain = ind.type === 'domain' ? ind.value : urlHost && !isIpLiteral(urlHost) ? urlHost : null;

    const isHash = ind.type === 'md5' || ind.type === 'sha1' || ind.type === 'sha256';

    // Intel 471 + CYFIRMA apply to every IOC type (IP / domain / URL / hash).
    if (i471Limiter) result.intel471 = await enrichIntel471(ind.value, ind.type);
    if (cyfirmaLimiter) result.cyfirma = await enrichCyfirma(ind.value, ind.type);

    if (isIp) {
      if (shodanLimiter) result.shodan = await enrichShodan(ind.value);
      if (maxmindLimiter) result.maxmind = await enrichMaxmind(ind.value);
      // DNSLytics IPInfo is the verified per-IP endpoint (there is no per-domain "domaininfo" in v1).
      if (dnslLimiter) result.dnslytics = await enrichDnslytics('ip', ind.value);
      if (dtLimiter) result.domaintools = await enrichDomaintools('ip', ind.value);
      if (tvLimiter) result.threatvision = await enrichThreatVision(ind.value, ind.type, 'ip');
    } else if (domain) {
      // Domains: DomainTools Iris Enrich (registration + infra + risk) + DNSLytics HostingHistory (DNS/IP history).
      if (dtLimiter) result.domaintools = await enrichDomaintools('domain', domain);
      if (dnslLimiter) result.dnslytics = await enrichDnslytics('domain', domain);
      if (tvLimiter) result.threatvision = await enrichThreatVision(domain, 'domain', 'domain');
    } else if (isHash) {
      // Hashes: ThreatVision sample attribution (0 AAP — adversary + malware family) via search.
      if (tvLimiter) result.threatvision = await enrichThreatVision(ind.value, ind.type, 'sample');
    }
  }

  async function worker(): Promise<void> {
    while (tasks.length && !fatal) {
      if (signal?.aborted) return;
      const ind = tasks.shift()!;
      inflight++;
      queue.push(progress());
      try {
        const links = await buildLinks(ind.type, ind.value);
        const outcome = await lookupWithRetry(ind);
        const result: NormalizedResult = normalizeVt({
          input: ind.input,
          value: ind.value,
          type: ind.type,
          status: outcome.status,
          data: outcome.data,
          links,
          includeRaw,
          errorMessage: outcome.errorMessage,
        });
        await attachContext(ind, result);
        queue.push({ event: 'result', result });
      } catch (e) {
        if (e instanceof FatalError) {
          fatal = true;
          queue.push({ event: 'error', message: e.message });
          queue.close();
          return;
        }
        const links = await buildLinks(ind.type, ind.value);
        queue.push({
          event: 'result',
          result: normalizeVt({
            input: ind.input,
            value: ind.value,
            type: ind.type,
            status: 'error',
            links,
            errorMessage: (e as Error).message,
          }),
        });
      } finally {
        inflight--;
        done++;
        if (!fatal) queue.push(progress());
      }
    }
  }

  queue.push(progress());
  const workers = Array.from({ length: Math.min(concurrency, total || 1) }, () => worker());
  void Promise.all(workers).then(() => {
    if (!fatal) {
      queue.push({ event: 'done', done, total, elapsedMs: Date.now() - start });
      queue.close();
    }
  });

  for await (const ev of queue) yield ev;
}

export function ndjson(ev: EnrichEvent): string {
  return JSON.stringify(ev) + '\n';
}
