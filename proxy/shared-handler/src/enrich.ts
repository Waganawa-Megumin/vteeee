import {
  buildLinks,
  normalizeVt,
  type EnrichEvent,
  type EnrichRequest,
  type NormalizedResult,
  type ResultStatus,
  type ShodanContext,
} from '@vteeee/shared';
import { FatalError, RateLimitError, type ProxyEnv } from './types';
import { RateLimiter } from './rateLimiter';
import { vtLookup } from './vtFetch';
import { shodanHostLookup } from './shodanFetch';
import { AsyncQueue, backoffMs, clamp, sleep } from './util';

const MAX_RL_RETRIES = 3;
const MAX_TRANSIENT_RETRIES = 2;
const DEFAULT_SHODAN_RPM = 60;

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
        if (shodanLimiter && (ind.type === 'ipv4' || ind.type === 'ipv6')) {
          result.shodan = await enrichShodan(ind.value);
        }
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
