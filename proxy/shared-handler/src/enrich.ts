import {
  buildLinks,
  normalizeVt,
  type EnrichEvent,
  type EnrichRequest,
  type NormalizedResult,
  type ResultStatus,
} from '@vteeee/shared';
import { FatalError, RateLimitError, type ProxyEnv } from './types';
import { RateLimiter } from './rateLimiter';
import { vtLookup } from './vtFetch';
import { AsyncQueue, backoffMs, clamp, sleep } from './util';

const MAX_RL_RETRIES = 3;
const MAX_TRANSIENT_RETRIES = 2;

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

  async function worker(): Promise<void> {
    while (tasks.length && !fatal) {
      if (signal?.aborted) return;
      const ind = tasks.shift()!;
      inflight++;
      queue.push(progress());
      try {
        if (env.consumeQuota && !env.consumeQuota()) {
          throw new FatalError('Daily quota reached');
        }
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
