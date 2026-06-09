import { describe, it, expect, vi, afterEach } from 'vitest';
import type { EnrichEvent } from '@vteeee/shared';
import { runEnrich } from '../enrich';
import { vtLookup } from '../vtFetch';
import { FatalError, RateLimitError, type ProxyEnv } from '../types';

const env: ProxyEnv = {
  vtApiKey: 'k',
  allowedOrigins: ['*'],
  defaultRpm: 600,
  maxRpm: 1000,
  xTool: 'vteeee',
};

function resp(status: number, body: unknown, headers?: Record<string, string>): Response {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers });
}

afterEach(() => vi.unstubAllGlobals());

describe('vtLookup status mapping', () => {
  it('maps 200/404/429/401', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => resp(200, { data: { attributes: { last_analysis_stats: { harmless: 5 } } } })),
    );
    expect((await vtLookup('ipv4', '1.1.1.1', env)).status).toBe('success');

    vi.stubGlobal('fetch', vi.fn(async () => resp(404, '{}')));
    expect((await vtLookup('domain', 'x.com', env)).status).toBe('not_found');

    vi.stubGlobal('fetch', vi.fn(async () => resp(429, '', { 'retry-after': '1' })));
    await expect(vtLookup('ipv4', '1.1.1.1', env)).rejects.toBeInstanceOf(RateLimitError);

    vi.stubGlobal('fetch', vi.fn(async () => resp(401, '{}')));
    await expect(vtLookup('ipv4', '1.1.1.1', env)).rejects.toBeInstanceOf(FatalError);
  });

  it('sends x-apikey and x-tool headers', async () => {
    const f = vi.fn(async (_url: string, _init?: RequestInit) =>
      resp(200, { data: { attributes: {} } }),
    );
    vi.stubGlobal('fetch', f);
    await vtLookup('domain', 'evil.com', env);
    const headers = f.mock.calls[0][1]?.headers as Record<string, string>;
    expect(headers['x-apikey']).toBe('k');
    expect(headers['x-tool']).toBe('vteeee');
  });
});

describe('runEnrich', () => {
  it('streams results + done, handling success and not_found', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        url.includes('/ip_addresses/')
          ? resp(200, {
              data: {
                attributes: {
                  last_analysis_stats: { malicious: 3, suspicious: 0, harmless: 60, undetected: 7 },
                  reputation: -5,
                },
              },
            })
          : resp(404, '{}'),
      ),
    );

    const events: EnrichEvent[] = [];
    for await (const ev of runEnrich(
      {
        indicators: [
          { type: 'ipv4', value: '9.9.9.9', input: '9.9.9.9' },
          { type: 'domain', value: 'nope.com', input: 'nope.com' },
        ],
      },
      env,
    )) {
      events.push(ev);
    }

    const results = events.flatMap((e) => (e.event === 'result' ? [e.result] : []));
    expect(results.find((r) => r.value === '9.9.9.9')?.verdict).toBe('malicious');
    expect(results.find((r) => r.value === 'nope.com')?.status).toBe('not_found');
    expect(events.some((e) => e.event === 'done')).toBe(true);
  });

  it('retries on 429 then succeeds', async () => {
    let n = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        n++;
        return n === 1
          ? resp(429, '', { 'retry-after': '0' })
          : resp(200, { data: { attributes: { last_analysis_stats: { harmless: 9 } } } });
      }),
    );

    const events: EnrichEvent[] = [];
    for await (const ev of runEnrich(
      { indicators: [{ type: 'ipv4', value: '1.2.3.4', input: '1.2.3.4' }] },
      env,
    )) {
      events.push(ev);
    }
    const r = events.flatMap((e) => (e.event === 'result' ? [e.result] : []))[0];
    expect(r.status).toBe('success');
    expect(n).toBe(2);
  });

  it('aborts the batch on a fatal auth error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => resp(403, '{}')));
    const events: EnrichEvent[] = [];
    for await (const ev of runEnrich(
      { indicators: [{ type: 'domain', value: 'a.com', input: 'a.com' }] },
      env,
    )) {
      events.push(ev);
    }
    expect(events.some((e) => e.event === 'error')).toBe(true);
    expect(events.some((e) => e.event === 'done')).toBe(false);
  });
});
