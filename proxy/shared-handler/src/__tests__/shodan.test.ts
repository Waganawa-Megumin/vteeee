import { describe, it, expect, vi, afterEach } from 'vitest';
import type { EnrichEvent } from '@vteeee/shared';
import { mapShodanHost, shodanHostLookup } from '../shodanFetch';
import { runEnrich } from '../enrich';
import type { ProxyEnv } from '../types';

const env: ProxyEnv = {
  vtApiKey: 'vt',
  shodanApiKey: 'shodan',
  shodanRpm: 600,
  allowedOrigins: ['*'],
  defaultRpm: 600,
  maxRpm: 1000,
  xTool: 'vteeee',
  maxBatch: 1000,
  dailyCap: 0,
  parseDailyCap: 0,
};

function resp(status: number, body: unknown, headers?: Record<string, string>): Response {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers });
}

const SAMPLE_HOST = {
  ip_str: '185.220.101.1',
  org: 'Example Org',
  isp: 'Example ISP',
  asn: 'AS60729',
  country_name: 'Germany',
  city: 'Frankfurt',
  os: null,
  hostnames: ['tor-exit.example', 'tor-exit.example'],
  ports: [9001, 22, 22, 80],
  tags: ['tor'],
  vulns: ['CVE-2016-20012'],
  last_update: '2024-05-01T00:00:00.000000',
  data: [
    { port: 22, transport: 'tcp', product: 'OpenSSH', version: '8.4p1', _shodan: { module: 'ssh' } },
    { port: 9001, transport: 'tcp', _shodan: { module: 'tor' }, vulns: { 'CVE-2023-38408': {} } },
    { notport: true },
  ],
};

afterEach(() => vi.unstubAllGlobals());

describe('mapShodanHost', () => {
  it('maps core fields, dedupes/sorts ports, collects vulns from both levels', () => {
    const ctx = mapShodanHost(SAMPLE_HOST);
    expect(ctx.found).toBe(true);
    expect(ctx.org).toBe('Example Org');
    expect(ctx.asn).toBe('AS60729');
    expect(ctx.country).toBe('Germany');
    expect(ctx.os).toBeUndefined(); // null os is dropped
    expect(ctx.hostnames).toEqual(['tor-exit.example']); // deduped
    expect(ctx.ports).toEqual([22, 80, 9001]); // deduped + sorted
    // top-level CVE + per-service CVE, sorted & unique
    expect(ctx.vulns).toEqual(['CVE-2016-20012', 'CVE-2023-38408']);
    expect(ctx.services).toHaveLength(2); // the `{ notport }` entry is skipped
    expect(ctx.services?.[0]).toMatchObject({ port: 22, product: 'OpenSSH', module: 'ssh' });
    expect(ctx.lastUpdate).toBe('2024-05-01T00:00:00.000000');
  });

  it('tolerates an empty / minimal host object', () => {
    const ctx = mapShodanHost({ ip_str: '1.2.3.4' });
    expect(ctx).toEqual({ found: true });
  });
});

describe('shodanHostLookup status mapping', () => {
  it('returns undefined when no key is configured', async () => {
    expect(await shodanHostLookup('1.1.1.1', { ...env, shodanApiKey: undefined })).toBeUndefined();
  });

  it('maps 200 / 404 / 401 / 429', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => resp(200, SAMPLE_HOST)));
    expect((await shodanHostLookup('1.1.1.1', env))?.found).toBe(true);

    vi.stubGlobal('fetch', vi.fn(async () => resp(404, '{}')));
    expect(await shodanHostLookup('1.1.1.1', env)).toEqual({ found: false });

    vi.stubGlobal('fetch', vi.fn(async () => resp(401, '{}')));
    expect((await shodanHostLookup('1.1.1.1', env))?.error).toMatch(/invalid API key/);

    vi.stubGlobal('fetch', vi.fn(async () => resp(429, '{}')));
    expect((await shodanHostLookup('1.1.1.1', env))?.error).toMatch(/rate limited/);
  });

  it('sends the API key in the query string, not a header', async () => {
    const f = vi.fn(async (_url: string) => resp(200, SAMPLE_HOST));
    vi.stubGlobal('fetch', f);
    await shodanHostLookup('1.1.1.1', env);
    expect(String(f.mock.calls[0][0])).toContain('key=shodan');
  });
});

describe('runEnrich + Shodan', () => {
  it('attaches Shodan context to IPs and skips non-IP indicators', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.includes('api.shodan.io')) return resp(200, SAMPLE_HOST);
        if (url.includes('/ip_addresses/'))
          return resp(200, { data: { attributes: { last_analysis_stats: { harmless: 9 } } } });
        return resp(404, '{}');
      }),
    );

    const events: EnrichEvent[] = [];
    for await (const ev of runEnrich(
      {
        indicators: [
          { type: 'ipv4', value: '185.220.101.1', input: '185.220.101.1' },
          { type: 'domain', value: 'example.com', input: 'example.com' },
        ],
      },
      env,
    )) {
      events.push(ev);
    }

    const results = events.flatMap((e) => (e.event === 'result' ? [e.result] : []));
    const ip = results.find((r) => r.value === '185.220.101.1');
    const dom = results.find((r) => r.value === 'example.com');
    expect(ip?.shodan?.found).toBe(true);
    expect(ip?.shodan?.ports).toEqual([22, 80, 9001]);
    expect(ip?.shodan?.vulns).toContain('CVE-2023-38408');
    expect(dom?.shodan).toBeUndefined(); // domains are not Shodan-enriched
  });

  it('leaves Shodan undefined when no key is configured', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => resp(200, { data: { attributes: {} } })));
    const events: EnrichEvent[] = [];
    for await (const ev of runEnrich(
      { indicators: [{ type: 'ipv4', value: '1.1.1.1', input: '1.1.1.1' }] },
      { ...env, shodanApiKey: undefined },
    )) {
      events.push(ev);
    }
    const r = events.flatMap((e) => (e.event === 'result' ? [e.result] : []))[0];
    expect(r.shodan).toBeUndefined();
  });
});
