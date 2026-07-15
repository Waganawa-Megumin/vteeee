import { describe, it, expect, vi, afterEach } from 'vitest';
import type { EnrichEvent } from '@vteeee/shared';
import { mapAbuseIpdb, abuseipdbCheck } from '../abuseipdbFetch';
import { runEnrich } from '../enrich';
import type { ProxyEnv } from '../types';

const env: ProxyEnv = {
  vtApiKey: 'vt',
  abuseipdbApiKey: 'abuse',
  abuseipdbRpm: 600,
  allowedOrigins: ['*'],
  defaultRpm: 600,
  maxRpm: 1000,
  xTool: 'vteeee',
  maxBatch: 1000,
  dailyCap: 0,
  parseDailyCap: 0,
  urlscanDailyCap: 0,
};

function resp(status: number, body: unknown, headers?: Record<string, string>): Response {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers });
}

const CHECK = {
  data: {
    ipAddress: '118.25.6.39',
    isPublic: true,
    ipVersion: 4,
    isWhitelisted: false,
    abuseConfidenceScore: 100,
    countryCode: 'CN',
    countryName: 'China',
    usageType: 'Data Center/Web Hosting/Transit',
    isp: 'Tencent Cloud',
    domain: 'tencent.com',
    hostnames: [],
    isTor: false,
    totalReports: 2,
    numDistinctUsers: 2,
    lastReportedAt: '2018-12-20T20:55:14+00:00',
    reports: [
      { reportedAt: '2018-12-20T20:55:14+00:00', comment: 'Invalid user oracle', categories: [18, 22], reporterCountryCode: 'US' },
      { reportedAt: '2018-12-19T10:00:00+00:00', comment: 'Port scan', categories: [14, 18], reporterCountryCode: 'DE' },
    ],
  },
};

afterEach(() => vi.unstubAllGlobals());

describe('mapAbuseIpdb', () => {
  it('maps score/attribution and turns category ids into labels + distinct set', () => {
    const a = mapAbuseIpdb(CHECK);
    expect(a.found).toBe(true);
    expect(a.abuseConfidenceScore).toBe(100);
    expect(a.usageType).toBe('Data Center/Web Hosting/Transit');
    expect(a.isTor).toBe(false);
    expect(a.isWhitelisted).toBe(false);
    // categories 18=Brute-Force, 22=SSH, 14=Port Scan — sorted by frequency (18 appears twice → first)
    expect(a.categories?.[0]).toBe('Brute-Force');
    expect(a.categories).toEqual(expect.arrayContaining(['SSH', 'Port Scan']));
    expect(a.reports).toHaveLength(2);
    expect(a.reports?.[0].categories).toEqual(['Brute-Force', 'SSH']);
  });

  it('tolerates an empty response', () => {
    expect(mapAbuseIpdb({}).found).toBe(false);
  });
});

describe('abuseipdbCheck status mapping', () => {
  it('returns undefined when no key is configured', async () => {
    expect(await abuseipdbCheck('1.1.1.1', { ...env, abuseipdbApiKey: undefined })).toBeUndefined();
  });

  it('sends the Key header + verbose and maps 200', async () => {
    const f = vi.fn(async (url: string, init?: RequestInit) => {
      expect((init?.headers as Record<string, string>).Key).toBe('abuse');
      expect(url).toContain('/check?ipAddress=118.25.6.39');
      expect(url).toContain('verbose');
      return resp(200, CHECK);
    });
    vi.stubGlobal('fetch', f);
    expect((await abuseipdbCheck('118.25.6.39', env))?.abuseConfidenceScore).toBe(100);
  });

  it('surfaces 401 / 429 with a helpful message', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => resp(401, { errors: [{ detail: 'bad key', status: 401 }] })));
    expect((await abuseipdbCheck('1.1.1.1', env))?.error).toMatch(/invalid API key/);

    vi.stubGlobal(
      'fetch',
      vi.fn(async () => resp(429, { errors: [{ detail: 'Daily rate limit of 1000 requests exceeded', status: 429 }] })),
    );
    expect((await abuseipdbCheck('1.1.1.1', env))?.error).toMatch(/rate limit/i);
  });
});

describe('runEnrich + AbuseIPDB', () => {
  it('attaches AbuseIPDB to IPs and skips non-IP indicators', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.includes('api.abuseipdb.com')) return resp(200, CHECK);
        if (url.includes('/ip_addresses/'))
          return resp(200, { data: { attributes: { last_analysis_stats: { malicious: 3 } } } });
        return resp(404, '{}');
      }),
    );
    const events: EnrichEvent[] = [];
    for await (const ev of runEnrich(
      {
        indicators: [
          { type: 'ipv4', value: '118.25.6.39', input: '118.25.6.39' },
          { type: 'domain', value: 'example.com', input: 'example.com' },
        ],
      },
      env,
    )) {
      events.push(ev);
    }
    const results = events.flatMap((e) => (e.event === 'result' ? [e.result] : []));
    expect(results.find((r) => r.value === '118.25.6.39')?.abuseipdb?.abuseConfidenceScore).toBe(100);
    expect(results.find((r) => r.value === 'example.com')?.abuseipdb).toBeUndefined();
  });

  it('skips AbuseIPDB when the client opts out (options.abuseipdb === false)', async () => {
    const f = vi.fn(async (url: string) => {
      if (url.includes('api.abuseipdb.com')) return resp(200, CHECK);
      return resp(200, { data: { attributes: {} } });
    });
    vi.stubGlobal('fetch', f);
    const events: EnrichEvent[] = [];
    for await (const ev of runEnrich(
      { indicators: [{ type: 'ipv4', value: '1.1.1.1', input: '1.1.1.1' }], options: { abuseipdb: false } },
      env,
    )) {
      events.push(ev);
    }
    expect(f.mock.calls.every(([u]) => !String(u).includes('api.abuseipdb.com'))).toBe(true);
  });
});
