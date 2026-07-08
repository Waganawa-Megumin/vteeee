import { describe, it, expect, vi, afterEach } from 'vitest';
import { mapUrlscanResult, urlscanSubmit, urlscanResult } from '../urlscanFetch';
import { mapInternetDb, shodanInternetDb, shodanScanRequest } from '../shodanFetch';
import type { ProxyEnv } from '../types';

const env: ProxyEnv = {
  vtApiKey: 'vt',
  shodanApiKey: 'shodan',
  urlscanApiKey: 'urlscankey',
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

const URLSCAN_RESULT = {
  task: {
    uuid: 'abc-123',
    url: 'http://phishy-malware-example.com/login.php',
    reportURL: 'https://urlscan.io/result/abc-123/',
    screenshotURL: 'https://urlscan.io/screenshots/abc-123.png',
  },
  page: {
    url: 'http://phishy-malware-example.com/account/verify',
    domain: 'phishy-malware-example.com',
    country: 'RU',
    server: 'nginx',
    ip: '185.220.101.1',
    asn: 'AS201814',
    asnname: 'BADHOST-AS',
    title: 'Sign in',
    status: '200',
  },
  lists: {
    ips: ['185.220.101.1', '93.184.216.34'],
    domains: ['phishy-malware-example.com', 'cdn.badhost.example'],
  },
  verdicts: {
    overall: { score: 87, malicious: true, brands: [{ name: 'Microsoft' }], tags: ['phishing'] },
  },
};

afterEach(() => vi.unstubAllGlobals());

describe('mapUrlscanResult', () => {
  it('maps page / verdict / lists into the flat shape', () => {
    const r = mapUrlscanResult(URLSCAN_RESULT);
    expect(r.uuid).toBe('abc-123');
    expect(r.finalUrl).toBe('http://phishy-malware-example.com/account/verify');
    expect(r.ip).toBe('185.220.101.1');
    expect(r.asn).toBe('AS201814');
    expect(r.asnName).toBe('BADHOST-AS');
    expect(r.status).toBe(200); // string "200" → number
    expect(r.malicious).toBe(true);
    expect(r.score).toBe(87);
    expect(r.brands).toEqual(['Microsoft']);
    expect(r.tags).toEqual(['phishing']);
    expect(r.contactedDomains).toContain('cdn.badhost.example');
    expect(r.contactedIps).toContain('93.184.216.34');
    expect(r.screenshotUrl).toBe('https://urlscan.io/screenshots/abc-123.png');
  });

  it('tolerates a minimal / empty document', () => {
    const r = mapUrlscanResult({});
    expect(r.malicious).toBeUndefined();
    expect(r.contactedDomains).toBeUndefined();
  });
});

describe('urlscanSubmit', () => {
  it('returns undefined when no key is configured', async () => {
    expect(await urlscanSubmit('http://x.example', { ...env, urlscanApiKey: undefined })).toBeUndefined();
  });

  it('submits with the API key, defaults to unlisted, and sends NO identifying tag', async () => {
    const f = vi.fn(async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      expect((init?.headers as Record<string, string>)['API-Key']).toBe('urlscankey');
      expect(body.visibility).toBe('unlisted');
      // OPSEC: no tags → scans can't be clustered/attributed via urlscan tag search.
      expect(body.tags).toBeUndefined();
      return resp(200, { uuid: 'u1', result: 'https://urlscan.io/result/u1/', api: 'https://urlscan.io/api/v1/result/u1/', visibility: 'unlisted', message: 'ok' });
    });
    vi.stubGlobal('fetch', f);
    const s = await urlscanSubmit('phishy-malware-example.com', env);
    expect(s?.uuid).toBe('u1');
    expect(s?.visibility).toBe('unlisted');
    expect(s?.screenshotUrl).toContain('/screenshots/u1.png');
    // bare domain got a scheme
    expect(JSON.parse(String(f.mock.calls[0][1]?.body)).url).toMatch(/^http:\/\//);
  });

  it('clamps a requested public visibility to unlisted (OPSEC default)', async () => {
    const f = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(JSON.parse(String(init?.body)).visibility).toBe('unlisted'); // clamped
      return resp(200, { uuid: 'u2', visibility: 'unlisted' });
    });
    vi.stubGlobal('fetch', f);
    await urlscanSubmit('http://x.example', env, 'public');
  });

  it('allows public only when the proxy explicitly opts in', async () => {
    const f = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(JSON.parse(String(init?.body)).visibility).toBe('public');
      return resp(200, { uuid: 'u3', visibility: 'public' });
    });
    vi.stubGlobal('fetch', f);
    await urlscanSubmit('http://x.example', { ...env, urlscanAllowPublic: true }, 'public');
  });

  it('only attaches tags when the operator configured them', async () => {
    const f = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(JSON.parse(String(init?.body)).tags).toEqual(['ir-2026', 'case42']);
      return resp(200, { uuid: 'u4', visibility: 'unlisted' });
    });
    vi.stubGlobal('fetch', f);
    await urlscanSubmit('http://x.example', { ...env, urlscanTags: 'ir-2026, case42' });
  });

  it('surfaces a 400 (unresolvable/blacklisted) as an error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => resp(400, { message: 'DNS Error - Could not resolve domain', status: 400 })));
    const s = await urlscanSubmit('http://nope.invalid', env);
    expect(s?.error).toMatch(/DNS Error/);
  });

  it('surfaces a 401 (bad key)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => resp(401, { message: 'bad key' })));
    expect((await urlscanSubmit('http://x.example', env))?.error).toMatch(/invalid API key/);
  });
});

describe('urlscanResult', () => {
  it('reports pending on 404 (still rendering)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => resp(404, { message: 'not done' })));
    expect(await urlscanResult('abc-123', env)).toEqual({ pending: true, uuid: 'abc-123' });
  });

  it('maps a finished result', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => resp(200, URLSCAN_RESULT)));
    const r = await urlscanResult('abc-123', env);
    expect(r?.malicious).toBe(true);
    expect(r?.ip).toBe('185.220.101.1');
  });
});

describe('Shodan InternetDB', () => {
  it('maps ports / vulns / cpes (deduped, sorted)', () => {
    const db = mapInternetDb(
      { ip: '1.1.1.1', ports: [443, 80, 80], vulns: ['CVE-2021-44228'], cpes: ['cpe:/a:nginx:nginx'], hostnames: ['h.example'], tags: ['cdn'] },
      '1.1.1.1',
    );
    expect(db.found).toBe(true);
    expect(db.ports).toEqual([80, 443]);
    expect(db.vulns).toEqual(['CVE-2021-44228']);
    expect(db.cpes).toEqual(['cpe:/a:nginx:nginx']);
  });

  it('needs no key; 404 → found:false, 200 → mapped', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => resp(404, { detail: 'No information available' })));
    expect(await shodanInternetDb('8.8.8.8')).toEqual({ found: false });

    vi.stubGlobal('fetch', vi.fn(async () => resp(200, { ip: '8.8.8.8', ports: [53, 443] })));
    const ok = await shodanInternetDb('8.8.8.8');
    expect(ok?.found).toBe(true);
    expect(ok?.ports).toEqual([53, 443]);
  });
});

describe('shodanScanRequest', () => {
  it('returns undefined without a Shodan key', async () => {
    expect(await shodanScanRequest('1.1.1.1', { ...env, shodanApiKey: undefined })).toBeUndefined();
  });

  it('maps an accepted scan (id + credits_left)', async () => {
    const f = vi.fn(async (url: string) => {
      expect(url).toContain('key=shodan');
      return resp(200, { id: 'R2XREGLHVK7BFDEZ', count: 1, credits_left: 99 });
    });
    vi.stubGlobal('fetch', f);
    const s = await shodanScanRequest('1.1.1.1', env);
    expect(s).toEqual({ id: 'R2XREGLHVK7BFDEZ', count: 1, creditsLeft: 99 });
  });

  it('surfaces "no credits" (403)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => resp(403, { error: 'no credits' })));
    expect((await shodanScanRequest('1.1.1.1', env))?.error).toMatch(/no scan credits|plan/);
  });
});
