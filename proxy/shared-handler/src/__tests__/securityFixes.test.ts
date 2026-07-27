import { describe, it, expect } from 'vitest';
import { apiPath } from '@vteeee/shared';
import { checkAccess, checkAdmin } from '../http';
import { rfSandboxIntel } from '../recordedfutureFetch';
import { smartParse } from '../parse';
import type { ProxyEnv } from '../types';

const base = { allowedOrigins: ['*'], defaultRpm: 4, maxRpm: 1000, maxBatch: 1000 } as unknown as ProxyEnv;

describe('VT apiPath injection guard', () => {
  it('builds the file path for a valid hash', () => {
    expect(apiPath('sha256', 'a'.repeat(64))).toBe(`https://www.virustotal.com/api/v3/files/${'a'.repeat(64)}`);
  });
  it('rejects a non-hash file value (path traversal / confused deputy)', () => {
    expect(() => apiPath('md5', '../users/me')).toThrow();
    expect(() => apiPath('sha256', '../../intelligence/search?query=x')).toThrow();
    expect(() => apiPath('sha1', 'not a hash')).toThrow();
  });
  it('still encodes/validates ip + domain', () => {
    expect(apiPath('ipv4', '1.1.1.1')).toContain('/ip_addresses/1.1.1.1');
    expect(apiPath('domain', 'evil.example')).toContain('/domains/evil.example');
  });
});

describe('RecordedFuture sandbox query injection guard', () => {
  it('rejects a non-hash before building the DSL query (returns undefined, no fetch)', async () => {
    const env = { ...base, recordedfutureApiKey: 'k' } as ProxyEnv;
    await expect(rfSandboxIntel('x" OR sandbox_score > 0 OR "', env)).resolves.toBeUndefined();
    await expect(rfSandboxIntel('not-a-hash', env)).resolves.toBeUndefined();
  });
});

describe('checkAccess fail-closed', () => {
  it('DENIES when no access token is configured (was fail-open)', () => {
    expect(checkAccess('Bearer whatever', base)).toBe(false);
    expect(checkAccess(null, base)).toBe(false);
  });
  it('allows unauthenticated only with the explicit ALLOW_ANONYMOUS opt-in', () => {
    expect(checkAccess(null, { ...base, allowAnonymous: true } as ProxyEnv)).toBe(true);
  });
  it('enforces the token when one is configured', () => {
    const env = { ...base, accessToken: 'secret' } as ProxyEnv;
    expect(checkAccess('Bearer secret', env)).toBe(true);
    expect(checkAccess('Bearer wrong', env)).toBe(false);
    expect(checkAccess(null, env)).toBe(false);
  });
  it('checkAdmin stays fail-closed (unset admin token denies)', () => {
    expect(checkAdmin('Bearer x', base)).toBe(false);
    expect(checkAdmin('Bearer a', { ...base, adminToken: 'a' } as ProxyEnv)).toBe(true);
  });
});

describe('parse input cap (DoS guard)', () => {
  it('handles a multi-hundred-KB body promptly via the regex fallback', async () => {
    const huge = ('1.2.3.4 ' + 'x'.repeat(50)).repeat(20_000); // ~1.1 MB
    const t0 = Date.now();
    const r = await smartParse(huge, base); // no anthropicApiKey → regex path, capped to 120k
    expect(Array.isArray(r.indicators)).toBe(true);
    expect(Date.now() - t0).toBeLessThan(2000); // bounded, not O(n^2) over the full input
  });
});
