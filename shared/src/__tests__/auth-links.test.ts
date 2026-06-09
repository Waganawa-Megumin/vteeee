import { describe, it, expect } from 'vitest';
import { hashPassword, verifyPassword, derive } from '../auth/hash';
import { checkToken, parseBearer } from '../auth/token';
import { urlApiId, sha256Hex, guiLink, apiPath } from '../vt-links';

describe('PBKDF2 password hashing', () => {
  it('verifies a correct password and rejects a wrong one', async () => {
    const rec = await hashPassword('correct horse battery staple', 50_000);
    expect(rec.iterations).toBe(50_000);
    expect(await verifyPassword('correct horse battery staple', rec)).toBe(true);
    expect(await verifyPassword('wrong password', rec)).toBe(false);
  });

  it('is deterministic for a fixed salt + iterations', async () => {
    const salt = 'AAAAAAAAAAAAAAAAAAAAAA==';
    const a = await derive('pw', salt, 10_000);
    const b = await derive('pw', salt, 10_000);
    expect(a).toBe(b);
    expect(a).not.toBe(await derive('pw2', salt, 10_000));
  });
});

describe('token helpers', () => {
  it('parses bearer headers', () => {
    expect(parseBearer('Bearer abc')).toBe('abc');
    expect(parseBearer('abc')).toBe('abc');
    expect(parseBearer(null)).toBeNull();
  });
  it('checks tokens in constant time and fails closed', () => {
    expect(checkToken('s3cret', 's3cret')).toBe(true);
    expect(checkToken('nope', 's3cret')).toBe(false);
    expect(checkToken('s3cret', undefined)).toBe(false);
    expect(checkToken(null, 's3cret')).toBe(false);
  });
});

describe('VT link/id helpers', () => {
  it('computes the url-safe base64 API id (no padding)', () => {
    // VirusTotal documented example.
    expect(urlApiId('http://www.virustotal.com')).toBe('aHR0cDovL3d3dy52aXJ1c3RvdGFsLmNvbQ');
  });

  it('builds GUI deep-links per type', () => {
    expect(guiLink('ipv4', '1.1.1.1')).toBe('https://www.virustotal.com/gui/ip-address/1.1.1.1');
    expect(guiLink('domain', 'evil.com')).toBe('https://www.virustotal.com/gui/domain/evil.com');
    expect(guiLink('sha256', 'abc')).toBe('https://www.virustotal.com/gui/file/abc');
    expect(guiLink('url', 'http://x.com', 'deadbeef')).toBe(
      'https://www.virustotal.com/gui/url/deadbeef',
    );
  });

  it('builds API paths', () => {
    expect(apiPath('domain', 'evil.com')).toBe(
      'https://www.virustotal.com/api/v3/domains/evil.com',
    );
    expect(apiPath('ipv4', '1.1.1.1')).toBe(
      'https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1',
    );
    expect(apiPath('url', 'http://www.virustotal.com')).toBe(
      'https://www.virustotal.com/api/v3/urls/aHR0cDovL3d3dy52aXJ1c3RvdGFsLmNvbQ',
    );
  });

  it('computes SHA-256 hex', async () => {
    // SHA-256 of the empty string.
    expect(await sha256Hex('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });
});
