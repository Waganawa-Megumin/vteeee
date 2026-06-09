import { describe, it, expect } from 'vitest';
import { classify } from '../classify';
import { extractIndicators } from '../extract';
import type { IocType } from '../types';

// EICAR test file hashes (safe, universally recognized).
const EICAR_MD5 = '44d88612fea8a8f36de82e1278abb02f';
const EICAR_SHA1 = '3395856ce81f2b7382dee72602f798b642f14140';
const EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

describe('classify (single token, with refang via extract for spaced forms)', () => {
  const cases: Array<[string, IocType, string]> = [
    ['1[.]1[.]1[.]1', 'ipv4', '1.1.1.1'],
    ['8(dot)8(dot)8(dot)8', 'ipv4', '8.8.8.8'],
    ['hxxp://evil[.]com/a?b=1', 'url', 'http://evil.com/a?b=1'],
    ['hXXps://Example[.]COM/Path', 'url', 'https://example.com/Path'],
    ['evil[.]com', 'domain', 'evil.com'],
    ['www.example.com/', 'domain', 'www.example.com'],
    ['bad.com/login.php', 'url', 'http://bad.com/login.php'],
    ['"http://x.com".', 'url', 'http://x.com'],
    ['<https://y.org/p>', 'url', 'https://y.org/p'],
    ['`1.2.3.4`', 'ipv4', '1.2.3.4'],
    ['2001:db8::1', 'ipv6', '2001:db8::1'],
    ['[2001:db8::1]:443', 'ipv6', '2001:db8::1'],
    [EICAR_MD5.toUpperCase(), 'md5', EICAR_MD5],
    [EICAR_SHA1, 'sha1', EICAR_SHA1],
    [EICAR_SHA256, 'sha256', EICAR_SHA256],
    ['999.1.1.1', 'unknown', '999.1.1.1'],
    ['localhost', 'unknown', 'localhost'],
  ];

  for (const [input, type, value] of cases) {
    it(`${input} -> ${type} ${value}`, () => {
      const c = classify(input);
      expect(c.type).toBe(type);
      expect(c.value).toBe(value);
    });
  }

  it('flags private / RFC1918 IPv4', () => {
    expect(classify('192.168.1.10')).toMatchObject({ type: 'ipv4', isPrivate: true });
    expect(classify('10.0.0.5')).toMatchObject({ type: 'ipv4', isPrivate: true });
    expect(classify('1.1.1.1')).toMatchObject({ type: 'ipv4', isPrivate: false });
  });

  it('classifies bare email as unknown (not enriched)', () => {
    expect(classify('user@evil.com').type).toBe('unknown');
  });

  it('punycodes internationalized domains', () => {
    const c = classify('пример.com');
    expect(c.type).toBe('domain');
    expect(c.value).toBe('xn--e1afmkfd.com');
  });

  it('refangs worded spaced dot via extract', () => {
    const { indicators } = extractIndicators('evil [dot] com');
    expect(indicators[0]).toMatchObject({ type: 'domain', value: 'evil.com' });
  });
});

describe('extractIndicators', () => {
  it('parses a mixed newline list and dedupes', () => {
    const input = [
      '1[.]1[.]1[.]1',
      '1.1.1.1', // duplicate of the above after refang
      'evil[.]com',
      'hxxps://bad[.]net/login',
      EICAR_SHA256,
      '192.168.1.10', // private
      'not an indicator',
    ].join('\n');

    const { indicators, stats } = extractIndicators(input);
    const byType = (t: IocType) => indicators.filter((i) => i.type === t).map((i) => i.value);

    // 1[.]1[.]1[.]1 and 1.1.1.1 collapse to one; the private IP is still typed ipv4.
    expect(byType('ipv4')).toEqual(['1.1.1.1', '192.168.1.10']);
    expect(byType('domain')).toContain('evil.com');
    expect(byType('url')).toEqual(['https://bad.net/login']);
    expect(byType('sha256')).toEqual([EICAR_SHA256]);
    expect(stats.duplicates).toBeGreaterThanOrEqual(1);

    const priv = indicators.find((i) => i.value === '192.168.1.10');
    expect(priv?.excludedReason).toBe('private');
  });

  it('extracts indicators from CSV cells', () => {
    const { indicators } = extractIndicators('evil.com,2024-01-01,phishing\nbad.net,2023-12-31,c2');
    const domains = indicators.filter((i) => i.type === 'domain').map((i) => i.value);
    expect(domains).toEqual(['evil.com', 'bad.net']);
  });

  it('extracts an indicator embedded in prose', () => {
    const { indicators } = extractIndicators('Indicator: 1.2.3.4 (C2).');
    const ips = indicators.filter((i) => i.type === 'ipv4').map((i) => i.value);
    expect(ips).toEqual(['1.2.3.4']);
  });

  it('computes enrichable count excluding private/unknown', () => {
    const { stats } = extractIndicators('1.1.1.1\n192.168.0.1\ngarbage-token');
    expect(stats.enrichable).toBe(1);
    expect(stats.private).toBe(1);
    expect(stats.unknown).toBe(1);
  });
});
