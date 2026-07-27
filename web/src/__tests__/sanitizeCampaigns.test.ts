import { describe, it, expect } from 'vitest';
import { sanitizeCampaignMap } from '../state/campaigns';

describe('sanitizeCampaignMap (shared-store poisoning / UI-DoS guard)', () => {
  it('coerces a missing/invalid name to a fallback and keeps valid entries', () => {
    const out = sanitizeCampaignMap({
      a: { id: 'a', iocs: {} }, // no name → fallback
      b: { id: 'b', name: 123 as unknown as string, iocs: {} }, // non-string name → fallback
      c: { id: 'c', name: 'Real', iocs: { x: {} } }, // valid → unchanged name
    });
    expect(out.a.name).toMatch(/^\(unnamed/);
    expect(out.b.name).toMatch(/^\(unnamed/);
    expect(out.c.name).toBe('Real');
    expect(out.c.iocs).toEqual({ x: {} });
  });

  it('drops non-object / garbage entries', () => {
    const out = sanitizeCampaignMap({ a: null, b: 5, c: 'str', d: [], e: { id: 'e', name: 'ok', iocs: {} } });
    expect(Object.keys(out)).toEqual(['e']);
  });

  it('returns {} for a non-object payload', () => {
    expect(sanitizeCampaignMap(null)).toEqual({});
    expect(sanitizeCampaignMap([1, 2])).toEqual({});
    expect(sanitizeCampaignMap('x')).toEqual({});
  });

  it('sorting the result by name never throws (the reported crash is impossible)', () => {
    const out = sanitizeCampaignMap({ a: { id: 'a', iocs: {} }, z: { id: 'z', name: 'Zed', iocs: {} } });
    expect(() => Object.values(out).sort((x, y) => x.name.localeCompare(y.name))).not.toThrow();
  });
});
