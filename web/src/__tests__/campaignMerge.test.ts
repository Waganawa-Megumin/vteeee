import { describe, it, expect } from 'vitest';
import { mergeCampaign, mergeCampaigns, type Campaign, type CampaignIoc } from '../state/campaigns';

const now = Date.now();
function ioc(value: string, over: Partial<CampaignIoc> = {}): CampaignIoc {
  return { value, type: 'ipv4', addedAt: now - 1000, updatedAt: now - 1000, ...over };
}
function camp(id: string, over: Partial<Campaign> = {}): Campaign {
  return { id, name: id, createdAt: now - 2000, updatedAt: now - 2000, iocs: {}, ...over };
}

describe('campaign sync merge (non-destructive union)', () => {
  it('mergeCampaigns keeps campaigns that exist only on one side (no data loss)', () => {
    const local = { a: camp('a') };
    const remote = { b: camp('b') };
    const merged = mergeCampaigns(local, remote);
    expect(Object.keys(merged).sort()).toEqual(['a', 'b']);
  });

  it('an empty local view can never wipe a remote campaign', () => {
    // Simulates the clobber race: a stale/empty client merges before writing back.
    const merged = mergeCampaigns({}, { x: camp('x') });
    expect(merged.x).toBeTruthy();
    expect(merged.x.name).toBe('x');
  });

  it('mergeCampaign unions IOCs from both sides of the same campaign', () => {
    const a = camp('c', { iocs: { '1.1.1.1': ioc('1.1.1.1') }, updatedAt: now });
    const b = camp('c', { iocs: { '2.2.2.2': ioc('2.2.2.2') }, updatedAt: now - 500 });
    const merged = mergeCampaign(a, b);
    expect(Object.keys(merged.iocs).sort()).toEqual(['1.1.1.1', '2.2.2.2']);
  });

  it('newer scalar fields (name/tlp) win by updatedAt', () => {
    const older = camp('c', { name: 'old', tlp: 'GREEN', updatedAt: now - 1000 });
    const newer = camp('c', { name: 'new', tlp: 'RED', updatedAt: now });
    const merged = mergeCampaign(older, newer);
    expect(merged.name).toBe('new');
    expect(merged.tlp).toBe('RED');
  });
});
