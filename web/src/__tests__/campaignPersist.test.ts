import { describe, it, expect, beforeEach } from 'vitest';
import { saveCampaigns, loadCampaigns, type Campaign, type CampaignAssessment } from '../state/campaigns';

// A localStorage mock with a hard byte budget, so we can exercise the quota-resilient progressive save.
class QuotaLocalStorage {
  store = new Map<string, string>();
  constructor(private budget: number) {}
  private size(exceptKey?: string): number {
    let n = 0;
    for (const [k, v] of this.store) if (k !== exceptKey) n += k.length + v.length;
    return n;
  }
  getItem(k: string): string | null {
    return this.store.has(k) ? this.store.get(k)! : null;
  }
  setItem(k: string, v: string): void {
    if (this.size(k) + k.length + v.length > this.budget) {
      const e = new Error('quota exceeded');
      e.name = 'QuotaExceededError';
      throw e;
    }
    this.store.set(k, v);
  }
  removeItem(k: string): void {
    this.store.delete(k);
  }
  clear(): void {
    this.store.clear();
  }
}

function bigAssessment(at: number): CampaignAssessment {
  return { text: 'X'.repeat(8000), at, by: 'a', model: 'm', tlp: 'AMBER' };
}
function campaignWithBigHistory(id: string): Campaign {
  const now = 1_700_000_000_000;
  const assessments = Array.from({ length: 15 }, (_, i) => bigAssessment(now - i * 1000));
  return {
    id,
    name: `C-${id}`,
    createdAt: now,
    updatedAt: now,
    tlp: 'AMBER',
    iocs: {},
    assessment: assessments[0],
    assessments,
  };
}

describe('saveCampaigns quota resilience', () => {
  beforeEach(() => {
    // ~50KB budget — far smaller than 15 × 8KB reports, so the full blob cannot fit.
    (globalThis as unknown as { localStorage: QuotaLocalStorage }).localStorage = new QuotaLocalStorage(50_000);
  });

  it('still persists the campaign list when the full blob exceeds the quota (drops old reports first)', () => {
    const m = { c1: campaignWithBigHistory('c1'), c2: campaignWithBigHistory('c2') };
    saveCampaigns(m);
    const loaded = loadCampaigns();
    // The campaigns themselves must survive (so CP-Mon's count shows on reload) even though the full
    // 15-report history could not fit — older reports are trimmed from the local cache.
    expect(Object.keys(loaded).sort()).toEqual(['c1', 'c2']);
    expect(loaded.c1.name).toBe('C-c1');
    expect((loaded.c1.assessments?.length ?? 0)).toBeLessThan(15);
  });

  it('persists everything when it comfortably fits', () => {
    (globalThis as unknown as { localStorage: QuotaLocalStorage }).localStorage = new QuotaLocalStorage(5_000_000);
    const m = { c1: campaignWithBigHistory('c1') };
    saveCampaigns(m);
    const loaded = loadCampaigns();
    expect(Object.keys(loaded)).toEqual(['c1']);
    // slimForLocal caps the local cache to the latest 3 reports (the rest stay on the shared proxy).
    expect(loaded.c1.assessments?.length).toBe(3);
  });
});
