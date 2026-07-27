import { test, expect, type Page } from '@playwright/test';

// A poisoned shared/stored campaigns blob with a name-less entry used to crash every teammate's UI
// (name-sort → TypeError → ErrorBoundary, and it re-synced on reload = persistent DoS). loadCampaigns
// now sanitizes on read, so the poisoned blob loads with a fallback name and nothing crashes.
async function open(page: Page): Promise<void> {
  const now = Date.now();
  const session = { username: 'admin', role: 'admin', token: 'e2e', expiresAt: now + 3_600_000 };
  const poisoned = {
    good: { id: 'good', name: 'Good Campaign', createdAt: now, updatedAt: now, iocs: {} },
    bad: { id: 'bad', createdAt: now, updatedAt: now, iocs: {} }, // ← no `name` (poison)
  };
  await page.addInitScript(
    ([s, c]) => {
      try {
        sessionStorage.setItem('vteeee.session', s);
        localStorage.setItem('vteeee.campaigns', c);
      } catch {
        /* ignore */
      }
    },
    [JSON.stringify(session), JSON.stringify(poisoned)] as [string, string],
  );
  await page.goto('/');
  await expect(page.locator('header.topbar')).toBeVisible();
}

test('a name-less campaign in the store does not crash the app (no ErrorBoundary)', async ({ page }) => {
  await open(page);
  // App booted normally — the top-level ErrorBoundary fallback is NOT shown.
  await expect(page.locator('.errbound')).toHaveCount(0);
  // CP-Mon opens and lists BOTH campaigns; the poisoned one shows a safe fallback name, not a crash.
  await page.getByRole('button', { name: /^CP-Mon/ }).click();
  await expect(page.locator('.errbound')).toHaveCount(0);
  await expect(page.locator('.cp-card', { hasText: 'Good Campaign' })).toBeVisible();
  await expect(page.locator('.cp-card', { hasText: 'unnamed' })).toBeVisible();
});
