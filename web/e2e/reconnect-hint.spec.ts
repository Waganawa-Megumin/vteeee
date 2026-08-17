import { test, expect, type Page } from '@playwright/test';

// Reproduces the "久々に開いたら消えてます" report: a browser "clear site data / clear cache" wipes
// localStorage + IndexedDB, so the access token is gone while the baked proxy URL is restored from the
// build. The shared fetches then 401 and CP-Mon/IP-Mon render empty — which reads as data loss even
// though the team's data is safe on the proxy. The ReconnectHint must appear in exactly that state and
// point the user to Settings, and must NOT appear once a token is present (they're connected).

async function boot(page: Page, settings: Record<string, unknown>): Promise<void> {
  await page.addInitScript((s) => {
    const sess = { username: 'admin', role: 'admin', token: 'e2e', expiresAt: Date.now() + 3_600_000 };
    try {
      sessionStorage.setItem('vteeee.session', JSON.stringify(sess));
      localStorage.setItem('vteeee.settings', JSON.stringify({ version: 1, settings: s }));
    } catch {
      /* ignore */
    }
  }, settings);
  await page.goto('/');
  await expect(page.locator('header.topbar')).toBeVisible();
}

// A proxy URL that fails fast. The hint is driven purely by settings (proxyBaseUrl set + no token), not
// by fetch results, so a dead proxy doesn't affect what we assert — it just guarantees an empty list.
const DEAD_PROXY = 'http://127.0.0.1:9';

test('CP-Mon: proxy set + NO access token → reconnect hint shows and points to Settings', async ({ page }) => {
  await boot(page, { proxyBaseUrl: DEAD_PROXY, shareMonitors: true }); // token wiped by a site-data clear
  await page.getByRole('button', { name: /^CP-Mon/ }).click();
  const hint = page.locator('.reconnect-hint');
  await expect(hint).toBeVisible();
  await expect(hint).toContainText('アクセストークン');
  await expect(hint).toContainText('消えていません'); // reassures that data is safe on the proxy
});

test('CP-Mon: proxy set + access token present → reconnect hint is hidden (connected)', async ({ page }) => {
  await boot(page, { proxyBaseUrl: DEAD_PROXY, accessToken: 'secret', shareMonitors: true });
  await page.getByRole('button', { name: /^CP-Mon/ }).click();
  await expect(page.locator('.cp-empty')).toBeVisible(); // empty screen still renders (dead proxy)…
  await expect(page.locator('.reconnect-hint')).toHaveCount(0); // …but the hint must NOT nag a connected user
});

test('demo (no proxy): reconnect hint stays hidden — nothing to reconnect to', async ({ page }) => {
  await boot(page, { proxyBaseUrl: null, shareMonitors: true });
  await page.getByRole('button', { name: /^CP-Mon/ }).click();
  await expect(page.locator('.cp-empty')).toBeVisible();
  await expect(page.locator('.reconnect-hint')).toHaveCount(0);
});
