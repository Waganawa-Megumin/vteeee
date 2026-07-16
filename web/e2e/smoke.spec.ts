import { test, expect, type Page } from '@playwright/test';

// Seed an authenticated admin session BEFORE the app boots, so we land on the real UI (not the login
// screen) without needing a proxy. addInitScript runs before the page's own scripts.
async function openApp(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const s = { username: 'admin', role: 'admin', token: 'e2e', expiresAt: Date.now() + 3_600_000 };
    try {
      sessionStorage.setItem('vteeee.session', JSON.stringify(s));
    } catch {
      /* ignore */
    }
  });
  await page.goto('/');
  await expect(page.locator('header.topbar')).toBeVisible();
}

test.beforeEach(async ({ page }) => {
  await openApp(page);
});

test('boots to the main app (topbar + brand render, not the login screen)', async ({ page }) => {
  await expect(page.locator('.brand')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Settings' })).toBeVisible();
  await expect(page.locator('.login')).toHaveCount(0);
});

test('Settings dialog opens and closes via the ✕ button', async ({ page }) => {
  await page.getByRole('button', { name: 'Settings' }).click();
  const modal = page.locator('.settings-modal');
  await expect(modal).toBeVisible();
  // The ✕ lives in the pinned header; clicking it must dismiss the dialog.
  await modal.locator('.modal-head button').click();
  await expect(page.locator('.settings-modal')).toHaveCount(0);
});

test('opening Settings never makes the page scroll horizontally', async ({ page }) => {
  await page.getByRole('button', { name: 'Settings' }).click();
  await expect(page.locator('.settings-modal')).toBeVisible();
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
  );
  expect(overflow).toBe(false);
});

test('mobile: Settings is a full-screen sheet with the ✕ inside the viewport', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'mobile', 'mobile-only layout regression guard');
  await page.getByRole('button', { name: 'Settings' }).click();
  const modal = page.locator('.settings-modal');
  await expect(modal).toBeVisible();
  const vw = page.viewportSize()!.width;
  const box = (await modal.boundingBox())!;
  // Full-width sheet — not the 600px desktop dialog that used to overflow a phone and push ✕ off-screen.
  expect(box.width).toBeLessThanOrEqual(vw + 1);
  const x = (await modal.locator('.modal-head button').boundingBox())!;
  expect(x.x + x.width).toBeLessThanOrEqual(vw); // ✕ fully within the viewport → reachable
  await modal.locator('.modal-head button').click();
  await expect(page.locator('.settings-modal')).toHaveCount(0);
});

test('Manage stays labeled "Manage" and toggles active (not relabeled to "Search")', async ({ page }) => {
  const manage = page.getByRole('button', { name: 'Manage', exact: true });
  await expect(manage).toBeVisible();
  await expect(manage).not.toHaveAttribute('aria-current', 'page');
  await manage.click();
  const active = page.getByRole('button', { name: 'Manage', exact: true });
  await expect(active).toHaveAttribute('aria-current', 'page'); // still "Manage", now highlighted
  await expect(page.getByRole('button', { name: 'Search', exact: true })).toHaveCount(0);
  await active.click(); // toggles back to search
  await expect(page.getByRole('button', { name: 'Manage', exact: true })).not.toHaveAttribute('aria-current', 'page');
});

test('primary nav: IP-Mon / CP-Mon open and TOP returns home', async ({ page }) => {
  const top = page.locator('button.nav-top'); // the topbar 🏠 TOP (not the breadcrumb's TOP link)
  // Leaving 'app' shows the breadcrumb trail; TOP takes us home again.
  await page.getByRole('button', { name: /^IP-Mon/ }).click();
  await expect(page.locator('.breadcrumbs')).toBeVisible();
  await top.click();
  await expect(page.locator('.breadcrumbs')).toHaveCount(0);
  await page.getByRole('button', { name: /^CP-Mon/ }).click();
  await expect(page.locator('.breadcrumbs')).toBeVisible();
  await top.click();
  await expect(page.locator('.breadcrumbs')).toHaveCount(0);
});
