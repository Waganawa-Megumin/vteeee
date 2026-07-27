import { test, expect, type Page } from '@playwright/test';

// Verify the MarkdownLite href allowlist: a poisoned assessment body (shared store / LLM output) with a
// javascript: link renders INERT, while a normal https link stays a working link (UX preserved).
const MD = [
  '## Assessment',
  'Good: [open report](https://legit.example/report) — normal external link.',
  'Bad: [CLICK ME EVIL](javascript:alert(document.domain)) — must NOT be a link.',
].join('\n\n');

async function openAssessment(page: Page): Promise<void> {
  const now = Date.now();
  const session = { username: 'admin', role: 'admin', token: 'e2e', expiresAt: now + 3_600_000 };
  const campaigns = {
    c1: {
      id: 'c1',
      name: 'SecTest',
      createdAt: now,
      updatedAt: now,
      iocs: {},
      assessment: { text: MD, at: now, tlp: 'AMBER' },
      assessments: [{ text: MD, at: now, tlp: 'AMBER' }],
    },
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
    [JSON.stringify(session), JSON.stringify(campaigns)] as [string, string],
  );
  await page.goto('/');
  await expect(page.locator('header.topbar')).toBeVisible();
  await page.getByRole('button', { name: /^CP-Mon/ }).click();
  await page.locator('.cp-card', { hasText: 'SecTest' }).first().click(); // NOT the "+ New campaign" card
  await page.locator('button', { hasText: 'Assessment' }).click(); // tab has role="tab", match by tag+text
  await expect(page.locator('.cp-report-md')).toBeVisible();
}

test('MarkdownLite renders https links but neutralizes javascript: links', async ({ page }) => {
  await openAssessment(page);
  const md = page.locator('.cp-report-md');
  // Legit external link is a working anchor.
  await expect(md.locator('a[href="https://legit.example/report"]')).toBeVisible();
  // No active javascript: link anywhere in the rendered report.
  await expect(md.locator('a[href^="javascript:"]')).toHaveCount(0);
  // The dangerous link's label is preserved as inert text (content not lost, but not clickable).
  await expect(md.getByText('CLICK ME EVIL')).toBeVisible();
  await expect(md.locator('a', { hasText: 'CLICK ME EVIL' })).toHaveCount(0);
});
