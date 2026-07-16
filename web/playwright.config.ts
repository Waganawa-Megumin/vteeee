import { defineConfig, devices } from '@playwright/test';

// End-to-end smoke tests: boot the built app in a real browser and drive the flows that are easy to
// break by accident and impossible to catch with unit tests — navigation, modals opening/closing, and
// mobile layout (the "Settings unclosable on a phone" class of bug). Runs against `vite preview` of the
// production build. In CI a matching Chromium is installed; locally it uses the environment's browser
// at PLAYWRIGHT_BROWSERS_PATH (pinned to the same version as the preinstalled build).
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  timeout: 30_000,
  expect: { timeout: 8_000 },
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'on-first-retry',
    // Local/CI browser resolution: CI runs `playwright install chromium` so the bundled build is found
    // automatically (leave PW_CHROMIUM unset). In a sandbox that ships a different Chromium revision,
    // set PW_CHROMIUM to its binary to run without a download.
    ...(process.env.PW_CHROMIUM ? { launchOptions: { executablePath: process.env.PW_CHROMIUM } } : {}),
  },
  // Serve the production build. Assumes `pnpm --filter @vteeee/web build` ran first (CI does; the
  // test:e2e npm script chains it locally). reuseExistingServer keeps local iteration fast.
  webServer: {
    command: 'vite preview --port 4173 --strictPort',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
  projects: [
    // Plain chromium (bundled) at a desktop viewport — NOT devices['Desktop Chrome'], which pins
    // channel:'chrome' (system Chrome, absent in CI).
    { name: 'desktop', use: { browserName: 'chromium', viewport: { width: 1280, height: 900 } } },
    { name: 'mobile', use: { ...devices['Pixel 5'] } },
  ],
});
