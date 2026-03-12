// @ts-check
const { defineConfig, devices } = require('@playwright/test');

/**
 * Informatica Conversion Tool — Playwright configuration
 *
 * Run all tests:   npx playwright test
 * Run one suite:   npx playwright test tests/playwright/auth.spec.js
 * Show report:     npx playwright show-report
 * UI mode:         npx playwright test --ui
 */

module.exports = defineConfig({
  testDir: './tests/playwright',
  timeout:        60_000,   // per-test timeout (pipeline steps can be slow)
  expect: { timeout: 10_000 },
  fullyParallel:  true,
  retries:        1,        // one retry on flaky network ops
  workers:        4,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'tests/playwright/report', open: 'never' }],
  ],
  use: {
    baseURL:       'http://localhost:8000',
    headless:      true,
    screenshot:    'only-on-failure',
    video:         'retain-on-failure',
    trace:         'on-first-retry',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
});
