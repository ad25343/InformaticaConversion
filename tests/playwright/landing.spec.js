/**
 * LANDING PAGE tests — greeting, action cards, live stats, navigation from cards.
 *
 * Covers: LAND-01 through LAND-07 in the test plan.
 */

const { test, expect } = require('@playwright/test');
const { login, goToView } = require('./helpers');

// ─── LAND-01: Personalised greeting ──────────────────────────────────────────
test('LAND-01: greeting shows first name of signed-in persona', async ({ page }) => {
  await login(page, 'Maya Patel');
  // Landing page is the default after login
  await expect(page.locator('#landingGreeting')).toBeVisible();
  await expect(page.locator('#landingGreeting')).toContainText('Maya');
});

test('LAND-01b: greeting includes time-of-day salutation', async ({ page }) => {
  await login(page, 'Sarah Chen');
  const greeting = await page.locator('#landingGreeting').textContent();
  const hasTimeOfDay = /Good morning|Good afternoon|Good evening/i.test(greeting || '');
  expect(hasTimeOfDay).toBe(true);
});

// ─── LAND-02: Three action cards ─────────────────────────────────────────────
test('LAND-02: landing page shows three action cards', async ({ page }) => {
  await login(page, 'Aravind Doma');

  await expect(page.locator('.action-card')).toHaveCount(3);
  await expect(page.locator('.action-card').filter({ hasText: 'Submit a Conversion' })).toBeVisible();
  await expect(page.locator('.action-card').filter({ hasText: 'Review Queue' })).toBeVisible();
  await expect(page.locator('.action-card').filter({ hasText: 'Job History' })).toBeVisible();
});

// ─── LAND-03: Submit card navigates to dashboard ──────────────────────────────
test('LAND-03: Submit card navigates to Submit panel', async ({ page }) => {
  await login(page, 'Aravind Doma');

  await page.locator('.action-card').filter({ hasText: 'Submit a Conversion' }).click();
  await page.waitForSelector('#panelDashboard:visible', { timeout: 6_000 });

  await expect(page.locator('#panelDashboard')).toBeVisible();
  await expect(page.locator('#panelLanding')).not.toBeVisible();

  // Active nav tab should be Submit
  const dashBtn = page.locator('#navDashboard');
  const borderColor = await dashBtn.evaluate(el => el.style.borderBottomColor);
  expect(borderColor).not.toBe('transparent');
});

// ─── LAND-04: Review Queue card navigates to review ───────────────────────────
test('LAND-04: Review Queue card navigates to Review Queue panel', async ({ page }) => {
  await login(page, 'Sarah Chen');

  await page.locator('.action-card').filter({ hasText: 'Review Queue' }).click();
  await page.waitForSelector('#panelReview:visible', { timeout: 6_000 });

  await expect(page.locator('#panelReview')).toBeVisible();
  await expect(page.locator('#panelLanding')).not.toBeVisible();
});

// ─── LAND-05: Job History card navigates to history ───────────────────────────
test('LAND-05: Job History card navigates to Job History panel', async ({ page }) => {
  await login(page, 'James Park');

  await page.locator('.action-card').filter({ hasText: 'Job History' }).click();
  await page.waitForSelector('#panelHistory:visible', { timeout: 6_000 });

  await expect(page.locator('#panelHistory')).toBeVisible();
  await expect(page.locator('#panelLanding')).not.toBeVisible();
});

// ─── LAND-06: Live stats tiles render ─────────────────────────────────────────
test('LAND-06: stats tiles show numeric values after load', async ({ page }) => {
  await login(page, 'Aravind Doma');

  // Stats fire an async fetch; wait for them to populate (leave "–")
  await page.waitForFunction(() => {
    const el = document.getElementById('lsTotal');
    return el && el.textContent !== '–';
  }, null, { timeout: 8_000 });

  // All four tiles should now have numeric text
  for (const id of ['#lsTotal', '#lsRunning', '#lsComplete', '#lsPending']) {
    const text = await page.locator(id).textContent();
    expect(text).toMatch(/^\d+$/);
  }
});

// ─── LAND-07: Home nav button always returns to landing ───────────────────────
test('LAND-07: Home nav button returns to landing from any view', async ({ page }) => {
  await login(page, 'Aravind Doma');

  const views = [
    { nav: '#navDashboard', panel: '#panelDashboard' },
    { nav: '#navHistory',   panel: '#panelHistory'   },
    { nav: '#navReview',    panel: '#panelReview'    },
  ];

  for (const { nav, panel } of views) {
    await page.click(nav);
    await page.waitForSelector(panel + ':visible');

    await page.click('#navHome');
    await page.waitForSelector('#panelLanding:visible', { timeout: 6_000 });

    await expect(page.locator('#panelLanding')).toBeVisible();
    await expect(page.locator('#landingGreeting')).toBeVisible();
  }
});

// ─── LAND: Landing page is the first view after login (not dashboard) ─────────
test('LAND: landing page is default view after login', async ({ page }) => {
  await login(page, 'Maya Patel');

  await expect(page.locator('#panelLanding')).toBeVisible();
  await expect(page.locator('#panelDashboard')).not.toBeVisible();
  await expect(page.locator('#panelHistory')).not.toBeVisible();
  await expect(page.locator('#panelReview')).not.toBeVisible();
});
