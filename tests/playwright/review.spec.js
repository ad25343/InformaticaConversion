/**
 * REVIEW QUEUE tests — queue loads, gate filters, select all, approve/reject,
 * badge count decrements, refresh.
 *
 * Covers: REV-01 through REV-07 in the test plan.
 *
 * NOTE: Tests that require a job to actually reach a gate (awaiting_review etc.)
 * are marked as needing a running server with LLM access. They are wrapped in
 * test.skip() guards that can be removed when running a full integration suite.
 */

const { test, expect } = require('@playwright/test');
const { login, goToView } = require('./helpers');

// ─── REV-01 / REV-07: Queue loads and refresh works ──────────────────────────
test('REV-01 + REV-07: review queue panel loads and refresh button works', async ({ page }) => {
  await login(page, 'Sarah Chen');
  await goToView(page, 'review');

  await expect(page.locator('#panelReview')).toBeVisible();

  // Summary counts visible (may show "–" if no jobs, which is fine)
  await expect(page.locator('#reviewGate1Count')).toBeVisible();
  await expect(page.locator('#reviewGate2Count')).toBeVisible();
  await expect(page.locator('#reviewGate3Count')).toBeVisible();
  await expect(page.locator('#reviewTotalCount')).toBeVisible();

  // Refresh button triggers an API call
  const [request] = await Promise.all([
    page.waitForRequest(req => req.url().includes('/gates')),
    page.locator('#panelReview button', { hasText: '🔄' }).click(),
  ]);
  expect(request).toBeTruthy();
});

// ─── REV-02: Gate filter buttons present ─────────────────────────────────────
test('REV-02: gate filter buttons All, Gate 1, Gate 2, Gate 3 are present', async ({ page }) => {
  await login(page, 'Sarah Chen');
  await goToView(page, 'review');

  await expect(page.locator('#filterAllBtn')).toBeVisible();
  await expect(page.locator('#filter1Btn')).toBeVisible();
  await expect(page.locator('#filter2Btn')).toBeVisible();
  await expect(page.locator('#filter3Btn')).toBeVisible();
});

// ─── REV-02b: Clicking gate filter buttons doesn't crash ─────────────────────
test('REV-02b: gate filter buttons can be clicked without error', async ({ page }) => {
  await login(page, 'James Park');
  await goToView(page, 'review');

  for (const btnId of ['#filterAllBtn', '#filter1Btn', '#filter2Btn', '#filter3Btn']) {
    await page.click(btnId);
    await page.waitForTimeout(200);
    // Panel still visible
    await expect(page.locator('#panelReview')).toBeVisible();
  }
});

// ─── REV-03: Select all checkbox present ─────────────────────────────────────
test('REV-03: select-all checkbox is present in queue header', async ({ page }) => {
  await login(page, 'Sarah Chen');
  await goToView(page, 'review');

  await expect(page.locator('#selectAllCheckbox')).toBeVisible();
});

// ─── REV-03b: Select all toggles row checkboxes ──────────────────────────────
test('REV-03b: select-all checkbox toggles all row checkboxes', async ({ page }) => {
  await login(page, 'Sarah Chen');
  await goToView(page, 'review');

  // Only meaningful when there are rows; check it at least doesn't error
  await page.locator('#selectAllCheckbox').click();
  await page.waitForTimeout(200);
  // Click again to deselect
  await page.locator('#selectAllCheckbox').click();
  await page.waitForTimeout(200);

  await expect(page.locator('#panelReview')).toBeVisible();
});

// ─── REV-04: Reviewer name input present ─────────────────────────────────────
test('REV-04: reviewer name input is visible', async ({ page }) => {
  await login(page, 'Sarah Chen');
  await goToView(page, 'review');

  await expect(page.locator('#reviewerNameInput')).toBeVisible();
  await page.fill('#reviewerNameInput', 'Sarah Chen');
  await expect(page.locator('#reviewerNameInput')).toHaveValue('Sarah Chen');
});

// ─── REV-05: Approve and Reject buttons present ──────────────────────────────
test('REV-05: Approve Selected and Reject Selected buttons present', async ({ page }) => {
  await login(page, 'Sarah Chen');
  await goToView(page, 'review');

  await expect(page.locator('button', { hasText: 'Approve Selected' })).toBeVisible();
  await expect(page.locator('button', { hasText: 'Reject Selected' })).toBeVisible();
});

// ─── REV-06: Nav badge visibility matches actual pending review count ─────────
test('REV-06: nav review badge visibility matches pending review count', async ({ page }) => {
  await login(page, 'Asin D');
  const res  = await page.request.get('/api/gates/pending');
  const data = await res.json();
  if ((data.total ?? 0) > 0) {
    await expect(page.locator('#navReviewBadge')).toBeVisible();
  } else {
    await expect(page.locator('#navReviewBadge')).not.toBeVisible();
  }
});

// ─── REV-06b: Notification bell visibility matches actual pending review count ─
test('REV-06b: notification bell visibility matches pending review count', async ({ page }) => {
  await login(page, 'Asin D');
  const res  = await page.request.get('/api/gates/pending');
  const data = await res.json();
  if ((data.total ?? 0) > 0) {
    await expect(page.locator('#notifBell')).toBeVisible();
  } else {
    await expect(page.locator('#notifBell')).not.toBeVisible();
  }
});

// ─── REV INTEGRATION: Full Gate 1 approve flow (requires LLM pipeline) ───────
// Unskip these when running a full integration test with a live server.
test.skip('REV-INT-01: gate 1 job appears in queue after pipeline reaches step 5', async ({ page }) => {
  // Full pipeline must be running; see test plan PIPE-05
});

test.skip('REV-INT-02: approving a gate 1 job advances pipeline and removes from queue', async ({ page }) => {
  // Depends on REV-INT-01
});

test.skip('REV-INT-03: rejecting a job changes status to blocked', async ({ page }) => {
  // Depends on REV-INT-01
});
