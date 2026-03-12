/**
 * HISTORY tests — Job History page: table renders, search filters, status
 * dropdown, refresh, clicking a row opens job in Dashboard panel, pagination.
 *
 * Covers: HIST-01 through HIST-07 in the test plan.
 *
 * Strategy: seed one job via the API directly (faster than running the full
 * pipeline) so history tests aren't dependent on pipeline completion time.
 */

const { test, expect } = require('@playwright/test');
const { login, goToView, uploadFile, SAMPLE_XML } = require('./helpers');

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Submit a job through the UI and wait until the stepper appears,
 * confirming a job_id was created. Returns the job_id extracted from the URL
 * or page state (if exposed).
 */
async function seedJob(page, overrides = {}) {
  await goToView(page, 'dashboard');
  await page.locator('#tabFiles').click();
  await uploadFile(page, '#fileInput', SAMPLE_XML);

  await page.fill('#submitterName',  overrides.name  || 'History Tester');
  await page.fill('#submitterTeam',  overrides.team  || 'QA Team');
  await page.fill('#submitterNotes', overrides.notes || 'HIST-ticket-001');

  await page.locator('#startBtn').click();
  await page.waitForSelector('.stepper', { timeout: 15_000 });
}

// ─── HIST-01: History table loads ─────────────────────────────────────────────
test('HIST-01: job history table shows submitted jobs', async ({ page }) => {
  await login(page, 'Asin D');

  // Seed a job so history is non-empty
  await seedJob(page, { name: 'HIST Tester', team: 'QA', notes: 'HIST-01' });

  await goToView(page, 'history');

  // Table header columns present
  await expect(page.locator('#panelHistory')).toBeVisible();
  await expect(page.locator('#historyTableBody tr')).not.toHaveCount(0);

  // Count element updated
  const countEl = page.locator('#historyCount');
  await expect(countEl).not.toHaveText('–');
});

// ─── HIST-01b: Column headers present ────────────────────────────────────────
test('HIST-01b: history table has all required column headers', async ({ page }) => {
  await login(page, 'Asin D');
  await goToView(page, 'history');

  const headers = page.locator('#panelHistory thead th');
  await expect(headers).toHaveCount(8);

  const texts = await headers.allTextContents();
  const expected = ['Filename', 'Submitter', 'Team', 'Ticket', 'Status', 'Tier', 'Submitted'];
  for (const col of expected) {
    expect(texts.some(t => t.toLowerCase().includes(col.toLowerCase())),
      `Expected column "${col}" in table headers`).toBe(true);
  }
});

// ─── HIST-02: Search filters rows ─────────────────────────────────────────────
test('HIST-02: search input filters history rows', async ({ page }) => {
  await login(page, 'Asin D');

  // Seed two jobs with distinct submitter names
  await seedJob(page, { name: 'AlphaUser', team: 'TeamA', notes: 'alpha-note' });
  await seedJob(page, { name: 'BetaUser',  team: 'TeamB', notes: 'beta-note'  });

  await goToView(page, 'history');

  // Search for "AlphaUser"
  await page.fill('#histSearchInput', 'AlphaUser');

  // Give filter a tick
  await page.waitForTimeout(500);

  const rows = page.locator('#historyTableBody tr');
  const count = await rows.count();
  expect(count).toBeGreaterThan(0);

  for (let i = 0; i < count; i++) {
    const rowText = await rows.nth(i).textContent();
    // Rows shown must contain the search term somewhere
    expect(rowText?.toLowerCase()).toContain('alphauser');
  }
});

// ─── HIST-03: Status dropdown filters ─────────────────────────────────────────
test('HIST-03: status filter dropdown narrows results', async ({ page }) => {
  await login(page, 'Asin D');
  await goToView(page, 'history');

  // Select "Complete" — with clean DB and no completed jobs, table should be empty
  await page.selectOption('#histStatusFilter', 'complete');
  await page.waitForTimeout(400);

  const rows = page.locator('#historyTableBody tr');
  const count = await rows.count();

  if (count > 0) {
    for (let i = 0; i < count; i++) {
      const rowText = await rows.nth(i).textContent();
      expect(rowText?.toLowerCase()).toContain('complete');
    }
  } else {
    // Empty result row
    const emptyText = await rows.first().textContent();
    expect(emptyText).toBeTruthy();
  }
});

// ─── HIST-03b: Clearing filter restores all rows ──────────────────────────────
test('HIST-03b: clearing status filter restores all rows', async ({ page }) => {
  await login(page, 'Asin D');
  await seedJob(page);

  await goToView(page, 'history');
  const allRowsBefore = await page.locator('#historyTableBody tr').count();

  // Apply a restrictive filter
  await page.selectOption('#histStatusFilter', 'complete');
  await page.waitForTimeout(300);

  // Reset
  await page.selectOption('#histStatusFilter', '');
  await page.waitForTimeout(300);

  const allRowsAfter = await page.locator('#historyTableBody tr').count();
  expect(allRowsAfter).toBe(allRowsBefore);
});

// ─── HIST-04: Refresh button reloads data ─────────────────────────────────────
test('HIST-04: refresh button triggers a reload', async ({ page }) => {
  await login(page, 'Asin D');
  await goToView(page, 'history');

  const refreshBtn = page.locator('#panelHistory button', { hasText: '🔄' });
  await expect(refreshBtn).toBeVisible();

  // Intercept the /jobs API call to confirm it fires on refresh
  const [request] = await Promise.all([
    page.waitForRequest(req => req.url().includes('/jobs')),
    refreshBtn.click(),
  ]);
  expect(request).toBeTruthy();
});

// ─── HIST-05: Clicking a row opens the job in Dashboard panel ────────────────
test('HIST-05: clicking a history row opens job in dashboard panel', async ({ page }) => {
  await login(page, 'Asin D');
  await seedJob(page, { name: 'ClickTester', notes: 'HIST-05' });

  await goToView(page, 'history');
  await page.waitForSelector('#historyTableBody tr', { timeout: 5_000 });

  // Click the first data row
  const firstRow = page.locator('#historyTableBody tr').first();
  await firstRow.click();

  // Dashboard panel should now be visible
  await page.waitForSelector('#panelDashboard:visible', { timeout: 8_000 });
  await expect(page.locator('#panelDashboard')).toBeVisible();
  await expect(page.locator('#panelHistory')).not.toBeVisible();
});

// ─── HIST-06: "View" button also opens job ───────────────────────────────────
test('HIST-06: View button in Actions column opens job in dashboard', async ({ page }) => {
  await login(page, 'Asin D');
  await seedJob(page, { notes: 'HIST-06' });

  await goToView(page, 'history');
  await page.waitForSelector('#historyTableBody tr');

  const viewBtn = page.locator('#historyTableBody tr').first().locator('button', { hasText: 'View' });
  await viewBtn.click();

  await page.waitForSelector('#panelDashboard:visible', { timeout: 8_000 });
  await expect(page.locator('#panelDashboard')).toBeVisible();
});

// ─── HIST-07: Pagination controls exist ──────────────────────────────────────
test('HIST-07: pagination controls are rendered', async ({ page }) => {
  await login(page, 'Asin D');
  await goToView(page, 'history');

  await expect(page.locator('#histPrevBtn')).toBeVisible();
  await expect(page.locator('#histNextBtn')).toBeVisible();
  await expect(page.locator('#histPageInfo')).toBeVisible();
});
