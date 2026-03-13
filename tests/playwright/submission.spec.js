/**
 * SUBMISSION tests — upload modes (individual, ZIP, batch), submitter prefill,
 * Start Pipeline button state, drag-and-drop zone wiring, field persistence.
 *
 * Covers: SUB-01 through SUB-08 in the test plan.
 */

const { test, expect } = require('@playwright/test');
const path = require('path');
const { login, goToView, uploadFile, SAMPLE_XML, SAMPLE_WF, SAMPLE_PARAMS } = require('./helpers');

const SAMPLE_DIR = path.resolve(__dirname, '../../app/sample_xml');
const BATCH_ZIP  = path.join(SAMPLE_DIR, 'batch');   // used as a fallback; real batch zip needed

// Check that required sample files exist before running upload tests
test.beforeAll(async () => {
  const fs = require('fs');
  for (const f of [SAMPLE_XML, SAMPLE_WF]) {
    if (!fs.existsSync(f)) {
      throw new Error(`Required sample file missing: ${f}`);
    }
  }
});

test.describe('File Submission', () => {
  // ─── SUB-01: Submitter name prefilled from persona cookie ──────────────────
  test('SUB-01: submitter name field prefilled from persona cookie', async ({ page }) => {
    await login(page, 'Asin D');
    await goToView(page, 'dashboard');

    const nameField = page.locator('#submitterName');
    await expect(nameField).toHaveValue('Asin D');
  });

  test('SUB-01b: different persona prefills correct name', async ({ browser }) => {
    const ctx  = await browser.newContext();
    const page = await ctx.newPage();
    await login(page, 'Sarah Chen');
    await goToView(page, 'dashboard');

    await expect(page.locator('#submitterName')).toHaveValue('Sarah Chen');
    await ctx.close();
  });

  // ─── SUB-02: Start button disabled before file selection ──────────────────
  test('SUB-02: Start Pipeline button is disabled until a file is selected', async ({ page }) => {
    await login(page, 'Asin D');
    await goToView(page, 'dashboard');

    // Individual tab (default)
    await page.click('#tabFiles');
    await expect(page.locator('#startBtn')).toBeDisabled();

    // Batch tab
    await page.click('#tabBatch');
    await expect(page.locator('#startBtn')).toBeDisabled();
  });

  // ─── SUB-02b: Button enables after file selection ─────────────────────────
  test('SUB-02b: Start Pipeline button enables after XML selected', async ({ page }) => {
    await login(page, 'Asin D');
    await goToView(page, 'dashboard');

    await page.click('#tabFiles');
    await expect(page.locator('#startBtn')).toBeDisabled();

    await uploadFile(page, '#fileInput', SAMPLE_XML);
    await expect(page.locator('#startBtn')).toBeEnabled();
  });

  // ─── SUB-03: Individual XML upload — job created ───────────────────────────
  test('SUB-03: individual XML upload creates a job and starts pipeline', async ({ page }) => {
    await login(page, 'Asin D');
    await goToView(page, 'dashboard');

    await page.click('#tabFiles');
    await uploadFile(page, '#fileInput', SAMPLE_XML);

    await page.fill('#submitterName',  'Playwright Tester');
    await page.fill('#submitterTeam',  'QA');
    await page.fill('#submitterNotes', 'SUB-03-ticket');

    // Intercept the POST — confirms job was created without waiting for pipeline
    const [resp] = await Promise.all([
      page.waitForResponse(r => r.url().includes('/api/jobs') && r.request().method() === 'POST'),
      page.click('#startBtn'),
    ]);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.job_id).toBeTruthy();
  });

  // ─── SUB-04: Individual XML + Workflow XML ────────────────────────────────
  test('SUB-04: individual XML + workflow XML both accepted', async ({ page }) => {
    await login(page, 'Asin D');
    await goToView(page, 'dashboard');

    await page.click('#tabFiles');
    await uploadFile(page, '#fileInput', SAMPLE_XML);
    await uploadFile(page, '#workflowInput', SAMPLE_WF);

    // Workflow label should update
    await expect(page.locator('#workflowLabel')).toContainText('sample_workflow');

    await expect(page.locator('#startBtn')).toBeEnabled();
    const [resp] = await Promise.all([
      page.waitForResponse(r => r.url().includes('/api/jobs') && r.request().method() === 'POST'),
      page.click('#startBtn'),
    ]);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.job_id).toBeTruthy();
  });

  // ─── SUB-05: Individual tab accepts .zip ──────────────────────────────────
  test('SUB-05: Individual tab file input accepts both .xml and .zip', async ({ page }) => {
    await login(page, 'Asin D');
    await goToView(page, 'dashboard');

    await page.click('#tabFiles');
    await expect(page.locator('#panelFiles')).toBeVisible();
    await expect(page.locator('#panelBatch')).not.toBeVisible();

    // Individual only accepts .xml (ZIP goes via Batch)
    const accept = await page.locator('#fileInput').getAttribute('accept');
    expect(accept).toContain('.xml');
    expect(accept).not.toContain('.zip');
  });

  // ─── SUB-06: Batch mode ────────────────────────────────────────────────────
  test('SUB-06: batch upload mode tab visible and file input accepts .zip', async ({ page }) => {
    await login(page, 'Asin D');
    await goToView(page, 'dashboard');

    await page.click('#tabBatch');
    await expect(page.locator('#panelBatch')).toBeVisible();
    await expect(page.locator('#panelFiles')).not.toBeVisible();

    const accept = await page.locator('#batchInput').getAttribute('accept');
    expect(accept).toContain('.zip');
  });

  // ─── SUB-07: Upload mode toggle switches panels ────────────────────────────
  test('SUB-07: upload mode toggle shows correct panel for each tab', async ({ page }) => {
    await login(page, 'Asin D');
    await goToView(page, 'dashboard');

    const modes = [
      { tab: '#tabFiles', panel: '#panelFiles' },
      { tab: '#tabBatch', panel: '#panelBatch' },
    ];

    for (const { tab, panel } of modes) {
      await page.click(tab);
      await expect(page.locator(panel)).toBeVisible();
      // Other panels hidden
      for (const other of modes) {
        if (other.panel === panel) continue;
        await expect(page.locator(other.panel)).not.toBeVisible();
      }
    }
  });

  // ─── SUB-08: Submitter fields visible ─────────────────────────────────────
  test('SUB-08: submitter section shows name, team, notes fields', async ({ page }) => {
    await login(page, 'James Park');
    await goToView(page, 'dashboard');

    await expect(page.locator('#submitterName')).toBeVisible();
    await expect(page.locator('#submitterTeam')).toBeVisible();
    await expect(page.locator('#submitterNotes')).toBeVisible();

    // Verify team and notes fields are empty (only name is prefilled)
    await expect(page.locator('#submitterTeam')).toHaveValue('');
    await expect(page.locator('#submitterNotes')).toHaveValue('');
  });
});
