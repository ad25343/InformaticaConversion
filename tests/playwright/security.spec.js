/**
 * SECURITY tests — unauthenticated API access, HTTP security headers,
 * health endpoint, non-XML upload rejection, empty XML handling.
 *
 * Covers: SEC-01 through SEC-06 in the test plan.
 */

const { test, expect } = require('@playwright/test');
const { login, BASE_URL } = require('./helpers');

// ─── SEC-01: Unauthenticated API returns 401 / redirects ─────────────────────
test('SEC-01: /jobs API requires authentication', async ({ request }) => {
  // Make a raw request with no cookies
  const res = await request.get(`${BASE_URL}/jobs`);
  // Should be 401 or 302 redirect to /login
  expect([401, 302, 303]).toContain(res.status());
});

test('SEC-01b: / requires authentication (no browser redirect loop)', async ({ request }) => {
  const res = await request.get(`${BASE_URL}/`, { maxRedirects: 0 });
  expect([302, 303]).toContain(res.status());
  expect(res.headers()['location']).toContain('/login');
});

// ─── SEC-04: Health endpoint public ──────────────────────────────────────────
test('SEC-04: /health returns 200 without authentication', async ({ request }) => {
  const res = await request.get(`${BASE_URL}/health`);
  expect(res.status()).toBe(200);

  const body = await res.json();
  expect(body.status).toBe('ok');
  expect(body.db).toBe('ok');
  expect(typeof body.uptime_seconds).toBe('number');
  expect(typeof body.version).toBe('string');
});

// ─── SEC-05: HTTP security headers ───────────────────────────────────────────
test('SEC-05: security headers present on login page response', async ({ request }) => {
  const res = await request.get(`${BASE_URL}/login`);
  const headers = res.headers();

  expect(headers['x-content-type-options']).toBe('nosniff');
  expect(headers['x-frame-options']).toBe('DENY');
  expect(headers['x-xss-protection']).toMatch(/1/);
  expect(headers['referrer-policy']).toBeTruthy();
  expect(headers['permissions-policy']).toBeTruthy();
  expect(headers['content-security-policy']).toBeTruthy();
});

test('SEC-05b: security headers present on authenticated main page', async ({ browser }) => {
  const ctx  = await browser.newContext();
  const page = await ctx.newPage();
  await login(page, 'Aravind Doma');

  const res = await ctx.request.get(`${BASE_URL}/`);
  const headers = res.headers();

  expect(headers['x-content-type-options']).toBe('nosniff');
  expect(headers['x-frame-options']).toBe('DENY');
  expect(headers['content-security-policy']).toBeTruthy();

  await ctx.close();
});

// ─── SEC-02: Non-XML file input restricted ────────────────────────────────────
test('SEC-02: mapping file input only accepts .xml', async ({ page }) => {
  await login(page, 'Aravind Doma');
  await page.click('#navDashboard');
  await page.waitForSelector('#panelDashboard:visible');

  await page.click('#tabFiles');
  const accept = await page.locator('#fileInput').getAttribute('accept');
  expect(accept).toContain('.xml');
  expect(accept).not.toContain('.pdf');
  expect(accept).not.toContain('.exe');
});

// ─── SEC-02b: ZIP and batch inputs also restricted ────────────────────────────
test('SEC-02b: ZIP and batch inputs only accept .zip', async ({ page }) => {
  await login(page, 'Aravind Doma');
  await page.click('#navDashboard');
  await page.waitForSelector('#panelDashboard:visible');

  for (const id of ['#zipInput', '#batchInput']) {
    await page.click(id === '#zipInput' ? '#tabZip' : '#tabBatch');
    const accept = await page.locator(id).getAttribute('accept');
    expect(accept).toContain('.zip');
    expect(accept).not.toContain('.exe');
  }
});

// ─── SEC-06: Submitting jobs with same filename creates distinct records ───────
test('SEC-06: duplicate filename submissions produce separate job IDs', async ({ page }) => {
  const { uploadFile, SAMPLE_XML, goToView } = require('./helpers');

  await login(page, 'Aravind Doma');

  // Submit once
  await goToView(page, 'dashboard');
  await page.click('#tabFiles');
  await uploadFile(page, '#fileInput', SAMPLE_XML);
  await page.click('#startBtn');
  await page.waitForSelector('.stepper', { timeout: 15_000 });

  // Capture first job ID from URL or page if available, or just check history count
  await page.click('#navHistory');
  await page.waitForSelector('#historyTableBody tr');
  const countAfterFirst = await page.locator('#historyTableBody tr').count();

  // Submit again with same file
  await goToView(page, 'dashboard');
  await page.click('#tabFiles');
  await uploadFile(page, '#fileInput', SAMPLE_XML);
  await page.click('#startBtn');
  await page.waitForSelector('.stepper', { timeout: 15_000 });

  await page.click('#navHistory');
  await page.waitForSelector('#historyTableBody tr');
  const countAfterSecond = await page.locator('#historyTableBody tr').count();

  // Should have one more row (a new distinct job)
  expect(countAfterSecond).toBeGreaterThan(countAfterFirst);
});

// ─── SEC-03: Empty/invalid XML causes graceful failure ────────────────────────
test.skip('SEC-03: empty XML fails at parse step with error card (requires file I/O)', async ({ page }) => {
  // Create an empty .xml file, upload it, assert job fails with an error card.
  // Skipped by default; enable when running integration tests.
});
