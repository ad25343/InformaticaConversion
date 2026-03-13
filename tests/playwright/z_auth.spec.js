/**
 * AUTH tests — login page, persona picker, session cookies, logout paths,
 * wrong password, rate limiting, unauthenticated redirect.
 *
 * Covers: AUTH-01 through AUTH-09 in the test plan.
 */

const { test, expect } = require('@playwright/test');
const { login, logout, PERSONAS, APP_PASSWORD } = require('./helpers');

// ─── AUTH-01: Login page structure ───────────────────────────────────────────
test('AUTH-01: login page shows 5 persona cards', async ({ page }) => {
  await page.goto('/login');

  const cards = page.locator('.persona-option');
  await expect(cards).toHaveCount(5);

  for (const p of PERSONAS) {
    await expect(page.locator('.persona-option').filter({ hasText: p.name })).toBeVisible();
    await expect(page.locator('.persona-option').filter({ hasText: p.role })).toBeVisible();
  }

  await expect(page.locator('input[name="password"]')).toBeVisible();
  await expect(page.locator('button[type="submit"]')).toBeVisible();
});

// ─── AUTH-02: Persona card selection highlight ────────────────────────────────
test('AUTH-02: selecting a persona card highlights it', async ({ page }) => {
  await page.goto('/login');

  for (const p of PERSONAS) {
    const card = page.locator('.persona-option').filter({ hasText: p.name });
    await card.click();
    await expect(card).toHaveClass(/selected/);

    // All other cards must NOT have selected class
    for (const other of PERSONAS) {
      if (other.name === p.name) continue;
      const otherCard = page.locator('.persona-option').filter({ hasText: other.name });
      await expect(otherCard).not.toHaveClass(/selected/);
    }
  }
});

// ─── AUTH-03: Correct password → landing page ─────────────────────────────────
test('AUTH-03: correct password logs in and shows landing page', async ({ page }) => {
  await login(page, 'Asin D');

  // Should be on the main app, not /login
  expect(page.url()).not.toContain('/login');

  // Landing page greeting visible
  await expect(page.locator('#landingGreeting')).toBeVisible();
  await expect(page.locator('#landingGreeting')).toContainText('Asin');

  // Session cookie present
  const cookies = await page.context().cookies();
  const sessionCookie = cookies.find(c => c.httpOnly && c.name !== 'persona');
  expect(sessionCookie).toBeTruthy();

  // Persona cookie present and readable
  const personaCookie = cookies.find(c => c.name === 'persona');
  expect(personaCookie).toBeTruthy();
  expect(decodeURIComponent(personaCookie.value)).toBe('Asin D');
});

// ─── AUTH-04: Wrong password → error banner ──────────────────────────────────
test('AUTH-04: wrong password shows error, stays on login page', async ({ page }) => {
  await page.goto('/login');
  const card = page.locator('.persona-option').filter({ hasText: 'Asin D' });
  await card.click();
  await page.fill('input[name="password"]', 'definitely-wrong-password-xyz');
  await page.click('button[type="submit"]');

  // Should redirect back to /login?error=1
  await page.waitForURL('**/login**');
  expect(page.url()).toContain('error');

  await expect(page.locator('#errorMsg')).toBeVisible();
  await expect(page.locator('#errorMsg')).toContainText('Incorrect');

  // No session cookie should be set
  const cookies = await page.context().cookies();
  const sessionCookie = cookies.find(c => c.httpOnly);
  expect(sessionCookie).toBeFalsy();
});

// ─── AUTH-05: All 5 personas can log in ──────────────────────────────────────
for (const persona of PERSONAS) {
  test(`AUTH-05: persona "${persona.name}" logs in successfully`, async ({ browser }) => {
    // Each persona gets its own isolated browser context (no shared cookies)
    const ctx  = await browser.newContext();
    const page = await ctx.newPage();

    await login(page, persona.name);

    // Greeting uses first name
    const firstName = persona.name.split(' ')[0];
    await expect(page.locator('#landingGreeting')).toContainText(firstName);

    // Nav chip shows full name
    await expect(page.locator('#personaNameNav')).toHaveText(persona.name);
    await expect(page.locator('#personaRoleNav')).toHaveText(persona.role);

    // Sidebar footer shows same
    await expect(page.locator('#sidebarName')).toHaveText(persona.name);
    await expect(page.locator('#sidebarRole')).toHaveText(persona.role);

    // persona cookie value
    const cookies = await ctx.cookies();
    const pc = cookies.find(c => c.name === 'persona');
    expect(decodeURIComponent(pc?.value ?? '')).toBe(persona.name);

    await ctx.close();
  });
}

// ─── AUTH-06: Top-nav Sign out ────────────────────────────────────────────────
test('AUTH-06: top-nav sign out clears session and redirects', async ({ page }) => {
  await login(page, 'Sarah Chen');

  // Click the "Sign out" link in the top nav
  await page.click('a[href="/logout"]');
  await page.waitForURL('**/login**');

  // Cookies cleared
  const cookies = await page.context().cookies();
  const sessionCookie = cookies.find(c => c.httpOnly);
  const personaCookie = cookies.find(c => c.name === 'persona');
  expect(sessionCookie).toBeFalsy();
  expect(personaCookie).toBeFalsy();
});

// ─── AUTH-07: Sidebar sign out ────────────────────────────────────────────────
test('AUTH-07: sidebar sign out button clears session and redirects', async ({ page }) => {
  await login(page, 'James Park');

  // Sidebar sign-out link — target the one in the sidebar footer
  const sidebarLogout = page.locator('aside a[href="/logout"]');
  await expect(sidebarLogout).toBeVisible();
  await sidebarLogout.click();
  await page.waitForURL('**/login**');

  const cookies = await page.context().cookies();
  expect(cookies.find(c => c.httpOnly)).toBeFalsy();
});

// ─── AUTH-08: Unauthenticated access redirects to /login ─────────────────────
test('AUTH-08: unauthenticated visit to / redirects to login', async ({ browser }) => {
  const ctx  = await browser.newContext(); // fresh context, no cookies
  const page = await ctx.newPage();

  await page.goto('/');
  await page.waitForURL('**/login**');
  expect(page.url()).toContain('/login');

  // No app content visible
  await expect(page.locator('#panelLanding')).not.toBeVisible();

  await ctx.close();
});

// ─── AUTH-09: Rate limiting ───────────────────────────────────────────────────
test('AUTH-09: rate limiting triggers after repeated failed logins', async ({ browser }) => {
  const ctx  = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto('/login');

  let throttled = false;

  // Fire 7 rapid wrong-password attempts
  for (let i = 0; i < 7; i++) {
    const card = page.locator('.persona-option').first();
    await card.click();
    await page.fill('input[name="password"]', `wrong-attempt-${i}`);

    const [response] = await Promise.all([
      page.waitForResponse(r => r.url().includes('/login') && r.request().method() === 'POST'),
      page.click('button[type="submit"]'),
    ]);

    if (response.status() === 429) {
      throttled = true;
      break;
    }

    // Navigate back if we got redirected
    if (page.url().includes('error')) {
      await page.goto('/login');
    }
  }

  expect(throttled, 'Expected HTTP 429 after repeated failed logins').toBe(true);
  await ctx.close();
});
