/**
 * NAVIGATION tests — top nav bar, sidebar persona, view switching, Home button,
 * active tab underline, notification bell.
 *
 * Covers: NAV-01 through NAV-06 in the test plan.
 */

const { test, expect } = require('@playwright/test');
const { login, goToView, PERSONAS } = require('./helpers');

// Re-use a single logged-in page for most nav tests (faster)
test.describe('Navigation (logged in as Asin D)', () => {
  let sharedPage;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    sharedPage = await ctx.newPage();
    await login(sharedPage, 'Asin D');
  });

  // ─── NAV-01: Top nav has 4 buttons ─────────────────────────────────────────
  test('NAV-01: top nav shows all 4 buttons', async () => {
    const page = sharedPage;
    await expect(page.locator('#navHome')).toBeVisible();
    await expect(page.locator('#navDashboard')).toBeVisible();
    await expect(page.locator('#navHistory')).toBeVisible();
    await expect(page.locator('#navReview')).toBeVisible();

    await expect(page.locator('#navHome')).toContainText('Home');
    await expect(page.locator('#navDashboard')).toContainText('Submit');
    await expect(page.locator('#navHistory')).toContainText('Job History');
    await expect(page.locator('#navReview')).toContainText('Review Queue');
  });

  // ─── NAV-02: Active tab gets indigo underline ────────────────────────────────
  test('NAV-02: active nav tab has accent colour and underline', async () => {
    const page = sharedPage;

    const viewMap = [
      { btn: '#navHistory',   panel: '#panelHistory'   },
      { btn: '#navReview',    panel: '#panelReview'    },
      { btn: '#navDashboard', panel: '#panelDashboard' },
      { btn: '#navHome',      panel: '#panelLanding'   },
    ];

    for (const { btn, panel } of viewMap) {
      await page.click(btn);
      await page.waitForSelector(panel + ':visible', { timeout: 6_000 });

      const borderColor = await page.$eval(btn, el => el.style.borderBottomColor);
      const textColor   = await page.$eval(btn, el => el.style.color);

      // Active button should be styled with accent (not transparent/muted)
      expect(borderColor).not.toBe('transparent');
      expect(textColor).not.toBe('');
    }
  });

  // ─── NAV-03: Persona chip — Asin D ────────────────────────────────────
  test('NAV-03: persona chip shows correct name and role', async () => {
    const page = sharedPage;
    await expect(page.locator('#personaNameNav')).toHaveText('Asin D');
    await expect(page.locator('#personaRoleNav')).toHaveText('Data Engineer');
    await expect(page.locator('#personaAvatarNav')).toContainText('AD');
  });

  // ─── NAV-04: Sidebar persona footer ─────────────────────────────────────────
  test('NAV-04: sidebar footer shows persona name, role and sign-out', async () => {
    const page = sharedPage;
    await expect(page.locator('#sidebarName')).toHaveText('Asin D');
    await expect(page.locator('#sidebarRole')).toHaveText('Data Engineer');
    await expect(page.locator('#sidebarAvatar')).toContainText('AD');
    await expect(page.locator('aside a[href="/logout"]')).toBeVisible();
  });

  // ─── NAV-05: Home button returns to landing page ─────────────────────────────
  test('NAV-05: Home button returns to landing page from any view', async () => {
    const page = sharedPage;

    // Navigate away first
    await page.click('#navHistory');
    await page.waitForSelector('#panelHistory:visible');

    // Click Home
    await page.click('#navHome');
    await page.waitForSelector('#panelLanding:visible', { timeout: 6_000 });

    await expect(page.locator('#landingGreeting')).toBeVisible();
    await expect(page.locator('.action-cards')).toBeVisible();
  });

  // ─── NAV-05b: Each nav button shows its panel ───────────────────────────────
  test('NAV-05b: each nav button shows the correct panel', async () => {
    const page = sharedPage;

    const cases = [
      { btn: '#navDashboard', panel: '#panelDashboard' },
      { btn: '#navHistory',   panel: '#panelHistory'   },
      { btn: '#navReview',    panel: '#panelReview'    },
      { btn: '#navHome',      panel: '#panelLanding'   },
    ];

    for (const { btn, panel } of cases) {
      await page.click(btn);
      await page.waitForSelector(panel + ':visible', { timeout: 6_000 });

      // All OTHER panels should be hidden
      for (const other of cases) {
        if (other.panel === panel) continue;
        await expect(page.locator(other.panel)).not.toBeVisible();
      }
    }
  });
});

// ─── NAV-03 variant: different persona chips ────────────────────────────────
for (const persona of PERSONAS) {
  test(`NAV-03 variant: "${persona.name}" — nav chip shows initials and role`, async ({ browser }) => {
    const ctx  = await browser.newContext();
    const page = await ctx.newPage();
    await login(page, persona.name);

    await expect(page.locator('#personaNameNav')).toHaveText(persona.name);
    await expect(page.locator('#personaRoleNav')).toHaveText(persona.role);
    await expect(page.locator('#personaAvatarNav')).toContainText(persona.initials);
    await expect(page.locator('#sidebarName')).toHaveText(persona.name);
    await expect(page.locator('#sidebarAvatar')).toContainText(persona.initials);

    await ctx.close();
  });
}

// ─── NAV-06: Notification bell appears when review items exist ───────────────
test('NAV-06: notification bell is hidden initially (clean DB)', async ({ page }) => {
  await login(page, 'Asin D');
  // With a clean database there should be no pending reviews
  await expect(page.locator('#notifBell')).not.toBeVisible();
  await expect(page.locator('#navReviewBadge')).not.toBeVisible();
});
