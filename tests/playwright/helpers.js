/**
 * Shared helpers for Informatica Conversion Tool Playwright tests.
 *
 * Import:  const { login, PERSONAS, BASE_URL, APP_PASSWORD } = require('./helpers');
 */

const path = require('path');

const BASE_URL    = process.env.APP_URL      || 'http://localhost:8000';
const APP_PASSWORD = process.env.APP_PASSWORD || 'test-password';

const PERSONAS = [
  { name: 'Asin D', role: 'Data Engineer',     initials: 'AD' },
  { name: 'Sarah Chen',   role: 'Migration Lead',     initials: 'SC' },
  { name: 'James Park',   role: 'Security Architect', initials: 'JP' },
  { name: 'Maya Patel',   role: 'Platform Engineer',  initials: 'MP' },
];

// Sample XML files shipped with the repo
const SAMPLE_DIR    = path.resolve(__dirname, '../../app/sample_xml');
const SAMPLE_XML    = path.join(SAMPLE_DIR, 'sample_mapping.xml');
const SAMPLE_WF     = path.join(SAMPLE_DIR, 'sample_workflow.xml');
const SAMPLE_PARAMS = path.join(SAMPLE_DIR, 'sample_params.txt');

/**
 * Log in as a given persona using the login form.
 * Navigates to /login, selects the persona card, enters the password,
 * submits, and waits for the landing page to be visible.
 *
 * @param {import('@playwright/test').Page} page
 * @param {string} personaName  - must match one of the four persona names exactly
 * @param {string} [password]   - defaults to APP_PASSWORD env var
 */
async function login(page, personaName, password) {
  password = password || APP_PASSWORD;
  await page.goto('/login');
  // Select persona card (the label wraps a hidden radio input)
  const card = page.locator('.persona-option').filter({ hasText: personaName });
  await card.click();
  await page.fill('input[name="password"]', password);
  await page.click('button[type="submit"]');
  // Wait for landing page
  await page.waitForSelector('#landingGreeting', { timeout: 10_000 });
}

/**
 * Log out by navigating to /logout directly.
 */
async function logout(page) {
  await page.goto('/logout');
  await page.waitForURL('**/login**');
}

/**
 * Navigate to a main view using the top nav.
 * view: 'landing' | 'dashboard' | 'history' | 'review'
 */
async function goToView(page, view) {
  const ids = {
    landing:   '#navHome',
    dashboard: '#navDashboard',
    history:   '#navHistory',
    review:    '#navReview',
  };
  await page.click(ids[view]);
  const panels = {
    landing:   '#panelLanding',
    dashboard: '#panelDashboard',
    history:   '#panelHistory',
    review:    '#panelReview',
  };
  await page.waitForSelector(panels[view] + ':visible', { timeout: 8_000 });
}

/**
 * Upload a file to a specific input element.
 * Works around native file picker by targeting the hidden <input type="file">.
 */
async function uploadFile(page, inputSelector, filePath) {
  const input = page.locator(inputSelector);
  await input.setInputFiles(filePath);
}

/**
 * Submit a single-file pipeline job and return once the status badge
 * leaves "pending" (i.e. pipeline has started).
 */
async function submitJob(page, xmlPath, { name, team, notes } = {}) {
  await goToView(page, 'dashboard');
  await page.locator('#tabFiles').click();
  await uploadFile(page, '#fileInput', xmlPath);

  if (name)  await page.fill('#submitterName',  name);
  if (team)  await page.fill('#submitterTeam',  team);
  if (notes) await page.fill('#submitterNotes', notes);

  await page.click('#startBtn');
  // Wait for the stepper to appear (pipeline started)
  await page.waitForSelector('.stepper', { timeout: 15_000 });
}

/**
 * Wait for a job to reach a specific status by polling the badge text.
 * Polls every 2 s up to maxWait ms.
 */
async function waitForStatus(page, statusText, maxWait = 120_000) {
  await page.waitForFunction(
    (text) => {
      const badge = document.querySelector('.badge');
      return badge && badge.textContent.toLowerCase().includes(text.toLowerCase());
    },
    statusText,
    { timeout: maxWait, polling: 2_000 }
  );
}

module.exports = {
  BASE_URL,
  APP_PASSWORD,
  PERSONAS,
  SAMPLE_XML,
  SAMPLE_WF,
  SAMPLE_PARAMS,
  login,
  logout,
  goToView,
  uploadFile,
  submitJob,
  waitForStatus,
};
