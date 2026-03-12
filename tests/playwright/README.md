# Playwright Test Suite — Informatica Conversion Tool

## Setup

```bash
# From project root
npm install
npx playwright install chromium
```

Set your server password in the environment before running:

```bash
export APP_PASSWORD="your-password-here"
```

> **Note:** `APP_PASSWORD` is a single shared password for the entire app — all personas
> use the same value. Persona selection on the login page controls identity only.

## Running tests

```bash
# All tests (headless, parallel)
npm run test:e2e

# Interactive UI mode — watch tests run, time-travel debug
npm run test:e2e:ui

# Single suite
npx playwright test tests/playwright/auth.spec.js

# Run with visible browser
npx playwright test --headed

# View last HTML report
npm run test:e2e:report
```

The server **must be running** on `http://localhost:8000` before tests execute:

```bash
cd app && python main.py
```

Or set a custom URL:

```bash
APP_URL=http://localhost:8080 npm run test:e2e
```

## Test files

| File | Covers |
|------|--------|
| `auth.spec.js` | AUTH-01–09: login, persona picker, cookies, logout, rate limiting |
| `landing.spec.js` | LAND-01–07: greeting, action cards, live stats, navigation |
| `navigation.spec.js` | NAV-01–06: top nav, sidebar persona chip, view switching |
| `submission.spec.js` | SUB-01–08: upload modes, submitter prefill, button state |
| `history.spec.js` | HIST-01–07: history table, search, filter, click-through |
| `review.spec.js` | REV-01–07: queue panel, gate filters, approve/reject buttons |
| `security.spec.js` | SEC-01–06: unauth API, HTTP headers, health endpoint |

## Test categories

**Runs without LLM** (fast, fully automated): all tests except those marked `test.skip`.

**Requires live LLM pipeline** (integration, slow): tests marked `test.skip` in
`review.spec.js` and `security.spec.js` — remove the `.skip` when running a full
integration pass with a real API key.

## Personas used

| Persona | Role | Gate | Used in |
|---------|------|------|---------|
| Asin D | Data Engineer | — (Admin / Submitter) | Auth, submission, history, security |
| Priya Nair | Business Analyst | Gate 1 — business logic review | Auth, review queue |
| James Park | Security Architect | Gate 2 — security findings | Auth, navigation, review |
| Sarah Chen | Migration Lead | Gate 3 — release sign-off | Auth, review queue |
| Maya Patel | Platform Engineer | — (Submitter) | Auth, landing page |

All five personas share the same `APP_PASSWORD`. AUTH-05 iterates through every persona
to verify each can log in and renders the correct name, role, and cookie value.
