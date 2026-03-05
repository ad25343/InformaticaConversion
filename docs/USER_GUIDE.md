# User Guide — Informatica Conversion Tool

> **Version:** 2.14.0
> **Audience:** Data engineers, migration leads, and operations teams

---

## What this tool does

The Informatica Conversion Tool takes an Informatica PowerCenter mapping XML export and converts it into production-ready code for your target stack — dbt, PySpark, Python, or SQL. It handles the full conversion lifecycle automatically, with three human review gates built in to ensure quality and sign-off before code is promoted.

For each mapping it produces:
- Translated source code (SQL models, PySpark scripts, dbt models)
- Source-to-Target mapping workbook (Excel)
- Technical documentation (Markdown)
- Test artifacts (coverage report, pytest suite, expression boundary tests, golden comparison script)
- A draft GitHub PR (if configured)

---

## Getting started

### 1. Copy the example environment file

```bash
cd app
cp .env.example .env
```

### 2. Fill in the required values

Open `.env` and set the three required variables:

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic API key — get one at https://console.anthropic.com |
| `APP_PASSWORD` | Login password shown on the tool's login screen |
| `SECRET_KEY` | Long random string for session signing — generate with: `python -c "import secrets; print(secrets.token_hex(32))"` |

### 3. Start the app

```bash
cd app
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000` in your browser.

---

## Manual conversion (single mapping)

### Step 1 — Upload your files

Click **Upload** and provide:

| File | Required? | Description |
|---|---|---|
| Mapping XML | **Yes** | Informatica PowerCenter mapping export (`.xml`) |
| Workflow XML | No | Enables session-level extraction (Step 0) |
| Parameter file | No | Enables `$$VARIABLE` resolution throughout the mapping |

You can also drag and drop a ZIP containing multiple mapping XMLs to run a **batch conversion** — the tool processes all mappings concurrently up to `BATCH_CONCURRENCY` (default: 3).

### Step 2 — Watch the pipeline run

The tool runs a 12-step pipeline automatically. Progress is visible in real time via the step indicator at the top of the job panel:

| Step | What happens |
|---|---|
| 1 — Parse | Extracts mappings, transformations, connectors, parameters from the XML |
| 2 — Classify | Assigns a complexity tier (Low / Medium / High / Very High) |
| 2b — S2T | Builds the Source-to-Target field mapping |
| 3 — Document | Generates technical documentation for the mapping |
| 4 — Verify | Runs structural checks and flags issues (NULL handling, unresolved params, etc.) |
| **5 — Gate 1** | **Human review: verify the mapping before code generation** |
| 6 — Stack | Assigns the target stack (dbt / PySpark / Python / SQL) |
| 7 — Convert | Generates the translated code |
| 8 — Security scan | Scans generated code for vulnerabilities |
| **9 — Gate 2** | **Human review: approve or fix security findings** |
| 10 — Quality | Reconciles the generated code against the original mapping |
| 11 — Tests | Generates test artifacts (coverage report, pytest suite, golden comparison script) |
| **12 — Gate 3** | **Human review: final code sign-off** |

### Step 3 — Review gates

There are three points where a named reviewer must act before the pipeline continues.

**Gate 1 — Verification review**

Triggered after Step 4. The reviewer sees all verification flags with their severity (CRITICAL / HIGH / MEDIUM / LOW), blocking status, and recommended actions. For each flag they can either accept it (acknowledge the risk and proceed) or note it as resolved (the issue has been addressed in the source mapping).

Actions: **Approve** (proceed to code generation) or **Reject** (stop — the mapping needs to be fixed and re-uploaded).

**Gate 2 — Security review**

Triggered after Step 8. The reviewer sees all security findings from the automated scan, with severity, line numbers, and remediation guidance.

Actions: **Approved** · **Acknowledged** (accept risk) · **Request fix** (loop back to Step 7 for remediation and re-scan) · **Failed** (hard stop).

**Gate 3 — Code sign-off**

Triggered after Step 11. The reviewer sees the generated code (syntax-highlighted), the quality reconciliation report, and the test coverage summary.

Actions: **Approved** (pipeline complete — outputs written to disk, PR opened if configured) · **Regenerate** (re-run conversion from Step 6) · **Rejected** (hard stop).

### Step 4 — Download your outputs

After Gate 3 approval, the following are available from the job panel:

| Output | How to get it |
|---|---|
| All generated code | **Download ZIP** button |
| Source-to-Target mapping | **Download S2T Excel** button |
| Pre-conversion manifest | **Download Manifest** button |
| Full pipeline report | **Download Report (Markdown)** or **Print to PDF** |
| Individual test files | Available in the ZIP under `tests/` |

---

## Scheduled ingestion (file watcher)

The file watcher lets you automate conversions without using the UI — useful for overnight batch runs or when a scripted Informatica export drops files to a shared folder.

### How it works

1. Enable the watcher in `.env` (see Configuration below).
2. After exporting from Informatica, drop all XML files into the watched directory.
3. Drop a `.manifest.json` file last — this signals the watcher that all files are ready.
4. The watcher picks up the manifest on its next poll (default every 30 seconds), reads the XML files, and submits a conversion job automatically.
5. The job appears in the UI sidebar within 5 seconds via the regular refresh cycle.
6. Gate reviews still require a human — the tool sends a webhook notification (if configured) when a gate is reached.

### Manifest file format

Create a file with any name ending in `.manifest.json` and place it in the watched directory alongside the XML files:

```json
{
    "version":       "1.0",
    "mapping":       "m_appraisal_rank.xml",
    "workflow":      "wf_appraisal.xml",
    "parameters":    "params.xml",
    "reviewer":      "Jane Smith",
    "reviewer_role": "Data Engineer"
}
```

| Field | Required | Description |
|---|---|---|
| `mapping` | **Yes** | Filename of the Informatica mapping XML |
| `workflow` | No | Filename of the workflow XML |
| `parameters` | No | Filename of the parameter file (.xml / .txt / .par) |
| `reviewer` | No | Reviewer name — surfaced in gate notifications |
| `reviewer_role` | No | Reviewer role |

All referenced files must be in the same directory as the manifest.

### What happens to the manifest after processing

| Outcome | Manifest moves to |
|---|---|
| Job submitted successfully | `WATCHER_DIR/processed/` |
| Referenced files missing (timed out) | `WATCHER_DIR/failed/` with `.error` sidecar |
| Invalid JSON or bad schema | `WATCHER_DIR/failed/` with `.error` sidecar immediately |

### Enabling the watcher

In `.env`:

```
WATCHER_ENABLED=true
WATCHER_DIR=/path/to/your/export/folder
```

Optional tuning:

```
WATCHER_POLL_INTERVAL_SECS=30    # how often to check for new manifests
WATCHER_INCOMPLETE_TTL_SECS=300  # seconds before a partial manifest is failed
```

---

## Webhook notifications

Configure a webhook to receive notifications when a job reaches a gate, completes, or fails — useful for alerting the review team without them having to poll the UI.

In `.env`:

```
WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
```

Works with Slack incoming webhooks, Microsoft Teams webhooks, PagerDuty, or any HTTP endpoint that accepts a JSON POST.

To verify that notifications come from this tool, set an HMAC signing key:

```
WEBHOOK_SECRET=<random hex string>
```

Every outbound request will include an `X-Webhook-Signature: sha256=<hex>` header. Your receiver can verify it by computing `HMAC-SHA256(WEBHOOK_SECRET, raw_body)` and comparing with constant-time equality.

---

## GitHub PR integration

When configured, the tool automatically opens a draft pull request after every Gate 3 approval — the generated code is committed and a PR is created targeting your main branch.

In `.env`:

```
GITHUB_TOKEN=ghp_...
GITHUB_REPO=myorg/data-migration
GITHUB_BASE_BRANCH=main
```

For GitHub Enterprise, also set:

```
GITHUB_API_URL=https://github.mycompany.com/api/v3
```

Generate a Personal Access Token at https://github.com/settings/tokens (classic) with the **repo** scope checked.

---

## Testing your converted code

The tool generates test artifacts as part of every conversion job (Step 11). These are delivered in the output ZIP under `tests/` and must be run by the data engineering team in their own environment — the tool itself does not execute them.

See **[docs/TESTING_GUIDE.md](TESTING_GUIDE.md)** for full instructions on:
- Reviewing the field coverage report
- Running the generated pytest suite
- Filling in expression boundary test helpers
- Running the golden CSV comparison script (`compare_golden.py`)

---

## Configuration reference

All settings are controlled via `.env`. Copy `.env.example` to `.env` as your starting point.

### Required

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `APP_PASSWORD` | UI login password |
| `SECRET_KEY` | Session signing key (long random string) |

### Server

| Variable | Default | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8000` | Listen port |
| `HTTPS` | `false` | Set to `true` when serving over HTTPS (enables secure cookie flag) |
| `CORS_ORIGINS` | unset | Comma-separated allowed origins for cross-origin deployments |
| `SHOW_DOCS` | `false` | Set to `true` to enable Swagger UI at `/docs` |

### Claude model

| Variable | Default | Description |
|---|---|---|
| `CLAUDE_MODEL` | `claude-sonnet-4-5-20250929` | Override the Claude model used for all agents |

### Upload limits

| Variable | Default | Description |
|---|---|---|
| `MAX_UPLOAD_MB` | `50` | Maximum size for a single uploaded file |
| `MAX_ZIP_EXTRACTED_MB` | `200` | Maximum total extracted size from a ZIP upload |
| `MAX_ZIP_FILE_COUNT` | `200` | Maximum number of files in a ZIP upload |
| `BATCH_CONCURRENCY` | `3` | Maximum concurrent pipeline runs in a batch |

### GitHub PR integration

| Variable | Default | Description |
|---|---|---|
| `GITHUB_TOKEN` | unset | Personal Access Token with `repo` scope |
| `GITHUB_REPO` | unset | Target repository in `owner/repo` format |
| `GITHUB_BASE_BRANCH` | `main` | Branch the PR targets |
| `GITHUB_API_URL` | `https://api.github.com` | Override for GitHub Enterprise |

### Webhook notifications

| Variable | Default | Description |
|---|---|---|
| `WEBHOOK_URL` | unset | Endpoint to receive gate/completion/failure notifications |
| `WEBHOOK_SECRET` | unset | HMAC-SHA256 signing key for payload verification |
| `WEBHOOK_TIMEOUT_SECS` | `10` | Timeout for outbound webhook POST requests |

### File watcher

| Variable | Default | Description |
|---|---|---|
| `WATCHER_ENABLED` | `false` | Set to `true` to activate scheduled ingestion |
| `WATCHER_DIR` | unset | Absolute path to the directory to watch |
| `WATCHER_POLL_INTERVAL_SECS` | `30` | Seconds between directory polls |
| `WATCHER_INCOMPLETE_TTL_SECS` | `300` | Seconds before an incomplete manifest is moved to `failed/` |

---

## Frequently asked questions

**Q: What Informatica export settings should I use?**
Export with *Include Dependencies* enabled so that any reusable transformations and mapplets are included in the XML. Missing dependencies will be flagged at Gate 1 with re-export guidance.

**Q: What if my mapping uses mapplets?**
The tool detects and inline-expands mapplet definitions automatically (v2.12). If a mapplet instance is found but its definition is not in the export, a HIGH severity flag is raised at Gate 1 advising you to re-export with dependencies included.

**Q: Can I override the target stack assigned by the tool?**
Not directly in the current version. If the assigned stack (Step 6) is wrong, reject at Gate 3 and re-upload — the tool will reassign on the next run. A manual override UI is planned for a future version.

**Q: How do I convert multiple mappings at once?**
Create a ZIP file containing all your mapping XMLs (you can include workflow and parameter files too) and upload the ZIP instead of a single XML. The tool processes all mappings concurrently.

**Q: My gate review was rejected — how do I retry?**
Fix the underlying issue in Informatica, re-export the mapping XML, and upload the file again as a new job. Deleted jobs retain their logs in the archive for reference.

**Q: Does the tool ever automatically execute the generated code or tests?**
No. The tool generates code and test artifacts but never runs them. Execution is the data engineering team's responsibility in their own environment. See `docs/TESTING_GUIDE.md`.

**Q: Can the watcher be used without the UI?**
Yes — the watcher submits jobs through the same internal pipeline, and the UI is optional. However, Gate 1, 2, and 3 reviews still require a human to open the UI and submit a decision. If you need notifications when a gate is reached, configure `WEBHOOK_URL` to alert your team.

**Q: Where are output files stored on disk?**
After Gate 3 approval, all artifacts are written to the configured `OUTPUT_DIR` (defaults to `<repo_root>/jobs/{job_id}/`). The directory structure is:

```
jobs/{job_id}/
  input/          original uploaded XML files
  output/         generated code files (preserving folder structure)
    tests/        generated test files
  docs/           documentation.md, s2t_mapping.xlsx, manifest.xlsx
  logs/           raw JSONL pipeline log
```
