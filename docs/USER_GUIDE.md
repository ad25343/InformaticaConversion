# User Guide — Informatica Conversion Tool

> **Version:** 2.18
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

## Navigating the UI

The tool has five main areas accessible from the top navigation bar:

| Tab | Purpose |
|---|---|
| **⚡ Home** | Landing page with at-a-glance stats (total jobs, running, complete, awaiting review) and quick-action cards |
| **🏠 Submit** | Upload files and start a pipeline; the right panel shows live insights after submission |
| **📋 Job History** | Full table of all jobs with search, status filter, and pagination |
| **👁 Review Queue** | All jobs waiting at a gate — click any row to open that job's sign-off form directly |
| **📖 Guide** | This guide, rendered in the browser |

The **left sidebar** shows live pipeline activity at all times regardless of which tab you are on:
- **Running** — in-progress jobs with a step progress bar and current step name. Click to open the job.
- **Needs Sign-off** — jobs paused at Gate 1, 2, or 3. Click to jump directly to the sign-off form.

Use **⌘K** (Mac) or **Ctrl+K** (Windows/Linux) to open the global search modal. Search across all jobs by filename, tracking ID, submitter name, team, status, or complexity tier.

Every job displays a short **tracking ID** (`#XXXXXXXX`) — an 8-character code derived from the job UUID — visible in job headers, history rows, review queue rows, and sidebar cards.

---

## Upload modes

Navigate to the **Submit** tab. Select your upload mode using the two tabs at the top:

| Mode | Use when |
|---|---|
| **📄 Individual** | Converting a single mapping — upload the `.xml` file directly |
| **📦 Batch** | Converting multiple mappings at once |

### Individual mode

Drop a Mapping XML (`.xml`) onto the upload area, or click to browse. Two optional companion files enhance the extraction:

| File | Required? | Description |
|---|---|---|
| Mapping XML (`.xml`) | **Yes** | Informatica PowerCenter mapping export |
| Workflow XML | No | Enables session-level extraction (Step 0) |
| Parameter file | No | Enables `$$VARIABLE` resolution throughout the mapping |

Individual mode accepts `.xml` files only.

### Batch mode

Batch mode lets you convert many mappings in a single operation.

**Select a folder** — click **📁 Select Folder** and pick a directory from your computer. The browser packages the folder into a ZIP automatically. No preparation needed.

**Select a pre-built ZIP** — click **📦 Select ZIP** if you already have a ZIP prepared.

**Folder / ZIP structure — subfolders (recommended for organised batches):**

```
my_batch_folder/
  mapping_a/mapping.xml
  mapping_b/mapping.xml
  mapping_b/workflow.xml    ← optional per mapping
  mapping_b/params.txt      ← optional per mapping
```

**Flat folder — all XMLs in one directory:**

If your folder contains multiple mapping XMLs at the root level with no subfolders, the tool automatically creates one job per XML file. No reorganisation is required.

```
my_flat_folder/
  m_customer_load.xml
  m_product_load.xml
  m_appraisal_rank.xml
```

The tool processes all mappings concurrently up to `BATCH_CONCURRENCY` (default: 3). Jobs waiting for a concurrency slot queue automatically and start as running slots free up — gate-paused jobs **release** their slot so they never block queued work.

---

## Pipeline modes

Before starting a job (Individual or Batch), choose how far through the pipeline to run:

| Mode | Steps | Use when |
|---|---|---|
| **🔄 Full Conversion** | Steps 1–12 (all gates included) | You want production-ready code — the default |
| **📋 Documentation Only** | Steps 1–4 (parse → classify → S2T → verify) | You only need the Source-to-Target mapping and technical docs, without generating code |

Select the mode using the toggle buttons on the Submit tab before clicking **▶ Start Pipeline**. The same mode applies to every mapping in a batch run.

**Documentation Only** exits cleanly after Step 4 verification completes, exports the S2T Excel and documentation Markdown, and marks the job complete. No human gates are triggered. This is useful for cataloguing a large migration inventory before committing to code generation.

---

## The 12-step pipeline (Full Conversion)

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

Progress is visible in real time via the step indicator at the top of the job panel. The animated progress bar shows N / 12 steps.

---

## Human review gates

There are three points where a named reviewer must act before the pipeline continues.

### Gate 1 — Verification review

Triggered after Step 4. The reviewer sees all verification flags with their severity (CRITICAL / HIGH / MEDIUM / LOW), blocking status, and recommended actions. For each flag they can either accept it (acknowledge the risk and proceed) or note it as resolved (the issue has been addressed in the source mapping).

Actions: **Approve** (proceed to code generation) or **Reject** (stop — the mapping needs to be fixed and re-uploaded).

### Gate 2 — Security review

Triggered after Step 8. The reviewer sees all security findings from the automated scan, with severity, line numbers, and remediation guidance.

Actions: **Approved** · **Acknowledged** (accept risk) · **Request fix** (loop back to Step 7 for remediation and re-scan) · **Failed** (hard stop).

### Gate 3 — Code sign-off

Triggered after Step 11. The reviewer sees the generated code (syntax-highlighted), the quality reconciliation report, and the test coverage summary.

Actions: **Approved** (pipeline complete — outputs written to disk, PR opened if configured) · **Regenerate** (re-run conversion from Step 6) · **Rejected** (hard stop).

---

## Monitoring your job

After clicking **▶ Start Pipeline**, the right column of the Submit tab immediately switches to a **Job Insights** panel. It shows live metrics as each pipeline step completes — no need to navigate away:

- Tracking ID, live status badge, complexity tier, and assigned stack
- Animated progress bar (N / 12 steps)
- Metric cards that populate as the pipeline runs: mappings found, sources, targets, transforms, blocking flags, security findings, review score, and test coverage

Click **View Full Details →** at any time to open the complete job view.

---

## Reviewing jobs at scale (Review Queue)

When running a large migration, many jobs can be waiting at gates simultaneously. The **Review Queue** tab shows all pending gate decisions in a single table.

**Opening a specific job for review:** click anywhere on a row (or the "Review →" button at the right) to open that job's full detail view. The page scrolls automatically to the active gate sign-off card. A "← Back to Review Queue" bar at the top lets you return to the list without losing your place.

**Bulk sign-off:** check the boxes next to multiple jobs, enter a reviewer name, then click **Approve Selected**, **Reject Selected**, or **Acknowledge Selected** (Gate 2 only). The summary bar shows how many jobs are waiting at Gate 1, Gate 2, and Gate 3 — use the filter buttons to focus on one gate at a time.

**Sidebar shortcut:** the **Needs Sign-off** section in the left sidebar always shows jobs at any gate regardless of which screen you are on. Clicking a card there navigates directly to that job's sign-off form.

---

## Output folders

After a job completes, all artifacts are written to readable directories on disk.

### Individual jobs

```
OUTPUT_DIR/
  individual/
    <mapping_stem>_<short_id>/
      input/          original uploaded XML files
      output/         generated code files
        tests/        generated test files
      docs/           documentation.md, s2t_mapping.xlsx
      logs/           raw JSONL pipeline log
```

Example: `individual/m_customer_load_a1b2c3d4/`

### Batch jobs

All mappings in a batch are grouped under a shared batch folder:

```
OUTPUT_DIR/
  batch_<short_batch_id>/
    m_customer_load/
      input/    output/    docs/    logs/
    m_product_load/
      input/    output/    docs/    logs/
    m_appraisal_rank/
      input/    output/    docs/    logs/
```

Example: `batch_e5f6a7b8/m_customer_load/`

This makes it easy to locate all outputs from a single batch run in one place.

### Downloads

From the job panel, after Gate 3 approval (or after Step 4 for Documentation Only jobs):

| Output | How to get it |
|---|---|
| All generated code | **Download ZIP** button |
| Source-to-Target mapping | **Download S2T Excel** button |
| Pre-conversion manifest | **Download Manifest** button |
| Full pipeline report | **Download Report (Markdown)** or **Print to PDF** |
| Individual test files | Available in the ZIP under `tests/` |

---

## Job History & cleanup

The **Job History** tab shows a full table of all jobs with search, status filter, and pagination.

### Deleting individual jobs

Each job row has a **🗑** delete button. Clicking it soft-deletes the job — it is removed from history and the sidebar but its log is retained in the database archive. Deletion is immediate and does not require confirmation.

### Deleting a batch

Each batch group in history has a **🗑 Delete batch** button in the header row. This soft-deletes all jobs in the batch at once. Useful for cleaning up test runs or failed experiments.

Deleted jobs and batches do not appear in any list view but can be recovered by an admin using the database directly if needed.

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

A manifest represents a **project group** — all the related Informatica files for one project that should be converted together as a batch. Create a file with any name ending in `.manifest.json` and place it in the watched directory alongside the XML files.

**Simple form** — all mappings share the same workflow and parameter file:

```json
{
    "version":       "1.0",
    "label":         "Customer Data Pipeline — Q1 2026",
    "mappings": [
        "m_customer_load.xml",
        "m_appraisal_rank.xml",
        "m_commission_calc.xml"
    ],
    "workflow":      "wf_pipeline.xml",
    "parameters":    "params_prod.xml",
    "reviewer":      "Jane Smith",
    "reviewer_role": "Data Engineer"
}
```

**Per-mapping overrides** — individual mappings can specify their own workflow or parameter file:

```json
{
    "version":    "1.0",
    "label":      "Customer Data Pipeline — Q1 2026",
    "mappings": [
        "m_customer_load.xml",
        "m_product_load.xml",
        {
            "mapping":    "m_appraisal_rank.xml",
            "workflow":   "wf_appraisal.xml",
            "parameters": "params_appraisal.xml"
        }
    ],
    "workflow":   "wf_default.xml",
    "parameters": "params_prod.xml",
    "reviewer":   "Jane Smith",
    "reviewer_role": "Data Engineer"
}
```

| Field | Required | Description |
|---|---|---|
| `label` | No | Human-readable name for the batch — used as the output folder name. Recommended. |
| `mappings` | **Yes** | Array of mapping XMLs. Each entry is a filename string or an object with per-mapping overrides. |
| `workflow` | No | Default workflow XML for all mappings |
| `parameters` | No | Default parameter file (.xml / .txt / .par) for all mappings |
| `reviewer` | No | Reviewer name — surfaced in gate notifications |
| `reviewer_role` | No | Reviewer role |

**Drop the manifest last** — it is the signal that all files are ready.

### Output directory structure (watcher)

```
OUTPUT_DIR/
  <label>_<YYYYMMDD_HHMMSS_ffffff>/
    m_customer_load/
      input/    output/    docs/    logs/
    m_appraisal_rank/
      input/    output/    docs/    logs/
```

The microsecond timestamp is always appended so re-runs with the same label never overwrite each other.

### What happens to the manifest after processing

| Outcome | Manifest moves to |
|---|---|
| Job submitted successfully | `WATCHER_DIR/processed/` |
| Referenced files missing (timed out) | `WATCHER_DIR/failed/` with `.error` sidecar |
| Invalid JSON or bad schema | `WATCHER_DIR/failed/` immediately |

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

## Time-based scheduled conversions

The time-based scheduler lets you automate conversion runs on a recurring cron schedule — useful for nightly batch jobs, weekly pipeline refreshes, or any scenario where conversions should fire at a specific time without manual intervention.

### How it works

1. Enable the scheduler and the file watcher in `.env`.
2. Create a `*.schedule.json` file in `SCHEDULER_DIR` that contains a cron expression and an embedded manifest.
3. At the scheduled time, the scheduler materialises a `.manifest.json` file into `WATCHER_DIR`.
4. The manifest file watcher picks it up and submits the conversion batch automatically.
5. Gate reviews still require a human. Configure `WEBHOOK_URL` to alert your team when a gate is reached.

### Schedule file format

```json
{
    "version":  "1.0",
    "cron":     "0 2 * * 1-5",
    "timezone": "America/New_York",
    "label":    "Customer Pipeline Nightly",
    "enabled":  true,
    "manifest": {
        "version":  "1.0",
        "mappings": [
            "m_customer_load.xml",
            "m_product_load.xml"
        ],
        "workflow":      "wf_default.xml",
        "parameters":    "params_prod.xml",
        "reviewer":      "Jane Smith",
        "reviewer_role": "Data Engineer"
    }
}
```

| Field | Required | Description |
|---|---|---|
| `cron` | **Yes** | 5-field cron expression |
| `timezone` | No | IANA timezone name (e.g. `"America/New_York"`). Defaults to UTC. |
| `label` | No | Human-readable run label. Defaults to schedule filename stem. |
| `enabled` | No | Set `false` to pause without deleting the file. Defaults to `true`. |
| `manifest` | **Yes** | Full manifest payload — same format as a hand-dropped manifest. |

### Cron expression quick reference

| Expression | Fires at |
|---|---|
| `"0 2 * * 1-5"` | Weekdays at 02:00 |
| `"30 6 * * *"` | Every day at 06:30 |
| `"0 */4 * * *"` | Every 4 hours on the hour |
| `"15 8 1 * *"` | 1st of every month at 08:15 |
| `"0 18 * * 5"` | Fridays at 18:00 |

### Enabling the scheduler

Both the scheduler and the file watcher must be enabled in `.env`:

```
WATCHER_ENABLED=true
WATCHER_DIR=/path/to/watch/folder
SCHEDULER_ENABLED=true
SCHEDULER_DIR=/path/to/schedules/folder
```

Schedule files are re-read on every poll — add, edit, or disable schedules without restarting the server.

---

## Webhook notifications

Configure a webhook to receive notifications when a job reaches a gate, completes, or fails.

In `.env`:

```
WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
```

Works with Slack incoming webhooks, Microsoft Teams webhooks, PagerDuty, or any HTTP endpoint that accepts a JSON POST.

To verify that notifications come from this tool, set an HMAC signing key:

```
WEBHOOK_SECRET=<random hex string>
```

Every outbound request will include an `X-Webhook-Signature: sha256=<hex>` header. Your receiver can verify it by computing `HMAC-SHA256(WEBHOOK_SECRET, raw_body)`.

---

## GitHub PR integration

When configured, the tool automatically opens a draft pull request after every Gate 3 approval.

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

The tool generates test artifacts as part of every Full Conversion job (Step 11). These are delivered in the output ZIP under `tests/` and must be run by the data engineering team in their own environment.

See **[docs/TESTING_GUIDE.md](TESTING_GUIDE.md)** for full instructions on:
- Reviewing the field coverage report
- Running the generated pytest suite
- Filling in expression boundary test helpers
- Running the golden CSV comparison script (`compare_golden.py`)

---

## Database scaling

SQLite is the default and is sufficient for pilots and migrations up to approximately 200 mappings.

**For migrations above 200 mappings, switch to PostgreSQL.** To switch, set `DATABASE_URL` in `backend/db/database.py`:

```python
DATABASE_URL = "postgresql+asyncpg://user:password@host:5432/informatica_conversion"
```

Install the async driver: `pip install asyncpg`. No schema migration needed — all tables are created automatically on first connect.

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
| `HTTPS` | `false` | Set to `true` when serving over HTTPS |
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

### Time-based scheduler

| Variable | Default | Description |
|---|---|---|
| `SCHEDULER_ENABLED` | `false` | Set to `true` to activate the cron-based scheduler |
| `SCHEDULER_DIR` | unset | Absolute path to the directory containing `*.schedule.json` files |
| `SCHEDULER_POLL_INTERVAL_SECS` | `60` | Seconds between cron evaluation polls |

---

## Customising for your organisation

All customisation is done through two optional YAML files and an optional prompts folder. No Python code changes are required.

### Pattern classification signals (`org_config.yaml`)

```yaml
# app/config/org_config.yaml
pattern_signals:
  scd2:
    target_name_contains: ["_HIST", "_ARCHIVE"]
  upsert:
    target_name_contains: ["_MERGE", "_UPSERT"]
  incremental_append:
    target_name_contains: ["_DELTA", "_INC"]
  expression_complexity:
    additional_indicators: ["DECODE", "INSTR"]
```

### Audit / DW columns (`org_config.yaml`)

```yaml
audit_fields:
  insert_timestamp:
    column: LOAD_DT
    expression: current_date()
  update_timestamp:
    column: REFRESH_DT
    expression: current_timestamp()
  source_system:
    column: SRC_SYS
    expression: "'INFORMATICA'"
```

### Verification flag severity (`org_config.yaml`)

```yaml
verification_policy:
  HARDCODED_VALUE:
    severity: HIGH
    blocking: true
  SOURCE_SQ_CONNECTIVITY:
    severity: INFO
    blocking: false
```

### Warehouse profiles (`warehouse_registry.yaml`)

Eight warehouses are pre-registered. Add any SQLAlchemy-compatible target by appending an entry:

```yaml
# app/config/warehouse_registry.yaml
my_custom_dw:
  adapter: sqlalchemy
  credential_vars:
    host: MY_DW_HOST
    port: MY_DW_PORT
    database: MY_DW_DATABASE
    username: MY_DW_USER
    password: MY_DW_PASSWORD
  defaults:
    port: 5439
```

### Skipping pipeline steps (`org_config.yaml`)

```yaml
pipeline_options:
  skip_steps:
    - step: 4
      when:
        tier: LOW
    - step: 11
      when:
        pattern_confidence: HIGH
  auto_approve_gates:
    - gate: 1
      when:
        tier: LOW
        pattern_confidence: HIGH
```

### System prompt overrides (`app/prompts/`)

| File | Replaces |
|---|---|
| `pyspark_system.j2` | PySpark conversion system prompt |
| `dbt_system.j2` | dbt conversion system prompt |
| `python_system.j2` | Python/Pandas conversion system prompt |

See `app/prompts/README.md` for variable reference and examples.

---

## Frequently asked questions

**Q: What Informatica export settings should I use?**
Export with *Include Dependencies* enabled so that any reusable transformations and mapplets are included in the XML. Missing dependencies will be flagged at Gate 1 with re-export guidance.

**Q: What if my mapping uses mapplets?**
The tool detects and inline-expands mapplet definitions automatically. If a mapplet instance is found but its definition is not in the export, a HIGH severity flag is raised at Gate 1.

**Q: Can I override the target stack assigned by the tool?**
Not directly in the current version. If the assigned stack (Step 6) is wrong, reject at Gate 3 and re-upload — the tool will reassign on the next run.

**Q: How do I convert multiple mappings at once?**
Use **Batch mode** on the Submit tab. Click **📁 Select Folder** to pick a folder (the browser packages it automatically), or click **📦 Select ZIP** if you already have one. Both flat folders and structured subfolders are supported.

**Q: I have 17 XML files in one folder — do I need to reorganise them into subfolders?**
No. If all XMLs are in the same directory with no subfolders, the tool automatically creates one job per XML file (flat-folder mode).

**Q: What is Documentation Only mode?**
It runs Steps 1–4 only (parse, classify, S2T, verify) and exits cleanly after producing the Source-to-Target Excel and technical docs. No code is generated, no gates are triggered. Use it to catalogue your mapping inventory before committing to full conversion.

**Q: My gate review was rejected — how do I retry?**
Fix the underlying issue in Informatica, re-export the mapping XML, and upload it again as a new job. Deleted jobs retain their logs in the archive for reference.

**Q: Does the tool ever automatically execute the generated code or tests?**
No. The tool generates code and test artifacts but never runs them. Execution is the data engineering team's responsibility in their own environment.

**Q: Can the watcher be used without the UI?**
Yes — gate reviews still require a human, but the watcher submits jobs automatically. Configure `WEBHOOK_URL` to alert your team when a gate is reached.

**Q: What happens to batch jobs if the server is restarted?**
Batch jobs that were queued but hadn't started are automatically re-queued on startup. Jobs that were paused at a gate are restored to the gate-waiting state and resume normally when the reviewer acts.

**Q: Where are output files stored?**
Individual jobs: `OUTPUT_DIR/individual/<mapping_stem>_<short_id>/`
Batch jobs: `OUTPUT_DIR/batch_<short_batch_id>/<mapping_stem>/`
See the **Output folders** section above for the full directory layout.
