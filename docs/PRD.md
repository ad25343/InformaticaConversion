# Product Requirements Document
## Informatica Conversion Tool

**Version:** 2.17.0 (complete) / App 2.17.0
**Author:** ad25343
**Last Updated:** 2026-03-11
**License:** CC BY-NC 4.0 — [github.com/ad25343/InformaticaConversion](https://github.com/ad25343/InformaticaConversion)
**Contact:** [github.com/ad25343/InformaticaConversion/issues](https://github.com/ad25343/InformaticaConversion/issues)

---

## 1. Problem Statement

Enterprise data teams spend months manually rewriting Informatica PowerCenter ETL mappings
into modern stacks (PySpark, dbt, Python). The work is repetitive, error-prone, and requires
two skills simultaneously — deep Informatica knowledge and the target-stack fluency — rarely
found in the same engineer.

The Informatica Conversion Tool automates this migration using Claude as the conversion
engine, structured human review gates to catch errors before code ships, and a bandit +
Claude security scan with a human security review gate to ensure generated code does not
inherit bad patterns from legacy Informatica designs.

---

## 2. Target Personas

**Primary: Data Migration Engineer**
Responsible for rewriting PowerCenter mappings to PySpark or dbt. Knows Informatica well
but needs help producing idiomatic modern-stack code quickly. Cares about correctness of
field mappings, filter logic, and business rules — not about writing boilerplate.

**Secondary: Data Engineering Lead / Reviewer**
Approves the generated code before it enters a CI pipeline. Needs a structured review
checklist, a Source-to-Target field mapping document, a security scan report with a
human decision gate, and a final code sign-off — not a wall of generated code with no summary.

**Tertiary: DevOps / Platform Engineer**
Deploying the tool inside a corporate network. Cares about CVE-free dependencies, no
plaintext secrets in generated code, and configurable upload size limits.

---

## 3. Version Scope

### v1.0 — MVP (shipped)

The single-file conversion pipeline. Accepts one Informatica Mapping XML export and
produces converted code through an agentic pipeline with two human review gates.

Steps:
1. XML parse and structural analysis
2. Complexity classification (LOW / MEDIUM / HIGH / VERY_HIGH)
S2T. Source-to-Target field mapping (S2T Excel workbook)
3. Documentation generation (Markdown)
4. Verification — flags unsupported transformations, dead columns, unresolved parameters
5. Gate 1 — human sign-off (APPROVE / REJECT)
6. Target stack assignment (PySpark / dbt / Python)
7. Code generation
8. Code quality review (Claude cross-check vs. documentation and S2T)
9. Test generation
10. Gate 2 — code review sign-off (APPROVE / REJECT)

Delivered: single-file upload, SSE progress stream, per-job structured logging, SQLite
job persistence, session-cookie authentication, sample mappings across three complexity
tiers.

### v1.1 — Session & Parameter Support (shipped)

Extends the pipeline with a new Step 0 that processes Workflow XML and parameter files
alongside the Mapping XML. Adds ZIP upload as a convenience upload path. Introduces a
dedicated Security Scan step (Step 8) with bandit + YAML regex + Claude review.

New features:
- Step 0 — file-type auto-detection, cross-reference validation, session config extraction, $$VAR resolution
- Three-file upload (Mapping + Workflow + Parameter) and ZIP archive upload
- YAML artifact generation (connections.yaml, runtime_config.yaml) from session config
- UNRESOLVED_VARIABLE flags when $$VARs have no value in the parameter file
- Security-hardened infrastructure: XXE protection, Zip Slip / Zip Bomb / symlink defense, 7 CVEs patched, CORS middleware, startup secret-key warning, per-upload file size enforcement
- Step 8 — Security Scan (dedicated step): bandit (Python/PySpark), YAML regex secrets check, Claude review for all stacks
- Paired sample files for all 9 sample mappings (simple / medium / complex)
- Collapsable job history in the UI with smart default (open when no active jobs)
- Downloadable report as Markdown and PDF (print dialog)

### v1.2 — Human Security Review Gate (current)

Replaces the automatic CRITICAL-block gate after the security scan with a human decision
gate. Reviewers now make an informed choice — they can see the full scan findings in the UI
and decide to approve, acknowledge risk, or fail the job. This extends the pipeline from
11 to 12 steps and adds a third human-in-the-loop gate.

New features:
- Step 9 — Human Security Review Gate: pipeline pauses when scan recommendation is
  REVIEW_RECOMMENDED or REQUIRES_FIXES; reviewers choose APPROVED / ACKNOWLEDGED / FAILED
- Three-decision security review: APPROVED (clean or no action needed), ACKNOWLEDGED
  (issues noted and accepted as known risk), FAILED (block pipeline permanently)
- Clean scans (APPROVED recommendation) auto-proceed without pausing the pipeline
- Security review record stored on the job (reviewer name, role, decision, notes, date)
- POST `/api/jobs/{id}/security-review` endpoint
- 12-dot stepper in the UI with "Sec Rev" dot at Step 9
- All downstream step numbers updated: Quality Review → 10, Tests → 11, Code Sign-Off → 12

### v1.3 — Logic Equivalence Check (current)

Upgrades Step 10 (Code Quality Review) with a new Logic Equivalence stage that goes
back to the original Informatica XML as the ground truth and verifies rule-by-rule
that the generated code correctly implements every transformation, expression, filter,
join, and null-handling pattern. This is a cross-check of Claude's own output against
the source XML — not against Claude's documentation of it.

New features:
- Stage A — Logic Equivalence: per-rule verdicts (VERIFIED / NEEDS_REVIEW / MISMATCH)
  comparing generated code directly against the original Informatica XML
- Stage B — Code Quality: existing 10-check static review (unchanged)
- Equivalence stats shown at Gate 3: X VERIFIED / Y NEEDS REVIEW / Z MISMATCHES + coverage %
- Per-rule detail in Gate 3 card: rule type, XML rule verbatim, generated implementation, note
- Mismatches detected by equivalence check cap code review recommendation at REVIEW_RECOMMENDED
- Logic Equivalence section added to downloadable Markdown and PDF reports
- `LogicEquivalenceCheck` and `LogicEquivalenceReport` added to data model

### v2.0 — Batch Conversion (current)

Introduces multi-mapping batch conversion so an entire set of Informatica exports can be
submitted in one upload and processed concurrently.

New features:
- Batch ZIP upload: one subfolder per mapping inside the ZIP; Workflow XML and parameter
  file are optional per folder and auto-detected from content
- `POST /api/jobs/batch` endpoint: validates the ZIP, creates a batch record, spawns an
  independent 12-step pipeline job for each mapping folder
- Up to 3 mapping pipelines run concurrently (asyncio Semaphore); rate-limited against the
  Claude API by the same semaphore
- Each job retains all existing human review gates independently (Gate 1, Gate 2, Gate 3)
- Batch tracking: `batches` DB table + `batch_id` on job records; `GET /api/batches/{id}`
  returns batch record + per-job summaries with a computed status
  (running / complete / partial / failed)
- Batch UI: "Batch" upload tab alongside "Individual Files" and "ZIP Archive"; uploaded
  jobs grouped under a batch header card in the sidebar with live summary stats
  (X complete · Y awaiting review · Z running · N blocked)

### v2.1 — Security Remediation + Reliable Documentation (current)

Quality and reliability improvements across the security and documentation pipeline.

New features:
- **Security remediation guidance (v1.4):** Every security finding now includes an
  actionable "How to fix" recommendation. Bandit findings (B101–B703) are matched to a
  static remediation lookup table; YAML secrets findings include a canned credential
  externalisation guide; Claude findings include a model-generated remediation field.
  The Gate 2 UI shows a green "🔧 How to fix:" section per finding.
- **Gate 2 REQUEST_FIX remediation loop:** Reviewers can now request that Claude actually
  fix the identified security findings rather than just accepting or rejecting them. Choosing
  REQUEST_FIX re-runs Step 7 (code generation) with all security findings injected into the
  conversion prompt as mandatory fix requirements (severity, location, description, and
  required fix per finding). Step 8 (security scan) then re-runs on the regenerated code and
  Gate 2 is re-presented to the reviewer. If the re-scan is clean it auto-proceeds to Step 10.
  Capped at 2 remediation rounds — the "Request Fix" button is hidden after round 2 to prevent
  infinite loops. Round number and remaining attempts are shown as a banner in the Gate 2 UI.
  The remediation round is tracked in `SecuritySignOffRecord.remediation_round`.
- **Two-pass documentation (Step 3):** Documentation generation now runs as two
  sequential Claude calls instead of one. Pass 1 covers Overview + all Transformations
  + Parameters & Variables; Pass 2 covers Field-Level Lineage + Session & Runtime
  Context + Ambiguities, with Pass 1 output as context. Each call uses the 64K
  extended-output beta, giving a combined ceiling of ~128K output tokens — sufficient
  for any Informatica mapping in practice. Eliminates the truncation failures seen on
  HIGH/VERY_HIGH complexity SCD2 and multi-target mappings.
- **Timestamp timezone fix:** All UI timestamps are now correctly displayed in the
  user's local timezone. Previously, UTC timestamps from the database were rendered
  without conversion, showing the wrong time for non-UTC users.
- **Step 3 completeness gate:** Documentation generation stamps a `<!-- DOC_COMPLETE -->`
  sentinel at the end of the output on success, or `<!-- DOC_TRUNCATED -->` if any pass
  hits the token limit. The orchestrator checks for the sentinel immediately after Step 3
  and fails the job before Step 4 runs — preventing verification from operating on an
  incomplete document.
- **DB_PATH persistence fix:** Default database path changed from the OS temp directory
  (data loss on reboot) to `app/data/jobs.db` relative to the repository root. Override
  with the `DB_PATH` environment variable for Docker or shared-filesystem deployments.
- **Step 3 progress heartbeat:** The orchestrator now runs documentation generation
  as a background async task and emits an SSE progress event every 30 seconds showing
  elapsed time and which pass is active. Large SCD2 mappings can take 15–20+ minutes —
  the pipeline is fully async so no other jobs are blocked. No timeout is imposed on
  the Claude calls; a hard cap would incorrectly fail valid long-running passes.
- **CI noise reduction:** GitHub Actions security scan now only fires when Python
  source files change (path filter); success emails suppressed — notifications sent
  only on scan failure.

### v2.2 — Security Knowledge Base + Reliability

Closes the feedback loop between Gate 2 security findings and future code generation so
the tool evolves with every conversion run.

New features:
- **Security Knowledge Base**: two-layer system injected into every conversion prompt.
  - *Standing rules* (`security_rules.yaml`, committed to source): 17 hand-curated rules
    covering hardcoded credentials, SQL injection, eval/exec, subprocess, XXE, Zip Slip,
    weak cryptography, insecure random, PII logging, TLS bypass, temp files, and 5
    dbt/Snowflake-specific rules derived from real job findings.
  - *Auto-learned patterns* (`security_patterns.json`, runtime state): after every Gate 2
    APPROVED or ACKNOWLEDGED decision the findings are merged into a persistent store keyed
    by `(test_id/test_name, severity)` with an occurrence counter. Patterns that recur
    across jobs accumulate weight and are injected into future prompts with the highest
    emphasis. Historical backfill on first run seeds patterns from all prior job logs.
  - `GET /api/security/knowledge` — returns `rules_count`, `patterns_count`, `top_patterns`.
  - Sidebar "🛡 Security KB: N rules · M learned patterns" badge shows KB state on load.
- **Security scan round history + fix-round diff**: each scan round is archived in
  `security_scan_rounds` before being overwritten. Gate 2 shows a ✅ Fixed / ⚠️ Remains /
  🆕 New comparison table after each REQUEST_FIX round.
- **Log Archive sidebar**: collapsible section shows historical jobs whose DB records are
  gone but log files remain on disk. Clicking opens a read-only log viewer.
  `GET /api/logs/history` and `GET /api/logs/history/{job_id}` endpoints.
- **Soft delete**: the 🗑 button stamps `deleted_at` on the job instead of issuing
  `DELETE FROM jobs`. Soft-deleted jobs disappear from the active list but all data is
  preserved and surfaced in the Log Archive. DB auto-migrates on startup.
- **BATCH_CONCURRENCY env var**: batch semaphore configurable via environment (default 3).
- **E2E mortgage batch test set (Stages 2–6)**: six-stage synthetic mortgage pipeline
  covering all three target stacks and all complexity tiers.
- **Documentation truncation changed to Gate 1 warning**: previously truncated docs caused
  a hard pipeline failure. Now the pipeline continues with a `doc_truncated` flag; the
  Step 3 UI card shows an orange border and TRUNCATED badge; a HIGH (non-blocking)
  `DOCUMENTATION_TRUNCATED` flag appears in the Gate 1 verification report.
- **Doc sentinels stripped before state storage**: `<!-- DOC_COMPLETE -->` and
  `<!-- DOC_TRUNCATED -->` are stripped from `documentation_md` before being stored in
  state, so they never appear in the UI, PDF report, or downstream agent prompts.

Fixed:
- Security findings injection in REQUEST_FIX was passing blank descriptions because wrong
  field names were used (`finding_type` / `location` / `description` → corrected to
  `test_name` / `filename` / `text`); offending code snippet and line number now included.
- Gate 2 approval buttons missing after regen — `REQUEST_FIX` was counted as a signed-off
  state, hiding the decision buttons. Fixed by excluding it from the `signedOff` check.
- Gate 2 security card rendered during Steps 7/8 regen. Gated on status correctly.
- Bandit `FileNotFoundError` despite being installed — subprocess path resolution on macOS
  fixed by using `sys.executable -m bandit` instead of the bare `bandit` shell command.
- `NameError: name 'os' is not defined` at startup — missing `import os` in `routes.py`.
- `loadJobs()` silently hiding live jobs when `/api/logs/history` errored.

### v2.2.2 — Verification & Documentation Token Efficiency (current)

Decouples the verification step from documentation and reduces documentation token usage
to eliminate the truncation-cascade failure mode on large mappings.

Changed:
- **Verification agent reads the graph, not the docs**: the documentation is human-facing
  and reviewed visually at Gate 1. Verification now runs graph structural checks
  (isolated transformations, disconnected sources/targets) and a Claude graph-risk review
  (hardcoded values, incomplete conditionals, high-risk logic, lineage gaps) — all driven
  by the mapping graph. Doc string-matching and the doc-based Claude quality call are
  removed.
- **Documentation: tier-based depth**: LOW-tier mappings (< 5 transformations) use a
  single pass — Overview + Transformations + Parameters only. MEDIUM/HIGH/VERY_HIGH use
  two passes as before.
- **Documentation Pass 2 no longer receives graph JSON**: Pass 1 output already contains
  all transformation detail. Removing the redundant payload cuts Pass 2 input tokens by
  ~50%, giving substantially more headroom before truncation.
- **Field-level lineage scoped to non-trivial fields**: derived, aggregated, lookup-result,
  conditional, and type-cast fields get full individual traces; passthrough and rename-only
  fields are consolidated into a single summary table. Eliminates the dominant source of
  Pass 2 output bloat on wide mappings.

### v2.3.0 — Code Review Hardening (current)

Addresses all immediate and short-term items from the external code review.

- **bcrypt password hashing**: replaced SHA-256 (fast hash, brute-forceable) with bcrypt
  work factor 12. Password hashed once at startup; `bcrypt.checkpw()` used for logins.
- **Claude API retry logic**: new `agents/retry.py` with exponential backoff (3 attempts,
  10 s base + jitter). Retries on 429/500/502/503/529. Applied to all agent Claude calls.
- **XML input validation**: upload endpoint rejects empty files and non-XML content with
  HTTP 400 before creating a job or spending API tokens.
- **Database indices**: `idx_jobs_status`, `idx_jobs_created_at`, `idx_jobs_batch_id`,
  `idx_jobs_deleted_at` — applied idempotently at startup.
- **`GET /api/health` endpoint**: liveness + readiness probe returning status, version,
  db connectivity, and uptime. HTTP 200 / 503. Suitable for Docker HEALTHCHECK.
- **Pydantic `Settings` class**: `backend/config.py` centralises all 20+ env var reads.
  Replaces scattered `os.environ.get()` calls across 10+ files.

### v2.3.6 — Verification Rank/Sorter Accuracy Improvements (current)

Fixed:
- **Parser captures Sorter sort keys** — `SORTKEYPOSITION` and `SORTDIRECTION` on Sorter
  `TRANSFORMFIELD` elements are now stored per port. Previously discarded; Claude had no
  visibility into the sort order feeding a downstream Rank.
- **Graph summary shows Rank config + Sorter sort order** — `_build_graph_summary()` emits
  `rank_config` (Number Of Ranks, Rank=TOP/BOTTOM) and `sort_keys` (field + direction).
  Eliminates false REVIEW_REQUIRED on Rank dedup mappings.
- **RANKINDEX DEAD_LOGIC suppression** — `rank_index_ports` collected and passed to Claude
  with an explicit prompt note. Post-filter also catches any DEAD_LOGIC Claude raises on
  RANKINDEX even if the prompt note is disregarded.
- **Accuracy check semantics corrected** — "No high-risk logic patterns detected" renamed
  to "Claude graph review completed". Passes when Claude ran; fails only on API error. High-
  risk findings surface as FLAGS — they no longer trigger a misleading REQUIRES_REMEDIATION.

### v2.3.5 — Verification Source Connectivity False Positive Fixes

Fixed:
- **Abbreviated SQ names**: source connectivity check now tests bidirectionally — if the SQ
  name (minus prefix) is a substring of the source name, the source is in-flow. Resolves
  false FAILED for patterns like `CORELOGIC_APPRAISALS` → `SQ_APPRAISALS`.
- **Lookup reference sources**: sources used as Lookup tables (e.g. `REF_COUNTY_LIMITS` via
  `LKP_COUNTY_LIMITS`) have no Source Qualifier. The check now inspects each Lookup
  transformation's `"Lookup table name"` attribute. These sources are now correctly marked
  as participating in data flow.
- **RANKINDEX orphaned port**: Rank transformations with `Number Of Ranks = 1` emit only the
  top-ranked row per group — deduplication is intrinsic; RANKINDEX never needs a downstream
  Filter connection. The false ORPHANED_PORT flag on `RANKINDEX` ports is suppressed.

### v2.3.2 — Verification Flag Auto-Handling

Fixed:
- **Source connectivity false positive**: the verification check always failed for Informatica
  source tables because they connect through Source Qualifiers (SQ_*), not directly.
  Check updated to detect `SQ_{source_name}` in the connected instance set. Renamed to
  "participates in data flow".

Added:
- **Verification flag auto-handling**: the conversion agent now receives all actionable
  Step 4 flags and addresses each in generated code. The tool converts successfully in
  the presence of verification flags rather than waiting for human intervention on
  auto-fixable issues. Per-flag rules: `INCOMPLETE_LOGIC` → pass-through + TODO stub;
  `ENVIRONMENT_SPECIFIC_VALUE` → config dict extraction; `LINEAGE_GAP` → None + TODO;
  `DEAD_LOGIC` → commented out; `REVIEW_REQUIRED` → best-effort + TODO; `UNRESOLVED_PARAMETER`
  → config placeholder; `UNSUPPORTED_TRANSFORMATION` → manual stub. Flags also carried
  into security fix rounds.

### v2.3.1 — Error Handling (Wrong File Type & Empty Pipeline) (shipped)

Fixed:
- **Wrong file type detection**: uploading a Workflow XML as the primary mapping file
  now produces an immediate BLOCKED result with a human-readable explanation. The parser
  detects `WORKFLOW` elements without `MAPPING` definitions and raises a `WRONG_FILE_TYPE`
  parse flag. Previously the pipeline silently advanced to steps 2–4 before blocking.
- **Empty mapping guard**: orchestrator explicitly checks for empty `mapping_names` after
  parsing and surfaces a descriptive error before advancing to Step 2.
- **Error message propagation**: parse flag `detail` text is stored in `state.error` and
  displayed in the UI error card. Users now see the exact reason a job blocked.
- **UI error card always renders**: the error card now appears for all FAILED/BLOCKED jobs.
  Falls back to parse flag details, then a generic step-number message. Tailored hints
  for known failure patterns: workflow-in-mapping-slot, no mappings found, missing API key.

### v2.4 — Mapping Manifest + Stability Fixes (shipped)

Pre-conversion manifest that surfaces naming-convention surprises before code generation
runs, plus a six-patch series closing all critical production stability gaps.

New features:
- **Step 1.5 — Mapping Manifest**: scores every source→SQ/Lookup connection (HIGH /
  MEDIUM / LOW / UNMAPPED), produces a three-sheet XLSX (Summary, Full Lineage, Review
  Required), and surfaces expressions, lookups, and unresolved parameters before Step 6
- **Reviewer override loop**: reviewer fills in the Override column for ambiguous rows
  and re-uploads; conversion agent reads overrides and injects them as hard requirements
- `POST /api/jobs/{id}/manifest-upload` — accepts annotated manifest XLSX
- `GET /api/jobs/{id}/manifest.xlsx` — downloads the current manifest
- **State compression** — zlib ~50× compression; `pipeline_log` capped at 300 entries;
  manifest XLSX no longer stored inline in state
- **Atomic batch creation** — `create_batch_atomic()` creates batch + all jobs in one
  SQLite transaction; rollback on failure prevents orphaned jobs
- **Deep-copy state** — all resume functions deep-copy state before mutation
- **Timeout watchdog** — jobs stuck in active pipeline statuses for 45+ minutes are
  automatically marked FAILED
- **Output validation** — `_validate_conversion_files()` checks every generated file for
  emptiness, placeholder-only (>60% TODOs), Python syntax errors, and missing
  SparkSession/SELECT
- **BEGIN IMMEDIATE write locking** — eliminates SQLite SQLITE_BUSY errors under concurrent batch runs
- **Audit trail** — every Gate 1/2/3 decision stamped to a dedicated `audit_log` table
- **GAP fixes**: SSE queue leak, download path traversal, graceful shutdown, model
  deprecation probe, startup secret-key guard, DB index idempotency

### v2.5 — Job Artifact Export (shipped)

Completed jobs can be exported to disk and downloaded as a ZIP archive.

New features:
- Gate 3 APPROVED jobs write a structured output directory: generated code files, test
  files, S2T Excel, security scan report, Markdown documentation, and a JSON manifest
- `GET /api/jobs/{id}/export` — builds and returns the output ZIP on demand
- Output directory configurable via `OUTPUT_DIR` env var; set to `disabled` to suppress disk writes

### v2.6 — Performance at Scale + Security Hardening (shipped)

Performance guidance baked into all code-generation prompts, infrastructure tuning for
production-scale workloads, and a security audit hardening pass.

New features:
- **PySpark performance rules**: partition strategy, broadcast joins, UDF ban, avoid
  `.collect()` inside loops, partition pruning, shuffle minimisation, `.cache()`
  checkpoints, `spark.sql.shuffle.partitions` default
- **dbt performance rules**: materialisation selection (view / incremental / table),
  incremental strategy per warehouse (BigQuery insert_overwrite, Snowflake merge),
  partition/cluster keys, SELECT ∗ ban, filter-early guidance
- **Python/Pandas performance rules**: `chunksize` mandatory on `pd.read_csv()`, no
  `iterrows()` on large frames, memory-efficient joins, chunk-pipeline pattern
- **Stage C — Performance Review**: third review stage after Stage B; checks generated
  code for scale anti-patterns (collect, UDFs, missing partition hints, cartesian joins,
  iterrows, read_csv without chunksize); advisory only — no pipeline gate
- `PerfReviewReport` added to data model and stored under `state["perf_review"]`
- **SQLite WAL mode** — concurrent readers no longer blocked by writers; `PRAGMA
  journal_mode=WAL` + `synchronous=NORMAL` set at `init_db()`
- **`complexity_tier` column** — jobs table stores the tier string so `GET /api/jobs`
  can filter/display tier without decompressing state
- **Pagination for `GET /api/jobs`** — accepts `?limit=N&offset=M&status=S`; returns
  `{"total": N, "jobs": [...]}` envelope
- **v2.6.1 security hardening**: path-traversal in export endpoint, SSRF in webhook
  stub, open redirect in auth, timing-safe token comparison, unsafe YAML load →
  `yaml.safe_load`, `schema_version` field on all persisted Pydantic models

### v2.7 — dbt Execution-Ready Output (shipped)

Generated dbt models now produce a complete, runnable project out-of-the-box.

New features:
- Every dbt conversion includes a `dbt_project.yml` at the project root with correct
  model paths, version, and profile reference
- `profiles.yml` template generated alongside code with `env_var()` stubs for all
  connection credentials — no hardcoded secrets
- `packages.yml` included when dbt-utils macros are used in generated models
- Macros written to `macros/` directory with correct Jinja function signatures
- `schema.yml` / `sources.yml` include `freshness` blocks and `not_null` / `unique`
  tests on primary key columns
- All file paths in generated `sources.yml` use the correct `database.schema.table`
  three-part reference format
- dbt `ref()` and `source()` calls validated: no bare table name references

### v2.8 — Validation Framework (shipped)

Comprehensive automated test suite covering the full pipeline from parsing through
reconciliation.

New features:
- **`tests/test_core.py`** — 76 unit tests: XML parser edge cases, complexity scoring,
  S2T extraction, documentation sentinels, verification flag logic, security scan
  patterns, code review checks, test generation, orchestrator state machine transitions
- **`tests/test_steps58.py`** — Steps 5–8 integration tests: Gate 1 sign-off logic,
  stack assignment, conversion output validation, security scan bandit/YAML/Claude paths
- **`tests/smoke_execute.py`** → `app/backend/smoke_execute.py` — static file validation
  without a live database: `py_compile` for Python/PySpark, SELECT/Jinja delimiter
  balance for dbt SQL, `yaml.safe_load` for YAML; now wired into pipeline as Step 7b
  (non-blocking, results stored as `smoke_flags` on `ConversionOutput`)
- **`app/backend/agents/reconciliation_agent.py`** — structural reconciliation: target
  field coverage, source table coverage, expression/business-rule coverage, stub
  completeness; `ReconciliationReport` with `match_rate`, `mismatched_fields`, and
  `final_status` (RECONCILED / PARTIAL / PENDING_EXECUTION); now wired into pipeline as
  Step 10b in both `resume_after_signoff` and `resume_after_security_review`
- **`tests/test_routes.py`** — REST API contract tests: all 20+ endpoints exercised
  against a test SQLite DB with fixture jobs; status code, content-type, and payload
  shape assertions
- **CI** — GitHub Actions `test.yml` workflow runs `pytest -x` on every push to `main`
  and on all PRs targeting `main`; job fails on first error
- **Version string centralised** — `APP_VERSION = "2.8.0"` in `config.py`; `main.py`
  (FastAPI + health endpoint) and `routes.py` both reference `_cfg.app_version` — no
  more scattered hardcoded strings
- **HTTP security headers** — new middleware in `main.py` adds `X-Content-Type-Options`,
  `X-Frame-Options: DENY`, `X-XSS-Protection`, `Referrer-Policy`,
  `Permissions-Policy`, `Content-Security-Policy`, and (when `HTTPS=true`)
  `Strict-Transport-Security` to every response

### v2.9 — Webhook Notifications (shipped)

Outbound HTTP notifications at every gate pause, completion, and hard failure —
no more polling the UI to find out a job is waiting.

New features:
- **`app/backend/webhook.py`** — async `fire_webhook()` function; non-blocking,
  non-fatal; all failures logged as warnings and swallowed
- **Three event types**: `gate_waiting` (Gates 1/2/3 paused for human decision),
  `job_complete` (Gate 3 approved, code ready), `job_failed` (terminal FAILED/BLOCKED)
- **Structured JSON payload** on every POST: `event`, `job_id`, `filename`, `step`,
  `status`, `message`, `gate`, `timestamp`, `tool`, `version`
- **Seven fire points** in the orchestrator: parse BLOCKED, Gate 1 pause,
  conversion FAILED, Gate 2 pause, Gate 3 pause (both pipeline paths), job COMPLETE
- **HMAC-SHA256 request signing** — set `WEBHOOK_SECRET` in `.env`; every request
  carries `X-Webhook-Signature: sha256=<hex>` so receivers can verify origin
- **Config**: `WEBHOOK_URL` (required), `WEBHOOK_SECRET` (optional), `WEBHOOK_TIMEOUT_SECS`
  (default 10) — all in `.env` / environment variables
- Works with Slack incoming webhooks, Teams incoming webhooks, PagerDuty Events API,
  or any HTTP endpoint that accepts a JSON POST

### v2.10 — GitHub PR Integration (shipped)

After Gate 3 approval the tool automatically opens a draft pull request with all
generated code and test files — no ZIP download or manual commit required.

New features:
- **`app/backend/git_pr.py`** — `create_pull_request()` async function; non-blocking,
  non-fatal; all errors logged as warnings
- **Branch naming**: `informatica/{mapping-name-slug}/{job-id-short}` — e.g.
  `informatica/m-loan-scd2/3f2a1b4c`
- **Draft PR** opened against `GITHUB_BASE_BRANCH` (default `main`) containing all
  generated code files and test files
- **Structured PR description**: mapping details, quality summary table (coverage,
  equivalence, reconciliation, code review), file list, and all three gate decisions
  with reviewer names
- **GitHub Enterprise support**: set `GITHUB_API_URL` to your GHE instance API root
- **`pr_url` stored in state** — visible via `GET /api/jobs/{id}` after completion;
  included in the `job_complete` webhook payload
- **Config**: `GITHUB_TOKEN`, `GITHUB_REPO`, `GITHUB_BASE_BRANCH`, `GITHUB_API_URL`

### v2.11 — Mapplet Detection (shipped)

Mapplets are reusable sub-mappings common in long-running Informatica estates.
v2.11 makes them visible at every pipeline stage so reviewers know exactly what
to verify manually.

- **`ParseReport.mapplets_detected`** — new list field; every unique mapplet name found
- **`graph["mapplets"]`** — new graph key passed to all downstream agents
- **`ParseFlag` per mapplet** — context-aware message distinguishes "definition present"
  (exported with *Include Dependencies*) from "instance only, definition missing"
  (re-export guidance included)
- **`VerificationFlag` at Gate 1** — consolidated HIGH-severity flag lists all detected
  mapplet names with an actionable recommendation; non-blocking so conversion continues
- **`FLAG_META["MAPPLET_DETECTED"]`** — severity and recommendation registered
- Detection is fully deterministic; no LLM call required

### v2.12 — Mapplet Inline Expansion (shipped)

The parser now replaces each mapplet instance with its fully resolved set of
transformations and connectors so the conversion agent sees no black-box references.

- **`_extract_mapplet_def()`** — extracts internal transformations, connectors,
  and Input/Output interface node names from each `<MAPPLET>` definition block
- **`_inline_expand_mapplets()`** — inlines definitions into mappings:
  prefixes each internal node as `{instance_name}__{node_name}`, rewires external
  connectors through the Input/Output interface, and adds all internal connectors
- **`ParseReport.mapplets_expanded`** — new list field; names of all expanded mapplets
- **Two flag types**: `MAPPLET_EXPANDED` (MEDIUM, definition found and expanded) and
  `MAPPLET_DETECTED` (HIGH, instance found but definition missing — re-export guidance)
- Supports multiple instances of the same mapplet in one mapping (distinct prefixes)
- Zero overhead for mappings with no mapplets

### v2.13 — Data-Level Equivalence Testing (shipped)

- **Component A — Expression boundary tests**: `test_agent.py` detects five high-risk
  expression categories (IIF, DECODE, date functions, string functions, aggregations)
  and generates parametrized pytest tests with NULL-boundary cases for each
- **Component B — Golden CSV comparison script**: self-contained `compare_golden.py`
  generated per job; data engineers run it externally after capturing Informatica
  output to field-by-field compare against generated-code output
- **`docs/TESTING_GUIDE.md`**: new guide documenting all test layers, execution
  sequence, helper-stub instructions, and FAQ; explicitly documents that the tool
  generates test artifacts but does not execute them

### v2.14 — Manifest-Based File Watcher (shipped)

- **`app/backend/watcher.py`**: background asyncio task polling a configured
  directory for `*.manifest.json` files; on finding a complete manifest (all
  referenced XML files present) automatically submits a conversion job through
  the same pipeline path as the API endpoint
- **Manifest format**: JSON file specifying mapping XML (required), workflow XML,
  parameter file, reviewer name/role (all optional); signals that all files for
  one conversion are ready — eliminates partial-export race conditions
- **Lifecycle**: processed manifests move to `processed/`; incomplete manifests
  retry each poll and move to `failed/` after configurable TTL; invalid manifests
  fail immediately with `.error` sidecar
- **UI transparent**: existing 5-second job list poll surfaces watcher jobs
  automatically; SSE streaming and all gate reviews work identically to
  manually uploaded jobs
- **Config**: `WATCHER_ENABLED`, `WATCHER_DIR`, `WATCHER_POLL_INTERVAL_SECS`,
  `WATCHER_INCOMPLETE_TTL_SECS` — all documented in `.env.example`

### v2.14.1 — Project-Group Manifest + Named Output Directories (shipped)

- **Option A manifest schema**: each entry in `"mappings"` is now either a plain
  filename string (inherits top-level `"workflow"` / `"parameters"` defaults) or
  an object with its own `"workflow"` / `"parameters"` fields that override the
  top-level values for that mapping only — accommodates projects where different
  mappings use different workflow XMLs without requiring separate manifests
- **`"label"` field**: optional human-readable batch name; drives the output
  folder name and the batch label shown in the UI; if omitted, falls back to
  the manifest filename stem
- **Named output directories**: watcher artifacts now written to
  `OUTPUT_DIR/<label>_<YYYYMMDD_HHMMSS_ffffff>/<mapping_stem>/` — output is
  navigable by project name and mapping name without querying the database;
  microsecond timestamp appended always so re-runs never overwrite prior output
- **`job_exporter.py`**: reads `watcher_output_dir` and `watcher_mapping_stem`
  hints from job state (set by watcher at creation time) to resolve named paths;
  UI-submitted jobs continue to use `OUTPUT_DIR/<job_id>/`
- Backward compatible: v2.14.0 single-string manifest entries and all prior
  formats continue to work without modification

### v2.15.0 — Time-Based Manifest Scheduler (shipped)

- **`app/backend/scheduler.py`** (new module): background asyncio task that
  evaluates `*.schedule.json` files in `SCHEDULER_DIR` every
  `SCHEDULER_POLL_INTERVAL_SECS` seconds and materialises `*.manifest.json`
  files into `WATCHER_DIR` when cron expressions fire
- **Schedule file format**: JSON with `cron` (5-field, required), `timezone`
  (IANA, optional — defaults to UTC), `label` (optional), `enabled` (optional
  — allows pausing without deletion), `manifest` (required — embedded manifest
  payload identical to a hand-dropped manifest)
- **Pure cron evaluator** (`_cron_matches`): supports `*`, `*/n`, `a-b`,
  `a-b/n`, `a,b,c` and comma-joined combinations; DOW 0 and 7 both map to
  Sunday; raises `ValueError` on malformed syntax so errors surface at
  schedule-read time rather than silently misfiring
- **Duplicate-fire guard**: tracks last `(hour, minute)` per schedule stem so a
  schedule fires at most once per minute even if `poll_interval < 60`
- **Timezone-aware evaluation** via `zoneinfo` (stdlib since Python 3.9); falls
  back to UTC with a warning log on unrecognised timezone names
- **Config**: `SCHEDULER_ENABLED`, `SCHEDULER_DIR`, `SCHEDULER_POLL_INTERVAL_SECS`
  — all documented in `config.py` and `.env.example`
- **Dependency on watcher**: scheduler logs an error and does not start if
  `WATCHER_ENABLED` is false or `WATCHER_DIR` is unset; both subsystems must be
  active for the full lights-out pipeline to function
- Schedule files are re-read on every poll — changes take effect without a
  server restart

### v2.15.1 — Security Hardening Patch (shipped)

Six targeted fixes across the app backend. No pipeline behaviour changes.

- **ReDoS fix** — `_YAML_PLACEHOLDER_RE` in `security.py` changed `<.+>` to `<.+?>`
  (non-greedy); eliminates catastrophic backtracking on adversarial YAML input
- **Rate-limit bypass closed** — new `_real_client_ip()` in `limiter.py`; default
  `TRUSTED_PROXY_COUNT=0` ignores `X-Forwarded-For` (prevents header-spoofing to
  bypass per-IP rate limits); `TRUSTED_PROXY_COUNT=N` enables correct proxy-chain IP
  extraction for nginx / CloudFlare deployments
- **Health endpoint exception leakage fixed** — `/api/health` and `/health` log
  failures at WARNING and return only `"error"`, not the raw exception string
- **`__import__` anti-pattern removed** — three `__import__("datetime").datetime`
  usages in `routes.py` and `orchestrator.py` replaced with a top-of-file import
- **Authorization model documented** — comment block in `routes.py` explains
  the single-credential design, consequence (no per-job ownership), and migration
  path for future multi-user isolation
- **`.env.example` completed** — all previously undocumented config variables
  now have inline explanations: `SESSION_HOURS`, `BCRYPT_ROUNDS`, `LOG_LEVEL`,
  `DB_PATH`, `JOB_RETENTION_DAYS`, `CLEANUP_INTERVAL_HOURS`, `OUTPUT_DIR`,
  `TRUSTED_PROXY_COUNT`, `RATE_LIMIT_JOBS`, `RATE_LIMIT_LOGIN`,
  `VERIFY_TIMEOUT_SECS`, `AGENT_TIMEOUT_SECS`, `EXTENDED_OUTPUT_BETA`

### v2.16.0 — Config-Driven Pattern Library (✅ complete — 2026-03-10)

A fundamental shift in conversion output quality and code footprint. Instead of
generating bespoke code for every mapping, the conversion agent identifies which
of ten recognised patterns a mapping fits, extracts the config parameters from
the XML, and emits a YAML config that drives a pre-built, tested library
component at runtime.

**Core design:** see `docs/DESIGN_PATTERN_LIBRARY.md` for the full specification.

**Status:** All 5 phases complete — 199/199 tests passing.
Package: `etl_patterns/` at repo root (pip-installable via `pip install -e etl_patterns/`).

#### Phase 1 — Foundation (✅ complete, commit `b8f8d77`)

84 tests. Full infrastructure layer — no pattern logic, needed by everything:

- **`etl_patterns/` pip-installable package** (`pyproject.toml`, `setuptools.build_meta`)
- **Exception hierarchy** (`exceptions.py`): `ETLPatternError` → `ConfigError`,
  `PatternNotFoundError`, `ReaderError`, `WriterError`, `ExpressionError`,
  `WatermarkError`, `ValidationError`, `PatternError`
- **Shared utilities** (`utils/`): `etl_metadata`, `null_safe`, `type_cast`,
  `string_clean`, `watermark_manager`, `file_lifecycle`
- **IO abstraction layer** (`io/`): `DatabaseReader`, `FlatFileReader`,
  `FixedWidthReader`, `DatabaseWriter`, `FlatFileWriter`, factory functions
- **Config loader** (`config_loader.py`): one-call `run("path.yaml")` entry point;
  lazy pattern dispatch; all 10 patterns registered
- **Expression evaluator** (`expression.py`): safe column DSL — `{COL}` references,
  named functions, arithmetic, comparison and boolean operators; no `eval`
- **Pattern base class** (`patterns/base.py`): IO wiring, metadata injection,
  timing, structured result dict
- **Two fully implemented patterns**: `pass_through`, `truncate_and_load`

#### Phase 2 — High-frequency Patterns (✅ complete, commit `a1a64d7`)

127 tests. 43 new tests added.

- **`incremental_append`** — watermark-driven append (DB + flat-file); patches
  `DatabaseReader.read()` with a watermark-filtered SQL closure; auto-advances
  watermark to `MAX(col)` after each successful run
- **`expression_transform`** — full column_map DSL with row-level `filter_expr`,
  `dedup_keys`, and `sort_by`
- **Expression DSL fix** — comparison operators (`==`, `!=`, `>=`, `<=`, `>`, `<`,
  `and`, `or`, `not`) now supported; `repr()` quoting for string values
- **WatermarkManager fix** — split DELETE + INSERT into two separate `conn.execute()`
  calls to comply with SQLAlchemy 2.x single-statement restriction

#### Phase 3 — Complex Patterns (✅ complete, commit `5fb0ef5`)

160 tests. 33 new tests added.

- **`upsert`** — SCD Type 1 merge on business key; validates `unique_key` config;
  existing rows overwritten, new rows inserted
- **`scd2`** — SCD Type 2 full-history merge with `effective_from`, `effective_to`,
  `is_current`; new rows inserted, changed rows expired + re-inserted, unchanged skipped;
  first-run safe (handles missing target table)
- **`lookup_enrich`** — N-way reference join (DB or flat-file); module-level cache;
  `join_keys` dict, optional `prefix`, `left`/`inner` join types
- **DB writer fix** — `_write_upsert` split into two transactions (DELETE then INSERT)
  to prevent SQLAlchemy 2.x silent transaction interference; numpy scalar coercion added

#### Phase 4 — Multi-stream Patterns (✅ complete, commit `4cd4756`)

199 tests. 39 new tests added.

- **`aggregation_load`** — GROUP BY + named aggregations (sum, count, avg→mean, min,
  max, first, last, nunique, std, var, median); optional `having` DSL filter;
  optional `sort_by`
- **`filter_and_route`** — Router equivalent; single source → N targets each with a
  `filter_expr`; optional per-target `column_map`; catch-all `"true"` target supported;
  overrides `BasePattern._write()`
- **`union_consolidate`** — Union equivalent; N sources each with optional per-source
  `column_map` for schema normalisation; `dedup_keys`; `sort_by`; overrides `execute()`
- **FlatFileReader fix** — ETL-style `column_map` (list of expression dicts) is stripped
  from reader config before IO wiring to prevent conflict with reader's rename-style map

#### Phase 5 — Classifier + Conversion Agent Integration (✅ complete, commit `3b43411`)

- **10-pattern decision tree** in `classifier_agent._classify_pattern()` — priority-ordered
  rules matching transformation topology to pattern name; returns `suggested_pattern`,
  `pattern_confidence` (HIGH / MEDIUM / LOW / NONE), and `pattern_rationale`
- **`_build_pattern_yaml_skeleton()`** — generates a pre-filled starter YAML config
  from the parsed graph (source/target names, pattern-specific blocks, all ambiguous
  fields annotated `# TODO`)
- **Conversion agent integration** — after code generation, when confidence ≠ NONE,
  emits `config/<mapping>.yaml` and `run.py` into the output file set; non-blocking
  (falls back gracefully on any error)
- **`ComplexityReport` schema extended** — three new optional fields:
  `suggested_pattern`, `pattern_confidence`, `pattern_rationale` (default `None`;
  fully backward-compatible with stored state blobs from prior versions)
- **Orchestrator updated** — both convert call sites (initial run + security-fix
  regeneration path) pass `complexity_report` to `convert()`

#### Summary

| Phase | Patterns added | Cumulative tests |
|-------|---------------|-----------------|
| 1 | pass_through, truncate_and_load + full infra | 84 |
| 2 | incremental_append, expression_transform | 127 |
| 3 | upsert, scd2, lookup_enrich | 160 |
| 4 | aggregation_load, filter_and_route, union_consolidate | 199 |
| 5 | Classifier decision tree + conversion agent integration | 199 |

All 10 patterns registered in `config_loader`. 199/199 tests passing.

#### Design notes

- **IO abstraction**: source/target blocks support database (SQLAlchemy), delimited
  flat files, and fixed-width flat files — any combination is valid
- **Confidence classification**: HIGH (auto-config), MEDIUM (config + flagged elements),
  LOW (pattern suggested, human confirms), NONE (falls back to bespoke LLM generation)
  — surfaces in the existing pipeline output, no new gate required
- **Deterministic decision tree**: pattern assignment driven by transformation topology
  — not naming conventions, not AI heuristics
- **Future roadmap (out of scope for v2.16.0)**: message queues (Kafka, SQS),
  REST API sources, FTP/SFTP, cloud storage (S3/ADLS/GCS), streaming targets

### v2.17.0 — Generic Component Architecture (✅ complete — 2026-03-11)

Eliminates hardcoded org-specific values from all pipeline agents and introduces a
config-first architecture. Every constant that previously required a code edit
(audit column names, pattern classification keywords, warehouse profiles, verification
flag severities, system prompts) is now externalisable via two optional YAML files and
a prompts folder. Backwards-compatible — all defaults are preserved; absent config files
produce identical output to v2.16.0.

#### G1 — Configurable pattern classification signals

`classifier_agent.py` previously hard-coded the keyword lists that identify SCD2, upsert,
and incremental-append patterns (e.g. `["_SCD2", "_HIST"]`). These are now loaded from
`app/config/org_config.yaml → pattern_signals` via `org_config_loader.get_pattern_signals()`.
Expression-complexity indicators are likewise externalised. Deployments with non-standard
naming conventions no longer require forking the classifier.

#### G2 — Configurable DW audit columns

`conversion_agent.py` previously had three audit columns (`DW_INSERT_DT`, `DW_UPDATE_DT`,
`DW_SOURCE_SYS`) hard-coded in the PySpark/dbt/Python system prompts. These are now read
from `org_config.yaml → audit_fields` and injected as a dynamic rule block via
`org_config_loader.build_dw_audit_rules()`. Any field can be renamed, have its expression
changed, or be suppressed entirely.

#### G3 — Jinja2 system prompt overrides

`conversion_agent.py` loads `app/prompts/<stack>_system.j2` at startup. If the file exists
it replaces the built-in system prompt for that stack entirely; otherwise the built-in
string is used unchanged. Template authoring guide at `app/prompts/README.md`.

#### G4 — Configurable verification flag policy

`verification_agent.py` previously had all flag severities and blocking statuses baked into
the `FLAG_META` constant. These are now merged with `org_config.yaml → verification_policy`
at call time via `org_config_loader.get_verification_policy()`. Operators can promote LOW
flags to HIGH, suppress noisy false positives to INFO, or change blocking status — all
without touching Python.

#### G5 — Extensible warehouse registry

`app/config/warehouse_registry.yaml` registers 8 warehouse profiles (PostgreSQL, Snowflake,
Redshift, BigQuery, Databricks, SQL Server, Azure Synapse, Microsoft Fabric). New targets
are added with a YAML entry — no Python changes required. `conversion_agent.py` consults
the registry before falling back to its built-in profiles.yml generator.

#### G6 — Conditional step skip + gate auto-approve

`orchestrator.py` evaluates `org_config.yaml → pipeline_options.skip_steps` and
`auto_approve_gates` before each skippable step (Step 4 — documentation; Step 11 — test
generation) and gate. Conditions are expressed as `{tier, pattern, pattern_confidence}`
predicates. Useful for CI pipelines and HIGH-confidence LOW-complexity bulk runs.

#### G7 — Configurable unsupported transformation types

All three agents that maintain `UNSUPPORTED_TYPES` (`classifier_agent.py`,
`verification_agent.py`, `parser_agent.py`) now call
`org_config_loader.get_unsupported_types()`, which merges the built-in set with
`org_config.yaml → parser_options.additional_unsupported_types`.

#### New files

| File | Purpose |
|---|---|
| `app/backend/org_config_loader.py` | Central config loader — single `lru_cache(1)` per YAML file; all agents import from here |
| `app/config/org_config.yaml` | Org overrides (all sections commented-out by default — safe to ship) |
| `app/config/warehouse_registry.yaml` | 8 pre-registered warehouse profiles |
| `app/config/__init__.py` | Package marker |
| `app/prompts/README.md` | Jinja2 template authoring guide |

#### Changed files

| File | Change |
|---|---|
| `app/backend/agents/classifier_agent.py` | G1: pattern signals + expression indicators from config; G7: unsupported types from config |
| `app/backend/agents/conversion_agent.py` | G2: dynamic audit rules; G3: Jinja2 prompt loader; G5: warehouse registry lookup |
| `app/backend/agents/verification_agent.py` | G4: verification policy override merge; G7: unsupported types from config |
| `app/backend/agents/parser_agent.py` | G7: unsupported types from config |
| `app/backend/orchestrator.py` | G6: skip_steps + auto_approve_gates evaluation |

#### Migration note

No database migration required. No `.env` changes required. Deploy v2.17.0 over any
v2.16.0 installation — if `app/config/org_config.yaml` does not exist all agents fall
back to built-in defaults and the pipeline behaves identically to v2.16.0.

---

### v2.18 — Estate Analyser + Migration Wave Management (planned)

Before the first mapping is converted, migration leads need to understand the full scope
of the estate, prioritise the work, and plan waves. v2.18 introduces a pre-conversion
analysis mode that operates at repository scale without triggering the full pipeline.

#### Estate Analyser

- **Bulk XML ingestion**: accept a ZIP of all Informatica mapping XMLs (no workflow or
  parameter files required); runs Step 0 + Step 1 + Step 2 only — no Claude API calls,
  no gates
- **Estate summary report**: pattern distribution (how many SCD2, upsert, pass-through,
  etc.), complexity tier breakdown, total source/target table count, $$VAR coverage rate,
  unsupported transformation inventory
- **Effort estimate**: maps complexity tier × average pipeline time to a per-mapping
  estimate; aggregates to total hours and Claude API cost projection across the full estate
- **`GET /api/estate/analyse`** — accepts a batch ZIP; returns `EstateReport` JSON +
  downloadable Excel summary workbook
- No jobs created, no state persisted — analysis is stateless and repeatable

#### Migration Wave Planner

- **Dependency graph**: parser detects cross-mapping dependencies (shared lookup tables,
  sequential session targets used as sources in another mapping); renders as a DAG
- **Wave sequencing**: topological sort of the dependency graph produces a recommended
  wave sequence — upstream mappings convert first, downstream mappings block on their
  dependencies completing
- **Wave assignment**: leads can accept the suggested waves or drag-and-drop reassign;
  assignments persisted as a `waves` table alongside jobs
- **Quick-win identification**: LOW-tier, HIGH-confidence, no-dependency mappings
  flagged as candidates for Wave 1 to build reviewer confidence early
- **`POST /api/waves`** — create / update wave plan for a batch
- **`GET /api/waves/{batch_id}`** — retrieve wave assignments and dependency graph

---

### v2.19 — Multi-User Access Control + SSO (planned)

Enterprise IT will not deploy a shared-password tool. v2.19 replaces the single-credential
auth model with named users, role-based permissions, and SSO.

#### Named user model

- **User table**: `users` — `user_id`, `email`, `display_name`, `role`, `created_at`,
  `last_login`; bcrypt passwords retained for local accounts
- **Roles**: `ADMIN` (manage users, view all jobs), `REVIEWER` (gate decisions only),
  `ENGINEER` (upload + view own jobs), `READ_ONLY` (view + download, no decisions)
- **Job ownership**: `created_by` + `reviewed_by` stamped on every job and gate decision;
  audit log records named reviewer on every gate
- **`POST /api/admin/users`** — ADMIN only; create, update, deactivate users
- **`GET /api/admin/users`** — ADMIN only; user list with last-login and job counts

#### SSO / OIDC

- **OIDC provider support**: `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` in
  `.env`; standard authorization-code flow; groups claim mapped to roles
- **SAML 2.0**: optional `SAML_METADATA_URL` for organisations that require SAML over OIDC
- **Just-in-time provisioning**: first SSO login creates a local user record with role
  derived from the IdP group claim; no pre-provisioning required
- **Local accounts**: retained for non-SSO deployments and service accounts (CI, watcher)
- **Session management**: per-user session tokens; admin can invalidate all sessions for
  a user; `SESSION_HOURS` applies per-user

#### Review assignment

- **Gate assignment**: batch upload or wave plan can designate a named reviewer per
  mapping; webhook notifications addressed to the assigned reviewer
- **Coverage view**: dashboard shows which jobs are awaiting review and who is assigned,
  preventing jobs from sitting unreviewed

---

### v3.0 — Vision

- **Continuous migration mode**: monitor Informatica Designer exports and auto-convert on
  change; diff-level PR updates when a mapping re-exports with changes — only changed
  rules re-verified, existing approved code preserved
- **Migration velocity dashboard**: conversion success rate, time-to-review per gate,
  rework rate (REQUEST_FIX frequency), security finding frequency by pattern type,
  team throughput — all queryable by date range, team, and complexity tier; exportable
  for steering committee reporting
- **Re-export delta handling**: when a mapping changes mid-migration and is re-uploaded,
  diff the new XML against the prior conversion; re-run only the affected pipeline steps;
  preserve Gate 3-approved sections unchanged
- **Self-hosted model support**: route conversion calls to an on-premise LLM endpoint for
  air-gapped environments; configurable per-step model routing (e.g. local model for
  documentation, Claude for code generation)
- **Repository-level object handling**: PowerCenter parameter sets, session configurations,
  shared containers, and repository-level reusable transformations handled natively —
  not surfaced as flags

---

## 4. Pipeline Architecture

```
Upload (Mapping XML + optional Workflow XML + optional Parameter File  OR  ZIP archive)
    │
    ▼
Step 0   Session & Parameter Parse
         Auto-detect file types → Cross-reference validation → $$VAR resolution
         → Scan uploaded XML for embedded credentials (passwords in CONNECTION attrs)
         → Blocked if INVALID (mapping/session mismatch); PARTIAL if warnings
    │
    ▼
Step 1   XML Parse & Graph Extraction  [deterministic, lxml + XXE-hardened parser]
Step 2   Complexity Classification     [rule-based, objective criteria from parsed XML]
Step S2T Source-to-Target Field Map    [Claude + openpyxl Excel output]
Step 3   Documentation Generation      [Claude, Markdown]
Step 4   Verification                  [deterministic + Claude flags]
    │
    ▼
Step 5   ◼ Gate 1 — Human Review Sign-off
         APPROVE → Step 6
         REJECT  → BLOCKED (terminal)
    │
    ▼
Step 6   Target Stack Assignment       [Claude classifier]
Step 7   Code Generation               [Claude, multi-file output]
Step 7b  Smoke Execution Check         [non-blocking; py_compile / SQL balance / yaml.safe_load]
         → Failures stored as HIGH smoke_flags on ConversionOutput; pipeline continues
    │
    ▼
Step 8   Security Scan                 [bandit (Python) + YAML regex + Claude review]
         → Produces: APPROVED / REVIEW_RECOMMENDED / REQUIRES_FIXES
    │
    ▼
Step 9   ◼ Gate 2 — Human Security Review
         APPROVED     → auto-proceed to Step 10 (scan was clean)
         ACKNOWLEDGED → proceed to Step 10 (issues noted, risk accepted)
         REQUEST_FIX  → re-run Step 7 with findings injected → re-run Step 8 → re-present Gate 2
                        (max 2 remediation rounds; auto-proceeds to Step 10 if re-scan is clean)
         FAILED       → BLOCKED (terminal)
         [Pauses only when scan is not APPROVED]
    │
    ▼
Step 10  Logic Equivalence Check       [Stage A: Claude, XML → code rule-by-rule comparison]
         Code Quality Review           [Stage B: Claude cross-check vs. docs, S2T, parse flags]
         Performance Review            [Stage C: advisory anti-pattern scan at scale]
Step 10b Structural Reconciliation     [non-blocking; field coverage, source coverage,
         → ReconciliationReport (RECONCILED / PARTIAL / PENDING_EXECUTION) stored in state]
Step 11  Test Generation               [Claude, pytest / dbt test stubs]
         → Security re-scan of generated test files (merged into Step 8 report)
    │
    ▼
Step 12  ◼ Gate 3 — Code Review Sign-off
         APPROVED  → COMPLETE
         REJECTED  → BLOCKED (terminal)
```

---

## 5. Stack Assignment Decision Matrix

Step 6 assigns one of three target stacks (or a documented hybrid) based on the
criteria below. The assignment is deterministic given the mapping characteristics —
reviewers can override at Gate 1 by adding a note, but the default follows this matrix.

| Criterion | PySpark | dbt | Python (Pandas) |
|---|---|---|---|
| **Complexity tier** | HIGH / VERY_HIGH | LOW / MEDIUM | LOW / MEDIUM |
| **Data volume** | > 50M rows | Any (SQL-bound) | < 1M rows |
| **Source type** | DB, files, streams | DB / warehouse | Files (CSV/JSON/XML), APIs |
| **Target type** | DB, data lake, files | Data warehouse | Files, APIs, lightweight DB |
| **Transformation types** | Complex joins, multi-aggregations, UDFs, procedural logic | SQL-expressible — filters, joins, aggregations, SCDs, derived fields | Simple field mapping, API calls, file format conversion |
| **SCD support** | SCD1 + SCD2 (merge/upsert) | SCD1 + SCD2 (snapshots) | SCD1 only (practical limit) |
| **Join complexity** | Multiple joiners, complex conditions, cross-dataset | Single or multi JOIN in SQL | Simple merges only |
| **Lookup handling** | Broadcast join, dynamic cache | CTE or ref() | Dict lookup / merge |
| **Expressions** | Spark functions + UDFs | SQL CASE/COALESCE/macros | Python functions |
| **Parallelism** | Native (Spark cluster) | Warehouse-native | None (single process) |
| **Test framework** | pytest + pyspark.testing | dbt tests (schema.yml) | pytest |
| **Output artifacts** | `.py` job + `requirements.txt` + YAML configs | `.sql` models + `schema.yml` + `sources.yml` + macros | `.py` script + `requirements.txt` |
| **Auto-assigned when** | ≥1 Joiner + HIGH tier, or VERY_HIGH, or volume flag | SQL-friendly transformations + warehouse target | LOW tier + file/API source or target |

**Hybrid:** Where a single mapping has sub-flows that suit different stacks, the assignment
record documents which component maps to which stack and why. Hybrid is rare — most
Informatica mappings have a dominant pattern that determines the stack clearly.

---

## 6. Security Architecture

Security is infrastructure, not a feature layer. Every file-handling path in the application
flows through `backend/security.py`.

| Threat | Defence |
|---|---|
| XML External Entity (XXE) | `safe_xml_parser()` — DTD loading and entity resolution disabled on every lxml parse |
| Zip Slip | `safe_zip_extract()` — every entry path resolved relative to virtual root before write |
| Zip Bomb | `safe_zip_extract()` — total extracted bytes and entry count capped |
| Symlink attacks | Symlink entries in ZIP silently skipped |
| Oversized uploads | `validate_upload_size()` called on every upload stream before processing |
| Dependency CVEs | 7 CVEs patched in v1.1 (python-multipart ×2, jinja2 ×3, starlette ×2); reproducible via `pip-audit` |
| Hardcoded secret key | Startup warning logged if `SECRET_KEY` is the default placeholder value |
| Unauthenticated access | Session-cookie middleware enforces login on all non-static routes |
| CORS misconfiguration | No CORS headers emitted by default (same-origin only); opt-in via `CORS_ORIGINS` env var |
| Credentials in uploaded XML | `scan_xml_for_secrets()` — checks CONNECTION/SESSION attrs for non-placeholder passwords at Step 0 |
| Insecure generated code | Step 8 — bandit (Python), YAML regex secrets scan, Claude review (all stacks) |
| Security gate bypass | Step 9 — human reviewer must explicitly approve, acknowledge, or fail before pipeline continues |
| Secrets in generated test code | Step 11 test files re-scanned and merged into Step 8 security report before Gate 3 |
| Recurring bad patterns in generated code | Security Knowledge Base — 17 standing rules + auto-learned patterns from all prior Gate 2 findings injected into every conversion prompt (v2.2) |

---

## 7. API Surface

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/jobs` | Upload Mapping (+ optional Workflow + Parameter) and start pipeline |
| `POST` | `/api/jobs/zip` | Upload a single-mapping ZIP archive — files auto-detected |
| `POST` | `/api/jobs/batch` | Upload a batch ZIP (one subfolder per mapping) — starts all pipelines |
| `GET` | `/api/batches/{id}` | Get batch record + per-job summaries and computed batch status |
| `GET` | `/api/jobs` | List all jobs |
| `GET` | `/api/jobs/{id}` | Get job state |
| `GET` | `/api/jobs/{id}/stream` | SSE progress stream |
| `DELETE` | `/api/jobs/{id}` | Soft-delete job (stamps `deleted_at`; data preserved in Log Archive) |
| `POST` | `/api/jobs/{id}/sign-off` | Gate 1 decision (APPROVE / REJECT) |
| `POST` | `/api/jobs/{id}/security-review` | Gate 2 decision (APPROVED / ACKNOWLEDGED / REQUEST_FIX / FAILED) |
| `POST` | `/api/jobs/{id}/code-signoff` | Gate 3 decision (APPROVED / REJECTED) |
| `GET` | `/api/jobs/{id}/logs` | Job log (JSON or plain text) |
| `GET` | `/api/jobs/{id}/logs/download` | Download raw JSONL log |
| `GET` | `/api/jobs/{id}/s2t/download` | Download S2T Excel workbook |
| `GET` | `/api/jobs/{id}/download/{file}` | Download a generated code file |
| `GET` | `/api/jobs/{id}/tests/download/{file}` | Download a generated test file |
| `GET` | `/api/logs/registry` | All jobs with log filenames and final status |
| `GET` | `/api/logs/history` | Soft-deleted DB jobs + orphaned registry entries for the Log Archive |
| `GET` | `/api/logs/history/{job_id}` | Read a historical job log without requiring a live DB record |
| `GET` | `/api/security/knowledge` | Security KB summary: rules count, patterns count, top 10 patterns |
| `POST` | `/api/jobs/{id}/manifest-upload` | Upload annotated manifest XLSX with reviewer overrides (v2.4) |
| `GET` | `/api/jobs/{id}/manifest.xlsx` | Download the pre-conversion mapping manifest (v2.4) |
| `GET` | `/api/jobs/{id}/export` | Build and return completed job artifact ZIP (v2.5) |
| `GET` | `/api/audit` | Audit trail of all Gate 1/2/3 decisions with reviewer metadata (v2.4.6) |
| `GET` | `/api/gates/pending` | All jobs awaiting a gate decision with flag summaries; filterable by gate and batch (v2.17.1) |
| `POST` | `/api/gates/batch-signoff` | Apply a single gate decision to multiple jobs at once (v2.17.1) |
| `GET` | `/api/progress` | Migration-level progress summary: counts by status, tier breakdown, throughput, ETA (v2.17.1) |
| `GET` | `/api/progress/export` | CSV download of all job statuses for management reporting (v2.17.1) |

---

## 8. Data Model (Key Fields)

```
Batch  (v2.0)
├── batch_id       UUID
├── source_zip     Original ZIP filename
├── mapping_count  Number of mapping folders detected in the ZIP
├── created_at / updated_at
└── [status]       Computed from job statuses: running / complete / partial / failed

Job
├── job_id             UUID
├── filename           Original mapping filename
├── batch_id           UUID of parent batch (v2.0, nullable — null for standalone jobs)
├── status             JobStatus enum (PARSING → COMPLETE / BLOCKED / FAILED)
├── current_step       0–12
├── xml_content        Mapping XML (stored in SQLite)
├── workflow_xml_content   Workflow XML (v1.1, nullable)
├── parameter_file_content Parameter file (v1.1, nullable)
└── state              JSON blob — pipeline artefacts per step
    ├── session_parse_report   Step 0
    ├── parse_report           Step 1
    ├── complexity             Step 2
    ├── s2t                    Step S2T (between Steps 2 and 3)
    ├── documentation_md       Step 3
    ├── verification           Step 4
    ├── sign_off               Step 5  (Gate 1)
    ├── stack_assignment       Step 6
    ├── conversion             Step 7  (files dict: filename → code)
    ├── security_scan          Step 8
    ├── security_scan_rounds   Step 8  (v2.2) list of prior scan rounds for fix-round diff
    ├── security_sign_off      Step 9  (Gate 2)
    ├── manifest               Step 1.5  (v2.4) ManifestReport
    ├── code_review            Step 10
    ├── perf_review            Step 10   (v2.6) PerfReviewReport — advisory only
    ├── reconciliation         Step 10b  (v2.8) ReconciliationReport
    ├── test_report            Step 11
    └── code_sign_off          Step 12 (Gate 3)
```

Key schema types:

```
VerificationFlag
├── flag_type             Flag category (e.g. ORPHANED_PORT, UNSUPPORTED_TRANSFORMATION)
├── severity              CRITICAL | HIGH | MEDIUM | LOW | INFO
├── description           Human-readable description of the issue
├── recommendation        Actionable guidance for the reviewer
└── auto_fix_suggestion   (optional) Specific code-level fix Claude proposes; if the
                          reviewer checks "Apply this fix" at Gate 1, the suggestion is
                          forwarded to the conversion agent at Step 7

SecurityReviewDecision  (v1.2 / v2.1)
    APPROVED              Scan was clean, or reviewer confirmed no action needed
    ACKNOWLEDGED          Issues noted and accepted as known risk (proceeds to Step 10)
    REQUEST_FIX           Re-run Step 7 with findings injected → re-run Step 8 →
                          re-present Gate 2 (max 2 rounds; auto-proceeds if clean)
    FAILED                Block pipeline permanently

SecuritySignOffRecord  (Gate 2 sign-off)
├── reviewer_name         Name of the security reviewer
├── reviewer_role         Role of the reviewer
├── review_date           Timestamp of decision (UTC, displayed in local timezone)
├── decision              SecurityReviewDecision enum value
├── notes                 Reviewer notes
└── remediation_round     (v2.1) Which REQUEST_FIX round produced this record (0 = no fix
                          requested; 1 = first round; 2 = second and final round)
```

---

## 9. Sample Files

The repository ships sample Informatica exports across three complexity tiers to allow
end-to-end testing without a live PowerCenter instance.

| Tier | Mappings | Workflow + Params? | Characteristics |
|---|---|---|---|
| Simple | 3 | Yes (all) | Single or dual source, no expressions, passthrough |
| Medium | 4 | Yes (all) | Lookups, filters, expressions, SCD1 targets |
| Complex | 2 | Yes (all) | SCD2, 3+ sources, 2+ targets, pre/post SQL, 9–11 $$VARs |

Root-level `sample_mapping.xml` / `sample_workflow.xml` / `sample_params.txt` provide a
quick single-set test. All 9 mapping sets pass Step 0 validation with
`parse_status=COMPLETE` and zero unresolved variables.

---

## 10. Success Metrics

| Metric | v2.2 | v2.4 | v2.5 | v2.6 | v2.7 | v2.8 |
|---|---|---|---|---|---|---|
| End-to-end pipeline completion rate | > 95% per job | > 95% | > 95% | > 95% | > 95% | > 95% |
| S2T field coverage | ≥ 95% | ≥ 95% | ≥ 95% | ≥ 95% | ≥ 95% | ≥ 95% |
| Code review pass rate (Gate 3 first attempt) | > 80% | > 80% | > 80% | > 80% | > 85% | > 85% |
| Security scan false-positive rate | < 10% | < 10% | < 10% | < 10% | < 10% | < 10% |
| Security gate review time (median) | < 5 min | < 5 min | < 5 min | < 5 min | < 5 min | < 5 min |
| Logic equivalence MISMATCH rate | < 5% | < 5% | < 5% | < 5% | < 5% | < 5% |
| Logic equivalence VERIFIED rate | > 80% | > 80% | > 80% | > 80% | > 80% | > 80% |
| Structural reconciliation match rate | — | — | — | — | — | ≥ 90% RECONCILED |
| CVE count in dependencies | 0 | 0 | 0 | 0 | 0 | 0 |
| $$VAR resolution rate (when param file provided) | 100% | 100% | 100% | 100% | 100% | 100% |
| Batch throughput (mappings / hour) | ≥ 3 concurrent | ≥ 3 concurrent | ≥ 3 concurrent | ≥ 3 concurrent | ≥ 3 concurrent | ≥ 3 concurrent |
| Doc truncation rate (HIGH/VERY_HIGH tier) | 0% | 0% | 0% | 0% | 0% | 0% |
| Security KB standing rules | 17 | 21 | 21 | 21 | 21 | 21 |
| Security KB patterns (after 10 jobs) | ≥ 20 unique | ≥ 20 unique | ≥ 20 unique | ≥ 20 unique | ≥ 20 unique | ≥ 20 unique |
| Automated test coverage | — | — | — | — | — | 100 tests / 5 modules |
| dbt project execution-ready (zero manual edits) | — | — | — | — | ≥ 95% | ≥ 95% |

---

## 11. Technical Constraints

- **Python 3.11+** — orchestrator uses `asyncio.TaskGroup` patterns; type annotations
  use `X | Y` union syntax
- **SQLite** — sufficient for single-instance MVP; PostgreSQL migration path via SQLAlchemy
  in v2.0
- **Claude API required** — Steps 3–4, 6–7, 8, 10–11 call the Anthropic API; no offline mode
- **bandit** — optional but strongly recommended; scan step degrades gracefully if not
  installed (pip install bandit)
- **No Docker required** — plain Python venv deployment; Dockerfile optional
- **License** — CC BY-NC 4.0; commercial use requires written permission from the author
