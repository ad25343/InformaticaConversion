# Architecture & Technical Design
## Informatica Conversion Tool

> **Version:** 2.26.0
> **Last Updated:** 2026-04-14
> **Audience:** Engineers building on, extending, or deploying the tool
> **Related docs:** [PRD.md](PRD.md) (product scope) · [USER_GUIDE.md](USER_GUIDE.md) (end-user) · [app/README.md](../app/README.md) (developer quickstart)

This is the **living technical design document** for the Informatica Conversion Tool. It covers pipeline architecture, stack assignment logic, security design, the full API surface, and the data model. Update this document whenever a version changes any of these concerns.

---

## Contents

1. [Pipeline Architecture](#1-pipeline-architecture)
2. [Greenfield Authoring (v2.22)](#2-greenfield-authoring-v222)
3. [Stack Assignment Decision Matrix](#3-stack-assignment-decision-matrix)
4. [Security Architecture](#4-security-architecture)
5. [API Surface](#5-api-surface)
6. [Data Model](#6-data-model)
7. [Technical Constraints](#7-technical-constraints)

---

## 1. Pipeline Architecture

The conversion pipeline is a 12-step async generator chain with 3 human review gates. Steps run sequentially within a job; multiple jobs can run concurrently.

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
Step S2T Source-to-Target Field Map    [deterministic backward-graph trace + openpyxl Excel]
         Lineage engine: backward connector index → BFS through transformations
         Joiner resolution: Style A (M_/D_ prefix on inputs), Style B (OUT_/O_ prefix on outputs)
         SQ resolution: exact name → suffix match → field-name overlap (≥3 ports, score ≥0.5)
         LKP resolution: maps LKP instance names to actual lookup tables via table_attribs
         TGT_ prefix handling: resolves TGT_TABLE_NAME → TABLE_NAME at trace start
Step 3   Documentation Generation      [Claude, Markdown]
         3a Systems Requirements        [parallel Claude call, 16K max tokens]
         3b Gaps & Review Findings      [parallel Claude call, 8K max tokens]
         3a + 3b run via asyncio.gather; wall-clock ≈ max(3a, 3b); each has own timeout
Step 4   Verification                  [deterministic + Claude flags]
    │
    ▼
Step 5   ◼ Gate 1 — Human Review Sign-off
         APPROVE                    → Step 6
         REJECT + restart_from_step → resume_from_step() → Step 1, 2, or 3
         REJECT (no restart)        → BLOCKED (terminal)
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
         → Expression boundary tests (tests/test_expressions_{mapping}.py)
         → Golden CSV comparison script (tests/compare_golden.py)
         → Security re-scan of generated test files (merged into Step 8 report)
    │
    ▼
Step 12  ◼ Gate 3 — Code Review Sign-off
         APPROVED                   → COMPLETE
         REJECTED + restart_from_step → resume_from_step() → Step 6, 7, or 10
         REJECTED (no restart)      → BLOCKED (terminal)
```

### Key design decisions

| Decision | Rationale |
|---|---|
| Steps are async generators | Enables SSE streaming of progress to the frontend without polling |
| State serialised to SQLite as zlib-compressed JSON | Survives server restarts; single-file deployment; compressed because state blobs can exceed 1 MB on complex mappings |
| Gates pause the generator; pipeline is resumable | Avoids holding a thread/process across human review time (hours/days) |
| Step 12 always writes COMPLETE before returning | All artifact export helpers are wrapped in try/except so a downstream failure cannot leave a job permanently stuck |
| Smoke check (7b) and reconciliation (10b) are non-blocking | Advisory findings must not block delivery; they feed into reviewer judgement at Gate 3 |
| Security Knowledge Base injected at every Step 7 prompt | Patterns learned from prior Gate 2 findings harden future generations automatically |

---

## 2. Greenfield Authoring (v2.22)

In addition to the conversion pipeline, the tool supports generating Informatica PowerCenter XML from scratch via a pattern-driven config. This is the reverse flow and operates independently of the conversion pipeline.

```
User provides: pattern name + YAML config + mapping name
    │
    ▼
POST /api/patterns/{name}/generate-xml
    │
    ├── Validate YAML config against Pydantic schema (etl_patterns/schemas.py)
    │
    ├── XmlGeneratorAgent — Claude generates Informatica PowerCenter XML
    │   (few-shot examples embedded; prompt includes schema constraints)
    │
    ├── xml.etree.ElementTree validation — rejects malformed XML before returning
    │
    └── Return XML + log to pattern_generation_log table
```

**Supported patterns (10):**

| Pattern name | Description |
|---|---|
| `truncate_and_load` | Full reload — truncate target, load all source rows |
| `incremental_append` | Append rows newer than a watermark column value |
| `upsert` | Insert-or-update on one or more key columns |
| `scd2` | Type-2 slowly changing dimension (effective date + is_current flag) |
| `lookup_enrich` | Enrich source rows with attributes from a lookup table |
| `aggregation_load` | Group-by aggregation (SUM, COUNT, AVG) into a target |
| `filter_and_route` | Route rows to different targets based on a condition |
| `union_consolidate` | Union multiple sources into a single target |
| `expression_transform` | Pure field transformation with no join or aggregation |
| `pass_through` | Identity load — source columns mapped 1:1 to target |

The generated XML can be imported directly into Informatica Designer or fed back into the conversion pipeline for round-trip validation.

---

## 3. Stack Assignment Decision Matrix

Step 6 assigns one of three target stacks (or a documented hybrid) based on the criteria below. The assignment is deterministic given the mapping characteristics — reviewers can override at Gate 1 by adding a note, but the default follows this matrix.

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

**Hybrid:** Where a single mapping has sub-flows that suit different stacks, the assignment record documents which component maps to which stack and why. Hybrid is rare — most Informatica mappings have a dominant pattern that determines the stack clearly.

---

## 4. Security Architecture

Security is infrastructure, not a feature layer. Every file-handling path in the application flows through `backend/security.py`.

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

## 5. API Surface

All endpoints are prefixed `/api/`. Authentication is session-cookie (enforced by middleware).

| Method | Path | Description | Since |
|---|---|---|---|
| `POST` | `/api/jobs` | Upload Mapping (+ optional Workflow + Parameter) and start pipeline | v1.0 |
| `POST` | `/api/jobs/zip` | Upload a single-mapping ZIP archive — files auto-detected | v2.5 |
| `POST` | `/api/jobs/batch` | Upload a batch ZIP (one subfolder per mapping) — starts all pipelines | v2.0 |
| `GET` | `/api/batches/{id}` | Get batch record + per-job summaries and computed batch status | v2.0 |
| `GET` | `/api/jobs` | List all jobs | v1.0 |
| `GET` | `/api/jobs/{id}` | Get job state | v1.0 |
| `GET` | `/api/jobs/{id}/stream` | SSE progress stream | v1.0 |
| `DELETE` | `/api/jobs/{id}` | Soft-delete job (stamps `deleted_at`; data preserved in Log Archive) | v1.0 |
| `POST` | `/api/jobs/{id}/sign-off` | Gate 1 decision (APPROVE / REJECT) | v1.0 |
| `POST` | `/api/jobs/{id}/security-review` | Gate 2 decision (APPROVED / ACKNOWLEDGED / REQUEST_FIX / FAILED) | v1.2 |
| `POST` | `/api/jobs/{id}/code-signoff` | Gate 3 decision (APPROVED / REJECTED) | v1.0 |
| `GET` | `/api/jobs/{id}/logs` | Job log (JSON or plain text) | v1.0 |
| `GET` | `/api/jobs/{id}/logs/download` | Download raw JSONL log | v1.0 |
| `GET` | `/api/jobs/{id}/s2t/download` | Download S2T Excel workbook | v1.0 |
| `GET` | `/api/jobs/{id}/download/{file}` | Download a generated code file | v1.0 |
| `GET` | `/api/jobs/{id}/tests/download/{file}` | Download a generated test file | v2.13 |
| `GET` | `/api/logs/registry` | All jobs with log filenames and final status | v1.0 |
| `GET` | `/api/logs/history` | Soft-deleted DB jobs + orphaned registry entries for the Log Archive | v1.0 |
| `GET` | `/api/logs/history/{job_id}` | Read a historical job log without requiring a live DB record | v1.0 |
| `GET` | `/api/security/knowledge` | Security KB summary: rules count, patterns count, top 10 patterns | v2.2 |
| `POST` | `/api/jobs/{id}/manifest-upload` | Upload annotated manifest XLSX with reviewer overrides | v2.4 |
| `GET` | `/api/jobs/{id}/manifest.xlsx` | Download the pre-conversion mapping manifest | v2.4 |
| `GET` | `/api/jobs/{id}/export` | Build and return completed job artifact ZIP | v2.5 |
| `GET` | `/api/audit` | Audit trail of all Gate 1/2/3 decisions with reviewer metadata | v2.4.6 |
| `GET` | `/api/gates/pending` | All jobs awaiting a gate decision; filterable by gate and batch | v2.17.1 |
| `POST` | `/api/gates/batch-signoff` | Apply a single gate decision to multiple jobs at once | v2.17.1 |
| `GET` | `/api/progress` | Migration-level progress: counts by status, tier breakdown, throughput, ETA | v2.17.1 |
| `GET` | `/api/progress/export` | CSV download of all job statuses for management reporting | v2.17.1 |
| `GET` | `/api/patterns` | List all 10 ETL patterns with names, descriptions, and JSON Schema configs | v2.22 |
| `POST` | `/api/patterns/{name}/generate-xml` | Generate Informatica PowerCenter XML from a YAML pattern config | v2.22 |

---

## 6. Data Model

### Core tables

```
Batch  (v2.0)
├── batch_id       UUID
├── source_zip     Original ZIP filename
├── mapping_count  Number of mapping folders detected in the ZIP
├── created_at / updated_at
└── [status]       Computed from job statuses: running / complete / partial / failed

Job
├── job_id                     UUID
├── filename                   Original mapping filename
├── batch_id                   UUID of parent batch (v2.0, nullable — null for standalone jobs)
├── status                     JobStatus enum (PARSING → COMPLETE / BLOCKED / FAILED)
├── current_step               0–12
├── xml_content                Mapping XML (stored in SQLite)
├── workflow_xml_content       Workflow XML (v1.1, nullable)
├── parameter_file_content     Parameter file (v1.1, nullable)
└── state_json                 zlib-compressed JSON blob of pipeline artefacts

PatternGenerationLog  (v2.22)
├── gen_id         UUID
├── pattern_name   One of the 10 ETL pattern names
├── mapping_name   Caller-supplied mapping name
├── requested_at   Timestamp
├── duration_ms    Generation duration in milliseconds
├── success        Boolean
├── error_message  Nullable
└── xml_length     Character length of the generated XML
```

### State JSON structure (`Job.state_json`)

The `state_json` blob is decoded via `_decode_state()` in `db/database.py` (handles both zlib-compressed `z:` prefix and legacy plain JSON).

| Key | Set at step | Contents |
|---|---|---|
| `session_parse_report` | Step 0 | Connection names, $$VAR resolution, cross-ref validation result |
| `parse_report` | Step 1 | Transformation graph, port definitions, connector chains |
| `complexity` | Step 2 | Tier (LOW/MEDIUM/HIGH/VERY_HIGH), score, contributing factors |
| `s2t` | Step S2T | Source-to-target field mapping records |
| `manifest` | Step 1.5 | ManifestReport with reviewer overrides (v2.4) |
| `documentation_md` | Step 3 | Markdown documentation string |
| `verification` | Step 4 | List of VerificationFlag objects |
| `sign_off` | Gate 1 | SignOffRecord (reviewer name/role, decision, timestamp) |
| `stack_assignment` | Step 6 | Assigned stack, rationale, hybrid breakdown if applicable |
| `conversion` | Step 7 | ConversionOutput: files dict (filename → code), target_stack, smoke_flags |
| `security_scan` | Step 8 | SecurityScanReport (bandit + YAML + Claude findings) |
| `security_scan_rounds` | Step 8 | List of prior scan rounds for fix-round diff display |
| `security_sign_off` | Gate 2 | SecuritySignOffRecord |
| `code_review` | Step 10 | Logic equivalence, code quality findings |
| `perf_review` | Step 10 | PerfReviewReport — advisory anti-pattern findings (v2.6) |
| `reconciliation` | Step 10b | ReconciliationReport: RECONCILED / PARTIAL / PENDING_EXECUTION |
| `test_report` | Step 11 | TestReport with generated test file references |
| `code_sign_off` | Gate 3 | CodeSignOffRecord |

### Key schema types

```
VerificationFlag
├── flag_type             Flag category (e.g. ORPHANED_PORT, UNSUPPORTED_TRANSFORMATION)
├── severity              CRITICAL | HIGH | MEDIUM | LOW | INFO
├── description           Human-readable description of the issue
├── recommendation        Actionable guidance for the reviewer
└── auto_fix_suggestion   (optional) Specific code-level fix forwarded to Step 7 if accepted

SignOffRequest  (Gate 1)
├── reviewer_name         Name of the reviewer
├── reviewer_role         Role of the reviewer
├── decision              APPROVE | REJECT
└── restart_from_step     (optional, v2.20) 1, 2, or 3 — omit for full restart (BLOCKED)

CodeSignOffRequest  (Gate 3)
├── reviewer_name         Name of the reviewer
├── reviewer_role         Role of the reviewer
├── decision              APPROVED | REJECTED
└── restart_from_step     (optional, v2.20) 6, 7, or 10 — omit for full restart (BLOCKED)

SecurityReviewDecision  (Gate 2)
    APPROVED              Scan clean, or no action needed
    ACKNOWLEDGED          Issues noted and accepted as known risk
    REQUEST_FIX           Re-run Step 7 with findings injected → re-run Step 8 (max 2 rounds)
    FAILED                Block pipeline permanently

SecuritySignOffRecord
├── reviewer_name
├── reviewer_role
├── review_date           UTC timestamp
├── decision              SecurityReviewDecision enum
├── notes
└── remediation_round     0 = no fix requested; 1 = first round; 2 = second/final round
```

---

## 7. Technical Constraints

| Constraint | Detail |
|---|---|
| **Python 3.11+** | Orchestrator uses `asyncio.TaskGroup` patterns; type annotations use `X \| Y` union syntax |
| **SQLite** | Sufficient for single-instance deployment; PostgreSQL migration path via SQLAlchemy in v2.0 |
| **Claude API required** | Steps 3–4, 6–7, 8, 10–11 call the Anthropic API; no offline mode |
| **bandit** | Optional but strongly recommended — scan step degrades gracefully if not installed (`pip install bandit`) |
| **No Docker required** | Plain Python venv deployment; Dockerfile optional |
| **State blob size** | Complex mappings (many ports, large expressions) can produce state blobs > 1 MB; zlib compression keeps SQLite rows manageable |
| **SSE streaming** | Gate-waiting jobs emit `state` + `done` immediately on SSE connect (no active pipeline); frontend uses `_sseHadProgress` flag to guard against spurious re-renders |
