# Product Requirements Document
## Informatica Conversion Tool

**Version:** 1.1
**Author:** ad25343
**Last Updated:** 2026-02-24
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
Claude security scan to ensure generated code does not inherit bad patterns from legacy
Informatica designs.

---

## 2. Target Personas

**Primary: Data Migration Engineer**
Responsible for rewriting PowerCenter mappings to PySpark or dbt. Knows Informatica well
but needs help producing idiomatic modern-stack code quickly. Cares about correctness of
field mappings, filter logic, and business rules — not about writing boilerplate.

**Secondary: Data Engineering Lead / Reviewer**
Approves the generated code before it enters a CI pipeline. Needs a structured review
checklist, a Source-to-Target field mapping document, and a security scan report — not a
wall of generated code with no summary.

**Tertiary: DevOps / Platform Engineer**
Deploying the tool inside a corporate network. Cares about CVE-free dependencies, no
plaintext secrets in generated code, and configurable upload size limits.

---

## 3. Version Scope

### v1.0 — MVP (shipped)

The single-file conversion pipeline. Accepts one Informatica Mapping XML export and
produces converted code through a 10-step agentic pipeline with two human review gates.

Steps:
1. XML parse and structural analysis
2. Source-to-Target field mapping (S2T Excel workbook)
3. Documentation generation (Markdown)
4. Verification — flags unsupported transformations, dead columns, unresolved parameters
5. Gate 1 — human sign-off (APPROVE / REJECT)
6. Target stack assignment (PySpark / dbt / Python)
7. Code generation
8. Code quality review (Claude cross-check vs. documentation and S2T)
9. Test generation
10. Gate 2 — code review sign-off (APPROVE / REGENERATE / REJECT)

Delivered: single-file upload, SSE progress stream, per-job structured logging, SQLite
job persistence, session-cookie authentication, sample mappings across three complexity
tiers.

### v1.1 — Session & Parameter Support (current)

Extends the pipeline with a new Step 0 that processes Workflow XML and parameter files
alongside the Mapping XML. Adds ZIP upload as a convenience upload path.

New features:
- Step 0 — file-type auto-detection, cross-reference validation, session config extraction, $$VAR resolution
- Three-file upload (Mapping + Workflow + Parameter) and ZIP archive upload
- YAML artifact generation (connections.yaml, runtime_config.yaml) from session config
- UNRESOLVED_VARIABLE flags when $$VARs have no value in the parameter file
- Security-hardened infrastructure: XXE protection, Zip Slip / Zip Bomb / symlink defense, 7 CVEs patched, CORS middleware, startup secret-key warning, per-upload file size enforcement
- Step 8 — Security Scan (dedicated step): bandit (Python/PySpark), YAML regex secrets check, Claude review for all stacks; CRITICAL findings block the pipeline before code review reaches the reviewer; test files re-scanned after Step 10
- Paired sample files for all 9 sample mappings (simple / medium / complex)

### v2.0 — Planned

- Multi-mapping batch conversion (one ZIP → multiple output packages)
- Git integration: open a pull request with generated code directly from the UI
- Incremental re-conversion: only re-run steps whose inputs changed
- Scheduler: run conversion nightly when source XMLs change in a watched directory
- Team mode: multiple reviewers, comment threads on individual flags
- Webhook notifications (Slack, Teams) on gate decisions

### v3.0 — Vision

- Continuous migration mode: monitor Informatica Designer exports and auto-convert on
  change, with diff-level PR updates
- Observability: track conversion success rate, time-to-review, and flag frequency across
  the entire Informatica estate
- Self-hosted model support: route to an on-premise LLM for air-gapped environments
- Support for PowerCenter parameter sets, session configurations, and repository-level objects

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
Step 2   S2T Field Mapping             [Claude + openpyxl Excel output]
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
    │
    ▼
Step 8   Security Scan                 [bandit (Python) + YAML regex + Claude review]
         → CRITICAL finding → BLOCKED (terminal — fix source and re-upload)
         → HIGH/MEDIUM      → REVIEW_RECOMMENDED (continues, flagged for reviewer)
         → clean            → APPROVED
    │
    ▼
Step 9   Code Quality Review           [Claude cross-check vs. docs, S2T, parse flags]
Step 10  Test Generation               [Claude, pytest / dbt test stubs]
         → Security re-scan of generated test files (merged into Step 8 report)
    │
    ▼
Step 11  ◼ Gate 2 — Code Review Sign-off
         APPROVE     → COMPLETE
         REGENERATE  → re-run Steps 7–10
         REJECT      → BLOCKED (terminal)
```

---

## 5. Security Architecture

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
| Insecure generated code | Step 8 — bandit (Python), YAML regex secrets scan, Claude review (all stacks); CRITICAL findings block pipeline |
| Secrets in generated test code | Step 10 test files re-scanned and merged into Step 8 security report before Gate 2 |

---

## 6. API Surface

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/jobs` | Upload Mapping (+ optional Workflow + Parameter) and start pipeline |
| `POST` | `/api/jobs/zip` | Upload a ZIP archive — files auto-detected |
| `GET` | `/api/jobs` | List all jobs |
| `GET` | `/api/jobs/{id}` | Get job state |
| `GET` | `/api/jobs/{id}/stream` | SSE progress stream |
| `DELETE` | `/api/jobs/{id}` | Delete job and associated files |
| `POST` | `/api/jobs/{id}/sign-off` | Gate 1 decision (APPROVE / REJECT) |
| `POST` | `/api/jobs/{id}/code-signoff` | Gate 2 decision (APPROVE / REGENERATE / REJECT) |
| `GET` | `/api/jobs/{id}/logs` | Job log (JSON or plain text) |
| `GET` | `/api/jobs/{id}/logs/download` | Download raw JSONL log |
| `GET` | `/api/jobs/{id}/s2t/download` | Download S2T Excel workbook |
| `GET` | `/api/jobs/{id}/download/{file}` | Download a generated code file |
| `GET` | `/api/jobs/{id}/tests/download/{file}` | Download a generated test file |
| `GET` | `/api/logs/registry` | All jobs with log filenames and final status |

---

## 7. Data Model (Key Fields)

```
Job
├── job_id             UUID
├── filename           Original mapping filename
├── status             JobStatus enum (PARSING → COMPLETE / BLOCKED / FAILED)
├── current_step       0–10
├── xml_content        Mapping XML (stored in SQLite)
├── workflow_xml_content   Workflow XML (v1.1, nullable)
├── parameter_file_content Parameter file (v1.1, nullable)
└── state              JSON blob — pipeline artefacts per step
    ├── session_parse_report   Step 0
    ├── parse_report           Step 1
    ├── s2t                    Step 2
    ├── documentation_md       Step 3
    ├── verification           Step 4
    ├── sign_off               Step 5
    ├── stack_assignment       Step 6
    ├── conversion             Step 7  (files dict: filename → code)
    ├── security_scan          Step 8
    ├── code_review            Step 9
    ├── test_report            Step 10
    └── code_sign_off          Step 11
```

---

## 8. Sample Files

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

## 9. Success Metrics

| Metric | v1.0 Target | v1.1 Target |
|---|---|---|
| End-to-end pipeline completion rate | > 85% (no BLOCKED/FAILED) | > 90% |
| S2T field coverage | ≥ 95% of target fields mapped | ≥ 95% |
| Code review pass rate (Gate 2 APPROVE on first attempt) | > 70% | > 75% |
| Security scan false-positive rate | — | < 10% of findings require no action |
| CVE count in dependencies | 0 | 0 |
| $$VAR resolution rate (when param file provided) | — | 100% of known vars resolved |

---

## 10. Technical Constraints

- **Python 3.11+** — orchestrator uses `asyncio.TaskGroup` patterns; type annotations
  use `X | Y` union syntax
- **SQLite** — sufficient for single-instance MVP; PostgreSQL migration path via SQLAlchemy
  in v2.0
- **Claude API required** — Steps 2–4, 6–9 call the Anthropic API; no offline mode
- **bandit** — optional but strongly recommended; scan step degrades gracefully if not
  installed (pip install bandit)
- **No Docker required** — plain Python venv deployment; Dockerfile optional
- **License** — CC BY-NC 4.0; commercial use requires written permission from the author
