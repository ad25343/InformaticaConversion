# Informatica Conversion Tool

Converts Informatica PowerCenter XML exports to PySpark, dbt, or Python.

10-step agentic pipeline powered by Claude, with two human-in-the-loop review gates.

---

## Install on a New Machine

```bash
# 1. Clone the repo
git clone https://github.com/ad25343/InformaticaConversion.git
cd InformaticaConversion/app

# 2. Install dependencies (Python 3.10+)
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Open .env and fill in:
#   ANTHROPIC_API_KEY  — get one at https://console.anthropic.com
#   APP_PASSWORD       — login password for the web UI
#   SECRET_KEY         — any long random string for session signing

# 4. Start the server
bash start.sh
# → Web UI:   http://localhost:8000
# → API docs: http://localhost:8000/docs
```

---

## Pipeline

| Step | Name | Powered By | Notes |
|------|------|-----------|-------|
| 1 | Parse XML | lxml (deterministic) | Fails fast on malformed XML |
| 2 | Classify Complexity | Rule-based | LOW / MEDIUM / HIGH / VERY_HIGH |
| S2T | Source-to-Target Map | Rule-based | Excel workbook generated |
| 3 | Generate Documentation | Claude | Full transformation specs in Markdown |
| 4 | Verify | Deterministic + Claude | 100+ checks; flags orphaned ports, lineage gaps, risks |
| **5** | **Human Review Gate 1** | UI sign-off | **Hard gate — APPROVED / REJECTED** |
| 6 | Stack Assignment | Rules + Claude | PySpark / dbt / Python |
| 7 | Convert | Claude | Production-ready code files |
| 8 | Code Quality Review | Claude | Static analysis, 10+ checks |
| 9 | Test Generation | Rule-based + Claude | Field + filter coverage report |
| **10** | **Human Review Gate 2** | UI sign-off | **APPROVED / REGENERATE / REJECTED** |

---

## Architecture

```
app/
├── main.py                        FastAPI entry point
├── start.sh                       Start script (checks .env, launches uvicorn)
├── requirements.txt
├── .env.example                   Copy to .env and fill in secrets
│
├── backend/
│   ├── orchestrator.py            Pipeline state machine
│   ├── routes.py                  REST API endpoints
│   ├── auth.py                    Session auth
│   ├── logger.py                  Structured per-job logging
│   ├── agents/
│   │   ├── parser_agent.py        Step 1  — XML parser (lxml)
│   │   ├── classifier_agent.py    Step 2  — Complexity classifier
│   │   ├── s2t_agent.py           Step S2T — Source-to-Target Excel
│   │   ├── documentation_agent.py Step 3  — Documentation (Claude)
│   │   ├── verification_agent.py  Step 4  — Verification
│   │   ├── conversion_agent.py    Steps 6-7 — Stack assignment + code generation
│   │   ├── review_agent.py        Step 8  — Code quality review
│   │   └── test_agent.py          Step 9  — Test generation
│   ├── models/
│   │   └── schemas.py             Pydantic models for all pipeline artifacts
│   └── db/
│       └── database.py            SQLite persistence (swap URL for PostgreSQL)
│
├── frontend/
│   └── templates/
│       ├── index.html             Main pipeline UI
│       └── login.html             Login screen
│
└── sample_xml/
    ├── simple/                    Simple mappings (1 source, basic expressions)
    ├── medium/                    Medium mappings (joins, lookups, aggregations)
    └── complex/                   Complex mappings (SCD2, multi-source, routing)
```

---

## Complexity Tiers & Token Budgets

| Tier | Criteria | Doc tokens | QC tokens |
|------|----------|-----------|-----------|
| LOW | < 5 transformations | 8 192 | 2 048 |
| MEDIUM | 5–9 transformations | 12 288 | 4 096 |
| HIGH | 10–14 transformations | 16 384 | 6 144 |
| VERY_HIGH | 15+ transformations, or 2+ independent HIGH structural criteria | 32 768 | 8 192 |

Documentation token budget auto-scales: `max(tier_floor, num_transformations × 1 500 + 4 000)`.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | Claude API key |
| `APP_PASSWORD` | Yes | Web UI login password |
| `SECRET_KEY` | Yes | Session signing key (any long random string) |
| `CLAUDE_MODEL` | No | Override Claude model (default: `claude-sonnet-4-5-20250929`) |
| `DOC_MAX_TOKENS_OVERRIDE` | No | Force a specific doc token limit — for testing truncation only |

---

## Current Scope

This tool currently handles **Mapping-level conversion only**.

Given an Informatica PowerCenter XML export, it converts the transformation logic (Source Qualifiers, Expressions, Joiners, Lookups, Routers, Aggregators, etc.) into production-ready PySpark, dbt, or Python code.

The following are **not yet in scope**:
- Workflows (WF) and Worklets
- Sessions (runtime config, reject handling, pre/post SQL, commit intervals)
- Parameter files (`$$VARIABLES`)
- Source/Target definitions
- Cross-mapping dependency graphs

See the Roadmap below for planned versions that address these gaps.

---

## Roadmap

| Version | Name | Scope |
|---------|------|-------|
| **v1.0** | Mapping Conversion | Transformation logic, human review gates, PySpark / dbt / Python code generation |
| **v1.1** | Session & Parameter Support | Session config extraction (connections, reject handling, pre/post SQL), parameter file resolution (`$$VARIABLES`) |
| **v2.0** | Workflow Conversion | WF → Airflow / Dagster / Prefect DAG; Sessions as task nodes; Worklets as TaskGroups |
| **v2.1** | Dependency Graph | Cross-mapping lineage, load order, shared staging table awareness |
| **v3.0** | Portfolio Migration | Bulk processing, migration dashboard, repository-level export, progress tracking across a full Informatica portfolio |

---

## Database

SQLite by default (`app/data/jobs.db`). To switch to PostgreSQL, change `DATABASE_URL` in `backend/db/database.py`.

Job logs are written to `app/logs/jobs/` as newline-delimited JSON.
