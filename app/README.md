# Informatica Conversion Tool — MVP

Converts Informatica PowerCenter XML exports to Python, PySpark, or dbt.
8-step agentic pipeline with human-in-the-loop review gate.

## Quick Start

```bash
cd app/

# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env — add your ANTHROPIC_API_KEY

# 3. Start the server
bash start.sh
# → UI at http://localhost:8000
# → API docs at http://localhost:8000/docs
```

## Architecture

```
app/
├── main.py                   FastAPI entry point
├── backend/
│   ├── routes.py             REST API routes
│   ├── orchestrator.py       Pipeline state machine
│   ├── agents/
│   │   ├── parser_agent.py       Step 1 — XML Parser (lxml, deterministic)
│   │   ├── classifier_agent.py   Step 2 — Complexity Classifier (rule-based)
│   │   ├── documentation_agent.py Step 3 — Documentation (Claude)
│   │   ├── verification_agent.py  Step 4 — Verification (deterministic + Claude)
│   │   └── conversion_agent.py   Steps 6-7 — Stack Assignment + Conversion (Claude)
│   ├── models/
│   │   └── schemas.py        Pydantic data models for all pipeline artifacts
│   └── db/
│       └── database.py       SQLite persistence layer
├── frontend/
│   └── templates/index.html  Web UI (upload, pipeline view, sign-off, code viewer)
├── sample_xml/
│   └── sample_mapping.xml    Test mapping (STG_ORDERS → FACT_ORDERS)
├── requirements.txt
└── .env.example
```

## Pipeline Steps

| Step | Agent | Powered By | Gate |
|------|-------|-----------|------|
| 1 | Parse | lxml (deterministic) | FAILED → stops |
| 2 | Classify | Rule-based | — |
| 3 | Document | Claude | — |
| 4 | Verify | Deterministic + Claude | All checks run, report produced |
| 5 | Human Review | UI sign-off form | **Hard gate — APPROVED required** |
| 6 | Stack Assignment | Rules + Claude rationale | — |
| 7 | Convert | Claude | — |
| 8 | Validate | Phase 3 (sandbox) | — |

## MVP Scope

- Supports: Low/Medium complexity mappings
- Target stack: PySpark (primary), dbt, Python/Pandas
- Validation (Step 8): placeholder — Phase 3 feature
- Database: SQLite (swap to PostgreSQL by changing DATABASE_URL in database.py)
