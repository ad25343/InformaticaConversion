# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Analyst View Generator — produces TWO outputs from parallel Claude calls:

  1. Systems Requirements Document (Step 3a) — clean PRD-style description of
     what the mapping does.  No ambiguity flags, no gap callouts.  Written for
     analysts, testers, and developers who need to understand the mapping.

  2. Gaps & Review Findings (Step 3b) — documentation gaps, ambiguities,
     missing metadata, and recommendations.  Separated so reviewers can assess
     completeness independently.

Both run as parallel asyncio tasks so wall-clock time ≈ max(3a, 3b) instead
of 3a + 3b.  Each call has its own timeout and failure is non-blocking.
"""
from __future__ import annotations

import logging
from typing import Optional

from ..models.schemas import ParseReport, SessionParseReport
from ._client import make_client
from ..config import settings as _cfg

log = logging.getLogger("conversion.analyst_view")

MODEL = _cfg.claude_model
_MAX_TOKENS_3A = 16_000   # Systems Requirements (larger — 8 sections + tables)
_MAX_TOKENS_3B =  8_000   # Gaps & Review Findings (smaller — checklist style)

# Kept for backwards-compat with any callers that imported it
SECTION_DELIMITER = "\n---SECTION_BREAK---\n"


# ── Prompts ──────────────────────────────────────────────────────────────────

_ANALYST_SYSTEM = """You are a senior data analyst writing a structured requirements
document for an Informatica PowerCenter mapping being converted to modern code.

Your audience: analysts, testers, QA leads, and developers who need to understand,
test, and convert this mapping WITHOUT opening PowerCenter Designer.

This document is the single source of truth for the mapping. It must be complete
enough that:
  1. An analyst can understand the mapping without opening Designer
  2. A tester can write UAT test cases directly from it
  3. A developer can convert it to Python/Spark without asking the ETL team
  4. A business user can validate the classification/routing logic

Formatting rules (STRICT):
- Use Markdown tables for ALL field listings, joins, source/target details, and test data.
- Table columns MUST match the template EXACTLY — do not add, remove, or rename columns.
- Use fenced code blocks (```) for EVERY Informatica expression — never inline them in prose.
- Use `> ⚠ **Note:**` callout blocks for gaps, missing logic, or structural concerns.
- Use `---` horizontal rules between major sections for visual separation.
- For Section 4.1 Pipeline Overview, use BOTH:
  (a) A Mermaid flowchart (```mermaid graph LR```) for visual overview — solid arrows
      for data flow, dashed arrows for bypass routes, label router branches with group names.
      Every node MUST have a label in brackets, e.g. `A[SOURCE_NAME]` not bare `A`.
  (b) A step table for precise detail (step number, transform, type, input, output, field count)
- Be HONEST about gaps: if a field has no expression, say "No expression found — passthrough"
  with ⚠ Gap status. Do NOT invent logic that doesn't exist in the metadata.
- Keep prose SHORT. Let tables, code blocks, and callouts do the heavy lifting.
- Output ONLY the Markdown document — no preamble, no commentary outside the doc.
- This document will be exported as PDF and DOCX. Ensure tables are well-structured
  and mermaid diagrams have labeled nodes for proper rendering in all formats.

Section structure (MANDATORY — follow this exact outline):

  ## 1. Purpose & Business Context
     2-3 sentences. What does this mapping do in business terms?

  ## 2. Source Systems
     One subsection per source table with a field table (Field | Type | Nullable | Description).
     Flag unused sources with ⚠ Note callout.

  ## 3. Target Systems
     Each target: name, owner, field count, field table.
     If field counts differ across targets, show a cross-target comparison table and explain why.

  ## 4. Data Flow & Transformation Rules
     ### 4.1 Pipeline Overview — Mermaid flowchart + step table
     ### 4.2 Joins — ALL joins in ONE table:
         | # | Transform | Join Type | Master | Detail | Condition | Business Meaning |
     ### 4.3 Lookups — table if any, otherwise "No lookups"
     ### 4.4 Filters — table if any, otherwise "No filters"
     ### 4.5 Derivations — one #### subsection per derived field with:
           - Fenced code block with verbatim Informatica expression
           - 1-2 sentence plain English explanation
           - What positive/negative/null values mean
     ### 4.6 Aggregations — table if any, otherwise "No aggregations"
     ### 4.7 Routing — Router group table:
         | Group | Condition | Target | Records | Reachable? |
         Note unreachable groups. Note ETL audit field bypass.
     ### 4.8 Complete Field Mapping — ONE consolidated table across ALL targets:
         | # | Source Table | Source Field | Transform Chain | Target Table | Target Field | Type | Expression | Status |
         Every row = one field lineage path from source to target.
         Status values: Direct, Derived, Derived (SQ), Derived (EXP), ⚠ Gap
         For Derived fields: show verbatim expression in the Expression column.
         For ⚠ Gap fields: write "No expression found — passthrough"

  ## 5. Key Business Rules
     Numbered list with formula notation where helpful.
     Include reconciliation formula if applicable.

  ## 6. Parameters & Runtime Dependencies
     Parameter table (Parameter | Type | Default | Description).
     Connection requirements. Upstream dependencies.

  ## 7. Testing Considerations
     ### 7.1 Reconciliation Points — table (# | Check | Validation)
     ### 7.2 Test Data — table per derived field (Inputs | Expected | Explanation)
           Use ACTUAL data types — integer fields get integer test values.
     ### 7.3 Edge Cases — bullet list (nulls, zeros, negatives, boundaries)
           Note unreachable Router groups.

  ## 8. Structural Observations
     Table (# | Observation | Detail | Severity).
     Cover: field count differences, unused sources, disconnected lookups,
     Router bypass, unreachable groups, passthrough fields missing logic."""

# Shared context block — injected into both prompts
_CONTEXT_BLOCK = """## Mapping Name
{mapping_name}

## Structured Summary
{structured_summary}

## Full Technical Documentation (reference only — do NOT copy)
{documentation_md}

─────────────────────────────────────────────────
"""

_PROMPT_3A = _CONTEXT_BLOCK + """
## Your Task: Systems Requirements Document

Produce ONLY Document 1 below.  Do NOT produce a gaps/review section.

## DOCUMENT 1: Systems Requirements

Follow this EXACT structure and formatting. Use tables everywhere. Be honest
about gaps — if an expression is missing, say so with ⚠ Gap status.

# {mapping_name} — Systems Requirements

---

## 1. Purpose & Business Context

2-3 sentences: what does this mapping do in business terms?

---

## 2. Source Systems

For EACH source table, write:

### SOURCE_TABLE_NAME
**Oracle** · `DBDNAME.OWNERNAME` · Description from metadata or one sentence you infer

For Flat File sources instead show:
**Flat File** · `filename.csv` · delimiter: `,` · header: yes/no

Then a field table:

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|
| FIELD_NAME | datatype(precision,scale) | PK / NOT NULL / YES | Brief description |

Under the field table, state the extraction method:
- If the Source Qualifier has a custom SQL override, write: **Extraction:** Custom SQL override (see Section 2.N)
- If there is a Source Filter (WHERE clause), write: **Extraction:** Default with filter — `WHERE condition`
- If neither exists, write: **Extraction:** Default (all rows, no SQL override)

If a source is declared but its fields are NOT used in any expression, flag it:
> ⚠ **Note:** This source is declared and wired but no expressions reference its fields.
> Confirm with the developer whether this is a placeholder or incomplete implementation.

After ALL source tables, if ANY Source Qualifiers have custom SQL, add:

### 2.N Source Qualifier Overrides

For each SQ with custom SQL:
1. One-sentence plain English summary of what the SQL does
2. The full SQL in a fenced code block

```sql
SELECT ... FROM ... WHERE ...
```

If no Source Qualifiers have custom SQL, omit this subsection entirely.

---

## 3. Target Systems

For each target, show name, owner, field count, and a field table:

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|

If targets have DIFFERENT field counts, show a comparison table:

| Field | TARGET_1 | TARGET_2 | TARGET_3 |
|-------|----------|----------|----------|
| FIELD_A | ✅ | ✅ | ❌ missing |

Explain WHY the difference exists (different grain, exception table, etc.)
If you don't know why, say so honestly.

---

## 4. Data Flow & Transformation Rules

### 4.1 Pipeline Overview

First, show a Mermaid flowchart for visual overview:

```mermaid
graph LR
    A[SOURCE_A] --> B[SQ_SOURCE_A]
    C[SOURCE_B] --> D[SQ_SOURCE_B]
    B --> E[JNR_NAME]
    D --> E
    E --> F[EXP_NAME]
    F --> G[RTR_NAME]
    G -->|Group1| H[TARGET_1]
    G -->|Group2| I[TARGET_2]
    F -.->|ETL audit direct| H
    F -.->|ETL audit direct| I
```

Use solid arrows (-->) for data flow, dashed arrows (-.->) for bypass routes.
Label router branches with group names.

Then, show a step table for precise detail:

| Step | Transform | Type | Input From | Output To | Fields |
|------|-----------|------|------------|-----------|--------|
| 1 | SOURCE_A | Source | — | SQ_SOURCE_A | N |
| 2 | SQ_SOURCE_A | Source Qualifier | Step 1 | JNR_NAME | N |

### 4.2 Joins

Show ALL joins in ONE table:

| # | Transform | Join Type | Master | Detail | Condition | Business Meaning |
|---|-----------|-----------|--------|--------|-----------|------------------|
| 1 | JNR_NAME | INNER JOIN | SQ_SOURCE_B | SQ_SOURCE_A | `TABLE_A.KEY = TABLE_B.KEY` | One sentence |

If no joins exist, write: "No joins — single source mapping."

### 4.3 Lookups

Use EXACTLY these columns:

| # | Transform | Lookup Table | Lookup Condition | Return Fields | Cache |
|---|-----------|-------------|-----------------|---------------|-------|
| 1 | LKP_NAME | TABLE_NAME | `TABLE.KEY = INPUT_KEY` | FIELD_A, FIELD_B | Persistent, 5MB |

If no lookups, write: "No lookups performed."
Do NOT add extra columns (e.g., Status) beyond the six above.

### 4.4 Filters

| # | Transform | Filter Condition | Purpose |
|---|-----------|-----------------|---------|

If no filters, write: "No filters — all source records are processed."

### 4.5 Derivations

For EVERY derived field, use this exact format:

#### FIELD_NAME

```
INFORMATICA_EXPRESSION_VERBATIM
```

One sentence plain English explanation. State what positive/negative/null values mean.

### 4.6 Aggregations

| # | Transform | Group By | Aggregate Fields | Function |
|---|-----------|----------|-----------------|----------|
| 1 | AGG_NAME | FIELD_A, FIELD_B | TOTAL_X | SUM(X) |

If no aggregations, write: "No aggregations — each source record produces one output record."

### 4.7 Routing

| Group | Condition | Target | Records | Reachable? |
|-------|-----------|--------|---------|------------|
| GROUP_1 | `FIELD = 'VALUE'` | TARGET_1 | Description | Yes / No |
| DEFAULT | *(none — catch-all)* | TARGET_N | Unmatched | Yes / ⚠ Unreachable |

Note if ETL audit fields bypass the Router (direct Expression→Target).
If no routing, write: "No routing — all records flow to a single target."

### 4.8 Complete Field Mapping

ONE consolidated table showing every field lineage path across ALL targets:

| # | Source Table | Source Field | Transform Chain | Target Table | Target Field | Type | Expression | Status |
|---|-------------|-------------|-----------------|-------------|-------------|------|------------|--------|
| 1 | SOURCE_A | FIELD_X | SQ → JNR → EXP → RTR | TARGET_1 | FIELD_X | number(10) | — | Direct |
| 2 | *Computed* | — | EXP → RTR | TARGET_1 | DERIVED_Y | decimal(18,2) | `ROUND(A * B, 2)` | Derived |
| 3 | — | — | — | TARGET_2 | MISSING_Z | decimal(18,6) | **No expression found** | ⚠ Gap |

Status values: Direct, Derived, Derived (SQ), Derived (EXP), ⚠ Gap
For Derived fields: show the verbatim Informatica expression in the Expression column.
For ⚠ Gap fields: write "**No expression found — passthrough**". Do NOT invent logic.

---

## 5. Key Business Rules

Numbered list. One sentence each. Include the formula notation where helpful:
e.g., "Allocation Effect = (Wp − Wb) × Rb"

Include a reconciliation formula if applicable:
e.g., "Total Active Return ≈ Σ(Allocation) + Σ(Selection) + Σ(Interaction)"

---

## 6. Parameters & Runtime Dependencies

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|

**Connections required:**
- bullet list of source and target connections

**Upstream dependencies:**
- bullet list of tables/processes that must complete before this mapping runs

---

## 7. Testing Considerations

### 7.1 Reconciliation Points

| # | Check | Validation |
|---|-------|-----------|
| 1 | Source-to-target row count | SUM(all targets) = source count |

### 7.2 Test Data

For each derived field, provide a test table with 3 rows.
Use EXACTLY these columns (replace Input_N with actual field names):

| Input_1 | Input_2 | Expected Output | Explanation |
|---------|---------|-----------------|-------------|
| value_a | value_b | expected_result | Why this result |

Rules:
- Use ACTUAL data types — integer fields get integer test values, not strings.
- Include at least one NULL input row to test null handling.
- Column headers MUST name the actual input fields (e.g., `INDICATOR_SCORE | PATTERN_WEIGHT | Expected FRAUD_SCORE`).

### 7.3 Edge Cases

Bullet list of edge cases (nulls, zeros, negatives, boundary values).
Note any Router groups that are unreachable and explain why.

---

## 8. Structural Observations

| # | Observation | Detail | Severity |
|---|-------------|--------|----------|
| 1 | Description | Explanation | High / Medium / Low |

Cover: differing target field counts, unused sources, disconnected lookups,
Router bypass patterns, unreachable groups, passthrough fields that may be missing logic.

"""

_PROMPT_3B = _CONTEXT_BLOCK + """
## Your Task: Gaps & Review Findings

Produce ONLY Document 2 below.  Do NOT reproduce the Systems Requirements.

## DOCUMENT 2: Gaps & Review Findings

This is a structured review checklist. Be factual, specific, and actionable.
Skip any section that has zero findings — do NOT include empty sections.
Table columns MUST match the templates below EXACTLY — do not add or remove columns.
Use `---` horizontal rules between major sections, same as Document 1.

# {mapping_name} — Gaps & Review Findings

---

## 1. Summary

| Category | Count | Highest Severity |
|----------|-------|-----------------|
| Documentation Gaps | N | Critical / High / Medium / Low |
| Ambiguities | N | ... |
| Data Quality Concerns | N | ... |
| Structural Issues | N | ... |

---

## 2. Documentation Gaps

Missing metadata that blocks accurate conversion or testing.

| # | Field / Transform | Gap | Impact | Severity |
|---|-------------------|-----|--------|----------|
| 1 | EXP_NAME.FIELD | No expression found — passthrough assumed | Tester cannot validate derivation | High |
| 2 | JNR_NAME | Join condition empty | Cannot verify join correctness | Critical |

---

## 3. Ambiguities

Where behavior is unclear or Document 1 made assumptions.

| # | Area | Assumption Made | Risk if Wrong | Severity |
|---|------|----------------|---------------|----------|
| 1 | Router group DEFAULT | Assumed catch-all for unmatched records | Records silently dropped if not catch-all | Medium |

---

## 4. Data Quality Concerns

| # | Issue | Detail | Recommendation | Severity |
|---|-------|--------|----------------|----------|
| 1 | Hardcoded value | 'SYSTEM' used for SOURCE_SYSTEM instead of $$param | Parameterize for environment portability | Low |
| 2 | Unused source | SOURCE_B wired but no fields referenced in expressions | Confirm if intentional or incomplete | Medium |

---

## 5. Structural Issues

| # | Issue | Detail | Severity |
|---|-------|--------|----------|
| 1 | Target field count mismatch | TARGET_A has 12 fields, TARGET_B has 10 — missing: X, Y | Medium |
| 2 | Router bypass | ETL audit fields route direct EXP→Target, bypassing Router | Low (expected pattern) |
| 3 | Unreachable Router group | Group X condition can never be TRUE given upstream logic | High |

---

## 6. Pre-Conversion Checklist

Action items that MUST be confirmed before starting conversion:

| # | Action | Owner | Priority |
|---|--------|-------|----------|
| 1 | Confirm FIELD_X derivation logic with source team — no expression in metadata | Analyst | P1 |
| 2 | Validate Router group DEFAULT is intentional catch-all | Developer | P2 |
| 3 | Confirm SOURCE_B is needed — appears unused | Analyst | P2 |

Priority: P1 = blocks conversion, P2 = should resolve before UAT, P3 = nice to have.
"""


# ── Structured summary builder ───────────────────────────────────────────────

def _build_structured_summary(graph: dict, parse_report: ParseReport,
                               session_parse_report: Optional[SessionParseReport],
                               s2t_records: list[dict] | None = None) -> str:
    """Build a compact structured summary from the graph for Claude context."""
    lines: list[str] = []
    txns: list[dict] = []
    for mapping in graph.get("mappings", []):
        txns.extend(mapping.get("transformations", []))

    # Sources with field-level detail
    sources = graph.get("sources", [])
    if sources:
        lines.append("### Sources")
        for s in sources:
            fields = s.get("fields", [])
            db_type = s.get("db_type", "—")
            db_name = s.get("db_name", "")
            owner = s.get("owner", "—")
            desc = s.get("description", "")
            flat = s.get("flat_file", {})
            source_info = f"type: {db_type}"
            if db_name:
                source_info += f", database: {db_name}"
            source_info += f", owner: {owner}"
            if flat:
                fname = flat.get("file_name", "")
                delim = flat.get("delimiter", ",")
                if fname:
                    source_info += f", file: {fname}, delimiter: '{delim}'"
            lines.append(f"- **{s.get('name', '?')}** ({source_info}, {len(fields)} fields)")
            if desc:
                lines.append(f"  Description: {desc}")
            for f in fields:
                dtype = f.get("datatype", "?")
                prec = f.get("precision", "")
                scale = f.get("scale", "")
                pk = " PK" if f.get("key_type", "").upper() == "PRIMARY KEY" else ""
                nullable = "" if f.get("nullable", "YES") == "YES" else " NOT NULL"
                type_str = f"{dtype}({prec},{scale})" if scale and scale != "0" else f"{dtype}({prec})"
                lines.append(f"  - {f.get('name', '?')}: {type_str}{pk}{nullable}")

    # Source Qualifier overrides — only show what's explicitly in the XML
    sq_sql_lines: list[str] = []
    for t in txns:
        if "source qualifier" not in t.get("type", "").lower():
            continue
        attribs = t.get("table_attribs", {})
        sq_name = t.get("name", "")
        custom_sql = (attribs.get("Sql Query", "") or "").strip()
        source_filter = (attribs.get("Source Filter", "") or "").strip()
        user_join = (attribs.get("User Defined Join", "") or "").strip()

        if custom_sql:
            sq_sql_lines.append(f"- **{sq_name}** — SQL Override:")
            sq_sql_lines.append(f"  ```sql\n  {custom_sql}\n  ```")
        if source_filter:
            sq_sql_lines.append(f"- **{sq_name}** — Source Filter: `{source_filter}`")
        if user_join:
            sq_sql_lines.append(f"- **{sq_name}** — User Defined Join: `{user_join}`")

    if sq_sql_lines:
        lines.append("### Source Qualifier Overrides")
        lines.extend(sq_sql_lines)

    # Targets with field-level detail + cross-target comparison
    targets = graph.get("targets", [])
    if targets:
        lines.append("### Targets")
        field_counts = {}
        for t in targets:
            fields = t.get("fields", [])
            field_names = [f.get("name", "") for f in fields]
            field_counts[t.get("name", "?")] = set(field_names)
            db_type = t.get("db_type", "—")
            db_name = t.get("db_name", "")
            owner = t.get("owner", "—")
            tgt_info = f"type: {db_type}"
            if db_name:
                tgt_info += f", database: {db_name}"
            tgt_info += f", owner: {owner}"
            lines.append(f"- **{t.get('name', '?')}** ({tgt_info}, {len(fields)} fields: "
                         f"{', '.join(field_names)})")

        # Flag differing field counts
        if len(field_counts) > 1:
            all_fields = set()
            for fset in field_counts.values():
                all_fields |= fset
            for tname, tfields in field_counts.items():
                missing = all_fields - tfields
                if missing:
                    lines.append(f"  ⚠ {tname} is missing fields present in other targets: {', '.join(sorted(missing))}")

    # Transformation type summary
    type_counts: dict[str, int] = {}
    for t in txns:
        ttype = t.get("type", "Unknown")
        type_counts[ttype] = type_counts.get(ttype, 0) + 1
    if type_counts:
        lines.append("### Transformations")
        for ttype, count in sorted(type_counts.items()):
            lines.append(f"- {ttype}: {count}")

    # Key conditions
    for t in txns:
        attribs = t.get("table_attribs", {})
        ttype = t.get("type", "").lower()
        tname = t.get("name", "")

        if "joiner" in ttype:
            jc = attribs.get("Join Condition", "").strip()
            jt = attribs.get("Join Type", attribs.get("Join type", "NORMAL")).strip()
            if jc:
                lines.append(f"### Join: {tname}")
                lines.append(f"- Type: {jt}")
                lines.append(f"- Condition: {jc}")

        elif "lookup" in ttype:
            lc = (attribs.get("Lookup Condition", "") or
                  attribs.get("Lookup condition", "")).strip()
            lt = (attribs.get("Lookup table name", "") or
                  attribs.get("Lookup Table Name", "")).strip()
            if lc or lt:
                lines.append(f"### Lookup: {tname}")
                if lt:
                    lines.append(f"- Table: {lt}")
                if lc:
                    lines.append(f"- Condition: {lc}")

        elif "filter" in ttype:
            fc = attribs.get("Filter Condition", "").strip()
            if not fc:
                for p in t.get("ports", []):
                    expr = p.get("expression", "").strip()
                    if expr and p.get("porttype", "").upper() == "OUTPUT":
                        fc = expr
                        break
            if fc:
                lines.append(f"### Filter: {tname}")
                lines.append(f"- Condition: {fc}")

        elif "source qualifier" in ttype:
            sql = attribs.get("Sql Query", "").strip()
            sf = attribs.get("Source Filter", "").strip()
            uj = attribs.get("User Defined Join", "").strip()
            if sql or sf or uj:
                lines.append(f"### Source Qualifier: {tname}")
                if sql:
                    lines.append(f"- Custom SQL: {sql[:500]}")
                if sf:
                    lines.append(f"- Filter: {sf}")
                if uj:
                    lines.append(f"- Join: {uj}")

        elif "router" in ttype:
            group_conds = []
            for k, v in sorted(attribs.items()):
                if "group filter condition" in k.lower() and v.strip():
                    group_conds.append(f"  - {k}: {v.strip()}")
            if group_conds:
                lines.append(f"### Router: {tname}")
                lines.extend(group_conds)

    # Connectors summary — flag unmapped targets
    connectors = []
    for mapping in graph.get("mappings", []):
        connectors.extend(mapping.get("connectors", []))
    if targets and connectors:
        target_names = {t.get("name", "").lower() for t in targets}
        connected_targets: dict[str, set[str]] = {n: set() for n in target_names}
        for c in connectors:
            to_inst = c.get("to_instance", "").lower()
            if to_inst in connected_targets:
                connected_targets[to_inst].add(c.get("to_field", ""))
        for tgt in targets:
            tname = tgt.get("name", "").lower()
            tgt_fields = {f.get("name", "") for f in tgt.get("fields", [])}
            mapped = connected_targets.get(tname, set())
            unmapped = tgt_fields - mapped
            if unmapped:
                lines.append(f"### Unmapped Target Fields: {tgt.get('name', '?')}")
                for f in sorted(unmapped):
                    lines.append(f"- {f} — no upstream connector")

    # Parameters
    unresolved = list(parse_report.unresolved_parameters)
    resolved = []
    if session_parse_report:
        resolved = [(p.name, p.value, p.scope) for p in (session_parse_report.parameters or [])]
        unresolved.extend(session_parse_report.unresolved_variables or [])

    if resolved or unresolved:
        lines.append("### Parameters")
        for name, value, scope in resolved:
            lines.append(f"- {name} = {value} [{scope}]")
        for v in unresolved:
            lines.append(f"- {v} = UNRESOLVED")

    # ── NEW: Verbatim expressions with data types ──
    expr_lines = []
    for t in txns:
        tname = t.get("name", "")
        ports_by_name = {p["name"]: p for p in t.get("ports", [])}
        for expr_entry in t.get("expressions", []):
            port_name = expr_entry.get("port", "")
            expr_text = expr_entry.get("expression", "")
            if not expr_text or expr_text in ("SYSDATE", "$$ETL_BATCH_ID") or port_name in ("ETL_LOAD_DT", "ETL_UPDATE_DT", "ETL_BATCH_ID", "SOURCE_SYSTEM"):
                continue
            port_info = ports_by_name.get(port_name, {})
            dtype = port_info.get("datatype", "?")
            prec = port_info.get("precision", "")
            scale = port_info.get("scale", "")
            type_str = f"{dtype}({prec},{scale})" if scale and scale != "0" else f"{dtype}({prec})"
            expr_lines.append(f"- **{tname}.{port_name}** ({type_str}): `{expr_text[:300]}`")

    if expr_lines:
        lines.append("### Expressions (verbatim with data types)")
        lines.extend(expr_lines)

    # ── NEW: Connector routing analysis ──
    if connectors and targets:
        target_names_set = {t.get("name", "").lower() for t in targets}
        router_names = {t.get("name", "") for t in txns if "router" in t.get("type", "").lower()}

        # Find connectors that bypass Router (go direct from Expression to Target)
        bypass_lines = []
        for c in connectors:
            from_inst = c.get("from_instance", "")
            to_inst = c.get("to_instance", "").lower()
            to_field = c.get("to_field", "")
            if to_inst in target_names_set and from_inst not in {r.lower() for r in router_names}:
                # This connector goes direct to target, not through router
                if router_names:  # Only flag if there IS a router in this mapping
                    bypass_lines.append(f"- {to_field}: {from_inst} → {c.get('to_instance', '')} (direct, bypasses Router)")

        if bypass_lines:
            lines.append("### Routing Observations")
            lines.append("These fields route directly from Expression to Target, bypassing the Router:")
            lines.extend(bypass_lines[:20])  # Cap at 20

        # Detect unreachable Router groups
        for t in txns:
            if "router" not in t.get("type", "").lower():
                continue
            attribs = t.get("table_attribs", {})
            num_groups = int(attribs.get("Number of Groups", "0") or "0")
            for i in range(1, num_groups + 1):
                gname = attribs.get(f"Group{i} Name", "")
                gcond = attribs.get(f"Group{i} Condition", "").strip()
                if not gcond:
                    lines.append(f"- Router group '{gname}' has empty condition (catch-all/default group)")

    # ── NEW: S2T lineage records ──
    if s2t_records:
        lines.append("### S2T Field Lineage (pre-computed)")
        lines.append("| Source Table | Source Field | → | Target Table | Target Field | Expression | Status |")
        lines.append("|---|---|---|---|---|---|---|")
        for r in s2t_records[:40]:  # Cap at 40 rows
            src_tbl = r.get("source_table", "—") or "—"
            src_fld = r.get("source_field", "—") or "—"
            tgt_tbl = r.get("target_table", "—") or "—"
            tgt_fld = r.get("target_field", "—") or "—"
            logic = (r.get("logic", "") or "")[:80]
            status = r.get("status", "—") or "—"
            lines.append(f"| {src_tbl} | {src_fld} | → | {tgt_tbl} | {tgt_fld} | {logic} | {status} |")

    return "\n".join(lines)


# ── Main entry point ─────────────────────────────────────────────────────────

async def _call_claude(prompt: str, max_tokens: int, label: str) -> str:
    """Single Claude call — returns the text response."""
    from .retry import claude_with_retry
    client = make_client()
    message = await claude_with_retry(
        lambda: client.messages.create(
            model=MODEL,
            max_tokens=max_tokens,
            system=_ANALYST_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        ),
        label=label,
    )
    return message.content[0].text


async def generate_analyst_view(
    graph: dict,
    parse_report: ParseReport,
    documentation_md: str,
    session_parse_report: Optional[SessionParseReport] = None,
    s2t_records: list[dict] | None = None,
) -> tuple[str, str]:
    """
    Produce the Analyst View (Systems Requirements + Gaps) from the graph
    and the technical documentation.

    Returns (analyst_view_md, analyst_gaps_md) — two separate markdown docs.
    Runs 3a and 3b as parallel Claude calls so wall-clock time ≈ max(3a, 3b).
    """
    import asyncio

    mapping_names = parse_report.mapping_names or ["(unknown)"]
    mapping_name = ", ".join(mapping_names)

    structured_summary = _build_structured_summary(graph, parse_report, session_parse_report, s2t_records)

    # Truncate documentation_md to keep the prompt under budget
    doc_for_prompt = documentation_md
    if len(doc_for_prompt) > 40_000:
        doc_for_prompt = doc_for_prompt[:40_000] + "\n\n... [truncated for length]"

    ctx = dict(mapping_name=mapping_name, structured_summary=structured_summary,
               documentation_md=doc_for_prompt)
    prompt_3a = _PROMPT_3A.format(**ctx)
    prompt_3b = _PROMPT_3B.format(**ctx)

    log.info("analyst_view: launching 3a + 3b in parallel for %s (3a max=%d, 3b max=%d)",
             mapping_name, _MAX_TOKENS_3A, _MAX_TOKENS_3B)

    # 3a generates up to 16K tokens (2× 3b) so give it proportionally more time.
    # Both run in parallel so wall-clock ≈ max(timeout_3a, timeout_3b) — not additive.
    _timeout_3b = _cfg.agent_timeout_secs          # e.g. 300s
    _timeout_3a = _cfg.agent_timeout_secs * 2      # e.g. 600s — 3a is the larger doc

    log.info("analyst_view: timeouts — 3a=%ds, 3b=%ds", _timeout_3a, _timeout_3b)

    results = await asyncio.gather(
        asyncio.wait_for(_call_claude(prompt_3a, _MAX_TOKENS_3A, "analyst view 3a"), timeout=_timeout_3a),
        asyncio.wait_for(_call_claude(prompt_3b, _MAX_TOKENS_3B, "analyst view 3b"), timeout=_timeout_3b),
        return_exceptions=True,
    )

    analyst_md = results[0] if isinstance(results[0], str) else ""
    gaps_md    = results[1] if isinstance(results[1], str) else ""

    if not isinstance(results[0], str):
        log.warning("analyst_view: 3a failed — %s: %s", type(results[0]).__name__, results[0])
    if not isinstance(results[1], str):
        log.warning("analyst_view: 3b failed — %s: %s", type(results[1]).__name__, results[1])

    log.info("analyst_view: 3a=%d chars, 3b=%d chars", len(analyst_md), len(gaps_md))
    return analyst_md, gaps_md
