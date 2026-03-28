# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Analyst View Generator — produces TWO outputs from a single Claude call:

  1. Systems Requirements Document (Step 3a) — clean PRD-style description of
     what the mapping does.  No ambiguity flags, no gap callouts.  Written for
     analysts, testers, and developers who need to understand the mapping.

  2. Gaps & Review Findings (Step 3b) — documentation gaps, ambiguities,
     missing metadata, and recommendations.  Separated so reviewers can assess
     completeness independently.

Both are separated by a delimiter in a single Claude response and split by
the caller.  This keeps cost to one lightweight call (~10k tokens max).
"""
from __future__ import annotations

import logging
from typing import Optional

from ..models.schemas import ParseReport, SessionParseReport
from ._client import make_client
from ..config import settings as _cfg

log = logging.getLogger("conversion.analyst_view")

MODEL = _cfg.claude_model
_ANALYST_MAX_TOKENS = 16_000

# Delimiter used to split the two sections in Claude's response
SECTION_DELIMITER = "\n---SECTION_BREAK---\n"


# ── Prompts ──────────────────────────────────────────────────────────────────

_ANALYST_SYSTEM = """You are a senior data analyst writing a structured requirements
document for an Informatica PowerCenter mapping being converted to modern code.

Your audience: analysts, testers, QA leads, and developers who need to understand,
test, and convert this mapping WITHOUT opening PowerCenter Designer.

Formatting rules (STRICT):
- Use Markdown tables for ALL field listings, source/target details, and test data.
- Use fenced code blocks (```) for EVERY Informatica expression — never inline them in prose.
- Use `> ⚠ **Note:**` callout blocks for gaps, missing logic, or structural concerns.
- Use `---` horizontal rules between major sections for visual separation.
- Use ASCII pipeline diagrams in Section 4.1 to show the transformation chain.
- Be HONEST about gaps: if a field has no expression, say "No expression found — passthrough" with ⚠ Gap status. Do NOT invent logic that doesn't exist in the metadata.
- Keep prose SHORT. Let tables, code blocks, and callouts do the heavy lifting.
- Output ONLY the Markdown document — no preamble, no commentary outside the doc."""

_ANALYST_PROMPT = """Produce TWO documents for this Informatica mapping, separated by
exactly this line on its own:

---SECTION_BREAK---

## Mapping Name
{mapping_name}

## Structured Summary
{structured_summary}

## Full Technical Documentation (reference only — do NOT copy)
{documentation_md}

─────────────────────────────────────────────────

## DOCUMENT 1: Systems Requirements (BEFORE the ---SECTION_BREAK--- line)

Follow this EXACT structure and formatting. Use tables everywhere. Be honest
about gaps — if an expression is missing, say so with ⚠ Gap status.

# {mapping_name} — Systems Requirements

---

## 1. Purpose & Business Context

2-3 sentences: what does this mapping do in business terms?

---

## 2. Source Systems

For EACH source table, write:

### SOURCE_TABLE_NAME (owner, database)

One sentence describing what data it provides. Then a field table:

| Field | Type | Description |
|-------|------|-------------|
| FIELD_NAME | datatype(precision,scale) PK/NOT NULL | Brief description |

If there is a Source Qualifier filter or custom SQL, show it in a code block.
If a source is declared but its fields are NOT used in any expression, flag it:
> ⚠ **Note:** This source is declared and wired but no expressions reference its fields.

---

## 3. Target Systems

For each target, show name, owner, field count, field list.
If targets have DIFFERENT field counts, show a comparison:

> ⚠ **Note:** TARGET_A has N fields, TARGET_B has M fields — TARGET_B is missing: FIELD_X, FIELD_Y

Explain WHY the difference exists (different grain, exception table, etc.)
If you don't know why, say so honestly.

---

## 4. Data Flow & Transformation Rules

### 4.1 Pipeline Overview

Show an ASCII diagram of the transformation chain:
```
SOURCE_A ──→ SQ ──→ JNR ──→ EXP ──→ RTR ──→ TARGET_1
SOURCE_B ──→ SQ ──↗              ↘──→ TARGET_2
                          ETL audit: EXP → both targets (direct, bypasses RTR)
```

### 4.2 Join

| Transform | Type | Condition |
|-----------|------|-----------|
| JNR_NAME | INNER JOIN | `TABLE_A.KEY = TABLE_B.KEY` |

One sentence explaining the business meaning.

### 4.3 Derivations

For EVERY derived field, use this exact format:

#### FIELD_NAME

```
INFORMATICA_EXPRESSION_VERBATIM
```

One sentence plain English explanation. State what positive/negative values mean.

### 4.4 Routing

| Router Group | Condition | Target | Description |
|-------------|-----------|--------|-------------|

Note if any group appears unreachable given upstream expression logic.
Note if ETL audit fields bypass the Router (direct Expression→Target).

### 4.5 Field Mapping — TARGET_1

| Target Field | Source | Type | Expression | Status |
|---|---|---|---|---|
| FIELD_A | SOURCE.FIELD_A | number(10) | — | Direct |
| FIELD_B | *Computed* | decimal(18,2) | `ROUND(X * Y, 2)` | Derived |
| FIELD_C | — | decimal(18,6) | **No expression found** | ⚠ Gap |

Repeat for each target table (4.6, 4.7, etc.)

IMPORTANT: If a field has NO expression in the metadata, write "**No expression found — passthrough**"
with status "⚠ Gap". Do NOT invent what the expression might be.

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

Then list connection requirements and upstream dependencies.

---

## 7. Testing Considerations

### 7.1 Reconciliation Points

| Check | Validation |
|-------|-----------|

### 7.2 Test Data

For each derived field, provide 3 test rows with expected results:

| Input_1 | Input_2 | Expected | Explanation |
|---------|---------|----------|-------------|

Use the ACTUAL data types — if a field is integer, test with integers only.

### 7.3 Edge Cases

Bullet list of edge cases (nulls, zeros, negatives, boundary values).
Note any Router groups that are unreachable.

---

## 8. Structural Observations

| Observation | Detail |
|-------------|--------|

Cover: differing target field counts, unused sources, disconnected lookups,
Router bypass patterns, unreachable groups, passthrough fields that may be missing logic.

─────────────────────────────────────────────────

## DOCUMENT 2: Gaps & Review Findings (AFTER the ---SECTION_BREAK--- line)

List everything ambiguous, missing, or needing review. Be factual and specific.

# {mapping_name} — Gaps & Review Findings

## Documentation Gaps
What metadata is missing? (empty expressions, no join conditions, no load type)

## Ambiguities
Where is behavior unclear? What assumptions were made in Document 1?

## Data Quality Concerns
Fields with no upstream connectors? Hardcoded values that should be parameterized?
Sources wired but unused? Lookups declared but not connected?

## Recommendations
Numbered action items the analyst/developer must confirm before conversion.

Skip any section that has no findings.
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
            lines.append(f"- **{s.get('name', '?')}** (owner: {s.get('owner', '—')}, "
                         f"db: {s.get('db_type', '—')}, {len(fields)} fields)")
            for f in fields:
                dtype = f.get("datatype", "?")
                prec = f.get("precision", "")
                scale = f.get("scale", "")
                pk = " PK" if f.get("key_type", "").upper() == "PRIMARY KEY" else ""
                nullable = "" if f.get("nullable", "YES") == "YES" else " NOT NULL"
                type_str = f"{dtype}({prec},{scale})" if scale and scale != "0" else f"{dtype}({prec})"
                lines.append(f"  - {f.get('name', '?')}: {type_str}{pk}{nullable}")

    # Targets with field-level detail + cross-target comparison
    targets = graph.get("targets", [])
    if targets:
        lines.append("### Targets")
        field_counts = {}
        for t in targets:
            fields = t.get("fields", [])
            field_names = [f.get("name", "") for f in fields]
            field_counts[t.get("name", "?")] = set(field_names)
            lines.append(f"- **{t.get('name', '?')}** (owner: {t.get('owner', '—')}, "
                         f"db: {t.get('db_type', '—')}, {len(fields)} fields: "
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
    Uses a single Claude call with a delimiter to split the output.
    """
    mapping_names = parse_report.mapping_names or ["(unknown)"]
    mapping_name = ", ".join(mapping_names)

    structured_summary = _build_structured_summary(graph, parse_report, session_parse_report, s2t_records)

    # Truncate documentation_md to keep the prompt under budget
    doc_for_prompt = documentation_md
    if len(doc_for_prompt) > 40_000:
        doc_for_prompt = doc_for_prompt[:40_000] + "\n\n... [truncated for length]"

    prompt = _ANALYST_PROMPT.format(
        mapping_name=mapping_name,
        structured_summary=structured_summary,
        documentation_md=doc_for_prompt,
    )

    from .retry import claude_with_retry

    client = make_client()
    log.info("analyst_view: generating PRD + gaps for %s — max_tokens=%d",
             mapping_name, _ANALYST_MAX_TOKENS)

    message = await claude_with_retry(
        lambda: client.messages.create(
            model=MODEL,
            max_tokens=_ANALYST_MAX_TOKENS,
            system=_ANALYST_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        ),
        label="analyst view",
    )

    text = message.content[0].text
    log.info("analyst_view: generated — %d chars", len(text))

    # Split on the delimiter
    if SECTION_DELIMITER.strip() in text:
        parts = text.split(SECTION_DELIMITER.strip(), 1)
        analyst_md = parts[0].strip()
        gaps_md = parts[1].strip() if len(parts) > 1 else ""
    else:
        # Fallback: try common variations
        for delimiter in ["---SECTION_BREAK---", "--- SECTION_BREAK ---", "—SECTION_BREAK—"]:
            if delimiter in text:
                parts = text.split(delimiter, 1)
                analyst_md = parts[0].strip()
                gaps_md = parts[1].strip() if len(parts) > 1 else ""
                break
        else:
            # No delimiter found — put everything in 3a, leave 3b empty
            log.warning("analyst_view: delimiter not found — all content goes to 3a")
            analyst_md = text.strip()
            gaps_md = ""

    return analyst_md, gaps_md
