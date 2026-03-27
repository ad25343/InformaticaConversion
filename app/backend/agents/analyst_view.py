# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Analyst View Generator — PRD / Systems Requirements style document.

Uses a lightweight Claude call to produce an analyst-readable requirements
document from the Pass 1 documentation output.  The goal is a document that
analysts, testers, and developers can read without needing to parse raw
transformation details.

Graph field names (from parser_agent.py):
  source/target: "name", "db_type", "owner", "fields"
  transformation: "name", "type", "ports", "expressions", "table_attribs"
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from ..models.schemas import ParseReport, SessionParseReport
from ._client import make_client
from ..config import settings as _cfg

log = logging.getLogger("conversion.analyst_view")

MODEL = _cfg.claude_model
_ANALYST_MAX_TOKENS = 8_000  # keep it tight — this is a summary, not full docs


# ── Prompt ───────────────────────────────────────────────────────────────────

_ANALYST_SYSTEM = """You are a senior data analyst writing a Systems Requirements Document
for an Informatica PowerCenter mapping that will be converted to modern code.

Your audience: analysts, testers, QA leads, and developers who need to understand
WHAT this mapping does — not HOW Informatica implements it.

Write in clear English prose with structured sections. Use tables only where they
add clarity (e.g., field-level rules). Do NOT reproduce raw expressions verbatim —
translate them into plain English business rules.

Output ONLY the Markdown document — no preamble, no commentary outside the doc."""

_ANALYST_PROMPT = """Produce a Systems Requirements Document for this Informatica mapping.

## Mapping Name
{mapping_name}

## Structured Summary
{structured_summary}

## Full Technical Documentation (reference only — do NOT copy)
{documentation_md}

## Instructions

Write a PRD-style requirements document with these sections:

# {mapping_name} — Systems Requirements

## 1. Purpose & Business Context
2-3 sentences: what does this mapping do in business terms? What data does it
produce and why?

## 2. Source Systems
For each source table: name, owner/schema, what data it provides, how many fields.
If there is a Source Qualifier filter or custom SQL, explain in plain English what
rows are selected and why.

## 3. Target Systems
For each target table: name, owner/schema, what data it receives, load strategy
(insert/update/upsert/delete).

## 4. Data Flow & Transformation Rules
Walk through the mapping logic in business terms:
- How are sources joined? (join type and business meaning of the condition)
- What lookups are performed and why? (reference table, what's being enriched)
- What filters are applied and why? (business rule behind the filter)
- What calculations / derivations are performed? (in plain English)
- What aggregations if any?

## 5. Key Business Rules
Numbered list of the critical business rules this mapping enforces.
Each rule: one plain English sentence.

## 6. Parameters & Runtime Dependencies
What parameters affect behavior? What connections/credentials are needed?
Any environment-specific values?

## 7. Testing Considerations
What should a tester validate? Edge cases, boundary conditions, null handling,
expected row counts, reconciliation points.

Keep the document concise — aim for 1-3 pages, not 10. Prioritize clarity over
completeness. If something is ambiguous in the source data, say so explicitly.
"""


# ── Structured summary builder ───────────────────────────────────────────────

def _build_structured_summary(graph: dict, parse_report: ParseReport,
                               session_parse_report: Optional[SessionParseReport]) -> str:
    """Build a compact structured summary from the graph for Claude context."""
    lines: list[str] = []
    txns: list[dict] = []
    for mapping in graph.get("mappings", []):
        txns.extend(mapping.get("transformations", []))

    # Sources
    sources = graph.get("sources", [])
    if sources:
        lines.append("### Sources")
        for s in sources:
            fields = s.get("fields", [])
            lines.append(f"- {s.get('name', '?')} (owner: {s.get('owner', '—')}, "
                         f"db: {s.get('db_type', '—')}, {len(fields)} fields)")

    # Targets
    targets = graph.get("targets", [])
    if targets:
        lines.append("### Targets")
        for t in targets:
            fields = t.get("fields", [])
            lines.append(f"- {t.get('name', '?')} (owner: {t.get('owner', '—')}, "
                         f"db: {t.get('db_type', '—')}, {len(fields)} fields)")

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

    return "\n".join(lines)


# ── Main entry point ─────────────────────────────────────────────────────────

async def generate_analyst_view(
    graph: dict,
    parse_report: ParseReport,
    documentation_md: str,
    session_parse_report: Optional[SessionParseReport] = None,
) -> str:
    """
    Produce a PRD / Systems Requirements Document from the parsed graph
    and the Pass 1 documentation.

    Uses a lightweight Claude call (max 8k tokens).
    """
    mapping_names = parse_report.mapping_names or ["(unknown)"]
    mapping_name = ", ".join(mapping_names)

    structured_summary = _build_structured_summary(graph, parse_report, session_parse_report)

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
    log.info("analyst_view: generating PRD for %s — max_tokens=%d", mapping_name, _ANALYST_MAX_TOKENS)

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
    return text
