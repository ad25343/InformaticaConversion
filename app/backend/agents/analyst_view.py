# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Analyst View Generator — deterministic extraction from the parsed graph.

Produces a structured, tabular Markdown document aimed at analysts, testers,
and developers.  Covers: source tables, target tables, joins, lookups, filters,
key business expressions, and parameters.

No Claude calls — purely deterministic.  Fast and free.
"""
from __future__ import annotations

import logging
from typing import Optional

from ..models.schemas import ParseReport, SessionParseReport

log = logging.getLogger("conversion.analyst_view")

# Expression length cap for the "Key Expressions" section
_EXPR_MAX_CHARS = 200
_MAX_EXPRESSIONS = 20


# ── Helpers ──────────────────────────────────────────────────────────────────

def _esc_pipe(val: str) -> str:
    """Escape pipe characters for markdown table cells and collapse whitespace."""
    return val.replace("|", "\\|").replace("\n", " ").strip()


def _trunc(val: str, limit: int = _EXPR_MAX_CHARS) -> str:
    """Truncate a string, appending ellipsis if it exceeds the limit."""
    val = val.replace("\n", " ").strip()
    return val if len(val) <= limit else val[:limit] + "…"


def _get_transformations(graph: dict) -> list[dict]:
    """Flatten all transformations from all mappings in the graph."""
    txns: list[dict] = []
    for mapping in graph.get("mappings", []):
        txns.extend(mapping.get("transformations", []))
    return txns


def _by_type(txns: list[dict], *types: str) -> list[dict]:
    """Filter transformations whose type contains any of the given substrings (case-insensitive)."""
    lower_types = [t.lower() for t in types]
    return [t for t in txns if any(lt in t.get("type", "").lower() for lt in lower_types)]


# ── Section builders ─────────────────────────────────────────────────────────

def _section_sources(graph: dict, txns: list[dict]) -> str:
    """Source tables with any custom SQL overrides."""
    lines = ["## Source Tables", ""]
    sources = graph.get("sources", [])
    sqs = _by_type(txns, "source qualifier")

    # Build a lookup of SQ SQL overrides keyed by SQ name
    sq_sql: dict[str, str] = {}
    for sq in sqs:
        sql = sq.get("table_attribs", {}).get("Sql Query", "").strip()
        if sql:
            sq_sql[sq["name"]] = sql

    if not sources and not sqs:
        lines.append("_No source tables detected._")
        return "\n".join(lines)

    lines.append("| # | Source Table | Database Type | Custom SQL Override |")
    lines.append("|---|-------------|---------------|---------------------|")
    if sources:
        for i, src in enumerate(sources, 1):
            name = _esc_pipe(src.get("name", "unknown"))
            db_type = _esc_pipe(src.get("databaseType", src.get("database_type", "—")))
            # Try to match SQ by name convention (SQ_<sourcename> or similar)
            sql_override = "—"
            for sq_name, sql in sq_sql.items():
                if name.lower() in sq_name.lower() or sq_name.lower() in name.lower():
                    sql_override = f"`{_trunc(_esc_pipe(sql))}`"
                    break
            lines.append(f"| {i} | {name} | {db_type} | {sql_override} |")
    else:
        # Fallback: use Source Qualifier transformations
        for i, sq in enumerate(sqs, 1):
            name = _esc_pipe(sq["name"])
            sql = sq.get("table_attribs", {}).get("Sql Query", "").strip()
            sql_col = f"`{_trunc(_esc_pipe(sql))}`" if sql else "—"
            lines.append(f"| {i} | {name} | — | {sql_col} |")

    return "\n".join(lines)


def _section_targets(graph: dict, txns: list[dict]) -> str:
    """Target tables with load type."""
    lines = ["## Target Tables", ""]
    targets = graph.get("targets", [])

    if not targets:
        lines.append("_No target tables detected._")
        return "\n".join(lines)

    lines.append("| # | Target Table | Database Type | Load Type |")
    lines.append("|---|-------------|---------------|-----------|")
    for i, tgt in enumerate(targets, 1):
        name = _esc_pipe(tgt.get("name", "unknown"))
        db_type = _esc_pipe(tgt.get("databaseType", tgt.get("database_type", "—")))
        # Target load type may come from matching target transformation attribs
        load_type = "—"
        for t in txns:
            if t.get("type", "").lower() == "target" and t.get("name", "").lower() == name.lower():
                lt = t.get("table_attribs", {}).get("Target Load Type", "")
                if lt:
                    load_type = _esc_pipe(lt)
                break
        lines.append(f"| {i} | {name} | {db_type} | {load_type} |")

    return "\n".join(lines)


def _section_joins(txns: list[dict]) -> str:
    """Join conditions from Joiner transformations."""
    joiners = _by_type(txns, "joiner")
    if not joiners:
        return ""

    lines = ["## Joins", ""]
    lines.append("| # | Joiner Name | Join Type | Condition |")
    lines.append("|---|------------|-----------|-----------|")
    for i, j in enumerate(joiners, 1):
        name = _esc_pipe(j["name"])
        attribs = j.get("table_attribs", {})
        join_type = _esc_pipe(attribs.get("Join Type", attribs.get("Join type", "NORMAL")))
        # Map Informatica join types to readable names
        jt_map = {"NORMAL": "Inner", "MASTER OUTER": "Left Outer",
                   "DETAIL OUTER": "Right Outer", "FULL OUTER": "Full Outer"}
        join_type_display = jt_map.get(join_type.upper(), join_type)
        condition = attribs.get("Join Condition", "").strip()
        cond_display = f"`{_trunc(_esc_pipe(condition))}`" if condition else "—"
        lines.append(f"| {i} | {name} | {join_type_display} | {cond_display} |")

    return "\n".join(lines)


def _section_lookups(txns: list[dict]) -> str:
    """Lookup transformations with conditions and return ports."""
    lookups = _by_type(txns, "lookup")
    if not lookups:
        return ""

    lines = ["## Lookups", ""]
    lines.append("| # | Lookup Name | Source Table | Condition | Return Ports |")
    lines.append("|---|-----------|-------------|-----------|--------------|")
    for i, lkp in enumerate(lookups, 1):
        name = _esc_pipe(lkp["name"])
        attribs = lkp.get("table_attribs", {})
        src_table = _esc_pipe(attribs.get("Lookup table name",
                              attribs.get("Lookup Table Name", "—")))
        condition = attribs.get("Lookup Condition",
                    attribs.get("Lookup condition", "")).strip()
        cond_display = f"`{_trunc(_esc_pipe(condition))}`" if condition else "—"
        # Return ports = output ports (non-input)
        out_ports = [p["name"] for p in lkp.get("ports", [])
                     if p.get("porttype", "").upper() in ("OUTPUT", "INPUT/OUTPUT")]
        ports_display = ", ".join(out_ports[:5])
        if len(out_ports) > 5:
            ports_display += f" (+{len(out_ports)-5} more)"
        lines.append(f"| {i} | {name} | {src_table} | {cond_display} | {_esc_pipe(ports_display) or '—'} |")

    return "\n".join(lines)


def _section_filters(txns: list[dict]) -> str:
    """Filter and Router conditions."""
    filters = _by_type(txns, "filter")
    routers = _by_type(txns, "router")
    if not filters and not routers:
        return ""

    lines = ["## Filters & Routers", ""]
    lines.append("| # | Name | Type | Condition |")
    lines.append("|---|------|------|-----------|")
    idx = 1

    for f in filters:
        name = _esc_pipe(f["name"])
        condition = f.get("table_attribs", {}).get("Filter Condition", "").strip()
        if not condition:
            # Sometimes filter condition is in the port expression
            for p in f.get("ports", []):
                if p.get("expression", "").strip():
                    condition = p["expression"].strip()
                    break
        cond_display = f"`{_trunc(_esc_pipe(condition))}`" if condition else "—"
        lines.append(f"| {idx} | {name} | Filter | {cond_display} |")
        idx += 1

    for r in routers:
        name = _esc_pipe(r["name"])
        attribs = r.get("table_attribs", {})
        # Router groups use "Group Filter Condition 1", "Group Filter Condition 2", etc.
        group_conditions = []
        for k, v in sorted(attribs.items()):
            if "group filter condition" in k.lower() and v.strip():
                group_conditions.append(v.strip())
        if group_conditions:
            for gc in group_conditions:
                cond_display = f"`{_trunc(_esc_pipe(gc))}`"
                lines.append(f"| {idx} | {name} | Router | {cond_display} |")
                idx += 1
        else:
            lines.append(f"| {idx} | {name} | Router | — |")
            idx += 1

    return "\n".join(lines)


def _section_expressions(txns: list[dict]) -> str:
    """Key non-trivial expressions (derived fields, calculations)."""
    expr_rows: list[tuple[str, str, str, str]] = []  # (txn_name, txn_type, port, expression)

    for t in txns:
        ttype = t.get("type", "")
        tname = t.get("name", "")
        for expr in t.get("expressions", []):
            raw = expr.get("expression", "").strip()
            port = expr.get("port", "")
            # Skip trivial: empty, or just a field name (no operators/functions)
            if not raw or (raw.isidentifier() and "(" not in raw):
                continue
            # Skip if expression is just the port name (passthrough)
            if raw.upper() == port.upper():
                continue
            expr_rows.append((tname, ttype, port, raw))

    if not expr_rows:
        return ""

    # Sort by expression length (most complex first), cap at _MAX_EXPRESSIONS
    expr_rows.sort(key=lambda r: len(r[3]), reverse=True)
    expr_rows = expr_rows[:_MAX_EXPRESSIONS]

    lines = ["## Key Business Rules & Expressions", ""]
    lines.append("| # | Transformation | Port | Expression |")
    lines.append("|---|---------------|------|------------|")
    for i, (tname, ttype, port, raw) in enumerate(expr_rows, 1):
        lines.append(f"| {i} | {_esc_pipe(tname)} ({_esc_pipe(ttype)}) | {_esc_pipe(port)} | `{_trunc(_esc_pipe(raw))}` |")

    if len(expr_rows) == _MAX_EXPRESSIONS:
        lines.append(f"\n_Showing top {_MAX_EXPRESSIONS} expressions by complexity. See Step 3b for full details._")

    return "\n".join(lines)


def _section_parameters(
    parse_report: ParseReport,
    session_parse_report: Optional[SessionParseReport],
) -> str:
    """Parameters and variables."""
    rows: list[tuple[str, str, str]] = []  # (name, value, scope)

    # Resolved parameters from session parse
    if session_parse_report and session_parse_report.parameters:
        for p in session_parse_report.parameters:
            rows.append((p.name, p.value, p.scope))

    # Unresolved from session parse
    if session_parse_report and session_parse_report.unresolved_variables:
        for v in session_parse_report.unresolved_variables:
            rows.append((v, "⚠ UNRESOLVED", "—"))

    # Unresolved from parse report (if not already captured)
    known = {r[0] for r in rows}
    for v in parse_report.unresolved_parameters:
        if v not in known:
            rows.append((v, "⚠ UNRESOLVED", "—"))

    if not rows:
        return ""

    lines = ["## Parameters & Variables", ""]
    lines.append("| # | Parameter | Value | Scope |")
    lines.append("|---|----------|-------|-------|")
    for i, (name, value, scope) in enumerate(rows, 1):
        lines.append(f"| {i} | `{_esc_pipe(name)}` | {_esc_pipe(_trunc(value, 100))} | {_esc_pipe(scope)} |")

    return "\n".join(lines)


# ── Main entry point ─────────────────────────────────────────────────────────

def generate_analyst_view(
    graph: dict,
    parse_report: ParseReport,
    session_parse_report: Optional[SessionParseReport] = None,
) -> str:
    """
    Produce the Analyst View markdown from the parsed graph.

    Returns a structured, tabular Markdown document covering sources, targets,
    joins, lookups, filters, key expressions, and parameters.
    """
    mapping_names = parse_report.mapping_names or ["(unknown)"]
    txns = _get_transformations(graph)

    header = f"# Analyst View — {', '.join(mapping_names)}\n"

    sections = [
        header,
        _section_sources(graph, txns),
        _section_targets(graph, txns),
        _section_joins(txns),
        _section_lookups(txns),
        _section_filters(txns),
        _section_expressions(txns),
        _section_parameters(parse_report, session_parse_report),
    ]

    # Filter out empty sections and join with double newlines
    md = "\n\n".join(s for s in sections if s.strip())
    log.info("Analyst view generated — %d chars, %d transformations scanned",
             len(md), len(txns))
    return md
