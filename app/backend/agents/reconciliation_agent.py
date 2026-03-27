# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
STEP 8b — Reconciliation Report (static / structural analysis)

Since the tool generates code rather than executing it, a runtime row-count
reconciliation is only possible after the generated code has been run against
real data.  This agent performs the next-best alternative: a STRUCTURAL
reconciliation that verifies the generated code correctly covers every target
field and every source reference declared in the mapping documentation.

What it checks
--------------
1. Field coverage — every target field from the S2T mapping appears somewhere
   in the generated code (by name).
2. Source table coverage — every source table/qualifier referenced in the
   parse report appears in the generated code.
3. Expression coverage — business-rule expressions documented in the mapping
   (e.g. ORDER_AMOUNT * 0.085) are present in at least one generated file.
4. Transformation completeness — no file is pure TODO stubs.

Output
------
ReconciliationReport with:
  - match_rate: float — % of target fields found in generated code
  - mismatched_fields: list of fields not found
  - final_status: RECONCILED | PARTIAL | PENDING_EXECUTION
  - informatica_rows / converted_rows: None (not executable without a database)
"""
from __future__ import annotations
import re
from typing import Optional

from ..models.schemas import (
    ReconciliationReport, ParseReport, ConversionOutput
)


def _resolve_source_tables(
    source_tables: Optional[list[str]],
    parse_report: ParseReport,
) -> list[str]:
    """Return source_tables if provided, otherwise derive from parse_report."""
    if source_tables is None:
        return list(parse_report.mapping_names) + _extract_source_qualifiers(parse_report)
    return source_tables


def generate_reconciliation_report(
    parse_report: ParseReport,
    conversion_output: ConversionOutput,
    s2t_field_list: Optional[list[str]] = None,
    source_tables: Optional[list[str]] = None,
    documented_expressions: Optional[list[str]] = None,
) -> ReconciliationReport:
    """
    Perform a structural reconciliation between the Informatica mapping
    specification and the generated code.

    Parameters
    ----------
    parse_report            Step 1 output — source of mapping/object names
    conversion_output       Step 6 output — the generated code files
    s2t_field_list          Optional list of target field names from the S2T
                            agent (Step 2).  If omitted, only source-table
                            coverage is checked.
    source_tables           Optional list of source table/qualifier names.
                            Defaults to objects_found from parse_report.
    documented_expressions  Optional list of expression fragments (substrings)
                            that should appear verbatim in the generated code
                            (e.g. ["ORDER_AMOUNT * 0.085", "0.15"]).

    Returns
    -------
    ReconciliationReport
    """
    mapping_name = conversion_output.mapping_name
    all_code_low = _combined_code(conversion_output.files).lower()

    mismatched:   list[dict] = []
    verified:     int        = 0
    total_checks: int        = 0

    v, t, m = _check_field_coverage_items(s2t_field_list or [], all_code_low)
    verified += v; total_checks += t; mismatched.extend(m)

    v, t, m = _check_source_table_coverage(
        _resolve_source_tables(source_tables, parse_report), all_code_low,
    )
    verified += v; total_checks += t; mismatched.extend(m)

    v, t, m = _check_expression_coverage(documented_expressions or [], all_code_low)
    verified += v; total_checks += t; mismatched.extend(m)

    stub_files = _detect_stub_files(conversion_output.files)
    if stub_files:
        mismatched.append({
            "type":   "STUB_COMPLETENESS",
            "field":  ", ".join(stub_files),
            "detail": f"Files are predominantly TODO stubs: {stub_files}. "
                      "Manual completion required.",
        })

    match_rate = round((verified / total_checks) * 100, 1) if total_checks > 0 else 100.0
    final_status, root_cause, resolution = _determine_status(match_rate, stub_files, mismatched)

    return ReconciliationReport(
        mapping_name=mapping_name,
        input_description=(
            f"Structural reconciliation of {len(conversion_output.files)} generated file(s) "
            f"against mapping '{mapping_name}'"
        ),
        informatica_rows=None,
        converted_rows=None,
        match_rate=match_rate,
        mismatched_fields=mismatched,
        root_cause=root_cause,
        resolution=resolution,
        final_status=final_status,
    )


def _check_field_coverage_items(
    fields: list[str],
    all_code_low: str,
) -> tuple[int, int, list[dict]]:
    """Check target field coverage. Returns (verified, total, mismatched)."""
    mismatched: list[dict] = []
    verified = 0
    for field in fields:
        if field.lower() in all_code_low:
            verified += 1
        else:
            mismatched.append({
                "type":   "TARGET_FIELD",
                "field":  field,
                "detail": f"Target field '{field}' not found in any generated file.",
            })
    return verified, len(fields), mismatched


def _check_source_table_coverage(
    source_tables: list[str],
    all_code_low: str,
) -> tuple[int, int, list[dict]]:
    """Check source table/qualifier coverage. Returns (verified, total, mismatched)."""
    non_empty = [t for t in source_tables if t]
    mismatched: list[dict] = []
    verified = 0
    for table in non_empty:
        if table.lower() in all_code_low:
            verified += 1
        else:
            mismatched.append({
                "type":   "SOURCE_TABLE",
                "field":  table,
                "detail": f"Source object '{table}' not referenced in any generated file.",
            })
    return verified, len(non_empty), mismatched


def _check_expression_coverage(
    expressions: list[str],
    all_code_low: str,
) -> tuple[int, int, list[dict]]:
    """Check documented expression coverage. Returns (verified, total, mismatched)."""
    non_empty = [e for e in expressions if e.strip()]
    mismatched: list[dict] = []
    verified = 0
    for expr in non_empty:
        if expr.lower() in all_code_low:
            verified += 1
        else:
            mismatched.append({
                "type":   "EXPRESSION",
                "field":  expr,
                "detail": f"Expression '{expr}' not found in generated code — "
                          "business rule may not be implemented.",
            })
    return verified, len(non_empty), mismatched


def _determine_status(
    match_rate: float,
    stub_files: list[str],
    mismatched: list[dict],
) -> tuple[str, Optional[str], Optional[str]]:
    """Return (final_status, root_cause, resolution) based on match_rate."""
    if match_rate == 100.0 and not stub_files:
        return "RECONCILED", None, None
    if match_rate >= 80.0:
        return (
            "PARTIAL",
            _describe_root_cause(mismatched),
            "Review mismatched fields above. "
            "Some target fields or source references may require manual mapping or renaming.",
        )
    return (
        "PENDING_EXECUTION",
        _describe_root_cause(mismatched),
        "Significant structural gaps detected. "
        "Re-review the conversion output against the original mapping documentation "
        "before executing the generated code.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _combined_code(files: dict[str, str]) -> str:
    """Concatenate all generated file contents for substring searching."""
    return "\n".join(files.values())


def _extract_source_qualifiers(parse_report: ParseReport) -> list[str]:
    """
    Pull likely source qualifier / table names from the parse report.

    parse_report.objects_found is a dict like {"Source Qualifier": 2, "Mapping": 1}.
    The actual transformation names come from mapping_names and reusable_components.
    We also scan for SQ_* or similar patterns commonly found in mapping names.
    """
    candidates: list[str] = []

    # Mapping names often embed source table hints (e.g. m_STG_ORDERS_to_FACT)
    for name in parse_report.mapping_names:
        # Split on "_to_" and take left side as a hint
        parts = re.split(r"_to_", name, flags=re.IGNORECASE)
        if parts:
            # Strip leading "m_" prefix
            raw = re.sub(r"^m_", "", parts[0], flags=re.IGNORECASE)
            if raw:
                candidates.append(raw)

    # Reusable components often include source object names
    candidates.extend(parse_report.reusable_components)

    return candidates


def _detect_stub_files(files: dict[str, str]) -> list[str]:
    """
    Return filenames where >60% of code lines are TODO/FIXME/STUB markers.
    Mirrors the logic in _validate_conversion_files for consistency.
    """
    return [
        fname for fname, content in files.items()
        if _is_stub_file(content)
    ]


def _non_empty_lines(stripped: str) -> list[str]:
    """Return stripped non-empty lines from content."""
    return [ln.strip() for ln in stripped.splitlines() if ln.strip()]


def _count_code_and_todo(lines: list[str]) -> tuple[int, int]:
    """Return (code_line_count, todo_line_count) for the given lines."""
    code_count = sum(1 for ln in lines if _is_code_line(ln))
    todo_count = sum(1 for ln in lines if _is_todo_line(ln))
    return code_count, todo_count


def _stub_ratio(lines: list[str]) -> float:
    """Return the ratio of TODO/FIXME/STUB lines to code lines."""
    code_count, todo_count = _count_code_and_todo(lines)
    if not code_count:
        return 0.0
    return todo_count / code_count


def _is_stub_file(content: str) -> bool:
    """Return True if >60% of code lines in content are TODO/FIXME/STUB markers."""
    stripped = content.strip()
    if not stripped:
        return False
    if len(stripped) > 150_000:
        return False
    lines = _non_empty_lines(stripped)
    return _stub_ratio(lines) > 0.6


def _is_code_line(line: str) -> bool:
    """Return True if line is a non-comment code line."""
    return bool(line) and not line.startswith("#") and not line.startswith('"""') and not line.startswith("'''")


def _is_todo_line(line: str) -> bool:
    """Return True if line contains a TODO/FIXME/STUB marker."""
    upper = line.upper()
    return "TODO" in upper or "FIXME" in upper or "STUB" in upper


_ROOT_CAUSE_MESSAGES: dict[str, str] = {
    "TARGET_FIELD":       "{n} target field(s) not found in generated code",
    "SOURCE_TABLE":       "{n} source object(s) not referenced",
    "EXPRESSION":         "{n} business expression(s) missing",
    "STUB_COMPLETENESS":  "One or more files are predominantly TODO stubs",
}


def _describe_root_cause(mismatched: list[dict]) -> str:
    type_counts: dict[str, int] = {}
    for m in mismatched:
        t = m.get("type", "UNKNOWN")
        type_counts[t] = type_counts.get(t, 0) + 1

    parts = [
        _ROOT_CAUSE_MESSAGES[k].format(n=n)
        for k, n in type_counts.items()
        if k in _ROOT_CAUSE_MESSAGES
    ]
    return "; ".join(parts) if parts else "Unknown structural mismatch"
