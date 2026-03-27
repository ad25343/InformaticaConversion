# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
STEP 6 — Stack Assignment
Rule-based logic that determines which target stack (dbt / PySpark / Python)
should be used for a given mapping, plus a Claude-generated rationale.
"""
from __future__ import annotations

from ._common import MODEL, make_client
from ...models.schemas import (
    ComplexityReport, ComplexityTier, StackAssignment, TargetStack, ParseReport,
)


def _select_stack(tier: ComplexityTier, all_trans_types: list[str]) -> TargetStack:
    """Pick target stack from complexity tier and transformation types."""
    if tier in (ComplexityTier.HIGH, ComplexityTier.VERY_HIGH):
        return TargetStack.PYSPARK
    if _is_sql_friendly(all_trans_types):
        return TargetStack.DBT
    if tier == ComplexityTier.LOW:
        return TargetStack.PYTHON
    return TargetStack.PYSPARK


def _collect_special_concerns(all_trans_types: list[str]) -> list[str]:
    """Return a list of special concern strings for the given transformation types."""
    concerns: list[str] = []
    if "HTTP Transformation" in all_trans_types:
        concerns.append("HTTP Transformation — API integration required in converted code")
    if any("Stored Procedure" in t for t in all_trans_types):
        concerns.append("Stored procedure references — will require manual resolution")
    return concerns


async def assign_stack(
    complexity: ComplexityReport,
    graph: dict,
    parse_report: ParseReport,
) -> StackAssignment:
    mapping_name = parse_report.mapping_names[0] if parse_report.mapping_names else "unknown"
    tier = complexity.tier

    all_trans_types: list[str] = []
    for m in graph.get("mappings", []):
        all_trans_types.extend(t["type"] for t in m.get("transformations", []))

    stack           = _select_stack(tier, all_trans_types)
    special_concerns = _collect_special_concerns(all_trans_types)
    rationale       = await _get_stack_rationale(stack, complexity, all_trans_types)

    return StackAssignment(
        mapping_name=mapping_name,
        complexity_tier=tier,
        assigned_stack=stack,
        rationale=rationale,
        data_volume_est=complexity.data_volume_est,
        special_concerns=special_concerns,
    )


def _is_sql_friendly(trans_types: list[str]) -> bool:
    sql_friendly = {"Expression", "Filter", "Aggregator", "Joiner",
                    "Lookup", "Router", "Source Qualifier", "Sorter"}
    non_sql = {"Java Transformation", "External Procedure", "HTTP Transformation",
               "Normalizer", "Transaction Control"}
    present = set(trans_types)
    return not (present & non_sql) and bool(present & sql_friendly)


async def _get_stack_rationale(
    stack: TargetStack,
    complexity: ComplexityReport,
    trans_types: list,
) -> str:
    from .._client import call_claude_with_retry
    client = make_client()
    prompt = (
        f"A mapping has been assigned to {stack.value}.\n"
        f"Complexity tier: {complexity.tier.value}\n"
        f"Criteria: {'; '.join(complexity.criteria_matched)}\n"
        f"Transformation types present: {', '.join(set(trans_types))}\n\n"
        "Write a 2-3 sentence rationale for this stack assignment, "
        "tied to the specific criteria and transformation types listed. "
        "Be concrete. No fluff."
    )
    try:
        msg = await call_claude_with_retry(
            client,
            model=MODEL, max_tokens=300,
            messages=[{"role": "user", "content": prompt}]
        )
        return msg.content[0].text
    except Exception:
        return f"Assigned {stack.value} based on complexity tier {complexity.tier.value}."
