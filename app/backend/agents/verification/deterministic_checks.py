# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Deterministic (rule-based) verification checks.

All checks in this module are pure Python — no Claude API calls.
Returns (completeness_checks, accuracy_checks, self_checks, flags, expr_input_ports, rank_index_ports).
"""
from __future__ import annotations

import re as _re
from typing import Optional

from ...models.schemas import (
    VerificationFlag, CheckResult,
    ComplexityTier, ComplexityReport, ParseReport, SessionParseReport,
)
from ..documentation_agent import DOC_TRUNCATION_SENTINEL
from .constants import UNSUPPORTED_TYPES, _make_flag


# ─────────────────────────────────────────
# Tier ordering for consistency check
# ─────────────────────────────────────────
_TIER_ORDER = [
    ComplexityTier.LOW,
    ComplexityTier.MEDIUM,
    ComplexityTier.HIGH,
    ComplexityTier.VERY_HIGH,
]

_TIER_THRESHOLDS = [
    # (min_trans, min_sources, tier)
    (30, 5, ComplexityTier.VERY_HIGH),
    (15, 4, ComplexityTier.HIGH),
    (5,  2, ComplexityTier.MEDIUM),
]


# ─────────────────────────────────────────
# Graph collection helpers
# ─────────────────────────────────────────

def _collect_all_transformations(graph: dict) -> list:
    """Flatten transformations from all mappings."""
    result = []
    for m in graph.get("mappings", []):
        result.extend(m.get("transformations", []))
    return result


def _collect_all_connectors(graph: dict) -> list:
    """Flatten connectors from all mappings."""
    result = []
    for m in graph.get("mappings", []):
        result.extend(m.get("connectors", []))
    return result


def _build_connected_instances(all_connectors: list) -> set:
    """Build set of instance names that appear in any connector."""
    instances = set()
    for conn in all_connectors:
        instances.add(conn.get("from_instance", ""))
        instances.add(conn.get("to_instance", ""))
    return instances


def _build_sq_connected(graph: dict, connected_instances: set) -> set:
    """Build set of Source Qualifier names that are connected."""
    return {
        t["name"]
        for m in graph.get("mappings", [])
        for t in m.get("transformations", [])
        if t.get("type") == "Source Qualifier" and t["name"] in connected_instances
    }


def _build_lookup_source_names(graph: dict) -> set:
    """Build set of table names referenced by Lookup transformations."""
    return {
        t.get("table_attribs", {}).get("Lookup table name", "").strip()
        for m in graph.get("mappings", [])
        for t in m.get("transformations", [])
        if t.get("type") == "Lookup"
    } - {""}


# ─────────────────────────────────────────
# Individual check sections
# ─────────────────────────────────────────

def _check_truncation(documentation_md: str, flags: list) -> None:
    """Append DOCUMENTATION_TRUNCATED flag if sentinel is present."""
    if DOC_TRUNCATION_SENTINEL not in documentation_md:
        return
    flags.append(_make_flag(
        "DOCUMENTATION_TRUNCATED",
        "Step 3 — Documentation Agent",
        (
            "The documentation was cut off by the AI token limit before all sections "
            "could be written. Review the Step 3 card in the UI to see where it ends. "
            "The mapping graph is complete — this flag reflects a doc generation limit only."
        ),
        blocking=False,
    ))


def _check_transformation_connectivity(
    all_transformations: list, connected_instances: set, completeness_checks: list
) -> None:
    """Check every non-source/target transformation is in the data flow."""
    _skip_types = ("source definition", "target definition", "source", "target")
    for t in all_transformations:
        if t.get("type", "").lower() in _skip_types:
            continue
        in_flow = t["name"] in connected_instances
        completeness_checks.append(CheckResult(
            name=f"Transformation '{t['name']}' connected in data flow",
            passed=in_flow,
            detail=None if in_flow else (
                f"Transformation '{t['name']}' ({t.get('type','')}) has no connectors — "
                "it is isolated from the data flow and will not be converted."
            ),
        ))


def _sq_connected_to(src_name: str, sq_connected: set) -> bool:
    """Return True if src_name is connected via any Source Qualifier name pattern."""
    return (
        f"SQ_{src_name}" in sq_connected                                            # (b) exact SQ
        or any(src_name in sq_name for sq_name in sq_connected)                     # (c) src in SQ name
        or any(sq_name.replace("SQ_", "") in src_name for sq_name in sq_connected)  # (d) SQ abbrev
    )


def _source_has_flow(
    src_name: str,
    all_connectors: list,
    sq_connected: set,
    lookup_source_names: set,
) -> bool:
    """Return True if the source participates in the data flow via any pattern."""
    return (
        any(c.get("from_instance") == src_name for c in all_connectors)  # (a) direct
        or _sq_connected_to(src_name, sq_connected)                       # (b/c/d) via SQ
        or src_name in lookup_source_names                                 # (e) Lookup source
    )


def _check_source_connectivity(
    graph: dict,
    all_connectors: list,
    sq_connected: set,
    lookup_source_names: set,
    completeness_checks: list,
) -> None:
    """Check every source participates in the data flow."""
    for src in graph.get("sources", []):
        src_name = src["name"]
        has_out = _source_has_flow(src_name, all_connectors, sq_connected, lookup_source_names)
        completeness_checks.append(CheckResult(
            name=f"Source '{src_name}' participates in data flow",
            passed=has_out,
            detail=None if has_out else (
                f"Source '{src_name}' has no Source Qualifier connected to the mapping — "
                "it may be an unused source definition or its SQ was not parsed correctly."
            ),
        ))


def _check_target_connectivity(
    graph: dict, all_connectors: list, completeness_checks: list
) -> None:
    """Check every target receives at least one incoming connector."""
    for tgt in graph.get("targets", []):
        has_in = any(c.get("to_instance") == tgt["name"] for c in all_connectors)
        completeness_checks.append(CheckResult(
            name=f"Target '{tgt['name']}' receives incoming connections",
            passed=has_in,
            detail=None if has_in else f"Target '{tgt['name']}' receives no data — it will be empty.",
        ))


def _check_tier_consistency(
    complexity: ComplexityReport,
    all_transformations: list,
    graph: dict,
    self_checks: list,
    flags: list,
) -> None:
    """Check classification tier is consistent with parsed XML content."""
    tier = complexity.tier
    expected_tier = _infer_expected_tier(all_transformations, graph)
    tier_consistent = tier == expected_tier or abs(
        _TIER_ORDER.index(tier) - _TIER_ORDER.index(expected_tier)
    ) <= 1

    self_checks.append(CheckResult(
        name="Complexity classification consistent with XML content",
        passed=tier_consistent,
        detail=None if tier_consistent else (
            f"Assigned: {tier.value}, Expected based on re-check: {expected_tier.value}"
        ),
    ))
    if not tier_consistent:
        flags.append(_make_flag(
            "CLASSIFICATION_MISMATCH",
            "Step 2 output",
            f"Assigned tier {tier.value} may not match XML content (re-check suggests {expected_tier.value})",
            blocking=False,
        ))


def _ports_by_direction(t: dict, direction: str) -> list:
    """Return port names whose porttype contains *direction* ('INPUT' or 'OUTPUT')."""
    return [p["name"] for p in t.get("ports", []) if direction in p.get("porttype", "")]


def _unsupported_flag_description(t: dict) -> str:
    """Build the description string for an UNSUPPORTED_TRANSFORMATION flag."""
    return (
        f"Type '{t['type']}' cannot be automatically converted. "
        f"Input ports: {_ports_by_direction(t, 'INPUT')}. "
        f"Output ports: {_ports_by_direction(t, 'OUTPUT')}."
    )


def _check_unsupported_transformations(
    all_transformations: list, mapping_name: str, self_checks: list, flags: list
) -> None:
    """Flag any transformations that cannot be automatically converted."""
    for t in all_transformations:
        if t["type"] not in UNSUPPORTED_TYPES:
            continue
        flags.append(_make_flag(
            "UNSUPPORTED_TRANSFORMATION",
            f"Mapping: {mapping_name} / Transformation: {t['name']}",
            _unsupported_flag_description(t),
            blocking=True,
        ))
        self_checks.append(CheckResult(
            name=f"Transformation '{t['name']}' is supported",
            passed=False,
            detail=f"Type '{t['type']}' is UNSUPPORTED — conversion of entire mapping is BLOCKED",
        ))


def _check_filter_conditions(
    all_transformations: list, self_checks: list, flags: list
) -> None:
    """Check Filter transformations each have a condition."""
    for t in all_transformations:
        if t.get("type") != "Filter":
            continue
        filter_cond = t.get("table_attribs", {}).get("Filter Condition", "").strip()
        self_checks.append(CheckResult(
            name=f"Filter '{t['name']}' has a condition",
            passed=bool(filter_cond),
            detail=None if filter_cond else (
                f"Filter '{t['name']}' has no Filter Condition attribute in the XML. "
                "The converted code will pass ALL records — verify the XML is complete."
            ),
        ))
        if not filter_cond:
            flags.append(_make_flag(
                "INCOMPLETE_LOGIC",
                t["name"],
                f"Filter transformation '{t['name']}' has no Filter Condition in the mapping XML. "
                "Conversion will generate a PASS-THROUGH stub with a TODO comment.",
                blocking=False,
            ))


def _check_unresolved_parameters(parse_report: ParseReport, flags: list) -> None:
    """Append a flag for every unresolved parameter."""
    for param in parse_report.unresolved_parameters:
        flags.append(_make_flag(
            "UNRESOLVED_PARAMETER",
            f"Parameter: {param}",
            f"Parameter '{param}' has no resolved value. May affect conversion output.",
            blocking=False,
        ))


def _check_unresolved_variables(
    session_parse_report: Optional[SessionParseReport],
    self_checks: list,
    flags: list,
) -> None:
    """Flag unresolved $$VARIABLES from session/parameter parse (Step 0)."""
    if not session_parse_report or not session_parse_report.unresolved_variables:
        return
    for var in session_parse_report.unresolved_variables:
        flags.append(_make_flag(
            "UNRESOLVED_VARIABLE",
            f"Session parameter: {var}",
            (
                f"$$VARIABLE '{var}' is referenced in the session config but has no value "
                "in the uploaded parameter file. The generated runtime_config.yaml contains "
                "a <fill_in> placeholder. Supply the value before deploying the converted code."
            ),
            blocking=False,
        ))
    self_checks.append(CheckResult(
        name="All session $$VARIABLES resolved",
        passed=False,
        detail=(
            f"{len(session_parse_report.unresolved_variables)} unresolved variable(s): "
            + ", ".join(session_parse_report.unresolved_variables)
        ),
    ))


def _is_rank_index_output(p: dict) -> bool:
    """Return True for a RANKINDEX output port."""
    return p["name"] == "RANKINDEX" and "OUTPUT" in p.get("porttype", "")


def _build_rank_index_ports(all_transformations: list) -> set:
    """Return set of 'TRANSFORM_NAME.RANKINDEX' strings for Rank transformations."""
    result: set[str] = set()
    for t in all_transformations:
        if t.get("type") != "Rank":
            continue
        for p in t.get("ports", []):
            if _is_rank_index_output(p):
                result.add(f"{t['name']}.RANKINDEX")
    return result


def _build_expr_vars(t: dict) -> set:
    """Return set of all variable tokens referenced in any expression of a transformation."""
    expr_vars: set = set()
    for expr in t.get("expressions", []):
        expr_text = expr.get("expression", "")
        tokens = set(_re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr_text))
        expr_vars.update(tokens)
    return expr_vars


def _is_expr_input_port(port: dict, expr_vars: set) -> bool:
    """Return True if the port is an INPUT/OUTPUT passthrough feeding an expression."""
    porttype  = port.get("porttype", "")
    port_name = port["name"]
    return (
        "INPUT" in porttype
        and port_name in expr_vars
        and port.get("expression", "") in ("", port_name)
    )


def _is_rank_index_port(t: dict, port_name: str) -> bool:
    """Return True for RANKINDEX output on a Rank transformation."""
    return t.get("type") == "Rank" and port_name == "RANKINDEX"


def _classify_orphaned_port(
    t: dict, port: dict, expr_vars: set
) -> str:
    """Return 'expr_input', 'rank_index', or 'orphaned' for an unwired output port."""
    if _is_expr_input_port(port, expr_vars):
        return "expr_input"
    if _is_rank_index_port(t, port["name"]):
        return "rank_index"
    return "orphaned"


def _check_orphaned_ports(
    all_transformations: list,
    graph: dict,
    flags: list,
) -> tuple[set, set]:
    """
    Detect output ports with no downstream connection.

    Returns (expr_input_ports, rank_index_ports).
    """
    connected_sources: set = set()
    for m in graph.get("mappings", []):
        for conn in m.get("connectors", []):
            connected_sources.add((conn["from_instance"], conn["from_field"]))

    expr_input_ports: set[str] = set()
    rank_index_ports = _build_rank_index_ports(all_transformations)

    for t in all_transformations:
        if t.get("type", "").lower() in ("target definition", "target"):
            continue
        expr_vars = _build_expr_vars(t)
        _process_transformation_ports(t, expr_vars, connected_sources, expr_input_ports, flags)

    return expr_input_ports, rank_index_ports


def _handle_classified_port(
    t: dict, port_name: str, kind: str, expr_input_ports: set, flags: list
) -> None:
    """Act on a classified orphan port — add to tracking set or emit a flag."""
    if kind == "expr_input":
        expr_input_ports.add(f"{t['name']}.{port_name}")
    elif kind == "orphaned":
        flags.append(_make_flag(
            "ORPHANED_PORT",
            f"{t['name']}.{port_name}",
            (
                f"Output port '{port_name}' on '{t['name']}' has no downstream connection "
                f"and is not referenced in any expression within the same transformation. "
                f"This port produces no output and can likely be safely removed."
            ),
            blocking=False,
        ))


def _process_transformation_ports(
    t: dict,
    expr_vars: set,
    connected_sources: set,
    expr_input_ports: set,
    flags: list,
) -> None:
    """Process all output ports of one transformation for orphan detection."""
    for port in t.get("ports", []):
        if "OUTPUT" not in port.get("porttype", ""):
            continue
        port_name = port["name"]
        if (t["name"], port_name) in connected_sources:
            continue
        kind = _classify_orphaned_port(t, port, expr_vars)
        _handle_classified_port(t, port_name, kind, expr_input_ports, flags)


def _check_parse_status(
    parse_report: ParseReport, self_checks: list, flags: list
) -> None:
    """Append a flag and self-check for parse failures."""
    if parse_report.parse_status == "FAILED":
        flags.append(_make_flag(
            "PARSE_FAILED",
            "Step 1 output",
            "XML parsing failed — conversion cannot proceed",
            blocking=True,
        ))
        self_checks.append(CheckResult(
            name="Parse completed successfully",
            passed=False,
            detail="Parse status is FAILED",
        ))
    else:
        self_checks.append(CheckResult(name="Parse completed successfully", passed=True))


def _plural_s(items: list) -> str:
    """Return 's' if *items* has more than one element, else ''."""
    return "s" if len(items) > 1 else ""


def _flag_mapplets_expanded(expanded: list, flags: list) -> None:
    """Append MAPPLET_EXPANDED flag for successfully expanded mapplets."""
    if not expanded:
        return
    mlt_names = ", ".join(f"'{n}'" for n in expanded)
    flags.append(_make_flag(
        "MAPPLET_EXPANDED",
        "Step 1 — XML Parser",
        (
            f"{len(expanded)} mapplet{_plural_s(expanded)} inline-expanded: {mlt_names}. "
            "Internal transformations and connectors have been added to the "
            "mapping graph and external connectors rewired through the Input/"
            "Output interface nodes. Review the expanded sections in the "
            "generated code to verify completeness."
        ),
        blocking=False,
        severity="MEDIUM",
    ))


def _flag_mapplets_detected(not_expanded: list, flags: list) -> None:
    """Append MAPPLET_DETECTED flag for mapplets whose definition was missing."""
    if not not_expanded:
        return
    mlt_names = ", ".join(f"'{n}'" for n in not_expanded)
    flags.append(_make_flag(
        "MAPPLET_DETECTED",
        "Step 1 — XML Parser",
        (
            f"{len(not_expanded)} mapplet{_plural_s(not_expanded)} referenced but definition missing: "
            f"{mlt_names}. "
            "Re-export the mapping with 'Include Dependencies' enabled in "
            "Informatica Repository Manager to allow full inline expansion. "
            "Until then, manually verify any references to these mapplets "
            "in the generated code."
        ),
        blocking=False,
        severity="HIGH",
    ))


def _check_mapplet_flags(parse_report: ParseReport, flags: list) -> None:
    """Promote mapplet parse flags into VerificationFlags."""
    expanded     = parse_report.mapplets_expanded
    detected     = parse_report.mapplets_detected
    not_expanded = [n for n in detected if n not in expanded]
    _flag_mapplets_expanded(expanded, flags)
    _flag_mapplets_detected(not_expanded, flags)


# ─────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────

def run_deterministic_checks(
    parse_report: ParseReport,
    complexity: ComplexityReport,
    documentation_md: str,
    graph: dict,
    session_parse_report: Optional[SessionParseReport] = None,
) -> tuple[
    list[CheckResult],   # completeness_checks
    list[CheckResult],   # accuracy_checks (placeholder — Claude fills accuracy)
    list[CheckResult],   # self_checks
    list[VerificationFlag],  # flags
    set[str],            # expr_input_ports
    set[str],            # rank_index_ports
]:
    """Run all deterministic checks and return structured results.

    The accuracy_checks list is intentionally empty here — Claude quality
    check results (accuracy) are appended by the orchestrator after the
    async Claude call completes.
    """
    completeness_checks: list[CheckResult] = []
    accuracy_checks: list[CheckResult] = []  # filled by orchestrator post-Claude call
    self_checks: list[CheckResult] = []
    flags: list[VerificationFlag] = []

    mapping_name = parse_report.mapping_names[0] if parse_report.mapping_names else "unknown"

    all_transformations = _collect_all_transformations(graph)
    all_connectors      = _collect_all_connectors(graph)
    connected_instances = _build_connected_instances(all_connectors)
    sq_connected        = _build_sq_connected(graph, connected_instances)
    lookup_source_names = _build_lookup_source_names(graph)

    _check_truncation(documentation_md, flags)

    _check_transformation_connectivity(all_transformations, connected_instances, completeness_checks)
    _check_source_connectivity(graph, all_connectors, sq_connected, lookup_source_names, completeness_checks)
    _check_target_connectivity(graph, all_connectors, completeness_checks)

    _check_tier_consistency(complexity, all_transformations, graph, self_checks, flags)
    _check_unsupported_transformations(all_transformations, mapping_name, self_checks, flags)
    _check_filter_conditions(all_transformations, self_checks, flags)
    _check_unresolved_parameters(parse_report, flags)
    _check_unresolved_variables(session_parse_report, self_checks, flags)

    expr_input_ports, rank_index_ports = _check_orphaned_ports(all_transformations, graph, flags)

    _check_parse_status(parse_report, self_checks, flags)
    _check_mapplet_flags(parse_report, flags)

    return completeness_checks, accuracy_checks, self_checks, flags, expr_input_ports, rank_index_ports


def _trans_types(transformations: list) -> list[str]:
    """Return a list of type strings from transformations."""
    return [t["type"] for t in transformations]


def _infer_expected_tier(transformations: list, graph: dict) -> ComplexityTier:
    """Quick re-check of tier for consistency validation."""
    num_trans   = len(transformations)
    num_sources = len(graph.get("sources", []))
    types       = _trans_types(transformations)

    if bool(UNSUPPORTED_TYPES & set(types)):
        return ComplexityTier.VERY_HIGH

    for min_trans, min_src, tier in _TIER_THRESHOLDS:
        if num_trans >= min_trans or num_sources >= min_src:
            return tier

    return ComplexityTier.LOW
