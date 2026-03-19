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

    # ─────────────────────────────────────────
    # TRUNCATION FLAG
    # ─────────────────────────────────────────
    if DOC_TRUNCATION_SENTINEL in documentation_md:
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

    # ─────────────────────────────────────────
    # GRAPH STRUCTURAL CHECKS (deterministic)
    # ─────────────────────────────────────────

    all_transformations = []
    for m in graph.get("mappings", []):
        all_transformations.extend(m.get("transformations", []))

    # Build connector sets for structural checks
    all_connectors: list[dict] = []
    for m in graph.get("mappings", []):
        all_connectors.extend(m.get("connectors", []))

    connected_instances = set()
    for conn in all_connectors:
        connected_instances.add(conn.get("from_instance", ""))
        connected_instances.add(conn.get("to_instance", ""))

    # Every transformation (except sources/targets) participates in the data flow?
    for t in all_transformations:
        t_type = t.get("type", "").lower()
        if t_type in ("source definition", "target definition", "source", "target"):
            continue
        in_flow = t["name"] in connected_instances
        completeness_checks.append(CheckResult(
            name=f"Transformation '{t['name']}' connected in data flow",
            passed=in_flow,
            detail=None if in_flow else (
                f"Transformation '{t['name']}' ({t.get('type','')}) has no connectors — "
                "it is isolated from the data flow and will not be converted."
            )
        ))

    # Every source participates in the data flow?
    # In Informatica's architecture, SOURCE elements never appear directly as FROMINSTANCE
    # in CONNECTOR elements — they always connect through a Source Qualifier (SQ_*) or a
    # Lookup transformation (for reference/dimension tables).
    #
    # We check four patterns:
    #   (a) Direct CONNECTOR match (non-standard but possible in older mappings)
    #   (b) SQ_{src_name} is in the connected SQ set (exact standard naming)
    #   (c) src_name is a substring of a connected SQ name (e.g. SQ_ORDERS for STAGING_ORDERS)
    #   (d) SQ name without the SQ_ prefix is a substring of src_name — handles abbreviated SQs
    #       e.g. SQ_APPRAISALS for source CORELOGIC_APPRAISALS ("APPRAISALS" in "CORELOGIC_APPRAISALS")
    #   (e) src_name matches a Lookup transformation's "Lookup table name" attribute — reference
    #       tables used in Lookups have no Source Qualifier; they are read directly by the LKP.
    sq_connected = {
        t["name"]
        for m in graph.get("mappings", [])
        for t in m.get("transformations", [])
        if t.get("type") == "Source Qualifier" and t["name"] in connected_instances
    }
    # Build a set of source names that are referenced as Lookup table sources.
    # In Informatica XML the Lookup table is stored as TABLEATTRIBUTE NAME="Lookup table name".
    # The parser stores these under transformation["table_attribs"].
    lookup_source_names = {
        t.get("table_attribs", {}).get("Lookup table name", "").strip()
        for m in graph.get("mappings", [])
        for t in m.get("transformations", [])
        if t.get("type") == "Lookup"
    } - {""}  # remove empty strings

    for src in graph.get("sources", []):
        src_name = src["name"]
        has_out = (
            any(c.get("from_instance") == src_name for c in all_connectors)        # (a) direct
            or f"SQ_{src_name}" in sq_connected                                      # (b) exact SQ
            or any(src_name in sq_name for sq_name in sq_connected)                  # (c) src in SQ name
            or any(sq_name.replace("SQ_", "") in src_name for sq_name in sq_connected)  # (d) SQ abbrev
            or src_name in lookup_source_names                                       # (e) Lookup source
        )
        completeness_checks.append(CheckResult(
            name=f"Source '{src_name}' participates in data flow",
            passed=has_out,
            detail=None if has_out else (
                f"Source '{src_name}' has no Source Qualifier connected to the mapping — "
                "it may be an unused source definition or its SQ was not parsed correctly."
            )
        ))

    # Every target receives at least one incoming connector?
    for tgt in graph.get("targets", []):
        has_in = any(c.get("to_instance") == tgt["name"] for c in all_connectors)
        completeness_checks.append(CheckResult(
            name=f"Target '{tgt['name']}' receives incoming connections",
            passed=has_in,
            detail=None if has_in else f"Target '{tgt['name']}' receives no data — it will be empty."
        ))

    # ─────────────────────────────────────────
    # SELF-CHECKS (deterministic)
    # ─────────────────────────────────────────

    # Classification consistent with parse?
    tier = complexity.tier
    expected_tier = _infer_expected_tier(all_transformations, graph)
    tier_consistent = tier == expected_tier or abs(
        [ComplexityTier.LOW, ComplexityTier.MEDIUM, ComplexityTier.HIGH, ComplexityTier.VERY_HIGH].index(tier) -
        [ComplexityTier.LOW, ComplexityTier.MEDIUM, ComplexityTier.HIGH, ComplexityTier.VERY_HIGH].index(expected_tier)
    ) <= 1

    self_checks.append(CheckResult(
        name="Complexity classification consistent with XML content",
        passed=tier_consistent,
        detail=None if tier_consistent else f"Assigned: {tier.value}, Expected based on re-check: {expected_tier.value}"
    ))
    if not tier_consistent:
        flags.append(_make_flag(
            "CLASSIFICATION_MISMATCH",
            "Step 2 output",
            f"Assigned tier {tier.value} may not match XML content (re-check suggests {expected_tier.value})",
            blocking=False,
        ))

    # Unsupported transformations?
    for t in all_transformations:
        if t["type"] in UNSUPPORTED_TYPES:
            flags.append(_make_flag(
                "UNSUPPORTED_TRANSFORMATION",
                f"Mapping: {mapping_name} / Transformation: {t['name']}",
                (
                    f"Type '{t['type']}' cannot be automatically converted. "
                    f"Input ports: {[p['name'] for p in t['ports'] if 'INPUT' in p.get('porttype','')]}. "
                    f"Output ports: {[p['name'] for p in t['ports'] if 'OUTPUT' in p.get('porttype','')]}."
                ),
                blocking=True,
            ))
            self_checks.append(CheckResult(
                name=f"Transformation '{t['name']}' is supported",
                passed=False,
                detail=f"Type '{t['type']}' is UNSUPPORTED — conversion of entire mapping is BLOCKED"
            ))

    # Filter transformations must have a condition — if the condition is absent the
    # converted code will pass ALL records through, silently dropping business logic.
    # Check table_attribs["Filter Condition"] which is where the parser stores it.
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
            )
        ))
        if not filter_cond:
            flags.append(_make_flag(
                "INCOMPLETE_LOGIC",
                t["name"],
                f"Filter transformation '{t['name']}' has no Filter Condition in the mapping XML. "
                "Conversion will generate a PASS-THROUGH stub with a TODO comment.",
                blocking=False,
            ))

    # Unresolved parameters?
    for param in parse_report.unresolved_parameters:
        flags.append(_make_flag(
            "UNRESOLVED_PARAMETER",
            f"Parameter: {param}",
            f"Parameter '{param}' has no resolved value. May affect conversion output.",
            blocking=False,
        ))

    # v1.1: Unresolved $$VARIABLES from session/parameter parse (Step 0)
    if session_parse_report and session_parse_report.unresolved_variables:
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

    # Orphaned output ports — field computed but never sent downstream
    # An output port is orphaned when it never appears as the FROM side of any connector.
    connected_sources = set()
    for m in graph.get("mappings", []):
        for conn in m.get("connectors", []):
            connected_sources.add((conn["from_instance"], conn["from_field"]))

    # Track expression-input-only ports so we can pass them to Claude and suppress
    # false DEAD_LOGIC flags for ports that feed derivations but aren't wired downstream.
    expr_input_ports: set[str] = set()   # "TRANSFORM_NAME.PORT_NAME" strings

    # Track RANKINDEX ports on Rank transformations — these are never wired downstream
    # in the standard Sorter→Rank(N=1) dedup pattern, and must not be flagged as dead.
    rank_index_ports: set[str] = set()   # "TRANSFORM_NAME.RANKINDEX" strings
    for t in all_transformations:
        if t.get("type") == "Rank":
            for p in t.get("ports", []):
                if p["name"] == "RANKINDEX" and "OUTPUT" in p.get("porttype", ""):
                    rank_index_ports.add(f"{t['name']}.RANKINDEX")

    for t in all_transformations:
        # Skip target definitions — they have no outgoing connectors by design
        if t.get("type", "").lower() in ("target definition", "target"):
            continue

        # Build a set of all field names that appear inside any expression in this transformation.
        # These are "consumed" fields — even if their passthrough isn't wired, their values feed
        # other derived ports within the same transformation.
        expr_vars: set = set()
        for expr in t.get("expressions", []):
            expr_text = expr.get("expression", "")
            tokens = set(_re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr_text))
            expr_vars.update(tokens)

        for port in t.get("ports", []):
            porttype = port.get("porttype", "")
            if "OUTPUT" not in porttype:
                continue
            port_name = port["name"]
            if (t["name"], port_name) in connected_sources:
                continue  # properly wired downstream — not orphaned

            # Determine whether this port is an expression-input passthrough:
            # INPUT/OUTPUT port whose value is referenced inside another expression
            # in the same transformation (e.g. ORDER_DATE feeds TO_CHAR(ORDER_DATE,...))
            is_expr_input = (
                "INPUT" in porttype               # must be INPUT/OUTPUT
                and port_name in expr_vars         # name referenced in some expression
                and port.get("expression", "") in ("", port_name)  # not itself a derived expression
            )

            if is_expr_input:
                expr_input_ports.add(f"{t['name']}.{port_name}")
                # The raw pass-through isn't wired, but the value IS consumed by derived fields.
                # No action needed — this is by design. Skip flagging entirely to avoid noise.
                # (Claude is told about these ports explicitly so it won't raise DEAD_LOGIC either.)
            elif t.get("type") == "Rank" and port_name == "RANKINDEX":
                # RANKINDEX is Informatica's internal rank counter output on Rank transformations.
                # When the Rank is configured with "Number Of Ranks = N", only the top-N rows are
                # output per group — the filtering is intrinsic to the transformation.  RANKINDEX
                # never needs to be wired to a downstream Filter to achieve deduplication; the
                # classic Informatica dedup pattern (Sorter → Rank[N=1]) works without connecting
                # RANKINDEX at all.  Flagging it as ORPHANED_PORT is a false positive.
                pass
            else:
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

    # Parse status check
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
            detail="Parse status is FAILED"
        ))
    else:
        self_checks.append(CheckResult(name="Parse completed successfully", passed=True))

    # ─────────────────────────────────────────
    # MAPPLET flags — promote parse flags into VerificationFlags.
    # Two distinct flag types:
    #   MAPPLET_EXPANDED  — definition found and inline-expanded (MEDIUM, non-blocking)
    #   MAPPLET_DETECTED  — instance found but definition missing (HIGH, non-blocking)
    # ─────────────────────────────────────────
    expanded   = parse_report.mapplets_expanded   # successfully expanded
    detected   = parse_report.mapplets_detected   # all found (superset)
    not_expanded = [n for n in detected if n not in expanded]

    if expanded:
        mlt_names = ", ".join(f"'{n}'" for n in expanded)
        plural = "s" if len(expanded) > 1 else ""
        flags.append(_make_flag(
            "MAPPLET_EXPANDED",
            "Step 1 — XML Parser",
            (
                f"{len(expanded)} mapplet{plural} inline-expanded: {mlt_names}. "
                "Internal transformations and connectors have been added to the "
                "mapping graph and external connectors rewired through the Input/"
                "Output interface nodes. Review the expanded sections in the "
                "generated code to verify completeness."
            ),
            blocking=False,
            severity="MEDIUM",
        ))

    if not_expanded:
        mlt_names = ", ".join(f"'{n}'" for n in not_expanded)
        plural = "s" if len(not_expanded) > 1 else ""
        flags.append(_make_flag(
            "MAPPLET_DETECTED",
            "Step 1 — XML Parser",
            (
                f"{len(not_expanded)} mapplet{plural} referenced but definition missing: "
                f"{mlt_names}. "
                "Re-export the mapping with 'Include Dependencies' enabled in "
                "Informatica Repository Manager to allow full inline expansion. "
                "Until then, manually verify any references to these mapplets "
                "in the generated code."
            ),
            blocking=False,
            severity="HIGH",
        ))

    return completeness_checks, accuracy_checks, self_checks, flags, expr_input_ports, rank_index_ports


def _infer_expected_tier(transformations: list, graph: dict) -> ComplexityTier:
    """Quick re-check of tier for consistency validation."""
    num_trans = len(transformations)
    num_sources = len(graph.get("sources", []))
    types = [t["type"] for t in transformations]

    unsupported = any(t in UNSUPPORTED_TYPES for t in types)
    if unsupported or num_trans >= 30 or num_sources >= 5:
        return ComplexityTier.VERY_HIGH
    if num_trans >= 15 or num_sources >= 4:
        return ComplexityTier.HIGH
    if num_trans >= 5 or num_sources >= 2:
        return ComplexityTier.MEDIUM
    return ComplexityTier.LOW
