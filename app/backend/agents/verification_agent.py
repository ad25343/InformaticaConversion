"""
STEP 4 — Verification Agent
Runs ALL checks without stopping. Produces one complete Verification Report.
Deterministic checks run in Python; qualitative flags use Claude.

Each flag now carries:
  severity       — CRITICAL | HIGH | MEDIUM | LOW | INFO
  recommendation — Actionable guidance for the human reviewer
"""
from __future__ import annotations
import json
import os
import anthropic

from typing import Optional
from ..models.schemas import (
    VerificationReport, VerificationFlag, CheckResult,
    ComplexityTier, ComplexityReport, ParseReport, SessionParseReport
)

from ..config import settings as _cfg
MODEL = _cfg.claude_model

# Import the truncation sentinel from the documentation agent so we detect it consistently.
from .documentation_agent import DOC_TRUNCATION_SENTINEL  # noqa: E402

# Tier-aware token budget for the Claude quality-check call.
# More transformations → more flags → more tokens needed in the response.
_QC_MAX_TOKENS: dict[ComplexityTier, int] = {
    ComplexityTier.LOW:       2_048,
    ComplexityTier.MEDIUM:    4_096,
    ComplexityTier.HIGH:      6_144,
    ComplexityTier.VERY_HIGH: 8_192,
}

UNSUPPORTED_TYPES = {
    "Java Transformation", "External Procedure",
    "Advanced External Procedure", "Stored Procedure"
}

BLOCKING_FLAG_TYPES = {
    "UNSUPPORTED_TRANSFORMATION", "UNRESOLVED_PARAMETER_BLOCKING",
    "SQL_REVIEW_REQUIRED", "PARSE_FAILED"
}

# ─────────────────────────────────────────────────────────────────────────────
# FLAG METADATA — severity + actionable recommendation per flag type
# ─────────────────────────────────────────────────────────────────────────────
FLAG_META: dict[str, dict] = {
    "UNSUPPORTED_TRANSFORMATION": {
        "severity": "CRITICAL",
        "recommendation": (
            "This transformation type cannot be automatically converted. Manual re-implementation "
            "is required before conversion can proceed. Consider splitting this mapping into a "
            "separate manual migration task and converting the rest automatically."
        ),
    },
    "PARSE_FAILED": {
        "severity": "CRITICAL",
        "recommendation": (
            "The XML could not be parsed. Verify this is a valid Informatica PowerCenter export "
            "(.xml). Re-export from Informatica Designer, ensure the file is not truncated, and "
            "check for XML encoding issues."
        ),
    },
    "SQL_REVIEW_REQUIRED": {
        "severity": "CRITICAL",
        "recommendation": (
            "This SQL override cannot be automatically converted. Manually translate the custom "
            "SQL into the target stack's equivalent (e.g., Spark SQL / dbt SQL). Review for "
            "database-specific syntax that won't port directly."
        ),
    },
    "UNRESOLVED_PARAMETER_BLOCKING": {
        "severity": "CRITICAL",
        "recommendation": (
            "This parameter is used in a critical position (filter, join condition, or SQL). "
            "Resolve the actual runtime value before conversion proceeds. Document the value "
            "in the converted code's config section."
        ),
    },
    "UNRESOLVED_PARAMETER": {
        "severity": "HIGH",
        "recommendation": (
            "Replace the parameter with its runtime value, or externalize it to a config "
            "file (.env or config.yaml). If it is a session-level parameter (e.g. $PMRootDir), "
            "document it as a required input in the converted code's README."
        ),
    },
    "ENVIRONMENT_SPECIFIC_VALUE": {
        "severity": "HIGH",
        "recommendation": (
            "Move this hardcoded value to an environment config file. Never embed connection "
            "strings, file paths, server names, or schema names directly in converted code — "
            "they will break across environments (dev/staging/prod)."
        ),
    },
    "HIGH_RISK": {
        "severity": "HIGH",
        "recommendation": (
            "Flag for additional peer review and UAT testing before promoting to production. "
            "Add reconciliation row counts and data quality assertions around this logic in "
            "the converted code. Ensure an audit trail is maintained."
        ),
    },
    "LINEAGE_GAP": {
        "severity": "HIGH",
        "recommendation": (
            "Trace this target field manually in the Informatica mapping. If truly unresolvable, "
            "document it as a known gap in the conversion notes and add a TODO comment in the "
            "generated code so downstream engineers are aware."
        ),
    },
    "ACCURACY_CONCERN": {
        "severity": "HIGH",
        "recommendation": (
            "Review the generated documentation against the original XML to verify no business "
            "logic was altered during the documentation step. If inaccurate, delete this job, "
            "correct the XML or the documentation prompt, and re-run."
        ),
    },
    "INCOMPLETE_LOGIC": {
        "severity": "HIGH",
        "recommendation": (
            "Review all branches of the conditional logic. Ensure every ELSE / default case is "
            "handled explicitly. Missing branches cause silent data loss, incorrect routing, or "
            "wrong aggregation results in production."
        ),
    },
    "REVIEW_REQUIRED": {
        "severity": "MEDIUM",
        "recommendation": (
            "Assign a subject matter expert to clarify the ambiguous logic before finalising "
            "the conversion. Document the interpretation chosen in the sign-off notes so the "
            "decision is auditable."
        ),
    },
    "CLASSIFICATION_MISMATCH": {
        "severity": "MEDIUM",
        "recommendation": (
            "Review the complexity tier manually. Misclassification may result in the wrong "
            "target stack being assigned (e.g., Python/Pandas selected for a mapping that "
            "processes millions of rows and should use PySpark)."
        ),
    },
    "DEAD_LOGIC": {
        "severity": "LOW",
        "recommendation": (
            "Confirm with the business owner whether this transformation is intentional. "
            "If confirmed unused, remove it to reduce code complexity and improve readability "
            "in the converted output. It adds no value to the data flow."
        ),
    },
    "ORPHANED_PORT": {
        "severity": "LOW",
        "recommendation": (
            "Confirm whether this port is intentionally disconnected (e.g. a placeholder or "
            "legacy field). If it serves no purpose, remove it from the mapping to reduce "
            "dead code and simplify the converted output."
        ),
    },
    "DOCUMENTATION_TRUNCATED": {
        "severity": "HIGH",
        "recommendation": (
            "The documentation was cut off by the AI token limit before all transformations "
            "were written. Any 'not found in documentation' failures below are caused by this "
            "truncation — they do NOT indicate missing logic in your Informatica mapping. "
            "Re-run Step 3 to regenerate the documentation. If truncation persists, contact "
            "your admin to increase the token budget for this complexity tier."
        ),
    },
}


def _make_flag(
    flag_type: str,
    location: str,
    description: str,
    blocking: bool,
    severity: str = None,
    recommendation: str = None,
    auto_fix_suggestion: str = None,
) -> VerificationFlag:
    """Create a VerificationFlag, auto-populating severity/recommendation from FLAG_META."""
    meta = FLAG_META.get(flag_type, {})
    return VerificationFlag(
        flag_type=flag_type,
        location=location,
        description=description,
        blocking=blocking,
        severity=severity or meta.get("severity", "MEDIUM"),
        recommendation=recommendation or meta.get("recommendation", "Review this flag with your team before proceeding."),
        auto_fix_suggestion=auto_fix_suggestion,
    )


async def verify(
    parse_report: ParseReport,
    complexity: ComplexityReport,
    documentation_md: str,
    graph: dict,
    session_parse_report: Optional[SessionParseReport] = None,
) -> VerificationReport:
    """Run all verification checks and return a complete VerificationReport."""

    completeness_checks: list[CheckResult] = []
    accuracy_checks: list[CheckResult] = []
    self_checks: list[CheckResult] = []
    flags: list[VerificationFlag] = []

    mapping_name = parse_report.mapping_names[0] if parse_report.mapping_names else "unknown"

    # ─────────────────────────────────────────
    # TRUNCATION FLAG
    # If the documentation agent hit the token limit, inject one prominent
    # flag so the reviewer is aware. We do NOT run doc-completeness string
    # matching — truncation causes cascading false failures and the reviewer
    # can already see the truncation banner on the Step 3 card in the UI.
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
    # Verify the parsed graph is internally consistent and ready for conversion.
    # These checks are against the graph — not the documentation text.
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
    # in CONNECTOR elements — they always connect through a Source Qualifier (SQ_*).
    # We check: (a) direct match (non-standard), (b) SQ_{name} is in the flow,
    # (c) any connected SQ whose name contains the source name (handles abbreviations).
    sq_connected = {
        t["name"]
        for m in graph.get("mappings", [])
        for t in m.get("transformations", [])
        if t.get("type") == "Source Qualifier" and t["name"] in connected_instances
    }
    for src in graph.get("sources", []):
        src_name = src["name"]
        has_out = (
            any(c.get("from_instance") == src_name for c in all_connectors)   # direct
            or f"SQ_{src_name}" in sq_connected                                 # standard SQ naming
            or any(src_name in sq_name for sq_name in sq_connected)             # partial match
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
            import re as _re
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
    # QUALITATIVE FLAGS — Claude (graph-based)
    # Claude reviews the mapping graph directly for logic risks, hardcoded
    # values, high-risk patterns, and ambiguous logic.  It no longer reads
    # the documentation — that is human-facing and reviewed visually at Gate 1.
    # ─────────────────────────────────────────

    claude_flags = await _run_claude_quality_checks(
        graph, mapping_name, expr_input_ports,
        tier=complexity.tier,
    )
    # Post-filter: suppress any DEAD_LOGIC flags Claude raised for ports we know are
    # expression-input-only — they are NOT dead, they feed derivations within the same transform.
    def _is_expr_input_flag(f: VerificationFlag) -> bool:
        if f.flag_type != "DEAD_LOGIC":
            return False
        return any(eip.split(".")[-1] in f.location for eip in expr_input_ports)

    flags.extend(f for f in claude_flags if not _is_expr_input_flag(f))

    # Build accuracy checks from Claude graph review
    accuracy_checks.append(CheckResult(
        name="No high-risk logic patterns detected (Claude graph review)",
        passed=all(f.flag_type not in ("HIGH_RISK", "INCOMPLETE_LOGIC") for f in claude_flags),
        detail="See flags section for details" if any(f.flag_type in ("HIGH_RISK", "INCOMPLETE_LOGIC") for f in claude_flags) else None
    ))
    accuracy_checks.append(CheckResult(
        name="No hardcoded environment values in expressions (Claude graph review)",
        passed=all(f.flag_type != "ENVIRONMENT_SPECIFIC_VALUE" for f in claude_flags),
        detail="See flags section for details" if any(f.flag_type == "ENVIRONMENT_SPECIFIC_VALUE" for f in claude_flags) else None
    ))

    # ─────────────────────────────────────────
    # Build final report
    # ─────────────────────────────────────────

    all_checks = completeness_checks + accuracy_checks + self_checks
    total_passed = sum(1 for c in all_checks if c.passed)
    total_failed = sum(1 for c in all_checks if not c.passed)
    blocking_flags = [f for f in flags if f.blocking]
    conversion_blocked = len(blocking_flags) > 0

    if conversion_blocked or total_failed > 0:
        overall_status = "REQUIRES_REMEDIATION"
        recommendation = "REQUIRES REMEDIATION — resolve all blocking issues and failed checks before conversion"
    else:
        overall_status = "APPROVED_FOR_CONVERSION"
        recommendation = "APPROVED FOR CONVERSION — all checks passed, proceed to Step 5 human review"

    return VerificationReport(
        mapping_name=mapping_name,
        complexity_tier=complexity.tier,
        overall_status=overall_status,
        completeness_checks=completeness_checks,
        accuracy_checks=accuracy_checks,
        self_checks=self_checks,
        flags=flags,
        total_checks=len(all_checks),
        total_passed=total_passed,
        total_failed=total_failed,
        total_flags=len(flags),
        conversion_blocked=conversion_blocked,
        blocked_reasons=[f.description for f in blocking_flags],
        recommendation=recommendation,
    )


def _build_graph_summary(graph: dict) -> str:
    """Build a compact, risk-focused summary of the graph for Claude quality review.

    Extracts expressions, SQL overrides, filter conditions, join conditions, and
    connector topology — everything Claude needs to spot conversion risks without
    the verbosity of the full JSON (which can exceed 80k chars).
    """
    lines: list[str] = []

    sources = graph.get("sources", [])
    targets = graph.get("targets", [])
    lines.append(f"Sources ({len(sources)}): {', '.join(s['name'] for s in sources)}")
    lines.append(f"Targets ({len(targets)}): {', '.join(t['name'] for t in targets)}")

    for m in graph.get("mappings", []):
        lines.append(f"\nMapping: {m.get('name', 'unknown')}")
        for t in m.get("transformations", []):
            lines.append(f"\n  [{t['type']}] {t['name']}")

            # Expressions
            for expr in t.get("expressions", []):
                e = expr.get("expression", "")
                if e and e != expr.get("port", ""):  # skip trivial pass-throughs
                    lines.append(f"    expr  {expr['port']} = {e[:300]}")

            # SQL / filter / join / lookup conditions
            for attr_key in ("sql_override", "filter_condition", "join_condition",
                             "lookup_condition", "pre_sql", "post_sql"):
                val = t.get(attr_key) or t.get("attributes", {}).get(attr_key, "")
                if val:
                    lines.append(f"    {attr_key}: {str(val)[:300]}")

            # Port list (names + types only, for connectivity context)
            port_names = [
                f"{p['name']}({'I' if 'INPUT' in p.get('porttype','') else ''}"
                f"{'O' if 'OUTPUT' in p.get('porttype','') else ''})"
                for p in t.get("ports", [])
            ]
            if port_names:
                lines.append(f"    ports: {', '.join(port_names[:20])}"
                             + (" ..." if len(port_names) > 20 else ""))

        # Connector summary (from → to)
        connectors = m.get("connectors", [])
        if connectors:
            lines.append(f"\n  Connectors ({len(connectors)}):")
            for c in connectors[:60]:  # cap at 60 to keep size manageable
                lines.append(f"    {c.get('from_instance')}.{c.get('from_field')} "
                             f"→ {c.get('to_instance')}.{c.get('to_field')}")
            if len(connectors) > 60:
                lines.append(f"    ... and {len(connectors) - 60} more connectors")

    summary = "\n".join(lines)
    # Hard cap — if still very large, truncate gracefully
    if len(summary) > 20_000:
        summary = summary[:20_000] + "\n... [graph summary truncated for length]"
    return summary


async def _run_claude_quality_checks(
    graph: dict,
    mapping_name: str,
    expr_input_ports: set[str] | None = None,
    tier: ComplexityTier = ComplexityTier.MEDIUM,
) -> list[VerificationFlag]:
    """Ask Claude to identify qualitative risks in the mapping graph.

    We review the graph — not the documentation.  The documentation is human-facing
    and is reviewed visually by the reviewer at Gate 1.  This call is about finding
    conversion risks: hardcoded values, high-risk logic, ambiguous expressions, dead
    logic, and incomplete conditionals — all detectable from the raw graph data.
    """
    client = anthropic.AsyncAnthropic(api_key=_cfg.anthropic_api_key)

    expr_input_note = ""
    if expr_input_ports:
        port_list = ", ".join(sorted(expr_input_ports))
        expr_input_note = f"""
IMPORTANT — the following ports are INPUT/OUTPUT passthroughs that feed expressions within the
same transformation but are NOT wired to a downstream connector. They are NOT dead logic —
they are expression inputs whose derived counterparts carry the value forward. Do NOT flag
these as DEAD_LOGIC:
{port_list}
"""

    # Build a compact graph summary for Claude — focus on expressions, SQL, and connectors.
    # Full graph JSON can be very large; we extract only what's needed for risk analysis.
    graph_summary = _build_graph_summary(graph)

    prompt = f"""You are a senior data engineer reviewing an Informatica PowerCenter mapping called '{mapping_name}' before automated conversion to dbt/PySpark.

Review the mapping graph below and identify ONLY real conversion risks — do not invent problems.
{expr_input_note}
Look for:
1. REVIEW_REQUIRED — logic that is unclear, ambiguous, or open to multiple interpretations
2. DEAD_LOGIC — transformation or port that has no effect on output data (exclude expression-input ports listed above)
3. ENVIRONMENT_SPECIFIC_VALUE — hardcoded connection strings, server names, schema names, file paths, or IP addresses in expressions or SQL overrides
4. HIGH_RISK — logic that is financially sensitive, performs updates/deletes, or processes PII
5. INCOMPLETE_LOGIC — IIF/DECODE/conditional expression that appears to be missing an ELSE branch or default case
6. LINEAGE_GAP — a target field whose source cannot be determined from the graph connectors and expressions

For each issue found, respond with a JSON array. Each item:
{{
  "flag_type": "one of the types above",
  "location": "transformation name and port/field if applicable",
  "description": "specific description of the issue found in the graph",
  "blocking": false,
  "severity": "HIGH or MEDIUM or LOW",
  "recommendation": "one sentence describing the specific action the reviewer should take",
  "auto_fix_suggestion": "A concrete instruction for the code generation prompt (e.g. 'Move the hardcoded value \\"PROD_DB\\" in SQ_ORDERS into a config variable DB_CONNECTION_STRING.'). Set to null if human judgement is needed."
}}

If no issues found, return: []

Mapping graph to review:
---
{graph_summary}
---

Respond with ONLY the JSON array. No other text."""

    try:
        import asyncio as _asyncio
        from .retry import claude_with_retry
        qc_max_tokens = _QC_MAX_TOKENS.get(tier, 4_096)
        # Hard timeout wraps the full retry sequence so a persistent outage
        # cannot leave the job stuck in 'verifying' state indefinitely.
        _VERIFY_TIMEOUT_SECS = _cfg.verify_timeout_secs
        message = await _asyncio.wait_for(
            claude_with_retry(
                lambda: client.messages.create(
                    model=MODEL,
                    max_tokens=qc_max_tokens,
                    messages=[{"role": "user", "content": prompt}],
                ),
                label="verification quality check",
            ),
            timeout=_VERIFY_TIMEOUT_SECS,
        )
        text = message.content[0].text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]

        # Try clean parse first; fall back to partial-recovery if Claude was truncated
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = _recover_truncated_json_array(text)

        flags = []
        for item in data:
            # Fill in meta defaults if Claude didn't supply them
            if "severity" not in item or not item["severity"]:
                item["severity"] = FLAG_META.get(item.get("flag_type",""), {}).get("severity", "MEDIUM")
            if "recommendation" not in item or not item["recommendation"]:
                item["recommendation"] = FLAG_META.get(item.get("flag_type",""), {}).get(
                    "recommendation", "Review this flag with your team before proceeding."
                )
            # Normalise auto_fix_suggestion — strip empty strings to None
            fix = item.get("auto_fix_suggestion") or None
            if fix and len(fix.strip()) < 10:  # too short to be a real suggestion
                fix = None
            item["auto_fix_suggestion"] = fix
            flags.append(VerificationFlag(**item))
        return flags
    except Exception as e:
        return [VerificationFlag(
            flag_type="REVIEW_REQUIRED",
            location="Verification Agent",
            description=f"Claude quality check could not complete: {str(e)}",
            blocking=False,
            severity="MEDIUM",
            recommendation="Re-run the verification step or check your ANTHROPIC_API_KEY and model settings.",
        )]


def _recover_truncated_json_array(text: str) -> list:
    """
    Extract all *complete* JSON objects from a potentially truncated JSON array.

    When Claude hits the token limit mid-response the output may look like:
        [{"flag_type": "HIGH_RISK", ...}, {"flag_type": "REVIEW_REQUIRED", "description": "Some long str
    — i.e. the last object's string is unterminated.  This function walks the text
    character-by-character and collects every successfully parsed ``{...}`` block,
    discarding only the incomplete tail.  This recovers all flags that were fully
    written before the cutoff.
    """
    objects: list = []
    depth = 0
    in_string = False
    escape_next = False
    start: int | None = None

    for i, ch in enumerate(text):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue

        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    obj = json.loads(text[start : i + 1])
                    objects.append(obj)
                except json.JSONDecodeError:
                    pass
                start = None

    return objects


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
