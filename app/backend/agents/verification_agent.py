# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
STEP 4 — Verification Agent (thin orchestrator)
Runs ALL checks without stopping. Produces one complete Verification Report.
Deterministic checks run in Python; qualitative flags use Claude.

Each flag now carries:
  severity       — CRITICAL | HIGH | MEDIUM | LOW | INFO
  recommendation — Actionable guidance for the human reviewer

Sub-modules:
  verification/constants.py          — FLAG_META, _make_flag, helpers
  verification/deterministic_checks.py — rule-based graph/self checks
  verification/claude_checks.py      — Claude API call + prompt building
"""
from __future__ import annotations

from typing import Optional

from ..models.schemas import (
    VerificationReport, VerificationFlag, CheckResult,
    ComplexityTier, ComplexityReport, ParseReport, SessionParseReport,
)
from .base import BaseAgent

# Sub-module imports — all logic lives in the verification/ package
from .verification.constants import (
    FLAG_META, BLOCKING_FLAG_TYPES, UNSUPPORTED_TYPES,
    _QC_MAX_TOKENS, _get_unsupported_types, _get_effective_flag_meta, _make_flag,
)
from .verification.deterministic_checks import run_deterministic_checks, _infer_expected_tier
from .verification.claude_checks import _run_claude_quality_checks, _build_graph_summary


class VerificationAgent(BaseAgent):

    async def verify(
        self,
        parse_report: ParseReport,
        complexity: ComplexityReport,
        documentation_md: str,
        graph: dict,
        session_parse_report: Optional[SessionParseReport] = None,
    ) -> VerificationReport:
        """Run all verification checks and return a complete VerificationReport."""
        return await _verify_impl(parse_report, complexity, documentation_md, graph, session_parse_report)


async def _verify_impl(
    parse_report: ParseReport,
    complexity: ComplexityReport,
    documentation_md: str,
    graph: dict,
    session_parse_report: Optional[SessionParseReport] = None,
) -> VerificationReport:
    """Run all verification checks and return a complete VerificationReport."""

    mapping_name = parse_report.mapping_names[0] if parse_report.mapping_names else "unknown"

    # ─────────────────────────────────────────
    # DETERMINISTIC CHECKS (pure Python)
    # ─────────────────────────────────────────
    (
        completeness_checks,
        _accuracy_placeholder,   # empty — filled below after Claude call
        self_checks,
        flags,
        expr_input_ports,
        rank_index_ports,
    ) = run_deterministic_checks(
        parse_report, complexity, documentation_md, graph, session_parse_report
    )

    # ─────────────────────────────────────────
    # QUALITATIVE FLAGS — Claude (graph-based)
    # Claude reviews the mapping graph directly for logic risks, hardcoded
    # values, high-risk patterns, and ambiguous logic.  It no longer reads
    # the documentation — that is human-facing and reviewed visually at Gate 1.
    # ─────────────────────────────────────────
    claude_flags = await _run_claude_quality_checks(
        graph, mapping_name, expr_input_ports,
        rank_index_ports=rank_index_ports,
        tier=complexity.tier,
    )

    # Post-filter: suppress DEAD_LOGIC flags Claude raised for known no-action ports.
    #   1. Expression-input-only ports: INPUT/OUTPUT passthroughs that feed derivations
    #      within the same transformation — they are not dead, the value IS consumed.
    #   2. RANKINDEX ports on Rank transformations: the deduplication is intrinsic to
    #      the Rank; RANKINDEX never needs a downstream connection.
    def _is_no_action_flag(f: VerificationFlag) -> bool:
        if f.flag_type != "DEAD_LOGIC":
            return False
        # Expr-input suppression: check if any expr_input port name appears in the location
        if any(eip.split(".")[-1] in f.location for eip in expr_input_ports):
            return True
        # RANKINDEX suppression: check if any rank_index_port string appears in the location
        if any(rip.split(".")[-1] in f.location for rip in rank_index_ports):
            return True
        return False

    flags.extend(f for f in claude_flags if not _is_no_action_flag(f))

    # Build accuracy checks from Claude graph review.
    # These checks reflect whether the qualitative review RAN successfully — not whether
    # findings were clean.  The actual risk findings (HIGH_RISK, INCOMPLETE_LOGIC, etc.)
    # are surfaced as FLAGS with severity, description, and recommendations.  Failing a
    # check here solely because Claude found something would cause a misleading
    # "REQUIRES REMEDIATION" status on a perfectly convertible mapping.
    #
    # A check FAILS only if the Claude review call itself could not complete (API error,
    # timeout, etc.) — in which case the result is a single REVIEW_REQUIRED flag from the
    # exception handler, and the reviewer should re-run.
    accuracy_checks: list[CheckResult] = []
    claude_errored = (
        len(claude_flags) == 1
        and claude_flags[0].flag_type == "REVIEW_REQUIRED"
        and "Claude quality check could not complete" in claude_flags[0].description
    )
    high_risk_count = sum(1 for f in claude_flags if f.flag_type in ("HIGH_RISK", "INCOMPLETE_LOGIC"))
    env_value_count = sum(1 for f in claude_flags if f.flag_type == "ENVIRONMENT_SPECIFIC_VALUE")

    accuracy_checks.append(CheckResult(
        name="Claude graph review completed (high-risk pattern check)",
        passed=not claude_errored,
        detail=(
            "Claude quality check could not complete — re-run verification. "
            "See flags section for details."
        ) if claude_errored else (
            f"{high_risk_count} high-risk / incomplete-logic flag(s) raised — see FLAGS section."
            if high_risk_count else None
        )
    ))
    accuracy_checks.append(CheckResult(
        name="Claude graph review completed (environment value check)",
        passed=not claude_errored,
        detail=(
            "Claude quality check could not complete — re-run verification."
        ) if claude_errored else (
            f"{env_value_count} hardcoded environment value flag(s) raised — see FLAGS section."
            if env_value_count else None
        )
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


# Backward-compat shim — keeps orchestrator.py call sites unchanged
async def verify(
    parse_report: ParseReport,
    complexity: ComplexityReport,
    documentation_md: str,
    graph: dict,
    session_parse_report: Optional[SessionParseReport] = None,
) -> VerificationReport:
    return await VerificationAgent().verify(parse_report, complexity, documentation_md, graph, session_parse_report)
