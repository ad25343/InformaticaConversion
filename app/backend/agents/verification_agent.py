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


# ── Helpers ──────────────────────────────────────────────────────────────────

def _port_in_location(ports: list[str], location: str) -> bool:
    """Return True if any port's field name appears in location."""
    return any(p.split(".")[-1] in location for p in ports)


def _is_no_action_dead_logic(
    f: VerificationFlag,
    expr_input_ports: list[str],
    rank_index_ports: list[str],
) -> bool:
    """
    Return True if a DEAD_LOGIC flag should be suppressed because it refers
    to a known no-action port (expression-input passthrough or RANKINDEX).
    """
    if f.flag_type != "DEAD_LOGIC":
        return False
    if _port_in_location(expr_input_ports, f.location):
        return True
    if _port_in_location(rank_index_ports, f.location):
        return True
    return False


def _detect_claude_error(claude_flags: list[VerificationFlag]) -> bool:
    """Return True if the Claude review call itself failed (not just found issues)."""
    return (
        len(claude_flags) == 1
        and claude_flags[0].flag_type == "REVIEW_REQUIRED"
        and "Claude quality check could not complete" in claude_flags[0].description
    )


def _build_check_detail(errored: bool, count: int, count_label: str) -> str | None:
    """Build the detail string for a Claude accuracy check."""
    if errored:
        return "Claude quality check could not complete — re-run verification. See flags section for details."
    if count:
        return f"{count} {count_label} flag(s) raised — see FLAGS section."
    return None


def _build_accuracy_checks(
    claude_flags: list[VerificationFlag],
) -> list[CheckResult]:
    """Build the two Claude graph-review accuracy checks."""
    claude_errored   = _detect_claude_error(claude_flags)
    high_risk_count  = sum(1 for f in claude_flags if f.flag_type in ("HIGH_RISK", "INCOMPLETE_LOGIC"))
    env_value_count  = sum(1 for f in claude_flags if f.flag_type == "ENVIRONMENT_SPECIFIC_VALUE")

    return [
        CheckResult(
            name="Claude graph review completed (high-risk pattern check)",
            passed=not claude_errored,
            detail=_build_check_detail(claude_errored, high_risk_count, "high-risk / incomplete-logic"),
        ),
        CheckResult(
            name="Claude graph review completed (environment value check)",
            passed=not claude_errored,
            detail=_build_check_detail(claude_errored, env_value_count, "hardcoded environment value"),
        ),
    ]


def _determine_overall_status(
    conversion_blocked: bool,
    total_failed: int,
) -> tuple[str, str]:
    """Return (overall_status, recommendation) based on blocking flags and failed checks."""
    if conversion_blocked or total_failed > 0:
        return (
            "REQUIRES_REMEDIATION",
            "REQUIRES REMEDIATION — resolve all blocking issues and failed checks before conversion",
        )
    return (
        "APPROVED_FOR_CONVERSION",
        "APPROVED FOR CONVERSION — all checks passed, proceed to Step 5 human review",
    )


def _first_mapping_name(parse_report: ParseReport) -> str:
    """Return first mapping name from parse report, or 'unknown'."""
    return parse_report.mapping_names[0] if parse_report.mapping_names else "unknown"


def _filter_action_flags(
    claude_flags: list[VerificationFlag],
    expr_input_ports: list[str],
    rank_index_ports: list[str],
) -> list[VerificationFlag]:
    """Return claude_flags excluding suppressed no-action DEAD_LOGIC flags."""
    return [
        f for f in claude_flags
        if not _is_no_action_dead_logic(f, expr_input_ports, rank_index_ports)
    ]


def _count_checks(all_checks: list) -> tuple[int, int]:
    """Return (total_passed, total_failed) for a list of CheckResult."""
    passed = sum(1 for c in all_checks if c.passed)
    failed = sum(1 for c in all_checks if not c.passed)
    return passed, failed


def _blocking_flags(flags: list[VerificationFlag]) -> list[VerificationFlag]:
    """Return flags that block conversion."""
    return [f for f in flags if f.blocking]


# ── Core implementation ───────────────────────────────────────────────────────

async def _verify_impl(
    parse_report: ParseReport,
    complexity: ComplexityReport,
    documentation_md: str,
    graph: dict,
    session_parse_report: Optional[SessionParseReport] = None,
) -> VerificationReport:
    """Run all verification checks and return a complete VerificationReport."""

    mapping_name = _first_mapping_name(parse_report)

    (
        completeness_checks,
        _accuracy_placeholder,
        self_checks,
        flags,
        expr_input_ports,
        rank_index_ports,
    ) = run_deterministic_checks(
        parse_report, complexity, documentation_md, graph, session_parse_report
    )

    claude_flags = await _run_claude_quality_checks(
        graph, mapping_name, expr_input_ports,
        rank_index_ports=rank_index_ports,
        tier=complexity.tier,
    )

    # Suppress DEAD_LOGIC flags for known no-action ports
    flags.extend(_filter_action_flags(claude_flags, expr_input_ports, rank_index_ports))

    accuracy_checks = _build_accuracy_checks(claude_flags)

    all_checks         = completeness_checks + accuracy_checks + self_checks
    total_passed, total_failed = _count_checks(all_checks)
    blocking_flags     = _blocking_flags(flags)
    conversion_blocked = bool(blocking_flags)

    overall_status, recommendation = _determine_overall_status(conversion_blocked, total_failed)

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
