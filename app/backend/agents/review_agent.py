# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
STEP 10 — Code Quality Review Agent (v2.5.0: Stage C Performance Review added)

Three-stage review:

Stage A — Logic Equivalence (v1.3):
  Goes back to the original Informatica XML as ground truth and verifies
  rule-by-rule that the generated code correctly implements every
  transformation, expression, filter, join, and null-handling pattern.
  Produces per-rule verdicts: VERIFIED / NEEDS_REVIEW / MISMATCH.

Stage B — Code Quality (existing):
  Claude cross-checks the converted code against:
    - The mapping documentation (Step 3)
    - The verification flags (Step 4)
    - The S2T field mapping (Step 2)
    - The parse report (Step 1)
  Produces a structured pass/fail checklist + overall recommendation.

Stage C — Performance Review (v2.5.0):
  Advisory-only scan for anti-patterns that cause correctness problems or
  extreme slowness at millions-of-rows scale. Runs after Stage B (never
  blocks on logic issues). Results stored under "perf_review" in state_json.

No execution needed — all stages are static reviews.
"""
from __future__ import annotations
import json
import os
import anthropic

from ..models.schemas import (
    CodeReviewReport, CodeReviewCheck,
    LogicEquivalenceCheck, LogicEquivalenceReport,
    PerfReviewCheck, PerfReviewReport,
    ReuseCandidate, ReuseAnalysisReport,
    ConversionOutput, ParseReport, VerificationReport,
)
from ._client import make_client, call_claude_with_retry
from .base import BaseAgent

from ..config import settings as _cfg
MODEL = _cfg.claude_model

# ── Stage A — Logic Equivalence System & Prompt ──────────────────────────────

EQUIVALENCE_SYSTEM = """You are a senior data engineering auditor performing a logic equivalence check.
Your job is to verify that converted code correctly implements the original Informatica mapping logic
by comparing the generated code directly against the original XML — not against any documentation.
You are checking Claude's own work for errors. Be sceptical and precise.
Flag any discrepancy, no matter how small.
"""

EQUIVALENCE_PROMPT = """Perform a rule-by-rule logic equivalence check.

Compare the GENERATED {stack} CODE against the ORIGINAL INFORMATICA XML.
Do NOT use the documentation as an intermediary — go directly from XML to code.

## Original Informatica XML (ground truth)
{xml_content}

## Source-to-Target Field Mapping (S2T — structured reference)
{s2t_summary}

## Generated {stack} Code Files
{code_files}

---

For every verifiable rule you can extract from the XML, produce one check entry.
Cover all of these rule types where present:
- FIELD       : Each source-to-target field mapping — is the field present and correctly derived?
- EXPRESSION  : Each Expression transformation port formula — is the equivalent logic in the code?
- FILTER      : Each Filter or Source Qualifier filter condition — correctly implemented?
- JOIN        : Each Joiner — correct join type (INNER/LEFT/RIGHT/FULL) and join condition?
- NULL_HANDLING: Each null-handling pattern (ISNULL, NVL, default values) — preserved?
- CHAIN       : Overall transformation sequence — does the code follow the same logical order?

Verdict rules per check:
- VERIFIED      : You are confident the generated code correctly implements this rule.
- NEEDS_REVIEW  : The logic appears equivalent but involves a non-trivial translation
                  (e.g. Informatica IIF → SQL CASE WHEN) that requires human confirmation.
- MISMATCH      : The generated code does not implement this rule correctly, or the rule
                  is absent from the generated code entirely.

Return ONLY this JSON (no markdown, no explanation outside it):
{{
  "checks": [
    {{
      "rule_type": "FIELD|EXPRESSION|FILTER|JOIN|NULL_HANDLING|CHAIN",
      "rule_id": "short identifier (e.g. field name, expression name, join name)",
      "verdict": "VERIFIED|NEEDS_REVIEW|MISMATCH",
      "xml_rule": "The original rule verbatim or summarised from the XML",
      "generated_impl": "What the generated code does for this rule, or NOT FOUND",
      "note": "Brief explanation of verdict — required for NEEDS_REVIEW and MISMATCH"
    }}
  ],
  "summary": "2-3 sentence plain-English summary of equivalence findings."
}}

Be thorough — a check per field, per expression, per filter, per join.
If the XML is very large, cover all CRITICAL rules (field mappings, joins, filters) fully,
then sample expressions (cover at least 5 or all if fewer than 5 exist).
"""

# ── Stage B — Code Quality System & Prompt ───────────────────────────────────

REVIEW_SYSTEM = """You are a senior data engineering code reviewer.
Your job is to verify that converted code correctly implements the original Informatica mapping logic.
You review code STATICALLY — no execution environment available.
Be precise, concrete, and focus on correctness over style.
"""

REVIEW_PROMPT = """Review the converted {stack} code below against the original mapping documentation and field mapping.

## Original Mapping Documentation
{documentation_md}

## Verification Flags from Step 4 (issues identified in original mapping)
{flags_summary}

## Source-to-Target Field Mapping (S2T)
{s2t_summary}

## Converted Code Files
{code_files}

---

Perform these specific checks and return a JSON object:

1. **field_coverage** — Are all mapped target fields present in the final output model/script?
2. **source_filter_implemented** — Are source-level filter conditions (e.g. STATUS != 'CANCELLED') implemented?
3. **business_rules_implemented** — Are all documented business rules/expressions present in the code?
4. **hardcoded_values_flagged** — Are environment-specific hardcoded values (thresholds, rates, connection strings) externalized or at least commented?
5. **target_filter_implemented** — Are target-level filter conditions (e.g. order_amount > 0) implemented?
6. **transformation_chain_correct** — Does the transformation layer sequence (staging → intermediate → mart or equivalent) match the documented pipeline?
7. **null_handling_present** — Are nullable fields handled appropriately (COALESCE, IS NULL checks, etc.)?
8. **naming_consistency** — Do output field names match the documented target schema (allowing for reasonable snake_case conversions)?
9. **no_extra_fields** — Does the final output avoid introducing undocumented extra fields?
10. **flags_addressed** — Are CRITICAL/HIGH severity flags from verification acknowledged or handled in the code?

Return ONLY this JSON (no markdown, no explanation outside it):
{{
  "checks": [
    {{"name": "field_coverage",              "passed": true, "severity": "CRITICAL", "note": "..."}},
    {{"name": "source_filter_implemented",   "passed": true, "severity": "HIGH",     "note": "..."}},
    {{"name": "business_rules_implemented",  "passed": true, "severity": "CRITICAL", "note": "..."}},
    {{"name": "hardcoded_values_flagged",    "passed": true, "severity": "MEDIUM",   "note": "..."}},
    {{"name": "target_filter_implemented",   "passed": true, "severity": "HIGH",     "note": "..."}},
    {{"name": "transformation_chain_correct","passed": true, "severity": "CRITICAL", "note": "..."}},
    {{"name": "null_handling_present",       "passed": true, "severity": "LOW",      "note": "..."}},
    {{"name": "naming_consistency",          "passed": true, "severity": "MEDIUM",   "note": "..."}},
    {{"name": "no_extra_fields",             "passed": true, "severity": "LOW",      "note": "..."}},
    {{"name": "flags_addressed",             "passed": true, "severity": "HIGH",     "note": "..."}}
  ],
  "recommendation": "APPROVED",
  "summary": "2-3 sentence plain-English verdict on the overall code quality."
}}

Rules for recommendation:
- APPROVED: all CRITICAL and HIGH checks pass
- REVIEW_RECOMMENDED: all CRITICAL checks pass but ≥1 HIGH fails, or code output was degraded
- REQUIRES_FIXES: any CRITICAL check fails
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _format_flags(verification: dict) -> str:
    flags = verification.get("flags", [])
    if not flags:
        return "No flags raised."
    lines = []
    for f in flags:
        sev      = f.get("severity", "MEDIUM")
        ftype    = f.get("flag_type", f.get("type", "?"))
        loc      = f.get("location", "")
        desc     = f.get("description", "")
        blocking = "BLOCKING" if f.get("blocking") else ""
        lines.append(f"[{sev}] {ftype} @ {loc} {blocking} — {desc}")
    return "\n".join(lines)


def _format_s2t_record(r: dict) -> str:
    """Format a single S2T record as a mapping line."""
    logic = f" [{r['logic']}]" if r.get("logic") else ""
    return (
        f"  {r.get('source_table','?')}.{r.get('source_field','?')} "
        f"\u2192 {r.get('target_table','?')}.{r.get('target_field','?')}"
        f" ({r.get('status','?')}){logic}"
    )


def _format_s2t_summary_lines(summary: dict, records: list) -> list[str]:
    """Build the header lines for the S2T summary block."""
    lines = [
        f"Mapped fields: {summary.get('mapped_fields', '?')}",
        f"Unmapped target fields: {summary.get('unmapped_target_fields', '?')}",
        f"Unmapped source fields: {summary.get('unmapped_source_fields', '?')}",
        "",
        "Field mappings (source \u2192 target):",
    ]
    lines.extend(_format_s2t_record(r) for r in records[:40])
    if len(records) > 40:
        lines.append(f"  ... and {len(records)-40} more fields")
    return lines


def _format_s2t(s2t: dict) -> str:
    if not s2t:
        return "S2T mapping not available."
    summary     = s2t.get("summary", {})
    records     = s2t.get("records", [])
    lines       = _format_s2t_summary_lines(summary, records)
    unmapped_tgt = s2t.get("unmapped_targets", [])
    if unmapped_tgt:
        lines.append("\nUnmapped target fields (no source):")
        lines.extend(f"  {u['target_table']}.{u['target_field']}" for u in unmapped_tgt)
    return "\n".join(lines)


def _format_code(files: dict[str, str]) -> str:
    parts = []
    for fname, content in files.items():
        # Truncate very large files
        if len(content) > 3000:
            content = content[:3000] + f"\n... [truncated — {len(content)} chars total]"
        parts.append(f"### {fname}\n```\n{content}\n```")
    return "\n\n".join(parts)


def _parse_json(raw: str) -> dict:
    """Strip markdown fences and parse JSON."""
    raw = raw.strip()
    if "```json" in raw:
        raw = raw.split("```json", 1)[1].split("```")[0].strip()
    elif "```" in raw:
        raw = raw.split("```", 1)[1].split("```")[0].strip()
    return json.loads(raw)


# ── Stage A — Logic Equivalence ───────────────────────────────────────────────

def _truncate_xml(xml_content: str) -> str:
    """Cap XML at 10,000 chars with a truncation note if needed."""
    if len(xml_content) <= 10_000:
        return xml_content
    return (
        xml_content[:10_000]
        + f"\n... [XML truncated — {len(xml_content)} chars total; key transformations shown]"
    )


def _count_verdicts(checks: list[LogicEquivalenceCheck]) -> tuple[int, int, int]:
    """Return (verified, needs_review, mismatches) counts from a list of checks."""
    counts: dict[str, int] = {"VERIFIED": 0, "NEEDS_REVIEW": 0, "MISMATCH": 0}
    for c in checks:
        if c.verdict in counts:
            counts[c.verdict] += 1
    return counts["VERIFIED"], counts["NEEDS_REVIEW"], counts["MISMATCH"]


def _build_equivalence_report(data: dict) -> LogicEquivalenceReport:
    """Construct a LogicEquivalenceReport from the parsed Claude JSON."""
    checks                       = [LogicEquivalenceCheck(**c) for c in data.get("checks", [])]
    total                        = len(checks)
    verified, needs_review, mismatches = _count_verdicts(checks)
    coverage_pct                 = round((verified + needs_review) / total * 100, 1) if total else 0.0
    return LogicEquivalenceReport(
        total_verified=verified,
        total_needs_review=needs_review,
        total_mismatches=mismatches,
        coverage_pct=coverage_pct,
        checks=checks,
        summary=data.get("summary", ""),
    )


async def _run_equivalence_check(
    client: anthropic.AsyncAnthropic,
    stack: str,
    xml_content: str,
    s2t: dict,
    files: dict[str, str],
) -> LogicEquivalenceReport:
    """Call Claude with the original XML + generated code and get per-rule verdicts."""
    prompt = EQUIVALENCE_PROMPT.format(
        stack=stack,
        xml_content=_truncate_xml(xml_content),
        s2t_summary=_format_s2t(s2t),
        code_files=_format_code(files),
    )

    message = await call_claude_with_retry(
        client,
        model=MODEL,
        max_tokens=4096,
        system=EQUIVALENCE_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )

    return _build_equivalence_report(_parse_json(message.content[0].text))


# ── Stage B — Code Quality ────────────────────────────────────────────────────

async def _run_quality_check(
    client: anthropic.AsyncAnthropic,
    conversion_output: ConversionOutput,
    documentation_md: str,
    verification: dict,
    s2t: dict,
) -> tuple[list[CodeReviewCheck], str]:
    """Run the existing 10-check code quality review. Returns (checks, recommendation, summary)."""
    prompt = REVIEW_PROMPT.format(
        stack=conversion_output.target_stack.value,
        documentation_md=documentation_md[:12_000],
        flags_summary=_format_flags(verification),
        s2t_summary=_format_s2t(s2t),
        code_files=_format_code(conversion_output.files),
    )

    message = await call_claude_with_retry(
        client,
        model=MODEL,
        max_tokens=4096,
        system=REVIEW_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )

    data   = _parse_json(message.content[0].text)
    checks = [CodeReviewCheck(**c) for c in data.get("checks", [])]
    return checks, data.get("recommendation", "REVIEW_RECOMMENDED"), data.get("summary", "")


# ── Stage C — Performance Review ─────────────────────────────────────────────

PERF_REVIEW_SYSTEM = """You are a performance-focused data engineering reviewer.
Your job is to identify anti-patterns in generated data pipeline code that will cause
correctness problems or extreme slowness at millions-of-rows scale.
Be specific — cite the exact line or code pattern you found."""

PERF_REVIEW_PROMPT = """Review the generated {stack} code below for performance anti-patterns
at scale (assume the source data may contain millions of rows).

## Generated Code Files
{code_files}

## Stack
{stack}

Check for these anti-patterns (only flag ones that are actually present):

PySpark:
- collect() / toPandas() called on a large DataFrame (not just a .count())
- Python UDF or pandas_udf where a native Spark function exists
- No partition hint on the initial DataFrame read
- Cartesian join or join without explicit join condition
- .count() or .show() inside a loop

dbt:
- Final mart model using materialized='view' (should be incremental or table)
- Missing unique_key on an incremental model
- SELECT * in a final model
- Filter / WHERE pushed after a large join instead of before

Python/Pandas:
- pd.read_csv() without chunksize on a file source
- df.iterrows() or df.apply(axis=1) on a potentially large DataFrame
- Full DataFrame loaded into memory before any filtering

For each issue found, produce one check entry.
For clean code, return an empty checks list.

Return ONLY this JSON (no markdown):
{{
  "checks": [
    {{
      "check_id": "PERF_01",
      "stack": "{stack}",
      "anti_pattern": "short name, e.g. collect_on_large_df",
      "severity": "HIGH|MEDIUM|LOW",
      "location": "filename:line or function name",
      "detail": "what the code does and why it is a problem at scale",
      "suggestion": "concrete fix, one sentence"
    }}
  ],
  "clean": true,
  "summary": "1-2 sentence summary of performance posture."
}}"""


async def run_perf_review(
    conversion: ConversionOutput,
    stack: str,
) -> PerfReviewReport:
    """Stage C — advisory performance anti-pattern scan. Non-blocking."""
    client = make_client()
    code_files = "\n\n".join(
        f"=== {fname} ===\n{content}"
        for fname, content in conversion.files.items()
    )
    # Cap total code sent to 8000 chars to avoid blowing context
    if len(code_files) > 8000:
        code_files = code_files[:8000] + f"\n... [truncated]"

    prompt = PERF_REVIEW_PROMPT.format(stack=stack, code_files=code_files)
    msg = await call_claude_with_retry(
        client,
        model=MODEL, max_tokens=2000,
        system=PERF_REVIEW_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = _parse_json(msg.content[0].text)
    checks = [PerfReviewCheck(**c) for c in raw.get("checks", [])]
    return PerfReviewReport(
        checks=checks,
        clean=raw.get("clean", len(checks) == 0),
        summary=raw.get("summary", ""),
    )


# ── Stage D — Framework / Code Reuse Analysis ────────────────────────────────

REUSE_SYSTEM = """You are a senior data engineering architect specialising in ETL framework design.
Your job is to review freshly generated migration code and identify:
  (A) Logic that SHOULD be using the existing etl_patterns shared library but isn't — these are
      adoption gaps and are higher priority than net-new candidates.
  (B) Logic that is genuinely net-new and should be extracted into a new shared utility.

The etl_patterns library is already installed and provides the following:
  - null_safe:        coalesce(), nvl(), nvl2(), is_null()
  - string_clean:     to_upper(), to_lower(), trim(), ltrim(), rtrim(), lpad(), rpad(), substr(), normalize_string()
  - type_cast:        type_cast(value, 'date'|'integer'|'decimal'|'float'|'string'|'boolean', **fmt)
  - date_utils:       to_date(), add_to_date(), date_diff(), trunc_date(), to_char_date(), last_day(), is_date()
  - numeric_utils:    safe_round(), trunc_num(), safe_abs(), safe_mod(), ceil_num(), floor_num()
  - watermark_manager: read_watermark(), write_watermark()
  - etl_metadata:     add_etl_metadata(), metadata_columns()
  - file_lifecycle:   archive_file(), reject_path_for()
  - Pattern classes:  TruncateAndLoadPattern, IncrementalAppendPattern, UpsertPattern, Scd2Pattern,
                      LookupEnrichPattern, AggregationLoadPattern, FilterAndRoutePattern,
                      UnionConsolidatePattern, ExpressionTransformPattern, PassThroughPattern

If the generated code reimplements any of the above inline (e.g. hand-rolled null checking, manual
date arithmetic, custom numeric rounding) instead of importing from etl_patterns, flag it as an
adoption gap — not just a reuse candidate."""

REUSE_PROMPT = """Analyse the generated {stack} code below and identify:
  (A) etl_patterns ADOPTION GAPS — where the code reinvents something already in etl_patterns.
  (B) NET-NEW candidates — logic not covered by etl_patterns that should become a new shared utility.

## Generated Code Files
{code_files}

## ETL Pattern Used
{pattern}

## Mapping Documentation (excerpt)
{doc_excerpt}

---

For every finding, produce one candidate entry.

Pattern types for ADOPTION GAPS (prefix with "gap_"):
- **gap_null_safe**      : Inline IIF/ISNULL/NVL logic instead of calling coalesce() / nvl()
- **gap_string_clean**   : Inline UPPER/TRIM/LTRIM/RTRIM/SUBSTR instead of using string_clean utils
- **gap_type_cast**      : Inline type casting (TO_NUMBER, TO_CHAR) instead of type_cast()
- **gap_date_utils**     : Inline date parsing/arithmetic (TO_DATE, ADD_TO_DATE, DATE_DIFF, TRUNC date, strftime) instead of date_utils
- **gap_numeric_utils**  : Inline ROUND/TRUNC/ABS/MOD/CEIL/FLOOR numeric logic instead of numeric_utils
- **gap_watermark**      : Custom watermark read/write logic instead of read_watermark()/write_watermark()
- **gap_etl_metadata**   : Hand-coded audit columns (ETL_LOAD_DATE, ETL_BATCH_ID etc) instead of add_etl_metadata()
- **gap_file_lifecycle** : Custom file archival/rejection instead of archive_file()/reject_path_for()
- **gap_pattern_class**  : Bespoke ETL flow code when an etl_patterns pattern class handles it

Pattern types for NET-NEW candidates:
- **lookup_helper**      : Reusable lookup/join logic not covered by etl_patterns
- **expression_lib**     : Non-trivial expressions worth centralising (date math, complex conditionals)
- **schema_validation**  : Input schema assertion patterns worth standardising
- **error_routing**      : Row-level error capture / dead-letter logic
- **framework_other**    : Any other reusable pattern not listed above

Only flag candidates that are genuinely worth actioning — do NOT flag trivial one-liners.
ADOPTION GAPS (gap_*) should be flagged even if effort is LOW — they represent rework the
team can fix without building anything new.

Return ONLY this JSON (no markdown):
{{
  "candidates": [
    {{
      "candidate_id": "REUSE_01",
      "pattern_type": "gap_null_safe|gap_string_clean|gap_type_cast|gap_date_utils|gap_numeric_utils|gap_watermark|gap_etl_metadata|gap_file_lifecycle|gap_pattern_class|lookup_helper|expression_lib|schema_validation|error_routing|framework_other",
      "gap_or_new": "ADOPTION_GAP|NET_NEW",
      "location": "filename or function/model name",
      "description": "What this code does (1 sentence)",
      "reuse_rationale": "For gaps: what etl_patterns function to use instead. For net-new: why extracting reduces risk/duplication.",
      "suggested_name": "etl_patterns function to use (gaps) or proposed new function name (net-new)",
      "effort": "LOW|MEDIUM|HIGH",
      "applicable_stacks": ["pyspark", "dbt", "python"]
    }}
  ],
  "total_found": 0,
  "high_value": 0,
  "adoption_gaps": 0,
  "net_new": 0,
  "summary": "1-2 sentence overall assessment. Note whether etl_patterns is being adopted correctly."
}}

Set high_value = count of candidates where effort == "LOW".
Set adoption_gaps = count where gap_or_new == "ADOPTION_GAP".
Set net_new = count where gap_or_new == "NET_NEW"."""


async def run_reuse_analysis(
    conversion: ConversionOutput,
    documentation_md: str,
) -> ReuseAnalysisReport:
    """Stage D — identify framework reuse candidates in the generated code. Non-blocking."""
    client = make_client()
    code_files = "\n\n".join(
        f"=== {fname} ===\n{content}"
        for fname, content in conversion.files.items()
    )
    if len(code_files) > 8000:
        code_files = code_files[:8000] + "\n... [truncated]"

    prompt = REUSE_PROMPT.format(
        stack=conversion.target_stack.value,
        code_files=code_files,
        pattern=getattr(conversion, "pattern", "unknown"),
        doc_excerpt=documentation_md[:3000] if documentation_md else "(not available)",
    )
    try:
        msg = await call_claude_with_retry(
            client,
            model=MODEL, max_tokens=2500,
            system=REUSE_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = _parse_json(msg.content[0].text)
        candidates = [ReuseCandidate(**c) for c in raw.get("candidates", [])]
        return ReuseAnalysisReport(
            candidates=candidates,
            total_found=raw.get("total_found", len(candidates)),
            high_value=raw.get("high_value", sum(1 for c in candidates if c.effort == "LOW")),
            summary=raw.get("summary", ""),
        )
    except Exception as e:
        return ReuseAnalysisReport(
            candidates=[],
            total_found=0,
            high_value=0,
            summary=f"Reuse analysis could not complete: {e}. Review generated code manually for shared utility opportunities.",
        )


# ── Agent class ───────────────────────────────────────────────────────────────

class ReviewAgent(BaseAgent):

    async def review(
        self,
        conversion_output: ConversionOutput,
        documentation_md: str,
        verification: dict,
        s2t: dict,
        parse_report: ParseReport,
        xml_content: str = "",
    ) -> CodeReviewReport:
        return await _review_impl(
            conversion_output, documentation_md, verification, s2t, parse_report, xml_content,
        )


# ── Public entry point ────────────────────────────────────────────────────────

async def _stage_a_equivalence(
    client,
    conversion_output: ConversionOutput,
    xml_content: str,
    s2t: dict,
) -> "LogicEquivalenceReport | None":
    """Run Stage A logic equivalence check; returns None if xml_content is empty."""
    if not xml_content:
        return None
    try:
        return await _run_equivalence_check(
            client=client,
            stack=conversion_output.target_stack.value,
            xml_content=xml_content,
            s2t=s2t,
            files=conversion_output.files,
        )
    except Exception as e:
        return LogicEquivalenceReport(
            total_verified=0,
            total_needs_review=0,
            total_mismatches=0,
            coverage_pct=0.0,
            checks=[],
            summary=f"Logic equivalence check could not complete: {e}. Review the code manually.",
        )


async def _stage_b_quality(
    client,
    conversion_output: ConversionOutput,
    documentation_md: str,
    verification: dict,
    s2t: dict,
) -> tuple:
    """Run Stage B code quality check; returns (checks, recommendation, summary)."""
    try:
        return await _run_quality_check(
            client=client,
            conversion_output=conversion_output,
            documentation_md=documentation_md,
            verification=verification,
            s2t=s2t,
        )
    except Exception as e:
        return (
            [],
            "REVIEW_RECOMMENDED",
            f"Automated quality review could not complete: {e}. Please review the converted code manually.",
        )


async def _stage_c_perf(conversion_output: ConversionOutput) -> "PerfReviewReport":
    """Run Stage C performance review; always returns a report (non-blocking)."""
    try:
        return await run_perf_review(
            conversion=conversion_output,
            stack=conversion_output.target_stack.value,
        )
    except Exception as e:
        return PerfReviewReport(
            checks=[],
            clean=True,
            summary=f"Performance review could not complete: {e}. Review code manually for scale patterns.",
        )


def _cap_recommendation(
    recommendation: str,
    equivalence_report: "LogicEquivalenceReport | None",
    parse_ok: bool,
) -> str:
    """Cap recommendation to REVIEW_RECOMMENDED when mismatch or degraded parse."""
    has_mismatch = equivalence_report is not None and equivalence_report.total_mismatches > 0
    is_degraded  = not parse_ok
    if (has_mismatch or is_degraded) and recommendation == "APPROVED":
        return "REVIEW_RECOMMENDED"
    return recommendation


async def _review_impl(
    conversion_output: ConversionOutput,
    documentation_md: str,
    verification: dict,
    s2t: dict,
    parse_report: ParseReport,
    xml_content: str = "",
) -> CodeReviewReport:
    client = make_client()

    equivalence_report = await _stage_a_equivalence(client, conversion_output, xml_content, s2t)
    checks, recommendation, summary = await _stage_b_quality(
        client, conversion_output, documentation_md, verification, s2t,
    )
    recommendation = _cap_recommendation(recommendation, equivalence_report, conversion_output.parse_ok)
    perf_report    = await _stage_c_perf(conversion_output)
    reuse_report   = await run_reuse_analysis(conversion_output, documentation_md)

    total_passed = sum(1 for c in checks if c.passed)
    total_failed = len(checks) - total_passed

    return CodeReviewReport(
        mapping_name=conversion_output.mapping_name,
        target_stack=conversion_output.target_stack.value,
        checks=checks,
        total_passed=total_passed,
        total_failed=total_failed,
        recommendation=recommendation,
        summary=summary,
        parse_degraded=not conversion_output.parse_ok,
        equivalence_report=equivalence_report,
        perf_review=perf_report,
        reuse_analysis=reuse_report,
    )


# Backward-compat shim — keeps orchestrator.py call sites unchanged
async def review(
    conversion_output: ConversionOutput,
    documentation_md: str,
    verification: dict,
    s2t: dict,
    parse_report: ParseReport,
    xml_content: str = "",
) -> CodeReviewReport:
    return await ReviewAgent().review(
        conversion_output, documentation_md, verification, s2t, parse_report, xml_content,
    )
