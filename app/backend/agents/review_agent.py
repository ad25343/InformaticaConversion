"""
STEP 8 — Code Quality Review Agent
Claude cross-checks the converted code against:
  - The mapping documentation (Step 3)
  - The verification flags (Step 4)
  - The S2T field mapping (Step 2b)
  - The parse report (Step 1)

No execution needed — this is a static/qualitative review.
Produces a structured pass/fail checklist + overall recommendation.
"""
from __future__ import annotations
import json
import os
import anthropic

from ..models.schemas import (
    CodeReviewReport, CodeReviewCheck,
    ConversionOutput, ParseReport, VerificationReport,
)

MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-5-20250929")

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
    {{"name": "field_coverage",              "passed": true/false, "severity": "CRITICAL", "note": "..."}},
    {{"name": "source_filter_implemented",   "passed": true/false, "severity": "HIGH",     "note": "..."}},
    {{"name": "business_rules_implemented",  "passed": true/false, "severity": "CRITICAL", "note": "..."}},
    {{"name": "hardcoded_values_flagged",    "passed": true/false, "severity": "MEDIUM",   "note": "..."}},
    {{"name": "target_filter_implemented",   "passed": true/false, "severity": "HIGH",     "note": "..."}},
    {{"name": "transformation_chain_correct","passed": true/false, "severity": "CRITICAL", "note": "..."}},
    {{"name": "null_handling_present",       "passed": true/false, "severity": "LOW",      "note": "..."}},
    {{"name": "naming_consistency",          "passed": true/false, "severity": "MEDIUM",   "note": "..."}},
    {{"name": "no_extra_fields",             "passed": true/false, "severity": "LOW",      "note": "..."}},
    {{"name": "flags_addressed",             "passed": true/false, "severity": "HIGH",     "note": "..."}}
  ],
  "recommendation": "APPROVED" | "REVIEW_RECOMMENDED" | "REQUIRES_FIXES",
  "summary": "2-3 sentence plain-English verdict on the overall code quality."
}}

Rules for recommendation:
- APPROVED: all CRITICAL and HIGH checks pass
- REVIEW_RECOMMENDED: all CRITICAL checks pass but ≥1 HIGH fails, or code output was degraded
- REQUIRES_FIXES: any CRITICAL check fails
"""


def _format_flags(verification: dict) -> str:
    flags = verification.get("flags", [])
    if not flags:
        return "No flags raised."
    lines = []
    for f in flags:
        sev  = f.get("severity", "MEDIUM")
        ftype = f.get("flag_type", f.get("type", "?"))
        loc  = f.get("location", "")
        desc = f.get("description", "")
        blocking = "BLOCKING" if f.get("blocking") else ""
        lines.append(f"[{sev}] {ftype} @ {loc} {blocking} — {desc}")
    return "\n".join(lines)


def _format_s2t(s2t: dict) -> str:
    if not s2t:
        return "S2T mapping not available."
    summary = s2t.get("summary", {})
    records = s2t.get("records", [])
    lines = [
        f"Mapped fields: {summary.get('mapped_fields', '?')}",
        f"Unmapped target fields: {summary.get('unmapped_target_fields', '?')}",
        f"Unmapped source fields: {summary.get('unmapped_source_fields', '?')}",
        "",
        "Field mappings (source → target):",
    ]
    for r in records[:40]:   # cap at 40 rows to fit in context
        logic = f" [{r['logic']}]" if r.get("logic") else ""
        lines.append(
            f"  {r.get('source_table','?')}.{r.get('source_field','?')} "
            f"→ {r.get('target_table','?')}.{r.get('target_field','?')}"
            f" ({r.get('status','?')}){logic}"
        )
    if len(records) > 40:
        lines.append(f"  ... and {len(records)-40} more fields")
    unmapped_tgt = s2t.get("unmapped_targets", [])
    if unmapped_tgt:
        lines.append("\nUnmapped target fields (no source):")
        for u in unmapped_tgt:
            lines.append(f"  {u['target_table']}.{u['target_field']}")
    return "\n".join(lines)


def _format_code(files: dict[str, str]) -> str:
    parts = []
    for fname, content in files.items():
        # Truncate very large files
        if len(content) > 3000:
            content = content[:3000] + f"\n... [truncated — {len(content)} chars total]"
        parts.append(f"### {fname}\n```\n{content}\n```")
    return "\n\n".join(parts)


async def review(
    conversion_output: ConversionOutput,
    documentation_md: str,
    verification: dict,
    s2t: dict,
    parse_report: ParseReport,
) -> CodeReviewReport:
    client = anthropic.AsyncAnthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

    prompt = REVIEW_PROMPT.format(
        stack=conversion_output.target_stack.value,
        documentation_md=documentation_md[:12_000],
        flags_summary=_format_flags(verification),
        s2t_summary=_format_s2t(s2t),
        code_files=_format_code(conversion_output.files),
    )

    message = await client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=REVIEW_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = message.content[0].text.strip()
    # Strip markdown fences if present
    if "```json" in raw:
        raw = raw.split("```json", 1)[1].split("```")[0].strip()
    elif "```" in raw:
        raw = raw.split("```", 1)[1].split("```")[0].strip()

    data = json.loads(raw)

    checks = [CodeReviewCheck(**c) for c in data.get("checks", [])]
    total_passed = sum(1 for c in checks if c.passed)
    total_failed = len(checks) - total_passed

    recommendation = data.get("recommendation", "REVIEW_RECOMMENDED")
    # Override: if conversion was degraded, cap at REVIEW_RECOMMENDED
    if not conversion_output.parse_ok and recommendation == "APPROVED":
        recommendation = "REVIEW_RECOMMENDED"

    return CodeReviewReport(
        mapping_name=conversion_output.mapping_name,
        target_stack=conversion_output.target_stack.value,
        checks=checks,
        total_passed=total_passed,
        total_failed=total_failed,
        recommendation=recommendation,
        summary=data.get("summary", ""),
        parse_degraded=not conversion_output.parse_ok,
    )
