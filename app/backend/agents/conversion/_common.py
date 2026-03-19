# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Shared imports, helpers, and module-level constants used across the conversion
sub-modules.  Nothing in here calls Claude — it is pure configuration and
utility code.
"""
from __future__ import annotations

import json
import re
import os
import anthropic

from typing import Optional
from ...models.schemas import (
    ComplexityReport, ComplexityTier, StackAssignment,
    ConversionOutput, TargetStack, ParseReport, SessionParseReport,
)
from ..classifier_agent import _build_pattern_yaml_skeleton
from .._client import make_client
from ..base import BaseAgent
from ...security_knowledge import build_security_context_block
from ...org_config_loader import (
    build_dw_audit_rules,
    get_warehouse_registry,
    get_warehouse_cred_overrides,
)
from ...config import settings as _cfg

MODEL = _cfg.claude_model

# G2: _DW_AUDIT_RULES is loaded from org_config.yaml at runtime.
_DW_AUDIT_RULES = build_dw_audit_rules()


def _load_prompt_template(stack_name: str, default: str) -> str:
    """G3: Load system prompt from app/prompts/<stack_name>_system.j2 if it exists,
    otherwise return the built-in default string."""
    try:
        from pathlib import Path
        import re as _re
        prompt_path = Path(__file__).parent.parent.parent.parent / "prompts" / f"{stack_name}_system.j2"
        if prompt_path.exists():
            template = prompt_path.read_text()
            # Simple Jinja-style {{var}} substitution from org_config vars
            from ...org_config_loader import get_org_config
            cfg = get_org_config()
            prompt_vars = cfg.get("conversion_prompts", {}).get(stack_name, {}).get("vars", {})
            for k, v in prompt_vars.items():
                template = template.replace("{{" + k + "}}", str(v))
            return template + ("\n" + _DW_AUDIT_RULES if _DW_AUDIT_RULES else "")
    except Exception:
        pass
    return default


# ─────────────────────────────────────────────────────────────────────────────
# Shared conversion prompt template (used by _dispatch.py)
# ─────────────────────────────────────────────────────────────────────────────

CONVERSION_PROMPT = """Convert the Informatica mapping documented below to {stack}.

{security_context}
## Stack Assignment Rationale
{rationale}
{approved_fixes_section}{flag_handling_section}{manifest_override_section}
## Full Mapping Documentation (your source of truth)
{documentation_md}

## Conversion Requirements
- Follow the documented logic EXACTLY
- Every business rule from the docs → inline comment in the code
- All hardcoded env-specific values → config dict / config file
- Structured logging at: job start, after each major transformation, job end (with row counts)
- Reject/error handling as documented
- Where a Reviewer-Approved Fix is listed above, apply it precisely as described
- Where a Verification Flag Handling rule is listed above, apply it — do NOT skip the transformation

Output complete, production-ready code.

Use this EXACT file delimiter format — do NOT use JSON, markdown code blocks, or any other wrapper:

<<<BEGIN_FILE: path/to/filename.ext>>>
<complete file contents here, raw — no escaping needed>
<<<END_FILE>>>

<<<BEGIN_FILE: path/to/another_file.ext>>>
<complete file contents here>
<<<END_FILE>>>

<<<NOTES>>>
Any conversion decisions or warnings, one per line.
<<<END_NOTES>>>

Rules for the delimiter format:
- The <<<BEGIN_FILE: ...>>> and <<<END_FILE>>> markers must be on their own lines
- Write file contents exactly as they would appear on disk — no escaping, no indentation of the delimiters
- Every file must have both BEGIN_FILE and END_FILE markers
- Put NOTES section at the end
"""


# ─────────────────────────────────────────────────────────────────────────────
# Prompt section builders (shared by _dispatch.py)
# ─────────────────────────────────────────────────────────────────────────────

def _build_flag_handling_section(verification_flags: list[dict]) -> str:
    """
    Build a prompt section that instructs Claude to auto-handle each verification flag.
    The tool addresses as much as possible in code; the human reviewer handles what can't be.
    Returns an empty string if there are no actionable flags.
    """
    if not verification_flags:
        return ""

    # Per-flag-type handling rules mapped to concrete code instructions
    _HANDLING_RULES: dict[str, str] = {
        "INCOMPLETE_LOGIC": (
            "The transformation has missing or incomplete logic (e.g. a Filter with no condition, "
            "a Router with an undefined group, or a conditional with no ELSE branch). "
            "Generate the transformation as a PASS-THROUGH (all records proceed). "
            "Add a prominent comment: "
            "# TODO [AUTO-FLAG]: INCOMPLETE_LOGIC — {detail}. "
            "Confirm the intended rule with the mapping owner before promoting to production."
        ),
        "ENVIRONMENT_SPECIFIC_VALUE": (
            "A hardcoded environment-specific value was found (connection string, file path, "
            "schema name, server name, rate, threshold, etc.). "
            "Move it to the config dict / config file at the top of the generated code. "
            "Never embed it inline. Add a comment: "
            "# CONFIG: {detail}"
        ),
        "HIGH_RISK": (
            "A high-risk logic pattern was detected (complex conditional, multi-branch routing, "
            "hardcoded business constant, potential data loss path, etc.). "
            "Implement the logic as documented. "
            "Add an assertion or row-count check immediately after the transformation. "
            "Add a comment: # HIGH-RISK [AUTO-FLAG]: {detail} — validate output with UAT."
        ),
        "LINEAGE_GAP": (
            "A target field could not be traced to a source. "
            "Set the field to None / NULL with a comment: "
            "# TODO [AUTO-FLAG]: LINEAGE GAP — {detail}. Trace manually in the Informatica mapping."
        ),
        "DEAD_LOGIC": (
            "A transformation is isolated from the data flow (no inputs or outputs). "
            "Comment it out entirely with: "
            "# DEAD LOGIC [AUTO-FLAG]: {detail} — confirm with mapping owner whether to remove."
        ),
        "REVIEW_REQUIRED": (
            "Logic is ambiguous or unclear from the documentation. "
            "Implement a best-effort interpretation based on field names and context. "
            "Add a comment: # TODO [AUTO-FLAG]: REVIEW REQUIRED — {detail}. "
            "Confirm interpretation with the mapping owner."
        ),
        "ORPHANED_PORT": (
            "A port has no connections. Skip it in the converted code. "
            "Add a comment: # ORPHANED PORT [AUTO-FLAG]: {detail}"
        ),
        "UNRESOLVED_PARAMETER": (
            "A parameter has no resolved value. "
            "Add it to the config dict with a placeholder: PARAM_NAME = '<fill_in>' "
            "and reference it from there. Never hardcode the parameter inline. "
            "Add a comment: # UNRESOLVED PARAM [AUTO-FLAG]: {detail}"
        ),
        "UNRESOLVED_VARIABLE": (
            "A $$VARIABLE has no resolved value. "
            "Add it to the config dict with a placeholder and reference it. "
            "Add a comment: # UNRESOLVED VARIABLE [AUTO-FLAG]: {detail}"
        ),
        "UNSUPPORTED_TRANSFORMATION": (
            "This transformation type cannot be automatically converted. "
            "Generate a clearly-marked stub with: "
            "# TODO [MANUAL REQUIRED]: UNSUPPORTED TRANSFORMATION — {detail}. "
            "Leave the stub in place so the engineer knows exactly what to implement."
        ),
    }

    lines: list[str] = []
    seen: set[str] = set()

    for flag in verification_flags:
        flag_type = flag.get("flag_type", "")
        location  = flag.get("location", "")
        detail    = flag.get("description", flag.get("detail", ""))
        rule      = _HANDLING_RULES.get(flag_type)
        if not rule:
            continue  # INFO/DOCUMENTATION_TRUNCATED flags don't need code handling
        key = f"{flag_type}::{location}"
        if key in seen:
            continue
        seen.add(key)

        instruction = rule.replace("{detail}", detail or flag_type)
        lines.append(f"- [{flag_type}] at {location or 'mapping level'}:\n  {instruction}")

    if not lines:
        return ""

    return (
        "\n## Verification Flag Auto-Handling — Apply These Rules During Conversion\n"
        "The verification step found the following issues. The tool will handle each one "
        "in code rather than blocking the conversion. Apply every rule below exactly. "
        "Do NOT skip any flagged transformation — generate code (or a clearly-marked stub) "
        "for every item:\n\n"
        + "\n\n".join(lines)
        + "\n\n"
    )


def _build_manifest_override_section(overrides: list[dict]) -> str:
    """
    Build a prompt section listing reviewer-confirmed overrides from the manifest xlsx.
    These take precedence over anything the tool inferred from naming patterns.
    Returns empty string if no overrides were supplied.
    """
    if not overrides:
        return ""

    lines: list[str] = []
    for o in overrides:
        location  = o.get("location", "")
        itype     = o.get("item_type", "")
        override  = o.get("reviewer_override", "").strip()
        notes     = o.get("notes", "")
        if not override or override.upper() in ("", "N/A"):
            continue
        note_str = f" (Note: {notes})" if notes else ""
        lines.append(f"- [{itype}] {location} → Reviewer confirmed: {override}{note_str}")

    if not lines:
        return ""

    return (
        "\n## Reviewer-Confirmed Manifest Overrides — These Take Precedence\n"
        "A human reviewer examined the pre-conversion manifest and supplied the following "
        "corrections. Use these INSTEAD OF any tool-inferred connection or determination "
        "for the listed items. Do not second-guess these — they are authoritative:\n\n"
        + "\n".join(lines)
        + "\n\n"
    )


def _validate_conversion_files(
    files: dict[str, str],
    stack,
    _cache: dict | None = None,
) -> list[str]:
    """
    GAP #7 — Non-blocking content validation of Claude-generated files.
    Returns a list of warning strings (empty = all clean).

    v2.6.0 scale improvements:
    - Optional _cache dict keyed by hash(content) → issues list.  Re-used
      across remediation rounds so unchanged files are never re-validated.
    - TODO ratio check now skips files > 150 KB (pathological edge case).
    - dbt SELECT check uses content[:5000] instead of full content.lower().
    - SparkSession check already scoped to content[:2000] (unchanged).
    """
    import ast
    import hashlib
    import re as _re

    if _cache is None:
        _cache = {}

    issues: list[str] = []

    for fname, content in files.items():
        # ── Cache check: skip re-validating content we've already seen ────
        _key = hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()
        if _key in _cache:
            issues.extend(_cache[_key])
            continue

        file_issues: list[str] = []
        stripped = content.strip()

        # 1. Empty file
        if not stripped:
            file_issues.append(
                f"VALIDATION: '{fname}' is empty — Claude may have failed to generate content."
            )
            _cache[_key] = file_issues
            issues.extend(file_issues)
            continue

        # 2. Placeholder-only file — skip for very large files (> 150 KB)
        if len(stripped) <= 150_000:
            lines = [l.strip() for l in stripped.splitlines() if l.strip()]
            code_lines = [
                l for l in lines
                if l and not l.startswith("#") and not l.startswith('"""') and not l.startswith("'''")
            ]
            todo_lines = [l for l in lines if "TODO" in l.upper() or "FIXME" in l.upper() or "STUB" in l.upper()]
            if code_lines and len(todo_lines) / max(len(code_lines), 1) > 0.6:
                file_issues.append(
                    f"VALIDATION: '{fname}' is mostly TODO stubs ({len(todo_lines)} TODO lines vs "
                    f"{len(code_lines)} code lines) — Claude may not have had enough context to fully convert."
                )

        # 3. Python syntax check (size-guarded at 500 KB)
        if fname.endswith((".py", ".pyx")) and len(stripped) < 500_000:
            try:
                ast.parse(stripped)
            except SyntaxError as e:
                file_issues.append(
                    f"VALIDATION: '{fname}' has a Python syntax error at line {e.lineno}: {e.msg}. "
                    "The file was saved but will not run without fixing this."
                )

        # 4. PySpark jobs should reference SparkSession (scoped to first 2 KB)
        if stack in (TargetStack.PYSPARK, TargetStack.HYBRID) and fname.endswith(".py"):
            if "SparkSession" not in content and "spark" not in content.lower()[:2000]:
                file_issues.append(
                    f"VALIDATION: '{fname}' appears to be a PySpark job but contains no "
                    "SparkSession reference — verify the conversion output is complete."
                )

        # 5. dbt models should have a SELECT or {{ ref( (scoped to first 5 KB)
        if stack == TargetStack.DBT and fname.endswith(".sql"):
            head = content[:5000].lower()
            if "select" not in head and "{{" not in content[:5000]:
                file_issues.append(
                    f"VALIDATION: '{fname}' appears to be a dbt model but contains no SELECT or "
                    "Jinja block — the model may be empty or malformed."
                )

        # 6. run_pipeline.py must reference subprocess and dbt
        if fname == "run_pipeline.py":
            if "subprocess" not in content:
                file_issues.append(
                    "VALIDATION: 'run_pipeline.py' does not reference subprocess — "
                    "orchestration wrapper may be incomplete."
                )
            if "dbt" not in content:
                file_issues.append(
                    "VALIDATION: 'run_pipeline.py' does not reference dbt — "
                    "orchestration wrapper may be incomplete."
                )

        # 7. Scale anti-pattern scan (INFO — non-blocking)
        _SCALE_PATTERNS = [
            (r'\.collect\(\)',         "collect() called — may OOM on large DataFrames"),
            (r'pd\.read_csv\([^)]+\)', "pd.read_csv() without chunksize — check for large sources"),
            (r'\.iterrows\(\)',        "iterrows() found — use vectorised operations for large data"),
        ]
        for pattern, msg in _SCALE_PATTERNS:
            if _re.search(pattern, content):
                # Only warn for pd.read_csv if chunksize is absent from the file
                if "read_csv" in pattern and "chunksize" in content:
                    continue
                file_issues.append(f"SCALE: '{fname}': {msg}")

        _cache[_key] = file_issues
        issues.extend(file_issues)

    return issues
