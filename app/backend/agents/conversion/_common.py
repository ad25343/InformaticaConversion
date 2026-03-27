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
# etl_patterns shared-library reference block (injected into every conversion)
# ─────────────────────────────────────────────────────────────────────────────

_ETL_LIBRARY_SECTION = """
## Shared Library: etl_patterns (ALWAYS USE — do not reinvent)

The `etl_patterns` package is installed alongside this project (`pip install -e etl_patterns/`).
It provides pre-built, tested implementations of every common ETL utility.
YOU MUST import and call these functions instead of writing equivalent logic inline.

### Utility modules — import and use directly

```python
from etl_patterns.utils.null_safe      import coalesce, nvl, nvl2, is_null
from etl_patterns.utils.string_clean   import to_upper, to_lower, trim, ltrim, rtrim, \
                                               lpad, rpad, substr, normalize_string
from etl_patterns.utils.type_cast      import type_cast          # type_cast(value, 'integer'/'decimal'/'string'/..., **fmt)
from etl_patterns.utils.date_utils     import to_date, add_to_date, date_diff, trunc_date, \
                                               to_char_date, last_day
from etl_patterns.utils.numeric_utils  import safe_round, trunc_num, safe_abs, safe_mod, \
                                               ceil_num, floor_num
from etl_patterns.utils.watermark_manager import read_watermark, write_watermark
from etl_patterns.utils.etl_metadata   import add_etl_metadata, metadata_columns
from etl_patterns.utils.file_lifecycle import archive_file, reject_path_for
```

### When to use each utility

| Informatica pattern | Use this instead |
|---|---|
| `IIF(ISNULL(x), default, x)` | `coalesce(x, default)` |
| `NVL(x, default)` | `nvl(x, default)` |
| `UPPER(TRIM(x))` | `to_upper(trim(x))` or `normalize_string(x)` |
| `TO_DATE(x, 'MM/DD/YYYY')` | `to_date(x, 'MM/DD/YYYY')` |
| `ADD_TO_DATE(x, 'MM', 1)` | `add_to_date(x, 'MM', 1)` |
| `DATE_DIFF(d1, d2, 'DD')` | `date_diff(d1, d2, 'DD')` |
| `TRUNC(date, 'MM')` | `trunc_date(date, 'MM')` |
| `TO_CHAR(date, 'MM/DD/YYYY')` | `to_char_date(date, 'MM/DD/YYYY')` |
| `LAST_DAY(date)` | `last_day(date)` |
| `ROUND(x, 2)` | `safe_round(x, 2)` |
| `TRUNC(number, 1)` | `trunc_num(number, 1)` |
| `ABS(x)` | `safe_abs(x)` |
| `MOD(x, y)` | `safe_mod(x, y)` |
| `CEIL(x)` / `FLOOR(x)` | `ceil_num(x)` / `floor_num(x)` |
| `TO_DECIMAL(x, 15, 2)` | `type_cast(x, 'decimal', precision=15, scale=2)` |
| `TO_INTEGER(x)` | `type_cast(x, 'integer')` |
| `TO_CHAR(x)` *(non-date)* | `type_cast(x, 'string')` |
| `LTRIM(RTRIM(x))` | `trim(x)` |
| `SUBSTR(x, 1, n)` | `substr(x, 1, n)` |
| ETL audit cols (load date, batch ID, source) | `add_etl_metadata(df)` (PySpark) or `metadata_columns()` (pandas/SQL) |
| Watermark read/write from control table | `read_watermark(conn, key)` / `write_watermark(conn, key, value)` |
| Archive processed file | `archive_file(path, archive_dir)` |
| Reject file path | `reject_path_for(source_path)` |

### Pattern classes — used via config YAML, not imported directly

The classifier has already identified this mapping's pattern (see Stack Assignment Rationale above).
If a `config/<mapping>.yaml` is provided, the library executes it at runtime via `config_loader.run()`.
Do NOT regenerate the pattern logic — write the config YAML and a `run.py` launcher.
For NONE-confidence or bespoke-override mappings, generate code as normal but STILL use the utility
functions above wherever the Informatica expression uses a covered pattern.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Shared conversion prompt template (used by _dispatch.py)
# ─────────────────────────────────────────────────────────────────────────────

CONVERSION_PROMPT = """Convert the Informatica mapping documented below to {stack}.

{security_context}
## Stack Assignment Rationale
{rationale}
{approved_fixes_section}{flag_handling_section}{manifest_override_section}{etl_library_section}
## Full Mapping Documentation (your source of truth)
{documentation_md}

## Conversion Requirements
- Follow the documented logic EXACTLY
- Every business rule from the docs → inline comment in the code
- All hardcoded env-specific values → config dict / config file
- Structured logging at: job start, after each major transformation, job end (with row counts)
- Reject/error handling as documented
- USE etl_patterns utilities (null_safe, string_clean, type_cast, date_utils, numeric_utils, etc.) — never reinvent them inline
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

# Per-flag-type handling rules mapped to concrete code instructions
_FLAG_HANDLING_RULES: dict[str, str] = {
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


def _format_flag_line(flag: dict, seen: set[str]) -> str | None:
    """Return formatted instruction line for a single flag, or None to skip."""
    flag_type = flag.get("flag_type", "")
    location  = flag.get("location", "")
    detail    = flag.get("description", flag.get("detail", ""))
    rule      = _FLAG_HANDLING_RULES.get(flag_type)
    if not rule:
        return None  # INFO/DOCUMENTATION_TRUNCATED flags don't need code handling
    key = f"{flag_type}::{location}"
    if key in seen:
        return None
    seen.add(key)
    instruction = rule.replace("{detail}", detail or flag_type)
    return f"- [{flag_type}] at {location or 'mapping level'}:\n  {instruction}"


def _build_flag_handling_section(verification_flags: list[dict]) -> str:
    """
    Build a prompt section that instructs Claude to auto-handle each verification flag.
    The tool addresses as much as possible in code; the human reviewer handles what can't be.
    Returns an empty string if there are no actionable flags.
    """
    if not verification_flags:
        return ""

    seen: set[str] = set()
    lines = [
        line for flag in verification_flags
        if (line := _format_flag_line(flag, seen)) is not None
    ]

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


def _format_override_line(o: dict) -> str | None:
    """Return formatted line for one manifest override entry, or None to skip."""
    location = o.get("location", "")
    itype    = o.get("item_type", "")
    override = o.get("reviewer_override", "").strip()
    notes    = o.get("notes", "")
    if not override or override.upper() in ("", "N/A"):
        return None
    note_str = f" (Note: {notes})" if notes else ""
    return f"- [{itype}] {location} → Reviewer confirmed: {override}{note_str}"


def _build_manifest_override_section(overrides: list[dict]) -> str:
    """
    Build a prompt section listing reviewer-confirmed overrides from the manifest xlsx.
    These take precedence over anything the tool inferred from naming patterns.
    Returns empty string if no overrides were supplied.
    """
    if not overrides:
        return ""

    lines = [
        line for o in overrides
        if (line := _format_override_line(o)) is not None
    ]

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


# ─────────────────────────────────────────────────────────────────────────────
# _validate_conversion_files helpers
# ─────────────────────────────────────────────────────────────────────────────

def _check_empty_file(fname: str, stripped: str) -> str | None:
    """Return a warning if the file is empty, else None."""
    if not stripped:
        return f"VALIDATION: '{fname}' is empty — Claude may have failed to generate content."
    return None


def _is_code_line(line: str) -> bool:
    """Return True if the line counts as code (not a comment/docstring blank)."""
    return bool(line) and not line.startswith("#") and not line.startswith('"""') and not line.startswith("'''")


def _is_todo_line(line: str) -> bool:
    """Return True if the line contains a TODO/FIXME/STUB marker."""
    upper = line.upper()
    return "TODO" in upper or "FIXME" in upper or "STUB" in upper


def _filter_lines(stripped: str) -> list[str]:
    """Return non-empty stripped lines from stripped content."""
    return [l.strip() for l in stripped.splitlines() if l.strip()]


def _count_stubs(lines: list[str]) -> tuple[int, int]:
    """Return (code_line_count, todo_line_count) for the given lines."""
    code_count = sum(1 for l in lines if _is_code_line(l))
    todo_count = sum(1 for l in lines if _is_todo_line(l))
    return code_count, todo_count


def _check_todo_ratio(fname: str, stripped: str) -> str | None:
    """Return a warning if the file is mostly TODO stubs (skipped for files > 150 KB)."""
    if len(stripped) > 150_000:
        return None
    lines = _filter_lines(stripped)
    code_count, todo_count = _count_stubs(lines)
    if code_count and todo_count / max(code_count, 1) > 0.6:
        return (
            f"VALIDATION: '{fname}' is mostly TODO stubs ({todo_count} TODO lines vs "
            f"{code_count} code lines) — Claude may not have had enough context to fully convert."
        )
    return None


def _check_python_syntax(fname: str, stripped: str) -> str | None:
    """Return a syntax error warning for Python files (size-guarded at 500 KB)."""
    import ast
    if not fname.endswith((".py", ".pyx")) or len(stripped) >= 500_000:
        return None
    try:
        ast.parse(stripped)
    except SyntaxError as e:
        return (
            f"VALIDATION: '{fname}' has a Python syntax error at line {e.lineno}: {e.msg}. "
            "The file was saved but will not run without fixing this."
        )
    return None


def _check_pyspark_session(fname: str, content: str, stack) -> str | None:
    """Return a warning if a PySpark job lacks a SparkSession reference."""
    if stack not in (TargetStack.PYSPARK, TargetStack.HYBRID) or not fname.endswith(".py"):
        return None
    if "SparkSession" not in content and "spark" not in content.lower()[:2000]:
        return (
            f"VALIDATION: '{fname}' appears to be a PySpark job but contains no "
            "SparkSession reference — verify the conversion output is complete."
        )
    return None


def _check_dbt_select(fname: str, content: str, stack) -> str | None:
    """Return a warning if a dbt SQL model lacks a SELECT or Jinja block."""
    if stack != TargetStack.DBT or not fname.endswith(".sql"):
        return None
    head = content[:5000].lower()
    if "select" not in head and "{{" not in content[:5000]:
        return (
            f"VALIDATION: '{fname}' appears to be a dbt model but contains no SELECT or "
            "Jinja block — the model may be empty or malformed."
        )
    return None


def _check_run_pipeline(fname: str, content: str) -> list[str]:
    """Return warnings if run_pipeline.py is missing expected references."""
    if fname != "run_pipeline.py":
        return []
    issues = []
    if "subprocess" not in content:
        issues.append(
            "VALIDATION: 'run_pipeline.py' does not reference subprocess — "
            "orchestration wrapper may be incomplete."
        )
    if "dbt" not in content:
        issues.append(
            "VALIDATION: 'run_pipeline.py' does not reference dbt — "
            "orchestration wrapper may be incomplete."
        )
    return issues


_SCALE_PATTERNS = [
    (r'\.collect\(\)',         "collect() called — may OOM on large DataFrames"),
    (r'pd\.read_csv\([^)]+\)', "pd.read_csv() without chunksize — check for large sources"),
    (r'\.iterrows\(\)',        "iterrows() found — use vectorised operations for large data"),
]


def _check_scale_patterns(fname: str, content: str) -> list[str]:
    """Return scale anti-pattern warnings for a file."""
    import re as _re
    issues = []
    for pattern, msg in _SCALE_PATTERNS:
        if not _re.search(pattern, content):
            continue
        if "read_csv" in pattern and "chunksize" in content:
            continue
        issues.append(f"SCALE: '{fname}': {msg}")
    return issues


def _collect_single_warnings(fname: str, content: str, stack) -> list[str]:
    """Collect structural/content warnings (excluding empty-file check)."""
    stripped = content.strip()
    single_checks = [
        _check_todo_ratio(fname, stripped),
        _check_python_syntax(fname, stripped),
        _check_pyspark_session(fname, content, stack),
        _check_dbt_select(fname, content, stack),
    ]
    issues = [w for w in single_checks if w is not None]
    issues.extend(_check_run_pipeline(fname, content))
    issues.extend(_check_scale_patterns(fname, content))
    return issues


def _validate_single_file(fname: str, content: str, stack) -> list[str]:
    """Run all validation checks for one file. Returns list of warning strings."""
    stripped = content.strip()
    empty_warn = _check_empty_file(fname, stripped)
    if empty_warn:
        return [empty_warn]  # No further checks make sense on an empty file
    return _collect_single_warnings(fname, content, stack)


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
    import hashlib

    if _cache is None:
        _cache = {}

    issues: list[str] = []

    for fname, content in files.items():
        _key = hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()
        if _key in _cache:
            issues.extend(_cache[_key])
            continue

        file_issues = _validate_single_file(fname, content, stack)
        _cache[_key] = file_issues
        issues.extend(file_issues)

    return issues
