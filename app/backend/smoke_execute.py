# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Smoke-execution validation for generated code files.

Goes one step beyond _validate_conversion_files() (which checks syntax via
ast.parse) by actually compiling / parsing the files through their respective
tool chains:

  Python / PySpark  → py_compile (catches byte-code compilation errors)
  dbt SQL models    → dbt parse (optional; requires dbt installed)
  YAML files        → yaml.safe_load (structural validity)

None of these checks require a live database — they are all static.

Usage
-----
    from backend.smoke_execute import smoke_execute_files

    results = smoke_execute_files(files, target_stack)
    # results: list of SmokeResult(filename, tool, passed, detail)

    errors = [r for r in results if not r.passed]
"""
from __future__ import annotations
import ast
import importlib
import py_compile
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .models.schemas import TargetStack


@dataclass
class SmokeResult:
    filename: str
    tool:     str          # "py_compile" | "dbt_parse" | "yaml_load" | "ast_parse"
    passed:   bool
    detail:   Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def _file_bucket(name: str) -> str:
    """Return 'py', 'sql', 'yml', or '' for an unrecognised extension."""
    if name.endswith((".py", ".pyx")):
        return "py"
    if name.endswith(".sql"):
        return "sql"
    if name.endswith((".yml", ".yaml")) and name != "profiles.yml":
        return "yml"
    return ""


def _partition_files(
    files: dict[str, str],
) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Split *files* into (py_files, sql_files, yml_files) by extension."""
    py_files:  dict[str, str] = {}
    sql_files: dict[str, str] = {}
    yml_files: dict[str, str] = {}
    buckets = {"py": py_files, "sql": sql_files, "yml": yml_files}
    for k, v in files.items():
        bucket = _file_bucket(k)
        if bucket:
            buckets[bucket][k] = v
    return py_files, sql_files, yml_files


def _run_python_checks(py_files: dict[str, str]) -> list[SmokeResult]:
    """Compile all Python/PySpark files via py_compile."""
    return [_check_py_compile(fname, content) for fname, content in py_files.items()]


def _run_dbt_checks(
    sql_files: dict[str, str],
    yml_files: dict[str, str],
    run_dbt_parse: bool,
) -> list[SmokeResult]:
    """Run SQL structure checks and optional dbt parse on dbt SQL models."""
    results = [_check_sql_structure(fname, content) for fname, content in sql_files.items()]
    if run_dbt_parse:
        results.extend(_check_dbt_parse(sql_files, yml_files))
    return results


def _run_yaml_checks(yml_files: dict[str, str]) -> list[SmokeResult]:
    """Parse all YAML files for structural validity."""
    return [_check_yaml(fname, content) for fname, content in yml_files.items()]


def smoke_execute_files(
    files: dict[str, str],
    target_stack: TargetStack,
    *,
    run_dbt_parse: bool = False,   # opt-in; requires dbt installed
) -> list[SmokeResult]:
    """
    Run all appropriate smoke checks on a set of generated files.

    Parameters
    ----------
    files          dict mapping filename → content (as produced by ConversionOutput)
    target_stack   used to choose which checks are relevant
    run_dbt_parse  if True and dbt is installed, run 'dbt parse' on SQL models

    Returns
    -------
    list[SmokeResult] — one entry per file checked; empty list if no checks apply.
    """
    py_files, sql_files, yml_files = _partition_files(files)

    results: list[SmokeResult] = _run_python_checks(py_files)

    if target_stack == TargetStack.DBT and sql_files:
        results.extend(_run_dbt_checks(sql_files, yml_files, run_dbt_parse))

    results.extend(_run_yaml_checks(yml_files))
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Individual checkers
# ─────────────────────────────────────────────────────────────────────────────

def _check_py_compile(fname: str, content: str) -> SmokeResult:
    """
    Compile a Python source string to bytecode using py_compile.
    Catches a broader class of errors than ast.parse() alone (e.g. encoding
    issues, f-string internals, match/case syntax on older interpreters).
    """
    if len(content.strip()) > 500_000:
        return SmokeResult(fname, "py_compile", True, "skipped — file > 500 KB")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        py_compile.compile(tmp_path, doraise=True)
        return SmokeResult(fname, "py_compile", True)
    except py_compile.PyCompileError as e:
        return SmokeResult(fname, "py_compile", False, str(e))
    finally:
        Path(tmp_path).unlink(missing_ok=True)
        cached = Path(tmp_path).with_suffix(".pyc")
        cached.unlink(missing_ok=True)


def _check_sql_structure(fname: str, content: str) -> SmokeResult:
    """
    Structural check for dbt SQL models.  Does not require a database:
    - File must contain at least one SELECT or a Jinja expression
    - Jinja blocks must be balanced ({{ }} and {% %})
    """
    head = content[:5000]
    low  = head.lower()

    if "select" not in low and "{{" not in head:
        return SmokeResult(
            fname, "sql_structure", False,
            "No SELECT or Jinja block found — model appears empty or malformed"
        )

    # Check balanced Jinja delimiters
    open_expr  = content.count("{{")
    close_expr = content.count("}}")
    open_tag   = content.count("{%")
    close_tag  = content.count("%}")

    if open_expr != close_expr:
        return SmokeResult(
            fname, "sql_structure", False,
            f"Unbalanced Jinja expression delimiters: "
            f"{open_expr} '{{{{' vs {close_expr} '}}}}'"
        )
    if open_tag != close_tag:
        return SmokeResult(
            fname, "sql_structure", False,
            f"Unbalanced Jinja tag delimiters: {open_tag} '{{% '}} vs {close_tag} ' %}}'"
        )

    return SmokeResult(fname, "sql_structure", True)


def _check_yaml(fname: str, content: str) -> SmokeResult:
    """Parse YAML for structural validity (no schema enforcement)."""
    try:
        import yaml
        yaml.safe_load(content)
        return SmokeResult(fname, "yaml_load", True)
    except Exception as e:
        return SmokeResult(fname, "yaml_load", False, str(e))


_DBT_PROJECT_YML = textwrap.dedent("""\
    name: smoke_test
    version: '1.0.0'
    config-version: 2
    model-paths: ["models"]
    profile: smoke_test
""")

_DBT_PROFILES_YML = textwrap.dedent("""\
    smoke_test:
      target: dev
      outputs:
        dev:
          type: duckdb
          path: ':memory:'
          threads: 1
""")


def _dbt_is_available() -> bool:
    """Return True if dbt is installed and callable; False otherwise."""
    try:
        subprocess.run(
            ["dbt", "--version"],
            capture_output=True, text=True, check=True, timeout=10,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _write_dbt_project(root: Path, sql_files: dict[str, str], yml_files: dict[str, str]) -> list[str]:
    """Write minimal dbt project files; return list of SQL model stems written."""
    (root / "dbt_project.yml").write_text(_DBT_PROJECT_YML)
    (root / "profiles.yml").write_text(_DBT_PROFILES_YML)
    models_dir = root / "models"
    models_dir.mkdir()
    written: list[str] = []
    for fname, content in sql_files.items():
        stem = Path(fname).name
        (models_dir / stem).write_text(content)
        written.append(stem)
    for fname, content in yml_files.items():
        (models_dir / Path(fname).name).write_text(content)
    return written


def _run_dbt_parse_proc(root: Path, written: list[str]) -> SmokeResult:
    """Execute 'dbt parse' in *root* and return the corresponding SmokeResult."""
    proc = subprocess.run(
        ["dbt", "parse", "--project-dir", str(root), "--profiles-dir", str(root)],
        capture_output=True, text=True, timeout=60,
    )
    label = f"{len(written)} model(s)"
    if proc.returncode == 0:
        return SmokeResult(label, "dbt_parse", True, f"dbt parse succeeded: {', '.join(written)}")
    return SmokeResult(label, "dbt_parse", False, (proc.stderr or proc.stdout)[:500])


def _check_dbt_parse(
    sql_files: dict[str, str],
    yml_files: dict[str, str],
) -> list[SmokeResult]:
    """
    Run 'dbt parse' in a temporary directory to validate SQL models.

    Only called when run_dbt_parse=True and dbt is installed.
    Creates a minimal dbt project structure so 'dbt parse' can work
    without a real profiles.yml or database connection.
    """
    if not _dbt_is_available():
        return [SmokeResult("dbt_parse", "dbt_parse", True, "dbt not installed — skipping dbt parse check")]

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        written = _write_dbt_project(root, sql_files, yml_files)
        return [_run_dbt_parse_proc(root, written)]


# ─────────────────────────────────────────────────────────────────────────────
# Convenience: human-readable summary
# ─────────────────────────────────────────────────────────────────────────────

def _format_result_line(r: SmokeResult) -> str:
    """Format one SmokeResult as a single display line."""
    icon   = "✅" if r.passed else "❌"
    detail = f"  {r.detail}" if r.detail else ""
    return f"  {icon} [{r.tool}] {r.filename}{detail}"


def _count_passed(results: list[SmokeResult]) -> int:
    """Return the number of passing results."""
    return sum(r.passed for r in results)


def format_smoke_results(results: list[SmokeResult]) -> str:
    """Return a plain-text summary suitable for logging or test output."""
    if not results:
        return "No smoke checks applicable."
    passed = _count_passed(results)
    lines  = [f"Smoke execution: {passed}/{len(results)} checks passed"]
    lines.extend(_format_result_line(r) for r in results)
    return "\n".join(lines)
