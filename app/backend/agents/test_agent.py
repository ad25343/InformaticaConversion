# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
STEP 9 — Test Generation + Coverage Check Agent
Fully deterministic — no Claude needed.

Three responsibilities:
  1. COVERAGE CHECK  — verify every S2T target field and every source filter
     appears in the generated code. Reports covered / missing.

  2. TEST GENERATION — produce stack-appropriate test files derived from the
     ACTUAL generated code (file names, model names, column names, target tables)
     rather than from hardcoded assumptions.

  3. DATA-LEVEL EQUIVALENCE (v2.13) — two additional test artifacts shipped
     with every job:
       a. Expression boundary tests (Component A): pytest parametrize tests for
          high-risk expression categories (IIF/DECODE, dates, strings, aggregations).
          Run with pytest — no database connection needed.
       b. Golden CSV comparison script (Component B): compare_golden.py — a
          self-contained script run OUTSIDE the tool after the team has captured
          Informatica output and run the generated code.  Requires only pandas.

Design principle: everything must be driven by `conversion_output.files`.
We parse the real code to discover models, tables, columns, and stack patterns —
then generate tests that reference those real artifacts.

NOTE ON EXECUTION (v2.13):
  The generated test files are ARTIFACTS delivered alongside the converted code.
  The conversion tool does NOT execute them.  Responsibility for running them
  lives with the data engineering team in their own environment.  See:
    docs/TESTING_GUIDE.md  — full instructions for each test type

Implementation split (v2.23):
  coverage_checker.py  — field/filter coverage checks and artifact discovery
  test_generator.py    — dbt, PySpark, Python, SQL test file generation
  test_agent.py        — thin orchestrator (this file); public API unchanged
"""
from __future__ import annotations

from ..models.schemas import (
    ConversionOutput, TestReport,
)
from .base import BaseAgent
from .coverage_checker import (
    discover_generated_artifacts,
    check_field_coverage,
    check_filter_coverage,
    extract_source_filters,
)
from .test_generator import (
    generate_tests_from_artifacts,
    generate_expression_boundary_tests,
)
from .golden_compare import generate_boundary_tests, generate_comparison_script  # noqa: F401


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

class TestAgent(BaseAgent):

    def generate_tests(
        self,
        conversion_output: ConversionOutput,
        s2t: dict,
        verification: dict,
        graph: dict,
    ) -> TestReport:
        return _generate_tests_impl(conversion_output, s2t, verification, graph)


def _generate_tests_impl(
    conversion_output: ConversionOutput,
    s2t: dict,
    verification: dict,
    graph: dict,
) -> TestReport:
    """
    Build the TestReport for Step 9.

    Parameters
    ----------
    conversion_output : ConversionOutput
        The code files produced by Step 7.
    s2t : dict
        The s2t_state dict stored in job state (records, unmapped_sources, etc.).
    verification : dict
        The VerificationReport dict (for extracting filter flags).
    graph : dict
        The parsed Informatica graph (for source filter attributes).
    """
    stack = conversion_output.target_stack
    files = conversion_output.files  # {filename: content}

    records = s2t.get("records", [])
    mapped  = [r for r in records if r.get("status") not in
               ("Unmapped Target", "Unmapped Source")]

    # ── Discover the real structure of what was generated ─────────────────────
    discovered = discover_generated_artifacts(files, stack)

    # ── 1. Field coverage ─────────────────────────────────────────────────────
    field_checks = check_field_coverage(mapped, files)

    fields_covered = sum(1 for c in field_checks if c.covered)
    fields_missing = len(field_checks) - fields_covered
    missing_fields = [c.target_field for c in field_checks if not c.covered]
    coverage_pct   = (round(100 * fields_covered / len(field_checks), 1)
                      if field_checks else 100.0)

    # ── 2. Filter coverage ────────────────────────────────────────────────────
    source_filters = extract_source_filters(graph)
    filter_checks  = check_filter_coverage(source_filters, files)

    filters_covered = sum(1 for c in filter_checks if c.covered)
    filters_missing = len(filter_checks) - filters_covered

    # ── 3. Test file generation ───────────────────────────────────────────────
    test_files, notes = generate_tests_from_artifacts(
        discovered=discovered,
        files=files,
        mapped=mapped,
        source_filters=source_filters,
        field_checks=field_checks,
        stack=stack,
    )

    # ── 4. Component A — Expression boundary tests (v2.13) ────────────────────
    expr_tests, expr_notes = generate_expression_boundary_tests(
        graph=graph,
        mapping_name=conversion_output.mapping_name or "mapping",
        stack=stack,
    )
    test_files.update(expr_tests)
    notes.extend(expr_notes)

    # ── 5. Component B — Golden CSV comparison script (v2.13) ─────────────────
    s2t_records = s2t.get("records", []) if s2t else []
    comparison_script = generate_comparison_script(
        mapping_name=conversion_output.mapping_name or "mapping",
        s2t_records=s2t_records,
    )
    test_files["tests/compare_golden.py"] = comparison_script
    notes.append(
        "📊 compare_golden.py generated — run OUTSIDE the tool after capturing "
        "Informatica output CSV and generated-code output CSV. "
        "See docs/TESTING_GUIDE.md for instructions."
    )

    if missing_fields:
        notes.append(
            f"⚠️ {fields_missing} target field(s) not found in generated code: "
            f"{', '.join(missing_fields)}. Review Step 7 output carefully."
        )
    if filters_missing > 0:
        notes.append(
            f"⚠️ {filters_missing} filter condition(s) may not be reflected in code: "
            + "; ".join(c.filter_description for c in filter_checks if not c.covered)
        )

    return TestReport(
        mapping_name=conversion_output.mapping_name or "",
        target_stack=stack.value,
        test_files=test_files,
        field_coverage=field_checks,
        filter_coverage=filter_checks,
        fields_covered=fields_covered,
        fields_missing=fields_missing,
        coverage_pct=coverage_pct,
        missing_fields=missing_fields,
        filters_covered=filters_covered,
        filters_missing=filters_missing,
        notes=notes,
    )


# Backward-compat shim — keeps orchestrator.py call sites unchanged
def generate_tests(
    conversion_output: ConversionOutput,
    s2t: dict,
    verification: dict,
    graph: dict,
) -> TestReport:
    return TestAgent().generate_tests(conversion_output, s2t, verification, graph)
