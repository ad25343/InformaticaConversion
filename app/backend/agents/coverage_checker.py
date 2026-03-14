# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Coverage Check Module — Step 9
Fully deterministic — no Claude needed.

Responsibility: verify every S2T target field and every source filter appears
in the generated code.  Produces FieldCoverageCheck and FilterCoverageCheck
results consumed by TestAgent and TestGenerator.

Also houses the artifact-discovery helpers that parse the generated code to
extract model names, column names, and Python function names — these are
shared with test_generator.py.
"""
from __future__ import annotations
import re
from typing import Optional

from ..models.schemas import (
    FieldCoverageCheck,
    FilterCoverageCheck,
    TargetStack,
)


# ─────────────────────────────────────────────────────────────────────────────
# Artifact discovery — read the REAL generated code
# ─────────────────────────────────────────────────────────────────────────────

def discover_generated_artifacts(
    files: dict[str, str],
    stack: TargetStack,
) -> dict:
    """
    Inspect the actual generated files and return a structured description:

    {
      "stack_hint":   "dbt" | "pyspark" | "python" | "sql" | "unknown",
      "sql_models":   [(filename, model_name, target_table, [columns]), ...],
      "yaml_schemas": [(filename, model_name_list), ...],
      "python_files": [(filename, function_names, dataframe_vars), ...],
      "final_model":  model_name or None,
      "final_table":  target_table or None,
      "all_columns":  sorted deduplicated list of column names found in code,
    }
    """
    result: dict = {
        "stack_hint": _infer_stack_hint(files, stack),
        "sql_models": [],
        "yaml_schemas": [],
        "python_files": [],
        "final_model": None,
        "final_table": None,
        "all_columns": [],
    }

    columns_seen: set[str] = set()

    for fname, content in files.items():
        ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""

        if ext == "sql":
            model_name, target_table, cols = parse_sql_file(fname, content)
            result["sql_models"].append((fname, model_name, target_table, cols))
            columns_seen.update(cols)

        elif ext in ("yml", "yaml"):
            model_names = parse_yaml_schema(content)
            result["yaml_schemas"].append((fname, model_names))

        elif ext == "py":
            funcs, df_vars, cols = parse_python_file(content)
            result["python_files"].append((fname, funcs, df_vars))
            columns_seen.update(cols)

        elif ext in ("scala", "java"):
            # Best-effort: extract column-like strings
            cols = extract_column_names_generic(content)
            columns_seen.update(cols)

    # Identify the "final" model: prefer fact/mart/output names, else last SQL
    final = None
    for fname, model_name, target_table, _ in result["sql_models"]:
        if any(k in (model_name or "").lower() for k in
               ("fact", "mart", "dim", "final", "output", "target")):
            final = (model_name, target_table)
            break
    if not final and result["sql_models"]:
        _, model_name, target_table, _ = result["sql_models"][-1]
        final = (model_name, target_table)

    if final:
        result["final_model"] = final[0]
        result["final_table"] = final[1] or final[0]

    result["all_columns"] = sorted(columns_seen)
    return result


def _infer_stack_hint(files: dict[str, str], stack: TargetStack) -> str:
    """Determine stack from file content rather than just the enum."""
    all_content = "\n".join(files.values())
    fnames = list(files.keys())

    if any("{{" in c and "ref(" in c for c in files.values()):
        return "dbt"
    if "from pyspark" in all_content.lower() or "sparksession" in all_content.lower():
        return "pyspark"
    if any(f.endswith(".py") for f in fnames):
        return "python"
    if any(f.endswith(".sql") for f in fnames):
        return "sql"
    # Fall back to schema enum
    return stack.value.lower()


def parse_sql_file(fname: str, content: str) -> tuple[str, Optional[str], list[str]]:
    """
    Extract from a SQL file:
      - model_name: stem of the filename (e.g. 'fact_orders')
      - target_table: name from INSERT INTO / CREATE TABLE if present, else None
      - columns: list of column aliases / named expressions found in SELECT
    """
    model_name = fname.split("/")[-1].rsplit(".", 1)[0]

    # Target table from DDL / DML
    target_table: Optional[str] = None
    m = re.search(r"(?:INSERT\s+(?:INTO|OVERWRITE)\s+(?:TABLE\s+)?)([A-Za-z_][A-Za-z0-9_.]*)",
                  content, re.IGNORECASE)
    if m:
        target_table = m.group(1).strip().split(".")[-1]
    else:
        m = re.search(r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|VIEW)\s+([A-Za-z_][A-Za-z0-9_.]*)",
                      content, re.IGNORECASE)
        if m:
            target_table = m.group(1).strip().split(".")[-1]

    # Column aliases from SELECT … AS alias  or  SELECT col  (final SELECT only)
    cols = extract_select_columns(content)

    return model_name, target_table, cols


def extract_select_columns(sql: str) -> list[str]:
    """
    Heuristically extract column names/aliases from the outermost SELECT block.
    Returns a list of lowercase identifiers.
    """
    cols: list[str] = []
    # Find AS aliases: anything matching "AS <identifier>"
    for m in re.finditer(r"\bAS\s+([A-Za-z_][A-Za-z0-9_]*)", sql, re.IGNORECASE):
        cols.append(m.group(1).lower())
    # Also pick up bare column names between SELECT and FROM (no alias)
    select_block = re.search(r"\bSELECT\b(.*?)\bFROM\b", sql,
                             re.DOTALL | re.IGNORECASE)
    if select_block:
        block = select_block.group(1)
        # Remove sub-selects / function calls to reduce noise
        block = re.sub(r"\([^)]*\)", "", block)
        for token in re.split(r"[,\n]", block):
            token = token.strip()
            # Last identifier in a token is typically the column name
            id_match = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", token)
            if id_match and id_match[-1].lower() not in ("as", "from", "select"):
                cols.append(id_match[-1].lower())
    return list(dict.fromkeys(cols))  # deduplicate, preserve order


def parse_yaml_schema(content: str) -> list[str]:
    """Extract model names referenced in a dbt schema YAML."""
    names: list[str] = []
    for m in re.finditer(r"^\s*-\s*name:\s*([A-Za-z_][A-Za-z0-9_]*)", content, re.MULTILINE):
        names.append(m.group(1))
    return names


def parse_python_file(content: str) -> tuple[list[str], list[str], list[str]]:
    """
    Extract:
      - function names defined in the file
      - DataFrame variable names (df, spark_df, result, etc.)
      - Column strings referenced in withColumn / selectExpr / .alias()
    """
    funcs  = re.findall(r"def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", content)
    df_vars = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:spark\.|df\.|pd\.)", content)
    # Strings passed to withColumn / selectExpr / alias / rename
    col_strings: list[str] = []
    for m in re.finditer(r"""(?:withColumn|selectExpr|alias|rename)\s*\(\s*["']([^"']+)["']""",
                         content):
        col_strings.append(m.group(1).lower())
    return funcs, df_vars, col_strings


def extract_column_names_generic(content: str) -> list[str]:
    """Generic fallback: extract quoted strings that look like column names."""
    cols: list[str] = []
    for m in re.finditer(r"""["']([A-Za-z_][A-Za-z0-9_]*)["']""", content):
        name = m.group(1)
        if len(name) >= 2 and name.upper() not in ("AS", "BY", "OR", "AND", "NOT",
                                                     "NULL", "TRUE", "FALSE"):
            cols.append(name.lower())
    return cols


# ─────────────────────────────────────────────────────────────────────────────
# Coverage checks
# ─────────────────────────────────────────────────────────────────────────────

def check_field_coverage(
    mapped: list[dict],
    files: dict[str, str],
) -> list[FieldCoverageCheck]:
    """
    For each mapped target field, search all generated files.
    Tries: exact case, lowercase, snake_case, and partial token match.
    """
    checks: list[FieldCoverageCheck] = []
    for rec in mapped:
        tgt_field = rec.get("target_field", "")
        tgt_table = rec.get("target_table", "")
        if not tgt_field:
            continue

        found_in: list[str] = []
        match_note = ""

        # Build search variants
        exact   = tgt_field          # e.g. ORDER_YEAR_MONTH or OrderYearMonth
        lower   = tgt_field.lower()  # e.g. order_year_month
        # CamelCase → snake_case only (skip if already ALL_CAPS/all_lower — lower handles those)
        snake   = re.sub(r"([a-z])([A-Z])", r"\1_\2", tgt_field).lower()

        for fname, content in files.items():
            c_lower = content.lower()
            if (exact in content or lower in c_lower or
                    (snake != lower and snake in c_lower)):
                found_in.append(fname)

        covered = bool(found_in)
        if covered:
            # Record which variant matched
            for fname, content in files.items():
                c_lower = content.lower()
                if exact in content:
                    match_note = f"Matched as '{exact}'"
                    break
                if lower in c_lower:
                    match_note = f"Matched as lowercase '{lower}'"
                    break
                if snake != lower and snake in c_lower:
                    match_note = f"Matched as snake_case '{snake}'"
                    break
        else:
            match_note = (
                f"Not found in any generated file — tried: "
                f"'{exact}', '{lower}', '{snake}'"
            )

        checks.append(FieldCoverageCheck(
            target_field=tgt_field,
            target_table=tgt_table,
            covered=covered,
            found_in_files=list(dict.fromkeys(found_in)),  # dedup
            note=match_note,
        ))
    return checks


def check_filter_coverage(
    source_filters: list[dict],
    files: dict[str, str],
) -> list[FilterCoverageCheck]:
    """
    For each source filter, search for its meaningful tokens in generated code.
    Ignores SQL keywords and short words to reduce noise.
    """
    checks: list[FilterCoverageCheck] = []
    _SQL_KEYWORDS = frozenset({
        "AND", "OR", "NOT", "NULL", "IS", "IN", "LIKE", "BETWEEN",
        "CASE", "WHEN", "THEN", "ELSE", "END", "SELECT", "FROM",
        "WHERE", "JOIN", "ON", "AS", "WITH",
    })

    for flt in source_filters:
        condition = flt["condition"]
        # Extract meaningful tokens: identifiers and quoted values
        tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|'[^']*'", condition)
        meaningful = [
            t.strip("'") for t in tokens
            if len(t.strip("'")) > 2 and t.upper().strip("'") not in _SQL_KEYWORDS
        ]

        found_files: list[str] = []
        if meaningful:
            for fname, content in files.items():
                c_lower = content.lower()
                # Require at least half the tokens to match (more robust than requiring all)
                matched = sum(1 for t in meaningful if t.lower() in c_lower)
                if matched >= max(1, len(meaningful) // 2):
                    found_files.append(fname)

        covered = bool(found_files)
        checks.append(FilterCoverageCheck(
            filter_description=condition,
            source=flt["source"],
            covered=covered,
            found_in_files=found_files,
            note="" if covered else
                  f"Tokens {meaningful} not found — filter may be missing from generated code",
        ))
    return checks


# ─────────────────────────────────────────────────────────────────────────────
# Source filter extraction
# ─────────────────────────────────────────────────────────────────────────────

def extract_source_filters(graph: dict) -> list[dict]:
    """Pull filter conditions from Source Qualifier and Filter transformation attributes."""
    filters: list[dict] = []
    for m in graph.get("mappings", []):
        for t in m.get("transformations", []):
            ttype = t.get("type", "")
            attrs = t.get("attributes", {})
            name  = t.get("name", "")

            if ttype == "Source Qualifier":
                sq_filter = attrs.get("Source Filter", "").strip()
                if sq_filter:
                    filters.append({
                        "condition": sq_filter,
                        "source": f"{name} (Source Qualifier filter)",
                    })
            elif ttype == "Filter":
                fil_cond = attrs.get("Filter Condition", "").strip()
                if fil_cond:
                    filters.append({
                        "condition": fil_cond,
                        "source": f"{name} (Filter transformation)",
                    })
    return filters


# ─────────────────────────────────────────────────────────────────────────────
# Private aliases kept for internal callers that used leading-underscore names
# ─────────────────────────────────────────────────────────────────────────────
_discover_generated_artifacts = discover_generated_artifacts
_check_field_coverage         = check_field_coverage
_check_filter_coverage        = check_filter_coverage
_extract_source_filters       = extract_source_filters
