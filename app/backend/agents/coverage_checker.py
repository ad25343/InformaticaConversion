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

_FINAL_MODEL_KEYWORDS = frozenset(("fact", "mart", "dim", "final", "output", "target"))


def _file_ext(fname: str) -> str:
    """Return the lowercase extension of fname, or '' if no extension."""
    return fname.rsplit(".", 1)[-1].lower() if "." in fname else ""


def _classify_file(
    fname: str,
    content: str,
    result: dict,
    columns_seen: set,
) -> None:
    """Classify one generated file and populate result in-place."""
    ext = _file_ext(fname)
    if ext == "sql":
        model_name, target_table, cols = parse_sql_file(fname, content)
        result["sql_models"].append((fname, model_name, target_table, cols))
        columns_seen.update(cols)
    elif ext in ("yml", "yaml"):
        result["yaml_schemas"].append((fname, parse_yaml_schema(content)))
    elif ext == "py":
        funcs, df_vars, cols = parse_python_file(content)
        result["python_files"].append((fname, funcs, df_vars))
        columns_seen.update(cols)
    elif ext in ("scala", "java"):
        columns_seen.update(extract_column_names_generic(content))


def _matches_final_keywords(model_name: Optional[str]) -> bool:
    """Return True if model_name contains any of the final-model keywords."""
    return any(k in (model_name or "").lower() for k in _FINAL_MODEL_KEYWORDS)


def _find_final_model(sql_models: list) -> Optional[tuple]:
    """Return (model_name, target_table) for the most likely final model."""
    for _, model_name, target_table, _ in sql_models:
        if _matches_final_keywords(model_name):
            return (model_name, target_table)
    if sql_models:
        _, model_name, target_table, _ = sql_models[-1]
        return (model_name, target_table)
    return None


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
        _classify_file(fname, content, result, columns_seen)

    final = _find_final_model(result["sql_models"])
    if final:
        result["final_model"] = final[0]
        result["final_table"] = final[1] or final[0]

    result["all_columns"] = sorted(columns_seen)
    return result


def _is_dbt_content(files: dict[str, str]) -> bool:
    """Return True if any file looks like a dbt model (Jinja + ref)."""
    return any("{{" in c and "ref(" in c for c in files.values())


def _is_pyspark_content(all_content_lower: str) -> bool:
    """Return True if content contains PySpark imports."""
    return "from pyspark" in all_content_lower or "sparksession" in all_content_lower


def _has_extension(fnames: list[str], ext: str) -> bool:
    """Return True if any filename ends with the given extension."""
    return any(f.endswith(ext) for f in fnames)


def _infer_stack_hint(files: dict[str, str], stack: TargetStack) -> str:
    """Determine stack from file content rather than just the enum."""
    fnames = list(files.keys())
    if _is_dbt_content(files):
        return "dbt"
    if _is_pyspark_content("\n".join(files.values()).lower()):
        return "pyspark"
    if _has_extension(fnames, ".py"):
        return "python"
    if _has_extension(fnames, ".sql"):
        return "sql"
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


_SELECT_RESERVED = frozenset(("as", "from", "select"))


def _cols_from_select_block(block: str) -> list[str]:
    """Extract bare column names from a SELECT...FROM block (no aliases)."""
    clean = re.sub(r"\([^)]*\)", "", block)
    cols: list[str] = []
    for token in re.split(r"[,\n]", clean):
        token = token.strip()
        id_match = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", token)
        if id_match and id_match[-1].lower() not in _SELECT_RESERVED:
            cols.append(id_match[-1].lower())
    return cols


def extract_select_columns(sql: str) -> list[str]:
    """
    Heuristically extract column names/aliases from the outermost SELECT block.
    Returns a list of lowercase identifiers.
    """
    cols = [m.group(1).lower() for m in re.finditer(r"\bAS\s+([A-Za-z_][A-Za-z0-9_]*)", sql, re.IGNORECASE)]
    select_block = re.search(r"\bSELECT\b(.*?)\bFROM\b", sql, re.DOTALL | re.IGNORECASE)
    if select_block:
        cols.extend(_cols_from_select_block(select_block.group(1)))
    return list(dict.fromkeys(cols))


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

def _field_variants(tgt_field: str) -> tuple[str, str, str]:
    """Return (exact, lower, snake_case) variants of a target field name."""
    exact = tgt_field
    lower = tgt_field.lower()
    snake = re.sub(r"([a-z])([A-Z])", r"\1_\2", tgt_field).lower()
    return exact, lower, snake


def _field_in_file(exact: str, lower: str, snake: str, content: str) -> bool:
    """Return True if any variant of the field name appears in content."""
    c_lower = content.lower()
    return exact in content or lower in c_lower or (snake != lower and snake in c_lower)


def _match_note_in_file(exact: str, lower: str, snake: str, content: str) -> str:
    """Return a match note for one file, or empty string if no match."""
    c_lower = content.lower()
    if exact in content:
        return f"Matched as '{exact}'"
    if lower in c_lower:
        return f"Matched as lowercase '{lower}'"
    if snake != lower and snake in c_lower:
        return f"Matched as snake_case '{snake}'"
    return ""


def _first_match_note(exact: str, lower: str, snake: str, files: dict[str, str]) -> str:
    """Return a note describing which variant first matched in files."""
    notes = (
        _match_note_in_file(exact, lower, snake, content)
        for content in files.values()
    )
    return next((n for n in notes if n), "")


def _check_one_field(tgt_field: str, tgt_table: str, files: dict[str, str]) -> FieldCoverageCheck:
    """Check coverage for a single target field across all generated files."""
    exact, lower, snake = _field_variants(tgt_field)
    found_in   = [f for f, c in files.items() if _field_in_file(exact, lower, snake, c)]
    covered    = bool(found_in)
    match_note = (
        _first_match_note(exact, lower, snake, files)
        if covered
        else f"Not found in any generated file — tried: '{exact}', '{lower}', '{snake}'"
    )
    return FieldCoverageCheck(
        target_field=tgt_field,
        target_table=tgt_table,
        covered=covered,
        found_in_files=list(dict.fromkeys(found_in)),
        note=match_note,
    )


def check_field_coverage(
    mapped: list[dict],
    files: dict[str, str],
) -> list[FieldCoverageCheck]:
    """
    For each mapped target field, search all generated files.
    Tries: exact case, lowercase, snake_case, and partial token match.
    """
    return [
        _check_one_field(rec.get("target_field", ""), rec.get("target_table", ""), files)
        for rec in mapped
        if rec.get("target_field", "")
    ]


_SQL_KEYWORDS = frozenset({
    "AND", "OR", "NOT", "NULL", "IS", "IN", "LIKE", "BETWEEN",
    "CASE", "WHEN", "THEN", "ELSE", "END", "SELECT", "FROM",
    "WHERE", "JOIN", "ON", "AS", "WITH",
})


def _extract_meaningful_tokens(condition: str) -> list[str]:
    """Extract non-keyword, non-short tokens from a filter condition."""
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|'[^']*'", condition)
    return [
        t.strip("'") for t in tokens
        if len(t.strip("'")) > 2 and t.upper().strip("'") not in _SQL_KEYWORDS
    ]


def _files_matching_tokens(meaningful: list[str], files: dict[str, str]) -> list[str]:
    """Return filenames where at least half the meaningful tokens appear."""
    threshold = max(1, len(meaningful) // 2)
    return [
        fname for fname, content in files.items()
        if sum(1 for t in meaningful if t.lower() in content.lower()) >= threshold
    ]


def check_filter_coverage(
    source_filters: list[dict],
    files: dict[str, str],
) -> list[FilterCoverageCheck]:
    """
    For each source filter, search for its meaningful tokens in generated code.
    Ignores SQL keywords and short words to reduce noise.
    """
    checks: list[FilterCoverageCheck] = []
    for flt in source_filters:
        condition  = flt["condition"]
        meaningful = _extract_meaningful_tokens(condition)
        found_files = _files_matching_tokens(meaningful, files) if meaningful else []
        covered    = bool(found_files)
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

def _extract_filter_from_transformation(t: dict) -> Optional[dict]:
    """Return a filter dict from a single transformation, or None if no filter applies."""
    ttype = t.get("type", "")
    attrs = t.get("attributes", {})
    name  = t.get("name", "")
    if ttype == "Source Qualifier":
        cond = attrs.get("Source Filter", "").strip()
        return {"condition": cond, "source": f"{name} (Source Qualifier filter)"} if cond else None
    if ttype == "Filter":
        cond = attrs.get("Filter Condition", "").strip()
        return {"condition": cond, "source": f"{name} (Filter transformation)"} if cond else None
    return None


def extract_source_filters(graph: dict) -> list[dict]:
    """Pull filter conditions from Source Qualifier and Filter transformation attributes."""
    filters: list[dict] = []
    for m in graph.get("mappings", []):
        for t in m.get("transformations", []):
            flt = _extract_filter_from_transformation(t)
            if flt:
                filters.append(flt)
    return filters


# ─────────────────────────────────────────────────────────────────────────────
# Private aliases kept for internal callers that used leading-underscore names
# ─────────────────────────────────────────────────────────────────────────────
_discover_generated_artifacts = discover_generated_artifacts
_check_field_coverage         = check_field_coverage
_check_filter_coverage        = check_filter_coverage
_extract_source_filters       = extract_source_filters
