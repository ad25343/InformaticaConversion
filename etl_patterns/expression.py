"""
expression.py — Safe column-expression evaluator
=================================================
Evaluates the ``expression`` strings found in column_map and filter blocks
of pattern YAML configs.

Supported expression syntax
----------------------------
Literal assignment:
  expression: "ACTIVE"              → the string "ACTIVE"
  expression: 1                     → the integer 1

Column reference:
  expression: "{CUST_ID}"           → row["CUST_ID"]

Null-safe helper:
  expression: "null_safe({AMT}, 0)" → null_safe(row["AMT"], 0)

Type cast:
  expression: "type_cast({AMT}, decimal, scale=2)"

String helpers:
  expression: "upper({NAME})"
  expression: "lower({NAME})"
  expression: "trim({ADDR})"
  expression: "substr({ACCT}, 1, 6)"
  expression: "lpad({CODE}, 5, '0')"
  expression: "concat({FIRST}, ' ', {LAST})"

Coalesce:
  expression: "coalesce({NICK}, {FIRST}, 'UNKNOWN')"

Arithmetic (simple):
  expression: "{UNIT_PRICE} * {QTY}"
  expression: "{GROSS} - {DISCOUNT}"

Boolean literal:
  expression: "true" | "false"

For complex Informatica EXP logic that cannot be expressed in this DSL,
set ``expression: null`` and handle the column manually in the pattern's
``custom_transform`` hook (see DESIGN_PATTERN_LIBRARY.md).
"""
from __future__ import annotations

import ast
import logging
import re
from typing import Any

from etl_patterns.exceptions import ExpressionError
from etl_patterns.utils.null_safe import _is_null, coalesce, null_safe
from etl_patterns.utils.string_clean import (
    instr,
    lpad,
    ltrim,
    replace_chr,
    replace_str,
    rpad,
    rtrim,
    substr,
    to_lower,
    to_upper,
    trim,
)
from etl_patterns.utils.type_cast import type_cast

log = logging.getLogger(__name__)

# ── Regex helpers ─────────────────────────────────────────────────────────────

# Matches {COLUMN_NAME} placeholders (alphanumeric + underscore)
_COL_REF = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

# Function call at the start: func_name(...)
_FUNC_CALL = re.compile(r"^([a-z_][a-z0-9_]*)\s*\((.+)\)\s*$", re.IGNORECASE | re.DOTALL)


# ── Public API ────────────────────────────────────────────────────────────────

def evaluate(expression: Any, row: dict[str, Any]) -> Any:
    """
    Evaluate *expression* in the context of *row* (a dict of column→value).

    Parameters
    ----------
    expression  The expression string from the YAML config, or a scalar literal.
    row         Current row as a {column_name: value} dict.

    Returns
    -------
    Computed value for the column.

    Raises
    ------
    ExpressionError  If the expression cannot be evaluated.
    """
    if expression is None:
        return None

    # Non-string literals: int, float, bool
    if not isinstance(expression, str):
        return expression

    expr = expression.strip()

    # Boolean literals
    if expr.lower() == "true":
        return True
    if expr.lower() == "false":
        return False

    # Pure column reference: {COL}
    m = _COL_REF.fullmatch(expr)
    if m:
        col = m.group(1)
        if col not in row:
            raise ExpressionError(f"Column {col!r} not found in row")
        return row[col]

    # Function call
    fm = _FUNC_CALL.match(expr)
    if fm:
        func_name = fm.group(1).lower()
        args_str  = fm.group(2)
        return _call_function(func_name, args_str, row)

    # Arithmetic: contains operators after column substitution
    if any(op in expr for op in ("+", "-", "*", "/", "%")):
        return _eval_arithmetic(expr, row)

    # Bare string (no {placeholders}) — literal value
    if not _COL_REF.search(expr):
        # Try numeric parse first
        try:
            return ast.literal_eval(expr)
        except (ValueError, SyntaxError):
            return expr

    # String template with embedded column references but no function wrapper
    return _interpolate(expr, row)


def apply_column_map(column_map: list[dict], row: dict[str, Any]) -> dict[str, Any]:
    """
    Apply a full column_map config list to a single row dict.

    Parameters
    ----------
    column_map  List of {target_col, expression} dicts from the YAML config.
    row         Source row.

    Returns
    -------
    New dict with target column names and evaluated values.
    """
    result = {}
    for mapping in column_map:
        target = mapping.get("target_col") or mapping.get("target")
        expr   = mapping.get("expression")
        if not target:
            raise ExpressionError(f"column_map entry missing 'target_col': {mapping}")
        try:
            result[target] = evaluate(expr, row)
        except ExpressionError:
            raise
        except Exception as exc:
            raise ExpressionError(
                f"Error evaluating expression for {target!r}: {expr!r} — {exc}"
            ) from exc
    return result


# ── Internals ─────────────────────────────────────────────────────────────────

def _resolve_col(col_name: str, row: dict) -> Any:
    if col_name not in row:
        raise ExpressionError(f"Column {col_name!r} not found in row")
    return row[col_name]


def _call_function(func_name: str, args_str: str, row: dict) -> Any:
    """Dispatch a recognised function call."""
    # Resolve {COL} placeholders in args before splitting
    args_resolved = _COL_REF.sub(
        lambda m: repr(_resolve_col(m.group(1), row)), args_str
    )
    try:
        args, kwargs = _parse_args(args_resolved)
    except Exception as exc:
        raise ExpressionError(
            f"Cannot parse args for {func_name}({args_str}): {exc}"
        ) from exc

    # Dispatch table
    _FUNCTIONS = {
        "null_safe":    lambda a, k: null_safe(a[0], a[1], **k),
        "coalesce":     lambda a, k: coalesce(*a, **k),
        "nvl":          lambda a, k: null_safe(a[0], a[1]),
        "type_cast":    lambda a, k: type_cast(a[0], a[1], **k),
        "upper":        lambda a, k: to_upper(a[0]),
        "lower":        lambda a, k: to_lower(a[0]),
        "trim":         lambda a, k: trim(a[0]),
        "ltrim":        lambda a, k: ltrim(a[0]),
        "rtrim":        lambda a, k: rtrim(a[0]),
        "substr":       lambda a, k: substr(a[0], *a[1:]),
        "lpad":         lambda a, k: lpad(a[0], *a[1:]),
        "rpad":         lambda a, k: rpad(a[0], *a[1:]),
        "instr":        lambda a, k: instr(a[0], *a[1:]),
        "replace_chr":  lambda a, k: replace_chr(a[0], *a[1:]),
        "replace_str":  lambda a, k: replace_str(a[0], *a[1:]),
        "concat":       lambda a, k: "".join(str(v) for v in a if v is not None),
        "isnull":       lambda a, k: _is_null(a[0]),
        "iif":          lambda a, k: a[1] if a[0] else a[2],
    }

    fn = _FUNCTIONS.get(func_name)
    if fn is None:
        raise ExpressionError(
            f"Unknown expression function: {func_name!r}. "
            f"Supported: {sorted(_FUNCTIONS)}"
        )
    try:
        return fn(args, kwargs)
    except ExpressionError:
        raise
    except Exception as exc:
        raise ExpressionError(
            f"Error in {func_name}({args_str}): {exc}"
        ) from exc


def _eval_arithmetic(expr: str, row: dict) -> Any:
    """Evaluate a simple arithmetic expression with column substitutions."""
    # Substitute {COL} → numeric value
    def _sub(m: re.Match) -> str:
        val = _resolve_col(m.group(1), row)
        if _is_null(val):
            return "None"
        return str(val)

    substituted = _COL_REF.sub(_sub, expr)
    try:
        result = eval(substituted, {"__builtins__": {}})  # noqa: S307
        return result
    except Exception as exc:
        raise ExpressionError(
            f"Arithmetic expression failed: {expr!r} (substituted: {substituted!r}): {exc}"
        ) from exc


def _interpolate(expr: str, row: dict) -> str:
    """Replace {COL} placeholders with string representations."""
    def _sub(m: re.Match) -> str:
        val = _resolve_col(m.group(1), row)
        return "" if _is_null(val) else str(val)
    return _COL_REF.sub(_sub, expr)


def _parse_args(args_str: str) -> tuple[list, dict]:
    """
    Parse a comma-separated argument string into positional and keyword lists.
    Uses ast for safety — no arbitrary code execution.

    Handles:
      - String / numeric / bytes literals
      - Bare names: True/False/None (case-insensitive 'true'/'false'/'none')
    """
    # Normalise lowercase true/false/none → Python True/False/None
    normalised = re.sub(
        r"\b(true|false|none)\b",
        lambda m: m.group(0).capitalize(),
        args_str,
        flags=re.IGNORECASE,
    )
    try:
        tree = ast.parse(f"_f({normalised})", mode="eval")
    except SyntaxError as exc:
        raise ValueError(f"Invalid args: {args_str!r}") from exc

    call = tree.body  # type: ignore[attr-defined]
    positional = [_safe_eval_node(a) for a in call.args]
    keyword    = {kw.arg: _safe_eval_node(kw.value) for kw in call.keywords}
    return positional, keyword


def _safe_eval_node(node: ast.expr) -> Any:
    """Evaluate a single AST node as a safe literal."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        _name_map: dict[str, Any] = {"True": True, "False": False, "None": None}
        if node.id in _name_map:
            return _name_map[node.id]
    return ast.literal_eval(node)
