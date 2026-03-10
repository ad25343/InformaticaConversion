"""
tests/test_expression.py — Unit tests for expression evaluator
"""
from __future__ import annotations

import pytest

from etl_patterns.expression import apply_column_map, evaluate
from etl_patterns.exceptions import ExpressionError


ROW = {
    "FIRST": "Alice",
    "LAST":  "Smith",
    "AMT":   "123.45",
    "QTY":   3,
    "PRICE": 9.99,
    "CODE":  "  ABC  ",
    "NULL_COL": None,
}


class TestEvaluate:
    def test_literal_string(self):
        assert evaluate("ACTIVE", ROW) == "ACTIVE"

    def test_literal_int(self):
        assert evaluate(42, ROW) == 42

    def test_literal_true(self):
        assert evaluate("true", ROW) is True

    def test_literal_false(self):
        assert evaluate("false", ROW) is False

    def test_column_reference(self):
        assert evaluate("{FIRST}", ROW) == "Alice"

    def test_upper_function(self):
        assert evaluate("upper({FIRST})", ROW) == "ALICE"

    def test_lower_function(self):
        assert evaluate("lower({LAST})", ROW) == "smith"

    def test_trim_function(self):
        assert evaluate("trim({CODE})", ROW) == "ABC"

    def test_concat_function(self):
        result = evaluate("concat({FIRST}, ' ', {LAST})", ROW)
        assert result == "Alice Smith"

    def test_null_safe_function(self):
        assert evaluate("null_safe({NULL_COL}, 0)", ROW) == 0

    def test_iif_true_branch(self):
        # iif(condition, true_val, false_val) — with bool literal
        assert evaluate("iif(true, 'YES', 'NO')", ROW) == "YES"

    def test_iif_false_branch(self):
        assert evaluate("iif(false, 'YES', 'NO')", ROW) == "NO"

    def test_arithmetic_multiply(self):
        result = evaluate("{QTY} * {PRICE}", ROW)
        assert abs(result - 29.97) < 0.001

    def test_none_expression_returns_none(self):
        assert evaluate(None, ROW) is None

    def test_unknown_column_raises(self):
        with pytest.raises(ExpressionError):
            evaluate("{NONEXISTENT}", ROW)

    def test_unknown_function_raises(self):
        with pytest.raises(ExpressionError):
            evaluate("do_something({FIRST})", ROW)

    def test_coalesce_function(self):
        result = evaluate("coalesce({NULL_COL}, {FIRST}, 'UNKNOWN')", ROW)
        assert result == "Alice"

    def test_lpad_function(self):
        result = evaluate("lpad({FIRST}, 8, '_')", ROW)
        assert result == "___Alice"

    def test_substr_function(self):
        result = evaluate("substr({FIRST}, 2, 3)", ROW)
        assert result == "lic"


class TestApplyColumnMap:
    def test_basic_column_map(self):
        col_map = [
            {"target_col": "FULL_NAME",  "expression": "concat({FIRST}, ' ', {LAST})"},
            {"target_col": "AMOUNT",     "expression": "{AMT}"},
            {"target_col": "ACTIVE_FLAG","expression": "true"},
        ]
        result = apply_column_map(col_map, ROW)
        assert result["FULL_NAME"]   == "Alice Smith"
        assert result["AMOUNT"]      == "123.45"
        assert result["ACTIVE_FLAG"] is True

    def test_missing_target_col_raises(self):
        col_map = [{"expression": "{FIRST}"}]  # no target_col
        with pytest.raises(ExpressionError):
            apply_column_map(col_map, ROW)

    def test_null_expression_yields_none(self):
        col_map = [{"target_col": "X", "expression": None}]
        result = apply_column_map(col_map, ROW)
        assert result["X"] is None
