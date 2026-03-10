"""
tests/test_expression_transform.py — Tests for ExpressionTransformPattern
==========================================================================
Tests cover: column_map transforms, row filtering, deduplication, sorting,
and end-to-end flat-file → flat-file round-trips.
"""
from __future__ import annotations

import pytest
import pandas as pd

from etl_patterns.patterns.expression_transform import ExpressionTransformPattern
from etl_patterns.exceptions import ExpressionError


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_pattern(tmp_path, column_map, *, extra: dict | None = None):
    src = tmp_path / "src.csv"
    src.write_text("PLACEHOLDER\n")   # content irrelevant — transform() tested directly
    out = tmp_path / "out.csv"
    cfg = {
        "pattern":      "expression_transform",
        "mapping_name": "test_et",
        "source":  {"type": "flat_file", "path": str(src)},
        "target":  {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
        "column_map": column_map,
    }
    if extra:
        cfg.update(extra)
    return ExpressionTransformPattern(cfg)


SOURCE_DF = pd.DataFrame([
    {"FIRST": "Alice", "LAST": "Smith",  "STATUS": "A", "AMT": 100, "TS": "2024-01-10"},
    {"FIRST": "Bob",   "LAST": "Jones",  "STATUS": "I", "AMT": 200, "TS": "2024-01-05"},
    {"FIRST": "Carol", "LAST": "Lee",    "STATUS": "A", "AMT": 150, "TS": "2024-01-20"},
    {"FIRST": "Dave",  "LAST": "Brown",  "STATUS": "A", "AMT": 100, "TS": "2024-01-10"},
])


# ── column_map transform ───────────────────────────────────────────────────────

class TestColumnMap:
    def test_literal_column_passthrough(self, tmp_path):
        p = _make_pattern(tmp_path, [{"target_col": "NAME", "expression": "{FIRST}"}])
        result = p.transform(SOURCE_DF.copy())
        assert list(result["NAME"]) == ["Alice", "Bob", "Carol", "Dave"]

    def test_concat_expression(self, tmp_path):
        p = _make_pattern(
            tmp_path,
            [{"target_col": "FULL", "expression": "concat({FIRST}, ' ', {LAST})"}],
        )
        result = p.transform(SOURCE_DF.copy())
        assert result["FULL"].iloc[0] == "Alice Smith"

    def test_upper_expression(self, tmp_path):
        p = _make_pattern(tmp_path, [{"target_col": "UP", "expression": "upper({FIRST})"}])
        result = p.transform(SOURCE_DF.copy())
        assert list(result["UP"]) == ["ALICE", "BOB", "CAROL", "DAVE"]

    def test_arithmetic_expression(self, tmp_path):
        p = _make_pattern(tmp_path, [{"target_col": "DBL", "expression": "{AMT} * 2"}])
        result = p.transform(SOURCE_DF.copy())
        assert list(result["DBL"]) == [200, 400, 300, 200]

    def test_literal_true_expression(self, tmp_path):
        p = _make_pattern(tmp_path, [{"target_col": "FLAG", "expression": "true"}])
        result = p.transform(SOURCE_DF.copy())
        assert all(result["FLAG"])

    def test_iif_expression(self, tmp_path):
        p = _make_pattern(
            tmp_path,
            [{"target_col": "IS_A", "expression": "iif(true, 'YES', 'NO')"}],
        )
        result = p.transform(SOURCE_DF.copy())
        assert list(result["IS_A"]) == ["YES", "YES", "YES", "YES"]

    def test_null_expression_yields_none(self, tmp_path):
        p = _make_pattern(tmp_path, [{"target_col": "X", "expression": None}])
        result = p.transform(SOURCE_DF.copy())
        assert all(pd.isna(result["X"]))

    def test_multiple_columns(self, tmp_path):
        p = _make_pattern(tmp_path, [
            {"target_col": "A", "expression": "{FIRST}"},
            {"target_col": "B", "expression": "upper({LAST})"},
        ])
        result = p.transform(SOURCE_DF.copy())
        assert list(result.columns) == ["A", "B"]
        assert result["B"].iloc[1] == "JONES"

    def test_missing_column_map_raises(self, tmp_path):
        src = tmp_path / "s.csv"
        src.write_text("X\n1\n")
        cfg = {
            "pattern":      "expression_transform",
            "mapping_name": "no_map",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(tmp_path / "out.csv"),
                       "write_mode": "overwrite"},
            # no column_map key
        }
        with pytest.raises(ValueError, match="column_map"):
            ExpressionTransformPattern(cfg).transform(pd.DataFrame({"X": [1]}))


# ── Row filter ─────────────────────────────────────────────────────────────────

class TestRowFilter:
    def test_filter_keeps_matching_rows(self, tmp_path):
        p = _make_pattern(
            tmp_path,
            [{"target_col": "NAME", "expression": "{FIRST}"}],
            extra={"filter_expr": "{STATUS} == 'A'"},
        )
        result = p.transform(SOURCE_DF.copy())
        # Bob (STATUS=I) should be filtered out
        assert "Bob" not in list(result["NAME"])
        assert len(result) == 3

    def test_filter_removes_all_when_no_match(self, tmp_path):
        p = _make_pattern(
            tmp_path,
            [{"target_col": "NAME", "expression": "{FIRST}"}],
            extra={"filter_expr": "{STATUS} == 'Z'"},
        )
        result = p.transform(SOURCE_DF.copy())
        assert len(result) == 0

    def test_filter_keeps_all_when_all_match(self, tmp_path):
        p = _make_pattern(
            tmp_path,
            [{"target_col": "NAME", "expression": "{FIRST}"}],
            extra={"filter_expr": "true"},
        )
        result = p.transform(SOURCE_DF.copy())
        assert len(result) == len(SOURCE_DF)

    def test_filter_error_excludes_row(self, tmp_path):
        """If filter_expr raises for a row, that row is discarded (not a crash)."""
        p = _make_pattern(
            tmp_path,
            [{"target_col": "NAME", "expression": "{FIRST}"}],
            extra={"filter_expr": "{NONEXISTENT} == 'X'"},  # unknown column
        )
        result = p.transform(SOURCE_DF.copy())
        assert len(result) == 0   # all rows raise ExpressionError → all excluded


# ── Deduplication ─────────────────────────────────────────────────────────────

class TestDedup:
    def test_dedup_on_key(self, tmp_path):
        p = _make_pattern(
            tmp_path,
            [
                {"target_col": "FIRST", "expression": "{FIRST}"},
                {"target_col": "AMT",   "expression": "{AMT}"},
            ],
            extra={"dedup_keys": ["AMT"]},
        )
        result = p.transform(SOURCE_DF.copy())
        # AMT=100 appears twice (Alice and Dave) — only first kept
        assert list(result["AMT"].value_counts()) == [1, 1, 1]  # each value unique now
        assert len(result) == 3

    def test_dedup_no_duplicates_unchanged(self, tmp_path):
        p = _make_pattern(
            tmp_path,
            [{"target_col": "FIRST", "expression": "{FIRST}"}],
            extra={"dedup_keys": ["FIRST"]},
        )
        result = p.transform(SOURCE_DF.copy())
        assert len(result) == len(SOURCE_DF)  # all unique


# ── Sorting ───────────────────────────────────────────────────────────────────

class TestSort:
    def test_sort_ascending(self, tmp_path):
        p = _make_pattern(
            tmp_path,
            [
                {"target_col": "FIRST", "expression": "{FIRST}"},
                {"target_col": "AMT",   "expression": "{AMT}"},
            ],
            extra={"sort_by": [{"col": "AMT", "asc": True}]},
        )
        result = p.transform(SOURCE_DF.copy())
        assert result["AMT"].tolist() == sorted(result["AMT"].tolist())

    def test_sort_descending(self, tmp_path):
        p = _make_pattern(
            tmp_path,
            [
                {"target_col": "FIRST", "expression": "{FIRST}"},
                {"target_col": "AMT",   "expression": "{AMT}"},
            ],
            extra={"sort_by": [{"col": "AMT", "asc": False}]},
        )
        result = p.transform(SOURCE_DF.copy())
        assert result["AMT"].tolist() == sorted(result["AMT"].tolist(), reverse=True)

    def test_sort_unknown_column_ignored(self, tmp_path):
        p = _make_pattern(
            tmp_path,
            [{"target_col": "FIRST", "expression": "{FIRST}"}],
            extra={"sort_by": [{"col": "NONEXISTENT", "asc": True}]},
        )
        result = p.transform(SOURCE_DF.copy())
        assert len(result) == len(SOURCE_DF)   # no crash; order unchanged

    def test_sort_empty_spec_ignored(self, tmp_path):
        p = _make_pattern(
            tmp_path,
            [{"target_col": "FIRST", "expression": "{FIRST}"}],
            extra={"sort_by": []},
        )
        result = p.transform(SOURCE_DF.copy())
        assert len(result) == len(SOURCE_DF)


# ── Combined filter + map + sort + dedup ──────────────────────────────────────

class TestCombined:
    def test_filter_map_sort_dedup(self, tmp_path):
        p = _make_pattern(
            tmp_path,
            [
                {"target_col": "NAME", "expression": "concat({FIRST}, ' ', {LAST})"},
                {"target_col": "AMT",  "expression": "{AMT}"},
            ],
            extra={
                "filter_expr": "{STATUS} == 'A'",
                "sort_by":     [{"col": "AMT", "asc": True}],
                "dedup_keys":  ["AMT"],
            },
        )
        result = p.transform(SOURCE_DF.copy())
        # After filter: Alice(100), Carol(150), Dave(100) — Bob removed
        # After column_map: NAME, AMT
        # After dedup on AMT=100: Alice kept (first), Dave removed → Alice(100), Carol(150)
        # After sort by AMT asc: Alice(100), Carol(150)
        assert len(result) == 2
        assert list(result["AMT"]) == [100, 150]
        assert result["NAME"].iloc[0] == "Alice Smith"


# ── End-to-end flat-file round-trip ───────────────────────────────────────────

class TestEndToEnd:
    def test_csv_to_csv_transform(self, tmp_path):
        src = tmp_path / "src.csv"
        src.write_text(
            "CUST_ID,FIRST_NAME,LAST_NAME,BALANCE\n"
            "1,Alice,Smith,1000\n"
            "2,Bob,Jones,2000\n"
            "3,Carol,Lee,3000\n"
        )
        out = tmp_path / "out.csv"

        cfg = {
            "pattern":      "expression_transform",
            "mapping_name": "e2e_test",
            "source":  {"type": "flat_file", "path": str(src)},
            "target":  {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "column_map": [
                {"target_col": "ID",        "expression": "{CUST_ID}"},
                {"target_col": "FULL_NAME", "expression": "concat({FIRST_NAME}, ' ', {LAST_NAME})"},
                {"target_col": "CENTS",     "expression": "{BALANCE} * 100"},
            ],
            "sort_by": [{"col": "ID", "asc": True}],
        }

        pattern = ExpressionTransformPattern(cfg)
        result  = pattern.execute()

        assert result["status"]       == "success"
        assert result["rows_read"]    == 3
        assert result["rows_written"] == 3

        output = pd.read_csv(out)
        assert list(output.columns) == ["ID", "FULL_NAME", "CENTS"]
        assert list(output["FULL_NAME"]) == ["Alice Smith", "Bob Jones", "Carol Lee"]
        assert list(output["CENTS"])     == [100000, 200000, 300000]

    def test_csv_to_csv_with_filter(self, tmp_path):
        src = tmp_path / "src.csv"
        src.write_text(
            "NAME,STATUS,AMT\n"
            "Alice,A,100\n"
            "Bob,I,200\n"
            "Carol,A,300\n"
        )
        out = tmp_path / "out.csv"

        cfg = {
            "pattern":      "expression_transform",
            "mapping_name": "e2e_filter",
            "source":  {"type": "flat_file", "path": str(src)},
            "target":  {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "column_map":  [{"target_col": "NAME", "expression": "{NAME}"},
                            {"target_col": "AMT",  "expression": "{AMT}"}],
            "filter_expr": "{STATUS} == 'A'",
        }

        pattern = ExpressionTransformPattern(cfg)
        result  = pattern.execute()

        assert result["rows_written"] == 2
        output = pd.read_csv(out)
        assert list(output["NAME"]) == ["Alice", "Carol"]

    def test_empty_source_produces_empty_target(self, tmp_path):
        src = tmp_path / "empty.csv"
        src.write_text("NAME,AMT\n")
        out = tmp_path / "out.csv"

        cfg = {
            "pattern":      "expression_transform",
            "mapping_name": "e2e_empty",
            "source":  {"type": "flat_file", "path": str(src)},
            "target":  {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "column_map": [{"target_col": "NAME", "expression": "{NAME}"}],
        }

        pattern = ExpressionTransformPattern(cfg)
        result  = pattern.execute()

        assert result["status"]       == "success"
        assert result["rows_read"]    == 0
        assert result["rows_written"] == 0
