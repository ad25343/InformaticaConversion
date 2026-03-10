"""
tests/test_phase4_patterns.py — Tests for AggregationLoadPattern,
                                 FilterAndRoutePattern, UnionConsolidatePattern
================================================================================
All DB tests use SQLite in-memory with StaticPool.
Flat-file tests use pytest tmp_path.
"""
from __future__ import annotations

import pandas as pd
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool

from etl_patterns.exceptions import ConfigError
from etl_patterns.patterns.aggregation_load import AggregationLoadPattern
from etl_patterns.patterns.filter_and_route import FilterAndRoutePattern
from etl_patterns.patterns.union_consolidate import UnionConsolidatePattern


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _bare_aggregation(cfg: dict) -> AggregationLoadPattern:
    """Bypass IO wiring and return an AggregationLoadPattern with config set."""
    p = object.__new__(AggregationLoadPattern)
    p._cfg    = cfg
    p._name   = cfg.get("mapping_name", "test_agg")
    p._reader = None
    p._writer = None
    p._writers = []
    return p


def _bare_far(cfg: dict) -> FilterAndRoutePattern:
    """Bypass IO wiring for FilterAndRoutePattern."""
    p = object.__new__(FilterAndRoutePattern)
    p._cfg    = cfg
    p._name   = cfg.get("mapping_name", "test_far")
    p._reader = None
    p._writer = None
    p._writers = []
    return p


def _sqlite_engine():
    return create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# AGGREGATION LOAD PATTERN
# ═══════════════════════════════════════════════════════════════════════════════

class TestAggregationLoadPattern:
    """Unit tests for AggregationLoadPattern.transform() and pre_load()."""

    def _sample_df(self) -> pd.DataFrame:
        return pd.DataFrame({
            "BRANCH_ID": ["B1", "B1", "B1", "B2", "B2"],
            "TXN_DATE":  ["2024-01-01", "2024-01-01", "2024-01-02",
                          "2024-01-01", "2024-01-02"],
            "TXN_ID":    [1, 2, 3, 4, 5],
            "AMOUNT":    [100.0, 200.0, 300.0, 50.0, 75.0],
            "CUST_ID":   ["C1", "C2", "C1", "C3", "C3"],
        })

    def _base_cfg(self, **extra) -> dict:
        return {
            "mapping_name": "test_agg",
            "group_by":     ["BRANCH_ID"],
            "aggregations": [
                {"target_col": "TXN_COUNT", "func": "count",  "source_col": "TXN_ID"},
                {"target_col": "TOTAL_AMT", "func": "sum",    "source_col": "AMOUNT"},
            ],
            **extra,
        }

    # ── pre_load validations ──────────────────────────────────────────────────

    def test_missing_group_by_raises(self):
        p = _bare_aggregation({"mapping_name": "x", "aggregations": [
            {"target_col": "C", "func": "count", "source_col": "X"}
        ]})
        with pytest.raises(ConfigError, match="group_by"):
            p.pre_load()

    def test_empty_aggregations_raises(self):
        p = _bare_aggregation({"mapping_name": "x", "group_by": ["A"]})
        with pytest.raises(ConfigError, match="aggregations"):
            p.pre_load()

    def test_unknown_function_raises(self):
        p = _bare_aggregation({"mapping_name": "x", "group_by": ["A"],
                                "aggregations": [
                                    {"target_col": "C", "func": "bogus", "source_col": "A"}
                                ]})
        with pytest.raises(ConfigError, match="bogus"):
            p.pre_load()

    def test_valid_config_does_not_raise(self):
        p = _bare_aggregation(self._base_cfg())
        p.pre_load()   # should not raise

    # ── transform: basic aggregation ─────────────────────────────────────────

    def test_basic_count_and_sum(self):
        p = _bare_aggregation(self._base_cfg())
        result = p.transform(self._sample_df())
        assert set(result.columns) == {"BRANCH_ID", "TXN_COUNT", "TOTAL_AMT"}
        b1 = result[result["BRANCH_ID"] == "B1"].iloc[0]
        assert b1["TXN_COUNT"] == 3
        assert b1["TOTAL_AMT"] == pytest.approx(600.0)
        b2 = result[result["BRANCH_ID"] == "B2"].iloc[0]
        assert b2["TXN_COUNT"] == 2
        assert b2["TOTAL_AMT"] == pytest.approx(125.0)

    def test_avg_function(self):
        p = _bare_aggregation({
            "mapping_name": "x",
            "group_by": ["BRANCH_ID"],
            "aggregations": [
                {"target_col": "AVG_AMT", "func": "avg", "source_col": "AMOUNT"},
            ],
        })
        result = p.transform(self._sample_df())
        b1_avg = result[result["BRANCH_ID"] == "B1"]["AVG_AMT"].iloc[0]
        assert b1_avg == pytest.approx(200.0)

    def test_nunique_function(self):
        p = _bare_aggregation({
            "mapping_name": "x",
            "group_by": ["BRANCH_ID"],
            "aggregations": [
                {"target_col": "UNIQ_CUST", "func": "nunique", "source_col": "CUST_ID"},
            ],
        })
        result = p.transform(self._sample_df())
        b1 = result[result["BRANCH_ID"] == "B1"]["UNIQ_CUST"].iloc[0]
        assert b1 == 2   # C1 and C2

    def test_multi_group_by(self):
        p = _bare_aggregation({
            "mapping_name": "x",
            "group_by": ["BRANCH_ID", "TXN_DATE"],
            "aggregations": [
                {"target_col": "CNT", "func": "count", "source_col": "TXN_ID"},
            ],
        })
        result = p.transform(self._sample_df())
        # B1 has 2 dates: 2024-01-01 (2 rows) and 2024-01-02 (1 row)
        assert len(result) == 4

    def test_having_filter(self):
        p = _bare_aggregation({
            "mapping_name": "x",
            "group_by": ["BRANCH_ID"],
            "aggregations": [
                {"target_col": "TXN_COUNT", "func": "count", "source_col": "TXN_ID"},
            ],
            "having": "{TXN_COUNT} > 2",
        })
        result = p.transform(self._sample_df())
        # Only B1 has count > 2 (count=3); B2 has count=2 → excluded
        assert len(result) == 1
        assert result.iloc[0]["BRANCH_ID"] == "B1"

    def test_sort_by(self):
        p = _bare_aggregation({
            "mapping_name": "x",
            "group_by": ["BRANCH_ID"],
            "aggregations": [
                {"target_col": "TOTAL_AMT", "func": "sum", "source_col": "AMOUNT"},
            ],
            "sort_by": [{"col": "TOTAL_AMT", "asc": False}],
        })
        result = p.transform(self._sample_df())
        # B1 total=600, B2 total=125 → B1 should be first (descending)
        assert result.iloc[0]["BRANCH_ID"] == "B1"

    def test_empty_dataframe_returns_correct_columns(self):
        p = _bare_aggregation(self._base_cfg())
        empty = pd.DataFrame(columns=["BRANCH_ID", "TXN_ID", "AMOUNT"])
        result = p.transform(empty)
        assert result.empty
        assert "TXN_COUNT" in result.columns
        assert "TOTAL_AMT" in result.columns

    def test_missing_source_col_raises(self):
        p = _bare_aggregation({
            "mapping_name": "x",
            "group_by": ["BRANCH_ID"],
            "aggregations": [
                {"target_col": "X", "func": "sum", "source_col": "NO_SUCH_COL"},
            ],
        })
        df = pd.DataFrame({"BRANCH_ID": ["B1"], "AMOUNT": [1.0]})
        with pytest.raises(ConfigError, match="column not found"):
            p.transform(df)

    # ── end-to-end via flat file ──────────────────────────────────────────────

    def test_end_to_end_flat_file(self, tmp_path):
        src = tmp_path / "txn.csv"
        src.write_text(
            "BRANCH_ID,TXN_ID,AMOUNT\n"
            "B1,1,100\nB1,2,200\nB2,3,50\n"
        )
        out = tmp_path / "agg.csv"
        cfg = {
            "pattern": "aggregation_load",
            "mapping_name": "e2e_agg",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "group_by": ["BRANCH_ID"],
            "aggregations": [
                {"target_col": "TOTAL", "func": "sum", "source_col": "AMOUNT"},
            ],
            "etl_metadata": False,
        }
        result = AggregationLoadPattern(cfg).execute()
        assert result["status"] == "success"
        df = pd.read_csv(out)
        assert len(df) == 2
        b1 = df[df["BRANCH_ID"] == "B1"]["TOTAL"].iloc[0]
        assert b1 == pytest.approx(300.0)


# ═══════════════════════════════════════════════════════════════════════════════
# FILTER AND ROUTE PATTERN
# ═══════════════════════════════════════════════════════════════════════════════

class TestFilterAndRoutePattern:
    """Tests for FilterAndRoutePattern."""

    def _sample_df(self) -> pd.DataFrame:
        return pd.DataFrame({
            "TXN_ID":   [1, 2, 3, 4, 5],
            "TXN_TYPE": ["SALE", "REFUND", "SALE", "REFUND", "SALE"],
            "AMOUNT":   [100.0, -50.0, 15000.0, -200.0, 500.0],
        })

    # ── pre_load validations ──────────────────────────────────────────────────

    def test_target_not_list_raises(self):
        p = _bare_far({
            "mapping_name": "x",
            "target": {"type": "flat_file", "path": "/tmp/x.csv", "filter_expr": "true"},
        })
        with pytest.raises(ConfigError, match="list"):
            p.pre_load()

    def test_missing_filter_expr_raises(self):
        p = _bare_far({
            "mapping_name": "x",
            "target": [
                {"name": "A", "type": "flat_file", "path": "/tmp/a.csv", "filter_expr": "true"},
                {"name": "B", "type": "flat_file", "path": "/tmp/b.csv"},  # missing
            ],
        })
        with pytest.raises(ConfigError, match="filter_expr"):
            p.pre_load()

    def test_empty_target_list_raises(self):
        p = _bare_far({"mapping_name": "x", "target": []})
        with pytest.raises(ConfigError, match="at least one"):
            p.pre_load()

    def test_valid_config_passes(self):
        p = _bare_far({
            "mapping_name": "x",
            "target": [{"name": "A", "filter_expr": "true"}],
        })
        p.pre_load()   # should not raise

    # ── _filter_rows ──────────────────────────────────────────────────────────

    def test_filter_rows_numeric_comparison(self):
        p = _bare_far({"mapping_name": "x", "target": []})
        df = self._sample_df()
        result = p._filter_rows(df, "{AMOUNT} > 1000", "HIGH")
        assert len(result) == 1
        assert result.iloc[0]["TXN_ID"] == 3

    def test_filter_rows_string_comparison(self):
        p = _bare_far({"mapping_name": "x", "target": []})
        df = self._sample_df()
        result = p._filter_rows(df, "{TXN_TYPE} == 'REFUND'", "REFUNDS")
        assert len(result) == 2

    def test_filter_rows_literal_true(self):
        p = _bare_far({"mapping_name": "x", "target": []})
        df = self._sample_df()
        result = p._filter_rows(df, "true", "ALL")
        assert len(result) == len(df)

    def test_filter_rows_literal_false(self):
        p = _bare_far({"mapping_name": "x", "target": []})
        df = self._sample_df()
        result = p._filter_rows(df, "false", "NONE")
        assert result.empty

    def test_filter_rows_bool_python_true(self):
        """Test non-string Python True (e.g. YAML parsed bool)."""
        p = _bare_far({"mapping_name": "x", "target": []})
        df = self._sample_df()
        result = p._filter_rows(df, True, "ALL")
        assert len(result) == len(df)

    def test_filter_rows_bad_expr_excludes_row(self):
        """Rows that raise on filter_expr evaluation are excluded."""
        p = _bare_far({"mapping_name": "x", "target": []})
        df = pd.DataFrame({"TXN_ID": [1, 2]})
        # Expression references a column that doesn't exist
        result = p._filter_rows(df, "{NO_COL} > 0", "X")
        assert result.empty

    # ── _write routing ────────────────────────────────────────────────────────

    def test_routing_to_multiple_flat_files(self, tmp_path):
        """End-to-end: 2 targets — SALE and REFUND files."""
        src = tmp_path / "txn.csv"
        src.write_text("TXN_ID,TXN_TYPE,AMOUNT\n1,SALE,100\n2,REFUND,-50\n3,SALE,200\n")
        sale_out   = tmp_path / "sales.csv"
        refund_out = tmp_path / "refunds.csv"

        cfg = {
            "pattern": "filter_and_route",
            "mapping_name": "route_test",
            "source": {"type": "flat_file", "path": str(src)},
            "target": [
                {
                    "name": "SALES", "type": "flat_file",
                    "path": str(sale_out), "write_mode": "overwrite",
                    "filter_expr": "{TXN_TYPE} == 'SALE'",
                },
                {
                    "name": "REFUNDS", "type": "flat_file",
                    "path": str(refund_out), "write_mode": "overwrite",
                    "filter_expr": "{TXN_TYPE} == 'REFUND'",
                },
            ],
            "etl_metadata": False,
        }

        result = FilterAndRoutePattern(cfg).execute()
        assert result["status"] == "success"
        assert result["rows_read"] == 3

        sales   = pd.read_csv(sale_out)
        refunds = pd.read_csv(refund_out)
        assert len(sales)   == 2
        assert len(refunds) == 1
        assert all(sales["TXN_TYPE"] == "SALE")
        assert all(refunds["TXN_TYPE"] == "REFUND")

    def test_routing_with_column_map(self, tmp_path):
        """Per-target column_map is applied before writing."""
        src = tmp_path / "txn.csv"
        src.write_text("TXN_ID,TXN_TYPE,AMOUNT\n1,REFUND,-50\n2,SALE,100\n")
        out = tmp_path / "refunds_mapped.csv"

        cfg = {
            "pattern": "filter_and_route",
            "mapping_name": "route_map_test",
            "source": {"type": "flat_file", "path": str(src)},
            "target": [
                {
                    "name": "REFUNDS", "type": "flat_file",
                    "path": str(out), "write_mode": "overwrite",
                    "filter_expr": "{TXN_TYPE} == 'REFUND'",
                    "column_map": [
                        {"target_col": "REF_ID",  "expression": "{TXN_ID}"},
                        {"target_col": "REF_AMT", "expression": "{AMOUNT}"},
                    ],
                },
            ],
            "etl_metadata": False,
        }

        FilterAndRoutePattern(cfg).execute()
        df = pd.read_csv(out)
        assert list(df.columns) == ["REF_ID", "REF_AMT"]
        assert df.iloc[0]["REF_ID"] == 1

    def test_catch_all_target(self, tmp_path):
        """A target with filter_expr='true' receives all rows."""
        src = tmp_path / "txn.csv"
        src.write_text("TXN_ID,AMOUNT\n1,100\n2,200\n3,300\n")
        all_out  = tmp_path / "all.csv"
        high_out = tmp_path / "high.csv"

        cfg = {
            "pattern": "filter_and_route",
            "mapping_name": "catch_all_test",
            "source": {"type": "flat_file", "path": str(src)},
            "target": [
                {
                    "name": "ALL", "type": "flat_file",
                    "path": str(all_out), "write_mode": "overwrite",
                    "filter_expr": "true",
                },
                {
                    "name": "HIGH", "type": "flat_file",
                    "path": str(high_out), "write_mode": "overwrite",
                    "filter_expr": "{AMOUNT} >= 200",
                },
            ],
            "etl_metadata": False,
        }
        FilterAndRoutePattern(cfg).execute()
        assert len(pd.read_csv(all_out))  == 3
        assert len(pd.read_csv(high_out)) == 2

    def test_no_match_skips_write(self, tmp_path):
        """Targets with zero matching rows do not create output files."""
        src = tmp_path / "txn.csv"
        src.write_text("TXN_ID,AMOUNT\n1,10\n")
        empty_out = tmp_path / "empty.csv"

        cfg = {
            "pattern": "filter_and_route",
            "mapping_name": "no_match",
            "source": {"type": "flat_file", "path": str(src)},
            "target": [
                {
                    "name": "HIGH", "type": "flat_file",
                    "path": str(empty_out), "write_mode": "overwrite",
                    "filter_expr": "{AMOUNT} > 9999",
                },
            ],
            "etl_metadata": False,
        }
        result = FilterAndRoutePattern(cfg).execute()
        assert result["rows_written"] == 0
        assert not empty_out.exists()


# ═══════════════════════════════════════════════════════════════════════════════
# UNION CONSOLIDATE PATTERN
# ═══════════════════════════════════════════════════════════════════════════════

class TestUnionConsolidatePattern:
    """Tests for UnionConsolidatePattern."""

    # ── constructor / config validation ──────────────────────────────────────

    def test_empty_sources_raises(self, tmp_path):
        out = tmp_path / "out.csv"
        with pytest.raises(ConfigError, match="sources"):
            UnionConsolidatePattern({
                "pattern": "union_consolidate",
                "mapping_name": "bad",
                "sources": [],
                "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            })

    def test_no_sources_key_raises(self, tmp_path):
        out = tmp_path / "out.csv"
        with pytest.raises((ConfigError, KeyError)):
            UnionConsolidatePattern({
                "pattern": "union_consolidate",
                "mapping_name": "bad",
                "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            })

    # ── transform: dedup ──────────────────────────────────────────────────────

    def test_dedup_removes_duplicates(self):
        p = object.__new__(UnionConsolidatePattern)
        p._cfg  = {"mapping_name": "x", "dedup_keys": ["ID"]}
        p._name = "x"
        df = pd.DataFrame({"ID": [1, 2, 1, 3], "VAL": ["a", "b", "c", "d"]})
        result = p.transform(df)
        assert len(result) == 3
        # First occurrence of ID=1 kept
        assert result[result["ID"] == 1]["VAL"].iloc[0] == "a"

    def test_dedup_string_key_coerced_to_list(self):
        """dedup_keys as a bare string should still work."""
        p = object.__new__(UnionConsolidatePattern)
        p._cfg  = {"mapping_name": "x", "dedup_keys": "ID"}
        p._name = "x"
        df = pd.DataFrame({"ID": [1, 1, 2]})
        result = p.transform(df)
        assert len(result) == 2

    def test_sort_by_applied(self):
        p = object.__new__(UnionConsolidatePattern)
        p._cfg  = {"mapping_name": "x", "sort_by": [{"col": "VAL", "asc": False}]}
        p._name = "x"
        df = pd.DataFrame({"VAL": [1, 3, 2]})
        result = p.transform(df)
        assert list(result["VAL"]) == [3, 2, 1]

    # ── _combine ──────────────────────────────────────────────────────────────

    def test_combine_concatenates(self):
        p = object.__new__(UnionConsolidatePattern)
        p._cfg  = {"mapping_name": "x"}
        p._name = "x"
        f1 = pd.DataFrame({"ID": [1, 2]})
        f2 = pd.DataFrame({"ID": [3, 4]})
        result = p._combine([f1, f2])
        assert list(result["ID"]) == [1, 2, 3, 4]

    def test_combine_all_empty_returns_empty(self):
        p = object.__new__(UnionConsolidatePattern)
        p._cfg  = {"mapping_name": "x"}
        p._name = "x"
        empty = pd.DataFrame(columns=["ID"])
        result = p._combine([empty, empty])
        assert result.empty

    def test_combine_ignores_empty_frames(self):
        p = object.__new__(UnionConsolidatePattern)
        p._cfg  = {"mapping_name": "x"}
        p._name = "x"
        f1 = pd.DataFrame({"ID": [1]})
        empty = pd.DataFrame(columns=["ID"])
        result = p._combine([f1, empty])
        assert len(result) == 1

    # ── end-to-end ────────────────────────────────────────────────────────────

    def test_end_to_end_two_flat_files(self, tmp_path):
        """Two CSVs with identical schema are unioned into one output."""
        src_a = tmp_path / "a.csv"
        src_b = tmp_path / "b.csv"
        src_a.write_text("ID,NAME\n1,Alice\n2,Bob\n")
        src_b.write_text("ID,NAME\n3,Carol\n4,Dave\n")
        out = tmp_path / "union.csv"

        cfg = {
            "pattern": "union_consolidate",
            "mapping_name": "union_e2e",
            "sources": [
                {"type": "flat_file", "path": str(src_a)},
                {"type": "flat_file", "path": str(src_b)},
            ],
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "etl_metadata": False,
        }
        result = UnionConsolidatePattern(cfg).execute()
        assert result["status"] == "success"
        assert result["rows_read"] == 4
        df = pd.read_csv(out)
        assert len(df) == 4
        assert set(df["NAME"]) == {"Alice", "Bob", "Carol", "Dave"}

    def test_end_to_end_with_column_map(self, tmp_path):
        """Per-source column_map normalises schema before union."""
        src_a = tmp_path / "a.csv"
        src_b = tmp_path / "b.csv"
        src_a.write_text("ACCOUNT_ID,ACCOUNT_NAME\n1,Alpha\n")
        src_b.write_text("ACCT_NO,ACCT_NAME\n2,Beta\n")
        out = tmp_path / "union.csv"

        cfg = {
            "pattern": "union_consolidate",
            "mapping_name": "schema_norm",
            "sources": [
                {
                    "type": "flat_file", "path": str(src_a),
                    "column_map": [
                        {"target_col": "ID",   "expression": "{ACCOUNT_ID}"},
                        {"target_col": "NAME", "expression": "{ACCOUNT_NAME}"},
                    ],
                },
                {
                    "type": "flat_file", "path": str(src_b),
                    "column_map": [
                        {"target_col": "ID",   "expression": "{ACCT_NO}"},
                        {"target_col": "NAME", "expression": "{ACCT_NAME}"},
                    ],
                },
            ],
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "etl_metadata": False,
        }
        UnionConsolidatePattern(cfg).execute()
        df = pd.read_csv(out)
        assert list(sorted(df.columns)) == ["ID", "NAME"]
        assert set(df["NAME"]) == {"Alpha", "Beta"}

    def test_end_to_end_with_dedup_and_sort(self, tmp_path):
        """Dedup and sort applied after union."""
        src_a = tmp_path / "a.csv"
        src_b = tmp_path / "b.csv"
        src_a.write_text("ID,SCORE\n1,90\n2,80\n")
        src_b.write_text("ID,SCORE\n2,99\n3,70\n")   # ID=2 is a duplicate
        out = tmp_path / "union.csv"

        cfg = {
            "pattern": "union_consolidate",
            "mapping_name": "dedup_sort",
            "sources": [
                {"type": "flat_file", "path": str(src_a)},
                {"type": "flat_file", "path": str(src_b)},
            ],
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "dedup_keys": ["ID"],
            "sort_by":    [{"col": "SCORE", "asc": False}],
            "etl_metadata": False,
        }
        UnionConsolidatePattern(cfg).execute()
        df = pd.read_csv(out)
        assert len(df) == 3           # duplicate ID=2 removed
        assert list(df["SCORE"]) == [90, 80, 70]   # descending

    def test_end_to_end_with_database_source(self, tmp_path):
        """One source is a file-based SQLite table; other is a CSV."""
        db_path  = tmp_path / "test_src.db"
        conn_str = f"sqlite:///{db_path}"
        engine   = create_engine(conn_str)
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE SRC_DB (ID INTEGER, NAME TEXT)"))
            conn.execute(text("INSERT INTO SRC_DB VALUES (10, 'DBAlice')"))
            conn.execute(text("INSERT INTO SRC_DB VALUES (20, 'DBBob')"))
        engine.dispose()

        src_csv = tmp_path / "csv_src.csv"
        src_csv.write_text("ID,NAME\n30,FileCarol\n")
        out = tmp_path / "union_db.csv"

        cfg = {
            "pattern": "union_consolidate",
            "mapping_name": "db_union",
            "sources": [
                {
                    "type": "database",
                    "connection_string": conn_str,
                    "query": "SELECT ID, NAME FROM SRC_DB",
                },
                {
                    "type": "flat_file",
                    "path": str(src_csv),
                },
            ],
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "sort_by": [{"col": "ID", "asc": True}],
            "etl_metadata": False,
        }
        result = UnionConsolidatePattern(cfg).execute()
        assert result["status"] == "success"
        df = pd.read_csv(out)
        assert len(df) == 3
        assert list(df["ID"]) == [10, 20, 30]
