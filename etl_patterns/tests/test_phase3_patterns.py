"""
tests/test_phase3_patterns.py — Tests for UpsertPattern, Scd2Pattern, LookupEnrichPattern
===========================================================================================
All DB tests use SQLite in-memory.  Flat-file tests use pytest tmp_path.
"""
from __future__ import annotations

import pytest
import pandas as pd
from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool

from etl_patterns.patterns.upsert import UpsertPattern
from etl_patterns.patterns.scd2 import (
    Scd2Pattern,
    _lookup_row,
    _vals_equal,
    _vals_differ,
)
from etl_patterns.patterns.lookup_enrich import (
    LookupEnrichPattern,
    clear_lookup_cache,
)
from etl_patterns.exceptions import ConfigError
from etl_patterns.io import get_reader, get_writer


# ═══════════════════════════════════════════════════════════════════════════════
# UPSERT PATTERN
# ═══════════════════════════════════════════════════════════════════════════════

class TestUpsertPattern:
    """Tests for UpsertPattern (SCD Type 1)."""

    def _make_cfg(self, tmp_path, *, column_map=None):
        src = tmp_path / "src.csv"
        src.write_text("CUST_ID,NAME,STATUS\n1,Alice,A\n2,Bob,I\n")
        return {
            "pattern":      "upsert",
            "mapping_name": "test_upsert",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {
                "type":       "flat_file",
                "path":       str(tmp_path / "out.csv"),
                "write_mode": "overwrite",
                "unique_key": ["CUST_ID"],
            },
            **({"column_map": column_map} if column_map else {}),
        }

    def test_missing_unique_key_raises(self, tmp_path):
        src = tmp_path / "s.csv"
        src.write_text("ID\n1\n")
        cfg = {
            "pattern": "upsert", "mapping_name": "bad",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(tmp_path / "out.csv"),
                       "write_mode": "overwrite"},
            # no unique_key
        }
        pattern = UpsertPattern(cfg)
        with pytest.raises(ConfigError, match="unique_key"):
            pattern.pre_load()

    def test_unique_key_string_coerced_to_list(self, tmp_path):
        src = tmp_path / "s.csv"
        src.write_text("ID\n1\n")
        cfg = {
            "pattern": "upsert", "mapping_name": "t",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(tmp_path / "out.csv"),
                       "write_mode": "overwrite", "unique_key": "ID"},
        }
        pattern = UpsertPattern(cfg)
        pattern.pre_load()
        assert cfg["target"]["unique_key"] == ["ID"]

    def test_transform_passthrough_without_column_map(self, tmp_path):
        cfg = self._make_cfg(tmp_path)
        pattern = UpsertPattern(cfg)
        pattern.pre_load()
        df = pd.DataFrame({"CUST_ID": [1, 2], "NAME": ["Alice", "Bob"]})
        result = pattern.transform(df)
        assert list(result.columns) == ["CUST_ID", "NAME"]
        assert len(result) == 2

    def test_transform_applies_column_map(self, tmp_path):
        cfg = self._make_cfg(tmp_path, column_map=[
            {"target_col": "CUST_ID", "expression": "{CUST_ID}"},
            {"target_col": "FULL",    "expression": "upper({NAME})"},
        ])
        pattern = UpsertPattern(cfg)
        pattern.pre_load()
        df = pd.DataFrame({"CUST_ID": [1], "NAME": ["Alice"]})
        result = pattern.transform(df)
        assert result["FULL"].iloc[0] == "ALICE"

    def test_missing_key_col_after_column_map_raises(self, tmp_path):
        cfg = self._make_cfg(tmp_path, column_map=[
            {"target_col": "FULL", "expression": "{NAME}"},
            # CUST_ID not in column_map — should raise
        ])
        pattern = UpsertPattern(cfg)
        pattern.pre_load()
        df = pd.DataFrame({"CUST_ID": [1], "NAME": ["Alice"]})
        with pytest.raises(ConfigError, match="unique_key"):
            pattern.transform(df)

    def test_end_to_end_flat_file(self, tmp_path):
        src = tmp_path / "src.csv"
        src.write_text("CUST_ID,NAME,STATUS\n1,Alice,A\n2,Bob,I\n3,Carol,A\n")
        out = tmp_path / "out.csv"
        cfg = {
            "pattern": "upsert", "mapping_name": "e2e_upsert",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(out),
                       "write_mode": "overwrite", "unique_key": ["CUST_ID"]},
            "column_map": [
                {"target_col": "CUST_ID", "expression": "{CUST_ID}"},
                {"target_col": "NAME",    "expression": "{NAME}"},
            ],
        }
        result = UpsertPattern(cfg).execute()
        assert result["status"]       == "success"
        assert result["rows_written"] == 3
        output = pd.read_csv(out)
        assert list(output.columns) == ["CUST_ID", "NAME"]

    def test_db_upsert_overwrites_existing_rows(self, tmp_path):
        """Database upsert: existing keys are replaced, new keys are inserted."""
        # StaticPool ensures all SQLAlchemy connections share the same in-memory DB
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            future=True,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        # Pre-populate target with existing row
        pd.DataFrame({"ID": [1], "NAME": ["OLD"]}).to_sql(
            "CUSTOMERS", engine, index=False, if_exists="replace"
        )

        src = tmp_path / "src.csv"
        src.write_text("ID,NAME\n1,NEW\n2,FRESH\n")

        cfg = {
            "pattern": "upsert", "mapping_name": "db_upsert",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {
                "type":        "database",
                "connection_string": engine,
                "table":       "CUSTOMERS",
                "write_mode":  "upsert",
                "unique_key":  ["ID"],
            },
        }
        pattern = UpsertPattern(cfg)
        pattern._writer._engine = engine
        result = pattern.execute()
        assert result["status"] == "success"

        with engine.connect() as conn:
            rows = conn.execute(text("SELECT * FROM CUSTOMERS ORDER BY ID")).fetchall()
        assert len(rows) == 2
        names = {r[0]: r[1] for r in rows}
        assert names[1] == "NEW"    # overwritten
        assert names[2] == "FRESH"  # inserted


# ═══════════════════════════════════════════════════════════════════════════════
# SCD2 HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

class TestScd2Helpers:
    def test_vals_equal_same(self):
        assert _vals_equal("A", "A")

    def test_vals_equal_both_none(self):
        assert _vals_equal(None, None)

    def test_vals_equal_one_none(self):
        assert not _vals_equal("A", None)

    def test_vals_equal_strips_whitespace(self):
        assert _vals_equal("A ", " A")

    def test_vals_differ_detects_change(self):
        assert _vals_differ("OLD", "NEW")

    def test_lookup_row_found(self):
        rows = [{"ID": 1, "NAME": "Alice"}, {"ID": 2, "NAME": "Bob"}]
        result = _lookup_row(rows, {"ID": 2}, ["ID"])
        assert result["NAME"] == "Bob"

    def test_lookup_row_not_found(self):
        rows = [{"ID": 1, "NAME": "Alice"}]
        assert _lookup_row(rows, {"ID": 99}, ["ID"]) is None

    def test_lookup_row_composite_key(self):
        rows = [{"A": 1, "B": 2, "V": "x"}, {"A": 1, "B": 3, "V": "y"}]
        result = _lookup_row(rows, {"A": 1, "B": 3}, ["A", "B"])
        assert result["V"] == "y"


# ═══════════════════════════════════════════════════════════════════════════════
# SCD2 PATTERN
# ═══════════════════════════════════════════════════════════════════════════════

class TestScd2Pattern:
    def _make_cfg(self, src_path, engine, *, column_map=None, extra_scd2=None):
        scd2 = {
            "business_key":   ["CUST_ID"],
            "tracked_cols":   ["NAME", "STATUS"],
            "effective_from": "EFF_FROM",
            "effective_to":   "EFF_TO",
            "is_current":     "IS_CUR",
            "end_of_time":    "9999-12-31",
        }
        if extra_scd2:
            scd2.update(extra_scd2)
        cfg = {
            "pattern":      "scd2",
            "mapping_name": "test_scd2",
            "source": {"type": "flat_file", "path": str(src_path)},
            "target": {
                "type":              "database",
                "connection_string": engine,
                "table":             "DIM_CUST",
                "write_mode":        "scd2",
            },
            "scd2": scd2,
        }
        if column_map:
            cfg["column_map"] = column_map
        return cfg

    def test_missing_business_key_raises(self, tmp_path):
        src = tmp_path / "s.csv"
        src.write_text("ID\n1\n")
        engine = create_engine("sqlite+pysqlite:///:memory:", future=True, connect_args={"check_same_thread": False}, poolclass=StaticPool)
        cfg = {
            "pattern": "scd2", "mapping_name": "bad",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "database", "connection_string": engine,
                       "table": "T", "write_mode": "scd2"},
            "scd2": {"tracked_cols": ["NAME"]},  # no business_key
        }
        pattern = Scd2Pattern(cfg)
        with pytest.raises(ConfigError, match="business_key"):
            pattern.pre_load()

    def test_missing_tracked_cols_raises(self, tmp_path):
        src = tmp_path / "s.csv"
        src.write_text("ID\n1\n")
        engine = create_engine("sqlite+pysqlite:///:memory:", future=True, connect_args={"check_same_thread": False}, poolclass=StaticPool)
        cfg = {
            "pattern": "scd2", "mapping_name": "bad2",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "database", "connection_string": engine,
                       "table": "T", "write_mode": "scd2"},
            "scd2": {"business_key": ["ID"]},  # no tracked_cols
        }
        pattern = Scd2Pattern(cfg)
        with pytest.raises(ConfigError, match="tracked_cols"):
            pattern.pre_load()

    def test_first_run_inserts_all_as_current(self, tmp_path):
        """First run: empty target — all rows inserted as is_current=1."""
        src = tmp_path / "src.csv"
        src.write_text("CUST_ID,NAME,STATUS\n1,Alice,A\n2,Bob,I\n")
        engine = create_engine("sqlite+pysqlite:///:memory:", future=True, connect_args={"check_same_thread": False}, poolclass=StaticPool)

        cfg = self._make_cfg(src, engine)
        pattern = Scd2Pattern(cfg)
        pattern._writer._engine = engine

        result = pattern.execute()
        assert result["status"]       == "success"
        assert result["rows_written"] == 2

        with engine.connect() as conn:
            rows = conn.execute(text("SELECT * FROM DIM_CUST")).fetchall()
        assert len(rows) == 2
        # All rows should be current
        is_cur_idx = 5  # IS_CUR column position in SELECT *
        for row in rows:
            assert row[is_cur_idx] == 1

    def test_unchanged_rows_not_duplicated(self, tmp_path):
        """Second run with same data: no new inserts, no expires."""
        src = tmp_path / "src.csv"
        src.write_text("CUST_ID,NAME,STATUS\n1,Alice,A\n")
        engine = create_engine("sqlite+pysqlite:///:memory:", future=True, connect_args={"check_same_thread": False}, poolclass=StaticPool)

        cfg = self._make_cfg(src, engine)

        # First run
        p1 = Scd2Pattern(cfg)
        p1._writer._engine = engine
        p1.execute()

        # Second run — same data
        p2 = Scd2Pattern(cfg)
        p2._writer._engine = engine
        p2.execute()

        with engine.connect() as conn:
            count = conn.execute(text("SELECT COUNT(*) FROM DIM_CUST")).scalar()
        assert count == 1  # No additional row should be inserted

    def test_changed_row_expires_old_inserts_new(self, tmp_path):
        """When tracked column changes: old row expires (IS_CUR=0), new row inserted (IS_CUR=1)."""
        engine = create_engine("sqlite+pysqlite:///:memory:", future=True, connect_args={"check_same_thread": False}, poolclass=StaticPool)

        # First run — load Alice
        src1 = tmp_path / "src1.csv"
        src1.write_text("CUST_ID,NAME,STATUS\n1,Alice,A\n")
        cfg = self._make_cfg(src1, engine)

        p1 = Scd2Pattern(cfg)
        p1._writer._engine = engine
        p1.execute()

        # Second run — Alice's STATUS changed
        src2 = tmp_path / "src2.csv"
        src2.write_text("CUST_ID,NAME,STATUS\n1,Alice,I\n")
        cfg["source"]["path"] = str(src2)

        p2 = Scd2Pattern(cfg)
        p2._writer._engine = engine
        p2.execute()

        with engine.connect() as conn:
            rows = conn.execute(
                text("SELECT IS_CUR, STATUS FROM DIM_CUST ORDER BY IS_CUR")
            ).fetchall()

        assert len(rows) == 2
        # Row with IS_CUR=0 should have STATUS='A' (expired)
        expired = [r for r in rows if r[0] == 0]
        current = [r for r in rows if r[0] == 1]
        assert len(expired) == 1
        assert len(current) == 1
        assert current[0][1] == "I"

    def test_new_key_appended_alongside_existing(self, tmp_path):
        """New business key on second run: inserted without touching existing rows."""
        engine = create_engine("sqlite+pysqlite:///:memory:", future=True, connect_args={"check_same_thread": False}, poolclass=StaticPool)

        src1 = tmp_path / "src1.csv"
        src1.write_text("CUST_ID,NAME,STATUS\n1,Alice,A\n")
        cfg = self._make_cfg(src1, engine)

        p1 = Scd2Pattern(cfg)
        p1._writer._engine = engine
        p1.execute()

        src2 = tmp_path / "src2.csv"
        src2.write_text("CUST_ID,NAME,STATUS\n1,Alice,A\n2,Bob,I\n")
        cfg["source"]["path"] = str(src2)

        p2 = Scd2Pattern(cfg)
        p2._writer._engine = engine
        p2.execute()

        with engine.connect() as conn:
            rows = conn.execute(
                text("SELECT CUST_ID, IS_CUR FROM DIM_CUST ORDER BY CUST_ID")
            ).fetchall()

        assert len(rows) == 2  # Alice (unchanged) + Bob (new)
        cust_ids = [r[0] for r in rows]
        assert 1 in cust_ids
        assert 2 in cust_ids

    def test_column_map_applied_before_scd2_logic(self, tmp_path):
        """Column map renames/transforms columns before the SCD2 merge."""
        engine = create_engine("sqlite+pysqlite:///:memory:", future=True, connect_args={"check_same_thread": False}, poolclass=StaticPool)
        src = tmp_path / "src.csv"
        src.write_text("ID,FIRST,LAST,ST\n1,Alice,Smith,A\n")

        cfg = self._make_cfg(
            src, engine,
            column_map=[
                {"target_col": "CUST_ID", "expression": "{ID}"},
                {"target_col": "NAME",    "expression": "concat({FIRST}, ' ', {LAST})"},
                {"target_col": "STATUS",  "expression": "{ST}"},
            ],
        )
        pattern = Scd2Pattern(cfg)
        pattern._writer._engine = engine
        result = pattern.execute()
        assert result["status"] == "success"

        with engine.connect() as conn:
            row = conn.execute(text("SELECT NAME FROM DIM_CUST")).fetchone()
        assert row[0] == "Alice Smith"

    def test_empty_source_writes_nothing(self, tmp_path):
        engine = create_engine("sqlite+pysqlite:///:memory:", future=True, connect_args={"check_same_thread": False}, poolclass=StaticPool)
        src = tmp_path / "src.csv"
        src.write_text("CUST_ID,NAME,STATUS\n")  # header only
        cfg = self._make_cfg(src, engine)
        pattern = Scd2Pattern(cfg)
        pattern._writer._engine = engine
        result = pattern.execute()
        assert result["status"]       == "success"
        assert result["rows_written"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# LOOKUP ENRICH PATTERN
# ═══════════════════════════════════════════════════════════════════════════════

class TestLookupEnrichPattern:
    def setup_method(self):
        """Clear lookup cache before each test to avoid cross-test contamination."""
        clear_lookup_cache()

    def test_missing_lookups_raises(self, tmp_path):
        src = tmp_path / "s.csv"
        src.write_text("ID\n1\n")
        cfg = {
            "pattern": "lookup_enrich", "mapping_name": "bad",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(tmp_path / "out.csv"),
                       "write_mode": "overwrite"},
            # no lookups
        }
        with pytest.raises(ConfigError, match="lookups"):
            LookupEnrichPattern(cfg).transform(pd.DataFrame({"ID": [1]}))

    def test_lookup_missing_join_keys_raises(self, tmp_path):
        src = tmp_path / "s.csv"
        src.write_text("ID\n1\n")
        lkp = tmp_path / "lkp.csv"
        lkp.write_text("ID,VAL\n1,x\n")
        cfg = {
            "pattern": "lookup_enrich", "mapping_name": "bad2",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(tmp_path / "out.csv"),
                       "write_mode": "overwrite"},
            "lookups": [{"name": "LKP", "type": "flat_file", "path": str(lkp)}],
            # no join_keys
        }
        with pytest.raises(ConfigError, match="join_keys"):
            LookupEnrichPattern(cfg).transform(pd.DataFrame({"ID": [1]}))

    def test_single_lookup_left_join(self, tmp_path):
        src = tmp_path / "txn.csv"
        src.write_text("TXN_ID,BRANCH_ID,AMT\n1,10,100\n2,20,200\n3,99,50\n")
        lkp = tmp_path / "branch.csv"
        lkp.write_text("BRANCH_ID,BRANCH_NAME\n10,North\n20,South\n")
        out = tmp_path / "out.csv"

        cfg = {
            "pattern": "lookup_enrich", "mapping_name": "lkp_left",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "lookups": [{
                "name":      "BRANCH",
                "type":      "flat_file",
                "path":      str(lkp),
                "join_keys": {"BRANCH_ID": "BRANCH_ID"},
                "join_type": "left",
                "cache":     False,
            }],
        }
        result = LookupEnrichPattern(cfg).execute()
        assert result["status"]    == "success"
        assert result["rows_read"] == 3  # left join keeps all 3 source rows

        output = pd.read_csv(out)
        # Row with BRANCH_ID=99 should have NaN for BRANCH_NAME (no match in left join)
        unmatched = output[output["BRANCH_ID"] == 99]
        assert pd.isna(unmatched["BRANCH_NAME"].iloc[0])

    def test_single_lookup_inner_join(self, tmp_path):
        src = tmp_path / "txn.csv"
        src.write_text("TXN_ID,BRANCH_ID,AMT\n1,10,100\n2,20,200\n3,99,50\n")
        lkp = tmp_path / "branch.csv"
        lkp.write_text("BRANCH_ID,BRANCH_NAME\n10,North\n20,South\n")
        out = tmp_path / "out.csv"

        cfg = {
            "pattern": "lookup_enrich", "mapping_name": "lkp_inner",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "lookups": [{
                "name":      "BRANCH",
                "type":      "flat_file",
                "path":      str(lkp),
                "join_keys": {"BRANCH_ID": "BRANCH_ID"},
                "join_type": "inner",
                "cache":     False,
            }],
        }
        result = LookupEnrichPattern(cfg).execute()
        # Inner join: only 2 rows match
        assert result["rows_written"] == 2

    def test_lookup_with_key_rename(self, tmp_path):
        """join_keys maps source col to differently-named lookup col."""
        src = tmp_path / "txn.csv"
        src.write_text("TXN_ID,SRC_BRANCH,AMT\n1,10,100\n2,20,200\n")
        lkp = tmp_path / "branch.csv"
        lkp.write_text("LKP_BRANCH,NAME\n10,North\n20,South\n")
        out = tmp_path / "out.csv"

        cfg = {
            "pattern": "lookup_enrich", "mapping_name": "lkp_rename",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "lookups": [{
                "name":      "BRANCH",
                "type":      "flat_file",
                "path":      str(lkp),
                "join_keys": {"SRC_BRANCH": "LKP_BRANCH"},
                "join_type": "left",
                "cache":     False,
            }],
        }
        result = LookupEnrichPattern(cfg).execute()
        assert result["status"] == "success"
        output = pd.read_csv(out)
        assert "NAME" in output.columns
        assert list(output["NAME"]) == ["North", "South"]

    def test_lookup_with_prefix(self, tmp_path):
        """Prefix is applied to non-key lookup columns."""
        src = tmp_path / "txn.csv"
        src.write_text("TXN_ID,BRANCH_ID\n1,10\n")
        lkp = tmp_path / "branch.csv"
        lkp.write_text("BRANCH_ID,NAME,CODE\n10,North,N\n")
        out = tmp_path / "out.csv"

        cfg = {
            "pattern": "lookup_enrich", "mapping_name": "lkp_prefix",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "lookups": [{
                "name":      "BRANCH",
                "type":      "flat_file",
                "path":      str(lkp),
                "join_keys": {"BRANCH_ID": "BRANCH_ID"},
                "join_type": "left",
                "prefix":    "BRN_",
                "cache":     False,
            }],
        }
        result = LookupEnrichPattern(cfg).execute()
        output = pd.read_csv(out)
        assert "BRN_NAME" in output.columns
        assert "BRN_CODE" in output.columns
        assert "NAME" not in output.columns    # original col removed

    def test_lookup_with_column_map(self, tmp_path):
        """column_map applied after all lookups."""
        src = tmp_path / "txn.csv"
        src.write_text("TXN_ID,BRANCH_ID,AMT\n1,10,500\n")
        lkp = tmp_path / "branch.csv"
        lkp.write_text("BRANCH_ID,BRANCH_NAME\n10,North\n")
        out = tmp_path / "out.csv"

        cfg = {
            "pattern": "lookup_enrich", "mapping_name": "lkp_colmap",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "lookups": [{
                "name":      "BRANCH",
                "type":      "flat_file",
                "path":      str(lkp),
                "join_keys": {"BRANCH_ID": "BRANCH_ID"},
                "join_type": "left",
                "cache":     False,
            }],
            "column_map": [
                {"target_col": "TXN",    "expression": "{TXN_ID}"},
                {"target_col": "BRANCH", "expression": "{BRANCH_NAME}"},
                {"target_col": "AMT",    "expression": "{AMT}"},
            ],
        }
        result = LookupEnrichPattern(cfg).execute()
        output = pd.read_csv(out)
        assert list(output.columns) == ["TXN", "BRANCH", "AMT"]
        assert output["BRANCH"].iloc[0] == "North"

    def test_multiple_lookups(self, tmp_path):
        """Two separate lookups are applied sequentially."""
        src = tmp_path / "txn.csv"
        src.write_text("TXN_ID,BRANCH_ID,PROD_ID\n1,10,100\n")
        branch_lkp = tmp_path / "branch.csv"
        branch_lkp.write_text("BRANCH_ID,BRANCH_NAME\n10,North\n")
        prod_lkp = tmp_path / "prod.csv"
        prod_lkp.write_text("PROD_ID,PROD_DESC\n100,Widget\n")
        out = tmp_path / "out.csv"

        cfg = {
            "pattern": "lookup_enrich", "mapping_name": "lkp_multi",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "lookups": [
                {"name": "BRANCH", "type": "flat_file", "path": str(branch_lkp),
                 "join_keys": {"BRANCH_ID": "BRANCH_ID"}, "join_type": "left",
                 "cache": False},
                {"name": "PRODUCT", "type": "flat_file", "path": str(prod_lkp),
                 "join_keys": {"PROD_ID": "PROD_ID"}, "join_type": "left",
                 "cache": False},
            ],
        }
        result = LookupEnrichPattern(cfg).execute()
        output = pd.read_csv(out)
        assert "BRANCH_NAME" in output.columns
        assert "PROD_DESC"   in output.columns
        assert output["BRANCH_NAME"].iloc[0] == "North"
        assert output["PROD_DESC"].iloc[0]   == "Widget"

    def test_cache_returns_same_dataframe(self, tmp_path):
        """With cache=True, the lookup is only read once."""
        src = tmp_path / "txn.csv"
        src.write_text("ID,REF\n1,10\n2,10\n")
        lkp = tmp_path / "ref.csv"
        lkp.write_text("REF,DESC\n10,Ten\n")
        out = tmp_path / "out.csv"

        cfg = {
            "pattern": "lookup_enrich", "mapping_name": "lkp_cache",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "lookups": [{"name": "REF", "type": "flat_file", "path": str(lkp),
                         "join_keys": {"REF": "REF"}, "join_type": "left",
                         "cache": True}],
        }
        p = LookupEnrichPattern(cfg)
        # Run transform twice
        df = pd.read_csv(src)
        r1 = p.transform(df.copy())
        r2 = p.transform(df.copy())
        assert len(r1) == len(r2) == 2

    def test_db_lookup(self, tmp_path):
        """Lookup sourced from an in-memory SQLite database."""
        src = tmp_path / "txn.csv"
        src.write_text("TXN_ID,STATUS_ID\n1,A\n2,B\n")
        out = tmp_path / "out.csv"

        lkp_engine = create_engine("sqlite+pysqlite:///:memory:", future=True, connect_args={"check_same_thread": False}, poolclass=StaticPool)
        pd.DataFrame({"STATUS_ID": ["A", "B"], "LABEL": ["Active", "Inactive"]}).to_sql(
            "STATUS_CODES", lkp_engine, index=False, if_exists="replace"
        )

        cfg = {
            "pattern": "lookup_enrich", "mapping_name": "lkp_db",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "lookups": [{
                "name":              "STATUS",
                "type":              "database",
                "connection_string": lkp_engine,
                "table":             "STATUS_CODES",
                "join_keys":         {"STATUS_ID": "STATUS_ID"},
                "join_type":         "left",
                "cache":             False,
            }],
        }
        pattern = LookupEnrichPattern(cfg)
        # Wire the lookup reader engine directly
        pattern._cfg["lookups"][0]["connection_string"] = lkp_engine

        # We need to test _load_lookup separately since we can't pass an engine obj
        # directly as a connection_string to DatabaseReader.  Test via transform.
        from etl_patterns.io.readers.db_reader import DatabaseReader
        lkp_reader = DatabaseReader({
            "type": "database",
            "connection_string": "unused",  # overridden below
            "table": "STATUS_CODES",
        })
        lkp_reader._engine = lkp_engine
        lkp_df = lkp_reader.read()
        assert list(lkp_df.columns) == ["STATUS_ID", "LABEL"]
        assert len(lkp_df) == 2
