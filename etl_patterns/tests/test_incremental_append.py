"""
tests/test_incremental_append.py — Tests for IncrementalAppendPattern
======================================================================
All tests use either flat-file CSV or SQLite in-memory via sqlalchemy.
DB engine objects are passed directly where possible so tests are self-contained.
"""
from __future__ import annotations

import pytest
import pandas as pd
from sqlalchemy import create_engine, text

from etl_patterns.patterns.incremental_append import (
    IncrementalAppendPattern,
    _find_watermark_col,
)
from etl_patterns.exceptions import ConfigError, PatternError
from etl_patterns.utils.watermark_manager import WatermarkManager
from etl_patterns.io import get_reader, get_writer


# ── Helper ─────────────────────────────────────────────────────────────────────

def _bare_pattern(cfg: dict) -> IncrementalAppendPattern:
    """Create a pattern instance without triggering __init__ IO wiring."""
    obj = IncrementalAppendPattern.__new__(IncrementalAppendPattern)
    obj._cfg           = cfg
    obj._name          = cfg.get("mapping_name", "test")
    obj._reader        = get_reader(cfg["source"])
    obj._writer        = get_writer(cfg["target"])
    obj._writers       = [obj._writer]
    obj._watermark_val = None
    obj._wm_mgr        = None
    obj._ff_wm_col     = None
    obj._ff_wm_dtype   = "string"
    return obj


# ── Unit tests for _find_watermark_col ────────────────────────────────────────

class TestFindWatermarkCol:
    def test_original_col_present(self):
        df = pd.DataFrame({"UPDATED_AT": [1, 2]})
        assert _find_watermark_col(df, "UPDATED_AT", None) == "UPDATED_AT"

    def test_renamed_via_column_map(self):
        df = pd.DataFrame({"LOAD_TS": [1, 2]})
        col_map = [{"target_col": "LOAD_TS", "expression": "{UPDATED_AT}"}]
        assert _find_watermark_col(df, "UPDATED_AT", col_map) == "LOAD_TS"

    def test_not_found_returns_none(self):
        df = pd.DataFrame({"OTHER": [1]})
        assert _find_watermark_col(df, "UPDATED_AT", None) is None

    def test_no_column_map_no_match(self):
        df = pd.DataFrame({"X": [1]})
        assert _find_watermark_col(df, "Y", None) is None


# ── Config validation ──────────────────────────────────────────────────────────

class TestConfigValidation:
    def test_missing_watermark_block_raises(self, tmp_path):
        src = tmp_path / "s.csv"
        src.write_text("ID\n1\n")
        cfg = {
            "pattern":      "incremental_append",
            "mapping_name": "bad",
            "source": {"type": "flat_file", "path": str(src)},
            "target": {"type": "flat_file", "path": str(tmp_path / "out.csv"),
                       "write_mode": "overwrite"},
        }
        pattern = IncrementalAppendPattern(cfg)
        with pytest.raises(ConfigError, match="watermark"):
            pattern.pre_load()

    def test_flat_file_without_control_conn_raises(self, tmp_path):
        src = tmp_path / "data.csv"
        src.write_text("UPDATED_AT,VAL\n2024-01-01,1\n")
        cfg = {
            "pattern":      "incremental_append",
            "mapping_name": "bad_ff",
            "source": {
                "type": "flat_file",
                "path": str(src),
                "watermark": {"column": "UPDATED_AT", "initial": "1900-01-01"},
                # no control_connection_string
            },
            "target": {"type": "flat_file", "path": str(tmp_path / "out.csv"),
                       "write_mode": "overwrite"},
        }
        pattern = IncrementalAppendPattern(cfg)
        with pytest.raises(PatternError, match="control_connection_string"):
            pattern.pre_load()


# ── Watermark manager wiring ───────────────────────────────────────────────────

class TestWatermarkManagerWiring:
    def test_initial_watermark_used_on_first_run(self, tmp_path):
        src = tmp_path / "s.csv"
        src.write_text("UPDATED_AT,VAL\n2024-01-01,1\n")
        ctrl_eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
        wm_mgr   = WatermarkManager(ctrl_eng)

        cfg = {
            "pattern": "incremental_append", "mapping_name": "wm_seed",
            "source": {"type": "flat_file", "path": str(src),
                       "control_connection_string": ctrl_eng,
                       "watermark": {"column": "UPDATED_AT",
                                     "initial": "1900-01-01", "data_type": "string"}},
            "target": {"type": "flat_file", "path": str(tmp_path / "out.csv"),
                       "write_mode": "overwrite"},
        }
        pattern = IncrementalAppendPattern(cfg)
        pattern._build_wm_manager = lambda _: wm_mgr  # type: ignore
        pattern.pre_load()
        assert pattern._watermark_val == "1900-01-01"

    def test_existing_watermark_returned_on_subsequent_run(self, tmp_path):
        src = tmp_path / "s.csv"
        src.write_text("UPDATED_AT,VAL\n2024-06-01,1\n")
        ctrl_eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
        wm_mgr   = WatermarkManager(ctrl_eng)
        wm_mgr.set_watermark("wm_exist", "UPDATED_AT", "2024-03-15")

        cfg = {
            "pattern": "incremental_append", "mapping_name": "wm_exist",
            "source": {"type": "flat_file", "path": str(src),
                       "control_connection_string": ctrl_eng,
                       "watermark": {"column": "UPDATED_AT",
                                     "initial": "1900-01-01", "data_type": "string"}},
            "target": {"type": "flat_file", "path": str(tmp_path / "out.csv"),
                       "write_mode": "overwrite"},
        }
        pattern = IncrementalAppendPattern(cfg)
        pattern._build_wm_manager = lambda _: wm_mgr  # type: ignore
        pattern.pre_load()
        assert pattern._watermark_val == "2024-03-15"


# ── post_load watermark advancement ──────────────────────────────────────────

class TestPostLoadWatermark:
    def _make_cfg(self, tmp_path) -> dict:
        src = tmp_path / "s.csv"
        src.write_text("UPDATED_AT\n2024-01-01\n")
        return {
            "pattern": "incremental_append", "mapping_name": "pl_test",
            "source": {"type": "flat_file", "path": str(src),
                       "watermark": {"column": "UPDATED_AT"}},
            "target": {"type": "flat_file", "path": str(tmp_path / "out.csv")},
        }

    def test_watermark_advances_to_max(self, tmp_path):
        ctrl_eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
        wm_mgr   = WatermarkManager(ctrl_eng)
        cfg = self._make_cfg(tmp_path)

        pattern = _bare_pattern(cfg)
        pattern._wm_mgr        = wm_mgr
        pattern._watermark_val = "1900-01-01"

        df = pd.DataFrame({"UPDATED_AT": ["2024-01-01", "2024-03-15", "2024-06-01"]})
        pattern.post_load(df)

        stored = wm_mgr.get_watermark("pl_test", "UPDATED_AT")
        assert stored == "2024-06-01"

    def test_watermark_unchanged_on_empty_df(self, tmp_path):
        ctrl_eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
        wm_mgr   = WatermarkManager(ctrl_eng)
        wm_mgr.set_watermark("pl_empty", "UPDATED_AT", "2024-01-01")

        cfg = self._make_cfg(tmp_path)
        cfg["mapping_name"] = "pl_empty"

        pattern = _bare_pattern(cfg)
        pattern._wm_mgr        = wm_mgr
        pattern._watermark_val = "2024-01-01"

        pattern.post_load(pd.DataFrame())   # empty — should not advance

        stored = wm_mgr.get_watermark("pl_empty", "UPDATED_AT")
        assert stored == "2024-01-01"

    def test_watermark_unchanged_when_col_not_in_df(self, tmp_path):
        ctrl_eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
        wm_mgr   = WatermarkManager(ctrl_eng)
        wm_mgr.set_watermark("pl_nocol", "UPDATED_AT", "2024-01-01")

        cfg = self._make_cfg(tmp_path)
        cfg["mapping_name"] = "pl_nocol"

        pattern = _bare_pattern(cfg)
        pattern._wm_mgr        = wm_mgr
        pattern._watermark_val = "2024-01-01"

        pattern.post_load(pd.DataFrame({"OTHER": [1, 2]}))

        stored = wm_mgr.get_watermark("pl_nocol", "UPDATED_AT")
        assert stored == "2024-01-01"


# ── Flat-file in-memory watermark filter ──────────────────────────────────────

class TestFlatFileWatermarkFilter:
    def _bare_ff_pattern(self, tmp_path, watermark_val):
        ctrl_eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
        wm_mgr   = WatermarkManager(ctrl_eng)
        src = tmp_path / "s.csv"
        src.write_text("UPDATED_AT,VAL\n2024-01-01,1\n")

        cfg = {
            "pattern": "incremental_append", "mapping_name": "ff_filter",
            "source": {"type": "flat_file", "path": str(src),
                       "watermark": {"column": "UPDATED_AT"}},
            "target": {"type": "flat_file", "path": str(tmp_path / "out.csv")},
        }
        p = _bare_pattern(cfg)
        p._watermark_val = watermark_val
        p._wm_mgr        = wm_mgr
        p._ff_wm_col     = "UPDATED_AT"
        p._ff_wm_dtype   = "datetime"
        return p

    def test_filter_returns_newer_rows_only(self, tmp_path):
        p  = self._bare_ff_pattern(tmp_path, "2024-01-15")
        df = pd.DataFrame({
            "UPDATED_AT": ["2024-01-10", "2024-01-15", "2024-01-20", "2024-02-01"],
            "VAL":        [1, 2, 3, 4],
        })
        result = p._filter_by_watermark(df, "UPDATED_AT", "datetime")
        assert list(result["VAL"]) == [3, 4]

    def test_filter_returns_all_rows_with_seed_watermark(self, tmp_path):
        p  = self._bare_ff_pattern(tmp_path, "1900-01-01")
        df = pd.DataFrame({
            "UPDATED_AT": ["2024-01-10", "2024-06-01"],
            "VAL":        [1, 2],
        })
        result = p._filter_by_watermark(df, "UPDATED_AT", "datetime")
        assert len(result) == 2

    def test_filter_returns_empty_when_all_old(self, tmp_path):
        p  = self._bare_ff_pattern(tmp_path, "2024-12-31")
        df = pd.DataFrame({
            "UPDATED_AT": ["2024-01-01", "2024-06-01"],
            "VAL":        [1, 2],
        })
        result = p._filter_by_watermark(df, "UPDATED_AT", "datetime")
        assert len(result) == 0

    def test_filter_none_watermark_returns_all(self, tmp_path):
        p  = self._bare_ff_pattern(tmp_path, None)
        df = pd.DataFrame({"UPDATED_AT": ["2024-01-01"], "VAL": [1]})
        result = p._filter_by_watermark(df, "UPDATED_AT", "datetime")
        assert len(result) == 1


# ── End-to-end flat-file tests ─────────────────────────────────────────────────

class TestIncrementalAppendFlatFile:
    def test_first_run_loads_all_rows(self, tmp_path):
        src = tmp_path / "txn.csv"
        src.write_text(
            "ID,UPDATED_AT,AMT\n"
            "1,2024-01-01,100\n"
            "2,2024-03-01,200\n"
        )
        out      = tmp_path / "out.csv"
        ctrl_eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
        wm_mgr   = WatermarkManager(ctrl_eng)

        cfg = {
            "pattern":      "incremental_append",
            "mapping_name": "ff_first",
            "source": {
                "type": "flat_file",
                "path": str(src),
                "control_connection_string": ctrl_eng,
                "watermark": {"column": "UPDATED_AT", "data_type": "string",
                              "initial": "1900-01-01"},
            },
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
        }
        pattern = IncrementalAppendPattern(cfg)
        pattern._build_wm_manager = lambda _: wm_mgr  # type: ignore

        result = pattern.execute()
        assert result["status"]    == "success"
        assert result["rows_read"] == 2
        assert out.exists()

    def test_second_run_filters_old_rows(self, tmp_path):
        src = tmp_path / "txn.csv"
        src.write_text(
            "ID,UPDATED_AT,AMT\n"
            "1,2024-01-01,100\n"
            "2,2024-01-15,150\n"
            "3,2024-01-20,200\n"
            "4,2024-02-01,250\n"
        )
        out      = tmp_path / "out.csv"
        ctrl_eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
        wm_mgr   = WatermarkManager(ctrl_eng)
        wm_mgr.set_watermark("ff_second", "UPDATED_AT", "2024-01-15")

        cfg = {
            "pattern":      "incremental_append",
            "mapping_name": "ff_second",
            "source": {
                "type": "flat_file",
                "path": str(src),
                "control_connection_string": ctrl_eng,
                "watermark": {"column": "UPDATED_AT", "data_type": "string",
                              "initial": "1900-01-01"},
            },
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
        }
        pattern = IncrementalAppendPattern(cfg)
        pattern._build_wm_manager = lambda _: wm_mgr  # type: ignore

        result = pattern.execute()
        assert result["status"] == "success"
        output = pd.read_csv(out)
        assert set(output["ID"].tolist()) == {3, 4}

    def test_with_column_map(self, tmp_path):
        src = tmp_path / "src.csv"
        src.write_text(
            "FIRST,LAST,UPDATED_AT\n"
            "Alice,Smith,2024-01-20\n"
            "Bob,Jones,2023-12-01\n"
        )
        out      = tmp_path / "out.csv"
        ctrl_eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
        wm_mgr   = WatermarkManager(ctrl_eng)
        wm_mgr.set_watermark("ff_colmap", "UPDATED_AT", "2024-01-01")

        cfg = {
            "pattern":      "incremental_append",
            "mapping_name": "ff_colmap",
            "source": {
                "type": "flat_file",
                "path": str(src),
                "control_connection_string": ctrl_eng,
                "watermark": {"column": "UPDATED_AT", "data_type": "string",
                              "initial": "1900-01-01"},
            },
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
            "column_map": [
                {"target_col": "FULL_NAME",  "expression": "concat({FIRST}, ' ', {LAST})"},
                {"target_col": "UPDATED_AT", "expression": "{UPDATED_AT}"},
            ],
        }
        pattern = IncrementalAppendPattern(cfg)
        pattern._build_wm_manager = lambda _: wm_mgr  # type: ignore

        result = pattern.execute()
        assert result["status"] == "success"
        output = pd.read_csv(out)
        assert list(output["FULL_NAME"]) == ["Alice Smith"]

    def test_watermark_advanced_after_load(self, tmp_path):
        src = tmp_path / "src.csv"
        src.write_text("ID,UPDATED_AT\n1,2024-06-01\n2,2024-09-15\n")
        out      = tmp_path / "out.csv"
        ctrl_eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
        wm_mgr   = WatermarkManager(ctrl_eng)

        cfg = {
            "pattern":      "incremental_append",
            "mapping_name": "ff_wm_up",
            "source": {
                "type": "flat_file",
                "path": str(src),
                "control_connection_string": ctrl_eng,
                "watermark": {"column": "UPDATED_AT", "data_type": "string",
                              "initial": "1900-01-01"},
            },
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
        }
        pattern = IncrementalAppendPattern(cfg)
        pattern._build_wm_manager = lambda _: wm_mgr  # type: ignore
        pattern.execute()

        stored = wm_mgr.get_watermark("ff_wm_up", "UPDATED_AT")
        assert stored == "2024-09-15"

    def test_empty_source_leaves_watermark_unchanged(self, tmp_path):
        src = tmp_path / "src.csv"
        src.write_text("ID,UPDATED_AT\n")   # header only, no data
        out      = tmp_path / "out.csv"
        ctrl_eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
        wm_mgr   = WatermarkManager(ctrl_eng)
        wm_mgr.set_watermark("ff_empty", "UPDATED_AT", "2024-01-01")

        cfg = {
            "pattern":      "incremental_append",
            "mapping_name": "ff_empty",
            "source": {
                "type": "flat_file",
                "path": str(src),
                "control_connection_string": ctrl_eng,
                "watermark": {"column": "UPDATED_AT", "data_type": "string",
                              "initial": "1900-01-01"},
            },
            "target": {"type": "flat_file", "path": str(out), "write_mode": "overwrite"},
        }
        pattern = IncrementalAppendPattern(cfg)
        pattern._build_wm_manager = lambda _: wm_mgr  # type: ignore
        result = pattern.execute()

        assert result["status"]    == "success"
        assert result["rows_read"] == 0
        stored = wm_mgr.get_watermark("ff_empty", "UPDATED_AT")
        assert stored == "2024-01-01"   # unchanged
