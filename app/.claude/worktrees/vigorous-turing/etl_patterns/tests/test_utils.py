"""
tests/test_utils.py — Unit tests for shared utilities
"""
from __future__ import annotations

import math
from datetime import date, datetime
from decimal import Decimal

import pandas as pd
import pytest

from etl_patterns.utils.null_safe import coalesce, is_null, null_safe, nvl, nvl2
from etl_patterns.utils.type_cast import type_cast
from etl_patterns.utils.string_clean import (
    instr, lpad, ltrim, replace_chr, replace_str, rpad, rtrim,
    substr, to_lower, to_upper, trim, clean_whitespace, normalize_string,
)
from etl_patterns.utils.etl_metadata import (
    add_etl_metadata, metadata_columns, COL_LOAD_DATE, COL_BATCH_ID,
    COL_SOURCE_SYSTEM, COL_SOURCE_FILE,
)


# ── null_safe ─────────────────────────────────────────────────────────────────

class TestNullSafe:
    def test_none_returns_default(self):
        assert null_safe(None, 0) == 0

    def test_nan_returns_default(self):
        assert null_safe(float("nan"), -1) == -1

    def test_pandas_na_returns_default(self):
        assert null_safe(pd.NA, "MISSING") == "MISSING"

    def test_valid_value_returned(self):
        assert null_safe("hello", "UNKNOWN") == "hello"

    def test_zero_is_not_null(self):
        assert null_safe(0, 99) == 0

    def test_empty_string_is_not_null(self):
        assert null_safe("", "FALLBACK") == ""

    def test_type_coerce(self):
        assert null_safe("42", 0, type_coerce=int) == 42

    def test_type_coerce_failure_returns_default(self):
        assert null_safe("abc", 0, type_coerce=int) == 0

    def test_coalesce_first_non_null(self):
        assert coalesce(None, None, "first_good") == "first_good"

    def test_coalesce_all_null(self):
        assert coalesce(None, None, default="FALLBACK") == "FALLBACK"

    def test_is_null_true(self):
        assert is_null(None)
        assert is_null(float("nan"))

    def test_is_null_false(self):
        assert not is_null(0)
        assert not is_null("")
        assert not is_null(False)

    def test_nvl(self):
        assert nvl(None, "X") == "X"
        assert nvl("Y", "X") == "Y"

    def test_nvl2(self):
        assert nvl2(None,  "not_null", "null_result") == "null_result"
        assert nvl2("val", "not_null", "null_result") == "not_null"


# ── type_cast ─────────────────────────────────────────────────────────────────

class TestTypeCast:
    def test_to_integer(self):
        assert type_cast("42", "integer") == 42

    def test_to_integer_with_formatting(self):
        assert type_cast("$1,234", "integer") == 1234

    def test_to_float(self):
        assert type_cast("3.14", "float") == pytest.approx(3.14)

    def test_to_decimal(self):
        result = type_cast("123.456", "decimal", scale=2)
        assert result == Decimal("123.46")

    def test_to_string(self):
        assert type_cast(42, "string") == "42"

    def test_to_date_iso(self):
        assert type_cast("2024-01-15", "date") == date(2024, 1, 15)

    def test_to_date_with_format(self):
        assert type_cast("15/01/2024", "date", format="%d/%m/%Y") == date(2024, 1, 15)

    def test_to_datetime(self):
        result = type_cast("2024-01-15 10:30:00", "datetime")
        assert result == datetime(2024, 1, 15, 10, 30, 0)

    def test_to_boolean_truthy(self):
        assert type_cast("true", "boolean") is True
        assert type_cast("1",    "boolean") is True
        assert type_cast("yes",  "boolean") is True

    def test_to_boolean_falsy(self):
        assert type_cast("false", "boolean") is False
        assert type_cast("0",     "boolean") is False

    def test_null_input_returns_default(self):
        assert type_cast(None, "integer", default=0) == 0

    def test_cast_failure_returns_default(self):
        assert type_cast("not_a_number", "integer", default=-1) == -1


# ── string_clean ──────────────────────────────────────────────────────────────

class TestStringClean:
    def test_to_upper(self):
        assert to_upper("hello") == "HELLO"

    def test_to_upper_null(self):
        assert to_upper(None) is None

    def test_to_lower(self):
        assert to_lower("HELLO") == "hello"

    def test_trim(self):
        assert trim("  hello  ") == "hello"

    def test_ltrim(self):
        assert ltrim("  hi") == "hi"

    def test_rtrim(self):
        assert rtrim("hi  ") == "hi"

    def test_lpad(self):
        assert lpad("42", 5, "0") == "00042"

    def test_lpad_no_truncate(self):
        assert lpad("hello_world", 5, "0") == "hello_world"

    def test_rpad(self):
        assert rpad("hi", 5, "-") == "hi---"

    def test_substr_1based(self):
        assert substr("ABCDE", 2, 3) == "BCD"

    def test_substr_to_end(self):
        assert substr("ABCDE", 3) == "CDE"

    def test_instr_found(self):
        assert instr("HELLO WORLD", "WORLD") == 7

    def test_instr_not_found(self):
        assert instr("HELLO", "X") == 0

    def test_replace_chr(self):
        assert replace_chr("A-B-C", "-") == "ABC"

    def test_replace_str(self):
        assert replace_str("foo bar foo", "foo", "baz") == "baz bar baz"

    def test_clean_whitespace(self):
        assert clean_whitespace("  hello   world  ") == "hello world"

    def test_normalize_string(self):
        assert normalize_string("  Hello  ", upper=True) == "HELLO"


# ── etl_metadata ─────────────────────────────────────────────────────────────

class TestEtlMetadata:
    def _make_df(self):
        return pd.DataFrame({"A": [1, 2], "B": ["x", "y"]})

    def test_adds_standard_cols(self):
        df = add_etl_metadata(self._make_df(), True)
        assert COL_LOAD_DATE     in df.columns
        assert COL_BATCH_ID      in df.columns
        assert COL_SOURCE_SYSTEM in df.columns
        assert COL_SOURCE_FILE   in df.columns

    def test_false_config_returns_unchanged(self):
        df = self._make_df()
        result = add_etl_metadata(df, False)
        assert list(result.columns) == ["A", "B"]

    def test_source_system_from_kwarg(self):
        df = add_etl_metadata(self._make_df(), True, source_system="FIRSTBANK")
        assert (df[COL_SOURCE_SYSTEM] == "FIRSTBANK").all()

    def test_source_system_from_config(self):
        cfg = {"source_system": "OLTP_DB", "load_date": True, "batch_id": True,
               "source_file": True}
        df = add_etl_metadata(self._make_df(), cfg)
        assert (df[COL_SOURCE_SYSTEM] == "OLTP_DB").all()

    def test_run_id_off_by_default(self):
        df = add_etl_metadata(self._make_df(), True)
        assert "ETL_RUN_ID" not in df.columns

    def test_run_id_on_when_configured(self):
        cfg = {"load_date": True, "batch_id": True, "source_system": True,
               "source_file": True, "run_id": True}
        df = add_etl_metadata(self._make_df(), cfg, run_id="RUN-001")
        assert "ETL_RUN_ID" in df.columns
        assert (df["ETL_RUN_ID"] == "RUN-001").all()

    def test_original_not_mutated(self):
        original = self._make_df()
        _ = add_etl_metadata(original, True)
        assert list(original.columns) == ["A", "B"]

    def test_metadata_columns_list(self):
        cols = metadata_columns(True)
        assert COL_LOAD_DATE in cols
        assert COL_BATCH_ID  in cols

    def test_metadata_columns_false(self):
        assert metadata_columns(False) == []
