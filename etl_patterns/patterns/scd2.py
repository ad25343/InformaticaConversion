# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
patterns/scd2.py — SCD Type 2 slowly-changing dimension pattern
================================================================
Equivalent to Informatica SCD2 mappings.  Maintains full row-level history
in the target table by:

  * **New rows** (business key not yet in target):
    INSERT with effective_from = now, effective_to = end_of_time, is_current = 1.

  * **Changed rows** (key exists AND at least one tracked column differs):
    UPDATE the current target row: set effective_to = now, is_current = 0.
    INSERT a new version:          effective_from = now, effective_to = end_of_time,
                                   is_current = 1.

  * **Unchanged rows** (key exists AND all tracked columns match): skip.

Config example
--------------
pattern:      scd2
mapping_name: m_dim_customer_scd2

source:
  type:              database
  connection_string: postgresql+psycopg2://user:pass@host/oltp
  table:             STG_CUSTOMERS

target:
  type:              database
  connection_string: postgresql+psycopg2://user:pass@host/dw
  table:             DIM_CUSTOMERS
  write_mode:        scd2           # handled by the pattern, not DatabaseWriter

scd2:
  business_key:    [CUSTOMER_ID]            # one or more columns
  tracked_cols:    [NAME, ADDRESS, PHONE]   # columns that trigger a version change
  effective_from:  EFFECTIVE_FROM_DT        # column name in the target table
  effective_to:    EFFECTIVE_TO_DT          # column name in the target table
  is_current:      IS_CURRENT_FLAG          # column name (1/0 or True/False)
  end_of_time:     "9999-12-31 00:00:00"   # sentinel value for open-ended rows

# Optional column mapping applied before SCD2 logic
column_map:
  - target_col: CUSTOMER_ID
    expression: "{CUSTOMER_ID}"
  - target_col: NAME
    expression: "concat({FIRST_NAME}, ' ', {LAST_NAME})"
  - target_col: ADDRESS
    expression: "{ADDRESS_LINE1}"
  - target_col: PHONE
    expression: "{PHONE_NUMBER}"

etl_metadata: true
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

import pandas as pd
from sqlalchemy import create_engine, text

from etl_patterns.exceptions import ConfigError, PatternError
from etl_patterns.expression import apply_column_map
from etl_patterns.io.readers.db_reader import DatabaseReader
from etl_patterns.io.writers.db_writer import DatabaseWriter
from etl_patterns.patterns.base import BasePattern

log = logging.getLogger(__name__)

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


def _validate_identifier(name: str, context: str = "identifier") -> None:
    """Raise ValueError if *name* is not a safe SQL identifier."""
    if not _IDENT_RE.match(name):
        raise ValueError(
            f"Invalid SQL identifier for {context}: {name!r}. "
            "Only letters, digits, underscores, and dots are permitted."
        )


_DEFAULT_END_OF_TIME = "9999-12-31 00:00:00"
_DEFAULT_EFFECTIVE_FROM = "EFFECTIVE_FROM_DT"
_DEFAULT_EFFECTIVE_TO   = "EFFECTIVE_TO_DT"
_DEFAULT_IS_CURRENT     = "IS_CURRENT_FLAG"


class Scd2Pattern(BasePattern):
    """SCD Type 2 — maintains full history with effective dates."""

    def pre_load(self) -> None:
        """Validate required SCD2 config keys."""
        scd2_cfg = self._cfg.get("scd2", {})
        if not scd2_cfg.get("business_key"):
            raise ConfigError(
                f"[{self._name}] scd2 pattern requires 'scd2.business_key' in config. "
                "Example: scd2: {business_key: [CUSTOMER_ID], tracked_cols: [NAME, ADDR]}"
            )
        if not scd2_cfg.get("tracked_cols"):
            raise ConfigError(
                f"[{self._name}] scd2 pattern requires 'scd2.tracked_cols' in config."
            )
        # Coerce string → list
        for key in ("business_key", "tracked_cols"):
            if isinstance(scd2_cfg.get(key), str):
                scd2_cfg[key] = [scd2_cfg[key]]

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply optional column_map and return the source DataFrame."""
        column_map = self._cfg.get("column_map")
        if not column_map:
            return df
        rows = [apply_column_map(column_map, row.to_dict()) for _, row in df.iterrows()]
        return pd.DataFrame(rows)

    # ── Override _write to implement SCD2 merge logic ────────────────────────

    def _write(self, df: pd.DataFrame) -> int:
        """
        SCD2 merge: compare source rows against current target, expire changed
        rows, and insert new versions.  Returns total rows written (inserts only).
        """
        if df.empty:
            log.info("[%s] SCD2: zero source rows — nothing to process.", self._name)
            return 0

        scd2_cfg      = self._cfg.get("scd2", {})
        business_key  = scd2_cfg.get("business_key", [])
        tracked_cols  = scd2_cfg.get("tracked_cols", [])
        eff_from_col  = scd2_cfg.get("effective_from", _DEFAULT_EFFECTIVE_FROM)
        eff_to_col    = scd2_cfg.get("effective_to",   _DEFAULT_EFFECTIVE_TO)
        is_cur_col    = scd2_cfg.get("is_current",     _DEFAULT_IS_CURRENT)
        end_of_time   = scd2_cfg.get("end_of_time",    _DEFAULT_END_OF_TIME)

        engine = self._get_target_engine()
        table  = self._cfg.get("target", {}).get("table")
        schema = self._cfg.get("target", {}).get("schema")
        fqn    = f"{schema}.{table}" if schema else table
        now    = datetime.now(tz=timezone.utc)

        # Read current target (active rows only)
        current_target = self._read_current_target(
            engine, fqn, is_cur_col, business_key
        )

        rows_inserted = 0

        # Classify each source row
        to_insert:  list[dict[str, Any]] = []
        to_expire:  list[dict[str, Any]] = []  # {key_col: key_val, ...}

        for _, src_row in df.iterrows():
            src = src_row.to_dict()
            key = {k: src[k] for k in business_key}

            # Find matching current target row
            tgt_match = _lookup_row(current_target, key, business_key)

            if tgt_match is None:
                # New key — insert fresh
                new_row = dict(src)
                new_row[eff_from_col] = now
                new_row[eff_to_col]   = end_of_time
                new_row[is_cur_col]   = 1
                to_insert.append(new_row)

            else:
                # Check if any tracked columns changed
                changed = any(
                    _vals_differ(src.get(col), tgt_match.get(col))
                    for col in tracked_cols
                    if col in src
                )
                if changed:
                    to_expire.append(key)
                    new_row = dict(src)
                    new_row[eff_from_col] = now
                    new_row[eff_to_col]   = end_of_time
                    new_row[is_cur_col]   = 1
                    to_insert.append(new_row)
                else:
                    log.debug(
                        "[%s] SCD2: key %s unchanged — skipped.", self._name, key
                    )

        # Expire changed rows
        if to_expire:
            self._expire_rows(engine, fqn, to_expire, business_key,
                              eff_to_col, is_cur_col, now)

        # Insert new / changed rows
        if to_insert:
            insert_df = pd.DataFrame(to_insert)
            insert_df.to_sql(
                name      = table,
                con       = engine,
                schema    = schema,
                if_exists = "append",
                index     = False,
                method    = "multi",
            )
            rows_inserted = len(insert_df)

        log.info(
            "[%s] SCD2 complete — %d expired, %d inserted.",
            self._name, len(to_expire), rows_inserted,
        )
        return rows_inserted

    # ── Internals ─────────────────────────────────────────────────────────────

    def _get_target_engine(self):
        if isinstance(self._writer, DatabaseWriter):
            return self._writer.get_engine()
        tgt_conn = self._cfg.get("target", {}).get("connection_string")
        if not tgt_conn:
            raise PatternError(
                f"[{self._name}] scd2 pattern requires a database target with "
                "'connection_string'."
            )
        return create_engine(tgt_conn, future=True)

    def _read_current_target(
        self,
        engine,
        fqn: str,
        is_cur_col: str,
        business_key: list[str],
    ) -> list[dict[str, Any]]:
        """
        Read active (is_current = 1) rows from the target table.
        Returns an empty list if the table doesn't exist yet.
        """
        cols = ", ".join(business_key)
        # include tracked cols too for comparison
        tracked_cols = self._cfg.get("scd2", {}).get("tracked_cols", [])
        all_cols = list(dict.fromkeys(business_key + tracked_cols))  # deduplicated, ordered
        select_cols = ", ".join(all_cols)

        _validate_identifier(fqn, "target table")
        _validate_identifier(is_cur_col, "is_current column")
        for _col in all_cols:
            _validate_identifier(_col, "selected column")

        sql = (
            f"SELECT {select_cols} FROM {fqn} "  # noqa: S608
            f"WHERE {is_cur_col} = 1"
        )
        try:
            with engine.connect() as conn:
                rows = conn.execute(text(sql)).mappings().fetchall()
            return [dict(r) for r in rows]
        except Exception:
            # Table doesn't exist yet — first ever load
            log.info(
                "[%s] SCD2: target table '%s' not found — treating as first run.",
                self._name, fqn,
            )
            return []

    def _expire_rows(
        self,
        engine,
        fqn: str,
        to_expire: list[dict[str, Any]],
        business_key: list[str],
        eff_to_col: str,
        is_cur_col: str,
        now: datetime,
    ) -> None:
        """Set effective_to = now and is_current = 0 for each expired key."""
        _validate_identifier(fqn, "target table")
        _validate_identifier(eff_to_col, "effective_to column")
        _validate_identifier(is_cur_col, "is_current column")
        for _col in business_key:
            _validate_identifier(_col, "business key column")
        where_clause = " AND ".join(f"{col} = :{col}" for col in business_key)
        sql = (
            f"UPDATE {fqn} "  # noqa: S608
            f"SET {eff_to_col} = :eff_to, {is_cur_col} = 0 "
            f"WHERE {where_clause} AND {is_cur_col} = 1"
        )
        with engine.begin() as conn:
            for key_dict in to_expire:
                params = dict(key_dict)
                params["eff_to"] = now
                conn.execute(text(sql), params)
        log.debug(
            "[%s] SCD2: expired %d rows.", self._name, len(to_expire)
        )


# ── Module helpers ────────────────────────────────────────────────────────────

def _lookup_row(
    current_target: list[dict[str, Any]],
    key: dict[str, Any],
    business_key: list[str],
) -> dict[str, Any] | None:
    """Find the first row in *current_target* whose business key matches *key*."""
    for row in current_target:
        if all(_vals_equal(row.get(k), key.get(k)) for k in business_key):
            return row
    return None


def _vals_equal(a: Any, b: Any) -> bool:
    """Null-safe equality comparison."""
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    return str(a).strip() == str(b).strip()


def _vals_differ(a: Any, b: Any) -> bool:
    return not _vals_equal(a, b)
