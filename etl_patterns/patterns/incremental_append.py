"""
patterns/incremental_append.py — Watermark-driven incremental append pattern
==============================================================================
Equivalent to Informatica mappings that use a watermark column (e.g. UPDATED_AT
or a monotonic integer key) to read only new / changed rows since the last
successful run, then append them to the target table.

How it works
------------
1. ``pre_load()`` — reads the current high-water-mark from ETL_WATERMARKS (or
   returns the ``initial`` seed value on the very first run), then patches the
   reader so the next ``read()`` call returns only rows newer than the watermark.
2. ``transform()`` — applies an optional ``column_map`` via the expression DSL.
   For flat-file sources, also applies the in-memory watermark filter here.
3. ``post_load()`` — after a successful write, finds the MAX of the watermark
   column in the loaded DataFrame and persists it back to ETL_WATERMARKS.

Config example — database source
---------------------------------
pattern:      incremental_append
mapping_name: m_txn_append

source:
  type:              database
  connection_string: postgresql+psycopg2://user:pass@host/oltp
  table:             TRANSACTIONS
  watermark:
    column:       UPDATED_AT
    data_type:    datetime
    initial:      "1900-01-01 00:00:00"
    table:        ETL_WATERMARKS          # optional override

  # Optional: separate DB for the watermark control table
  # control_connection_string: sqlite:///control.db

target:
  type:              database
  connection_string: postgresql+psycopg2://user:pass@host/dw
  table:             FACT_TRANSACTIONS
  write_mode:        append               # MUST be append for this pattern

# Optional column mapping / expression transforms
column_map:
  - target_col: TXN_KEY
    expression: "{TXN_ID}"
  - target_col: AMOUNT_USD
    expression: "{AMOUNT}"
  - target_col: LOAD_FLAG
    expression: "true"

etl_metadata: true

Config example — flat-file source
----------------------------------
source:
  type:    flat_file
  path:    /data/exports/transactions_*.csv
  watermark:
    column:    UPDATED_AT
    data_type: datetime
    initial:   "1900-01-01"
  control_connection_string: sqlite:///control.db
"""
from __future__ import annotations

import logging
from typing import Any

import pandas as pd
from sqlalchemy import create_engine, text as _sql_text

from etl_patterns.exceptions import ConfigError, PatternError
from etl_patterns.expression import apply_column_map
from etl_patterns.io.readers.db_reader import DatabaseReader
from etl_patterns.patterns.base import BasePattern
from etl_patterns.utils.watermark_manager import WatermarkManager

log = logging.getLogger(__name__)


class IncrementalAppendPattern(BasePattern):
    """Watermark-driven incremental append — reads new rows, appends to target."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._watermark_val: Any = None
        self._wm_mgr: WatermarkManager | None = None
        # Set for flat-file sources so transform() knows to apply an in-memory filter
        self._ff_wm_col: str | None = None
        self._ff_wm_dtype: str = "string"

    # ── Lifecycle hooks ───────────────────────────────────────────────────────

    def pre_load(self) -> None:
        """
        1. Read / seed the watermark.
        2. Patch the reader so the next read() call is watermark-filtered.
        """
        wm_cfg = self._cfg.get("source", {}).get("watermark")
        if not wm_cfg:
            raise ConfigError(
                f"[{self._name}] incremental_append requires a 'watermark' block "
                "inside the 'source' config section."
            )

        self._wm_mgr = self._build_wm_manager(wm_cfg)
        self._watermark_val = self._wm_mgr.get_watermark(
            mapping_name  = self._name,
            watermark_col = wm_cfg["column"],
            data_type     = wm_cfg.get("data_type", "string"),
            initial       = wm_cfg.get("initial"),
        )
        log.info(
            "[%s] Watermark '%s' = %r",
            self._name,
            wm_cfg["column"],
            self._watermark_val,
        )

        # Patch the reader so the actual read() uses the filtered query.
        if isinstance(self._reader, DatabaseReader):
            self._patch_db_reader(wm_cfg["column"])
        else:
            # Flat-file: full read, then filter in transform()
            self._ff_wm_col   = wm_cfg["column"]
            self._ff_wm_dtype = wm_cfg.get("data_type", "string")

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply in-memory watermark filter (flat-file only), then column_map."""
        # Flat-file watermark filter
        if self._ff_wm_col and self._ff_wm_col in df.columns:
            df = self._filter_by_watermark(df, self._ff_wm_col, self._ff_wm_dtype)

        # Column expression map
        column_map = self._cfg.get("column_map")
        if not column_map:
            return df

        rows = []
        for _, row in df.iterrows():
            rows.append(apply_column_map(column_map, row.to_dict()))
        return pd.DataFrame(rows)

    def post_load(self, df: pd.DataFrame) -> None:
        """Advance the watermark to the MAX value in this batch."""
        wm_cfg = self._cfg.get("source", {}).get("watermark", {})
        wm_col = wm_cfg.get("column")
        if not wm_col or self._wm_mgr is None or df.empty:
            if df.empty:
                log.info("[%s] Zero rows loaded — watermark unchanged.", self._name)
            return

        # The watermark col may have been renamed by column_map.
        target_col = _find_watermark_col(df, wm_col, self._cfg.get("column_map"))
        if target_col is None or target_col not in df.columns:
            log.warning(
                "[%s] Watermark column '%s' not found in output DataFrame — "
                "watermark NOT advanced.",
                self._name, wm_col,
            )
            return

        new_val = df[target_col].max()
        if pd.isna(new_val):
            log.warning(
                "[%s] MAX('%s') is NULL — watermark NOT advanced.",
                self._name, target_col,
            )
            return

        self._wm_mgr.set_watermark(
            mapping_name  = self._name,
            watermark_col = wm_col,
            value         = new_val,
        )
        log.info(
            "[%s] Watermark '%s' advanced to %r", self._name, wm_col, new_val
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _patch_db_reader(self, wm_col: str) -> None:
        """
        Replace the DatabaseReader's ``read()`` with a closure that executes
        the watermark-filtered SQL.  This is called from ``pre_load()`` so the
        patched method is in place when BasePattern.execute() calls read().
        """
        sql, params = self._reader.build_incremental_query(self._watermark_val)
        engine  = self._reader.get_engine()
        name    = self._name
        wm_val  = self._watermark_val

        def _filtered_read() -> pd.DataFrame:
            with engine.connect() as conn:
                result_df = pd.read_sql(_sql_text(sql), conn, params=params)
            log.info(
                "[%s] Incremental DB read: %d rows (watermark col=%s > %r)",
                name, len(result_df), wm_col, wm_val,
            )
            return result_df

        self._reader.read = _filtered_read  # type: ignore[method-assign]

    def _build_wm_manager(self, wm_cfg: dict) -> WatermarkManager:
        """Build a WatermarkManager using source or dedicated control engine."""
        ctrl_conn = self._cfg.get("source", {}).get("control_connection_string")
        if ctrl_conn:
            engine = create_engine(ctrl_conn, future=True)
        elif isinstance(self._reader, DatabaseReader):
            engine = self._reader.get_engine()
        else:
            raise PatternError(
                f"[{self._name}] incremental_append with a flat-file source requires "
                "a 'control_connection_string' inside the 'source' config to persist "
                "watermarks."
            )
        table = wm_cfg.get("table", "ETL_WATERMARKS")
        return WatermarkManager(engine, table=table)

    def _filter_by_watermark(
        self,
        df: pd.DataFrame,
        col: str,
        dtype: str,
    ) -> pd.DataFrame:
        """Filter DataFrame rows where col > current watermark (flat-file path)."""
        if self._watermark_val is None:
            return df

        wm = self._watermark_val
        try:
            mask = pd.to_datetime(df[col]) > pd.to_datetime(wm)
        except Exception:
            try:
                mask = df[col].astype(str) > str(wm)
            except Exception:
                log.warning(
                    "[%s] Could not filter column '%s' by watermark — returning all rows.",
                    self._name, col,
                )
                return df

        filtered = df[mask]
        log.info(
            "[%s] Flat-file watermark filter: %d/%d rows kept (col=%s > %r)",
            self._name, len(filtered), len(df), col, wm,
        )
        return filtered.reset_index(drop=True)


# ── Module helpers ────────────────────────────────────────────────────────────

def _find_watermark_col(
    df: pd.DataFrame,
    original_col: str,
    column_map: list | None,
) -> str | None:
    """
    Find which column in *df* corresponds to the watermark column.

    Checks: (1) original name unchanged, (2) a target_col in column_map whose
    expression is exactly ``{ORIGINAL_COL}``.
    """
    if original_col in df.columns:
        return original_col

    if column_map:
        for entry in column_map:
            expr = str(entry.get("expression", "")).strip()
            if expr == f"{{{original_col}}}":
                target = entry.get("target_col")
                if target and target in df.columns:
                    return target

    return None
