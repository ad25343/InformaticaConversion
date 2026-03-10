"""
io/writers/db_writer.py — SQLAlchemy database writer
=====================================================
Supports four write modes:
  append        — INSERT rows; fail on PK collision (default for incremental_append)
  replace       — DROP + recreate table then INSERT (truncate_and_load)
  upsert        — Merge on unique_key columns (upsert pattern)
  scd2          — Specialised SCD2 merge; handled by the scd2 pattern, not here

Config block (``target:`` section of the pattern YAML)
-------------------------------------------------------
target:
  type: database
  name: DIM_CUSTOMER
  connection_string: postgresql+psycopg2://user:pass@host/dw
  table:  DIM_CUSTOMER
  schema: dbo                    # optional
  write_mode: append             # append | replace | upsert
  unique_key: [CUSTOMER_ID]      # required for write_mode: upsert
  chunksize: 10000               # rows per INSERT batch
  if_exists: append              # pandas fallback; overridden by write_mode
"""
from __future__ import annotations

import logging
from typing import List

import pandas as pd
from sqlalchemy import create_engine, text

from etl_patterns.exceptions import ConfigError, WriterError
from etl_patterns.io.base import BaseWriter

log = logging.getLogger(__name__)


class DatabaseWriter(BaseWriter):
    """Write a DataFrame to a relational database table."""

    def __init__(self, config: dict) -> None:
        super().__init__(config)
        self._engine = None

    # ── Public ────────────────────────────────────────────────────────────────

    def write(self, df: pd.DataFrame) -> int:
        mode = self._cfg.get("write_mode", "append").lower()
        if mode == "replace":
            return self._write_replace(df)
        if mode == "upsert":
            return self._write_upsert(df)
        return self._write_append(df)

    def truncate(self) -> None:
        """Truncate the target table (used by truncate_and_load pattern)."""
        table = self._fqn()
        engine = self._get_engine()
        try:
            with engine.begin() as conn:
                conn.execute(text(f"TRUNCATE TABLE {table}"))  # noqa: S608
            log.info("Truncated %s", table)
        except Exception as exc:
            raise WriterError(f"Failed to truncate {table}: {exc}") from exc

    def get_engine(self):  # noqa: ANN201
        return self._get_engine()

    # ── Write modes ───────────────────────────────────────────────────────────

    def _write_append(self, df: pd.DataFrame) -> int:
        """Standard INSERT — uses pandas to_sql with if_exists='append'."""
        table     = self._cfg.get("table")
        schema    = self._cfg.get("schema")
        chunksize = self._cfg.get("chunksize", 10_000)
        engine    = self._get_engine()

        if not table:
            raise ConfigError(f"target '{self.target_name}' is missing 'table'")

        try:
            df.to_sql(
                name      = table,
                con       = engine,
                schema    = schema,
                if_exists = "append",
                index     = False,
                chunksize = chunksize,
                method    = "multi",
            )
            log.info("DatabaseWriter: appended %d rows to %s", len(df), self._fqn())
            return len(df)
        except Exception as exc:
            raise WriterError(f"Failed to append to {self._fqn()}: {exc}") from exc

    def _write_replace(self, df: pd.DataFrame) -> int:
        """DROP + recreate via pandas if_exists='replace', then INSERT."""
        table     = self._cfg.get("table")
        schema    = self._cfg.get("schema")
        chunksize = self._cfg.get("chunksize", 10_000)
        engine    = self._get_engine()

        if not table:
            raise ConfigError(f"target '{self.target_name}' is missing 'table'")

        try:
            df.to_sql(
                name      = table,
                con       = engine,
                schema    = schema,
                if_exists = "replace",
                index     = False,
                chunksize = chunksize,
                method    = "multi",
            )
            log.info("DatabaseWriter: replaced %d rows in %s", len(df), self._fqn())
            return len(df)
        except Exception as exc:
            raise WriterError(f"Failed to replace {self._fqn()}: {exc}") from exc

    def _write_upsert(self, df: pd.DataFrame) -> int:
        """
        Merge-style upsert: DELETE matching rows then INSERT.

        This dialect-agnostic implementation works on any SQLAlchemy-supported DB.
        Production users on a specific warehouse may override with native MERGE.
        """
        table      = self._cfg.get("table")
        schema     = self._cfg.get("schema")
        unique_key: List[str] = self._cfg.get("unique_key") or []
        chunksize  = self._cfg.get("chunksize", 10_000)
        engine     = self._get_engine()

        if not table:
            raise ConfigError(f"target '{self.target_name}' is missing 'table'")
        if not unique_key:
            raise ConfigError(f"target '{self.target_name}' upsert requires 'unique_key'")

        fqn = self._fqn()
        try:
            # Process in chunks to bound memory usage.
            # DELETE and INSERT are split into two separate transactions so that
            # pandas to_sql() (which manages its own connection scope) does not
            # interfere with the DELETE transaction on SQLAlchemy 2.x connections.
            rows_written = 0
            for i in range(0, len(df), chunksize):
                batch = df.iloc[i : i + chunksize]

                # Phase 1 — DELETE matching keys (committed immediately)
                key_vals = batch[unique_key].drop_duplicates()
                with engine.begin() as conn:
                    for _, key_row in key_vals.iterrows():
                        where = " AND ".join(
                            f"{col} = :{col}" for col in unique_key
                        )
                        params = {k: _coerce_param(v) for k, v in dict(key_row).items()}
                        conn.execute(
                            text(f"DELETE FROM {fqn} WHERE {where}"),  # noqa: S608
                            params,
                        )

                # Phase 2 — INSERT new rows
                batch.to_sql(
                    name      = table,
                    con       = engine,
                    schema    = schema,
                    if_exists = "append",
                    index     = False,
                    method    = "multi",
                )
                rows_written += len(batch)
            log.info("DatabaseWriter: upserted %d rows into %s", rows_written, fqn)
            return rows_written
        except Exception as exc:
            raise WriterError(f"Failed to upsert into {fqn}: {exc}") from exc

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_engine(self):
        if self._engine is None:
            conn_str = self._cfg.get("connection_string")
            if not conn_str:
                raise ConfigError(
                    f"target '{self.target_name}' is missing 'connection_string'"
                )
            self._engine = create_engine(conn_str, future=True)
        return self._engine

    def _fqn(self) -> str:
        table  = self._cfg.get("table", "")
        schema = self._cfg.get("schema")
        return f"{schema}.{table}" if schema else table


# ── Module helpers ────────────────────────────────────────────────────────────

def _coerce_param(value):
    """
    Coerce numpy scalar types to native Python types for SQLAlchemy binding.
    numpy.int64 and numpy.float64 may not bind correctly on some dialects.
    """
    import numpy as np  # lazy import — numpy is already a pandas dependency
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, (np.bool_,)):
        return bool(value)
    return value
