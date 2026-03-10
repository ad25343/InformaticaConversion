"""
io/readers/db_reader.py — SQLAlchemy database reader
=====================================================
Reads source data from any SQLAlchemy-supported database.

Config block (``source:`` section of the pattern YAML)
-------------------------------------------------------
source:
  type: database
  name: SRC_ACCOUNTS            # optional label
  connection_string: postgresql+psycopg2://user:pass@host/db
  # --- ONE of the following ---
  table:  ACCOUNTS              # simple full-table read
  query: >                      # custom SQL (use when filters / joins are in the mapping)
    SELECT acct_id, name, balance
    FROM ACCOUNTS
    WHERE status = 'ACTIVE'
  # --- Optional watermark filter (injected at runtime by incremental_append) ---
  watermark:
    column:    UPDATED_AT
    data_type: datetime
    initial:   "1900-01-01"
  # --- Optional schema / chunksize ---
  schema:    dbo
  chunksize: 100000
"""
from __future__ import annotations

import logging
from typing import Iterator

import pandas as pd
from sqlalchemy import create_engine, text

from etl_patterns.exceptions import ConfigError, ReaderError
from etl_patterns.io.base import BaseReader

log = logging.getLogger(__name__)


class DatabaseReader(BaseReader):
    """Read a full table or custom SQL query via SQLAlchemy."""

    def __init__(self, config: dict) -> None:
        super().__init__(config)
        self._engine = None  # lazy init

    # ── Public ────────────────────────────────────────────────────────────────

    def read(self) -> pd.DataFrame:
        """Read the entire result set into a DataFrame."""
        sql, params = self._build_query()
        engine = self._get_engine()
        try:
            log.info("DatabaseReader: reading from %s", self.source_name)
            with engine.connect() as conn:
                df = pd.read_sql(text(sql), conn, params=params)
            log.info("DatabaseReader: %d rows read", len(df))
            return df
        except Exception as exc:
            raise ReaderError(f"Failed to read from {self.source_name}: {exc}") from exc

    def read_chunks(self, chunksize: int | None = None) -> Iterator[pd.DataFrame]:
        """Yield chunks using pandas chunksize support."""
        cs    = chunksize or self._cfg.get("chunksize", 100_000)
        sql, params = self._build_query()
        engine = self._get_engine()
        try:
            log.info(
                "DatabaseReader: chunked read from %s (chunksize=%d)",
                self.source_name, cs,
            )
            with engine.connect() as conn:
                for chunk in pd.read_sql(text(sql), conn, params=params, chunksize=cs):
                    yield chunk
        except Exception as exc:
            raise ReaderError(
                f"Failed during chunked read from {self.source_name}: {exc}"
            ) from exc

    def get_engine(self):  # noqa: ANN201
        """Expose the engine for patterns that need it (e.g. watermark writes)."""
        return self._get_engine()

    # ── Internals ─────────────────────────────────────────────────────────────

    def _get_engine(self):
        if self._engine is None:
            conn_str = self._cfg.get("connection_string")
            if not conn_str:
                raise ConfigError(
                    f"source '{self.source_name}' is missing 'connection_string'"
                )
            self._engine = create_engine(conn_str, future=True)
        return self._engine

    def _build_query(self, watermark_val=None) -> tuple[str, dict]:
        """
        Build the SQL query and params dict.

        If a ``watermark`` block is present and *watermark_val* is supplied,
        a WHERE clause is appended (handled by the pattern, not the reader).
        This method builds the base query only.
        """
        if "query" in self._cfg:
            return self._cfg["query"], {}

        table  = self._cfg.get("table")
        if not table:
            raise ConfigError(
                f"source '{self.source_name}' must have 'table' or 'query'"
            )
        schema = self._cfg.get("schema")
        fqn    = f"{schema}.{table}" if schema else table
        return f"SELECT * FROM {fqn}", {}  # noqa: S608

    def build_incremental_query(self, watermark_val) -> tuple[str, dict]:
        """
        Build a watermark-filtered query for incremental_append pattern.

        Returns (sql, params) where params contains the watermark value.
        """
        wm_cfg = self._cfg.get("watermark")
        if not wm_cfg:
            raise ConfigError(
                f"source '{self.source_name}' has no 'watermark' block for incremental read"
            )
        col = wm_cfg["column"]

        base_sql, _ = self._build_query()
        if "WHERE" in base_sql.upper():
            sql = f"{base_sql} AND {col} > :wm_val"
        else:
            sql = f"{base_sql} WHERE {col} > :wm_val"

        return sql, {"wm_val": watermark_val}
