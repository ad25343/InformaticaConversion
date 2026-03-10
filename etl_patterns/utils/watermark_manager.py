"""
utils/watermark_manager.py — ETL_WATERMARKS control-table reader / writer
==========================================================================
Manages high-water-mark values for incremental_append and upsert patterns.
Reads the last successful watermark from a control table and writes the new
value after a successful load.

Control table DDL (auto-created on first use)
---------------------------------------------
CREATE TABLE ETL_WATERMARKS (
    mapping_name   VARCHAR(200) NOT NULL,
    watermark_col  VARCHAR(200) NOT NULL,
    watermark_val  VARCHAR(500),          -- serialised as string; cast on read
    updated_at     TIMESTAMP NOT NULL,
    PRIMARY KEY (mapping_name, watermark_col)
);

Config block (inside the pattern YAML)
---------------------------------------
source:
  watermark:
    column:    UPDATED_AT
    data_type: datetime          # string | integer | decimal | datetime | date
    initial:   "1900-01-01"      # seed value for first run
    table:     ETL_WATERMARKS    # optional override (default: ETL_WATERMARKS)

Connection to the control table uses the same SQLAlchemy engine that is
passed into the pattern.  If a dedicated control_db engine is not provided
the source engine is used.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Engine

from etl_patterns.exceptions import WatermarkError
from etl_patterns.utils.type_cast import type_cast

log = logging.getLogger(__name__)

_DEFAULT_TABLE = "ETL_WATERMARKS"

_DDL = """
CREATE TABLE IF NOT EXISTS {table} (
    mapping_name   VARCHAR(200)  NOT NULL,
    watermark_col  VARCHAR(200)  NOT NULL,
    watermark_val  VARCHAR(500),
    updated_at     TIMESTAMP     NOT NULL,
    PRIMARY KEY (mapping_name, watermark_col)
)
"""


class WatermarkManager:
    """
    Reads and writes ETL watermarks in a relational control table.

    Parameters
    ----------
    engine          SQLAlchemy Engine pointing at the control DB.
    table           Override the default control table name.
    auto_create     Create the table if it does not exist (default True).
    """

    def __init__(
        self,
        engine: Engine,
        *,
        table: str = _DEFAULT_TABLE,
        auto_create: bool = True,
    ) -> None:
        self._engine = engine
        self._table  = table
        if auto_create:
            self._ensure_table()

    # ── Public API ────────────────────────────────────────────────────────────

    def get_watermark(
        self,
        mapping_name: str,
        watermark_col: str,
        data_type: str = "string",
        initial: Any = None,
    ) -> Any:
        """
        Return the current watermark value for *mapping_name* / *watermark_col*.

        If no row exists yet, *initial* is returned (seed value for first run).

        Parameters
        ----------
        mapping_name   Unique identifier for the mapping (e.g. "m_acct_load").
        watermark_col  Column name that is tracked (e.g. "UPDATED_AT").
        data_type      Target type for the returned value ("datetime", "integer", …).
        initial        Value to return when no watermark exists yet.
        """
        sql = text(
            f"SELECT watermark_val FROM {self._table} "  # noqa: S608
            " WHERE mapping_name = :mn AND watermark_col = :wc"
        )
        try:
            with self._engine.connect() as conn:
                row = conn.execute(sql, {"mn": mapping_name, "wc": watermark_col}).fetchone()
        except Exception as exc:
            raise WatermarkError(
                f"Failed to read watermark for {mapping_name}/{watermark_col}: {exc}"
            ) from exc

        if row is None:
            log.info(
                "No watermark found for %s/%s — using initial value %r",
                mapping_name, watermark_col, initial,
            )
            return initial

        raw = row[0]
        if raw is None:
            return initial

        return type_cast(raw, data_type, default=initial)

    def set_watermark(
        self,
        mapping_name: str,
        watermark_col: str,
        value: Any,
    ) -> None:
        """
        Persist *value* as the new watermark for *mapping_name* / *watermark_col*.

        The value is serialised to a string for storage (VARCHAR 500).
        """
        serialised = _serialise(value)
        now        = datetime.now(tz=timezone.utc)

        upsert_sql = _build_upsert(self._table)
        try:
            with self._engine.begin() as conn:
                conn.execute(
                    text(upsert_sql),
                    {
                        "mn":  mapping_name,
                        "wc":  watermark_col,
                        "val": serialised,
                        "ts":  now,
                    },
                )
            log.info(
                "Watermark updated: %s/%s = %r",
                mapping_name, watermark_col, serialised,
            )
        except Exception as exc:
            raise WatermarkError(
                f"Failed to write watermark for {mapping_name}/{watermark_col}: {exc}"
            ) from exc

    # ── Internals ─────────────────────────────────────────────────────────────

    def _ensure_table(self) -> None:
        """Create the watermark table if it does not exist."""
        try:
            with self._engine.begin() as conn:
                conn.execute(text(_DDL.format(table=self._table)))
        except Exception as exc:
            raise WatermarkError(f"Failed to ensure watermark table: {exc}") from exc


# ── Module-level convenience functions ───────────────────────────────────────

def read_watermark(
    engine: Engine,
    mapping_name: str,
    watermark_col: str,
    data_type: str = "string",
    initial: Any = None,
    *,
    table: str = _DEFAULT_TABLE,
) -> Any:
    """Convenience wrapper — creates a WatermarkManager and reads in one call."""
    return WatermarkManager(engine, table=table).get_watermark(
        mapping_name, watermark_col, data_type, initial
    )


def write_watermark(
    engine: Engine,
    mapping_name: str,
    watermark_col: str,
    value: Any,
    *,
    table: str = _DEFAULT_TABLE,
) -> None:
    """Convenience wrapper — creates a WatermarkManager and writes in one call."""
    WatermarkManager(engine, table=table).set_watermark(mapping_name, watermark_col, value)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _serialise(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _build_upsert(table: str) -> str:
    """
    Build a dialect-agnostic upsert.  We use a DELETE + INSERT pattern which
    works on SQLite, PostgreSQL, MySQL, and SQL Server without dialect flags.
    """
    return (
        f"DELETE FROM {table} WHERE mapping_name = :mn AND watermark_col = :wc; "
        f"INSERT INTO {table} (mapping_name, watermark_col, watermark_val, updated_at) "
        f"VALUES (:mn, :wc, :val, :ts)"
    )
