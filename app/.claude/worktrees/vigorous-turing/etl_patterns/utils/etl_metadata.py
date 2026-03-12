"""
utils/etl_metadata.py — Standard ETL audit column injection
============================================================
Appends a consistent set of audit columns to every DataFrame before it is
written to the target.  Eliminates the repeated EXP ports that every Informatica
mapping adds for ETL tracking.

Standard columns
----------------
ETL_LOAD_DATE     Timestamp when the row was written (UTC).
ETL_BATCH_ID      Unique identifier for the current run.
ETL_SOURCE_SYSTEM Name of the source system (from config).
ETL_SOURCE_FILE   File path for file-based loads; None/NULL for DB loads.
ETL_RUN_ID        Optional run ID from the control framework.

Config forms
------------
# All columns with defaults:
etl_metadata: true

# Fine-grained control:
etl_metadata:
  load_date: true
  batch_id: true
  source_system: "FIRSTBANK_OLTP"
  source_file: true          # populated automatically for file-based sources
  run_id: false
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import pandas as pd

# ── Column name constants ────────────────────────────────────────────────────
COL_LOAD_DATE     = "ETL_LOAD_DATE"
COL_BATCH_ID      = "ETL_BATCH_ID"
COL_SOURCE_SYSTEM = "ETL_SOURCE_SYSTEM"
COL_SOURCE_FILE   = "ETL_SOURCE_FILE"
COL_RUN_ID        = "ETL_RUN_ID"


def add_etl_metadata(
    df: pd.DataFrame,
    config: bool | dict[str, Any],
    *,
    source_system: str = "",
    source_file: str | None = None,
    batch_id: str | None = None,
    run_id: str | None = None,
    run_ts: datetime | None = None,
) -> pd.DataFrame:
    """
    Append ETL audit columns to a DataFrame.

    Parameters
    ----------
    df            The DataFrame to augment.
    config        True (all defaults) or a dict with fine-grained control.
    source_system Override or supplement the source_system from config.
    source_file   File path for file-based sources; None for DB sources.
    batch_id      Batch identifier — auto-generated UUID4 if not provided.
    run_id        Optional run ID from the control framework.
    run_ts        Timestamp to use; defaults to utcnow().

    Returns
    -------
    A new DataFrame with the ETL columns appended.  The original is not mutated.
    """
    if config is False:
        return df

    cfg = _normalise_config(config)
    ts  = run_ts or datetime.now(tz=timezone.utc)
    bid = batch_id or str(uuid.uuid4())

    result = df.copy()

    if cfg.get("load_date", True):
        result[COL_LOAD_DATE] = ts

    if cfg.get("batch_id", True):
        result[COL_BATCH_ID] = bid

    if cfg.get("source_system", True):
        sys_name = cfg.get("source_system") if isinstance(cfg.get("source_system"), str) else source_system
        result[COL_SOURCE_SYSTEM] = sys_name or ""

    if cfg.get("source_file", True):
        result[COL_SOURCE_FILE] = source_file  # None → NULL in DB write

    if cfg.get("run_id", False):
        result[COL_RUN_ID] = run_id

    return result


def metadata_columns(config: bool | dict[str, Any]) -> list[str]:
    """
    Return the list of ETL metadata column names that will be added for a given
    config.  Useful for schema validation before writing.
    """
    if config is False:
        return []
    cfg  = _normalise_config(config)
    cols = []
    if cfg.get("load_date",     True):  cols.append(COL_LOAD_DATE)
    if cfg.get("batch_id",      True):  cols.append(COL_BATCH_ID)
    if cfg.get("source_system", True):  cols.append(COL_SOURCE_SYSTEM)
    if cfg.get("source_file",   True):  cols.append(COL_SOURCE_FILE)
    if cfg.get("run_id",        False): cols.append(COL_RUN_ID)
    return cols


# ── Helpers ──────────────────────────────────────────────────────────────────

def _normalise_config(config: bool | dict[str, Any]) -> dict[str, Any]:
    """Normalise the etl_metadata config value to a dict."""
    if config is True:
        return {
            "load_date":     True,
            "batch_id":      True,
            "source_system": True,
            "source_file":   True,
            "run_id":        False,
        }
    if isinstance(config, dict):
        return config
    raise TypeError(f"etl_metadata config must be bool or dict, got {type(config).__name__}")
