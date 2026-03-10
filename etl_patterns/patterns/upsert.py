"""
patterns/upsert.py — SCD Type 1 upsert (merge-on-key) pattern
==============================================================
Equivalent to Informatica mappings that implement a SCD Type 1 merge:
existing target rows matching the business key are overwritten with the
latest source values; new keys are inserted.  No history is preserved.

How it works
------------
1. ``transform()`` applies an optional ``column_map`` via the expression DSL.
2. ``_write()`` (via BasePattern) delegates to ``DatabaseWriter._write_upsert()``,
   which executes a dialect-agnostic DELETE-matching-keys + batch INSERT loop.

Config example
--------------
pattern:      upsert
mapping_name: m_customer_scd1

source:
  type:              database
  connection_string: postgresql+psycopg2://user:pass@host/oltp
  table:             STG_CUSTOMERS

target:
  type:              database
  connection_string: postgresql+psycopg2://user:pass@host/dw
  table:             DIM_CUSTOMERS
  write_mode:        upsert
  unique_key:        [CUSTOMER_ID]      # required — business key for the merge
  chunksize:         10000              # rows per DELETE+INSERT batch

# Optional column mapping
column_map:
  - target_col: CUSTOMER_ID
    expression: "{CUSTOMER_ID}"
  - target_col: FULL_NAME
    expression: "concat({FIRST_NAME}, ' ', {LAST_NAME})"
  - target_col: STATUS
    expression: "{STATUS}"

etl_metadata: true
"""
from __future__ import annotations

import logging
from typing import Any

import pandas as pd

from etl_patterns.exceptions import ConfigError
from etl_patterns.expression import apply_column_map
from etl_patterns.patterns.base import BasePattern

log = logging.getLogger(__name__)


class UpsertPattern(BasePattern):
    """
    SCD Type 1 upsert — merge source rows into target on a unique business key.

    Existing rows that match the key are replaced; new keys are inserted.
    No history is preserved (use ``scd2`` for full history).
    """

    # ── Validation ────────────────────────────────────────────────────────────

    def pre_load(self) -> None:
        """Validate that ``unique_key`` is configured on the target before reading."""
        tgt = self._cfg.get("target", {})
        if not tgt.get("unique_key"):
            raise ConfigError(
                f"[{self._name}] upsert pattern requires 'unique_key' on the target config. "
                "Example: unique_key: [CUSTOMER_ID]"
            )
        # Coerce to list if a bare string was supplied
        if isinstance(tgt["unique_key"], str):
            tgt["unique_key"] = [tgt["unique_key"]]
        # Ensure write_mode is upsert
        if tgt.get("write_mode", "").lower() not in ("upsert", ""):
            log.warning(
                "[%s] target write_mode is %r — overriding to 'upsert'",
                self._name, tgt["write_mode"],
            )
        tgt["write_mode"] = "upsert"

    # ── Transform ─────────────────────────────────────────────────────────────

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply optional column_map, then return the DataFrame for upsert writing."""
        column_map = self._cfg.get("column_map")
        if not column_map:
            return df

        rows = []
        for _, row in df.iterrows():
            rows.append(apply_column_map(column_map, row.to_dict()))
        result = pd.DataFrame(rows)

        # Validate that all unique_key columns are present after the transform
        unique_key: list[str] = self._cfg.get("target", {}).get("unique_key", [])
        missing = [k for k in unique_key if k not in result.columns]
        if missing:
            raise ConfigError(
                f"[{self._name}] unique_key column(s) {missing} not found in the "
                "output DataFrame after applying column_map. Ensure each key column "
                "has a mapping entry in column_map."
            )
        return result
