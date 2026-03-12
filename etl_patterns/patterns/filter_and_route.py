# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
patterns/filter_and_route.py — Filter-and-route (conditional multi-target) pattern
====================================================================================
Equivalent to Informatica mappings that use a Router transformation to send each
source row to one (or more) target tables based on per-target conditions.

Behaviour
---------
- Reads one source (same as all other patterns).
- Evaluates a ``filter_expr`` for each target; rows that satisfy the condition are
  written to that target.
- A single source row CAN match multiple target conditions (e.g. an "all records"
  catch-all target alongside a filtered target).  If you want mutually-exclusive
  routing (like Informatica's default router), structure your expressions accordingly.
- An optional per-target ``column_map`` is applied to the filtered subset before
  writing.
- Rows that match **no** target are silently dropped (Informatica default router
  behaviour for the "else" group when no else target is configured).

Config example
--------------
pattern:      filter_and_route
mapping_name: m_txn_route

source:
  type: flat_file
  path: /data/transactions/*.csv

target:
  - name:        HIGH_VALUE
    type:        flat_file
    path:        /output/high_value_{date}.csv
    write_mode:  overwrite
    filter_expr: "{AMOUNT} > 10000"

  - name:        REFUNDS
    type:        flat_file
    path:        /output/refunds_{date}.csv
    write_mode:  overwrite
    filter_expr: "{TXN_TYPE} == 'REFUND'"
    column_map:
      - target_col: TXN_ID
        expression: "{TXN_ID}"
      - target_col: REFUND_AMT
        expression: "{AMOUNT}"

  - name:        ALL_RECORDS
    type:        database
    connection_string: postgresql+psycopg2://user:pass@host/dw
    table:       FACT_TXN
    write_mode:  append
    filter_expr: "true"     # catch-all — every row lands here

etl_metadata: true
"""
from __future__ import annotations

import logging
from typing import Any

import pandas as pd

from etl_patterns.exceptions import ConfigError
from etl_patterns.expression import apply_column_map, evaluate
from etl_patterns.patterns.base import BasePattern

log = logging.getLogger(__name__)


class FilterAndRoutePattern(BasePattern):
    """
    Route source rows to N targets based on per-target ``filter_expr`` conditions.

    Each writer in ``self._writers`` is paired with the corresponding target config
    dict from ``config["target"]``.  Filtering and optional per-target column_map
    are applied inside the overridden ``_write()`` method.
    """

    def pre_load(self) -> None:
        """Validate that target is a list and every entry has a filter_expr."""
        tgt = self._cfg.get("target")
        if not isinstance(tgt, list):
            raise ConfigError(
                f"[{self._name}] filter_and_route requires 'target' to be a list of "
                "target configs, each with a 'filter_expr' field."
            )
        if not tgt:
            raise ConfigError(
                f"[{self._name}] filter_and_route requires at least one entry in 'target'."
            )
        for i, entry in enumerate(tgt):
            if not entry.get("filter_expr"):
                raise ConfigError(
                    f"[{self._name}] target[{i}] (name={entry.get('name', '?')!r}) "
                    "is missing 'filter_expr'. Use \"true\" to match all rows."
                )

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Pass-through — routing happens in _write()."""
        return df

    # ── Overridden write ───────────────────────────────────────────────────────

    def _write(self, df: pd.DataFrame) -> int:
        """
        For each (writer, target_cfg) pair:
          1. Filter source rows using ``filter_expr``.
          2. Apply per-target ``column_map`` if present.
          3. Write the filtered (and optionally remapped) subset.

        Returns the total number of rows written across all targets.
        """
        targets: list[dict[str, Any]] = self._cfg["target"]
        total_written = 0

        for writer, tgt_cfg in zip(self._writers, targets):
            tgt_name    = tgt_cfg.get("name", f"target_{id(writer)}")
            filter_expr = tgt_cfg["filter_expr"]
            column_map  = tgt_cfg.get("column_map")

            # ── Step 1: filter ────────────────────────────────────────────────
            subset = self._filter_rows(df, filter_expr, tgt_name)

            if subset.empty:
                log.info(
                    "[%s] target '%s': 0/%d rows matched — skipping write.",
                    self._name, tgt_name, len(df),
                )
                continue

            log.info(
                "[%s] target '%s': %d/%d rows matched filter '%s'.",
                self._name, tgt_name, len(subset), len(df), filter_expr,
            )

            # ── Step 2: optional per-target column_map ────────────────────────
            if column_map:
                rows = []
                for _, row in subset.iterrows():
                    rows.append(apply_column_map(column_map, row.to_dict()))
                subset = pd.DataFrame(rows)

            # ── Step 3: write ─────────────────────────────────────────────────
            n = writer.write(subset)
            total_written += n
            log.info(
                "[%s] target '%s': wrote %d rows.",
                self._name, tgt_name, n,
            )

        return total_written

    # ── Internals ─────────────────────────────────────────────────────────────

    def _filter_rows(
        self,
        df: pd.DataFrame,
        filter_expr: str,
        tgt_name: str,
    ) -> pd.DataFrame:
        """Return the subset of *df* where *filter_expr* evaluates to truthy."""
        # Non-string literal (e.g. YAML ``true`` parsed as Python True)
        if not isinstance(filter_expr, str):
            return df.copy() if filter_expr else df.iloc[0:0].copy()

        keep: list[bool] = []
        for _, row in df.iterrows():
            try:
                result = evaluate(filter_expr, row.to_dict())
                keep.append(bool(result))
            except Exception as exc:
                log.debug(
                    "[%s] target '%s': filter_expr '%s' raised %s — row excluded.",
                    self._name, tgt_name, filter_expr, exc,
                )
                keep.append(False)

        return df[keep].reset_index(drop=True)
