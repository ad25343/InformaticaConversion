# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
patterns/aggregation_load.py — GROUP BY aggregation pattern
============================================================
Equivalent to Informatica mappings that use an Aggregator transformation to
compute GROUP BY + aggregate metrics.  Supports all standard aggregation
functions (sum, count, avg, min, max, first, last, nunique) and an optional
``having`` filter applied after aggregation.

Config example
--------------
pattern:      aggregation_load
mapping_name: m_branch_daily_summary

source:
  type:    flat_file
  path:    /data/transactions/*.csv

target:
  type:       database
  connection_string: postgresql+psycopg2://user:pass@host/dw
  table:      BRANCH_DAILY_SUMMARY
  write_mode: replace

# Required — at least one groupby column
group_by:
  - BRANCH_ID
  - TXN_DATE

# Required — at least one aggregate metric
aggregations:
  - target_col: TXN_COUNT
    func:        count
    source_col:  TXN_ID

  - target_col: TOTAL_AMT
    func:        sum
    source_col:  AMOUNT

  - target_col: AVG_AMT
    func:        avg
    source_col:  AMOUNT

  - target_col: MAX_AMT
    func:        max
    source_col:  AMOUNT

  - target_col: UNIQUE_CUSTOMERS
    func:        nunique
    source_col:  CUSTOMER_ID

# Optional: post-aggregation filter (HAVING equivalent)
having: "{TXN_COUNT} > 5"

# Optional: sort order on the output
sort_by:
  - col: TXN_DATE
    asc: true
  - col: TXN_COUNT
    asc: false

etl_metadata: false    # metadata is per-row; not meaningful after aggregation
"""
from __future__ import annotations

import logging
from typing import Any

import pandas as pd

from etl_patterns.exceptions import ConfigError
from etl_patterns.expression import evaluate
from etl_patterns.patterns.base import BasePattern

log = logging.getLogger(__name__)

# Mapping from config function names → pandas named-agg functions
_AGG_FUNC_MAP: dict[str, str] = {
    "sum":     "sum",
    "count":   "count",
    "avg":     "mean",
    "mean":    "mean",
    "min":     "min",
    "max":     "max",
    "first":   "first",
    "last":    "last",
    "nunique": "nunique",
    "std":     "std",
    "var":     "var",
    "median":  "median",
}


class AggregationLoadPattern(BasePattern):
    """GROUP BY aggregation — computes aggregate metrics over the source rows."""

    def pre_load(self) -> None:
        """Validate required config keys."""
        if not self._cfg.get("group_by"):
            raise ConfigError(
                f"[{self._name}] aggregation_load requires 'group_by' (list of columns)."
            )
        aggs = self._cfg.get("aggregations", [])
        if not aggs:
            raise ConfigError(
                f"[{self._name}] aggregation_load requires at least one entry in "
                "'aggregations'."
            )
        # Validate each aggregation entry
        for entry in aggs:
            func = entry.get("func", "").lower()
            if func not in _AGG_FUNC_MAP:
                raise ConfigError(
                    f"[{self._name}] Unknown aggregation function {func!r}. "
                    f"Supported: {sorted(_AGG_FUNC_MAP)}"
                )

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Group, aggregate, apply HAVING filter, and sort."""
        group_by   = self._cfg["group_by"]
        aggs       = self._cfg.get("aggregations", [])
        having_expr = self._cfg.get("having")
        sort_spec  = self._cfg.get("sort_by", [])

        if isinstance(group_by, str):
            group_by = [group_by]

        if df.empty:
            # Return empty DataFrame with the expected output columns
            out_cols = list(group_by) + [a["target_col"] for a in aggs]
            return pd.DataFrame(columns=out_cols)

        # Build pandas named-aggregation dict
        # Format: {target_col: (source_col, pd_func)}
        named_agg: dict[str, Any] = {}
        for entry in aggs:
            target = entry.get("target_col")
            src    = entry.get("source_col")
            func   = entry.get("func", "").lower()

            if not target:
                raise ConfigError(
                    f"[{self._name}] aggregation entry missing 'target_col': {entry}"
                )
            if not src:
                raise ConfigError(
                    f"[{self._name}] aggregation entry missing 'source_col': {entry}"
                )

            pd_func = _AGG_FUNC_MAP.get(func)
            named_agg[target] = (src, pd_func)

        try:
            result = df.groupby(group_by, as_index=False).agg(**named_agg)
        except KeyError as exc:
            raise ConfigError(
                f"[{self._name}] Aggregation failed — column not found: {exc}. "
                f"Available columns: {list(df.columns)}"
            ) from exc

        log.info(
            "[%s] Aggregation: %d source rows → %d groups",
            self._name, len(df), len(result),
        )

        # HAVING filter
        if having_expr:
            result = self._apply_having(result, having_expr)

        # Sort
        if sort_spec:
            result = self._apply_sort(result, sort_spec)

        return result.reset_index(drop=True)

    # ── Internals ─────────────────────────────────────────────────────────────

    def _apply_having(self, df: pd.DataFrame, having_expr: str) -> pd.DataFrame:
        """Post-aggregation row filter (HAVING clause equivalent)."""
        keep: list[bool] = []
        for _, row in df.iterrows():
            try:
                result = evaluate(having_expr, row.to_dict())
                keep.append(bool(result))
            except Exception as exc:
                log.debug(
                    "[%s] having expr '%s' raised %s — row excluded.",
                    self._name, having_expr, exc,
                )
                keep.append(False)

        filtered = df[keep].reset_index(drop=True)
        log.info(
            "[%s] HAVING filter: %d/%d groups kept.",
            self._name, len(filtered), len(df),
        )
        return filtered

    def _apply_sort(
        self,
        df: pd.DataFrame,
        sort_spec: list[dict[str, Any]],
    ) -> pd.DataFrame:
        cols:      list[str]  = []
        ascending: list[bool] = []
        for entry in sort_spec:
            col = entry.get("col")
            if col and col in df.columns:
                cols.append(col)
                ascending.append(bool(entry.get("asc", True)))
        if not cols:
            return df
        return df.sort_values(by=cols, ascending=ascending).reset_index(drop=True)
