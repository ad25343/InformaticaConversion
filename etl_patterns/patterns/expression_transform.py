"""
patterns/expression_transform.py — Expression-driven column transformation pattern
====================================================================================
Equivalent to Informatica mappings that consist primarily of an Expression
transformation: each output column is defined by a formula over the source
columns.  Supports pre-load row filtering, output sorting, and column dedup.

Use this pattern when the Informatica mapping contains:
  * An Expression transformation with non-trivial column formulas
  * Derived columns computed from multiple source columns
  * Type-casting or string-cleaning logic across many columns
  * Optional row-level filter conditions

Config example
--------------
pattern:      expression_transform
mapping_name: m_customer_enrich

source:
  type:  flat_file
  path:  /data/customers/*.csv

target:
  type:       flat_file
  path:       /output/customers_enriched_{date}.csv
  write_mode: overwrite

# Column-level expression map (required)
column_map:
  - target_col: CUST_ID
    expression: "{CUSTOMER_ID}"

  - target_col: FULL_NAME
    expression: "concat({FIRST_NAME}, ' ', {LAST_NAME})"

  - target_col: EMAIL_UPPER
    expression: "upper({EMAIL})"

  - target_col: AMOUNT_CENTS
    expression: "{BALANCE} * 100"

  - target_col: IS_ACTIVE
    expression: "iif({STATUS} == 'A', true, false)"

  - target_col: LOAD_FLAG
    expression: "true"

# Optional: discard rows that do NOT match this expression before mapping.
# The expression is evaluated against the raw source row dict.
# Example: keep only active customers.
filter_expr: "{STATUS} == 'A'"

# Optional: sort output by one or more columns (applied after column_map).
sort_by:
  - col:  CUST_ID
    asc:  true

# Optional: deduplicate output on these columns (first occurrence wins).
dedup_keys:
  - CUST_ID

etl_metadata: true
"""
from __future__ import annotations

import logging
from typing import Any

import pandas as pd

from etl_patterns.expression import apply_column_map, evaluate
from etl_patterns.patterns.base import BasePattern

log = logging.getLogger(__name__)


class ExpressionTransformPattern(BasePattern):
    """
    Expression-driven column transformation pattern.

    Applies a ``column_map`` of expression formulas to every row, with optional
    pre-map row filtering, post-map sorting, and deduplication.
    """

    # ── Core transform ────────────────────────────────────────────────────────

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        column_map = self._cfg.get("column_map")
        if not column_map:
            raise ValueError(
                f"[{self._name}] expression_transform requires a 'column_map' section "
                "in the pattern config."
            )

        # 1. Pre-map row filter
        filter_expr = self._cfg.get("filter_expr")
        if filter_expr:
            df = self._apply_row_filter(df, filter_expr)

        # 2. Apply expression column map
        df = self._apply_column_map(df, column_map)

        # 3. Deduplication
        dedup_keys = self._cfg.get("dedup_keys")
        if dedup_keys:
            before = len(df)
            df = df.drop_duplicates(subset=dedup_keys, keep="first")
            dupes = before - len(df)
            if dupes:
                log.info(
                    "[%s] Deduplicated %d rows on keys: %s",
                    self._name, dupes, dedup_keys,
                )

        # 4. Sorting
        sort_spec = self._cfg.get("sort_by")
        if sort_spec:
            df = self._apply_sort(df, sort_spec)

        return df

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _apply_row_filter(
        self,
        df: pd.DataFrame,
        filter_expr: str,
    ) -> pd.DataFrame:
        """
        Evaluate *filter_expr* for each source row and keep only rows where
        the result is truthy.

        The expression is evaluated against the raw source row dict using the
        same DSL as column expressions.  Non-boolean results are coerced:
        ``None`` / empty string / ``0`` → discard.
        """
        keep: list[bool] = []
        for _, row in df.iterrows():
            row_dict = row.to_dict()
            try:
                result = evaluate(filter_expr, row_dict)
                keep.append(bool(result))
            except Exception as exc:
                log.debug(
                    "[%s] filter_expr '%s' raised %s for row — row excluded.",
                    self._name, filter_expr, exc,
                )
                keep.append(False)

        filtered = df[keep].reset_index(drop=True)
        discarded = len(df) - len(filtered)
        if discarded:
            log.info(
                "[%s] filter_expr discarded %d/%d rows.",
                self._name, discarded, len(df),
            )
        return filtered

    def _apply_column_map(
        self,
        df: pd.DataFrame,
        column_map: list[dict[str, Any]],
    ) -> pd.DataFrame:
        """Apply the column_map expression list row-by-row, returning a new DataFrame."""
        rows: list[dict[str, Any]] = []
        for _, row in df.iterrows():
            rows.append(apply_column_map(column_map, row.to_dict()))
        return pd.DataFrame(rows)

    def _apply_sort(
        self,
        df: pd.DataFrame,
        sort_spec: list[dict[str, Any]],
    ) -> pd.DataFrame:
        """
        Sort *df* according to *sort_spec*.

        Each entry is ``{col: COLUMN_NAME, asc: true|false}``.
        Unknown columns are silently ignored to avoid breaking on optional cols.
        """
        cols: list[str] = []
        ascending: list[bool] = []
        for entry in sort_spec:
            col = entry.get("col")
            if col and col in df.columns:
                cols.append(col)
                ascending.append(bool(entry.get("asc", True)))

        if not cols:
            log.debug("[%s] sort_by: no valid columns found — skipping sort.", self._name)
            return df

        return df.sort_values(by=cols, ascending=ascending).reset_index(drop=True)
