"""
patterns/lookup_enrich.py — Lookup enrichment pattern
======================================================
Equivalent to Informatica mappings that join one or more static dimension or
reference tables into a main transaction stream.  Supports:

  - Multiple lookups (applied left-to-right)
  - Database lookups (SQLAlchemy) and flat-file lookups (CSV)
  - In-memory caching of lookup DataFrames (recommended for small dimensions)
  - Left or inner join semantics per lookup
  - Column-name collision resolution via ``prefix`` (optional)
  - Final ``column_map`` applied after all joins

Config example
--------------
pattern:      lookup_enrich
mapping_name: m_txn_enrich

source:
  type:    flat_file
  path:    /data/transactions/*.csv

lookups:
  - name:       BRANCH
    type:       database
    connection_string: postgresql+psycopg2://user:pass@host/dw
    table:      DIM_BRANCH
    join_keys:
      TXN_BRANCH_ID: BRANCH_ID     # source_col: lookup_col
    join_type:  left                # left (default) | inner
    cache:      true
    prefix:     BRN_                # optional: prefix lookup cols to avoid clashes

  - name:       PRODUCT
    type:       flat_file
    path:       /data/lookups/products.csv
    join_keys:
      PRODUCT_CODE: PROD_CD
    join_type:  left
    cache:      true

target:
  type:       flat_file
  path:       /output/txn_enriched_{date}.csv
  write_mode: overwrite

column_map:
  - target_col: TXN_ID
    expression: "{TXN_ID}"
  - target_col: BRANCH_NAME
    expression: "{BRN_BRANCH_NAME}"
  - target_col: PRODUCT_DESC
    expression: "{PRODUCT_DESC}"

etl_metadata: true
"""
from __future__ import annotations

import logging
from typing import Any

import pandas as pd

from etl_patterns.exceptions import ConfigError
from etl_patterns.expression import apply_column_map
from etl_patterns.io.readers.db_reader import DatabaseReader
from etl_patterns.io.readers.flat_file_reader import FlatFileReader
from etl_patterns.patterns.base import BasePattern

log = logging.getLogger(__name__)

# Module-level cache so repeated calls within the same process share lookup DFs
_LOOKUP_CACHE: dict[str, pd.DataFrame] = {}


class LookupEnrichPattern(BasePattern):
    """Join N reference tables into the main source stream, then apply column_map."""

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        For each lookup in config:
          1. Load (or retrieve from cache) the lookup DataFrame.
          2. Rename the join key column(s) in the lookup to match source names.
          3. Apply the configured prefix to non-join lookup columns.
          4. Merge using pandas merge (left or inner join).

        Finally apply the column_map expression list.
        """
        lookups = self._cfg.get("lookups") or []
        if not lookups:
            raise ConfigError(
                f"[{self._name}] lookup_enrich requires at least one entry under "
                "'lookups' in the config."
            )

        enriched = df.copy()

        for lkp_cfg in lookups:
            enriched = self._apply_lookup(enriched, lkp_cfg)

        # Final column map
        column_map = self._cfg.get("column_map")
        if not column_map:
            return enriched

        rows = []
        for _, row in enriched.iterrows():
            rows.append(apply_column_map(column_map, row.to_dict()))
        return pd.DataFrame(rows)

    # ── Per-lookup logic ──────────────────────────────────────────────────────

    def _apply_lookup(
        self,
        main_df: pd.DataFrame,
        lkp_cfg: dict[str, Any],
    ) -> pd.DataFrame:
        """Load one lookup, join it into *main_df*, return the merged DataFrame."""
        lkp_name  = lkp_cfg.get("name", "LOOKUP")
        join_keys = lkp_cfg.get("join_keys", {})  # {src_col: lkp_col}
        join_type = lkp_cfg.get("join_type", "left").lower()
        prefix    = lkp_cfg.get("prefix", "")
        use_cache = lkp_cfg.get("cache", True)

        if not join_keys:
            raise ConfigError(
                f"[{self._name}] Lookup '{lkp_name}' is missing 'join_keys'. "
                "Example: join_keys: {TXN_BRANCH_ID: BRANCH_ID}"
            )

        lkp_df = self._load_lookup(lkp_cfg, use_cache)

        # Rename lookup join columns → source column names (when they differ)
        lkp_rename = {v: k for k, v in join_keys.items() if v != k}
        if lkp_rename:
            lkp_df = lkp_df.rename(columns=lkp_rename)

        # Apply prefix to non-join columns to avoid collisions
        join_col_names = list(join_keys.keys())
        if prefix:
            prefixed = {
                col: f"{prefix}{col}"
                for col in lkp_df.columns
                if col not in join_col_names
            }
            if prefixed:
                lkp_df = lkp_df.rename(columns=prefixed)

        # Drop any non-key lookup columns that would conflict with main columns
        overlap = [
            c for c in lkp_df.columns
            if c in main_df.columns and c not in join_col_names
        ]
        if overlap:
            lkp_df = lkp_df.drop(columns=overlap)

        try:
            merged = pd.merge(main_df, lkp_df, on=join_col_names, how=join_type)
        except KeyError as exc:
            raise ConfigError(
                f"[{self._name}] Lookup '{lkp_name}' join failed — "
                f"key column not found: {exc}. "
                f"Main columns: {list(main_df.columns)}, "
                f"Lookup columns: {list(lkp_df.columns)}"
            ) from exc

        log.info(
            "[%s] Lookup '%s': %d main × %d lookup → %d merged (%s join)",
            self._name, lkp_name, len(main_df), len(lkp_df), len(merged), join_type,
        )
        return merged.reset_index(drop=True)

    def _load_lookup(
        self,
        lkp_cfg: dict[str, Any],
        use_cache: bool,
    ) -> pd.DataFrame:
        """Load the lookup DataFrame, optionally from the module-level cache."""
        cache_key = _make_cache_key(lkp_cfg)
        if use_cache and cache_key in _LOOKUP_CACHE:
            log.debug("Lookup cache hit: %s", cache_key)
            return _LOOKUP_CACHE[cache_key]

        lkp_type = lkp_cfg.get("type", "").lower()

        if lkp_type in ("database", "db"):
            reader = DatabaseReader(lkp_cfg)
        elif lkp_type in ("flat_file", "csv", "file"):
            reader = FlatFileReader(lkp_cfg)
        else:
            raise ConfigError(
                f"Lookup type {lkp_type!r} not supported. Use 'database' or 'flat_file'."
            )

        try:
            df = reader.read()
        except Exception as exc:
            raise ConfigError(
                f"Failed to load lookup '{lkp_cfg.get('name', '?')}': {exc}"
            ) from exc

        if use_cache:
            _LOOKUP_CACHE[cache_key] = df
        return df


def clear_lookup_cache() -> None:
    """Clear the module-level lookup cache.  Call between test runs or pipeline resets."""
    _LOOKUP_CACHE.clear()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_cache_key(cfg: dict[str, Any]) -> str:
    parts = [
        cfg.get("name", ""),
        cfg.get("type", ""),
        cfg.get("connection_string", ""),
        cfg.get("table", ""),
        cfg.get("query", ""),
        cfg.get("path", ""),
    ]
    return "|".join(str(p) for p in parts)
