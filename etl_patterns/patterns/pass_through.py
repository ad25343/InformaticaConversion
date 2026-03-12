# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
patterns/pass_through.py — Trivial extract with no meaningful transformation
=============================================================================
Maps directly to Informatica mappings that contain only a Source Qualifier
and a Target Definition with a 1:1 column mapping and no expression logic.

Config example
--------------
pattern:      pass_through
mapping_name: m_ref_currency_load

source:
  type: database
  connection_string: postgresql+psycopg2://user:pass@host/oltp
  table: REF_CURRENCIES

target:
  type: database
  connection_string: postgresql+psycopg2://user:pass@host/dw
  table: REF_CURRENCIES
  write_mode: replace

etl_metadata: true
"""
from __future__ import annotations

import pandas as pd

from etl_patterns.patterns.base import BasePattern


class PassThroughPattern(BasePattern):
    """Extract source data and write to target with no transformation."""

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        # Apply optional column selection / renaming from config
        col_select = self._cfg.get("columns")
        col_rename = self._cfg.get("column_rename") or {}

        if col_select:
            df = df[[c for c in col_select if c in df.columns]]
        if col_rename:
            df = df.rename(columns=col_rename)

        return df
