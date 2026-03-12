"""
patterns/truncate_and_load.py — Full-refresh (drop + reload) pattern
=====================================================================
Equivalent to Informatica mappings that use a pre-load command TRUNCATE TABLE
followed by a bulk INSERT.  No history is preserved.

Config example
--------------
pattern:      truncate_and_load
mapping_name: m_dim_branch_load

source:
  type:              database
  connection_string: postgresql+psycopg2://user:pass@host/oltp
  table:             BRANCHES

target:
  type:              database
  connection_string: postgresql+psycopg2://user:pass@host/dw
  table:             DIM_BRANCH
  schema:            dbo
  write_mode:        replace    # replace = truncate + re-create via pandas

# Optional column mapping
column_map:
  - target_col: BRANCH_KEY
    expression: "{BRANCH_ID}"
  - target_col: BRANCH_NAME
    expression: "upper({BRANCH_NAME})"
  - target_col: ACTIVE_FLAG
    expression: "true"

etl_metadata: true
"""
from __future__ import annotations

import pandas as pd

from etl_patterns.expression import apply_column_map, evaluate
from etl_patterns.patterns.base import BasePattern


class TruncateAndLoadPattern(BasePattern):
    """Full-refresh: truncate target, reload from source."""

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        column_map = self._cfg.get("column_map")
        if not column_map:
            return df

        rows = []
        for _, row in df.iterrows():
            row_dict = row.to_dict()
            rows.append(apply_column_map(column_map, row_dict))

        return pd.DataFrame(rows)
