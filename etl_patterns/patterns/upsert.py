"""
patterns/upsert.py — Stub (Phase 2/3/4 implementation)
=================================================
This pattern is planned for a future phase. See docs/DESIGN_PATTERN_LIBRARY.md.
"""
from __future__ import annotations
import pandas as pd
from etl_patterns.patterns.base import BasePattern
from etl_patterns.exceptions import PatternNotFoundError

class UpsertPattern(BasePattern):
    \"\"\"Not yet implemented — Phase 2/3/4.\"\"\"
    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        raise PatternNotFoundError(
            f"Pattern 'upsert' is not yet implemented in this version of etl_patterns. "
            "See docs/DESIGN_PATTERN_LIBRARY.md for the build schedule."
        )
