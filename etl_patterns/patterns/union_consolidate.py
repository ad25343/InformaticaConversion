"""
patterns/union_consolidate.py — Union consolidation pattern
============================================================
Equivalent to Informatica mappings that use a Union transformation to combine
multiple source streams into a single target.  Supports:

  - N source configs (flat-file or database)
  - Per-source optional ``column_map`` to normalise schema before union
  - ``dedup_keys`` to remove duplicate rows after consolidation
  - ``sort_by`` to impose an output order
  - All standard ETL metadata injection and write modes on the single target

Config example
--------------
pattern:      union_consolidate
mapping_name: m_accounts_union

sources:
  - type: flat_file
    path: /data/accounts_region_a/*.csv
    column_map:
      - target_col: ACCT_ID
        expression: "{ACCOUNT_ID}"
      - target_col: ACCT_NAME
        expression: "{NAME}"
      - target_col: REGION
        expression: "A"

  - type: flat_file
    path: /data/accounts_region_b/*.csv
    column_map:
      - target_col: ACCT_ID
        expression: "{ACCT_NO}"
      - target_col: ACCT_NAME
        expression: "{ACCT_NAME}"
      - target_col: REGION
        expression: "B"

  - type: database
    connection_string: postgresql+psycopg2://user:pass@host/dw
    query: "SELECT ACCT_ID, ACCT_NAME, 'C' AS REGION FROM ACCOUNTS_REGION_C"

target:
  type:       database
  connection_string: postgresql+psycopg2://user:pass@host/dw
  table:      DIM_ACCOUNTS
  write_mode: replace

dedup_keys:
  - ACCT_ID

sort_by:
  - col: REGION
    asc: true
  - col: ACCT_ID
    asc: true

etl_metadata: true

Implementation notes
--------------------
Because ``union_consolidate`` has multiple source configs (``sources``) rather than a
single ``source``, it overrides ``execute()`` entirely.  The parent ``__init__`` still
wires the single target writer from the ``target`` key normally.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import pandas as pd

from etl_patterns.exceptions import ConfigError
from etl_patterns.expression import apply_column_map
from etl_patterns.io import get_reader
from etl_patterns.patterns.base import BasePattern

log = logging.getLogger(__name__)


class UnionConsolidatePattern(BasePattern):
    """
    Reads N sources, applies per-source column_maps, concatenates into one
    DataFrame, deduplicates, sorts, and writes to a single target.
    """

    # ── Constructor override ──────────────────────────────────────────────────

    def __init__(self, config: dict[str, Any]) -> None:
        """
        Build one reader per source entry in config["sources"].
        The single target writer is wired by the parent __init__ via config["target"].

        We inject a dummy ``source`` key so that the parent does not raise a
        KeyError when it calls ``get_reader(config["source"])``.
        """
        sources = config.get("sources", [])
        if not sources:
            raise ConfigError(
                f"[{config.get('mapping_name', 'union_consolidate')}] "
                "union_consolidate requires at least one entry under 'sources'."
            )

        # Inject a synthetic ``source`` so BasePattern.__init__ won't fail.
        # We override execute() so the base reader is never actually called.
        if "source" not in config:
            config = dict(config)          # shallow copy — don't mutate caller's dict
            config["source"] = sources[0]  # safe fallback; never used by this pattern

        super().__init__(config)

        # Build per-source readers.
        # Strip the ETL-style ``column_map`` (list of expression dicts) from the
        # reader config so FlatFileReader doesn't try to interpret it as a plain
        # {src_col: tgt_col} rename dict.  We keep the expression column_map in
        # self._source_cfgs for use in _read_all_sources().
        reader_cfgs = []
        for s in sources:
            rc = {k: v for k, v in s.items() if k != "column_map"}
            reader_cfgs.append(rc)

        self._source_readers = [get_reader(rc) for rc in reader_cfgs]
        self._source_cfgs    = sources    # originals retain column_map

    # ── Entry point ───────────────────────────────────────────────────────────

    def execute(self) -> dict[str, Any]:
        """Override: read multiple sources, consolidate, write once."""
        log.info("[%s] Starting (union_consolidate)", self._name)
        t0 = time.monotonic()
        result: dict[str, Any] = {
            "pattern":      self._cfg.get("pattern"),
            "mapping_name": self._name,
            "status":       "success",
            "rows_read":    0,
            "rows_written": 0,
            "elapsed_s":    0.0,
        }
        try:
            self.pre_load()
            frames = self._read_all_sources()
            total_read = sum(len(f) for f in frames)
            result["rows_read"] = total_read
            log.info("[%s] Read %d total rows from %d sources.", self._name, total_read, len(frames))

            combined = self._combine(frames)
            combined = self._inject_metadata(combined)
            combined = self.transform(combined)

            rows_written = self._write(combined)
            result["rows_written"] = rows_written

            self.post_load(combined)

        except Exception as exc:
            result["status"] = "error"
            result["error"]  = str(exc)
            log.exception("[%s] Failed: %s", self._name, exc)
            raise
        finally:
            result["elapsed_s"] = round(time.monotonic() - t0, 3)
            log.info(
                "[%s] Finished — status=%s rows_read=%d rows_written=%d elapsed=%.1fs",
                self._name,
                result["status"],
                result.get("rows_read", 0),
                result.get("rows_written", 0),
                result["elapsed_s"],
            )
        return result

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply dedup and sort to the consolidated DataFrame."""
        dedup_keys = self._cfg.get("dedup_keys")
        sort_spec  = self._cfg.get("sort_by", [])

        if dedup_keys:
            if isinstance(dedup_keys, str):
                dedup_keys = [dedup_keys]
            before = len(df)
            # Keep the first occurrence of each key combination
            df = df.drop_duplicates(subset=dedup_keys, keep="first").reset_index(drop=True)
            log.info(
                "[%s] Dedup on %s: %d → %d rows.", self._name, dedup_keys, before, len(df),
            )

        if sort_spec:
            cols:      list[str]  = []
            ascending: list[bool] = []
            for entry in sort_spec:
                col = entry.get("col")
                if col and col in df.columns:
                    cols.append(col)
                    ascending.append(bool(entry.get("asc", True)))
            if cols:
                df = df.sort_values(by=cols, ascending=ascending).reset_index(drop=True)

        return df

    # ── Internals ─────────────────────────────────────────────────────────────

    def _read_all_sources(self) -> list[pd.DataFrame]:
        """Read each source and apply its per-source column_map if present."""
        frames: list[pd.DataFrame] = []
        for i, (reader, src_cfg) in enumerate(
            zip(self._source_readers, self._source_cfgs)
        ):
            df = reader.read()
            log.info(
                "[%s] Source[%d] (%s): read %d rows.",
                self._name, i, src_cfg.get("path") or src_cfg.get("table") or "?", len(df),
            )

            column_map = src_cfg.get("column_map")
            if column_map:
                rows = []
                for _, row in df.iterrows():
                    rows.append(apply_column_map(column_map, row.to_dict()))
                df = pd.DataFrame(rows)
                log.info(
                    "[%s] Source[%d]: column_map applied → %d columns.",
                    self._name, i, len(df.columns),
                )

            frames.append(df)
        return frames

    def _combine(self, frames: list[pd.DataFrame]) -> pd.DataFrame:
        """Concatenate frames; return empty DataFrame when all frames are empty."""
        non_empty = [f for f in frames if not f.empty]
        if not non_empty:
            # Return an empty DataFrame; use the columns of the first frame if available
            cols = frames[0].columns.tolist() if frames else []
            return pd.DataFrame(columns=cols)

        combined = pd.concat(non_empty, ignore_index=True, sort=False)
        log.info("[%s] Combined %d frames → %d rows.", self._name, len(frames), len(combined))
        return combined
