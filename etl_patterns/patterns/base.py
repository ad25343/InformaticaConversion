"""
patterns/base.py — Abstract base class for all ETL patterns
============================================================
Every pattern inherits from BasePattern and must implement ``transform()``.
The base class handles:
  - IO wiring (reader + writer from config)
  - ETL metadata injection
  - Logging and timing
  - Result dict construction

Subclasses should override ``transform()`` and optionally ``pre_load()`` /
``post_load()`` for pattern-specific logic.
"""
from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any

import pandas as pd

from etl_patterns.io import get_reader, get_writer
from etl_patterns.utils.etl_metadata import add_etl_metadata

log = logging.getLogger(__name__)


class BasePattern(ABC):
    """Abstract base for all ETL patterns."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg     = config
        self._name    = config.get("mapping_name", type(self).__name__)
        self._reader  = get_reader(config["source"])
        # target may be a list (filter_and_route) or a single dict
        tgt = config.get("target")
        if isinstance(tgt, list):
            self._writers = [get_writer(t) for t in tgt]
            self._writer  = None
        else:
            self._writer  = get_writer(tgt) if tgt else None
            self._writers = [self._writer] if self._writer else []

    # ── Public entry point ────────────────────────────────────────────────────

    def execute(self) -> dict[str, Any]:
        """Run the full ETL cycle and return a result summary."""
        log.info("[%s] Starting", self._name)
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
            df = self._reader.read()
            result["rows_read"] = len(df)
            log.info("[%s] Read %d rows", self._name, len(df))

            df = self._inject_metadata(df)
            df = self.transform(df)

            rows_written = self._write(df)
            result["rows_written"] = rows_written

            self.post_load(df)
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

    # ── Hooks for subclasses ──────────────────────────────────────────────────

    def pre_load(self) -> None:
        """Called before the source read.  Override for truncation, setup, etc."""

    @abstractmethod
    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply pattern-specific transformations to the source DataFrame.

        Parameters
        ----------
        df  Source DataFrame (ETL metadata already injected).

        Returns
        -------
        Transformed DataFrame ready to write to the target.
        """

    def post_load(self, df: pd.DataFrame) -> None:
        """Called after a successful write.  Override for watermark update, etc."""

    # ── Internals ─────────────────────────────────────────────────────────────

    def _inject_metadata(self, df: pd.DataFrame) -> pd.DataFrame:
        """Inject ETL audit columns if configured."""
        meta_cfg = self._cfg.get("etl_metadata")
        if meta_cfg is None:
            return df
        return add_etl_metadata(
            df,
            meta_cfg,
            source_system = self._cfg.get("source_system", ""),
            source_file   = self._cfg.get("source_file"),
            batch_id      = self._cfg.get("batch_id"),
            run_id        = self._cfg.get("run_id"),
        )

    def _write(self, df: pd.DataFrame) -> int:
        """Write to the target(s) and return total rows written."""
        if self._writer:
            return self._writer.write(df)
        # filter_and_route pattern overrides this
        return 0
