"""
io/writers/flat_file_writer.py — Delimited flat-file writer
============================================================
Writes a DataFrame to a delimited output file.  Supports optional
compression, date/decimal formatting, and column selection / ordering.

Config block (``target:`` section of the pattern YAML)
-------------------------------------------------------
target:
  type: flat_file
  name: ACCT_EXTRACT
  path: /data/out/accounts_{date}.csv   # {date} substituted with YYYY-MM-DD
  delimiter: ","
  encoding:  utf-8
  write_header: true          # write column names as first row (default true)
  quoting: minimal            # minimal | all | nonnumeric | none
  compression: null           # null | gzip | bz2 | zip | xz
  date_format: "%Y-%m-%d"
  decimal: "."                # decimal separator character
  columns:                    # optional: only write these columns in this order
    - ACCT_ID
    - CUST_NAME
    - BALANCE
  write_mode: overwrite       # overwrite | append (default overwrite)
"""
from __future__ import annotations

import csv
import logging
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from etl_patterns.exceptions import ConfigError, WriterError
from etl_patterns.io.base import BaseWriter

log = logging.getLogger(__name__)

_QUOTING_MAP = {
    "minimal":    csv.QUOTE_MINIMAL,
    "all":        csv.QUOTE_ALL,
    "nonnumeric": csv.QUOTE_NONNUMERIC,
    "none":       csv.QUOTE_NONE,
}


class FlatFileWriter(BaseWriter):
    """Write a DataFrame to a delimited output file."""

    def write(self, df: pd.DataFrame) -> int:
        path = self._resolve_path()
        path.parent.mkdir(parents=True, exist_ok=True)

        # Column selection / ordering
        columns = self._cfg.get("columns")
        if columns:
            missing = [c for c in columns if c not in df.columns]
            if missing:
                raise WriterError(
                    f"target '{self.target_name}' column(s) not in DataFrame: {missing}"
                )
            df = df[columns]

        delimiter   = self._cfg.get("delimiter", ",")
        encoding    = self._cfg.get("encoding", "utf-8")
        write_header = self._cfg.get("write_header", True)
        quoting_key  = self._cfg.get("quoting", "minimal")
        quoting      = _QUOTING_MAP.get(quoting_key, csv.QUOTE_MINIMAL)
        compression  = self._cfg.get("compression") or None
        date_fmt     = self._cfg.get("date_format")
        decimal      = self._cfg.get("decimal", ".")
        write_mode   = self._cfg.get("write_mode", "overwrite")
        mode         = "a" if write_mode == "append" else "w"
        # In append mode, skip header if file exists and already has content
        header = write_header
        if mode == "a" and path.exists() and path.stat().st_size > 0:
            header = False

        try:
            df.to_csv(
                path,
                sep         = delimiter,
                encoding    = encoding,
                index       = False,
                header      = header,
                quoting     = quoting,
                compression = compression,
                date_format = date_fmt,
                decimal     = decimal,
                mode        = mode,
            )
            log.info(
                "FlatFileWriter: wrote %d rows to %s", len(df), path
            )
            return len(df)
        except Exception as exc:
            raise WriterError(f"Failed to write {path}: {exc}") from exc

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolve_path(self) -> Path:
        raw = self._cfg.get("path")
        if not raw:
            raise ConfigError(f"target '{self.target_name}' is missing 'path'")
        # Substitute {date} placeholder
        today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        resolved = str(raw).replace("{date}", today)
        return Path(resolved)

    @property
    def target_name(self) -> str:
        return str(self._cfg.get("name") or self._cfg.get("path") or "flat_file")
