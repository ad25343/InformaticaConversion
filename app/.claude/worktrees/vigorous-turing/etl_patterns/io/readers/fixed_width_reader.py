"""
io/readers/fixed_width_reader.py — Fixed-width flat-file reader
================================================================
Reads mainframe / legacy fixed-width files using column position + length
definitions that come directly from the Informatica source definition.

Config block
------------
source:
  type: fixed_width
  name: MAINFRAME_ACCTS
  path: /data/in/accts_*.dat
  encoding: latin-1              # common for mainframe extracts
  skip_rows: 1                   # header rows to skip
  chunksize: 100000
  columns:
    - name:   ACCT_ID
      start:  1                  # 1-based (matches Informatica)
      length: 10
    - name:   CUST_NAME
      start:  11
      length: 40
    - name:   BALANCE
      start:  51
      length: 15
      strip:  true               # strip whitespace from this column
      dtype:  float              # optional per-column cast
"""
from __future__ import annotations

import glob
import logging
from pathlib import Path
from typing import Iterator

import pandas as pd

from etl_patterns.exceptions import ConfigError, ReaderError
from etl_patterns.io.base import BaseReader

log = logging.getLogger(__name__)


class FixedWidthReader(BaseReader):
    """Read one or more fixed-width files using column position/length specs."""

    def read(self) -> pd.DataFrame:
        chunks = list(self.read_chunks())
        if not chunks:
            return pd.DataFrame()
        df = pd.concat(chunks, ignore_index=True)
        log.info("FixedWidthReader: %d total rows from %s", len(df), self.source_name)
        return df

    def read_chunks(self, chunksize: int | None = None) -> Iterator[pd.DataFrame]:
        paths = self._resolve_paths()
        if not paths:
            raise ReaderError(
                f"No files matched pattern: {self._cfg.get('path')}"
            )
        cs = chunksize or self._cfg.get("chunksize", 100_000)
        for path in paths:
            log.info("FixedWidthReader: reading %s", path)
            yield from self._read_file(path, cs)

    # ── Internals ─────────────────────────────────────────────────────────────

    def _resolve_paths(self) -> list[Path]:
        pattern = self._cfg.get("path")
        if not pattern:
            raise ConfigError(f"source '{self.source_name}' is missing 'path'")
        return [Path(p) for p in sorted(glob.glob(str(pattern))) if Path(p).is_file()]

    def _get_col_specs(self) -> tuple[list[tuple[int, int]], list[str], dict, dict]:
        """
        Parse the ``columns`` config and return:
          colspecs  — list of (start_0based, end_0based) tuples for pd.read_fwf
          names     — column names in order
          per_strip — {col_name: bool} strip flag per column
          per_dtype — {col_name: dtype_str} dtype overrides
        """
        cols = self._cfg.get("columns")
        if not cols:
            raise ConfigError(
                f"source '{self.source_name}' is missing 'columns' definition"
            )
        colspecs  = []
        names     = []
        per_strip = {}
        per_dtype = {}

        for col in cols:
            name   = col["name"]
            start  = int(col["start"]) - 1          # convert to 0-based
            length = int(col["length"])
            colspecs.append((start, start + length))
            names.append(name)
            if col.get("strip", False):
                per_strip[name] = True
            if col.get("dtype"):
                per_dtype[name] = col["dtype"]

        return colspecs, names, per_strip, per_dtype

    def _read_file(self, path: Path, chunksize: int) -> Iterator[pd.DataFrame]:
        colspecs, names, per_strip, per_dtype = self._get_col_specs()
        encoding  = self._cfg.get("encoding", "latin-1")
        skip_rows = self._cfg.get("skip_rows", 0)

        try:
            # pd.read_fwf does not support chunked reading natively — use
            # line-by-line approach for large files.
            with open(path, encoding=encoding, errors="replace") as fh:
                for _ in range(skip_rows):
                    fh.readline()

                buffer = []
                for line in fh:
                    row = {}
                    for name, (start, end) in zip(names, colspecs):
                        raw = line[start:end]
                        if per_strip.get(name, True):
                            raw = raw.strip()
                        row[name] = raw
                    buffer.append(row)
                    if len(buffer) >= chunksize:
                        chunk = pd.DataFrame(buffer)
                        chunk = self._apply_dtypes(chunk, per_dtype)
                        yield chunk
                        buffer = []

                if buffer:
                    chunk = pd.DataFrame(buffer)
                    chunk = self._apply_dtypes(chunk, per_dtype)
                    yield chunk

        except Exception as exc:
            raise ReaderError(f"Failed to read fixed-width file {path}: {exc}") from exc

    @staticmethod
    def _apply_dtypes(df: pd.DataFrame, per_dtype: dict) -> pd.DataFrame:
        for col, dtype in per_dtype.items():
            if col in df.columns:
                try:
                    df[col] = df[col].astype(dtype)
                except (ValueError, TypeError):
                    pass  # leave as-is; let the pattern handle nulls
        return df

    @property
    def source_name(self) -> str:
        return str(self._cfg.get("name") or self._cfg.get("path") or "fixed_width")
