"""
io/readers/flat_file_reader.py — Delimited flat-file reader
============================================================
Supports single files and glob patterns (multiple input files).
Always uses chunked I/O internally; exposes a single DataFrame via ``read()``.

Config block
------------
source:
  type: flat_file
  name: TXN_INPUT
  path: /data/in/transactions_*.csv   # glob OK
  delimiter: ","                       # default ","
  encoding:  utf-8                     # default utf-8
  has_header: true                     # default true
  skip_rows:  0                        # rows to skip before header
  null_values: ["NULL", "N/A", ""]     # treated as NaN
  chunksize:  100000
  # Optional column typing (avoids pandas mis-inference)
  dtype:
    ACCT_ID: str
    AMOUNT:  float
  # Optional column renaming (source_col: target_col)
  column_map:
    ACCT_NUM: ACCT_ID
  file_lifecycle:
    archive_dir:  /data/archive
    archive_dated: true
    reject_dir:   /data/rejects
    validate:
      min_rows: 1
"""
from __future__ import annotations

import glob
import logging
from pathlib import Path
from typing import Iterator

import pandas as pd

from etl_patterns.exceptions import ConfigError, ReaderError
from etl_patterns.io.base import BaseReader
from etl_patterns.utils.file_lifecycle import FileValidator, lifecycle_from_config

log = logging.getLogger(__name__)

_DEFAULT_NULL_VALUES = ["NULL", "null", "N/A", "n/a", "NA", "na", ""]


class FlatFileReader(BaseReader):
    """Read one or more delimited flat files into a DataFrame."""

    # ── Public ────────────────────────────────────────────────────────────────

    def read(self) -> pd.DataFrame:
        """Read all matching files and concatenate into a single DataFrame."""
        chunks = list(self.read_chunks())
        if not chunks:
            return pd.DataFrame()
        df = pd.concat(chunks, ignore_index=True)
        log.info("FlatFileReader: %d total rows from %s", len(df), self.source_name)
        return df

    def read_chunks(self, chunksize: int | None = None) -> Iterator[pd.DataFrame]:
        """Yield chunks across all matching files."""
        paths = self._resolve_paths()
        if not paths:
            raise ReaderError(
                f"No files matched pattern: {self._cfg.get('path')}"
            )

        validator = self._get_validator()
        cs = chunksize or self._cfg.get("chunksize", 100_000)

        for path in paths:
            log.info("FlatFileReader: reading %s", path)
            if validator:
                validator.validate(path)
            yield from self._read_file(path, cs)

    # ── Internals ─────────────────────────────────────────────────────────────

    def _resolve_paths(self) -> list[Path]:
        pattern = self._cfg.get("path")
        if not pattern:
            raise ConfigError(
                f"source '{self.source_name}' is missing 'path'"
            )
        matches = sorted(glob.glob(str(pattern)))
        return [Path(p) for p in matches if Path(p).is_file()]

    def _read_file(self, path: Path, chunksize: int) -> Iterator[pd.DataFrame]:
        col_map   = self._cfg.get("column_map") or {}
        delimiter = self._cfg.get("delimiter", ",")
        encoding  = self._cfg.get("encoding", "utf-8")
        has_header = self._cfg.get("has_header", True)
        skip_rows = self._cfg.get("skip_rows", 0)
        null_vals = self._cfg.get("null_values", _DEFAULT_NULL_VALUES)
        dtype     = self._cfg.get("dtype") or {}

        try:
            reader = pd.read_csv(
                path,
                delimiter    = delimiter,
                encoding     = encoding,
                header       = 0 if has_header else None,
                skiprows     = skip_rows if skip_rows else None,
                keep_default_na = True,
                na_values    = null_vals,
                dtype        = dtype or None,
                chunksize    = chunksize,
            )
            for chunk in reader:  # type: ignore[union-attr]
                if col_map:
                    chunk = chunk.rename(columns=col_map)
                yield chunk
        except Exception as exc:
            raise ReaderError(f"Failed to read {path}: {exc}") from exc

    def _get_validator(self) -> FileValidator | None:
        lc = self._cfg.get("file_lifecycle")
        if not lc:
            return None
        return lifecycle_from_config(lc).get("validator")

    @property
    def source_name(self) -> str:
        return str(self._cfg.get("name") or self._cfg.get("path") or "flat_file")
