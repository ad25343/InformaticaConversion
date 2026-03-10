"""
utils/file_lifecycle.py — Post-load file management
====================================================
Handles the file lifecycle tasks that every Informatica flat-file mapping
performs after a successful (or failed) load:

  archive     Move processed files to an archive directory (optional datestamp subdir).
  reject      Write rejected rows to a separate reject file.
  validate    Pre-read checks: file exists, non-empty, expected column count.

Config block (inside the pattern YAML, under ``source:``)
---------------------------------------------------------
file_lifecycle:
  archive_dir:   /data/archive          # None = do not archive
  archive_dated: true                   # add YYYY-MM-DD subdir (default true)
  reject_dir:    /data/rejects          # None = do not write rejects
  reject_suffix: _rejected              # appended before extension (default _rejected)
  validate:
    min_rows: 1                         # fail if fewer rows (after header)
    expected_cols: 12                   # fail if column count differs
"""
from __future__ import annotations

import csv
import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

from etl_patterns.exceptions import ReaderError, WriterError

log = logging.getLogger(__name__)


# ── Archive ───────────────────────────────────────────────────────────────────

def archive_file(
    source_path: str | Path,
    archive_dir: str | Path,
    *,
    dated: bool = True,
    overwrite: bool = False,
) -> Path:
    """
    Move *source_path* into *archive_dir* after successful processing.

    Parameters
    ----------
    source_path  File to archive.
    archive_dir  Root archive directory.
    dated        If True, create a YYYY-MM-DD sub-directory (default True).
    overwrite    If True, overwrite an existing file in the archive.

    Returns
    -------
    Path of the archived file.
    """
    src  = Path(source_path)
    root = Path(archive_dir)

    if dated:
        date_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        dest_dir = root / date_str
    else:
        dest_dir = root

    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name

    if dest.exists() and not overwrite:
        # Append a counter to avoid collision
        stem  = src.stem
        suf   = src.suffix
        count = 1
        while dest.exists():
            dest = dest_dir / f"{stem}_{count}{suf}"
            count += 1

    shutil.move(str(src), str(dest))
    log.info("Archived %s → %s", src, dest)
    return dest


def archive_glob(
    source_dir: str | Path,
    pattern: str,
    archive_dir: str | Path,
    *,
    dated: bool = True,
) -> list[Path]:
    """Archive all files matching *pattern* in *source_dir*."""
    src_dir = Path(source_dir)
    archived = []
    for f in sorted(src_dir.glob(pattern)):
        if f.is_file():
            archived.append(archive_file(f, archive_dir, dated=dated))
    return archived


# ── Reject writer ─────────────────────────────────────────────────────────────

class RejectWriter:
    """
    Writes rejected rows to a delimited reject file.

    Usage
    -----
    with RejectWriter("/data/rejects/orders_rejected.csv") as rw:
        for row in bad_rows:
            rw.write(row, reason="null key")
    rw.reject_count  # → N
    """

    def __init__(
        self,
        path: str | Path,
        *,
        delimiter: str = ",",
        include_reason: bool = True,
    ) -> None:
        self._path          = Path(path)
        self._delimiter     = delimiter
        self._include_reason = include_reason
        self._fp            = None
        self._writer        = None
        self._header_written = False
        self.reject_count   = 0

    def __enter__(self) -> "RejectWriter":
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fp     = open(self._path, "w", newline="", encoding="utf-8")  # noqa: SIM115
        self._writer = csv.writer(self._fp, delimiter=self._delimiter)
        return self

    def __exit__(self, *_: Any) -> None:
        if self._fp:
            self._fp.close()
        if self.reject_count:
            log.warning("RejectWriter: %d rows written to %s", self.reject_count, self._path)

    def write(self, row: dict | list, *, reason: str = "") -> None:
        """Write a single rejected row."""
        if self._writer is None:
            raise WriterError("RejectWriter must be used as a context manager")

        if isinstance(row, dict):
            if not self._header_written:
                headers = list(row.keys())
                if self._include_reason:
                    headers.append("_reject_reason")
                self._writer.writerow(headers)
                self._header_written = True
            values = list(row.values())
            if self._include_reason:
                values.append(reason)
            self._writer.writerow(values)
        else:
            if not self._header_written and self._include_reason:
                # No header for list rows; just emit
                self._header_written = True
            out = list(row)
            if self._include_reason:
                out.append(reason)
            self._writer.writerow(out)

        self.reject_count += 1

    def write_dataframe(self, df: pd.DataFrame, *, reason: str = "") -> None:
        """Write all rows of a DataFrame as rejects."""
        df = df.copy()
        if self._include_reason:
            df["_reject_reason"] = reason
        if not self._header_written:
            df.to_csv(self._fp, index=False, sep=self._delimiter, header=True)  # type: ignore[arg-type]
            self._header_written = True
        else:
            df.to_csv(self._fp, index=False, sep=self._delimiter, header=False)  # type: ignore[arg-type]
        self.reject_count += len(df)

    @property
    def path(self) -> Path:
        return self._path


def reject_path_for(
    source_path: str | Path,
    reject_dir: str | Path,
    *,
    suffix: str = "_rejected",
) -> Path:
    """
    Derive a reject file path from the source file.

    Example: source_path = "/data/in/orders.csv", suffix="_rejected"
             → "/data/rejects/orders_rejected.csv"
    """
    src = Path(source_path)
    return Path(reject_dir) / f"{src.stem}{suffix}{src.suffix}"


# ── Pre-read validation ───────────────────────────────────────────────────────

class FileValidator:
    """
    Validates a source file before the main read begins.

    Checks performed (all optional, controlled by config):
      - File exists
      - File is non-empty (size > 0)
      - Minimum row count (after header row)
      - Expected column count (from header or first data row)
    """

    def __init__(
        self,
        min_rows: int = 0,
        expected_cols: int | None = None,
        *,
        delimiter: str = ",",
        has_header: bool = True,
    ) -> None:
        self.min_rows      = min_rows
        self.expected_cols = expected_cols
        self.delimiter     = delimiter
        self.has_header    = has_header

    def validate(self, path: str | Path) -> None:
        """
        Run all configured checks against *path*.

        Raises
        ------
        ReaderError  If any check fails.
        """
        p = Path(path)
        self._check_exists(p)
        self._check_non_empty(p)
        if self.min_rows or self.expected_cols:
            self._check_content(p)

    def _check_exists(self, p: Path) -> None:
        if not p.exists():
            raise ReaderError(f"Source file not found: {p}")
        if not p.is_file():
            raise ReaderError(f"Source path is not a file: {p}")

    def _check_non_empty(self, p: Path) -> None:
        if p.stat().st_size == 0:
            raise ReaderError(f"Source file is empty: {p}")

    def _check_content(self, p: Path) -> None:
        with open(p, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh, delimiter=self.delimiter)
            rows_seen = 0
            header_done = False
            for row in reader:
                if self.has_header and not header_done:
                    if self.expected_cols and len(row) != self.expected_cols:
                        raise ReaderError(
                            f"Expected {self.expected_cols} columns in header, "
                            f"got {len(row)}: {p}"
                        )
                    header_done = True
                    continue
                rows_seen += 1
                if rows_seen == 1 and self.expected_cols and not self.has_header:
                    if len(row) != self.expected_cols:
                        raise ReaderError(
                            f"Expected {self.expected_cols} columns, "
                            f"got {len(row)}: {p}"
                        )

        if self.min_rows and rows_seen < self.min_rows:
            raise ReaderError(
                f"File has {rows_seen} data row(s); minimum required is {self.min_rows}: {p}"
            )


# ── Convenience builder ───────────────────────────────────────────────────────

def lifecycle_from_config(cfg: dict) -> dict:
    """
    Parse the ``file_lifecycle`` config block and return a dict of ready objects.

    Returns
    -------
    {
        "validator":    FileValidator | None,
        "archive_dir":  Path | None,
        "archive_dated": bool,
        "reject_dir":   Path | None,
        "reject_suffix": str,
    }
    """
    lc = cfg if cfg else {}
    val_cfg = lc.get("validate") or {}

    validator: FileValidator | None = None
    if val_cfg:
        validator = FileValidator(
            min_rows      = val_cfg.get("min_rows", 0),
            expected_cols = val_cfg.get("expected_cols"),
        )

    archive_raw = lc.get("archive_dir")
    reject_raw  = lc.get("reject_dir")

    return {
        "validator":     validator,
        "archive_dir":   Path(archive_raw) if archive_raw else None,
        "archive_dated": bool(lc.get("archive_dated", True)),
        "reject_dir":    Path(reject_raw) if reject_raw else None,
        "reject_suffix": lc.get("reject_suffix", "_rejected"),
    }
