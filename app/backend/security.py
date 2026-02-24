"""
security.py — Central security utilities for the Informatica Conversion Tool.

Every file-handling path in the application goes through this module.
Do NOT bypass these helpers to accept raw user input.

Protections provided
────────────────────
  XXE        — safe_xml_parser() disables DTD loading and external entity resolution
  Zip Slip   — safe_zip_extract() validates every entry path before writing
  Zip Bomb   — safe_zip_extract() enforces total extracted-size and entry-count limits
  File Size  — validate_upload_size() enforces per-file byte limits
  Code Scan  — scan_python_with_bandit() wraps bandit for generated-code audits
"""
from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Optional

from fastapi import HTTPException
from lxml import etree

log = logging.getLogger("conversion.security")

# ─────────────────────────────────────────────────────────────────────────────
# Limits
# ─────────────────────────────────────────────────────────────────────────────

MAX_UPLOAD_BYTES: int = int(os.environ.get("MAX_UPLOAD_MB", "50")) * 1024 * 1024
"""Maximum size for any single uploaded file (default 50 MB)."""

MAX_ZIP_EXTRACTED_BYTES: int = int(os.environ.get("MAX_ZIP_EXTRACTED_MB", "200")) * 1024 * 1024
"""Maximum total extracted size from a ZIP upload (default 200 MB — prevents zip bombs)."""

MAX_ZIP_FILE_COUNT: int = int(os.environ.get("MAX_ZIP_FILE_COUNT", "200"))
"""Maximum number of files inside a ZIP upload."""

MAX_BANDIT_LINES: int = 10_000
"""Skip bandit scan on files longer than this (avoids runaway subprocess time)."""


# ─────────────────────────────────────────────────────────────────────────────
# XML / XXE protection
# ─────────────────────────────────────────────────────────────────────────────

def safe_xml_parser() -> etree.XMLParser:
    """
    Return an lxml XMLParser with all external-entity and DTD features disabled.

    Prevents XML External Entity (XXE) injection:
      - resolve_entities=False  → never substitute &entity; references
      - no_network=True         → block any network fetch during parsing
      - load_dtd=False          → ignore <!DOCTYPE ...> declarations
      - huge_tree=False         → block Billion Laughs / deeply-nested bombs

    Use this parser for EVERY call to etree.fromstring() or etree.parse().
    """
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        huge_tree=False,
    )


def safe_parse_xml(content: str | bytes) -> etree._Element:
    """
    Parse XML content safely (XXE-hardened).

    Parameters
    ----------
    content : str or bytes
        The raw XML to parse.

    Returns
    -------
    lxml Element (root)

    Raises
    ------
    etree.XMLSyntaxError if the content is not valid XML.
    """
    if isinstance(content, str):
        content = content.encode("utf-8")
    return etree.fromstring(content, parser=safe_xml_parser())


# ─────────────────────────────────────────────────────────────────────────────
# File size validation
# ─────────────────────────────────────────────────────────────────────────────

def validate_upload_size(
    content: bytes,
    label: str = "file",
    limit: Optional[int] = None,
) -> None:
    """
    Raise HTTP 413 if `content` exceeds the configured upload limit.

    Parameters
    ----------
    content : bytes   Raw file bytes to check.
    label   : str     Human-readable name used in the error message.
    limit   : int     Override the global limit for this specific check.
    """
    cap = limit if limit is not None else MAX_UPLOAD_BYTES
    if len(content) > cap:
        mb = cap // 1024 // 1024
        actual_mb = len(content) / 1024 / 1024
        log.warning("Upload rejected: %s is %.1f MB (limit %d MB)", label, actual_mb, mb)
        raise HTTPException(
            status_code=413,
            detail=f"{label} is {actual_mb:.1f} MB — maximum allowed is {mb} MB.",
        )


# ─────────────────────────────────────────────────────────────────────────────
# ZIP extraction (Zip Slip + Zip Bomb protection)
# ─────────────────────────────────────────────────────────────────────────────

class ZipExtractionError(ValueError):
    """Raised when a ZIP archive fails safety checks."""


def safe_zip_extract(zip_bytes: bytes) -> dict[str, bytes]:
    """
    Safely extract a ZIP archive into an in-memory dict.

    Protections
    ───────────
    Zip Slip    Every entry path is resolved relative to a virtual root.
                Any path that would escape (e.g. ``../../etc/passwd``) is
                rejected immediately and the whole archive is discarded.
    Zip Bomb    Total extracted bytes are tracked.  If the sum exceeds
                MAX_ZIP_EXTRACTED_BYTES the extraction stops and raises.
    Entry Count If the archive contains more than MAX_ZIP_FILE_COUNT entries
                it is rejected before any extraction begins.
    Symlinks    Symbolic-link entries are silently skipped.

    Parameters
    ----------
    zip_bytes : bytes  Raw ZIP file content.

    Returns
    -------
    dict mapping ``filename → file_bytes`` for every valid entry.

    Raises
    ------
    ZipExtractionError  on any safety violation.
    zipfile.BadZipFile  if the bytes are not a valid ZIP.
    """
    try:
        zf = zipfile.ZipFile(BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        raise ZipExtractionError(f"Not a valid ZIP file: {exc}") from exc

    entries = zf.infolist()

    if len(entries) > MAX_ZIP_FILE_COUNT:
        raise ZipExtractionError(
            f"ZIP contains {len(entries)} entries — maximum is {MAX_ZIP_FILE_COUNT}."
        )

    extracted: dict[str, bytes] = {}
    total_bytes = 0
    virtual_root = PurePosixPath("/safe_root")

    for entry in entries:
        # Skip directories and symlinks
        if entry.filename.endswith("/"):
            continue
        if entry.external_attr >> 28 == 0xA:  # symlink flag
            log.warning("Skipping symlink entry in ZIP: %s", entry.filename)
            continue

        # ── Zip Slip check ────────────────────────────────────────────────
        # Resolve the entry path relative to our virtual root.
        # If the resolved path no longer starts with the virtual root,
        # the archive is trying to escape — reject it.
        try:
            resolved = (virtual_root / entry.filename).resolve()
        except Exception:
            raise ZipExtractionError(
                f"Malformed path in ZIP entry: {entry.filename!r}"
            )

        if not str(resolved).startswith(str(virtual_root)):
            raise ZipExtractionError(
                f"Zip Slip detected: entry '{entry.filename}' would escape the "
                "extraction directory. Archive rejected."
            )

        # ── Zip Bomb check ────────────────────────────────────────────────
        total_bytes += entry.file_size
        if total_bytes > MAX_ZIP_EXTRACTED_BYTES:
            mb = MAX_ZIP_EXTRACTED_BYTES // 1024 // 1024
            raise ZipExtractionError(
                f"ZIP extraction stopped: total expanded size exceeds {mb} MB limit "
                "(possible zip bomb)."
            )

        content = zf.read(entry.filename)
        # Normalise path separator and strip leading slashes
        safe_name = entry.filename.replace("\\", "/").lstrip("/")
        extracted[safe_name] = content

    return extracted


# ─────────────────────────────────────────────────────────────────────────────
# Generated-code security scanner (bandit)
# ─────────────────────────────────────────────────────────────────────────────

def scan_python_with_bandit(code: str, filename: str = "converted.py") -> dict:
    """
    Run bandit static analysis on generated Python / PySpark code.

    bandit checks for:
      - Hardcoded passwords / credentials (B105, B106, B107)
      - SQL injection (B608)
      - Insecure use of subprocess / shell (B602, B603, B605)
      - Use of assert for security checks (B101)
      - Binding to all interfaces 0.0.0.0 (B104)
      - Use of exec / eval (B102, B307)
      - Insecure deserialization (B301, B302, B303)
      - MD5 / SHA1 for security (B303, B324)

    Returns
    -------
    dict with keys:
      ran         bool — False if bandit is not installed or skipped
      findings    list[dict] — one entry per issue found
      high_count  int
      medium_count int
      low_count   int
      error       str | None — if scan failed for a non-security reason
    """
    result: dict = {
        "ran": False,
        "findings": [],
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "error": None,
    }

    if len(code.splitlines()) > MAX_BANDIT_LINES:
        result["error"] = (
            f"File too large for bandit scan ({len(code.splitlines())} lines > "
            f"{MAX_BANDIT_LINES} limit) — manual review recommended."
        )
        return result

    # Write to a temp file so bandit can process it
    try:
        with tempfile.NamedTemporaryFile(
            suffix=".py", mode="w", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        proc = subprocess.run(
            ["bandit", "-f", "json", "-q", tmp_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        Path(tmp_path).unlink(missing_ok=True)

        import json as _json
        try:
            bandit_out = _json.loads(proc.stdout)
        except Exception:
            result["error"] = f"bandit output parse failed: {proc.stderr[:200]}"
            return result

        result["ran"] = True
        for issue in bandit_out.get("results", []):
            sev = issue.get("issue_severity", "LOW").upper()
            result["findings"].append({
                "test_id":    issue.get("test_id"),
                "test_name":  issue.get("test_name"),
                "severity":   sev,
                "confidence": issue.get("issue_confidence", ""),
                "line":       issue.get("line_number"),
                "text":       issue.get("issue_text", ""),
                "code":       issue.get("code", "").strip()[:200],
            })
            if sev == "HIGH":
                result["high_count"] += 1
            elif sev == "MEDIUM":
                result["medium_count"] += 1
            else:
                result["low_count"] += 1

    except FileNotFoundError:
        result["error"] = "bandit is not installed — pip install bandit to enable scanning."
    except subprocess.TimeoutExpired:
        result["error"] = "bandit scan timed out after 30 seconds."
    except Exception as exc:
        result["error"] = f"bandit scan error: {exc}"
    finally:
        Path(tmp_path).unlink(missing_ok=True) if "tmp_path" in dir() else None

    return result
