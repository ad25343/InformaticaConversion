"""
zip_extractor.py — ZIP upload handling for the Informatica Conversion Tool.

Accepts a raw ZIP upload and returns the three logical files
(mapping XML, workflow XML, parameter file) by auto-detecting their types.

Security
--------
All extraction is delegated to security.safe_zip_extract() which guards against:
  - Zip Slip (path traversal)
  - Zip Bombs (size and entry-count limits)
  - Symlink entries (silently skipped)

File-type detection delegates to session_parser_agent._detect_type() so
the ZIP route shares exactly the same detection logic as the three-file route.
"""
from __future__ import annotations

import logging
from typing import Optional

from .security import safe_zip_extract, validate_upload_size, ZipExtractionError
from .agents.session_parser_agent import _detect_type
from .models.schemas import FileType

log = logging.getLogger("conversion.zip_extractor")


class ZipParseResult:
    """
    The typed output of extract_informatica_zip().

    Attributes
    ----------
    mapping_xml     : str  | None — content of the detected Mapping XML
    workflow_xml    : str  | None — content of the detected Workflow XML
    parameter_file  : str  | None — content of the detected parameter file
    mapping_filename  : str | None — original filename of the mapping entry
    workflow_filename : str | None — original filename of the workflow entry
    param_filename    : str | None — original filename of the parameter entry
    skipped         : list[str]   — entries that could not be classified
    warnings        : list[str]   — non-fatal issues (e.g. multiple mappings found)
    """

    def __init__(self) -> None:
        self.mapping_xml:      Optional[str] = None
        self.workflow_xml:     Optional[str] = None
        self.parameter_file:   Optional[str] = None
        self.mapping_filename: Optional[str] = None
        self.workflow_filename: Optional[str] = None
        self.param_filename:   Optional[str] = None
        self.skipped:  list[str] = []
        self.warnings: list[str] = []


def extract_informatica_zip(zip_bytes: bytes) -> ZipParseResult:
    """
    Safely extract and classify files from a ZIP archive.

    The archive should contain one or more of:
      - An Informatica Mapping XML export  (.xml with <MAPPING> element)
      - An Informatica Workflow XML export (.xml with <WORKFLOW>/<SESSION> elements)
      - An Informatica parameter file      (.txt / .par with $$VAR=value lines)

    Parameters
    ----------
    zip_bytes : bytes
        Raw bytes of the uploaded ZIP file (already read from the UploadFile stream).
        Size validation against MAX_UPLOAD_BYTES should be done *before* calling this.

    Returns
    -------
    ZipParseResult

    Raises
    ------
    ZipExtractionError  — on any ZIP safety violation (re-raised from security module)
    fastapi.HTTPException (413) — if total extracted bytes exceed the ZIP bomb limit
        (raised inside safe_zip_extract via the security module)
    """
    # ── 1. Extract safely (Zip Slip + Zip Bomb + symlink protection) ─────────
    extracted: dict[str, bytes] = safe_zip_extract(zip_bytes)
    log.info("ZIP extracted: %d entries", len(extracted))

    result = ZipParseResult()

    # ── 2. Classify each entry by its content ────────────────────────────────
    for name, content_bytes in extracted.items():
        # Skip macOS / Windows metadata files
        lower = name.lower()
        if lower.startswith("__macosx/") or lower.startswith(".") or lower.endswith(".ds_store"):
            log.debug("Skipping metadata entry: %s", name)
            continue

        try:
            text = content_bytes.decode("utf-8", errors="replace")
        except Exception:
            log.warning("Could not decode entry as UTF-8, skipping: %s", name)
            result.skipped.append(name)
            continue

        detected = _detect_type(text)
        log.debug("Entry '%s' detected as %s", name, detected.value)

        if detected == FileType.MAPPING:
            if result.mapping_xml is not None:
                result.warnings.append(
                    f"Multiple Mapping XML files found — using first detected "
                    f"('{result.mapping_filename}'). Ignoring '{name}'."
                )
                log.warning("Duplicate mapping entry ignored: %s", name)
            else:
                result.mapping_xml = text
                result.mapping_filename = name

        elif detected == FileType.WORKFLOW:
            if result.workflow_xml is not None:
                result.warnings.append(
                    f"Multiple Workflow XML files found — using first detected "
                    f"('{result.workflow_filename}'). Ignoring '{name}'."
                )
                log.warning("Duplicate workflow entry ignored: %s", name)
            else:
                result.workflow_xml = text
                result.workflow_filename = name

        elif detected == FileType.PARAMETER:
            if result.parameter_file is not None:
                result.warnings.append(
                    f"Multiple parameter files found — using first detected "
                    f"('{result.param_filename}'). Ignoring '{name}'."
                )
                log.warning("Duplicate parameter entry ignored: %s", name)
            else:
                result.parameter_file = text
                result.param_filename = name

        else:
            log.debug("Unclassified entry skipped: %s", name)
            result.skipped.append(name)

    # ── 3. Sanity check ──────────────────────────────────────────────────────
    if result.mapping_xml is None:
        raise ZipExtractionError(
            "No Informatica Mapping XML (<MAPPING> element) found inside the ZIP. "
            "The archive must contain at least one mapping export."
        )

    log.info(
        "ZIP classification complete: mapping=%s workflow=%s params=%s skipped=%d",
        result.mapping_filename,
        result.workflow_filename,
        result.param_filename,
        len(result.skipped),
    )

    return result
