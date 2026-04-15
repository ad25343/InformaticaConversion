# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
zip_extractor.py — ZIP upload handling for the Informatica Conversion Tool.

Two public functions:

extract_informatica_zip(zip_bytes) -> ZipParseResult
    Single-mapping ZIP: one or more of mapping/workflow/param files in a flat
    archive (or any folder structure — first mapping found wins).

extract_batch_zip(zip_bytes) -> list[ZipParseResult]
    Batch ZIP (v2.0): one subfolder per mapping.  Each subfolder must contain
    at least one Mapping XML; workflow XML and parameter file are optional.
    Returns one ZipParseResult per valid mapping folder, ordered by folder name.

Security
--------
All extraction is delegated to security.safe_zip_extract() which guards against:
  - Zip Slip (path traversal)
  - Zip Bombs (size and entry-count limits)
  - Symlink entries (silently skipped)

File-type detection delegates to session_parser_agent._detect_type() so
all ZIP routes share exactly the same detection logic as the three-file route.
"""
from __future__ import annotations

import logging
import posixpath
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


def _is_metadata_entry(name: str) -> bool:
    """Return True for macOS / Windows metadata entries that should be skipped."""
    lower = name.lower()
    return (lower.startswith("__macosx/") or
            lower.startswith(".") or
            lower.endswith(".ds_store"))


# Maps FileType to (content_attr, filename_attr, human_label)
_FILE_TYPE_SLOTS: dict[FileType, tuple[str, str, str]] = {
    FileType.MAPPING:   ("mapping_xml",    "mapping_filename",  "Mapping XML"),
    FileType.WORKFLOW:  ("workflow_xml",   "workflow_filename", "Workflow XML"),
    FileType.PARAMETER: ("parameter_file", "param_filename",    "parameter"),
}


def _store_entry_in_result(
    result: ZipParseResult, detected: FileType, name: str, text: str,
) -> None:
    """Store *text* for *detected* type if slot empty; append duplicate warning if not."""
    content_attr, name_attr, label = _FILE_TYPE_SLOTS[detected]
    existing = getattr(result, name_attr)
    if existing is not None:
        result.warnings.append(
            f"Multiple {label} files found — using first detected "
            f"('{existing}'). Ignoring '{name}'."
        )
        log.warning("Duplicate %s entry ignored: %s", label.lower(), name)
    else:
        setattr(result, content_attr, text)
        setattr(result, name_attr, name)


def _apply_single_entry_to_result(result: ZipParseResult, name: str, text: str) -> None:
    """Classify one decoded text entry and store it in *result* (in-place)."""
    detected = _detect_type(text)
    log.debug("Entry '%s' detected as %s", name, detected.value)
    if detected in _FILE_TYPE_SLOTS:
        _store_entry_in_result(result, detected, name, text)
    else:
        log.debug("Unclassified entry skipped: %s", name)
        result.skipped.append(name)


def _decode_zip_entry(name: str, content_bytes: bytes) -> Optional[str]:
    """Decode bytes to UTF-8 string; return None and log on failure."""
    try:
        return content_bytes.decode("utf-8", errors="replace")
    except Exception:
        log.warning("Could not decode entry as UTF-8, skipping: %s", name)
        return None


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
    extracted: dict[str, bytes] = safe_zip_extract(zip_bytes)
    log.info("ZIP extracted: %d entries", len(extracted))

    result = ZipParseResult()

    for name, content_bytes in extracted.items():
        if _is_metadata_entry(name):
            log.debug("Skipping metadata entry: %s", name)
            continue
        text = _decode_zip_entry(name, content_bytes)
        if text is None:
            result.skipped.append(name)
            continue
        _apply_single_entry_to_result(result, name, text)

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


def _assign_to_folder(
    name: str,
    content_bytes: bytes,
    folders: dict[str, dict[str, bytes]],
    top_level_files: list[str],
) -> None:
    """Place one ZIP entry into *folders* or *top_level_files* based on its path."""
    parts = name.split("/")
    if len(parts) < 2 or parts[0] == "":
        top_level_files.append(name)
        log.debug("Ignoring top-level (non-folder) entry: %s", name)
        return
    folder   = parts[0]
    rel_path = "/".join(parts[1:])
    if rel_path:
        folders.setdefault(folder, {})[rel_path] = content_bytes


def _group_by_folder(
    extracted: dict[str, bytes],
) -> tuple[dict[str, dict[str, bytes]], list[str]]:
    """Group extracted ZIP entries by top-level folder; return (folders, top_level_files)."""
    folders: dict[str, dict[str, bytes]] = {}
    top_level_files: list[str] = []
    for name, content_bytes in extracted.items():
        if _is_metadata_entry(name):
            log.debug("Skipping metadata entry: %s", name)
            continue
        _assign_to_folder(name.replace("\\", "/"), content_bytes, folders, top_level_files)
    return folders, top_level_files


def _classify_folder_entries(
    folder_name: str,
    entries: dict[str, bytes],
) -> tuple[dict[str, str], dict[str, str], dict[str, str], list[str]]:
    """Decode and bucket entries by file type. Returns (mapping_xmls, workflow_xmls, params, skipped)."""
    mapping_xmls:    dict[str, str] = {}
    workflow_xmls:   dict[str, str] = {}
    parameter_files: dict[str, str] = {}
    skipped:         list[str]      = []

    _buckets = {
        FileType.MAPPING:   mapping_xmls,
        FileType.WORKFLOW:  workflow_xmls,
        FileType.PARAMETER: parameter_files,
    }

    for rel_path, content_bytes in sorted(entries.items()):
        text = _decode_zip_entry(f"{folder_name}/{rel_path}", content_bytes)
        if text is None:
            skipped.append(f"{folder_name}/{rel_path}")
            continue
        detected = _detect_type(text)
        log.debug("Batch entry '%s/%s' detected as %s", folder_name, rel_path, detected.value)
        bucket = _buckets.get(detected)
        if bucket is not None:
            bucket[rel_path] = text
        else:
            skipped.append(f"{folder_name}/{rel_path}")
    return mapping_xmls, workflow_xmls, parameter_files, skipped


def _pick_first_with_warning(
    items: dict[str, str],
    folder_name: str,
    label: str,
    content_attr: str,
    name_attr: str,
    result: "ZipParseResult",
) -> None:
    """Store first item of *items* on *result*; append warnings for extras."""
    for idx, (rel_path, text) in enumerate(items.items()):
        if idx == 0:
            setattr(result, content_attr, text)
            setattr(result, name_attr, f"{folder_name}/{rel_path}")
        else:
            first = getattr(result, name_attr)
            result.warnings.append(
                f"Folder '{folder_name}': multiple {label} found — "
                f"using '{first}', ignoring '{rel_path}'."
            )


def _stem(filename: str) -> str:
    """
    Return a normalised base name for similarity matching.

    Strips the file extension and common Informatica prefixes
    (m_, wkf_, wf_, s_, seq_) so that
    ``m_FNMA_LOAN_DELIVERY.xml`` and ``wkf_FNMA_LOAN_DELIVERY.xml``
    both reduce to ``fnma_loan_delivery`` and match each other.
    """
    import os
    base = os.path.splitext(os.path.basename(filename))[0].lower()
    for prefix in ("m_", "wkf_", "wf_", "s_", "seq_"):
        if base.startswith(prefix):
            base = base[len(prefix):]
            break
    return base


def _best_match(mapping_stem: str, candidates: dict[str, str]) -> Optional[tuple[str, str]]:
    """
    Return the (rel_path, content) from *candidates* whose stem best matches
    *mapping_stem*, or None if no candidate scores above 0.5.

    Scoring (highest wins):
      1.0  — stems are identical after prefix stripping
      0.8  — one stem contains the other
      n    — length of shared leading characters / max stem length
    """
    best_path, best_text, best_score = None, None, 0.0
    for rel_path, text in candidates.items():
        cand_stem = _stem(rel_path)
        if mapping_stem == cand_stem:
            score = 1.0
        elif mapping_stem in cand_stem or cand_stem in mapping_stem:
            score = 0.8
        else:
            common = sum(1 for a, b in zip(mapping_stem, cand_stem) if a == b)
            score  = common / max(len(mapping_stem), len(cand_stem), 1)
        if score > best_score:
            best_score, best_path, best_text = score, rel_path, text
    if best_score >= 0.5:
        return best_path, best_text
    return None


def _process_standard_folder(
    folder_name: str,
    mapping_xmls: dict[str, str],
    workflow_xmls: dict[str, str],
    parameter_files: dict[str, str],
    skipped_in_folder: list[str],
) -> "ZipParseResult":
    """Build a ZipParseResult for a single-mapping folder."""
    result = ZipParseResult()
    result.warnings = []
    result.skipped  = list(skipped_in_folder)
    _pick_first_with_warning(mapping_xmls,    folder_name, "Mapping XMLs",    "mapping_xml",    "mapping_filename",  result)
    _pick_first_with_warning(workflow_xmls,   folder_name, "Workflow XMLs",   "workflow_xml",   "workflow_filename", result)
    _pick_first_with_warning(parameter_files, folder_name, "parameter files", "parameter_file", "param_filename",   result)
    log.info(
        "Batch folder '%s': mapping=%s workflow=%s params=%s",
        folder_name, result.mapping_filename, result.workflow_filename, result.param_filename,
    )
    return result


def _process_flat_folder(
    folder_name: str, mapping_xmls: dict[str, str],
) -> list["ZipParseResult"]:
    """Expand a flat folder of mapping XMLs (no workflow/params) into one job each."""
    log.info(
        "Batch folder '%s': flat-folder mode — %d mapping XML(s) → %d job(s)",
        folder_name, len(mapping_xmls), len(mapping_xmls),
    )
    results = []
    for rel_path, text in mapping_xmls.items():
        r = ZipParseResult()
        r.mapping_xml      = text
        r.mapping_filename = f"{folder_name}/{rel_path}"
        r.warnings         = []
        r.skipped          = []
        results.append(r)
    return results


def _process_mixed_folder(
    folder_name: str,
    mapping_xmls: dict[str, str],
    workflow_xmls: dict[str, str],
    parameter_files: dict[str, str],
) -> list["ZipParseResult"]:
    """
    Expand a flat folder that has multiple mappings WITH workflows/params.

    Matches each mapping to its best-fit workflow and parameter file by
    filename similarity (after stripping Informatica prefixes like m_, wkf_).

    Example — all in one folder:
        m_FNMA_LOAN.xml   →  wkf_FNMA_LOAN.xml  +  m_FNMA_LOAN.par
        m_FRAUD_SCORE.xml →  wkf_FRAUD_SCORE.xml +  m_FRAUD_SCORE.par
    """
    log.info(
        "Batch folder '%s': mixed flat mode — %d mappings, %d workflows, %d params → matching by name",
        folder_name, len(mapping_xmls), len(workflow_xmls), len(parameter_files),
    )
    remaining_wf  = dict(workflow_xmls)
    remaining_par = dict(parameter_files)
    results: list[ZipParseResult] = []

    for rel_path, text in sorted(mapping_xmls.items()):
        r = ZipParseResult()
        r.mapping_xml      = text
        r.mapping_filename = f"{folder_name}/{rel_path}"
        r.warnings         = []
        r.skipped          = []

        m_stem = _stem(rel_path)

        # Match workflow
        wf_match = _best_match(m_stem, remaining_wf)
        if wf_match:
            wf_path, wf_text = wf_match
            r.workflow_xml      = wf_text
            r.workflow_filename = f"{folder_name}/{wf_path}"
            del remaining_wf[wf_path]   # consume so it can't match another mapping

        # Match parameter file
        par_match = _best_match(m_stem, remaining_par)
        if par_match:
            par_path, par_text = par_match
            r.parameter_file = par_text
            r.param_filename = f"{folder_name}/{par_path}"
            del remaining_par[par_path]

        log.info(
            "  %s → workflow=%s params=%s",
            r.mapping_filename,
            r.workflow_filename or "(none)",
            r.param_filename    or "(none)",
        )
        results.append(r)

    # Anything left unmatched goes into warnings on the first result
    for leftover in list(remaining_wf) + list(remaining_par):
        msg = f"Unmatched file in '{folder_name}': {leftover} — could not pair with any mapping"
        log.warning(msg)
        if results:
            results[0].warnings.append(msg)

    return results


def _process_folder(
    folder_name: str,
    entries: dict[str, bytes],
) -> list["ZipParseResult"]:
    """Classify one folder's entries and return the ZipParseResult(s) for it."""
    mapping_xmls, workflow_xmls, parameter_files, skipped_in_folder = (
        _classify_folder_entries(folder_name, entries)
    )
    if not mapping_xmls:
        log.warning("Batch ZIP: folder '%s' has no Mapping XML — skipping", folder_name)
        return []

    n_mappings = len(mapping_xmls)

    if n_mappings == 1:
        # Single mapping — standard mode (existing behaviour)
        return [_process_standard_folder(
            folder_name, mapping_xmls, workflow_xmls, parameter_files, skipped_in_folder
        )]

    if not workflow_xmls and not parameter_files:
        # Multiple mappings, no support files — simple flat expand
        return _process_flat_folder(folder_name, mapping_xmls)

    # Multiple mappings WITH workflows/params — match by filename similarity
    return _process_mixed_folder(folder_name, mapping_xmls, workflow_xmls, parameter_files)


def extract_batch_zip(zip_bytes: bytes) -> list[ZipParseResult]:
    """
    Extract and classify files from a batch ZIP archive (v2.0).

    Expected structure — one subfolder per mapping::

        batch.zip/
          mapping1/
            mapping.xml        ← required (<MAPPING> element)
            workflow.xml       ← optional
            params.txt         ← optional
          mapping2/
            mapping.xml
            ...

    Rules
    -----
    - Top-level files (not inside any folder) are ignored with a warning.
    - Folders with no Mapping XML are skipped with a warning.
    - Each valid folder produces one ZipParseResult; results are returned
      sorted by folder name for deterministic ordering.
    - macOS (__MACOSX/) and hidden entries (dot-prefixed) are always skipped.

    Parameters
    ----------
    zip_bytes : bytes
        Raw bytes of the uploaded ZIP.

    Returns
    -------
    list[ZipParseResult]
        One entry per mapping folder.  Empty list if no valid folders found.

    Raises
    ------
    ZipExtractionError  — if the archive fails security checks or no valid
                          mapping folders are found at all.
    """
    extracted: dict[str, bytes] = safe_zip_extract(zip_bytes)
    log.info("Batch ZIP extracted: %d entries", len(extracted))

    folders, top_level_files = _group_by_folder(extracted)

    if top_level_files:
        log.warning(
            "Batch ZIP: %d top-level file(s) ignored (must be inside a subfolder): %s",
            len(top_level_files), top_level_files,
        )

    if not folders:
        raise ZipExtractionError(
            "No subfolders found in the batch ZIP. "
            "Each mapping must be in its own subfolder (e.g. mapping1/mapping.xml)."
        )

    results: list[ZipParseResult] = []
    for folder_name in sorted(folders.keys()):
        results.extend(_process_folder(folder_name, folders[folder_name]))

    if not results:
        raise ZipExtractionError(
            "No valid mapping folders found in the batch ZIP. "
            "Each subfolder must contain an Informatica Mapping XML (<MAPPING> element), "
            "or select a flat folder of .xml files."
        )

    log.info("Batch ZIP classification complete: %d mapping(s) found", len(results))
    return results
