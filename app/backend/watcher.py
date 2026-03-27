# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
watcher.py — Manifest-based file watcher for scheduled conversions (v2.14.1)
=============================================================================

Watches a configured directory for manifest files.  When a manifest appears
and ALL its referenced files are present on disk, the watcher automatically
submits a conversion batch through the same pipeline as the API endpoint.

MANIFEST FILE FORMAT (v2.14.1 — Option A)
------------------------------------------
Drop a file named <anything>.manifest.json into the watched directory.

Top-level "workflow" and "parameters" are shared defaults for every mapping
in the batch.  Individual entries in "mappings" can be a plain filename string
(uses the defaults) or an object with their own workflow/parameters overrides.

    {
        "version":   "1.0",
        "label":     "Customer Data Pipeline — Q1 2026",
        "mappings": [
            "m_customer_load.xml",
            "m_product_load.xml",
            {
                "mapping":    "m_appraisal_rank.xml",
                "workflow":   "wf_appraisal.xml",
                "parameters": "params_appraisal.xml"
            }
        ],
        "workflow":      "wf_default.xml",
        "parameters":    "params_prod.xml",
        "reviewer":      "Jane Smith",
        "reviewer_role": "Data Engineer"
    }

Fields:
  label        Optional.  Human-readable name used for the output folder and
               the batch label in the UI.  If omitted, the manifest filename
               stem is used.  A microsecond timestamp is always appended so
               re-runs never overwrite each other.
  mappings     Required.  Array of mapping XMLs.  Each entry is either a
               filename string (inherits top-level workflow/parameters) or an
               object with its own "mapping", "workflow", "parameters" fields
               that override the top-level defaults for that mapping only.
  workflow     Optional top-level default.  Shared across all mappings unless
               a mapping entry provides its own override.
  parameters   Optional top-level default.  Same override logic as workflow.
  reviewer     Optional.  Recorded in logs and webhook notifications.
  reviewer_role Optional.

All referenced files must live in the SAME directory as the manifest.
The manifest is the signal that all files are ready — drop it last.

BACKWARD COMPATIBILITY
----------------------
v2.14.0 singular form ("mapping": "file.xml") is automatically normalised to
the array form so older manifests continue to work without modification.

OUTPUT DIRECTORY NAMING
-----------------------
For each watcher-submitted batch, artifacts are written to:

    OUTPUT_DIR/<label>_<YYYYMMDD_HHMMSS_ffffff>/<mapping_stem>/

where <label> is sanitized from the manifest "label" field (or the manifest
filename stem if no label is provided), and the timestamp always uses
microseconds for uniqueness even across rapid re-runs.

LIFECYCLE
---------
1. Watcher polls the directory every WATCHER_POLL_INTERVAL_SECS seconds.
2. On finding a *.manifest.json, validates the JSON and checks all files
   are present on disk.
3. If complete:  reads files → creates batch → launches pipeline tasks
                 moves manifest to processed/<timestamp>_<name>.manifest.json
4. If incomplete (files missing):  logs warning, retries each poll.
   After WATCHER_INCOMPLETE_TTL_SECS seconds moves to failed/ with .error sidecar.
5. If invalid JSON:  moves immediately to failed/ with .error sidecar.

ENABLING
--------
Set in .env:
    WATCHER_ENABLED=true
    WATCHER_DIR=/path/to/watch/folder
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("conversion.watcher")


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point — called from main.py lifespan
# ─────────────────────────────────────────────────────────────────────────────

def _setup_watch_dirs(watch_dir: str) -> Optional[tuple[Path, Path, Path]]:
    """
    Ensure the watch directory and its processed/failed subdirs exist.
    Returns (root, processed_dir, failed_dir) on success, or None if setup fails.
    """
    root = Path(watch_dir)
    if not root.exists():
        try:
            root.mkdir(parents=True, exist_ok=True)
            logger.info("Watcher: created watch directory %s", root)
        except Exception as exc:
            logger.error(
                "Watcher: cannot create watch directory %s — %s. Watcher disabled.",
                root, exc,
            )
            return None

    processed_dir = root / "processed"
    failed_dir    = root / "failed"
    processed_dir.mkdir(exist_ok=True)
    failed_dir.mkdir(exist_ok=True)
    return root, processed_dir, failed_dir


async def run_watcher_loop(
    watch_dir: str,
    poll_interval: int = 30,
    incomplete_ttl: int = 300,
) -> None:
    """
    Long-running coroutine that polls `watch_dir` for manifest files.
    Designed to be run as an asyncio background task via asyncio.create_task().
    """
    dirs = _setup_watch_dirs(watch_dir)
    if dirs is None:
        return
    root, processed_dir, failed_dir = dirs

    seen_incomplete: dict[str, float] = {}
    logger.info(
        "Watcher started — watching %s every %ds (incomplete TTL: %ds)",
        root, poll_interval, incomplete_ttl,
    )

    while True:
        try:
            await _poll_once(
                root=root,
                processed_dir=processed_dir,
                failed_dir=failed_dir,
                seen_incomplete=seen_incomplete,
                incomplete_ttl=incomplete_ttl,
            )
        except asyncio.CancelledError:
            logger.info("Watcher: received cancellation — stopping.")
            raise
        except Exception as exc:
            logger.exception("Watcher: unexpected error during poll — %s", exc)

        await asyncio.sleep(poll_interval)


# ─────────────────────────────────────────────────────────────────────────────
# Poll logic
# ─────────────────────────────────────────────────────────────────────────────

def _collect_all_paths(resolved_entries: list[dict], root: Path) -> list[Path]:
    """Return deduplicated list of all file Paths referenced by resolved manifest entries."""
    all_paths: list[Path] = []
    seen_names: set[str] = set()

    def _add(fname: Optional[str]) -> None:
        if fname and fname not in seen_names:
            seen_names.add(fname)
            all_paths.append(root / fname)

    for entry in resolved_entries:
        _add(entry["mapping"])
        _add(entry["workflow"])
        _add(entry["parameters"])
    return all_paths


def _read_all_files(manifest_path: Path, all_paths: list[Path]) -> Optional[dict[str, str]]:
    """Read all referenced files into a cache dict. Returns None on OSError."""
    file_cache: dict[str, str] = {}
    try:
        for p in all_paths:
            file_cache[p.name] = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.error("Watcher: could not read files for %s — %s. Leaving for retry.",
                     manifest_path.name, exc)
        return None
    return file_cache


def _find_bad_xmls(resolved_entries: list[dict], file_cache: dict[str, str]) -> list[str]:
    """Return mapping filenames whose content does not look like XML."""
    return [
        entry["mapping"]
        for entry in resolved_entries
        if not file_cache.get(entry["mapping"], "").lstrip().startswith("<")
    ]


def _build_batch_payload(resolved_entries: list[dict], file_cache: dict[str, str]) -> list[dict]:
    """Build the mappings_payload list for _submit_batch."""
    return [
        {
            "filename":       entry["mapping"],
            "xml":            file_cache[entry["mapping"]],
            "workflow_xml":   file_cache.get(entry["workflow"])   if entry["workflow"]   else None,
            "parameter_file": file_cache.get(entry["parameters"]) if entry["parameters"] else None,
        }
        for entry in resolved_entries
    ]


def _get_manifest_base(manifest_path: Path) -> str:
    """Strip '.manifest.json' suffix cleanly; fall back to stem for non-standard names."""
    name = manifest_path.name
    if name.lower().endswith(".manifest.json"):
        return name[: -len(".manifest.json")]
    return manifest_path.stem


async def _submit_manifest(
    manifest_path: Path,
    manifest: dict,
    resolved_entries: list[dict],
    file_cache: dict[str, str],
    processed_dir: Path,
    failed_dir: Path,
) -> None:
    """Validate XML, build payload, submit batch, and move manifest to processed/."""
    bad_xmls = _find_bad_xmls(resolved_entries, file_cache)
    if bad_xmls:
        logger.error("Watcher: invalid XML in %s: %s — moving to failed/.",
                     manifest_path.name, ", ".join(bad_xmls))
        dest = _move_to(manifest_path, failed_dir, prefix="badxml_")
        _write_error_sidecar(dest, f"Not valid XML: {', '.join(bad_xmls)}")
        return

    mappings_payload = _build_batch_payload(resolved_entries, file_cache)
    label          = manifest.get("label") or None
    manifest_base  = _get_manifest_base(manifest_path)
    batch_dir_name = _make_output_dir_name(label, manifest_base)
    source_label   = label or manifest_base
    try:
        batch_id, job_count = await _submit_batch(
            source_label, mappings_payload, batch_dir_name
        )
    except Exception as exc:
        logger.error("Watcher: failed to submit batch for %s — %s. Moving to failed/.",
                     manifest_path.name, exc)
        dest = _move_to(manifest_path, failed_dir, prefix="submitfail_")
        _write_error_sidecar(dest, str(exc))
        return

    _move_to(manifest_path, processed_dir)
    logger.info(
        "Watcher: batch %s created — %d job(s) from manifest %s "
        "(output dir: %s, reviewer: %s).",
        batch_id, job_count, manifest_path.name,
        batch_dir_name,
        manifest.get("reviewer", "unassigned"),
    )


def _handle_invalid_manifest(
    manifest_path: Path,
    key: str,
    exc: Exception,
    failed_dir: Path,
    seen_incomplete: dict[str, float],
) -> None:
    """Move an invalid manifest to failed/ and clean up tracking state."""
    logger.error("Watcher: invalid manifest %s — %s. Moving to failed/.",
                 manifest_path.name, exc)
    dest = _move_to(manifest_path, failed_dir, prefix="invalid_")
    _write_error_sidecar(dest, str(exc))
    seen_incomplete.pop(key, None)


def _get_missing_paths(all_paths: list) -> list[str]:
    """Return names of paths that do not exist on disk."""
    return [p.name for p in all_paths if not p.exists()]


async def _process_manifest_entry(
    manifest_path: Path,
    key: str,
    root: Path,
    processed_dir: Path,
    failed_dir: Path,
    seen_incomplete: dict[str, float],
    incomplete_ttl: int,
    now: float,
) -> None:
    """Parse, check completeness, read files, and submit one manifest."""
    try:
        manifest = _read_manifest(manifest_path)
    except (json.JSONDecodeError, ValueError) as exc:
        _handle_invalid_manifest(manifest_path, key, exc, failed_dir, seen_incomplete)
        return

    resolved_entries = manifest["_resolved_entries"]
    all_paths = _collect_all_paths(resolved_entries, root)
    missing = _get_missing_paths(all_paths)
    if missing:
        _handle_missing_files(
            key, manifest_path, missing, now, seen_incomplete, incomplete_ttl, failed_dir
        )
        return

    seen_incomplete.pop(key, None)
    file_cache = _read_all_files(manifest_path, all_paths)
    if file_cache is None:
        return
    await _submit_manifest(
        manifest_path, manifest, resolved_entries, file_cache, processed_dir, failed_dir
    )


def _handle_missing_files(
    key: str,
    manifest_path: Path,
    missing: list[str],
    now: float,
    seen_incomplete: dict[str, float],
    incomplete_ttl: int,
    failed_dir: Path,
) -> None:
    """Update seen_incomplete tracking; move manifest to failed/ if TTL expired."""
    if key not in seen_incomplete:
        seen_incomplete[key] = now
        logger.warning("Watcher: manifest %s waiting for: %s",
                       manifest_path.name, ", ".join(missing))
        return
    age = now - seen_incomplete[key]
    if age >= incomplete_ttl:
        logger.error(
            "Watcher: manifest %s still incomplete after %ds — "
            "moving to failed/. Missing: %s",
            manifest_path.name, int(age), ", ".join(missing),
        )
        dest = _move_to(manifest_path, failed_dir, prefix="timeout_")
        _write_error_sidecar(
            dest,
            f"Files still missing after {incomplete_ttl}s: {', '.join(missing)}",
        )
        seen_incomplete.pop(key, None)


async def _poll_once(
    root: Path,
    processed_dir: Path,
    failed_dir: Path,
    seen_incomplete: dict[str, float],
    incomplete_ttl: int,
) -> None:
    manifest_files = sorted(root.glob("*.manifest.json"))
    if not manifest_files:
        return

    now = datetime.now(timezone.utc).timestamp()
    for manifest_path in manifest_files:
        key = str(manifest_path)
        await _process_manifest_entry(
            manifest_path, key, root, processed_dir, failed_dir,
            seen_incomplete, incomplete_ttl, now,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Batch submission — mirrors the /jobs/batch route pattern exactly
# ─────────────────────────────────────────────────────────────────────────────

async def _submit_batch(
    source_label: str,
    mappings_payload: list[dict],
    batch_dir_name: str,
) -> tuple[str, int]:
    """
    Create a batch and launch all pipeline tasks.
    Stores watcher_output_dir and watcher_mapping_stem in each job's state so
    job_exporter writes to OUTPUT_DIR/<batch_dir_name>/<mapping_stem>/ instead
    of OUTPUT_DIR/<job_id>/.

    Returns (batch_id, job_count).
    """
    from backend.db import database as db
    from backend import orchestrator
    from backend.routes import _progress_queues, _active_tasks, _batch_semaphore

    batch_id, job_ids = await db.create_batch_atomic(source_label, mappings_payload)

    # Tag each job with the watcher output directory hint before the pipeline starts
    for job_id, entry in zip(job_ids, mappings_payload):
        mapping_stem = Path(entry["filename"]).stem
        await db.update_job(job_id, "pending", 0, {
            "watcher_output_dir":     batch_dir_name,
            "watcher_mapping_stem":   mapping_stem,
        })

    job_entries = []
    for job_id, entry in zip(job_ids, mappings_payload):
        queue: asyncio.Queue = asyncio.Queue()
        _progress_queues[job_id] = queue
        job_entries.append({"job_id": job_id, "filename": entry["filename"]})

    async def _run_with_semaphore(j_id: str, fname: str) -> None:
        try:
            async with _batch_semaphore:
                async for progress in orchestrator.run_pipeline(j_id, fname):
                    await _progress_queues[j_id].put(progress)
        except Exception as exc:
            logger.error("Watcher batch pipeline crashed: job_id=%s error=%s",
                         j_id, exc, exc_info=True)
            try:
                await db.update_job(j_id, "failed", -1,
                                    {"error": f"Watcher batch runner crashed: {exc}"})
            except Exception as db_exc:
                logger.debug("Watcher: DB update failed during crash handler: job_id=%s error=%s",
                             j_id, db_exc)
            await _progress_queues[j_id].put(
                {"step": -1, "status": "failed", "message": f"Pipeline crashed: {exc}"}
            )
        finally:
            await _progress_queues[j_id].put(None)

    for entry in job_entries:
        task = asyncio.create_task(
            _run_with_semaphore(entry["job_id"], entry["filename"])
        )
        task.set_name(f"watcher_{batch_id}_{entry['job_id']}")
        _active_tasks[entry["job_id"]] = task

    return batch_id, len(job_entries)


# ─────────────────────────────────────────────────────────────────────────────
# Manifest reading and validation
# ─────────────────────────────────────────────────────────────────────────────

def _validate_manifest_structure(data: object) -> None:
    """Validate the top-level shape of the manifest dict."""
    if not isinstance(data, dict):
        raise ValueError("Manifest must be a JSON object.")
    _normalise_singular_mapping(data)  # type: ignore[arg-type]
    _validate_mappings_field(data)     # type: ignore[arg-type]
    _validate_label_field(data)        # type: ignore[arg-type]


def _normalise_singular_mapping(data: dict) -> None:
    """Upgrade v2.14.0 singular 'mapping' field to the 'mappings' array form."""
    if "mapping" in data and "mappings" not in data:
        data["mappings"] = [data.pop("mapping")]


def _validate_mappings_field(data: dict) -> None:
    """Assert that 'mappings' is present, non-empty, and a list."""
    if "mappings" not in data or not data["mappings"]:
        raise ValueError("Manifest missing required field: 'mappings' (list of mapping XMLs)")
    if not isinstance(data["mappings"], list):
        raise ValueError("'mappings' must be a JSON array.")


def _validate_label_field(data: dict) -> None:
    """Assert that 'label', when present, is a string."""
    if "label" in data and not isinstance(data["label"], str):
        raise ValueError("'label' must be a string.")


def _validate_top_level_workflow(data: dict) -> None:
    """Validate the optional top-level 'workflow' field."""
    if not data.get("workflow"):
        return
    if not isinstance(data["workflow"], str):
        raise ValueError(
            f"'workflow' must be a string filename, got: {type(data['workflow']).__name__}"
        )
    _assert_plain_filename(data["workflow"], "'workflow'")
    if not data["workflow"].lower().endswith(".xml"):
        raise ValueError(f"'workflow' must be a .xml file, got: {data['workflow']!r}")


def _validate_top_level_parameters(data: dict) -> None:
    """Validate the optional top-level 'parameters' field."""
    if not data.get("parameters"):
        return
    if not isinstance(data["parameters"], str):
        raise ValueError(
            f"'parameters' must be a string filename, got: {type(data['parameters']).__name__}"
        )
    _assert_plain_filename(data["parameters"], "'parameters'")
    if not data["parameters"].lower().endswith((".xml", ".txt", ".par")):
        raise ValueError(
            f"'parameters' must be .xml/.txt/.par, got: {data['parameters']!r}"
        )


def _resolve_all_entries(
    mappings: list, top_workflow: Optional[str], top_parameters: Optional[str]
) -> list[dict]:
    """Resolve every raw entry in the 'mappings' array to a normalised dict."""
    return [
        _resolve_entry(entry, top_workflow, top_parameters, idx)
        for idx, entry in enumerate(mappings)
    ]


def _check_duplicate_mappings(resolved: list[dict]) -> None:
    """Raise ValueError if any mapping filename appears more than once."""
    seen: set[str] = set()
    for r in resolved:
        fname = r["mapping"]
        if fname in seen:
            raise ValueError(
                f"Duplicate mapping filename in 'mappings': {fname!r}. "
                "Each mapping must appear only once per manifest."
            )
        seen.add(fname)


def _read_manifest(path: Path) -> dict:
    """
    Parse and validate a manifest JSON file.
    Raises ValueError for schema violations, json.JSONDecodeError for bad JSON.

    Normalisation applied:
    - v2.14.0 singular "mapping" field → "mappings" array (backward compat)
    - Each entry in "mappings" is resolved to a full dict via _resolve_entry(),
      merging per-mapping overrides with top-level defaults.  The resolved list
      is stored under "_resolved_entries" so _poll_once() never has to re-apply
      defaults.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    _validate_manifest_structure(data)
    _validate_top_level_workflow(data)
    _validate_top_level_parameters(data)

    top_workflow   = data.get("workflow") or None
    top_parameters = data.get("parameters") or None
    resolved       = _resolve_all_entries(data["mappings"], top_workflow, top_parameters)
    _check_duplicate_mappings(resolved)

    data["_resolved_entries"] = resolved
    return data


def _validate_entry_workflow(entry: dict, idx: int) -> None:
    """Validate the per-entry 'workflow' override field if present."""
    if not entry.get("workflow"):
        return
    _assert_plain_filename(str(entry["workflow"]), f"Entry #{idx} 'workflow'")
    if not str(entry["workflow"]).lower().endswith(".xml"):
        raise ValueError(
            f"Entry #{idx} 'workflow' must be a .xml file, got: {entry['workflow']!r}"
        )


def _validate_entry_parameters(entry: dict, idx: int) -> None:
    """Validate the per-entry 'parameters' override field if present."""
    if not entry.get("parameters"):
        return
    _assert_plain_filename(str(entry["parameters"]), f"Entry #{idx} 'parameters'")
    if not str(entry["parameters"]).lower().endswith((".xml", ".txt", ".par")):
        raise ValueError(
            f"Entry #{idx} 'parameters' must be .xml/.txt/.par, "
            f"got: {entry['parameters']!r}"
        )


def _validate_mapping_filename(mapping_file: str, idx: int) -> None:
    """Assert that the mapping filename is a plain .xml file."""
    _assert_plain_filename(mapping_file, f"Entry #{idx} mapping")
    if not mapping_file.lower().endswith(".xml"):
        raise ValueError(
            f"Entry #{idx} mapping filename must be a .xml file, got: {mapping_file!r}"
        )


def _resolve_dict_entry(
    entry: dict,
    top_workflow: Optional[str],
    top_parameters: Optional[str],
    idx: int,
) -> tuple[str, Optional[str], Optional[str]]:
    """Extract and validate fields from a dict-style mapping entry."""
    mapping_file = entry.get("mapping", "")
    if not mapping_file:
        raise ValueError(
            f"Entry #{idx} in 'mappings' is an object but missing required 'mapping' field."
        )
    wf     = entry.get("workflow")   or top_workflow
    params = entry.get("parameters") or top_parameters
    _validate_entry_workflow(entry, idx)
    _validate_entry_parameters(entry, idx)
    return mapping_file, wf, params


def _resolve_entry(
    entry: object,
    top_workflow: Optional[str],
    top_parameters: Optional[str],
    idx: int,
) -> dict:
    """
    Normalise a single entry in the "mappings" array to a uniform dict:
        {"mapping": str, "workflow": str|None, "parameters": str|None}

    Entry may be:
    - A plain string filename         → uses top-level defaults
    - A dict with "mapping" key       → per-mapping overrides; falls back to defaults
    """
    if isinstance(entry, str):
        mapping_file, wf, params = entry, top_workflow, top_parameters
    elif isinstance(entry, dict):
        mapping_file, wf, params = _resolve_dict_entry(entry, top_workflow, top_parameters, idx)
    else:
        raise ValueError(
            f"Entry #{idx} in 'mappings' must be a filename string or an object, "
            f"got: {type(entry).__name__}"
        )

    _validate_mapping_filename(str(mapping_file), idx)
    return {"mapping": str(mapping_file), "workflow": wf, "parameters": params}


# ─────────────────────────────────────────────────────────────────────────────
# Output directory naming
# ─────────────────────────────────────────────────────────────────────────────

def _make_output_dir_name(label: Optional[str], manifest_stem: str) -> str:
    """
    Build the batch output directory name:
        <sanitized_label>_<YYYYMMDD_HHMMSS_ffffff>

    Always appends a microsecond timestamp so repeated runs with the same label
    never collide and output folders sort chronologically.

    If label is None or empty, the manifest filename stem is used as the base.
    re.ASCII restricts \\w to [a-zA-Z0-9_] only, preventing Unicode characters
    from producing non-ASCII filesystem names.
    """
    base = (label or manifest_stem).strip()
    safe = re.sub(r"[^\w\s-]", "", base, flags=re.ASCII)    # strip non-ASCII / special chars
    safe = re.sub(r"[\s\-]+", "_", safe).strip("_")         # spaces/hyphens → underscore
    safe = safe[:80].rstrip("_") or "batch"                 # max 80 chars, never empty
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S_%f")      # microseconds (%f = 6 digits)
    return f"{safe}_{ts}"


def _assert_plain_filename(fname: str, label: str) -> None:
    """
    Reject filenames that contain path separators or are absolute paths.

    Prevents path traversal attacks where a manifest entry like
    "../../etc/passwd.xml" would escape WATCHER_DIR via `root / fname`.

    Path(fname).name strips all directory components — if the result differs
    from the original string, the filename contained separators.
    """
    if Path(fname).name != fname:
        raise ValueError(
            f"{label} must be a plain filename with no path components, got: {fname!r}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# File system helpers
# ─────────────────────────────────────────────────────────────────────────────

def _move_to(src: Path, dest_dir: Path, prefix: str = "") -> Path:
    """Move src into dest_dir with a UTC timestamp prefix. Returns the destination path."""
    ts   = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = dest_dir / f"{ts}_{prefix}{src.name}"
    try:
        shutil.move(str(src), str(dest))
    except Exception as exc:
        logger.warning("Watcher: could not move %s → %s — %s", src, dest, exc)
    return dest


def _write_error_sidecar(manifest_dest: Path, message: str) -> None:
    try:
        manifest_dest.with_suffix(".error").write_text(
            f"Watcher error: {datetime.now(timezone.utc).isoformat()}\n{message}\n",
            encoding="utf-8",
        )
    except Exception:  # nosec B110 — intentional: sidecar is best-effort; cannot log here
        pass            # as the logger itself may be what's failing
