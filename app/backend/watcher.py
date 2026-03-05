"""
watcher.py — Manifest-based file watcher for scheduled conversions (v2.14.0)
=============================================================================

Watches a configured directory for manifest files.  When a manifest appears
and all its referenced XML files are present, the watcher automatically
submits a conversion job through the same pipeline as the API endpoint.

MANIFEST FILE FORMAT
--------------------
Drop a file named  <anything>.manifest.json  into the watched directory:

    {
        "version":       "1.0",
        "mapping":       "m_appraisal_rank.xml",     // required
        "workflow":      "wf_appraisal.xml",          // optional
        "parameters":    "params.xml",                // optional
        "reviewer":      "Jane Smith",                // optional — shown in gate notifications
        "reviewer_role": "Data Engineer"              // optional
    }

All referenced XML files must live in the SAME directory as the manifest.

LIFECYCLE
---------
1. Watcher polls the directory every WATCHER_POLL_INTERVAL_SECS seconds.
2. On finding a *.manifest.json file, it validates the manifest and checks
   that all referenced files are present.
3. If complete:  reads file content → creates job → launches pipeline task
                 moves manifest to processed/<timestamp>_<name>.manifest.json
4. If incomplete (files missing):  logs a warning, leaves manifest in place,
   retries on the next poll.  After WATCHER_INCOMPLETE_TTL_SECS seconds the
   manifest is moved to failed/ so it does not block the watched directory.
5. If invalid JSON:  moves immediately to failed/ with a .error sidecar.

ENABLING
--------
Set in .env:
    WATCHER_ENABLED=true
    WATCHER_DIR=/path/to/watch/folder

Optional tuning (all have sensible defaults):
    WATCHER_POLL_INTERVAL_SECS=30
    WATCHER_INCOMPLETE_TTL_SECS=300

The watcher starts as a background asyncio task during app startup and shuts
down cleanly on SIGTERM/SIGINT.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("conversion.watcher")


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point — called from main.py lifespan
# ─────────────────────────────────────────────────────────────────────────────

async def run_watcher_loop(
    watch_dir: str,
    poll_interval: int = 30,
    incomplete_ttl: int = 300,
) -> None:
    """
    Long-running coroutine that polls `watch_dir` for manifest files.
    Designed to be run as an asyncio background task via asyncio.create_task().

    Parameters
    ----------
    watch_dir       : Absolute or relative path to the directory to watch.
    poll_interval   : Seconds between polls (default: 30).
    incomplete_ttl  : Seconds before a manifest with missing files is moved
                      to failed/ (default: 300 = 5 minutes).
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
            return

    processed_dir = root / "processed"
    failed_dir    = root / "failed"
    processed_dir.mkdir(exist_ok=True)
    failed_dir.mkdir(exist_ok=True)

    # seen_incomplete: {manifest_path_str: first_seen_utc_timestamp}
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
            # Never let a poll error kill the watcher loop
            logger.exception("Watcher: unexpected error during poll — %s", exc)

        await asyncio.sleep(poll_interval)


# ─────────────────────────────────────────────────────────────────────────────
# Poll logic
# ─────────────────────────────────────────────────────────────────────────────

async def _poll_once(
    root: Path,
    processed_dir: Path,
    failed_dir: Path,
    seen_incomplete: dict[str, float],
    incomplete_ttl: int,
) -> None:
    """Scan the root directory once and process any ready manifests."""
    manifest_files = sorted(root.glob("*.manifest.json"))

    if not manifest_files:
        return

    now = datetime.now(timezone.utc).timestamp()

    for manifest_path in manifest_files:
        key = str(manifest_path)

        # ── Parse manifest ────────────────────────────────────────────────
        try:
            manifest = _read_manifest(manifest_path)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.error(
                "Watcher: invalid manifest %s — %s. Moving to failed/.",
                manifest_path.name, exc,
            )
            _move_to(manifest_path, failed_dir, prefix="invalid_")
            _write_error_sidecar(failed_dir / f"invalid_{manifest_path.name}", str(exc))
            seen_incomplete.pop(key, None)
            continue

        mapping_file = root / manifest["mapping"]
        workflow_file: Optional[Path] = (
            root / manifest["workflow"] if manifest.get("workflow") else None
        )
        parameter_file: Optional[Path] = (
            root / manifest["parameters"] if manifest.get("parameters") else None
        )

        # ── Check all files are present ───────────────────────────────────
        missing = _find_missing_files(mapping_file, workflow_file, parameter_file)

        if missing:
            if key not in seen_incomplete:
                seen_incomplete[key] = now
                logger.warning(
                    "Watcher: manifest %s waiting for files: %s",
                    manifest_path.name, ", ".join(missing),
                )
            else:
                age = now - seen_incomplete[key]
                if age >= incomplete_ttl:
                    logger.error(
                        "Watcher: manifest %s still incomplete after %ds — "
                        "moving to failed/. Missing: %s",
                        manifest_path.name, int(age), ", ".join(missing),
                    )
                    _move_to(manifest_path, failed_dir, prefix="timeout_")
                    _write_error_sidecar(
                        failed_dir / f"timeout_{manifest_path.name}",
                        f"Files still missing after {incomplete_ttl}s: {', '.join(missing)}"
                    )
                    seen_incomplete.pop(key, None)
            continue

        # All files present — clear incomplete tracking
        seen_incomplete.pop(key, None)

        # ── Read file contents ────────────────────────────────────────────
        try:
            xml_str      = mapping_file.read_text(encoding="utf-8", errors="replace")
            workflow_str = (
                workflow_file.read_text(encoding="utf-8", errors="replace")
                if workflow_file else None
            )
            param_str = (
                parameter_file.read_text(encoding="utf-8", errors="replace")
                if parameter_file else None
            )
        except OSError as exc:
            logger.error(
                "Watcher: could not read files for %s — %s. Leaving for retry.",
                manifest_path.name, exc,
            )
            continue

        # Validate mapping content is non-empty XML
        if not xml_str.strip() or not xml_str.lstrip().startswith("<"):
            logger.error(
                "Watcher: mapping file %s is empty or not valid XML — moving to failed/.",
                mapping_file.name,
            )
            _move_to(manifest_path, failed_dir, prefix="badxml_")
            _write_error_sidecar(
                failed_dir / f"badxml_{manifest_path.name}",
                f"{mapping_file.name} is empty or does not start with an XML element."
            )
            continue

        # ── Submit job ────────────────────────────────────────────────────
        try:
            job_id = await _submit_job(
                filename=mapping_file.name,
                xml_str=xml_str,
                workflow_str=workflow_str,
                param_str=param_str,
                manifest=manifest,
            )
        except Exception as exc:
            logger.error(
                "Watcher: failed to submit job for %s — %s. Moving manifest to failed/.",
                manifest_path.name, exc,
            )
            _move_to(manifest_path, failed_dir, prefix="submitfail_")
            _write_error_sidecar(
                failed_dir / f"submitfail_{manifest_path.name}",
                str(exc)
            )
            continue

        # ── Move manifest to processed/ ───────────────────────────────────
        _move_to(manifest_path, processed_dir)
        logger.info(
            "Watcher: job %s created for %s (reviewer: %s). "
            "Manifest moved to processed/.",
            job_id,
            mapping_file.name,
            manifest.get("reviewer", "unassigned"),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Job submission — mirrors the API route pattern exactly
# ─────────────────────────────────────────────────────────────────────────────

async def _submit_job(
    filename: str,
    xml_str: str,
    workflow_str: Optional[str],
    param_str: Optional[str],
    manifest: dict,
) -> str:
    """
    Create a job in the database and launch the pipeline task.
    Returns the new job_id.

    This mirrors the create_job() route handler but is called internally
    without going through HTTP, so it bypasses rate limiting and file-size
    validation (the watcher operator is trusted).
    """
    # Import here to avoid circular imports at module load time
    from backend.db import database as db
    from backend import orchestrator
    from backend.routes import _progress_queues, _active_tasks

    # Attach any manifest metadata as initial job notes
    reviewer      = manifest.get("reviewer", "")
    reviewer_role = manifest.get("reviewer_role", "")

    job_id = await db.create_job(
        filename,
        xml_str,
        workflow_xml_content=workflow_str,
        parameter_file_content=param_str,
        # Pass reviewer info if the DB schema supports it, otherwise it's
        # gracefully ignored by the keyword-arg handler in create_job()
        reviewer=reviewer or None,
        reviewer_role=reviewer_role or None,
    )

    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues[job_id] = queue

    async def _run() -> None:
        async for progress in orchestrator.run_pipeline(job_id, filename):
            await queue.put(progress)
        await queue.put(None)  # sentinel — closes any open SSE stream

    task = asyncio.create_task(_run())
    task.set_name(f"watcher_pipeline_{job_id}")
    _active_tasks[job_id] = task

    return job_id


# ─────────────────────────────────────────────────────────────────────────────
# Manifest reading and validation
# ─────────────────────────────────────────────────────────────────────────────

def _read_manifest(path: Path) -> dict:
    """
    Parse and validate a manifest JSON file.
    Raises ValueError for schema violations, json.JSONDecodeError for bad JSON.
    """
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)

    if not isinstance(data, dict):
        raise ValueError("Manifest must be a JSON object.")

    if "mapping" not in data or not data["mapping"]:
        raise ValueError("Manifest missing required field: 'mapping'")

    if not str(data["mapping"]).lower().endswith(".xml"):
        raise ValueError(
            f"'mapping' must reference a .xml file, got: {data['mapping']!r}"
        )

    for opt_key in ("workflow", "parameters"):
        if opt_key in data and data[opt_key]:
            if not str(data[opt_key]).lower().endswith((".xml", ".txt", ".par")):
                raise ValueError(
                    f"'{opt_key}' must reference a .xml/.txt/.par file, "
                    f"got: {data[opt_key]!r}"
                )

    return data


def _find_missing_files(
    mapping_file: Path,
    workflow_file: Optional[Path],
    parameter_file: Optional[Path],
) -> list[str]:
    """Return a list of filenames that are referenced but not yet present on disk."""
    missing: list[str] = []
    if not mapping_file.exists():
        missing.append(mapping_file.name)
    if workflow_file and not workflow_file.exists():
        missing.append(workflow_file.name)
    if parameter_file and not parameter_file.exists():
        missing.append(parameter_file.name)
    return missing


# ─────────────────────────────────────────────────────────────────────────────
# File system helpers
# ─────────────────────────────────────────────────────────────────────────────

def _move_to(src: Path, dest_dir: Path, prefix: str = "") -> None:
    """Move src to dest_dir, prepending a UTC timestamp + optional prefix."""
    ts   = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"{ts}_{prefix}{src.name}"
    dest = dest_dir / name
    try:
        shutil.move(str(src), str(dest))
    except Exception as exc:
        logger.warning("Watcher: could not move %s to %s — %s", src, dest, exc)


def _write_error_sidecar(manifest_dest: Path, message: str) -> None:
    """Write a .error file alongside a moved manifest explaining why it failed."""
    error_path = manifest_dest.with_suffix(".error")
    try:
        error_path.write_text(
            f"Watcher error: {datetime.now(timezone.utc).isoformat()}\n{message}\n",
            encoding="utf-8",
        )
    except Exception:
        pass  # best-effort; do not propagate
