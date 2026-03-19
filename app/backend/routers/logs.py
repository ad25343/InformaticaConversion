# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Logs sub-router: job log retrieval, download, registry, and history.
"""
from __future__ import annotations
import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse

from ._helpers import (
    db, logger,
    _validate_job_id,
    read_job_log, job_log_path, list_log_registry,
)

router = APIRouter(prefix="")


# ─────────────────────────────────────────────
# Job Logs
# ─────────────────────────────────────────────

@router.get("/jobs/{job_id}/logs")
async def get_job_logs(job_id: str, format: str = "json"):
    """
    Return the full log for a job.
    ?format=json  → JSON array of log entries (default)
    ?format=text  → Human-readable plain text (one line per entry)
    """
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")

    entries = read_job_log(job_id)

    if format == "text":
        lines = []
        for e in entries:
            ts   = e.get("ts", "")[:19].replace("T", " ")
            lvl  = e.get("level", "INFO").ljust(8)
            step = f"[step {e['step']}]" if e.get("step") is not None else "         "
            msg  = e.get("message", "")
            data = e.get("data")
            line = f"{ts} {lvl} {step} {msg}"
            if data:
                line += f"  |  {json.dumps(data)}"
            if e.get("exc"):
                line += f"\n{e['exc']}"
            lines.append(line)
        return PlainTextResponse("\n".join(lines))

    return JSONResponse({"job_id": job_id, "entries": entries, "count": len(entries)})


@router.get("/jobs/{job_id}/logs/download")
async def download_job_log(job_id: str):
    """Download the raw JSONL log file for a job (meaningful filename)."""
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")

    path = job_log_path(job_id)
    if not path or not path.exists():
        raise HTTPException(404, "Log file not found — job may not have started yet")

    content = path.read_text(encoding="utf-8")
    return PlainTextResponse(
        content,
        headers={"Content-Disposition": f'attachment; filename="{path.name}"'},
    )


# ─────────────────────────────────────────────
# Log Registry
# ─────────────────────────────────────────────

@router.get("/logs/registry")
async def get_log_registry():
    """Return the log registry — all jobs with their log filenames and final status."""
    return {"registry": list_log_registry()}


@router.get("/logs/history")
async def get_log_history():
    """Return archived jobs: soft-deleted DB records + orphaned registry entries."""
    from ..logger import list_orphaned_registry_entries
    # Live (non-deleted) jobs — excluded from archive
    live_jobs    = await db.list_jobs()
    live_ids     = {j["job_id"] for j in live_jobs}
    # Soft-deleted jobs (still in DB, flagged deleted_at)
    deleted_jobs = await db.list_deleted_jobs()
    deleted_ids  = {j["job_id"] for j in deleted_jobs}
    # Normalise deleted DB rows to the same shape as registry entries
    deleted_entries = []
    for j in deleted_jobs:
        mn = j.get("mapping_name")
        if isinstance(mn, dict):
            mn = None
        deleted_entries.append({
            "job_id":       j["job_id"],
            "xml_filename": j["filename"],
            "mapping_name": mn or j["filename"],
            "status":       j["status"],
            "started_at":   j["created_at"],
            "deleted_at":   j.get("deleted_at"),
            "log_readable": True,
        })
    # Orphaned registry entries (not in DB at all)
    all_known_ids = live_ids | deleted_ids
    orphans = list_orphaned_registry_entries(all_known_ids)
    # Merge: deleted DB jobs first (most recent), then orphans
    history = deleted_entries + orphans
    history.sort(key=lambda e: e.get("deleted_at") or e.get("started_at", ""), reverse=True)
    return {"history": history}


@router.get("/logs/history/{job_id}")
async def get_history_log(job_id: str):
    """Read the log file for a historical (DB-orphaned) job."""
    from ..logger import read_job_log, job_log_path
    path = job_log_path(job_id)
    if not path:
        _validate_job_id(job_id)
        raise HTTPException(404, "Log file not found")
    entries = read_job_log(job_id)
    return JSONResponse({"job_id": job_id, "entries": entries, "count": len(entries)})
