# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
FastAPI routes — REST API for the Informatica Conversion Tool.
"""
from __future__ import annotations
import asyncio
from datetime import datetime as _datetime
import json
import logging
import os
from pathlib import Path
import re
import time
import uuid as _uuid_mod
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, File, UploadFile, HTTPException, BackgroundTasks, Form, Request
from starlette.background import BackgroundTask
from fastapi.responses import StreamingResponse, JSONResponse, PlainTextResponse, Response
from typing import Optional as _Opt

from .db import database as db
from .limiter import jobs_limiter
from .security_knowledge import record_findings, knowledge_base_stats
from .models.schemas import (
    SignOffRecord, SignOffRequest, ReviewDecision, JobStatus,
    CodeSignOffRequest, CodeSignOffRecord, CodeReviewDecision,
    SecuritySignOffRecord, SecuritySignOffRequest, SecurityReviewDecision,
    BatchStatus,
)
from . import orchestrator
from .logger import read_job_log, read_job_log_raw, job_log_path, list_log_registry
from .agents.s2t_agent import s2t_excel_path
from .security import validate_upload_size, ZipExtractionError
from .zip_extractor import extract_informatica_zip, extract_batch_zip
from .job_exporter import build_output_zip
from .config import settings as _cfg

router = APIRouter(prefix="/api")
logger = logging.getLogger("conversion.routes")

_ROUTE_START_TIME = time.monotonic()

# ── Authorization model ──────────────────────────────────────────────────────
# This tool uses a SINGLE shared password (APP_PASSWORD) — there are no
# individual user accounts.  All authenticated callers are treated as the
# same principal (the team), so there is no per-job ownership check.
#
# Consequence: any authenticated user can read, modify, or delete any job.
# This is acceptable for a small internal team sharing one credential, and
# job IDs are random UUIDs (not guessable by outsiders).
#
# If multi-user isolation is required in future, add a `user_id` column to
# the jobs table (see database.py), persist it on job creation via a session
# claim, and enforce it in every handler below.
# ────────────────────────────────────────────────────────────────────────────

# ── Security helpers ────────────────────────────────────────────────────────

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Allowed MIME types for file uploads (enforced in addition to extension checks)
_ALLOWED_XML_CONTENT_TYPES = {
    "text/xml", "application/xml", "text/plain",
    "application/octet-stream",   # some clients send this for .xml
}
_ALLOWED_ZIP_CONTENT_TYPES = {
    "application/zip", "application/x-zip-compressed",
    "application/octet-stream",
}


def _validate_job_id(job_id: str) -> str:
    """FastAPI dependency — raise 400 if job_id is not a valid UUID.

    Prevents path-traversal/injection attacks using crafted job_id strings.
    Usage: job_id: str
    """
    if not _UUID_RE.match(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format.")
    return job_id


def _validate_xml_content_type(upload: UploadFile) -> None:
    """Reject uploads whose declared content-type is clearly not XML/text."""
    ct = (upload.content_type or "").split(";")[0].strip().lower()
    if ct and ct not in _ALLOWED_XML_CONTENT_TYPES:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported content type '{ct}' — expected XML or plain text.",
        )


def _validate_zip_content_type(upload: UploadFile) -> None:
    """Reject uploads whose declared content-type is clearly not a ZIP archive."""
    ct = (upload.content_type or "").split(";")[0].strip().lower()
    if ct and ct not in _ALLOWED_ZIP_CONTENT_TYPES:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported content type '{ct}' — expected a ZIP archive.",
        )

# ── Active pipeline tasks (in-memory for MVP) ─────
_active_tasks: dict[str, asyncio.Task] = {}
_progress_queues: dict[str, asyncio.Queue] = {}


# ─────────────────────────────────────────────
# User Guide
# ─────────────────────────────────────────────

_GUIDE_PATH = Path(__file__).parent.parent.parent / "docs" / "USER_GUIDE.md"

@router.get("/docs/user-guide", response_class=Response)
async def get_user_guide():
    """Serve USER_GUIDE.md as plain text for in-browser markdown rendering."""
    try:
        content = _GUIDE_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="User guide not found")
    return Response(content=content, media_type="text/plain; charset=utf-8")


# ─────────────────────────────────────────────
# Health Check
# ─────────────────────────────────────────────

@router.get("/health")
async def health_check():
    """
    Liveness + readiness probe.

    Returns 200 when the application and database are healthy.
    Returns 503 when the database is unreachable.
    Used by load balancers, Docker HEALTHCHECK, and uptime monitors.
    """
    import aiosqlite
    import time
    db_status = "ok"
    try:
        async with aiosqlite.connect(db.DB_PATH) as conn:
            await conn.execute("SELECT 1")
    except Exception as exc:
        logger.warning("Health check: DB connectivity failure (%s: %s)", type(exc).__name__, exc)
        db_status = "error"

    uptime = round(time.monotonic() - _ROUTE_START_TIME, 1)
    payload = {
        "status": "ok" if db_status == "ok" else "degraded",
        "version": _cfg.app_version,
        "db": db_status,
        "uptime_seconds": uptime,
    }
    status_code = 200 if db_status == "ok" else 503
    return JSONResponse(content=payload, status_code=status_code)


# ─────────────────────────────────────────────
# Upload + Start
# ─────────────────────────────────────────────

@router.post("/jobs")
async def create_job(
    file:             UploadFile = File(...),
    workflow_file:    _Opt[UploadFile] = File(default=None),
    parameter_file:   _Opt[UploadFile] = File(default=None),
    submitter_name:   _Opt[str] = Form(default=None),
    submitter_team:   _Opt[str] = Form(default=None),
    submitter_notes:  _Opt[str] = Form(default=None),
    pipeline_mode:    str = Form(default="full"),   # "full" | "docs_only"
    _rl:              None = Depends(jobs_limiter),
):
    """Upload files and start the conversion pipeline.

    Required
    --------
    file            Informatica Mapping XML (.xml)

    Optional (v1.1)
    ---------------
    workflow_file   Informatica Workflow XML (.xml) — enables Step 0 session extraction
    parameter_file  Informatica parameter file (.txt / .par) — enables $$VAR resolution
    """
    if not file.filename.lower().endswith(".xml"):
        raise HTTPException(400, "Mapping file must be a .xml Informatica export")
    _validate_xml_content_type(file)

    mapping_content = await file.read()
    validate_upload_size(mapping_content, label=file.filename)

    # Validate the file is non-empty and looks like XML before doing anything else
    if not mapping_content:
        raise HTTPException(400, "Uploaded mapping file is empty.")
    xml_str = mapping_content.decode("utf-8", errors="replace").strip()
    if not xml_str:
        raise HTTPException(400, "Uploaded mapping file is empty after decoding.")
    if not xml_str.lstrip().startswith("<"):
        raise HTTPException(400, "Uploaded file does not appear to be valid XML — "
                               "it must start with an XML element or declaration.")

    workflow_str: _Opt[str] = None
    if workflow_file and workflow_file.filename:
        wf_content = await workflow_file.read()
        validate_upload_size(wf_content, label=workflow_file.filename)
        workflow_str = wf_content.decode("utf-8", errors="replace")
        logger.info("Workflow file uploaded: filename=%s size=%d bytes",
                    workflow_file.filename, len(wf_content))

    param_str: _Opt[str] = None
    if parameter_file and parameter_file.filename:
        pf_content = await parameter_file.read()
        validate_upload_size(pf_content, label=parameter_file.filename)
        param_str = pf_content.decode("utf-8", errors="replace")
        logger.info("Parameter file uploaded: filename=%s size=%d bytes",
                    parameter_file.filename, len(pf_content))

    # Normalise and validate pipeline_mode
    _pm = (pipeline_mode or "full").strip().lower()
    if _pm not in ("full", "docs_only"):
        _pm = "full"

    job_id = await db.create_job(
        file.filename,
        xml_str,
        workflow_xml_content=workflow_str,
        parameter_file_content=param_str,
        submitter_name=submitter_name or None,
        submitter_team=submitter_team or None,
        submitter_notes=submitter_notes or None,
    )

    # Stamp pipeline_mode + readable output-folder hints immediately after creation
    mapping_stem  = Path(file.filename).stem
    await db.update_job(job_id, "pending", 0, {
        "pipeline_mode":       _pm,
        "watcher_output_dir":  "individual",
        "watcher_mapping_stem": f"{mapping_stem}_{job_id[:8]}",
    })

    logger.info("Job created: job_id=%s filename=%s size=%d bytes has_workflow=%s has_params=%s submitter=%s mode=%s",
                job_id, file.filename, len(mapping_content),
                workflow_str is not None, param_str is not None,
                submitter_name or "(anonymous)", _pm)

    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues[job_id] = queue

    async def _run():
        async for progress in orchestrator.run_pipeline(job_id, file.filename):
            await queue.put(progress)
        await queue.put(None)  # sentinel

    task = asyncio.create_task(_run())
    _active_tasks[job_id] = task

    return {
        "job_id":        job_id,
        "filename":      file.filename,
        "has_workflow":  workflow_str is not None,
        "has_params":    param_str is not None,
        "status":        "started",
    }


# ─────────────────────────────────────────────
# SSE Progress Stream
# ─────────────────────────────────────────────

@router.get("/jobs/{job_id}/stream")
async def stream_progress(job_id: str):
    """Server-Sent Events stream for real-time pipeline progress."""
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")

    async def event_generator() -> AsyncGenerator[str, None]:
        queue = _progress_queues.get(job_id)

        if queue:
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=60.0)
                    if item is None:
                        yield f"data: {json.dumps({'type': 'done'})}\n\n"
                        break
                    yield f"data: {json.dumps({'type': 'progress', **item})}\n\n"
                except asyncio.TimeoutError:
                    yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
        else:
            current = await db.get_job(job_id)
            yield f"data: {json.dumps({'type': 'state', 'status': current['status'], 'step': current['current_step']})}\n\n"
            yield f"data: {json.dumps({'type': 'done'})}\n\n"

    async def _cleanup():
        # GAP #11 — release the queue once the stream is done to prevent memory leak
        _progress_queues.pop(job_id, None)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        background=BackgroundTask(_cleanup),
    )


# ─────────────────────────────────────────────
# Job State
# ─────────────────────────────────────────────

@router.get("/jobs/stats")
async def job_stats():
    """Return total job counts grouped by status bucket — used by the landing page."""
    running_statuses = (
        "pending","parsing","classifying","documenting","verifying",
        "assigning_stack","converting","security_scanning","validating",
        "reviewing","testing",
    )
    gate_statuses = ("awaiting_review","awaiting_security_review","awaiting_code_review")
    placeholders_r = ",".join("?" * len(running_statuses))
    placeholders_g = ",".join("?" * len(gate_statuses))
    async with db._connect() as conn:
        async with conn.execute(
            f"""SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status IN ({placeholders_r}) THEN 1 ELSE 0 END) AS running,
                SUM(CASE WHEN status = 'complete'            THEN 1 ELSE 0 END) AS complete,
                SUM(CASE WHEN status IN ({placeholders_g})   THEN 1 ELSE 0 END) AS awaiting_review
            FROM jobs WHERE deleted_at IS NULL""",
            (*running_statuses, *gate_statuses),
        ) as cur:
            row = await cur.fetchone()
    if row:
        return {"total": row[0] or 0, "running": row[1] or 0,
                "complete": row[2] or 0, "awaiting_review": row[3] or 0}
    return {"total": 0, "running": 0, "complete": 0, "awaiting_review": 0}


@router.get("/jobs")
async def list_jobs(page: int = 1, page_size: int = 20):
    """List jobs newest-first with pagination.

    Query params:
      page      — 1-based page number (default 1)
      page_size — jobs per page (default 20, max 100)
    """
    page_size = min(max(page_size, 1), 100)
    page      = max(page, 1)
    offset    = (page - 1) * page_size
    jobs      = await db.list_jobs(limit=page_size, offset=offset)
    total     = await db.count_jobs()
    return {
        "jobs":      jobs,
        "total":     total,
        "page":      page,
        "page_size": page_size,
        "pages":     max(1, -(-total // page_size)),   # ceiling division
    }


@router.delete("/jobs/{job_id}")
async def delete_job(job_id: str):
    """Soft-delete a job (sets deleted_at; preserves DB record and log file)."""
    from .agents.s2t_agent import s2t_excel_path

    flagged = await db.delete_job(job_id)
    if not flagged:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found or already deleted")

    # S2T Excel is an intermediate artefact — still clean it up.
    # Log file and registry entry are kept so the job appears in Log Archive.
    cleaned = []
    s2t_path = s2t_excel_path(job_id)
    if s2t_path and s2t_path.exists():
        try:
            s2t_path.unlink()
            cleaned.append("s2t")
        except OSError:
            pass

    return {"flagged_deleted": True, "job_id": job_id, "cleaned": cleaned}


@router.delete("/batches/{batch_id}")
async def delete_batch(batch_id: str):
    """Soft-delete every non-deleted job in a batch in one operation.
    Preserves DB records and log files for the audit trail."""
    from .agents.s2t_agent import s2t_excel_path

    count = await db.delete_batch_jobs(batch_id)
    if count == 0:
        raise HTTPException(404, "Batch not found or all jobs already deleted")

    # Clean up any S2T artefacts for each batch job
    batch_jobs = await db.get_batch_jobs(batch_id)
    cleaned_s2t = 0
    for j in batch_jobs:
        s2t_path = s2t_excel_path(j["job_id"])
        if s2t_path and s2t_path.exists():
            try:
                s2t_path.unlink()
                cleaned_s2t += 1
            except OSError:
                pass

    logger.info("Batch soft-deleted: batch_id=%s jobs_deleted=%d s2t_cleaned=%d",
                batch_id, count, cleaned_s2t)
    return {"flagged_deleted": True, "batch_id": batch_id, "jobs_deleted": count}


@router.get("/jobs/{job_id}")
async def get_job(job_id: str):
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")
    return {
        "job_id":       job["job_id"],
        "filename":     job["filename"],
        "status":       job["status"],
        "current_step": job["current_step"],
        "created_at":   job["created_at"],
        "updated_at":   job["updated_at"],
        "state":        job["state"],
    }


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
    from .logger import list_orphaned_registry_entries
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
    from .logger import read_job_log, job_log_path
    path = job_log_path(job_id)
    if not path:
        _validate_job_id(job_id)
        raise HTTPException(404, "Log file not found")
    entries = read_job_log(job_id)
    return JSONResponse({"job_id": job_id, "entries": entries, "count": len(entries)})


# ─────────────────────────────────────────────
# Human Sign-off (Step 5 gate)
# ─────────────────────────────────────────────

@router.post("/jobs/{job_id}/sign-off")
async def submit_signoff(job_id: str, payload: SignOffRequest):
    """Submit human review decision. If APPROVED, resumes pipeline."""
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")
    if job["status"] != JobStatus.AWAITING_REVIEW.value:
        raise HTTPException(400, f"Job is not awaiting review (status: {job['status']})")

    sign_off = SignOffRecord(
        reviewer_name=payload.reviewer_name,
        reviewer_role=payload.reviewer_role,
        review_date=_datetime.utcnow().isoformat(),
        blocking_resolved=[],
        flags_accepted=[r for r in payload.flag_resolutions if r.action == "accepted"],
        flags_resolved=[r for r in payload.flag_resolutions if r.action == "resolved"],
        decision=payload.decision,
        notes=payload.notes,
    )

    logger.info("Sign-off received: job_id=%s decision=%s reviewer=%s",
                job_id, payload.decision, payload.reviewer_name)

    await db.update_job(job_id, JobStatus.AWAITING_REVIEW.value, 5,
                        {"sign_off": sign_off.model_dump()})

    # GAP #17 — immutable audit record for Gate 1 decision
    await db.add_audit_entry(
        job_id=job_id,
        gate="gate1",
        event_type=payload.decision.lower(),
        reviewer_name=payload.reviewer_name,
        reviewer_role=payload.reviewer_role,
        decision=payload.decision,
        notes=payload.notes,
    )

    if payload.decision == ReviewDecision.REJECTED:
        await db.update_job(job_id, JobStatus.BLOCKED.value, 5, {})
        logger.info("Job rejected: job_id=%s", job_id)
        return {"message": "Job rejected. Pipeline will not proceed."}

    # APPROVED — resume pipeline in background
    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues[job_id] = queue

    state    = job["state"]
    filename = job["filename"]

    resume_gen = orchestrator.resume_after_signoff(job_id, state, filename)
    if job_id in _batch_job_ids:
        # Batch job: reacquire the concurrency semaphore before resuming so the
        # active-pipeline cap is respected.  The slot was freed when the job
        # first reached this gate in _run_with_semaphore.
        task = asyncio.create_task(_resume_batch_job(job_id, resume_gen))
    else:
        async def _resume():
            async for progress in resume_gen:
                await queue.put(progress)
            await queue.put(None)
        task = asyncio.create_task(_resume())

    _active_tasks[job_id] = task
    logger.info("Pipeline resuming after approval: job_id=%s batch=%s",
                job_id, job_id in _batch_job_ids)

    return {"message": "Sign-off accepted. Pipeline resuming from Step 6.", "job_id": job_id}


# ─────────────────────────────────────────────
# Security Review Sign-off (Step 9 gate)
# ─────────────────────────────────────────────

@router.post("/jobs/{job_id}/security-review")
async def submit_security_review(job_id: str, payload: SecuritySignOffRequest):
    """
    Submit human security review decision (Gate 2 — Step 9).
    APPROVED / ACKNOWLEDGED  → resume pipeline from Step 10.
    REQUEST_FIX              → re-run Steps 7-8 with findings as fix context, re-present Gate 2.
    FAILED                   → block the job permanently.
    """
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")
    if job["status"] != JobStatus.AWAITING_SEC_REVIEW.value:
        raise HTTPException(400, f"Job is not awaiting security review (status: {job['status']})")

    state    = job["state"]
    filename = job["filename"]

    # Determine remediation round — increments each time REQUEST_FIX is chosen
    prev_round = state.get("remediation_round", 0)
    this_round = prev_round + 1 if payload.decision == SecurityReviewDecision.REQUEST_FIX else prev_round

    sec_signoff = SecuritySignOffRecord(
        reviewer_name=payload.reviewer_name,
        reviewer_role=payload.reviewer_role,
        review_date=_datetime.utcnow().isoformat() + "Z",
        decision=payload.decision,
        notes=payload.notes,
        remediation_round=prev_round,
    )

    logger.info("Security review received: job_id=%s decision=%s reviewer=%s round=%d",
                job_id, payload.decision, payload.reviewer_name, prev_round)

    await db.update_job(job_id, JobStatus.AWAITING_SEC_REVIEW.value, 9,
                        {"security_sign_off": sec_signoff.model_dump()})

    # GAP #17 — immutable audit record for Gate 2 decision
    await db.add_audit_entry(
        job_id=job_id,
        gate="gate2",
        event_type=payload.decision.lower(),
        reviewer_name=payload.reviewer_name,
        reviewer_role=payload.reviewer_role,
        decision=payload.decision,
        notes=payload.notes,
        extra={"remediation_round": prev_round},
    )

    if payload.decision == SecurityReviewDecision.FAILED:
        await db.update_job(job_id, JobStatus.BLOCKED.value, 9, {})
        logger.info("Security review failed — job blocked: job_id=%s", job_id)
        return {
            "message": "Security review failed. Job is blocked — pipeline will not proceed.",
            "job_id": job_id,
            "decision": payload.decision,
        }

    if payload.decision == SecurityReviewDecision.REQUEST_FIX:
        # Re-run Steps 7-8 with security findings injected, then re-pause at Gate 2
        queue: asyncio.Queue = asyncio.Queue()
        _progress_queues[job_id] = queue

        state["security_sign_off"] = sec_signoff.model_dump()
        state["remediation_round"] = this_round

        fix_gen = orchestrator.resume_after_security_fix_request(
            job_id, state, filename, remediation_round=this_round
        )
        if job_id in _batch_job_ids:
            task = asyncio.create_task(_resume_batch_job(job_id, fix_gen))
        else:
            async def _fix_and_rescan():
                async for progress in fix_gen:
                    await queue.put(progress)
                await queue.put(None)
            task = asyncio.create_task(_fix_and_rescan())
        _active_tasks[job_id] = task
        logger.info("Pipeline re-running Steps 7-8 for security fix: job_id=%s round=%d",
                    job_id, this_round)
        return {
            "message": f"Security fix requested (round {this_round}). Regenerating code and re-scanning.",
            "job_id": job_id,
            "decision": payload.decision,
            "remediation_round": this_round,
        }

    # APPROVED or ACKNOWLEDGED — capture findings into the security knowledge base,
    # then resume pipeline from Step 10
    queue = asyncio.Queue()
    _progress_queues[job_id] = queue

    state["security_sign_off"] = sec_signoff.model_dump()

    # ── Record findings in the knowledge base so future jobs learn from them ──
    scan = state.get("security_scan") or {}
    findings = scan.get("findings") if isinstance(scan, dict) else []
    if findings:
        try:
            n = record_findings(job_id, findings)
            logger.info("Security KB: recorded %d pattern(s) from job %s", n, job_id)
        except Exception as kb_err:
            logger.warning("Security KB: failed to record findings: %s", kb_err)

    sec_resume_gen = orchestrator.resume_after_security_review(job_id, state, filename)
    if job_id in _batch_job_ids:
        task = asyncio.create_task(_resume_batch_job(job_id, sec_resume_gen))
    else:
        async def _resume():
            async for progress in sec_resume_gen:
                await queue.put(progress)
            await queue.put(None)
        task = asyncio.create_task(_resume())

    _active_tasks[job_id] = task
    logger.info("Pipeline resuming after security review: job_id=%s decision=%s batch=%s",
                job_id, payload.decision, job_id in _batch_job_ids)

    return {
        "message": f"Security review recorded ({payload.decision}). Pipeline resuming from Step 10.",
        "job_id": job_id,
        "decision": payload.decision,
    }


# ─────────────────────────────────────────────
# Code Review Sign-off (Step 12 gate)
# ─────────────────────────────────────────────

@router.post("/jobs/{job_id}/code-signoff")
async def submit_code_signoff(job_id: str, payload: CodeSignOffRequest):
    """
    Submit code review decision (Gate 3 — Step 12).
      APPROVED → mark job COMPLETE.
      REJECTED → block the job permanently.
    """
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")
    if job["status"] != JobStatus.AWAITING_CODE_REVIEW.value:
        raise HTTPException(400, f"Job is not awaiting code review (status: {job['status']})")

    code_signoff = CodeSignOffRecord(
        reviewer_name=payload.reviewer_name,
        reviewer_role=payload.reviewer_role,
        review_date=_datetime.utcnow().isoformat(),
        decision=payload.decision,
        notes=payload.notes,
    )

    logger.info("Code sign-off received: job_id=%s decision=%s reviewer=%s",
                job_id, payload.decision, payload.reviewer_name)

    await db.update_job(job_id, JobStatus.AWAITING_CODE_REVIEW.value, 12,
                        {"code_sign_off": code_signoff.model_dump()})

    # GAP #17 — immutable audit record for Gate 3 decision
    await db.add_audit_entry(
        job_id=job_id,
        gate="gate3",
        event_type=payload.decision.lower(),
        reviewer_name=payload.reviewer_name,
        reviewer_role=payload.reviewer_role,
        decision=payload.decision,
        notes=payload.notes,
    )

    # REJECTED — block the job immediately
    if payload.decision == CodeReviewDecision.REJECTED:
        await db.update_job(job_id, JobStatus.BLOCKED.value, 12, {})
        logger.info("Code review rejected: job_id=%s reviewer=%s",
                    job_id, payload.reviewer_name)
        return {
            "message": (
                "Code review rejected. Job is blocked — upload the mapping again "
                "to start a fresh conversion."
            ),
            "job_id":   job_id,
            "decision": payload.decision,
        }

    # APPROVED — resume to write COMPLETE status
    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues[job_id] = queue

    state    = job["state"]
    state["code_sign_off"] = code_signoff.model_dump()
    filename = job["filename"]

    code_resume_gen = orchestrator.resume_after_code_signoff(job_id, state, filename)
    if job_id in _batch_job_ids:
        task = asyncio.create_task(_resume_batch_job(job_id, code_resume_gen))
    else:
        async def _resume():
            async for progress in code_resume_gen:
                await queue.put(progress)
            await queue.put(None)
        task = asyncio.create_task(_resume())

    _active_tasks[job_id] = task
    logger.info("Pipeline resuming after code sign-off: job_id=%s decision=%s batch=%s",
                job_id, payload.decision, job_id in _batch_job_ids)

    return {
        "message": f"Code sign-off recorded ({payload.decision}). Pipeline resuming.",
        "job_id": job_id,
        "decision": payload.decision,
    }


# ─────────────────────────────────────────────
# Audit trail  (GAP #17)
# ─────────────────────────────────────────────

@router.get("/jobs/{job_id}/audit")
async def get_job_audit(job_id: str):
    """Return all gate-decision audit entries for a job, oldest first.

    Each entry contains: audit_id, gate (gate1/gate2/gate3), event_type,
    _validate_job_id(job_id)
    reviewer_name, reviewer_role, decision, notes, extra, created_at.
    """
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    entries = await db.get_audit_log(job_id)
    return {"job_id": job_id, "entries": entries}


# ─────────────────────────────────────────────
# Retry failed / blocked job  (v2.17.3)
# ─────────────────────────────────────────────

@router.post("/jobs/{job_id}/retry")
async def retry_job(job_id: str):
    """
    Reset a failed or blocked job back to pending and re-run the full pipeline.

    Only jobs in status 'failed' or 'blocked' can be retried.
    The original XML content is preserved; state is cleared so the pipeline
    starts fresh from Step 1.  Audit entries are preserved for traceability.

    Returns the same structure as POST /api/jobs on success.
    """
    _validate_job_id(job_id)
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")

    retryable = {JobStatus.FAILED.value, JobStatus.BLOCKED.value}
    if job["status"] not in retryable:
        raise HTTPException(
            400,
            f"Job cannot be retried (status: {job['status']}). "
            "Only failed or blocked jobs are retryable.",
        )

    # Verify the original XML is still available
    xml_row = await db.get_xml(job_id)
    if not xml_row:
        raise HTTPException(
            409,
            "Cannot retry — original XML content has been purged. "
            "Please re-upload the file.",
        )

    # Reset job state: back to pending, step 0, clear pipeline state
    async with db._connect() as conn:
        now = _datetime.utcnow().isoformat()
        await conn.execute(
            "UPDATE jobs SET status='pending', current_step=0, state_json='{}', "
            "updated_at=? WHERE job_id=?",
            (now, job_id),
        )
        await conn.commit()

    # Write an audit entry so the retry is traceable
    await db.add_audit_entry(
        job_id=job_id,
        gate="retry",
        event_type="retry",
        reviewer_name="system",
        reviewer_role="system",
        decision="RETRY",
        notes=f"Job retried from status '{job['status']}' at {now}",
    )

    # Re-launch the pipeline
    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues[job_id] = queue

    filename = job["filename"]

    async def _rerun():
        async for progress in orchestrator.run_pipeline(job_id, filename):
            await queue.put(progress)
        await queue.put(None)

    task = asyncio.create_task(_rerun())
    _active_tasks[job_id] = task

    logger.info("Job retried: job_id=%s filename=%s prev_status=%s",
                job_id, filename, job["status"])

    return {
        "job_id":   job_id,
        "filename": filename,
        "status":   "started",
        "retried":  True,
    }


# ─────────────────────────────────────────────
# Download converted code
# ─────────────────────────────────────────────

@router.get("/jobs/{job_id}/s2t/download")
async def download_s2t_excel(job_id: str):
    """Download the Source-to-Target mapping Excel workbook for a job."""
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")

    path = s2t_excel_path(job_id)
    if not path or not path.exists():
        raise HTTPException(404, "S2T Excel file not found — the job may not have completed Step 2 yet")

    from fastapi.responses import FileResponse
    return FileResponse(
        str(path),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=path.name,
    )


@router.get("/jobs/{job_id}/manifest.xlsx")
async def download_manifest_xlsx(job_id: str):
    """
    Generate and return the pre-conversion mapping manifest xlsx on demand.
    The manifest is NOT stored in state (too large); it is regenerated from the
    graph dict each time this endpoint is called.
    """
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")
    graph = job.get("state", {}).get("graph")
    if not graph:
        raise HTTPException(404, "Manifest not available — job has not completed parsing yet")

    from .agents import manifest_agent
    import io as _io
    report = manifest_agent.build_manifest(graph)
    xlsx_bytes = manifest_agent.write_xlsx_bytes(report)
    safe = job.get("filename", "mapping").replace(".xml", "").replace(" ", "_")
    return StreamingResponse(
        _io.BytesIO(xlsx_bytes),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="manifest_{safe}.xlsx"'},
    )


@router.post("/jobs/{job_id}/manifest-upload")
async def upload_manifest_overrides(job_id: str, file: UploadFile = File(...)):
    """
    Accept a reviewer-annotated manifest xlsx and store the overrides in job state.

    The reviewer downloads the manifest via GET /jobs/{job_id}/manifest.xlsx,
    fills in the 'Reviewer Override' column on the 'Review Required' sheet for any
    LOW or UNMAPPED rows, then re-uploads the annotated file here.

    Must be called while the job is at Gate 1 (awaiting_review).
    The conversion agent picks up the stored overrides when the pipeline resumes
    after sign-off, resolving lineage gaps before generating code.
    """
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")

    if job["status"] != JobStatus.AWAITING_REVIEW.value:
        raise HTTPException(
            400,
            f"Manifest overrides can only be uploaded while the job is awaiting review "
            f"(current status: {job['status']}). Download the manifest, annotate it, "
            f"then upload it before submitting your sign-off.",
        )

    fname = (file.filename or "").lower()
    if not fname.endswith(".xlsx"):
        raise HTTPException(400, "Manifest file must be a .xlsx file")

    xlsx_bytes = await file.read()
    validate_upload_size(xlsx_bytes, label=file.filename)

    if not xlsx_bytes:
        raise HTTPException(400, "Uploaded manifest file is empty")

    # Parse overrides from the annotated xlsx.
    # load_overrides() takes a file path, so write to a temp file first.
    from .agents import manifest_agent
    import tempfile as _tempfile
    import os as _os

    with _tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
        tmp.write(xlsx_bytes)
        tmp_path = tmp.name

    try:
        overrides = manifest_agent.load_overrides(tmp_path)
    finally:
        _os.unlink(tmp_path)

    overrides_dicts = [o.model_dump() for o in overrides]

    # Store overrides in job state — conversion agent reads state["manifest_overrides"]
    # at Step 6 (resume_after_signoff) and injects them into the conversion prompt.
    await db.update_job(
        job_id,
        JobStatus.AWAITING_REVIEW.value,
        5,
        {"manifest_overrides": overrides_dicts},
    )

    logger.info(
        "Manifest overrides uploaded: job_id=%s override_count=%d",
        job_id, len(overrides_dicts),
    )

    return {
        "message": f"Manifest uploaded successfully. {len(overrides_dicts)} override(s) stored.",
        "job_id": job_id,
        "override_count": len(overrides_dicts),
        "overrides": overrides_dicts,
    }


@router.get("/jobs/{job_id}/download/{filename}")
async def download_file(job_id: str, filename: str):
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")
    conversion = job["state"].get("conversion", {})
    files = conversion.get("files", {})
    if filename not in files:
        raise HTTPException(404, f"File '{filename}' not found in conversion output")

    # GAP #14 — Validate the filename is safe before serving
    # Reject path traversal attempts and non-whitelisted extensions
    import pathlib
    _safe_name = pathlib.PurePosixPath(filename).name  # strip any directory components
    _ALLOWED_EXTS = {".py", ".sql", ".yaml", ".yml", ".txt", ".md", ".json", ".sh", ".cfg", ".ini", ".toml"}
    _ext = pathlib.PurePosixPath(_safe_name).suffix.lower()
    if _ext not in _ALLOWED_EXTS:
        logger.warning("Blocked download of disallowed extension: job=%s filename=%s", job_id, filename)
        raise HTTPException(400, f"File extension '{_ext}' is not permitted for download.")

    return JSONResponse({"filename": filename, "content": files[filename]})


@router.get("/jobs/{job_id}/tests/download/{filename:path}")
async def download_test_file(job_id: str, filename: str):
    """Download a generated test file by path (e.g. tests/test_conversion.py)."""
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")
    test_report = job["state"].get("test_report", {})
    files = test_report.get("test_files", {})
    if filename not in files:
        raise HTTPException(404, f"Test file '{filename}' not found")
    return JSONResponse({"filename": filename, "content": files[filename]})


# ─────────────────────────────────────────────
# Output ZIP Download (v2.5.0)
# ─────────────────────────────────────────────

@router.get("/jobs/{job_id}/output.zip")
async def download_output_zip(job_id: str):
    """
    Download all generated conversion output files as a ZIP archive.

    Bundles every file from state["conversion"]["files"] into a single
    ZIP preserving folder structure.  Built directly from DB state so it
    works regardless of whether the job folder has been written to disk.

    Only available for jobs that have reached AWAITING_CODE_REVIEW or
    COMPLETE status (i.e. conversion has run).
    """
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")

    state = job.get("state", {})
    conversion = state.get("conversion", {})
    files = conversion.get("files", {})
    if not files:
        raise HTTPException(404, "No output files found — conversion has not completed for this job.")

    zip_bytes = build_output_zip(state)
    mapping_name = conversion.get("mapping_name", job_id)
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in mapping_name)
    filename = f"{safe_name}_output.zip"

    return StreamingResponse(
        iter([zip_bytes]),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ─────────────────────────────────────────────
# ZIP Upload (v1.1+)
# ─────────────────────────────────────────────

@router.post("/jobs/zip")
async def create_job_from_zip(
    file:            UploadFile = File(...),
    submitter_name:  _Opt[str] = Form(default=None),
    submitter_team:  _Opt[str] = Form(default=None),
    submitter_notes: _Opt[str] = Form(default=None),
    _rl:             None = Depends(jobs_limiter),
):
    """
    Upload a single ZIP archive containing Informatica export files and start
    the conversion pipeline.

    The ZIP may contain any combination of:
      - Mapping XML  (.xml with a <MAPPING> element)       — REQUIRED
      - Workflow XML (.xml with <WORKFLOW>/<SESSION>)       — optional
      - Parameter file (.txt / .par with $$VAR= lines)     — optional

    File types are auto-detected from content — filenames don't matter.
    The archive is protected against Zip Slip, Zip Bombs, and symlink attacks.

    Size limits (configurable via environment variables):
      MAX_UPLOAD_MB          — per-file limit for the ZIP itself (default 50 MB)
      MAX_ZIP_EXTRACTED_MB   — total extracted size limit (default 200 MB)
      MAX_ZIP_FILE_COUNT     — maximum entries in the archive (default 200)
    """
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "File must be a .zip archive")

    _validate_zip_content_type(file)
    zip_bytes = await file.read()
    validate_upload_size(zip_bytes, label=file.filename)

    try:
        extracted = extract_informatica_zip(zip_bytes)
    except ZipExtractionError as exc:
        raise HTTPException(400, str(exc))

    warnings = extracted.warnings
    if extracted.skipped:
        warnings = warnings + [
            f"Skipped {len(extracted.skipped)} unclassified entries: "
            + ", ".join(extracted.skipped[:5])
            + ("…" if len(extracted.skipped) > 5 else "")
        ]

    job_id = await db.create_job(
        extracted.mapping_filename or file.filename,
        extracted.mapping_xml,
        workflow_xml_content=extracted.workflow_xml,
        parameter_file_content=extracted.parameter_file,
        submitter_name=submitter_name or None,
        submitter_team=submitter_team or None,
        submitter_notes=submitter_notes or None,
    )

    logger.info(
        "ZIP job created: job_id=%s zip=%s mapping=%s workflow=%s params=%s",
        job_id, file.filename,
        extracted.mapping_filename, extracted.workflow_filename, extracted.param_filename,
    )

    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues[job_id] = queue

    async def _run():
        async for progress in orchestrator.run_pipeline(
            job_id, extracted.mapping_filename or file.filename
        ):
            await queue.put(progress)
        await queue.put(None)

    task = asyncio.create_task(_run())
    _active_tasks[job_id] = task

    return {
        "job_id":            job_id,
        "source_zip":        file.filename,
        "mapping_filename":  extracted.mapping_filename,
        "workflow_filename": extracted.workflow_filename,
        "param_filename":    extracted.param_filename,
        "has_workflow":      extracted.workflow_xml is not None,
        "has_params":        extracted.parameter_file is not None,
        "warnings":          warnings,
        "status":            "started",
    }


# ─────────────────────────────────────────────
# Batch Upload (v2.0)
# ─────────────────────────────────────────────

# Semaphore: cap concurrent mapping pipelines to respect Claude API limits.
# Override with BATCH_CONCURRENCY env var (default: 3).
from .config import settings as _cfg
_BATCH_CONCURRENCY: int = _cfg.batch_concurrency
_batch_semaphore = asyncio.Semaphore(_BATCH_CONCURRENCY)

# Statuses that mean the pipeline is paused waiting for human input.
# When a batch job reaches one of these we release the semaphore so a queued
# mapping can advance — the slot is reacquired when the gate is approved.
_GATE_WAITING_STATUSES: frozenset[str] = frozenset({
    JobStatus.AWAITING_REVIEW.value,
    JobStatus.AWAITING_SEC_REVIEW.value,
    JobStatus.AWAITING_CODE_REVIEW.value,
})

# Track which job_ids belong to a batch so sign-off handlers know to
# reacquire the semaphore before resuming.
_batch_job_ids: set[str] = set()


async def _resume_batch_job(j_id: str, resume_gen) -> None:
    """
    Re-acquire the batch concurrency semaphore, drive *resume_gen* to
    completion (or to the next gate), then release the slot.

    Called when a human approves a gate on a batch job.  The slot was freed
    when the pipeline first reached the gate in _run_with_semaphore / a
    previous call to this function.
    """
    await _batch_semaphore.acquire()
    semaphore_held = True
    try:
        async for progress in resume_gen:
            await _progress_queues[j_id].put(progress)
            # Hit another gate — release the slot so other jobs can advance
            if semaphore_held and progress.get("status") in _GATE_WAITING_STATUSES:
                _batch_semaphore.release()
                semaphore_held = False
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Batch resume crashed unexpectedly: job_id=%s error=%s", j_id, exc, exc_info=True,
        )
        try:
            await db.update_job(j_id, JobStatus.FAILED.value, -1,
                                {"error": f"Batch resume crashed: {exc}"})
        except Exception:  # pragma: no cover
            logger.exception("Failed to mark crashed batch resume job as FAILED: job_id=%s", j_id)
        await _progress_queues[j_id].put(
            {"step": -1, "status": JobStatus.FAILED.value,
             "message": f"Resume crashed: {exc}"}
        )
    finally:
        if semaphore_held:
            _batch_semaphore.release()
        await _progress_queues[j_id].put(None)


async def recover_batch_jobs() -> dict:
    """
    Called once at startup (from main.py lifespan) after recover_stuck_jobs().

    Does two things:

    1. Re-queues any batch job with status 'pending'.
       These were created atomically but their asyncio tasks never started (or
       were waiting behind the semaphore) when the server stopped.  Each is
       relaunched via _run_with_semaphore so the concurrency cap is respected.

    2. Repopulates _batch_job_ids for gate-waiting batch jobs so that when a
       human approves a gate after a server restart, _resume_batch_job() is
       called and the semaphore is correctly reacquired.

    Returns a summary dict for startup logging.
    """
    # -- Gate-waiting: just restore the tracking set; no task needed --
    gate_job_ids = await db.get_gate_waiting_batch_jobs()
    for jid in gate_job_ids:
        _batch_job_ids.add(jid)

    # -- Pending: re-queue each job --
    pending_jobs = await db.get_pending_batch_jobs()
    requeued = 0
    for pj in pending_jobs:
        j_id   = pj["job_id"]
        fname  = pj["filename"]
        queue: asyncio.Queue = asyncio.Queue()
        _progress_queues[j_id] = queue
        _batch_job_ids.add(j_id)
        task = asyncio.create_task(_run_with_semaphore(j_id, fname))
        _active_tasks[j_id] = task
        requeued += 1
        logger.info(
            "Startup recovery: re-queued pending batch job job_id=%s batch_id=%s filename=%s",
            j_id, pj["batch_id"], fname,
        )

    return {
        "requeued":    requeued,
        "gate_restored": len(gate_job_ids),
    }


def _compute_batch_status(job_statuses: list[str]) -> str:
    """Derive a BatchStatus string from a list of individual job status strings."""
    if not job_statuses:
        return BatchStatus.FAILED.value
    terminal = {JobStatus.COMPLETE.value, JobStatus.FAILED.value, JobStatus.BLOCKED.value}
    complete_set = {JobStatus.COMPLETE.value}
    in_flight = [s for s in job_statuses if s not in terminal]
    if in_flight:
        return BatchStatus.RUNNING.value
    completed = [s for s in job_statuses if s in complete_set]
    if len(completed) == len(job_statuses):
        return BatchStatus.COMPLETE.value
    if completed:
        return BatchStatus.PARTIAL.value
    return BatchStatus.FAILED.value


@router.post("/jobs/batch")
async def create_batch_jobs(
    file:          UploadFile = File(...),
    pipeline_mode: str = Form(default="full"),   # "full" | "docs_only"
    _rl:           None = Depends(jobs_limiter),
):
    """
    Upload a batch ZIP archive and start a parallel conversion pipeline for
    each mapping folder.

    Expected ZIP structure::

        batch.zip/
          mapping_a/
            mapping.xml         ← required
            workflow.xml        ← optional
            params.txt          ← optional
          mapping_b/
            mapping.xml
          ...

    Each mapping folder is processed as an independent job with the full 12-step
    pipeline and its own human review gates.  Up to 3 mappings run concurrently.
    """
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Batch upload must be a .zip archive")

    zip_bytes = await file.read()
    validate_upload_size(zip_bytes, label=file.filename)

    try:
        mapping_results = extract_batch_zip(zip_bytes)
    except ZipExtractionError as exc:
        raise HTTPException(400, str(exc))

    if not mapping_results:
        raise HTTPException(400, "No valid mapping folders found in the batch ZIP.")

    # Normalise pipeline_mode
    _batch_pm = (pipeline_mode or "full").strip().lower()
    if _batch_pm not in ("full", "docs_only"):
        _batch_pm = "full"

    # GAP #4 — Create batch record + all jobs atomically in one transaction.
    # If any insertion fails, the whole batch is rolled back — no orphaned jobs.
    mappings_payload = [
        {
            "filename":       parsed.mapping_filename or file.filename,
            "xml":            parsed.mapping_xml,
            "workflow_xml":   parsed.workflow_xml,
            "parameter_file": parsed.parameter_file,
        }
        for parsed in mapping_results
    ]
    try:
        batch_id, job_ids = await db.create_batch_atomic(file.filename, mappings_payload)
    except Exception as exc:
        logger.error("Atomic batch creation failed: %s", exc, exc_info=True)
        raise HTTPException(500, f"Failed to create batch jobs: {exc}")

    logger.info(
        "Batch created (atomic): batch_id=%s source_zip=%s mapping_count=%d",
        batch_id, file.filename, len(mapping_results),
    )

    # Stamp output-folder hints so job_exporter groups all mappings under one
    # human-readable folder instead of 17 anonymous UUID directories:
    #   OUTPUT_DIR/batch_<short_id>/<mapping_stem>/input|output|docs|logs/
    # This mirrors the watcher batch layout (watcher_output_dir / watcher_mapping_stem).
    batch_dir_name = f"batch_{batch_id[:8]}"
    for job_id, parsed in zip(job_ids, mapping_results):
        mapping_fname = parsed.mapping_filename or file.filename
        mapping_stem  = Path(mapping_fname).stem
        try:
            await db.update_job(
                job_id, "pending", 0,
                {
                    "watcher_output_dir":   batch_dir_name,
                    "watcher_mapping_stem": mapping_stem,
                    "pipeline_mode":        _batch_pm,
                },
            )
        except Exception as hint_exc:  # non-fatal — missing hints just fall back to UUID path
            logger.warning(
                "Could not stamp output hints (non-fatal): job_id=%s error=%s",
                job_id, hint_exc,
            )

    job_entries: list[dict] = []
    for job_id, parsed in zip(job_ids, mapping_results):
        mapping_fname = parsed.mapping_filename or file.filename
        queue: asyncio.Queue = asyncio.Queue()
        _progress_queues[job_id] = queue
        job_entries.append({"job_id": job_id, "filename": mapping_fname, "parsed": parsed})
        # Register as batch job so sign-off endpoints reacquire the semaphore on resume.
        _batch_job_ids.add(job_id)

    # Launch all pipelines concurrently (semaphore caps at BATCH_CONCURRENCY in-flight).
    #
    # GAP #8 — Wrap in try/except/finally so the sentinel is always placed on the
    # queue even when the async generator or semaphore acquisition itself raises.
    #
    # v2.18.17 — Release the semaphore slot when the job hits a human review gate
    # (awaiting_review / awaiting_security_review / awaiting_code_review) instead
    # of holding it for the entire duration of human think-time.  The slot is
    # reacquired by _resume_batch_job() when the reviewer approves the gate.
    # This lets all N mappings advance to their first gate concurrently rather
    # than serialising behind the semaphore during human review.
    async def _run_with_semaphore(j_id: str, fname: str):
        await _batch_semaphore.acquire()
        semaphore_held = True
        try:
            async for progress in orchestrator.run_pipeline(j_id, fname):
                await _progress_queues[j_id].put(progress)
                # Release the slot as soon as the job is waiting for a human —
                # the semaphore is reacquired when the gate is approved.
                if semaphore_held and progress.get("status") in _GATE_WAITING_STATUSES:
                    _batch_semaphore.release()
                    semaphore_held = False
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Batch pipeline crashed unexpectedly: job_id=%s error=%s",
                j_id, exc, exc_info=True,
            )
            # Mark the job FAILED in the DB so the batch status rolls up correctly.
            try:
                await db.update_job(j_id, JobStatus.FAILED.value, -1,
                                    {"error": f"Batch runner crashed: {exc}"})
            except Exception:  # pragma: no cover
                logger.exception("Failed to mark crashed batch job as FAILED: job_id=%s", j_id)
            # Push a synthetic FAILED progress event so any open SSE stream closes cleanly.
            await _progress_queues[j_id].put(
                {"step": -1, "status": JobStatus.FAILED.value,
                 "message": f"Pipeline crashed: {exc}"}
            )
        finally:
            # Always release the semaphore if we still hold it (normal completion or crash).
            if semaphore_held:
                _batch_semaphore.release()
            # Sentinel always placed — closes the SSE generator regardless of outcome.
            await _progress_queues[j_id].put(None)

    for entry in job_entries:
        task = asyncio.create_task(
            _run_with_semaphore(entry["job_id"], entry["filename"])
        )
        _active_tasks[entry["job_id"]] = task
        logger.info("Batch job started: batch_id=%s job_id=%s filename=%s",
                    batch_id, entry["job_id"], entry["filename"])

    return {
        "batch_id":      batch_id,
        "output_folder": batch_dir_name,   # e.g. "batch_a1b2c3d4" under OUTPUT_DIR
        "mapping_count": len(job_entries),
        "jobs": [{"job_id": e["job_id"], "filename": e["filename"]} for e in job_entries],
        "status":        "running",
    }


# ─────────────────────────────────────────────
# Security Knowledge Base (read-only inspection)
# ─────────────────────────────────────────────

@router.get("/security/knowledge")
async def get_security_knowledge():
    """
    Return a summary of the security knowledge base:
      - rules_count    — number of active standing rules
      - patterns_count — number of auto-learned patterns
      - top_patterns   — top 10 most-recurring patterns across all jobs
    """
    return knowledge_base_stats()


# ─────────────────────────────────────────────
# Batch routes
# ─────────────────────────────────────────────

@router.get("/batches/{batch_id}")
async def get_batch(batch_id: str):
    """
    Return the batch record and a summary of all its constituent jobs.

    Response includes:
      - batch_id, source_zip, mapping_count
      - status  — computed from job statuses: running / complete / partial / failed
      - jobs    — list of job summaries (job_id, filename, status, current_step, etc.)
    """
    batch = await db.get_batch(batch_id)
    if not batch:
        raise HTTPException(404, f"Batch '{batch_id}' not found")

    jobs = await db.get_batch_jobs(batch_id)
    batch["status"] = _compute_batch_status([j["status"] for j in jobs])
    batch["jobs"] = jobs
    return batch


# ─────────────────────────────────────────────
# Gate Review Queue (v2.17.1)
# ─────────────────────────────────────────────

def _get_gate_from_status(status: str) -> _Opt[int]:
    """Map job status to gate number: 1 (review), 2 (security), 3 (code)."""
    if status == JobStatus.AWAITING_REVIEW.value:
        return 1
    elif status == JobStatus.AWAITING_SEC_REVIEW.value:
        return 2
    elif status == JobStatus.AWAITING_CODE_REVIEW.value:
        return 3
    return None


def _extract_flags_for_gate(state: dict, gate: int) -> dict:
    """Extract flag summary and top flags from state based on gate."""
    flag_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    top_flags = []

    if gate == 1:
        # Gate 1: Extract from verification.flags
        verification = state.get("verification", {})
        flags = verification.get("flags", [])
        for flag in flags:
            severity = flag.get("severity", "MEDIUM").upper()
            if severity in flag_summary:
                flag_summary[severity] += 1
            flag_type = flag.get("flag_type", "UNKNOWN")
            if flag_type not in top_flags:
                top_flags.append(flag_type)
                if len(top_flags) >= 2:
                    break
    # For gates 2 and 3, leave empty (as per spec: "don't fail if parsing state is expensive, just return empty dict")

    return {"flag_summary": flag_summary, "top_flags": top_flags}


@router.get("/gates/pending")
async def get_pending_gate_jobs(gate: _Opt[int] = None, batch_id: _Opt[str] = None):
    """
    Return all jobs currently waiting at human gates with enough context for batch review.

    Query params:
      - gate: 1, 2, or 3 to filter to specific gate
      - batch_id: filter to specific batch

    Returns jobs sorted by waiting_since ascending (longest waiting first).
    """
    try:
        async with db._connect() as conn:
            conn.row_factory = __import__("aiosqlite").Row

            # Build WHERE clause
            where_clauses = [
                "deleted_at IS NULL",
                f"status IN ('{JobStatus.AWAITING_REVIEW.value}', "
                f"'{JobStatus.AWAITING_SEC_REVIEW.value}', "
                f"'{JobStatus.AWAITING_CODE_REVIEW.value}')",
            ]
            params = []

            if gate:
                status_map = {
                    1: JobStatus.AWAITING_REVIEW.value,
                    2: JobStatus.AWAITING_SEC_REVIEW.value,
                    3: JobStatus.AWAITING_CODE_REVIEW.value,
                }
                if gate not in status_map:
                    raise HTTPException(400, "Gate must be 1, 2, or 3")
                where_clauses.append(f"status = ?")
                params.append(status_map[gate])

            if batch_id:
                where_clauses.append("batch_id = ?")
                params.append(batch_id)

            where_sql = " AND ".join(where_clauses)

            # Fetch all pending jobs
            async with conn.execute(
                f"SELECT job_id, filename, batch_id, status, complexity_tier, "
                f"       created_at, updated_at, state_json FROM jobs "
                f"WHERE {where_sql} ORDER BY updated_at ASC",
                params,
            ) as cur:
                rows = await cur.fetchall()

            # Process rows
            jobs = []
            by_gate = {1: 0, 2: 0, 3: 0}

            for row in rows:
                job_dict = dict(row)
                status = job_dict["status"]
                gate_num = _get_gate_from_status(status)
                if gate_num is None:
                    continue

                by_gate[gate_num] += 1

                state = db._decode_state(job_dict["state_json"])
                complexity = state.get("complexity", {})

                # Calculate waiting time
                now = _datetime.utcnow().isoformat() + "Z"
                created_dt = _datetime.fromisoformat(job_dict["updated_at"].replace("Z", "+00:00"))
                now_dt = _datetime.utcnow()
                waiting_seconds = (now_dt - created_dt.replace(tzinfo=None)).total_seconds()
                waiting_minutes = int(waiting_seconds / 60)

                flag_data = _extract_flags_for_gate(state, gate_num)

                jobs.append({
                    "job_id": job_dict["job_id"],
                    "filename": job_dict["filename"],
                    "batch_id": job_dict["batch_id"],
                    "gate": gate_num,
                    "complexity_tier": complexity.get("tier", "unknown"),
                    "suggested_pattern": complexity.get("suggested_pattern", ""),
                    "pattern_confidence": complexity.get("pattern_confidence", ""),
                    "waiting_since": job_dict["updated_at"],
                    "waiting_minutes": waiting_minutes,
                    **flag_data,
                })

            return {
                "total": len(jobs),
                "by_gate": by_gate,
                "jobs": jobs,
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching pending gate jobs: {e}")
        raise HTTPException(500, f"Error fetching pending gate jobs: {str(e)}")


from pydantic import BaseModel as _PydanticBaseModel


class BatchSignOffRequest(_PydanticBaseModel):
    """Request body for batch gate sign-off."""
    job_ids: list[str]
    gate: int
    decision: str
    reviewer_name: str
    reviewer_role: str
    notes: _Opt[str] = None


@router.post("/gates/batch-signoff")
async def batch_signoff(payload: BatchSignOffRequest):
    """
    Apply a gate decision to multiple jobs at once.

    Supported decisions by gate:
      - Gate 1: APPROVE, REJECT
      - Gate 2: APPROVED, ACKNOWLEDGED, FAILED
      - Gate 3: APPROVED, REJECTED

    Returns {succeeded: [...], failed: [...], errors: {...}}
    """
    try:
        if payload.gate not in (1, 2, 3):
            raise HTTPException(400, "Gate must be 1, 2, or 3")

        # Validate decision for gate
        valid_decisions = {
            1: ["APPROVE", "REJECT"],
            2: ["APPROVED", "ACKNOWLEDGED", "FAILED"],
            3: ["APPROVED", "REJECTED"],
        }
        if payload.decision not in valid_decisions[payload.gate]:
            raise HTTPException(400, f"Invalid decision '{payload.decision}' for gate {payload.gate}")

        succeeded = []
        failed = []
        errors = {}

        # Process each job sequentially to avoid DB locking
        for job_id in payload.job_ids:
            try:
                job = await db.get_job(job_id)
                if not job:
                    errors[job_id] = "Job not found"
                    failed.append(job_id)
                    continue

                # Verify job is at the correct gate
                expected_status = {
                    1: JobStatus.AWAITING_REVIEW.value,
                    2: JobStatus.AWAITING_SEC_REVIEW.value,
                    3: JobStatus.AWAITING_CODE_REVIEW.value,
                }[payload.gate]

                if job["status"] != expected_status:
                    errors[job_id] = f"Job not at gate {payload.gate} (status: {job['status']})"
                    failed.append(job_id)
                    continue

                # Apply decision based on gate and payload decision
                if payload.gate == 1:
                    # Gate 1: APPROVE or REJECT
                    review_decision = ReviewDecision.APPROVED if payload.decision == "APPROVE" else ReviewDecision.REJECTED
                    sign_off = SignOffRecord(
                        reviewer_name=payload.reviewer_name,
                        reviewer_role=payload.reviewer_role,
                        review_date=_datetime.utcnow().isoformat(),
                        blocking_resolved=[],
                        flags_accepted=[],
                        flags_resolved=[],
                        decision=review_decision,
                        notes=payload.notes,
                    )
                    await db.update_job(job_id, JobStatus.AWAITING_REVIEW.value, 5,
                                      {"sign_off": sign_off.model_dump()})

                    await db.add_audit_entry(
                        job_id=job_id,
                        gate="gate1",
                        event_type=payload.decision.lower(),
                        reviewer_name=payload.reviewer_name,
                        reviewer_role=payload.reviewer_role,
                        decision=payload.decision,
                        notes=payload.notes,
                    )

                    if payload.decision == "REJECT":
                        await db.update_job(job_id, JobStatus.BLOCKED.value, 5, {})
                    else:
                        # Resume pipeline for APPROVE
                        queue: asyncio.Queue = asyncio.Queue()
                        _progress_queues[job_id] = queue
                        state = job["state"]
                        filename = job["filename"]

                        async def _resume_gate1():
                            async for progress in orchestrator.resume_after_signoff(job_id, state, filename):
                                await queue.put(progress)
                            await queue.put(None)

                        task = asyncio.create_task(_resume_gate1())
                        _active_tasks[job_id] = task

                elif payload.gate == 2:
                    # Gate 2: APPROVED, ACKNOWLEDGED, or FAILED
                    sec_decision_map = {
                        "APPROVED": SecurityReviewDecision.APPROVED,
                        "ACKNOWLEDGED": SecurityReviewDecision.ACKNOWLEDGED,
                        "FAILED": SecurityReviewDecision.FAILED,
                    }
                    sec_decision = sec_decision_map[payload.decision]

                    state = job["state"]
                    prev_round = state.get("remediation_round", 0)

                    sec_signoff = SecuritySignOffRecord(
                        reviewer_name=payload.reviewer_name,
                        reviewer_role=payload.reviewer_role,
                        review_date=_datetime.utcnow().isoformat() + "Z",
                        decision=sec_decision,
                        notes=payload.notes,
                        remediation_round=prev_round,
                    )

                    await db.update_job(job_id, JobStatus.AWAITING_SEC_REVIEW.value, 9,
                                      {"security_sign_off": sec_signoff.model_dump()})

                    await db.add_audit_entry(
                        job_id=job_id,
                        gate="gate2",
                        event_type=payload.decision.lower(),
                        reviewer_name=payload.reviewer_name,
                        reviewer_role=payload.reviewer_role,
                        decision=payload.decision,
                        notes=payload.notes,
                        extra={"remediation_round": prev_round},
                    )

                    if payload.decision == "FAILED":
                        await db.update_job(job_id, JobStatus.BLOCKED.value, 9, {})
                    elif payload.decision in ("APPROVED", "ACKNOWLEDGED"):
                        # Resume pipeline for APPROVED or ACKNOWLEDGED
                        queue: asyncio.Queue = asyncio.Queue()
                        _progress_queues[job_id] = queue
                        filename = job["filename"]

                        async def _resume_gate2():
                            async for progress in orchestrator.resume_after_security_review(
                                job_id, state, filename
                            ):
                                await queue.put(progress)
                            await queue.put(None)

                        task = asyncio.create_task(_resume_gate2())
                        _active_tasks[job_id] = task

                elif payload.gate == 3:
                    # Gate 3: APPROVED or REJECTED
                    code_decision = CodeReviewDecision.APPROVED if payload.decision == "APPROVED" else CodeReviewDecision.REJECTED

                    code_signoff = CodeSignOffRecord(
                        reviewer_name=payload.reviewer_name,
                        reviewer_role=payload.reviewer_role,
                        review_date=_datetime.utcnow().isoformat(),
                        decision=code_decision,
                        notes=payload.notes,
                    )

                    await db.update_job(job_id, JobStatus.AWAITING_CODE_REVIEW.value, 12,
                                      {"code_sign_off": code_signoff.model_dump()})

                    await db.add_audit_entry(
                        job_id=job_id,
                        gate="gate3",
                        event_type=payload.decision.lower(),
                        reviewer_name=payload.reviewer_name,
                        reviewer_role=payload.reviewer_role,
                        decision=payload.decision,
                        notes=payload.notes,
                    )

                    if payload.decision == "APPROVED":
                        await db.update_job(job_id, JobStatus.COMPLETE.value, 13, {})
                    else:
                        # REJECTED
                        await db.update_job(job_id, JobStatus.BLOCKED.value, 12, {})

                succeeded.append(job_id)
                logger.info(f"Batch sign-off succeeded: job_id={job_id} gate={payload.gate} decision={payload.decision}")

            except Exception as e:
                logger.error(f"Error processing batch sign-off for job {job_id}: {e}")
                errors[job_id] = str(e)
                failed.append(job_id)

        return {
            "succeeded": succeeded,
            "failed": failed,
            "errors": errors,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in batch_signoff: {e}")
        raise HTTPException(500, f"Batch sign-off failed: {str(e)}")


@router.get("/progress")
async def get_migration_progress():
    """
    Return migration-level progress summary across all non-deleted jobs.

    Includes:
      - Status counts (not_started, in_pipeline, awaiting_gate, complete, blocked, failed)
      - Complexity tier breakdown
      - Throughput metrics and ETA
    """
    try:
        async with db._connect() as conn:
            conn.row_factory = __import__("aiosqlite").Row

            # Fetch all non-deleted jobs with minimal fields
            async with conn.execute(
                "SELECT status, complexity_tier, created_at, updated_at "
                "FROM jobs WHERE deleted_at IS NULL"
            ) as cur:
                rows = await cur.fetchall()

        # Count statuses and tiers
        status_counts = {
            "not_started": 0,
            "in_pipeline": 0,
            "awaiting_gate_1": 0,
            "awaiting_gate_2": 0,
            "awaiting_gate_3": 0,
            "complete": 0,
            "blocked": 0,
            "failed": 0,
        }
        tier_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "VERY_HIGH": 0, "unknown": 0}

        # Pipeline statuses (active, not gate, not terminal)
        pipeline_statuses = {
            "parsing", "classifying", "documenting", "verifying",
            "assigning_stack", "converting", "validating", "security_scanning",
            "reviewing", "testing",
        }

        for row in rows:
            status = row["status"]
            tier = row["complexity_tier"] or "unknown"

            # Map tier names
            tier_map = {"Low": "LOW", "Medium": "MEDIUM", "High": "HIGH", "Very High": "VERY_HIGH"}
            tier = tier_map.get(tier, "unknown")
            if tier in tier_counts:
                tier_counts[tier] += 1

            if status == "pending":
                status_counts["not_started"] += 1
            elif status in pipeline_statuses:
                status_counts["in_pipeline"] += 1
            elif status == JobStatus.AWAITING_REVIEW.value:
                status_counts["awaiting_gate_1"] += 1
            elif status == JobStatus.AWAITING_SEC_REVIEW.value:
                status_counts["awaiting_gate_2"] += 1
            elif status == JobStatus.AWAITING_CODE_REVIEW.value:
                status_counts["awaiting_gate_3"] += 1
            elif status == JobStatus.COMPLETE.value:
                status_counts["complete"] += 1
            elif status == JobStatus.BLOCKED.value:
                status_counts["blocked"] += 1
            elif status == JobStatus.FAILED.value:
                status_counts["failed"] += 1

        # Calculate throughput (jobs completed in last 7 days)
        seven_days_ago = (_datetime.utcnow() - __import__("datetime").timedelta(days=7)).isoformat()
        async with db._connect() as conn:
            async with conn.execute(
                "SELECT COUNT(*) FROM jobs WHERE status = ? AND updated_at >= ? AND deleted_at IS NULL",
                (JobStatus.COMPLETE.value, seven_days_ago),
            ) as cur:
                result = await cur.fetchone()
                completed_7d = result[0] if result else 0

        throughput_per_day = round(completed_7d / 7.0, 1)

        # Calculate ETA
        total = len(rows)
        not_started = status_counts["not_started"]
        in_pipeline = status_counts["in_pipeline"]
        awaiting_gate = (status_counts["awaiting_gate_1"] +
                        status_counts["awaiting_gate_2"] +
                        status_counts["awaiting_gate_3"])

        remaining = not_started + in_pipeline + awaiting_gate
        estimated_days = None
        estimated_date = None

        if throughput_per_day > 0:
            estimated_days = round(remaining / throughput_per_day, 1)
            completion_date = _datetime.utcnow() + __import__("datetime").timedelta(days=estimated_days)
            estimated_date = completion_date.date().isoformat()

        now = _datetime.utcnow().isoformat() + "Z"

        return {
            "total": total,
            "not_started": not_started,
            "in_pipeline": in_pipeline,
            "awaiting_gate": {
                "1": status_counts["awaiting_gate_1"],
                "2": status_counts["awaiting_gate_2"],
                "3": status_counts["awaiting_gate_3"],
            },
            "complete": status_counts["complete"],
            "blocked": status_counts["blocked"],
            "failed": status_counts["failed"],
            "by_tier": tier_counts,
            "throughput_per_day": throughput_per_day,
            "estimated_completion_days": estimated_days,
            "estimated_completion_date": estimated_date,
            "as_of": now,
        }

    except Exception as e:
        logger.error(f"Error fetching migration progress: {e}")
        raise HTTPException(500, f"Error fetching migration progress: {str(e)}")


@router.get("/progress/export")
async def export_progress_csv():
    """
    Return a CSV download of all job statuses for management reporting.

    Columns: job_id, filename, batch_id, status, complexity_tier, created_at, updated_at, waiting_at_gate, complete_at
    """
    try:
        async with db._connect() as conn:
            conn.row_factory = __import__("aiosqlite").Row
            async with conn.execute(
                "SELECT job_id, filename, batch_id, status, complexity_tier, "
                "       created_at, updated_at FROM jobs WHERE deleted_at IS NULL "
                "ORDER BY created_at DESC"
            ) as cur:
                rows = await cur.fetchall()

        # Build CSV
        csv_lines = ["job_id,filename,batch_id,status,complexity_tier,created_at,updated_at,waiting_at_gate,complete_at"]

        for row in rows:
            job_id = row["job_id"]
            filename = row["filename"]
            batch_id = row["batch_id"] or ""
            status = row["status"]
            tier = row["complexity_tier"] or ""
            created = row["created_at"]
            updated = row["updated_at"]

            # Determine waiting_at_gate
            waiting_gate = ""
            if status == JobStatus.AWAITING_REVIEW.value:
                waiting_gate = "1"
            elif status == JobStatus.AWAITING_SEC_REVIEW.value:
                waiting_gate = "2"
            elif status == JobStatus.AWAITING_CODE_REVIEW.value:
                waiting_gate = "3"

            # Use updated_at as proxy for complete_at
            complete_at = updated if status == JobStatus.COMPLETE.value else ""

            # Escape CSV values
            def escape_csv(val):
                if val is None:
                    return ""
                val_str = str(val)
                if "," in val_str or '"' in val_str or "\n" in val_str:
                    return '"' + val_str.replace('"', '""') + '"'
                return val_str

            line = f"{escape_csv(job_id)},{escape_csv(filename)},{escape_csv(batch_id)},{escape_csv(status)},{escape_csv(tier)},{escape_csv(created)},{escape_csv(updated)},{escape_csv(waiting_gate)},{escape_csv(complete_at)}"
            csv_lines.append(line)

        csv_content = "\n".join(csv_lines)
        now = _datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        return StreamingResponse(
            iter([csv_content]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="migration_progress_{now}.csv"'},
        )

    except Exception as e:
        logger.error(f"Error exporting progress CSV: {e}")
        raise HTTPException(500, f"Error exporting progress CSV: {str(e)}")


# ─────────────────────────────────────────────
# Test Runner  (admin only — persona: Asin D)
# ─────────────────────────────────────────────

_SUITE_FILES = {
    "landing":    "tests/playwright/landing.spec.js",
    "navigation": "tests/playwright/navigation.spec.js",
    "submission": "tests/playwright/submission.spec.js",
    "history":    "tests/playwright/history.spec.js",
    "review":     "tests/playwright/review.spec.js",
    "security":   "tests/playwright/security.spec.js",
    "auth":       "tests/playwright/z_auth.spec.js",   # z_ prefix forces alphabetical sort LAST
}

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@router.get("/run-tests")
async def run_tests(request: Request, suites: str = ""):
    """
    SSE stream that runs the selected Playwright suites and streams output
    line-by-line.  Admin-only: requires persona cookie == 'Asin D'.
    """
    from urllib.parse import unquote as _unquote
    persona = _unquote(request.cookies.get("persona", ""))
    if persona != "Asin D":
        raise HTTPException(403, "Test runner is restricted to the admin persona.")

    # Build list of spec files to pass to playwright
    selected = [s.strip() for s in suites.split(",") if s.strip() in _SUITE_FILES]
    if not selected:
        raise HTTPException(400, "No valid suites specified.")

    spec_paths = [_SUITE_FILES[s] for s in selected]
    cmd = [
        "npx", "playwright", "test",
        "--reporter=list",   # newline-terminated output — safe for SSE streaming
        "--timeout=15000",   # 15 s per test (fast-fail if server unreachable)
        "--retries=0",       # no retries in health-check mode
        "--workers=1",       # serial execution — prevents rate-limiter tests from blocking parallel logins
    ] + spec_paths

    async def _stream() -> AsyncGenerator[str, None]:
        import re as _re

        def _evt(payload: dict) -> str:
            return f"data: {json.dumps(payload)}\n\n"

        yield _evt({"type": "start", "suites": selected, "cmd": " ".join(cmd)})

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=_REPO_ROOT,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={
                    **os.environ,
                    "FORCE_COLOR": "0",
                    "CI": "1",
                    # Disable Node/npm stdout buffering
                    "NODE_NO_WARNINGS": "1",
                },
            )

            passed = failed = skipped = 0
            buf = ""
            # Read in small chunks so we don't wait for a full newline to arrive.
            # Playwright can buffer output when stdout is a pipe; chunked reads
            # unblock the stream as soon as any bytes arrive.
            READ_TIMEOUT = 30.0   # seconds to wait for ANY new output before giving up

            while True:
                try:
                    chunk = await asyncio.wait_for(
                        proc.stdout.read(2048), timeout=READ_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    # Nothing arrived for 30 s — report and kill
                    yield _evt({
                        "type": "error",
                        "text": (
                            "No output from test runner after 30 s. "
                            "Playwright may not be installed — try running: "
                            "npx playwright install chromium"
                        ),
                    })
                    proc.kill()
                    break

                if not chunk:
                    break  # EOF — process finished

                buf += chunk.decode("utf-8", errors="replace")

                # Emit complete lines as they accumulate in the buffer
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.rstrip("\r")
                    if not line:
                        continue

                    # Parse Playwright summary: "5 passed (12s)"  /  "2 failed"
                    m_pass  = _re.search(r"(\d+)\s+passed",  line)
                    m_fail  = _re.search(r"(\d+)\s+failed",  line)
                    m_skip  = _re.search(r"(\d+)\s+skipped", line)
                    if m_pass:  passed  = int(m_pass.group(1))
                    if m_fail:  failed  = int(m_fail.group(1))
                    if m_skip:  skipped = int(m_skip.group(1))

                    yield _evt({"type": "line", "text": line})

            # Flush any remaining partial line
            if buf.strip():
                yield _evt({"type": "line", "text": buf.strip()})

            await proc.wait()
            rc = proc.returncode

            yield _evt({
                "type":    "done",
                "rc":      rc,
                "passed":  passed,
                "failed":  failed,
                "skipped": skipped,
            })

        except Exception as exc:
            yield _evt({"type": "error", "text": str(exc)})

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
