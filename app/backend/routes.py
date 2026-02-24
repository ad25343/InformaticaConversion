"""
FastAPI routes — REST API for the Informatica Conversion Tool.
"""
from __future__ import annotations
import asyncio
import json
import logging
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, File, UploadFile, HTTPException, BackgroundTasks, Form, Request
from fastapi.responses import StreamingResponse, JSONResponse, PlainTextResponse
from typing import Optional as _Opt

from .db import database as db
from .limiter import jobs_limiter
from .models.schemas import (
    SignOffRecord, SignOffRequest, ReviewDecision, JobStatus,
    CodeSignOffRequest, CodeSignOffRecord, CodeReviewDecision,
    SecuritySignOffRecord, SecuritySignOffRequest, SecurityReviewDecision,
)
from . import orchestrator
from .logger import read_job_log, read_job_log_raw, job_log_path, list_log_registry
from .agents.s2t_agent import s2t_excel_path
from .security import validate_upload_size, ZipExtractionError
from .zip_extractor import extract_informatica_zip

router = APIRouter(prefix="/api")
logger = logging.getLogger("conversion.routes")

# ── Active pipeline tasks (in-memory for MVP) ─────
_active_tasks: dict[str, asyncio.Task] = {}
_progress_queues: dict[str, asyncio.Queue] = {}


# ─────────────────────────────────────────────
# Upload + Start
# ─────────────────────────────────────────────

@router.post("/jobs")
async def create_job(
    file:           UploadFile = File(...),
    workflow_file:  _Opt[UploadFile] = File(default=None),
    parameter_file: _Opt[UploadFile] = File(default=None),
    _rl:            None = Depends(jobs_limiter),
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

    mapping_content = await file.read()
    validate_upload_size(mapping_content, label=file.filename)
    xml_str = mapping_content.decode("utf-8", errors="replace")

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

    job_id = await db.create_job(
        file.filename,
        xml_str,
        workflow_xml_content=workflow_str,
        parameter_file_content=param_str,
    )

    logger.info("Job created: job_id=%s filename=%s size=%d bytes has_workflow=%s has_params=%s",
                job_id, file.filename, len(mapping_content),
                workflow_str is not None, param_str is not None)

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

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─────────────────────────────────────────────
# Job State
# ─────────────────────────────────────────────

@router.get("/jobs")
async def list_jobs():
    jobs = await db.list_jobs()
    return {"jobs": jobs}


@router.delete("/jobs/{job_id}")
async def delete_job(job_id: str):
    """Delete a job and clean up its associated log and S2T files."""
    from .logger import job_log_path
    from .agents.s2t_agent import s2t_excel_path

    deleted = await db.delete_job(job_id)
    if not deleted:
        raise HTTPException(404, "Job not found")

    # Best-effort cleanup of associated files
    cleaned = []
    log_path = job_log_path(job_id)
    if log_path and log_path.exists():
        try:
            log_path.unlink()
            cleaned.append("log")
        except OSError:
            pass

    s2t_path = s2t_excel_path(job_id)
    if s2t_path and s2t_path.exists():
        try:
            s2t_path.unlink()
            cleaned.append("s2t")
        except OSError:
            pass

    return {"deleted": True, "job_id": job_id, "cleaned": cleaned}


@router.get("/jobs/{job_id}")
async def get_job(job_id: str):
    job = await db.get_job(job_id)
    if not job:
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


# ─────────────────────────────────────────────
# Human Sign-off (Step 5 gate)
# ─────────────────────────────────────────────

@router.post("/jobs/{job_id}/sign-off")
async def submit_signoff(job_id: str, payload: SignOffRequest):
    """Submit human review decision. If APPROVED, resumes pipeline."""
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] != JobStatus.AWAITING_REVIEW.value:
        raise HTTPException(400, f"Job is not awaiting review (status: {job['status']})")

    sign_off = SignOffRecord(
        reviewer_name=payload.reviewer_name,
        reviewer_role=payload.reviewer_role,
        review_date=__import__("datetime").datetime.utcnow().isoformat(),
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

    if payload.decision == ReviewDecision.REJECTED:
        await db.update_job(job_id, JobStatus.BLOCKED.value, 5, {})
        logger.info("Job rejected: job_id=%s", job_id)
        return {"message": "Job rejected. Pipeline will not proceed."}

    # APPROVED — resume pipeline in background
    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues[job_id] = queue

    state    = job["state"]
    filename = job["filename"]

    async def _resume():
        async for progress in orchestrator.resume_after_signoff(job_id, state, filename):
            await queue.put(progress)
        await queue.put(None)

    task = asyncio.create_task(_resume())
    _active_tasks[job_id] = task
    logger.info("Pipeline resuming after approval: job_id=%s", job_id)

    return {"message": "Sign-off accepted. Pipeline resuming from Step 6.", "job_id": job_id}


# ─────────────────────────────────────────────
# Security Review Sign-off (Step 9 gate)
# ─────────────────────────────────────────────

@router.post("/jobs/{job_id}/security-review")
async def submit_security_review(job_id: str, payload: SecuritySignOffRequest):
    """
    Submit human security review decision (Gate 2 — Step 9).
    APPROVED / ACKNOWLEDGED  → resume pipeline from Step 10.
    FAILED                   → block the job permanently.
    """
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] != JobStatus.AWAITING_SEC_REVIEW.value:
        raise HTTPException(400, f"Job is not awaiting security review (status: {job['status']})")

    sec_signoff = SecuritySignOffRecord(
        reviewer_name=payload.reviewer_name,
        reviewer_role=payload.reviewer_role,
        review_date=__import__("datetime").datetime.utcnow().isoformat(),
        decision=payload.decision,
        notes=payload.notes,
    )

    logger.info("Security review received: job_id=%s decision=%s reviewer=%s",
                job_id, payload.decision, payload.reviewer_name)

    await db.update_job(job_id, JobStatus.AWAITING_SEC_REVIEW.value, 9,
                        {"security_sign_off": sec_signoff.model_dump()})

    if payload.decision == SecurityReviewDecision.FAILED:
        await db.update_job(job_id, JobStatus.BLOCKED.value, 9, {})
        logger.info("Security review failed — job blocked: job_id=%s", job_id)
        return {
            "message": "Security review failed. Job is blocked — pipeline will not proceed.",
            "job_id": job_id,
            "decision": payload.decision,
        }

    # APPROVED or ACKNOWLEDGED — resume pipeline from Step 10
    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues[job_id] = queue

    state    = job["state"]
    state["security_sign_off"] = sec_signoff.model_dump()
    filename = job["filename"]

    async def _resume():
        async for progress in orchestrator.resume_after_security_review(job_id, state, filename):
            await queue.put(progress)
        await queue.put(None)

    task = asyncio.create_task(_resume())
    _active_tasks[job_id] = task
    logger.info("Pipeline resuming after security review: job_id=%s decision=%s",
                job_id, payload.decision)

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
        raise HTTPException(404, "Job not found")
    if job["status"] != JobStatus.AWAITING_CODE_REVIEW.value:
        raise HTTPException(400, f"Job is not awaiting code review (status: {job['status']})")

    code_signoff = CodeSignOffRecord(
        reviewer_name=payload.reviewer_name,
        reviewer_role=payload.reviewer_role,
        review_date=__import__("datetime").datetime.utcnow().isoformat(),
        decision=payload.decision,
        notes=payload.notes,
    )

    logger.info("Code sign-off received: job_id=%s decision=%s reviewer=%s",
                job_id, payload.decision, payload.reviewer_name)

    await db.update_job(job_id, JobStatus.AWAITING_CODE_REVIEW.value, 12,
                        {"code_sign_off": code_signoff.model_dump()})

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

    async def _resume():
        async for progress in orchestrator.resume_after_code_signoff(job_id, state, filename):
            await queue.put(progress)
        await queue.put(None)

    task = asyncio.create_task(_resume())
    _active_tasks[job_id] = task
    logger.info("Pipeline resuming after code sign-off: job_id=%s decision=%s",
                job_id, payload.decision)

    return {
        "message": f"Code sign-off recorded ({payload.decision}). Pipeline resuming.",
        "job_id": job_id,
        "decision": payload.decision,
    }


# ─────────────────────────────────────────────
# Download converted code
# ─────────────────────────────────────────────

@router.get("/jobs/{job_id}/s2t/download")
async def download_s2t_excel(job_id: str):
    """Download the Source-to-Target mapping Excel workbook for a job."""
    job = await db.get_job(job_id)
    if not job:
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


@router.get("/jobs/{job_id}/download/{filename}")
async def download_file(job_id: str, filename: str):
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    conversion = job["state"].get("conversion", {})
    files = conversion.get("files", {})
    if filename not in files:
        raise HTTPException(404, f"File '{filename}' not found in conversion output")
    return JSONResponse({"filename": filename, "content": files[filename]})


@router.get("/jobs/{job_id}/tests/download/{filename:path}")
async def download_test_file(job_id: str, filename: str):
    """Download a generated test file by path (e.g. tests/test_conversion.py)."""
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    test_report = job["state"].get("test_report", {})
    files = test_report.get("test_files", {})
    if filename not in files:
        raise HTTPException(404, f"Test file '{filename}' not found")
    return JSONResponse({"filename": filename, "content": files[filename]})


# ─────────────────────────────────────────────
# ZIP Upload (v1.1+)
# ─────────────────────────────────────────────

@router.post("/jobs/zip")
async def create_job_from_zip(
    file: UploadFile = File(...),
    _rl:  None = Depends(jobs_limiter),
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
