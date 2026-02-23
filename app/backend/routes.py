"""
FastAPI routes — REST API for the Informatica Conversion Tool.
"""
from __future__ import annotations
import asyncio
import json
import logging
from typing import AsyncGenerator

from fastapi import APIRouter, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse, JSONResponse, PlainTextResponse

from .db import database as db
from .models.schemas import (
    SignOffRecord, SignOffRequest, ReviewDecision, JobStatus,
    CodeSignOffRequest, CodeSignOffRecord, CodeReviewDecision,
)
from . import orchestrator
from .logger import read_job_log, read_job_log_raw, job_log_path, list_log_registry
from .agents.s2t_agent import s2t_excel_path

router = APIRouter(prefix="/api")
logger = logging.getLogger("conversion.routes")

# ── Active pipeline tasks (in-memory for MVP) ─────
_active_tasks: dict[str, asyncio.Task] = {}
_progress_queues: dict[str, asyncio.Queue] = {}


# ─────────────────────────────────────────────
# Upload + Start
# ─────────────────────────────────────────────

@router.post("/jobs")
async def create_job(file: UploadFile = File(...)):
    """Upload an Informatica XML file and start the pipeline."""
    if not file.filename.endswith(".xml"):
        raise HTTPException(400, "File must be a .xml Informatica export")

    content = await file.read()
    xml_str = content.decode("utf-8", errors="replace")
    job_id = await db.create_job(file.filename, xml_str)

    logger.info("Job created: job_id=%s filename=%s size=%d bytes",
                job_id, file.filename, len(content))

    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues[job_id] = queue

    async def _run():
        async for progress in orchestrator.run_pipeline(job_id, file.filename):
            await queue.put(progress)
        await queue.put(None)  # sentinel

    task = asyncio.create_task(_run())
    _active_tasks[job_id] = task

    return {"job_id": job_id, "filename": file.filename, "status": "started"}


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
# Code Review Sign-off (Step 10 gate)
# ─────────────────────────────────────────────

@router.post("/jobs/{job_id}/code-signoff")
async def submit_code_signoff(job_id: str, payload: CodeSignOffRequest):
    """Submit code review decision (APPROVED | REGENERATE). If APPROVED, marks job complete."""
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] != JobStatus.AWAITING_CODE_REVIEW.value:
        raise HTTPException(400, f"Job is not awaiting code review (status: {job['status']})")

    # Decision validation is handled by Pydantic (CodeReviewDecision enum)

    code_signoff = CodeSignOffRecord(
        reviewer_name=payload.reviewer_name,
        reviewer_role=payload.reviewer_role,
        review_date=__import__("datetime").datetime.utcnow().isoformat(),
        decision=payload.decision,
        notes=payload.notes,
    )

    logger.info("Code sign-off received: job_id=%s decision=%s reviewer=%s",
                job_id, payload.decision, payload.reviewer_name)

    await db.update_job(job_id, JobStatus.AWAITING_CODE_REVIEW.value, 10,
                        {"code_sign_off": code_signoff.model_dump()})

    # Hard reject — block the job immediately, no pipeline resume needed
    if payload.decision == CodeReviewDecision.REJECTED:
        await db.update_job(job_id, JobStatus.BLOCKED.value, 10, {})
        logger.info("Code review hard-rejected: job_id=%s reviewer=%s",
                    job_id, payload.reviewer_name)
        return {
            "message": (
                "Code review rejected. Job is blocked — pipeline will not proceed. "
                "Upload the mapping again to start a fresh conversion."
            ),
            "job_id":   job_id,
            "decision": payload.decision,
        }

    # Resume pipeline to write final status
    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues[job_id] = queue

    state    = job["state"]
    # Merge the new sign-off into state before passing
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
