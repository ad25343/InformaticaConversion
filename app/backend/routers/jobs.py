# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Jobs sub-router: job listing, retrieval, deletion, audit, and retry.
"""
from __future__ import annotations
import asyncio
from datetime import datetime as _datetime

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from typing import Optional as _Opt

from ._helpers import (
    db, logger, orchestrator,
    _validate_job_id,
    _active_tasks, _progress_queues,
    JobStatus,
    s2t_excel_path,
)

router = APIRouter(prefix="")


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


@router.delete("/jobs/{job_id}")
async def delete_job(job_id: str):
    """Soft-delete a job (sets deleted_at; preserves DB record and log file)."""
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
