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
from pydantic import BaseModel
from typing import Optional as _Opt

from ._helpers import (
    db, logger, orchestrator,
    _validate_job_id,
    _active_tasks, _progress_queues,
    JobStatus,
    s2t_excel_path,
)
from ..db.database import _decode_state

router = APIRouter(prefix="")


# ─────────────────────────────────────────────
# Job State
# ─────────────────────────────────────────────

_RUNNING_STATUSES = (
    "pending","parsing","classifying","documenting","verifying",
    "assigning_stack","converting","security_scanning","validating",
    "reviewing","testing",
)
_GATE_STATUSES = ("awaiting_review","awaiting_security_review","awaiting_code_review")
_EMPTY_STATS = {"total": 0, "running": 0, "complete": 0, "awaiting_review": 0}


def _row_to_stats(row) -> dict:
    """Convert a stats DB row to the response dict."""
    return {
        "total": row[0] or 0,
        "running": row[1] or 0,
        "complete": row[2] or 0,
        "awaiting_review": row[3] or 0,
    }


@router.get("/jobs/stats")
async def job_stats():
    """Return total job counts grouped by status bucket — used by the landing page."""
    ph_r = ",".join("?" * len(_RUNNING_STATUSES))
    ph_g = ",".join("?" * len(_GATE_STATUSES))
    async with db._connect() as conn:
        async with conn.execute(
            f"""SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status IN ({ph_r}) THEN 1 ELSE 0 END) AS running,
                SUM(CASE WHEN status = 'complete'          THEN 1 ELSE 0 END) AS complete,
                SUM(CASE WHEN status IN ({ph_g}) THEN 1 ELSE 0 END) AS awaiting_review
            FROM jobs WHERE deleted_at IS NULL""",
            (*_RUNNING_STATUSES, *_GATE_STATUSES),
        ) as cur:
            row = await cur.fetchone()
    return _row_to_stats(row) if row else _EMPTY_STATS


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


# ─────────────────────────────────────────────
# Batch-cancel blocked / failed jobs  (v2.17.3)
# ─────────────────────────────────────────────

class _BatchCancelPayload(BaseModel):
    job_ids: list[str]
    reviewer_name: str = "system"


@router.post("/jobs/batch-cancel")
async def batch_cancel_jobs(payload: _BatchCancelPayload):
    """
    Cancel a list of blocked or failed jobs.

    Sets status to 'cancelled', writes an audit entry for each job,
    and returns a summary of successes and skips.
    """
    cancellable = {JobStatus.FAILED.value, JobStatus.BLOCKED.value}
    results: list[dict] = []
    now = _datetime.utcnow().isoformat()

    for job_id in payload.job_ids:
        try:
            _validate_job_id(job_id)
            job = await db.get_job(job_id)
            if not job:
                results.append({"job_id": job_id, "status": "not_found"})
                continue
            if job["status"] not in cancellable:
                results.append({"job_id": job_id, "status": "skipped",
                                 "reason": f"status is '{job['status']}'"})
                continue
            async with db._connect() as conn:
                await conn.execute(
                    "UPDATE jobs SET status='cancelled', updated_at=? WHERE job_id=?",
                    (now, job_id),
                )
                await conn.commit()
            await db.add_audit_entry(
                job_id=job_id,
                gate="cancel",
                event_type="cancel",
                reviewer_name=payload.reviewer_name,
                reviewer_role="reviewer",
                decision="CANCELLED",
                notes=f"Job cancelled from status '{job['status']}' at {now}",
            )
            results.append({"job_id": job_id, "status": "cancelled"})
        except Exception as exc:
            results.append({"job_id": job_id, "status": "error", "reason": str(exc)})

    cancelled = sum(1 for r in results if r["status"] == "cancelled")
    logger.info("Batch cancel: %d/%d jobs cancelled by %s",
                cancelled, len(payload.job_ids), payload.reviewer_name)
    return {"cancelled": cancelled, "total": len(payload.job_ids), "results": results}


# ─────────────────────────────────────────────
# Conversion Audit Report  (v2.17.3)
# ─────────────────────────────────────────────

@router.get("/jobs/{job_id}/audit-report")
async def get_audit_report(job_id: str):
    """
    Return the Conversion Audit Report for a job as a plain-text Markdown response.

    Generates the report on-the-fly from the job record and state_json so it
    always reflects the latest pipeline state (useful before Gate 3 approval
    and for re-generation after any state updates).
    """
    import json as _json
    from fastapi.responses import PlainTextResponse
    from ..job_exporter import _render_audit_report_md

    _validate_job_id(job_id)
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")

    state: dict = _decode_state(dict(job).get("state_json") or "")

    # Attach audit entries to job dict so the renderer can include sign-off chain
    audit_rows = await db.get_audit_entries(job_id)
    job_dict = dict(job)
    job_dict["audit_entries"] = [dict(r) for r in (audit_rows or [])]

    md = _render_audit_report_md(job_dict, state)
    filename = (job_dict.get("filename") or "report").replace(" ", "_")
    return PlainTextResponse(
        content=md,
        headers={"Content-Disposition": f'attachment; filename="{filename}_AUDIT_REPORT.md"'},
    )


# ─────────────────────────────────────────────
# Cross-Job Reuse Analysis  (v2.23.0)
# ─────────────────────────────────────────────

class _ReuseAnalysisRequest(BaseModel):
    job_ids:    list[str]
    reviewer_name: _Opt[str] = None


@router.post("/jobs/reuse-analysis")
async def cross_job_reuse_analysis(payload: _ReuseAnalysisRequest):
    """
    Portfolio-level framework reuse analysis across a set of completed jobs.

    Collects per-job Stage D reuse candidates (already computed by Step 10)
    and asks Claude to synthesise cross-job patterns — logic that appears in
    multiple mappings and is therefore the highest-value shared utility target.

    Returns a structured report: per-pattern frequency, recommended extraction
    order, and a plain-English implementation roadmap.
    """
    import json as _json
    from ..agents._client import make_client, call_claude_with_retry
    from ..config import settings as _cfg

    if not payload.job_ids:
        raise HTTPException(400, "At least one job_id is required")
    if len(payload.job_ids) > 50:
        raise HTTPException(400, "Maximum 50 job IDs per call")

    # Collect per-job reuse candidates from state_json
    per_job: list[dict] = []
    for jid in payload.job_ids:
        try:
            _validate_job_id(jid)
        except Exception:
            continue
        job = await db.get_job(jid)
        if not job:
            continue
        state = _decode_state(dict(job).get("state_json") or "")
        cr = state.get("code_review") or {}
        reuse = cr.get("reuse_analysis") or {}
        candidates = reuse.get("candidates") or []
        if candidates:
            per_job.append({
                "job_id":       jid,
                "filename":     dict(job).get("filename", "—"),
                "target_stack": dict(job).get("target_stack") or cr.get("target_stack") or "—",
                "candidates":   candidates,
            })

    if not per_job:
        return {
            "jobs_analysed": 0,
            "message": "No completed jobs with reuse analysis found in the provided list.",
            "cross_job_patterns": [],
            "roadmap": [],
            "summary": "",
        }

    # Build prompt for Claude
    jobs_block = _json.dumps(per_job, indent=2)[:12_000]

    CROSS_JOB_SYSTEM = (
        "You are a senior data engineering architect. "
        "You receive per-mapping reuse candidates from an automated ETL migration tool "
        "and must synthesise which patterns are worth centralising into a shared framework library. "
        "Focus on patterns that appear in multiple mappings — those are the highest ROI extractions."
    )

    CROSS_JOB_PROMPT = f"""Below is a JSON array of completed ETL conversion jobs, each with a list
of per-mapping framework reuse candidates identified by the automated review.

## Per-Job Reuse Candidates
{jobs_block}

---

Synthesise the data above into a portfolio-level reuse analysis:

1. **Cross-job patterns**: Group candidates by pattern_type and suggested_name (or semantic similarity).
   For each group, count how many jobs contain it and rate the extraction priority.

2. **Recommended roadmap**: Rank the top patterns by (frequency × inverse effort) — most frequent
   + lowest effort = highest priority. Produce a numbered action list.

3. **Quick wins**: Patterns appearing in 2+ jobs with effort=LOW — list by suggested_name.

Return ONLY this JSON (no markdown):
{{
  "cross_job_patterns": [
    {{
      "pattern_type": "e.g. scd2_merge",
      "suggested_name": "e.g. merge_scd2_dimension()",
      "frequency": 3,
      "jobs": ["job_id_1", "job_id_2", "job_id_3"],
      "consolidated_rationale": "Why this matters across the portfolio (1-2 sentences)",
      "effort": "LOW|MEDIUM|HIGH",
      "priority": 1
    }}
  ],
  "roadmap": [
    {{
      "step": 1,
      "action": "Create shared utility function merge_scd2_dimension() in etl_utils.py",
      "pattern_type": "scd2_merge",
      "estimated_effort": "LOW",
      "impacted_jobs": 3
    }}
  ],
  "quick_wins": ["merge_scd2_dimension()", "coalesce_nulls()"],
  "summary": "2-3 sentence plain-English assessment of the portfolio reuse posture."
}}"""

    client = make_client()
    msg = await call_claude_with_retry(
        client,
        model=_cfg.claude_model,
        max_tokens=3000,
        system=CROSS_JOB_SYSTEM,
        messages=[{"role": "user", "content": CROSS_JOB_PROMPT}],
    )

    import re as _re
    raw_text = msg.content[0].text
    json_match = _re.search(r"\{[\s\S]*\}", raw_text)
    try:
        result = _json.loads(json_match.group(0)) if json_match else {}
    except Exception:
        result = {}

    return {
        "jobs_analysed":        len(per_job),
        "jobs_with_candidates": len(per_job),
        "cross_job_patterns":   result.get("cross_job_patterns", []),
        "roadmap":              result.get("roadmap", []),
        "quick_wins":           result.get("quick_wins", []),
        "summary":              result.get("summary", ""),
        "reviewer":             payload.reviewer_name,
    }
