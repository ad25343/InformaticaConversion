# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Gates sub-router: human review sign-off endpoints and gate queue inspection.
"""
from __future__ import annotations
import asyncio
from datetime import datetime as _datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel as _PydanticBaseModel
from typing import Optional as _Opt

from ._helpers import (
    db, logger, orchestrator, record_findings,
    _validate_job_id,
    _active_tasks, _progress_queues, _batch_job_ids,
    _resume_batch_job,
    _get_gate_from_status, _extract_flags_for_gate,
    _make_pipeline_task, _make_simple_pipeline_task,
    _setup_queue,
    _try_record_security_findings,
    _validate_gate_payload, _expected_status_for_gate,
    JobStatus,
    SignOffRecord, SignOffRequest, ReviewDecision,
    CodeSignOffRequest, CodeSignOffRecord, CodeReviewDecision,
    SecuritySignOffRecord, SecuritySignOffRequest, SecurityReviewDecision,
)
from ..models.schemas import VALID_RESTART_STEPS_GATE1, VALID_RESTART_STEPS_GATE3

router = APIRouter(prefix="")


# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

def _build_sign_off(payload: SignOffRequest) -> SignOffRecord:
    """Build a Gate 1 SignOffRecord from a sign-off payload."""
    return SignOffRecord(
        reviewer_name=payload.reviewer_name,
        reviewer_role=payload.reviewer_role,
        review_date=_datetime.utcnow().isoformat(),
        blocking_resolved=[],
        flags_accepted=[r for r in payload.flag_resolutions if r.action == "accepted"],
        flags_resolved=[r for r in payload.flag_resolutions if r.action == "resolved"],
        decision=payload.decision,
        notes=payload.notes,
    )


async def _launch_resume(job_id: str, resume_gen, *, use_batch: bool) -> None:
    """Set up queue + task for a resume generator, honouring batch semaphore."""
    queue = _setup_queue(job_id)
    if use_batch:
        task = asyncio.create_task(_resume_batch_job(job_id, resume_gen))
    else:
        task = await _make_pipeline_task(job_id, resume_gen, queue)
    _active_tasks[job_id] = task


async def _launch_checkpoint_restart(
    job_id: str, filename: str, restart_step: int, state: dict
) -> None:
    """Set up queue + task for a checkpoint restart."""
    queue = _setup_queue(job_id)
    restart_gen = orchestrator.resume_from_step(job_id, filename, restart_step, state)
    task = await _make_pipeline_task(job_id, restart_gen, queue)
    _active_tasks[job_id] = task


# ─────────────────────────────────────────────
# Human Sign-off (Step 5 gate)
# ─────────────────────────────────────────────

async def _handle_signoff_rejection(job_id: str, payload: SignOffRequest, job: dict) -> dict:
    """Handle REJECTED decision for Gate 1; return response dict."""
    restart_step = payload.restart_from_step
    if restart_step and restart_step in VALID_RESTART_STEPS_GATE1:
        await db.update_job(job_id, JobStatus.PENDING.value, 5, {"error": None})
        await db.add_audit_entry(
            job_id=job_id, gate="gate1", event_type="reject_restart",
            reviewer_name=payload.reviewer_name, reviewer_role=payload.reviewer_role,
            decision=payload.decision, notes=payload.notes,
            extra={"restart_from_step": restart_step},
        )
        state = job["state"]
        await _launch_checkpoint_restart(job_id, job["filename"], restart_step, state)
        logger.info("Pipeline checkpoint-restarting from step %s: job_id=%s", restart_step, job_id)
        return {
            "message": f"Job rejected with checkpoint restart from Step {restart_step}.",
            "job_id": job_id,
            "restart_from_step": restart_step,
        }
    await db.update_job(job_id, JobStatus.BLOCKED.value, 5, {})
    logger.info("Job rejected: job_id=%s", job_id)
    return {"message": "Job rejected. Pipeline will not proceed."}


@router.post("/jobs/{job_id}/sign-off")
async def submit_signoff(job_id: str, payload: SignOffRequest):
    """Submit human review decision. If APPROVED, resumes pipeline."""
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")
    if job["status"] != JobStatus.AWAITING_REVIEW.value:
        raise HTTPException(400, f"Job is not awaiting review (status: {job['status']})")

    sign_off = _build_sign_off(payload)

    logger.info("Sign-off received: job_id=%s decision=%s reviewer=%s",
                job_id, payload.decision, payload.reviewer_name)

    await db.update_job(job_id, JobStatus.AWAITING_REVIEW.value, 5,
                        {"sign_off": sign_off.model_dump()})
    await db.add_audit_entry(
        job_id=job_id, gate="gate1", event_type=payload.decision.lower(),
        reviewer_name=payload.reviewer_name, reviewer_role=payload.reviewer_role,
        decision=payload.decision, notes=payload.notes,
    )

    if payload.decision == ReviewDecision.REJECTED:
        return await _handle_signoff_rejection(job_id, payload, job)

    # APPROVED — resume pipeline in background
    resume_gen = orchestrator.resume_after_signoff(job_id, job["state"], job["filename"])
    await _launch_resume(job_id, resume_gen, use_batch=job_id in _batch_job_ids)
    logger.info("Pipeline resuming after approval: job_id=%s batch=%s",
                job_id, job_id in _batch_job_ids)
    return {"message": "Sign-off accepted. Pipeline resuming from Step 6.", "job_id": job_id}


# ─────────────────────────────────────────────
# Security Review Sign-off (Step 9 gate)
# ─────────────────────────────────────────────

async def _handle_sec_request_fix(
    job_id: str, payload: SecuritySignOffRequest,
    sec_signoff: SecuritySignOffRecord, state: dict, filename: str, this_round: int,
) -> dict:
    """Handle REQUEST_FIX decision for Gate 2."""
    state["security_sign_off"] = sec_signoff.model_dump()
    state["remediation_round"] = this_round
    fix_gen = orchestrator.resume_after_security_fix_request(
        job_id, state, filename, remediation_round=this_round
    )
    queue = _setup_queue(job_id)
    if job_id in _batch_job_ids:
        task = asyncio.create_task(_resume_batch_job(job_id, fix_gen))
    else:
        task = _make_simple_pipeline_task(job_id, fix_gen, queue)
    _active_tasks[job_id] = task
    logger.info("Pipeline re-running Steps 7-8 for security fix: job_id=%s round=%d",
                job_id, this_round)
    return {
        "message": f"Security fix requested (round {this_round}). Regenerating code and re-scanning.",
        "job_id": job_id,
        "decision": payload.decision,
        "remediation_round": this_round,
    }


def _build_sec_signoff(
    payload: SecuritySignOffRequest, prev_round: int
) -> tuple["SecuritySignOffRecord", int]:
    """Build a Gate 2 SecuritySignOffRecord and compute the current remediation round."""
    this_round = prev_round + 1 if payload.decision == SecurityReviewDecision.REQUEST_FIX else prev_round
    record = SecuritySignOffRecord(
        reviewer_name=payload.reviewer_name,
        reviewer_role=payload.reviewer_role,
        review_date=_datetime.utcnow().isoformat() + "Z",
        decision=payload.decision,
        notes=payload.notes,
        remediation_round=prev_round,
    )
    return record, this_round


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

    state = job["state"]
    filename = job["filename"]
    prev_round = state.get("remediation_round", 0)
    sec_signoff, this_round = _build_sec_signoff(payload, prev_round)

    logger.info("Security review received: job_id=%s decision=%s reviewer=%s round=%d",
                job_id, payload.decision, payload.reviewer_name, prev_round)

    await db.update_job(job_id, JobStatus.AWAITING_SEC_REVIEW.value, 9,
                        {"security_sign_off": sec_signoff.model_dump()})
    await db.add_audit_entry(
        job_id=job_id, gate="gate2", event_type=payload.decision.lower(),
        reviewer_name=payload.reviewer_name, reviewer_role=payload.reviewer_role,
        decision=payload.decision, notes=payload.notes,
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
        return await _handle_sec_request_fix(
            job_id, payload, sec_signoff, state, filename, this_round
        )

    # APPROVED or ACKNOWLEDGED
    state["security_sign_off"] = sec_signoff.model_dump()
    _try_record_security_findings(job_id, state)
    sec_resume_gen = orchestrator.resume_after_security_review(job_id, state, filename)
    await _launch_resume(job_id, sec_resume_gen, use_batch=job_id in _batch_job_ids)
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

async def _handle_code_rejection(
    job_id: str, payload: CodeSignOffRequest,
    code_signoff: CodeSignOffRecord, job: dict,
) -> dict:
    """Handle REJECTED decision for Gate 3."""
    restart_step = payload.restart_from_step
    if restart_step and restart_step in VALID_RESTART_STEPS_GATE3:
        await db.update_job(job_id, JobStatus.PENDING.value, 12, {"error": None})
        await db.add_audit_entry(
            job_id=job_id, gate="gate3", event_type="reject_restart",
            reviewer_name=payload.reviewer_name, reviewer_role=payload.reviewer_role,
            decision=payload.decision, notes=payload.notes,
            extra={"restart_from_step": restart_step},
        )
        state = job["state"]
        state["code_sign_off"] = code_signoff.model_dump()
        await _launch_checkpoint_restart(job_id, job["filename"], restart_step, state)
        logger.info("Pipeline checkpoint-restarting from step %s after Gate 3 reject: job_id=%s",
                    restart_step, job_id)
        return {
            "message": f"Code review rejected with checkpoint restart from Step {restart_step}.",
            "job_id": job_id,
            "decision": payload.decision,
            "restart_from_step": restart_step,
        }
    await db.update_job(job_id, JobStatus.BLOCKED.value, 12, {})
    logger.info("Code review rejected: job_id=%s reviewer=%s", job_id, payload.reviewer_name)
    return {
        "message": (
            "Code review rejected. Job is blocked — upload the mapping again "
            "to start a fresh conversion."
        ),
        "job_id": job_id,
        "decision": payload.decision,
    }


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
    await db.add_audit_entry(
        job_id=job_id, gate="gate3", event_type=payload.decision.lower(),
        reviewer_name=payload.reviewer_name, reviewer_role=payload.reviewer_role,
        decision=payload.decision, notes=payload.notes,
    )

    if payload.decision == CodeReviewDecision.REJECTED:
        return await _handle_code_rejection(job_id, payload, code_signoff, job)

    # APPROVED — resume to write COMPLETE status
    state = job["state"]
    state["code_sign_off"] = code_signoff.model_dump()
    code_resume_gen = orchestrator.resume_after_code_signoff(job_id, state, job["filename"])
    await _launch_resume(job_id, code_resume_gen, use_batch=job_id in _batch_job_ids)
    logger.info("Pipeline resuming after code sign-off: job_id=%s decision=%s batch=%s",
                job_id, payload.decision, job_id in _batch_job_ids)
    return {
        "message": f"Code sign-off recorded ({payload.decision}). Pipeline resuming.",
        "job_id": job_id,
        "decision": payload.decision,
    }


# ─────────────────────────────────────────────
# Gate Review Queue (v2.17.1)
# ─────────────────────────────────────────────

_ACTIONABLE_STATUSES = (
    JobStatus.AWAITING_REVIEW.value,
    JobStatus.AWAITING_SEC_REVIEW.value,
    JobStatus.AWAITING_CODE_REVIEW.value,
    JobStatus.BLOCKED.value,
    JobStatus.FAILED.value,
)


def _build_gate_where(gate: _Opt[int], batch_id: _Opt[str]) -> tuple[str, list]:
    """Build SQL WHERE clause and params for pending gate query."""
    placeholders = ",".join("?" * len(_ACTIONABLE_STATUSES))
    where_clauses = [
        "deleted_at IS NULL",
        f"status IN ({placeholders})",
    ]
    params: list = list(_ACTIONABLE_STATUSES)
    if gate:
        status_map = {
            1: JobStatus.AWAITING_REVIEW.value,
            2: JobStatus.AWAITING_SEC_REVIEW.value,
            3: JobStatus.AWAITING_CODE_REVIEW.value,
        }
        if gate not in status_map:
            raise HTTPException(400, "Gate must be 1, 2, or 3")
        where_clauses.append("status = ?")
        params.append(status_map[gate])
    if batch_id:
        where_clauses.append("batch_id = ?")
        params.append(batch_id)
    return " AND ".join(where_clauses), params


def _build_job_row(job_dict: dict, state: dict, gate_num: _Opt[int]) -> dict:
    """Build the response dict for a single pending-gate job row."""
    complexity = state.get("complexity", {})
    created_dt = _datetime.fromisoformat(job_dict["updated_at"].replace("Z", "+00:00"))
    waiting_seconds = (_datetime.utcnow() - created_dt.replace(tzinfo=None)).total_seconds()
    flag_data = _extract_flags_for_gate(state, gate_num) if gate_num else {}
    status = job_dict["status"]
    tier = (complexity.get("tier") or job_dict.get("complexity_tier") or "unknown")
    raw_error = state.get("error") or state.get("error_message") or state.get("pipeline_error") or ""
    error_summary = (str(raw_error)[:120] + "…") if len(str(raw_error)) > 120 else str(raw_error)
    return {
        "job_id": job_dict["job_id"],
        "filename": job_dict["filename"],
        "batch_id": job_dict["batch_id"],
        "submitter_name": job_dict.get("submitter_name") or "–",
        "status": status,
        "gate": gate_num,
        "retryable": status in (JobStatus.BLOCKED.value, JobStatus.FAILED.value),
        "failed_step": job_dict.get("current_step"),
        "error_summary": error_summary,
        "complexity_tier": tier,
        "suggested_pattern": complexity.get("suggested_pattern", ""),
        "pattern_confidence": complexity.get("pattern_confidence", ""),
        "waiting_since": job_dict["updated_at"],
        "waiting_minutes": int(waiting_seconds / 60),
        **flag_data,
    }


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
        where_sql, params = _build_gate_where(gate, batch_id)
        async with db._connect() as conn:
            conn.row_factory = __import__("aiosqlite").Row
            async with conn.execute(
                f"SELECT job_id, filename, batch_id, submitter_name, status, current_step, "
                f"       complexity_tier, created_at, updated_at, state_json FROM jobs "
                f"WHERE {where_sql} ORDER BY updated_at ASC",
                params,
            ) as cur:
                rows = await cur.fetchall()

        jobs = []
        by_gate = {1: 0, 2: 0, 3: 0, "blocked": 0, "failed": 0}
        for row in rows:
            job_dict = dict(row)
            status = job_dict["status"]
            gate_num = _get_gate_from_status(status)
            state = db._decode_state(job_dict["state_json"])
            if gate_num is not None:
                by_gate[gate_num] += 1
            elif status == JobStatus.BLOCKED.value:
                by_gate["blocked"] += 1
            elif status == JobStatus.FAILED.value:
                by_gate["failed"] += 1
            jobs.append(_build_job_row(job_dict, state, gate_num))

        return {"total": len(jobs), "by_gate": by_gate, "jobs": jobs}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching pending gate jobs: {e}")
        raise HTTPException(500, f"Error fetching pending gate jobs: {str(e)}")


# ─────────────────────────────────────────────
# Batch Sign-off
# ─────────────────────────────────────────────

class BatchSignOffRequest(_PydanticBaseModel):
    """Request body for batch gate sign-off."""
    job_ids: list[str]
    gate: int
    decision: str
    reviewer_name: str
    reviewer_role: str
    notes: _Opt[str] = None


async def _apply_gate1(job_id: str, job: dict, payload: BatchSignOffRequest) -> None:
    """Apply Gate 1 decision (APPROVE/REJECT) to a single job."""
    review_decision = ReviewDecision.APPROVED if payload.decision == "APPROVE" else ReviewDecision.REJECTED
    sign_off = SignOffRecord(
        reviewer_name=payload.reviewer_name,
        reviewer_role=payload.reviewer_role,
        review_date=_datetime.utcnow().isoformat(),
        blocking_resolved=[], flags_accepted=[], flags_resolved=[],
        decision=review_decision, notes=payload.notes,
    )
    await db.update_job(job_id, JobStatus.AWAITING_REVIEW.value, 5,
                        {"sign_off": sign_off.model_dump()})
    await db.add_audit_entry(
        job_id=job_id, gate="gate1", event_type=payload.decision.lower(),
        reviewer_name=payload.reviewer_name, reviewer_role=payload.reviewer_role,
        decision=payload.decision, notes=payload.notes,
    )
    if payload.decision == "REJECT":
        await db.update_job(job_id, JobStatus.BLOCKED.value, 5, {})
        return
    queue = _setup_queue(job_id)
    resume_gen = orchestrator.resume_after_signoff(job_id, job["state"], job["filename"])
    _active_tasks[job_id] = _make_simple_pipeline_task(job_id, resume_gen, queue)


async def _apply_gate2(job_id: str, job: dict, payload: BatchSignOffRequest) -> None:
    """Apply Gate 2 decision (APPROVED/ACKNOWLEDGED/FAILED) to a single job."""
    sec_decision_map = {
        "APPROVED": SecurityReviewDecision.APPROVED,
        "ACKNOWLEDGED": SecurityReviewDecision.ACKNOWLEDGED,
        "FAILED": SecurityReviewDecision.FAILED,
    }
    state = job["state"]
    prev_round = state.get("remediation_round", 0)
    sec_signoff = SecuritySignOffRecord(
        reviewer_name=payload.reviewer_name,
        reviewer_role=payload.reviewer_role,
        review_date=_datetime.utcnow().isoformat() + "Z",
        decision=sec_decision_map[payload.decision],
        notes=payload.notes,
        remediation_round=prev_round,
    )
    await db.update_job(job_id, JobStatus.AWAITING_SEC_REVIEW.value, 9,
                        {"security_sign_off": sec_signoff.model_dump()})
    await db.add_audit_entry(
        job_id=job_id, gate="gate2", event_type=payload.decision.lower(),
        reviewer_name=payload.reviewer_name, reviewer_role=payload.reviewer_role,
        decision=payload.decision, notes=payload.notes,
        extra={"remediation_round": prev_round},
    )
    if payload.decision == "FAILED":
        await db.update_job(job_id, JobStatus.BLOCKED.value, 9, {})
        return
    queue = _setup_queue(job_id)
    resume_gen = orchestrator.resume_after_security_review(job_id, state, job["filename"])
    _active_tasks[job_id] = _make_simple_pipeline_task(job_id, resume_gen, queue)


async def _apply_gate3(job_id: str, payload: BatchSignOffRequest) -> None:
    """Apply Gate 3 decision (APPROVED/REJECTED) to a single job."""
    code_decision = CodeReviewDecision.APPROVED if payload.decision == "APPROVED" else CodeReviewDecision.REJECTED
    code_signoff = CodeSignOffRecord(
        reviewer_name=payload.reviewer_name,
        reviewer_role=payload.reviewer_role,
        review_date=_datetime.utcnow().isoformat(),
        decision=code_decision, notes=payload.notes,
    )
    await db.update_job(job_id, JobStatus.AWAITING_CODE_REVIEW.value, 12,
                        {"code_sign_off": code_signoff.model_dump()})
    await db.add_audit_entry(
        job_id=job_id, gate="gate3", event_type=payload.decision.lower(),
        reviewer_name=payload.reviewer_name, reviewer_role=payload.reviewer_role,
        decision=payload.decision, notes=payload.notes,
    )
    if payload.decision == "APPROVED":
        await db.update_job(job_id, JobStatus.COMPLETE.value, 13, {})
    else:
        await db.update_job(job_id, JobStatus.BLOCKED.value, 12, {})


async def _apply_gate_decision(job_id: str, job: dict, payload: BatchSignOffRequest) -> None:
    """Dispatch to the correct gate handler."""
    if payload.gate == 1:
        await _apply_gate1(job_id, job, payload)
    elif payload.gate == 2:
        await _apply_gate2(job_id, job, payload)
    else:
        await _apply_gate3(job_id, payload)


async def _process_batch_job(
    job_id: str, payload: BatchSignOffRequest,
    succeeded: list, failed: list, errors: dict,
) -> None:
    """Process a single job within batch_signoff; update succeeded/failed/errors in place."""
    try:
        job = await db.get_job(job_id)
        if not job:
            errors[job_id] = "Job not found"
            failed.append(job_id)
            return

        expected = _expected_status_for_gate(payload.gate)
        if job["status"] != expected:
            errors[job_id] = f"Job not at gate {payload.gate} (status: {job['status']})"
            failed.append(job_id)
            return

        await _apply_gate_decision(job_id, job, payload)
        succeeded.append(job_id)
        logger.info("Batch sign-off succeeded: job_id=%s gate=%s decision=%s",
                    job_id, payload.gate, payload.decision)
    except Exception as e:
        logger.error("Error processing batch sign-off for job %s: %s", job_id, e)
        errors[job_id] = str(e)
        failed.append(job_id)


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
        _validate_gate_payload(payload.gate, payload.decision)
        succeeded: list = []
        failed: list = []
        errors: dict = {}
        for job_id in payload.job_ids:
            await _process_batch_job(job_id, payload, succeeded, failed, errors)
        return {"succeeded": succeeded, "failed": failed, "errors": errors}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in batch_signoff: {e}")
        raise HTTPException(500, f"Batch sign-off failed: {str(e)}")


# ─────────────────────────────────────────────
# Retry (blocked / failed jobs)
# ─────────────────────────────────────────────

@router.post("/jobs/{job_id}/retry")
async def retry_job(job_id: str):
    """
    Re-queue a blocked or failed job from step 1.

    Only allowed for jobs in 'blocked' or 'failed' status.
    Resets the job to 'pending' at step 0 so the watcher picks it up again.
    """
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")

    if job["status"] not in (JobStatus.BLOCKED.value, JobStatus.FAILED.value):
        raise HTTPException(
            400,
            f"Job is '{job['status']}' — only blocked or failed jobs can be retried",
        )

    await db.update_job(job_id, JobStatus.PENDING.value, 0, {"retried": True})
    logger.info("Job retried from scratch: job_id=%s previous_status=%s", job_id, job["status"])
    return {"job_id": job_id, "status": JobStatus.PENDING.value, "message": "Job re-queued from step 1"}
