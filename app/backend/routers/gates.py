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
    JobStatus,
    SignOffRecord, SignOffRequest, ReviewDecision,
    CodeSignOffRequest, CodeSignOffRecord, CodeReviewDecision,
    SecuritySignOffRecord, SecuritySignOffRequest, SecurityReviewDecision,
)
from ..models.schemas import VALID_RESTART_STEPS_GATE1, VALID_RESTART_STEPS_GATE3

router = APIRouter(prefix="")


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
        restart_step = payload.restart_from_step
        if restart_step and restart_step in VALID_RESTART_STEPS_GATE1:
            # Checkpoint-based restart — resume from the requested step
            await db.update_job(job_id, JobStatus.PENDING.value, 5, {"error": None})
            await db.add_audit_entry(
                job_id=job_id,
                gate="gate1",
                event_type="reject_restart",
                reviewer_name=payload.reviewer_name,
                reviewer_role=payload.reviewer_role,
                decision=payload.decision,
                notes=payload.notes,
                extra={"restart_from_step": restart_step},
            )
            queue: asyncio.Queue = asyncio.Queue()
            _progress_queues[job_id] = queue
            state    = job["state"]
            filename = job["filename"]
            restart_gen = orchestrator.resume_from_step(job_id, filename, restart_step, state)

            async def _restart_resume():
                try:
                    async for progress in restart_gen:
                        await queue.put(progress)
                except orchestrator.EmitError as _emit_exc:
                    await queue.put(_emit_exc.event)
                finally:
                    await queue.put(None)

            task = asyncio.create_task(_restart_resume())
            _active_tasks[job_id] = task
            logger.info("Pipeline checkpoint-restarting from step %s: job_id=%s",
                        restart_step, job_id)
            return {
                "message": f"Job rejected with checkpoint restart from Step {restart_step}.",
                "job_id": job_id,
                "restart_from_step": restart_step,
            }
        else:
            # Existing behavior — hard block
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
            try:
                async for progress in resume_gen:
                    await queue.put(progress)
            except orchestrator.EmitError as _emit_exc:
                await queue.put(_emit_exc.event)
            finally:
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
            try:
                async for progress in sec_resume_gen:
                    await queue.put(progress)
            except orchestrator.EmitError as _emit_exc:
                await queue.put(_emit_exc.event)
            finally:
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

    # REJECTED — checkpoint restart or hard block
    if payload.decision == CodeReviewDecision.REJECTED:
        restart_step = payload.restart_from_step
        if restart_step and restart_step in VALID_RESTART_STEPS_GATE3:
            # Checkpoint-based restart from within the conversion phase
            await db.update_job(job_id, JobStatus.PENDING.value, 12, {"error": None})
            await db.add_audit_entry(
                job_id=job_id,
                gate="gate3",
                event_type="reject_restart",
                reviewer_name=payload.reviewer_name,
                reviewer_role=payload.reviewer_role,
                decision=payload.decision,
                notes=payload.notes,
                extra={"restart_from_step": restart_step},
            )
            queue: asyncio.Queue = asyncio.Queue()
            _progress_queues[job_id] = queue
            state    = job["state"]
            state["code_sign_off"] = code_signoff.model_dump()
            filename = job["filename"]
            restart_gen = orchestrator.resume_from_step(job_id, filename, restart_step, state)

            async def _code_restart_resume():
                try:
                    async for progress in restart_gen:
                        await queue.put(progress)
                except orchestrator.EmitError as _emit_exc:
                    await queue.put(_emit_exc.event)
                finally:
                    await queue.put(None)

            task = asyncio.create_task(_code_restart_resume())
            _active_tasks[job_id] = task
            logger.info("Pipeline checkpoint-restarting from step %s after Gate 3 reject: job_id=%s",
                        restart_step, job_id)
            return {
                "message": f"Code review rejected with checkpoint restart from Step {restart_step}.",
                "job_id":   job_id,
                "decision": payload.decision,
                "restart_from_step": restart_step,
            }
        else:
            # Existing behavior — hard block
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
            try:
                async for progress in code_resume_gen:
                    await queue.put(progress)
            except orchestrator.EmitError as _emit_exc:
                await queue.put(_emit_exc.event)
            finally:
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
# Gate Review Queue (v2.17.1)
# ─────────────────────────────────────────────

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
