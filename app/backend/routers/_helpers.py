# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Shared helpers, global state, and imports for all sub-routers.
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

from ..db import database as db
from ..limiter import jobs_limiter
from ..security_knowledge import record_findings, knowledge_base_stats
from ..models.schemas import (
    SignOffRecord, SignOffRequest, ReviewDecision, JobStatus,
    CodeSignOffRequest, CodeSignOffRecord, CodeReviewDecision,
    SecuritySignOffRecord, SecuritySignOffRequest, SecurityReviewDecision,
    BatchStatus,
)
from .. import orchestrator
from ..logger import read_job_log, read_job_log_raw, job_log_path, list_log_registry
from ..agents.s2t_agent import s2t_excel_path
from ..security import validate_upload_size, ZipExtractionError
from ..zip_extractor import extract_informatica_zip, extract_batch_zip
from ..job_exporter import build_output_zip
from ..config import settings as _cfg

logger = logging.getLogger("conversion.routes")

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

# ── Batch semaphore + tracking ─────────────────────
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


async def _mark_batch_job_failed(j_id: str, exc: Exception) -> None:
    """Best-effort: mark a crashed batch job as FAILED in the DB."""
    logger.error(
        "Batch resume crashed unexpectedly: job_id=%s error=%s", j_id, exc, exc_info=True,
    )
    try:
        await db.update_job(j_id, JobStatus.FAILED.value, -1,
                            {"error": f"Batch resume crashed: {exc}"})
    except Exception:  # pragma: no cover
        logger.exception("Failed to mark crashed batch resume job as FAILED: job_id=%s", j_id)
    await _progress_queues[j_id].put(
        {"step": -1, "status": JobStatus.FAILED.value, "message": f"Resume crashed: {exc}"}
    )


async def _drain_resume_gen(j_id: str, resume_gen, semaphore_held_ref: list) -> None:
    """Drain resume_gen, releasing semaphore on gate-wait."""
    async for progress in resume_gen:
        await _progress_queues[j_id].put(progress)
        if semaphore_held_ref[0] and progress.get("status") in _GATE_WAITING_STATUSES:
            _batch_semaphore.release()
            semaphore_held_ref[0] = False


async def _resume_batch_job(j_id: str, resume_gen) -> None:
    """
    Re-acquire the batch concurrency semaphore, drive *resume_gen* to
    completion (or to the next gate), then release the slot.

    Called when a human approves a gate on a batch job.  The slot was freed
    when the pipeline first reached the gate in _run_with_semaphore / a
    previous call to this function.
    """
    await _batch_semaphore.acquire()
    semaphore_held_ref = [True]
    try:
        await _drain_resume_gen(j_id, resume_gen, semaphore_held_ref)
    except Exception as exc:  # noqa: BLE001
        await _mark_batch_job_failed(j_id, exc)
    finally:
        if semaphore_held_ref[0]:
            _batch_semaphore.release()
        await _progress_queues[j_id].put(None)


def _all_terminal(job_statuses: list[str], terminal: set) -> bool:
    """Return True when every status is in the terminal set."""
    return all(s in terminal for s in job_statuses)


def _count_complete(job_statuses: list[str]) -> int:
    """Count jobs with COMPLETE status."""
    return job_statuses.count(JobStatus.COMPLETE.value)


def _compute_batch_status(job_statuses: list[str]) -> str:
    """Derive a BatchStatus string from a list of individual job status strings."""
    if not job_statuses:
        return BatchStatus.FAILED.value
    terminal = {JobStatus.COMPLETE.value, JobStatus.FAILED.value, JobStatus.BLOCKED.value}
    if not _all_terminal(job_statuses, terminal):
        return BatchStatus.RUNNING.value
    n_complete = _count_complete(job_statuses)
    if n_complete == len(job_statuses):
        return BatchStatus.COMPLETE.value
    if n_complete:
        return BatchStatus.PARTIAL.value
    return BatchStatus.FAILED.value


def _get_gate_from_status(status: str) -> _Opt[int]:
    """Map job status to gate number: 1 (review), 2 (security), 3 (code)."""
    if status == JobStatus.AWAITING_REVIEW.value:
        return 1
    elif status == JobStatus.AWAITING_SEC_REVIEW.value:
        return 2
    elif status == JobStatus.AWAITING_CODE_REVIEW.value:
        return 3
    return None


def _tally_gate1_flags(flags: list) -> tuple[dict, list]:
    """Count severities and collect up to 2 unique flag types from gate-1 flags."""
    flag_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    top_flags: list = []
    for flag in flags:
        severity = flag.get("severity", "MEDIUM").upper()
        if severity in flag_summary:
            flag_summary[severity] += 1
        flag_type = flag.get("flag_type", "UNKNOWN")
        if flag_type not in top_flags:
            top_flags.append(flag_type)
            if len(top_flags) >= 2:
                break
    return flag_summary, top_flags


def _extract_flags_for_gate(state: dict, gate: int) -> dict:
    """Extract flag summary and top flags from state based on gate."""
    if gate != 1:
        # For gates 2 and 3, return empty (parsing state is not required here)
        return {"flag_summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "top_flags": []}
    verification = state.get("verification", {})
    flags = verification.get("flags", [])
    flag_summary, top_flags = _tally_gate1_flags(flags)
    return {"flag_summary": flag_summary, "top_flags": top_flags}


# ── Gate decision helpers ────────────────────────────────────────────────────

_GATE_EXPECTED_STATUS = {
    1: lambda: JobStatus.AWAITING_REVIEW.value,
    2: lambda: JobStatus.AWAITING_SEC_REVIEW.value,
    3: lambda: JobStatus.AWAITING_CODE_REVIEW.value,
}

_GATE_VALID_DECISIONS = {
    1: ["APPROVE", "REJECT"],
    2: ["APPROVED", "ACKNOWLEDGED", "FAILED"],
    3: ["APPROVED", "REJECTED"],
}


def _validate_gate_payload(gate: int, decision: str) -> None:
    """Raise HTTPException if gate or decision is invalid."""
    if gate not in (1, 2, 3):
        raise HTTPException(400, "Gate must be 1, 2, or 3")
    if decision not in _GATE_VALID_DECISIONS[gate]:
        raise HTTPException(400, f"Invalid decision '{decision}' for gate {gate}")


def _expected_status_for_gate(gate: int) -> str:
    """Return the job status string expected for the given gate number."""
    return _GATE_EXPECTED_STATUS[gate]()


async def _make_pipeline_task(
    job_id: str,
    resume_gen,
    queue: asyncio.Queue,
) -> "asyncio.Task":
    """Create an asyncio task that drains *resume_gen* into *queue*."""
    async def _runner():
        try:
            async for progress in resume_gen:
                await queue.put(progress)
        except orchestrator.EmitError as _emit_exc:
            await queue.put(_emit_exc.event)
        finally:
            await queue.put(None)

    return asyncio.create_task(_runner())


def _make_simple_pipeline_task(
    job_id: str,
    resume_gen,
    queue: asyncio.Queue,
) -> "asyncio.Task":
    """Create a simple (no EmitError handling) pipeline task."""
    async def _runner():
        async for progress in resume_gen:
            await queue.put(progress)
        await queue.put(None)

    return asyncio.create_task(_runner())


def _setup_queue(job_id: str) -> asyncio.Queue:
    """Create and register a progress queue for a job."""
    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues[job_id] = queue
    return queue


def _try_record_security_findings(job_id: str, state: dict) -> None:
    """Best-effort: record security findings into the knowledge base."""
    scan = state.get("security_scan") or {}
    findings = scan.get("findings") if isinstance(scan, dict) else []
    if not findings:
        return
    try:
        n = record_findings(job_id, findings)
        logger.info("Security KB: recorded %d pattern(s) from job %s", n, job_id)
    except Exception as kb_err:
        logger.warning("Security KB: failed to record findings: %s", kb_err)


def _normalize_pipeline_mode(pipeline_mode: str) -> str:
    """Return 'full' or 'docs_only'; default to 'full' for unknown values."""
    normalized = (pipeline_mode or "full").strip().lower()
    return normalized if normalized in ("full", "docs_only") else "full"


def _escape_csv(val) -> str:
    """Escape a single value for CSV output."""
    if val is None:
        return ""
    val_str = str(val)
    if "," in val_str or '"' in val_str or "\n" in val_str:
        return '"' + val_str.replace('"', '""') + '"'
    return val_str


def _gate_waiting_label(status: str) -> str:
    """Return '1', '2', '3', or '' based on gate-waiting status."""
    return {
        JobStatus.AWAITING_REVIEW.value: "1",
        JobStatus.AWAITING_SEC_REVIEW.value: "2",
        JobStatus.AWAITING_CODE_REVIEW.value: "3",
    }.get(status, "")


def _build_mappings_payload(mapping_results, fallback_filename: str) -> list[dict]:
    """Convert extraction results to the atomic batch-create payload format."""
    return [
        {
            "filename":       parsed.mapping_filename or fallback_filename,
            "xml":            parsed.mapping_xml,
            "workflow_xml":   parsed.workflow_xml,
            "parameter_file": parsed.parameter_file,
        }
        for parsed in mapping_results
    ]


async def _stamp_batch_output_hints(
    job_ids: list, mapping_results, batch_dir_name: str, batch_pm: str
) -> None:
    """Write output-folder hints to each batch job (non-fatal on failure)."""
    for job_id, parsed in zip(job_ids, mapping_results):
        mapping_stem = Path(parsed.mapping_filename or "mapping").stem
        try:
            await db.update_job(
                job_id, "pending", 0,
                {
                    "watcher_output_dir":   batch_dir_name,
                    "watcher_mapping_stem": mapping_stem,
                    "pipeline_mode":        batch_pm,
                },
            )
        except Exception as hint_exc:
            logger.warning(
                "Could not stamp output hints (non-fatal): job_id=%s error=%s",
                job_id, hint_exc,
            )


def _cleanup_s2t_files(jobs: list) -> int:
    """Delete S2T artefacts for each job; return count of files removed."""
    from ..agents.s2t_agent import s2t_excel_path as _s2t_path
    cleaned = 0
    for j in jobs:
        path = _s2t_path(j["job_id"])
        if not (path and path.exists()):
            continue
        try:
            path.unlink()
            cleaned += 1
        except OSError:
            pass
    return cleaned
