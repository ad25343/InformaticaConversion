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
