# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Batch sub-router: batch upload, retrieval, deletion, and startup recovery.
"""
from __future__ import annotations
import asyncio
from pathlib import Path

from fastapi import APIRouter, Depends, File, UploadFile, HTTPException, Form

from ._helpers import (
    db, logger, orchestrator, jobs_limiter,
    _active_tasks, _progress_queues, _batch_job_ids,
    _batch_semaphore, _BATCH_CONCURRENCY, _GATE_WAITING_STATUSES,
    _resume_batch_job, _compute_batch_status,
    validate_upload_size, ZipExtractionError, extract_batch_zip,
    JobStatus,
    s2t_excel_path,
)

router = APIRouter(prefix="")


# ─────────────────────────────────────────────
# Batch Upload (v2.0)
# ─────────────────────────────────────────────

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


@router.delete("/batches/{batch_id}")
async def delete_batch(batch_id: str):
    """Soft-delete every non-deleted job in a batch in one operation.
    Preserves DB records and log files for the audit trail."""
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


# ─────────────────────────────────────────────
# Startup recovery (called from main.py lifespan)
# ─────────────────────────────────────────────

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

        async def _run_with_semaphore_recovery(j_id: str, fname: str):
            await _batch_semaphore.acquire()
            semaphore_held = True
            try:
                async for progress in orchestrator.run_pipeline(j_id, fname):
                    await _progress_queues[j_id].put(progress)
                    if semaphore_held and progress.get("status") in _GATE_WAITING_STATUSES:
                        _batch_semaphore.release()
                        semaphore_held = False
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Batch pipeline crashed unexpectedly: job_id=%s error=%s",
                    j_id, exc, exc_info=True,
                )
                try:
                    await db.update_job(j_id, JobStatus.FAILED.value, -1,
                                        {"error": f"Batch runner crashed: {exc}"})
                except Exception:  # pragma: no cover
                    logger.exception("Failed to mark crashed batch job as FAILED: job_id=%s", j_id)
                await _progress_queues[j_id].put(
                    {"step": -1, "status": JobStatus.FAILED.value,
                     "message": f"Pipeline crashed: {exc}"}
                )
            finally:
                if semaphore_held:
                    _batch_semaphore.release()
                await _progress_queues[j_id].put(None)

        task = asyncio.create_task(_run_with_semaphore_recovery(j_id, fname))
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
