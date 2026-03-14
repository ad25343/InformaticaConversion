# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Upload sub-router: job creation endpoints and SSE progress stream.
"""
from __future__ import annotations
import asyncio
import json
from pathlib import Path
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, File, UploadFile, HTTPException, Form
from starlette.background import BackgroundTask
from fastapi.responses import StreamingResponse
from typing import Optional as _Opt

from ._helpers import (
    db, logger, orchestrator, jobs_limiter,
    _validate_xml_content_type, _validate_zip_content_type,
    _active_tasks, _progress_queues,
    validate_upload_size, ZipExtractionError,
    extract_informatica_zip,
    _cfg,
)

router = APIRouter(prefix="")


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
        try:
            async for progress in orchestrator.run_pipeline(job_id, file.filename):
                await queue.put(progress)
        except orchestrator.EmitError as _emit_exc:
            # DB write exhausted all retries — surface the failure event to the
            # SSE stream so the UI shows a clean error rather than hanging.
            await queue.put(_emit_exc.event)
        finally:
            await queue.put(None)  # sentinel — always sent, even after EmitError

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
        from ._helpers import _validate_job_id
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
