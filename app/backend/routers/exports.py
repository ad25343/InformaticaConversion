# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Exports sub-router: file download endpoints for converted output.
"""
from __future__ import annotations

from fastapi import APIRouter, File, UploadFile, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from typing import Optional as _Opt

from ._helpers import (
    db, logger,
    _validate_job_id,
    s2t_excel_path,
    validate_upload_size,
    build_output_zip,
    JobStatus,
)

router = APIRouter(prefix="")


# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

def _safe_filename(name: str) -> str:
    """Sanitise a mapping name for use in a download filename."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in name)


def _load_manifest_overrides_from_bytes(xlsx_bytes: bytes) -> list:
    """Write bytes to a temp file, parse overrides, clean up, return list."""
    from ..agents import manifest_agent
    import tempfile as _tempfile
    import os as _os

    with _tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
        tmp.write(xlsx_bytes)
        tmp_path = tmp.name
    try:
        return manifest_agent.load_overrides(tmp_path)
    finally:
        _os.unlink(tmp_path)


def _validate_manifest_job_for_upload(job, job_id: str) -> None:
    """Raise HTTPException if the job is missing or not in awaiting_review state."""
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")
    if job["status"] != JobStatus.AWAITING_REVIEW.value:
        raise HTTPException(
            400,
            f"Manifest overrides can only be uploaded while the job is awaiting review "
            f"(current status: {job['status']}). Download the manifest, annotate it, "
            f"then upload it before submitting your sign-off.",
        )


# ─────────────────────────────────────────────
# Download converted code
# ─────────────────────────────────────────────

@router.get("/jobs/{job_id}/s2t/download")
async def download_s2t_excel(job_id: str):
    """Download the Source-to-Target mapping Excel workbook for a job."""
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
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


@router.get("/jobs/{job_id}/manifest.xlsx")
async def download_manifest_xlsx(job_id: str):
    """
    Generate and return the pre-conversion mapping manifest xlsx on demand.
    The manifest is NOT stored in state (too large); it is regenerated from the
    graph dict each time this endpoint is called.
    """
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")
    graph = job.get("state", {}).get("graph")
    if not graph:
        raise HTTPException(404, "Manifest not available — job has not completed parsing yet")

    from ..agents import manifest_agent
    import io as _io
    report = manifest_agent.build_manifest(graph)
    xlsx_bytes = manifest_agent.write_xlsx_bytes(report)
    safe = job.get("filename", "mapping").replace(".xml", "").replace(" ", "_")
    return StreamingResponse(
        _io.BytesIO(xlsx_bytes),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="manifest_{safe}.xlsx"'},
    )


@router.post("/jobs/{job_id}/manifest-upload")
async def upload_manifest_overrides(job_id: str, file: UploadFile = File(...)):
    """
    Accept a reviewer-annotated manifest xlsx and store the overrides in job state.

    The reviewer downloads the manifest via GET /jobs/{job_id}/manifest.xlsx,
    fills in the 'Reviewer Override' column on the 'Review Required' sheet for any
    LOW or UNMAPPED rows, then re-uploads the annotated file here.

    Must be called while the job is at Gate 1 (awaiting_review).
    The conversion agent picks up the stored overrides when the pipeline resumes
    after sign-off, resolving lineage gaps before generating code.
    """
    job = await db.get_job(job_id)
    _validate_manifest_job_for_upload(job, job_id)

    fname = (file.filename or "").lower()
    if not fname.endswith(".xlsx"):
        raise HTTPException(400, "Manifest file must be a .xlsx file")

    xlsx_bytes = await file.read()
    validate_upload_size(xlsx_bytes, label=file.filename)
    if not xlsx_bytes:
        raise HTTPException(400, "Uploaded manifest file is empty")

    overrides = _load_manifest_overrides_from_bytes(xlsx_bytes)
    overrides_dicts = [o.model_dump() for o in overrides]

    await db.update_job(
        job_id, JobStatus.AWAITING_REVIEW.value, 5,
        {"manifest_overrides": overrides_dicts},
    )

    logger.info("Manifest overrides uploaded: job_id=%s override_count=%d",
                job_id, len(overrides_dicts))

    return {
        "message": f"Manifest uploaded successfully. {len(overrides_dicts)} override(s) stored.",
        "job_id": job_id,
        "override_count": len(overrides_dicts),
        "overrides": overrides_dicts,
    }


@router.get("/jobs/{job_id}/download/{filename}")
async def download_file(job_id: str, filename: str):
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")
    conversion = job["state"].get("conversion", {})
    files = conversion.get("files", {})
    if filename not in files:
        raise HTTPException(404, f"File '{filename}' not found in conversion output")

    # GAP #14 — Validate the filename is safe before serving
    import pathlib
    _safe_name = pathlib.PurePosixPath(filename).name
    _ALLOWED_EXTS = {".py", ".sql", ".yaml", ".yml", ".txt", ".md", ".json", ".sh", ".cfg", ".ini", ".toml"}
    _ext = pathlib.PurePosixPath(_safe_name).suffix.lower()
    if _ext not in _ALLOWED_EXTS:
        logger.warning("Blocked download of disallowed extension: job=%s filename=%s", job_id, filename)
        raise HTTPException(400, f"File extension '{_ext}' is not permitted for download.")

    return JSONResponse({"filename": filename, "content": files[filename]})


@router.get("/jobs/{job_id}/tests/download/{filename:path}")
async def download_test_file(job_id: str, filename: str):
    """Download a generated test file by path (e.g. tests/test_conversion.py)."""
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")
    test_report = job["state"].get("test_report", {})
    files = test_report.get("test_files", {})
    if filename not in files:
        raise HTTPException(404, f"Test file '{filename}' not found")

    import pathlib
    _ALLOWED_EXTS = {".py", ".sql", ".yaml", ".yml", ".txt", ".md", ".json", ".sh", ".cfg", ".ini", ".toml"}
    _ext = pathlib.PurePosixPath(filename).suffix.lower()
    if _ext not in _ALLOWED_EXTS:
        logger.warning("Blocked test download of disallowed extension: job=%s filename=%s", job_id, filename)
        raise HTTPException(400, f"File extension '{_ext}' is not permitted for download.")

    return JSONResponse({"filename": filename, "content": files[filename]})


# ─────────────────────────────────────────────
# Output ZIP Download (v2.5.0)
# ─────────────────────────────────────────────

@router.get("/jobs/{job_id}/output.zip")
async def download_output_zip(job_id: str):
    """
    Download all generated conversion output files as a ZIP archive.

    Bundles every file from state["conversion"]["files"] into a single
    ZIP preserving folder structure.  Built directly from DB state so it
    works regardless of whether the job folder has been written to disk.

    Only available for jobs that have reached AWAITING_CODE_REVIEW or
    COMPLETE status (i.e. conversion has run).
    """
    job = await db.get_job(job_id)
    if not job:
        _validate_job_id(job_id)
        raise HTTPException(404, "Job not found")

    state = job.get("state", {})
    conversion = state.get("conversion", {})
    files = conversion.get("files", {})
    if not files:
        raise HTTPException(404, "No output files found — conversion has not completed for this job.")

    zip_bytes = build_output_zip(state)
    mapping_name = conversion.get("mapping_name", job_id)
    filename = f"{_safe_filename(mapping_name)}_output.zip"

    return StreamingResponse(
        iter([zip_bytes]),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
