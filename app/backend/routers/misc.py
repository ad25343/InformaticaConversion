# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Misc sub-router: health check, user guide, security knowledge base, progress,
and test runner endpoints.
"""
from __future__ import annotations
import asyncio
import json
import os
import time
from datetime import datetime as _datetime
from pathlib import Path
from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse, JSONResponse, Response

from ._helpers import (
    db, logger,
    knowledge_base_stats,
    JobStatus,
    _cfg,
    _escape_csv,
    _gate_waiting_label,
)

router = APIRouter(prefix="")

_ROUTE_START_TIME = time.monotonic()

# ─────────────────────────────────────────────
# User Guide
# ─────────────────────────────────────────────

_GUIDE_PATH = Path(__file__).parent.parent.parent.parent / "docs" / "USER_GUIDE.md"

@router.get("/docs/user-guide", response_class=Response)
async def get_user_guide():
    """Serve USER_GUIDE.md as plain text for in-browser markdown rendering."""
    try:
        content = _GUIDE_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="User guide not found")
    return Response(content=content, media_type="text/plain; charset=utf-8")


# ─────────────────────────────────────────────
# Health Check
# ─────────────────────────────────────────────

@router.get("/health")
async def health_check():
    """
    Liveness + readiness probe.

    Returns 200 when the application and database are healthy.
    Returns 503 when the database is unreachable.
    Used by load balancers, Docker HEALTHCHECK, and uptime monitors.
    """
    import aiosqlite
    db_status = "ok"
    try:
        async with aiosqlite.connect(db.DB_PATH) as conn:
            await conn.execute("SELECT 1")
    except Exception as exc:
        logger.warning("Health check: DB connectivity failure (%s: %s)", type(exc).__name__, exc)
        db_status = "error"

    uptime = round(time.monotonic() - _ROUTE_START_TIME, 1)
    payload = {
        "status": "ok" if db_status == "ok" else "degraded",
        "version": _cfg.app_version,
        "db": db_status,
        "uptime_seconds": uptime,
    }
    status_code = 200 if db_status == "ok" else 503
    return JSONResponse(content=payload, status_code=status_code)


# ─────────────────────────────────────────────
# Security Knowledge Base (read-only inspection)
# ─────────────────────────────────────────────

@router.get("/security/knowledge")
async def get_security_knowledge():
    """
    Return a summary of the security knowledge base:
      - rules_count    — number of active standing rules
      - patterns_count — number of auto-learned patterns
      - top_patterns   — top 10 most-recurring patterns across all jobs
    """
    return knowledge_base_stats()


# ─────────────────────────────────────────────
# Migration Progress helpers
# ─────────────────────────────────────────────

_PIPELINE_STATUSES = frozenset({
    "parsing", "classifying", "documenting", "verifying",
    "assigning_stack", "converting", "validating", "security_scanning",
    "reviewing", "testing",
})

_TIER_MAP = {"Low": "LOW", "Medium": "MEDIUM", "High": "HIGH", "Very High": "VERY_HIGH"}


def _classify_status(status: str) -> str:
    """Map a raw job status to a status-count key."""
    if status == "pending":
        return "not_started"
    if status in _PIPELINE_STATUSES:
        return "in_pipeline"
    _gate_map = {
        JobStatus.AWAITING_REVIEW.value: "awaiting_gate_1",
        JobStatus.AWAITING_SEC_REVIEW.value: "awaiting_gate_2",
        JobStatus.AWAITING_CODE_REVIEW.value: "awaiting_gate_3",
        JobStatus.COMPLETE.value: "complete",
        JobStatus.BLOCKED.value: "blocked",
        JobStatus.FAILED.value: "failed",
    }
    return _gate_map.get(status, "")


def _tally_rows(rows) -> tuple[dict, dict]:
    """Count status and tier occurrences from DB rows."""
    status_counts = {
        "not_started": 0, "in_pipeline": 0,
        "awaiting_gate_1": 0, "awaiting_gate_2": 0, "awaiting_gate_3": 0,
        "complete": 0, "blocked": 0, "failed": 0,
    }
    tier_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "VERY_HIGH": 0, "unknown": 0}
    for row in rows:
        tier = _TIER_MAP.get(row["complexity_tier"] or "", "unknown")
        if tier in tier_counts:
            tier_counts[tier] += 1
        bucket = _classify_status(row["status"])
        if bucket:
            status_counts[bucket] += 1
    return status_counts, tier_counts


async def _fetch_completed_7d() -> int:
    """Return number of jobs completed in the last 7 days."""
    seven_days_ago = (_datetime.utcnow() - __import__("datetime").timedelta(days=7)).isoformat()
    async with db._connect() as conn:
        async with conn.execute(
            "SELECT COUNT(*) FROM jobs WHERE status = ? AND updated_at >= ? AND deleted_at IS NULL",
            (JobStatus.COMPLETE.value, seven_days_ago),
        ) as cur:
            result = await cur.fetchone()
    return result[0] if result else 0


def _estimate_eta(remaining: int, throughput_per_day: float) -> tuple:
    """Return (estimated_days, estimated_date) or (None, None)."""
    if throughput_per_day <= 0:
        return None, None
    estimated_days = round(remaining / throughput_per_day, 1)
    completion_date = _datetime.utcnow() + __import__("datetime").timedelta(days=estimated_days)
    return estimated_days, completion_date.date().isoformat()


# ─────────────────────────────────────────────
# Migration Progress (v2.17.2)
# ─────────────────────────────────────────────

@router.get("/progress")
async def get_migration_progress():
    """
    Return migration-level progress summary across all non-deleted jobs.

    Includes:
      - Status counts (not_started, in_pipeline, awaiting_gate, complete, blocked, failed)
      - Complexity tier breakdown
      - Throughput metrics and ETA
    """
    try:
        async with db._connect() as conn:
            conn.row_factory = __import__("aiosqlite").Row
            async with conn.execute(
                "SELECT status, complexity_tier, created_at, updated_at "
                "FROM jobs WHERE deleted_at IS NULL"
            ) as cur:
                rows = await cur.fetchall()

        status_counts, tier_counts = _tally_rows(rows)
        completed_7d = await _fetch_completed_7d()
        throughput_per_day = round(completed_7d / 7.0, 1)

        awaiting_gate = (status_counts["awaiting_gate_1"] +
                         status_counts["awaiting_gate_2"] +
                         status_counts["awaiting_gate_3"])
        remaining = status_counts["not_started"] + status_counts["in_pipeline"] + awaiting_gate
        estimated_days, estimated_date = _estimate_eta(remaining, throughput_per_day)

        return {
            "total": len(rows),
            "not_started": status_counts["not_started"],
            "in_pipeline": status_counts["in_pipeline"],
            "awaiting_gate": {
                "1": status_counts["awaiting_gate_1"],
                "2": status_counts["awaiting_gate_2"],
                "3": status_counts["awaiting_gate_3"],
            },
            "complete": status_counts["complete"],
            "blocked": status_counts["blocked"],
            "failed": status_counts["failed"],
            "by_tier": tier_counts,
            "throughput_per_day": throughput_per_day,
            "estimated_completion_days": estimated_days,
            "estimated_completion_date": estimated_date,
            "as_of": _datetime.utcnow().isoformat() + "Z",
        }

    except Exception as e:
        logger.error(f"Error fetching migration progress: {e}")
        raise HTTPException(500, f"Error fetching migration progress: {str(e)}")


# ─────────────────────────────────────────────
# Export CSV helpers
# ─────────────────────────────────────────────

def _row_to_csv_line(row) -> str:
    """Convert a DB row to a CSV line string."""
    batch_id = row["batch_id"] or ""
    tier = row["complexity_tier"] or ""
    status = row["status"]
    updated = row["updated_at"]
    waiting_gate = _gate_waiting_label(status)
    complete_at = updated if status == JobStatus.COMPLETE.value else ""
    vals = (
        row["job_id"], row["filename"], batch_id, status, tier,
        row["created_at"], updated, waiting_gate, complete_at,
    )
    return ",".join(_escape_csv(v) for v in vals)


@router.get("/progress/export")
async def export_progress_csv():
    """
    Return a CSV download of all job statuses for management reporting.

    Columns: job_id, filename, batch_id, status, complexity_tier, created_at, updated_at, waiting_at_gate, complete_at
    """
    try:
        async with db._connect() as conn:
            conn.row_factory = __import__("aiosqlite").Row
            async with conn.execute(
                "SELECT job_id, filename, batch_id, status, complexity_tier, "
                "       created_at, updated_at FROM jobs WHERE deleted_at IS NULL "
                "ORDER BY created_at DESC"
            ) as cur:
                rows = await cur.fetchall()

        header = "job_id,filename,batch_id,status,complexity_tier,created_at,updated_at,waiting_at_gate,complete_at"
        csv_lines = [header] + [_row_to_csv_line(row) for row in rows]
        csv_content = "\n".join(csv_lines)
        now = _datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        return StreamingResponse(
            iter([csv_content]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="migration_progress_{now}.csv"'},
        )

    except Exception as e:
        logger.error(f"Error exporting progress CSV: {e}")
        raise HTTPException(500, f"Error exporting progress CSV: {str(e)}")


# ─────────────────────────────────────────────
# Test Runner  (admin only — persona: Asin D)
# ─────────────────────────────────────────────

_SUITE_FILES = {
    "landing":    "tests/playwright/landing.spec.js",
    "navigation": "tests/playwright/navigation.spec.js",
    "submission": "tests/playwright/submission.spec.js",
    "history":    "tests/playwright/history.spec.js",
    "review":     "tests/playwright/review.spec.js",
    "security":   "tests/playwright/security.spec.js",
    "auth":       "tests/playwright/z_auth.spec.js",   # z_ prefix forces alphabetical sort LAST
}

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def _parse_playwright_counts(line: str, passed: int, failed: int, skipped: int) -> tuple[int, int, int]:
    """Extract running totals from a Playwright output line."""
    import re as _re
    m_pass  = _re.search(r"(\d+)\s+passed",  line)
    m_fail  = _re.search(r"(\d+)\s+failed",  line)
    m_skip  = _re.search(r"(\d+)\s+skipped", line)
    return (
        int(m_pass.group(1))  if m_pass  else passed,
        int(m_fail.group(1))  if m_fail  else failed,
        int(m_skip.group(1))  if m_skip  else skipped,
    )


def _sse_evt(payload: dict) -> str:
    """Format one SSE payload line."""
    return f"data: {json.dumps(payload)}\n\n"


def _build_playwright_cmd(spec_paths: list[str]) -> list[str]:
    """Build the npx playwright test command for the given spec paths."""
    return [
        "npx", "playwright", "test",
        "--reporter=list",
        "--timeout=15000",
        "--retries=0",
        "--workers=1",
    ] + spec_paths


def _flush_buf_lines(buf: str, counts: list) -> tuple[list[str], str]:
    """Split complete lines from buf, update counts, return (line_evts, remaining_buf)."""
    evts = []
    while "\n" in buf:
        line, buf = buf.split("\n", 1)
        line = line.rstrip("\r")
        if line:
            counts[0], counts[1], counts[2] = _parse_playwright_counts(
                line, counts[0], counts[1], counts[2]
            )
            evts.append(_sse_evt({"type": "line", "text": line}))
    return evts, buf


_PLAYWRIGHT_TIMEOUT_MSG = (
    "No output from test runner after 30 s. "
    "Playwright may not be installed — try running: "
    "npx playwright install chromium"
)


async def _chunk_stream(proc, timeout: float) -> AsyncGenerator[bytes | None, None]:
    """Yield raw chunks from proc.stdout; yields None once on timeout (proc killed)."""
    while True:
        try:
            chunk = await asyncio.wait_for(proc.stdout.read(2048), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            yield None
            return
        if not chunk:
            return
        yield chunk


async def _stream_playwright_output(proc, selected: list[str]) -> AsyncGenerator[str, None]:
    """Yield SSE events from a running Playwright process until it exits."""
    counts = [0, 0, 0]  # [passed, failed, skipped]
    buf = ""

    async for chunk in _chunk_stream(proc, 30.0):
        if chunk is None:
            yield _sse_evt({"type": "error", "text": _PLAYWRIGHT_TIMEOUT_MSG})
            return
        buf += chunk.decode("utf-8", errors="replace")
        line_evts, buf = _flush_buf_lines(buf, counts)
        for evt in line_evts:
            yield evt

    if buf.strip():
        yield _sse_evt({"type": "line", "text": buf.strip()})

    await proc.wait()
    yield _sse_evt({"type": "done", "rc": proc.returncode,
                    "passed": counts[0], "failed": counts[1], "skipped": counts[2]})


async def _make_test_stream(cmd: list[str], selected: list[str]) -> AsyncGenerator[str, None]:
    """Yield SSE events for a Playwright test run (start, output lines, done/error)."""
    yield _sse_evt({"type": "start", "suites": selected, "cmd": " ".join(cmd)})
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=_REPO_ROOT,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, "FORCE_COLOR": "0", "CI": "1", "NODE_NO_WARNINGS": "1"},
        )
        async for event in _stream_playwright_output(proc, selected):
            yield event
    except Exception as exc:
        yield _sse_evt({"type": "error", "text": str(exc)})


def _parse_suites(suites_str: str) -> tuple[list[str], list[str]]:
    """Return (selected suite names, spec file paths) for valid suite names in suites_str."""
    selected = [s.strip() for s in suites_str.split(",") if s.strip() in _SUITE_FILES]
    spec_paths = [_SUITE_FILES[s] for s in selected]
    return selected, spec_paths


@router.get("/run-tests")
async def run_tests(request: Request, suites: str = ""):
    """
    SSE stream that runs the selected Playwright suites and streams output
    line-by-line.  Admin-only: requires persona cookie == 'Asin D'.
    """
    from urllib.parse import unquote as _unquote
    persona = _unquote(request.cookies.get("persona", ""))
    if persona != "Asin D":
        raise HTTPException(403, "Test runner is restricted to the admin persona.")

    selected, spec_paths = _parse_suites(suites)
    if not selected:
        raise HTTPException(400, "No valid suites specified.")

    cmd = _build_playwright_cmd(spec_paths)

    return StreamingResponse(
        _make_test_stream(cmd, selected),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
