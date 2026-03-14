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

            # Fetch all non-deleted jobs with minimal fields
            async with conn.execute(
                "SELECT status, complexity_tier, created_at, updated_at "
                "FROM jobs WHERE deleted_at IS NULL"
            ) as cur:
                rows = await cur.fetchall()

        # Count statuses and tiers
        status_counts = {
            "not_started": 0,
            "in_pipeline": 0,
            "awaiting_gate_1": 0,
            "awaiting_gate_2": 0,
            "awaiting_gate_3": 0,
            "complete": 0,
            "blocked": 0,
            "failed": 0,
        }
        tier_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "VERY_HIGH": 0, "unknown": 0}

        # Pipeline statuses (active, not gate, not terminal)
        pipeline_statuses = {
            "parsing", "classifying", "documenting", "verifying",
            "assigning_stack", "converting", "validating", "security_scanning",
            "reviewing", "testing",
        }

        for row in rows:
            status = row["status"]
            tier = row["complexity_tier"] or "unknown"

            # Map tier names
            tier_map = {"Low": "LOW", "Medium": "MEDIUM", "High": "HIGH", "Very High": "VERY_HIGH"}
            tier = tier_map.get(tier, "unknown")
            if tier in tier_counts:
                tier_counts[tier] += 1

            if status == "pending":
                status_counts["not_started"] += 1
            elif status in pipeline_statuses:
                status_counts["in_pipeline"] += 1
            elif status == JobStatus.AWAITING_REVIEW.value:
                status_counts["awaiting_gate_1"] += 1
            elif status == JobStatus.AWAITING_SEC_REVIEW.value:
                status_counts["awaiting_gate_2"] += 1
            elif status == JobStatus.AWAITING_CODE_REVIEW.value:
                status_counts["awaiting_gate_3"] += 1
            elif status == JobStatus.COMPLETE.value:
                status_counts["complete"] += 1
            elif status == JobStatus.BLOCKED.value:
                status_counts["blocked"] += 1
            elif status == JobStatus.FAILED.value:
                status_counts["failed"] += 1

        # Calculate throughput (jobs completed in last 7 days)
        seven_days_ago = (_datetime.utcnow() - __import__("datetime").timedelta(days=7)).isoformat()
        async with db._connect() as conn:
            async with conn.execute(
                "SELECT COUNT(*) FROM jobs WHERE status = ? AND updated_at >= ? AND deleted_at IS NULL",
                (JobStatus.COMPLETE.value, seven_days_ago),
            ) as cur:
                result = await cur.fetchone()
                completed_7d = result[0] if result else 0

        throughput_per_day = round(completed_7d / 7.0, 1)

        # Calculate ETA
        total = len(rows)
        not_started = status_counts["not_started"]
        in_pipeline = status_counts["in_pipeline"]
        awaiting_gate = (status_counts["awaiting_gate_1"] +
                        status_counts["awaiting_gate_2"] +
                        status_counts["awaiting_gate_3"])

        remaining = not_started + in_pipeline + awaiting_gate
        estimated_days = None
        estimated_date = None

        if throughput_per_day > 0:
            estimated_days = round(remaining / throughput_per_day, 1)
            completion_date = _datetime.utcnow() + __import__("datetime").timedelta(days=estimated_days)
            estimated_date = completion_date.date().isoformat()

        now = _datetime.utcnow().isoformat() + "Z"

        return {
            "total": total,
            "not_started": not_started,
            "in_pipeline": in_pipeline,
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
            "as_of": now,
        }

    except Exception as e:
        logger.error(f"Error fetching migration progress: {e}")
        raise HTTPException(500, f"Error fetching migration progress: {str(e)}")


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

        # Build CSV
        csv_lines = ["job_id,filename,batch_id,status,complexity_tier,created_at,updated_at,waiting_at_gate,complete_at"]

        for row in rows:
            job_id = row["job_id"]
            filename = row["filename"]
            batch_id = row["batch_id"] or ""
            status = row["status"]
            tier = row["complexity_tier"] or ""
            created = row["created_at"]
            updated = row["updated_at"]

            # Determine waiting_at_gate
            waiting_gate = ""
            if status == JobStatus.AWAITING_REVIEW.value:
                waiting_gate = "1"
            elif status == JobStatus.AWAITING_SEC_REVIEW.value:
                waiting_gate = "2"
            elif status == JobStatus.AWAITING_CODE_REVIEW.value:
                waiting_gate = "3"

            # Use updated_at as proxy for complete_at
            complete_at = updated if status == JobStatus.COMPLETE.value else ""

            # Escape CSV values
            def escape_csv(val):
                if val is None:
                    return ""
                val_str = str(val)
                if "," in val_str or '"' in val_str or "\n" in val_str:
                    return '"' + val_str.replace('"', '""') + '"'
                return val_str

            line = f"{escape_csv(job_id)},{escape_csv(filename)},{escape_csv(batch_id)},{escape_csv(status)},{escape_csv(tier)},{escape_csv(created)},{escape_csv(updated)},{escape_csv(waiting_gate)},{escape_csv(complete_at)}"
            csv_lines.append(line)

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

    # Build list of spec files to pass to playwright
    selected = [s.strip() for s in suites.split(",") if s.strip() in _SUITE_FILES]
    if not selected:
        raise HTTPException(400, "No valid suites specified.")

    spec_paths = [_SUITE_FILES[s] for s in selected]
    cmd = [
        "npx", "playwright", "test",
        "--reporter=list",   # newline-terminated output — safe for SSE streaming
        "--timeout=15000",   # 15 s per test (fast-fail if server unreachable)
        "--retries=0",       # no retries in health-check mode
        "--workers=1",       # serial execution — prevents rate-limiter tests from blocking parallel logins
    ] + spec_paths

    async def _stream() -> AsyncGenerator[str, None]:
        import re as _re

        def _evt(payload: dict) -> str:
            return f"data: {json.dumps(payload)}\n\n"

        yield _evt({"type": "start", "suites": selected, "cmd": " ".join(cmd)})

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=_REPO_ROOT,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={
                    **os.environ,
                    "FORCE_COLOR": "0",
                    "CI": "1",
                    # Disable Node/npm stdout buffering
                    "NODE_NO_WARNINGS": "1",
                },
            )

            passed = failed = skipped = 0
            buf = ""
            # Read in small chunks so we don't wait for a full newline to arrive.
            # Playwright can buffer output when stdout is a pipe; chunked reads
            # unblock the stream as soon as any bytes arrive.
            READ_TIMEOUT = 30.0   # seconds to wait for ANY new output before giving up

            while True:
                try:
                    chunk = await asyncio.wait_for(
                        proc.stdout.read(2048), timeout=READ_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    # Nothing arrived for 30 s — report and kill
                    yield _evt({
                        "type": "error",
                        "text": (
                            "No output from test runner after 30 s. "
                            "Playwright may not be installed — try running: "
                            "npx playwright install chromium"
                        ),
                    })
                    proc.kill()
                    break

                if not chunk:
                    break  # EOF — process finished

                buf += chunk.decode("utf-8", errors="replace")

                # Emit complete lines as they accumulate in the buffer
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.rstrip("\r")
                    if not line:
                        continue

                    # Parse Playwright summary: "5 passed (12s)"  /  "2 failed"
                    m_pass  = _re.search(r"(\d+)\s+passed",  line)
                    m_fail  = _re.search(r"(\d+)\s+failed",  line)
                    m_skip  = _re.search(r"(\d+)\s+skipped", line)
                    if m_pass:  passed  = int(m_pass.group(1))
                    if m_fail:  failed  = int(m_fail.group(1))
                    if m_skip:  skipped = int(m_skip.group(1))

                    yield _evt({"type": "line", "text": line})

            # Flush any remaining partial line
            if buf.strip():
                yield _evt({"type": "line", "text": buf.strip()})

            await proc.wait()
            rc = proc.returncode

            yield _evt({
                "type":    "done",
                "rc":      rc,
                "passed":  passed,
                "failed":  failed,
                "skipped": skipped,
            })

        except Exception as exc:
            yield _evt({"type": "error", "text": str(exc)})

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
