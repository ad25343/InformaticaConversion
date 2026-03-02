"""
Job TTL cleanup — deletes jobs (and their associated log/S2T files) that are
older than JOB_RETENTION_DAYS.

Runs as a background asyncio loop started during app lifespan.
Can also be called directly for one-off cleanup (e.g., from a script).

Environment variables
---------------------
  JOB_RETENTION_DAYS      Days to keep completed jobs (default: 30)
  CLEANUP_INTERVAL_HOURS  How often the background loop runs (default: 24)
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

import aiosqlite

from .db.database import DB_PATH
from .logger import job_log_path
from .agents.s2t_agent import s2t_excel_path

log = logging.getLogger("conversion.cleanup")

from .config import settings as _cfg
JOB_RETENTION_DAYS     = _cfg.job_retention_days
CLEANUP_INTERVAL_HOURS = _cfg.cleanup_interval_hours


async def cleanup_old_jobs() -> dict[str, int]:
    """
    Delete jobs created more than JOB_RETENTION_DAYS ago together with
    their associated log files and S2T Excel workbooks.

    Returns a dict: {"deleted_jobs": N, "deleted_files": N}
    """
    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=JOB_RETENTION_DAYS)
    ).isoformat()

    # ── Collect job IDs to delete ───────────────────────────────────────────
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT job_id FROM jobs WHERE created_at < ?", (cutoff,)
        )
        rows = await cursor.fetchall()

    job_ids: list[str] = [row["job_id"] for row in rows]
    if not job_ids:
        log.debug("Cleanup: no jobs older than %d days", JOB_RETENTION_DAYS)
        return {"deleted_jobs": 0, "deleted_files": 0}

    # ── Delete associated files ─────────────────────────────────────────────
    deleted_files = 0
    for job_id in job_ids:
        for path_fn in (job_log_path, s2t_excel_path):
            path = path_fn(job_id)
            if path and path.exists():
                try:
                    path.unlink()
                    deleted_files += 1
                except OSError as exc:
                    log.warning("Could not delete file for job %s: %s", job_id, exc)

    # ── Delete rows from DB ─────────────────────────────────────────────────
    async with aiosqlite.connect(DB_PATH) as conn:
        placeholders = ",".join("?" * len(job_ids))
        await conn.execute(
            f"DELETE FROM jobs WHERE job_id IN ({placeholders})", job_ids
        )
        await conn.commit()

    log.info(
        "Cleanup: removed %d job(s) older than %d days; %d file(s) deleted",
        len(job_ids), JOB_RETENTION_DAYS, deleted_files,
    )
    return {"deleted_jobs": len(job_ids), "deleted_files": deleted_files}


async def run_cleanup_loop() -> None:
    """
    Background coroutine — sleeps for CLEANUP_INTERVAL_HOURS then runs cleanup,
    forever.  Start with asyncio.create_task() during app lifespan.
    """
    log.info(
        "Job cleanup loop started (retention=%d days, interval=%dh)",
        JOB_RETENTION_DAYS, CLEANUP_INTERVAL_HOURS,
    )
    while True:
        await asyncio.sleep(CLEANUP_INTERVAL_HOURS * 3_600)
        try:
            result = await cleanup_old_jobs()
            if result["deleted_jobs"] > 0:
                log.info("Scheduled cleanup complete: %s", result)
        except Exception as exc:
            log.error("Cleanup loop error: %s", exc, exc_info=True)


# ── GAP #16 — Timeout watchdog ──────────────────────────────────────────────
# Active-pipeline statuses that indicate a job is being processed by Claude.
# These statuses should not persist beyond STUCK_JOB_TIMEOUT_MINUTES.
_ACTIVE_STATUSES = {
    "parsing", "classifying", "documenting", "verifying",
    "assigning_stack", "converting", "security_scanning",
}
STUCK_JOB_TIMEOUT_MINUTES = int(getattr(_cfg, "stuck_job_timeout_minutes", 45))
WATCHDOG_POLL_SECONDS = 60   # check every minute


async def _watchdog_tick() -> int:
    """Mark jobs stuck in active statuses for longer than the timeout as FAILED.
    Returns the number of jobs timed out."""
    from .db.database import DB_PATH
    import aiosqlite
    from datetime import datetime, timedelta

    cutoff = (datetime.utcnow() - timedelta(minutes=STUCK_JOB_TIMEOUT_MINUTES)).isoformat()
    timed_out = 0
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        placeholders = ",".join("?" for _ in _ACTIVE_STATUSES)
        async with db.execute(
            f"SELECT job_id, status, updated_at FROM jobs "
            f"WHERE status IN ({placeholders}) AND updated_at < ? AND deleted_at IS NULL",
            (*_ACTIVE_STATUSES, cutoff),
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]

        now = datetime.utcnow().isoformat()
        for row in rows:
            log.warning(
                "Watchdog: job %s stuck in status '%s' since %s (>%dm) — marking FAILED",
                row["job_id"], row["status"], row["updated_at"], STUCK_JOB_TIMEOUT_MINUTES,
            )
            await db.execute(
                "UPDATE jobs SET status='failed', updated_at=?, "
                "state_json=state_json WHERE job_id=?",
                (now, row["job_id"]),
            )
            timed_out += 1
        if timed_out:
            await db.commit()
    return timed_out


async def run_watchdog_loop() -> None:
    """
    GAP #16 — Background watchdog that kills jobs stuck in active statuses.
    Polls every WATCHDOG_POLL_SECONDS, marks jobs FAILED after
    STUCK_JOB_TIMEOUT_MINUTES of no state updates.
    Start with asyncio.create_task() during app lifespan.
    """
    log.info(
        "Stuck-job watchdog started (timeout=%dm, poll=%ds)",
        STUCK_JOB_TIMEOUT_MINUTES, WATCHDOG_POLL_SECONDS,
    )
    while True:
        await asyncio.sleep(WATCHDOG_POLL_SECONDS)
        try:
            n = await _watchdog_tick()
            if n:
                log.warning("Watchdog timed out %d stuck job(s)", n)
        except Exception as exc:
            log.error("Watchdog loop error: %s", exc, exc_info=True)
