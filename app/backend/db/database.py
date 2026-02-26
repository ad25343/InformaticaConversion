"""
SQLite database layer — stores job state as JSON blobs.
Simple and portable for MVP. Swap to Postgres by changing DATABASE_URL.
"""
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List

import aiosqlite

import os
import tempfile

# Use DB_PATH env var if set, otherwise default to system temp dir.
# (Mounted/network filesystems often don't support SQLite file locking.)
_default_db = Path(tempfile.gettempdir()) / "informatica_converter" / "jobs.db"
DB_PATH = Path(os.environ.get("DB_PATH", str(_default_db)))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id                  TEXT PRIMARY KEY,
    filename                TEXT NOT NULL,
    xml_content             TEXT,
    workflow_xml_content    TEXT,
    parameter_file_content  TEXT,
    status                  TEXT NOT NULL DEFAULT 'pending',
    current_step            INTEGER NOT NULL DEFAULT 0,
    state_json              TEXT NOT NULL DEFAULT '{}',
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    batch_id                TEXT
);
"""

CREATE_BATCH_TABLE = """
CREATE TABLE IF NOT EXISTS batches (
    batch_id        TEXT PRIMARY KEY,
    source_zip      TEXT NOT NULL,
    mapping_count   INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
"""

# Columns added in v1.1 — applied via ALTER TABLE so existing DBs keep working
_V1_1_MIGRATIONS = [
    "ALTER TABLE jobs ADD COLUMN workflow_xml_content   TEXT",
    "ALTER TABLE jobs ADD COLUMN parameter_file_content TEXT",
]

# Columns / tables added in v2.0 — batch conversion support
_V2_0_MIGRATIONS = [
    "ALTER TABLE jobs ADD COLUMN batch_id TEXT",
    CREATE_BATCH_TABLE.strip(),
]


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(CREATE_TABLE)
        await db.execute(CREATE_BATCH_TABLE)
        # Apply v1.1 migrations idempotently — SQLite raises OperationalError
        # "duplicate column name" if column already exists; we swallow that.
        for sql in _V1_1_MIGRATIONS:
            try:
                await db.execute(sql)
            except Exception:
                pass  # column already present
        # Apply v2.0 migrations idempotently
        for sql in _V2_0_MIGRATIONS:
            try:
                await db.execute(sql)
            except Exception:
                pass  # column/table already present
        await db.commit()


async def create_job(
    filename: str,
    xml_content: str,
    workflow_xml_content: Optional[str] = None,
    parameter_file_content: Optional[str] = None,
    batch_id: Optional[str] = None,
) -> str:
    job_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO jobs "
            "(job_id, filename, xml_content, workflow_xml_content, parameter_file_content, "
            " status, current_step, state_json, created_at, updated_at, batch_id) "
            "VALUES (?, ?, ?, ?, ?, 'pending', 0, '{}', ?, ?, ?)",
            (job_id, filename, xml_content, workflow_xml_content, parameter_file_content, now, now, batch_id),
        )
        await db.commit()
    return job_id


async def get_job(job_id: str) -> Optional[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)) as cur:
            row = await cur.fetchone()
            if not row:
                return None
            d = dict(row)
            d["state"] = json.loads(d["state_json"])
            return d


async def get_xml(job_id: str) -> Optional[str]:
    """Return only the primary mapping XML (backward-compatible)."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT xml_content FROM jobs WHERE job_id = ?", (job_id,)) as cur:
            row = await cur.fetchone()
            return row[0] if row else None


async def get_session_files(job_id: str) -> Optional[dict]:
    """Return all three file contents for v1.1 Step 0.

    Returns a dict with keys:
      - xml_content             (mapping XML — always present)
      - workflow_xml_content    (workflow XML — may be None)
      - parameter_file_content  (parameter file — may be None)
    Returns None if the job does not exist.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT xml_content, workflow_xml_content, parameter_file_content "
            "FROM jobs WHERE job_id = ?",
            (job_id,),
        ) as cur:
            row = await cur.fetchone()
            if not row:
                return None
            return {
                "xml_content":            row[0],
                "workflow_xml_content":   row[1],
                "parameter_file_content": row[2],
            }


async def update_job(job_id: str, status: str, step: int, state_patch: dict):
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT state_json FROM jobs WHERE job_id = ?", (job_id,)) as cur:
            row = await cur.fetchone()
            current = json.loads(row[0]) if row else {}
        current.update(state_patch)
        await db.execute(
            "UPDATE jobs SET status=?, current_step=?, state_json=?, updated_at=? WHERE job_id=?",
            (status, step, json.dumps(current), now, job_id),
        )
        await db.commit()


async def create_batch(source_zip: str, mapping_count: int) -> str:
    """Create a batch record and return its batch_id."""
    batch_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO batches (batch_id, source_zip, mapping_count, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (batch_id, source_zip, mapping_count, now, now),
        )
        await db.commit()
    return batch_id


async def get_batch(batch_id: str) -> Optional[dict]:
    """Return the batch record (without jobs). Returns None if not found."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM batches WHERE batch_id = ?", (batch_id,)
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def get_batch_jobs(batch_id: str) -> List[dict]:
    """Return all jobs belonging to a batch, minimal fields only."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT job_id, filename, status, current_step, created_at, updated_at, state_json "
            "FROM jobs WHERE batch_id = ? ORDER BY created_at ASC",
            (batch_id,),
        ) as cur:
            rows = await cur.fetchall()
            result = []
            for row in rows:
                d = dict(row)
                state = json.loads(d.pop("state_json", "{}"))
                d["complexity"] = state.get("complexity", {}).get("tier") if state.get("complexity") else None
                d["batch_id"] = batch_id
                result.append(d)
            return result


async def delete_job(job_id: str) -> bool:
    """Delete a job record and its XML content. Returns True if a row was deleted."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM jobs WHERE job_id = ?", (job_id,))
        await db.commit()
        return db.total_changes > 0


async def recover_stuck_jobs() -> List[str]:
    """
    Mark jobs that were left in mid-pipeline states as FAILED.

    Called once at startup.  Any job whose status is a transient processing
    state (parsing, classifying, documenting, verifying, converting) will
    never complete after a server restart because its asyncio task is gone.
    Marking them FAILED makes the UI show an actionable state (delete + retry)
    rather than a spinner that never resolves.

    Returns the list of job_ids that were recovered.
    """
    # Statuses that represent in-flight pipeline work (not terminal, not gates)
    _STUCK_STATUSES = (
        "parsing", "classifying", "documenting", "verifying", "converting",
    )
    placeholders = ",".join("?" * len(_STUCK_STATUSES))
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT job_id FROM jobs WHERE status IN ({placeholders})",
            _STUCK_STATUSES,
        ) as cur:
            rows = await cur.fetchall()
        job_ids = [row["job_id"] for row in rows]
        if job_ids:
            state_patch_json = json.dumps({
                "error": (
                    "Job was interrupted by a server restart while the pipeline was running. "
                    "Delete this job and re-upload the mapping to start a fresh conversion."
                )
            })
            for job_id in job_ids:
                await db.execute(
                    "UPDATE jobs SET status='failed', state_json=?, updated_at=? "
                    "WHERE job_id=?",
                    (state_patch_json, now, job_id),
                )
            await db.commit()
    return job_ids


async def list_jobs() -> List[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT job_id, filename, status, current_step, created_at, updated_at, state_json, batch_id "
            "FROM jobs ORDER BY created_at DESC LIMIT 50"
        ) as cur:
            rows = await cur.fetchall()
            result = []
            for row in rows:
                d = dict(row)
                state = json.loads(d.pop("state_json", "{}"))
                d["complexity"] = state.get("complexity", {}).get("tier") if state.get("complexity") else None
                result.append(d)
            return result
