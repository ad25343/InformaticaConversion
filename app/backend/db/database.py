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
    job_id       TEXT PRIMARY KEY,
    filename     TEXT NOT NULL,
    xml_content  TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',
    current_step INTEGER NOT NULL DEFAULT 0,
    state_json   TEXT NOT NULL DEFAULT '{}',
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
"""


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(CREATE_TABLE)
        await db.commit()


async def create_job(filename: str, xml_content: str) -> str:
    job_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO jobs (job_id, filename, xml_content, status, current_step, state_json, created_at, updated_at) "
            "VALUES (?, ?, ?, 'pending', 0, '{}', ?, ?)",
            (job_id, filename, xml_content, now, now),
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
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT xml_content FROM jobs WHERE job_id = ?", (job_id,)) as cur:
            row = await cur.fetchone()
            return row[0] if row else None


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


async def delete_job(job_id: str) -> bool:
    """Delete a job record and its XML content. Returns True if a row was deleted."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM jobs WHERE job_id = ?", (job_id,))
        await db.commit()
        return db.total_changes > 0


async def list_jobs() -> List[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT job_id, filename, status, current_step, created_at, updated_at, state_json "
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
