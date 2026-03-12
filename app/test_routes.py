"""
API route tests using FastAPI TestClient.

No live server needed — all tests run in-process.
No ANTHROPIC_API_KEY needed — pipeline is not triggered (jobs are created
but the orchestrator background task is not awaited).

Run:  python3 test_routes.py [-v]
"""
import asyncio
import io
import os
import sys
import unittest
from pathlib import Path

# ── env before backend imports ─────────────────────────────────────────────────
os.environ["SECRET_KEY"]   = "test-route-secret-key-32-chars!!"
os.environ["APP_PASSWORD"] = "route-test-password"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///test_routes_tmp.db"

sys.path.insert(0, str(Path(__file__).parent))

from fastapi.testclient import TestClient

# Build the app (mirrors main.py but without the lifespan startup overhead)
from backend.config  import settings
from backend.routes  import router
from backend.auth    import (
    create_session_token, check_password,
    COOKIE_NAME, is_authenticated,
)
from backend.limiter import jobs_limiter, login_limiter, RateLimiter

import fastapi
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ── Minimal test app (no lifespan so DB init doesn't block) ───────────────────
_test_app = FastAPI(title="ICT Test")
_test_app.include_router(router)


@_test_app.middleware("http")
async def _auth_middleware(request: fastapi.Request, call_next):
    """Mirrors the auth guard in main.py for protected-route tests."""
    public = {"/api/health", "/login", "/favicon.ico"}
    if request.url.path in public or request.url.path.startswith("/static"):
        return await call_next(request)
    if not is_authenticated(request):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    return await call_next(request)


# ── Initialise the test DB once ────────────────────────────────────────────────
async def _init():
    from backend.db.database import init_db
    await init_db()


asyncio.get_event_loop().run_until_complete(_init())

# ── Shared sample XML ──────────────────────────────────────────────────────────
SAMPLE_XML = (
    Path(__file__).parent / "sample_xml" / "sample_mapping.xml"
).read_bytes()

MINIMAL_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<POWERMART CREATION_DATE="01/01/2024" REPOSITORY_NAME="TEST">
  <REPOSITORY NAME="TEST">
    <FOLDER NAME="TEST">
      <MAPPING NAME="m_TEST_MAPPING" ISVALID="YES">
        <TRANSFORMATION NAME="SQ_SOURCE" TYPE="Source Qualifier"/>
      </MAPPING>
    </FOLDER>
  </REPOSITORY>
</POWERMART>
"""


def _auth_cookie() -> dict:
    """Return a cookie dict for an authenticated session."""
    return {COOKIE_NAME: create_session_token()}


# ══════════════════════════════════════════════════════════════════════════════
# 1. Health check
# ══════════════════════════════════════════════════════════════════════════════

class TestHealthCheck(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(_test_app, raise_server_exceptions=False)

    def test_health_returns_200(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)

    def test_health_body_structure(self):
        r = self.client.get("/api/health")
        body = r.json()
        self.assertIn("status",          body)
        self.assertIn("version",         body)
        self.assertIn("uptime_seconds",  body)

    def test_health_version_is_string(self):
        r = self.client.get("/api/health")
        self.assertIsInstance(r.json()["version"], str)
        self.assertTrue(r.json()["version"].startswith("2."))

    def test_health_no_auth_needed(self):
        """Health check must be publicly accessible (used by load balancers)."""
        r = self.client.get("/api/health")
        self.assertNotEqual(r.status_code, 401)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Auth — protected routes
# ══════════════════════════════════════════════════════════════════════════════

class TestAuthMiddleware(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(_test_app, raise_server_exceptions=False)

    def test_protected_route_without_cookie_returns_401(self):
        r = self.client.get("/api/jobs")
        self.assertEqual(r.status_code, 401)

    def test_protected_route_with_valid_cookie_passes_auth(self):
        r = self.client.get("/api/jobs", cookies=_auth_cookie())
        # 200 or 404 are both fine — 401 is not
        self.assertNotEqual(r.status_code, 401)

    def test_tampered_cookie_returns_401(self):
        bad_cookie = {COOKIE_NAME: "tampered.token.value"}
        r = self.client.get("/api/jobs", cookies=bad_cookie)
        self.assertEqual(r.status_code, 401)

    def test_health_accessible_without_auth(self):
        r = self.client.get("/api/health")
        self.assertNotEqual(r.status_code, 401)


# ══════════════════════════════════════════════════════════════════════════════
# 3. Job creation — validation
# ══════════════════════════════════════════════════════════════════════════════

class TestJobCreation(unittest.TestCase):

    def setUp(self):
        self.client  = TestClient(_test_app, raise_server_exceptions=False)
        self.cookies = _auth_cookie()

    def test_create_job_with_valid_xml_returns_200(self):
        r = self.client.post(
            "/api/jobs",
            files={"file": ("test.xml", io.BytesIO(SAMPLE_XML), "text/xml")},
            cookies=self.cookies,
        )
        self.assertIn(r.status_code, (200, 202))

    def test_create_job_returns_job_id(self):
        r = self.client.post(
            "/api/jobs",
            files={"file": ("test.xml", io.BytesIO(SAMPLE_XML), "text/xml")},
            cookies=self.cookies,
        )
        body = r.json()
        self.assertIn("job_id", body)
        self.assertRegex(
            body["job_id"],
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        )

    def test_create_job_with_non_xml_extension_returns_400(self):
        r = self.client.post(
            "/api/jobs",
            files={"file": ("mapping.csv", io.BytesIO(b"a,b,c"), "text/plain")},
            cookies=self.cookies,
        )
        self.assertEqual(r.status_code, 400)

    def test_create_job_with_empty_file_returns_400(self):
        r = self.client.post(
            "/api/jobs",
            files={"file": ("empty.xml", io.BytesIO(b""), "text/xml")},
            cookies=self.cookies,
        )
        self.assertEqual(r.status_code, 400)

    def test_create_job_with_non_xml_content_returns_400(self):
        r = self.client.post(
            "/api/jobs",
            files={"file": ("fake.xml", io.BytesIO(b"not xml content"), "text/xml")},
            cookies=self.cookies,
        )
        self.assertEqual(r.status_code, 400)

    def test_create_job_without_auth_returns_401(self):
        r = self.client.post(
            "/api/jobs",
            files={"file": ("test.xml", io.BytesIO(MINIMAL_XML), "text/xml")},
        )
        self.assertEqual(r.status_code, 401)

    def test_create_job_with_minimal_valid_xml(self):
        r = self.client.post(
            "/api/jobs",
            files={"file": ("minimal.xml", io.BytesIO(MINIMAL_XML), "text/xml")},
            cookies=self.cookies,
        )
        self.assertIn(r.status_code, (200, 202))


# ══════════════════════════════════════════════════════════════════════════════
# 4. Job ID validation
# ══════════════════════════════════════════════════════════════════════════════

class TestJobIdValidation(unittest.TestCase):

    def setUp(self):
        self.client  = TestClient(_test_app, raise_server_exceptions=False)
        self.cookies = _auth_cookie()

    def test_valid_uuid_accepted(self):
        """A properly formatted UUID should pass ID validation (may 404 if job not found)."""
        r = self.client.get(
            "/api/jobs/00000000-0000-0000-0000-000000000000",
            cookies=self.cookies,
        )
        # 404 (job not found) is OK; 400 (bad format) is not
        self.assertNotEqual(r.status_code, 400)

    def test_path_traversal_job_id_rejected(self):
        r = self.client.get(
            "/api/jobs/../../../etc/passwd",
            cookies=self.cookies,
        )
        self.assertIn(r.status_code, (400, 404, 422))

    def test_sql_injection_job_id_rejected(self):
        r = self.client.get(
            "/api/jobs/1; DROP TABLE jobs; --",
            cookies=self.cookies,
        )
        self.assertIn(r.status_code, (400, 404, 422))

    def test_short_garbage_job_id_rejected(self):
        r = self.client.get(
            "/api/jobs/notauuid",
            cookies=self.cookies,
        )
        self.assertIn(r.status_code, (400, 422))


# ══════════════════════════════════════════════════════════════════════════════
# 5. Content-type enforcement
# ══════════════════════════════════════════════════════════════════════════════

class TestContentTypeEnforcement(unittest.TestCase):

    def setUp(self):
        self.client  = TestClient(_test_app, raise_server_exceptions=False)
        self.cookies = _auth_cookie()

    def test_pdf_content_type_rejected(self):
        r = self.client.post(
            "/api/jobs",
            files={"file": ("mapping.xml", io.BytesIO(b"%PDF-1.4"), "application/pdf")},
            cookies=self.cookies,
        )
        self.assertEqual(r.status_code, 415)

    def test_octet_stream_accepted(self):
        """Clients sending application/octet-stream for XML should be allowed."""
        r = self.client.post(
            "/api/jobs",
            files={"file": ("test.xml", io.BytesIO(MINIMAL_XML), "application/octet-stream")},
            cookies=self.cookies,
        )
        self.assertIn(r.status_code, (200, 202))


# ══════════════════════════════════════════════════════════════════════════════
# 6. Rate limiter — unit-level (not via HTTP to avoid flakiness)
# ══════════════════════════════════════════════════════════════════════════════

class TestRateLimiterIntegration(unittest.TestCase):
    """
    Tests the RateLimiter class in isolation rather than through HTTP
    to avoid test-order flakiness from the shared singleton instances.
    """

    def _make_req(self, ip="10.0.0.99"):
        from unittest.mock import MagicMock
        req = MagicMock()
        req.client.host = ip
        return req

    def test_limiter_allows_burst_then_blocks(self):
        from fastapi import HTTPException
        limiter = RateLimiter("3/minute")
        req = self._make_req()
        for _ in range(3):
            asyncio.get_event_loop().run_until_complete(limiter(req))
        with self.assertRaises(HTTPException) as ctx:
            asyncio.get_event_loop().run_until_complete(limiter(req))
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertIn("Rate limit exceeded", ctx.exception.detail)

    def test_login_limiter_is_stricter_than_jobs_limiter(self):
        """login_limiter (5/min) should have a lower max than jobs_limiter (20/min)."""
        self.assertLess(login_limiter.max_calls, jobs_limiter.max_calls)

    def test_limiter_detail_message_contains_limit_info(self):
        from fastapi import HTTPException
        limiter = RateLimiter("1/minute")
        req = self._make_req(ip="192.168.1.200")
        asyncio.get_event_loop().run_until_complete(limiter(req))
        with self.assertRaises(HTTPException) as ctx:
            asyncio.get_event_loop().run_until_complete(limiter(req))
        self.assertIn("1", ctx.exception.detail)


# ══════════════════════════════════════════════════════════════════════════════
# 7. Gate review queue — GET /api/gates/pending
# ══════════════════════════════════════════════════════════════════════════════

def _insert_gate_jobs_sync() -> dict:
    """
    Insert one job at each gate status into the test DB and return their IDs.
    Called once before TestGatesPending / TestBatchSignoff tests run.
    """
    import uuid
    from datetime import datetime, timezone
    from backend.db.database import _connect

    now = datetime.now(timezone.utc).isoformat()
    ids: dict[str, str] = {}

    async def _run():
        async with _connect() as conn:
            for status in ("awaiting_review", "awaiting_sec_review", "awaiting_code_review"):
                jid = str(uuid.uuid4())
                await conn.execute(
                    "INSERT INTO jobs "
                    "(job_id, filename, xml_content, status, current_step, "
                    " state_json, created_at, updated_at, batch_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (jid, f"gate_test_{status}.xml", "<x/>", status, 5,
                     "{}", now, now, "batch-gate-test"),
                )
                ids[status] = jid
            await conn.commit()

    asyncio.get_event_loop().run_until_complete(_run())
    return ids


# Inserted once; shared across both gate test classes.
_GATE_JOB_IDS = _insert_gate_jobs_sync()


class TestGatesPending(unittest.TestCase):

    def setUp(self):
        self.client  = TestClient(_test_app, raise_server_exceptions=False)
        self.cookies = _auth_cookie()

    def test_requires_auth(self):
        r = self.client.get("/api/gates/pending")
        self.assertEqual(r.status_code, 401)

    def test_returns_200_with_auth(self):
        r = self.client.get("/api/gates/pending", cookies=self.cookies)
        self.assertEqual(r.status_code, 200)

    def test_response_top_level_keys(self):
        r = self.client.get("/api/gates/pending", cookies=self.cookies)
        body = r.json()
        for key in ("total", "by_gate", "jobs"):
            self.assertIn(key, body)

    def test_by_gate_has_three_keys(self):
        r = self.client.get("/api/gates/pending", cookies=self.cookies)
        by_gate = r.json()["by_gate"]
        self.assertEqual(len(by_gate), 3)

    def test_total_matches_jobs_list_length(self):
        r = self.client.get("/api/gates/pending", cookies=self.cookies)
        body = r.json()
        self.assertEqual(body["total"], len(body["jobs"]))

    def test_gate_filter_returns_only_that_gate(self):
        r = self.client.get("/api/gates/pending?gate=1", cookies=self.cookies)
        self.assertEqual(r.status_code, 200)
        for job in r.json()["jobs"]:
            self.assertEqual(job["gate"], 1)

    def test_gate_filter_gate2(self):
        r = self.client.get("/api/gates/pending?gate=2", cookies=self.cookies)
        self.assertEqual(r.status_code, 200)
        for job in r.json()["jobs"]:
            self.assertEqual(job["gate"], 2)

    def test_gate_filter_gate3(self):
        r = self.client.get("/api/gates/pending?gate=3", cookies=self.cookies)
        self.assertEqual(r.status_code, 200)
        for job in r.json()["jobs"]:
            self.assertEqual(job["gate"], 3)

    def test_invalid_gate_returns_400(self):
        r = self.client.get("/api/gates/pending?gate=99", cookies=self.cookies)
        self.assertEqual(r.status_code, 400)

    def test_batch_id_filter(self):
        r = self.client.get(
            "/api/gates/pending?batch_id=batch-gate-test", cookies=self.cookies
        )
        self.assertEqual(r.status_code, 200)
        for job in r.json()["jobs"]:
            self.assertEqual(job["batch_id"], "batch-gate-test")

    def test_unknown_batch_id_returns_empty(self):
        r = self.client.get(
            "/api/gates/pending?batch_id=no-such-batch", cookies=self.cookies
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["total"], 0)

    def test_job_entry_required_fields(self):
        r = self.client.get("/api/gates/pending?gate=1", cookies=self.cookies)
        jobs = r.json()["jobs"]
        self.assertTrue(len(jobs) >= 1, "Expected at least one job at gate 1")
        job = jobs[0]
        for field in ("job_id", "filename", "gate", "waiting_since", "waiting_minutes"):
            self.assertIn(field, job)

    def test_waiting_minutes_is_non_negative(self):
        r = self.client.get("/api/gates/pending", cookies=self.cookies)
        for job in r.json()["jobs"]:
            self.assertGreaterEqual(job["waiting_minutes"], 0)


# ══════════════════════════════════════════════════════════════════════════════
# 8. Batch gate sign-off — POST /api/gates/batch-signoff
# ══════════════════════════════════════════════════════════════════════════════

class TestBatchSignoff(unittest.TestCase):

    def setUp(self):
        self.client  = TestClient(_test_app, raise_server_exceptions=False)
        self.cookies = _auth_cookie()

    def _base_payload(self, **overrides):
        payload = {
            "job_ids": [_GATE_JOB_IDS["awaiting_code_review"]],
            "gate": 3,
            "decision": "REJECTED",   # REJECT at gate 3 → blocked (no pipeline resume)
            "reviewer_name": "Test Reviewer",
            "reviewer_role": "QA Engineer",
            "notes": "batch signoff test",
        }
        payload.update(overrides)
        return payload

    def test_requires_auth(self):
        r = self.client.post("/api/gates/batch-signoff", json=self._base_payload())
        self.assertEqual(r.status_code, 401)

    def test_invalid_gate_returns_400(self):
        r = self.client.post(
            "/api/gates/batch-signoff",
            json=self._base_payload(gate=99, job_ids=[]),
            cookies=self.cookies,
        )
        self.assertEqual(r.status_code, 400)

    def test_invalid_decision_for_gate_returns_400(self):
        r = self.client.post(
            "/api/gates/batch-signoff",
            json=self._base_payload(gate=1, decision="INVALID_DECISION"),
            cookies=self.cookies,
        )
        self.assertEqual(r.status_code, 400)

    def test_nonexistent_job_goes_to_failed_list(self):
        fake_id = "00000000-0000-0000-0000-000000000000"
        r = self.client.post(
            "/api/gates/batch-signoff",
            json=self._base_payload(job_ids=[fake_id]),
            cookies=self.cookies,
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn(fake_id, body["failed"])
        self.assertIn(fake_id, body["errors"])

    def test_job_at_wrong_gate_goes_to_failed_list(self):
        # _GATE_JOB_IDS["awaiting_review"] is at gate 1; submit as gate 3 → error
        wrong_gate_id = _GATE_JOB_IDS["awaiting_review"]
        r = self.client.post(
            "/api/gates/batch-signoff",
            json=self._base_payload(
                job_ids=[wrong_gate_id], gate=3, decision="APPROVED"
            ),
            cookies=self.cookies,
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn(wrong_gate_id, body["failed"])

    def test_response_structure(self):
        r = self.client.post(
            "/api/gates/batch-signoff",
            json=self._base_payload(),
            cookies=self.cookies,
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        for key in ("succeeded", "failed", "errors"):
            self.assertIn(key, body)

    def test_valid_gate3_reject_succeeds(self):
        """Gate 3 REJECTED → job moved to blocked, no pipeline call needed."""
        import uuid
        from datetime import datetime, timezone
        from backend.db.database import _connect

        now = datetime.now(timezone.utc).isoformat()
        jid = str(uuid.uuid4())

        async def _insert():
            async with _connect() as conn:
                await conn.execute(
                    "INSERT INTO jobs "
                    "(job_id, filename, xml_content, status, current_step, "
                    " state_json, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (jid, "gate3_reject_test.xml", "<x/>",
                     "awaiting_code_review", 12, "{}", now, now),
                )
                await conn.commit()

        asyncio.get_event_loop().run_until_complete(_insert())

        r = self.client.post(
            "/api/gates/batch-signoff",
            json={
                "job_ids": [jid],
                "gate": 3,
                "decision": "REJECTED",
                "reviewer_name": "Tester",
                "reviewer_role": "QA",
            },
            cookies=self.cookies,
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn(jid, body["succeeded"])
        self.assertEqual(body["failed"], [])

    def test_valid_gate1_reject_moves_job_to_blocked(self):
        """Gate 1 REJECT → job goes to blocked, no pipeline call needed."""
        import uuid
        from datetime import datetime, timezone
        from backend.db.database import _connect

        now = datetime.now(timezone.utc).isoformat()
        jid = str(uuid.uuid4())

        async def _insert():
            async with _connect() as conn:
                await conn.execute(
                    "INSERT INTO jobs "
                    "(job_id, filename, xml_content, status, current_step, "
                    " state_json, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (jid, "gate1_reject_test.xml", "<x/>",
                     "awaiting_review", 5, "{}", now, now),
                )
                await conn.commit()

        asyncio.get_event_loop().run_until_complete(_insert())

        r = self.client.post(
            "/api/gates/batch-signoff",
            json={
                "job_ids": [jid],
                "gate": 1,
                "decision": "REJECT",
                "reviewer_name": "Tester",
                "reviewer_role": "QA",
            },
            cookies=self.cookies,
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn(jid, body["succeeded"])

        # Verify DB status is now blocked
        async def _check():
            from backend.db.database import get_job
            job = await get_job(jid)
            return job["status"]

        status = asyncio.get_event_loop().run_until_complete(_check())
        self.assertEqual(status, "blocked")

    def test_empty_job_ids_returns_empty_succeeded(self):
        r = self.client.post(
            "/api/gates/batch-signoff",
            json={
                "job_ids": [],
                "gate": 1,
                "decision": "APPROVE",
                "reviewer_name": "Tester",
                "reviewer_role": "QA",
            },
            cookies=self.cookies,
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["succeeded"], [])
        self.assertEqual(body["failed"], [])


# ══════════════════════════════════════════════════════════════════════════════
# 9. Migration progress — GET /api/progress
# ══════════════════════════════════════════════════════════════════════════════

class TestProgress(unittest.TestCase):

    def setUp(self):
        self.client  = TestClient(_test_app, raise_server_exceptions=False)
        self.cookies = _auth_cookie()

    def test_requires_auth(self):
        r = self.client.get("/api/progress")
        self.assertEqual(r.status_code, 401)

    def test_returns_200_with_auth(self):
        r = self.client.get("/api/progress", cookies=self.cookies)
        self.assertEqual(r.status_code, 200)

    def test_response_top_level_keys(self):
        r = self.client.get("/api/progress", cookies=self.cookies)
        body = r.json()
        expected = (
            "total", "not_started", "in_pipeline", "awaiting_gate",
            "complete", "blocked", "failed",
            "by_tier", "throughput_per_day", "as_of",
        )
        for key in expected:
            self.assertIn(key, body)

    def test_awaiting_gate_has_three_gate_keys(self):
        r = self.client.get("/api/progress", cookies=self.cookies)
        awaiting = r.json()["awaiting_gate"]
        for gate_key in ("1", "2", "3"):
            self.assertIn(gate_key, awaiting)

    def test_by_tier_has_expected_keys(self):
        r = self.client.get("/api/progress", cookies=self.cookies)
        by_tier = r.json()["by_tier"]
        for tier in ("LOW", "MEDIUM", "HIGH", "VERY_HIGH", "unknown"):
            self.assertIn(tier, by_tier)

    def test_counts_are_non_negative(self):
        r = self.client.get("/api/progress", cookies=self.cookies)
        body = r.json()
        for key in ("total", "not_started", "in_pipeline", "complete", "blocked", "failed"):
            self.assertGreaterEqual(body[key], 0)

    def test_status_sum_does_not_exceed_total(self):
        """
        The sum of all counted status buckets must be <= total.  Equality holds
        for clean DBs; the test permits a small gap for legacy/unknown statuses
        (e.g. 'awaiting_security_review' from pre-rename migrations) that the
        endpoint intentionally does not map to a bucket.
        """
        r = self.client.get("/api/progress", cookies=self.cookies)
        body = r.json()
        gate_total = sum(body["awaiting_gate"].values())
        status_sum = (
            body["not_started"] + body["in_pipeline"] + gate_total
            + body["complete"] + body["blocked"] + body["failed"]
        )
        total = body["total"]
        self.assertLessEqual(status_sum, total,
                             "Bucket sum exceeds total — overcounting detected")
        self.assertGreaterEqual(status_sum, total - 10,
                                "More than 10 jobs have unrecognised statuses")

    def test_throughput_per_day_is_numeric(self):
        r = self.client.get("/api/progress", cookies=self.cookies)
        self.assertIsInstance(r.json()["throughput_per_day"], (int, float))

    def test_as_of_ends_with_z(self):
        r = self.client.get("/api/progress", cookies=self.cookies)
        self.assertTrue(r.json()["as_of"].endswith("Z"))

    def test_estimated_completion_date_is_none_or_date_string(self):
        r = self.client.get("/api/progress", cookies=self.cookies)
        val = r.json().get("estimated_completion_date")
        if val is not None:
            import re
            self.assertRegex(val, r"^\d{4}-\d{2}-\d{2}$")


# ══════════════════════════════════════════════════════════════════════════════
# 10. Progress CSV export — GET /api/progress/export
# ══════════════════════════════════════════════════════════════════════════════

class TestProgressExport(unittest.TestCase):

    def setUp(self):
        self.client  = TestClient(_test_app, raise_server_exceptions=False)
        self.cookies = _auth_cookie()

    def test_requires_auth(self):
        r = self.client.get("/api/progress/export")
        self.assertEqual(r.status_code, 401)

    def test_returns_200_with_auth(self):
        r = self.client.get("/api/progress/export", cookies=self.cookies)
        self.assertEqual(r.status_code, 200)

    def test_content_type_is_csv(self):
        r = self.client.get("/api/progress/export", cookies=self.cookies)
        self.assertIn("text/csv", r.headers.get("content-type", ""))

    def test_content_disposition_header_present(self):
        r = self.client.get("/api/progress/export", cookies=self.cookies)
        disposition = r.headers.get("content-disposition", "")
        self.assertIn("attachment", disposition)
        self.assertIn("migration_progress_", disposition)
        self.assertIn(".csv", disposition)

    def test_csv_has_header_row(self):
        r = self.client.get("/api/progress/export", cookies=self.cookies)
        first_line = r.text.splitlines()[0]
        self.assertIn("job_id", first_line)
        self.assertIn("status", first_line)
        self.assertIn("filename", first_line)

    def test_csv_header_columns(self):
        r = self.client.get("/api/progress/export", cookies=self.cookies)
        header = r.text.splitlines()[0]
        expected_cols = (
            "job_id", "filename", "batch_id", "status",
            "complexity_tier", "created_at", "updated_at",
            "waiting_at_gate", "complete_at",
        )
        for col in expected_cols:
            self.assertIn(col, header)

    def test_csv_row_count_matches_job_count(self):
        """Number of data rows should equal number of jobs in the DB."""
        r_csv = self.client.get("/api/progress/export", cookies=self.cookies)
        r_jobs = self.client.get("/api/progress", cookies=self.cookies)
        csv_data_rows = len(r_csv.text.splitlines()) - 1   # subtract header
        total_jobs    = r_jobs.json()["total"]
        self.assertEqual(csv_data_rows, total_jobs)

    def test_filename_contains_timestamp(self):
        r = self.client.get("/api/progress/export", cookies=self.cookies)
        disposition = r.headers.get("content-disposition", "")
        import re
        self.assertRegex(disposition, r"\d{8}_\d{6}")


# ══════════════════════════════════════════════════════════════════════════════
# Runner
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    unittest.main(verbosity=2)
