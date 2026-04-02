# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Informatica Conversion Tool — FastAPI Application Entry Point
"""
import asyncio
import logging
import os
import sys
import time
import urllib.parse
from pathlib import Path
from contextlib import asynccontextmanager

# etl_patterns lives at the repo root (one level above app/).
# Add it to sys.path so it is importable without a separate install step.
_REPO_ROOT = str(Path(__file__).parent.parent.resolve())
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from fastapi import Depends, FastAPI, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from dotenv import load_dotenv

load_dotenv()

from backend.config import settings as _cfg          # centralised config — must be first
from backend.db.database import init_db, DB_PATH
from backend.routes import router
from backend.logger import configure_app_logging
from backend.auth import (
    is_authenticated, check_password,
    create_session_token, COOKIE_NAME, SESSION_HOURS,
    SECRET_KEY,
)
from backend.limiter import login_limiter
from backend.cleanup import run_cleanup_loop, run_watchdog_loop

_startup_log = logging.getLogger("conversion.startup")
_log = logging.getLogger(__name__)

TEMPLATES = Path(__file__).parent / "frontend" / "templates"


_APP_START_TIME = time.monotonic()


# ── Lifespan helper functions ──────────────────────────────────────────────

def _check_secret_key() -> None:
    """Raise or warn if SECRET_KEY or APP_PASSWORD are misconfigured."""
    if SECRET_KEY == "change-me-in-production-please":
        if _cfg.app_password:
            raise RuntimeError(
                "FATAL: SECRET_KEY is the default insecure placeholder while "
                "APP_PASSWORD is set (production mode). Generate a strong key with:\n"
                "  python -c \"import secrets; print(secrets.token_hex(32))\"\n"
                "and set SECRET_KEY in your .env file. Refusing to start."
            )
        _startup_log.warning(
            "SECURITY WARNING: SECRET_KEY is the default insecure value. "
            "Set a strong random SECRET_KEY in your .env before any non-local deployment."
        )
    if not _cfg.app_password:
        _startup_log.warning(
            "SECURITY WARNING: APP_PASSWORD is not set. "
            "The application is running in open-access dev mode — all requests are unauthenticated. "
            "Set APP_PASSWORD in your .env for any non-local deployment."
        )


async def _recover_and_log_stuck_jobs() -> None:
    """Mark mid-pipeline jobs FAILED after a restart and log the result."""
    from backend.db.database import recover_stuck_jobs
    recovered = await recover_stuck_jobs()
    if recovered:
        _startup_log.warning(
            "Startup recovery: marked %d stuck job(s) as FAILED "
            "(were mid-pipeline when server last stopped). "
            "Delete and re-upload to retry.",
            len(recovered),
        )


async def _recover_and_log_batch_jobs() -> None:
    """Re-queue pending batch jobs and restore gate-waiting semaphore tracking."""
    from backend.routes import recover_batch_jobs as _recover_batch_jobs
    batch_recovery = await _recover_batch_jobs()
    if batch_recovery["requeued"]:
        _startup_log.info(
            "Startup recovery: re-queued %d pending batch job(s).",
            batch_recovery["requeued"],
        )
    if batch_recovery["gate_restored"]:
        _startup_log.info(
            "Startup recovery: restored semaphore tracking for %d gate-waiting batch job(s).",
            batch_recovery["gate_restored"],
        )


async def _probe_anthropic_api() -> None:
    """Check the configured model and API key are valid; log any issues."""
    try:
        import anthropic as _anthropic
        _probe = _anthropic.AsyncAnthropic(api_key=_cfg.anthropic_api_key)
        await _probe.messages.create(
            model=_cfg.claude_model, max_tokens=1,
            messages=[{"role": "user", "content": "ping"}],
        )
    except _anthropic.NotFoundError:
        _startup_log.error(
            "MODEL DEPRECATED: '%s' returned 404 — update claude_model in .env "
            "to a current model string. All jobs will fail until this is fixed.",
            _cfg.claude_model,
        )
    except _anthropic.AuthenticationError:
        _startup_log.error(
            "API KEY INVALID: Anthropic rejected the key in ANTHROPIC_API_KEY. "
            "All jobs will fail until a valid key is provided in .env."
        )
    except _anthropic.PermissionDeniedError:
        _startup_log.error(
            "API PERMISSION DENIED: the configured API key lacks required access. "
            "All jobs will fail until key permissions are corrected."
        )
    except Exception as _probe_exc:
        _startup_log.warning(
            "Startup API probe inconclusive (%s: %s) — will retry on first job.",
            type(_probe_exc).__name__, str(_probe_exc)[:120],
        )


def _maybe_start_watcher(bg_tasks: list) -> None:
    """Start the manifest file-watcher background task if configured."""
    if _cfg.watcher_enabled:
        if not _cfg.watcher_dir:
            _startup_log.error(
                "Watcher: WATCHER_ENABLED=true but WATCHER_DIR is not set — "
                "file watcher will NOT start.  Set WATCHER_DIR in .env."
            )
            return
        from backend.watcher import run_watcher_loop
        _bg_watcher = asyncio.create_task(
            run_watcher_loop(
                watch_dir=_cfg.watcher_dir,
                poll_interval=_cfg.watcher_poll_interval_secs,
                incomplete_ttl=_cfg.watcher_incomplete_ttl_secs,
            )
        )
        _bg_watcher.set_name("manifest_watcher")
        bg_tasks.append(_bg_watcher)
        _startup_log.info(
            "Watcher: monitoring %s every %ds for manifest files.",
            _cfg.watcher_dir,
            _cfg.watcher_poll_interval_secs,
        )
    else:
        _startup_log.info(
            "Watcher: disabled (set WATCHER_ENABLED=true and WATCHER_DIR "
            "in .env to enable scheduled ingestion)."
        )


def _maybe_start_scheduler(bg_tasks: list) -> None:
    """Start the time-based manifest scheduler background task if configured."""
    if not _cfg.scheduler_enabled:
        _startup_log.info(
            "Scheduler: disabled (set SCHEDULER_ENABLED=true, SCHEDULER_DIR, "
            "WATCHER_ENABLED=true, and WATCHER_DIR in .env to enable "
            "time-based scheduled ingestion)."
        )
        return
    if not _cfg.scheduler_dir:
        _startup_log.error(
            "Scheduler: SCHEDULER_ENABLED=true but SCHEDULER_DIR is not set — "
            "scheduler will NOT start.  Set SCHEDULER_DIR in .env."
        )
        return
    if not _cfg.watcher_enabled or not _cfg.watcher_dir:
        _startup_log.error(
            "Scheduler: SCHEDULER_ENABLED=true but WATCHER_ENABLED is false or "
            "WATCHER_DIR is not set.  The scheduler materialises manifests into "
            "WATCHER_DIR, which must also be configured.  Scheduler will NOT start."
        )
        return
    from backend.scheduler import run_scheduler_loop
    _bg_scheduler = asyncio.create_task(
        run_scheduler_loop(
            schedule_dir=_cfg.scheduler_dir,
            watcher_dir=_cfg.watcher_dir,
            poll_interval=_cfg.scheduler_poll_interval_secs,
        )
    )
    _bg_scheduler.set_name("manifest_scheduler")
    bg_tasks.append(_bg_scheduler)
    _startup_log.info(
        "Scheduler: monitoring %s every %ds for schedule files.",
        _cfg.scheduler_dir,
        _cfg.scheduler_poll_interval_secs,
    )


async def _shutdown_bg_tasks(bg_tasks: list) -> None:
    """Cancel and await all background loop tasks."""
    for _bg in bg_tasks:
        _bg.cancel()
    await asyncio.gather(*bg_tasks, return_exceptions=True)
    _startup_log.info("Shutdown: background loops cancelled.")


async def _shutdown_pipeline_tasks() -> None:
    """Cancel any in-flight pipeline tasks so they don't outlive the process."""
    from backend.routes import _active_tasks
    if not _active_tasks:
        return
    _startup_log.info("Shutdown: cancelling %d active pipeline task(s)…", len(_active_tasks))
    for _task in list(_active_tasks.values()):
        _task.cancel()
    await asyncio.gather(*_active_tasks.values(), return_exceptions=True)
    _startup_log.info("Shutdown: all pipeline tasks cancelled.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_app_logging(_cfg.log_level)
    await init_db()

    _check_secret_key()
    await _recover_and_log_stuck_jobs()
    await _recover_and_log_batch_jobs()
    await _probe_anthropic_api()

    _bg_cleanup = asyncio.create_task(run_cleanup_loop())
    _bg_cleanup.set_name("cleanup_loop")
    _bg_watchdog = asyncio.create_task(run_watchdog_loop())
    _bg_watchdog.set_name("watchdog_loop")
    _bg_tasks = [_bg_cleanup, _bg_watchdog]

    _maybe_start_watcher(_bg_tasks)
    _maybe_start_scheduler(_bg_tasks)

    yield

    await _shutdown_bg_tasks(_bg_tasks)
    await _shutdown_pipeline_tasks()


app = FastAPI(
    title="Informatica Conversion Tool",
    description="Converts Informatica PowerCenter mappings to Python, PySpark, or dbt",
    version=_cfg.app_version,
    lifespan=lifespan,
    # Hide docs behind auth in production — set SHOW_DOCS=false in .env
    docs_url="/docs" if _cfg.show_docs else None,
    redoc_url=None,
)

# ── CORS — restrict to same-origin by default ────────────
# Allow additional origins via CORS_ORIGINS="https://your.domain,https://other.domain"
_cors_origins_env = _cfg.cors_origins
_allowed_origins: list[str] = (
    [o.strip() for o in _cors_origins_env.split(",") if o.strip()]
    if _cors_origins_env
    else []  # empty → same-origin only (browser enforces; no CORS headers emitted)
)
if _allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type", "Authorization"],
    )
    _startup_log.info("CORS enabled for origins: %s", _allowed_origins)
else:
    _startup_log.info("CORS: same-origin only (CORS_ORIGINS not set; no cross-origin headers emitted)")

# ── Static files (always public — just CSS/JS assets) ────
static_dir = Path(__file__).parent / "frontend" / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# ── Login page ────────────────────────────────────────────
@app.get("/login")
async def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse("/", status_code=302)
    return FileResponse(str(TEMPLATES / "login.html"))


@app.get("/health")
async def health_check():
    """Lightweight health check — used by load balancers and uptime monitors."""
    import aiosqlite
    db_ok = False
    try:
        async with aiosqlite.connect(DB_PATH) as conn:
            await conn.execute("SELECT 1")
        db_ok = True
    except Exception as exc:
        _log.warning("Health check: DB connectivity failure (%s: %s)", type(exc).__name__, exc)
    return JSONResponse({
        "status":         "ok" if db_ok else "degraded",
        "version":        _cfg.app_version,
        "uptime_seconds": round(time.monotonic() - _APP_START_TIME, 1),
        "db":             "ok" if db_ok else "error",
    }, status_code=200 if db_ok else 503)


_VALID_PERSONAS = {
    "Priya Nair",
    "Alex Rivera",
    "Sarah Chen",
    "James Park",
    "Maya Patel",
}

@app.post("/login")
async def login_submit(
    request: Request,
    password: str = Form(...),
    persona:  str = Form(default=""),
):
    # Check failed-attempt rate limit before processing (successful logins never count)
    await login_limiter.check(request)

    if check_password(password):
        token = create_session_token()
        response = RedirectResponse("/", status_code=302)
        response.set_cookie(
            key=COOKIE_NAME,
            value=token,
            httponly=True,
            samesite="lax",
            max_age=SESSION_HOURS * 3600,
            secure=_cfg.https,
        )
        # Store persona in a JS-readable cookie (not httponly) so the UI can
        # display the current user's name without a round-trip.
        safe_persona = persona.strip() if persona.strip() in _VALID_PERSONAS else "User"
        response.set_cookie(
            key="persona",
            value=urllib.parse.quote(safe_persona),  # URL-encode to avoid RFC-2109 auto-quoting of spaces
            httponly=False,      # readable by JS
            samesite="lax",
            max_age=SESSION_HOURS * 3600,
            secure=_cfg.https,
        )
        return response

    # Wrong password — record this failure toward the rate limit
    await login_limiter.record_failure(request)
    return RedirectResponse("/login?error=1", status_code=302)


@app.get("/logout")
async def logout():
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie(COOKIE_NAME)
    response.delete_cookie("persona")
    return response


# ── HTTP Security Headers ─────────────────────────────────
# Applied to every response before auth enforcement so that even error pages
# and unauthenticated redirects are hardened.
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    # Prevent browsers from MIME-sniffing responses away from the declared content-type
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Block this app from being embedded in an <iframe> on other origins (clickjacking)
    response.headers["X-Frame-Options"] = "DENY"
    # Stop legacy IE/Edge XSS auditor from mangling content; modern browsers ignore this
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Only send the origin (no path) in the Referer header when navigating cross-origin
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Restrict permissions for browser APIs — no geolocation, camera, or microphone
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    # Content Security Policy — tightened for a tool that serves no third-party content
    # 'unsafe-inline' kept for styles/scripts because the SPA uses inline event handlers.
    # Tighten further (nonce/hash) once the front-end is refactored to avoid inline JS.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    # Force HTTPS for 1 year when the tool is deployed with TLS (HTTPS=true in .env)
    if _cfg.https:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


# ── Protected API routes ──────────────────────────────────

_PUBLIC_EXACT  = frozenset({"/health", "/api/health", "/favicon.ico"})
_PUBLIC_PREFIX = ("/login", "/static")


def _is_public_path(path: str) -> bool:
    """Return True for paths that bypass authentication."""
    return path in _PUBLIC_EXACT or path.startswith(_PUBLIC_PREFIX)


def _unauthenticated_response(path: str):
    """Return the appropriate response for an unauthenticated request."""
    if path.startswith("/api/"):
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    return RedirectResponse("/login", status_code=302)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if _is_public_path(path):
        return await call_next(request)
    if not is_authenticated(request):
        return _unauthenticated_response(path)
    return await call_next(request)


# ── API routes ────────────────────────────────────────────
app.include_router(router)


# ── Serve the main UI (catch-all, auth enforced by middleware) ──
@app.get("/")
@app.get("/{path:path}")
async def serve_ui(path: str = ""):
    index = TEMPLATES / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return {"message": "Informatica Conversion Tool API", "docs": "/docs"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
