"""
Informatica Conversion Tool — FastAPI Application Entry Point
"""
import os
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from dotenv import load_dotenv

load_dotenv()

from backend.db.database import init_db
from backend.routes import router
from backend.logger import configure_app_logging
from backend.auth import (
    is_authenticated, check_password,
    create_session_token, COOKIE_NAME, SESSION_HOURS
)

TEMPLATES = Path(__file__).parent / "frontend" / "templates"


@asynccontextmanager
async def lifespan(app: FastAPI):
    log_level = os.environ.get("LOG_LEVEL", "INFO")
    configure_app_logging(log_level)
    await init_db()
    yield


app = FastAPI(
    title="Informatica Conversion Tool",
    description="Converts Informatica PowerCenter mappings to Python, PySpark, or dbt",
    version="1.0.0-mvp",
    lifespan=lifespan,
    # Hide docs behind auth in production — set SHOW_DOCS=false in .env
    docs_url="/docs" if os.environ.get("SHOW_DOCS", "true").lower() != "false" else None,
    redoc_url=None,
)

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


@app.post("/login")
async def login_submit(request: Request, password: str = Form(...)):
    if check_password(password):
        token = create_session_token()
        response = RedirectResponse("/", status_code=302)
        response.set_cookie(
            key=COOKIE_NAME,
            value=token,
            httponly=True,
            samesite="lax",
            max_age=SESSION_HOURS * 3600,
            secure=os.environ.get("HTTPS", "false").lower() == "true",
        )
        return response
    return RedirectResponse("/login?error=1", status_code=302)


@app.get("/logout")
async def logout():
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie(COOKIE_NAME)
    return response


# ── Protected API routes ──────────────────────────────────
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path

    # Always allow: login page, static assets, favicon
    if (path.startswith("/login") or
        path.startswith("/static") or
        path == "/favicon.ico"):
        return await call_next(request)

    # Check authentication for everything else
    if not is_authenticated(request):
        # API calls → 401 JSON
        if path.startswith("/api/"):
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)
        # UI/browser requests → redirect to login
        return RedirectResponse(f"/login", status_code=302)

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
