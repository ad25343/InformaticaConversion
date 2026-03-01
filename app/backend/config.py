"""
Centralised application configuration.

All environment variables are declared here with their types and defaults.
Import `settings` from this module everywhere instead of calling
`os.environ.get()` directly.

Usage:
    from .config import settings
    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)

The Settings class uses pydantic-settings, which reads from:
  1. Environment variables (highest priority)
  2. A .env file in the working directory (if present)
  3. The default values declared below
"""
from __future__ import annotations
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore",       # silently ignore unknown env vars
    )

    # ── Claude API ──────────────────────────────────────────────────────────
    anthropic_api_key: str = ""
    claude_model: str = "claude-sonnet-4-5-20250929"

    # ── Authentication ──────────────────────────────────────────────────────
    app_password: str = ""
    secret_key: str = "change-me-in-production-please"
    session_hours: int = 8

    # ── Server ──────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    show_docs: bool = True
    cors_origins: str = ""       # comma-separated list; empty = same-origin only
    https: bool = False
    log_level: str = "INFO"

    # ── File upload limits ──────────────────────────────────────────────────
    max_upload_mb: int = 50
    max_zip_extracted_mb: int = 200
    max_zip_file_count: int = 200

    # ── Database ────────────────────────────────────────────────────────────
    # Leave empty to use the default path (app/data/jobs.db relative to repo root).
    # Set to an absolute path for Docker or shared-filesystem deployments.
    db_path: str = ""

    # ── Job lifecycle ───────────────────────────────────────────────────────
    job_retention_days: int = 30
    cleanup_interval_hours: int = 24

    # ── Rate limiting ───────────────────────────────────────────────────────
    rate_limit_jobs: str = "20/minute"
    rate_limit_login: str = "5/minute"

    # ── Batch conversion ────────────────────────────────────────────────────
    batch_concurrency: int = 3

    # ── Agent tuning ────────────────────────────────────────────────────────
    # Override documentation token budget for testing truncation behaviour.
    doc_max_tokens_override: int | None = None
    # Hard timeout (seconds) for the verification Claude call.
    verify_timeout_secs: int = 300


# Single shared instance — imported by all modules
settings = Settings()
