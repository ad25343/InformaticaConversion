# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
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
        extra="ignore",                        # silently ignore unknown env vars
        protected_namespaces=("settings_",),   # allow model_id field without warning
    )

    # ── Claude API ──────────────────────────────────────────────────────────
    anthropic_api_key: str = ""
    claude_model: str = "claude-sonnet-4-5-20250929"

    # ── Authentication ──────────────────────────────────────────────────────
    app_password: str = ""
    secret_key: str = "change-me-in-production-please"
    session_hours: int = 8
    bcrypt_rounds: int = 12   # work factor for bcrypt password hashing (12 ≈ 250ms)

    # ── Server ──────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"  # nosec B104 — intentional; runs in container/VM, not exposed directly
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
    # Number of trusted reverse proxies in front of this app (nginx, CloudFlare, etc.).
    # When > 0 the rate limiter reads the real client IP from X-Forwarded-For,
    # skipping the last N entries (which are the trusted proxy hops).
    # Leave at 0 when the app is exposed directly (no proxy).
    trusted_proxy_count: int = 0

    # ── Batch conversion ────────────────────────────────────────────────────
    batch_concurrency: int = 3

    # ── Job export (disk write) ─────────────────────────────────────────────
    # Directory where completed job artifacts are written after Gate 3 approval.
    # Defaults to <repo_root>/jobs if left empty.  Set to an absolute path for
    # Docker or CI deployments.  Set to "disabled" to suppress disk writes entirely.
    output_dir: str = ""

    # ── GitHub PR integration (v2.10.0) ─────────────────────────────────────
    # Set GITHUB_TOKEN + GITHUB_REPO to automatically open a draft PR after
    # every Gate 3 approval.  Leave either empty to disable.
    github_token: str = ""          # PAT with repo scope, or a GitHub App token
    github_repo: str = ""           # "owner/repo" — e.g. "myorg/data-migration"
    github_base_branch: str = "main"  # Branch the PR targets
    # Override for GitHub Enterprise Server (include /api/v3 path if required)
    github_api_url: str = "https://api.github.com"

    # ── Email notifications (v2.17.2) ───────────────────────────────────────
    # Set SMTP_HOST to enable email alerts on gate pauses and job failures.
    # No dedicated mail server required — relay through an existing SMTP
    # provider (Office 365, Exchange, Gmail, SendGrid, AWS SES, etc.).
    #
    # Triggers (when configured):
    #   • Job reaches Gate 1 / 2 / 3 — email sent to NOTIFY_GATE_EMAILS list
    #   • Job reaches FAILED or BLOCKED terminal state — same list
    #
    # Example .env:
    #   SMTP_HOST=smtp.office365.com
    #   SMTP_PORT=587
    #   SMTP_USER=ict-noreply@myorg.com
    #   SMTP_PASSWORD=<app-password>
    #   SMTP_FROM=ict-noreply@myorg.com
    #   SMTP_TLS=true                     # STARTTLS on port 587 (default)
    #   SMTP_SSL=false                    # SSL on port 465; mutually exclusive with SMTP_TLS
    #   NOTIFY_GATE_EMAILS=reviewer1@myorg.com,reviewer2@myorg.com
    smtp_host:           str  = ""       # empty = email notifications disabled
    smtp_port:           int  = 587
    smtp_user:           str  = ""
    smtp_password:       str  = ""
    smtp_from:           str  = ""       # defaults to smtp_user if left empty
    smtp_tls:            bool = True     # STARTTLS (port 587) — most common
    smtp_ssl:            bool = False    # Direct SSL (port 465) — mutually exclusive
    notify_gate_emails:  str  = ""       # comma-separated recipient list

    # ── Webhook notifications ────────────────────────────────────────────────
    # Set WEBHOOK_URL to receive a JSON POST at gate pauses, job completion,
    # and hard failures.  Works with Slack/Teams incoming webhooks, PagerDuty,
    # or any HTTP endpoint that accepts JSON.  Leave empty to disable.
    webhook_url: str = ""
    # Optional HMAC-SHA256 signing key.  When set, every request carries an
    # X-Webhook-Signature: sha256=<hex> header for receiver-side verification.
    webhook_secret: str = ""
    # Per-request timeout for outbound webhook POSTs (seconds).
    webhook_timeout_secs: int = 10

    # ── File watcher / scheduled ingestion (v2.14.1) ────────────────────────
    # When WATCHER_ENABLED=true the app polls WATCHER_DIR for manifest files.
    # Each manifest signals that all XML files for one conversion are ready.
    #
    # Manifest format (drop as <name>.manifest.json in WATCHER_DIR):
    #   {
    #     "version":  "1.0",
    #     "label":    "Customer Pipeline Q1 2026",   // optional — output folder name
    #     "mappings": [                               // required — one or more XMLs
    #       "m_customer.xml",                         // string: inherits top-level defaults
    #       { "mapping": "m_rank.xml",                // object: per-mapping overrides
    #         "workflow": "wf_rank.xml" }
    #     ],
    #     "workflow":      "wf_default.xml",          // optional default for all mappings
    #     "parameters":    "params.xml",              // optional default for all mappings
    #     "reviewer":      "Jane Smith",              // optional
    #     "reviewer_role": "Data Engineer"            // optional
    #   }
    #
    # After submission the manifest is moved to WATCHER_DIR/processed/.
    # Manifests with missing files are retried each poll; after
    # WATCHER_INCOMPLETE_TTL_SECS they are moved to WATCHER_DIR/failed/.
    # Artifacts written to OUTPUT_DIR/<label>_<timestamp>/<mapping_stem>/
    watcher_enabled:             bool = False
    watcher_dir:                 str  = ""    # required when watcher_enabled=True
    watcher_poll_interval_secs:  int  = 30    # how often to scan the directory
    watcher_incomplete_ttl_secs: int  = 300   # seconds before a partial manifest is failed

    # ── Time-based scheduler (v2.15.0) ──────────────────────────────────────
    # When SCHEDULER_ENABLED=true the app polls SCHEDULER_DIR for
    # *.schedule.json files and materialises *.manifest.json files into
    # WATCHER_DIR when their cron expressions fire.  The manifest file watcher
    # then picks up and processes them as normal.
    #
    # WATCHER_ENABLED and WATCHER_DIR must also be configured.
    #
    # Schedule file format (drop as <name>.schedule.json in SCHEDULER_DIR):
    #   {
    #     "version":  "1.0",
    #     "cron":     "0 2 * * 1-5",              // required — 5-field cron expression
    #     "timezone": "America/New_York",          // optional — IANA timezone (default UTC)
    #     "label":    "Customer Pipeline Nightly", // optional — output folder name
    #     "enabled":  true,                        // optional — set false to pause
    #     "manifest": {                            // required — manifest payload
    #       "version":  "1.0",
    #       "mappings": ["m_customer.xml"],
    #       "workflow": "wf_customer.xml"
    #     }
    #   }
    #
    # Cron fields: minute  hour  day-of-month  month  day-of-week (0=Sun … 6=Sat)
    # Examples:  "0 2 * * 1-5"   weekdays at 02:00
    #            "30 6 * * *"    every day at 06:30
    #            "0 */4 * * *"   every 4 hours on the hour
    #
    # Schedule files are re-read on every poll — edits take effect immediately.
    scheduler_enabled:            bool = False
    scheduler_dir:                str  = ""   # required when scheduler_enabled=True
    scheduler_poll_interval_secs: int  = 60   # how often to evaluate cron expressions

    # ── Application version ─────────────────────────────────────────────────
    # Single source of truth — referenced by main.py, routes.py, and the health endpoint.
    # Bump this string on every release; do NOT hard-code versions elsewhere.
    app_version: str = "2.17.2"

    # ── Agent tuning ────────────────────────────────────────────────────────
    # Override documentation token budget for testing truncation behaviour.
    doc_max_tokens_override: int | None = None
    # Hard timeout (seconds) for the verification Claude call.
    verify_timeout_secs: int = 300
    # Hard timeout (seconds) applied to every Claude API call in all agents.
    # Prevents pipelines from stalling indefinitely when the Anthropic API hangs.
    agent_timeout_secs: int = 300
    # Anthropic beta header for extended output (documentation agent).
    # Update when Anthropic promotes a newer beta.
    extended_output_beta: str = "output-128k-2025-02-19"

    # ── Enterprise AI Gateway (optional) ────────────────────────────────────
    # Set USE_API_GATEWAY=true to route all Claude API calls through your
    # enterprise gateway (Bedrock, Apigee, Azure APIM, etc.) instead of
    # calling the Anthropic API directly.
    #
    # When false (default) every setting in this section is completely ignored
    # and the existing AsyncAnthropic code path runs unchanged.
    use_api_gateway: bool = False

    # Full inference endpoint URL of the gateway.
    ai_gw_url: str = ""

    # Static API key / bearer token accepted by the gateway.
    # Used as the x-api-key header on every request.
    ai_key: str = ""

    # OAuth2 client-credentials grant — leave both empty to skip token fetch.
    # When set, the client fetches a bearer token and adds Authorization: Bearer <token>.
    client_id: str = ""
    client_secret: str = ""

    # Model identifier sent inside the request body to the gateway.
    # May differ from claude_model (e.g. a Bedrock ARN or an Apigee model alias).
    model_id: str = ""

    # Number of retry attempts for gateway calls (default matches Anthropic path).
    no_of_retries: int = 3

    # Log the full request body and first 500 chars of the response for debugging.
    # Do NOT enable in production — responses contain customer data.
    enable_trace: bool = False


# Single shared instance — imported by all modules
settings = Settings()
