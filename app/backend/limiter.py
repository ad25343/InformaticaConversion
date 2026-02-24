"""
Shared rate-limiter instance.

Import this module in main.py to wire the limiter into the app,
and in routes.py to apply per-endpoint limits.

Limits are configurable via environment variables (read once at startup):
  RATE_LIMIT_JOBS   — job creation endpoints  (default: "20/minute")
  RATE_LIMIT_LOGIN  — login POST              (default: "5/minute")

Both accept any slowapi/limits string, e.g. "100/hour", "5/minute", "1/second".
"""
from __future__ import annotations

import os

from slowapi import Limiter
from slowapi.util import get_remote_address

# Rate limit strings — read from env at import time (after load_dotenv() in main.py)
RATE_LIMIT_JOBS  = os.environ.get("RATE_LIMIT_JOBS",  "20/minute")
RATE_LIMIT_LOGIN = os.environ.get("RATE_LIMIT_LOGIN", "5/minute")

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],          # no blanket default — only decorated routes are limited
    headers_enabled=True,       # emit X-RateLimit-* response headers
)
