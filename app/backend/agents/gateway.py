# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Enterprise AI Gateway client — activated only when USE_API_GATEWAY=true.

All Claude API calls are routed through the configured enterprise gateway
(Bedrock, Apigee, Azure APIM, etc.) using a standard HTTP POST.  OAuth2
client-credentials token fetch is included and caches the token until near
expiry.

This module is only imported when USE_API_GATEWAY=true.  When the flag is
false, the existing AsyncAnthropic code path in _client.py runs unchanged
and this file is never loaded.

Called via asyncio.to_thread() so the blocking requests.post() does not
stall the FastAPI async event loop.
"""
from __future__ import annotations

import logging
import time

import requests

from ..config import settings as _cfg

_gw_log = logging.getLogger("conversion.agents.gateway")

# Simple in-process token cache — avoids a token round-trip on every call.
_token_cache: dict = {"token": None, "expires_at": 0.0}


def _fetch_oauth_token() -> str:
    """
    Fetch a bearer token using OAuth2 client-credentials grant.

    Caches the token and reuses it until 30 seconds before expiry.
    Skips the fetch entirely if CLIENT_ID / CLIENT_SECRET are not configured.
    """
    now = time.monotonic()
    if _token_cache["token"] and now < _token_cache["expires_at"] - 30:
        return _token_cache["token"]

    _gw_log.debug("Fetching new OAuth token from gateway.")
    resp = requests.post(
        f"{_cfg.ai_gw_url.rstrip('/')}/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": _cfg.client_id,
            "client_secret": _cfg.client_secret,
        },
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    _token_cache["token"] = data["access_token"]
    _token_cache["expires_at"] = now + float(data.get("expires_in", 3600))
    _gw_log.debug("OAuth token acquired, expires in %ds.", data.get("expires_in", 3600))
    return _token_cache["token"]


def invoke_apigateway(body: dict) -> requests.Response:
    """
    POST *body* to the enterprise AI gateway and return the raw Response.

    Raises ``requests.HTTPError`` on non-2xx responses so the retry loop
    in ``call_claude_with_retry()`` can handle transient 5xx failures the
    same way it handles Anthropic SDK errors.

    This function is intentionally synchronous.  Callers MUST invoke it via
    ``await asyncio.to_thread(invoke_apigateway, body)`` so it does not block
    the FastAPI event loop.
    """
    headers: dict[str, str] = {
        "Content-Type": "application/json",
    }

    if _cfg.ai_key:
        headers["x-api-key"] = _cfg.ai_key

    # Add OAuth bearer token when client credentials are configured.
    if _cfg.client_id and _cfg.client_secret:
        token = _fetch_oauth_token()
        headers["Authorization"] = f"Bearer {token}"

    if _cfg.enable_trace:
        _gw_log.debug("Gateway request → %s  body: %s", _cfg.ai_gw_url, body)

    resp = requests.post(
        _cfg.ai_gw_url,
        json=body,
        headers=headers,
        timeout=119,
    )

    if _cfg.enable_trace:
        _gw_log.debug(
            "Gateway response [%d]: %s",
            resp.status_code,
            resp.text[:500],
        )

    resp.raise_for_status()
    return resp
