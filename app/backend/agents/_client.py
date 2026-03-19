# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Shared Anthropic client factory.

All agents MUST construct their AsyncAnthropic client through make_client()
so that the per-call timeout is applied consistently from config.  Direct
`anthropic.AsyncAnthropic(api_key=...)` calls bypass the timeout and allow
the pipeline to hang indefinitely if the Anthropic API becomes unresponsive.

Usage:
    from ._client import make_client
    client = make_client()
"""
from __future__ import annotations

import asyncio
import logging

import anthropic

from ..config import settings as _cfg

_client_log = logging.getLogger("conversion.agents._client")

# Error classes that warrant a retry — transient infrastructure problems.
# AuthenticationError / InvalidRequestError are NOT retried (programmer errors).
_RETRYABLE_ERRORS = (
    anthropic.RateLimitError,
    anthropic.APIConnectionError,
    anthropic.APITimeoutError,
    anthropic.InternalServerError,
)


def make_client() -> anthropic.AsyncAnthropic:
    """Return a configured AsyncAnthropic client with a hard per-call timeout."""
    return anthropic.AsyncAnthropic(
        api_key=_cfg.anthropic_api_key,
        timeout=float(_cfg.agent_timeout_secs),
    )


def make_sync_client() -> anthropic.Anthropic:
    """Return a configured synchronous Anthropic client with a hard per-call timeout."""
    return anthropic.Anthropic(
        api_key=_cfg.anthropic_api_key,
        timeout=float(_cfg.agent_timeout_secs),
    )


async def call_claude_with_retry(
    client: anthropic.AsyncAnthropic,
    *,
    max_retries: int = 3,
    base_delay: float = 2.0,
    **kwargs,
) -> anthropic.types.Message:
    """
    Call ``client.messages.create(**kwargs)`` with exponential backoff.

    Retries on rate-limit, connection, timeout, and 5xx errors only.
    Non-retryable errors (AuthenticationError, InvalidRequestError, etc.)
    propagate immediately without retrying.

    Parameters
    ----------
    client        AsyncAnthropic client (from make_client()).
    max_retries   Maximum total attempts (default 3 → up to 2 retries).
    base_delay    Base back-off in seconds; doubles each attempt (default 2s).
                  Maximum wait per attempt is capped at 60 s.
    **kwargs      Forwarded verbatim to client.messages.create().
    """
    last_exc: Exception | None = None
    for attempt in range(max_retries):
        try:
            return await client.messages.create(**kwargs)
        except _RETRYABLE_ERRORS as exc:
            last_exc = exc
            if attempt == max_retries - 1:
                _client_log.error(
                    "Claude API call failed after %d attempt(s): %s",
                    max_retries, exc,
                )
                raise
            delay = min(base_delay * (2 ** attempt), 60.0)
            _client_log.warning(
                "Claude API transient error (attempt %d/%d) — retrying in %.1fs: %s",
                attempt + 1, max_retries, delay, exc,
            )
            await asyncio.sleep(delay)
    raise last_exc  # unreachable but satisfies type checkers
