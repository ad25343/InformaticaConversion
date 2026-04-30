# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Shared Anthropic client factory and call helper.

All agents MUST call Claude through ``call_claude_with_retry()`` so that:
  • the per-call timeout is applied consistently
  • retries use exponential back-off
  • the enterprise gateway path is used when USE_API_GATEWAY=true

When USE_API_GATEWAY=false (default):
    AsyncAnthropic is used directly — no change to any existing behaviour.

When USE_API_GATEWAY=true:
    Calls are routed through the configured enterprise gateway
    (Bedrock, Apigee, Azure APIM, etc.) via a synchronous requests.post()
    wrapped in asyncio.to_thread() so the FastAPI event loop is never blocked.
    The gateway response (OpenAI-compatible format) is adapted into the same
    ``message.content[0].text`` interface so no agent file needs to change.

Usage:
    from ._client import make_client, call_claude_with_retry
    client = make_client()
    message = await call_claude_with_retry(client, model=..., messages=..., ...)
    text = message.content[0].text
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


# ── Anthropic SDK client factories ──────────────────────────────────────────

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


# ── Gateway response adapter ─────────────────────────────────────────────────

class _GatewayMessage:
    """
    Minimal adapter so gateway responses are consumed identically to
    Anthropic SDK Message objects.

    Agents access ``message.content[0].text`` — this class satisfies that
    interface without requiring any agent code to change.
    """

    class _Block:
        def __init__(self, text: str) -> None:
            self.text = text
            self.type = "text"

    def __init__(self, text: str) -> None:
        self.content = [self._Block(text)]
        self.stop_reason = "end_turn"


def _extract_gateway_text(response_data: dict) -> str:
    """Extract the model's text from an OpenAI-compatible gateway response."""
    choices = response_data.get("choices") or [{}]
    return choices[0].get("message", {}).get("content", "")


def _build_gateway_body(**kwargs) -> dict:
    """
    Convert Anthropic SDK keyword arguments into the gateway request body.

    Handles the common fields used by pipeline agents:
      model, max_tokens, messages, system, temperature, betas (ignored)
    """
    messages = list(kwargs.get("messages", []))

    # Prepend system prompt as a system-role message if provided
    system = kwargs.get("system")
    if system:
        messages = [{"role": "system", "content": system}] + messages

    model = _cfg.model_id or kwargs.get("model", _cfg.claude_model)

    body: dict = {
        "model": model,
        "messages": messages,
        "max_tokens": kwargs.get("max_tokens", 4096),
        "temperature": kwargs.get("temperature", 0),
    }
    return body


# ── Unified retry helper ─────────────────────────────────────────────────────

async def call_claude_with_retry(
    client: anthropic.AsyncAnthropic,
    *,
    max_retries: int | None = None,
    base_delay: float = 2.0,
    **kwargs,
) -> anthropic.types.Message | _GatewayMessage:
    """
    Call Claude with exponential back-off retries.

    When USE_API_GATEWAY=false (default):
        Delegates to ``client.messages.create(**kwargs)``.

    When USE_API_GATEWAY=true:
        Builds a gateway request body, calls ``invoke_apigateway()`` via
        ``asyncio.to_thread()`` (non-blocking), and wraps the response in
        ``_GatewayMessage`` so all callers get the same interface.

    Parameters
    ----------
    client        AsyncAnthropic client (ignored in gateway mode, kept for
                  a consistent call signature across all agents).
    max_retries   Total attempts before raising. Defaults to NO_OF_RETRIES
                  from config (default 3).
    base_delay    Base back-off in seconds; doubles each attempt (max 60 s).
    **kwargs      Forwarded to client.messages.create() or converted to a
                  gateway body dict.
    """
    _max = max_retries if max_retries is not None else _cfg.no_of_retries

    if _cfg.use_api_gateway:
        return await _call_gateway_with_retry(_max, base_delay, **kwargs)

    return await _call_anthropic_with_retry(client, _max, base_delay, **kwargs)


async def _call_anthropic_with_retry(
    client: anthropic.AsyncAnthropic,
    max_retries: int,
    base_delay: float,
    **kwargs,
) -> anthropic.types.Message:
    """Direct Anthropic SDK path — unchanged from original implementation."""
    # Strip internal-only kwargs that are not Anthropic SDK parameters
    api_kwargs = {k: v for k, v in kwargs.items() if k not in ("label",)}
    last_exc: Exception | None = None
    for attempt in range(max_retries):
        try:
            return await client.messages.create(**api_kwargs)
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


async def _call_gateway_with_retry(
    max_retries: int,
    base_delay: float,
    **kwargs,
) -> _GatewayMessage:
    """Enterprise gateway path — sync call wrapped in asyncio.to_thread()."""
    from .gateway import invoke_apigateway  # imported only when gateway is enabled

    body = _build_gateway_body(**kwargs)
    last_exc: Exception | None = None

    for attempt in range(max_retries):
        try:
            resp = await asyncio.to_thread(invoke_apigateway, body)
            text = _extract_gateway_text(resp.json())
            return _GatewayMessage(text)
        except Exception as exc:
            last_exc = exc
            if attempt == max_retries - 1:
                _client_log.error(
                    "Gateway API call failed after %d attempt(s): %s",
                    max_retries, exc,
                )
                raise
            delay = min(base_delay * (2 ** attempt), 60.0)
            _client_log.warning(
                "Gateway transient error (attempt %d/%d) — retrying in %.1fs: %s",
                attempt + 1, max_retries, delay, exc,
            )
            await asyncio.sleep(delay)
    raise last_exc  # unreachable but satisfies type checkers
