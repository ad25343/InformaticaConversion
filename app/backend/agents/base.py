# Copyright (c) 2026 ad25343
# Licensed under CC BY-NC 4.0.
"""
agents/base.py — BaseAgent
==========================
Abstract base class for all Claude-calling agents.

Provides:
  - Shared client construction via make_client()
  - Retry-aware Claude call via call_claude_with_retry()
  - Consistent _call_claude() / _call_claude_json() helpers

All subclasses remain callable via backward-compat module-level functions
so orchestrator.py call sites don't change.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import anthropic

from ._client import make_client, call_claude_with_retry
from ..config import settings as _cfg

log = logging.getLogger("conversion.agents.base")


class BaseAgent:
    """
    Base class for all Claude-calling agents.

    Subclasses override the relevant method (document(), verify(), etc.)
    and call self._call_claude() instead of constructing a client directly.
    Module-level shim functions keep existing call sites unchanged.
    """

    MODEL: str = _cfg.claude_model

    async def _call_claude(
        self,
        *,
        system: str,
        user_prompt: str,
        max_tokens: int,
        **kwargs: Any,
    ) -> anthropic.types.Message:
        """
        Call Claude with retry logic.
        Extra kwargs (e.g. temperature, betas) are forwarded verbatim.
        """
        client = make_client()
        return await call_claude_with_retry(
            client,
            model=self.MODEL,
            system=system,
            messages=[{"role": "user", "content": user_prompt}],
            max_tokens=max_tokens,
            **kwargs,
        )

    async def _call_claude_json(
        self,
        *,
        system: str,
        user_prompt: str,
        max_tokens: int,
        **kwargs: Any,
    ) -> dict:
        """
        Call Claude expecting a JSON response.
        Strips markdown fences and parses the content.
        Raises ValueError if the response is not valid JSON.
        """
        response = await self._call_claude(
            system=system,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            **kwargs,
        )
        raw = response.content[0].text.strip()
        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[-1]
            if raw.endswith("```"):
                raw = raw[: raw.rfind("```")]
        return json.loads(raw)
