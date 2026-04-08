# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Mock Enterprise AI Gateway — local simulation for USE_API_GATEWAY testing.

Accepts the gateway-format POST body, forwards to the real Anthropic API,
and returns an OpenAI-compatible response so the full USE_API_GATEWAY=true
code path can be exercised without enterprise infrastructure.

Usage
-----
1. Start the mock in a separate terminal:
       python mock_gateway.py

2. Set these in your .env (temporarily):
       USE_API_GATEWAY=true
       AI_GW_URL=http://localhost:9999/v1/chat/completions
       AI_KEY=mock-key
       MODEL_ID=claude-sonnet-4-5-20250929

3. Run the app normally — all Claude calls will route through here.

4. Restore .env when done:
       USE_API_GATEWAY=false

The mock also accepts x-api-key and Authorization headers (both are
accepted as-is so token/auth logic in gateway.py is exercised).
"""
import os
import sys
import json
import logging
from pathlib import Path

# Allow running from the app/ directory
sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
# Load .env from the app/ directory regardless of the caller's CWD
load_dotenv(Path(__file__).parent / ".env")

try:
    import anthropic
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    import uvicorn
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install fastapi uvicorn anthropic")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [mock-gateway] %(message)s")
log = logging.getLogger("mock_gateway")

app = FastAPI(title="Mock AI Gateway", docs_url=None)

_client = anthropic.Anthropic(
    api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
    timeout=300.0,
)


@app.post("/v1/chat/completions")
async def completions(request: Request):
    body = await request.json()

    log.info(
        "← incoming  model=%s  max_tokens=%s  messages=%d",
        body.get("model"), body.get("max_tokens"), len(body.get("messages", [])),
    )

    # Split system message from conversation messages
    messages = body.get("messages", [])
    system_parts = [m["content"] for m in messages if m.get("role") == "system"]
    conv_messages = [m for m in messages if m.get("role") != "system"]

    kwargs = dict(
        model=body.get("model", "claude-sonnet-4-5-20250929"),
        max_tokens=body.get("max_tokens", 4096),
        messages=conv_messages,
    )
    if system_parts:
        kwargs["system"] = "\n\n".join(system_parts)
    if "temperature" in body:
        kwargs["temperature"] = body["temperature"]

    try:
        response = _client.messages.create(**kwargs)
        text = response.content[0].text
    except Exception as exc:
        log.error("Anthropic call failed: %s", exc)
        return JSONResponse({"error": str(exc)}, status_code=502)

    # Return in OpenAI-compatible format — matches what invoke_apigateway() parses
    result = {
        "id": f"mock-{response.id}",
        "object": "chat.completion",
        "model": response.model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": text,
                },
                "finish_reason": response.stop_reason or "stop",
            }
        ],
        "usage": {
            "prompt_tokens":     response.usage.input_tokens,
            "completion_tokens": response.usage.output_tokens,
            "total_tokens":      response.usage.input_tokens + response.usage.output_tokens,
        },
    }

    log.info(
        "→ response  stop=%s  in=%d  out=%d  preview=%s",
        response.stop_reason,
        response.usage.input_tokens,
        response.usage.output_tokens,
        text[:80].replace("\n", " "),
    )

    return JSONResponse(result)


@app.get("/health")
async def health():
    return {"status": "ok", "mode": "mock-gateway"}


if __name__ == "__main__":
    port = int(os.environ.get("MOCK_GATEWAY_PORT", 9999))
    log.info("Mock gateway starting on http://localhost:%d", port)
    log.info("Set in .env:  USE_API_GATEWAY=true")
    log.info("             AI_GW_URL=http://localhost:%d/v1/chat/completions", port)
    log.info("             AI_KEY=mock-key")
    log.info("             MODEL_ID=claude-sonnet-4-5-20250929")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
