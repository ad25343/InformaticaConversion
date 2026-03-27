# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Pattern router.
GET /patterns  list all ETL patterns with schemas (used by documentation/reference)
"""
from __future__ import annotations

from fastapi import APIRouter

from etl_patterns.schemas import PATTERN_SCHEMAS, PATTERN_DESCRIPTIONS

router = APIRouter(prefix="")


@router.get("/patterns")
async def list_patterns():
    """Return all registered ETL patterns with JSON Schema for each config model."""
    patterns = [
        {
            "name": name,
            "description": PATTERN_DESCRIPTIONS.get(name, ""),
            "schema": schema_cls.model_json_schema(),
        }
        for name, schema_cls in PATTERN_SCHEMAS.items()
    ]
    return {"patterns": patterns}
