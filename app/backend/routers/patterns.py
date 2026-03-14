# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Pattern router — Phase 3 bidirectional migration.
GET  /patterns                             list all 10 ETL patterns with schemas
POST /patterns/{pattern_name}/generate-xml generate Informatica XML from pattern config
"""
from __future__ import annotations

from typing import Optional

import yaml
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ValidationError

from ._helpers import logger
from ..agents.xml_generator import XmlGeneratorAgent
from etl_patterns.schemas import PATTERN_SCHEMAS, PATTERN_DESCRIPTIONS

router = APIRouter(prefix="")


class GenerateXmlRequest(BaseModel):
    config_yaml: str
    mapping_name: str
    metadata: Optional[dict] = None


class GenerateXmlResponse(BaseModel):
    pattern_name: str
    mapping_name: str
    xml_content: str
    notes: list = []
    duration_ms: int


@router.get("/patterns")
async def list_patterns():
    """Return all 10 registered ETL patterns with JSON Schema for each config model."""
    patterns = []
    for name, schema_cls in PATTERN_SCHEMAS.items():
        patterns.append({
            "name": name,
            "description": PATTERN_DESCRIPTIONS.get(name, ""),
            "schema": schema_cls.model_json_schema(),
        })
    return {"patterns": patterns}


@router.post("/patterns/{pattern_name}/generate-xml", response_model=GenerateXmlResponse)
async def generate_xml_from_pattern(pattern_name: str, payload: GenerateXmlRequest):
    """Validate a YAML pattern config and generate Informatica PowerCenter XML."""
    if pattern_name not in PATTERN_SCHEMAS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown pattern: '{pattern_name}'. Valid patterns: {sorted(PATTERN_SCHEMAS)}",
        )

    try:
        parsed_config = yaml.safe_load(payload.config_yaml)
    except yaml.YAMLError as e:
        raise HTTPException(status_code=422, detail=f"Invalid YAML: {e}")

    if not isinstance(parsed_config, dict):
        raise HTTPException(status_code=422, detail="config_yaml must be a YAML mapping (dict)")

    schema_cls = PATTERN_SCHEMAS[pattern_name]
    try:
        schema_cls(**parsed_config)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())

    try:
        result = await XmlGeneratorAgent().generate_xml(
            pattern_name=pattern_name,
            pattern_config=parsed_config,
            mapping_name=payload.mapping_name,
            metadata=payload.metadata,
        )
    except Exception as e:
        logger.error("XML generation failed for pattern=%s: %s", pattern_name, e)
        raise HTTPException(status_code=500, detail=f"XML generation failed: {e}")

    # Log to DB (best-effort, non-blocking)
    try:
        from ..db.database import log_pattern_generation
        await log_pattern_generation(
            pattern_name=pattern_name,
            mapping_name=payload.mapping_name,
            duration_ms=result.duration_ms,
            success=True,
            xml_length=len(result.xml_content),
        )
    except Exception:
        pass  # Non-critical

    return GenerateXmlResponse(
        pattern_name=result.pattern_name,
        mapping_name=result.mapping_name,
        xml_content=result.xml_content,
        notes=result.notes,
        duration_ms=result.duration_ms,
    )
