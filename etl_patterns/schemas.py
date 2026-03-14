# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
etl_patterns/schemas.py — Pydantic v2 schemas for all 10 ETL pattern configs.

Phase 3 — bidirectional migration / greenfield authoring.
These schemas are used by the /api/patterns/* endpoints to validate
user-supplied pattern configs before generating Informatica XML.
"""
from __future__ import annotations

from typing import Optional, List, Dict, Union

from pydantic import BaseModel, Field


# ── Connection / IO primitives ────────────────────────────────────────────────

class SourceConfig(BaseModel):
    type: str  # "database" | "file" | "s3"
    connection_string: Optional[str] = None
    table: Optional[str] = None
    file_path: Optional[str] = None
    file_format: Optional[str] = None
    delimiter: Optional[str] = None
    query: Optional[str] = None


class TargetConfig(BaseModel):
    type: str
    connection_string: Optional[str] = None
    table: Optional[str] = None
    write_mode: Optional[str] = None  # "append", "replace", "upsert"
    file_path: Optional[str] = None
    file_format: Optional[str] = None


class ColumnMapEntry(BaseModel):
    target_col: str
    expression: str


# ── Base pattern config ───────────────────────────────────────────────────────

class BasePatternConfig(BaseModel):
    pattern: str
    mapping_name: Optional[str] = None
    source: SourceConfig
    target: Union[TargetConfig, List[TargetConfig]]
    column_map: Optional[List[ColumnMapEntry]] = None
    etl_metadata: bool = False


# ── Watermark (used by incremental_append) ───────────────────────────────────

class WatermarkConfig(BaseModel):
    column: str
    data_type: str  # "datetime" | "integer" | "string"
    initial: str
    table: str = "ETL_WATERMARKS"
    control_connection_string: Optional[str] = None


# ── Pattern-specific configs ──────────────────────────────────────────────────

class TruncateAndLoadConfig(BasePatternConfig):
    pattern: str = "truncate_and_load"


class IncrementalAppendConfig(BasePatternConfig):
    pattern: str = "incremental_append"
    watermark: WatermarkConfig


class UpsertConfig(BasePatternConfig):
    pattern: str = "upsert"
    unique_key: List[str]  # column name(s) to merge on


class Scd2SpecConfig(BaseModel):
    business_key: List[str]
    tracked_cols: List[str]
    effective_from: str
    effective_to: str
    is_current: str
    end_of_time: str = "9999-12-31 00:00:00"


class Scd2Config(BasePatternConfig):
    pattern: str = "scd2"
    scd2: Scd2SpecConfig


class LookupConfig(BaseModel):
    table: str
    connection_string: Optional[str] = None
    join_key: List[str]
    select_cols: Optional[List[str]] = None


class LookupEnrichConfig(BasePatternConfig):
    pattern: str = "lookup_enrich"
    lookup: LookupConfig


class AggregationConfig(BaseModel):
    group_by: List[str]
    aggregates: Dict[str, str]  # e.g. {"total_amt": "SUM(amount)", "cnt": "COUNT(*)"}


class AggregationLoadConfig(BasePatternConfig):
    pattern: str = "aggregation_load"
    aggregation: AggregationConfig


class RouteConfig(BaseModel):
    condition: str
    target: TargetConfig


class FilterAndRouteConfig(BasePatternConfig):
    pattern: str = "filter_and_route"
    routes: List[RouteConfig]
    default_target: Optional[TargetConfig] = None


class UnionConsolidateConfig(BasePatternConfig):
    pattern: str = "union_consolidate"
    union_sources: List[SourceConfig]  # additional sources beyond the main `source`


class ExpressionTransformConfig(BasePatternConfig):
    pattern: str = "expression_transform"
    # column_map is required for this pattern (inherited from BasePatternConfig as Optional,
    # but enforced by the XML generator and API validation)


class PassThroughConfig(BasePatternConfig):
    pattern: str = "pass_through"


# ── Registry ──────────────────────────────────────────────────────────────────

PATTERN_SCHEMAS: Dict[str, type] = {
    "truncate_and_load":    TruncateAndLoadConfig,
    "incremental_append":   IncrementalAppendConfig,
    "upsert":               UpsertConfig,
    "scd2":                 Scd2Config,
    "lookup_enrich":        LookupEnrichConfig,
    "aggregation_load":     AggregationLoadConfig,
    "filter_and_route":     FilterAndRouteConfig,
    "union_consolidate":    UnionConsolidateConfig,
    "expression_transform": ExpressionTransformConfig,
    "pass_through":         PassThroughConfig,
}

PATTERN_DESCRIPTIONS: Dict[str, str] = {
    "truncate_and_load":    "Full-refresh: truncate target then load all source rows",
    "incremental_append":   "Watermark-driven incremental append of new rows",
    "upsert":               "Merge on key columns: insert new rows, update existing (SCD Type 1)",
    "scd2":                 "Slowly Changing Dimension Type 2: track full history with effective dates",
    "lookup_enrich":        "Enrich source rows by joining to a lookup/reference table",
    "aggregation_load":     "GROUP BY aggregation load",
    "filter_and_route":     "Conditional routing: different rows go to different targets based on conditions",
    "union_consolidate":    "Union/consolidate multiple source tables into a single target",
    "expression_transform": "Column-level expression transformations (IIF, DECODE, string/date functions)",
    "pass_through":         "Direct extract with no transformation",
}
