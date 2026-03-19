# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
conversion/ — Stack Assignment + Conversion Agent package.

Public API (mirrors the original conversion_agent.py exports so that all
existing import sites continue to work without modification):

    from .conversion import assign_stack, convert, ConversionAgent
"""
from __future__ import annotations

from ._assign import assign_stack, _is_sql_friendly
from ._common import _build_flag_handling_section, _validate_conversion_files
from ._dbt import build_dbt_runtime_artifacts
from ._dispatch import convert, ConversionAgent

# Backward-compat alias: tests import _build_dbt_runtime_artifacts (with underscore)
_build_dbt_runtime_artifacts = build_dbt_runtime_artifacts

__all__ = [
    "assign_stack",
    "convert",
    "ConversionAgent",
    "_is_sql_friendly",
    "_validate_conversion_files",
    "_build_dbt_runtime_artifacts",
    "_build_flag_handling_section",
]
