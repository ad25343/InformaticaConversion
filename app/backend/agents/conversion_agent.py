# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
conversion_agent.py — backward-compat shim (delegates to conversion/ package).

All logic has been moved into app/backend/agents/conversion/:
  _common.py   — shared imports, helpers, MODEL, _cfg
  _assign.py   — stack assignment (Step 6)
  _dbt.py      — dbt system prompt + runtime artifact generation
  _pyspark.py  — PySpark system prompt
  _python.py   — Python/Pandas system prompt
  _dispatch.py — ConversionAgent class + convert() dispatcher (Step 7)

Existing import sites (orchestrator.py, tests, etc.) require no changes.
"""
from .conversion import assign_stack, convert, ConversionAgent  # noqa: F401
