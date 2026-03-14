# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
conversion/ — Stack Assignment + Conversion Agent package.

Public API (mirrors the original conversion_agent.py exports so that all
existing import sites continue to work without modification):

    from .conversion import assign_stack, convert, ConversionAgent
"""
from __future__ import annotations

from ._assign import assign_stack
from ._dispatch import convert, ConversionAgent

__all__ = [
    "assign_stack",
    "convert",
    "ConversionAgent",
]
