# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
utils/null_safe.py — Null-safe value accessors
================================================
Informatica expressions rely heavily on IIF(ISNULL(value), default, value).
These helpers centralise that idiom for use in Python pattern implementations
so every pattern does not re-implement the same guard.

Usage
-----
from etl_patterns.utils.null_safe import null_safe, coalesce

# Single value with typed default
null_safe(row["AMOUNT"], 0.0)          # → 0.0 when AMOUNT is None/NaN
null_safe(row["NAME"],   "UNKNOWN")    # → "UNKNOWN" when NAME is None/NaN

# First non-null from a list (mirrors Informatica IIF chains)
coalesce(row["NICK"], row["FIRST"], "UNKNOWN")
"""
from __future__ import annotations

import math
from typing import Any, TypeVar

T = TypeVar("T")


# ── Primary helpers ───────────────────────────────────────────────────────────

def null_safe(value: Any, default: T, *, type_coerce: type | None = None) -> T:
    """
    Return *value* when it is not null/None/NaN, otherwise return *default*.

    Parameters
    ----------
    value       The value to test.
    default     Fallback when *value* is null.
    type_coerce If provided, cast the returned (non-null) value to this type.
                The default is never coerced — it is returned as-is.

    Examples
    --------
    >>> null_safe(None, 0)
    0
    >>> null_safe(float("nan"), 0.0)
    0.0
    >>> null_safe("hello", "UNKNOWN")
    'hello'
    >>> null_safe("42", 0, type_coerce=int)
    42
    """
    if _is_null(value):
        return default
    if type_coerce is not None:
        try:
            return type_coerce(value)  # type: ignore[return-value]
        except (ValueError, TypeError):
            return default
    return value  # type: ignore[return-value]


def coalesce(*values: Any, default: Any = None) -> Any:
    """
    Return the first non-null value from *values*, or *default* if all are null.

    Mirrors the SQL COALESCE / Informatica IIF chain pattern.

    Examples
    --------
    >>> coalesce(None, None, "first_good")
    'first_good'
    >>> coalesce(None, None, default="UNKNOWN")
    'UNKNOWN'
    """
    for v in values:
        if not _is_null(v):
            return v
    return default


def is_null(value: Any) -> bool:
    """
    Public null-check that mirrors Informatica ISNULL().

    Treats Python None, float NaN, and pandas NA/NaT as null.
    Empty string is **not** null (matches Informatica behaviour).
    """
    return _is_null(value)


def nvl(value: Any, replacement: T) -> T:
    """Alias for null_safe — mirrors the Oracle NVL / Informatica NVL function."""
    return null_safe(value, replacement)


def nvl2(value: Any, not_null_result: T, null_result: T) -> T:
    """
    Mirrors Oracle NVL2 / Informatica IIF(ISNULL(v), null_result, not_null_result).

    Returns *not_null_result* when *value* is NOT null,
    returns *null_result*    when *value* IS null.
    """
    if _is_null(value):
        return null_result
    return not_null_result


# ── Internal ──────────────────────────────────────────────────────────────────

def _is_null(value: Any) -> bool:
    """Return True for None, float('nan'), and pandas NA/NaT."""
    if value is None:
        return True
    # Avoid importing pandas just for the NA/NaT check; use duck-typing
    try:
        import pandas as pd  # noqa: PLC0415
        if pd.isna(value):
            return True
    except (ImportError, TypeError, ValueError):
        pass
    # Check for plain float NaN without pandas
    if isinstance(value, float) and math.isnan(value):
        return True
    return False
