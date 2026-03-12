# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
utils/type_cast.py — Type-casting helpers
==========================================
Centralises all the type-conversion logic that Informatica TO_DATE, TO_DECIMAL,
TO_INTEGER, TO_CHAR expressions produce.  Each function is null-safe by default:
a null input always returns None unless a *default* is supplied.

Supported target types
----------------------
string    → str
integer   → int
decimal   → Decimal (with optional precision / scale)
float     → float
date      → datetime.date
datetime  → datetime.datetime
boolean   → bool  (truthy strings: "1","true","yes","y","on"; falsy: "0","false", …)

Config form (used inside expression_transform column_map)
----------------------------------------------------------
  target_type: decimal
  precision: 18
  scale: 4
  format: "%Y-%m-%d"      # for date / datetime only
  default: 0              # returned on cast failure instead of None
"""
from __future__ import annotations

import re
from datetime import date, datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any

from etl_patterns.utils.null_safe import _is_null

# ── Truthy / falsy string sets for boolean coercion ──────────────────────────
_TRUTHY  = {"1", "true", "yes", "y", "on",  "t"}
_FALSY   = {"0", "false", "no",  "n", "off", "f", ""}


def type_cast(
    value: Any,
    target_type: str,
    *,
    format: str | None = None,        # noqa: A002  (shadows built-in intentionally)
    precision: int | None = None,
    scale: int | None = None,
    default: Any = None,
) -> Any:
    """
    Cast *value* to the Informatica-equivalent *target_type*.

    Parameters
    ----------
    value       Source value (any Python type).
    target_type One of: string, integer, decimal, float, date, datetime, boolean.
    format      strptime/strftime format string for date / datetime targets.
    precision   Total significant digits for decimal targets.
    scale       Decimal places for decimal targets.
    default     Value to return when *value* is null or the cast fails.
                None by default (mirrors Informatica null propagation).

    Returns
    -------
    Converted value, or *default* on null / failure.
    """
    if _is_null(value):
        return default

    t = target_type.lower().strip()

    try:
        if t in {"string", "str", "varchar", "char", "nvarchar"}:
            return _to_string(value)
        if t in {"integer", "int", "bigint", "smallint", "tinyint"}:
            return _to_integer(value)
        if t in {"decimal", "numeric", "number"}:
            return _to_decimal(value, precision=precision, scale=scale)
        if t in {"float", "double", "real"}:
            return _to_float(value)
        if t in {"date"}:
            return _to_date(value, format=format)
        if t in {"datetime", "timestamp"}:
            return _to_datetime(value, format=format)
        if t in {"boolean", "bool"}:
            return _to_boolean(value)
    except (ValueError, TypeError, InvalidOperation, OverflowError):
        return default

    raise ValueError(f"Unknown target_type: {target_type!r}")


# ── Per-type converters ───────────────────────────────────────────────────────

def _to_string(value: Any) -> str:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return str(value)


def _to_integer(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float, Decimal)):
        return int(value)
    # Strip formatting characters common in financial strings: "$1,234"
    cleaned = re.sub(r"[,$€£\s]", "", str(value))
    return int(Decimal(cleaned))


def _to_decimal(
    value: Any,
    *,
    precision: int | None,
    scale: int | None,
) -> Decimal:
    if isinstance(value, bool):
        raw = Decimal(int(value))
    elif isinstance(value, Decimal):
        raw = value
    else:
        cleaned = re.sub(r"[,$€£\s]", "", str(value))
        raw = Decimal(cleaned)

    if scale is not None:
        quantizer = Decimal(10) ** (-scale)
        raw = raw.quantize(quantizer, rounding=ROUND_HALF_UP)

    # Precision check (informational — does not truncate)
    if precision is not None:
        digits = len(raw.as_tuple().digits)
        if digits > precision:
            raise ValueError(
                f"Value {raw} exceeds precision {precision} (has {digits} digits)"
            )

    return raw


def _to_float(value: Any) -> float:
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, float):
        return value
    cleaned = re.sub(r"[,$€£\s]", "", str(value))
    return float(cleaned)


def _to_date(value: Any, *, format: str | None) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    s = str(value).strip()
    if format:
        return datetime.strptime(s, format).date()
    # Try ISO first, then common financial formats
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y", "%Y%m%d"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    raise ValueError(f"Cannot parse date: {value!r}")


def _to_datetime(value: Any, *, format: str | None) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    s = str(value).strip()
    if format:
        return datetime.strptime(s, format)
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse datetime: {value!r}")


def _to_boolean(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    s = str(value).lower().strip()
    if s in _TRUTHY:
        return True
    if s in _FALSY:
        return False
    raise ValueError(f"Cannot coerce {value!r} to boolean")
