"""
utils/string_clean.py — String normalisation helpers
=====================================================
Mirrors the common Informatica string transformation functions used across
virtually every mapping: UPPER, LOWER, LTRIM, RTRIM, TRIM, LPAD, RPAD,
SUBSTR, INSTR, REPLACECHR, REPLACESTR.

All functions are null-safe: a null/None input returns None (matching
Informatica's null propagation) unless an explicit *default* is supplied.

Usage
-----
from etl_patterns.utils.string_clean import (
    to_upper, to_lower, trim, lpad, rpad, substr, instr, replace_chr, replace_str,
)
"""
from __future__ import annotations

from typing import Any

from etl_patterns.utils.null_safe import _is_null


# ── Case ─────────────────────────────────────────────────────────────────────

def to_upper(value: Any, *, default: str | None = None) -> str | None:
    """Mirrors Informatica UPPER(). Returns None on null input."""
    if _is_null(value):
        return default
    return str(value).upper()


def to_lower(value: Any, *, default: str | None = None) -> str | None:
    """Mirrors Informatica LOWER(). Returns None on null input."""
    if _is_null(value):
        return default
    return str(value).lower()


# ── Trimming ─────────────────────────────────────────────────────────────────

def trim(value: Any, chars: str | None = None, *, default: str | None = None) -> str | None:
    """Mirrors Informatica TRIM() — trims both ends. Optional *chars* set."""
    if _is_null(value):
        return default
    return str(value).strip(chars)


def ltrim(value: Any, chars: str | None = None, *, default: str | None = None) -> str | None:
    """Mirrors Informatica LTRIM()."""
    if _is_null(value):
        return default
    return str(value).lstrip(chars)


def rtrim(value: Any, chars: str | None = None, *, default: str | None = None) -> str | None:
    """Mirrors Informatica RTRIM()."""
    if _is_null(value):
        return default
    return str(value).rstrip(chars)


# ── Padding ───────────────────────────────────────────────────────────────────

def lpad(
    value: Any,
    length: int,
    pad_char: str = " ",
    *,
    default: str | None = None,
) -> str | None:
    """
    Mirrors Informatica LPAD(value, length, pad_char).
    If len(str(value)) >= length the string is returned unchanged (no truncation).
    """
    if _is_null(value):
        return default
    s = str(value)
    if len(s) >= length:
        return s
    pad = (pad_char or " ")[0]  # Use first char only
    return s.rjust(length, pad)


def rpad(
    value: Any,
    length: int,
    pad_char: str = " ",
    *,
    default: str | None = None,
) -> str | None:
    """Mirrors Informatica RPAD(value, length, pad_char)."""
    if _is_null(value):
        return default
    s = str(value)
    if len(s) >= length:
        return s
    pad = (pad_char or " ")[0]
    return s.ljust(length, pad)


# ── Substring / search ────────────────────────────────────────────────────────

def substr(
    value: Any,
    start: int,
    length: int | None = None,
    *,
    default: str | None = None,
) -> str | None:
    """
    Mirrors Informatica SUBSTR(value, start [, length]).

    Informatica uses 1-based indexing; negative start counts from the end.
    If *length* is omitted, returns from *start* to end of string.
    """
    if _is_null(value):
        return default
    s = str(value)
    # Convert 1-based to 0-based (Informatica: start=1 → first char)
    if start > 0:
        idx = start - 1
    elif start < 0:
        idx = max(0, len(s) + start)
    else:
        idx = 0  # Informatica treats 0 same as 1

    if length is None:
        return s[idx:]
    return s[idx : idx + length]


def instr(
    value: Any,
    search: str,
    start: int = 1,
    occurrence: int = 1,
    *,
    default: int = 0,
) -> int:
    """
    Mirrors Informatica INSTR(value, search [, start [, occurrence]]).

    Returns 1-based position of *search* in *value*, or 0 if not found.
    """
    if _is_null(value) or _is_null(search):
        return default
    s   = str(value)
    sub = str(search)
    idx = (start - 1) if start > 0 else max(0, len(s) + start)

    found = 0
    for _ in range(occurrence):
        pos = s.find(sub, idx)
        if pos == -1:
            return 0
        found = pos + 1  # 1-based
        idx   = pos + 1  # advance past this occurrence

    return found


# ── Character / string replacement ───────────────────────────────────────────

def replace_chr(
    value: Any,
    old_char: str,
    new_char: str = "",
    *,
    default: str | None = None,
) -> str | None:
    """
    Mirrors Informatica REPLACECHR(value, old_char, new_char).
    Replaces every occurrence of a single character.  If *old_char* is longer
    than one character, all characters in the set are replaced individually.
    """
    if _is_null(value):
        return default
    s = str(value)
    for ch in str(old_char):
        s = s.replace(ch, new_char)
    return s


def replace_str(
    value: Any,
    old_str: str,
    new_str: str = "",
    *,
    default: str | None = None,
) -> str | None:
    """Mirrors Informatica REPLACESTR(value, old_str, new_str)."""
    if _is_null(value):
        return default
    return str(value).replace(str(old_str), str(new_str))


# ── Convenience ──────────────────────────────────────────────────────────────

def clean_whitespace(value: Any, *, default: str | None = None) -> str | None:
    """Trim and collapse interior whitespace runs to a single space."""
    if _is_null(value):
        return default
    import re  # noqa: PLC0415
    return re.sub(r"\s+", " ", str(value).strip())


def normalize_string(
    value: Any,
    *,
    upper: bool = False,
    lower: bool = False,
    strip: bool = True,
    default: str | None = None,
) -> str | None:
    """
    One-stop string normalisation used by expression_transform column maps.

    Parameters
    ----------
    upper / lower  Apply case transform (mutually exclusive; upper takes priority).
    strip          Strip surrounding whitespace (default True).
    """
    if _is_null(value):
        return default
    s = str(value)
    if strip:
        s = s.strip()
    if upper:
        s = s.upper()
    elif lower:
        s = s.lower()
    return s
