# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
org_config_loader.py
Loads org_config.yaml and warehouse_registry.yaml once at startup.
All agents import from here. Missing files / keys fall back to built-in defaults.
"""
from __future__ import annotations
import os
import time
import yaml
from pathlib import Path

_CONFIG_DIR = Path(__file__).parent.parent / "config"

# ── TTL cache for YAML files ──────────────────────────────────────────────────
# Replaces @lru_cache(maxsize=1) so that runtime edits to org_config.yaml or
# warehouse_registry.yaml are picked up within _TTL_SECS without a restart.
#
# Strategy:
#   - On every call, check if _TTL_SECS have elapsed since the last mtime check.
#   - If yes, stat the file; if the mtime changed, reload it.
#   - If the mtime is unchanged (or the stat interval hasn't elapsed), return cached data.
#
# No external dependencies (watchdog, inotify) required.

_TTL_SECS = 60.0          # seconds between mtime checks
_yaml_cache: dict[Path, tuple[float, float, dict]] = {}
# _yaml_cache[path] = (last_mtime, last_check_monotonic, data_dict)


def _get_mtime(path: Path) -> float:
    """Return os.path.getmtime or 0.0 on error."""
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


def _cache_hit(path: Path, now: float) -> tuple[bool, dict]:
    """Return (hit, data) from cache if still valid; (False, {}) if stale or absent."""
    if path not in _yaml_cache:
        return False, {}
    last_mtime, last_check, data = _yaml_cache[path]
    if now - last_check < _TTL_SECS:
        return True, data
    current_mtime = _get_mtime(path)
    if current_mtime == 0.0 or current_mtime == last_mtime:
        _yaml_cache[path] = (last_mtime, now, data)
        return True, data
    return False, {}


def _fresh_load(path: Path, now: float) -> dict:
    """Load YAML from disk (or return {} if absent/unreadable), update cache."""
    if not path.exists():
        _yaml_cache[path] = (0.0, now, {})
        return {}
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        data = {}
    mtime = _get_mtime(path)
    _yaml_cache[path] = (mtime, now, data)
    return data


def _load_yaml(path: Path) -> dict:
    """Load a YAML file with a TTL-based mtime cache. Thread-safe for asyncio."""
    now = time.monotonic()
    hit, data = _cache_hit(path, now)
    if hit:
        return data
    return _fresh_load(path, now)


def get_org_config() -> dict:
    return _load_yaml(_CONFIG_DIR / "org_config.yaml")


def get_warehouse_registry() -> dict:
    data = _load_yaml(_CONFIG_DIR / "warehouse_registry.yaml")
    return data.get("warehouses", {})


# ── G1: pattern signals ───────────────────────────────────────────────────────
_DEFAULT_SCD2_SIGNALS      = ("SCD", "HISTORY", "HIST", "ARCHIVE", "SCD2", "DIM_HIST")
_DEFAULT_UPSERT_SIGNALS    = ("UPSERT", "UPDATE", "MERGE", "DIM_", "_DIM", "DIMENSION")
_DEFAULT_INC_SIGNALS       = ("APPEND", "_INC", "INC_", "DELTA", "INCREMENTAL", "RECENT")
_DEFAULT_EXPR_INDICATORS   = [
    "IIF(", "DECODE(", "TO_DATE(", "IN(", "INSTR(", "SUBSTR(",
    "TRUNC(", "ROUND(", ":LKP.", "$$", "$$$"
]


def get_pattern_signals() -> dict:
    cfg = get_org_config().get("pattern_signals", {})
    return {
        "scd2": tuple(list(_DEFAULT_SCD2_SIGNALS) +
                      cfg.get("scd2", {}).get("target_name_contains", [])),
        "upsert": tuple(list(_DEFAULT_UPSERT_SIGNALS) +
                        cfg.get("upsert", {}).get("target_name_contains", [])),
        "incremental_append": tuple(list(_DEFAULT_INC_SIGNALS) +
                                    cfg.get("incremental_append", {}).get("target_name_contains", [])),
        "expression_complexity": list(_DEFAULT_EXPR_INDICATORS) +
                                  cfg.get("expression_complexity", {}).get("additional_indicators", []),
    }


# ── G2: audit fields ──────────────────────────────────────────────────────────
_DEFAULT_AUDIT_FIELDS = {
    "insert_timestamp": {"column": "DW_INSERT_DT",  "expression": "current_timestamp()"},
    "update_timestamp": {"column": "DW_UPDATE_DT",  "expression": "current_timestamp()"},
    "batch_id":         {"column": "ETL_BATCH_ID",  "expression": "%(job_parameter)s"},
    "source_system":    {"column": "ETL_SOURCE",    "expression": "%(source_system_name)s"},
}


def get_audit_fields() -> list[dict] | None:
    """
    Returns list of {column, expression} dicts, or None if disabled.
    If org_config audit_fields is an empty list, returns None (disabled).
    """
    cfg = get_org_config()
    if "audit_fields" not in cfg:
        # Use defaults
        return list(_DEFAULT_AUDIT_FIELDS.values())
    val = cfg["audit_fields"]
    if val == [] or val is None:
        return None  # disabled
    # Merge: org overrides default
    merged = dict(_DEFAULT_AUDIT_FIELDS)
    if isinstance(val, dict):
        merged.update(val)
    return list(merged.values())


def build_dw_audit_rules() -> str:
    """Build the _DW_AUDIT_RULES string from config."""
    fields = get_audit_fields()
    if not fields:
        return ""  # audit fields disabled
    lines = [
        "Standard DW audit fields — apply to ALL target tables regardless of documentation:"
    ]
    for f in fields:
        col = f.get("column", "")
        expr = f.get("expression", "current_timestamp()")
        lines.append(f"- Any target field matching {col} → populate with {expr}")
    lines += [
        "These fields are standard DW convention and intentionally 'unmapped' in Informatica.",
        "Never leave them NULL in generated code — always populate with appropriate runtime values.",
    ]
    return "\n".join(lines)


# ── G4: verification policy ───────────────────────────────────────────────────
def get_verification_policy() -> dict:
    return get_org_config().get("verification_policy", {})


# ── G5: warehouse credential overrides ───────────────────────────────────────
def get_warehouse_cred_overrides() -> dict:
    return get_org_config().get("warehouse_credential_overrides", {})


# ── G6: pipeline options ──────────────────────────────────────────────────────
def get_pipeline_options() -> dict:
    return get_org_config().get("pipeline_options", {"skip_steps": [], "auto_approve_gates": []})


def should_skip_step(step_num: int, pattern: str | None = None,
                     tier: str | None = None, confidence: str | None = None) -> bool:
    opts = get_pipeline_options()
    for rule in opts.get("skip_steps", []):
        if rule.get("step") != step_num:
            continue
        cond = rule.get("condition", "always")
        if _eval_condition(cond, pattern, tier, confidence):
            return True
    return False


def should_auto_approve_gate(gate_num: int, pattern: str | None = None,
                              tier: str | None = None, confidence: str | None = None) -> bool:
    opts = get_pipeline_options()
    for rule in opts.get("auto_approve_gates", []):
        if rule.get("gate") != gate_num:
            continue
        cond = rule.get("condition", "never")
        if _eval_condition(cond, pattern, tier, confidence):
            return True
    return False


def _cond_is_always_or_never(cond: str) -> bool | None:
    """Return True/False for 'always'/'never', None for other conditions."""
    if cond == "always":
        return True
    if cond == "never":
        return False
    return None


def _pattern_matches(cond_l: str, pattern: str | None) -> bool:
    """Return True if cond_l contains an exact pattern== match."""
    return bool(pattern and f"pattern=={pattern.lower()}" in cond_l.replace(" ", ""))


def _tier_matches(cond_l: str, tier: str | None) -> bool:
    """Return True if tier is listed inside a 'tier in [...]' clause in cond_l."""
    if not tier:
        return False
    import re
    m = re.search(r"tier in \[([^\]]+)\]", cond_l)
    if not m:
        return False
    allowed = {t.strip().upper() for t in m.group(1).split(",")}
    return tier.upper() in allowed


def _eval_condition(cond: str, pattern: str | None,
                    tier: str | None, confidence: str | None) -> bool:
    result = _cond_is_always_or_never(cond)
    if result is not None:
        return result
    cond_l = cond.lower()
    return _pattern_matches(cond_l, pattern) or _tier_matches(cond_l, tier)


# ── G7: parser unsupported types ─────────────────────────────────────────────
_DEFAULT_UNSUPPORTED_TYPES = {
    "Java Transformation", "External Procedure",
    "Advanced External Procedure", "Stored Procedure"
}


def get_unsupported_types() -> set[str]:
    extra = get_org_config().get("parser_options", {}).get("additional_unsupported_types", [])
    return _DEFAULT_UNSUPPORTED_TYPES | set(extra)
