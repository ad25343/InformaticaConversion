# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
config_loader.py — YAML config loader and pattern dispatcher
=============================================================
Entry point for all converted Informatica mappings.

Usage
-----
from etl_patterns import config_loader

# Run a single mapping
config_loader.run("config/m_dim_customer_load.yaml")

# Or pass an already-parsed dict
config_loader.run_dict(cfg)

Config envelope
---------------
See docs/DESIGN_PATTERN_LIBRARY.md §7 for the full schema.

Minimum required fields:
  pattern:  truncate_and_load   # one of the 10 registered patterns
  source:
    type:   database
    ...
  target:
    type:   database
    ...
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from etl_patterns.exceptions import ConfigError, PatternNotFoundError

log = logging.getLogger(__name__)

# ── Pattern registry ─────────────────────────────────────────────────────────
# Patterns are imported lazily so the library stays usable even if a subset of
# dependencies is missing (e.g. no SQLAlchemy installed for pure file jobs).

_PATTERN_REGISTRY: dict[str, str] = {
    "truncate_and_load":   "etl_patterns.patterns.truncate_and_load:TruncateAndLoadPattern",
    "incremental_append":  "etl_patterns.patterns.incremental_append:IncrementalAppendPattern",
    "upsert":              "etl_patterns.patterns.upsert:UpsertPattern",
    "scd2":                "etl_patterns.patterns.scd2:Scd2Pattern",
    "lookup_enrich":       "etl_patterns.patterns.lookup_enrich:LookupEnrichPattern",
    "aggregation_load":    "etl_patterns.patterns.aggregation_load:AggregationLoadPattern",
    "filter_and_route":    "etl_patterns.patterns.filter_and_route:FilterAndRoutePattern",
    "union_consolidate":   "etl_patterns.patterns.union_consolidate:UnionConsolidatePattern",
    "expression_transform":"etl_patterns.patterns.expression_transform:ExpressionTransformPattern",
    "pass_through":        "etl_patterns.patterns.pass_through:PassThroughPattern",
}

# ── Required top-level keys ───────────────────────────────────────────────────
_REQUIRED_KEYS = {"pattern", "source", "target"}


# ── Public API ────────────────────────────────────────────────────────────────

def run(config_path: str | Path, **overrides: Any) -> dict[str, Any]:
    """
    Load a YAML config file and execute the referenced pattern.

    Parameters
    ----------
    config_path  Path to the mapping YAML file.
    **overrides  Key-value pairs that override top-level config values.
                 Useful for injecting runtime batch_id, run_id, etc.

    Returns
    -------
    A result dict with at minimum:
      {"rows_read": N, "rows_written": N, "pattern": "...", "status": "success|error"}
    """
    cfg = load(config_path)
    cfg.update(overrides)
    return run_dict(cfg)


def run_dict(config: dict[str, Any]) -> dict[str, Any]:
    """
    Execute a pattern from an already-parsed config dict.

    Parameters
    ----------
    config  Fully-parsed pattern configuration.

    Returns
    -------
    Result dict (same shape as ``run()``).
    """
    validate(config)
    pattern_name = config["pattern"]
    pattern_cls  = _load_pattern_class(pattern_name)

    log.info(
        "config_loader: running pattern '%s' (mapping: %s)",
        pattern_name,
        config.get("mapping_name", "<unnamed>"),
    )

    pattern = pattern_cls(config)
    return pattern.execute()


def load(config_path: str | Path) -> dict[str, Any]:
    """
    Parse a YAML config file and return the config dict.

    Raises
    ------
    ConfigError  If the file does not exist or cannot be parsed.
    """
    p = Path(config_path)
    if not p.exists():
        raise ConfigError(f"Config file not found: {p}")
    try:
        with open(p, encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML parse error in {p}: {exc}") from exc

    if not isinstance(cfg, dict):
        raise ConfigError(f"Config file must be a YAML mapping, got {type(cfg).__name__}: {p}")

    # Inject the config path so patterns can use it for logging
    cfg.setdefault("_config_path", str(p))
    return cfg


def validate(config: dict[str, Any]) -> None:
    """
    Validate required top-level fields.

    Raises
    ------
    ConfigError  On validation failure.
    """
    missing = _REQUIRED_KEYS - set(config.keys())
    if missing:
        raise ConfigError(
            f"Config is missing required key(s): {sorted(missing)}"
        )

    pattern_name = config.get("pattern", "")
    if pattern_name not in _PATTERN_REGISTRY:
        raise PatternNotFoundError(
            f"Unknown pattern: {pattern_name!r}. "
            f"Registered: {sorted(_PATTERN_REGISTRY)}"
        )

    if not isinstance(config.get("source"), dict):
        raise ConfigError("'source' must be a YAML mapping")
    if not isinstance(config.get("target"), (dict, list)):
        raise ConfigError("'target' must be a YAML mapping (or list for filter_and_route)")


def registered_patterns() -> list[str]:
    """Return the list of registered pattern names."""
    return sorted(_PATTERN_REGISTRY)


# ── Internals ─────────────────────────────────────────────────────────────────

def _load_pattern_class(name: str):
    """
    Dynamically import and return the pattern class for *name*.
    """
    import importlib  # noqa: PLC0415
    ref = _PATTERN_REGISTRY.get(name)
    if ref is None:
        raise PatternNotFoundError(f"Pattern not registered: {name!r}")

    module_path, class_name = ref.rsplit(":", 1)
    try:
        module = importlib.import_module(module_path)
    except ImportError as exc:
        raise PatternNotFoundError(
            f"Cannot import pattern module '{module_path}': {exc}"
        ) from exc

    try:
        return getattr(module, class_name)
    except AttributeError as exc:
        raise PatternNotFoundError(
            f"Class '{class_name}' not found in '{module_path}'"
        ) from exc
