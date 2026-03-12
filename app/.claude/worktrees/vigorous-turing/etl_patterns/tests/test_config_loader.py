"""
tests/test_config_loader.py — Unit tests for config_loader
"""
from __future__ import annotations

import pytest
import yaml

from etl_patterns.config_loader import load, validate, registered_patterns
from etl_patterns.exceptions import ConfigError, PatternNotFoundError


MINIMAL_CONFIG = {
    "pattern":      "pass_through",
    "mapping_name": "test_mapping",
    "source": {"type": "flat_file", "path": "/tmp/in.csv"},
    "target": {"type": "flat_file", "path": "/tmp/out.csv"},
}


class TestValidate:
    def test_valid_config_passes(self):
        validate(MINIMAL_CONFIG)  # should not raise

    def test_missing_pattern_raises(self):
        cfg = {k: v for k, v in MINIMAL_CONFIG.items() if k != "pattern"}
        with pytest.raises(ConfigError, match="missing required key"):
            validate(cfg)

    def test_missing_source_raises(self):
        cfg = {k: v for k, v in MINIMAL_CONFIG.items() if k != "source"}
        with pytest.raises(ConfigError, match="missing required key"):
            validate(cfg)

    def test_missing_target_raises(self):
        cfg = {k: v for k, v in MINIMAL_CONFIG.items() if k != "target"}
        with pytest.raises(ConfigError, match="missing required key"):
            validate(cfg)

    def test_unknown_pattern_raises(self):
        cfg = {**MINIMAL_CONFIG, "pattern": "not_a_pattern"}
        with pytest.raises(PatternNotFoundError):
            validate(cfg)

    def test_source_not_dict_raises(self):
        cfg = {**MINIMAL_CONFIG, "source": "just_a_string"}
        with pytest.raises(ConfigError):
            validate(cfg)


class TestRegisteredPatterns:
    def test_all_ten_patterns_registered(self):
        patterns = registered_patterns()
        expected = {
            "truncate_and_load", "incremental_append", "upsert", "scd2",
            "lookup_enrich", "aggregation_load", "filter_and_route",
            "union_consolidate", "expression_transform", "pass_through",
        }
        assert expected == set(patterns)


class TestLoad:
    def test_load_missing_file_raises(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load(tmp_path / "nonexistent.yaml")

    def test_load_valid_yaml(self, tmp_path):
        p = tmp_path / "test.yaml"
        p.write_text(yaml.dump(MINIMAL_CONFIG), encoding="utf-8")
        cfg = load(p)
        assert cfg["pattern"] == "pass_through"
        assert "_config_path" in cfg

    def test_load_invalid_yaml_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("key: [unmatched bracket", encoding="utf-8")
        with pytest.raises(ConfigError, match="YAML parse error"):
            load(p)
