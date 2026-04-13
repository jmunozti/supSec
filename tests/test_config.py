"""Tests for config file loading and filtering."""

import textwrap
from pathlib import Path

import pytest

from supsec.config import SupSecConfig, load_config
from supsec.models import Severity


@pytest.fixture
def write_config(tmp_path):
    def _write(content: str) -> Path:
        p = tmp_path / ".supsec.yaml"
        p.write_text(textwrap.dedent(content))
        return p

    return _write


class TestLoadConfig:
    def test_missing_file_returns_defaults(self, tmp_path):
        cfg = load_config(tmp_path / "nonexistent.yaml")
        assert cfg.ignore_paths == []
        assert cfg.ignore_rules == []

    def test_loads_ignore_paths(self, write_config):
        cfg = load_config(
            write_config("""\
            ignore_paths:
              - vendor/
              - "*.min.js"
        """)
        )
        assert "vendor/" in cfg.ignore_paths

    def test_loads_ignore_rules(self, write_config):
        cfg = load_config(
            write_config("""\
            ignore_rules:
              - DOCKER-011
        """)
        )
        assert "DOCKER-011" in cfg.ignore_rules

    def test_loads_severity_overrides(self, write_config):
        cfg = load_config(
            write_config("""\
            severity_overrides:
              DOCKER-011: HIGH
        """)
        )
        assert cfg.get_severity_override("DOCKER-011") == Severity.HIGH

    def test_loads_scanner_filter(self, write_config):
        cfg = load_config(
            write_config("""\
            scanners:
              - dockerfile
              - secrets
        """)
        )
        assert cfg.scanners == ["dockerfile", "secrets"]


class TestPathIgnoring:
    def test_ignores_matching_path(self):
        cfg = SupSecConfig(ignore_paths=["vendor/", "*.min.js"])
        assert cfg.is_path_ignored("vendor/lib/thing.py")
        assert cfg.is_path_ignored("app.min.js")

    def test_does_not_ignore_non_matching(self):
        cfg = SupSecConfig(ignore_paths=["vendor/"])
        assert not cfg.is_path_ignored("src/app.py")


class TestRuleIgnoring:
    def test_ignores_specified_rules(self):
        cfg = SupSecConfig(ignore_rules=["DOCKER-011"])
        assert cfg.is_rule_ignored("DOCKER-011")
        assert not cfg.is_rule_ignored("DOCKER-001")


class TestSeverityOverride:
    def test_overrides_severity(self):
        cfg = SupSecConfig(severity_overrides={"DOCKER-011": "HIGH"})
        assert cfg.get_severity_override("DOCKER-011") == Severity.HIGH

    def test_returns_none_for_no_override(self):
        cfg = SupSecConfig()
        assert cfg.get_severity_override("DOCKER-001") is None

    def test_invalid_severity_returns_none(self):
        cfg = SupSecConfig(severity_overrides={"DOCKER-011": "INVALID"})
        assert cfg.get_severity_override("DOCKER-011") is None
