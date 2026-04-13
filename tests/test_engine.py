"""Integration tests for the ScanEngine orchestrator."""

from pathlib import Path

import pytest

from supsec.engine import ScanEngine
from supsec.models import Severity


@pytest.fixture
def vulnerable_dir():
    return Path(__file__).parent.parent / "examples" / "vulnerable"


@pytest.fixture
def clean_dir():
    return Path(__file__).parent.parent / "examples" / "clean"


class TestScanEngine:
    def test_scan_vulnerable_finds_issues(self, vulnerable_dir):
        engine = ScanEngine()
        result = engine.scan(vulnerable_dir)
        assert len(result.findings) > 0
        assert result.has_blockers

    def test_scan_vulnerable_finds_critical(self, vulnerable_dir):
        engine = ScanEngine()
        result = engine.scan(vulnerable_dir)
        assert result.critical_count > 0

    def test_scan_clean_no_blockers(self, clean_dir):
        engine = ScanEngine()
        result = engine.scan(clean_dir)
        blockers = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(blockers) == 0

    def test_filter_by_scanner_name(self, vulnerable_dir):
        engine = ScanEngine()
        result = engine.scan_with_filter(vulnerable_dir, ["dockerfile"])
        assert all(f.scanner == "dockerfile" for f in result.findings)
        assert len(result.findings) > 0

    def test_filter_excludes_other_scanners(self, vulnerable_dir):
        engine = ScanEngine()
        result = engine.scan_with_filter(vulnerable_dir, ["terraform"])
        assert all(f.scanner == "terraform" for f in result.findings)


class TestScanResult:
    def test_sorted_findings_critical_first(self, vulnerable_dir):
        engine = ScanEngine()
        result = engine.scan(vulnerable_dir)
        sorted_f = result.sorted_findings()
        if len(sorted_f) >= 2:
            assert sorted_f[0].severity.weight >= sorted_f[-1].severity.weight
