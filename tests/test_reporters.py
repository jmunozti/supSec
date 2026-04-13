"""Tests for report output formats."""

import json

import pytest

from supsec.models import Finding, ScanResult, Severity
from supsec.reporters.console import ConsoleReporter
from supsec.reporters.markdown import MarkdownReporter
from supsec.reporters.sarif import SARIFReporter


@pytest.fixture
def sample_result():
    return ScanResult(
        target="./test",
        findings=[
            Finding(
                "DOCKER-001",
                Severity.HIGH,
                "Dockerfile",
                3,
                "Runs as root",
                "Add USER app",
                "dockerfile",
            ),
            Finding(
                "SEC-001",
                Severity.CRITICAL,
                "config.py",
                10,
                "AWS key detected",
                "Rotate and remove",
                "secrets",
            ),
            Finding(
                "TF-002",
                Severity.HIGH,
                "main.tf",
                5,
                "Open security group",
                "Restrict CIDR",
                "terraform",
            ),
        ],
    )


@pytest.fixture
def empty_result():
    return ScanResult(target="./clean", findings=[])


class TestConsoleReporter:
    def test_renders_findings(self, sample_result):
        report = ConsoleReporter().render(sample_result)
        assert "CRITICAL" in report
        assert "BLOCKED" in report

    def test_renders_clean(self, empty_result):
        report = ConsoleReporter().render(empty_result)
        assert "No security issues" in report


class TestSARIFReporter:
    def test_valid_json(self, sample_result):
        report = SARIFReporter().render(sample_result)
        sarif = json.loads(report)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 3

    def test_rule_ids_present(self, sample_result):
        report = SARIFReporter().render(sample_result)
        sarif = json.loads(report)
        rule_ids = [r["ruleId"] for r in sarif["runs"][0]["results"]]
        assert "SEC-001" in rule_ids

    def test_empty_result(self, empty_result):
        report = SARIFReporter().render(empty_result)
        sarif = json.loads(report)
        assert len(sarif["runs"][0]["results"]) == 0


class TestMarkdownReporter:
    def test_contains_table(self, sample_result):
        report = MarkdownReporter().render(sample_result)
        assert "| Severity |" in report
        assert "DOCKER-001" in report

    def test_contains_remediation(self, sample_result):
        report = MarkdownReporter().render(sample_result)
        assert "## Remediations" in report

    def test_blocked_verdict(self, sample_result):
        report = MarkdownReporter().render(sample_result)
        assert "BLOCKED" in report

    def test_clean_verdict(self, empty_result):
        report = MarkdownReporter().render(empty_result)
        assert "No security issues" in report
