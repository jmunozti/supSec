"""Tests for JSON reporter."""

import json

from supsec.models import Finding, ScanResult, Severity
from supsec.reporters.json_reporter import JSONReporter


class TestJSONReporter:
    def test_valid_json(self):
        result = ScanResult(target="./test", findings=[
            Finding("TEST-001", Severity.HIGH, "file.py", 1, "msg", "fix", "test"),
        ])
        output = JSONReporter().render(result)
        data = json.loads(output)
        assert data["total"] == 1
        assert data["has_blockers"] is True
        assert data["findings"][0]["rule_id"] == "TEST-001"

    def test_empty_result(self):
        result = ScanResult(target="./clean", findings=[])
        output = JSONReporter().render(result)
        data = json.loads(output)
        assert data["total"] == 0
        assert data["has_blockers"] is False
        assert data["findings"] == []
