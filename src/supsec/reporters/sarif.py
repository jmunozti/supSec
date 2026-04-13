"""SARIF 2.1.0 reporter — compatible with GitHub Security tab."""

import json

from supsec.models import ScanResult, Severity
from supsec.reporters.base import BaseReporter

SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


class SARIFReporter(BaseReporter):
    @property
    def name(self) -> str:
        return "sarif"

    def render(self, result: ScanResult) -> str:
        rules = {}
        results = []

        for f in result.sorted_findings():
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "shortDescription": {"text": f.message},
                    "helpUri": f.reference or "",
                    "properties": {"scanner": f.scanner},
                }
            results.append({
                "ruleId": f.rule_id,
                "level": SARIF_SEVERITY_MAP.get(f.severity, "note"),
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line},
                    }
                }],
                "fixes": [{
                    "description": {"text": f.remediation},
                }] if f.remediation else [],
            })

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "supSec",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/jmunozti/supSec",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }],
        }
        return json.dumps(sarif, indent=2)
