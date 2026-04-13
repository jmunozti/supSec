"""Plain JSON reporter — for scripting with jq."""

import json

from supsec.models import ScanResult
from supsec.reporters.base import BaseReporter


class JSONReporter(BaseReporter):
    @property
    def name(self) -> str:
        return "json"

    def render(self, result: ScanResult) -> str:
        return json.dumps(
            {
                "target": result.target,
                "total": len(result.findings),
                "critical": result.critical_count,
                "high": result.high_count,
                "has_blockers": result.has_blockers,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity.value,
                        "file": f.file,
                        "line": f.line,
                        "message": f.message,
                        "remediation": f.remediation,
                        "scanner": f.scanner,
                        "reference": f.reference,
                    }
                    for f in result.sorted_findings()
                ],
            },
            indent=2,
        )
