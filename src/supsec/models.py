"""Core data models for findings and scan results."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    file: str
    line: int
    message: str
    remediation: str
    scanner: str
    reference: str = ""

    @property
    def sort_key(self) -> tuple:
        return (-self.severity.weight, self.file, self.line)


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def has_blockers(self) -> bool:
        return self.critical_count > 0 or self.high_count > 0

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key)
