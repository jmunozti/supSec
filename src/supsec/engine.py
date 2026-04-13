"""Scan engine — orchestrates scanners and produces a ScanResult."""

from pathlib import Path

from supsec.models import ScanResult
from supsec.scanners import get_all_scanners
from supsec.scanners.base import BaseScanner


class ScanEngine:
    """Orchestrates all registered scanners across a target directory.

    OOP pattern: Strategy — each scanner is a strategy for a file type.
    The engine delegates to each scanner based on its `accepts()` method.
    """

    def __init__(self, scanners: list[BaseScanner] | None = None):
        self.scanners = scanners or get_all_scanners()

    def scan(self, target: Path) -> ScanResult:
        result = ScanResult(target=str(target))
        for scanner in self.scanners:
            findings = scanner.scan_tree(target)
            result.findings.extend(findings)
        return result

    def scan_with_filter(self, target: Path, scanner_names: list[str]) -> ScanResult:
        """Run only the named scanners."""
        filtered = [s for s in self.scanners if s.name in scanner_names]
        engine = ScanEngine(scanners=filtered)
        return engine.scan(target)
