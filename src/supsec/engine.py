"""Scan engine — orchestrates scanners, applies config filters, caches results."""

import hashlib
from pathlib import Path

from supsec.config import SupSecConfig
from supsec.models import Finding, ScanResult
from supsec.scanners import get_all_scanners
from supsec.scanners.base import BaseScanner


class ScanEngine:
    """Orchestrates all registered scanners across a target directory.

    OOP patterns:
      - Strategy: each scanner is a strategy for a file type
      - Config-driven filtering: ignore paths, rules, severity overrides
      - Cache: skip files with identical content hash
    """

    def __init__(
        self,
        scanners: list[BaseScanner] | None = None,
        config: SupSecConfig | None = None,
    ):
        self.config = config or SupSecConfig()
        all_scanners = scanners or get_all_scanners()
        if self.config.scanners:
            self.scanners = [s for s in all_scanners if s.name in self.config.scanners]
        else:
            self.scanners = all_scanners
        self._cache: dict[str, list[Finding]] = {}

    def scan(self, target: Path) -> ScanResult:
        result = ScanResult(target=str(target))
        for scanner in self.scanners:
            findings = scanner.scan_tree(target)
            result.findings.extend(self._apply_filters(findings))
        return result

    def scan_files(self, files: list[Path]) -> ScanResult:
        """Scan only specific files (for --changed-only mode)."""
        result = ScanResult(target="changed files")
        for path in files:
            if not path.exists() or not path.is_file():
                continue
            rel = str(path)
            if self.config.is_path_ignored(rel):
                continue
            for scanner in self.scanners:
                if scanner.accepts(path):
                    content_hash = self._hash_file(path)
                    cache_key = f"{scanner.name}:{content_hash}"
                    if cache_key in self._cache:
                        result.findings.extend(self._cache[cache_key])
                    else:
                        findings = self._apply_filters(scanner.scan(path))
                        self._cache[cache_key] = findings
                        result.findings.extend(findings)
        return result

    def scan_with_filter(self, target: Path, scanner_names: list[str]) -> ScanResult:
        """Run only the named scanners."""
        filtered = [s for s in self.scanners if s.name in scanner_names]
        engine = ScanEngine(scanners=filtered, config=self.config)
        return engine.scan(target)

    def _apply_filters(self, findings: list[Finding]) -> list[Finding]:
        """Apply config-driven ignore rules, path filters, and severity overrides."""
        filtered = []
        for f in findings:
            if self.config.is_path_ignored(f.file):
                continue
            if self.config.is_rule_ignored(f.rule_id):
                continue
            override = self.config.get_severity_override(f.rule_id)
            if override:
                f = Finding(
                    rule_id=f.rule_id,
                    severity=override,
                    file=f.file,
                    line=f.line,
                    message=f.message,
                    remediation=f.remediation,
                    scanner=f.scanner,
                    reference=f.reference,
                )
            filtered.append(f)
        return filtered

    @staticmethod
    def _hash_file(path: Path) -> str:
        return hashlib.md5(path.read_bytes()).hexdigest()
