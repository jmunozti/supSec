"""Abstract base class for all scanners."""

from abc import ABC, abstractmethod
from pathlib import Path

from supsec.models import Finding

# Directories that should never be scanned regardless of config
ALWAYS_SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".ruff_cache",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".egg-info",
}


class BaseScanner(ABC):
    """Every scanner must implement scan() and declare which files it handles."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable scanner name."""

    @abstractmethod
    def accepts(self, path: Path) -> bool:
        """Return True if this scanner should inspect the given file."""

    @abstractmethod
    def scan(self, path: Path) -> list[Finding]:
        """Scan a single file and return findings."""

    def scan_tree(self, root: Path) -> list[Finding]:
        """Walk a directory tree and scan all accepted files."""
        findings: list[Finding] = []
        if root.is_file():
            if self.accepts(root):
                findings.extend(self.scan(root))
            return findings
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            if any(skip in p.parts for skip in ALWAYS_SKIP_DIRS):
                continue
            if self.accepts(p):
                findings.extend(self.scan(p))
        return findings
