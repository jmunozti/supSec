"""Abstract base reporter."""

from abc import ABC, abstractmethod
from pathlib import Path

from supsec.models import ScanResult


class BaseReporter(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Reporter format name."""

    @abstractmethod
    def render(self, result: ScanResult) -> str:
        """Return the report as a string."""

    def write(self, result: ScanResult, output_path: Path) -> None:
        """Write the report to a file."""
        output_path.write_text(self.render(result))
