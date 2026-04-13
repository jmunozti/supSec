"""Report output plugins."""

from supsec.reporters.base import BaseReporter
from supsec.reporters.console import ConsoleReporter
from supsec.reporters.markdown import MarkdownReporter
from supsec.reporters.sarif import SARIFReporter

REPORTERS: dict[str, type[BaseReporter]] = {
    "console": ConsoleReporter,
    "sarif": SARIFReporter,
    "markdown": MarkdownReporter,
}
