"""Rich terminal output reporter."""

import io

from rich.console import Console
from rich.table import Table

from supsec.models import ScanResult, Severity
from supsec.reporters.base import BaseReporter

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


class ConsoleReporter(BaseReporter):
    @property
    def name(self) -> str:
        return "console"

    def render(self, result: ScanResult) -> str:
        buf = io.StringIO()
        console = Console(file=buf, width=120, force_terminal=True)
        findings = result.sorted_findings()

        if not findings:
            console.print("[bold green]No security issues found.[/bold green]")
            return buf.getvalue()

        table = Table(title=f"supSec scan: {result.target}", show_lines=False, expand=True)
        table.add_column("Severity", width=10)
        table.add_column("File:Line", width=35)
        table.add_column("Rule", width=12)
        table.add_column("Message")

        for f in findings:
            style = SEVERITY_COLORS.get(f.severity, "")
            table.add_row(
                f"[{style}]{f.severity.value}[/{style}]",
                f"{f.file}:{f.line}",
                f.rule_id,
                f.message,
            )

        console.print(table)
        console.print()

        counts = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        summary_parts = [f"{v} {k.lower()}" for k, v in counts.items()]
        console.print(f"[bold]{len(findings)} findings[/bold] ({', '.join(summary_parts)})")

        if result.has_blockers:
            console.print(
                "[bold red]BLOCKED — critical or high severity issues must be fixed[/bold red]"
            )
        else:
            console.print("[green]PASSED — no blocking issues[/green]")

        return buf.getvalue()
