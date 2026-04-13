"""supSec CLI — the main user interface.

Usage:
    supsec scan .                          # scan current dir, console output
    supsec scan ./project --format sarif   # SARIF for GitHub Security tab
    supsec scan . --format markdown -o report.md
    supsec scan . --scanners dockerfile,secrets
    supsec install-hook                    # install git pre-commit hook
"""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from supsec import __version__
from supsec.engine import ScanEngine
from supsec.reporters import REPORTERS

app = typer.Typer(
    name="supsec",
    help="supSec — DevSecOps scanner for Dockerfiles, CI configs, Terraform, and secrets",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    target: Path = typer.Argument(".", help="Directory or file to scan"),
    format: str = typer.Option("console", "--format", "-f", help="Output format: console, sarif, markdown"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write report to file"),
    scanners: Optional[str] = typer.Option(None, "--scanners", "-s", help="Comma-separated scanner names"),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit 1 if findings at this severity or above: critical, high, medium, low"),
) -> None:
    """Scan a directory for security issues."""
    if not target.exists():
        console.print(f"[red]Target not found: {target}[/red]")
        raise typer.Exit(1)

    engine = ScanEngine()
    if scanners:
        result = engine.scan_with_filter(target, scanners.split(","))
    else:
        result = engine.scan(target)

    # Select reporter
    reporter_cls = REPORTERS.get(format)
    if not reporter_cls:
        console.print(f"[red]Unknown format: {format}. Available: {', '.join(REPORTERS)}[/red]")
        raise typer.Exit(1)

    reporter = reporter_cls()
    report_text = reporter.render(result)

    if output:
        reporter.write(result, output)
        console.print(f"Report written to {output}")
    else:
        if format == "console":
            # ConsoleReporter already uses rich; just print the captured text
            print(report_text)
        else:
            print(report_text)

    # Exit code logic
    severity_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    threshold = severity_map.get(fail_on.lower(), 4)
    max_severity = max((f.severity.weight for f in result.findings), default=0)
    if max_severity >= threshold:
        raise typer.Exit(1)


@app.command()
def install_hook() -> None:
    """Install a git pre-commit hook that runs supSec before every commit."""
    git_dir = Path(".git")
    if not git_dir.is_dir():
        console.print("[red]Not a git repository. Run this from the repo root.[/red]")
        raise typer.Exit(1)

    hook_path = git_dir / "hooks" / "pre-commit"
    hook_content = """#!/usr/bin/env bash
# supSec pre-commit hook — blocks commits with critical/high findings
set -euo pipefail

echo "Running supSec scan..."
if command -v supsec &>/dev/null; then
    supsec scan . --fail-on high
else
    echo "supsec not found — install with: pip install -e ."
    exit 1
fi
"""
    hook_path.write_text(hook_content)
    hook_path.chmod(0o755)
    console.print(f"[green]Pre-commit hook installed at {hook_path}[/green]")


@app.command()
def version() -> None:
    """Show supSec version."""
    console.print(f"supSec {__version__}")


if __name__ == "__main__":
    app()
