"""supSec CLI — the main user interface.

Usage:
    supsec scan .                          # scan current dir, console output
    supsec scan ./project --fmt sarif      # SARIF for GitHub Security tab
    supsec scan . --fmt markdown -o report.md
    supsec scan . --scanners dockerfile,secrets
    supsec scan . --changed-only           # only scan git-changed files
    supsec fix .                           # auto-fix simple issues
    supsec install-hook                    # install git pre-commit hook
"""

import subprocess
import sys
from pathlib import Path

import typer
from rich.console import Console

from supsec import __version__
from supsec.config import load_config
from supsec.engine import ScanEngine
from supsec.reporters import REPORTERS

app = typer.Typer(
    name="supsec",
    help="supSec — DevSecOps scanner for Dockerfiles, CI configs, Terraform, K8s manifests, and secrets",
    no_args_is_help=True,
)
console = Console()


def _get_changed_files(target: Path) -> list[Path]:
    """Get files changed in the current git working tree (staged + unstaged + untracked)."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMRT", "HEAD"],
            capture_output=True, text=True, timeout=10, cwd=target,
        )
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            capture_output=True, text=True, timeout=10, cwd=target,
        )
        files = set(result.stdout.strip().splitlines() + untracked.stdout.strip().splitlines())
        return [target / f for f in files if f]
    except Exception:
        return []


@app.command()
def scan(
    target: Path = typer.Argument(".", help="Directory or file to scan"),
    output_format: str = typer.Option("console", "--fmt", "-f", help="Output format: console, sarif, markdown, json"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to file"),
    scanners: str | None = typer.Option(None, "--scanners", "-s", help="Comma-separated scanner names"),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit 1 if findings at this severity or above"),
    changed_only: bool = typer.Option(False, "--changed-only", help="Only scan git-changed files"),
    config_file: Path | None = typer.Option(None, "--config", "-c", help="Path to .supsec.yaml config"),
) -> None:
    """Scan a directory for security issues."""
    if not target.exists():
        console.print(f"[red]Target not found: {target}[/red]")
        sys.exit(1)

    cfg = load_config(config_file or target / ".supsec.yaml")
    engine = ScanEngine(config=cfg)

    if scanners:
        result = engine.scan_with_filter(target, scanners.split(","))
    elif changed_only:
        result = engine.scan_files(_get_changed_files(target))
    else:
        result = engine.scan(target)

    reporter_cls = REPORTERS.get(output_format)
    if not reporter_cls:
        console.print(f"[red]Unknown format: {output_format}. Available: {', '.join(REPORTERS)}[/red]")
        sys.exit(1)

    reporter = reporter_cls()
    report_text = reporter.render(result)

    if output:
        reporter.write(result, output)
        console.print(f"Report written to {output}")
    else:
        print(report_text)

    severity_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    threshold = severity_map.get(fail_on.lower(), 4)
    max_severity = max((f.severity.weight for f in result.findings), default=0)
    if max_severity >= threshold:
        sys.exit(1)


@app.command()
def fix(
    target: Path = typer.Argument(".", help="Directory to auto-fix"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be fixed without modifying files"),
) -> None:
    """Auto-fix simple security issues (Dockerfiles, CI configs)."""
    from supsec.fixer import AutoFixer

    fixer = AutoFixer(dry_run=dry_run)
    fixes = fixer.fix_tree(target)
    if not fixes:
        console.print("[green]Nothing to fix.[/green]")
    else:
        for f in fixes:
            prefix = "[dim]DRY-RUN[/dim] " if dry_run else ""
            console.print(f"{prefix}[cyan]FIXED[/cyan] {f.file}:{f.line} — {f.description}")
        console.print(f"\n{len(fixes)} fix(es) {'would be ' if dry_run else ''}applied.")


@app.command()
def install_hook() -> None:
    """Install a git pre-commit hook that runs supSec before every commit."""
    git_dir = Path(".git")
    if not git_dir.is_dir():
        console.print("[red]Not a git repository. Run this from the repo root.[/red]")
        sys.exit(1)

    hook_path = git_dir / "hooks" / "pre-commit"
    hook_content = """#!/usr/bin/env bash
# supSec pre-commit hook — blocks commits with critical/high findings
set -euo pipefail

echo "Running supSec scan..."
if command -v supsec &>/dev/null; then
    supsec scan . --changed-only --fail-on high
elif command -v uv &>/dev/null; then
    uv run supsec scan . --changed-only --fail-on high
else
    echo "supsec not found — install with: uv sync"
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
