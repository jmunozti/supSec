"""Markdown reporter — suitable for PR comments and documentation."""

from supsec.models import ScanResult, Severity
from supsec.reporters.base import BaseReporter

EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "ℹ️",
}


class MarkdownReporter(BaseReporter):
    @property
    def name(self) -> str:
        return "markdown"

    def render(self, result: ScanResult) -> str:
        findings = result.sorted_findings()
        lines = [f"# supSec Scan Report\n", f"**Target:** `{result.target}`\n"]

        if not findings:
            lines.append("**Result:** No security issues found.\n")
            return "\n".join(lines)

        lines.append(f"**Findings:** {len(findings)}\n")
        lines.append("| Severity | File | Line | Rule | Message |")
        lines.append("|---|---|---|---|---|")

        for f in findings:
            emoji = EMOJI.get(f.severity, "")
            lines.append(
                f"| {emoji} {f.severity.value} | `{f.file}` | {f.line} | {f.rule_id} | {f.message} |"
            )

        lines.append("")

        # Remediation section
        lines.append("## Remediations\n")
        seen = set()
        for f in findings:
            key = f.rule_id
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"### {f.rule_id}: {f.message}\n")
            lines.append(f"**Fix:** {f.remediation}\n")
            if f.reference:
                lines.append(f"**Reference:** {f.reference}\n")

        # Verdict
        lines.append("---\n")
        if result.has_blockers:
            lines.append("**BLOCKED** — fix critical and high severity issues before merging.\n")
        else:
            lines.append("**PASSED** — no blocking issues.\n")

        return "\n".join(lines)
