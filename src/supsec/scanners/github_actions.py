"""GitHub Actions workflow security scanner.

Checks for unpinned actions, exposed secrets, missing permissions, etc.
"""

import re
from pathlib import Path

import yaml

from supsec.models import Finding, Severity
from supsec.scanners.base import BaseScanner


class GitHubActionsScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "github-actions"

    def accepts(self, path: Path) -> bool:
        return ".github/workflows" in str(path) and path.suffix in (".yml", ".yaml")

    def scan(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        rel = str(path)
        try:
            text = path.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            return findings
        lines = text.splitlines()

        try:
            workflow = yaml.safe_load(text)
        except yaml.YAMLError:
            findings.append(
                Finding(
                    rule_id="GHA-000",
                    severity=Severity.HIGH,
                    file=rel,
                    line=1,
                    message="Invalid YAML — workflow will not parse",
                    remediation="Fix YAML syntax errors",
                    scanner=self.name,
                )
            )
            return findings

        if not isinstance(workflow, dict):
            return findings

        # RULE: No top-level permissions (defaults to read-write all)
        if "permissions" not in workflow:
            findings.append(
                Finding(
                    rule_id="GHA-001",
                    severity=Severity.HIGH,
                    file=rel,
                    line=1,
                    message="No top-level permissions block — defaults to read-write for all scopes",
                    remediation="Add 'permissions: contents: read' at the workflow level and grant per-job",
                    scanner=self.name,
                    reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication",
                )
            )

        # Line-level checks
        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # RULE: Unpinned action (uses @v4 instead of @sha256:...)
            match = re.search(r"uses:\s*([^@]+)@(v\d+|main|master|latest)", stripped)
            if match:
                action = match.group(1)
                tag = match.group(2)
                # Skip official GitHub actions owned by actions/ or github/
                findings.append(
                    Finding(
                        rule_id="GHA-002",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=i,
                        message=f"Action '{action}' pinned to mutable tag '{tag}' — supply chain risk",
                        remediation=f"Pin to a full SHA: uses: {action}@<sha256>",
                        scanner=self.name,
                        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
                    )
                )

            # RULE: Secret in plain text (not using ${{ secrets.X }})
            if (
                re.search(
                    r"(api[_-]?key|password|secret|token)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{10,}",
                    stripped,
                    re.IGNORECASE,
                )
                and "${{" not in stripped
            ):
                findings.append(
                    Finding(
                        rule_id="GHA-003",
                        severity=Severity.CRITICAL,
                        file=rel,
                        line=i,
                        message="Possible secret hardcoded in workflow — not using ${{ secrets.* }}",
                        remediation="Store the value in GitHub Secrets and reference via ${{ secrets.NAME }}",
                        scanner=self.name,
                    )
                )

            # RULE: run with curl | bash
            if "run:" in stripped or (stripped.startswith("-") and "curl" in stripped):
                if re.search(r"curl.*\|\s*(ba)?sh", stripped) or re.search(
                    r"wget.*\|\s*(ba)?sh", stripped
                ):
                    findings.append(
                        Finding(
                            rule_id="GHA-004",
                            severity=Severity.HIGH,
                            file=rel,
                            line=i,
                            message="Piping curl/wget to shell in CI — supply chain risk",
                            remediation="Download, verify checksum, then execute",
                            scanner=self.name,
                        )
                    )

            # RULE: pull_request_target with checkout (pwn request vector)
            if "pull_request_target" in stripped:
                findings.append(
                    Finding(
                        rule_id="GHA-005",
                        severity=Severity.HIGH,
                        file=rel,
                        line=i,
                        message="pull_request_target trigger — if combined with checkout of PR code, it's a 'pwn request' vector",
                        remediation="Avoid checking out PR code in pull_request_target. Use pull_request instead.",
                        scanner=self.name,
                        reference="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
                    )
                )

        # Job-level checks
        for job_name, job in (workflow.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue

            # RULE: Job without explicit permissions inherits workflow-level
            if "permissions" not in job and "permissions" not in workflow:
                # Find approximate line for this job
                line = _find_line(lines, f"{job_name}:")
                findings.append(
                    Finding(
                        rule_id="GHA-006",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=line,
                        message=f"Job '{job_name}' has no permissions block and inherits over-broad defaults",
                        remediation=f"Add 'permissions:' to job '{job_name}' with minimal required scopes",
                        scanner=self.name,
                    )
                )

            # RULE: Self-hosted runner without explicit environment
            runs_on = job.get("runs-on", "")
            if "self-hosted" in str(runs_on) and "environment" not in job:
                line = _find_line(lines, "self-hosted")
                findings.append(
                    Finding(
                        rule_id="GHA-007",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=line,
                        message=f"Job '{job_name}' uses self-hosted runner without environment protection",
                        remediation="Add 'environment:' with required reviewers for self-hosted runners",
                        scanner=self.name,
                    )
                )

        return findings


def _find_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return 1
