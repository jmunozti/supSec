"""Dockerfile security scanner.

Rules based on CIS Docker Benchmark and Dockerfile best practices.
"""

import re
from pathlib import Path

from supsec.models import Finding, Severity
from supsec.scanners.base import BaseScanner


class DockerfileScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "dockerfile"

    def accepts(self, path: Path) -> bool:
        name = path.name.lower()
        return name == "dockerfile" or name.startswith("dockerfile.")

    def scan(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, UnicodeDecodeError):
            return findings
        rel = str(path)

        has_user = False
        has_healthcheck = False
        last_from_line = 0

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            upper = stripped.upper()

            # Track multi-stage context
            if upper.startswith("FROM "):
                last_from_line = i

            # RULE: USER root
            if upper.startswith("USER ") and "root" in stripped.lower():
                findings.append(
                    Finding(
                        rule_id="DOCKER-001",
                        severity=Severity.HIGH,
                        file=rel,
                        line=i,
                        message="Container runs as root (CIS 4.1)",
                        remediation="Add a non-root USER instruction: RUN useradd -r app && USER app",
                        scanner=self.name,
                        reference="https://cisecurity.org/benchmark/docker",
                    )
                )

            if upper.startswith("USER ") and "root" not in stripped.lower():
                has_user = True

            if upper.startswith("HEALTHCHECK"):
                has_healthcheck = True

            # RULE: apt-get without --no-install-recommends
            if "apt-get install" in stripped and "--no-install-recommends" not in stripped:
                findings.append(
                    Finding(
                        rule_id="DOCKER-002",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=i,
                        message="apt-get install without --no-install-recommends increases image size and attack surface",
                        remediation="Add --no-install-recommends flag",
                        scanner=self.name,
                    )
                )

            # RULE: ADD instead of COPY
            if upper.startswith("ADD ") and not any(
                x in stripped for x in ["http://", "https://", ".tar", ".gz"]
            ):
                findings.append(
                    Finding(
                        rule_id="DOCKER-003",
                        severity=Severity.LOW,
                        file=rel,
                        line=i,
                        message="ADD used where COPY would suffice — ADD has implicit tar extraction and URL fetch",
                        remediation="Use COPY unless you specifically need tar extraction",
                        scanner=self.name,
                    )
                )

            # RULE: COPY or ADD with --chmod=777
            if re.search(r"--chmod=0?777", stripped):
                findings.append(
                    Finding(
                        rule_id="DOCKER-004",
                        severity=Severity.HIGH,
                        file=rel,
                        line=i,
                        message="World-writable permissions (chmod 777) on copied files",
                        remediation="Use restrictive permissions: --chmod=755 for executables, --chmod=644 for files",
                        scanner=self.name,
                    )
                )

            # RULE: curl | bash (piped install)
            if re.search(r"curl.*\|\s*(ba)?sh", stripped) or re.search(
                r"wget.*\|\s*(ba)?sh", stripped
            ):
                findings.append(
                    Finding(
                        rule_id="DOCKER-005",
                        severity=Severity.HIGH,
                        file=rel,
                        line=i,
                        message="Piping curl/wget to shell is a supply chain risk",
                        remediation="Download the script first, verify its checksum, then execute",
                        scanner=self.name,
                    )
                )

            # RULE: ENV with secrets
            if upper.startswith("ENV ") and re.search(
                r"(password|secret|api[_-]?key|token|credential)", stripped, re.IGNORECASE
            ):
                findings.append(
                    Finding(
                        rule_id="DOCKER-006",
                        severity=Severity.CRITICAL,
                        file=rel,
                        line=i,
                        message="Secret value exposed in ENV instruction — baked into image layer",
                        remediation="Use build-time --secret mount or runtime environment variables",
                        scanner=self.name,
                        reference="https://docs.docker.com/build/building/secrets/",
                    )
                )

            # RULE: EXPOSE privileged port
            if upper.startswith("EXPOSE "):
                ports = re.findall(r"\d+", stripped)
                for port in ports:
                    if int(port) < 1024 and int(port) != 443 and int(port) != 80:
                        findings.append(
                            Finding(
                                rule_id="DOCKER-007",
                                severity=Severity.MEDIUM,
                                file=rel,
                                line=i,
                                message=f"Privileged port {port} requires root — use a port above 1024",
                                remediation=f"Use port 8080 or similar instead of {port}",
                                scanner=self.name,
                            )
                        )

            # RULE: latest tag
            if upper.startswith("FROM ") and ":latest" in stripped:
                findings.append(
                    Finding(
                        rule_id="DOCKER-008",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=i,
                        message="Using :latest tag makes builds non-reproducible",
                        remediation="Pin to a specific version tag or SHA digest",
                        scanner=self.name,
                    )
                )

            # RULE: no tag at all (implicit latest)
            if (
                upper.startswith("FROM ")
                and ":" not in stripped.split()[-1]
                and " AS " not in upper
            ):
                parts = stripped.split()
                if len(parts) >= 2 and ":" not in parts[1] and parts[1].lower() != "scratch":
                    findings.append(
                        Finding(
                            rule_id="DOCKER-009",
                            severity=Severity.MEDIUM,
                            file=rel,
                            line=i,
                            message="No tag specified in FROM — defaults to :latest",
                            remediation="Pin to a specific version: e.g., python:3.12-slim",
                            scanner=self.name,
                        )
                    )

        # Post-file checks
        if not has_user:
            findings.append(
                Finding(
                    rule_id="DOCKER-010",
                    severity=Severity.HIGH,
                    file=rel,
                    line=last_from_line or 1,
                    message="No USER instruction — container will run as root by default",
                    remediation="Add USER instruction with a non-root user",
                    scanner=self.name,
                    reference="https://cisecurity.org/benchmark/docker",
                )
            )

        if not has_healthcheck:
            findings.append(
                Finding(
                    rule_id="DOCKER-011",
                    severity=Severity.INFO,
                    file=rel,
                    line=1,
                    message="No HEALTHCHECK instruction — orchestrator cannot detect unhealthy containers",
                    remediation="Add HEALTHCHECK CMD to verify the service is responding",
                    scanner=self.name,
                )
            )

        return findings
