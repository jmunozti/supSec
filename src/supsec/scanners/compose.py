"""Docker Compose security scanner."""

from pathlib import Path

import yaml

from supsec.models import Finding, Severity
from supsec.scanners.base import BaseScanner


class ComposeScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "docker-compose"

    def accepts(self, path: Path) -> bool:
        name = path.name.lower()
        return name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")

    def scan(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        rel = str(path)
        try:
            text = path.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            return findings
        lines = text.splitlines()

        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            return findings

        if not isinstance(doc, dict):
            return findings

        services = doc.get("services", {})
        if not isinstance(services, dict):
            return findings

        for svc_name, svc in services.items():
            if not isinstance(svc, dict):
                continue

            # RULE: privileged mode
            if svc.get("privileged"):
                findings.append(
                    Finding(
                        rule_id="COMPOSE-001",
                        severity=Severity.CRITICAL,
                        file=rel,
                        line=self._find_line(lines, "privileged"),
                        message=f"Service '{svc_name}' runs in privileged mode — full host access",
                        remediation="Remove privileged: true. Use cap_add for specific capabilities.",
                        scanner=self.name,
                    )
                )

            # RULE: secrets in environment
            env = svc.get("environment", {})
            env_list = (
                env
                if isinstance(env, list)
                else [f"{k}={v}" for k, v in env.items()]
                if isinstance(env, dict)
                else []
            )
            for entry in env_list:
                entry_str = str(entry)
                import re

                if re.search(
                    r"(PASSWORD|SECRET|API_KEY|TOKEN)\s*=\s*[^\$].{5,}", entry_str, re.IGNORECASE
                ):
                    if "${" not in entry_str and "$$" not in entry_str:
                        findings.append(
                            Finding(
                                rule_id="COMPOSE-002",
                                severity=Severity.HIGH,
                                file=rel,
                                line=self._find_line(lines, entry_str.split("=")[0]),
                                message=f"Service '{svc_name}' has hardcoded secret in environment",
                                remediation="Use Docker secrets, .env file (gitignored), or external secrets manager",
                                scanner=self.name,
                            )
                        )

            # RULE: host network mode
            if svc.get("network_mode") == "host":
                findings.append(
                    Finding(
                        rule_id="COMPOSE-003",
                        severity=Severity.HIGH,
                        file=rel,
                        line=self._find_line(lines, "network_mode"),
                        message=f"Service '{svc_name}' uses host network — exposes all host ports",
                        remediation="Use bridge network with explicit port mappings",
                        scanner=self.name,
                    )
                )

            # RULE: dangerous volume mounts
            volumes = svc.get("volumes", [])
            for vol in volumes:
                vol_str = str(vol)
                if vol_str.startswith("/:/") or vol_str.startswith("/var/run/docker.sock"):
                    findings.append(
                        Finding(
                            rule_id="COMPOSE-004",
                            severity=Severity.CRITICAL,
                            file=rel,
                            line=self._find_line(lines, vol_str.split(":")[0]),
                            message=f"Service '{svc_name}' mounts dangerous host path: {vol_str}",
                            remediation="Avoid mounting / or docker.sock. Use named volumes.",
                            scanner=self.name,
                        )
                    )

            # RULE: no healthcheck
            if "healthcheck" not in svc:
                findings.append(
                    Finding(
                        rule_id="COMPOSE-005",
                        severity=Severity.LOW,
                        file=rel,
                        line=self._find_line(lines, svc_name),
                        message=f"Service '{svc_name}' has no healthcheck",
                        remediation="Add healthcheck to enable dependency_condition: service_healthy",
                        scanner=self.name,
                    )
                )

            # RULE: image uses :latest
            image = svc.get("image", "")
            if ":latest" in image:
                findings.append(
                    Finding(
                        rule_id="COMPOSE-006",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=self._find_line(lines, image),
                        message=f"Service '{svc_name}' uses :latest tag",
                        remediation="Pin to a specific version",
                        scanner=self.name,
                    )
                )

            # RULE: cap_add ALL or SYS_ADMIN
            cap_add = svc.get("cap_add", [])
            for cap in cap_add:
                if cap in ("ALL", "SYS_ADMIN", "NET_ADMIN"):
                    findings.append(
                        Finding(
                            rule_id="COMPOSE-007",
                            severity=Severity.HIGH,
                            file=rel,
                            line=self._find_line(lines, cap),
                            message=f"Service '{svc_name}' adds dangerous capability: {cap}",
                            remediation="Only add the minimum capabilities needed",
                            scanner=self.name,
                        )
                    )

        return findings

    @staticmethod
    def _find_line(lines: list[str], needle: str) -> int:
        for i, line in enumerate(lines, 1):
            if needle in line:
                return i
        return 1
