"""Shell script security scanner."""

import re
from pathlib import Path

from supsec.models import Finding, Severity
from supsec.scanners.base import BaseScanner


class ShellScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "shell"

    def accepts(self, path: Path) -> bool:
        if path.suffix in (".sh", ".bash"):
            return True
        try:
            first_line = path.read_text(errors="ignore").split("\n")[0]
            return first_line.startswith("#!") and ("bash" in first_line or "sh" in first_line)
        except Exception:
            return False

    def scan(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        rel = str(path)
        text = path.read_text(errors="ignore")
        lines = text.splitlines()

        has_set_e = False
        has_set_u = False
        has_set_o_pipefail = False

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Track safety flags
            if "set -e" in stripped or "set -euo" in stripped or "set -eu" in stripped:
                has_set_e = True
                has_set_u = True
            if "set -o pipefail" in stripped or "set -euo pipefail" in stripped:
                has_set_o_pipefail = True
            if "set -u" in stripped:
                has_set_u = True

            if stripped.startswith("#"):
                continue

            # RULE: eval usage
            if re.match(r"\beval\b", stripped):
                findings.append(
                    Finding(
                        rule_id="SHELL-001",
                        severity=Severity.HIGH,
                        file=rel,
                        line=i,
                        message="Use of 'eval' — code injection risk if input is untrusted",
                        remediation="Avoid eval. Use arrays or parameter expansion instead.",
                        scanner=self.name,
                    )
                )

            # RULE: curl | bash
            if re.search(r"curl.*\|\s*(ba)?sh", stripped) or re.search(
                r"wget.*\|\s*(ba)?sh", stripped
            ):
                findings.append(
                    Finding(
                        rule_id="SHELL-002",
                        severity=Severity.HIGH,
                        file=rel,
                        line=i,
                        message="Piping curl/wget to shell — supply chain risk",
                        remediation="Download first, verify checksum, then execute",
                        scanner=self.name,
                    )
                )

            # RULE: unquoted variables in dangerous positions
            if re.search(r"rm\s+(-rf?\s+)?\$[A-Za-z_]", stripped) and '"$' not in stripped:
                findings.append(
                    Finding(
                        rule_id="SHELL-003",
                        severity=Severity.HIGH,
                        file=rel,
                        line=i,
                        message="Unquoted variable in rm command — could delete unintended paths if variable is empty",
                        remediation='Quote variables: rm -rf "${DIR}"',
                        scanner=self.name,
                    )
                )

            # RULE: chmod 777
            if re.search(r"chmod\s+0?777", stripped):
                findings.append(
                    Finding(
                        rule_id="SHELL-004",
                        severity=Severity.HIGH,
                        file=rel,
                        line=i,
                        message="chmod 777 — world-writable permissions",
                        remediation="Use restrictive permissions: 755 for dirs/executables, 644 for files",
                        scanner=self.name,
                    )
                )

            # RULE: hardcoded credentials
            if re.search(
                r"(PASSWORD|SECRET|API_KEY|TOKEN)\s*=\s*['\"][^$'\"][^'\"]{5,}['\"]",
                stripped,
                re.IGNORECASE,
            ):
                findings.append(
                    Finding(
                        rule_id="SHELL-005",
                        severity=Severity.CRITICAL,
                        file=rel,
                        line=i,
                        message="Hardcoded credential in shell script",
                        remediation="Use environment variables, .env file, or a secrets manager",
                        scanner=self.name,
                    )
                )

            # RULE: mktemp not used for temp files
            if re.search(r">\s*/tmp/[a-zA-Z]", stripped) and "mktemp" not in text:
                findings.append(
                    Finding(
                        rule_id="SHELL-006",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=i,
                        message="Writing to predictable /tmp path — symlink attack risk",
                        remediation="Use mktemp: TMPFILE=$(mktemp)",
                        scanner=self.name,
                    )
                )

            # RULE: sudo in scripts
            if re.match(r"sudo\b", stripped) or re.search(r"\bsudo\s", stripped):
                findings.append(
                    Finding(
                        rule_id="SHELL-007",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=i,
                        message="'sudo' in script — script may fail in environments without sudo",
                        remediation="Run the script as the required user, or document root requirement",
                        scanner=self.name,
                    )
                )

        # Post-file checks
        if lines and not stripped.startswith("#"):
            if not has_set_e:
                findings.append(
                    Finding(
                        rule_id="SHELL-008",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=1,
                        message="Missing 'set -e' — script continues after errors",
                        remediation="Add 'set -euo pipefail' at the top of the script",
                        scanner=self.name,
                    )
                )
            if not has_set_u:
                findings.append(
                    Finding(
                        rule_id="SHELL-009",
                        severity=Severity.LOW,
                        file=rel,
                        line=1,
                        message="Missing 'set -u' — unset variables won't cause errors",
                        remediation="Add 'set -u' or 'set -euo pipefail'",
                        scanner=self.name,
                    )
                )
            if not has_set_o_pipefail:
                findings.append(
                    Finding(
                        rule_id="SHELL-010",
                        severity=Severity.LOW,
                        file=rel,
                        line=1,
                        message="Missing 'set -o pipefail' — pipe failures are silently ignored",
                        remediation="Add 'set -o pipefail' or 'set -euo pipefail'",
                        scanner=self.name,
                    )
                )

        return findings
