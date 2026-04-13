"""Auto-fixer for simple, safe remediations.

Only fixes issues that have a single, unambiguous correct fix.
Never touches logic or business code — only infrastructure config.
"""

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class FixResult:
    file: str
    line: int
    rule_id: str
    description: str


class AutoFixer:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def fix_tree(self, root: Path) -> list[FixResult]:
        fixes: list[FixResult] = []
        if root.is_file():
            fixes.extend(self._fix_file(root))
        else:
            for p in sorted(root.rglob("*")):
                if p.is_file():
                    fixes.extend(self._fix_file(p))
        return fixes

    def _fix_file(self, path: Path) -> list[FixResult]:
        name = path.name.lower()
        if name == "dockerfile" or name.startswith("dockerfile."):
            return self._fix_dockerfile(path)
        if path.suffix in (".sh", ".bash"):
            return self._fix_shell(path)
        return []

    def _fix_dockerfile(self, path: Path) -> list[FixResult]:
        fixes: list[FixResult] = []
        lines = path.read_text().splitlines(keepends=True)
        modified = False

        for i, line in enumerate(lines):
            stripped = line.strip()

            # FIX: apt-get without --no-install-recommends
            if "apt-get install" in stripped and "--no-install-recommends" not in stripped:
                lines[i] = line.replace(
                    "apt-get install", "apt-get install --no-install-recommends"
                )
                fixes.append(
                    FixResult(str(path), i + 1, "DOCKER-002", "Added --no-install-recommends")
                )
                modified = True

            # FIX: ADD → COPY (when not using tar/URL features)
            upper = stripped.upper()
            if upper.startswith("ADD ") and not any(
                x in stripped for x in ["http://", "https://", ".tar", ".gz"]
            ):
                lines[i] = re.sub(r"^(\s*)ADD\b", r"\1COPY", line)
                fixes.append(FixResult(str(path), i + 1, "DOCKER-003", "Changed ADD to COPY"))
                modified = True

        # FIX: Add USER if missing
        has_user = any(
            ln.strip().upper().startswith("USER ") and "root" not in ln.lower() for ln in lines
        )
        has_cmd = any(ln.strip().upper().startswith(("CMD ", "ENTRYPOINT ")) for ln in lines)
        if not has_user and has_cmd:
            for i in range(len(lines) - 1, -1, -1):
                if lines[i].strip().upper().startswith("CMD ") or lines[
                    i
                ].strip().upper().startswith("ENTRYPOINT "):
                    lines.insert(i, "USER 10001\n")
                    fixes.append(
                        FixResult(str(path), i + 1, "DOCKER-010", "Added USER 10001 before CMD")
                    )
                    modified = True
                    break

        if modified and not self.dry_run:
            path.write_text("".join(lines))
        return fixes

    def _fix_shell(self, path: Path) -> list[FixResult]:
        fixes: list[FixResult] = []
        text = path.read_text()
        lines = text.splitlines(keepends=True)

        if not lines:
            return fixes

        # FIX: Add set -euo pipefail if missing
        has_strict = "set -euo pipefail" in text or ("set -e" in text and "set -u" in text)
        if not has_strict:
            # Insert after shebang
            insert_idx = 1 if lines[0].startswith("#!") else 0
            lines.insert(insert_idx, "set -euo pipefail\n")
            fixes.append(
                FixResult(str(path), insert_idx + 1, "SHELL-008", "Added set -euo pipefail")
            )
            if not self.dry_run:
                path.write_text("".join(lines))

        return fixes
