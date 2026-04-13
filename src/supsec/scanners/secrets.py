"""Secrets scanner — detects hardcoded credentials via regex patterns and entropy analysis."""

import math
import re
from pathlib import Path

from supsec.models import Finding, Severity
from supsec.scanners.base import BaseScanner

# High-confidence patterns: provider-specific key formats
SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL),
    (
        "AWS Secret Key",
        r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})",
        Severity.CRITICAL,
    ),
    ("GitHub Token", r"gh[ps]_[A-Za-z0-9_]{36,}", Severity.CRITICAL),
    ("GitHub PAT (fine-grained)", r"github_pat_[A-Za-z0-9_]{22,}", Severity.CRITICAL),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z\-]{10,}", Severity.CRITICAL),
    ("OpenAI API Key", r"sk-[A-Za-z0-9]{32,}", Severity.CRITICAL),
    ("Stripe Key", r"[rs]k_(live|test)_[A-Za-z0-9]{20,}", Severity.CRITICAL),
    ("Twilio Token", r"SK[0-9a-fA-F]{32}", Severity.HIGH),
    ("SendGrid Key", r"SG\.[A-Za-z0-9_\-]{22,}", Severity.HIGH),
    (
        "Private Key Header",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        Severity.CRITICAL,
    ),
    (
        "Generic password assignment",
        r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"$]{8,}['\"]",
        Severity.HIGH,
    ),
    (
        "Generic API key assignment",
        r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][^'\"$]{10,}['\"]",
        Severity.HIGH,
    ),
    (
        "Generic secret assignment",
        r"(?i)(secret|token)\s*[=:]\s*['\"][^'\"$]{10,}['\"]",
        Severity.HIGH,
    ),
]

# Files to skip entirely
SKIP_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".lock",
    ".sum",
}

SKIP_NAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "go.sum",
    "Cargo.lock",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class SecretsScanner(BaseScanner):
    ENTROPY_THRESHOLD = 4.5
    MIN_HIGH_ENTROPY_LEN = 16

    @property
    def name(self) -> str:
        return "secrets"

    def accepts(self, path: Path) -> bool:
        if path.suffix in SKIP_EXTENSIONS:
            return False
        if path.name in SKIP_NAMES:
            return False
        if ".git/" in str(path) or "__pycache__" in str(path):
            return False
        return True

    def scan(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        rel = str(path)

        try:
            text = path.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            return findings

        lines = text.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip comments
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            # Skip example/template placeholders
            if re.search(
                r"(REPLACE_ME|CHANGE_ME|your[-_]?key|xxx|dummy|example|placeholder)",
                stripped,
                re.IGNORECASE,
            ):
                continue

            # Pattern-based detection
            for label, pattern, severity in SECRET_PATTERNS:
                if re.search(pattern, stripped):
                    findings.append(
                        Finding(
                            rule_id="SEC-001",
                            severity=severity,
                            file=rel,
                            line=i,
                            message=f"Detected {label}",
                            remediation="Remove the secret from code. Rotate it immediately. Use a secrets manager.",
                            scanner=self.name,
                        )
                    )

            # Entropy-based detection for unquoted high-entropy strings
            # Catches secrets that don't match known patterns
            tokens = re.findall(r"[A-Za-z0-9+/=_\-]{16,}", stripped)
            for token in tokens:
                if (
                    len(token) >= self.MIN_HIGH_ENTROPY_LEN
                    and _shannon_entropy(token) >= self.ENTROPY_THRESHOLD
                ):
                    # Avoid false positives on known non-secret patterns
                    if any(re.search(p, token) for _, p, _ in SECRET_PATTERNS):
                        continue  # already caught above
                    if token.startswith("sha256:") or token.startswith("sha512:"):
                        continue
                    if re.match(r"^[a-f0-9]+$", token) and len(token) in (32, 40, 64):
                        continue  # likely a git SHA or hash
                    findings.append(
                        Finding(
                            rule_id="SEC-002",
                            severity=Severity.MEDIUM,
                            file=rel,
                            line=i,
                            message=f"High-entropy string detected (entropy={_shannon_entropy(token):.1f}) — possible secret",
                            remediation="Verify this is not a secret. If it is, remove and rotate.",
                            scanner=self.name,
                        )
                    )

        return findings
