"""Configuration file support (.supsec.yaml).

Example .supsec.yaml:
    ignore_paths:
      - vendor/
      - node_modules/
      - "*.min.js"
    ignore_rules:
      - DOCKER-011   # we don't use HEALTHCHECK in dev
    severity_overrides:
      DOCKER-011: HIGH   # but in prod, make it HIGH
    scanners:
      - dockerfile
      - github-actions
      - terraform
      - secrets
      - kubernetes
      - docker-compose
      - shell
"""

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from supsec.models import Severity


@dataclass
class SupSecConfig:
    ignore_paths: list[str] = field(default_factory=list)
    ignore_rules: list[str] = field(default_factory=list)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    scanners: list[str] | None = None

    def is_path_ignored(self, path: str) -> bool:
        from fnmatch import fnmatch
        for pattern in self.ignore_paths:
            if fnmatch(path, pattern) or pattern in path:
                return True
        return False

    def is_rule_ignored(self, rule_id: str) -> bool:
        return rule_id in self.ignore_rules

    def get_severity_override(self, rule_id: str) -> Severity | None:
        override = self.severity_overrides.get(rule_id)
        if override:
            try:
                return Severity(override.upper())
            except ValueError:
                return None
        return None


def load_config(path: Path) -> SupSecConfig:
    if not path.exists():
        return SupSecConfig()
    try:
        data = yaml.safe_load(path.read_text()) or {}
        return SupSecConfig(
            ignore_paths=data.get("ignore_paths", []),
            ignore_rules=data.get("ignore_rules", []),
            severity_overrides=data.get("severity_overrides", {}),
            scanners=data.get("scanners"),
        )
    except Exception:
        return SupSecConfig()
