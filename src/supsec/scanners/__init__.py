"""Scanner plugin system.

Every scanner implements the BaseScanner ABC. The registry auto-discovers
all scanners by importing this package.
"""

from supsec.scanners.base import BaseScanner
from supsec.scanners.compose import ComposeScanner
from supsec.scanners.dockerfile import DockerfileScanner
from supsec.scanners.github_actions import GitHubActionsScanner
from supsec.scanners.kubernetes import KubernetesScanner
from supsec.scanners.secrets import SecretsScanner
from supsec.scanners.shell import ShellScanner
from supsec.scanners.terraform import TerraformScanner

ALL_SCANNERS: list[type[BaseScanner]] = [
    DockerfileScanner,
    GitHubActionsScanner,
    TerraformScanner,
    SecretsScanner,
    KubernetesScanner,
    ComposeScanner,
    ShellScanner,
]


def get_all_scanners() -> list[BaseScanner]:
    return [cls() for cls in ALL_SCANNERS]
