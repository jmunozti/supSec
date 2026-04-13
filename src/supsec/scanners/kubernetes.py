"""Kubernetes manifest security scanner.

Checks for common security misconfigurations in Deployments, Pods, Services.
"""

from pathlib import Path

import yaml

from supsec.models import Finding, Severity
from supsec.scanners.base import BaseScanner


class KubernetesScanner(BaseScanner):
    K8S_KINDS = {
        "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob",
        "Pod", "ReplicaSet", "Service", "Ingress", "NetworkPolicy",
    }

    @property
    def name(self) -> str:
        return "kubernetes"

    def accepts(self, path: Path) -> bool:
        if path.suffix not in (".yml", ".yaml"):
            return False
        if ".github" in str(path):
            return False
        try:
            text = path.read_text(errors="ignore")
            docs = list(yaml.safe_load_all(text))
            return any(
                isinstance(d, dict) and d.get("kind") in self.K8S_KINDS
                for d in docs if d
            )
        except Exception:
            return False

    def scan(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        rel = str(path)
        try:
            docs = list(yaml.safe_load_all(path.read_text()))
        except Exception:
            return findings

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "")
            if kind not in self.K8S_KINDS:
                continue
            findings.extend(self._check_doc(doc, rel, kind))
        return findings

    def _check_doc(self, doc: dict, rel: str, kind: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = open(rel).readlines() if Path(rel).exists() else []

        containers = self._extract_containers(doc, kind)
        for container in containers:
            name = container.get("name", "?")

            # RULE: No securityContext
            sc = container.get("securityContext", {})
            if not sc:
                findings.append(Finding(
                    rule_id="K8S-001",
                    severity=Severity.HIGH,
                    file=rel, line=self._find_line(lines, name),
                    message=f"Container '{name}' has no securityContext",
                    remediation="Add securityContext with runAsNonRoot, readOnlyRootFilesystem, drop ALL capabilities",
                    scanner=self.name,
                    reference="https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                ))

            # RULE: Running as root
            if sc.get("runAsUser") == 0 or (not sc.get("runAsNonRoot", False) and not sc):
                pass  # already caught by K8S-001

            if sc.get("runAsUser") == 0:
                findings.append(Finding(
                    rule_id="K8S-002",
                    severity=Severity.HIGH,
                    file=rel, line=self._find_line(lines, "runAsUser"),
                    message=f"Container '{name}' runs as root (runAsUser: 0)",
                    remediation="Set runAsUser to a non-zero UID (e.g., 10001)",
                    scanner=self.name,
                ))

            # RULE: Privileged container
            if sc.get("privileged"):
                findings.append(Finding(
                    rule_id="K8S-003",
                    severity=Severity.CRITICAL,
                    file=rel, line=self._find_line(lines, "privileged"),
                    message=f"Container '{name}' is privileged — full host access",
                    remediation="Remove privileged: true. Use specific capabilities if needed.",
                    scanner=self.name,
                ))

            # RULE: No resource limits
            resources = container.get("resources", {})
            if not resources.get("limits"):
                findings.append(Finding(
                    rule_id="K8S-004",
                    severity=Severity.MEDIUM,
                    file=rel, line=self._find_line(lines, name),
                    message=f"Container '{name}' has no resource limits — can consume entire node",
                    remediation="Add resources.limits.cpu and resources.limits.memory",
                    scanner=self.name,
                ))

            # RULE: No readOnlyRootFilesystem
            if not sc.get("readOnlyRootFilesystem"):
                findings.append(Finding(
                    rule_id="K8S-005",
                    severity=Severity.MEDIUM,
                    file=rel, line=self._find_line(lines, name),
                    message=f"Container '{name}' does not set readOnlyRootFilesystem",
                    remediation="Set securityContext.readOnlyRootFilesystem: true and use emptyDir for writable paths",
                    scanner=self.name,
                ))

            # RULE: Capabilities not dropped
            caps = sc.get("capabilities", {})
            if not caps.get("drop"):
                findings.append(Finding(
                    rule_id="K8S-006",
                    severity=Severity.MEDIUM,
                    file=rel, line=self._find_line(lines, name),
                    message=f"Container '{name}' does not drop capabilities",
                    remediation="Add capabilities.drop: [ALL] and only add back what's needed",
                    scanner=self.name,
                ))

            # RULE: Image uses :latest or no tag
            image = container.get("image", "")
            if ":latest" in image:
                findings.append(Finding(
                    rule_id="K8S-007",
                    severity=Severity.MEDIUM,
                    file=rel, line=self._find_line(lines, image),
                    message=f"Container '{name}' uses :latest tag — non-reproducible",
                    remediation="Pin to a specific version tag or SHA digest",
                    scanner=self.name,
                ))
            elif ":" not in image and "@" not in image and image:
                findings.append(Finding(
                    rule_id="K8S-008",
                    severity=Severity.MEDIUM,
                    file=rel, line=self._find_line(lines, image),
                    message=f"Container '{name}' image has no tag (implicit :latest)",
                    remediation="Pin to a specific version tag",
                    scanner=self.name,
                ))

        # RULE: Service type LoadBalancer without annotation (might be public)
        if doc.get("kind") == "Service":
            spec = doc.get("spec", {})
            if spec.get("type") == "LoadBalancer":
                annotations = doc.get("metadata", {}).get("annotations", {})
                if "internal" not in str(annotations).lower():
                    findings.append(Finding(
                        rule_id="K8S-009",
                        severity=Severity.MEDIUM,
                        file=rel, line=self._find_line(lines, "LoadBalancer"),
                        message="Service type LoadBalancer may be internet-facing",
                        remediation="Add annotation for internal load balancer if not intended to be public",
                        scanner=self.name,
                    ))

        # RULE: No NetworkPolicy in namespace
        # (detected at file level — if a namespace has deployments but no NetworkPolicy)

        return findings

    def _extract_containers(self, doc: dict, kind: str) -> list[dict]:
        """Navigate to the containers list regardless of resource kind."""
        if kind == "Pod":
            return doc.get("spec", {}).get("containers", [])
        if kind in ("CronJob",):
            return (
                doc.get("spec", {})
                .get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("spec", {})
                .get("containers", [])
            )
        # Deployment, StatefulSet, DaemonSet, Job, ReplicaSet
        return (
            doc.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )

    @staticmethod
    def _find_line(lines: list[str], needle: str) -> int:
        for i, line in enumerate(lines, 1):
            if needle in line:
                return i
        return 1
