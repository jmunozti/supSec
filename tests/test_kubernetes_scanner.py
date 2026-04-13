"""Tests for KubernetesScanner."""

import textwrap

import pytest

from supsec.models import Severity
from supsec.scanners.kubernetes import KubernetesScanner


@pytest.fixture
def scanner():
    return KubernetesScanner()


@pytest.fixture
def scan_k8s(tmp_path, scanner):
    def _scan(content: str):
        p = tmp_path / "deploy.yaml"
        p.write_text(textwrap.dedent(content))
        return scanner.scan(p)

    return _scan


class TestAccepts:
    def test_accepts_k8s_manifest(self, tmp_path, scanner):
        p = tmp_path / "deploy.yaml"
        p.write_text("apiVersion: apps/v1\nkind: Deployment\nspec: {}")
        assert scanner.accepts(p)

    def test_rejects_non_k8s_yaml(self, tmp_path, scanner):
        p = tmp_path / "config.yaml"
        p.write_text("key: value")
        assert not scanner.accepts(p)


class TestPrivilegedContainer:
    def test_detects_privileged(self, scan_k8s):
        findings = scan_k8s("""\
            apiVersion: apps/v1
            kind: Deployment
            spec:
              template:
                spec:
                  containers:
                    - name: app
                      image: myapp:v1
                      securityContext:
                        privileged: true
        """)
        assert any(f.rule_id == "K8S-003" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings if f.rule_id == "K8S-003")


class TestNoSecurityContext:
    def test_detects_missing_security_context(self, scan_k8s):
        findings = scan_k8s("""\
            apiVersion: apps/v1
            kind: Deployment
            spec:
              template:
                spec:
                  containers:
                    - name: app
                      image: myapp:v1
        """)
        assert any(f.rule_id == "K8S-001" for f in findings)


class TestResourceLimits:
    def test_detects_no_limits(self, scan_k8s):
        findings = scan_k8s("""\
            apiVersion: apps/v1
            kind: Deployment
            spec:
              template:
                spec:
                  containers:
                    - name: app
                      image: myapp:v1
        """)
        assert any(f.rule_id == "K8S-004" for f in findings)

    def test_passes_with_limits(self, scan_k8s):
        findings = scan_k8s("""\
            apiVersion: apps/v1
            kind: Deployment
            spec:
              template:
                spec:
                  containers:
                    - name: app
                      image: myapp:v1
                      resources:
                        limits:
                          cpu: "1"
                          memory: 512Mi
                      securityContext:
                        runAsNonRoot: true
                        readOnlyRootFilesystem: true
                        capabilities:
                          drop: [ALL]
        """)
        assert not any(f.rule_id == "K8S-004" for f in findings)


class TestImageTag:
    def test_detects_latest(self, scan_k8s):
        findings = scan_k8s("""\
            apiVersion: apps/v1
            kind: Deployment
            spec:
              template:
                spec:
                  containers:
                    - name: app
                      image: myapp:latest
                      securityContext:
                        runAsNonRoot: true
                        readOnlyRootFilesystem: true
                        capabilities:
                          drop: [ALL]
                      resources:
                        limits:
                          cpu: "1"
        """)
        assert any(f.rule_id == "K8S-007" for f in findings)

    def test_detects_no_tag(self, scan_k8s):
        findings = scan_k8s("""\
            apiVersion: apps/v1
            kind: Deployment
            spec:
              template:
                spec:
                  containers:
                    - name: app
                      image: myapp
                      securityContext:
                        runAsNonRoot: true
                        readOnlyRootFilesystem: true
                        capabilities:
                          drop: [ALL]
                      resources:
                        limits:
                          cpu: "1"
        """)
        assert any(f.rule_id == "K8S-008" for f in findings)
