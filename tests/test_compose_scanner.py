"""Tests for ComposeScanner."""

import textwrap
from pathlib import Path

import pytest

from supsec.models import Severity
from supsec.scanners.compose import ComposeScanner


@pytest.fixture
def scanner():
    return ComposeScanner()


@pytest.fixture
def scan_compose(tmp_path, scanner):
    def _scan(content: str):
        p = tmp_path / "docker-compose.yml"
        p.write_text(textwrap.dedent(content))
        return scanner.scan(p)

    return _scan


class TestAccepts:
    def test_accepts_compose_files(self, scanner):
        assert scanner.accepts(Path("docker-compose.yml"))
        assert scanner.accepts(Path("docker-compose.yaml"))
        assert scanner.accepts(Path("compose.yml"))

    def test_rejects_other_yaml(self, scanner):
        assert not scanner.accepts(Path("config.yaml"))


class TestPrivileged:
    def test_detects_privileged(self, scan_compose):
        findings = scan_compose("""\
            services:
              app:
                image: myapp:v1
                privileged: true
        """)
        assert any(f.rule_id == "COMPOSE-001" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings if f.rule_id == "COMPOSE-001")


class TestSecretInEnv:
    def test_detects_hardcoded_password(self, scan_compose):
        findings = scan_compose("""\
            services:
              db:
                image: postgres:16
                environment:
                  POSTGRES_PASSWORD: "SuperSecret123!"
        """)
        assert any(f.rule_id == "COMPOSE-002" for f in findings)


class TestHostNetwork:
    def test_detects_host_network(self, scan_compose):
        findings = scan_compose("""\
            services:
              app:
                image: myapp:v1
                network_mode: host
        """)
        assert any(f.rule_id == "COMPOSE-003" for f in findings)


class TestDangerousVolume:
    def test_detects_docker_sock_mount(self, scan_compose):
        findings = scan_compose("""\
            services:
              app:
                image: myapp:v1
                volumes:
                  - /var/run/docker.sock:/var/run/docker.sock
        """)
        assert any(f.rule_id == "COMPOSE-004" for f in findings)


class TestCapabilities:
    def test_detects_sys_admin(self, scan_compose):
        findings = scan_compose("""\
            services:
              app:
                image: myapp:v1
                cap_add:
                  - SYS_ADMIN
        """)
        assert any(f.rule_id == "COMPOSE-007" for f in findings)
