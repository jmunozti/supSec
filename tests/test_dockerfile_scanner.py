"""Tests for DockerfileScanner."""

import textwrap
from pathlib import Path

import pytest

from supsec.models import Severity
from supsec.scanners.dockerfile import DockerfileScanner


@pytest.fixture
def scanner():
    return DockerfileScanner()


@pytest.fixture
def scan_text(tmp_path, scanner):
    """Helper: write Dockerfile content to a temp file and scan it."""
    def _scan(content: str):
        p = tmp_path / "Dockerfile"
        p.write_text(textwrap.dedent(content))
        return scanner.scan(p)
    return _scan


class TestAccepts:
    def test_accepts_dockerfile(self, scanner):
        assert scanner.accepts(Path("Dockerfile"))
        assert scanner.accepts(Path("Dockerfile.prod"))
        assert scanner.accepts(Path("dockerfile"))

    def test_rejects_non_dockerfile(self, scanner):
        assert not scanner.accepts(Path("main.py"))
        assert not scanner.accepts(Path("docker-compose.yml"))


class TestRootUser:
    def test_detects_user_root(self, scan_text):
        findings = scan_text("FROM python:3.12\nUSER root\n")
        ids = [f.rule_id for f in findings]
        assert "DOCKER-001" in ids

    def test_non_root_user_passes(self, scan_text):
        findings = scan_text("FROM python:3.12\nUSER app\nHEALTHCHECK CMD true\n")
        ids = [f.rule_id for f in findings]
        assert "DOCKER-001" not in ids
        assert "DOCKER-010" not in ids


class TestAptGet:
    def test_detects_missing_no_install_recommends(self, scan_text):
        findings = scan_text("FROM ubuntu:22.04\nRUN apt-get install -y curl\nUSER app\nHEALTHCHECK CMD true\n")
        assert any(f.rule_id == "DOCKER-002" for f in findings)

    def test_passes_with_flag(self, scan_text):
        findings = scan_text("FROM ubuntu:22.04\nRUN apt-get install -y --no-install-recommends curl\nUSER app\nHEALTHCHECK CMD true\n")
        assert not any(f.rule_id == "DOCKER-002" for f in findings)


class TestCurlPipe:
    def test_detects_curl_pipe_bash(self, scan_text):
        findings = scan_text("FROM ubuntu:22.04\nRUN curl -sSL https://x.com/install.sh | bash\nUSER app\nHEALTHCHECK CMD true\n")
        assert any(f.rule_id == "DOCKER-005" for f in findings)

    def test_detects_wget_pipe_sh(self, scan_text):
        findings = scan_text("FROM ubuntu:22.04\nRUN wget -O- https://x.com/install.sh | sh\nUSER app\nHEALTHCHECK CMD true\n")
        assert any(f.rule_id == "DOCKER-005" for f in findings)


class TestSecretInEnv:
    def test_detects_api_key_in_env(self, scan_text):
        findings = scan_text('FROM python:3.12\nENV API_KEY="sk-1234"\nUSER app\nHEALTHCHECK CMD true\n')
        assert any(f.rule_id == "DOCKER-006" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings if f.rule_id == "DOCKER-006")


class TestLatestTag:
    def test_detects_explicit_latest(self, scan_text):
        findings = scan_text("FROM python:latest\nUSER app\nHEALTHCHECK CMD true\n")
        assert any(f.rule_id == "DOCKER-008" for f in findings)

    def test_detects_implicit_latest(self, scan_text):
        findings = scan_text("FROM python\nUSER app\nHEALTHCHECK CMD true\n")
        assert any(f.rule_id == "DOCKER-009" for f in findings)

    def test_pinned_tag_passes(self, scan_text):
        findings = scan_text("FROM python:3.12-slim\nUSER app\nHEALTHCHECK CMD true\n")
        assert not any(f.rule_id in ("DOCKER-008", "DOCKER-009") for f in findings)


class TestNoUser:
    def test_detects_missing_user(self, scan_text):
        findings = scan_text("FROM python:3.12\nRUN echo hi\nHEALTHCHECK CMD true\n")
        assert any(f.rule_id == "DOCKER-010" for f in findings)


class TestNoHealthcheck:
    def test_detects_missing_healthcheck(self, scan_text):
        findings = scan_text("FROM python:3.12\nUSER app\n")
        assert any(f.rule_id == "DOCKER-011" for f in findings)


class TestCleanDockerfile:
    def test_clean_dockerfile_no_blockers(self, scan_text):
        findings = scan_text("""\
            FROM python:3.12-slim AS builder
            WORKDIR /app
            RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
            COPY . .
            FROM python:3.12-slim
            COPY --from=builder /app /app
            RUN useradd -r app
            USER app
            EXPOSE 8080
            HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1
            CMD ["python", "app.py"]
        """)
        blockers = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(blockers) == 0
