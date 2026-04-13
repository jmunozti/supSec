"""Tests for GitHubActionsScanner."""

import textwrap
from pathlib import Path

import pytest

from supsec.models import Severity
from supsec.scanners.github_actions import GitHubActionsScanner


@pytest.fixture
def scanner():
    return GitHubActionsScanner()


@pytest.fixture
def scan_workflow(tmp_path, scanner):
    def _scan(content: str):
        d = tmp_path / ".github" / "workflows"
        d.mkdir(parents=True)
        p = d / "ci.yml"
        p.write_text(textwrap.dedent(content))
        return scanner.scan(p)

    return _scan


class TestAccepts:
    def test_accepts_workflow(self, scanner):
        assert scanner.accepts(Path(".github/workflows/ci.yml"))
        assert scanner.accepts(Path(".github/workflows/deploy.yaml"))

    def test_rejects_non_workflow(self, scanner):
        assert not scanner.accepts(Path("config.yml"))
        assert not scanner.accepts(Path(".github/CODEOWNERS"))


class TestPermissions:
    def test_detects_missing_permissions(self, scan_workflow):
        findings = scan_workflow("""\
            name: CI
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
        """)
        assert any(f.rule_id == "GHA-001" for f in findings)

    def test_passes_with_permissions(self, scan_workflow):
        findings = scan_workflow("""\
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
        """)
        assert not any(f.rule_id == "GHA-001" for f in findings)


class TestUnpinnedActions:
    def test_detects_mutable_tag(self, scan_workflow):
        findings = scan_workflow("""\
            name: CI
            on: push
            permissions: {}
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: some-org/action@main
        """)
        assert any(f.rule_id == "GHA-002" for f in findings)

    def test_detects_v_tag(self, scan_workflow):
        findings = scan_workflow("""\
            name: CI
            on: push
            permissions: {}
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: some-org/action@v4
        """)
        assert any(f.rule_id == "GHA-002" for f in findings)


class TestHardcodedSecrets:
    def test_detects_plain_text_secret(self, scan_workflow):
        findings = scan_workflow("""\
            name: CI
            on: push
            permissions: {}
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: API_KEY=ghp_abc123def456ghi789jkl012mno345pqr678
        """)
        assert any(f.rule_id == "GHA-003" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings if f.rule_id == "GHA-003")


class TestPullRequestTarget:
    def test_detects_pr_target(self, scan_workflow):
        findings = scan_workflow("""\
            name: CI
            on: [push, pull_request_target]
            permissions: {}
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
        """)
        assert any(f.rule_id == "GHA-005" for f in findings)


class TestCleanWorkflow:
    def test_clean_workflow_no_blockers(self, scan_workflow):
        findings = scan_workflow("""\
            name: CI
            on: [push]
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                permissions:
                  contents: read
                steps:
                  - uses: actions/checkout@abc123abc123abc123abc123abc123abc123abc1
                  - run: echo "hello"
        """)
        blockers = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(blockers) == 0
