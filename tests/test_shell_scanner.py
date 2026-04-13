"""Tests for ShellScanner."""

import textwrap
from pathlib import Path

import pytest

from supsec.models import Severity
from supsec.scanners.shell import ShellScanner


@pytest.fixture
def scanner():
    return ShellScanner()


@pytest.fixture
def scan_sh(tmp_path, scanner):
    def _scan(content: str):
        p = tmp_path / "script.sh"
        p.write_text(textwrap.dedent(content))
        return scanner.scan(p)
    return _scan


class TestAccepts:
    def test_accepts_sh_files(self, scanner):
        assert scanner.accepts(Path("deploy.sh"))
        assert scanner.accepts(Path("run.bash"))

    def test_accepts_shebang(self, tmp_path, scanner):
        p = tmp_path / "myscript"
        p.write_text("#!/bin/bash\necho hi\n")
        assert scanner.accepts(p)

    def test_rejects_python(self, scanner):
        assert not scanner.accepts(Path("app.py"))


class TestEval:
    def test_detects_eval(self, scan_sh):
        findings = scan_sh("#!/bin/bash\nset -euo pipefail\neval \"$INPUT\"\n")
        assert any(f.rule_id == "SHELL-001" for f in findings)


class TestCurlPipe:
    def test_detects_curl_pipe(self, scan_sh):
        findings = scan_sh("#!/bin/bash\nset -euo pipefail\ncurl -sSL https://x.com/i.sh | bash\n")
        assert any(f.rule_id == "SHELL-002" for f in findings)


class TestUnquotedRm:
    def test_detects_unquoted_variable_in_rm(self, scan_sh):
        findings = scan_sh("#!/bin/bash\nset -euo pipefail\nrm -rf $DIR\n")
        assert any(f.rule_id == "SHELL-003" for f in findings)


class TestChmod777:
    def test_detects_world_writable(self, scan_sh):
        findings = scan_sh("#!/bin/bash\nset -euo pipefail\nchmod 777 /tmp/data\n")
        assert any(f.rule_id == "SHELL-004" for f in findings)


class TestHardcodedSecret:
    def test_detects_password(self, scan_sh):
        findings = scan_sh("#!/bin/bash\nset -euo pipefail\nPASSWORD='MySecret123!'\n")
        assert any(f.rule_id == "SHELL-005" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings if f.rule_id == "SHELL-005")


class TestSetFlags:
    def test_detects_missing_set_e(self, scan_sh):
        findings = scan_sh("#!/bin/bash\necho hi\n")
        assert any(f.rule_id == "SHELL-008" for f in findings)

    def test_passes_with_set_euo(self, scan_sh):
        findings = scan_sh("#!/bin/bash\nset -euo pipefail\necho hi\n")
        assert not any(f.rule_id == "SHELL-008" for f in findings)
        assert not any(f.rule_id == "SHELL-009" for f in findings)
        assert not any(f.rule_id == "SHELL-010" for f in findings)


class TestSudo:
    def test_detects_sudo(self, scan_sh):
        findings = scan_sh("#!/bin/bash\nset -euo pipefail\nsudo systemctl restart app\n")
        assert any(f.rule_id == "SHELL-007" for f in findings)
