"""Tests for AutoFixer."""


import pytest

from supsec.fixer import AutoFixer


@pytest.fixture
def fixer():
    return AutoFixer(dry_run=False)


@pytest.fixture
def dry_fixer():
    return AutoFixer(dry_run=True)


class TestDockerfileFixer:
    def test_adds_no_install_recommends(self, tmp_path, fixer):
        p = tmp_path / "Dockerfile"
        p.write_text("FROM python:3.12\nRUN apt-get install -y curl\nCMD [\"python\"]\n")
        fixes = fixer.fix_tree(p)
        assert any(f.rule_id == "DOCKER-002" for f in fixes)
        assert "--no-install-recommends" in p.read_text()

    def test_converts_add_to_copy(self, tmp_path, fixer):
        p = tmp_path / "Dockerfile"
        p.write_text("FROM python:3.12\nADD . /app\nCMD [\"python\"]\n")
        fixes = fixer.fix_tree(p)
        assert any(f.rule_id == "DOCKER-003" for f in fixes)
        assert "COPY . /app" in p.read_text()

    def test_adds_user_before_cmd(self, tmp_path, fixer):
        p = tmp_path / "Dockerfile"
        p.write_text("FROM python:3.12\nCOPY . /app\nCMD [\"python\"]\n")
        fixes = fixer.fix_tree(p)
        assert any(f.rule_id == "DOCKER-010" for f in fixes)
        content = p.read_text()
        user_idx = content.index("USER")
        cmd_idx = content.index("CMD")
        assert user_idx < cmd_idx

    def test_dry_run_does_not_modify(self, tmp_path, dry_fixer):
        p = tmp_path / "Dockerfile"
        original = "FROM python:3.12\nRUN apt-get install -y curl\nCMD [\"python\"]\n"
        p.write_text(original)
        fixes = dry_fixer.fix_tree(p)
        assert len(fixes) > 0
        assert p.read_text() == original


class TestShellFixer:
    def test_adds_strict_mode(self, tmp_path, fixer):
        p = tmp_path / "script.sh"
        p.write_text("#!/bin/bash\necho hi\n")
        fixes = fixer.fix_tree(p)
        assert any(f.rule_id == "SHELL-008" for f in fixes)
        assert "set -euo pipefail" in p.read_text()

    def test_inserts_after_shebang(self, tmp_path, fixer):
        p = tmp_path / "script.sh"
        p.write_text("#!/bin/bash\necho hi\n")
        fixer.fix_tree(p)
        lines = p.read_text().splitlines()
        assert lines[0] == "#!/bin/bash"
        assert lines[1] == "set -euo pipefail"

    def test_does_not_add_if_already_present(self, tmp_path, fixer):
        p = tmp_path / "script.sh"
        p.write_text("#!/bin/bash\nset -euo pipefail\necho hi\n")
        fixes = fixer.fix_tree(p)
        assert not any(f.rule_id == "SHELL-008" for f in fixes)
