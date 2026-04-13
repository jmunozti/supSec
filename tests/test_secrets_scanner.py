"""Tests for SecretsScanner."""

import textwrap
from pathlib import Path

import pytest

from supsec.scanners.secrets import SecretsScanner, _shannon_entropy


@pytest.fixture
def scanner():
    return SecretsScanner()


@pytest.fixture
def scan_file(tmp_path, scanner):
    def _scan(filename: str, content: str):
        p = tmp_path / filename
        p.write_text(textwrap.dedent(content))
        return scanner.scan(p)
    return _scan


class TestShannonEntropy:
    def test_low_entropy_string(self):
        assert _shannon_entropy("aaaaaaaaa") < 1.0

    def test_high_entropy_string(self):
        assert _shannon_entropy("aB3$xY9!kL2@mN5#") > 3.5

    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0


class TestAWSKeys:
    def test_detects_aws_access_key(self, scan_file):
        # Note: can't use "EXAMPLE" in the value — it triggers the placeholder skip filter
        findings = scan_file("config.py", 'AWS_KEY = "AKIAIOSFODNN7PRODKEY1"\n')
        assert any(f.rule_id == "SEC-001" and "AWS Access Key" in f.message for f in findings)

    def test_detects_aws_secret_key(self, scan_file):
        findings = scan_file("config.py", 'aws_secret_access_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYPRODKEYVALUE"\n')
        assert any(f.rule_id == "SEC-001" for f in findings)

    def test_skips_example_keys(self, scan_file):
        """Keys containing 'EXAMPLE' are placeholder values and should NOT trigger."""
        findings = scan_file("config.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        assert not any(f.rule_id == "SEC-001" and "AWS Access Key" in f.message for f in findings)


class TestGitHubTokens:
    def test_detects_github_pat(self, scan_file):
        findings = scan_file("script.sh", 'TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n')
        assert any(f.rule_id == "SEC-001" and "GitHub Token" in f.message for f in findings)

    def test_detects_fine_grained_pat(self, scan_file):
        findings = scan_file("script.sh", 'TOKEN=github_pat_ABCDEFGHIJKLMNOPQRSTUV\n')
        assert any("GitHub PAT" in f.message for f in findings)


class TestOpenAIKey:
    def test_detects_openai_key(self, scan_file):
        findings = scan_file(".env", 'OPENAI_API_KEY=sk-proj1234567890abcdef1234567890abcdef\n')
        assert any("OpenAI" in f.message for f in findings)


class TestPrivateKey:
    def test_detects_private_key_header(self, scan_file):
        findings = scan_file("id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n")
        assert any(f.rule_id == "SEC-001" and "Private Key" in f.message for f in findings)


class TestGenericPasswords:
    def test_detects_password_assignment(self, scan_file):
        findings = scan_file("config.yaml", 'password: "MyS3cretPass!"\n')
        assert any(f.rule_id == "SEC-001" for f in findings)


class TestSkips:
    def test_skips_binary_files(self, scanner):
        assert not scanner.accepts(Path("image.png"))
        assert not scanner.accepts(Path("archive.tar.gz"))

    def test_skips_lock_files(self, scanner):
        assert not scanner.accepts(Path("poetry.lock"))
        assert not scanner.accepts(Path("package-lock.json"))

    def test_skips_comments(self, scan_file):
        findings = scan_file("script.sh", '# password = "not_a_real_secret_here"\n')
        assert len(findings) == 0

    def test_skips_placeholders(self, scan_file):
        findings = scan_file("config.env", 'API_KEY="REPLACE_ME"\n')
        assert len(findings) == 0


class TestCleanFile:
    def test_clean_python_file_no_findings(self, scan_file):
        findings = scan_file("app.py", """\
            import os

            API_KEY = os.environ["API_KEY"]
            DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

            def main():
                print("Hello, world!")

            if __name__ == "__main__":
                main()
        """)
        assert len(findings) == 0
