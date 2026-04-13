"""Tests for TerraformScanner."""

import textwrap
from pathlib import Path

import pytest

from supsec.models import Severity
from supsec.scanners.terraform import TerraformScanner


@pytest.fixture
def scanner():
    return TerraformScanner()


@pytest.fixture
def scan_tf(tmp_path, scanner):
    def _scan(content: str):
        p = tmp_path / "main.tf"
        p.write_text(textwrap.dedent(content))
        return scanner.scan(p)
    return _scan


class TestS3Encryption:
    def test_detects_unencrypted_bucket(self, scan_tf):
        findings = scan_tf("""\
            resource "aws_s3_bucket" "data" {
              bucket = "my-bucket"
            }
        """)
        assert any(f.rule_id == "TF-001" for f in findings)

    def test_passes_with_separate_encryption_resource(self, scan_tf):
        findings = scan_tf("""\
            resource "aws_s3_bucket" "data" {
              bucket = "my-bucket"
            }
            resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
              bucket = aws_s3_bucket.data.id
            }
        """)
        assert not any(f.rule_id == "TF-001" for f in findings)


class TestSecurityGroup:
    def test_detects_open_ingress(self, scan_tf):
        findings = scan_tf("""\
            resource "aws_security_group" "open" {
              ingress {
                cidr_blocks = ["0.0.0.0/0"]
              }
            }
        """)
        assert any(f.rule_id == "TF-002" for f in findings)

    def test_restricted_cidr_passes(self, scan_tf):
        findings = scan_tf("""\
            resource "aws_security_group" "ok" {
              ingress {
                cidr_blocks = ["10.0.0.0/8"]
              }
            }
        """)
        assert not any(f.rule_id == "TF-002" for f in findings)


class TestRDSPublic:
    def test_detects_public_rds(self, scan_tf):
        findings = scan_tf("""\
            resource "aws_db_instance" "db" {
              engine         = "postgres"
              instance_class = "db.t3.micro"
              publicly_accessible = true
            }
        """)
        assert any(f.rule_id == "TF-003" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings if f.rule_id == "TF-003")


class TestHardcodedCredentials:
    def test_detects_hardcoded_password(self, scan_tf):
        findings = scan_tf("""\
            resource "aws_db_instance" "db" {
              password = "SuperSecret123!"
            }
        """)
        assert any(f.rule_id == "TF-004" for f in findings)

    def test_variable_reference_passes(self, scan_tf):
        findings = scan_tf("""\
            resource "aws_db_instance" "db" {
              password = var.db_password
            }
        """)
        assert not any(f.rule_id == "TF-004" for f in findings)


class TestKMSRotation:
    def test_detects_missing_rotation(self, scan_tf):
        findings = scan_tf("""\
            resource "aws_kms_key" "main" {
              description = "my key"
            }
        """)
        assert any(f.rule_id == "TF-006" for f in findings)

    def test_passes_with_rotation(self, scan_tf):
        findings = scan_tf("""\
            resource "aws_kms_key" "main" {
              description         = "my key"
              enable_key_rotation = true
            }
        """)
        assert not any(f.rule_id == "TF-006" for f in findings)


class TestEncryptionDisabled:
    def test_detects_explicit_no_encryption(self, scan_tf):
        findings = scan_tf("""\
            resource "aws_ebs_volume" "vol" {
              encrypted = false
            }
        """)
        assert any(f.rule_id == "TF-007" for f in findings)


class TestWildcardIAM:
    def test_detects_star_action(self, scan_tf):
        findings = scan_tf("""\
            resource "aws_iam_role_policy" "admin" {
              policy = jsonencode({
                Statement = [{
                  Effect = "Allow"
                  "Action" = "*"
                  Resource = "*"
                }]
              })
            }
        """)
        assert any(f.rule_id == "TF-008" for f in findings)
