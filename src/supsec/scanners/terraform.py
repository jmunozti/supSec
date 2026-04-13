"""Terraform security scanner.

Checks .tf files for common misconfigurations without requiring terraform CLI.
"""

import re
from pathlib import Path

from supsec.models import Finding, Severity
from supsec.scanners.base import BaseScanner


class TerraformScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "terraform"

    def accepts(self, path: Path) -> bool:
        return path.suffix == ".tf"

    def scan(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        rel = str(path)
        text = path.read_text()
        lines = text.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # RULE: S3 bucket without encryption
            if 'resource "aws_s3_bucket"' in stripped:
                # Look ahead for encryption config in the next 30 lines
                block = "\n".join(lines[i - 1 : i + 30])
                if (
                    "server_side_encryption" not in block
                    and "aws_s3_bucket_server_side_encryption" not in text
                ):
                    findings.append(
                        Finding(
                            rule_id="TF-001",
                            severity=Severity.HIGH,
                            file=rel,
                            line=i,
                            message="S3 bucket without server-side encryption configuration",
                            remediation="Add aws_s3_bucket_server_side_encryption_configuration resource with AES256 or KMS",
                            scanner=self.name,
                            reference="https://avd.aquasec.com/misconfig/avd-aws-0088/",
                        )
                    )

            # RULE: Security group with 0.0.0.0/0 ingress
            if re.search(r'cidr_blocks\s*=\s*\[?"0\.0\.0\.0/0"', stripped):
                findings.append(
                    Finding(
                        rule_id="TF-002",
                        severity=Severity.HIGH,
                        file=rel,
                        line=i,
                        message="Security group allows ingress from 0.0.0.0/0 (entire internet)",
                        remediation="Restrict cidr_blocks to specific IP ranges or use security group references",
                        scanner=self.name,
                        reference="https://avd.aquasec.com/misconfig/avd-aws-0107/",
                    )
                )

            # RULE: RDS publicly accessible
            if "publicly_accessible" in stripped and re.search(r"=\s*true", stripped):
                if "rds" in text.lower() or "db_instance" in text.lower():
                    findings.append(
                        Finding(
                            rule_id="TF-003",
                            severity=Severity.CRITICAL,
                            file=rel,
                            line=i,
                            message="RDS instance is publicly accessible",
                            remediation="Set publicly_accessible = false",
                            scanner=self.name,
                        )
                    )

            # RULE: Hardcoded credentials
            if re.search(
                r'(password|secret_key|access_key)\s*=\s*"[^$][^"]{5,}"',
                stripped,
                re.IGNORECASE,
            ):
                findings.append(
                    Finding(
                        rule_id="TF-004",
                        severity=Severity.CRITICAL,
                        file=rel,
                        line=i,
                        message="Hardcoded credential in Terraform configuration",
                        remediation="Use variables with sensitive=true or reference AWS Secrets Manager / SSM Parameter Store",
                        scanner=self.name,
                    )
                )

            # RULE: deletion_protection disabled
            if "deletion_protection" in stripped and re.search(r"=\s*false", stripped):
                findings.append(
                    Finding(
                        rule_id="TF-005",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=i,
                        message="Deletion protection is disabled — resource can be accidentally destroyed",
                        remediation="Set deletion_protection = true for production resources",
                        scanner=self.name,
                    )
                )

            # RULE: KMS key without rotation
            if 'resource "aws_kms_key"' in stripped:
                block = "\n".join(lines[i - 1 : i + 15])
                if "enable_key_rotation" not in block:
                    findings.append(
                        Finding(
                            rule_id="TF-006",
                            severity=Severity.MEDIUM,
                            file=rel,
                            line=i,
                            message="KMS key without automatic key rotation",
                            remediation="Add enable_key_rotation = true",
                            scanner=self.name,
                        )
                    )

            # RULE: EBS/RDS without encryption
            if re.search(r"(storage_encrypted|encrypted)\s*=\s*false", stripped):
                findings.append(
                    Finding(
                        rule_id="TF-007",
                        severity=Severity.HIGH,
                        file=rel,
                        line=i,
                        message="Storage encryption is explicitly disabled",
                        remediation="Set encrypted = true / storage_encrypted = true",
                        scanner=self.name,
                    )
                )

            # RULE: Wildcard IAM actions
            if re.search(r'"iam:.*\*"', stripped) or ('"Action"' in stripped and '"*"' in stripped):
                findings.append(
                    Finding(
                        rule_id="TF-008",
                        severity=Severity.HIGH,
                        file=rel,
                        line=i,
                        message="Wildcard IAM actions — violates least privilege principle",
                        remediation="Specify exact actions needed instead of wildcards",
                        scanner=self.name,
                        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
                    )
                )

            # RULE: skip_final_snapshot = true in production
            if "skip_final_snapshot" in stripped and re.search(r"=\s*true", stripped):
                findings.append(
                    Finding(
                        rule_id="TF-009",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=i,
                        message="skip_final_snapshot = true — data loss risk on terraform destroy",
                        remediation="Set skip_final_snapshot = false and provide final_snapshot_identifier",
                        scanner=self.name,
                    )
                )

            # RULE: CloudWatch log group without retention
            if 'resource "aws_cloudwatch_log_group"' in stripped:
                block = "\n".join(lines[i - 1 : i + 10])
                if "retention_in_days" not in block:
                    findings.append(
                        Finding(
                            rule_id="TF-010",
                            severity=Severity.LOW,
                            file=rel,
                            line=i,
                            message="CloudWatch log group without retention period — logs will accumulate forever",
                            remediation="Add retention_in_days = 30 (or appropriate value)",
                            scanner=self.name,
                        )
                    )

        return findings
