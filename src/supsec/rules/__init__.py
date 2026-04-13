"""Industry-standard security rules catalog.

Maps each rule to the compliance frameworks and benchmarks it satisfies.
This is what a hiring manager sees and thinks "this person knows the standards."
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    title: str
    scanner: str
    frameworks: list[str]  # CIS, NIST, PCI-DSS, OWASP, SOC2, etc.
    description: str


RULES_CATALOG: dict[str, RuleMetadata] = {
    # === Dockerfile rules (CIS Docker Benchmark) ===
    "DOCKER-001": RuleMetadata("DOCKER-001", "Container runs as root", "dockerfile",
        ["CIS Docker 4.1", "NIST 800-190", "PCI-DSS 7.1"], "Containers must not run as root. Use a dedicated non-root user."),
    "DOCKER-002": RuleMetadata("DOCKER-002", "apt-get without --no-install-recommends", "dockerfile",
        ["CIS Docker 4.6"], "Minimizing installed packages reduces the attack surface."),
    "DOCKER-003": RuleMetadata("DOCKER-003", "ADD instead of COPY", "dockerfile",
        ["CIS Docker 4.9"], "ADD has implicit tar extraction and URL fetch; COPY is explicit and safer."),
    "DOCKER-004": RuleMetadata("DOCKER-004", "World-writable file permissions", "dockerfile",
        ["CIS Docker 4.1", "NIST 800-53 AC-6"], "chmod 777 exposes files to all users in the container."),
    "DOCKER-005": RuleMetadata("DOCKER-005", "Piped curl/wget to shell", "dockerfile",
        ["CIS Docker 4.7", "OWASP Supply Chain", "SLSA Level 1"], "Remote code execution without verification is a supply chain risk."),
    "DOCKER-006": RuleMetadata("DOCKER-006", "Secret in ENV instruction", "dockerfile",
        ["CIS Docker 4.10", "PCI-DSS 3.4", "SOC2 CC6.1"], "Secrets baked into image layers are extractable by anyone with image access."),
    "DOCKER-007": RuleMetadata("DOCKER-007", "Privileged port exposure", "dockerfile",
        ["CIS Docker 4.1"], "Privileged ports (<1024) require root. Use high ports instead."),
    "DOCKER-008": RuleMetadata("DOCKER-008", "Using :latest tag", "dockerfile",
        ["CIS Docker 4.7", "SLSA Level 1", "NIST 800-190"], "Mutable tags break build reproducibility. Pin to specific version or digest."),
    "DOCKER-009": RuleMetadata("DOCKER-009", "No tag on FROM image", "dockerfile",
        ["CIS Docker 4.7", "SLSA Level 1"], "Implicit :latest — same risk as DOCKER-008."),
    "DOCKER-010": RuleMetadata("DOCKER-010", "No USER instruction", "dockerfile",
        ["CIS Docker 4.1", "NIST 800-190", "PCI-DSS 7.1"], "Default user is root. Always set a non-root USER."),
    "DOCKER-011": RuleMetadata("DOCKER-011", "No HEALTHCHECK", "dockerfile",
        ["CIS Docker 4.6"], "Without HEALTHCHECK, orchestrators cannot detect unhealthy containers."),

    # === GitHub Actions rules ===
    "GHA-001": RuleMetadata("GHA-001", "No top-level permissions", "github-actions",
        ["GitHub Security Hardening", "OWASP CI/CD Top 10"], "Default GITHUB_TOKEN has read-write on all scopes."),
    "GHA-002": RuleMetadata("GHA-002", "Unpinned action version", "github-actions",
        ["OWASP Supply Chain", "SLSA Level 3"], "Mutable tags (v4, main) can be hijacked by the action maintainer."),
    "GHA-003": RuleMetadata("GHA-003", "Hardcoded secret in workflow", "github-actions",
        ["PCI-DSS 3.4", "SOC2 CC6.1", "OWASP CI/CD Top 10"], "Secrets must be stored in GitHub Secrets, not in code."),
    "GHA-004": RuleMetadata("GHA-004", "Piped curl/wget to shell in CI", "github-actions",
        ["OWASP Supply Chain", "SLSA Level 1"], "Supply chain attack vector — verify downloads before executing."),
    "GHA-005": RuleMetadata("GHA-005", "pull_request_target trigger", "github-actions",
        ["GitHub Security Lab PWN-001"], "Combined with checkout, enables arbitrary code execution from forks."),
    "GHA-006": RuleMetadata("GHA-006", "Job without permissions block", "github-actions",
        ["GitHub Security Hardening"], "Inherits over-broad workflow-level or default permissions."),
    "GHA-007": RuleMetadata("GHA-007", "Self-hosted runner without environment", "github-actions",
        ["OWASP CI/CD Top 10 CICD-SEC-1"], "Self-hosted runners can be exploited to access internal networks."),

    # === Terraform rules ===
    "TF-001": RuleMetadata("TF-001", "S3 bucket without encryption", "terraform",
        ["CIS AWS 2.1.1", "PCI-DSS 3.4", "SOC2 CC6.1", "HIPAA 164.312(a)(2)(iv)"], "Data at rest must be encrypted."),
    "TF-002": RuleMetadata("TF-002", "Security group open to 0.0.0.0/0", "terraform",
        ["CIS AWS 5.2", "PCI-DSS 1.3", "NIST 800-53 SC-7"], "Unrestricted ingress from the internet is a critical risk."),
    "TF-003": RuleMetadata("TF-003", "RDS publicly accessible", "terraform",
        ["CIS AWS 2.3.1", "PCI-DSS 1.3.6"], "Databases must not be directly reachable from the internet."),
    "TF-004": RuleMetadata("TF-004", "Hardcoded credential in Terraform", "terraform",
        ["PCI-DSS 3.4", "SOC2 CC6.1"], "Use Secrets Manager or SSM Parameter Store for credentials."),
    "TF-005": RuleMetadata("TF-005", "Deletion protection disabled", "terraform",
        ["SOC2 CC6.1", "CIS AWS 2.3.1"], "Production resources should have deletion protection."),
    "TF-006": RuleMetadata("TF-006", "KMS key without rotation", "terraform",
        ["CIS AWS 2.8", "PCI-DSS 3.6.4", "NIST 800-57"], "Encryption keys must be rotated annually."),
    "TF-007": RuleMetadata("TF-007", "Storage encryption disabled", "terraform",
        ["CIS AWS 2.1.1", "HIPAA 164.312(a)(2)(iv)"], "All persistent storage must be encrypted at rest."),
    "TF-008": RuleMetadata("TF-008", "Wildcard IAM actions", "terraform",
        ["CIS AWS 1.16", "PCI-DSS 7.1", "NIST 800-53 AC-6"], "Least privilege: grant only the actions needed."),
    "TF-009": RuleMetadata("TF-009", "skip_final_snapshot enabled", "terraform",
        ["SOC2 CC6.1"], "Risk of data loss if resource is destroyed without snapshot."),
    "TF-010": RuleMetadata("TF-010", "CloudWatch log group without retention", "terraform",
        ["CIS AWS 3.1", "SOC2 CC7.2"], "Unbounded log growth increases cost and complicates compliance."),

    # === Secrets rules ===
    "SEC-001": RuleMetadata("SEC-001", "Known secret pattern detected", "secrets",
        ["PCI-DSS 3.4", "SOC2 CC6.1", "OWASP A02:2021"], "Provider-specific key formats detected in source code."),
    "SEC-002": RuleMetadata("SEC-002", "High-entropy string", "secrets",
        ["PCI-DSS 3.4"], "String with high Shannon entropy may be an unrecognized secret."),
}


def get_frameworks_for_rule(rule_id: str) -> list[str]:
    meta = RULES_CATALOG.get(rule_id)
    return meta.frameworks if meta else []
