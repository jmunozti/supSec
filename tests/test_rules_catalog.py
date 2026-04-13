"""Tests for the rules catalog — ensures all rules have compliance framework mappings."""

from supsec.rules import RULES_CATALOG, get_frameworks_for_rule


class TestRulesCatalog:
    def test_all_rules_have_frameworks(self):
        for rule_id, meta in RULES_CATALOG.items():
            assert len(meta.frameworks) > 0, f"{rule_id} has no compliance frameworks"

    def test_all_rules_have_description(self):
        for rule_id, meta in RULES_CATALOG.items():
            assert meta.description, f"{rule_id} has no description"

    def test_docker_rules_reference_cis(self):
        docker_rules = {k: v for k, v in RULES_CATALOG.items() if k.startswith("DOCKER-")}
        for rule_id, meta in docker_rules.items():
            assert any("CIS" in f for f in meta.frameworks), (
                f"{rule_id} should reference CIS Docker Benchmark"
            )

    def test_tf_rules_reference_cis_or_pci(self):
        tf_rules = {k: v for k, v in RULES_CATALOG.items() if k.startswith("TF-")}
        for rule_id, meta in tf_rules.items():
            assert any(
                "CIS" in f
                or "PCI" in f
                or "SOC2" in f
                or "NIST" in f
                or "HIPAA" in f
                or "SLSA" in f
                for f in meta.frameworks
            ), f"{rule_id} should reference a compliance framework"

    def test_secret_rules_reference_pci(self):
        sec_rules = {k: v for k, v in RULES_CATALOG.items() if k.startswith("SEC-")}
        for rule_id, meta in sec_rules.items():
            assert any("PCI" in f for f in meta.frameworks), f"{rule_id} should reference PCI-DSS"

    def test_get_frameworks_returns_list(self):
        assert isinstance(get_frameworks_for_rule("DOCKER-001"), list)
        assert len(get_frameworks_for_rule("DOCKER-001")) > 0

    def test_get_frameworks_unknown_rule(self):
        assert get_frameworks_for_rule("NONEXISTENT") == []

    def test_total_rule_count(self):
        assert len(RULES_CATALOG) >= 20, "Expected at least 20 rules in the catalog"
