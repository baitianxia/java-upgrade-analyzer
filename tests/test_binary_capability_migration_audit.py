import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from binary_capability_migration_audit import (  # noqa: E402
    REGISTRY_PATH,
    audit_capability_migration,
)


class BinaryCapabilityMigrationAuditTest(unittest.TestCase):
    def registry(self):
        return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))

    def test_every_main_capability_family_is_accounted_and_references_load(self):
        result = audit_capability_migration(ROOT, self.registry())

        self.assertTrue(result["registry_structurally_valid"], result["issues"])
        self.assertEqual(result["baseline_family_count"], 9)
        self.assertEqual(result["accounted_family_count"], 9)
        self.assertEqual(result["monitored_deleted_production_path_count"], 48)
        self.assertEqual(result["monitored_deleted_test_asset_count"], 18)
        self.assertEqual(result["release_status"], "blocked")

    def test_known_dropped_mechanisms_remain_explicit_release_blockers(self):
        result = audit_capability_migration(ROOT, self.registry())

        self.assertEqual(result["missing_mechanisms"], [
            "automatic_runtime_profile_materialization",
            "branch_mutation_flaky_health_gates",
            "declarative_http_client_dispatch",
            "dubbo_spi_dispatch",
            "dynamic_proxy_dispatch",
            "generated_topology_and_metamorphic_regression",
            "implicit_data_contract_dispatch",
            "mybatis_proxy_dispatch",
            "nested_executable_materialization",
            "real_project_rotation",
            "reflection_and_method_handle_dispatch",
            "spring_aop_dispatch",
            "spring_bean_wiring_dispatch",
            "spring_component_condition_activation",
            "spring_data_repository_dispatch",
            "spring_security_filter_dispatch",
            "spring_transaction_proxy_dispatch",
            "spring_xml_activation",
            "typed_tool_failure_matrix",
        ])
        self.assertIn(
            "dependency_source_snapshot_alignment",
            result["incomplete_mechanisms"],
        )
        self.assertIn("jpa_entity_activation_proof", result["incomplete_mechanisms"])

    def test_deleting_a_family_or_test_reference_invalidates_the_registry(self):
        missing_family = self.registry()
        missing_family["families"] = missing_family["families"][1:]
        missing_result = audit_capability_migration(ROOT, missing_family)
        self.assertFalse(missing_result["registry_structurally_valid"])
        self.assertTrue(any(
            item["reason_code"] == "CAPABILITY_BASELINE_SET_MISMATCH"
            for item in missing_result["issues"]
        ))

        broken_test = copy.deepcopy(self.registry())
        broken_test["mechanism_inventory"][0]["evidence_tests"] = [
            "tests.test_binary_entrypoint_discovery.MissingTest.test_missing"
        ]
        broken_result = audit_capability_migration(ROOT, broken_test)
        self.assertFalse(broken_result["registry_structurally_valid"])
        self.assertTrue(any(
            item["reason_code"] == "CAPABILITY_TEST_REFERENCE_INVALID"
            for item in broken_result["issues"]
        ))

    def test_deleting_a_monitored_path_or_mechanism_is_detected(self):
        missing_path = self.registry()
        missing_path["baseline"]["monitored_deleted_production_paths"] = (
            missing_path["baseline"]["monitored_deleted_production_paths"][1:]
        )
        path_result = audit_capability_migration(ROOT, missing_path)
        self.assertFalse(path_result["registry_structurally_valid"])
        self.assertTrue(any(
            item["reason_code"]
            == "CAPABILITY_DELETED_PRODUCTION_PATH_SET_MISMATCH"
            for item in path_result["issues"]
        ))

        missing_mechanism = self.registry()
        missing_mechanism["mechanism_inventory"] = (
            missing_mechanism["mechanism_inventory"][1:]
        )
        mechanism_result = audit_capability_migration(ROOT, missing_mechanism)
        self.assertFalse(mechanism_result["registry_structurally_valid"])
        self.assertTrue(any(
            item["reason_code"] == "CAPABILITY_MECHANISM_SET_MISMATCH"
            for item in mechanism_result["issues"]
        ))


if __name__ == "__main__":
    unittest.main()
