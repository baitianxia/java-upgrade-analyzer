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
        self.assertEqual(result["baseline_topology_count"], 18)
        self.assertEqual(result["accounted_topology_count"], 18)
        self.assertEqual(result["baseline_mechanism_count"], 36)
        self.assertEqual(result["accounted_mechanism_count"], 36)
        self.assertEqual(result["monitored_deleted_production_path_count"], 48)
        self.assertEqual(result["monitored_deleted_test_path_count"], 72)
        self.assertEqual(result["monitored_deleted_test_asset_count"], 18)
        self.assertEqual(
            result["accounted_deleted_test_asset_replacement_count"], 18
        )
        self.assertEqual(result["release_status"], "passed")

    def test_every_monitored_mechanism_has_enforced_replacement_evidence(self):
        result = audit_capability_migration(ROOT, self.registry())

        self.assertEqual(result["missing_mechanisms"], [])
        self.assertEqual(result["incomplete_mechanisms"], [])
        self.assertEqual(result["incomplete_families"], [])
        self.assertEqual(result["incomplete_topologies"], [])

    def test_deleting_a_family_or_test_reference_invalidates_the_registry(self):
        missing_family = self.registry()
        missing_family["families"] = missing_family["families"][1:]
        missing_result = audit_capability_migration(ROOT, missing_family)
        self.assertFalse(missing_result["registry_structurally_valid"])
        self.assertTrue(any(
            item["reason_code"] == "CAPABILITY_BASELINE_SET_MISMATCH"
            for item in missing_result["issues"]
        ))

        missing_test_path = self.registry()
        missing_test_path["baseline"]["monitored_deleted_test_paths"] = (
            missing_test_path["baseline"]["monitored_deleted_test_paths"][1:]
        )
        test_path_result = audit_capability_migration(ROOT, missing_test_path)
        self.assertFalse(test_path_result["registry_structurally_valid"])
        self.assertTrue(any(
            item["reason_code"] == "CAPABILITY_DELETED_TEST_PATH_SET_MISMATCH"
            for item in test_path_result["issues"]
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

        self_erased = self.registry()
        removed = self_erased["baseline"]["monitored_mechanism_ids"].pop()
        self_erased["mechanism_inventory"] = [
            item for item in self_erased["mechanism_inventory"]
            if item["mechanism_id"] != removed
        ]
        self_erased_result = audit_capability_migration(ROOT, self_erased)
        self.assertFalse(self_erased_result["registry_structurally_valid"])
        self.assertTrue(any(
            item["reason_code"]
            == "CAPABILITY_MECHANISM_BASELINE_DECLARATION_MISMATCH"
            for item in self_erased_result["issues"]
        ))

        erased_family = self.registry()
        removed_family = erased_family["baseline"][
            "legacy_capability_family_ids"
        ].pop()
        erased_family["families"] = [
            item for item in erased_family["families"]
            if item["family_id"] != removed_family
        ]
        erased_family_result = audit_capability_migration(ROOT, erased_family)
        self.assertFalse(erased_family_result["registry_structurally_valid"])
        self.assertTrue(any(
            item["reason_code"] == "CAPABILITY_BASELINE_DECLARATION_MISMATCH"
            for item in erased_family_result["issues"]
        ))

        erased_topology = self.registry()
        removed_topology = erased_topology["baseline"]["legacy_topology_ids"].pop()
        erased_topology["topology_inventory"] = [
            item for item in erased_topology["topology_inventory"]
            if item["topology_id"] != removed_topology
        ]
        erased_topology_result = audit_capability_migration(ROOT, erased_topology)
        self.assertFalse(erased_topology_result["registry_structurally_valid"])
        self.assertTrue(any(
            item["reason_code"]
            == "CAPABILITY_TOPOLOGY_BASELINE_DECLARATION_MISMATCH"
            for item in erased_topology_result["issues"]
        ))

        erased_asset_replacement = self.registry()
        erased_asset_replacement["legacy_asset_replacements"].pop()
        erased_asset_result = audit_capability_migration(
            ROOT, erased_asset_replacement
        )
        self.assertFalse(erased_asset_result["registry_structurally_valid"])
        self.assertTrue(any(
            item["reason_code"]
            == "CAPABILITY_ASSET_REPLACEMENT_SET_MISMATCH"
            for item in erased_asset_result["issues"]
        ))


if __name__ == "__main__":
    unittest.main()
