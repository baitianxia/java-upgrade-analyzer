import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import fault_injection  # noqa: E402


class FaultInjectionRegistryTest(unittest.TestCase):
    def setUp(self):
        self.edge = {
            "api_identity": "vendor:api|vendor.Api.call|()|method|REMOVED",
            "artifact_sha256": "a" * 64,
            "artifact_entry": "BOOT-INF/classes/app/Entry.class",
            "caller_owner": "app.Entry",
            "caller_member": "run",
            "caller_descriptor": "()V",
            "callee_owner": "vendor.Api",
            "callee_member": "call",
            "callee_descriptor": "()V",
            "opcode_family": "invokestatic",
            "instruction_offset": "12",
        }
        self.scan = fault_injection.seal_oracle_scan({
            "artifact_sha256": "a" * 64,
            "complete": True,
            "edges": [dict(self.edge)],
            "failures": [],
            "artifact_entries": [self.edge["artifact_entry"]],
        })

    def apply(self, mode):
        analyzer = [dict(self.edge)]
        scan = copy.deepcopy(self.scan)
        result = fault_injection.apply_fault_injection(mode, analyzer, scan)
        self.assertEqual(analyzer, [self.edge])
        self.assertEqual(scan, self.scan)
        return result

    def test_drop_analyzer_edge_removes_one_row(self):
        result = self.apply("drop_analyzer_edge")
        self.assertEqual(result.analyzer_rows, ())
        self.assertFalse(result.oracle_mutated)
        self.assertEqual(result.expected_verdict, "missing")

    def test_add_analyzer_edge_creates_distinct_physical_occurrence(self):
        result = self.apply("add_analyzer_edge")
        self.assertEqual(len(result.analyzer_rows), 2)
        self.assertNotEqual(
            result.analyzer_rows[0]["instruction_offset"],
            result.analyzer_rows[1]["instruction_offset"],
        )
        self.assertEqual(result.expected_verdict, "extra")

    def test_wrong_descriptor_changes_only_mutated_analyzer_row(self):
        result = self.apply("wrong_analyzer_descriptor")
        self.assertEqual(result.analyzer_rows[0]["callee_descriptor"], "(I)V")
        self.assertFalse(result.oracle_mutated)
        self.assertEqual(result.expected_verdict, "missing")

    def test_wrong_descriptor_cannot_be_a_no_op(self):
        self.edge["callee_descriptor"] = "(I)V"

        result = self.apply("wrong_analyzer_descriptor")

        self.assertNotEqual(
            result.analyzer_rows[0]["callee_descriptor"],
            self.edge["callee_descriptor"],
        )
        self.assertEqual(result.metadata["original_descriptor"], "(I)V")
        self.assertEqual(
            result.metadata["mutated_descriptor"],
            result.analyzer_rows[0]["callee_descriptor"],
        )

    def test_corrupt_oracle_digest_is_marked_as_truth_mutation(self):
        result = self.apply("corrupt_oracle_digest")
        self.assertTrue(result.oracle_mutated)
        self.assertEqual(result.oracle_scan["artifact_sha256"], "a" * 64)
        self.assertEqual(result.oracle_scan["complete"], True)
        self.assertNotEqual(
            result.oracle_scan["oracle_payload_sha256"],
            fault_injection.oracle_payload_sha256(result.oracle_scan),
        )
        self.assertEqual(result.expected_signal, "oracle_invalid")

    def test_corrupt_oracle_digest_changes_an_already_long_descriptor(self):
        self.scan["edges"][0]["callee_descriptor"] = "(J)V"
        self.scan = fault_injection.seal_oracle_scan(self.scan)

        result = self.apply("corrupt_oracle_digest")

        self.assertEqual(result.oracle_scan["edges"][0]["callee_descriptor"], "(I)V")
        self.assertEqual(
            fault_injection.detect_oracle_mutation(self.scan, result.oracle_scan),
            "oracle_invalid",
        )

    def test_corrupt_oracle_digest_always_changes_an_edge_free_payload(self):
        self.scan = fault_injection.seal_oracle_scan({
            "artifact_sha256": "a" * 64,
            "complete": True,
            "edges": [],
            "failures": [],
            "api_reachability": {"fault-injected-api": "reachable"},
        })

        result = self.apply("corrupt_oracle_digest")

        self.assertNotEqual(result.oracle_scan, self.scan)
        self.assertNotEqual(
            result.oracle_scan["api_reachability"]["fault-injected-api"],
            self.scan["api_reachability"]["fault-injected-api"],
        )
        self.assertEqual(
            fault_injection.detect_oracle_mutation(self.scan, result.oracle_scan),
            "oracle_invalid",
        )

    def test_truncate_oracle_scan_is_incomplete(self):
        result = self.apply("truncate_oracle_scan")
        self.assertTrue(result.oracle_mutated)
        self.assertFalse(result.oracle_scan["complete"])
        self.assertEqual(result.oracle_scan["edges"], [])
        self.assertIn("fault_injection:oracle_scan_truncated", result.oracle_scan["failures"])

    def test_unknown_mode_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unsupported_fault_injection:invent"):
            self.apply("invent")


if __name__ == "__main__":
    unittest.main()
