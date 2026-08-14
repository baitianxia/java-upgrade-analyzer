import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import test_suite_runner as runner  # noqa: E402


class TestSuiteRunnerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = runner.load_policy()

    def test_classification_is_public_boundary_first_then_performance_then_whitebox(self):
        self.assertEqual(
            runner.classify_test_id(
                "tests.blackbox.test_public_binary_cli.PublicBinaryCliBlackboxTest.test_contract",
                self.policy,
            ),
            "blackbox",
        )
        self.assertEqual(
            runner.classify_test_id(
                "tests.test_binary_performance_gate.BinaryPerformanceGateTest.test_probe",
                self.policy,
            ),
            "performance",
        )
        self.assertEqual(
            runner.classify_test_id(
                "tests.test_binary_output.BinaryOutputTest.test_contract",
                self.policy,
            ),
            "whitebox",
        )

    def test_every_discovered_test_has_exactly_one_partition(self):
        discovered = runner.discover_tests(ROOT)
        partitions = runner.partition_tests(discovered, self.policy)
        partitioned_ids = [
            test.id()
            for suite_name in ("blackbox", "whitebox", "performance")
            for test in partitions[suite_name]
        ]

        self.assertEqual(len(partitioned_ids), len(discovered))
        self.assertEqual(len(partitioned_ids), len(set(partitioned_ids)))
        self.assertTrue(partitions["blackbox"])
        self.assertTrue(partitions["whitebox"])
        self.assertTrue(partitions["performance"])

    def test_blackbox_performance_and_windows_profiles_are_strict_about_skips(self):
        self.assertTrue(runner.skips_are_forbidden("blackbox"))
        self.assertTrue(runner.skips_are_forbidden("performance"))
        self.assertTrue(runner.skips_are_forbidden("windows"))
        self.assertFalse(runner.skips_are_forbidden("whitebox"))
        self.assertFalse(runner.skips_are_forbidden("all"))
        performance_id = (
            "tests.test_binary_performance_gate.BinaryPerformanceGateTest.test_probe"
        )
        whitebox_id = "tests.test_binary_output.BinaryOutputTest.test_contract"
        self.assertTrue(
            runner.skipped_test_is_forbidden("all", performance_id, self.policy)
        )
        self.assertFalse(
            runner.skipped_test_is_forbidden("all", whitebox_id, self.policy)
        )

    def test_isolated_suite_discovery_loads_only_its_own_tests(self):
        blackbox = runner.discover_tests(
            ROOT, start_directory="tests/blackbox"
        )
        performance = runner.load_performance_tests(self.policy)

        self.assertTrue(blackbox)
        self.assertTrue(performance)
        self.assertEqual(
            {runner.classify_test_id(test.id(), self.policy) for test in blackbox},
            {"blackbox"},
        )
        self.assertEqual(
            {
                runner.classify_test_id(test.id(), self.policy)
                for test in performance
            },
            {"performance"},
        )

    def test_windows_selectors_load_full_blackbox_and_native_contract_without_gaps(self):
        windows, gaps = runner.load_selector_tests(
            self.policy, "windows_test_selectors", ROOT,
        )
        ids = {test.id() for test in windows}

        self.assertEqual(gaps, [])
        self.assertGreaterEqual(
            len(windows), self.policy["minimum_windows_test_count"]
        )
        self.assertTrue(any(value.startswith("tests.blackbox.") for value in ids))
        self.assertIn(
            "tests.windows_native_contract.WindowsNativeContractTest."
            "test_pythonw_parent_captures_unicode_and_metacharacter_argument",
            ids,
        )
        self.assertIn(
            "tests.windows_native_contract.WindowsNativeContractTest."
            "test_native_process_metrics_report_cpu_and_peak_memory",
            ids,
        )
        self.assertIn(
            "tests.test_binary_performance_gate.BinaryPerformanceGateTest."
            "test_small_fixture_enforces_class_conservation_and_zero_warm_parse",
            ids,
        )

    def test_windows_suite_refuses_non_native_platform_instead_of_skipping(self):
        self.assertEqual(runner.windows_suite_precondition("nt"), "")
        self.assertEqual(
            runner.windows_suite_precondition("posix"),
            "WINDOWS_SUITE_REQUIRES_NATIVE_WINDOWS",
        )

    def test_only_full_release_claim_is_blocked_by_incomplete_capability_matrix(self):
        incomplete = {"capability_readiness": {"status": "incomplete"}}
        complete = {"capability_readiness": {"status": "complete"}}

        self.assertFalse(
            runner.public_capability_readiness_blocks("blackbox", incomplete)
        )
        self.assertFalse(
            runner.public_capability_readiness_blocks("whitebox", incomplete)
        )
        self.assertTrue(
            runner.public_capability_readiness_blocks("all", incomplete)
        )
        self.assertTrue(
            runner.public_capability_readiness_blocks("windows", incomplete)
        )
        self.assertFalse(
            runner.public_capability_readiness_blocks("all", complete)
        )


if __name__ == "__main__":
    unittest.main()
