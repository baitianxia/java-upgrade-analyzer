import json
import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


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
        allowed_whitebox_id = (
            "tests.test_platform_contract.PlatformContractTest."
            "test_pythonw_parent_repeatedly_captures_real_git_stdout"
        )
        self.assertTrue(
            runner.skipped_test_is_forbidden("all", performance_id, self.policy)
        )
        self.assertTrue(
            runner.skipped_test_is_forbidden("all", whitebox_id, self.policy)
        )
        self.assertFalse(
            runner.skipped_test_is_forbidden(
                "whitebox", allowed_whitebox_id, self.policy
            )
        )
        self.assertTrue(
            runner.skipped_test_is_forbidden(
                "whitebox", whitebox_id, self.policy
            )
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

    def test_windows_selectors_load_governed_blackbox_and_native_replacements(self):
        windows, gaps = runner.load_windows_tests(self.policy, ROOT)
        ids = {test.id() for test in windows}

        self.assertEqual(gaps, [])
        self.assertEqual(len(ids), len(windows))
        self.assertGreaterEqual(
            len(windows), self.policy["minimum_windows_test_count"]
        )
        self.assertTrue(any(value.startswith("tests.blackbox.") for value in ids))
        self.assertIn(
            "tests.windows_native_contract.WindowsNativeContractTest."
            "test_pythonw_parent_captures_unicode_and_metacharacter_argument",
            ids,
        )
        self.assertNotIn(
            "tests.blackbox.test_public_failure_contracts."
            "PublicFailureContractsBlackboxTest."
            "test_environment_failures_are_preflighted_and_only_transient_failures_retry",
            ids,
        )
        self.assertIn(
            "tests.windows_native_contract.WindowsNativeContractTest."
            "test_native_process_metrics_report_cpu_and_peak_memory",
            ids,
        )
        self.assertIn(
            "tests.windows_native_contract.WindowsNativeContractTest."
            "test_cmd_and_bat_wrappers_preserve_unicode_and_metacharacters",
            ids,
        )
        self.assertIn(
            "tests.windows_native_contract.WindowsNativeContractTest."
            "test_near_limit_unicode_path_survives_git_and_atomic_json",
            ids,
        )
        self.assertNotIn(
            "tests.test_build_tool_selection.BuildToolSelectionTest."
            "test_maven_uses_shell_for_non_executable_project_wrapper",
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

    @unittest.skipIf(sys.platform == "win32", "requires a non-Windows host")
    def test_early_suite_failure_is_still_written_as_execution_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "windows.json"
            completed = subprocess.run(
                [
                    sys.executable, str(ROOT / "scripts" / "test_suite_runner.py"),
                    "--suite", "windows", "--json-out", str(evidence),
                ],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            payload = json.loads(evidence.read_text(encoding="utf-8"))

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(
            payload["reason_code"], "WINDOWS_SUITE_REQUIRES_NATIVE_WINDOWS"
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

    def test_execution_evidence_records_failure_identity_and_selection_counts(self):
        class EvidencePassCase(unittest.TestCase):
            def runTest(self):
                pass

        class EvidenceFailCase(unittest.TestCase):
            def runTest(self):
                self.fail("independent synthetic failure")

        trust = {"status": "passed", "capability_readiness": {"status": "complete"}}
        policy = {"blackbox_test_roots": [], "performance_test_selectors": []}
        selected = [EvidencePassCase(), EvidenceFailCase()]
        failure_id = selected[1].id()
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "suite.json"
            with (
                mock.patch.object(runner, "run_trust_gate", return_value=trust),
                mock.patch.object(runner, "load_policy", return_value=policy),
                mock.patch.object(runner, "discover_tests", return_value=selected),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                returncode = runner.main([
                    "--suite", "all", "--root", str(ROOT),
                    "--json-out", str(evidence), "--verbosity", "0",
                ])
            payload = json.loads(evidence.read_text(encoding="utf-8"))

        self.assertEqual(returncode, 1)
        self.assertEqual(payload["reason_code"], "TEST_SUITE_FAILED")
        self.assertEqual(payload["counts"]["selected"], 2)
        self.assertEqual(payload["counts"]["unique_selected"], 2)
        self.assertEqual(payload["counts"]["duplicate_selections"], 0)
        self.assertEqual(payload["counts"]["run"], 2)
        self.assertEqual(payload["counts"]["failures"], 1)
        self.assertEqual(payload["failures"][0]["test_id"], failure_id)
        self.assertIn("independent synthetic failure", payload["failures"][0]["detail"])

    def test_overlapping_suite_selection_runs_once_and_fails_contract(self):
        class EvidencePassCase(unittest.TestCase):
            def runTest(self):
                pass

        trust = {"status": "passed", "capability_readiness": {"status": "complete"}}
        policy = {"blackbox_test_roots": [], "performance_test_selectors": []}
        selected = [EvidencePassCase(), EvidencePassCase()]
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "suite.json"
            with (
                mock.patch.object(runner, "run_trust_gate", return_value=trust),
                mock.patch.object(runner, "load_policy", return_value=policy),
                mock.patch.object(runner, "discover_tests", return_value=selected),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                returncode = runner.main([
                    "--suite", "all", "--root", str(ROOT),
                    "--json-out", str(evidence), "--verbosity", "0",
                ])
            payload = json.loads(evidence.read_text(encoding="utf-8"))

        self.assertEqual(returncode, 1)
        self.assertEqual(payload["reason_code"], "TEST_SUITE_SELECTION_OVERLAP")
        self.assertEqual(payload["counts"]["selected"], 2)
        self.assertEqual(payload["counts"]["unique_selected"], 1)
        self.assertEqual(payload["counts"]["duplicate_selections"], 1)
        self.assertEqual(payload["counts"]["run"], 1)

    def test_expected_failure_is_never_a_passing_governed_suite(self):
        class EvidenceExpectedFailureCase(unittest.TestCase):
            @unittest.expectedFailure
            def runTest(self):
                self.fail("known defect must remain merge-blocking")

        trust = {"status": "passed", "capability_readiness": {"status": "complete"}}
        policy = {"blackbox_test_roots": [], "performance_test_selectors": []}
        selected = [EvidenceExpectedFailureCase()]
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "suite.json"
            with (
                mock.patch.object(runner, "run_trust_gate", return_value=trust),
                mock.patch.object(runner, "load_policy", return_value=policy),
                mock.patch.object(runner, "discover_tests", return_value=selected),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                returncode = runner.main([
                    "--suite", "all", "--root", str(ROOT),
                    "--json-out", str(evidence), "--verbosity", "0",
                ])
            payload = json.loads(evidence.read_text(encoding="utf-8"))

        self.assertEqual(returncode, 1)
        self.assertEqual(payload["reason_code"], "TEST_SUITE_EXPECTED_FAILURE")
        self.assertEqual(payload["counts"]["expected_failures"], 1)
        self.assertEqual(len(payload["expected_failures"]), 1)

if __name__ == "__main__":
    unittest.main()
