import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import quality_gate  # noqa: E402


class QualityGateTest(unittest.TestCase):
    def test_quick_and_step5_profiles_target_only_current_binary_contracts(self):
        for profile in ("quick", "step5"):
            command = quality_gate.command_for(profile)
            rendered = " ".join(command)
            self.assertTrue(command[1].endswith("unittest_evidence_runner.py"))
            self.assertIn("test_binary_", rendered)
            self.assertIn("tests.test_binary_result_truth", rendered)
            self.assertIn("tests.test_blackbox_harness", rendered)
            self.assertIn("tests.blackbox.test_managed_process", rendered)
            self.assertIn("tests.test_test_trust_gate", rendered)
            self.assertIn("tests.blackbox.test_public_binary_cli", rendered)
            self.assertIn("tests.test_ci_quality_contract", rendered)
            self.assertIn("tests.test_platform_contract", rendered)
            self.assertIn("--allow-skip", command)
            self.assertNotIn("s4_jar_compare", rendered)
            self.assertNotIn("s5_call_chain_engine_integrated", rendered)

    def test_quick_skip_exceptions_are_exact_policy_entries_with_native_replacements(self):
        policy = json.loads((
            ROOT / "tests" / "fixtures" / "test_suite_policy.json"
        ).read_text(encoding="utf-8"))
        allowed = set(policy["allowed_whitebox_skip_selectors"])

        self.assertEqual(
            set(quality_gate.QUICK_ALLOWED_SKIP_SELECTORS),
            {next(selector for selector in allowed if "pythonw_parent" in selector)},
        )
        self.assertEqual(
            set(quality_gate.STEP5_ALLOWED_SKIP_SELECTORS), allowed
        )

    def test_every_profile_can_persist_test_execution_evidence(self):
        for profile in (
            "quick", "step5", "blackbox", "whitebox", "performance", "release",
        ):
            with self.subTest(profile=profile):
                command = quality_gate.command_for(profile, json_out="/tmp/run.json")
                self.assertIn("--json-out", command)
                self.assertIn("/tmp/run.json", command)

    def test_execution_evidence_requires_matching_nonempty_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "execution.json"
            path.write_text(json.dumps({
                "schema": "java-upgrade-analyzer.unittest-execution.v1",
                "suite_label": "quick",
                "status": "passed",
                "counts": {
                    "selected": 3,
                    "unique_selected": 3,
                    "duplicate_selections": 0,
                    "run": 3,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 0,
                    "expected_failures": 0,
                    "unexpected_successes": 0,
                    "loader_failures": 0,
                },
                "duplicate_selections": [],
                "failures": [],
                "errors": [],
                "skips": [],
                "expected_failures": [],
                "unexpected_successes": [],
                "loader_failures": [],
                "allowed_skip_selectors": list(
                    quality_gate.QUICK_ALLOWED_SKIP_SELECTORS
                ),
                "skip_policy": "allowlisted_only",
            }), encoding="utf-8")
            payload, error = quality_gate.load_test_execution_evidence(
                path, profile="quick", returncode=0,
            )
            self.assertEqual(error, "")
            self.assertEqual(payload["counts"]["run"], 3)

            payload["counts"]["run"] = 0
            path.write_text(json.dumps(payload), encoding="utf-8")
            _payload, error = quality_gate.load_test_execution_evidence(
                path, profile="quick", returncode=0,
            )
            self.assertEqual(error, "TEST_EXECUTION_EVIDENCE_EMPTY")

            payload["counts"].update({
                "run": 2,
                "selected": 3,
                "unique_selected": 3,
            })
            path.write_text(json.dumps(payload), encoding="utf-8")
            _payload, error = quality_gate.load_test_execution_evidence(
                path, profile="quick", returncode=0,
            )
            self.assertEqual(
                error, "TEST_EXECUTION_EVIDENCE_SELECTION_MISMATCH"
            )

    def test_execution_evidence_rejects_hidden_outcomes_and_weak_skip_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "execution.json"
            payload = {
                "schema": "java-upgrade-analyzer.unittest-execution.v1",
                "suite_label": "quick",
                "status": "passed",
                "counts": {
                    "selected": 1,
                    "unique_selected": 1,
                    "duplicate_selections": 0,
                    "run": 1,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 0,
                    "expected_failures": 0,
                    "unexpected_successes": 0,
                    "loader_failures": 0,
                },
                "duplicate_selections": [],
                "failures": [],
                "errors": [],
                "skips": [],
                "expected_failures": [],
                "unexpected_successes": [],
                "loader_failures": [],
                "skip_policy": "reported",
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            _payload, error = quality_gate.load_test_execution_evidence(
                path, profile="quick", returncode=0,
            )
            self.assertEqual(
                error, "TEST_EXECUTION_EVIDENCE_SKIP_POLICY_MISMATCH"
            )

            payload["skip_policy"] = "allowlisted_only"
            payload["allowed_skip_selectors"] = list(
                quality_gate.QUICK_ALLOWED_SKIP_SELECTORS
            )
            payload["counts"]["failures"] = 1
            path.write_text(json.dumps(payload), encoding="utf-8")
            _payload, error = quality_gate.load_test_execution_evidence(
                path, profile="quick", returncode=0,
            )
            self.assertEqual(
                error, "TEST_EXECUTION_EVIDENCE_DETAILS_MISMATCH"
            )

    def test_quick_profile_guards_critical_step4_regressions(self):
        quick = quality_gate.command_for("quick")
        step5 = quality_gate.command_for("step5")

        exact_in_both_profiles = (
            *quality_gate.QUICK_STEP4_ORACLE_REGRESSION_TESTS,
            *quality_gate.QUICK_STEP4_VALIDATION_REGRESSION_TESTS,
        )
        for selector in exact_in_both_profiles:
            self.assertEqual(quick.count(selector), 1)
            if selector.startswith("tests.test_binary_fact_store."):
                self.assertNotIn(selector, step5)
            else:
                self.assertEqual(step5.count(selector), 1)
        covered_by_complete_step5_modules = (
            *quality_gate.QUICK_STEP4_PIPELINE_REGRESSION_TESTS,
            *quality_gate.QUICK_STEP4_RUN_STEP_REGRESSION_TESTS,
        )
        for selector in covered_by_complete_step5_modules:
            self.assertEqual(quick.count(selector), 1)
            self.assertNotIn(selector, step5)
        self.assertEqual(step5.count("tests.test_binary_pipeline"), 1)
        self.assertEqual(step5.count("tests.test_binary_fact_store"), 1)
        self.assertEqual(step5.count("tests.test_run_step_main_state"), 1)

    def test_step5_does_not_duplicate_exact_tests_covered_by_complete_modules(self):
        step5 = quality_gate.STEP5_MODULES
        for module in quality_gate._STEP5_COMPLETE_MODULES:
            self.assertEqual(step5.count(module), 1)
            self.assertFalse(any(
                selector.startswith(module + ".") for selector in step5
            ), module)

    def test_quick_and_step5_selection_plans_have_no_overlapping_selectors(self):
        for profile, selectors in (
            ("quick", quality_gate.QUICK_MODULES),
            ("step5", quality_gate.STEP5_MODULES),
        ):
            with self.subTest(profile=profile):
                overlaps = [
                    (left, right)
                    for index, left in enumerate(selectors)
                    for right in selectors[index + 1:]
                    if (
                        left == right
                        or left.startswith(right + ".")
                        or right.startswith(left + ".")
                    )
                ]
                self.assertEqual(overlaps, [])

    def test_release_discovers_all_current_tests(self):
        command = quality_gate.command_for("release")
        self.assertTrue(command[1].endswith("test_suite_runner.py"))
        self.assertEqual(command[-2:], ["--suite", "all"])
        self.assertTrue(
            quality_gate.test_health_command()[-1].endswith(
                "binary_test_health_gate.py"
            )
        )
        real = quality_gate.real_project_command(
            "/tmp/audit", cache_root="/tmp/cache", jdk_home="/tmp/jdk"
        )
        self.assertTrue(real[1].endswith("binary_real_project_guard.py"))
        self.assertIn("--download", real)
        performance = quality_gate.performance_command("/tmp/audit")
        self.assertTrue(performance[1].endswith("binary_performance_gate.py"))
        self.assertIn("--gate", performance)
        recorded = quality_gate.performance_command(
            "/tmp/audit", evidence_mode="recorded"
        )
        self.assertIn("--verify-recorded-gate", recorded)
        self.assertNotIn("--gate", recorded)
        matrix = quality_gate.real_project_commands(
            "/tmp/audit", cache_root="/tmp/cache", jdk_home="/tmp/jdk"
        )
        self.assertGreaterEqual(len(matrix), 3)
        self.assertTrue(all("--manifest" in item for item in matrix))

        first = quality_gate.performance_command(
            "/tmp/audit",
            output_path="/tmp/audit/performance-result-1.json",
        )
        second = quality_gate.performance_command(
            "/tmp/audit",
            output_path="/tmp/audit/performance-result-2.json",
        )
        self.assertNotEqual(
            first[first.index("--output") + 1],
            second[second.index("--output") + 1],
        )

    def test_quality_children_have_finite_timeout_and_timeout_result(self):
        timeout = subprocess.TimeoutExpired(["child"], 1, output="partial")
        with patch.object(
            quality_gate,
            "run_managed_subprocess",
            side_effect=timeout,
        ) as managed:
            completed, timed_out = quality_gate._run_bounded_subprocess(
                ["child"], timeout_seconds=1, check=False,
            )

        self.assertTrue(timed_out)
        self.assertEqual(completed.returncode, 124)
        self.assertEqual(completed.stdout, "partial")
        self.assertEqual(managed.call_args.kwargs["timeout"], 1.0)
        self.assertTrue(all(
            seconds > 0
            for seconds in quality_gate.TEST_TIMEOUT_SECONDS_BY_PROFILE.values()
        ))

    def test_named_test_suites_have_stable_quality_gate_profiles(self):
        for profile in ("blackbox", "whitebox", "performance"):
            command = quality_gate.command_for(profile)
            self.assertTrue(command[1].endswith("test_suite_runner.py"))
            self.assertEqual(command[-2:], ["--suite", profile])

    def test_release_authorization_requires_every_capability_replacement(self):
        migration = quality_gate.capability_migration_status(ROOT)
        self.assertTrue(migration["registry_structurally_valid"], migration["issues"])
        self.assertEqual(migration["release_status"], "passed")
        self.assertEqual(migration["incomplete_families"], [])
        self.assertEqual(migration["incomplete_mechanisms"], [])

    def test_dry_run_is_non_mutating_and_exposes_exact_command(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts/quality_gate.py"),
             "--profile", "step5", "--dry-run"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("tests.test_binary_pipeline", completed.stdout)
        self.assertNotIn("source_first", completed.stdout)


if __name__ == "__main__":
    unittest.main()
