import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "unittest_evidence_runner.py"


class UnittestEvidenceRunnerTest(unittest.TestCase):
    def run_sample(self, source, *selectors):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "execution_sample_tests.py").write_text(
                textwrap.dedent(source), encoding="utf-8"
            )
            evidence = root / "evidence.json"
            environment = dict(os.environ)
            environment["PYTHONPATH"] = os.pathsep.join(
                [str(root), str(ROOT), environment.get("PYTHONPATH", "")]
            ).rstrip(os.pathsep)
            completed = subprocess.run(
                [
                    sys.executable, str(RUNNER),
                    "--suite-label", "runner-self-test",
                    "--json-out", str(evidence),
                    *selectors,
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            payload = json.loads(evidence.read_text(encoding="utf-8"))
            return completed, payload

    def test_success_and_skip_counts_are_persisted(self):
        completed, payload = self.run_sample(
            """
            import unittest

            class SampleTest(unittest.TestCase):
                def test_passes(self):
                    self.assertEqual(2 + 2, 4)

                @unittest.skip("authored skip reason")
                def test_skips(self):
                    self.fail("not reached")
            """,
            "execution_sample_tests.SampleTest",
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["status"], "passed")
        self.assertEqual(payload["counts"]["run"], 2)
        self.assertEqual(payload["counts"]["skipped"], 1)
        self.assertEqual(payload["skips"][0]["reason"], "authored skip reason")
        self.assertEqual(payload["skip_policy"], "reported")

    def test_merge_gate_mode_rejects_every_skip(self):
        completed, payload = self.run_sample(
            """
            import unittest

            class SampleTest(unittest.TestCase):
                @unittest.skip("missing execution evidence")
                def test_skips(self):
                    self.fail("not reached")
            """,
            "--forbid-skips",
            "execution_sample_tests.SampleTest.test_skips",
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["reason_code"], "UNITTEST_UNEXPECTED_SKIP")
        self.assertEqual(payload["skip_policy"], "forbidden")
        self.assertEqual(payload["counts"]["skipped"], 1)
        self.assertEqual(len(payload["unexpected_skips"]), 1)

    def test_exact_platform_replacement_skip_is_the_only_allowed_exception(self):
        completed, payload = self.run_sample(
            """
            import unittest

            class SampleTest(unittest.TestCase):
                @unittest.skip("executed by native platform replacement")
                def test_platform_only(self):
                    self.fail("not reached")
            """,
            "--forbid-skips",
            "--allow-skip",
            "execution_sample_tests.SampleTest.test_platform_only",
            "execution_sample_tests.SampleTest.test_platform_only",
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["status"], "passed")
        self.assertEqual(payload["skip_policy"], "allowlisted_only")
        self.assertEqual(payload["counts"]["skipped"], 1)
        self.assertEqual(payload["unexpected_skips"], [])

    def test_expected_failure_cannot_be_reported_as_a_passing_gate(self):
        completed, payload = self.run_sample(
            """
            import unittest

            class SampleTest(unittest.TestCase):
                @unittest.expectedFailure
                def test_known_failure(self):
                    self.fail("known product defect")
            """,
            "execution_sample_tests.SampleTest.test_known_failure",
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["reason_code"], "UNITTEST_EXPECTED_FAILURE")
        self.assertEqual(payload["counts"]["expected_failures"], 1)
        self.assertIn(
            "known product defect", payload["expected_failures"][0]["detail"]
        )

    def test_failure_details_and_nonzero_status_are_persisted(self):
        completed, payload = self.run_sample(
            """
            import unittest

            class SampleTest(unittest.TestCase):
                def test_fails(self):
                    self.assertEqual("actual", "expected")
            """,
            "execution_sample_tests.SampleTest.test_fails",
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["counts"]["run"], 1)
        self.assertEqual(payload["counts"]["failures"], 1)
        self.assertIn("actual", payload["failures"][0]["detail"])

    def test_missing_selector_is_an_auditable_loader_failure(self):
        completed, payload = self.run_sample(
            "import unittest\n",
            "execution_sample_tests.MissingTest.test_missing",
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(payload["reason_code"], "UNITTEST_LOAD_FAILED")
        self.assertEqual(payload["counts"]["loader_failures"], 1)

    def test_overlapping_selectors_run_once_and_fail_the_execution_contract(self):
        completed, payload = self.run_sample(
            """
            import unittest

            class SampleTest(unittest.TestCase):
                def test_passes(self):
                    self.assertTrue(True)
            """,
            "execution_sample_tests.SampleTest",
            "execution_sample_tests.SampleTest.test_passes",
        )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(payload["reason_code"], "UNITTEST_SELECTION_OVERLAP")
        self.assertEqual(payload["counts"]["selected"], 2)
        self.assertEqual(payload["counts"]["unique_selected"], 1)
        self.assertEqual(payload["counts"]["run"], 1)
        self.assertEqual(payload["counts"]["duplicate_selections"], 1)


if __name__ == "__main__":
    unittest.main()
