import importlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release-regression.yml"
PLATFORM_WORKFLOW = ROOT / ".github" / "workflows" / "platform-contract.yml"
SMOKE_WORKFLOW = ROOT / ".github" / "workflows" / "smoke-regression.yml"
TEST_MODULE_PATTERN = re.compile(r"\btests\.(test_[A-Za-z0-9_]+)\b")


class CiQualityContractTest(unittest.TestCase):
    def test_release_workflow_references_only_importable_test_modules(self):
        text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        modules = sorted({f"tests.{name}" for name in TEST_MODULE_PATTERN.findall(text)})

        self.assertTrue(modules, "release workflow must name its matrix tests explicitly")
        failures = []
        for module in modules:
            try:
                importlib.import_module(module)
            except Exception as error:  # noqa: BLE001 - report every invalid CI reference
                failures.append(f"{module}: {type(error).__name__}: {error}")
        self.assertEqual(failures, [])

    def test_release_matrix_covers_current_artifact_topology_safety_and_contract_tests(self):
        text = RELEASE_WORKFLOW.read_text(encoding="utf-8")

        for module in (
            "tests.test_binary_generated_regression",
            "tests.test_binary_artifact_diff",
            "tests.test_binary_artifact_safety",
            "tests.test_database_contract_scan",
        ):
            self.assertIn(module, text)

    def test_release_matrix_runs_independent_blackbox_contract(self):
        text = RELEASE_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("quality_gate.py --profile blackbox", text)
        self.assertIn("unittest_evidence_runner.py", text)
        self.assertIn("--forbid-skips", text)
        self.assertIn("Upload Artifact Topology Evidence", text)

    def test_complete_release_gate_provisions_every_required_build_toolchain(self):
        text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        release_job = text.split("  release-regression:", 1)[1]

        self.assertIn("Setup Reference Java 8", release_job)
        self.assertIn("JAVA8_HOME=${JAVA_HOME}", release_job)
        self.assertIn("Setup Reference Java 17", release_job)
        self.assertIn("JAVA17_HOME=${JAVA_HOME}", release_job)
        self.assertIn("gradle/actions/setup-gradle@v6", release_job)
        self.assertIn("gradle --version", release_job)

    def test_pull_requests_run_all_orthogonal_suites_and_effectiveness_gate(self):
        text = SMOKE_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("quick-regression:", text)
        self.assertIn("blackbox-regression:", text)
        self.assertIn("whitebox-regression:", text)
        self.assertIn("performance-regression:", text)
        self.assertIn("test-effectiveness:", text)
        self.assertIn("pre-merge-quality:", text)
        self.assertIn("quality_gate.py --profile quick", text)
        self.assertIn("quality_gate.py --profile blackbox", text)
        self.assertIn("quality_gate.py --profile whitebox", text)
        self.assertIn("quality_gate.py --profile performance", text)
        self.assertIn("binary_test_health_gate.py", text)
        self.assertIn("github.event_name == 'pull_request'", text)
        self.assertIn(
            "needs: [quick-regression, blackbox-regression, whitebox-regression, performance-regression, test-effectiveness]",
            text,
        )

    def test_premerge_profiles_always_upload_structured_quality_evidence(self):
        text = SMOKE_WORKFLOW.read_text(encoding="utf-8")

        self.assertEqual(text.count("if: always()"), 5)
        self.assertEqual(text.count("actions/upload-artifact@v4"), 5)
        self.assertIn("jua-quick-quality-gate.json", text)
        self.assertIn("jua-blackbox-quality-gate.json", text)
        self.assertIn("jua-whitebox-quality-gate.json", text)
        self.assertIn("jua-performance-quality-gate.json", text)
        self.assertIn("jua-test-effectiveness.json", text)

    def test_windows_matrix_runs_strict_native_blackbox_and_performance_contract(self):
        text = PLATFORM_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("windows-2022", text)
        self.assertIn("windows-2025", text)
        self.assertIn("test_suite_runner.py --suite windows", text)
        self.assertIn("windows-native-suite.json", text)
        self.assertIn("platform-quality:", text)
        self.assertIn("needs: platform-contract", text)
        self.assertIn('test "${PLATFORM_MATRIX_RESULT}" = "success"', text)
        self.assertNotIn("continue-on-error", text)


if __name__ == "__main__":
    unittest.main()
