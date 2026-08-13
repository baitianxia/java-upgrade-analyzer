import importlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release-regression.yml"
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


if __name__ == "__main__":
    unittest.main()
