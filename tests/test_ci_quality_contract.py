import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "quality_gate", ROOT / "scripts" / "quality_gate.py"
)
quality_gate = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(quality_gate)


class CiQualityContractTest(unittest.TestCase):
    def test_smoke_workflow_covers_behavior_paths_and_explicit_java_tools(self):
        text = (ROOT / ".github/workflows/smoke-regression.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('"references/**"', text)
        self.assertIn("actions/setup-java@", text)
        self.assertIn("mvn -version", text)
        self.assertIn("--profile step5", text)
        self.assertIn("--json-out", text)

    def test_release_workflow_is_scheduled_manual_and_runs_guard_release_gate(self):
        path = ROOT / ".github/workflows/release-regression.yml"
        self.assertTrue(path.is_file())
        text = path.read_text(encoding="utf-8")

        self.assertIn("schedule:", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("actions/setup-java@", text)
        self.assertIn("--profile release", text)
        self.assertIn("--real-case guard", text)
        self.assertIn("--continue-on-failure", text)
        self.assertIn("--json-out", text)

    def test_required_tools_report_every_missing_executable(self):
        with patch.object(quality_gate.shutil, "which", return_value=None):
            missing = quality_gate.validate_required_tools(
                ("java", "javac", "javap", "jdeps", "mvn", "git")
            )

        self.assertEqual(
            missing, ["java", "javac", "javap", "jdeps", "mvn", "git"]
        )

    def test_every_gate_profile_starts_with_required_tool_preflight(self):
        for profile in ("quick", "step5", "release"):
            with self.subTest(profile=profile):
                plan = quality_gate.build_plan(profile, skip_real=True)
                self.assertEqual(plan[0].name, "required_tools")

    def test_tool_preflight_matches_profile_dependencies(self):
        quick = quality_gate.build_plan("quick", skip_real=True)[0]
        step5 = quality_gate.build_plan("step5", skip_real=True)[0]

        self.assertNotIn("mvn", quick.command)
        self.assertIn("mvn", step5.command)

    def test_required_tool_preflight_fails_instead_of_skipping(self):
        task = quality_gate._required_tools_task()
        with patch.object(
            quality_gate, "validate_required_tools", return_value=["javap"]
        ):
            result = quality_gate._run_required_tools_task(task)

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.returncode, 1)
        self.assertIn("javap", result.purpose)


if __name__ == "__main__":
    unittest.main()
