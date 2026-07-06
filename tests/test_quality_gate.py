import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import quality_gate  # noqa: E402


class QualityGateTest(unittest.TestCase):
    def test_quick_profile_includes_core_semantic_gate(self):
        tasks = quality_gate.build_plan("quick", python_exe="pythonX")
        names = [task.name for task in tasks]

        self.assertEqual(names[0], "py_compile_scripts")
        self.assertIn("accuracy_benchmark_core", names)
        self.assertIn("unit_core_semantics", names)
        self.assertIn("smoke_core", names)
        self.assertNotIn("real_project_all", names)

    def test_step5_profile_can_skip_real_project_matrix(self):
        tasks = quality_gate.build_plan("step5", python_exe="pythonX", skip_real=True)
        names = [task.name for task in tasks]

        self.assertIn("accuracy_benchmark_step5", names)
        self.assertIn("unit_step5_semantics", names)
        self.assertIn("smoke_step5", names)
        self.assertFalse(any(task.real_project for task in tasks))

    def test_release_profile_includes_real_project_and_diff_check_by_default(self):
        tasks = quality_gate.build_plan(
            "release",
            python_exe="pythonX",
            report_root="/tmp/jua-real",
        )
        names = [task.name for task in tasks]

        self.assertIn("accuracy_benchmark_all", names)
        self.assertIn("unit_all", names)
        self.assertIn("smoke_all", names)
        self.assertIn("real_project_all", names)
        self.assertIn("git_diff_check", names)
        real_task = next(task for task in tasks if task.name == "real_project_all")
        self.assertIn("/tmp/jua-real", real_task.command)

    def test_dry_run_outputs_json_plan_without_running_tasks(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "quality_gate.py"),
                "--profile",
                "step5",
                "--skip-real",
                "--dry-run",
            ],
            cwd=str(ROOT),
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(completed.stdout)

        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["profile"], "step5")
        task_names = [task["name"] for task in payload["tasks"]]
        self.assertIn("accuracy_benchmark_step5", task_names)
        self.assertIn("unit_step5_semantics", task_names)
        self.assertNotIn("real_project_all", task_names)


if __name__ == "__main__":
    unittest.main()
