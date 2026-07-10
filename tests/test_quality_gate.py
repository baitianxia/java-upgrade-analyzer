import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import quality_gate  # noqa: E402


class QualityGateTest(unittest.TestCase):
    def test_release_plan_runs_signal_audit_after_real_project_matrix(self):
        tasks = quality_gate.build_plan(
            "release",
            python_exe="python3",
            skip_real=False,
            real_case="all",
            report_root="/tmp/jua-real",
        )
        names = [task.name for task in tasks]

        self.assertIn("real_project_all", names)
        self.assertIn("quality_signal_audit", names)
        self.assertGreater(names.index("quality_signal_audit"), names.index("real_project_all"))
        audit = next(task for task in tasks if task.name == "quality_signal_audit")
        self.assertIn("--fail-on-blocking", audit.command)

    def test_release_plan_skips_signal_audit_when_real_projects_are_skipped(self):
        tasks = quality_gate.build_plan(
            "release",
            python_exe="python3",
            skip_real=True,
            real_case="all",
            report_root="/tmp/jua-real",
        )

        self.assertNotIn("quality_signal_audit", [task.name for task in tasks])


if __name__ == "__main__":
    unittest.main()
