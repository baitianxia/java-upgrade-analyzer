import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import quality_gate  # noqa: E402


class QualityGateTest(unittest.TestCase):
    def test_quick_and_release_profiles_require_oracle_independence(self):
        for profile in ("quick", "release"):
            with self.subTest(profile=profile):
                tasks = quality_gate.build_plan(profile, skip_real=True)
                task = next(item for item in tasks if item.name == "oracle_independence")
                self.assertIn("scripts/oracle_independence.py", task.command)
                self.assertIn("tests/fixtures/oracle_boundary.json", task.command)

    def test_round_input_files_are_initialized_without_overwriting_reviews(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reviews = root / "test_round_reviews.json"
            history = root / "test_round_history.json"
            reviews.write_text('{"findings":[{"finding_id":"kept"}]}', encoding="utf-8")
            tasks = quality_gate.build_plan(
                "step5", report_root=str(root), skip_real=False
            )

            quality_gate.ensure_round_input_files(tasks)

            self.assertEqual(
                json.loads(reviews.read_text(encoding="utf-8"))["findings"][0]["finding_id"],
                "kept",
            )
            self.assertEqual(json.loads(history.read_text(encoding="utf-8")), [])

    def test_step5_default_real_matrix_uses_reproducible_guards(self):
        tasks = quality_gate.build_plan(
            "step5", python_exe="python3", skip_real=False,
            report_root="/tmp/jua-real",
        )

        real = next(task for task in tasks if task.real_project)
        self.assertEqual(real.name, "real_project_guard")
        self.assertIn("guard", real.command)

    def test_missing_audit_still_writes_blocked_retrospective(self):
        import json
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real.json"
            output_json = Path(tmp) / "retrospective.json"
            output_md = Path(tmp) / "retrospective.md"
            real.write_text(json.dumps({"status": "failed", "results": []}), encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "test_round_retrospective.py"),
                    str(real),
                    str(Path(tmp) / "missing-audit.json"),
                    "--json-out", str(output_json),
                    "--markdown-out", str(output_md),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
            )

            payload = json.loads(output_json.read_text(encoding="utf-8"))
            markdown = output_md.read_text(encoding="utf-8")

        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(payload["decision"], "blocked")
        self.assertIn("状态：`failed`", markdown)
        self.assertTrue(any(error.startswith("audit_input_error:") for error in payload["errors"]))

    def test_malformed_nested_payload_still_writes_blocked_retrospective(self):
        import json
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real.json"
            audit = Path(tmp) / "audit.json"
            output_json = Path(tmp) / "retrospective.json"
            output_md = Path(tmp) / "retrospective.md"
            real.write_text(json.dumps({"status": "passed", "results": [None]}), encoding="utf-8")
            audit.write_text(json.dumps({"signals": [None]}), encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "test_round_retrospective.py"),
                    str(real), str(audit),
                    "--json-out", str(output_json),
                    "--markdown-out", str(output_md),
                ],
                cwd=str(ROOT), capture_output=True, text=True,
            )
            payload = json.loads(output_json.read_text(encoding="utf-8"))
            markdown = output_md.read_text(encoding="utf-8")

        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(payload["decision"], "blocked")
        self.assertIn("retrospective_build_error:", "\n".join(payload["errors"]))
        self.assertIn("状态：`failed`", markdown)

    def test_task_clears_declared_output_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            stale = Path(tmp) / "result.json"
            stale.write_text("stale", encoding="utf-8")
            task = quality_gate.GateTask(
                "producer", [], "", output_paths=(str(stale),)
            )
            completed = __import__("subprocess").CompletedProcess([], 0)
            with patch.object(quality_gate.subprocess, "run", return_value=completed):
                quality_gate._run_task(task)

            self.assertFalse(stale.exists())

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
        self.assertNotIn("--fail-on-blocking", audit.command)
        self.assertTrue(audit.run_after_failure)

        self.assertIn("test_round_retrospective", names)
        self.assertGreater(
            names.index("test_round_retrospective"),
            names.index("quality_signal_audit"),
        )
        retrospective = next(
            task for task in tasks if task.name == "test_round_retrospective"
        )
        self.assertIn("scripts/test_round_retrospective.py", retrospective.command)
        self.assertIn("--history", retrospective.command)
        self.assertTrue(retrospective.run_after_failure)
        self.assertIn("capability_family_closure", names)
        self.assertGreater(
            names.index("capability_family_closure"),
            names.index("test_round_retrospective"),
        )
        closure = next(
            task for task in tasks if task.name == "capability_family_closure"
        )
        self.assertIn("scripts/capability_family_closure.py", closure.command)
        self.assertIn("tests/fixtures/capability_families.json", closure.command)
        self.assertTrue(closure.run_after_failure)

    def test_release_plan_skips_signal_audit_when_real_projects_are_skipped(self):
        tasks = quality_gate.build_plan(
            "release",
            python_exe="python3",
            skip_real=True,
            real_case="all",
            report_root="/tmp/jua-real",
        )

        self.assertNotIn("quality_signal_audit", [task.name for task in tasks])
        self.assertNotIn("test_round_retrospective", [task.name for task in tasks])
        self.assertNotIn("capability_family_closure", [task.name for task in tasks])

    def test_step5_plan_runs_retrospective_after_signal_audit(self):
        tasks = quality_gate.build_plan(
            "step5",
            python_exe="python3",
            skip_real=False,
            real_case="spring-petclinic",
            report_root="/tmp/jua-real",
        )
        names = [task.name for task in tasks]

        self.assertGreater(
            names.index("test_round_retrospective"),
            names.index("quality_signal_audit"),
        )
        self.assertGreater(
            names.index("capability_family_closure"),
            names.index("test_round_retrospective"),
        )

    def test_failed_real_project_still_runs_audit_and_retrospective(self):
        tasks = [
            quality_gate.GateTask("real", [], "", real_project=True),
            quality_gate.GateTask("audit", [], "", run_after_failure=True),
            quality_gate.GateTask("retro", [], "", run_after_failure=True),
            quality_gate.GateTask("closure", [], "", run_after_failure=True),
            quality_gate.GateTask("later", [], ""),
        ]
        outcomes = {
            "real": "failed",
            "audit": "passed",
            "retro": "failed",
            "closure": "failed",
        }

        def fake_run(task, env=None):
            status = outcomes[task.name]
            return quality_gate.GateResult(
                task.name, task.command, status,
                returncode=0 if status == "passed" else 1,
            )

        with patch.object(quality_gate, "_run_task", side_effect=fake_run):
            results, overall = quality_gate._execute_tasks(
                tasks, env={}, continue_on_failure=False
            )

        self.assertEqual(
            [result.name for result in results],
            ["real", "audit", "retro", "closure"],
        )
        self.assertEqual(overall, "failed")


if __name__ == "__main__":
    unittest.main()
