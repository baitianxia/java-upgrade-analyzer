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
    def test_evidence_identity_binds_commit_environment_and_dependency_lock(self):
        identity = quality_gate.build_evidence_identity(
            "release", real_scope_mode="included", real_case="guard"
        )

        self.assertTrue(identity["commit"])
        self.assertEqual(identity["profile"], "release")
        self.assertEqual(identity["real_project_scope"]["selector"], "guard")
        self.assertEqual(identity["python"]["executable"], sys.executable)
        self.assertEqual(len(identity["runtime_dependencies"]["requirements_sha256"]), 64)
        self.assertEqual(identity["runtime_dependencies"]["declared"], {
            "tree-sitter": "0.25.2",
            "tree-sitter-java": "0.23.5",
        })
        self.assertIn("checks", identity["environment_contract"])

    def test_all_profiles_default_to_regression_only(self):
        for profile in ("quick", "step5", "release"):
            with self.subTest(profile=profile):
                tasks = quality_gate.build_plan(profile)

                self.assertFalse(
                    any(task.real_project for task in tasks),
                    f"{profile} must not run real projects without explicit opt-in",
                )

    def test_cli_requires_explicit_real_project_opt_in(self):
        import subprocess

        default = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "quality_gate.py"),
             "--profile", "step5", "--dry-run"],
            cwd=str(ROOT), capture_output=True, text=True,
        )
        included = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "quality_gate.py"),
             "--profile", "step5", "--include-real", "--dry-run"],
            cwd=str(ROOT), capture_output=True, text=True,
        )

        self.assertEqual(default.returncode, 0, default.stderr)
        self.assertEqual(included.returncode, 0, included.stderr)
        default_payload = json.loads(default.stdout)
        included_payload = json.loads(included.stdout)
        default_tasks = default_payload["tasks"]
        included_tasks = included_payload["tasks"]
        self.assertFalse(any(task["real_project"] for task in default_tasks))
        self.assertTrue(any(task["real_project"] for task in included_tasks))
        self.assertEqual(default_payload["real_project_scope"]["mode"], "not_planned")
        self.assertEqual(included_payload["real_project_scope"]["mode"], "included")
        self.assertEqual(default_payload["release_decision"], "not_evaluated")
        self.assertEqual(included_payload["release_decision"], "not_evaluated")

    def test_cli_distinguishes_explicit_real_project_skip(self):
        import subprocess

        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "quality_gate.py"),
             "--profile", "release", "--skip-real", "--dry-run"],
            cwd=str(ROOT), capture_output=True, text=True,
        )
        payload = json.loads(completed.stdout)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["real_project_scope"]["mode"], "explicitly_skipped")
        self.assertEqual(payload["real_project_status"], "skipped")
        self.assertEqual(payload["release_decision"], "not_evaluated")

    def test_quick_and_release_profiles_require_oracle_independence(self):
        for profile in ("quick", "release"):
            with self.subTest(profile=profile):
                tasks = quality_gate.build_plan(profile, skip_real=True)
                task = next(item for item in tasks if item.name == "oracle_independence")
                self.assertIn("scripts/oracle_independence.py", task.command)
                self.assertIn("tests/fixtures/oracle_boundary.json", task.command)

    def test_release_profile_has_explicit_production_mutation_gate(self):
        tasks = quality_gate.build_plan("release", skip_real=True)
        task = next(item for item in tasks if item.name == "production_mutations")

        self.assertEqual(
            task.command[-1],
            "tests.test_production_mutation.ProductionMutationTest.test_registered_production_mutants_are_all_killed",
        )
        self.assertTrue(task.heavy)

    def test_quick_and_release_profiles_have_explicit_determinism_gates(self):
        quick = quality_gate.build_plan("quick", skip_real=True)
        release = quality_gate.build_plan("release", skip_real=True)

        quick_task = next(item for item in quick if item.name == "determinism_core")
        release_task = next(item for item in release if item.name == "determinism_full")
        self.assertTrue(quick_task.command[-1].endswith("test_generated_core_matrix_is_semantically_identical"))
        self.assertTrue(release_task.command[-1].endswith("test_generated_production_matrix_is_semantically_identical"))

    def test_accuracy_benchmarks_preserve_every_category_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            tasks = quality_gate.build_plan(
                "quick", report_root=tmp, skip_real=True
            )
            task = next(item for item in tasks if item.name == "accuracy_benchmark_core")

            self.assertIn("--continue-on-failure", task.command)
            self.assertIn("--json-out", task.command)
            self.assertEqual(
                task.command[-1], str(Path(tmp) / "accuracy_benchmark_core.json")
            )
            self.assertEqual(task.output_paths, (task.command[-1],))

    def test_quick_smoke_writes_structured_failure_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            tasks = quality_gate.build_plan("quick", report_root=tmp, skip_real=True)
            task = next(item for item in tasks if item.name == "smoke_core")

            self.assertIn("--json-out", task.command)
            self.assertEqual(task.command[-1], str(Path(tmp) / "smoke_core.json"))
            self.assertEqual(task.output_paths, (task.command[-1],))

    def test_release_profile_has_explicit_execution_fault_gate(self):
        tasks = quality_gate.build_plan("release", skip_real=True)
        task = next(item for item in tasks if item.name == "execution_faults")

        self.assertEqual(task.command[-1], "tests.test_execution_faults")

    def test_release_profile_has_generated_complexity_gate(self):
        tasks = quality_gate.build_plan("release", skip_real=True)
        task = next(item for item in tasks if item.name == "generated_complexity")

        self.assertTrue(task.command[-1].endswith("test_real_generated_collector_produces_valid_1x_2x_4x_tiers"))

    def test_release_profile_has_clean_claude_skill_contract(self):
        tasks = quality_gate.build_plan("release", skip_real=True)
        task = next(item for item in tasks if item.name == "claude_skill_contract")

        self.assertEqual(task.command[-1], "tests.test_claude_skill_contract")

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

    def test_step5_explicit_real_matrix_uses_reproducible_guards(self):
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

    def test_unexecuted_audit_cannot_reuse_stale_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit_json = Path(tmp) / "audit.json"
            audit_json.write_text(json.dumps({
                "summary": {"blocking_signals": 0, "by_type": {}},
            }), encoding="utf-8")
            task = quality_gate._quality_signal_audit_task(
                "python3", str(Path(tmp) / "real.json"), str(audit_json)
            )

            summary = quality_gate._read_audit_summary([task], results=[])

        self.assertEqual(summary, {})

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

    def test_release_decision_requires_complete_guard_and_clean_audit(self):
        tasks = quality_gate.build_plan("release", skip_real=False, real_case="guard")
        results = [
            quality_gate.GateResult(task.name, task.command, "passed")
            for task in tasks
        ]
        summary = quality_gate.build_gate_decision_summary(
            "release", tasks, results,
            real_scope_mode="included", real_case="guard",
            audit_summary={
                "blocking_signals": 0,
                "non_blocking_signals": 1,
                "fixture_debt": 0,
                "by_type": {},
            },
        )

        self.assertEqual(summary["local_regression_status"], "passed")
        self.assertEqual(summary["real_project_status"], "passed")
        self.assertEqual(summary["release_decision"], "release_allowed")

    def test_release_decision_blocks_narrow_failed_or_infra_skipped_runs(self):
        tasks = quality_gate.build_plan("release", skip_real=False, real_case="commons-text")
        passed = [quality_gate.GateResult(task.name, task.command, "passed") for task in tasks]

        narrow = quality_gate.build_gate_decision_summary(
            "release", tasks, passed,
            real_scope_mode="included", real_case="commons-text",
            audit_summary={"blocking_signals": 0, "fixture_debt": 0, "by_type": {}},
        )
        infra_skipped = quality_gate.build_gate_decision_summary(
            "release", tasks, passed,
            real_scope_mode="included", real_case="guard",
            audit_summary={
                "blocking_signals": 1,
                "fixture_debt": 0,
                "by_type": {"infra_skip": 1},
            },
        )
        failed = list(passed)
        failed[0] = quality_gate.GateResult(
            tasks[0].name, tasks[0].command, "failed", returncode=1
        )
        local_failed = quality_gate.build_gate_decision_summary(
            "release", tasks, failed,
            real_scope_mode="included", real_case="guard",
            audit_summary={"blocking_signals": 0, "fixture_debt": 0, "by_type": {}},
        )
        real_failed_results = list(passed)
        real_index = next(index for index, task in enumerate(tasks) if task.real_project)
        real_failed_results[real_index] = quality_gate.GateResult(
            tasks[real_index].name, tasks[real_index].command, "failed", returncode=1
        )
        real_failed = quality_gate.build_gate_decision_summary(
            "release", tasks, real_failed_results,
            real_scope_mode="included", real_case="guard",
            audit_summary={"blocking_signals": 0, "fixture_debt": 0, "by_type": {}},
        )

        self.assertEqual(narrow["release_decision"], "release_blocked")
        self.assertEqual(infra_skipped["real_project_status"], "skipped")
        self.assertEqual(infra_skipped["release_decision"], "release_blocked")
        self.assertEqual(local_failed["local_regression_status"], "failed")
        self.assertEqual(local_failed["release_decision"], "release_blocked")
        self.assertEqual(real_failed["real_project_status"], "failed")
        self.assertEqual(real_failed["release_decision"], "release_blocked")

    def test_release_decision_blocks_when_planned_tasks_or_audit_are_missing(self):
        tasks = quality_gate.build_plan("release", skip_real=False, real_case="guard")
        partial_results = [
            quality_gate.GateResult(task.name, task.command, "passed")
            for task in tasks[:-1]
        ]

        summary = quality_gate.build_gate_decision_summary(
            "release", tasks, partial_results,
            real_scope_mode="included", real_case="guard", audit_summary={},
        )

        self.assertEqual(summary["local_regression_status"], "not_evaluated")
        self.assertEqual(summary["release_decision"], "release_blocked")

    def test_successful_non_release_profile_never_allows_release(self):
        tasks = quality_gate.build_plan("quick", skip_real=True)
        results = [quality_gate.GateResult(task.name, task.command, "passed") for task in tasks]

        summary = quality_gate.build_gate_decision_summary(
            "quick", tasks, results,
            real_scope_mode="not_planned", real_case="guard", audit_summary={},
        )

        self.assertEqual(summary["local_regression_status"], "passed")
        self.assertEqual(summary["real_project_status"], "not_evaluated")
        self.assertEqual(summary["release_decision"], "not_evaluated")

    def test_release_cli_fails_when_requested_scope_cannot_allow_release(self):
        def all_pass(tasks, env=None, continue_on_failure=False):
            return ([
                quality_gate.GateResult(task.name, task.command, "passed")
                for task in tasks
            ], "passed")

        clean_audit = {
            "blocking_signals": 0,
            "non_blocking_signals": 0,
            "fixture_debt": 0,
            "by_type": {},
        }
        with patch.object(quality_gate, "_execute_tasks", side_effect=all_pass), \
                patch.object(quality_gate, "_read_audit_summary", return_value=clean_audit), \
                patch.object(quality_gate, "ensure_round_input_files"), \
                patch("builtins.print"):
            narrow_returncode = quality_gate.main([
                "--profile", "release", "--include-real",
                "--real-case", "commons-text",
            ])
            guard_returncode = quality_gate.main([
                "--profile", "release", "--include-real", "--real-case", "guard",
            ])

        self.assertEqual(narrow_returncode, 1)
        self.assertEqual(guard_returncode, 0)


if __name__ == "__main__":
    unittest.main()
