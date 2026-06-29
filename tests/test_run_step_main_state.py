import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import run_step  # noqa: E402


class RunStepMainStateTest(unittest.TestCase):
    def _make_default_args(self, project_dir, report_dir):
        return SimpleNamespace(
            project_dir=str(project_dir),
            report_dir=str(report_dir),
            base_branch=None,
            current_branch=None,
            modules=None,
            source_dirs=None,
            dependency_source_dirs=[],
            dependency_source_mappings=[],
            source_repo_hints=[],
            dependency_repo_mappings=[],
            dependency_git_ref_overrides_json="",
            japicmp_jar="",
            step4_git_diff_timeout=None,
            step4_japicmp_timeout=None,
            step4_fetch_timeout=None,
            step5_timeout=None,
            base_artifact_path="",
            current_artifact_path="",
            base_source_project_dir="",
            current_source_project_dir="",
            base_jdk_home="",
            current_jdk_home="",
            primary_module="",
            manual_coord_overrides=[],
            include_test_scope=False,
            max_depth=None,
            tool="maven",
            allow_degraded=False,
            strict_risk_gate=False,
            allow_unresolved=False,
        )

    def test_auto_step_reads_from_main_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "step4"
            run_step.save_main_state(report_dir, state)

            loaded = run_step.load_main_state(report_dir)
            self.assertEqual(run_step.resolve_requested_step("auto", loaded), "step4")

    def test_user_response_updates_target_step_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["step2"]["input"] = {
                "base_branch": "main",
                "current_branch": "feature/a",
                "source_dirs": [],
            }
            pending = {
                "step_id": "step2",
                "status": "awaiting_user_input",
                "options": [{"id": "continue"}],
            }
            response = {
                "action": "continue",
                "base_branch": "release/1.0",
                "source_dirs": ["src/main/java"],
            }

            updated_state, updated = run_step.apply_user_response_to_main_state(
                state,
                pending,
                response,
                project_dir,
                target_step_id="step2",
            )

            self.assertEqual(updated["base_branch"], "release/1.0")
            self.assertEqual(updated_state["step2"]["input"]["base_branch"], "release/1.0")
            self.assertEqual(
                updated_state["step2"]["input"]["source_dirs"],
                [str((project_dir / "src/main/java").resolve())],
            )

    def test_user_response_primary_module_overrides_stale_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["step1"]["input"] = {
                "base_branch": "base",
                "current_branch": "upgrade",
                "primary_module": "mybatis-example",
                "modules": ["mybatis-example"],
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "source_dirs_status": "explicit",
            }
            pending = {
                "step_id": "step1",
                "status": "awaiting_user_input",
                "options": [{"id": "continue"}],
            }
            response = {
                "action": "continue",
                "primary_module": ".",
            }

            updated_state, updated = run_step.apply_user_response_to_main_state(
                state,
                pending,
                response,
                project_dir,
                target_step_id="step1",
            )

            self.assertEqual(updated["primary_module"], ".")
            self.assertEqual(updated["modules"], ["."])
            self.assertNotIn("source_dirs", updated)
            self.assertEqual(updated_state["step1"]["input"]["primary_module"], ".")
            self.assertEqual(updated_state["step1"]["input"]["modules"], ["."])
            self.assertNotIn("source_dirs", updated_state["step1"]["input"])

    def test_materialize_step5_input_keeps_only_selected_candidate_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            all_changed_path = report_dir / "all_changed_apis.csv"
            risk_candidates_path = report_dir / run_step.STEP3_RISK_CANDIDATES_FILE
            all_changed_path.write_text(
                "\n".join(
                    [
                        "coord,api_name,api_simple,api_signature,symbol_kind,change_type,confirmed,severity,source,analysis_scope",
                        "sample:base,com.lib.Base.call,call,(),method,REMOVED,true,P1,japicmp,api",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            risk_candidates_path.write_text(
                "\n".join(
                    [
                        "coord,api_name,api_simple,api_signature,symbol_kind,change_type,confirmed,severity,source,analysis_scope,candidate_bucket",
                        "sample:base,com.lib.Base,Base,,class,REMOVED,false,P1,candidate_scan,class_usage,system_source",
                        "sample:candidate,com.lib.Candidate,Candidate,,class,REMOVED,false,P1,candidate_scan,class_usage,system_source",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            materialized_path, selection_summary = run_step.materialize_step5_all_changed_apis_input(
                all_changed_path,
                report_dir,
                {"step5_selected_coords": ["sample:candidate"]},
            )

            self.assertEqual(selection_summary["matched_coords"], ["sample:candidate"])
            with materialized_path.open(encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["coord"], "sample:candidate")
            self.assertEqual(rows[0]["source"], "candidate_scan")

    def test_step1_review_continue_propagates_confirmed_branches_to_step2_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            artifact_context = {
                "base_artifact_path": str((project_dir / "base.jar").resolve()),
                "current_artifact_path": str((project_dir / "current.jar").resolve()),
                "artifact_input_mode": True,
            }
            state = run_step.new_main_state(report_dir)
            state["step1"]["input"] = dict(artifact_context)
            state["step1"]["output"] = dict(artifact_context)
            state["step2"]["input"] = dict(artifact_context)
            pending = {
                "step_id": "step1",
                "kind": "review",
                "status": "awaiting_user_input",
                "options": [{"id": "continue"}],
            }

            updated_state, updated = run_step.apply_user_response_to_main_state(
                state,
                pending,
                {
                    "action": "continue",
                    "base_branch": "origin/main",
                    "current_branch": "feature/upgrade",
                },
                project_dir,
                target_step_id="step1",
            )

            self.assertEqual(updated["base_branch"], "origin/main")
            self.assertEqual(updated["current_branch"], "feature/upgrade")
            self.assertEqual(updated_state["step1"]["input"]["base_branch"], "origin/main")
            self.assertEqual(updated_state["step1"]["input"]["current_branch"], "feature/upgrade")
            self.assertEqual(updated_state["step2"]["input"]["base_branch"], "origin/main")
            self.assertEqual(updated_state["step2"]["input"]["current_branch"], "feature/upgrade")
            self.assertEqual(
                updated_state["step2"]["input"]["base_artifact_path"],
                str((project_dir / "base.jar").resolve()),
            )

    def test_apply_structured_user_response_bridges_response_without_pending_interaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "step1"
            state["step1"]["input"] = {
                "base_branch": "base",
                "current_branch": "upgrade",
                "primary_module": "mybatis-example",
                "modules": ["mybatis-example"],
            }
            args = SimpleNamespace(
                step="auto",
                response_json=json.dumps(
                    {
                        "intent_patch": {
                            "action": "continue",
                            "set": {
                                "primary_module": ".",
                                "modules": ["."],
                            },
                        }
                    },
                    ensure_ascii=False,
                ),
                response_file="",
            )
            result = run_step.apply_structured_user_response_if_present(
                args,
                project_dir,
                report_dir,
                state,
                "step1",
            )

            self.assertIsNone(result["early_exit_code"])
            self.assertEqual(result["step_id"], "step1")
            self.assertEqual(state["state"]["current_step"], "step1")
            self.assertEqual(state["step1"]["input"]["primary_module"], ".")
            self.assertEqual(state["step1"]["input"]["modules"], ["."])
            self.assertEqual(state["state"]["last_user_response"]["step_id"], "step1")

    def test_apply_structured_user_response_infers_target_step_when_current_step_done(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "done"
            state["state"]["completed_step"] = "step6"
            state["step5"]["input"] = {
                "base_branch": "main",
                "current_branch": "feature/upgrade",
            }
            args = SimpleNamespace(
                step="auto",
                response_json=json.dumps(
                    {
                        "intent_patch": {
                            "action": "continue",
                            "set": {
                                "step5_selected_coords": ["com.example:demo-lib"],
                            },
                        }
                    },
                    ensure_ascii=False,
                ),
                response_file="",
            )

            result = run_step.apply_structured_user_response_if_present(
                args,
                project_dir,
                report_dir,
                state,
                "",
            )

            self.assertIsNone(result["early_exit_code"])
            self.assertEqual(result["step_id"], "step5")
            self.assertEqual(state["state"]["current_step"], "step5")
            self.assertEqual(
                state["step5"]["input"]["step5_selected_coords"],
                ["com.example:demo-lib"],
            )

    def test_apply_structured_user_response_resolves_selected_targets_without_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            (report_dir / "s4_jar_compare").mkdir(parents=True, exist_ok=True)
            with (report_dir / "s4_jar_compare" / "all_changed_apis.csv").open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=["coord", "class_name", "member"])
                writer.writeheader()
                writer.writerow(
                    {
                        "coord": "com.example:demo-lib",
                        "class_name": "com.example.Demo",
                        "member": "run()",
                    }
                )
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "done"
            args = SimpleNamespace(
                step="auto",
                response_json=json.dumps(
                    {
                        "intent_patch": {
                            "action": "continue",
                            "set": {
                                "selected_targets": ["coord:com.example:demo-lib"],
                            },
                        }
                    },
                    ensure_ascii=False,
                ),
                response_file="",
            )

            result = run_step.apply_structured_user_response_if_present(
                args,
                project_dir,
                report_dir,
                state,
                "",
            )

            self.assertIsNone(result["early_exit_code"])
            self.assertEqual(result["step_id"], "step5")
            self.assertEqual(
                state["step5"]["input"]["step5_selected_coords"],
                ["com.example:demo-lib"],
            )

    def test_apply_structured_user_response_rejects_ambiguous_selected_targets_without_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            (report_dir / "s4_jar_compare").mkdir(parents=True, exist_ok=True)
            with (report_dir / "s4_jar_compare" / "all_changed_apis.csv").open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=["coord", "class_name", "member"])
                writer.writeheader()
                writer.writerow({"coord": "com.example:demo-lib", "class_name": "a.A", "member": "m()"})
                writer.writerow({"coord": "org.example:demo-lib", "class_name": "b.B", "member": "m()"})
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "done"
            args = SimpleNamespace(
                step="auto",
                response_json=json.dumps(
                    {
                        "intent_patch": {
                            "action": "continue",
                            "set": {
                                "selected_targets": ["demo-lib"],
                            },
                        }
                    },
                    ensure_ascii=False,
                ),
                response_file="",
            )

            with self.assertRaisesRegex(run_step.StepError, "selected_targets 存在歧义"):
                run_step.apply_structured_user_response_if_present(
                    args,
                    project_dir,
                    report_dir,
                    state,
                    "",
                )

    def test_build_canonical_user_response_supports_intent_patch(self):
        canonical = run_step.build_canonical_user_response(
            {
                "intent_patch": {
                    "action": "restart_from_step",
                    "set": {
                        "dependency_source_dirs": ["dep-repo"],
                    },
                    "restart_step_id": "step2",
                    "notes": "修正源码目录后从 step2 重跑",
                }
            }
        )

        self.assertEqual(canonical["action"], "restart_from_step")
        self.assertEqual(canonical["dependency_source_dirs"], ["dep-repo"])
        self.assertEqual(canonical["restart_step_id"], "step2")
        self.assertEqual(canonical["notes"], "修正源码目录后从 step2 重跑")
        self.assertIn("__intent_patch", canonical)

    def test_build_canonical_user_response_rejects_unresolved_slots(self):
        with self.assertRaises(run_step.StepError):
            run_step.build_canonical_user_response(
                {
                    "intent_patch": {
                        "action": "continue",
                        "unresolved_slots": ["dependency_source_dirs"],
                    }
                }
            )

    def test_intent_patch_clear_removes_dependency_source_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "step2"
            pending = {
                "step_id": "step2",
                "status": "awaiting_user_input",
                "options": [{"id": "continue"}],
            }
            state["step2"]["input"] = {
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "dependency_source_dirs": [str((project_dir / "dep-repo").resolve())],
                "dependency_repo_mappings": [f"com.example:demo={str((project_dir / 'dep-repo').resolve())}"],
            }

            updated_state, updated = run_step.apply_user_response_to_main_state(
                state,
                pending,
                {
                    "intent_patch": {
                        "action": "continue",
                        "clear": ["dependency_source_dirs"],
                    }
                },
                project_dir,
                target_step_id="step2",
            )

            self.assertNotIn("dependency_source_dirs", updated)
            self.assertNotIn("dependency_repo_mappings", updated)
            self.assertNotIn("dependency_source_dirs", updated_state["step2"]["input"])

    def test_step2_continue_with_clear_rebuilds_outputs_before_advancing(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            dep_repo = project_dir / "dep-repo"
            dep_repo.mkdir()
            state = run_step.new_main_state(report_dir)
            stale_context = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str(source_dir.resolve())],
                "source_dirs_status": "explicit",
                "dependency_source_dirs": [str(dep_repo.resolve())],
                "dependency_repo_mappings": [f"com.example:demo={str(dep_repo.resolve())}"],
                "dependency_source_mappings": [f"com.example:demo={str(dep_repo.resolve())}"],
            }
            state["step2"]["input"] = dict(stale_context)
            state["step2"]["output"] = dict(stale_context)
            state["step3"]["input"] = dict(stale_context)
            pending = {
                "step_id": "step2",
                "status": "awaiting_user_input",
                "options": [{"id": "continue"}],
            }
            user_response = run_step.build_canonical_user_response(
                {
                    "intent_patch": {
                        "action": "continue",
                        "clear": ["dependency_source_dirs"],
                    }
                }
            )

            updated_state, _updated = run_step.apply_user_response_to_main_state(
                state,
                pending,
                user_response,
                project_dir,
                target_step_id="step2",
            )

            refreshed_context = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str(source_dir.resolve())],
                "source_dirs_status": "explicit",
                "dependency_source_dirs": [],
                "dependency_repo_mappings": [],
                "dependency_source_mappings": [],
                "report_dir": str(report_dir.resolve()),
            }
            args = self._make_default_args(project_dir, report_dir)

            with patch.object(run_step, "build_run_context", return_value=refreshed_context), patch.object(
                run_step, "refresh_step2_outputs"
            ) as refresh_mock:
                run_step.handle_step2_resume_followups(
                    args,
                    updated_state,
                    report_dir,
                    project_dir,
                    "step2",
                    "continue",
                    user_response,
                )

            refresh_mock.assert_called_once_with(report_dir, project_dir, refreshed_context)
            self.assertEqual(updated_state["step2"]["input"]["dependency_source_dirs"], [])
            self.assertEqual(updated_state["step2"]["output"]["dependency_source_dirs"], [])
            self.assertEqual(updated_state["step2"]["output"]["dependency_repo_mappings"], [])
            self.assertEqual(updated_state["step3"]["input"]["dependency_source_dirs"], [])
            self.assertEqual(updated_state["step3"]["input"]["dependency_repo_mappings"], [])

    def test_apply_user_response_prefers_current_input_over_current_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            fresh_source_dir = project_dir / "module-a" / "src" / "main" / "java"
            fresh_source_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["step2"]["output"] = {
                "base_branch": "stale-base",
                "current_branch": "stale-current",
                "source_dirs": ["/tmp/stale-src"],
            }
            state["step2"]["input"] = {
                "base_branch": "fresh-base",
                "current_branch": "fresh-current",
                "source_dirs": [str(fresh_source_dir.resolve())],
            }
            pending = {
                "step_id": "step2",
                "kind": "review",
                "status": "awaiting_user_input",
                "options": [{"id": "continue"}],
            }

            updated_state, updated = run_step.apply_user_response_to_main_state(
                state,
                pending,
                {"action": "continue"},
                project_dir,
                target_step_id="step2",
            )

            self.assertEqual(updated["base_branch"], "fresh-base")
            self.assertEqual(updated["current_branch"], "fresh-current")
            self.assertEqual(updated["source_dirs"], [str(fresh_source_dir.resolve())])
            self.assertEqual(updated_state["step2"]["input"]["base_branch"], "fresh-base")
            self.assertEqual(updated_state["step3"]["input"]["base_branch"], "fresh-base")

    def test_annotate_dependency_source_dirs_interaction_marks_existing_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            dep_repo = project_dir / "dep-repo"
            module_dir = dep_repo / "demo-lib"
            (module_dir / "src/main/java").mkdir(parents=True)
            (dep_repo / ".git").mkdir()
            (module_dir / "pom.xml").write_text(
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>com.example</groupId><artifactId>demo-lib</artifactId><version>1.0.0</version>"
                "</project>",
                encoding="utf-8",
            )
            interaction = {
                "step_id": "step4",
                "reason_code": "step4_git_refs_need_confirmation",
                "question": "请确认 git refs 后重跑 Step4。",
                "response_schema": {
                    "type": "object",
                    "required": ["action"],
                    "properties": {
                        "action": {"type": "string"},
                        "dependency_source_dirs": {"type": "array"},
                    },
                },
            }

            annotated = run_step.annotate_dependency_source_dirs_interaction(
                interaction,
                {"dependency_source_dirs": [str(dep_repo.resolve())]},
                project_dir / ".upgrade-report",
            )

            self.assertTrue(annotated["dependency_source_dirs_state"]["provided"])
            self.assertIn("已收到 dependency_source_dirs", annotated["question"])
            self.assertIn("仅当现有目录不正确", annotated["response_schema"]["properties"]["dependency_source_dirs"]["description"])

    def test_validate_pending_interaction_response_rejects_empty_step5_rerun(self):
        interaction = {
            "step_id": "step5",
            "reason_code": "step5_dependency_source_mapping_missing",
            "response_schema": {
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "dependency_source_dirs": {"type": "array"},
                    "allow_degraded": {"type": "boolean"},
                },
            },
        }

        with self.assertRaisesRegex(run_step.StepError, "dependency_source_dirs"):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "rerun_current_step"},
            )

    def test_validate_pending_interaction_response_accepts_step5_rerun_with_dependency_source_dirs(self):
        interaction = {
            "step_id": "step5",
            "reason_code": "step5_dependency_source_mapping_missing",
            "response_schema": {
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "dependency_source_dirs": {"type": "array"},
                    "allow_degraded": {"type": "boolean"},
                },
            },
        }

        run_step.validate_pending_interaction_response(
            interaction,
            {
                "action": "rerun_current_step",
                "dependency_source_dirs": ["/tmp/dep-repo"],
            },
        )

    def test_validate_pending_interaction_response_accepts_step5_rerun_with_allow_degraded(self):
        interaction = {
            "step_id": "step5",
            "reason_code": "step5_dependency_source_mapping_missing",
            "response_schema": {
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "dependency_source_dirs": {"type": "array"},
                    "allow_degraded": {"type": "boolean"},
                },
            },
        }

        run_step.validate_pending_interaction_response(
            interaction,
            {
                "action": "rerun_current_step",
                "allow_degraded": True,
            },
        )

    def test_build_resume_command_examples_uses_intent_patch_payload(self):
        examples = run_step.build_resume_command_examples(
            [{"id": "restart_from_step", "label": "从指定步骤重跑"}],
            [],
            {
                "action": {"type": "string"},
                "dependency_source_dirs": {"type": "array"},
                "restart_step_id": {"type": "string"},
                "notes": {"type": "string"},
            },
            Path("/tmp/project"),
            Path("/tmp/project/.upgrade-report"),
        )

        restart_example = examples[0]
        self.assertIn('"intent_patch"', restart_example["command"])
        self.assertIn('"action": "restart_from_step"', restart_example["command"])
        self.assertIn('"restart_step_id": "<step1|step2|step3|step4|step5>"', restart_example["command"])

    def test_build_input_normalization_contract_uses_intent_patch_examples(self):
        contract = run_step.build_input_normalization_contract(
            [{"id": "continue", "label": "继续", "description": "继续执行"}],
            ["base_branch"],
            {
                "action": {"type": "string"},
                "base_branch": {"type": "string"},
                "notes": {"type": "string"},
            },
        )

        example = contract["action_examples"][0]["normalized_response_example"]
        self.assertIn("intent_patch", example)
        self.assertEqual(example["intent_patch"]["action"], "continue")
        self.assertEqual(example["intent_patch"]["set"]["base_branch"], "origin/main")

    def test_apply_interaction_protocol_enhancements_defaults_continue_requirements(self):
        interaction = run_step.apply_interaction_protocol_enhancements(
            {
                "step_id": "step1",
                "options": [
                    {"id": "continue", "label": "继续"},
                    {"id": "cancel", "label": "取消"},
                ],
                "required_fields": ["base_branch", "current_branch"],
                "response_schema": {
                    "type": "object",
                    "required": ["action"],
                    "properties": {
                        "action": {"type": "string"},
                        "base_branch": {"type": "string"},
                        "current_branch": {"type": "string"},
                    },
                },
                "input_normalization": {"enabled": True},
            },
            "step1",
        )

        self.assertEqual(
            interaction["action_requirements"]["continue"]["required_fields"],
            ["base_branch", "current_branch"],
        )

    def test_validate_pending_interaction_response_enforces_action_requirements(self):
        interaction = {
            "step_id": "step4",
            "response_schema": {
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "dependency_source_dirs": {"type": "array"},
                    "dependency_git_ref_overrides": {"type": "array"},
                },
            },
            "action_requirements": {
                "rerun_current_step": {
                    "at_least_one_of": ["dependency_source_dirs", "dependency_git_ref_overrides"],
                }
            },
        }

        with self.assertRaisesRegex(run_step.StepError, "至少需要提供以下字段之一"):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "rerun_current_step"},
            )

    def test_validate_pending_interaction_response_rejects_ambiguous_selected_targets(self):
        selection_options = run_step.build_interaction_selection_options(
            [
                {"coord": "com.example:demo-lib", "name": "demo-lib"},
                {"coord": "org.example:demo-lib", "name": "demo-lib"},
            ]
        )
        interaction = run_step.apply_interaction_protocol_enhancements(
            {
                "step_id": "step4",
                "options": [{"id": "continue", "label": "继续"}],
                "response_schema": {
                    "type": "object",
                    "required": ["action"],
                    "properties": {
                        "action": {"type": "string"},
                    },
                },
                "selection_options": selection_options,
                "input_normalization": {"enabled": True},
            },
            "step4",
        )

        with self.assertRaisesRegex(run_step.StepError, "selected_targets 存在歧义"):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "continue", "selected_targets": ["demo-lib"]},
            )

    def test_build_run_context_keeps_dependency_source_mappings(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            expected_mapping = f"com.example:demo={str((project_dir / 'src/dependency/java').resolve())}"
            args = SimpleNamespace(
                project_dir=str(project_dir),
                report_dir=str(report_dir),
                base_branch=None,
                current_branch=None,
                modules=None,
                source_dirs=None,
                dependency_source_dirs=[],
                dependency_source_mappings=["com.example:demo=src/dependency/java"],
                source_repo_hints=[],
                dependency_repo_mappings=[],
                dependency_git_ref_overrides_json="",
                japicmp_jar="",
                step4_git_diff_timeout=None,
                step4_japicmp_timeout=None,
                step4_fetch_timeout=None,
                step5_timeout=None,
                base_artifact_path="",
                current_artifact_path="",
                base_source_project_dir="",
                current_source_project_dir="",
                base_jdk_home="",
                current_jdk_home="",
                primary_module="",
                manual_coord_overrides=[],
                include_test_scope=False,
                max_depth=None,
                tool="maven",
                allow_degraded=False,
                strict_risk_gate=False,
            )

            run_context = run_step.build_run_context(args, {}, {})

        self.assertEqual(run_context["dependency_source_mappings"], [expected_mapping])

    def test_build_run_context_does_not_collapse_dependency_source_mapping_to_repo_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            source_dir = project_dir / "dependency-sources" / "demo" / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            (project_dir / ".git").mkdir()
            args = SimpleNamespace(
                project_dir=str(project_dir),
                report_dir=str(report_dir),
                base_branch=None,
                current_branch=None,
                modules=None,
                source_dirs=None,
                dependency_source_dirs=[],
                dependency_source_mappings=[f"com.example:demo={source_dir}"],
                source_repo_hints=[],
                dependency_repo_mappings=[],
                dependency_git_ref_overrides_json="",
                japicmp_jar="",
                step4_git_diff_timeout=None,
                step4_japicmp_timeout=None,
                step4_fetch_timeout=None,
                step5_timeout=None,
                base_artifact_path="",
                current_artifact_path="",
                base_source_project_dir="",
                current_source_project_dir="",
                base_jdk_home="",
                current_jdk_home="",
                primary_module="",
                manual_coord_overrides=[],
                include_test_scope=False,
                max_depth=None,
                tool="maven",
                allow_degraded=False,
                strict_risk_gate=False,
            )

            run_context = run_step.build_run_context(args, {}, {})

        self.assertEqual(
            run_context["dependency_source_mappings"],
            [f"com.example:demo={source_dir.resolve()}"],
        )

    def test_build_step_input_context_prefers_current_input_over_previous_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["step1"]["output"] = {
                "source_dirs": ["from-step1"],
                "dependency_source_dirs": [],
            }
            state["step2"]["input"] = {
                "dependency_source_dirs": ["/tmp/dep-repo"],
            }

            context = run_step.build_step_input_context(state, "step2")

            self.assertEqual(context["source_dirs"], ["from-step1"])
            self.assertEqual(context["dependency_source_dirs"], ["/tmp/dep-repo"])

    def test_build_run_context_does_not_guess_workspace_branches(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            args = SimpleNamespace(
                project_dir=str(project_dir),
                report_dir=str(report_dir),
                base_branch=None,
                current_branch=None,
                modules=None,
                source_dirs=None,
                dependency_source_dirs=[],
                dependency_source_mappings=[],
                source_repo_hints=[],
                dependency_repo_mappings=[],
                dependency_git_ref_overrides_json="",
                japicmp_jar="",
                step4_git_diff_timeout=None,
                step4_japicmp_timeout=None,
                step4_fetch_timeout=None,
                step5_timeout=None,
                base_artifact_path="",
                current_artifact_path="",
                base_source_project_dir="",
                current_source_project_dir="",
                base_jdk_home="",
                current_jdk_home="",
                primary_module="",
                manual_coord_overrides=[],
                include_test_scope=False,
                max_depth=None,
                tool="maven",
                allow_degraded=False,
                strict_risk_gate=False,
            )

            run_context = run_step.build_run_context(args, {}, {})

        self.assertEqual(run_context["base_branch"], "")
        self.assertEqual(run_context["current_branch"], "")

    def test_step1_preflight_triggers_when_entry_mode_is_still_unknown(self):
        interaction = run_step.build_step1_preflight_interaction({})

        self.assertIsNotNone(interaction)
        self.assertEqual(interaction["reason_code"], "missing_step1_entry_inputs")
        self.assertEqual(interaction["kind"], "input_request")

    def test_review_interaction_continue_advances_to_next_step(self):
        interaction = {
            "kind": "review",
            "options": [{"id": "continue"}, {"id": "cancel"}],
        }

        self.assertEqual(run_step.current_step_for_pending_interaction("step2", interaction), "step3")

    def test_input_request_interaction_stays_on_current_step(self):
        interaction = {
            "kind": "input_request",
            "options": [{"id": "continue"}, {"id": "cancel"}],
        }

        self.assertEqual(run_step.current_step_for_pending_interaction("step1", interaction), "step1")

    def test_clear_steps_from_preserves_restart_target_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["step2"]["input"] = {
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "dependency_source_dirs": [],
            }
            state["step4"]["output"] = {"dependency_source_dirs": []}
            pending = {
                "step_id": "step5",
                "status": "awaiting_user_input",
                "options": [{"id": "restart_from_step"}],
            }
            response = {
                "action": "restart_from_step",
                "restart_step_id": "step2",
                "dependency_source_dirs": ["dep-repo"],
            }

            updated_state, _updated = run_step.apply_user_response_to_main_state(
                state,
                pending,
                response,
                project_dir,
                target_step_id="step2",
            )
            preserved_input = dict(updated_state["step2"]["input"])
            run_step.clear_steps_from(
                updated_state,
                "step2",
                preserve_current_input=preserved_input,
            )

            self.assertEqual(
                updated_state["step2"]["input"]["dependency_source_dirs"],
                [str((project_dir / "dep-repo").resolve())],
            )
            self.assertEqual(updated_state["step3"]["input"], {})
            self.assertEqual(updated_state["step4"]["output"], {})

    def test_restart_from_step_reuses_pending_step_branch_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["step2"]["input"] = {
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
            }
            state["step4"]["output"] = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "dependency_repo_mappings": [f"com.example:demo={str((project_dir / 'dep-repo').resolve())}"],
            }
            pending = {
                "step_id": "step4",
                "status": "awaiting_user_input",
                "options": [{"id": "restart_from_step"}],
            }
            response = {
                "action": "restart_from_step",
                "restart_step_id": "step2",
                "notes": "从 step2 重新开始",
            }

            updated_state, updated = run_step.apply_user_response_to_main_state(
                state,
                pending,
                response,
                project_dir,
                target_step_id="step2",
            )

            self.assertEqual(updated["base_branch"], "base")
            self.assertEqual(updated["current_branch"], "current")
            self.assertEqual(updated_state["step2"]["input"]["base_branch"], "base")
            self.assertEqual(updated_state["step2"]["input"]["current_branch"], "current")

    def test_restart_from_step_prefers_pending_checkpoint_context_over_stale_target_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            fresh_dep_repo = project_dir / "dep-repo-new"
            fresh_dep_repo.mkdir()
            state = run_step.new_main_state(report_dir)
            state["step2"]["input"] = {
                "base_branch": "stale-base",
                "current_branch": "stale-current",
                "dependency_source_dirs": [str((project_dir / "dep-repo-old").resolve())],
            }
            state["step4"]["output"] = {
                "base_branch": "fresh-base",
                "current_branch": "fresh-current",
                "dependency_source_dirs": [str(fresh_dep_repo.resolve())],
            }
            pending = {
                "step_id": "step4",
                "kind": "review",
                "status": "awaiting_user_input",
                "options": [{"id": "restart_from_step"}],
            }

            updated_state, updated = run_step.apply_user_response_to_main_state(
                state,
                pending,
                {
                    "action": "restart_from_step",
                    "restart_step_id": "step2",
                },
                project_dir,
                target_step_id="step2",
            )

            self.assertEqual(updated["base_branch"], "fresh-base")
            self.assertEqual(updated["current_branch"], "fresh-current")
            self.assertEqual(
                updated["dependency_source_dirs"],
                [str(fresh_dep_repo.resolve())],
            )
            self.assertEqual(updated_state["step2"]["input"]["base_branch"], "fresh-base")
            self.assertEqual(updated_state["step2"]["input"]["current_branch"], "fresh-current")

    def test_execute_step1_does_not_pass_business_inputs_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "base_branch": "main",
                "current_branch": "feature/demo",
                "primary_module": "app",
                "modules": ["app"],
                "manual_coord_overrides": ["demo:1.0.0 -> com.example:demo"],
            }
            manifest_steps = {"step1": {"gate": "step1_scope"}}
            captured = {}

            def fake_run_python(script_name, script_args, _cwd, **_kwargs):
                captured["script_name"] = script_name
                captured["script_args"] = list(script_args)

            with patch.object(run_step, "validate_run_context_for_step"), \
                 patch.object(run_step, "ensure_exists"), \
                 patch.object(run_step, "run_python", side_effect=fake_run_python), \
                 patch.object(run_step, "run_gate"), \
                 patch.object(run_step, "build_interaction_payload", return_value={}), \
                 patch.object(run_step, "build_run_context", return_value=run_context):
                run_step.execute_step("step1", args, manifest_steps, run_context)

        self.assertEqual(captured["script_name"], "s1_dep_diff.py")
        self.assertNotIn("--base", captured["script_args"])
        self.assertNotIn("--current", captured["script_args"])
        self.assertNotIn("--primary-module", captured["script_args"])
        self.assertNotIn("--modules", captured["script_args"])
        self.assertNotIn("--manual-coord-override", captured["script_args"])

    def test_execute_step2_does_not_pass_business_inputs_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "base_branch": "main",
                "current_branch": "feature/demo",
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "source_dirs_status": "provided",
            }
            manifest_steps = {"step2": {"gate": "context"}}
            captured = {}

            def fake_run_python(script_name, script_args, _cwd, **_kwargs):
                captured["script_name"] = script_name
                captured["script_args"] = list(script_args)

            with patch.object(run_step, "ensure_exists"), \
                 patch.object(run_step, "run_python", side_effect=fake_run_python), \
                 patch.object(run_step, "run_gate"), \
                 patch.object(run_step, "build_interaction_payload", return_value={}), \
                 patch.object(run_step, "build_run_context", return_value=run_context):
                run_step.execute_step("step2", args, manifest_steps, run_context)

        self.assertEqual(captured["script_name"], "s2_context_from_deps.py")
        self.assertNotIn("--base", captured["script_args"])
        self.assertNotIn("--current", captured["script_args"])
        self.assertNotIn("--source-dirs", captured["script_args"])

    def test_execute_step2_missing_branches_error_points_to_main_state_and_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "base_branch": "",
                "current_branch": "",
                "artifact_input_mode": False,
            }
            manifest_steps = {"step2": {"gate": "context"}}

            with patch.object(run_step, "ensure_exists"):
                with self.assertRaisesRegex(
                    run_step.StepError,
                    "main_state.json.*step2.input / step1.output.*--response-json / --response-file",
                ):
                    run_step.execute_step("step2", args, manifest_steps, run_context)

    def test_execute_step2_same_branch_error_no_longer_points_to_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "base_branch": "main",
                "current_branch": "main",
                "artifact_input_mode": False,
            }
            manifest_steps = {"step2": {"gate": "context"}}

            with patch.object(run_step, "ensure_exists"), patch.object(run_step, "is_git_repo", return_value=True):
                with self.assertRaisesRegex(
                    run_step.StepError,
                    "checkpoint 或修正 main_state.json.*两个不同分支",
                ):
                    run_step.execute_step("step2", args, manifest_steps, run_context)

    def test_refresh_step2_outputs_does_not_pass_business_inputs_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            (report_dir / "s1_dep_changes.csv").write_text("coord\n", encoding="utf-8")
            run_context = {
                "base_branch": "main",
                "current_branch": "feature/demo",
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
            }
            captured = {}

            def fake_run_python(script_name, script_args, _cwd, **_kwargs):
                captured["script_name"] = script_name
                captured["script_args"] = list(script_args)

            with patch.object(run_step, "run_python", side_effect=fake_run_python):
                run_step.refresh_step2_outputs(report_dir, project_dir, run_context)

        self.assertEqual(captured["script_name"], "s2_context_from_deps.py")
        self.assertNotIn("--base", captured["script_args"])
        self.assertNotIn("--current", captured["script_args"])
        self.assertNotIn("--source-dirs", captured["script_args"])

    def test_execute_step3_does_not_pass_business_inputs_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            (report_dir / "s2_context.json").write_text("{}", encoding="utf-8")
            (report_dir / "s1_deps_current_resolved.csv").write_text("coord\n", encoding="utf-8")
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "source_dirs_status": "provided",
                "include_test_scope": True,
            }
            manifest_steps = {"step3": {"gate": "scan"}}
            captured = {}

            def fake_run_python(script_name, script_args, _cwd, **_kwargs):
                captured["script_name"] = script_name
                captured["script_args"] = list(script_args)

            with patch.object(run_step, "validate_run_context_for_step"), \
                 patch.object(run_step, "ensure_exists"), \
                 patch.object(run_step, "run_python", side_effect=fake_run_python), \
                 patch.object(run_step, "run_gate"), \
                 patch.object(run_step, "build_interaction_payload", return_value={}), \
                 patch.object(run_step, "build_run_context", return_value=run_context):
                run_step.execute_step("step3", args, manifest_steps, run_context)

        self.assertEqual(captured["script_name"], "s3_scan.py")
        self.assertNotIn("--source-dirs", captured["script_args"])
        self.assertNotIn("--include-test-scope", captured["script_args"])
        self.assertNotIn("--jdk-upgraded", captured["script_args"])
        self.assertNotIn("--sb-major-upgrade", captured["script_args"])
        self.assertNotIn("--target-jdk", captured["script_args"])

    def test_execute_step4_does_not_pass_business_inputs_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            (project_dir / "src" / "main" / "java").mkdir(parents=True)
            dep_repo = project_dir / "demo-lib-repo"
            (dep_repo / "src" / "main" / "java").mkdir(parents=True)
            (dep_repo / "pom.xml").write_text(
                (
                    "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
                    "<modelVersion>4.0.0</modelVersion>"
                    "<groupId>com.example</groupId>"
                    "<artifactId>demo-lib</artifactId>"
                    "<version>1.0.0</version>"
                    "</project>"
                ),
                encoding="utf-8",
            )
            (report_dir / "s1_dep_changes.csv").write_text(
                "coord,change_type,resolution_status,old_version,new_version\n"
                "com.example:demo-lib,升级,resolved,1.0.0,2.0.0\n",
                encoding="utf-8",
            )
            (report_dir / "s2_context.json").write_text(
                "{\"changed_dependencies\":[{\"coord\":\"com.example:demo-lib\"}]}",
                encoding="utf-8",
            )
            args = self._make_default_args(project_dir, report_dir)
            run_context = run_step.build_run_context(
                args,
                {},
                {"dependency_repo_mappings": [str(dep_repo)]},
            )
            manifest_steps = {"step4": {"gate": "binary_diff"}}
            captured = {}

            def fake_run_python(script_name, script_args, _cwd, **_kwargs):
                captured["script_name"] = script_name
                captured["script_args"] = list(script_args)

            with patch.object(run_step, "validate_run_context_for_step"), \
                 patch.object(run_step, "ensure_exists"), \
                 patch.object(run_step, "run_python", side_effect=fake_run_python), \
                 patch.object(run_step, "run_gate"), \
                 patch.object(run_step, "build_interaction_payload", return_value={}):
                run_step.execute_step("step4", args, manifest_steps, run_context)

        self.assertEqual(captured["script_name"], "s4_jar_compare.py")
        self.assertNotIn("--dependency-repo-mappings", captured["script_args"])
        self.assertNotIn("--source-branches", captured["script_args"])
        self.assertNotIn("--allow-degraded", captured["script_args"])

    def test_build_run_context_accepts_step5_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            args = self._make_default_args(project_dir, report_dir)

            run_context = run_step.build_run_context(args, {"step5_timeout": "900"}, {})

        self.assertEqual(run_context["step5_timeout"], 900)

    def test_run_python_has_no_default_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            captured = {}

            def fake_run_cmd(cmd, cwd=None, timeout=None, _input_text=None, env=None):
                captured["cmd"] = list(cmd)
                captured["cwd"] = cwd
                captured["timeout"] = timeout
                captured["env"] = dict(env or {})
                return "", "", 0

            with patch.object(run_step, "run_cmd", side_effect=fake_run_cmd):
                run_step.run_python("s3_scan.py", ["--all"], tmp, report_dir=tmp)

        self.assertIsNone(captured["timeout"])
        self.assertEqual(captured["cwd"], tmp)

    def test_handle_step4_resume_followups_seeds_step5_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["step4"]["input"] = {
                "step5_selected_coords": ["com.example:demo"],
                "step5_selected_names": ["core-lib"],
            }
            state["step5"]["input"] = {"source_dirs": ["/tmp/src"]}

            run_step.handle_step4_resume_followups(
                state,
                report_dir,
                "step4",
                "continue",
            )

            self.assertEqual(state["step5"]["input"]["step5_selected_coords"], ["com.example:demo"])
            self.assertEqual(state["step5"]["input"]["step5_selected_names"], ["core-lib"])

    def test_handle_step4_resume_followups_clears_stale_step5_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["step4"]["input"] = {}
            state["step5"]["input"] = {
                "step5_selected_coords": ["com.example:stale"],
                "step5_selected_names": ["stale-lib"],
            }

            run_step.handle_step4_resume_followups(
                state,
                report_dir,
                "step4",
                "continue",
            )

            self.assertNotIn("step5_selected_coords", state["step5"]["input"])
            self.assertNotIn("step5_selected_names", state["step5"]["input"])

    def test_build_interaction_payload_step4_exposes_step5_target_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            s4_dir = report_dir / "s4_jar_compare"
            s4_dir.mkdir(parents=True)
            with open(s4_dir / "all_changed_apis.csv", "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=run_step.ALL_CHANGED_APIS_FIELDS)
                writer.writeheader()
                writer.writerow(
                    {
                        "coord": "com.example:demo-lib",
                        "old_version": "1.0.0",
                        "new_version": "2.0.0",
                        "change_type": "REMOVED",
                        "api_name": "com.example.Demo.call",
                        "api_simple": "call",
                        "symbol_kind": "method",
                        "api_signature": "()",
                        "confirmed": "true",
                        "severity": "P0",
                        "source": "japicmp",
                    }
                )
            manifest_steps = {
                "step4": {
                    "title": "jar 包变更对比",
                    "interaction": {
                        "type": "review",
                        "question": "请确认",
                        "options": [{"id": "continue", "label": "继续", "description": "继续"}],
                    },
                    "outputs": ["s4_jar_compare/all_changed_apis.csv"],
                }
            }

            payload = run_step.build_interaction_payload(
                "step4",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={},
                main_state=run_step.new_main_state(report_dir),
            )

            properties = payload["response_schema"]["properties"]
            self.assertIn("step5_selected_coords", properties)
            self.assertIn("step5_selected_names", properties)
            self.assertIn("selected_targets", properties)
            self.assertTrue(payload["selection_resolution"]["enabled"])
            self.assertEqual(payload["selection_options"][0]["coord"], "com.example:demo-lib")
            self.assertEqual(payload["selection_options"][0]["name"], "demo-lib")
            self.assertEqual(payload["selection_options"][0]["selection_key"], "coord:com.example:demo-lib")

    def test_apply_user_response_to_main_state_resolves_selected_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            pending_interaction = run_step.apply_interaction_protocol_enhancements(
                {
                    "step_id": "step4",
                    "kind": "review",
                    "options": [{"id": "continue", "label": "继续"}],
                    "response_schema": {
                        "type": "object",
                        "required": ["action"],
                        "properties": {
                            "action": {"type": "string"},
                            "selected_targets": {"type": "array"},
                        },
                    },
                    "selection_options": [
                        {"coord": "com.example:demo-lib", "name": "demo-lib"},
                    ],
                    "input_normalization": {"enabled": True},
                },
                "step4",
                project_dir=project_dir,
                report_dir=report_dir,
            )

            updated_state, _ = run_step.apply_user_response_to_main_state(
                state,
                pending_interaction,
                {
                    "intent_patch": {
                        "action": "continue",
                        "set": {"selected_targets": ["coord:com.example:demo-lib"]},
                    }
                },
                project_dir,
                target_step_id="step4",
            )
            run_step.handle_step4_resume_followups(
                updated_state,
                report_dir,
                "step4",
                "continue",
            )

        self.assertEqual(
            updated_state["step4"]["input"]["step5_selected_coords"],
            ["com.example:demo-lib"],
        )
        self.assertEqual(
            updated_state["step5"]["input"]["step5_selected_coords"],
            ["com.example:demo-lib"],
        )

    def test_apply_user_response_to_main_state_accepts_strict_risk_gate_intent_patch(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            pending_interaction = {
                "step_id": "step5",
                "kind": "review",
                "response_schema": {
                    "type": "object",
                    "required": ["action"],
                    "properties": {
                        "action": {"type": "string"},
                        "strict_risk_gate": {"type": "boolean"},
                    },
                },
            }

            updated_state, updated_context = run_step.apply_user_response_to_main_state(
                state,
                pending_interaction,
                {
                    "intent_patch": {
                        "action": "continue",
                        "set": {"strict_risk_gate": True},
                    }
                },
                project_dir,
                target_step_id="step5",
            )

        self.assertTrue(updated_context["strict_risk_gate"])
        self.assertTrue(updated_state["step5"]["input"]["strict_risk_gate"])

    def test_execute_step5_does_not_pass_business_inputs_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            (report_dir / "s4_jar_compare").mkdir(parents=True)
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "source_dirs_status": "provided",
                "dependency_source_mappings": [f"com.example:demo={str((project_dir / 'dep-src').resolve())}"],
                "max_depth": 5,
                "allow_degraded": True,
                "step5_timeout": None,
            }
            manifest_steps = {"step5": {"gate": "call_chain"}}
            captured = {}

            def fake_run_python(script_name, script_args, _cwd, **_kwargs):
                captured["script_name"] = script_name
                captured["script_args"] = list(script_args)

            with patch.object(run_step, "validate_run_context_for_step"), \
                 patch.object(run_step, "ensure_exists"), \
                 patch.object(run_step, "run_python", side_effect=fake_run_python), \
                 patch.object(run_step, "run_gate"), \
                 patch.object(run_step, "build_interaction_payload", return_value={}), \
                 patch.object(run_step, "build_run_context", return_value=run_context):
                run_step.execute_step("step5", args, manifest_steps, run_context)

        self.assertEqual(captured["script_name"], "s5_call_chain_engine_integrated.py")
        self.assertNotIn("--source-dirs", captured["script_args"])
        self.assertNotIn("--dependency-source-mappings", captured["script_args"])
        self.assertNotIn("--max-depth", captured["script_args"])
        self.assertNotIn("--allow-degraded", captured["script_args"])
        self.assertIsNone(captured.get("timeout"))

    def test_execute_step5_filters_all_changed_apis_by_selected_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            s4_dir = report_dir / "s4_jar_compare"
            s4_dir.mkdir(parents=True)
            with open(s4_dir / "all_changed_apis.csv", "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=run_step.ALL_CHANGED_APIS_FIELDS)
                writer.writeheader()
                for row in [
                    {
                        "coord": "com.example:demo-lib",
                        "old_version": "1.0.0",
                        "new_version": "2.0.0",
                        "change_type": "REMOVED",
                        "api_name": "com.example.Demo.call",
                        "api_simple": "call",
                        "symbol_kind": "method",
                        "api_signature": "()",
                        "confirmed": "true",
                        "severity": "P0",
                        "source": "japicmp",
                    },
                    {
                        "coord": "com.example:core-lib",
                        "old_version": "1.0.0",
                        "new_version": "2.0.0",
                        "change_type": "REMOVED",
                        "api_name": "com.example.Core.call",
                        "api_simple": "call",
                        "symbol_kind": "method",
                        "api_signature": "()",
                        "confirmed": "true",
                        "severity": "P0",
                        "source": "japicmp",
                    },
                    {
                        "coord": "com.example:other-lib",
                        "old_version": "1.0.0",
                        "new_version": "2.0.0",
                        "change_type": "REMOVED",
                        "api_name": "com.example.Other.call",
                        "api_simple": "call",
                        "symbol_kind": "method",
                        "api_signature": "()",
                        "confirmed": "true",
                        "severity": "P0",
                        "source": "japicmp",
                    },
                ]:
                    writer.writerow(row)
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "source_dirs_status": "provided",
                "dependency_source_mappings": [],
                "step5_selected_coords": ["com.example:demo-lib"],
                "step5_selected_names": ["core-lib"],
                "step5_timeout": None,
            }
            manifest_steps = {"step5": {"gate": "call_chain"}}
            captured = {}

            def fake_run_python(script_name, script_args, _cwd, **kwargs):
                captured["script_name"] = script_name
                captured["script_args"] = list(script_args)
                captured["timeout"] = kwargs.get("timeout")
                selected_path = Path(script_args[script_args.index("--all-changed-apis") + 1])
                captured["selected_path"] = selected_path
                with open(selected_path, "r", encoding="utf-8", newline="") as f:
                    captured["selected_rows"] = list(csv.DictReader(f))

            with patch.object(run_step, "validate_run_context_for_step"), \
                 patch.object(run_step, "run_python", side_effect=fake_run_python), \
                 patch.object(run_step, "run_gate"), \
                 patch.object(run_step, "build_interaction_payload", return_value={}), \
                 patch.object(run_step, "build_run_context", return_value=run_context):
                run_step.execute_step("step5", args, manifest_steps, run_context)

        self.assertEqual(captured["script_name"], "s5_call_chain_engine_integrated.py")
        self.assertEqual(captured["selected_path"].name, "selected_all_changed_apis.csv")
        self.assertEqual(
            {row["coord"] for row in captured["selected_rows"]},
            {"com.example:demo-lib", "com.example:core-lib"},
        )

    def test_execute_step5_rejects_unmatched_selected_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            s4_dir = report_dir / "s4_jar_compare"
            s4_dir.mkdir(parents=True)
            with open(s4_dir / "all_changed_apis.csv", "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=run_step.ALL_CHANGED_APIS_FIELDS)
                writer.writeheader()
                writer.writerow(
                    {
                        "coord": "com.example:demo-lib",
                        "old_version": "1.0.0",
                        "new_version": "2.0.0",
                        "change_type": "REMOVED",
                        "api_name": "com.example.Demo.call",
                        "api_simple": "call",
                        "symbol_kind": "method",
                        "api_signature": "()",
                        "confirmed": "true",
                        "severity": "P0",
                        "source": "japicmp",
                    }
                )
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "source_dirs_status": "provided",
                "dependency_source_mappings": [],
                "step5_selected_coords": ["com.example:not-found"],
            }
            manifest_steps = {"step5": {"gate": "call_chain"}}

            with patch.object(run_step, "validate_run_context_for_step"), \
                 patch.object(run_step, "run_gate"), \
                 patch.object(run_step, "build_interaction_payload", return_value={}):
                with self.assertRaises(run_step.StepError):
                    run_step.execute_step("step5", args, manifest_steps, run_context)

    def test_execute_step5_passes_timeout_to_run_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            (report_dir / "s4_jar_compare").mkdir(parents=True)
            args = SimpleNamespace(
                project_dir=str(project_dir),
                report_dir=str(report_dir),
                source_dirs=None,
                dependency_source_mappings=[],
                max_depth=None,
                step5_timeout=None,
            )
            run_context = {
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "source_dirs_status": "provided",
                "dependency_source_mappings": [],
                "max_depth": 5,
                "allow_degraded": True,
                "step5_timeout": 900,
            }
            manifest_steps = {"step5": {"gate": "call_chain"}}
            captured = {}

            def fake_run_python(script_name, script_args, _cwd, **kwargs):
                captured["script_name"] = script_name
                captured["script_args"] = list(script_args)
                captured["timeout"] = kwargs.get("timeout")

            with patch.object(run_step, "validate_run_context_for_step"), \
                 patch.object(run_step, "ensure_exists"), \
                 patch.object(run_step, "run_python", side_effect=fake_run_python), \
                 patch.object(run_step, "run_gate"), \
                 patch.object(run_step, "build_interaction_payload", return_value={}), \
                 patch.object(run_step, "build_run_context", return_value=run_context):
                run_step.execute_step("step5", args, manifest_steps, run_context)

        self.assertEqual(captured["script_name"], "s5_call_chain_engine_integrated.py")
        self.assertEqual(captured["timeout"], 900)

    def test_build_run_context_expands_path_only_dependency_repo_mappings(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            dep_repo = project_dir / "demo-lib-repo"
            (dep_repo / "src" / "main" / "java").mkdir(parents=True)
            (dep_repo / "pom.xml").write_text(
                (
                    "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
                    "<modelVersion>4.0.0</modelVersion>"
                    "<groupId>com.example</groupId>"
                    "<artifactId>demo-lib</artifactId>"
                    "<version>1.0.0</version>"
                    "</project>"
                ),
                encoding="utf-8",
            )
            (report_dir / "s1_dep_changes.csv").write_text(
                "coord,change_type,resolution_status,old_version,new_version\n"
                "com.example:demo-lib,升级,resolved,1.0.0,2.0.0\n",
                encoding="utf-8",
            )
            args = self._make_default_args(project_dir, report_dir)

            run_context = run_step.build_run_context(
                args,
                {},
                {"dependency_repo_mappings": [str(dep_repo)]},
            )

        self.assertEqual(
            run_context["dependency_repo_mappings"],
            [f"com.example:demo-lib={dep_repo.resolve()}"],
        )

    def test_build_run_context_expands_group_prefix_dependency_repo_mappings(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            dep_repo = project_dir / "demo-lib-repo"
            (dep_repo / "src" / "main" / "java").mkdir(parents=True)
            (dep_repo / "pom.xml").write_text(
                (
                    "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
                    "<modelVersion>4.0.0</modelVersion>"
                    "<groupId>com.example</groupId>"
                    "<artifactId>demo-lib</artifactId>"
                    "<version>1.0.0</version>"
                    "</project>"
                ),
                encoding="utf-8",
            )
            (report_dir / "s1_dep_changes.csv").write_text(
                "coord,change_type,resolution_status,old_version,new_version\n"
                "com.example:demo-lib,升级,resolved,1.0.0,2.0.0\n",
                encoding="utf-8",
            )
            args = self._make_default_args(project_dir, report_dir)

            run_context = run_step.build_run_context(
                args,
                {},
                {"dependency_repo_mappings": [{"coord": "com.example", "path": str(dep_repo)}]},
            )

        self.assertEqual(
            run_context["dependency_repo_mappings"],
            [f"com.example:demo-lib={dep_repo.resolve()}"],
        )

    def test_main_loads_seed_json_before_building_step4_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True)
            (project_dir / "src" / "main" / "java").mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            dep_repo = project_dir / "demo-lib-repo"
            (dep_repo / "src" / "main" / "java").mkdir(parents=True)
            (dep_repo / "pom.xml").write_text(
                (
                    "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
                    "<modelVersion>4.0.0</modelVersion>"
                    "<groupId>com.example</groupId>"
                    "<artifactId>demo-lib</artifactId>"
                    "<version>1.0.0</version>"
                    "</project>"
                ),
                encoding="utf-8",
            )
            (report_dir / "s1_dep_changes.csv").write_text(
                "coord,change_type,resolution_status,old_version,new_version\n"
                "com.example:demo-lib,升级,resolved,1.0.0,2.0.0\n",
                encoding="utf-8",
            )
            seed_json_path = report_dir / "main_state_seed.json"
            seed_json_path.write_text(
                f"{{\"dependency_repo_mappings\":[\"{dep_repo}\"]}}",
                encoding="utf-8",
            )
            captured = {}

            def fake_execute_step(step_id, _args, _manifest_steps, run_context, **_kwargs):
                captured["step_id"] = step_id
                captured["run_context"] = dict(run_context)
                return None

            with patch.object(
                sys,
                "argv",
                [
                    "run_step.py",
                    "--step",
                    "step4",
                    "--project-dir",
                    str(project_dir),
                    "--report-dir",
                    str(report_dir),
                    "--seed-json",
                    str(seed_json_path),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=({}, {"step4": {"gate": "binary_diff"}}),
            ), patch.object(
                run_step,
                "execute_step",
                side_effect=fake_execute_step,
            ):
                exit_code = run_step.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(captured["step_id"], "step4")
        self.assertEqual(
            captured["run_context"]["dependency_repo_mappings"],
            [f"com.example:demo-lib={dep_repo.resolve()}"],
        )

    def test_build_run_context_prefers_existing_main_state_over_seed_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            args = self._make_default_args(project_dir, report_dir)

            run_context = run_step.build_run_context(
                args,
                {"base_branch": "from-main-state", "current_branch": "feature/a"},
                {"base_branch": "from-runtime-config", "current_branch": "feature/b"},
                allow_external_seed=False,
            )

        self.assertEqual(run_context["base_branch"], "from-main-state")
        self.assertEqual(run_context["current_branch"], "feature/a")

    def test_execute_step4_does_not_pass_git_ref_overrides_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            (report_dir / "s1_dep_changes.csv").write_text(
                "coord,change_type,resolution_status,old_version,new_version\n"
                "com.example:demo-lib,升级,resolved,1.0.0,2.0.0\n",
                encoding="utf-8",
            )
            (report_dir / "s2_context.json").write_text("{}", encoding="utf-8")
            args = self._make_default_args(project_dir, report_dir)
            captured = []

            def fake_run_python(script_name, script_args, *_args, **_kwargs):
                captured.append((script_name, list(script_args)))
                return None

            with patch.object(run_step, "run_python", side_effect=fake_run_python):
                run_step.execute_step(
                    "step4",
                    args,
                    {"step4": {"gate": "jar_compare"}},
                    {
                        "base_branch": "main",
                        "current_branch": "feature/upgrade",
                        "source_dirs": [str(source_dir.resolve())],
                        "source_dirs_status": "provided",
                        "dependency_git_ref_overrides": [
                            {
                                "coord": "com.example:demo-lib",
                                "old_ref": "v1.0.0",
                                "new_ref": "v2.0.0",
                            }
                        ],
                    },
                )

        s4_calls = [item for item in captured if item[0] == "s4_jar_compare.py"]
        self.assertEqual(len(s4_calls), 1)
        _, script_args = s4_calls[0]
        self.assertNotIn("--dependency-git-ref-overrides-json", script_args)

    def test_cleanup_step_outputs_only_removes_current_step_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            step2_context = report_dir / "s2_context.json"
            step2_graph = report_dir / "s2_dep_graph.json"
            step2_summary = report_dir / "s2_source_mapping_summary.json"
            step1_output = report_dir / "s1_dep_changes.csv"
            main_state = report_dir / "main_state.json"
            interaction = report_dir / "interaction.json"
            step2_context.write_text("{}", encoding="utf-8")
            step2_graph.write_text("{}", encoding="utf-8")
            step2_summary.write_text("{}", encoding="utf-8")
            step1_output.write_text("coord", encoding="utf-8")
            main_state.write_text("{}", encoding="utf-8")
            interaction.write_text("{}", encoding="utf-8")

            run_step.cleanup_step_outputs("step2", report_dir)

            self.assertFalse(step2_context.exists())
            self.assertFalse(step2_graph.exists())
            self.assertFalse(step2_summary.exists())
            self.assertTrue(step1_output.exists())
            self.assertTrue(main_state.exists())
            self.assertTrue(interaction.exists())

    def test_cleanup_step_outputs_removes_all_step1_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            step1_alerts = report_dir / "s1_dep_alerts.csv"
            step1_changes = report_dir / "s1_dep_changes.csv"
            step1_summary = report_dir / "s1_dep_summary.txt"
            step1_resolved = report_dir / "s1_deps_current_resolved.csv"
            main_state = report_dir / "main_state.json"
            interaction = report_dir / "interaction.json"
            step1_alerts.write_text("coord\n", encoding="utf-8")
            step1_changes.write_text("coord\n", encoding="utf-8")
            step1_summary.write_text("summary\n", encoding="utf-8")
            step1_resolved.write_text("coord\n", encoding="utf-8")
            main_state.write_text("{}", encoding="utf-8")
            interaction.write_text("{}", encoding="utf-8")

            run_step.cleanup_step_outputs("step1", report_dir)

            self.assertFalse(step1_alerts.exists())
            self.assertFalse(step1_changes.exists())
            self.assertFalse(step1_summary.exists())
            self.assertFalse(step1_resolved.exists())
            self.assertTrue(main_state.exists())
            self.assertTrue(interaction.exists())

    def test_cleanup_step_outputs_step3_removes_bridge_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            risk_candidates = report_dir / run_step.STEP3_RISK_CANDIDATES_FILE
            risk_candidates.write_text("coord\n", encoding="utf-8")
            per_dep_dir = report_dir / "per_dependency" / "sample_demo"
            per_dep_dir.mkdir(parents=True)
            candidate_hits = per_dep_dir / "candidate_hits.csv"
            candidate_hits.write_text("coord\nsample:demo\n", encoding="utf-8")
            summary_path = per_dep_dir / "summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "coord": "sample:demo",
                        "step3": {"candidate_hit_count": 1},
                        "step4": {"target_count": 2},
                        "artifacts": {
                            "candidate_hits_csv": str(candidate_hits),
                            "resolved_targets_csv": "resolved_targets.csv",
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            run_step.cleanup_step_outputs("step3", report_dir)

            self.assertFalse(risk_candidates.exists())
            self.assertFalse(candidate_hits.exists())
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertNotIn("step3", summary)
            self.assertEqual(summary["step4"]["target_count"], 2)
            self.assertNotIn("candidate_hits_csv", summary["artifacts"])

    def test_main_explicit_step_run_resets_current_and_downstream_state_and_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True)
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "done"
            state["state"]["completed_step"] = "step6"
            state["state"]["status"] = "completed"
            state["step2"]["output"] = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str(source_dir.resolve())],
            }
            state["step3"]["input"] = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str(source_dir.resolve())],
            }
            state["step3"]["output"] = {"summary": "stale-step3"}
            state["step4"]["input"] = {"dependency_source_dirs": [str((project_dir / "dep-repo").resolve())]}
            state["step4"]["output"] = {"summary": "stale-step4"}
            state["step5"]["output"] = {"summary": "stale-step5"}
            state["step6"]["output"] = {"report": "stale-step6"}
            run_step.save_main_state(report_dir, state)

            (report_dir / "s1_dep_changes.csv").write_text("coord\n", encoding="utf-8")
            (report_dir / "s3_jdk_removed_api.csv").write_text("symbol\n", encoding="utf-8")
            (report_dir / "s4_jar_compare").mkdir()
            (report_dir / "s4_jar_compare" / "all_changed_apis.csv").write_text("coord\n", encoding="utf-8")
            (report_dir / "s5_call_chain").mkdir()
            (report_dir / "s5_call_chain" / "summary.json").write_text("{}", encoding="utf-8")
            (report_dir / "s6_findings.json").write_text("{}", encoding="utf-8")
            (report_dir / "s6_report.md").write_text("# stale\n", encoding="utf-8")

            captured = {}

            def fake_execute_step(step_id, _args, _manifest_steps, run_context, **_kwargs):
                captured["step_id"] = step_id
                captured["run_context"] = dict(run_context)
                captured["state"] = run_step.load_main_state(report_dir)
                captured["step1_output_exists"] = (report_dir / "s1_dep_changes.csv").exists()
                captured["step3_output_exists"] = (report_dir / "s3_jdk_removed_api.csv").exists()
                captured["step4_output_exists"] = (report_dir / "s4_jar_compare").exists()
                captured["step5_output_exists"] = (report_dir / "s5_call_chain").exists()
                captured["step6_findings_exists"] = (report_dir / "s6_findings.json").exists()
                captured["step6_report_exists"] = (report_dir / "s6_report.md").exists()
                return None

            with patch.object(
                sys,
                "argv",
                [
                    "run_step.py",
                    "--step",
                    "step3",
                    "--project-dir",
                    str(project_dir),
                    "--report-dir",
                    str(report_dir),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=({}, {"step3": {"gate": "context_build"}}),
            ), patch.object(
                run_step,
                "execute_step",
                side_effect=fake_execute_step,
            ):
                exit_code = run_step.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(captured["step_id"], "step3")
        self.assertEqual(captured["run_context"]["base_branch"], "base")
        self.assertEqual(captured["run_context"]["current_branch"], "current")
        self.assertEqual(captured["run_context"]["source_dirs"], [str(source_dir.resolve())])
        self.assertFalse(captured["step3_output_exists"])
        self.assertFalse(captured["step4_output_exists"])
        self.assertFalse(captured["step5_output_exists"])
        self.assertFalse(captured["step6_findings_exists"])
        self.assertFalse(captured["step6_report_exists"])
        self.assertTrue(captured["step1_output_exists"])
        self.assertEqual(captured["state"]["state"]["current_step"], "step3")
        self.assertEqual(captured["state"]["state"]["completed_step"], "step2")
        self.assertEqual(captured["state"]["state"]["status"], "ready")
        self.assertEqual(
            captured["state"]["step3"]["input"]["source_dirs"],
            [str(source_dir.resolve())],
        )
        self.assertEqual(captured["state"]["step3"]["output"], {})
        self.assertEqual(captured["state"]["step4"], run_step.empty_step_state())
        self.assertEqual(captured["state"]["step5"], run_step.empty_step_state())
        self.assertEqual(captured["state"]["step6"], run_step.empty_step_state())
        self.assertEqual(
            captured["state"]["step2"]["output"]["source_dirs"],
            [str(source_dir.resolve())],
        )

    def test_main_marks_step5_as_awaiting_user_when_script_requests_interaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "step5"
            state["state"]["completed_step"] = "step4"
            run_step.save_main_state(report_dir, state)
            interaction = {
                "schema": "java-upgrade-analyzer.interaction.v2",
                "checkpoint": True,
                "hard_stop": True,
                "status": "awaiting_user_input",
                "kind": "review",
                "step_id": "step5",
                "title": "step5 缺少依赖源码映射",
                "question": "请补充 dependency_source_dirs 后重跑 Step5。",
                "reason_code": "step5_dependency_source_mapping_missing",
                "options": [{"id": "rerun_current_step"}],
                "response_schema": {
                    "type": "object",
                    "required": ["action"],
                    "properties": {
                        "action": {"type": "string", "enum": ["rerun_current_step"]},
                        "dependency_source_dirs": {"type": "array"},
                    },
                },
            }

            with patch.object(
                sys,
                "argv",
                [
                    "run_step.py",
                    "--step",
                    "step5",
                    "--project-dir",
                    str(project_dir),
                    "--report-dir",
                    str(report_dir),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=({}, {"step5": {"gate": "call_chain"}}),
            ), patch.object(
                run_step,
                "execute_step",
                side_effect=run_step.StepInteractionRequired(interaction),
            ):
                exit_code = run_step.main()

            saved = run_step.load_main_state(report_dir)
            interaction_exists = (report_dir / "interaction.json").exists()

            self.assertEqual(exit_code, run_step.EXIT_AWAITING_USER)
            self.assertEqual(saved["state"]["status"], "awaiting_user_input")
            self.assertEqual(saved["state"]["current_step"], "step5")
            self.assertEqual(saved["state"]["completed_step"], "step4")
            self.assertEqual(saved["state"]["pending_interaction"]["reason_code"], "step5_dependency_source_mapping_missing")
            self.assertTrue(interaction_exists)

    def test_main_auto_repairs_missing_step4_prereq_by_restarting_step1(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True)
            (project_dir / "src" / "main" / "java").mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "step4"
            state["state"]["completed_step"] = "step3"
            state["step1"]["input"] = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "analysis_mode": "checkout_build",
            }
            state["step2"]["output"] = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
            }
            state["step3"]["output"] = dict(state["step2"]["output"])
            run_step.save_main_state(report_dir, state)
            (report_dir / "s2_context.json").write_text("{}", encoding="utf-8")
            captured = {}

            def fake_execute_step(step_id, _args, _manifest_steps, run_context, **_kwargs):
                captured["step_id"] = step_id
                captured["run_context"] = dict(run_context)
                return None

            with patch.object(
                sys,
                "argv",
                [
                    "run_step.py",
                    "--step",
                    "auto",
                    "--project-dir",
                    str(project_dir),
                    "--report-dir",
                    str(report_dir),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=({}, {"step1": {}, "step4": {}}),
            ), patch.object(
                run_step,
                "execute_step",
                side_effect=fake_execute_step,
            ):
                exit_code = run_step.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(captured["step_id"], "step1")
        self.assertEqual(captured["run_context"]["base_branch"], "base")
        self.assertEqual(captured["run_context"]["current_branch"], "current")

    def test_main_auto_bridges_non_pending_intent_when_current_step_done(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "done"
            state["state"]["completed_step"] = "step6"
            state["step5"]["input"] = {
                "base_branch": "base",
                "current_branch": "current",
            }
            run_step.save_main_state(report_dir, state)
            (report_dir / "s4_jar_compare").mkdir(parents=True, exist_ok=True)
            (report_dir / "s4_jar_compare" / "all_changed_apis.csv").write_text(
                "coord,class_name,member\ncom.example:demo-lib,com.example.Demo,run()\n",
                encoding="utf-8",
            )
            captured = {}

            def fake_execute_step(step_id, _args, _manifest_steps, run_context, **_kwargs):
                captured["step_id"] = step_id
                captured["run_context"] = dict(run_context)
                return None

            with patch.object(
                sys,
                "argv",
                [
                    "run_step.py",
                    "--step",
                    "auto",
                    "--project-dir",
                    str(project_dir),
                    "--report-dir",
                    str(report_dir),
                    "--response-json",
                    json.dumps(
                        {
                            "intent_patch": {
                                "action": "continue",
                                "set": {
                                    "selected_targets": ["coord:com.example:demo-lib"],
                                },
                            }
                        },
                        ensure_ascii=False,
                    ),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=({}, {"step5": {"gate": "call_chain"}}),
            ), patch.object(
                run_step,
                "execute_step",
                side_effect=fake_execute_step,
            ):
                exit_code = run_step.main()

            saved = run_step.load_main_state(report_dir)
            self.assertEqual(exit_code, 0)
            self.assertEqual(captured["step_id"], "step5")
            self.assertEqual(
                captured["run_context"]["step5_selected_coords"],
                ["com.example:demo-lib"],
            )
            self.assertEqual(saved["state"]["current_step"], "step6")
            self.assertEqual(saved["state"]["completed_step"], "step5")


if __name__ == "__main__":
    unittest.main()
