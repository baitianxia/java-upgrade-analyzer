import csv
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import run_step  # noqa: E402


class RunStepMainStateTest(unittest.TestCase):
    def test_json_reader_rejects_bom_prefixed_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            invalid_path = Path(tmp) / "invalid.json"
            invalid_path.write_bytes(
                b"\xef\xbb\xbf" + '{"message":"中文"}'.encode("utf-8")
            )
            with self.assertRaises(json.JSONDecodeError):
                run_step.read_json(invalid_path)

    def test_internal_tool_failure_reason_is_recorded_as_system_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            diagnostic = run_step.step4_api_changes_dir(report_dir) / "japicmp_preflight.json"
            diagnostic.parent.mkdir(parents=True)
            diagnostic.write_text(
                json.dumps(
                    {
                        "status": "blocked_by_system",
                        "reason_code": "step4_japicmp_missing_need_resolution",
                    }
                ),
                encoding="utf-8",
            )

            reason_codes = run_step.read_step_system_block_reason_codes(
                "s4_jar_compare.py", report_dir
            )

        self.assertEqual(
            reason_codes, ["STEP4_JAPICMP_MISSING_NEED_RESOLUTION"]
        )

    def test_step1_artifact_preflight_asks_only_for_missing_module_and_shows_candidates(self):
        interaction = run_step.build_step1_preflight_interaction(
            {
                "base_artifact_path": "/artifacts/base.jar",
                "current_artifact_path": "/artifacts/current.jar",
                "project_scope": {
                    "candidate_modules": ["app", "services/order-service"],
                },
            }
        )

        card = "\n".join(run_step.build_user_decision_card(interaction))

        self.assertEqual(interaction["required_fields"], ["target_module"])
        self.assertIn("两侧编译产物已经齐全", interaction["question"])
        self.assertNotIn("source_project_dir", interaction["question"])
        self.assertNotIn("补齐缺失侧的 branch", interaction["question"])
        self.assertIn("检测到的目标模块候选", card)
        self.assertIn("`app`", card)
        self.assertIn("`services/order-service`", card)

    def test_step1_artifact_review_collects_missing_context_refs_in_existing_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            manifest_steps = {
                "step1": {
                    "title": "分析对象与依赖范围",
                    "interaction": {
                        "type": "review",
                        "question": "请确认依赖范围。",
                        "required_fields": ["action"],
                        "options": [{"id": "continue", "label": "继续"}],
                    },
                    "outputs": [],
                }
            }

            payload = run_step.build_interaction_payload(
                "step1",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={
                    "base_artifact_path": "/artifacts/base.jar",
                    "current_artifact_path": "/artifacts/current.jar",
                    "target_module": "app",
                },
                main_state=run_step.new_main_state(report_dir),
            )

        self.assertEqual(payload["reason_code"], "STEP1_CONTEXT_REFS_REQUIRED")
        self.assertEqual(payload["required_fields"], ["base_branch", "current_branch"])
        self.assertEqual(
            payload["action_requirements"]["continue"]["required_fields"],
            ["base_branch", "current_branch"],
        )
        self.assertIn("制品和依赖变化范围已经生成", payload["question"])

    def test_step2_skips_repeated_confirmation_when_context_facts_are_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            context_dir = report_dir / "evidence" / "context"
            source_dir = project_dir / "src" / "main" / "java"
            context_dir.mkdir(parents=True)
            source_dir.mkdir(parents=True)
            (context_dir / "context.json").write_text(
                json.dumps(
                    {
                        "base_branch": "main",
                        "current_branch": "upgrade",
                        "jdk_base": "8",
                        "jdk_current": "17",
                        "springboot_base": "2.7.18",
                        "springboot_current": "3.3.1",
                        "changed_dependencies": [],
                    }
                ),
                encoding="utf-8",
            )
            (context_dir / "dep_graph.json").write_text("{}\n", encoding="utf-8")
            manifest_steps = {
                "step2": {
                    "title": "升级上下文",
                    "conditional_confirmation": True,
                    "interaction": {
                        "type": "decision",
                        "question": "请确认上下文。",
                        "options": [{"id": "continue", "label": "继续"}],
                    },
                    "outputs": [],
                }
            }

            payload = run_step.build_interaction_payload(
                "step2",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={
                    "target_module": "app",
                    "source_dirs": [str(source_dir)],
                    "source_dirs_status": "explicit",
                },
                main_state=run_step.new_main_state(report_dir),
            )
            review_exists = (context_dir / "review.md").is_file()

        self.assertIsNone(payload)
        self.assertTrue(review_exists)

    def test_step2_stops_once_when_material_context_facts_are_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            context_dir = report_dir / "evidence" / "context"
            source_dir = project_dir / "src" / "main" / "java"
            context_dir.mkdir(parents=True)
            source_dir.mkdir(parents=True)
            (context_dir / "context.json").write_text(
                json.dumps(
                    {
                        "base_branch": "main",
                        "current_branch": "upgrade",
                        "jdk_base": None,
                        "jdk_current": None,
                        "changed_dependencies": [],
                    }
                ),
                encoding="utf-8",
            )
            (context_dir / "dep_graph.json").write_text("{}\n", encoding="utf-8")
            manifest_steps = {
                "step2": {
                    "title": "升级上下文",
                    "conditional_confirmation": True,
                    "interaction": {
                        "type": "decision",
                        "question": "请确认上下文。",
                        "options": [{"id": "continue", "label": "继续"}],
                    },
                    "outputs": [],
                }
            }

            payload = run_step.build_interaction_payload(
                "step2",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={
                    "target_module": "app",
                    "source_dirs": [str(source_dir)],
                    "source_dirs_status": "explicit",
                },
                main_state=run_step.new_main_state(report_dir),
            )

        self.assertEqual(payload["reason_code"], "STEP2_CONTEXT_FACTS_UNRESOLVED")
        self.assertEqual(payload["required_fields"], ["jdk_base", "jdk_current"])
        self.assertIn("升级前 JDK", payload["question"])
        self.assertIn("升级后 JDK", payload["question"])
        self.assertNotIn("依赖源码目录", payload["question"])
        self.assertIn("jdk_base", payload["response_schema"]["properties"])
        self.assertIn("jdk_current", payload["response_schema"]["properties"])

    def test_step2_stops_for_explicit_source_hint_decision_without_forcing_acceptance(self):
        confirmation = run_step.build_step2_confirmation_requirements(
            {"jdk_base": "8", "jdk_current": "17"},
            {
                "source_dirs": ["/project/src/main/java"],
                "source_dirs_status": "explicit",
                "source_repo_hint_suggestions": {
                    "proposed": [
                        {
                            "coord": "com.example:demo-lib",
                            "repo_path": "/repos/demo-lib",
                        }
                    ]
                },
            },
        )
        pending = {
            "step_id": "step2",
            "reason_code": confirmation["reason_code"],
            "response_schema": {
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "accept_suggested_mappings": {"type": "boolean"},
                },
            },
            "action_requirements": {
                "continue": {
                    "required_fields": confirmation["required_fields"],
                }
            },
        }

        self.assertEqual(
            confirmation["reason_code"],
            "step2_source_mapping_decision_required",
        )
        self.assertEqual(
            confirmation["required_fields"], ["accept_suggested_mappings"]
        )
        run_step.validate_pending_interaction_response(
            pending,
            {"action": "continue", "accept_suggested_mappings": False},
        )
        persisted_decline = run_step.merge_user_response_into_run_context(
            {},
            {"action": "continue", "accept_suggested_mappings": False},
            Path("/project"),
        )
        self.assertIs(persisted_decline["accept_suggested_mappings"], False)
        with self.assertRaisesRegex(run_step.StepError, "accept_suggested_mappings"):
            run_step.validate_pending_interaction_response(
                pending,
                {"action": "continue"},
            )
        declined = run_step.build_step2_confirmation_requirements(
            {"jdk_base": "8", "jdk_current": "17"},
            {
                "source_dirs": ["/project/src/main/java"],
                "source_dirs_status": "explicit",
                "source_repo_hint_suggestions": {
                    "proposed": confirmation["proposed_mappings"]
                },
            },
            {"accept_suggested_mappings": False},
        )
        self.assertFalse(declined["required"])

    def test_step2_version_corrections_work_through_intent_patch(self):
        canonical = run_step.build_canonical_user_response(
            {
                "intent_patch": {
                    "action": "continue",
                    "set": {
                        "jdk_base": "11",
                        "jdk_current": "21",
                        "springboot_base": "2.7.18",
                        "springboot_current": "3.3.2",
                    },
                }
            }
        )
        updated = run_step.merge_user_response_into_run_context(
            {}, canonical, Path("/project")
        )

        self.assertEqual(updated["jdk_base"], "11")
        self.assertEqual(updated["jdk_current"], "21")
        self.assertEqual(updated["springboot_base"], "2.7.18")
        self.assertEqual(updated["springboot_current"], "3.3.2")
        self.assertEqual(run_step.infer_non_pending_target_step_from_payload(canonical), "step2")

    def test_auto_mode_runs_until_next_material_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"].update({"current_step": "step3", "completed_step": "step2"})
            state["step3"]["input"] = {
                "target_module": ".",
                "source_dirs": [str(source_dir)],
                "source_dirs_status": "explicit",
            }
            run_step.save_main_state(report_dir, state)
            executed = []

            def fake_execute(step_id, _args, _steps, _context, **_kwargs):
                executed.append(step_id)
                if step_id == "step4":
                    return {
                        "kind": "review",
                        "status": "awaiting_user_input",
                        "step_id": "step4",
                        "question": "请选择全量或部分分析范围。",
                        "options": [{"id": "continue"}, {"id": "cancel"}],
                    }
                return None

            manifest = {
                "auto_run_until_checkpoint": True,
            }
            steps = {
                "step3": {"gate": "scan", "interaction": None},
                "step4": {
                    "gate": "jar_compare",
                    "requires_scope_confirmation": True,
                },
            }
            with patch.object(
                run_step, "contract_payload", return_value={"status": "passed", "checks": []}
            ), patch.object(
                run_step, "load_manifest", return_value=(manifest, steps)
            ), patch.object(
                run_step, "detect_integrity_repair_step", return_value=None
            ), patch.object(
                run_step, "detect_current_branch", return_value=""
            ), patch.object(
                run_step, "detect_build_tool", return_value="maven"
            ), patch.object(
                run_step, "execute_step", side_effect=fake_execute
            ):
                exit_code = run_step.main(
                    [
                        "--step", "auto",
                        "--project-dir", str(project_dir),
                        "--report-dir", str(report_dir),
                    ]
                )

            saved = run_step.load_main_state(report_dir)

        self.assertEqual(exit_code, run_step.EXIT_AWAITING_USER)
        self.assertEqual(executed, ["step3", "step4"])
        self.assertEqual(saved["state"]["completed_step"], "step4")
        self.assertEqual(saved["state"]["pending_interaction"]["step_id"], "step4")

    def test_step2_input_reply_rebuilds_step2_exactly_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            pending = {
                "status": "awaiting_user_input",
                "kind": "input_request",
                "step_id": "step2",
                "options": [{"id": "continue"}],
                "response_schema": {
                    "required": ["action"],
                    "properties": {
                        "action": {"type": "string"},
                        "jdk_base": {"type": "string"},
                        "jdk_current": {"type": "string"},
                    },
                },
                "action_requirements": {
                    "continue": {"required_fields": ["jdk_base", "jdk_current"]}
                },
            }
            state = run_step.new_main_state(report_dir)
            state["state"].update(
                {
                    "current_step": "step2",
                    "completed_step": "step1",
                    "status": "awaiting_user_input",
                    "pending_interaction": pending,
                }
            )
            state["step2"]["input"] = {
                "base_branch": "base",
                "current_branch": "upgrade",
                "target_module": ".",
                "source_dirs": [str(source_dir)],
                "source_dirs_status": "explicit",
            }
            state["step2"]["output"] = {"jdk_base": "unknown", "jdk_current": "unknown"}
            run_step.save_main_state(report_dir, state)
            executed = []

            def fake_execute(step_id, _args, _steps, run_context, **_kwargs):
                executed.append((step_id, run_context["jdk_base"], run_context["jdk_current"]))
                return None

            with patch.object(
                run_step, "contract_payload", return_value={"status": "passed", "checks": []}
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=(
                    {"auto_run_until_checkpoint": False},
                    {"step2": {"gate": "context", "auto_continue_on_success": True}},
                ),
            ), patch.object(
                run_step, "detect_integrity_repair_step", return_value=None
            ), patch.object(
                run_step, "detect_current_branch", return_value=""
            ), patch.object(
                run_step, "detect_build_tool", return_value="maven"
            ), patch.object(
                run_step, "execute_step", side_effect=fake_execute
            ):
                exit_code = run_step.main(
                    [
                        "--step",
                        "auto",
                        "--project-dir",
                        str(project_dir),
                        "--report-dir",
                        str(report_dir),
                        "--response-json",
                        json.dumps(
                            {
                                "action": "continue",
                                "jdk_base": "8",
                                "jdk_current": "17",
                            }
                        ),
                    ]
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(executed, [("step2", "8", "17")])

    def test_legacy_step2_review_only_reruns_when_reply_changes_step2_input(self):
        pending = {"step_id": "step2", "kind": "review"}

        self.assertEqual(
            run_step.resolve_resume_step_id(
                "step3", pending, "continue", {"action": "continue"}
            ),
            "step3",
        )
        self.assertEqual(
            run_step.resolve_resume_step_id(
                "step3",
                pending,
                "continue",
                {"action": "continue", "jdk_current": "21"},
            ),
            "step2",
        )

    def test_auto_mode_runs_system_reachability_and_report_without_extra_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"].update({"current_step": "step5", "completed_step": "step4"})
            state["step5"]["input"] = {
                "target_module": ".",
                "source_dirs": [str(source_dir)],
                "source_dirs_status": "explicit",
            }
            run_step.save_main_state(report_dir, state)
            executed = []

            def fake_execute(step_id, _args, _steps, _context, **_kwargs):
                executed.append(step_id)
                return None

            manifest = {"auto_run_until_checkpoint": True}
            steps = {
                "step5": {
                    "gate": "call_chain",
                    "auto_continue_on_success": True,
                    "interaction": None,
                },
                "step6": {"gate": "report", "interaction": None},
            }
            with patch.object(
                run_step, "contract_payload", return_value={"status": "passed", "checks": []}
            ), patch.object(
                run_step, "load_manifest", return_value=(manifest, steps)
            ), patch.object(
                run_step, "detect_integrity_repair_step", return_value=None
            ), patch.object(
                run_step, "detect_current_branch", return_value=""
            ), patch.object(
                run_step, "detect_build_tool", return_value="maven"
            ), patch.object(
                run_step, "execute_step", side_effect=fake_execute
            ):
                exit_code = run_step.main(
                    [
                        "--step", "auto",
                        "--project-dir", str(project_dir),
                        "--report-dir", str(report_dir),
                    ]
                )

            saved = run_step.load_main_state(report_dir)

        self.assertEqual(exit_code, 0)
        self.assertEqual(executed, ["step5", "step6"])
        self.assertEqual(saved["state"]["current_step"], "done")
        self.assertEqual(saved["state"]["completed_step"], "step6")
        self.assertIn(
            saved["state"]["status"],
            {"completed", "completed_with_limits"},
        )

    def test_step4_scope_review_is_preserved_and_step5_success_review_auto_continues(self):
        interaction = {
            "status": "awaiting_user_input",
            "options": [{"id": "continue"}, {"id": "cancel"}],
        }
        manifest = {
            "step4": {
                "auto_continue_on_success": True,
                "requires_scope_confirmation": True,
            },
            "step5": {"auto_continue_on_success": True},
        }

        self.assertFalse(
            run_step.should_auto_continue_success_review("step4", interaction, manifest)
        )
        self.assertTrue(
            run_step.should_auto_continue_success_review("step5", interaction, manifest)
        )
        self.assertFalse(
            run_step.should_auto_continue_success_review(
                "step4",
                {**interaction, "reason_code": "step4_git_refs_need_confirmation"},
                manifest,
            )
        )
        self.assertFalse(
            run_step.should_auto_continue_success_review("step2", interaction, manifest)
        )

    def test_main_auto_continues_routine_step5_success_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "step5"
            state["state"]["completed_step"] = "step4"
            run_step.save_main_state(report_dir, state)
            routine_review = {
                "status": "awaiting_user_input",
                "step_id": "step5",
                "options": [{"id": "continue"}, {"id": "cancel"}],
            }

            with patch.object(
                sys,
                "argv",
                [
                    "run_step.py",
                    "--step", "step5",
                    "--project-dir", str(project_dir),
                    "--report-dir", str(report_dir),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=(
                    {},
                    {
                        "step5": {
                            "gate": "call_chain",
                            "auto_continue_on_success": True,
                        }
                    },
                ),
            ), patch.object(
                run_step,
                "execute_step",
                return_value=routine_review,
            ):
                exit_code = run_step.main()

            saved = run_step.load_main_state(report_dir)
            informational = run_step.read_json(
                report_dir / ".runtime" / "state" / "interaction.json"
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(saved["state"]["current_step"], "step6")
        self.assertEqual(saved["state"]["completed_step"], "step5")
        self.assertEqual(saved["state"]["status"], "ready")
        self.assertIsNone(saved["state"]["pending_interaction"])
        self.assertEqual(informational["status"], "informational")
        self.assertEqual(informational["event"], "step_completed_information")
        self.assertFalse(informational["must_wait_for_user_reply"])
        self.assertEqual(informational["exit_code"], 0)
        card = "\n".join(informational["user_decision_card"])
        self.assertIn("阶段结果：", card)
        self.assertIn("本卡无需回复", card)
        self.assertNotIn("为什么暂停", card)

    def test_step5_generates_standard_five_state_card_when_manifest_skips_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            call_chain_dir = report_dir / "evidence" / "call_chain"
            call_chain_dir.mkdir(parents=True)
            (call_chain_dir / "summary.json").write_text(
                json.dumps({
                    "reachable": 2,
                    "not_impacted": 3,
                    "uncertain": 4,
                    "not_analyzed": 5,
                    "not_found_in_static_analysis": 6,
                }),
                encoding="utf-8",
            )
            payload = run_step.build_interaction_payload(
                "step5",
                report_dir,
                {
                    "step5": {
                        "title": "系统触达证据",
                        "interaction": None,
                        "auto_continue_on_success": True,
                    }
                },
                project_dir,
                run_context={},
                main_state=run_step.new_main_state(report_dir),
            )

        self.assertIsNotNone(payload)
        informational = run_step.build_informational_success_interaction(
            "step5", payload
        )
        self.assertEqual(informational["status"], "informational")
        card = "\n".join(informational["user_decision_card"])
        self.assertIn("reachable（已确认静态触达）=2", card)
        self.assertIn("not_impacted（已确认不受 API 调用影响）=3", card)
        self.assertIn("uncertain（存在候选证据或已知分析边界）=4", card)
        self.assertIn("not_analyzed（输入不足或分析未完成）=5", card)
        self.assertIn("not_found_in_static_analysis（当前静态范围未找到路径）=6", card)
        self.assertIn("不表示安全", card)
        self.assertFalse(informational["decision_required"])

    def test_completion_cleanup_preserves_step5_informational_card_when_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            informational = run_step.build_informational_success_interaction(
                "step5",
                {
                    "step_id": "step5",
                    "checklist_lines": ["reachable=1", "uncertain=2"],
                },
            )
            run_step.save_interaction_file(report_dir, informational)

            run_step.clear_interaction_file(
                report_dir,
                preserve_informational=True,
            )
            preserved = run_step.read_json(
                report_dir / ".runtime" / "state" / "interaction.json"
            )

        self.assertEqual(preserved["status"], "informational")
        self.assertEqual(preserved["step_id"], "step5")
        self.assertEqual(preserved["event"], "step_completed_information")

    def test_legacy_nonterminal_completed_state_normalizes_to_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"].update(
                {
                    "current_step": "step6",
                    "completed_step": "step5",
                    "status": "completed",
                    "completion_summary": {"status": "completed"},
                }
            )

            normalized = run_step.ensure_main_state_structure(state, report_dir)

        self.assertEqual(normalized["state"]["current_step"], "step6")
        self.assertEqual(normalized["state"]["completed_step"], "step5")
        self.assertEqual(normalized["state"]["status"], "ready")
        self.assertIsNone(normalized["state"]["completion_summary"])

    def test_terminal_completed_state_remains_terminal(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            completion_summary = {"status": "completed", "finding_count": 0}
            state["state"].update(
                {
                    "current_step": "done",
                    "completed_step": "step6",
                    "status": "completed",
                    "completion_summary": completion_summary,
                }
            )

            normalized = run_step.ensure_main_state_structure(state, report_dir)

        self.assertEqual(normalized["state"]["status"], "completed")
        self.assertEqual(
            normalized["state"]["completion_summary"], completion_summary
        )

    def test_main_keeps_step4_scope_confirmation_even_if_auto_continue_is_misconfigured(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "step4"
            state["state"]["completed_step"] = "step3"
            run_step.save_main_state(report_dir, state)
            scope_review = {
                "status": "awaiting_user_input",
                "step_id": "step4",
                "question": "请选择 Step5 的分析范围",
                "options": [{"id": "continue"}, {"id": "cancel"}],
            }

            with patch.object(
                sys,
                "argv",
                [
                    "run_step.py",
                    "--step", "step4",
                    "--project-dir", str(project_dir),
                    "--report-dir", str(report_dir),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=(
                    {},
                    {
                        "step4": {
                            "gate": "jar_compare",
                            "auto_continue_on_success": True,
                            "requires_scope_confirmation": True,
                        }
                    },
                ),
            ), patch.object(
                run_step,
                "execute_step",
                return_value=scope_review,
            ):
                exit_code = run_step.main()

            saved = run_step.load_main_state(report_dir)

        self.assertEqual(exit_code, run_step.EXIT_AWAITING_USER)
        self.assertEqual(saved["state"]["current_step"], "step5")
        self.assertEqual(saved["state"]["status"], "awaiting_user_input")
        self.assertEqual(saved["state"]["pending_interaction"]["step_id"], "step4")

    def test_user_response_merges_active_maven_profiles_into_step1_context(self):
        updated = run_step.merge_user_response_into_run_context(
            {
                "active_maven_profiles": [],
                "source_dirs": ["/project/profile-a/src/main/java"],
                "source_dirs_status": "project_scope",
            },
            {"active_maven_profiles": ["boot", "boot"]},
            Path("/project"),
        )

        self.assertEqual(updated["active_maven_profiles"], ["boot"])
        self.assertNotIn("source_dirs", updated)
        self.assertNotIn("source_dirs_status", updated)
        self.assertEqual(
            run_step.infer_non_pending_target_step_from_payload(
                {"active_maven_profiles": ["boot"]}
            ),
            "step1",
        )

    def test_run_context_applies_explicit_maven_profiles_to_project_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report"
            (root / "pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>root</artifactId><version>1</version>
                <packaging>pom</packaging><profiles><profile><id>boot</id>
                <modules><module>application</module></modules></profile></profiles>
                </project>""",
                encoding="utf-8",
            )
            (root / "application/src/main/java").mkdir(parents=True)
            (root / "application/pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>application</artifactId>
                <version>1</version></project>""",
                encoding="utf-8",
            )
            args = self._make_default_args(root, report)
            args.target_module = ""
            args.active_maven_profiles = None

            context = run_step.build_run_context(
                args,
                existing={},
                seed_payload={
                    "target_module": "application",
                    "active_maven_profiles": ["boot"],
                },
            )

        self.assertEqual(context["active_maven_profiles"], ["boot"])
        self.assertEqual(
            context["project_scope"]["included_modules"], ["application"]
        )

    def _dep_dir(self, report_dir):
        return run_step.evidence_dependencies_dir(report_dir)

    def _context_dir(self, report_dir):
        return run_step.evidence_context_dir(report_dir)

    def _static_scan_dir(self, report_dir):
        return run_step.evidence_static_scan_dir(report_dir)

    def _api_changes_dir(self, report_dir):
        return run_step.evidence_api_changes_dir(report_dir)

    def _call_chain_dir(self, report_dir):
        return run_step.evidence_call_chain_dir(report_dir)

    def _runtime_state_dir(self, report_dir):
        return run_step.runtime_state_dir(report_dir)

    def _runtime_cache_dir(self, report_dir):
        return run_step.runtime_cache_dir(report_dir)

    def _deliverables_dir(self, report_dir):
        return run_step.deliverables_dir(report_dir)

    def _write_text(self, path, text, **kwargs):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path.write_text(text, **kwargs)

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

    def test_jar_compare_gate_failure_carries_structured_coverage_reason_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            coverage_path = report_dir / ".runtime" / "coverage" / "s4_coverage.json"
            self._write_text(
                coverage_path,
                json.dumps(
                    {
                        "binary_api_diff": {
                            "status": "insufficient",
                            "reason_codes": [
                                "japicmp_or_old_jar_failed",
                                "FINAL_ARTIFACT_JAR_EVIDENCE_MISSING",
                            ],
                        },
                        "behavior_diff": {"status": "complete", "reason_codes": []},
                    }
                ),
                encoding="utf-8",
            )

            with patch.object(
                run_step,
                "run_python",
                side_effect=run_step.StepError("gate.py execution failed"),
            ), self.assertRaises(run_step.StepError) as raised:
                run_step.run_gate("jar_compare", report_dir, Path(tmp))

            self.assertEqual(
                raised.exception.reason_codes,
                [
                    "japicmp_or_old_jar_failed",
                    "FINAL_ARTIFACT_JAR_EVIDENCE_MISSING",
                ],
            )

    def test_persist_step_error_saves_machine_readable_reason_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            error = run_step.StepError(
                "gate.py execution failed",
                reason_codes=["FINAL_ARTIFACT_JAR_EVIDENCE_MISSING"],
            )

            run_step.persist_step_error(state, "step4", report_dir, error)

            saved = run_step.read_json(run_step.main_state_path(report_dir))
            self.assertEqual(saved["state"]["status"], "blocked_by_system")
            self.assertEqual(
                saved["state"]["blocking_reason_codes"],
                ["FINAL_ARTIFACT_JAR_EVIDENCE_MISSING"],
            )

    def test_step5_artifact_preflight_failure_carries_system_block_reason_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            diagnostic_path = (
                report_dir
                / "evidence"
                / "call_chain"
                / "artifact_preflight_failure.json"
            )
            self._write_text(
                diagnostic_path,
                json.dumps(
                    {
                        "status": "blocked_by_system",
                        "reason_code": (
                            "STEP1_RETAINED_ARTIFACT_EVIDENCE_INVALID"
                        ),
                    }
                ),
                encoding="utf-8",
            )

            reason_codes = run_step.read_step_system_block_reason_codes(
                "s5_call_chain_engine_integrated.py",
                report_dir,
            )

        self.assertEqual(
            reason_codes,
            ["STEP1_RETAINED_ARTIFACT_EVIDENCE_INVALID"],
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

    def test_user_response_accumulates_manual_coord_overrides_across_rounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            state = run_step.new_main_state(project_dir / ".upgrade-report")
            first_round = [
                f"lib-{index}:1.0 -> com.example:lib-{index}"
                for index in range(1, 10)
            ]
            state["step1"]["input"] = {
                "manual_coord_overrides": first_round,
            }

            _, updated = run_step.apply_user_response_to_main_state(
                state,
                {"step_id": "step1", "kind": "input_request"},
                {
                    "action": "rerun_current_step",
                    "manual_coord_overrides": [
                        "asm-util:7.1 -> org.ow2.asm:asm-util",
                    ],
                },
                project_dir,
                target_step_id="step1",
            )

            self.assertEqual(
                updated["manual_coord_overrides"],
                first_round + ["asm-util:7.1 -> org.ow2.asm:asm-util"],
            )

    def test_user_response_replaces_manual_identity_for_same_physical_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            state = run_step.new_main_state(project_dir / ".upgrade-report")
            state["step1"]["input"] = {
                "manual_artifact_identities": [{
                    "side": "current",
                    "lib_entry": "BOOT-INF/lib/renamed.jar",
                    "group_id": "org.example",
                    "artifact_id": "demo",
                    "version": "1.0",
                    "classifier": "",
                }],
            }

            _, updated = run_step.apply_user_response_to_main_state(
                state,
                {"step_id": "step1", "kind": "input_request"},
                {
                    "action": "rerun_current_step",
                    "manual_artifact_identities": [{
                        "side": "current",
                        "lib_entry": "BOOT-INF/lib/renamed.jar",
                        "group_id": "org.example",
                        "artifact_id": "demo",
                        "version": "2.0",
                        "classifier": "",
                    }],
                },
                project_dir,
                target_step_id="step1",
            )

            self.assertEqual(len(updated["manual_artifact_identities"]), 1)
            self.assertEqual(
                updated["manual_artifact_identities"][0]["version"],
                "2.0",
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

    def test_materialize_step5_input_does_not_promote_step3_candidates_to_targets(self):
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

            with self.assertRaises(run_step.StepError):
                run_step.materialize_step5_all_changed_apis_input(
                    all_changed_path,
                    report_dir,
                    {"step5_selected_coords": ["sample:candidate"]},
                )

            materialized_path, selection_summary = run_step.materialize_step5_all_changed_apis_input(
                all_changed_path, report_dir, {}
            )
            self.assertEqual(materialized_path, all_changed_path)
            self.assertEqual(len(selection_summary["matched_rows"]), 1)
            self.assertEqual(selection_summary["matched_rows"][0]["source"], "japicmp")
            scope = json.loads(
                (report_dir / ".runtime" / "cache" / "step5_selection.json").read_text(encoding="utf-8")
            )
            self.assertEqual(scope["mode"], "full")
            self.assertEqual(scope["included_dependency_count"], 1)

    def test_materialize_step5_input_name_filter_keeps_all_matching_coords(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            all_changed_path = report_dir / "all_changed_apis.csv"
            all_changed_path.write_text(
                "\n".join(
                    [
                        "coord,api_name,api_simple,api_signature,symbol_kind,change_type,confirmed,severity,source,analysis_scope",
                        "com.example:demo-lib,com.example.Demo.call,call,(),method,REMOVED,true,P1,japicmp,api",
                        "org.example:demo-lib,org.example.Demo.call,call,(),method,REMOVED,true,P1,japicmp,api",
                        "com.example:core-lib,com.example.Core.call,call,(),method,REMOVED,true,P1,japicmp,api",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            materialized_path, selection_summary = run_step.materialize_step5_all_changed_apis_input(
                all_changed_path,
                report_dir,
                {"step5_selected_names": ["demo-lib"]},
            )

            self.assertEqual(materialized_path.name, "selected_all_changed_apis.csv")
            self.assertEqual(selection_summary["matched_names"], ["demo-lib"])
            self.assertEqual(
                {row["coord"] for row in selection_summary["matched_rows"]},
                {"com.example:demo-lib", "org.example:demo-lib"},
            )
            scope = json.loads(
                (report_dir / ".runtime" / "cache" / "step5_selection.json").read_text(encoding="utf-8")
            )
            self.assertEqual(scope["mode"], "partial")
            self.assertEqual(scope["available_dependency_count"], 3)
            self.assertEqual(scope["included_dependency_count"], 2)
            self.assertEqual(scope["excluded_dependency_coords"], ["com.example:core-lib"])

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
            self._api_changes_dir(report_dir).mkdir(parents=True, exist_ok=True)
            with (self._api_changes_dir(report_dir) / "all_changed_apis.csv").open("w", encoding="utf-8", newline="") as fh:
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
                                "selected_targets": ["com.example:demo-lib"],
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

    def test_step4_checkpoint_uses_changed_dependencies_for_selection_options(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            api_dir = report_dir / "evidence" / "api_changes"
            api_dir.mkdir(parents=True, exist_ok=True)
            (api_dir / "changed_dependencies.csv").write_text(
                "selection_key,coord,dependency_name,changed_api_count,high_risk_api_count,business_exact_referenced_api_count,business_candidate_referenced_api_count,business_reference_occurrence_count,business_bytecode_scan_status,dependency_source_status,impact_priority_rank,change_types,symbol_kinds,recommended,review_focus,detail\n"
                "coord:com.acme:alpha,com.acme:alpha,alpha,42,5,2,1,4,complete,available,1,removed,method,true,业务最终制品直接引用 2 个变更 API,s4_per_dependency/com.acme__alpha/summary.json\n"
                "coord:com.acme:beta,com.acme:beta,beta,3,0,0,0,0,complete,unavailable,2,modified,method,true,未观察到业务字节码直接引用,s4_per_dependency/com.acme__beta/summary.json\n",
                encoding="utf-8",
            )

            selection_resolution = run_step.build_report_dir_step5_selection_resolution(report_dir)

            self.assertTrue(selection_resolution["enabled"])
            self.assertEqual(selection_resolution["options"][0]["selection_key"], "coord:com.acme:alpha")
            self.assertEqual(selection_resolution["options"][0]["coord"], "com.acme:alpha")
            self.assertEqual(selection_resolution["options"][0]["api_count"], 42)
            self.assertEqual(selection_resolution["options"][0]["high_risk_api_count"], 5)
            self.assertEqual(
                selection_resolution["options"][0][
                    "business_exact_referenced_api_count"
                ],
                2,
            )

            summary = run_step.build_step5_dependency_selection_summary(report_dir)
            self.assertEqual(summary["recommended_target_count"], 2)
            self.assertEqual(summary["recommended_targets"][0]["coord"], "com.acme:alpha")

            _, manifest_steps = run_step.load_manifest(ROOT_DIR / "scripts" / "step_manifest.json")
            interaction = run_step.build_interaction_payload(
                "step4",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={},
                main_state=run_step.new_main_state(report_dir),
            )
            properties = interaction["response_schema"]["properties"]
            self.assertIn("分析范围", interaction["question"])
            self.assertIn("selected_targets", properties)
            self.assertNotIn("dependency_source_dirs", properties)
            self.assertNotIn("dependency_git_ref_overrides", properties)
            self.assertNotIn("step4_git_diff_timeout", properties)
            self.assertEqual(
                interaction["scope_preview"],
                {
                    "available_dependency_count": 2,
                    "total_api_count": 45,
                    "high_risk_api_count": 5,
                    "business_exact_referenced_api_count": 2,
                    "business_candidate_referenced_api_count": 1,
                    "partial_scope_effect": "未选择的变化依赖不会进入系统触达分析；最终报告只适用于所选范围。",
                },
            )
            self.assertEqual(
                interaction["files_to_review"],
                [str((api_dir / "changed_dependencies.md").resolve())],
            )
            card_text = "\n".join(interaction["user_decision_card"])
            self.assertIn("`com.acme:alpha`", card_text)
            self.assertIn("`com.acme:beta`", card_text)
            self.assertIn("完整依赖选择清单", card_text)
            self.assertIn("从“依赖包”列复制名称或完整坐标", card_text)
            self.assertNotIn("selected_targets", card_text)
            self.assertNotIn("selection_key", card_text)

    def test_step4_scope_checkpoint_is_skipped_when_no_real_scope_choice_exists(self):
        _, manifest_steps = run_step.load_manifest(ROOT_DIR / "scripts" / "step_manifest.json")
        for dependency_rows in (
            [],
            ["coord:com.acme:alpha,com.acme:alpha,alpha,1,1,removed,method,true,detail"],
        ):
            with self.subTest(candidate_count=len(dependency_rows)), tempfile.TemporaryDirectory() as tmp:
                project_dir = Path(tmp) / "project"
                report_dir = project_dir / ".upgrade-report"
                api_dir = report_dir / "evidence" / "api_changes"
                api_dir.mkdir(parents=True, exist_ok=True)
                (api_dir / "changed_dependencies.csv").write_text(
                    "selection_key,coord,dependency_name,changed_api_count,high_risk_api_count,change_types,symbol_kinds,recommended,detail\n"
                    + "\n".join(dependency_rows)
                    + ("\n" if dependency_rows else ""),
                    encoding="utf-8",
                )

                interaction = run_step.build_interaction_payload(
                    "step4",
                    report_dir,
                    manifest_steps,
                    project_dir,
                    run_context={},
                    main_state=run_step.new_main_state(report_dir),
                )

                self.assertIsNone(interaction)

    def test_report_landing_doc_is_single_dynamic_user_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            for relative in (
                "evidence/dependencies",
                "evidence/context",
                "evidence/static_scan",
                "evidence/api_changes",
                "evidence/call_chain",
            ):
                (report_dir / relative).mkdir(parents=True, exist_ok=True)

            for relative in (
                "deliverables/README.md",
                "evidence/README.md",
                ".runtime/README.md",
                "evidence/dependencies/README.md",
            ):
                path = report_dir / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("旧导航\n", encoding="utf-8")

            state = run_step.new_main_state(report_dir)
            state["state"].update(
                {
                    "current_step": "step5",
                    "completed_step": "step4",
                    "status": "awaiting_user_input",
                    "blocking_reason": "请确认系统触达证据的分析范围。",
                    "pending_interaction": {
                        "question": "请选择全量分析或部分分析。",
                        "options": [
                            {"id": "continue", "label": "全量分析"},
                            {"id": "continue_with_selection", "label": "部分分析"},
                        ],
                        "selection_options": [{"coord": "com.acme:alpha"}],
                        "files_to_review": [
                            str(report_dir / "evidence" / "api_changes" / "changed_dependencies.md")
                        ],
                    },
                }
            )
            (report_dir / "evidence" / "api_changes" / "changed_dependencies.md").write_text(
                "# 变化依赖\n", encoding="utf-8"
            )
            run_step.write_report_landing_docs(report_dir, state)

            root_readme = (report_dir / "README.md").read_text(encoding="utf-8")
            self.assertIn("当前状态：等待你确认", root_readme)
            self.assertIn("当前任务：系统触达证据", root_readme)
            self.assertIn("请确认系统触达证据的分析范围", root_readme)
            self.assertIn("## 当前需要你决定", root_readme)
            self.assertIn("请选择全量分析或部分分析", root_readme)
            self.assertIn("`全量分析`", root_readme)
            self.assertIn("完整依赖选择清单（包含未展示候选）", root_readme)
            self.assertIn("从“依赖包”列复制名称或完整坐标", root_readme)
            self.assertIn(
                "[evidence/api_changes/changed_dependencies.md](evidence/api_changes/changed_dependencies.md)",
                root_readme,
            )
            self.assertNotIn("deliverables/report.md", root_readme)
            self.assertNotIn("Step1", root_readme)
            self.assertNotIn("Step5", root_readme)
            self.assertEqual((report_dir / "deliverables" / "README.md").read_text(encoding="utf-8"), "旧导航\n")
            self.assertEqual((report_dir / "evidence" / "README.md").read_text(encoding="utf-8"), "旧导航\n")
            self.assertEqual((report_dir / ".runtime" / "README.md").read_text(encoding="utf-8"), "旧导航\n")
            self.assertEqual((report_dir / "evidence" / "dependencies" / "README.md").read_text(encoding="utf-8"), "旧导航\n")

    def test_user_runtime_messages_cover_start_completion_and_failure_without_internal_state(self):
        start = "\n".join(run_step.build_user_runtime_message("start", "step3"))
        complete = "\n".join(run_step.build_user_runtime_message("complete", "step3"))
        finished = "\n".join(run_step.build_user_runtime_message("complete", "step6"))
        failed = "\n".join(run_step.build_user_runtime_message("failed", "step4", reason="无法读取依赖包"))

        self.assertIn("正在分析：兼容性线索", start)
        self.assertIn("兼容性线索已完成", complete)
        self.assertIn("接下来：依赖 API 变化", complete)
        self.assertIn("分析已完成", finished)
        self.assertIn("deliverables/report.md", finished)
        self.assertIn("依赖 API 变化未完成", failed)
        self.assertIn("无法读取依赖包", failed)
        self.assertIn("系统已停止当前任务", failed)
        self.assertIn("已有证据会保留", failed)
        for text in (start, complete, finished, failed):
            self.assertNotRegex(text, r"\b[Ss]tep\d+\b")
            self.assertNotIn("main_state", text)
            self.assertNotIn("退出码", text)

    def test_completed_step_publishes_compact_resume_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            output = (
                report_dir
                / "evidence"
                / "static_scan"
                / "s3_jdk_removed_api.csv"
            )
            output.parent.mkdir(parents=True)
            output.write_text("api\n", encoding="utf-8")
            state = run_step.new_main_state(report_dir)

            run_step.persist_completed_step(
                state,
                "step3",
                report_dir,
                {"project_scope": {}},
            )

            summary_path = run_step.last_step_summary_path(report_dir)
            summary_bytes = summary_path.read_bytes()
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            resume_text = run_step.resume_context_path(report_dir).read_text(
                encoding="utf-8"
            )

        self.assertFalse(summary_bytes.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(summary["event"], "step_completed")
        self.assertEqual(summary["last_step"]["step_id"], "step3")
        self.assertTrue(summary["last_step"]["completed"])
        self.assertEqual(summary["workflow_state"]["current_step"], "step4")
        self.assertFalse(summary["needs_user_input"])
        self.assertIn(
            "evidence/static_scan/s3_jdk_removed_api.csv",
            summary["outputs"],
        )
        self.assertIn("## 可直接转述的状态", resume_text)
        self.assertIn("兼容性线索", resume_text)
        self.assertIn("继续执行依赖 API 变化", resume_text)

    def test_completed_checkpoint_snapshot_names_required_user_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            interaction = {
                "step_id": "step4",
                "status": "awaiting_user_input",
                "question": "请选择全量分析或指定依赖。",
                "options": [{"id": "continue", "label": "全量分析"}],
            }

            run_step.persist_step_interaction(
                state,
                "step4",
                report_dir,
                {"project_scope": {}},
                interaction,
            )
            summary = run_step.read_json(
                run_step.last_step_summary_path(report_dir)
            )
            resume_text = run_step.resume_context_path(report_dir).read_text(
                encoding="utf-8"
            )

        self.assertEqual(summary["event"], "step_completed_awaiting_user")
        self.assertTrue(summary["last_step"]["completed"])
        self.assertTrue(summary["needs_user_input"])
        self.assertEqual(
            summary["user_input"]["question"],
            "请选择全量分析或指定依赖。",
        )
        self.assertIn("是否需要用户输入：是", resume_text)
        self.assertIn("请选择全量分析或指定依赖", resume_text)

    def test_environment_block_message_names_only_failed_prerequisites_and_preserves_business_input(self):
        text = "\n".join(
            run_step.build_environment_block_message(
                {
                    "status": "failed",
                    "checks": [
                        {
                            "component": "python",
                            "status": "passed",
                            "observed": "CPython 3.12.9",
                            "expected": "CPython 3.10 or newer",
                        },
                        {
                            "component": "tool:mvn",
                            "status": "failed",
                            "observed": "未检测到",
                            "expected": "installed and executable",
                        },
                    ],
                }
            )
        )

        self.assertIn("命令行工具 mvn", text)
        self.assertNotIn("Python 运行时：", text)
        self.assertIn("业务输入和分析范围无需修改", text)
        self.assertNotIn("action=", text)

    def test_environment_warning_explains_unverified_python_without_blocking(self):
        lines = run_step.build_environment_warning_messages(
            {
                "status": "passed",
                "warnings": [
                    {
                        "component": "python",
                        "status": "warning",
                        "observed": "CPython 3.11.9",
                        "expected": "CPython 3.10 or newer",
                        "reason": "python_version_not_ci_verified",
                    }
                ],
            }
        )

        self.assertEqual(len(lines), 1)
        self.assertIn("满足最低运行要求", lines[0])
        self.assertIn("尚未进入 CI 验证矩阵", lines[0])

    def test_final_completion_summary_marks_partial_scope_and_uncertainty_as_limited(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            findings_path = report_dir / ".runtime" / "findings" / "s6_findings.json"
            findings_path.parent.mkdir(parents=True)
            findings_path.write_text(
                json.dumps(
                    {
                        "coverage": {"overall_status": "complete"},
                        "analysis_scope": {
                            "mode": "partial",
                            "included_dependency_count": 1,
                            "available_dependency_count": 3,
                            "analyzed_api_count": 7,
                            "total_api_count": 19,
                            "included_dependency_coords": [
                                "com.example:demo"
                            ],
                            "excluded_dependency_coords": [
                                "com.example:other",
                                "com.example:third",
                            ],
                        },
                        "dependency_changes": [
                            {
                                "coord": "com.example:demo",
                                "old_version": "1.0.0",
                                "new_version": "2.0.0",
                                "change_type": "major",
                            },
                            {
                                "coord": "com.example:other",
                                "old_version": "1.0.0",
                                "new_version": "2.0.0",
                                "change_type": "major",
                            },
                            {
                                "coord": "com.example:third",
                                "old_version": "1.0.0",
                                "new_version": "2.0.0",
                                "change_type": "major",
                            },
                        ],
                        "changed_api_inventory": [
                            {
                                "coord": "com.example:demo",
                                "api": (
                                    "com.example.Api.confirmed"
                                    if index == 0
                                    else (
                                        "com.example.Api.uncertain"
                                        if index == 1
                                        else f"com.example.Api.pending{index}"
                                    )
                                ),
                                "api_signature": "()",
                                "symbol_kind": "method",
                                "change_type": "REMOVED",
                            }
                            for index in range(7)
                        ],
                        "p0": [{
                            "coord": "com.example:demo",
                            "api": "com.example.Api.confirmed",
                            "api_signature": "()",
                            "symbol_kind": "method",
                            "change_type": "REMOVED",
                        }],
                        "p1": [],
                        "p2": [],
                        "probable_impact": [],
                        "uncertain": [{
                            "coord": "com.example:demo",
                            "api": "com.example.Api.uncertain",
                            "api_signature": "()",
                            "symbol_kind": "method",
                            "change_type": "REMOVED",
                        }],
                        "needs_input": [],
                        "not_analyzed": [],
                        "diagnostics": [],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            summary = run_step.build_final_completion_summary(report_dir)
            message = "\n".join(
                run_step.build_user_runtime_message(
                    "complete", "step6", completion_summary=summary
                )
            )

        self.assertEqual(summary["status"], "completed_with_limits")
        self.assertEqual(summary["confirmed_count"], 1)
        self.assertIn("用户选择了部分变化依赖", summary["limitations"])
        self.assertIn("1 项存在候选证据但结论未确定", summary["limitations"])
        self.assertIn("分析已完成，但存在结论限制", message)
        for limitation in summary["limitations"]:
            self.assertIn(limitation, message)
        self.assertIn("部分依赖（1/3）", message)
        self.assertEqual(summary["dependency_total_count"], 1)
        self.assertEqual(summary["dependency_completed_count"], 0)
        self.assertEqual(summary["dependency_incomplete_count"], 1)
        self.assertEqual(summary["dependency_confirmed_count"], 1)
        self.assertEqual(summary["api_total_count"], 7)
        self.assertEqual(summary["api_completed_count"], 2)
        self.assertEqual(summary["api_incomplete_count"], 5)
        self.assertEqual(summary["api_confirmed_count"], 1)
        self.assertIn(
            "依赖：变化 1，已完成分析 0，未完成分析 1，含确认影响 1。",
            message,
        )
        self.assertIn(
            "API：变化 7，已完成分析 2，未完成分析 5，确认影响 1。",
            message,
        )
        self.assertIn(
            "deliverables/all-affected-dependencies.md",
            message,
        )
        self.assertIn(
            "deliverables/all-affected-dependencies.csv",
            message,
        )
        self.assertIn("deliverables/all-impact-details.md", message)
        self.assertIn("deliverables/all-impact-details.csv", message)
        self.assertNotIn("deliverables/analysis-scope.md", message)

    def test_final_completion_separates_candidate_uncertainty_from_analysis_limitations(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            findings_path = run_step.s6_findings_path(report_dir)
            findings_path.parent.mkdir(parents=True)
            findings_path.write_text(
                json.dumps({
                    "coverage": {"overall_status": "complete"},
                    "analysis_scope": {"mode": "full"},
                    "p0": [], "p1": [], "p2": [], "probable_impact": [],
                    "uncertain": [
                        {"uncertainty_kind": "candidate_evidence"},
                        {"uncertainty_kind": "analysis_limitation"},
                    ],
                    "needs_input": [], "not_analyzed": [], "diagnostics": [],
                }, ensure_ascii=False),
                encoding="utf-8",
            )

            summary = run_step.build_final_completion_summary(report_dir)

        self.assertEqual(summary["uncertain_count"], 2)
        self.assertEqual(summary["uncertain_candidate_count"], 1)
        self.assertEqual(summary["uncertain_analysis_limitation_count"], 1)
        self.assertIn(
            "1 项存在候选证据但结论未确定",
            summary["limitations"],
        )
        self.assertIn(
            "1 项受静态分析能力边界限制，未发现候选调用证据且结论未确定",
            summary["limitations"],
        )

    def test_landing_status_does_not_hide_completion_limits(self):
        state = {
            "state": {
                "current_step": "done",
                "status": "completed_with_limits",
            }
        }

        text = "\n".join(run_step._landing_status_lines(state))

        self.assertIn("分析已完成，但存在结论限制", text)
        self.assertIn("结论适用范围以本轮分析范围为边界", text)
        self.assertNotIn("请先", text)

    def test_completed_landing_page_links_only_existing_outputs_and_shows_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            deliverables = report_dir / "deliverables"
            deliverables.mkdir(parents=True)
            (deliverables / "report.md").write_text("# 报告\n", encoding="utf-8")
            (deliverables / "all-affected-dependencies.md").write_text(
                "# 完整依赖分析\n",
                encoding="utf-8",
            )
            (deliverables / "all-affected-dependencies.csv").write_text(
                "依赖,分析结果\n",
                encoding="utf-8",
            )
            (deliverables / "all-impact-details.md").write_text(
                "# 完整 API 与调用关系\n",
                encoding="utf-8",
            )
            (deliverables / "all-impact-details.csv").write_text(
                "依赖,API,分析结果\n",
                encoding="utf-8",
            )
            (deliverables / "analysis-scope.md").write_text("# 范围\n", encoding="utf-8")
            state = run_step.new_main_state(report_dir)
            state["state"].update(
                {
                    "current_step": "done",
                    "completed_step": "step6",
                    "status": "completed_with_limits",
                    "completion_summary": {
                        "scope_mode": "partial",
                        "included_dependency_count": 1,
                        "available_dependency_count": 3,
                        "confirmed_count": 2,
                        "probable_count": 1,
                        "uncertain_count": 4,
                        "needs_input_count": 3,
                        "not_analyzed_count": 0,
                        "dependency_total_count": 3,
                        "dependency_completed_count": 2,
                        "dependency_incomplete_count": 1,
                        "dependency_confirmed_count": 1,
                        "api_total_count": 10,
                        "api_completed_count": 7,
                        "api_incomplete_count": 3,
                        "api_confirmed_count": 2,
                        "limitations": ["用户选择了部分变化依赖"],
                    },
                }
            )

            run_step.write_report_landing_docs(report_dir, state)
            text = (report_dir / "README.md").read_text(encoding="utf-8")

        self.assertIn("分析范围：部分依赖（1/3）", text)
        self.assertIn(
            "依赖：变化 3，已完成分析 2，未完成分析 1，含确认影响 1。",
            text,
        )
        self.assertIn(
            "API：变化 10，已完成分析 7，未完成分析 3，确认影响 2。",
            text,
        )
        self.assertIn("结论限制：用户选择了部分变化依赖", text)
        self.assertIn("[deliverables/report.md](deliverables/report.md)", text)
        self.assertIn(
            "[deliverables/all-affected-dependencies.md]"
            "(deliverables/all-affected-dependencies.md)",
            text,
        )
        self.assertIn(
            "[deliverables/all-impact-details.md]"
            "(deliverables/all-impact-details.md)",
            text,
        )
        self.assertIn(
            "[deliverables/all-affected-dependencies.csv]"
            "(deliverables/all-affected-dependencies.csv)",
            text,
        )
        self.assertIn(
            "[deliverables/all-impact-details.csv]"
            "(deliverables/all-impact-details.csv)",
            text,
        )
        self.assertIn(
            "[deliverables/analysis-scope.md](deliverables/analysis-scope.md)", text
        )
        self.assertNotIn("evidence/dependencies/dep_changes.csv", text)

    def test_final_completion_counts_named_not_analyzed_subcategories_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            findings_path = report_dir / ".runtime" / "findings" / "s6_findings.json"
            findings_path.parent.mkdir(parents=True)
            probable = {
                "coord": "com.example:demo",
                "api": "com.example.Api.probable",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "user_conclusion": "可能影响",
            }
            needs_input = {
                "coord": "com.example:demo",
                "api": "com.example.Api.needsInput",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "user_conclusion": "需要补充输入",
            }
            residual = {
                "coord": "com.example:demo",
                "api": "com.example.Api.notAnalyzed",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "user_conclusion": "当前无法确认",
            }
            findings_path.write_text(
                json.dumps(
                    {
                        "coverage": {"overall_status": "complete"},
                        "analysis_scope": {"mode": "full"},
                        "p0": [],
                        "p1": [],
                        "p2": [],
                        "probable_impact": [probable],
                        "uncertain": [],
                        "needs_input": [needs_input],
                        "not_analyzed": [probable, needs_input, residual],
                        "diagnostics": [],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            summary = run_step.build_final_completion_summary(report_dir)
            terminal = "\n".join(
                run_step.build_user_runtime_message(
                    "complete", "step6", completion_summary=summary
                )
            )
            landing = "\n".join(
                run_step._landing_status_lines(
                    {
                        "state": {
                            "current_step": "done",
                            "status": summary["status"],
                            "completion_summary": summary,
                        }
                    }
                )
            )

        self.assertEqual(summary["probable_count"], 1)
        self.assertEqual(summary["needs_input_count"], 1)
        self.assertEqual(summary["not_analyzed_count"], 1)
        self.assertEqual(summary["dependency_total_count"], 1)
        self.assertEqual(summary["dependency_completed_count"], 0)
        self.assertEqual(summary["dependency_incomplete_count"], 1)
        self.assertEqual(summary["dependency_confirmed_count"], 0)
        self.assertEqual(summary["api_total_count"], 3)
        self.assertEqual(summary["api_completed_count"], 1)
        self.assertEqual(summary["api_incomplete_count"], 2)
        self.assertEqual(summary["api_confirmed_count"], 0)
        for text in (terminal, landing):
            self.assertIn(
                "依赖：变化 1，已完成分析 0，未完成分析 1，含确认影响 0。",
                text,
            )
            self.assertIn(
                "API：变化 3，已完成分析 1，未完成分析 2，确认影响 0。",
                text,
            )
            self.assertNotIn("建议", text)
            self.assertNotIn("下一步", text)

    def test_upgrade_context_checkpoint_generates_one_human_review_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            context_dir = report_dir / "evidence" / "context"
            context_dir.mkdir(parents=True)
            (context_dir / "context.json").write_text(
                json.dumps(
                    {
                        "base_branch": "release/1.x",
                        "current_branch": "feature/upgrade",
                        "jdk_base": "8",
                        "jdk_current": "17",
                        "springboot_base": "2.7.18",
                        "springboot_current": "3.3.1",
                        "changed_dependencies": [{"coord": "com.acme:demo"}],
                        "source_dirs": ["src/main/java"],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (context_dir / "dep_graph.json").write_text("{}\n", encoding="utf-8")
            manifest_steps = {
                "step2": {
                    "title": "升级上下文",
                    "interaction": {
                        "type": "review",
                        "question": "请确认升级上下文。",
                        "options": [{"id": "continue", "label": "确认范围"}],
                    },
                    "outputs": ["evidence/context/context.json", "evidence/context/dep_graph.json"],
                }
            }

            payload = run_step.build_interaction_payload(
                "step2",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={"target_module": "app"},
                main_state=run_step.new_main_state(report_dir),
            )

            review_path = context_dir / "review.md"
            review = review_path.read_text(encoding="utf-8")
            files = payload.get("files_to_review") or []
            card = "\n".join(run_step.build_user_decision_card(payload))

        self.assertEqual(files, [str(review_path.resolve())])
        self.assertIn("本文件回答：本次升级分析使用了什么范围和版本信息。", review)
        self.assertIn("release/1.x", review)
        self.assertIn("feature/upgrade", review)
        self.assertIn("8 → 17", review)
        self.assertIn("2.7.18 → 3.3.1", review)
        self.assertIn("app", review)
        self.assertIn("目标模块：app", card)
        self.assertNotIn("context.json", card)
        self.assertNotIn("dep_graph.json", card)
        self.assertNotIn("source_dirs_status", card)
        self.assertNotIn("base_branch=", card)

    def test_later_action_persists_paused_user_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            interaction = {
                "step_id": "step4",
                "status": "awaiting_user_input",
                "options": [
                    {"id": "continue", "label": "全量继续"},
                    {"id": "cancel", "label": "稍后处理"},
                ],
            }
            state["state"].update(
                {
                    "current_step": "step5",
                    "completed_step": "step4",
                    "status": "awaiting_user_input",
                    "pending_interaction": interaction,
                }
            )
            run_step.save_main_state(report_dir, state)
            args = SimpleNamespace(
                response_json=json.dumps({"action": "cancel"}, ensure_ascii=False),
                response_file="",
            )

            result = run_step.apply_structured_user_response_if_present(
                args,
                project_dir,
                report_dir,
                state,
                "step5",
            )
            saved = run_step.load_main_state(report_dir)
            landing = (report_dir / "README.md").read_text(encoding="utf-8")

        self.assertEqual(result["early_exit_code"], 0)
        self.assertEqual(saved["state"]["status"], "paused_by_user")
        self.assertEqual(saved["state"]["current_step"], "step5")
        self.assertEqual(saved["state"]["pending_interaction"]["step_id"], "step4")
        self.assertIn("当前状态：已暂停", landing)
        self.assertIn("已保留：依赖 API 变化及之前的正式产物", landing)
        self.assertIn("恢复后：从系统触达证据继续，不重复已完成任务", landing)
        self.assertIn("再次运行分析时，会回到当前确认任务", landing)

    def test_user_decision_card_hides_internal_fields_and_shows_direct_replies(self):
        interaction = {
            "step_id": "step4",
            "question": "Step5 是全量分析，还是只分析部分依赖包？",
            "recommended_action": "依赖包数量不多时，选择全量继续。",
            "options": [
                {"id": "continue", "label": "全量继续"},
                {"id": "rerun_current_step", "label": "补材料后重跑"},
            ],
            "selection_options": [
                {
                    "selection_key": "coord:com.acme:alpha",
                    "coord": "com.acme:alpha",
                    "api_count": 42,
                    "high_risk_api_count": 5,
                    "business_exact_referenced_api_count": 3,
                    "business_candidate_referenced_api_count": 1,
                    "business_reference_occurrence_count": 7,
                    "dependency_source_status": "available",
                    "impact_priority_rank": 1,
                    "recommendation_reason": "业务最终制品直接引用 3 个变更 API",
                }
            ],
            "selection_resolution": {"enabled": True},
            "action_requirements": {"continue": {"required_fields": []}},
            "files_to_review": ["/tmp/.upgrade-report/evidence/api_changes/changed_dependencies.md"],
        }

        lines = run_step.build_user_decision_card(interaction)
        text = "\n".join(lines)

        self.assertIn("当前需要确认：系统触达证据是覆盖全部依赖，还是只分析部分依赖包？", text)
        self.assertIn("推荐动作：依赖包数量不多时，选择全量继续。", text)
        self.assertIn("`com.acme:alpha`", text)
        self.assertIn("直接回复依赖名称或完整坐标", text)
        self.assertIn("完整依赖选择清单", text)
        self.assertIn("你可以直接回复：", text)
        self.assertNotIn("Step5", text)
        self.assertNotIn("selected_targets", text)
        self.assertNotIn("`continue`", text)
        self.assertNotIn("`rerun_current_step`", text)
        self.assertNotIn("coord:com.acme:alpha", text)
        self.assertNotIn("action_requirements", text)
        self.assertNotIn("selection_resolution", text)

    def test_dependency_selection_card_names_full_list_when_candidates_are_truncated(self):
        all_candidates = [
            {
                "selection_key": f"coord:com.acme:lib-{index}",
                "coord": f"com.acme:lib-{index}",
                "api_count": index + 1,
                "high_risk_api_count": index % 3,
                "business_exact_referenced_api_count": max(10 - index, 0),
                "business_candidate_referenced_api_count": 0,
                "business_reference_occurrence_count": max(10 - index, 0),
                "dependency_source_status": "available" if index % 2 else "unavailable",
                "impact_priority_rank": index + 1,
                "recommendation_reason": f"优先级依据 {index + 1}",
                "recommended": index < 10,
            }
            for index in range(37)
        ]
        interaction = {
            "step_id": "step4",
            "question": "请选择系统触达证据的分析范围。",
            "options": [{"id": "continue", "label": "全部分析"}],
            "selection_options": all_candidates[:10],
            "recommended_selection_options": all_candidates[:10],
            "recommended_candidate_count": 10,
            "selection_resolution": {
                "enabled": True,
                "options": all_candidates,
                "source_file": "/project/.upgrade-report/evidence/api_changes/changed_dependencies.md",
            },
            "files_to_review": [
                "/project/.upgrade-report/evidence/api_changes/changed_dependencies.md",
                "/project/.upgrade-report/evidence/api_changes/all_changed_apis.csv",
                "/project/.upgrade-report/evidence/api_changes/summary.txt",
                "/project/.upgrade-report/evidence/api_changes/git_ref_matches.txt",
                "/project/.upgrade-report/evidence/api_changes/timeouts.json",
                "/project/.upgrade-report/evidence/api_changes/all_changed_apis_part_001.csv",
                "/project/.upgrade-report/evidence/api_changes/all_changed_apis_part_002.csv",
            ],
        }

        text = "\n".join(run_step.build_user_decision_card(interaction))

        self.assertIn("覆盖全部 37 个变化依赖", text)
        self.assertIn("Top 10 影响复核优先项，展示 10 / 10 个", text)
        self.assertIn("精确直接引用 API", text)
        self.assertIn("删除、签名变化等变更类型不额外加权", text)
        self.assertIn("依赖源码是否可用只展示分析条件，不参与影响排序", text)
        self.assertIn("其余 27 个候选未在卡片中展开", text)
        self.assertIn(
            "该文件不是普通复核材料；需要选择未展示的依赖时",
            text,
        )
        self.assertNotIn("selected_targets", text)
        self.assertNotIn("完整候选请看下面的文件", text)
        self.assertNotIn("interaction.json", text)
        self.assertIn("all_changed_apis_part_002.csv", text)

    def test_dependency_selection_card_explains_how_to_select_from_full_list(self):
        interaction = {
            "step_id": "step4",
            "question": "请选择系统触达证据的分析范围。",
            "options": [
                {"id": "continue", "label": "继续（全量分析）"},
            ],
            "selection_options": [
                {
                    "selection_key": "coord:com.acme:alpha",
                    "coord": "com.acme:alpha",
                    "api_count": 42,
                    "high_risk_api_count": 5,
                    "business_exact_referenced_api_count": 3,
                    "business_candidate_referenced_api_count": 1,
                    "business_reference_occurrence_count": 7,
                    "dependency_source_status": "available",
                    "impact_priority_rank": 1,
                    "recommendation_reason": "业务最终制品直接引用 3 个变更 API",
                }
            ],
            "recommended_selection_options": [
                {
                    "selection_key": "coord:com.acme:alpha",
                    "coord": "com.acme:alpha",
                    "api_count": 42,
                    "high_risk_api_count": 5,
                    "business_exact_referenced_api_count": 3,
                    "business_candidate_referenced_api_count": 1,
                    "business_reference_occurrence_count": 7,
                    "dependency_source_status": "available",
                    "impact_priority_rank": 1,
                    "recommendation_reason": "业务最终制品直接引用 3 个变更 API",
                }
            ],
            "recommended_candidate_count": 1,
            "selection_resolution": {
                "enabled": True,
                "options": [
                    {
                        "selection_key": "coord:com.acme:alpha",
                        "coord": "com.acme:alpha",
                    },
                    {
                        "selection_key": "coord:com.acme:beta",
                        "coord": "com.acme:beta",
                    },
                ],
            },
            "files_to_review": [
                "/project/.upgrade-report/evidence/api_changes/changed_dependencies.md",
            ],
        }

        text = "\n".join(run_step.build_user_decision_card(interaction))

        self.assertIn("请选择分析范围：", text)
        self.assertIn("1. 全量分析", text)
        self.assertIn("覆盖全部 2 个变化依赖", text)
        self.assertIn("2. 部分分析（仅在明确控制耗时时）", text)
        self.assertIn("Top 1 影响复核优先项，展示 1 / 1 个", text)
        self.assertIn("先比较业务最终制品精确直接引用的变更 API 数", text)
        self.assertIn("不表示系统建议缩小范围，也不代表已经确认影响", text)
        self.assertIn("| 1 | `com.acme:alpha` | 3 | 1 | 7 | 42 | 可用 |", text)
        self.assertIn(
            "完整依赖选择清单：`/project/.upgrade-report/evidence/api_changes/changed_dependencies.md`",
            text,
        )
        self.assertIn("从“依赖包”列复制名称或完整坐标", text)
        self.assertIn("只分析 com.acme:alpha", text)
        self.assertNotIn("selected_targets", text)

    def test_terminal_pause_message_only_shows_user_facing_decision_information(self):
        interaction = {
            "step_id": "step4",
            "title": "jar 包变更对比",
            "question": "请确认依赖 API 变化是否完整。",
            "hard_stop": True,
            "runtime_rules": ["must_wait_for_user_reply"],
            "next_action_rule": "resume_only",
            "resume_command_examples": [{"label": "continue", "command": "python run_step.py --response-json ..."}],
            "options": [
                {"id": "continue", "label": "结果完整，继续分析"},
                {"id": "rerun_current_step"},
            ],
            "files_to_review": ["/tmp/.upgrade-report/evidence/api_changes/changed_dependencies.md"],
        }
        stderr = io.StringIO()
        stdout = io.StringIO()

        with patch.object(sys, "stderr", stderr), patch.object(sys, "stdout", stdout):
            run_step.print_interaction_to_streams(interaction, Path("/tmp/.upgrade-report"))

        text = stderr.getvalue()
        self.assertIn("依赖 API 变化", text)
        self.assertIn("为什么暂停", text)
        self.assertIn("结果完整，继续分析", text)
        self.assertIn("补充信息后重新分析", text)
        self.assertIn("你可以直接回复", text)
        self.assertIn("changed_dependencies.md", text)
        for internal_text in (
            "AWAITING USER INPUT",
            "HARD STOP",
            "RULE:",
            "NEXT ACTION ONLY",
            "continue`",
            "rerun_current_step",
            "interaction.json",
            "main_state",
            "response_schema",
            "--response-json",
        ):
            self.assertNotIn(internal_text, text)
        machine_line = next(line for line in stdout.getvalue().splitlines() if line.startswith("JUA_CONFIRMATION_JSON:"))
        machine_event = json.loads(machine_line.split(":", 1)[1])
        self.assertEqual(machine_event["schema"], "java-upgrade-analyzer.confirmation.v1")
        self.assertEqual(machine_event["event"], "interaction_required")
        self.assertEqual(
            machine_event["user_decision_card"],
            run_step.build_user_decision_card(interaction),
        )
        self.assertNotIn(
            "selected_targets",
            "\n".join(machine_event["user_decision_card"]),
        )

    def test_human_interaction_output_mode_hides_machine_protocol(self):
        interaction = {
            "step_id": "step4",
            "question": "请选择分析范围。",
            "options": [{"id": "continue", "label": "全量继续"}],
        }
        stderr = io.StringIO()
        stdout = io.StringIO()

        with patch.dict(os.environ, {"JUA_INTERACTION_OUTPUT": "human"}), \
                patch.object(sys, "stderr", stderr), patch.object(sys, "stdout", stdout):
            run_step.print_interaction_to_streams(interaction, Path("/tmp/.upgrade-report"))

        self.assertIn("请选择分析范围", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")

    def test_user_task_names_and_manifest_checkpoint_copy_are_human_facing(self):
        expected_names = {
            "step1": "分析对象与依赖范围",
            "step2": "升级上下文",
            "step3": "兼容性线索",
            "step4": "依赖 API 变化",
            "step5": "系统触达证据",
            "step6": "分析报告",
        }
        self.assertEqual(run_step.USER_TASK_NAMES, expected_names)

        manifest = json.loads((ROOT_DIR / "scripts" / "step_manifest.json").read_text(encoding="utf-8"))
        for step in manifest["steps"]:
            self.assertEqual(step["title"], expected_names[step["id"]])
            interaction = step.get("interaction")
            if not interaction:
                continue
            visible_copy = [interaction.get("question", "")]
            visible_copy.extend(option.get("description", "") for option in interaction.get("options", []))
            for copy in visible_copy:
                self.assertIsNone(re.search(r"\bStep\d+\b|\bstep\d+\b", copy), copy)
                self.assertNotIn("action=", copy)
                self.assertNotIn("_step", copy)

    def test_step4_checkpoint_points_dependency_selection_to_markdown_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            api_dir = self._api_changes_dir(report_dir)
            api_dir.mkdir(parents=True)
            with (api_dir / "changed_dependencies.csv").open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["selection_key", "coord", "name", "api_count", "high_risk_api_count", "change_types"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "selection_key": "coord:com.example:demo-lib",
                        "coord": "com.example:demo-lib",
                        "name": "demo-lib",
                        "api_count": "42",
                        "high_risk_api_count": "5",
                        "change_types": "REMOVED",
                    }
                )
            (api_dir / "all_changed_apis.csv").write_text(
                "coord,api_name,api_signature,symbol_kind,change_type,severity\n"
                "com.example:demo-lib,com.example.Demo.removed,(),method,REMOVED,P1\n",
                encoding="utf-8",
            )
            manifest_steps = {
                "step4": {
                    "title": "API 变化分析",
                    "interaction": {
                        "type": "review",
                        "question": "Step5 是全量分析，还是只分析部分依赖包？",
                        "options": [{"id": "continue", "label": "继续"}],
                    },
                    "outputs": ["evidence/api_changes/all_changed_apis.csv"],
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

        checklist_text = "\n".join(payload.get("checklist_lines") or [])
        review_files = "\n".join(payload.get("files_to_review") or [])
        self.assertIn("完整依赖包清单见 changed_dependencies.md", checklist_text)
        self.assertIn("API 级明细不作为普通选择入口", checklist_text)
        self.assertIn("changed_dependencies.md", review_files)
        self.assertNotIn("summary.txt", review_files)
        self.assertNotIn("git_ref_matches.txt", review_files)
        self.assertNotIn("all_changed_apis.csv", review_files)

    def test_user_decision_card_covers_step1_missing_input_request(self):
        interaction = run_step.build_step1_preflight_interaction({})

        lines = run_step.build_user_decision_card(interaction)
        text = "\n".join(lines)

        self.assertIn("需要补充的信息：", text)
        self.assertIn("可选输入方式：", text)
        self.assertIn("升级前构建产物", text)
        self.assertIn("升级后构建产物", text)
        self.assertIn("基准分支", text)
        self.assertIn("当前分支", text)
        self.assertIn("你可以直接回复：", text)
        self.assertIn("目标模块是 app", text)
        self.assertNotIn("response_schema", text)
        self.assertNotIn("input_normalization", text)
        self.assertNotIn("action_requirements", text)

    def test_user_decision_card_covers_dependency_source_rerun_without_generic_continue_example(self):
        interaction = {
            "step_id": "step5",
            "question": "需要补充依赖源码目录后重跑 Step5。",
            "options": [
                {"id": "rerun_current_step", "label": "补源码后重跑"},
                {"id": "cancel", "label": "取消"},
            ],
            "response_schema": {
                "type": "object",
                "properties": {
                    "action": {"type": "string"},
                    "dependency_source_dirs": {"type": "array"},
                },
            },
            "action_requirements": {
                "rerun_current_step": {"at_least_one_of": ["dependency_source_dirs"]}
            },
        }

        text = "\n".join(run_step.build_user_decision_card(interaction))

        self.assertIn("依赖源码目录是 /path/to/dependency-repo，补充后重跑", text)
        self.assertNotIn("“继续”", text)
        self.assertNotIn("action_requirements", text)

    def test_user_decision_card_humanizes_option_descriptions(self):
        interaction = {
            "step_id": "step5",
            "question": "请选择后续处理方式。",
            "options": [
                {
                    "id": "restart_from_step",
                    "label": "从指定步骤重跑",
                    "description": "若需要回到更早步骤修正输入，可指定 restart_step_id 后重跑。",
                },
                {
                    "id": "rerun_current_step",
                    "label": "降级后重跑",
                    "description": "相关 API 将标记为 not_analyzed。",
                },
            ],
        }

        text = "\n".join(run_step.build_user_decision_card(interaction))

        self.assertIn("重跑起始步骤", text)
        self.assertIn("本次未完成分析", text)
        self.assertNotIn("restart_step_id", text)
        self.assertNotIn("not_analyzed", text)

    def test_step5_missing_source_interaction_question_uses_human_field_name(self):
        interaction = {
            "step_id": "step5",
            "reason_code": "step5_dependency_source_mapping_missing",
            "question": "请补充 dependency_source_dirs 后重跑 Step5。",
            "response_schema": {
                "type": "object",
                "properties": {
                    "action": {"type": "string"},
                    "dependency_source_dirs": {"type": "array"},
                },
            },
        }

        annotated = run_step.annotate_dependency_source_dirs_interaction(
            interaction,
            {},
            Path("/tmp/.upgrade-report"),
        )

        self.assertIn("依赖源码目录", annotated["question"])
        self.assertNotIn("dependency_source_dirs", annotated["question"])
        self.assertIn("dependency_source_dirs", annotated["response_schema"]["properties"])

    def test_apply_structured_user_response_resolves_name_selected_targets_without_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            self._api_changes_dir(report_dir).mkdir(parents=True, exist_ok=True)
            with (self._api_changes_dir(report_dir) / "all_changed_apis.csv").open("w", encoding="utf-8", newline="") as fh:
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
                state["step5"]["input"]["step5_selected_names"],
                ["demo-lib"],
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

    def test_build_canonical_user_response_hoists_restart_step_from_set(self):
        canonical = run_step.build_canonical_user_response(
            {
                "intent_patch": {
                    "action": "restart_from_step",
                    "set": {"restart_step_id": "step2"},
                }
            }
        )

        self.assertEqual(canonical["restart_step_id"], "step2")
        self.assertEqual(canonical["__intent_patch"]["set"], {})
        self.assertEqual(
            canonical["__intent_patch"]["restart_step_id"],
            "step2",
        )

    def test_build_canonical_user_response_rejects_conflicting_restart_steps(self):
        with self.assertRaisesRegex(run_step.StepError, "restart_step_id.*冲突"):
            run_step.build_canonical_user_response(
                {
                    "intent_patch": {
                        "action": "restart_from_step",
                        "restart_step_id": "step2",
                        "set": {"restart_step_id": "step3"},
                    }
                }
            )

    def test_build_canonical_user_response_allows_action_only_intent_patch(self):
        canonical = run_step.build_canonical_user_response(
            {"intent_patch": {"action": "continue"}}
        )

        self.assertEqual(canonical["action"], "continue")
        self.assertEqual(canonical["__intent_patch"]["set"], {})

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

    def test_intent_patch_clear_resets_accumulated_manual_coord_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            state = run_step.new_main_state(project_dir / ".upgrade-report")
            pending = {
                "step_id": "step1",
                "status": "awaiting_user_input",
                "kind": "input_request",
            }
            state["step1"]["input"] = {
                "manual_coord_overrides": [
                    "old-lib:1.0 -> com.example:old-lib",
                ],
            }

            state, cleared = run_step.apply_user_response_to_main_state(
                state,
                pending,
                {
                    "intent_patch": {
                        "action": "rerun_current_step",
                        "set": {
                            "manual_coord_overrides": [
                                "discarded-lib:1.0 -> com.example:discarded-lib",
                            ],
                        },
                        "clear": ["manual_coord_overrides"],
                    }
                },
                project_dir,
                target_step_id="step1",
            )

            self.assertNotIn("manual_coord_overrides", cleared)
            self.assertNotIn("manual_coord_overrides", state["step1"]["input"])

            _, resubmitted = run_step.apply_user_response_to_main_state(
                state,
                pending,
                {
                    "action": "rerun_current_step",
                    "manual_coord_overrides": [
                        "new-lib:2.0 -> com.example:new-lib",
                    ],
                },
                project_dir,
                target_step_id="step1",
            )

            self.assertEqual(
                resubmitted["manual_coord_overrides"],
                ["new-lib:2.0 -> com.example:new-lib"],
            )

    def test_step2_continue_with_clear_invalidates_outputs_for_one_normal_rerun(self):
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

            with patch.object(run_step, "refresh_step2_outputs") as refresh_mock:
                run_step.handle_step2_resume_followups(
                    updated_state,
                    report_dir,
                    "step2",
                    "step2",
                    "continue",
                    user_response,
                )

            refresh_mock.assert_not_called()
            self.assertNotIn("dependency_source_dirs", updated_state["step2"]["input"])
            self.assertEqual(updated_state["step2"]["output"], {})
            self.assertEqual(updated_state["step3"], run_step.empty_step_state())

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
            self.assertEqual(annotated["question"], "请确认 git refs 后重跑 Step4。")
            self.assertIn("仅当现有目录不正确", annotated["response_schema"]["properties"]["dependency_source_dirs"]["description"])

    def test_step5_review_does_not_require_removed_target_source_when_analysis_did_not_need_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            dep_repo = Path(tmp) / "dependency-repo"
            module = dep_repo / "helper"
            (module / "src/main/java").mkdir(parents=True)
            (dep_repo / ".git").mkdir()
            (module / "pom.xml").write_text(
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>com.example</groupId><artifactId>helper</artifactId><version>1</version>"
                "</project>",
                encoding="utf-8",
            )
            self._write_text(
                self._api_changes_dir(report_dir) / "all_changed_apis.csv",
                "coord,new_version,change_type,api_name,symbol_kind\n"
                "org.slf4j:slf4j-api,-,REMOVED,org.slf4j.Logger,class\n",
                encoding="utf-8",
            )
            self._write_text(
                self._call_chain_dir(report_dir) / "summary.json",
                json.dumps({
                    "reachable": 1,
                    "uncertain": 0,
                    "not_analyzed": 0,
                    "reachable_apis": [{
                        "coord": "org.slf4j:slf4j-api",
                        "api": "org.slf4j.Logger",
                        "reason_code": "BUSINESS_ARTIFACT_BYTECODE_USAGE",
                    }],
                }),
                encoding="utf-8",
            )
            interaction = {
                "step_id": "step5",
                "question": "请确认 Step5 结果。",
                "response_schema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string"},
                        "dependency_source_dirs": {"type": "array"},
                    },
                },
            }

            annotated = run_step.annotate_dependency_source_dirs_interaction(
                interaction,
                {"dependency_source_dirs": [str(dep_repo.resolve())]},
                report_dir,
            )

        self.assertNotIn("仍未覆盖这些目标依赖坐标", annotated["question"])
        self.assertEqual(annotated["question"], "请确认 Step5 结果。")

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

        with self.assertRaisesRegex(run_step.StepError, "依赖源码目录"):
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

    def test_validate_pending_interaction_response_accepts_step5_rerun_with_selected_coords(self):
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
                    "step5_selected_coords": {"type": "array"},
                },
            },
            "action_requirements": {
                "rerun_current_step": {
                    "at_least_one_of": ["dependency_source_dirs", "allow_degraded"],
                }
            },
        }

        run_step.validate_pending_interaction_response(
            interaction,
            {
                "action": "rerun_current_step",
                "step5_selected_coords": ["com.example:demo-lib"],
            },
        )

    def test_validate_pending_interaction_response_requires_japicmp_confirmation(self):
        interaction = {
            "step_id": "step4",
            "reason_code": "step4_japicmp_missing_need_resolution",
            "response_schema": {
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "japicmp_jar": {"type": "string"},
                    # Simulate a stale checkpoint produced before the strict
                    # parser policy. Validation itself must still reject this
                    # bypass rather than relying on the schema omission.
                    "allow_degraded": {"type": "boolean"},
                },
            },
        }

        with self.assertRaises(run_step.StepError):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "rerun_current_step"},
            )

        run_step.validate_pending_interaction_response(
            interaction,
            {"action": "rerun_current_step", "japicmp_jar": "/tmp/japicmp.jar"},
        )
        with self.assertRaises(run_step.StepError):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "rerun_current_step", "allow_degraded": True},
            )

    def test_validate_pending_interaction_response_requires_tree_sitter_install_confirmation(self):
        interaction = {
            "step_id": "step5",
            "reason_code": "step5_tree_sitter_missing_need_resolution",
            "response_schema": {
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "tree_sitter_installed": {"type": "boolean"},
                    # A hand-crafted or stale response cannot re-enable the
                    # removed parser-degradation path.
                    "allow_degraded": {"type": "boolean"},
                },
            },
        }

        with self.assertRaises(run_step.StepError):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "rerun_current_step"},
            )

        run_step.validate_pending_interaction_response(
            interaction,
            {"action": "rerun_current_step", "tree_sitter_installed": True},
        )
        with self.assertRaises(run_step.StepError):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "rerun_current_step", "allow_degraded": True},
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

    def test_resume_command_uses_powershell_safe_argument_quoting(self):
        command = run_step._format_resume_shell_command(
            [
                r"C:\Program Files\Python\python.exe",
                r"C:\work dir\run_step.py",
                "--response-json",
                """{"notes":"O'Brien"}""",
            ],
            platform_name="win32",
        )

        self.assertTrue(command.startswith("& 'C:\\Program Files\\Python\\python.exe'"))
        self.assertIn("'C:\\work dir\\run_step.py'", command)
        self.assertIn("""'{"notes":"O''Brien"}'""", command)

    def test_continue_resume_example_does_not_fill_optional_scope_fields(self):
        examples = run_step.build_resume_command_examples(
            [{"id": "continue", "label": "继续（全量或定向分析）"}],
            [],
            {
                "action": {"type": "string"},
                "dependency_source_dirs": {"type": "array"},
                "selected_targets": {"type": "array"},
                "strict_risk_gate": {"type": "boolean"},
            },
            Path("/tmp/project"),
            Path("/tmp/project/.upgrade-report"),
        )

        command = examples[0]["command"]
        self.assertIn('"action": "continue"', command)
        self.assertNotIn("依赖包完整坐标", command)
        self.assertNotIn("dependency_source_dirs", command)
        self.assertNotIn("strict_risk_gate", command)

    def test_continue_resume_example_fills_every_required_context_field(self):
        examples = run_step.build_resume_command_examples(
            [{"id": "continue", "label": "补齐后继续"}],
            ["jdk_base", "jdk_current", "source_dirs"],
            {
                "action": {"type": "string"},
                "jdk_base": {"type": "string"},
                "jdk_current": {"type": "string"},
                "source_dirs": {"type": "array"},
            },
            Path("/tmp/project"),
            Path("/tmp/project/.upgrade-report"),
        )

        command = examples[0]["command"]
        self.assertIn('"jdk_base": "8"', command)
        self.assertIn('"jdk_current": "17"', command)
        self.assertIn('"source_dirs"', command)

    def test_source_mapping_resume_examples_cover_accept_and_decline(self):
        examples = run_step.build_resume_command_examples(
            [{"id": "continue", "label": "说明后继续"}],
            ["accept_suggested_mappings"],
            {
                "action": {"type": "string"},
                "accept_suggested_mappings": {"type": "boolean"},
            },
            Path("/tmp/project"),
            Path("/tmp/project/.upgrade-report"),
        )

        decision_examples = [item for item in examples if item["action"] == "continue"]
        self.assertEqual(len(decision_examples), 2)
        self.assertIn('"accept_suggested_mappings": true', decision_examples[0]["command"])
        self.assertIn('"accept_suggested_mappings": false', decision_examples[1]["command"])

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

    def test_selection_protocol_rebuilds_normalization_examples_after_adding_selected_targets(self):
        interaction = run_step.apply_interaction_protocol_enhancements(
            {
                "step_id": "step4",
                "options": [{"id": "continue", "label": "继续"}],
                "response_schema": {
                    "type": "object",
                    "required": ["action"],
                    "properties": {
                        "action": {"type": "string"},
                        "step5_selected_coords": {"type": "array"},
                    },
                },
                "required_fields": ["step5_selected_coords"],
                "selection_options": [{"coord": "com.example:demo-lib", "name": "demo-lib"}],
                "input_normalization": run_step.build_input_normalization_contract(
                    [{"id": "continue", "label": "继续"}],
                    [],
                    {
                        "action": {"type": "string"},
                        "step5_selected_coords": {"type": "array"},
                    },
                ),
            },
            "step4",
        )

        normalization = interaction["input_normalization"]
        self.assertEqual(
            interaction["required_fields"],
            ["selected_targets", "scope_mode"],
        )
        self.assertIn("selected_targets", normalization["field_hints"])
        self.assertIn("scope_mode", normalization["field_hints"])
        self.assertIn("selected_targets", interaction["response_schema"]["properties"])
        self.assertIn("scope_mode", interaction["response_schema"]["properties"])
        self.assertNotIn("step5_selected_coords", interaction["response_schema"]["properties"])
        self.assertNotIn("step5_selected_names", interaction["response_schema"]["properties"])
        example = normalization["action_examples"][0]["normalized_response_example"]
        self.assertEqual(
            example["intent_patch"]["set"],
            {
                "selected_targets": ["com.example:demo-lib"],
                "scope_mode": "partial",
            },
        )
        self.assertNotIn("step5_selected_coords", json.dumps(example, ensure_ascii=False))

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

    def test_validate_pending_interaction_response_allows_name_selected_targets(self):
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

        run_step.validate_pending_interaction_response(
            interaction,
            {
                "action": "continue",
                "scope_mode": "partial",
                "selected_targets": ["demo-lib"],
            },
        )
        normalized = run_step.resolve_selected_targets(
            interaction.get("selection_resolution") or {},
            ["demo-lib"],
        )

        self.assertEqual(normalized["selected_targets"], ["demo-lib"])
        self.assertEqual(normalized["step5_selected_coords"], [])
        self.assertEqual(normalized["step5_selected_names"], ["demo-lib"])

    def test_step4_scope_confirmation_rejects_notes_only_partial_selection(self):
        selection_options = run_step.build_interaction_selection_options(
            [
                {
                    "coord": "org.apache.seata:seata-common",
                    "name": "seata-common",
                },
                {
                    "coord": "net.sf.json-lib:json-lib:jdk15",
                    "name": "json-lib",
                },
            ]
        )
        # Simulate a persisted checkpoint created before scope_mode was added.
        interaction = {
            "step_id": "step4",
            "options": [{"id": "continue", "label": "继续"}],
            "response_schema": {
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "selected_targets": {"type": "array"},
                    "notes": {"type": "string"},
                },
            },
            "selection_resolution": run_step.build_selection_resolution(
                selection_options
            ),
        }

        with self.assertRaisesRegex(run_step.StepError, "notes 不参与范围控制"):
            run_step.validate_pending_interaction_response(
                interaction,
                {
                    "action": "continue",
                    "notes": (
                        "只分析 org.apache.seata:seata-common 和 "
                        "net.sf.json-lib:json-lib:jdk15"
                    ),
                },
            )

    def test_step4_scope_confirmation_requires_consistent_explicit_mode(self):
        interaction = run_step.apply_interaction_protocol_enhancements(
            {
                "step_id": "step4",
                "options": [{"id": "continue", "label": "继续"}],
                "response_schema": {
                    "type": "object",
                    "required": ["action"],
                    "properties": {
                        "action": {"type": "string"},
                        "notes": {"type": "string"},
                    },
                },
                "selection_options": [
                    {
                        "coord": "org.apache.seata:seata-common",
                        "name": "seata-common",
                    }
                ],
            },
            "step4",
        )

        with self.assertRaisesRegex(run_step.StepError, "scope_mode"):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "continue", "notes": "全量分析"},
            )
        with self.assertRaisesRegex(run_step.StepError, "非空 selected_targets"):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "continue", "scope_mode": "partial"},
            )
        with self.assertRaisesRegex(run_step.StepError, "不能同时提供 selected_targets"):
            run_step.validate_pending_interaction_response(
                interaction,
                {
                    "action": "continue",
                    "scope_mode": "full",
                    "selected_targets": ["org.apache.seata:seata-common"],
                },
            )
        run_step.validate_pending_interaction_response(
            interaction,
            {"action": "continue", "scope_mode": "full"},
        )

    def test_step5_checkpoint_allows_selected_targets_from_step4_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            s4_dir = self._api_changes_dir(report_dir)
            s4_dir.mkdir(parents=True)
            with (s4_dir / "all_changed_apis.csv").open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=run_step.ALL_CHANGED_APIS_FIELDS)
                writer.writeheader()
                writer.writerow({
                    "coord": "com.example:demo-lib",
                    "api_name": "com.example.Demo.removed",
                    "api_simple": "removed",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                })
            manifest_steps = {
                "step5": {
                    "title": "调用链分析",
                    "interaction": {
                        "type": "review",
                        "question": "请确认 Step5 结果。",
                        "options": [
                            {"id": "rerun_current_step", "label": "重跑"},
                            {"id": "continue", "label": "继续"},
                        ],
                    },
                    "outputs": ["evidence/call_chain/summary.json"],
                }
            }

            payload = run_step.build_interaction_payload(
                "step5",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={},
                main_state=run_step.new_main_state(report_dir),
            )

        properties = payload["response_schema"]["properties"]
        self.assertIn("selected_targets", properties)
        self.assertNotIn("step5_selected_coords", properties)
        self.assertNotIn("step5_selected_names", properties)
        self.assertTrue(payload["selection_resolution"]["enabled"])
        run_step.validate_pending_interaction_response(
            payload,
            {"action": "rerun_current_step", "selected_targets": ["com.example:demo-lib"]},
        )

    def test_step5_checkpoint_review_files_point_to_alerts_not_summary_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            manifest_steps = {
                "step5": {
                    "title": "调用链分析",
                    "interaction": {
                        "type": "review",
                        "question": "请确认 Step5 结果。",
                        "options": [{"id": "continue", "label": "继续"}],
                    },
                    "outputs": ["evidence/call_chain/summary.json"],
                }
            }

            payload = run_step.build_interaction_payload(
                "step5",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={},
                main_state=run_step.new_main_state(report_dir),
            )

        review_files = "\n".join(payload.get("files_to_review") or [])
        self.assertIn("evidence/call_chain/alerts.csv", review_files)
        self.assertNotIn("summary.txt", review_files)
        self.assertNotIn("summary.json", review_files)

    def test_step5_checkpoint_uses_reader_facing_conclusion_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            s5_dir = self._call_chain_dir(report_dir)
            s5_dir.mkdir(parents=True)
            (s5_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "reachable": 1,
                        "not_impacted": 1,
                        "user_conclusion_summary": {
                            "confirmed_impact": 1,
                            "probable_impact": 2,
                            "confirmed_no_impact": 1,
                            "inconclusive": 3,
                            "input_required": 4,
                        },
                        "quality_gate": {"inconclusive": 3, "needs_input": 4},
                        "uncertain_apis": [
                            {
                                "severity": "P1",
                                "coord": "com.example:demo",
                                "api": "com.example.Demo.changed",
                                "user_conclusion": "当前无法确认",
                                "reason": "字节码命中，但没有找到从当前系统入口到该调用点的完整路径",
                            }
                        ],
                        "not_analyzed_apis": [
                            {
                                "severity": "P1",
                                "coord": "com.example:needs-input",
                                "api": "com.example.Input.changed",
                                "user_conclusion": "需要补充输入",
                                "reason": "缺少依赖源码目录",
                            }
                        ],
                        "not_found_apis": [
                            {
                                "severity": "P2",
                                "coord": "com.example:not-found",
                                "api": "com.example.NotFound.changed",
                                "reason": "静态分析没有发现调用路径",
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            manifest_steps = {
                "step5": {
                    "title": "调用链分析",
                    "interaction": {
                        "type": "review",
                        "question": "请确认 Step5 结果。",
                        "options": [{"id": "continue", "label": "继续"}],
                    },
                    "outputs": ["evidence/call_chain/summary.json"],
                }
            }

            payload = run_step.build_interaction_payload(
                "step5",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={},
                main_state=run_step.new_main_state(report_dir),
            )

        checklist_text = "\n".join(payload.get("checklist_lines") or [])
        self.assertIn("需人工复核=3", checklist_text)
        self.assertIn("缺少输入=4", checklist_text)
        self.assertIn("not_analyzed（输入不足或分析未完成）=1", checklist_text)
        self.assertIn(
            "not_found_in_static_analysis（当前静态范围未找到路径）=1",
            checklist_text,
        )
        self.assertIn("需人工复核示例", checklist_text)
        self.assertIn("缺少依赖源码/构建产物示例", checklist_text)
        self.assertNotIn("当前无法确认=", checklist_text)
        self.assertNotIn("当前无法确认示例", checklist_text)

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

    def test_build_run_context_normalizes_string_source_repo_hints(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            repo_dir = project_dir / "dependency-repo"
            repo_dir.mkdir()
            (repo_dir / "pom.xml").write_text(
                "<project><modelVersion>4.0.0</modelVersion>"
                "<groupId>com.example</groupId><artifactId>demo-lib</artifactId>"
                "<version>1.0</version></project>",
                encoding="utf-8",
            )
            args = self._make_default_args(project_dir, project_dir / ".upgrade-report")
            args.source_repo_hints = [str(repo_dir)]

            run_context = run_step.build_run_context(args, {}, {})

        self.assertEqual(len(run_context["source_repo_hints"]), 1)
        self.assertEqual(run_context["source_repo_hints"][0]["repo_path"], str(repo_dir.resolve()))
        self.assertEqual(
            run_context["source_repo_hints"][0]["repo_inferred_coords"],
            ["com.example:demo-lib"],
        )

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

    def test_non_pending_restart_reuses_latest_step_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"].update({
                "current_step": "step5",
                "completed_step": "step4",
                "status": "completed",
            })
            state["step2"]["input"] = {"source_dirs": [str(project_dir / "src/main/java")]}
            state["step5"]["input"] = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str(project_dir / "src/main/java")],
            }
            args = SimpleNamespace(step="auto")
            stderr = io.StringIO()

            with patch.object(sys, "stderr", stderr):
                result = run_step.apply_non_pending_structured_response(
                    args,
                    project_dir,
                    report_dir,
                    state,
                    {
                        "action": "restart_from_step",
                        "restart_step_id": "step2",
                    },
                )

            self.assertEqual(result["step_id"], "step2")
            self.assertEqual(result["main_state"]["step2"]["input"]["base_branch"], "base")
            self.assertEqual(result["main_state"]["step2"]["input"]["current_branch"], "current")
            self.assertIn("分析对象与依赖范围及之前的正式产物继续保留", stderr.getvalue())
            self.assertIn("升级上下文及之后的产物会按新输入重建", stderr.getvalue())

    def test_blocked_system_state_allows_action_only_rerun(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            retained_path = (
                run_step.evidence_static_scan_dir(report_dir)
                / "s3_jdk_removed_api.csv"
            )
            incomplete_path = (
                run_step.step4_api_changes_dir(report_dir)
                / "partial.csv"
            )
            self._write_text(retained_path, "retained\n")
            self._write_text(incomplete_path, "incomplete\n")
            state = run_step.new_main_state(report_dir)
            state["state"].update({
                "current_step": "step4",
                "completed_step": "step3",
                "status": "blocked_by_system",
                "blocking_reason": "temporary Python failure",
            })
            state["step3"]["output"] = {"completed": True}
            state["step4"]["input"] = {
                "base_branch": "base",
                "current_branch": "current",
            }
            state["step4"]["output"] = {"partial": True}

            with patch.object(sys, "stderr", io.StringIO()):
                result = run_step.apply_non_pending_structured_response(
                    SimpleNamespace(step="auto"),
                    project_dir,
                    report_dir,
                    state,
                    {"action": "rerun_current_step"},
                )

            self.assertEqual(result["step_id"], "step4")
            self.assertEqual(state["state"]["status"], "ready")
            self.assertIsNone(state["state"]["blocking_reason"])
            self.assertEqual(state["step3"]["output"], {"completed": True})
            self.assertEqual(state["step4"]["input"]["base_branch"], "base")
            self.assertEqual(state["step4"]["output"], {})
            self.assertTrue(retained_path.exists())
            self.assertFalse(incomplete_path.exists())

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

    def test_execute_step1_accepts_gradle_run_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            (project_dir / "settings.gradle").write_text("include ':app'\n", encoding="utf-8")
            (project_dir / "build.gradle").write_text("group = 'com.acme'\n", encoding="utf-8")
            (project_dir / "app").mkdir()
            (project_dir / "app/build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
            (project_dir / "app/src/main/java").mkdir(parents=True)
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "tool": "gradle",
                "base_branch": "main",
                "current_branch": "feature/demo",
                "target_module": ":app",
            }
            captured = []
            with patch.object(run_step, "run_python", side_effect=lambda name, *_args, **_kwargs: captured.append(name)), \
                    patch.object(run_step, "ensure_exists"), \
                    patch.object(run_step, "run_gate"), \
                    patch.object(run_step, "build_interaction_payload", return_value={}):
                run_step.execute_step(
                    "step1",
                    args,
                    {"step1": {"gate": "step1_scope"}},
                    run_context,
                )

        self.assertEqual(captured, ["s1_dep_diff.py"])

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
                    r"checkpoint 或修正 \.runtime/state/main_state\.json.*两个不同分支",
                ):
                    run_step.execute_step("step2", args, manifest_steps, run_context)

    def test_refresh_step2_outputs_does_not_pass_business_inputs_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            self._write_text(run_step.step1_dep_changes_path(report_dir), "coord\n", encoding="utf-8")
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
            self._write_text(run_step.step2_context_path(report_dir), "{}", encoding="utf-8")
            self._write_text(run_step.step1_current_resolved_path(report_dir), "coord\n", encoding="utf-8")
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
            self._write_text(run_step.step1_dep_changes_path(report_dir),
                "coord,change_type,resolution_status,old_version,new_version\n"
                "com.example:demo-lib,升级,resolved,1.0.0,2.0.0\n",
                encoding="utf-8",
            )
            self._write_text(run_step.step2_context_path(report_dir),
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

    def test_run_python_emits_heartbeat_during_silent_long_phase(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            stderr = io.StringIO()

            def slow_run_cmd(*_args, **_kwargs):
                time.sleep(0.06)
                return "", "", 0

            with patch.dict(
                os.environ,
                {"JUA_HEARTBEAT_INTERVAL_SECONDS": "0.01"},
            ), patch.object(
                run_step,
                "run_cmd",
                side_effect=slow_run_cmd,
            ), patch.object(sys, "stderr", stderr):
                run_step.run_python(
                    "s3_scan.py",
                    ["--all"],
                    tmp,
                    report_dir=report_dir,
                )

            progress_path = report_dir / ".runtime" / "observability" / "progress.jsonl"
            events = [
                json.loads(line)
                for line in progress_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertIn("[进度][兼容性线索][运行中]", stderr.getvalue())
        self.assertTrue(any(item.get("phase") == "heartbeat" for item in events))

    def test_step5_heartbeat_uses_reliable_completed_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            progress_snapshot = (
                run_step.runtime_observability_dir(report_dir)
                / run_step.STEP5_PROGRESS_FILE
            )
            run_step.write_json(
                progress_snapshot,
                {
                    "schema": "java-upgrade-analyzer.step5-progress.v1",
                    "step_id": "step5",
                    "phase": "trace",
                    "status": "running",
                    "completed": 2606,
                    "total": 2953,
                    "elapsed_sec": 1500.0,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            stderr = io.StringIO()

            def slow_run_cmd(*_args, **_kwargs):
                time.sleep(0.06)
                return "", "", 0

            with patch.dict(
                os.environ,
                {"JUA_HEARTBEAT_INTERVAL_SECONDS": "0.01"},
            ), patch.object(
                run_step,
                "run_cmd",
                side_effect=slow_run_cmd,
            ), patch.object(sys, "stderr", stderr):
                run_step.run_python(
                    "s5_call_chain_engine_integrated.py",
                    [],
                    tmp,
                    report_dir=report_dir,
                )

        self.assertIn("[2606/2953]", stderr.getvalue())
        self.assertIn("[88.2%]", stderr.getvalue())
        self.assertIn("预计剩余约", stderr.getvalue())

    def test_step5_heartbeat_omits_eta_for_stale_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            progress_snapshot = (
                run_step.runtime_observability_dir(report_dir)
                / run_step.STEP5_PROGRESS_FILE
            )
            run_step.write_json(
                progress_snapshot,
                {
                    "schema": "java-upgrade-analyzer.step5-progress.v1",
                    "step_id": "step5",
                    "phase": "trace",
                    "status": "running",
                    "completed": 2606,
                    "total": 2953,
                    "elapsed_sec": 1500.0,
                    "updated_at": "2000-01-01T00:00:00+00:00",
                },
            )
            stderr = io.StringIO()

            def slow_run_cmd(*_args, **_kwargs):
                time.sleep(0.04)
                return "", "", 0

            with patch.dict(
                os.environ,
                {"JUA_HEARTBEAT_INTERVAL_SECONDS": "0.01"},
            ), patch.object(
                run_step,
                "run_cmd",
                side_effect=slow_run_cmd,
            ), patch.object(sys, "stderr", stderr):
                run_step.run_python(
                    "s5_call_chain_engine_integrated.py",
                    [],
                    tmp,
                    report_dir=report_dir,
                )

        self.assertIn("[2606/2953]", stderr.getvalue())
        self.assertIn("无新增完成项", stderr.getvalue())
        self.assertNotIn("预计剩余约", stderr.getvalue())

    def test_keyboard_interrupt_cleans_partial_current_step_and_can_resume_safely(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            project_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["state"].update(
                {
                    "current_step": "step3",
                    "completed_step": "step2",
                    "status": "ready",
                }
            )
            state["step3"]["input"] = {"source_dirs": [str(project_dir)]}
            run_step.save_main_state(report_dir, state)
            partial_output = (
                report_dir / "evidence" / "static_scan" / "s3_jdk_removed_api.csv"
            )
            partial_output.parent.mkdir(parents=True)
            partial_output.write_text("partial\n", encoding="utf-8")
            stderr = io.StringIO()

            with patch.object(
                run_step,
                "load_manifest",
                return_value=({}, {"step3": {"gate": "scan", "interaction": None}}),
            ), patch.object(
                run_step,
                "detect_integrity_repair_step",
                return_value="",
            ), patch.object(
                run_step,
                "execute_step",
                side_effect=KeyboardInterrupt,
            ), patch.object(sys, "stderr", stderr):
                exit_code = run_step.main(
                    [
                        "--step", "auto",
                        "--project-dir", str(project_dir),
                        "--report-dir", str(report_dir),
                    ],
                    _skip_environment_contract=True,
                )

            saved = run_step.load_main_state(report_dir)
            landing = (report_dir / "README.md").read_text(encoding="utf-8")
            partial_exists_after = partial_output.exists()

        self.assertEqual(exit_code, run_step.EXIT_INTERRUPTED)
        self.assertEqual(saved["state"]["status"], "paused_by_user")
        self.assertEqual(saved["state"]["current_step"], "step3")
        self.assertEqual(saved["state"]["completed_step"], "step2")
        self.assertFalse(partial_exists_after)
        self.assertIn("已安全停止当前任务", stderr.getvalue())
        self.assertIn("从兼容性线索重新开始", stderr.getvalue())
        self.assertIn("从当前任务安全重试", landing)

    def test_completed_integrity_check_repairs_from_earliest_missing_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            for relative_path in (
                "evidence/context/context.json",
                "evidence/api_changes/all_changed_apis.csv",
                "evidence/call_chain/summary.json",
            ):
                path = report_dir / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}\n", encoding="utf-8")

            repair_step = run_step.detect_integrity_repair_step("step6", report_dir)

        self.assertEqual(repair_step, "step1")

    def test_cli_main_hides_unexpected_traceback_and_records_internal_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            stderr = io.StringIO()

            with patch.object(
                run_step,
                "main",
                side_effect=RuntimeError("internal detail must stay private"),
            ), patch.object(sys, "stderr", stderr):
                exit_code = run_step.cli_main(["--report-dir", str(report_dir)])

            diagnostic_path = (
                report_dir / ".runtime" / "observability" / "internal_error.json"
            )
            diagnostic = json.loads(diagnostic_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 1)
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertNotIn("internal detail must stay private", stderr.getvalue())
        self.assertIn("已停止以避免生成不完整结论", stderr.getvalue())
        self.assertEqual(diagnostic["error_type"], "RuntimeError")
        self.assertIn("internal detail must stay private", diagnostic["traceback"])

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

    def test_full_continue_clears_previous_step4_and_step5_target_selection(self):
        for response_set in ({}, {"selected_targets": []}):
            with self.subTest(response_set=response_set), tempfile.TemporaryDirectory() as tmp:
                project_dir = Path(tmp)
                report_dir = project_dir / ".upgrade-report"
                report_dir.mkdir(parents=True)
                state = run_step.new_main_state(report_dir)
                state["step4"]["input"] = {
                    "step5_selected_coords": ["com.example:previous"],
                    "step5_selected_names": ["previous"],
                }
                state["step5"]["input"] = {
                    "step5_selected_coords": ["com.example:previous"],
                    "step5_selected_names": ["previous"],
                }
                pending_interaction = run_step.apply_interaction_protocol_enhancements(
                    {
                        "step_id": "step4",
                        "kind": "review",
                        "options": [{"id": "continue", "label": "继续"}],
                        "response_schema": {
                            "type": "object",
                            "required": ["action"],
                            "properties": {"action": {"type": "string"}},
                        },
                        "selection_options": [{"coord": "com.example:previous", "name": "previous"}],
                    },
                    "step4",
                    project_dir=project_dir,
                    report_dir=report_dir,
                )

                updated_state, _ = run_step.apply_user_response_to_main_state(
                    state,
                    pending_interaction,
                    {"intent_patch": {"action": "continue", "set": response_set}},
                    project_dir,
                    target_step_id="step4",
                )
                run_step.handle_step4_resume_followups(
                    updated_state,
                    report_dir,
                    "step4",
                    "continue",
                )

                self.assertNotIn("step5_selected_coords", updated_state["step4"]["input"])
                self.assertNotIn("step5_selected_names", updated_state["step4"]["input"])
                self.assertNotIn("step5_selected_coords", updated_state["step5"]["input"])
                self.assertNotIn("step5_selected_names", updated_state["step5"]["input"])

    def test_new_target_selection_replaces_old_coordinate_and_name_filters(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["step4"]["input"] = {
                "step5_selected_coords": ["com.old:old-lib"],
                "step5_selected_names": ["old-lib"],
            }
            pending_interaction = run_step.apply_interaction_protocol_enhancements(
                {
                    "step_id": "step4",
                    "kind": "review",
                    "options": [{"id": "continue", "label": "继续"}],
                    "response_schema": {
                        "type": "object",
                        "required": ["action"],
                        "properties": {"action": {"type": "string"}},
                    },
                    "selection_options": [{"coord": "com.new:new-lib", "name": "new-lib"}],
                },
                "step4",
            )

            updated_state, _ = run_step.apply_user_response_to_main_state(
                state,
                pending_interaction,
                {
                    "intent_patch": {
                        "action": "continue",
                        "set": {"selected_targets": ["com.new:new-lib"]},
                    }
                },
                project_dir,
                target_step_id="step4",
            )

        self.assertEqual(
            updated_state["step4"]["input"]["step5_selected_coords"],
            ["com.new:new-lib"],
        )
        self.assertNotIn("step5_selected_names", updated_state["step4"]["input"])

    def test_full_continue_with_no_current_candidates_clears_old_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["step4"]["input"] = {
                "step5_selected_coords": ["com.old:old-lib"],
                "step5_selected_names": ["old-lib"],
            }
            pending_interaction = {
                "step_id": "step4",
                "kind": "review",
                "selection_resolution": {},
            }

            updated_state, _ = run_step.apply_user_response_to_main_state(
                state,
                pending_interaction,
                {"intent_patch": {"action": "continue", "set": {}}},
                project_dir,
                target_step_id="step4",
            )

        self.assertNotIn("step5_selected_coords", updated_state["step4"]["input"])
        self.assertNotIn("step5_selected_names", updated_state["step4"]["input"])

    def test_fallback_high_risk_count_matches_step4_when_severity_is_present(self):
        summary = run_step.build_step5_selection_summary(
            [
                {
                    "coord": "com.example:demo",
                    "severity": "P2",
                    "change_type": "REMOVED",
                }
            ]
        )

        target = summary["available_targets"][0]
        self.assertEqual(target["high_risk_api_count"], 0)
        self.assertTrue(target["recommended"])

    def test_build_interaction_payload_step4_exposes_step5_target_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            s4_dir = self._api_changes_dir(report_dir)
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
                    "outputs": ["evidence/api_changes/all_changed_apis.csv"],
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
            self.assertIn("selected_targets", properties)
            self.assertIn("scope_mode", properties)
            self.assertNotIn("step5_selected_coords", properties)
            self.assertNotIn("step5_selected_names", properties)
            self.assertIn("scope_mode", payload["required_fields"])
            self.assertIn(
                "scope_mode",
                payload["action_requirements"]["continue"]["required_fields"],
            )
            self.assertTrue(payload["selection_resolution"]["enabled"])
            self.assertEqual(payload["selection_options"][0]["coord"], "com.example:demo-lib")
            self.assertEqual(payload["selection_options"][0]["name"], "demo-lib")
            self.assertEqual(payload["selection_options"][0]["selection_key"], "coord:com.example:demo-lib")
            self.assertEqual(payload["recommended_candidate_count"], 1)
            self.assertEqual(
                payload["recommended_selection_options"][0]["coord"],
                "com.example:demo-lib",
            )
            self.assertNotIn(
                "scope_mode",
                "\n".join(payload["user_decision_card"]),
            )

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
                        "set": {"selected_targets": ["com.example:demo-lib"]},
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

    def test_partial_scope_keeps_two_selected_dependencies_out_of_eighty_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            selected = [
                "org.apache.seata:seata-common",
                "net.sf.json-lib:json-lib:jdk15",
            ]
            coords = selected + [
                f"com.example:dependency-{index:02d}" for index in range(79)
            ]
            rows = [
                {
                    "coord": coord,
                    "class_name": "com.example.Demo",
                    "member": "run()",
                }
                for coord in coords
            ]
            selection_options = run_step.build_interaction_selection_options(
                [
                    {
                        "coord": coord,
                        "name": run_step._artifact_name_from_coord(coord),
                    }
                    for coord in coords
                ]
            )
            interaction = run_step.apply_interaction_protocol_enhancements(
                {
                    "step_id": "step4",
                    "kind": "review",
                    "options": [{"id": "continue", "label": "继续"}],
                    "response_schema": {
                        "type": "object",
                        "required": ["action"],
                        "properties": {"action": {"type": "string"}},
                    },
                    "selection_options": selection_options,
                },
                "step4",
            )
            response = {
                "intent_patch": {
                    "action": "continue",
                    "set": {
                        "scope_mode": "partial",
                        "selected_targets": selected,
                    },
                }
            }
            canonical = run_step.build_canonical_user_response(response)
            run_step.validate_pending_interaction_response(interaction, canonical)
            state = run_step.new_main_state(report_dir)

            _, context = run_step.apply_user_response_to_main_state(
                state,
                interaction,
                response,
                project_dir,
                target_step_id="step4",
            )
            summary = run_step.build_step5_selection_summary(
                rows,
                selected_coords=context.get("step5_selected_coords"),
                selected_names=context.get("step5_selected_names"),
            )

        self.assertEqual(context["step5_scope_mode"], "partial")
        self.assertEqual(context["step5_selected_coords"], selected)
        self.assertEqual(
            {row["coord"] for row in summary["matched_rows"]},
            set(selected),
        )
        self.assertEqual(summary["available_target_count"], 81)
        self.assertEqual(summary["matched_row_count"], 2)

    def test_build_interaction_payload_step4_keeps_full_selection_resolution_when_display_truncated(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            self._api_changes_dir(report_dir).mkdir(parents=True)
            with (self._api_changes_dir(report_dir) / "all_changed_apis.csv").open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=["coord", "class_name", "member"])
                writer.writeheader()
                for idx in range(21):
                    writer.writerow(
                        {
                            "coord": f"com.example:demo-lib-{idx:02d}",
                            "class_name": f"com.example.Demo{idx}",
                            "member": "run()",
                        }
                    )
            manifest_steps = {
                "step4": {
                    "interaction": {
                        "title": "请确认",
                        "question": "请确认",
                        "options": [{"id": "continue", "label": "继续", "description": "继续"}],
                    },
                    "outputs": ["evidence/api_changes/all_changed_apis.csv"],
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

        self.assertEqual(len(payload["selection_options"]), 10)
        self.assertEqual(len(payload["selection_resolution"]["options"]), 21)
        self.assertEqual(
            payload["selection_resolution"]["options"][-1]["selection_key"],
            "coord:com.example:demo-lib-20",
        )

    def test_apply_user_response_to_main_state_resolves_selected_targets_outside_display_slice(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            full_selection_options = run_step.build_interaction_selection_options(
                [
                    {
                        "coord": f"com.example:demo-lib-{idx:02d}",
                        "name": f"demo-lib-{idx:02d}",
                    }
                    for idx in range(21)
                ]
            )
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
                    "selection_options": full_selection_options[:20],
                    "selection_resolution": run_step.build_selection_resolution(full_selection_options),
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
                        "set": {"selected_targets": ["com.example:demo-lib-20"]},
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
            ["com.example:demo-lib-20"],
        )
        self.assertEqual(
            updated_state["step5"]["input"]["step5_selected_coords"],
            ["com.example:demo-lib-20"],
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
            self._api_changes_dir(report_dir).mkdir(parents=True)
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
            s4_dir = self._api_changes_dir(report_dir)
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

    def test_materialize_step5_rejects_partial_scope_without_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            all_changed_path = (
                self._api_changes_dir(report_dir) / "all_changed_apis.csv"
            )
            all_changed_path.parent.mkdir(parents=True)
            with all_changed_path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=run_step.ALL_CHANGED_APIS_FIELDS,
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "coord": "com.example:demo-lib",
                        "api_name": "com.example.Demo.call",
                        "api_simple": "call",
                        "api_signature": "()",
                        "symbol_kind": "method",
                        "change_type": "REMOVED",
                    }
                )

            with self.assertRaisesRegex(
                run_step.StepError,
                "不能静默回退为全量分析",
            ):
                run_step.materialize_step5_all_changed_apis_input(
                    all_changed_path,
                    report_dir,
                    {"step5_scope_mode": "partial"},
                )

    def test_execute_step5_rejects_unmatched_selected_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            s4_dir = self._api_changes_dir(report_dir)
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
            self._api_changes_dir(report_dir).mkdir(parents=True)
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
            self._write_text(run_step.step1_dep_changes_path(report_dir),
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

    def test_dependency_source_plan_expands_module_ga_to_classifier_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            dep_repo = Path(tmp) / "native-repo"
            source_dir = dep_repo / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            (dep_repo / "pom.xml").write_text(
                (
                    "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
                    "<modelVersion>4.0.0</modelVersion>"
                    "<groupId>com.example</groupId>"
                    "<artifactId>native</artifactId>"
                    "<version>1.0.0</version>"
                    "</project>"
                ),
                encoding="utf-8",
            )

            plan = run_step._build_dependency_source_plan(
                [str(dep_repo)],
                relevant_coords=[
                    "com.example:native:osx-aarch_64",
                    "com.example:native:osx-x86_64",
                ],
            )

        self.assertEqual(
            plan["dependency_repo_mappings"],
            [
                f"com.example:native:osx-aarch_64={dep_repo.resolve()}",
                f"com.example:native:osx-x86_64={dep_repo.resolve()}",
            ],
        )
        self.assertEqual(
            plan["dependency_source_mappings"],
            [
                f"com.example:native:osx-aarch_64={source_dir.resolve()}",
                f"com.example:native:osx-x86_64={source_dir.resolve()}",
            ],
        )
        self.assertEqual(plan["unmatched_relevant_coords"], [])

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
            self._write_text(run_step.step1_dep_changes_path(report_dir),
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
            self._write_text(run_step.step1_dep_changes_path(report_dir),
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
            self._write_text(run_step.step1_dep_changes_path(report_dir), 
                "coord,change_type,resolution_status,old_version,new_version\n"
                "com.example:demo-lib,升级,resolved,1.0.0,2.0.0\n",
                encoding="utf-8",
            )
            self._write_text(run_step.step2_context_path(report_dir), "{}", encoding="utf-8")
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
            step2_context = run_step.step2_context_path(report_dir)
            step2_graph = run_step.step2_dep_graph_path(report_dir)
            step2_summary = run_step.step2_source_mapping_summary_path(report_dir)
            step1_output = run_step.step1_dep_changes_path(report_dir)
            main_state = run_step.main_state_path(report_dir)
            interaction = self._runtime_state_dir(report_dir) / "interaction.json"
            self._write_text(step2_context, "{}", encoding="utf-8")
            self._write_text(step2_graph, "{}", encoding="utf-8")
            self._write_text(step2_summary, "{}", encoding="utf-8")
            self._write_text(step1_output, "coord", encoding="utf-8")
            self._write_text(main_state, "{}", encoding="utf-8")
            self._write_text(interaction, "{}", encoding="utf-8")

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
            step1_alerts = run_step.step1_dep_alerts_path(report_dir)
            step1_changes = run_step.step1_dep_changes_path(report_dir)
            step1_summary = run_step.step1_dep_summary_path(report_dir)
            step1_resolved = run_step.step1_current_resolved_path(report_dir)
            build_provenance = run_step.build_provenance_path(report_dir)
            artifacts_dir = run_step.step1_artifacts_dir(report_dir)
            main_state = run_step.main_state_path(report_dir)
            interaction = self._runtime_state_dir(report_dir) / "interaction.json"
            self._write_text(step1_alerts, "coord\n", encoding="utf-8")
            self._write_text(step1_changes, "coord\n", encoding="utf-8")
            self._write_text(step1_summary, "summary\n", encoding="utf-8")
            self._write_text(step1_resolved, "coord\n", encoding="utf-8")
            self._write_text(build_provenance, "{}", encoding="utf-8")
            artifacts_dir.mkdir(parents=True)
            (artifacts_dir / "current.jar").write_text("jar\n", encoding="utf-8")
            self._write_text(main_state, "{}", encoding="utf-8")
            self._write_text(interaction, "{}", encoding="utf-8")

            run_step.cleanup_step_outputs("step1", report_dir)

            self.assertFalse(step1_alerts.exists())
            self.assertFalse(step1_changes.exists())
            self.assertFalse(step1_summary.exists())
            self.assertFalse(step1_resolved.exists())
            self.assertFalse(build_provenance.exists())
            self.assertFalse(artifacts_dir.exists())
            self.assertTrue(main_state.exists())
            self.assertTrue(interaction.exists())

    def test_cleanup_step_outputs_preserves_reusable_business_bytecode_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            step5_dir = self._call_chain_dir(report_dir)
            artifact_catalog = self._runtime_cache_dir(report_dir) / run_step.STEP5_ARTIFACT_BYTECODE_CATALOG_FILE
            artifact_index = self._runtime_cache_dir(report_dir) / run_step.STEP5_ARTIFACT_BYTECODE_INDEX_FILE
            artifact_bytecode_dir = self._runtime_cache_dir(report_dir) / run_step.STEP5_ARTIFACT_BYTECODE_DIRNAME
            framework_adapters = self._call_chain_dir(report_dir) / "framework_adapters.json"
            source_alignment = self._call_chain_dir(report_dir) / "source_artifact_alignment.json"
            diagnostics = (
                run_step.runtime_observability_dir(report_dir)
                / run_step.STEP5_DIAGNOSTICS_FILE
            )
            progress_snapshot = (
                run_step.runtime_observability_dir(report_dir)
                / run_step.STEP5_PROGRESS_FILE
            )
            main_state = self._runtime_state_dir(report_dir) / "main_state.json"
            interaction = self._runtime_state_dir(report_dir) / "interaction.json"
            step5_dir.mkdir(parents=True)
            (step5_dir / "summary.json").write_text("{}", encoding="utf-8")
            artifact_bytecode_dir.mkdir(parents=True)
            (artifact_bytecode_dir / "current.jar").write_text("jar\n", encoding="utf-8")
            artifact_catalog.parent.mkdir(parents=True, exist_ok=True)
            artifact_catalog.write_text("{}", encoding="utf-8")
            artifact_index.write_text("{}", encoding="utf-8")
            framework_adapters.write_text("{}", encoding="utf-8")
            source_alignment.write_text("{}", encoding="utf-8")
            diagnostics.parent.mkdir(parents=True, exist_ok=True)
            diagnostics.write_text("{}\n", encoding="utf-8")
            progress_snapshot.write_text("{}\n", encoding="utf-8")
            main_state.parent.mkdir(parents=True, exist_ok=True)
            main_state.write_text("{}", encoding="utf-8")
            interaction.write_text("{}", encoding="utf-8")

            run_step.cleanup_step_outputs("step5", report_dir)

            self.assertFalse(step5_dir.exists())
            self.assertFalse(artifact_bytecode_dir.exists())
            self.assertFalse(artifact_catalog.exists())
            self.assertTrue(artifact_index.exists())
            self.assertFalse(framework_adapters.exists())
            self.assertFalse(source_alignment.exists())
            self.assertFalse(diagnostics.exists())
            self.assertFalse(progress_snapshot.exists())
            self.assertTrue(main_state.exists())
            self.assertTrue(interaction.exists())

    def test_cleanup_step_outputs_step3_removes_bridge_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            risk_candidates = self._static_scan_dir(report_dir) / run_step.STEP3_RISK_CANDIDATES_FILE
            risk_candidates.parent.mkdir(parents=True, exist_ok=True)
            risk_candidates.write_text("coord\n", encoding="utf-8")
            per_dep_dir = self._api_changes_dir(report_dir) / run_step.PER_DEPENDENCY_DIRNAME / "sample_demo"
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

            self._write_text(run_step.step1_dep_changes_path(report_dir), "coord\n", encoding="utf-8")
            self._write_text(self._static_scan_dir(report_dir) / "s3_jdk_removed_api.csv", "symbol\n", encoding="utf-8")
            self._api_changes_dir(report_dir).mkdir()
            (self._api_changes_dir(report_dir) / "all_changed_apis.csv").write_text("coord\n", encoding="utf-8")
            self._call_chain_dir(report_dir).mkdir()
            (self._call_chain_dir(report_dir) / "summary.json").write_text("{}", encoding="utf-8")
            self._write_text(run_step.s6_findings_path(report_dir), "{}", encoding="utf-8")
            self._write_text(run_step.s6_report_path(report_dir), "# stale\n", encoding="utf-8")

            captured = {}

            def fake_execute_step(step_id, _args, _manifest_steps, run_context, **_kwargs):
                captured["step_id"] = step_id
                captured["run_context"] = dict(run_context)
                captured["state"] = run_step.load_main_state(report_dir)
                captured["step1_output_exists"] = (run_step.step1_dep_changes_path(report_dir)).exists()
                captured["step3_output_exists"] = (self._static_scan_dir(report_dir) / "s3_jdk_removed_api.csv").exists()
                captured["step4_output_exists"] = self._api_changes_dir(report_dir).exists()
                captured["step5_output_exists"] = self._call_chain_dir(report_dir).exists()
                captured["step6_findings_exists"] = run_step.s6_findings_path(report_dir).exists()
                captured["step6_report_exists"] = run_step.s6_report_path(report_dir).exists()
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
            interaction_exists = (self._runtime_state_dir(report_dir) / "interaction.json").exists()

            self.assertEqual(exit_code, run_step.EXIT_AWAITING_USER)
            self.assertEqual(saved["state"]["status"], "awaiting_user_input")
            self.assertEqual(saved["state"]["current_step"], "step5")
            self.assertEqual(saved["state"]["completed_step"], "step4")
            self.assertEqual(
                saved["state"]["pending_interaction"]["reason_code"],
                "STEP5_DEPENDENCY_SOURCE_MAPPING_MISSING",
            )
            pending_properties = saved["state"]["pending_interaction"]["response_schema"]["properties"]
            self.assertNotIn("step5_selected_coords", pending_properties)
            self.assertNotIn("step5_selected_names", pending_properties)
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
                "target_module": ".",
            }
            state["step2"]["output"] = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
            }
            state["step3"]["output"] = dict(state["step2"]["output"])
            run_step.save_main_state(report_dir, state)
            self._write_text(run_step.step2_context_path(report_dir), "{}", encoding="utf-8")
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
            ), patch.object(
                run_step,
                "resolve_step1_refs_for_execution",
                side_effect=lambda context, _project: (dict(context), None),
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
            (project_dir / "src" / "main" / "java").mkdir(parents=True)
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
            self._api_changes_dir(report_dir).mkdir(parents=True, exist_ok=True)
            (self._api_changes_dir(report_dir) / "all_changed_apis.csv").write_text(
                "coord,class_name,member\ncom.example:demo-lib,com.example.Demo,run()\n",
                encoding="utf-8",
            )
            dependencies_dir = report_dir / "evidence" / "dependencies"
            dependencies_dir.mkdir(parents=True, exist_ok=True)
            (dependencies_dir / "dep_changes.csv").write_text(
                "coord,old_version,new_version\ncom.example:demo-lib,1,2\n",
                encoding="utf-8",
            )
            context_dir = report_dir / "evidence" / "context"
            context_dir.mkdir(parents=True, exist_ok=True)
            (context_dir / "context.json").write_text("{}\n", encoding="utf-8")
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
                                    "selected_targets": ["com.example:demo-lib"],
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

    def test_main_auto_restarts_from_step_after_pipeline_done_without_business_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "done"
            state["state"]["completed_step"] = "step6"
            base_context = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "analysis_mode": "checkout_build",
                "target_module": ".",
            }
            state["step1"]["output"] = dict(base_context)
            state["step2"]["output"] = dict(base_context)
            state["step3"]["output"] = dict(base_context)
            state["step4"]["input"] = dict(base_context)
            state["step4"]["output"] = dict(base_context)
            state["step5"]["output"] = {"stale": True}
            state["step6"]["output"] = {"stale": True}
            run_step.save_main_state(report_dir, state)

            self._write_text(run_step.step1_dep_changes_path(report_dir), 
                "change_type,group_id,artifact_id,base_version,current_version\n",
                encoding="utf-8",
            )
            self._write_text(run_step.step2_context_path(report_dir), "{}", encoding="utf-8")
            self._api_changes_dir(report_dir).mkdir(parents=True, exist_ok=True)
            (self._api_changes_dir(report_dir) / "all_changed_apis.csv").write_text(
                "coord,class_name,member\ncom.example:demo,com.example.Demo,run()\n",
                encoding="utf-8",
            )
            self._call_chain_dir(report_dir).mkdir(parents=True, exist_ok=True)
            (self._call_chain_dir(report_dir) / "alerts.csv").write_text("x\n", encoding="utf-8")
            self._write_text(run_step.s6_report_path(report_dir), "# stale\n", encoding="utf-8")
            captured = {}

            def fake_execute_step(step_id, _args, _manifest_steps, run_context, **_kwargs):
                captured["step_id"] = step_id
                captured["run_context"] = dict(run_context)
                captured["s4_exists_before_step"] = self._api_changes_dir(report_dir).exists()
                captured["s5_exists_before_step"] = self._call_chain_dir(report_dir).exists()
                captured["s6_exists_before_step"] = run_step.s6_report_path(report_dir).exists()
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
                                "action": "restart_from_step",
                                "restart_step_id": "step4",
                            }
                        },
                        ensure_ascii=False,
                    ),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=({}, {"step4": {"gate": "jar_compare"}}),
            ), patch.object(
                run_step,
                "execute_step",
                side_effect=fake_execute_step,
            ):
                exit_code = run_step.main()

            saved = run_step.load_main_state(report_dir)
            self.assertEqual(exit_code, 0)
            self.assertEqual(captured["step_id"], "step4")
            self.assertEqual(captured["run_context"]["base_branch"], "base")
            self.assertEqual(captured["run_context"]["current_branch"], "current")
            self.assertFalse(captured["s4_exists_before_step"])
            self.assertFalse(captured["s5_exists_before_step"])
            self.assertFalse(captured["s6_exists_before_step"])
            self.assertEqual(saved["state"]["current_step"], "step5")
            self.assertEqual(saved["state"]["completed_step"], "step4")
            self.assertEqual(saved["step5"]["input"]["base_branch"], "base")

    def test_step1_ref_preflight_persists_unique_remote_ref_and_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {
                "analysis_mode": "artifact_inputs",
                "current_branch": "release-2.0.0",
                "current_source_project_dir": str(project_dir),
            }
            resolution = {
                "status": "resolved",
                "requested_ref": "release-2.0.0",
                "resolved_ref": "origin/release-2.0.0",
                "resolved_commit": "a" * 40,
                "resolution_mode": "unique_remote",
                "candidates": [
                    {"ref": "origin/release-2.0.0", "commit": "a" * 40, "kind": "remote", "score": 200},
                ],
                "fingerprint": "fingerprint-current",
            }

            with patch.object(run_step, "resolve_step1_ref", return_value=resolution):
                updated, interaction = run_step.resolve_step1_refs_for_execution(context, project_dir)

        self.assertIsNone(interaction)
        self.assertEqual(updated["current_branch"], "release-2.0.0")
        self.assertEqual(updated["current_requested_ref"], "release-2.0.0")
        self.assertEqual(updated["current_resolved_ref"], "origin/release-2.0.0")
        self.assertEqual(updated["current_resolved_commit"], "a" * 40)
        self.assertEqual(updated["current_ref_resolution_mode"], "unique_remote")
        self.assertEqual(updated["current_ref_candidate_count"], 1)
        self.assertEqual(
            updated["current_ref_binding"],
            {
                "schema": "java-upgrade-analyzer.remote-ref-binding.v1",
                "repo_dir": str(project_dir.resolve()),
                "requested_ref": "release-2.0.0",
                "remote": "",
                "canonical_ref": "",
                "expected_commit": "a" * 40,
                "artifact_path": "",
            },
        )

    def test_step1_ref_preflight_discards_unbound_expected_commit_from_old_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {
                "analysis_mode": "checkout_build",
                "base_branch": "release",
                "base_expected_commit": "a" * 40,
                "base_resolved_commit": "a" * 40,
                "base_requested_ref": "release",
            }
            resolution = {
                "status": "resolved",
                "requested_ref": "release",
                "resolved_ref": "origin/release",
                "resolved_commit": "b" * 40,
                "remote": "origin",
                "remote_ref": "refs/heads/release",
                "resolution_mode": "live_remote",
                "candidates": [{
                    "ref": "origin/release",
                    "commit": "b" * 40,
                    "remote": "origin",
                    "canonical_ref": "refs/heads/release",
                }],
            }

            with patch.object(
                run_step, "resolve_step1_ref", return_value=resolution
            ) as resolver:
                updated, interaction = run_step.resolve_step1_refs_for_execution(
                    context, project_dir
                )

        self.assertIsNone(interaction)
        self.assertEqual(resolver.call_args.kwargs["expected_commit"], "")
        self.assertEqual(updated["base_expected_commit"], "b" * 40)
        self.assertEqual(updated["base_resolved_commit"], "b" * 40)

    def test_step1_ref_preflight_reuses_expected_commit_only_with_matching_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {
                "analysis_mode": "checkout_build",
                "base_branch": "release",
                "base_expected_commit": "a" * 40,
                "base_ref_binding": {
                    "schema": "java-upgrade-analyzer.remote-ref-binding.v1",
                    "repo_dir": str(project_dir.resolve()),
                    "requested_ref": "release",
                    "remote": "origin",
                    "canonical_ref": "refs/heads/release",
                    "expected_commit": "a" * 40,
                    "artifact_path": "",
                },
            }
            resolution = {
                "status": "resolved",
                "requested_ref": "release",
                "resolved_ref": "origin/release",
                "resolved_commit": "a" * 40,
                "remote": "origin",
                "remote_ref": "refs/heads/release",
                "resolution_mode": "live_remote_expected_commit",
                "candidates": [],
            }

            with patch.object(
                run_step, "resolve_step1_ref", return_value=resolution
            ) as resolver:
                updated, interaction = run_step.resolve_step1_refs_for_execution(
                    context, project_dir
                )

        self.assertIsNone(interaction)
        self.assertEqual(
            resolver.call_args.kwargs["expected_commit"],
            "a" * 40,
        )
        self.assertEqual(resolver.call_args.kwargs["expected_remote"], "origin")
        self.assertEqual(
            resolver.call_args.kwargs["expected_remote_ref"],
            "refs/heads/release",
        )
        self.assertEqual(updated["base_expected_commit"], "a" * 40)

    def test_step1_unmaterializable_pinned_commit_is_system_error_not_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {
                "analysis_mode": "checkout_build",
                "base_branch": "release",
                "base_expected_commit": "a" * 40,
                "base_ref_binding": {
                    "schema": "java-upgrade-analyzer.remote-ref-binding.v1",
                    "repo_dir": str(project_dir.resolve()),
                    "requested_ref": "release",
                    "remote": "origin",
                    "canonical_ref": "refs/heads/release",
                    "expected_commit": "a" * 40,
                    "artifact_path": "",
                },
            }
            resolution = {
                "status": "fetch_failed",
                "source_status": "remote_expected_commit_unmaterializable",
                "expected_commit": "a" * 40,
                "observed_commit": "b" * 40,
            }

            with patch.object(
                run_step,
                "resolve_step1_ref",
                return_value=resolution,
            ), self.assertRaises(run_step.StepError) as raised:
                run_step.resolve_step1_refs_for_execution(
                    context,
                    project_dir,
                )

        self.assertIn("不会要求用户重新选择 ref", str(raised.exception))
        self.assertEqual(
            raised.exception.reason_codes,
            ["STEP1_REMOTE_EXPECTED_COMMIT_UNMATERIALIZABLE"],
        )

    def test_step1_remote_operation_failure_is_system_error_not_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {
                "analysis_mode": "checkout_build",
                "base_branch": "release",
            }
            resolution = {
                "status": "fetch_failed",
                "source_status": "remote_query_failed",
                "repository_path": str(project_dir),
                "failures": [{
                    "remote": "origin",
                    "stage": "targeted_ls_remote",
                    "reason": "ssh handshake timed out",
                    "reason_code": "transient_network_failure",
                    "attempts": [{"attempt": 1}, {"attempt": 2}, {"attempt": 3}],
                }],
            }

            with patch.object(
                run_step,
                "resolve_step1_ref",
                return_value=resolution,
            ), self.assertRaises(run_step.StepError) as raised:
                run_step.resolve_step1_refs_for_execution(
                    context,
                    project_dir,
                )

        self.assertIn("ssh handshake timed out", str(raised.exception))
        self.assertEqual(
            raised.exception.reason_codes,
            ["STEP1_REMOTE_OPERATION_FAILED"],
        )

    def test_step1_input_change_invalidates_bound_ref_snapshot(self):
        project_dir = Path("/project")
        old_context = {
            "analysis_mode": "artifact_inputs",
            "base_artifact_path": "/artifacts/old-base.jar",
            "base_source_project_dir": "/repos/old",
            "base_branch": "release",
            "base_expected_commit": "a" * 40,
            "base_resolved_commit": "a" * 40,
            "base_requested_ref": "release",
            "base_ref_binding": {
                "schema": "java-upgrade-analyzer.remote-ref-binding.v1",
                "repo_dir": "/repos/old",
                "requested_ref": "release",
                "remote": "origin",
                "canonical_ref": "refs/heads/release",
                "expected_commit": "a" * 40,
                "artifact_path": "/artifacts/old-base.jar",
            },
        }

        updated = run_step.merge_user_response_into_run_context(
            old_context,
            {
                "base_artifact_path": "/artifacts/new-base.jar",
                "base_source_project_dir": "/repos/new",
            },
            project_dir,
        )

        self.assertNotIn("base_expected_commit", updated)
        self.assertNotIn("base_resolved_commit", updated)
        self.assertNotIn("base_requested_ref", updated)
        self.assertNotIn("base_ref_binding", updated)

    def test_step1_ref_preflight_resolves_both_branches_from_project_remote(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            remote = root / "origin.git"
            project_dir = root / "project"

            def git(cwd, *args):
                completed = subprocess.run(
                    ["git", *args],
                    cwd=cwd,
                    check=True,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                )
                return completed.stdout.strip()

            git(root, "init", "--bare", str(remote))
            git(root, "clone", str(remote), str(project_dir))
            git(project_dir, "config", "user.email", "step1@example.invalid")
            git(project_dir, "config", "user.name", "Step1 Test")
            git(project_dir, "commit", "--allow-empty", "-m", "base")
            base_commit = git(project_dir, "rev-parse", "HEAD")
            git(project_dir, "branch", "nbs-base", base_commit)
            git(project_dir, "commit", "--allow-empty", "-m", "current")
            current_commit = git(project_dir, "rev-parse", "HEAD")
            git(
                project_dir,
                "branch",
                "nbs-mid26.07.22.DEV",
                current_commit,
            )
            git(
                project_dir,
                "push",
                "origin",
                "nbs-base",
                "nbs-mid26.07.22.DEV",
            )

            updated, interaction = run_step.resolve_step1_refs_for_execution(
                {
                    "analysis_mode": "checkout_build",
                    "base_branch": "nbs-base",
                    "current_branch": "nbs-mid26.07.22.DEV",
                },
                project_dir,
            )

        self.assertIsNone(interaction)
        self.assertEqual(updated["base_resolved_commit"], base_commit)
        self.assertEqual(updated["current_resolved_commit"], current_commit)
        self.assertEqual(updated["base_ref_remote"], "origin")
        self.assertEqual(updated["current_ref_remote"], "origin")

    def test_step1_direct_artifacts_do_not_resolve_refs_before_coordinate_fallback(self):
        context = {
            "analysis_mode": "artifact_inputs",
            "base_artifact_path": "/tmp/base.jar",
            "current_artifact_path": "/tmp/current.jar",
            "base_branch": "possibly-ambiguous-base",
            "current_branch": "possibly-ambiguous-current",
        }

        with patch.object(run_step, "resolve_step1_ref") as resolver:
            updated, interaction = run_step.resolve_step1_refs_for_execution(
                context, "/tmp/project"
            )

        self.assertIsNone(interaction)
        self.assertEqual(updated, context)
        resolver.assert_not_called()

    def test_step1_ref_preflight_stops_for_ambiguous_remote_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {"current_branch": "release-2.0.0"}
            resolution = {
                "status": "ambiguous",
                "requested_ref": "release-2.0.0",
                "resolved_ref": "",
                "resolved_commit": "",
                "resolution_mode": "unresolved",
                "candidates": [
                    {"ref": "origin/release-2.0.0", "commit": "a" * 40, "kind": "remote", "score": 200},
                    {"ref": "upstream/release-2.0.0", "commit": "b" * 40, "kind": "remote", "score": 200},
                ],
                "fingerprint": "ambiguous-current",
            }

            with patch.object(run_step, "resolve_step1_ref", return_value=resolution):
                _updated, interaction = run_step.resolve_step1_refs_for_execution(context, project_dir)

        self.assertEqual(interaction["reason_code"], "ambiguous_step1_source_ref")
        self.assertEqual(interaction["kind"], "input_request")
        self.assertEqual(interaction["required_fields"], ["current_branch"])
        self.assertEqual(len(interaction["ref_resolution_requests"][0]["candidates"]), 2)
        self.assertTrue(interaction["must_wait_for_user_reply"])

    def test_step1_remote_failure_offers_explicit_local_fallback_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {"current_branch": "release-2.0.0"}
            resolution = {
                "status": "not_found",
                "source_status": "awaiting_local_source_confirmation",
                "requested_ref": "release-2.0.0",
                "resolved_ref": "",
                "resolved_commit": "",
                "resolution_mode": "unresolved",
                "candidates": [],
                "failures": [{"remote": "origin", "stage": "ls_remote", "reason": "network unavailable"}],
                "local_candidate_commit": "d" * 40,
                "dirty": False,
                "fingerprint": "remote-unavailable-current",
            }

            with patch.object(run_step, "resolve_step1_ref", return_value=resolution):
                _updated, interaction = run_step.resolve_step1_refs_for_execution(context, project_dir)

        self.assertEqual(interaction["reason_code"], "step1_remote_source_unavailable")
        self.assertIn("current_allow_local_source", interaction["response_schema"]["properties"])
        self.assertIn("confirm_local_source", {row["id"] for row in interaction["options"]})
        request = interaction["ref_resolution_requests"][0]
        self.assertEqual(request["local_candidate_commit"], "d" * 40)
        self.assertEqual(request["remote_failures"][0]["stage"], "ls_remote")

    def test_step1_passes_confirmed_local_fallback_flags_to_resolver(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {
                "current_branch": "release-2.0.0",
                "current_ref_binding": {},
                "current_allow_local_source": True,
                "current_allow_dirty_local_source": True,
            }
            resolution = {
                "status": "resolved",
                "source_status": "user_confirmed_local_source",
                "requested_ref": "release-2.0.0",
                "resolved_ref": "release-2.0.0",
                "resolved_commit": "e" * 40,
                "resolution_mode": "user_confirmed_local_source",
                "candidates": [],
                "fingerprint": "confirmed-local-current",
            }

            with patch.object(run_step, "resolve_step1_ref", return_value=resolution) as resolver:
                updated, interaction = run_step.resolve_step1_refs_for_execution(context, project_dir)

        self.assertIsNone(interaction)
        self.assertEqual(updated["current_ref_source_status"], "user_confirmed_local_source")
        self.assertTrue(resolver.call_args.kwargs["allow_local_source"])
        self.assertTrue(resolver.call_args.kwargs["allow_dirty_local_source"])

    def test_step1_source_only_input_requires_revision_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {"base_source_project_dir": str(project_dir)}
            head_resolution = {
                "status": "resolved",
                "requested_ref": "HEAD",
                "resolved_ref": "HEAD",
                "resolved_commit": "c" * 40,
                "resolution_mode": "exact",
                "candidates": [],
                "fingerprint": "source-head",
            }

            with patch.object(run_step, "resolve_step1_ref", return_value=head_resolution):
                _updated, interaction = run_step.resolve_step1_refs_for_execution(context, project_dir)

        self.assertEqual(
            interaction["reason_code"],
            "step1_source_revision_confirmation_required",
        )
        self.assertEqual(interaction["required_fields"], ["base_branch"])
        request = interaction["ref_resolution_requests"][0]
        self.assertEqual(request["detected_commit"], "c" * 40)
        self.assertEqual(request["source_project_dir"], str(project_dir.resolve()))

    def test_step1_ref_confirmation_rejects_same_unresolved_value(self):
        interaction = {
            "step_id": "step1",
            "reason_code": "ambiguous_step1_source_ref",
            "options": [{"id": "continue"}],
            "required_fields": ["current_branch"],
            "action_requirements": {
                "continue": {"required_fields": ["current_branch"]},
            },
            "ref_resolution_requests": [
                {
                    "field": "current_branch",
                    "requested_ref": "release-2.0.0",
                }
            ],
        }

        with self.assertRaisesRegex(run_step.StepError, "不同的明确 ref"):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "continue", "current_branch": "release-2.0.0"},
            )

    def test_step1_ref_confirmation_accepts_same_ref_when_repository_changes(self):
        interaction = {
            "step_id": "step1",
            "reason_code": "step1_remote_source_unavailable",
            "options": [{"id": "continue"}],
            "required_fields": ["current_branch"],
            "action_requirements": {
                "continue": {"required_fields": ["current_branch"]},
            },
            "response_schema": {
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "current_branch": {"type": "string"},
                    "current_source_project_dir": {"type": "string"},
                },
            },
            "ref_resolution_requests": [
                {
                    "side": "current",
                    "field": "current_branch",
                    "requested_ref": "nbs-mid26.07.22.DEV",
                    "source_project_dir": "/stale/repository",
                }
            ],
        }

        run_step.validate_pending_interaction_response(
            interaction,
            {
                "action": "continue",
                "current_branch": "nbs-mid26.07.22.DEV",
                "current_source_project_dir": "/actual/repository",
            },
        )

    def test_step1_ref_confirmation_accepts_explicit_remote_requery(self):
        interaction = {
            "step_id": "step1",
            "reason_code": "step1_remote_source_unavailable",
            "options": [{"id": "continue"}],
            "required_fields": ["current_branch"],
            "action_requirements": {
                "continue": {"required_fields": ["current_branch"]},
            },
            "response_schema": {
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "current_branch": {"type": "string"},
                    "retry_remote_fetch": {"type": "boolean"},
                },
            },
            "ref_resolution_requests": [
                {
                    "side": "current",
                    "field": "current_branch",
                    "status": "not_found",
                    "requested_ref": "nbs-mid26.07.22.DEV",
                    "source_project_dir": "/actual/repository",
                    "remote_failures": [
                        {
                            "stage": "resolve",
                            "reason": "repository has no configured remote",
                        }
                    ],
                }
            ],
        }

        run_step.validate_pending_interaction_response(
            interaction,
            {
                "action": "continue",
                "retry_remote_fetch": True,
            },
        )

    def test_step1_ref_protocol_exposes_actual_repository_correction_field(self):
        interaction = {
            "step_id": "step1",
            "reason_code": "step1_remote_source_unavailable",
            "options": [{"id": "continue"}],
            "required_fields": ["current_branch"],
            "response_schema": {
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "current_branch": {"type": "string"},
                },
            },
            "ref_resolution_requests": [
                {
                    "side": "current",
                    "field": "current_branch",
                    "requested_ref": "nbs-mid26.07.22.DEV",
                    "source_project_dir": "/actual/repository",
                }
            ],
        }

        enhanced = run_step.apply_interaction_protocol_enhancements(
            interaction,
            "step1",
        )

        self.assertIn(
            "current_source_project_dir",
            enhanced["response_schema"]["properties"],
        )

    def test_step1_old_artifact_ref_card_clarifies_other_side_was_not_queried(self):
        interaction = {
            "step_id": "step1",
            "reason_code": "step1_remote_source_unavailable",
            "question": "请确认当前侧 ref。",
            "options": [{"id": "continue"}],
            "required_fields": ["current_branch"],
            "response_schema": {
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "current_branch": {"type": "string"},
                },
            },
            "ref_resolution_requests": [
                {
                    "side": "current",
                    "field": "current_branch",
                    "requested_ref": "nbs-mid26.07.22.DEV",
                    "source_project_dir": "/actual/repository",
                    "artifact_path": "/tmp/current.jar",
                }
            ],
            "source_ref_decision_items": [
                {
                    "side": "current",
                    "field": "current_branch",
                    "requested_ref": "nbs-mid26.07.22.DEV",
                }
            ],
        }

        enhanced = run_step.apply_interaction_protocol_enhancements(
            interaction,
            "step1",
        )

        self.assertEqual(
            enhanced["ref_resolution_scope"]["queried_sides"],
            ["current"],
        )
        self.assertEqual(
            enhanced["ref_resolution_scope"]["not_evaluated_sides"],
            ["base"],
        )
        self.assertIn("不表示基准侧执行过远端查询", enhanced["question"])
        self.assertEqual(
            enhanced["source_ref_decision_items"][0]["source_project_dir"],
            "/actual/repository",
        )


if __name__ == "__main__":
    unittest.main()
