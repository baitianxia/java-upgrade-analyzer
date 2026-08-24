from __future__ import annotations

import csv
import copy
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path, PosixPath
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import run_step


class _LockManager:
    def __init__(self, *, enter_value="locked", enter_error=None):
        self.enter_value = enter_value
        self.enter_error = enter_error
        self.exit_calls = []

    def __enter__(self):
        if self.enter_error is not None:
            raise self.enter_error
        return self.enter_value

    def __exit__(self, *args):
        self.exit_calls.append(args)
        return False


class _AttributeProxy:
    def __init__(self, target, **overrides):
        self._target = target
        self._overrides = overrides

    def __getattr__(self, name):
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._target, name)


class RunStepCompletionBoundaryTest(unittest.TestCase):
    def _invoke_main_case(
        self,
        project,
        report,
        *,
        argv=None,
        state=None,
        manifest_data=None,
        manifest_steps=None,
        overrides=None,
        skip_environment=True,
    ):
        state = state if state is not None else run_step.new_main_state(report)
        manifest_data = dict(
            manifest_data
            if manifest_data is not None
            else {"auto_run_until_checkpoint": False}
        )
        manifest_steps = dict(
            manifest_steps
            if manifest_steps is not None
            else {
                step: {
                    "gate": f"gate-{step}",
                    "auto_continue_on_success": False,
                    "requires_scope_confirmation": False,
                }
                for step in run_step.STEP_SEQUENCE
            }
        )
        argv = list(
            argv
            if argv is not None
            else [
                "--step",
                "step1",
                "--project-dir",
                str(project),
                "--report-dir",
                str(report),
            ]
        )

        def response_result(
            _args,
            _project_dir,
            _report_dir,
            current_state,
            current_step,
            user_response=None,
        ):
            return {
                "main_state": current_state,
                "step_id": current_step,
                "pending_interaction": None,
                "resumed_interaction_step_id": "",
                "response_action": "",
                "user_response": dict(user_response or {}),
                "early_exit_code": None,
            }

        specs = {
            "load_seed_json_arg": {"return_value": {}},
            "load_main_state": {"return_value": state},
            "recover_worktrees_before_execution": {
                "return_value": {"removed_count": 0}
            },
            "load_manifest": {"return_value": (manifest_data, manifest_steps)},
            "resolve_user_response": {"return_value": {"action": "continue"}},
            "recover_downstream_report_publications": {
                "return_value": {"actions": []}
            },
            "build_restore_context": {"return_value": {}},
            "_recover_and_apply_step4_startup_state": {"return_value": {}},
            "_apply_downstream_release_startup_state": {"return_value": {}},
            "apply_interaction_protocol_enhancements": {
                "side_effect": lambda value, *_args, **_kwargs: value
            },
            "apply_structured_user_response_if_present": {
                "side_effect": response_result
            },
            "clear_stale_git_interaction_for_recheck": {"return_value": False},
            "maybe_return_pending_interaction": {"return_value": None},
            "handle_step4_resume_followups": {},
            "prepare_main_state_for_step_execution": {
                "side_effect": lambda _args, _state, step, _report: step
            },
            "build_step_input_context": {"return_value": {}},
            "build_run_context": {
                "side_effect": lambda _args, base, *_rest, **_kwargs: dict(base or {})
            },
            "store_step_input": {},
            "save_main_state": {},
            "execute_step": {"return_value": None},
            "should_auto_continue_success_review": {"return_value": False},
            "persist_completed_step": {"return_value": None},
            "persist_step_interaction": {
                "side_effect": lambda _state, _step, _report, _context, value: value
            },
            "persist_interaction_required_error": {
                "side_effect": lambda _state, _step, _report, value: value
            },
            "persist_step_error": {},
            "persist_user_interrupt": {},
            "build_user_runtime_message": {"return_value": ["runtime-message"]},
            "print_interaction_to_streams": {},
            "print_auto_continue_success_review": {},
            "save_interaction_file": {},
            "clear_interaction_file": {},
            "reset_step_state_for_restart": {},
            "require_current_release_stage": {},
            "detect_integrity_repair_step": {"return_value": ""},
            "build_final_completion_summary": {
                "return_value": {"status": "completed"}
            },
            "write_report_landing_docs": {},
            "_record_binary_failure_best_effort": {},
        }
        for name, spec in (overrides or {}).items():
            specs[name] = dict(spec)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with ExitStack() as stack:
            mocks = {
                name: stack.enter_context(patch.object(run_step, name, **spec))
                for name, spec in specs.items()
            }
            stack.enter_context(patch("sys.stdout", stdout))
            stack.enter_context(patch("sys.stderr", stderr))
            result = run_step._main_with_workflow_lock_held(
                argv,
                _skip_environment_contract=skip_environment,
            )
        return result, mocks, stdout.getvalue(), stderr.getvalue(), state

    def test_small_scalar_collection_and_invalid_state_matrix(self):
        self.assertEqual(run_step._binary_runtime_overrides(None), {})
        self.assertEqual(run_step._binary_runtime_overrides({}), {})
        self.assertEqual(
            run_step._binary_runtime_overrides({"base_jdk_home": []}),
            {},
        )
        state = {"state": {"step4_report_republication_pending": {"id": 1}}}
        run_step._clear_step4_republication_marker(state)
        self.assertNotIn("step4_report_republication_pending", state["state"])
        self.assertIsNone(run_step._clear_step4_republication_marker(None))

        self.assertEqual(
            run_step._collect_worktree_repository_path_values({None: "/repo"}),
            [],
        )
        self.assertEqual(
            run_step._collect_worktree_repository_path_values(
                {"project_dir": None, "source_dirs": ["", "/repo"]}
            ),
            ["/repo"],
        )
        with self.assertRaisesRegex(ValueError, "unsupported"):
            run_step._downstream_report_publication_destinations("/tmp/report", "other")

        self.assertFalse(run_step._is_step4_scope_confirmation({}, "continue"))
        self.assertFalse(run_step._is_step4_scope_confirmation({
            "step_id": "step4",
            "selection_options": [{}],
        }, "cancel"))
        self.assertTrue(run_step._is_step4_scope_confirmation({
            "step_id": "step4",
            "selection_options": [{}],
        }, "continue"))

        self.assertEqual(run_step._without_background_flag(None), [])
        self.assertEqual(
            run_step._without_background_flag(["--background", "--step", "step1"]),
            ["--step", "step1"],
        )
        self.assertEqual(
            run_step._resolve_branch_value_for_run_context(
                None, {"base_branch": "persisted"}, "base_branch", "default", False,
            ),
            "default",
        )
        self.assertEqual(
            run_step._resolve_branch_value_for_run_context(
                [], {"base_branch": "persisted"}, "base_branch", "default", True,
            ),
            "persisted",
        )

        with patch.object(run_step, "_matching_step1_ref_binding", return_value={}):
            sanitized, binding = run_step._sanitize_step1_ref_state(None, "base", "/repo")
        self.assertEqual(sanitized, {})
        self.assertEqual(binding, {})
        with self.assertRaisesRegex(ValueError, "root is not an object"):
            run_step._strict_step4_checkpoint_json(b"[]")

        self.assertEqual(run_step.previous_step_output({"step1": {}}, "step1"), {})
        self.assertEqual(
            run_step.previous_step_output(
                {"step1": {"output": {"value": 1}}}, "step2"
            ),
            {"value": 1},
        )
        self.assertEqual(run_step.step_output_paths_for_cleanup(None, "/tmp/report"), [])

    def test_json_csv_manifest_and_state_fallback_matrix(self):
        with patch.object(run_step, "read_json", return_value=[]):
            self.assertEqual(run_step._read_background_json("status.json"), {})
        with patch.object(run_step, "read_json", side_effect=ValueError("bad")):
            self.assertEqual(run_step._read_background_json("status.json"), {})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text('{"steps": []}', encoding="utf-8")
            with self.assertRaises(run_step.StepError):
                run_step.load_manifest(manifest)

            missing_rules = root / "missing-rules.txt"
            with patch.object(run_step, "CHECKPOINT_RULES_FILE", missing_rules):
                self.assertEqual(run_step.load_checkpoint_rules(), [])

            output = root / "rows.csv"
            run_step.write_csv_rows(output, None, ["value"])
            self.assertEqual(output.read_text(encoding="utf-8-sig").strip(), "value")
            run_step.write_csv_rows(output, [{"value": None}, {"value": "x"}], ["value"])
            with output.open(encoding="utf-8-sig", newline="") as handle:
                self.assertEqual(list(csv.DictReader(handle)), [{"value": ""}, {"value": "x"}])

            selected = root / "selected.csv"
            with patch.object(run_step, "ALL_CHANGED_APIS_FIELDS", ("coord",)):
                run_step.write_step5_selected_input(selected, {"matched_rows": None})
                run_step.write_step5_selected_input(
                    selected, {"matched_rows": [{"coord": "g:a"}]}
                )
            self.assertIn("g:a", selected.read_text(encoding="utf-8-sig"))

            csv_path = root / "input.csv"
            csv_path.write_text("value\nkept\n", encoding="utf-8")
            with patch.object(csv, "DictReader", return_value=[None, {"value": " kept "}]):
                self.assertEqual(run_step.read_csv_rows(csv_path), [{"value": "kept"}])

        main_state = {step: {"input": {}, "derived": {}, "output": {}} for step in run_step.STEP_SEQUENCE}
        main_state["state"] = {}
        run_step.store_step_input(main_state, "step1", None)
        self.assertEqual(main_state["step1"]["input"], {})
        with patch.object(run_step, "build_step_derived_snapshot", return_value={}), patch.object(
            run_step, "_sanitize_git_persistence_payload", side_effect=lambda value: value,
        ):
            run_step.store_step_output(main_state, "step1", None, "/tmp/report")
        self.assertEqual(main_state["step1"]["output"], {})

        normalized = {"state": {}}
        with patch.object(
            run_step, "ensure_main_state_structure", return_value=normalized,
        ), patch.object(run_step, "write_json") as write_json, patch.object(
            run_step, "write_report_landing_docs",
        ):
            run_step.save_main_state("/tmp/report", {"state": {}})
        write_json.assert_called_once()

    def test_lock_ref_active_descriptor_and_git_failure_matrix(self):
        timeout_manager = _LockManager(enter_error=TimeoutError("busy"))
        with patch.object(
            run_step, "exclusive_file_lock", return_value=timeout_manager,
        ), self.assertRaises(run_step.StepError) as caught:
            with run_step._binary_step4_pipeline_writer_lock(
                "/tmp/report", timeout_seconds=0, operation="handoff",
            ):
                pass
        self.assertIn("DEFERRED_HANDOFF", caught.exception.reason_codes[0])

        env_manager = _LockManager()
        with patch.object(
            run_step, "exclusive_file_lock", return_value=env_manager,
        ), patch.dict(
            os.environ, {"JUA_STEP4_RUN_LOCK_TIMEOUT_SECONDS": "2.5"}, clear=False,
        ):
            with run_step._binary_step4_serialization_lock("/tmp/report") as value:
                self.assertEqual(value, "locked")
        self.assertEqual(len(env_manager.exit_calls), 1)

        with patch.object(
            run_step, "read_pending_binary_generation", return_value=None,
        ), patch.object(
            run_step, "read_active_binary_generation", return_value=None,
        ):
            self.assertEqual(
                run_step._read_step4_active_descriptor("/tmp/report", missing_ok=True),
                {},
            )

        with patch.object(run_step, "run_cmd", return_value=("", "failed", 1)):
            self.assertIsNone(run_step._git_repository_root("/tmp"))
        with patch.object(run_step, "run_cmd", return_value=("", "", 0)):
            self.assertIsNone(run_step._git_repository_root("/tmp"))

        unavailable_manager = _LockManager(enter_error=OSError("denied"))
        with patch.object(
            run_step, "exclusive_file_lock", return_value=unavailable_manager,
        ), self.assertRaises(run_step.StepError) as unavailable:
            with run_step._binary_step4_pipeline_writer_lock(
                "/tmp/report", timeout_seconds=0, operation="handoff",
            ):
                pass
        self.assertIn("DEFERRED_HANDOFF", unavailable.exception.reason_codes[0])

    def test_remaining_small_boolean_and_progress_matrix(self):
        self.assertEqual(
            run_step._binary_runtime_overrides({"base_jdk_home": "/jdk"}),
            {"base_jdk_home": "/jdk"},
        )
        self.assertFalse(run_step._is_step4_scope_confirmation({
            "step_id": "step4", "selection_options": [{}],
        }, None))
        self.assertEqual(run_step.previous_step_output({}, "step0"), {})
        self.assertEqual(
            run_step._resolve_branch_value_for_run_context(
                "   ", {"base_branch": "saved"}, "base_branch", "default", False,
            ),
            "default",
        )
        self.assertEqual(
            run_step._resolve_branch_value_for_run_context(
                " main ", {}, "base_branch", "default", False,
            ),
            "main",
        )

        progress_cases = (
            ({"progress_bound_to_attempt": False}, (True, {})),
            ({
                "progress_bound_to_attempt": True,
                "attempt_identity": "attempt",
                "last_progress": [],
            }, (True, {})),
            ({
                "progress_bound_to_attempt": True,
                "attempt_identity": "attempt",
                "last_progress": {"attempt_identity": "other"},
            }, (True, {})),
            ({
                "progress_bound_to_attempt": True,
                "attempt_identity": "attempt",
                "last_progress": {"attempt_identity": "attempt", "phase": "scan"},
            }, (True, {"attempt_identity": "attempt", "phase": "scan"})),
        )
        for failure, expected in progress_cases:
            with self.subTest(failure=failure), patch.object(
                run_step, "_binary_pipeline_failure_payload", return_value=failure,
            ):
                self.assertEqual(run_step._attempt_bound_child_progress({}), expected)

        self.assertFalse(run_step._background_starting_claim_is_fresh({}, 0))
        self.assertTrue(run_step._background_starting_claim_is_fresh(
            {"starting_deadline_epoch": "2"}, 1,
        ))
        with patch.object(run_step.time, "time", return_value=3):
            self.assertFalse(run_step._background_starting_claim_is_fresh(
                {"starting_deadline_epoch": 2}, None,
            ))

        self.assertEqual(run_step._dependency_source_side_choices({}), [{}])
        self.assertEqual(
            run_step._dependency_source_side_choices({"candidates": [{"ref": "main"}]}),
            [{"ref": "main"}],
        )
        self.assertFalse(run_step._is_high_risk_selection_api_row(None))
        self.assertTrue(run_step._is_high_risk_selection_api_row({"severity": "p1"}))
        self.assertTrue(run_step._is_high_risk_selection_api_row({
            "severity": "", "change_type": "removed",
        }))

    def test_source_plan_resume_and_workflow_context_matrix(self):
        with patch.object(run_step, "normalize_source_dirs", return_value=["/explicit"]):
            self.assertEqual(
                run_step._resolve_source_dirs_plan("/repo")["status"], "explicit",
            )
        with patch.object(run_step, "normalize_source_dirs", return_value=[]):
            self.assertEqual(
                run_step._resolve_source_dirs_plan(
                    "/repo", project_scope={"source_roots": ["/scope"]},
                )["status"],
                "project_scope",
            )
        with patch.object(run_step, "normalize_source_dirs", return_value=[]), patch.object(
            run_step, "detect_source_dirs", return_value=[],
        ):
            self.assertEqual(
                run_step._resolve_source_dirs_plan("/repo", project_scope=None)["status"],
                "missing",
            )

        self.assertEqual(run_step._resume_boundary_lines(None, None), [])
        self.assertEqual(
            len(run_step._resume_boundary_lines("step2", "step1")), 2,
        )
        self.assertEqual(
            len(run_step._resume_boundary_lines("unknown", "step1")), 1,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "folder"
            folder.mkdir()
            file_path = root / "file.txt"
            file_path.write_text("x", encoding="utf-8")
            self.assertEqual(run_step._resume_display_path("folder", root), "folder/")
            self.assertEqual(run_step._resume_display_path(file_path, root), "file.txt")
            outside = root.parent / "outside.txt"
            self.assertEqual(run_step._resume_display_path(outside, root), str(outside.resolve()))

        context = run_step._WORKFLOW_MUTATION_CONTEXT
        old_values = (
            getattr(context, "depth", None),
            getattr(context, "process_id", None),
            getattr(context, "report_roots", None),
        )
        try:
            context.depth = 0
            context.process_id = os.getpid()
            context.report_roots = ()
            self.assertFalse(run_step._workflow_mutation_lock_is_held())
            context.depth = 1
            context.process_id = os.getpid() + 1
            self.assertFalse(run_step._workflow_mutation_lock_is_held())
            context.process_id = os.getpid()
            context.report_roots = ()
            self.assertFalse(run_step._workflow_mutation_lock_is_held("/tmp/report"))
            context.report_roots = (Path("/tmp/report").resolve(),)
            self.assertTrue(run_step._workflow_mutation_lock_is_held())
            self.assertTrue(run_step._workflow_mutation_lock_is_held("/tmp/report"))
            self.assertFalse(run_step._workflow_mutation_lock_is_held("/tmp/other"))
        finally:
            context.depth, context.process_id, context.report_roots = old_values

        default_report = Path(".upgrade-report").resolve()
        self.assertEqual(
            run_step._workflow_report_dir_from_argv(["--report-dir"]),
            default_report,
        )
        self.assertEqual(
            run_step._workflow_report_dir_from_argv(["--report-dir", ""]),
            default_report,
        )
        self.assertEqual(
            run_step._workflow_report_dir_from_argv(["--report-dir", "/tmp/custom"]),
            Path("/tmp/custom").resolve(),
        )

    def test_cleanup_binding_and_private_checkpoint_matrix(self):
        directory_stat = SimpleNamespace(st_mode=0o040755)
        with patch.object(run_step.os, "stat", return_value=directory_stat), patch.object(
            run_step.os, "fstat", return_value=directory_stat,
        ), patch.object(run_step.os.path, "samestat", side_effect=[False]):
            with self.assertRaises(OSError):
                run_step._verify_cleanup_directory_binding(1, "child", 2, directory_stat)
        with patch.object(run_step.os, "stat", return_value=directory_stat), patch.object(
            run_step.os, "fstat", return_value=directory_stat,
        ), patch.object(run_step.os.path, "samestat", side_effect=[True, False]):
            with self.assertRaises(OSError):
                run_step._verify_cleanup_directory_binding(1, "child", 2, directory_stat)
        with patch.object(
            run_step, "_windows_cleanup_directory_stat", return_value=directory_stat,
        ), patch.object(run_step.os.path, "samestat", return_value=False):
            with self.assertRaises(OSError):
                run_step._verify_windows_cleanup_bindings([(Path("child"), directory_stat)])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkpoint = root / "checkpoint.json"
            checkpoint.write_bytes(b'{"status":"ready"}')
            self.assertEqual(
                run_step._read_private_step4_checkpoint(checkpoint),
                b'{"status":"ready"}',
            )
            descriptor = os.open(root, os.O_RDONLY)
            try:
                self.assertEqual(
                    run_step._read_private_step4_checkpoint(
                        checkpoint.name, parent_fd=descriptor,
                    ),
                    b'{"status":"ready"}',
                )
            finally:
                os.close(descriptor)

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            child = report / "child.txt"
            child.write_text("x", encoding="utf-8")
            with patch.object(
                run_step, "_secure_step_output_cleanup_supported", return_value=True,
            ), patch.object(
                run_step,
                "_remove_step_output_with_directory_descriptors",
                return_value=True,
            ):
                self.assertTrue(
                    run_step._remove_step_output_without_following_parent_links(
                        report, child,
                    )
                )

    def test_gate_receipt_git_error_prune_and_information_matrix(self):
        receipts = (
            ({}, False),
            ({"gate_receipt": {}}, False),
            ({
                "gate_receipt": {
                    "gate_name": "",
                    "strict_risk_gate": True,
                }
            }, True),
            ({
                "gate_receipt": {
                    "gate_name": "gate",
                    "strict_risk_gate": True,
                }
            }, True),
        )
        for receipt, expected in receipts:
            with self.subTest(receipt=receipt), patch.object(
                run_step, "report_publication_committed_receipt", return_value=receipt,
            ):
                self.assertIs(
                    run_step._downstream_gate_policy_is_current(
                        "/tmp/report", "step6",
                        expected_gate_name=(
                            None
                            if receipt.get("gate_receipt", {}).get("gate_name") == ""
                            else "gate"
                        ),
                        expected_strict_risk_gate=True,
                    ),
                    expected,
                )

        git_failures = (
            ("", "", 1, "git exited with 1"),
            ("stdout-detail", "", 1, "stdout-detail"),
            ("", "stderr-detail", 1, "stderr-detail"),
            ("", "", 0, "git exited with 0"),
        )
        for stdout, stderr, rc, message in git_failures:
            with self.subTest(rc=rc, message=message), patch.object(
                run_step, "run_cmd", return_value=(stdout, stderr, rc),
            ), self.assertRaises(run_step.StepError) as caught:
                run_step._pinned_source_git_root("/repo")
            self.assertIn(message, str(caught.exception))

        class ReasonedError(RuntimeError):
            reason_code = "GC_FAILED"

        for error, expected_reason in (
            (RuntimeError("plain"), ""),
            (ReasonedError("reasoned"), "GC_FAILED"),
        ):
            captured = {}
            with self.subTest(error=type(error).__name__), patch.object(
                run_step, "prune_unreferenced_binary_generations", side_effect=error,
            ), patch.object(
                run_step, "write_json", side_effect=lambda _path, value: captured.update(value),
            ):
                run_step._prune_binary_step4_generations_best_effort("/tmp/report")
            self.assertEqual(captured["failures"][0]["reason_code"], expected_reason)

        for step_id, expected_fragment in (
            ("step5", "调用关系分析已完成"),
            ("step2", "本阶段已完成"),
        ):
            with patch.object(
                run_step, "build_user_decision_card", return_value={},
            ):
                card = run_step.build_informational_success_interaction(step_id, None)
            self.assertIn(expected_fragment, card["question"])

    def test_interaction_file_clear_save_and_step_reset_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            interaction_path = run_step.runtime_state_dir(report) / "interaction.json"
            interaction_path.parent.mkdir(parents=True)
            interaction_path.write_text(
                json.dumps({"status": "informational"}), encoding="utf-8",
            )
            run_step.clear_interaction_file(report, preserve_informational=True)
            self.assertTrue(interaction_path.exists())
            interaction_path.write_text(
                json.dumps({"status": "awaiting_user"}), encoding="utf-8",
            )
            run_step.clear_interaction_file(report, preserve_informational=True)
            self.assertFalse(interaction_path.exists())
            interaction_path.write_text("{}", encoding="utf-8")
            run_step.clear_interaction_file(report, preserve_informational=True)
            self.assertFalse(interaction_path.exists())

            with patch.object(run_step, "write_json") as write:
                run_step.save_interaction_file(report, None)
                write.assert_not_called()
                run_step.save_interaction_file(report, {"status": "informational"})
                write.assert_called_once()

        state = {
            step: {"input": {"old": True}, "derived": {}, "output": {}}
            for step in run_step.STEP_SEQUENCE
        }
        run_step.clear_steps_from(state, "step2", preserve_current_input=None)
        self.assertEqual(state["step2"]["input"], {})
        run_step.clear_steps_from(state, "step2", preserve_current_input={})
        self.assertEqual(state["step2"]["input"], {})

        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            run_step.print_auto_continue_success_review("step2", {})
            run_step.print_auto_continue_success_review("step5", {})
            run_step.print_auto_continue_success_review("step1", {})
        self.assertIn("升级上下文", stderr.getvalue())
        self.assertIn("最终报告", stderr.getvalue())

    def test_refresh_step2_branch_completeness_matrix(self):
        with patch.object(run_step, "ensure_exists"), patch.object(
            run_step, "run_python",
        ) as run_python:
            for context in (
                {},
                {"base_branch": "base"},
                {"current_branch": "current"},
            ):
                with self.subTest(context=context), self.assertRaises(run_step.StepError):
                    run_step.refresh_step2_outputs("/tmp/report", "/tmp/project", context)
            run_step.refresh_step2_outputs(
                "/tmp/report", "/tmp/project",
                {"base_branch": "base", "current_branch": "current"},
            )
        run_python.assert_called_once()

    def test_report_selection_integrity_and_application_source_failure_matrix(self):
        with patch.object(
            run_step,
            "build_step5_dependency_selection_summary",
            return_value={"available_targets": [{"coord": "", "name": ""}]},
        ), patch.object(
            run_step, "build_interaction_selection_options", side_effect=lambda rows: rows,
        ), patch.object(
            run_step, "build_selection_resolution", side_effect=lambda rows: rows,
        ):
            resolution = run_step.build_report_dir_step5_selection_resolution("/tmp/report")
        self.assertEqual(resolution[0]["label"], "")

        self.assertEqual(run_step.detect_integrity_repair_step(None, "/tmp/report"), "")
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            with patch.object(run_step, "is_dependency_source_git_url", return_value=False), patch.object(
                run_step, "_git_repository_root", return_value=None,
            ):
                with self.assertRaises(run_step.StepError) as caught:
                    run_step.materialize_application_source(
                        str(project), project, project / "report"
                    )
            self.assertIn("APPLICATION_SOURCE_GIT_REQUIRED", caught.exception.reason_codes)

    def test_recovery_result_and_cli_without_report_matrix(self):
        with patch.object(
            run_step, "_startup_step4_recovery_target_hint", return_value="step4",
        ), patch.object(
            run_step, "_recover_binary_step4_transaction", return_value={"status": "none"},
        ), patch.object(
            run_step, "_classify_step4_recovery_disposition", return_value=None,
        ), patch.object(
            run_step, "_apply_step4_startup_recovery", return_value={},
        ):
            result = run_step._recover_and_apply_step4_startup_state_under_locks(
                args=SimpleNamespace(),
                main_state={},
                report_dir="/tmp/report",
                project_dir="/tmp/project",
                manifest_steps={},
                structured_user_response={},
                has_structured_response=False,
                gate_name="gate",
                strict_risk_gate=False,
            )
        self.assertEqual(result["decision"], {})
        self.assertEqual(result["target_hint"], "step4")
        self.assertEqual(run_step._record_unexpected_cli_error(RuntimeError("x"), []), "")

    def test_root_cleanup_and_interaction_blocking_fallback_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            with self.assertRaises(run_step.StepError) as caught:
                run_step._remove_step_output_without_following_parent_links(report, report)
            self.assertIn("WORKFLOW_OUTPUT_CLEANUP_PATH_UNSAFE", caught.exception.reason_codes)

        main_state = {
            step: {"input": {}, "derived": {}, "output": {}}
            for step in run_step.STEP_SEQUENCE
        }
        main_state["state"] = {}
        with patch.object(run_step, "store_step_output"), patch.object(
            run_step, "seed_next_step_input",
        ), patch.object(
            run_step,
            "apply_interaction_protocol_enhancements",
            return_value={"step_id": "step4", "status": "awaiting_user"},
        ), patch.object(
            run_step, "_sanitize_git_persistence_payload", side_effect=lambda value: value,
        ), patch.object(run_step, "save_main_state"), patch.object(
            run_step, "save_interaction_file",
        ), patch.object(run_step, "write_resume_snapshot"), patch.object(
            run_step, "write_coverage_report",
        ), patch.object(
            run_step, "current_step_for_pending_interaction", return_value="step4",
        ):
            interaction = run_step.persist_step_interaction(
                main_state, "step4", "/tmp/report", {}, {}
            )
        self.assertEqual(interaction["step_id"], "step4")
        self.assertEqual(main_state["state"]["blocking_reason"], "step4")

    def test_step6_internal_input_failure_owner_authentication_matrix(self):
        structured = {
            "schema": "java-upgrade-analyzer.binary-report-publication-failure.v1",
            "status": "failed",
            "phase": "step6",
            "reason_code": "BINARY_STEP6_INTERNAL_INPUT_INVALID",
            "owner_step": "step2",
            "failure_contract": {
                "schema": "java-upgrade-analyzer.step6-internal-input-failure.v1",
                "status": "failed",
                "owner_step": "step2",
                "failures": [{"owner_step": "step3"}, {"owner_step": "step2"}],
            },
        }

        def classify(value):
            return run_step.step6_internal_input_failure_owner_from_step_error(value)

        self.assertEqual(
            classify(run_step.StepError("failed", diagnostic={"structured_result": structured})),
            "step2",
        )
        alternate = copy.deepcopy(structured)
        alternate["reason_code"] = "BINARY_STEP6_UPSTREAM_EVIDENCE_MISSING"
        self.assertEqual(
            classify(run_step.StepError("failed", diagnostic={"structured_result": alternate})),
            "step2",
        )
        self.assertIsNone(classify(RuntimeError("not authenticated")))
        self.assertIsNone(classify(run_step.StepError("missing diagnostic")))
        self.assertIsNone(
            classify(run_step.StepError("bad payload", diagnostic={"structured_result": []}))
        )

        mutations = (
            ("publication schema", lambda value: value.update(schema="wrong")),
            ("publication status", lambda value: value.update(status="passed")),
            ("publication phase", lambda value: value.update(phase="step5")),
            ("publication reason", lambda value: value.update(reason_code="OTHER")),
            ("missing owner", lambda value: value.update(owner_step="")),
            ("invalid owner", lambda value: value.update(owner_step="step6")),
            ("contract type", lambda value: value.update(failure_contract=[])),
            (
                "contract schema",
                lambda value: value["failure_contract"].update(schema="wrong"),
            ),
            (
                "contract status",
                lambda value: value["failure_contract"].update(status="passed"),
            ),
            (
                "contract owner mismatch",
                lambda value: value["failure_contract"].update(owner_step="step1"),
            ),
            (
                "failures type",
                lambda value: value["failure_contract"].update(failures={}),
            ),
            (
                "failures empty",
                lambda value: value["failure_contract"].update(failures=[]),
            ),
            (
                "failure item type",
                lambda value: value["failure_contract"].update(failures=[None]),
            ),
            (
                "failure owner missing",
                lambda value: value["failure_contract"].update(
                    failures=[{"owner_step": ""}]
                ),
            ),
            (
                "failure owner invalid",
                lambda value: value["failure_contract"].update(
                    failures=[{"owner_step": "step6"}]
                ),
            ),
            (
                "earliest owner mismatch",
                lambda value: value["failure_contract"].update(
                    failures=[{"owner_step": "step1"}, {"owner_step": "step2"}]
                ),
            ),
        )
        for label, mutate in mutations:
            candidate = copy.deepcopy(structured)
            mutate(candidate)
            with self.subTest(label=label):
                self.assertIsNone(
                    classify(
                        run_step.StepError(
                            "failed", diagnostic={"structured_result": candidate}
                        )
                    )
                )

    def test_environment_block_message_exhaustive_component_matrix(self):
        no_details = "\n".join(run_step.build_environment_block_message(None))
        self.assertIn("缺少可识别的失败明细", no_details)
        self.assertIn("业务输入和分析范围无需修改", no_details)

        python_failures = {
            "checks": [
                {
                    "component": "python_package:lxml",
                    "status": "failed",
                    "observed": "5.0",
                    "expected": "6.0",
                },
                {
                    "component": "python_import:yaml",
                    "status": "failed",
                    "observed": "",
                    "expected": "",
                },
                {"component": "python", "status": "passed"},
            ]
        }
        python_text = "\n".join(
            run_step.build_environment_block_message(python_failures)
        )
        self.assertIn("Python 依赖 lxml：当前为 5.0；需要 6.0", python_text)
        self.assertIn("Python 模块 yaml：当前为 未检测到；需要 可正常使用", python_text)
        self.assertIn("bootstrap_runtime.py", python_text)
        self.assertNotIn("Python 运行时：", python_text)

        mixed_text = "\n".join(
            run_step.build_environment_block_message(
                {
                    "checks": [
                        {"component": "tool:mvn", "status": "failed"},
                        {"component": "platform", "status": "failed"},
                        {"component": "custom", "status": "failed"},
                        {"component": "", "status": "failed"},
                    ]
                }
            )
        )
        self.assertIn("命令行工具 mvn", mixed_text)
        self.assertIn("操作系统", mixed_text)
        self.assertIn("custom", mixed_text)
        self.assertIn("运行组件", mixed_text)
        self.assertNotIn("bootstrap_runtime.py", mixed_text)

    def test_dependency_coordinate_collection_truth_table(self):
        rows = [
            {},
            {"coord": "g:unchanged", "change_type": "未变"},
            {"coord": "g:unresolved", "resolution_status": "unresolved"},
            {"coord": "g:empty", "old_version": "-", "new_version": "-"},
            {
                "coord": " g:kept ",
                "change_type": "升级",
                "resolution_status": "resolved",
                "old_version": "1",
                "new_version": "2",
            },
            {"coord": "g:kept", "change_type": "新增", "new_version": "2"},
            {"coord": "g:other", "change_type": "删除", "old_version": "1"},
        ]
        with patch.object(run_step, "read_csv_rows", return_value=rows):
            self.assertEqual(
                run_step._collect_relevant_dependency_coords("/tmp/report", {}),
                ["g:kept", "g:other"],
            )

        fallback = {
            "changed_dependencies": [
                {},
                {"coord": " g:fallback "},
                {"coord": "g:fallback"},
                {"coord": "g:second"},
            ]
        }
        with patch.object(run_step, "read_csv_rows", return_value=[]):
            self.assertEqual(
                run_step._collect_relevant_dependency_coords("/tmp/report", fallback),
                ["g:fallback", "g:second"],
            )
        with patch.object(run_step, "read_csv_rows", return_value=[]), patch.object(
            run_step.Path, "exists", return_value=False,
        ):
            self.assertEqual(
                run_step._collect_relevant_dependency_coords("/tmp/report"), []
            )
        with patch.object(run_step, "read_csv_rows", return_value=[]), patch.object(
            run_step.Path, "exists", return_value=True,
        ), patch.object(run_step, "read_json", return_value=fallback):
            self.assertEqual(
                run_step._collect_relevant_dependency_coords("/tmp/report"),
                ["g:fallback", "g:second"],
            )

    def test_durable_step1_binding_failure_matrix(self):
        commit = "a" * 40
        repo = "/tmp/repository"
        self.assertEqual(
            run_step._durable_step1_ref_binding_from_failure(
                None, repo, "main"
            ),
            {},
        )
        self.assertEqual(
            run_step._durable_step1_ref_binding_from_failure(
                {"expected_commit": "short"}, repo, "main"
            ),
            {},
        )
        inferred = run_step._durable_step1_ref_binding_from_failure(
            {
                "expected_commit": commit.upper(),
                "candidates": [
                    None,
                    {"commit": "b" * 40, "remote": "wrong"},
                    {
                        "commit": commit,
                        "remote": "origin",
                        "canonical_ref": "refs/remotes/origin/main",
                    },
                ],
            },
            repo,
            "main",
            artifact_path="/tmp/a.jar",
        )
        self.assertEqual(inferred["remote"], "origin")
        self.assertEqual(inferred["canonical_ref"], "refs/remotes/origin/main")
        self.assertEqual(inferred["expected_commit"].lower(), commit.lower())

        explicit = run_step._durable_step1_ref_binding_from_failure(
            {
                "expected_commit": commit,
                "remote": "upstream",
                "remote_ref": "refs/heads/main",
                "candidates": [
                    {
                        "commit": commit,
                        "remote": "origin",
                        "canonical_ref": "refs/remotes/origin/main",
                    },
                    {
                        "commit": commit,
                        "remote": "mirror",
                        "canonical_ref": "refs/remotes/mirror/main",
                    },
                ],
            },
            repo,
            "main",
        )
        self.assertEqual(explicit["remote"], "upstream")
        self.assertEqual(explicit["canonical_ref"], "refs/heads/main")

        existing = run_step._durable_step1_ref_binding_from_failure(
            {"expected_commit": commit, "candidates": []},
            repo,
            "main",
            existing_binding={
                "expected_commit": commit.upper(),
                "remote": "origin",
                "canonical_ref": "refs/remotes/origin/main",
            },
        )
        self.assertEqual(existing["remote"], "origin")
        self.assertEqual(
            run_step._durable_step1_ref_binding_from_failure(
                {"expected_commit": commit},
                repo,
                "main",
                existing_binding={"expected_commit": "b" * 40},
            ),
            {},
        )
        self.assertEqual(
            run_step._durable_step1_ref_binding_from_failure(
                {
                    "expected_commit": commit,
                    "remote": "origin",
                    "remote_ref": "",
                },
                repo,
                "main",
            ),
            {},
        )

    def test_step5_selection_and_scope_truth_table(self):
        rows = [
            None,
            {"coord": ""},
            {"coord": "g:a", "change_type": "REMOVED", "severity": "P1"},
            {"coord": "g:a", "change_type": "ADDED", "severity": "P4"},
            {"coord": "g:b", "change_type": "", "severity": "P2"},
        ]
        all_targets = run_step.build_step5_selection_summary(rows)
        self.assertEqual(all_targets["matched_rows"], rows)
        self.assertEqual(
            [item["coord"] for item in all_targets["available_targets"]],
            ["g:a", "g:b"],
        )
        self.assertEqual(all_targets["available_targets"][0]["api_count"], 2)
        self.assertEqual(
            all_targets["available_targets"][0]["change_types"], "ADDED, REMOVED"
        )

        selected = run_step.build_step5_selection_summary(
            rows,
            selected_coords=["G:A", "g:missing"],
            selected_names=["b", "missing-name"],
        )
        self.assertEqual(selected["matched_coords"], ["g:a"])
        self.assertEqual(selected["matched_names"], ["b"])
        self.assertEqual(selected["unmatched_coords"], ["g:missing"])
        self.assertEqual(selected["unmatched_names"], ["missing-name"])
        self.assertEqual(selected["matched_row_count"], 3)

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report"
            input_path = Path(directory) / "all.csv"
            input_path.write_text("unused", encoding="utf-8")
            persisted = []
            with patch.object(run_step, "read_csv_rows", return_value=rows[2:]), patch.object(
                run_step, "write_json", side_effect=lambda _path, value: persisted.append(value)
            ):
                base, summary = run_step.materialize_step5_all_changed_apis_input(
                    input_path, report, {}
                )
            self.assertEqual(base, input_path)
            self.assertEqual(summary["matched_row_count"], 3)
            self.assertEqual(persisted[-1]["mode"], "full")
            self.assertEqual(persisted[-1]["selection_basis"], "all_targets")

            with patch.object(run_step, "read_csv_rows", return_value=rows[2:]):
                with self.assertRaisesRegex(run_step.StepError, "全量分析不能同时"):
                    run_step.materialize_step5_all_changed_apis_input(
                        input_path,
                        report,
                        {"step5_scope_mode": "full", "step5_selected_coords": ["g:a"]},
                    )
                with self.assertRaisesRegex(run_step.StepError, "未匹配坐标"):
                    run_step.materialize_step5_all_changed_apis_input(
                        input_path,
                        report,
                        {
                            "step5_scope_mode": "partial",
                            "step5_selected_coords": ["g:missing"],
                        },
                    )
                with self.assertRaisesRegex(run_step.StepError, "未匹配名称"):
                    run_step.materialize_step5_all_changed_apis_input(
                        input_path,
                        report,
                        {
                            "step5_scope_mode": "partial",
                            "step5_selected_names": ["missing"],
                        },
                    )

            persisted.clear()
            with patch.object(run_step, "read_csv_rows", return_value=rows[2:]), patch.object(
                run_step, "write_json", side_effect=lambda _path, value: persisted.append(value)
            ):
                filtered, summary = run_step.materialize_step5_all_changed_apis_input(
                    input_path,
                    report,
                    {
                        "step5_scope_mode": "partial",
                        "step5_selected_coords": ["g:a"],
                    },
                )
            self.assertNotEqual(filtered, input_path)
            self.assertTrue(filtered.is_file())
            self.assertEqual(summary["matched_row_count"], 2)
            self.assertEqual(persisted[-1]["mode"], "partial")
            self.assertEqual(persisted[-1]["excluded_dependency_coords"], ["g:b"])

    def test_coord_path_normalization_complete_shape_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            repo = project / "repo"
            repo.mkdir()
            with patch.object(run_step, "infer_maven_coords", return_value=["g:a"]):
                self.assertEqual(
                    run_step.normalize_coord_path_items(
                        [f"g:a={repo}", {"owner_coord": "g:a", "root": str(repo)}],
                        project,
                        "sources",
                    ),
                    [f"g:a={repo.resolve()}"],
                )
                self.assertEqual(
                    run_step.normalize_coord_path_items(
                        [str(repo)],
                        project,
                        "sources",
                        allow_repo_inference=True,
                    ),
                    [f"g:a={repo.resolve()}"],
                )
                self.assertEqual(
                    run_step.normalize_coord_path_items(
                        [{"path": str(repo)}],
                        project,
                        "sources",
                        allow_repo_inference=True,
                        expand_all_inferred=True,
                    ),
                    [f"g:a={repo.resolve()}"],
                )
            with self.assertRaisesRegex(run_step.StepError, "字符串项格式错误"):
                run_step.normalize_coord_path_items([str(repo)], project, "sources")
            with self.assertRaisesRegex(run_step.StepError, "包含 coord 与 path"):
                run_step.normalize_coord_path_items(
                    [{"path": str(repo)}], project, "sources"
                )
            with patch.object(run_step, "looks_like_remote_repo", return_value=True), patch.object(
                run_step.Path, "exists", return_value=False,
            ), self.assertRaisesRegex(run_step.StepError, "暂不支持直接传远程"):
                run_step.normalize_coord_path_items(
                    ["g:a=https://example.invalid/repo.git"], project, "sources"
                )

    def test_user_response_interaction_and_landing_output_matrix(self):
        args = SimpleNamespace(response_json=None, response_file=None)
        self.assertIsNone(run_step.load_user_response(args, Path("/tmp")))
        with self.assertRaisesRegex(run_step.StepError, "不能同时使用"):
            run_step.load_user_response(
                SimpleNamespace(response_json="{}", response_file="response.json"),
                Path("/tmp"),
            )
        self.assertEqual(
            run_step.load_user_response(
                SimpleNamespace(response_json='{"action":"continue"}', response_file=None),
                Path("/tmp"),
            ),
            {"action": "continue"},
        )
        with self.assertRaisesRegex(run_step.StepError, "合法 JSON"):
            run_step.load_user_response(
                SimpleNamespace(response_json="{", response_file=None), Path("/tmp")
            )
        with self.assertRaisesRegex(run_step.StepError, "必须是 JSON 对象"):
            run_step.load_user_response(
                SimpleNamespace(response_json="[]", response_file=None), Path("/tmp")
            )
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            relative = project / "response.json"
            relative.write_text('{"action":"cancel"}', encoding="utf-8")
            self.assertEqual(
                run_step.load_user_response(
                    SimpleNamespace(response_json=None, response_file="response.json"),
                    project,
                ),
                {"action": "cancel"},
            )
            self.assertEqual(
                run_step.load_user_response(
                    SimpleNamespace(response_json=None, response_file=str(relative)),
                    project,
                ),
                {"action": "cancel"},
            )
            with self.assertRaisesRegex(run_step.StepError, "不存在"):
                run_step.load_user_response(
                    SimpleNamespace(response_json=None, response_file="missing.json"),
                    project,
                )

        interaction = {
            "step_id": "step4",
            "title": "选择范围",
            "status": "awaiting_user",
            "fallback_inputs": [{"name": "fallback"}],
            "input_modes": [{"id": "json", "required_fields": []}],
            "options": [{"id": "continue", "label": "继续"}],
            "selection_options": [{"coord": "g:a"}],
        }
        for mode, expect_human, expect_machine in (
            ("human", True, False),
            ("json", False, True),
            ("both", True, True),
            ("invalid", True, True),
        ):
            stdout, stderr = io.StringIO(), io.StringIO()
            with self.subTest(mode=mode), patch.dict(
                os.environ, {"JUA_INTERACTION_OUTPUT": mode}, clear=False,
            ), patch("sys.stdout", stdout), patch("sys.stderr", stderr):
                run_step.print_interaction_to_streams(interaction, "/tmp/report")
            self.assertEqual("分析已暂停" in stderr.getvalue(), expect_human)
            self.assertEqual("JUA_CONFIRMATION_JSON:" in stdout.getvalue(), expect_machine)
            if expect_machine:
                payload = json.loads(stdout.getvalue().split(":", 1)[1])
                self.assertEqual(payload["fallback_inputs"], [{"name": "fallback"}])
                self.assertEqual(payload["selection_options"], [{"coord": "g:a"}])
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            run_step.print_interaction_to_streams(None, "/tmp/report")
        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", ""))

        status_cases = (
            (None, "尚未开始"),
            ({"state": {"status": "awaiting_custom", "current_step": "step2"}}, "等待你确认"),
            ({"state": {"status": "paused_by_user", "current_step": "step2"}}, "安全重试"),
            ({"state": {"status": "paused_by_user", "current_step": "step2", "pending_interaction": {"id": 1}}}, "回到当前确认任务"),
            ({"state": {"status": "blocked_by_system", "current_step": "step3"}}, "分析未完成"),
            ({"state": {"status": "blocked_by_system", "current_step": "step3", "blocking_reason": "tool failed"}}, "tool failed"),
            ({"state": {"current_step": "step3", "completed_step": "step2"}}, "已完成"),
            ({"state": {"current_step": "done", "status": "completed"}}, "分析已完成"),
            ({"state": {"current_step": "done", "status": "completed", "completion_summary": {"scope_mode": "full"}}}, "全部变化依赖"),
            ({"state": {"current_step": "done", "status": "completed", "completion_summary": {"scope_mode": "unknown"}}}, "不支持全量结论"),
            ({"state": {"current_step": "done", "status": "completed_with_limits", "completion_summary": {"scope_mode": "partial", "included_dependency_count": 1, "available_dependency_count": 2, "limitations": ["证据不足"]}}}, "证据不足"),
        )
        for state, expected in status_cases:
            with self.subTest(expected=expected):
                self.assertIn(expected, "\n".join(run_step._landing_status_lines(state)))

    def test_step1_runtime_artifact_preflight_truth_table(self):
        with patch.object(
            run_step,
            "materialize_binary_pipeline_config",
            side_effect=run_step.BinaryRuntimeMaterializationError(
                "BINARY_CONFIG_INVALID", "bad config"
            ),
        ), self.assertRaises(run_step.StepError) as caught:
            run_step.validate_step1_runtime_inputs({}, "/tmp/report")
        self.assertEqual(
            caught.exception.reason_codes,
            ["STEP1_RUNTIME_PREFLIGHT_FAILED", "BINARY_CONFIG_INVALID"],
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            valid_jar = root / "valid.jar"
            with zipfile.ZipFile(valid_jar, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
                archive.writestr("example/A.class", b"class-bytes")
            valid_sha = hashlib.sha256(valid_jar.read_bytes()).hexdigest()

            def run_config(config):
                with patch.object(
                    run_step, "materialize_binary_pipeline_config", return_value=config
                ):
                    return run_step.validate_step1_runtime_inputs(
                        {"base_jdk_home": "/jdk"}, report
                    )

            for artifact, reason in (
                ({"path": str(valid_jar), "content_sha256": ""}, "IDENTITY_INVALID"),
                ({"path": str(root / "missing.jar"), "content_sha256": "a" * 64}, "DIGEST_MISMATCH"),
                ({"path": str(valid_jar), "content_sha256": "b" * 64}, "DIGEST_MISMATCH"),
            ):
                with self.subTest(reason=reason), self.assertRaises(
                    run_step.StepError
                ) as error:
                    run_config({"base": {"artifacts": [artifact]}, "current": {}})
                self.assertIn(
                    f"STEP1_RUNTIME_ARTIFACT_{reason}", error.exception.reason_codes
                )

            invalid_jar = root / "invalid.jar"
            invalid_jar.write_bytes(b"not a zip")
            invalid_sha = hashlib.sha256(invalid_jar.read_bytes()).hexdigest()
            with self.assertRaises(run_step.StepError) as invalid:
                run_config(
                    {
                        "base": {},
                        "current": {
                            "artifacts": [
                                {
                                    "path": str(invalid_jar),
                                    "content_sha256": invalid_sha,
                                }
                            ]
                        },
                    }
                )
            self.assertIn(
                "STEP1_RUNTIME_ARTIFACT_INVALID", invalid.exception.reason_codes
            )

            class CorruptArchive:
                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return False

                def infolist(self):
                    return [object()]

                def testzip(self):
                    return "example/A.class"

            with patch.object(run_step.zipfile, "ZipFile", return_value=CorruptArchive()), self.assertRaises(
                run_step.StepError
            ) as corrupt:
                run_config(
                    {
                        "base": {
                            "artifacts": [
                                {
                                    "path": str(valid_jar),
                                    "content_sha256": valid_sha,
                                }
                            ]
                        },
                        "current": None,
                    }
                )
            self.assertIn(
                "STEP1_RUNTIME_ARTIFACT_CORRUPT", corrupt.exception.reason_codes
            )

            payload = run_config(
                {
                    "base": {
                        "artifacts": [
                            {"path": str(valid_jar), "content_sha256": valid_sha}
                        ]
                    },
                    "current": {
                        "artifacts": [
                            {"path": str(valid_jar), "content_sha256": valid_sha}
                        ]
                    },
                }
            )
            self.assertEqual(payload["status"], "passed")
            self.assertEqual(payload["artifact_count"], 2)
            self.assertEqual(
                [item["side"] for item in payload["artifacts"]],
                ["base", "current"],
            )
            self.assertEqual(
                len(payload["step1_runtime_preflight_identity"]), 64
            )
            self.assertTrue(run_step.step1_runtime_preflight_path(report).is_file())

    def test_final_completion_summary_failure_and_limitation_truth_table(self):
        def summarize(findings, *, release=True):
            with patch.object(
                run_step, "report_uses_release_protocol", return_value=release
            ), patch.object(
                run_step,
                "load_consistent_step6_publication",
                return_value={"findings": findings},
            ):
                return run_step.build_final_completion_summary("/tmp/report")

        missing = summarize(None)
        self.assertEqual(missing["status"], "completed_with_limits")
        self.assertIn("最终结构化结果缺失或无法读取", missing["limitations"])

        malformed_populations = (
            [],
            {"total_count": "1", "completed_count": 1, "incomplete_count": 0, "population_unconfirmed": False},
            {"total_count": 1, "completed_count": -1, "incomplete_count": 2, "population_unconfirmed": False},
            {"total_count": 1, "completed_count": 0, "incomplete_count": -1, "population_unconfirmed": False},
            {"total_count": 3, "completed_count": 1, "incomplete_count": 1, "population_unconfirmed": False},
            {"total_count": 1, "completed_count": 1, "incomplete_count": 0, "population_unconfirmed": "false"},
        )
        for population in malformed_populations:
            findings = {
                "schema": "java-upgrade-analyzer.binary-findings.v2",
                "coverage": {"overall_status": "complete"},
                "analysis_scope": {"mode": "full", "validation_status": "valid"},
                "report_population": {
                    "schema": "java-upgrade-analyzer.step6-report-population.v1",
                    "apis": population,
                    "dependencies": {
                        "total_count": 0,
                        "completed_count": 0,
                        "incomplete_count": 0,
                        "population_unconfirmed": False,
                    },
                },
            }
            with self.subTest(population=population):
                summary = summarize(findings)
                self.assertIn(
                    "最终报告对象数量合同缺失或无效", summary["limitations"]
                )

        findings = {
            "schema": "java-upgrade-analyzer.binary-findings.v2",
            "coverage": {"overall_status": "partial"},
            "analysis_scope": {
                "mode": "full",
                "validation_status": "invalid",
                "total_api_count": 2,
                "analyzed_api_count": 2,
                "available_dependency_count": 2,
                "analyzed_dependency_count": 2,
            },
            "probable_impact": [
                "non-object",
                {},
                {"coord": ""},
                {"coord": "g:a"},
                {"coord": "g:a"},
            ],
            "uncertain": [None, {}, {"uncertainty_kind": "analysis_limitation"}],
            "not_analyzed": [{"api": "g:a#missing"}],
            "diagnostics": [{"reason_code": "INPUT_INVALID"}],
            "report_population": {
                "schema": "java-upgrade-analyzer.step6-report-population.v1",
                "apis": {
                    "total_count": 2,
                    "completed_count": 2,
                    "incomplete_count": 0,
                    "population_unconfirmed": True,
                },
                "dependencies": {
                    "total_count": 2,
                    "completed_count": 2,
                    "incomplete_count": 0,
                    "population_unconfirmed": True,
                },
            },
        }
        limited = summarize(findings)
        self.assertEqual(limited["dependency_probable_count"], 1)
        self.assertEqual(limited["probable_count"], 5)
        self.assertEqual(limited["uncertain_candidate_count"], 2)
        self.assertEqual(limited["uncertain_analysis_limitation_count"], 1)
        self.assertIn("分析范围记录未通过一致性校验", limited["limitations"])
        self.assertIn("关键证据覆盖不完整", limited["limitations"])
        self.assertIn("变化依赖总数在不同产物中的记录不一致", limited["limitations"])
        self.assertIn("变化 API 总数在不同产物中的记录不一致", limited["limitations"])
        self.assertIn("1 项未完成分析", limited["limitations"])
        self.assertIn("记录了 1 项输入读取或结构异常", limited["limitations"])

        with patch.object(
            run_step, "report_uses_release_protocol", return_value=True
        ), patch.object(
            run_step,
            "load_consistent_step6_publication",
            side_effect=run_step.BinaryReportError("PUBLICATION_INVALID", "bad"),
        ):
            unreadable = run_step.build_final_completion_summary("/tmp/report")
        self.assertIn("最终结构化结果缺失或无法读取", unreadable["limitations"])

    def test_dependency_binding_and_business_scan_root_truth_table(self):
        empty = run_step._dependency_source_binding_candidate(
            None, None, None, {}, None, None
        )
        self.assertEqual(empty["coord"], "")
        self.assertEqual(empty["repo_path"], "")
        self.assertEqual(empty["source_dirs"], [])
        self.assertEqual(empty["base_ref"], "")

        populated = run_step._dependency_source_binding_candidate(
            " g:a ",
            {
                "repo_path": " /repo ",
                "source_dirs": ["src", "src"],
                "module_roots": ["module"],
            },
            {"base": "1", "current": "2"},
            {
                "base": {"status": "resolved"},
                "current": {"status": "ambiguous"},
            },
            {
                "display_ref": "origin/v1",
                "commit": "a" * 40,
                "remote": "origin",
                "canonical_ref": "refs/tags/v1",
                "aliases": ["v1"],
            },
            {
                "ref": "origin/v2",
                "commit": "b" * 40,
                "remote": "",
                "canonical_ref": "",
                "aliases": [],
            },
        )
        self.assertEqual(populated["coord"], "g:a")
        self.assertEqual(populated["source_dirs"], ["src"])
        self.assertEqual(populated["base_ref"], "origin/v1")
        self.assertEqual(populated["current_ref"], "origin/v2")
        self.assertTrue(populated["selection_key"].startswith("depsrc:"))

        self.assertEqual(run_step.step3_business_scan_roots(None), [])
        self.assertEqual(run_step.step3_business_scan_roots({}, {}), [])
        self.assertEqual(
            run_step.step3_business_scan_roots(
                {}, {"source_dirs": ["src", "src"], "resource_dirs": ["res"]}
            ),
            ["src", "res"],
        )
        self.assertEqual(
            run_step.step3_business_scan_roots(
                {
                    "source_dirs": ["src"],
                    "project_scope": {"resource_roots": ["res", "src"]},
                }
            ),
            ["src", "res"],
        )

    def test_step1_ref_resolution_default_and_failure_truth_table(self):
        self.assertEqual(
            run_step.resolve_step1_refs_for_execution(None, "/tmp/project"),
            ({}, None),
        )
        commit = "a" * 40
        callback_rows = []
        unresolved = {
            "status": "not_found",
            "expected_commit": commit,
            "source_status": "",
            "fingerprint": "",
            "candidates": [],
            "queried_at": "",
        }
        with patch.object(run_step, "resolve_step1_ref", return_value=unresolved), patch.object(
            run_step,
            "build_step1_ref_confirmation_interaction",
            side_effect=lambda _context, requests: {"requests": requests},
        ):
            updated, interaction = run_step.resolve_step1_refs_for_execution(
                {
                    "base_branch": "main",
                    "base_source_project_dir": "/tmp/source",
                },
                "/tmp/project",
                on_side_resolved=lambda context, side, resolution: callback_rows.append(
                    (context, side, resolution)
                ),
            )
        self.assertEqual(updated["base_expected_commit"], commit)
        self.assertEqual(interaction["requests"][0]["source_project_dir"], "/tmp/source")
        self.assertEqual(callback_rows[0][1], "base")

        failure_cases = (
            (
                {
                    "status": "fetch_failed",
                    "remote_failures": [{"reason": ""}],
                    "reason": "top-level reason",
                },
                "top-level reason",
            ),
            (
                {"status": "fetch_failed", "failures": [], "source_status": "remote failed"},
                "remote failed",
            ),
            ({"status": "fetch_failed"}, "未知 Git 远端错误"),
        )
        for resolution, expected in failure_cases:
            with self.subTest(expected=expected), patch.object(
                run_step, "resolve_step1_ref", return_value=resolution
            ), self.assertRaises(run_step.StepError) as error:
                run_step.resolve_step1_refs_for_execution(
                    {"base_branch": "main"}, "/tmp/project"
                )
            self.assertIn(expected, str(error.exception))

        with patch.object(
            run_step,
            "resolve_step1_ref",
            return_value={
                "status": "fetch_failed",
                "source_status": "remote_ref_moved",
            },
        ), self.assertRaises(run_step.StepError) as moved:
            run_step.resolve_step1_refs_for_execution(
                {
                    "base_branch": "main",
                    "base_expected_commit": commit,
                    "base_ref_binding": {
                        "schema": run_step.STEP1_REF_BINDING_SCHEMA,
                        "repo_dir": str(Path("/tmp/project").resolve()),
                        "requested_ref": "main",
                        "remote": "origin",
                        "canonical_ref": "refs/heads/main",
                        "expected_commit": commit,
                        "artifact_path": "",
                    },
                },
                "/tmp/project",
            )
        self.assertIn(commit, str(moved.exception))

        with patch.object(
            run_step, "resolve_step1_ref", return_value={"status": "resolved"}
        ):
            resolved, interaction = run_step.resolve_step1_refs_for_execution(
                {"current_branch": "main"}, "/tmp/project"
            )
        self.assertIsNone(interaction)
        self.assertEqual(resolved["current_resolved_ref"], "main")
        self.assertEqual(resolved["current_resolved_commit"], "")
        self.assertEqual(resolved["current_ref_resolution_mode"], "exact")
        self.assertEqual(
            resolved["current_ref_source_status"], "remote_source_resolved"
        )

        with patch.object(run_step, "resolve_step1_ref") as resolver:
            unchanged, interaction = run_step.resolve_step1_refs_for_execution(
                {"base_source_project_dir": "/tmp/source"},
                "/tmp/project",
                confirm_source_only=False,
            )
        resolver.assert_not_called()
        self.assertIsNone(interaction)
        self.assertEqual(unchanged["base_source_project_dir"], "/tmp/source")

    def test_remaining_step5_and_coord_path_boundary_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "all.csv"
            input_path.write_text("unused", encoding="utf-8")
            report = root / "report"
            persisted = []
            rows = [
                {"coord": "g:a", "change_type": None},
                {"coord": "g:b", "change_type": "REMOVED"},
            ]
            with patch.object(run_step, "read_csv_rows", return_value=rows), patch.object(
                run_step, "write_json", side_effect=lambda _path, value: persisted.append(value)
            ):
                filtered, summary = run_step.materialize_step5_all_changed_apis_input(
                    input_path,
                    report,
                    {
                        "step5_selected_names": ["a", "b"],
                        "step5_scope_mode": "partial",
                    },
                )
            self.assertTrue(filtered.is_file())
            self.assertEqual(summary["matched_row_count"], 2)
            self.assertEqual(persisted[-1]["mode"], "full")
            self.assertEqual(persisted[-1]["selected_names"], ["a", "b"])

            persisted.clear()
            with patch.object(run_step, "read_csv_rows", return_value=[]), patch.object(
                run_step, "write_json", side_effect=lambda _path, value: persisted.append(value)
            ):
                base, summary = run_step.materialize_step5_all_changed_apis_input(
                    input_path, report, {}
                )
            self.assertEqual(base, input_path)
            self.assertEqual(summary["matched_rows"], [])
            self.assertEqual(persisted[-1]["analyzed_api_count"], 0)

            fake_summary = {
                "selected_coords": ["g:a"],
                "selected_names": [],
                "unmatched_coords": [],
                "unmatched_names": [],
                "matched_rows": [],
            }
            with patch.object(run_step, "read_csv_rows", return_value=rows), patch.object(
                run_step, "build_step5_selection_summary", return_value=fake_summary
            ), self.assertRaisesRegex(run_step.StepError, "过滤后为空"):
                run_step.materialize_step5_all_changed_apis_input(
                    input_path,
                    report,
                    {"step5_selected_coords": ["g:a"], "step5_scope_mode": "partial"},
                )

            repo = root / "repo"
            repo.mkdir()
            with patch.object(run_step, "infer_maven_coords", return_value=["group:a"]):
                self.assertEqual(
                    run_step.normalize_coord_path_items(
                        ["group=" + str(repo)],
                        root,
                        "sources",
                        allow_repo_inference=True,
                    ),
                    [f"group:a={repo.resolve()}"],
                )
                self.assertEqual(
                    run_step.normalize_coord_path_items(
                        ["group:a=" + str(repo)],
                        root,
                        "sources",
                        allow_repo_inference=True,
                    ),
                    [f"group:a={repo.resolve()}"],
                )
            with patch.object(run_step, "looks_like_remote_repo", return_value=True), patch.object(
                run_step.Path, "exists", return_value=True
            ):
                self.assertEqual(
                    run_step.normalize_coord_path_items(
                        ["g:a=" + str(repo)], root, "sources"
                    ),
                    [f"g:a={repo.resolve()}"],
                )

    def test_dependency_source_mapping_and_inference_truth_table(self):
        self.assertEqual(run_step._step0_dependency_source_values({}), [])
        context = {
            "dependency_source_git_urls": ["https://example.invalid/a.git"],
            "dependency_source_git_materializations": [
                None,
                {},
                {"repo_path": "/materialized"},
            ],
            "dependency_source_dirs": ["/materialized", "/local", 7],
        }
        self.assertEqual(
            run_step._step0_dependency_source_values(context),
            ["https://example.invalid/a.git", "/local", "7"],
        )

        candidates = [
            "",
            "g:a=",
            "=/repo",
            "g:a=/other",
            "g:a=/repo",
            "g:b=/repo",
            "other:c=/repo",
        ]
        self.assertEqual(
            run_step._matching_repo_mappings_from_source_plan(
                "", "/repo", candidates
            ),
            ["g:a=/repo", "g:b=/repo", "other:c=/repo"],
        )
        self.assertEqual(
            run_step._matching_repo_mappings_from_source_plan(
                "g:a", "/repo", candidates
            ),
            ["g:a=/repo"],
        )
        self.assertEqual(
            run_step._matching_repo_mappings_from_source_plan(
                "g", "/repo", candidates
            ),
            ["g:a=/repo", "g:b=/repo"],
        )
        self.assertEqual(
            run_step._matching_repo_mappings_from_source_plan(
                "missing", None, None
            ),
            [],
        )

        inferred = ["org.demo:alpha-client", "org.demo:beta-service"]
        cases = (
            ((None, "", "/tmp/project"), []),
            ((["g:a"], "", "/tmp/project"), ["g:a"]),
            ((inferred, "org.demo:beta-service", "/tmp/project"), ["org.demo:beta-service"]),
            ((inferred, "x:alpha-client", "/tmp/project"), ["org.demo:alpha-client"]),
            ((inferred, "x:missing", "/tmp/beta-service"), ["org.demo:beta-service"]),
            ((inferred, "x:alpha", "/tmp/none"), ["org.demo:alpha-client"]),
            ((inferred, "x:missing", "/tmp/beta"), ["org.demo:beta-service"]),
            ((["g:alpha-one", "g:alpha-two"], "x:alpha", "/tmp/alpha"), []),
        )
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                self.assertEqual(
                    run_step._filter_inferred_coords_by_hint(*arguments), expected
                )

    def test_runtime_message_and_explicit_reset_truth_table(self):
        self.assertEqual(
            run_step.build_user_runtime_message("start", None),
            ["正在分析：当前分析"],
        )
        failed_without_reason = run_step.build_user_runtime_message(
            "failed", "step2", ""
        )
        self.assertNotIn("原因：", "\n".join(failed_without_reason))
        failed_with_reason = run_step.build_user_runtime_message(
            "failed", "step2", "tool_error"
        )
        self.assertIn("原因：tool_error", "\n".join(failed_with_reason))

        partial = run_step.build_user_runtime_message(
            "complete",
            "step6",
            completion_summary={
                "status": "completed_with_limits",
                "scope_mode": "partial",
                "included_dependency_count": 0,
                "available_dependency_count": 0,
                "limitations": ["证据不足"],
            },
        )
        self.assertIn("部分依赖（0/0）", "\n".join(partial))
        self.assertIn("证据不足", "\n".join(partial))
        full = run_step.build_user_runtime_message(
            "complete", "step6", completion_summary={"scope_mode": "full"}
        )
        self.assertIn("全部变化依赖", "\n".join(full))
        unknown = run_step.build_user_runtime_message(
            "complete", "step6", completion_summary=None
        )
        self.assertIn("不支持全量结论", "\n".join(unknown))
        self.assertIn(
            "接下来：升级上下文",
            "\n".join(run_step.build_user_runtime_message("complete", "step1")),
        )
        self.assertEqual(
            run_step.build_user_runtime_message("complete", "step6")[-1],
            "完整 API 与调用关系：deliverables/all-impact-details.md、deliverables/all-impact-details.csv",
        )

        self.assertFalse(run_step.should_reset_for_explicit_step_run(None, "step1", "auto"))
        self.assertFalse(run_step.should_reset_for_explicit_step_run(None, "unknown", "unknown"))
        self.assertFalse(run_step.should_reset_for_explicit_step_run(None, "step2", "step2"))
        self.assertTrue(
            run_step.should_reset_for_explicit_step_run(
                {"state": {"completed_step": "step2"}}, "step2", "step2"
            )
        )
        self.assertTrue(
            run_step.should_reset_for_explicit_step_run(
                {"state": {"current_step": "step3"}}, "step2", "step2"
            )
        )
        for section in ("input", "derived", "output"):
            state = {"state": {}, "step3": {section: {"value": 1}}}
            with self.subTest(section=section):
                self.assertTrue(
                    run_step.should_reset_for_explicit_step_run(
                        state, "step2", "step2"
                    )
                )

    def test_step3_candidate_cleanup_complete_filesystem_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            aggregate = (
                run_step.evidence_static_scan_dir(report)
                / run_step.STEP3_RISK_CANDIDATES_FILE
            )
            aggregate.parent.mkdir(parents=True)
            aggregate.write_text("stale", encoding="utf-8")
            run_step.cleanup_step3_candidate_outputs(report)
            self.assertFalse(aggregate.exists())

            per_dependency = (
                run_step.step4_api_changes_dir(report)
                / run_step.PER_DEPENDENCY_DIRNAME
            )
            per_dependency.mkdir(parents=True)
            (per_dependency / "plain-file").write_text("keep", encoding="utf-8")

            missing_summary = per_dependency / "missing-summary"
            missing_summary.mkdir()
            (missing_summary / run_step.PER_DEPENDENCY_CANDIDATE_HITS_FILE).write_text(
                "hits", encoding="utf-8"
            )

            invalid_summary = per_dependency / "invalid-summary"
            invalid_summary.mkdir()
            (invalid_summary / run_step.PER_DEPENDENCY_SUMMARY_FILE).write_text(
                "not-json", encoding="utf-8"
            )

            remaining = per_dependency / "remaining"
            remaining.mkdir()
            remaining_summary = remaining / run_step.PER_DEPENDENCY_SUMMARY_FILE
            remaining_summary.write_text(
                json.dumps(
                    {
                        "step3": {"stale": True},
                        "keep": True,
                        "artifacts": {
                            "candidate_hits_csv": "old.csv",
                            "other": "keep.csv",
                        },
                    }
                ),
                encoding="utf-8",
            )

            empty = per_dependency / "empty"
            empty.mkdir()
            empty_summary = empty / run_step.PER_DEPENDENCY_SUMMARY_FILE
            empty_summary.write_text(
                json.dumps(
                    {
                        "step3": {"stale": True},
                        "artifacts": {"candidate_hits_csv": "old.csv"},
                    }
                ),
                encoding="utf-8",
            )

            run_step.cleanup_step3_candidate_outputs(report)
            self.assertTrue((per_dependency / "plain-file").is_file())
            self.assertFalse(
                (missing_summary / run_step.PER_DEPENDENCY_CANDIDATE_HITS_FILE).exists()
            )
            self.assertTrue(
                (invalid_summary / run_step.PER_DEPENDENCY_SUMMARY_FILE).exists()
            )
            saved = json.loads(remaining_summary.read_text(encoding="utf-8"))
            self.assertEqual(saved, {"keep": True, "artifacts": {"other": "keep.csv"}})
            self.assertFalse(empty_summary.exists())

    def test_step4_resume_followup_scope_contract_matrix(self):
        state = {
            "step4": {"input": {}},
            "step5": {"input": {}},
        }
        with patch.object(run_step, "save_main_state") as save:
            run_step.handle_step4_resume_followups(
                state, "/tmp/report", "step3", "continue"
            )
            run_step.handle_step4_resume_followups(
                state, "/tmp/report", "step4", "cancel"
            )
        save.assert_not_called()

        for step4_input, expected_error in (
            ({"step5_scope_mode": "partial"}, "部分分析缺少目标依赖"),
            (
                {
                    "step5_scope_mode": "full",
                    "step5_selected_coords": ["g:a"],
                },
                "全量分析与目标依赖筛选条件冲突",
            ),
        ):
            candidate = {
                "step4": {"input": step4_input},
                "step5": {"input": {}},
            }
            with self.subTest(step4_input=step4_input), self.assertRaisesRegex(
                run_step.StepError, expected_error
            ):
                run_step.handle_step4_resume_followups(
                    candidate, "/tmp/report", "step4", "continue"
                )

        full_state = {
            "step4": {"input": {"step5_scope_mode": ""}},
            "step5": {"input": {"step5_selected_coords": ["stale"]}},
        }
        with patch.object(run_step, "save_main_state"), patch.object(
            run_step, "read_csv_rows", return_value=[]
        ), patch("sys.stderr", io.StringIO()) as stderr:
            run_step.handle_step4_resume_followups(
                full_state, "/tmp/report", "step4", "continue"
            )
        self.assertEqual(full_state["step5"]["input"]["step5_scope_mode"], "full")
        self.assertNotIn("step5_selected_coords", full_state["step5"]["input"])
        self.assertIn("已确认全量分析", stderr.getvalue())

        partial_state = {
            "step4": {
                "input": {
                    "step5_selected_coords": ["g:a"],
                    "step5_selected_names": [],
                }
            },
            "step5": {"input": {}},
        }
        rows = [{}, {"coord": ""}, {"coord": "g:a", "severity": "P1"}]
        with patch.object(run_step, "save_main_state"), patch.object(
            run_step, "read_csv_rows", return_value=rows
        ), patch("sys.stderr", io.StringIO()) as stderr:
            run_step.handle_step4_resume_followups(
                partial_state, "/tmp/report", "step4", "continue"
            )
        self.assertEqual(partial_state["step5"]["input"]["step5_scope_mode"], "partial")
        self.assertIn("纳入 1/1 个变化依赖", stderr.getvalue())

    def test_report_candidate_prepare_phase_and_failure_matrix(self):
        with self.assertRaisesRegex(run_step.StepError, "候选阶段无效"):
            run_step._prepare_binary_report_publication_candidate_in_process(
                phase=None, report_dir="/tmp/report"
            )
        with patch.object(
            run_step, "_workflow_mutation_lock_is_held", return_value=False
        ), self.assertRaisesRegex(run_step.StepError, "workflow mutation lock"):
            run_step._prepare_binary_report_publication_candidate_in_process(
                phase="step4", report_dir="/tmp/report"
            )

        functions = {
            "step4": "prepare_step4_publication_candidate",
            "step5": "prepare_step5_publication_candidate",
            "step6": "prepare_step6_publication_candidate",
        }
        for phase, function_name in functions.items():
            with self.subTest(phase=phase), patch.object(
                run_step, "_workflow_mutation_lock_is_held", return_value=True
            ), patch.object(
                run_step, function_name, return_value=None
            ) as prepare:
                result = run_step._prepare_binary_report_publication_candidate_in_process(
                    phase=phase,
                    report_dir="/tmp/report",
                    selected_coords=None,
                    selected_names=None,
                    candidate_activation_identity=None,
                )
            self.assertEqual(result, {})
            prepare.assert_called_once()

        for reason_code in ("", "PUBLICATION_INVALID"):
            with self.subTest(reason_code=reason_code), patch.object(
                run_step, "_workflow_mutation_lock_is_held", return_value=True
            ), patch.object(
                run_step,
                "prepare_step6_publication_candidate",
                side_effect=run_step.BinaryReportError(reason_code, "bad report"),
            ), self.assertRaises(run_step.StepError) as caught:
                run_step._prepare_binary_report_publication_candidate_in_process(
                    phase="step6", report_dir="/tmp/report"
                )
            effective_reason = reason_code or "BINARY_FIRST_CONTRACT_VIOLATION"
            self.assertEqual(caught.exception.reason_codes, [effective_reason])
            self.assertEqual(
                caught.exception.diagnostic["cause_reason_code"], effective_reason
            )

    def test_resume_snapshot_empty_and_interaction_fallback_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            run_step.write_resume_snapshot(
                None,
                "step1",
                report,
                event="awaiting_user_input",
                interaction={"title": "确认标题", "reason_code": "WAIT"},
            )
            payload = json.loads(
                run_step.last_step_summary_path(report).read_text(encoding="utf-8")
            )
            markdown = run_step.resume_context_path(report).read_text(encoding="utf-8")
            self.assertEqual(payload["workflow_state"]["status"], "")
            self.assertEqual(payload["user_input"]["question"], "确认标题")
            self.assertEqual(payload["user_input"]["reason_code"], "WAIT")
            self.assertIn("确认标题", markdown)

            run_step.write_resume_snapshot(
                {"state": {"current_step": "step2", "status": "ready"}},
                "step1",
                report,
                event="step_completed",
                completion_summary={"limitations": [" 证据 `缺口` "]},
            )
            payload = json.loads(
                run_step.last_step_summary_path(report).read_text(encoding="utf-8")
            )
            markdown = run_step.resume_context_path(report).read_text(encoding="utf-8")
            self.assertFalse(payload["needs_user_input"])
            self.assertIsNone(payload["user_input"])
            self.assertIn("证据 '缺口'", markdown)

            run_step.write_resume_snapshot(
                {"state": {"current_step": "step2"}},
                "step1",
                report,
                event="awaiting_user_input",
                interaction={},
            )
            markdown = run_step.resume_context_path(report).read_text(encoding="utf-8")
            self.assertIn("请读取 interaction.json", markdown)

    def test_state_normalization_resume_and_review_truth_table(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report"
            base = run_step.ensure_main_state_structure([], report)
            self.assertEqual(base["schema"], run_step.MAIN_STATE_SCHEMA)
            self.assertEqual(
                run_step.ensure_main_state_structure({"schema": "wrong"}, report)["state"]["current_step"],
                "step0",
            )
            raw = {
                "schema": run_step.MAIN_STATE_SCHEMA,
                "state": {
                    "current_step": "",
                    "status": "completed_with_limits",
                    "completion_summary": {"stale": True},
                },
                "step0": [],
                "step1": {
                    "input": {"kept": 1},
                    "derived": [],
                    "output": {"value": 2},
                },
            }
            normalized = run_step.ensure_main_state_structure(
                raw, report, manifest_path="manifest.yaml"
            )
            self.assertEqual(normalized["state"]["current_step"], "")
            self.assertEqual(normalized["state"]["status"], "ready")
            self.assertIsNone(normalized["state"]["completion_summary"])
            self.assertEqual(normalized["step0"], run_step.empty_step_state())
            self.assertEqual(normalized["step1"]["input"], {"kept": 1})
            self.assertEqual(normalized["step1"]["derived"], {})
            self.assertEqual(normalized["step1"]["output"], {"value": 2})
            self.assertEqual(
                normalized["state"]["manifest_path"],
                str(Path("manifest.yaml").resolve()),
            )

            rules = Path(directory) / "rules.md"
            rules.write_text(
                "\n# comment\nfirst rule\n  # indented comment\nsecond rule  \n",
                encoding="utf-8",
            )
            with patch.object(run_step, "CHECKPOINT_RULES_FILE", rules):
                self.assertEqual(run_step.load_checkpoint_rules(), ["first rule", "second rule"])

        self.assertEqual(
            run_step.resolve_resume_step_id("step4", None, "continue"), "step4"
        )
        self.assertEqual(
            run_step.resolve_resume_step_id(
                "step4", {"step_id": "step3", "kind": "review"}, "continue"
            ),
            "step4",
        )
        self.assertEqual(
            run_step.resolve_resume_step_id(
                "step4", {"step_id": "", "kind": "input_request"}, "rerun_current_step"
            ),
            "step4",
        )

        self.assertFalse(run_step.should_auto_continue_success_review("step2", None, None))
        self.assertFalse(
            run_step.should_auto_continue_success_review(
                "step2", {}, {"step2": {"auto_continue_on_success": True}}
            )
        )
        self.assertFalse(
            run_step.should_auto_continue_success_review(
                "step2",
                {"reason_code": "BLOCK", "options": [{"id": "continue"}]},
                {"step2": {"auto_continue_on_success": True}},
            )
        )
        self.assertFalse(
            run_step.should_auto_continue_success_review(
                "step2",
                {"reason_code": "", "options": [{"id": ""}, {}]},
                {"step2": {"auto_continue_on_success": True}},
            )
        )
        self.assertTrue(
            run_step.should_auto_continue_success_review(
                "step2",
                {"options": [{"id": "continue"}]},
                {"step2": {"auto_continue_on_success": True}},
            )
        )

    def test_pinned_scope_and_derived_snapshot_truth_table(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            inside = project / "src"
            outside = Path(directory) / "outside"
            inside.mkdir(parents=True)
            outside.mkdir()
            empty = run_step._logicalize_project_scope_paths(None, project)
            self.assertEqual(empty["system_source"], ".")
            self.assertNotIn("candidate_module_details", empty)

            insufficient = run_step._logicalize_project_scope_paths(
                {
                    "status": "insufficient",
                    "reason_codes": ["existing"],
                    "source_roots": [str(outside)],
                    "candidate_module_details": [
                        None,
                        {"module": "empty", "module_dir": ""},
                    ],
                },
                project,
            )
            self.assertEqual(insufficient["status"], "insufficient")
            self.assertEqual(
                insufficient["reason_codes"],
                ["existing", "pinned_source_root_outside_project"],
            )
            self.assertEqual(
                insufficient["candidate_module_details"],
                [None, {"module": "empty", "module_dir": ""}],
            )

            commit = "a" * 40
            valid = {
                "schema": run_step.PINNED_SOURCE_SNAPSHOT_SCHEMA,
                "commit": commit,
                "project_path": ".",
                "target_module": "app",
                "active_maven_profiles": ["prod", "prod"],
            }
            context = {
                "current_resolved_commit": commit.upper(),
                "target_module": "app",
                "active_maven_profiles": ["prod"],
            }
            self.assertTrue(run_step._pinned_snapshot_matches_context(valid, context))
            for mutation in (
                None,
                {**valid, "schema": "wrong"},
                {**valid, "commit": "short"},
                {**valid, "commit": "b" * 40},
                {**valid, "project_path": "../escape"},
                {**valid, "target_module": "other"},
                {**valid, "active_maven_profiles": ["dev"]},
            ):
                with self.subTest(snapshot=mutation):
                    self.assertFalse(
                        run_step._pinned_snapshot_matches_context(mutation, context)
                    )

            context_path = run_step.step2_context_path(project)
            context_path.parent.mkdir(parents=True)
            context_path.write_text(
                json.dumps({"jdk_upgraded": True, "springboot_major_upgrade": False}),
                encoding="utf-8",
            )
            self.assertEqual(run_step.build_step_derived_snapshot("unknown", None, project), {})
            self.assertEqual(run_step.build_step_derived_snapshot("step0", {}, project), {})
            self.assertEqual(
                run_step.build_step_derived_snapshot(
                    "step0", {"analysis_mode": "checkout", "ignored": 1}, project
                ),
                {"analysis_mode": "checkout"},
            )
            self.assertEqual(
                run_step.build_step_derived_snapshot(
                    "step1", {"result_source": "built", "ignored": 1}, project
                ),
                {"result_source": "built"},
            )
            self.assertEqual(
                run_step.build_step_derived_snapshot(
                    "step2", {"source_dirs_status": "explicit"}, project
                ),
                {"source_dirs_status": "explicit"},
            )
            self.assertEqual(
                run_step.build_step_derived_snapshot(
                    "step4", {"step5_scope_mode": "full"}, project
                ),
                {"step5_scope_mode": "full"},
            )
            self.assertEqual(
                run_step.build_step_derived_snapshot("step3", {}, project),
                {"jdk_upgraded": True, "springboot_major_upgrade": False},
            )

    def test_resume_output_and_interaction_persistence_boundary_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report"
            report.mkdir()
            relative = report / "relative.txt"
            relative.write_text("x", encoding="utf-8")
            outside = Path(directory) / "outside.txt"
            outside.write_text("y", encoding="utf-8")
            with patch.object(
                run_step, "step_output_paths_for_cleanup", return_value=[relative, relative]
            ):
                outputs = run_step._resume_output_paths(
                    "step1",
                    report,
                    {"files_to_review": ["relative.txt", str(outside), "", "missing"]},
                )
            self.assertEqual(outputs.count("relative.txt"), 1)
            self.assertIn(str(outside.resolve()), outputs)

            with patch.object(
                run_step, "step_output_paths_for_cleanup", return_value=[relative]
            ), patch.object(
                run_step, "_resume_display_path", side_effect=OSError("race")
            ):
                self.assertEqual(run_step._resume_output_paths("step1", report), [])

        base_state = {
            "state": {},
            "step1": {"input": None, "output": {"prior": True}},
        }
        enhanced = {"status": "awaiting_user", "title": "Need input"}
        updates = []
        with patch.object(
            run_step, "previous_step_output", return_value={"prior": True}
        ), patch.object(
            run_step, "apply_interaction_protocol_enhancements", return_value=enhanced
        ), patch.object(
            run_step, "update_main_state_state", side_effect=lambda *_a, **kw: updates.append(kw)
        ), patch.object(run_step, "save_main_state"), patch.object(
            run_step, "save_interaction_file"
        ), patch.object(run_step, "write_resume_snapshot"):
            result = run_step.persist_interaction_required_error(
                base_state, "step1", "/tmp/report", {"title": "Need input"}
            )
        self.assertEqual(result["title"], "Need input")
        self.assertEqual(updates[0]["completed_step"], None)
        self.assertEqual(updates[0]["blocking_reason"], "Need input")

        state = {"state": {}, "step1": {"input": {}}}
        with patch.object(
            run_step, "pending_interaction_needs_git_recheck", return_value=False
        ):
            self.assertFalse(
                run_step.clear_stale_git_interaction_for_recheck(
                    state, "/tmp/report", None
                )
            )
        state["state"]["status"] = "paused_by_user"
        with patch.object(
            run_step, "pending_interaction_needs_git_recheck", return_value=True
        ):
            self.assertFalse(
                run_step.clear_stale_git_interaction_for_recheck(
                    state, "/tmp/report", {"step_id": "step1"}
                )
            )
        state["state"]["status"] = "ready"
        updates.clear()
        with patch.object(
            run_step, "pending_interaction_needs_git_recheck", return_value=True
        ), patch.object(
            run_step, "update_main_state_state", side_effect=lambda *_a, **kw: updates.append(kw)
        ), patch.object(run_step, "save_main_state"), patch.object(
            run_step, "clear_interaction_file"
        ):
            self.assertTrue(
                run_step.clear_stale_git_interaction_for_recheck(
                    state, "/tmp/report", {}
                )
            )
        self.assertEqual(updates[0]["current_step"], "step0")

    def test_windows_and_descriptor_cleanup_rejection_matrix(self):
        directory_mode = stat.S_IFDIR | 0o755
        regular_mode = stat.S_IFREG | 0o644
        symlink_mode = stat.S_IFLNK | 0o777
        base_stat = SimpleNamespace(st_mode=directory_mode)

        class JunctionPath:
            def is_junction(self):
                return True

        for observed, path_value in (
            (SimpleNamespace(st_mode=regular_mode), Path("/tmp/file")),
            (SimpleNamespace(st_mode=symlink_mode), Path("/tmp/link")),
            (base_stat, JunctionPath()),
        ):
            with self.subTest(mode=observed.st_mode), patch.object(
                run_step.os, "lstat", return_value=observed
            ), self.assertRaises(OSError):
                run_step._windows_cleanup_directory_stat(path_value)

        reparse = 0x400
        with patch.object(run_step.stat, "FILE_ATTRIBUTE_REPARSE_POINT", reparse, create=True), patch.object(
            run_step.os,
            "lstat",
            return_value=SimpleNamespace(
                st_mode=directory_mode, st_file_attributes=reparse
            ),
        ), self.assertRaises(OSError):
            run_step._windows_cleanup_directory_stat(Path("/tmp/reparse"))
        with patch.object(run_step.os, "lstat", return_value=base_stat):
            self.assertIs(run_step._windows_cleanup_directory_stat(Path("/tmp/dir")), base_stat)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing"
            self.assertFalse(
                run_step._remove_step_output_with_directory_descriptors(
                    missing, Path("child")
                )
            )
            file_root = root / "file-root"
            file_root.write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(OSError, "not a real directory"):
                run_step._remove_step_output_with_directory_descriptors(
                    file_root, Path("child")
                )
            report = root / "report"
            nested = report / "nested"
            nested.mkdir(parents=True)
            directory_leaf = nested / "tree"
            (directory_leaf / "child").mkdir(parents=True)
            (directory_leaf / "child" / "value.txt").write_text("x", encoding="utf-8")
            self.assertTrue(
                run_step._remove_step_output_with_directory_descriptors(
                    report, Path("nested/tree"), synchronize_parent=True
                )
            )
            self.assertFalse(directory_leaf.exists())
            self.assertFalse(
                run_step._remove_step_output_with_directory_descriptors(
                    report, Path("nested/missing")
                )
            )
            try:
                parent_link = report / "parent-link"
                parent_link.symlink_to(nested, target_is_directory=True)
            except (OSError, NotImplementedError):
                parent_link = None
            if parent_link is not None:
                with self.assertRaisesRegex(OSError, "output parent"):
                    run_step._remove_step_output_with_directory_descriptors(
                        report, Path("parent-link/value.txt")
                    )

    def test_pinned_snapshot_application_and_materialization_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            self.assertEqual(run_step._materialize_project_scope_paths(None, project), {})
            scope = run_step._materialize_project_scope_paths(
                {
                    "source_roots": ["src"],
                    "resource_roots": [],
                    "missing_declared_roots": [],
                    "candidate_module_details": [
                        None,
                        {"module": "root", "module_dir": ""},
                        {"module": "app", "module_dir": "module"},
                    ],
                },
                project,
            )
            self.assertEqual(scope["system_source"], str(project.resolve()))
            self.assertEqual(scope["source_roots"], [str((project / "src").resolve())])
            self.assertEqual(scope["candidate_module_details"][0], None)
            self.assertEqual(
                scope["candidate_module_details"][2]["module_dir"],
                str((project / "module").resolve()),
            )

            snapshot = {
                "source_roots": [],
                "project_scope": {},
                "build_tool": "",
                "source_dirs_status": "",
            }
            with patch.object(
                run_step, "_pinned_snapshot_matches_context", return_value=False
            ):
                self.assertIsNone(run_step._apply_pinned_source_snapshot(None, project))
            with patch.object(
                run_step, "_pinned_snapshot_matches_context", return_value=True
            ):
                applied = run_step._apply_pinned_source_snapshot(
                    {
                        "pinned_source_snapshot": snapshot,
                        "current_tool": "maven",
                    },
                    project,
                )
            self.assertEqual(applied["current_tool"], "maven")
            self.assertEqual(applied["source_dirs"], [])
            self.assertEqual(applied["source_dirs_status"], "missing")

            with patch.object(
                run_step, "_pinned_snapshot_matches_context", return_value=True
            ):
                applied = run_step._apply_pinned_source_snapshot(
                    {
                        "pinned_source_snapshot": {
                            "source_roots": ["src"],
                            "build_tool": "gradle",
                            "source_dirs_status": "detected",
                            "project_scope": {"source_roots": ["src"]},
                        },
                        "tool": "maven",
                    },
                    project,
                )
            self.assertEqual(applied["tool"], "gradle")
            self.assertEqual(applied["source_dirs"], [str((project / "src").resolve())])

        with patch.object(
            run_step, "_pinned_snapshot_matches_context", return_value=True
        ):
            original = {"pinned_source_snapshot": {"id": 1}, "tool": "maven"}
            self.assertEqual(run_step._discard_unpinned_local_source_discovery(original), original)
        with patch.object(
            run_step, "_pinned_snapshot_matches_context", return_value=False
        ):
            cleared = run_step._discard_unpinned_local_source_discovery(None)
            explicit = run_step._discard_unpinned_local_source_discovery(
                {
                    "target_module": " app ",
                    "source_dirs_status": "explicit",
                    "source_dirs": ["src"],
                    "tool_explicit": True,
                    "tool": "maven",
                }
            )
        self.assertEqual(cleared["project_scope"]["target_module"], "")
        self.assertEqual(cleared["source_dirs_status"], "missing")
        self.assertEqual(cleared["tool"], "")
        self.assertEqual(explicit["source_dirs"], ["src"])
        self.assertEqual(explicit["tool"], "maven")

    def test_dependency_focus_versions_and_mapping_candidate_matrix(self):
        fallback = {
            "changed_dependencies": [
                None,
                {},
                {"coord": " g:a "},
                {"coord": "g:a"},
                {"coord": "g:b"},
            ]
        }
        with patch.object(run_step.Path, "exists", return_value=False):
            self.assertEqual(run_step._collect_focus_dependency_coords("/tmp/report"), [])
        with patch.object(run_step.Path, "exists", return_value=True), patch.object(
            run_step, "read_json", return_value=fallback
        ):
            self.assertEqual(
                run_step._collect_focus_dependency_coords("/tmp/report"),
                ["g:a", "g:b"],
            )
        self.assertEqual(
            run_step._collect_focus_dependency_coords("/tmp/report", fallback),
            ["g:a", "g:b"],
        )

        version_rows = [
            {},
            {"coord": "g:unresolved", "resolution_status": "unresolved"},
            {"coord": "g:none", "old_version": "-", "new_version": ""},
            {"coord": "g:a", "old_version": "1", "new_version": "2"},
        ]
        with patch.object(run_step, "read_csv_rows", return_value=version_rows):
            self.assertEqual(
                run_step._dependency_change_versions("/tmp/report"),
                {"g:a": {"base": "1", "current": "2"}},
            )

        plan = {
            "candidates": [
                {},
                {"coord": "g:a", "repo_path": ""},
                {"coord": "", "repo_path": "/repo"},
                {
                    "coord": "g:a",
                    "repo_path": "/repo",
                    "source_dir": "src",
                    "module_root": "module",
                },
                {
                    "coord": "g:a",
                    "repo_path": "/repo",
                    "source_dir": "src2",
                    "module_root": "",
                },
            ]
        }
        with patch.object(
            run_step, "_dependency_change_versions", return_value={"g:a": {}}
        ), patch.object(
            run_step, "_build_dependency_source_plan", return_value=plan
        ) as build:
            returned_plan, mappings = run_step._dependency_repo_mapping_candidates(
                {"dependency_source_dirs": None}, "/tmp/report"
            )
        self.assertIs(returned_plan, plan)
        self.assertEqual(build.call_args.args[0], [])
        self.assertEqual(mappings["g:a"]["/repo"]["source_dirs"], ["src", "src2"])
        self.assertEqual(mappings["g:a"]["/repo"]["module_roots"], ["module"])

    def test_scope_notes_selection_summary_and_release_repair_matrix(self):
        self.assertFalse(run_step._notes_look_like_partial_scope("inspect g:a", None))
        self.assertFalse(
            run_step._notes_look_like_partial_scope(
                "inspect g:a", {"options": [None, {}, {"coord": ""}]}
            )
        )
        self.assertTrue(
            run_step._notes_look_like_partial_scope(
                "inspect G:A", {"options": [{"coord": "g:a"}]}
            )
        )

        dependency_rows = [
            {},
            {"coord": ""},
            {
                "coord": "g:a",
                "selection_key": "",
                "dependency_name": "",
                "impact_priority_rank": "",
                "change_types": "",
                "recommended": "true",
            },
            {
                "coord": "g:b",
                "selection_key": "custom",
                "dependency_name": "Bee",
                "impact_priority_rank": "2",
                "change_types": "REMOVED",
            },
        ]
        with patch.object(run_step, "read_csv_rows", return_value=dependency_rows):
            summary = run_step.build_step5_dependency_selection_summary("/tmp/report")
        self.assertEqual(summary["available_target_count"], 2)
        self.assertEqual(summary["available_targets"][0]["coord"], "g:b")
        self.assertEqual(summary["available_targets"][1]["selection_key"], "coord:g:a")

        with patch.object(run_step, "read_csv_rows", side_effect=[[], []]):
            fallback = run_step.build_step5_dependency_selection_summary("/tmp/report")
        self.assertEqual(fallback["available_target_count"], 0)

        release = {
            "step4": {"status": "current"},
            "step5": {"status": "stale"},
            "step6": {"status": "current"},
        }
        self.assertEqual(run_step._release_prerequisite_repair_step(release, None), "")
        self.assertEqual(run_step._release_prerequisite_repair_step(release, "step4"), "")
        self.assertEqual(run_step._release_prerequisite_repair_step(release, "step5"), "")
        self.assertEqual(run_step._release_prerequisite_repair_step(release, "step6"), "step5")
        self.assertEqual(run_step._release_prerequisite_repair_step(release, "done"), "step5")
        self.assertEqual(
            run_step._release_prerequisite_repair_step(
                {stage: {"status": "current"} for stage in ("step4", "step5", "step6")},
                "done",
            ),
            "",
        )

    def test_request_resolution_validation_and_input_context_matrix(self):
        with self.assertRaisesRegex(run_step.StepError, "显式指定"):
            run_step.resolve_requested_step("auto", None)
        with self.assertRaisesRegex(run_step.StepError, "显式指定"):
            run_step.resolve_requested_step(
                "auto", {"state": {"current_step": "done"}}
            )
        self.assertEqual(
            run_step.resolve_requested_step(
                "auto", {"state": {"current_step": "step3"}}
            ),
            "step3",
        )
        self.assertEqual(
            run_step.resolve_requested_step("step4", None), "step4"
        )

        self.assertIsNone(run_step.validate_run_context_for_step("step2", {}))
        for step_id in ("step3", "step4", "step5", "step6"):
            with self.subTest(step_id=step_id), self.assertRaises(run_step.StepError) as missing_confirmation:
                run_step.validate_run_context_for_step(step_id, {"source_dirs": ["src"]})
            self.assertIn("STEP0_CONFIRMATION_REQUIRED", missing_confirmation.exception.reason_codes)
            with self.assertRaisesRegex(run_step.StepError, "没有在固定 Current commit"):
                run_step.validate_run_context_for_step(
                    step_id, {"step0_confirmed": True, "source_dirs": []}
                )
            self.assertIsNone(
                run_step.validate_run_context_for_step(
                    step_id, {"step0_confirmed": True, "source_dirs": ["src"]}
                )
            )

        state = {
            "step0": {"input": {}},
            "step1": {"input": {"existing": 1}},
            "step2": {"input": {}},
        }
        self.assertEqual(
            run_step.build_step_input_context(state, "step0", {"fallback": 1}),
            {"fallback": 1},
        )
        self.assertEqual(
            run_step.build_step_input_context(state, "step1", {"fallback": 1}),
            {"existing": 1},
        )
        with patch.object(run_step, "previous_step_output", return_value={"prior": 1}):
            self.assertEqual(
                run_step.build_step_input_context(state, "step2"), {"prior": 1}
            )
        with patch.object(run_step, "previous_step_output", return_value={}):
            self.assertEqual(
                run_step.build_step_input_context(
                    state, "step2", {"fallback": 2}
                ),
                {"fallback": 2},
            )

        with self.assertRaises(run_step.StepError):
            run_step.resolve_user_response(
                SimpleNamespace(response_json=None, response_file=None), Path("/tmp")
            )
        with patch.object(run_step, "load_user_response", return_value=None), patch.object(
            run_step, "build_canonical_user_response", side_effect=lambda value: value
        ):
            self.assertEqual(
                run_step.resolve_user_response(
                    SimpleNamespace(response_json="{}", response_file=None), Path("/tmp")
                ),
                {},
            )
        with patch.object(run_step, "load_user_response", return_value={"action": "continue"}), patch.object(
            run_step, "build_canonical_user_response", return_value={"action": "continue"}
        ):
            self.assertEqual(
                run_step.resolve_user_response(
                    SimpleNamespace(response_json=None, response_file="response.json"),
                    Path("/tmp"),
                ),
                {"action": "continue"},
            )

    def test_progress_sanitization_and_platform_capability_matrix(self):
        tuple_payload = run_step._sanitize_git_persistence_payload(
            ("https://user:secret@example.invalid/repo.git", "plain")
        )
        self.assertIsInstance(tuple_payload, list)
        self.assertNotIn("secret", tuple_payload[0])
        self.assertEqual(
            run_step._sanitize_git_persistence_payload("value", key_hint="access_token"),
            "***",
        )
        self.assertEqual(run_step._sanitize_git_persistence_payload(7), 7)

        cases = (
            ((None, None), {}),
            (({}, (1, 2)), {}),
            (({"phase": "old"}, (1, 2)), {"phase": "old"}),
            (({"phase": "same"}, (1, 2)), {}),
            (({"phase": "foreign", "attempt_identity": "other"}, (2, 3)), {}),
        )
        snapshots = [
            (None, None),
            ({}, None),
            ({"phase": "old"}, (2, 3)),
            ({"phase": "same"}, (1, 2)),
            ({"phase": "foreign", "attempt_identity": "other"}, (2, 3)),
        ]
        for (arguments, expected), snapshot in zip(cases, snapshots):
            _unused_path, baseline = arguments
            with self.subTest(snapshot=snapshot), patch.object(
                run_step, "_binary_progress_file_snapshot", return_value=snapshot
            ):
                self.assertEqual(
                    run_step._legacy_progress_after_baseline("progress", baseline),
                    expected,
                )

        original_supports = (
            run_step.os.supports_dir_fd,
            run_step.os.supports_follow_symlinks,
            run_step.os.supports_fd,
        )
        try:
            with patch.object(run_step.os, "name", "nt"):
                self.assertFalse(run_step._secure_step_output_cleanup_supported())
            with patch.object(run_step.os, "name", "posix"), patch.object(
                run_step.os, "O_DIRECTORY", 0
            ):
                self.assertFalse(run_step._secure_step_output_cleanup_supported())
            with patch.object(run_step.os, "name", "posix"), patch.object(
                run_step.os, "O_DIRECTORY", 1
            ), patch.object(run_step.os, "O_NOFOLLOW", 0):
                self.assertFalse(run_step._secure_step_output_cleanup_supported())
            run_step.os.supports_dir_fd = set()
            with patch.object(run_step.os, "name", "posix"), patch.object(
                run_step.os, "O_DIRECTORY", 1
            ), patch.object(run_step.os, "O_NOFOLLOW", 1):
                self.assertFalse(run_step._secure_step_output_cleanup_supported())
        finally:
            (
                run_step.os.supports_dir_fd,
                run_step.os.supports_follow_symlinks,
                run_step.os.supports_fd,
            ) = original_supports

        flags = run_step._cleanup_directory_open_flags()
        self.assertTrue(flags & run_step.os.O_RDONLY == run_step.os.O_RDONLY)

    def test_workflow_lock_context_and_main_wrapper_matrix(self):
        manager = _LockManager()
        context = run_step._WORKFLOW_MUTATION_CONTEXT
        old = (
            getattr(context, "depth", None),
            getattr(context, "report_roots", None),
            getattr(context, "process_id", None),
        )
        try:
            context.depth = 2
            context.report_roots = (Path("/tmp/parent").resolve(),)
            context.process_id = os.getpid()
            with patch.object(
                run_step, "exclusive_file_lock", return_value=manager
            ), patch.dict(
                os.environ, {"JUA_WORKFLOW_MUTATION_LOCK_TIMEOUT_SECONDS": "bad"}
            ):
                with run_step._workflow_mutation_lock("/tmp/report"):
                    self.assertEqual(context.depth, 3)
                    self.assertEqual(context.report_roots[-1], Path("/tmp/report").resolve())
            self.assertEqual(context.depth, 2)

            context.depth = 3
            context.report_roots = (Path("/tmp/inherited").resolve(),)
            context.process_id = os.getpid() + 1
            manager = _LockManager()
            with patch.object(
                run_step, "exclusive_file_lock", return_value=manager
            ):
                with run_step._workflow_mutation_lock("/tmp/report", timeout_seconds=0):
                    self.assertEqual(context.depth, 1)
                    self.assertEqual(context.report_roots, (Path("/tmp/report").resolve(),))
        finally:
            context.depth, context.report_roots, context.process_id = old

        with patch.object(
            run_step, "_main_with_workflow_lock_held", return_value=17
        ) as inner:
            self.assertEqual(run_step.main(["--describe-step0-contract"]), 17)
        inner.assert_called_once()

        original_recovery_attempts = set(
            run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS
        )
        try:
            run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS.clear()
            report_key = str(Path("/tmp/report").resolve())
            other_key = str(Path("/tmp/other").resolve())
            run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS.update(
                {(report_key, "step1"), (other_key, "step2")}
            )
            with patch.object(
                run_step,
                "_workflow_report_dir_from_argv",
                return_value=Path("/tmp/report"),
            ), patch.object(
                run_step, "_workflow_mutation_lock", return_value=_LockManager()
            ), patch.object(
                run_step, "_main_with_workflow_lock_held", return_value=0
            ):
                self.assertEqual(run_step.main([]), 0)
            self.assertEqual(
                run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS,
                {(other_key, "step2")},
            )
        finally:
            run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS.clear()
            run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS.update(
                original_recovery_attempts
            )

    def test_remaining_pure_decision_branch_matrix(self):
        recommendation_cases = (
            (None, False),
            ({"recommended": "false", "impact_priority_rank": "1"}, False),
            ({"recommended": "true"}, True),
            ({"impact_priority_rank": "5"}, True),
            ({"impact_priority_rank": "11"}, False),
        )
        for row, expected in recommendation_cases:
            with self.subTest(recommendation=row):
                self.assertEqual(
                    run_step._is_recommended_selection_target(row), expected
                )

        with patch.object(
            run_step,
            "read_csv_rows",
            return_value=[
                {"coord": "g:empty", "old_version": "", "new_version": "-"},
                {"coord": "g:new", "old_version": "-", "new_version": "2"},
                {"coord": "g:old", "old_version": "1", "new_version": "-"},
            ],
        ):
            self.assertEqual(
                run_step._dependency_change_versions("/tmp/report"),
                {
                    "g:new": {"base": "-", "current": "2"},
                    "g:old": {"base": "1", "current": "-"},
                },
            )

        self.assertEqual(
            run_step._filter_inferred_coords_by_prefix(None, ""), []
        )
        self.assertEqual(
            run_step._filter_inferred_coords_by_prefix(
                ["g:a", "g:b", "other:c", ""], "g:a"
            ),
            ["g:a"],
        )
        self.assertEqual(
            run_step._filter_inferred_coords_by_prefix(
                ["g:a", "g:b", "other:c", ""], "g"
            ),
            ["g:a", "g:b"],
        )
        hint_cases = (
            (["g:only"], "", "/repo/unknown", ["g:only"]),
            (["g:a", "g:b"], "x:a", "/repo/no-match", ["g:a"]),
            (["g:a", "g:b"], "x:no", "/repo/b", ["g:b"]),
            (["g:alpha-core", "g:beta"], "x:alpha", "/repo/no", ["g:alpha-core"]),
            (["g:alpha", "g:beta-core"], "x:no", "/repo/beta", ["g:beta-core"]),
            (["g:alpha", "g:alphabet"], "x:alp", "/repo/no", []),
            ([], "x:a", "/repo/a", []),
        )
        for coords, hint, path, expected in hint_cases:
            with self.subTest(coords=coords, hint=hint, path=path):
                self.assertEqual(
                    run_step._filter_inferred_coords_by_hint(coords, hint, path),
                    expected,
                )

        self.assertEqual(run_step._step0_cell(None), "请提供")
        self.assertEqual(
            run_step._step0_cell(None, optional=True), "未提供（可选）"
        )
        self.assertEqual(run_step._step0_cell("  "), "请提供")
        self.assertIn("自动识别", run_step._step0_cell("value", "detected"))
        self.assertIn("待确认", run_step._step0_cell("value", "user"))

        self.assertIn(
            "当前任务未完成",
            run_step._resume_event_description(None, "step_failed"),
        )
        self.assertIn(
            "原因：bad",
            run_step._resume_event_description("step2", "step_failed", "bad"),
        )
        self.assertIn(
            "安全暂停",
            run_step._resume_event_description("step2", "paused_by_user"),
        )
        self.assertIn(
            "下一任务",
            run_step._resume_next_action({"current_step": ""}, "updated"),
        )

    def test_cli_boundary_and_diagnostic_truth_table(self):
        with patch.object(sys, "argv", ["run_step.py", "--report-dir", "/tmp/from-sys"]):
            self.assertEqual(
                run_step._cli_report_dir(None), Path("/tmp/from-sys").resolve()
            )
        self.assertIsNone(run_step._cli_report_dir([]))
        self.assertIsNone(run_step._cli_report_dir(["--report-dir"]))
        self.assertIsNone(run_step._cli_report_dir(["--report-dir", None]))
        self.assertEqual(
            run_step._cli_report_dir(["--report-dir", " /tmp/report "]),
            Path("/tmp/report").resolve(),
        )

        cases = (
            {
                "name": "empty_step_error",
                "ownership": None,
                "main_error": run_step.StepError(""),
                "finish": True,
                "diagnostic": "",
                "expected": 1,
                "message": "当前输入或状态不完整",
            },
            {
                "name": "inner_unexpected_with_diagnostic",
                "ownership": None,
                "main_error": RuntimeError("boom"),
                "finish": True,
                "diagnostic": "/tmp/diagnostic.json",
                "expected": 1,
                "message": "诊断已记录",
            },
            {
                "name": "no_background_ownership_needed",
                "ownership": None,
                "main_result": 0,
                "finish": False,
                "diagnostic": "",
                "expected": 0,
                "message": "",
            },
            {
                "name": "lost_background_ownership",
                "ownership": {"lease": 1},
                "main_result": 0,
                "finish": False,
                "diagnostic": "",
                "expected": 1,
                "message": "后台任务已失去",
            },
        )
        for case in cases:
            stderr = io.StringIO()
            main_effect = case.get("main_error", case.get("main_result"))
            with self.subTest(case=case["name"]), patch.object(
                run_step,
                "_background_child_lease",
                return_value=_LockManager(enter_value=case["ownership"]),
            ), patch.object(
                run_step, "main", side_effect=main_effect
                if isinstance(main_effect, BaseException)
                else None,
                return_value=main_effect
                if not isinstance(main_effect, BaseException)
                else None,
            ), patch.object(
                run_step, "finish_background_run", return_value=case["finish"]
            ), patch.object(
                run_step,
                "_record_unexpected_cli_error",
                return_value=case["diagnostic"],
            ), patch("sys.stderr", stderr):
                self.assertEqual(run_step.cli_main([]), case["expected"])
            self.assertIn(case["message"], stderr.getvalue())

        outer_cases = (
            (
                run_step._BackgroundOwnershipError(""),
                "",
                1,
                "当前输入或状态不完整",
            ),
            (KeyboardInterrupt(), "", run_step.EXIT_INTERRUPTED, "运行已停止"),
            (RuntimeError("outer"), "/tmp/outer.json", 1, "诊断已记录"),
            (RuntimeError("outer"), "", 1, "无法写入诊断"),
        )
        for error, diagnostic, expected, message in outer_cases:
            stderr = io.StringIO()
            with self.subTest(error=type(error).__name__, diagnostic=diagnostic), patch.object(
                run_step,
                "_background_child_lease",
                return_value=_LockManager(enter_error=error),
            ), patch.object(
                run_step,
                "_record_unexpected_cli_error",
                return_value=diagnostic,
            ), patch("sys.stderr", stderr):
                self.assertEqual(run_step.cli_main([]), expected)
            self.assertIn(message, stderr.getvalue())

    def test_runtime_state_and_interaction_residual_matrix(self):
        self.assertEqual(run_step.build_environment_warning_messages(None), [])
        self.assertEqual(
            run_step.build_environment_warning_messages(
                {"warnings": [{}, {"reason": "other"}]}
            ),
            [],
        )
        warnings = run_step.build_environment_warning_messages(
            {
                "warnings": [
                    {"reason": "python_version_not_ci_verified"},
                    {
                        "reason": "python_version_not_ci_verified",
                        "observed": "Python 3.15",
                    },
                ]
            }
        )
        self.assertIn("Python 版本", warnings[0])
        self.assertIn("Python 3.15", warnings[1])

        self.assertEqual(
            run_step.build_user_runtime_message("done", "step5")[-1],
            "接下来：分析报告",
        )
        self.assertEqual(
            run_step.build_user_runtime_message("done", "step6", completion_summary={})[0],
            "分析已完成。",
        )
        limited = run_step.build_user_runtime_message(
            "done",
            "step6",
            completion_summary={
                "status": "completed_with_limits",
                "scope_mode": "partial",
                "included_dependency_count": None,
                "available_dependency_count": 3,
                "dependency_completed_count": 2,
            },
        )
        self.assertIn("部分依赖（0/3）", limited[1])
        self.assertEqual(
            run_step.build_user_runtime_message("done", "step6", completion_summary={"scope_mode": "full"})[1],
            "分析范围：依赖 API 变化分析识别出的全部变化依赖。",
        )

        state = run_step.ensure_main_state_structure(
            {"schema": run_step.MAIN_STATE_SCHEMA}, "/tmp/report"
        )
        self.assertEqual(state["state"]["status"], "idle")
        completed = run_step.ensure_main_state_structure(
            {
                "schema": run_step.MAIN_STATE_SCHEMA,
                "state": {
                    "current_step": "done",
                    "status": "completed",
                    "completion_summary": {"status": "completed"},
                },
            },
            "/tmp/report",
        )
        self.assertEqual(completed["state"]["status"], "completed")
        restarted = run_step.ensure_main_state_structure(
            {
                "schema": run_step.MAIN_STATE_SCHEMA,
                "state": {
                    "current_step": "step2",
                    "status": "completed_with_limits",
                    "completion_summary": {"stale": True},
                },
            },
            "/tmp/report",
        )
        self.assertEqual(restarted["state"]["status"], "ready")
        self.assertIsNone(restarted["state"]["completion_summary"])

        state = {"step0": {}, "step1": {}, "step2": {}}
        self.assertEqual(run_step.build_step_input_context(state, "step0"), {})
        with patch.object(run_step, "previous_step_output", return_value={"prior": 1}):
            self.assertEqual(
                run_step.build_step_input_context(
                    {"step2": {"input": {"current": 2}}}, "step2"
                ),
                {"prior": 1, "current": 2},
            )

        interaction_cases = (
            {
                "step_id": "unknown",
                "title": "Fallback title",
                "user_decision_card": ["prebuilt"],
                "options": None,
            },
            {"step_id": "", "title": "", "options": []},
        )
        for interaction in interaction_cases:
            stderr = io.StringIO()
            with self.subTest(interaction=interaction), patch.dict(
                os.environ, {"JUA_INTERACTION_OUTPUT": "human"}, clear=False
            ), patch("sys.stderr", stderr):
                run_step.print_interaction_to_streams(interaction, "/tmp/report")
            self.assertTrue(stderr.getvalue())

    def test_private_checkpoint_race_and_size_truth_table(self):
        regular_mode = stat.S_IFREG | 0o600

        def observed(size=1, *, mode=regular_mode, links=1, inode=1):
            return SimpleNamespace(
                st_dev=1,
                st_ino=inode,
                st_mode=mode,
                st_nlink=links,
                st_size=size,
                st_mtime=1.0,
                st_mtime_ns=1,
            )

        for initial in (
            observed(mode=stat.S_IFDIR | 0o700),
            observed(links=2),
            observed(run_step._STEP4_VALIDATION_CHECKPOINT_MAX_BYTES + 1),
        ):
            with self.subTest(initial=initial), patch.object(
                run_step.os, "lstat", return_value=initial
            ), patch.object(run_step.os, "open") as open_file, self.assertRaisesRegex(
                OSError, "bounded private regular file"
            ):
                run_step._read_private_step4_checkpoint("checkpoint")
            open_file.assert_not_called()

        initial = observed(1)
        opened = observed(1)
        current = observed(1)
        completed = observed(1)
        final = observed(1)

        def invoke(identities, chunks, *, completed_stat=completed, max_bytes=None):
            constant = (
                run_step._STEP4_VALIDATION_CHECKPOINT_MAX_BYTES
                if max_bytes is None
                else max_bytes
            )
            lstat = Mock(side_effect=[initial, current, final])
            open_file = Mock(return_value=17)
            fstat = Mock(side_effect=[opened, completed_stat])
            read_file = Mock(side_effect=chunks)
            close_file = Mock()
            os_proxy = _AttributeProxy(
                run_step.os,
                lstat=lstat,
                open=open_file,
                fstat=fstat,
                read=read_file,
                close=close_file,
            )
            with patch.object(
                run_step, "_STEP4_VALIDATION_CHECKPOINT_MAX_BYTES", constant
            ), patch.object(
                run_step, "os", os_proxy
            ), patch.object(
                run_step,
                "_step4_checkpoint_stat_identity",
                side_effect=identities,
            ):
                try:
                    return run_step._read_private_step4_checkpoint("checkpoint")
                finally:
                    close_file.assert_called_once_with(17)

        original_os = run_step.os
        flag_proxy = _AttributeProxy(
            original_os,
            O_NOFOLLOW=0,
            O_NONBLOCK=0,
            O_CLOEXEC=0,
            O_BINARY=8,
        )
        with patch.object(run_step, "os", flag_proxy):
            self.assertEqual(invoke(["same"] * 8, [b"x", b""]), b"x")

        for identities, message in (
            (["initial", "opened"], "changed while opening"),
            (["same", "same", "opened", "current"], "changed while opening"),
            (
                ["same"] * 4 + ["opened", "completed"],
                "changed while reading",
            ),
            (
                ["same"] * 6 + ["completed", "final"],
                "changed while reading",
            ),
        ):
            with self.subTest(identities=identities), self.assertRaisesRegex(
                OSError, message
            ):
                invoke(identities, [b"x", b""])

        with self.assertRaisesRegex(OSError, "changed while reading"):
            invoke(["same"] * 4, [b"abc"], max_bytes=2)
        with self.assertRaisesRegex(OSError, "changed while reading"):
            invoke(
                ["same"] * 4,
                [b"x", b""],
                completed_stat=observed(2),
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "checkpoint.json").write_bytes(b"{}")
            directory_fd = os.open(root, os.O_RDONLY)
            try:
                self.assertEqual(
                    run_step._read_private_step4_checkpoint(
                        "checkpoint.json", parent_fd=directory_fd
                    ),
                    b"{}",
                )
            finally:
                os.close(directory_fd)

    def test_descriptor_cleanup_and_checkpoint_binding_truth_table(self):
        directory_mode = stat.S_IFDIR | 0o700
        regular_mode = stat.S_IFREG | 0o600
        symlink_mode = stat.S_IFLNK | 0o777

        with patch.object(run_step.os, "open", return_value=9), patch.object(
            run_step.os,
            "fstat",
            return_value=SimpleNamespace(st_mode=regular_mode),
        ), patch.object(run_step.os, "close") as close_file, self.assertRaisesRegex(
            OSError, "not a directory"
        ):
            run_step._open_cleanup_directory("value")
        close_file.assert_called_once_with(9)

        expected = SimpleNamespace(st_mode=directory_mode)
        opened = SimpleNamespace(st_mode=directory_mode)
        with patch.object(run_step.os, "open", return_value=10), patch.object(
            run_step.os, "fstat", return_value=opened
        ), patch.object(run_step.os.path, "samestat", return_value=False), patch.object(
            run_step.os, "close"
        ) as close_file, self.assertRaisesRegex(OSError, "changed while opening"):
            run_step._open_cleanup_directory("value", expected=expected)
        close_file.assert_called_once_with(10)
        with patch.object(run_step.os, "open", return_value=11), patch.object(
            run_step.os, "fstat", return_value=opened
        ):
            self.assertEqual(
                run_step._open_cleanup_directory("value", expected=None)[0], 11
            )

        with self.assertRaisesRegex(OSError, "nesting exceeds"):
            run_step._remove_cleanup_directory_tree_at(1, "deep", expected, depth=257)
        with patch.object(
            run_step, "_open_cleanup_directory", return_value=(12, opened)
        ), patch.object(
            run_step.os, "listdir", side_effect=[[], ["late"]]
        ), patch.object(run_step.os, "close"), self.assertRaisesRegex(
            OSError, "changed while removing"
        ):
            run_step._remove_cleanup_directory_tree_at(1, "changing", expected)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "report"
            root.mkdir()
            try:
                root_link = Path(directory) / "report-link"
                root_link.symlink_to(root, target_is_directory=True)
            except (OSError, NotImplementedError):
                root_link = None
            if root_link is not None:
                with self.assertRaisesRegex(OSError, "report root"):
                    run_step._remove_step_output_with_directory_descriptors(
                        root_link, Path("value")
                    )
                with self.assertRaisesRegex(OSError, "report root"):
                    run_step._read_step4_checkpoint_with_directory_descriptors(
                        root_link, Path("checkpoint.json")
                    )

            parent_file = root / "parent-file"
            parent_file.write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(OSError, "output parent"):
                run_step._remove_step_output_with_directory_descriptors(
                    root, Path("parent-file/value")
                )
            with self.assertRaisesRegex(OSError, "checkpoint parent"):
                run_step._read_step4_checkpoint_with_directory_descriptors(
                    root, Path("parent-file/value")
                )

            target = root / "target.txt"
            target.write_text("x", encoding="utf-8")
            target_link = root / "target-link"
            try:
                target_link.symlink_to(target)
            except (OSError, NotImplementedError):
                target_link = None
            if target_link is not None:
                self.assertTrue(
                    run_step._remove_step_output_with_directory_descriptors(
                        root, Path("target-link")
                    )
                )
                self.assertFalse(target_link.exists())

            fifo = root / "special"
            if hasattr(os, "mkfifo"):
                os.mkfifo(fifo)
                with self.assertRaisesRegex(OSError, "not a regular file"):
                    run_step._remove_step_output_with_directory_descriptors(
                        root, Path("special")
                    )
                fifo.unlink()

            checkpoint = root / "checkpoint.json"
            checkpoint.write_bytes(b"{}")
            self.assertEqual(
                run_step._read_step4_checkpoint_with_directory_descriptors(
                    root, Path("checkpoint.json")
                ),
                b"{}",
            )
            self.assertIsNone(
                run_step._read_step4_checkpoint_with_directory_descriptors(
                    root, Path("missing.json")
                )
            )

            race_target = root / "race.txt"
            race_target.write_text("x", encoding="utf-8")
            with patch.object(
                run_step.os.path, "samestat", side_effect=[True, True, False]
            ), self.assertRaisesRegex(OSError, "report root changed"):
                run_step._remove_step_output_with_directory_descriptors(
                    root, Path("race.txt")
                )

            checkpoint.write_bytes(b"{}")
            with patch.object(
                run_step.os.path, "samestat", side_effect=[True, True, False]
            ), self.assertRaisesRegex(OSError, "report root changed"):
                run_step._read_step4_checkpoint_with_directory_descriptors(
                    root, Path("checkpoint.json")
                )

    def test_progress_snapshot_and_publication_expectation_truth_table(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            progress = root / "progress.json"
            progress.write_bytes(
                b"x" * (run_step._BINARY_PROGRESS_MAX_BYTES + 1)
            )
            self.assertEqual(
                run_step._binary_progress_file_snapshot(progress), (None, None)
            )
            progress.write_text("[]", encoding="utf-8")
            value, identity = run_step._binary_progress_file_snapshot(progress)
            self.assertIsNone(value)
            self.assertIsNotNone(identity)
            progress.write_text('{"phase":"running"}', encoding="utf-8")
            value, identity = run_step._binary_progress_file_snapshot(progress)
            self.assertEqual(value, {"phase": "running"})

        before = SimpleNamespace(st_dev=1, st_ino=1, st_size=2, st_mtime_ns=1)
        after = SimpleNamespace(st_dev=1, st_ino=2, st_size=2, st_mtime_ns=1)
        fake_path = SimpleNamespace(
            stat=Mock(side_effect=[before, after]),
            read_bytes=Mock(return_value=b"{}"),
        )
        with patch.object(run_step, "Path", return_value=fake_path):
            self.assertEqual(
                run_step._binary_progress_file_snapshot("progress"), (None, None)
            )

        baseline = (1, 2)
        legacy_cases = (
            ((None, baseline), {}),
            (({"phase": "same"}, baseline), {}),
            (({"attempt_identity": "foreign"}, (2, 3)), {}),
            (({"phase": "new"}, (2, 3)), {"phase": "new"}),
        )
        for snapshot, expected in legacy_cases:
            with self.subTest(snapshot=snapshot), patch.object(
                run_step, "_binary_progress_file_snapshot", return_value=snapshot
            ):
                self.assertEqual(
                    run_step._legacy_progress_after_baseline("progress", baseline),
                    expected,
                )

        valid_id = "a" * 32
        valid_binding = {"generation": "g1"}
        publication_cases = (
            (None, None),
            ({}, None),
            (
                {
                    "publication_transaction": {
                        "transaction_id": valid_id,
                        "binding": valid_binding,
                    }
                },
                {"transaction_id": valid_id, "binding": valid_binding},
            ),
            (
                {
                    "report_publication_transaction": {},
                    "publication_transaction": {
                        "transaction_id": valid_id,
                        "binding": valid_binding,
                    },
                },
                {"transaction_id": valid_id, "binding": valid_binding},
            ),
            (
                {
                    "report_publication_transaction": {
                        "transaction_id": "g" * 32,
                        "binding": valid_binding,
                    }
                },
                None,
            ),
            (
                {
                    "report_publication_transaction": {
                        "transaction_id": "a" * 31,
                        "binding": valid_binding,
                    }
                },
                None,
            ),
            (
                {
                    "report_publication_transaction": {
                        "transaction_id": valid_id,
                        "binding": {},
                    }
                },
                None,
            ),
        )
        for payload, expected in publication_cases:
            with self.subTest(payload=payload):
                self.assertEqual(
                    run_step._report_publication_expectation(
                        payload, stage="step5"
                    ),
                    expected,
                )
        with self.assertRaisesRegex(run_step.StepError, "transaction_id"):
            run_step._report_publication_expectation(
                {"publication_transaction": {}}, stage="step6", required=True
            )

    def test_ref_binding_snapshot_and_step5_row_shape_matrix(self):
        commit = "a" * 40
        repo = "/tmp/repository"
        candidate_cases = (
            (
                {
                    "expected_commit": commit,
                    "candidates": [{}, {"commit": commit, "canonical_ref": "refs/heads/main"}],
                },
                None,
                {},
            ),
            (
                {
                    "expected_commit": commit,
                    "candidates": [{"commit": commit, "remote": "origin"}],
                },
                None,
                {},
            ),
            (
                {"expected_commit": commit},
                {
                    "expected_commit": commit,
                    "remote": "",
                    "canonical_ref": "",
                },
                {},
            ),
            (
                {
                    "expected_commit": commit,
                    "remote": "upstream",
                    "remote_ref": "refs/heads/main",
                },
                {
                    "expected_commit": commit,
                    "remote": "old",
                    "canonical_ref": "refs/old/main",
                },
                {"remote": "upstream", "canonical_ref": "refs/heads/main"},
            ),
            (
                {
                    "expected_commit": commit,
                    "remote": "upstream",
                },
                {
                    "expected_commit": commit,
                    "remote": "old",
                    "canonical_ref": "refs/old/main",
                },
                {"remote": "upstream", "canonical_ref": "refs/old/main"},
            ),
            (
                {
                    "expected_commit": commit,
                    "remote_ref": "refs/heads/main",
                },
                {
                    "expected_commit": commit,
                    "remote": "origin",
                    "canonical_ref": "refs/old/main",
                },
                {"remote": "origin", "canonical_ref": "refs/heads/main"},
            ),
        )
        for resolution, existing, expected_fields in candidate_cases:
            with self.subTest(resolution=resolution, existing=existing):
                result = run_step._durable_step1_ref_binding_from_failure(
                    resolution,
                    repo,
                    "main",
                    existing_binding=existing,
                )
                for key, expected in expected_fields.items():
                    self.assertEqual(result[key], expected)
                if not expected_fields:
                    self.assertEqual(result, {})

        valid_binding = run_step._step1_ref_binding(
            repo,
            "main",
            commit,
            remote="origin",
            canonical_ref="refs/remotes/origin/main",
        )
        base_context = {
            "base_branch": "main",
            "base_expected_commit": commit,
            "base_ref_binding": valid_binding,
        }
        self.assertEqual(
            run_step._matching_step1_ref_binding(base_context, "base", repo),
            valid_binding,
        )
        self.assertEqual(
            run_step._matching_step1_ref_binding(
                {**base_context, "base_expected_commit": ""}, "base", repo
            ),
            {},
        )
        self.assertEqual(
            run_step._matching_step1_ref_binding(
                {
                    **base_context,
                    "base_ref_binding": {**valid_binding, "schema": "old"},
                },
                "base",
                repo,
            ),
            {},
        )
        self.assertEqual(
            run_step._matching_step1_ref_binding(
                {**base_context, "base_branch": "other"}, "base", repo
            ),
            {},
        )
        artifact_binding = run_step._step1_ref_binding(
            repo,
            "main",
            commit,
            remote="origin",
            canonical_ref="refs/remotes/origin/main",
            artifact_path="/tmp/current.jar",
        )
        self.assertEqual(
            run_step._matching_step1_ref_binding(
                {
                    "current_branch": "main",
                    "current_expected_commit": commit,
                    "current_artifact_path": "/tmp/current.jar",
                    "current_ref_binding": artifact_binding,
                },
                "current",
                repo,
            )["artifact_path"],
            str(Path("/tmp/current.jar").resolve()),
        )

        snapshot = {
            "schema": run_step.PINNED_SOURCE_SNAPSHOT_SCHEMA,
            "commit": commit,
            "project_path": ".",
            "target_module": "",
            "active_maven_profiles": [],
        }
        self.assertTrue(
            run_step._pinned_snapshot_matches_context(
                snapshot, {"current_resolved_commit": commit}
            )
        )
        self.assertFalse(
            run_step._pinned_snapshot_matches_context(
                snapshot,
                {
                    "current_resolved_commit": commit,
                    "target_module": "app",
                },
            )
        )
        self.assertTrue(
            run_step._pinned_snapshot_matches_context(
                {**snapshot, "active_maven_profiles": ["prod"]},
                {
                    "current_resolved_commit": commit,
                    "active_maven_profiles": ["prod", "prod"],
                },
            )
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "all.csv"
            input_path.write_text("unused", encoding="utf-8")
            rows = [None, {}, {"coord": ""}, {"coord": "g:a"}]
            persisted = []
            with patch.object(run_step, "read_csv_rows", return_value=rows), patch.object(
                run_step,
                "write_json",
                side_effect=lambda _path, value: persisted.append(value),
            ):
                _path, summary = run_step.materialize_step5_all_changed_apis_input(
                    input_path, root / "report", {}
                )
            self.assertEqual(summary["available_target_count"], 1)
            self.assertEqual(persisted[-1]["included_dependency_coords"], ["g:a"])

        state = {
            "step4": {"input": {"step5_selected_coords": ["g:a"]}},
            "step5": {"input": {}},
        }
        selection = {
            "matched_rows": [None, {}, {"coord": ""}, {"coord": "g:a"}],
            "available_target_count": 1,
            "matched_row_count": 4,
        }
        with patch.object(run_step, "save_main_state"), patch.object(
            run_step, "read_csv_rows", return_value=[None, {"coord": "g:a"}]
        ), patch.object(
            run_step, "build_step5_selection_summary", return_value=selection
        ), patch("sys.stderr", io.StringIO()) as stderr:
            run_step.handle_step4_resume_followups(
                state, "/tmp/report", "step4", "continue"
            )
        self.assertIn("纳入 1/1", stderr.getvalue())

        selection_with_empty_name = run_step.build_step5_selection_summary(
            [{"coord": ":", "change_type": "ADDED"}],
            selected_names=["missing"],
        )
        self.assertEqual(selection_with_empty_name["unmatched_names"], ["missing"])

    def test_landing_artifact_authority_and_status_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            relative_paths = (
                "deliverables/report.md",
                "evidence/call_chain/alerts.csv",
                "evidence/api_changes/all_changed_apis.csv",
                "evidence/context/review.md",
                "evidence/dependencies/dep_changes.csv",
            )
            for relative in relative_paths:
                target = report / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("x", encoding="utf-8")

            with patch.object(
                run_step, "report_uses_release_protocol", return_value=False
            ):
                rows = run_step._landing_existing_artifact_rows(report)
                invalid_state_rows = run_step._landing_existing_artifact_rows(
                    report, {"state": {"completed_step": "invalid"}}
                )
                step4_rows = run_step._landing_existing_artifact_rows(
                    report, {"state": {"completed_step": "step4"}}
                )
            self.assertIn(("依赖与 API 升级影响报告", "deliverables/report.md"), rows)
            self.assertNotIn("deliverables/report.md", dict(invalid_state_rows).values())
            self.assertIn(
                "evidence/dependencies/dep_changes.csv",
                dict(invalid_state_rows).values(),
            )
            self.assertIn(
                "evidence/api_changes/all_changed_apis.csv",
                dict(step4_rows).values(),
            )
            self.assertNotIn(
                "evidence/call_chain/alerts.csv", dict(step4_rows).values()
            )

            findings_path = run_step.s6_findings_path(report)
            findings_path.parent.mkdir(parents=True, exist_ok=True)
            findings_path.write_text("{}", encoding="utf-8")
            with patch.object(
                run_step, "report_uses_release_protocol", return_value=False
            ), patch.object(run_step, "read_json", return_value={"artifacts": None}):
                legacy_rows = run_step._landing_existing_artifact_rows(report)
            legacy_values = set(dict(legacy_rows).values())
            self.assertNotIn("evidence/call_chain/alerts.csv", legacy_values)
            self.assertNotIn("evidence/context/review.md", legacy_values)

            current_release = {
                stage: {"status": "current"}
                for stage in ("step4", "step5", "step6")
            }
            with patch.object(
                run_step, "report_uses_release_protocol", return_value=True
            ), patch.object(
                run_step, "reconcile_current_release", return_value=current_release
            ), patch.object(
                run_step,
                "load_consistent_step6_publication",
                return_value={"findings": None, "deliverable_names": None},
            ):
                empty_protocol_rows = run_step._landing_existing_artifact_rows(report)
            self.assertNotIn(
                "deliverables/report.md", dict(empty_protocol_rows).values()
            )

            with patch.object(
                run_step, "report_uses_release_protocol", return_value=True
            ), patch.object(
                run_step, "reconcile_current_release", return_value=current_release
            ), patch.object(
                run_step,
                "load_consistent_step6_publication",
                return_value={
                    "findings": {
                        "artifacts": {
                            "alerts_csv": True,
                            "changed_apis_csv": True,
                        }
                    },
                    "deliverable_names": ["report.md"],
                },
            ):
                protocol_rows = run_step._landing_existing_artifact_rows(report)
            protocol_values = set(dict(protocol_rows).values())
            self.assertIn("deliverables/report.md", protocol_values)
            self.assertIn("evidence/call_chain/alerts.csv", protocol_values)

            with patch.object(
                run_step, "report_uses_release_protocol", return_value=True
            ), patch.object(
                run_step,
                "reconcile_current_release",
                side_effect=RuntimeError("corrupt receipt"),
            ):
                stale_rows = run_step._landing_existing_artifact_rows(report)
            stale_values = set(dict(stale_rows).values())
            self.assertNotIn("deliverables/report.md", stale_values)
            self.assertIn("evidence/context/review.md", stale_values)

        status_cases = (
            (
                {
                    "state": {
                        "status": "completed",
                        "current_step": "done",
                        "completion_summary": {"status": "completed"},
                    }
                },
                "未记录",
            ),
            (
                {
                    "state": {
                        "status": "completed_with_limits",
                        "current_step": "done",
                        "completion_summary": {
                            "scope_mode": "partial",
                            "included_dependency_count": None,
                            "available_dependency_count": 4,
                        },
                    }
                },
                "部分依赖（0/4）",
            ),
        )
        for state, expected in status_cases:
            self.assertIn(expected, "\n".join(run_step._landing_status_lines(state)))

    def test_git_entry_dispatch_and_dependency_population_residual_matrix(self):
        git_cases = (
            ((None, "", 0), None),
            (("", "", 0), None),
            (("/tmp/repo\n", "", 1), None),
            (("/tmp/repo\n", "", 0), Path("/tmp/repo").resolve()),
        )
        for result, expected in git_cases:
            with self.subTest(result=result), patch.object(
                run_step, "run_cmd", return_value=result
            ):
                self.assertEqual(run_step._git_repository_root("/tmp"), expected)

        branch_cases = (
            ((None, "", 0), ""),
            (("", "", 0), ""),
            (("main\n", "", 1), ""),
            (("main\n", "", 0), "main"),
        )
        for result, expected in branch_cases:
            with self.subTest(result=result), patch.object(
                run_step, "run_cmd", return_value=result
            ):
                self.assertEqual(run_step.detect_current_git_branch("/tmp"), expected)

        with patch.object(
            run_step, "_execute_step_unlocked", return_value={"step": "step3"}
        ) as unlocked:
            self.assertEqual(
                run_step.execute_step(None, SimpleNamespace(), {}, {}),
                {"step": "step3"},
            )
        unlocked.assert_called_once()

        args = SimpleNamespace(report_dir="/tmp/report", strict_risk_gate=False)
        with patch.object(
            run_step, "_binary_step4_run_lock", return_value=_LockManager()
        ) as lock, patch.object(
            run_step, "_execute_step_unlocked", return_value={"step": "step4"}
        ):
            self.assertEqual(
                run_step.execute_step("step4", args, {"step4": {}}, {}),
                {"step": "step4"},
            )
        self.assertEqual(lock.call_args.kwargs["expected_gate_name"], "")

        with patch.object(
            run_step,
            "read_csv_rows",
            return_value=[
                {
                    "coord": "g:ignored",
                    "old_version": "-",
                    "new_version": "-",
                },
                {
                    "coord": "g:included",
                    "old_version": "1",
                    "new_version": "2",
                },
            ],
        ):
            self.assertEqual(
                run_step._collect_relevant_dependency_coords("/tmp/report"),
                ["g:included"],
            )

        with patch.object(
            run_step, "_dependency_change_versions", return_value={}
        ), patch.object(
            run_step, "_build_dependency_source_plan", return_value={"candidates": None}
        ):
            plan, mappings = run_step._dependency_repo_mapping_candidates(
                {}, "/tmp/report"
            )
        self.assertIsNone(plan["candidates"])
        self.assertEqual(mappings, {})

    def test_coord_inference_and_release_recovery_exhaustive_matrix(self):
        path = "/tmp/repository"
        inference_cases = (
            (["", "g:a"], "", True, [f"g:a={path}"]),
            (["g:a", "g:b"], "", False, [f"g:a={path}", f"g:b={path}"]),
            (["g:a", "g:b"], "g:a", False, [f"g:a={path}"]),
            ([], "g:a", False, [f"g:a={path}"]),
        )
        for inferred, coord, expand_all, expected in inference_cases:
            with self.subTest(inferred=inferred, coord=coord), patch.object(
                run_step, "infer_maven_coords", return_value=inferred
            ):
                self.assertEqual(
                    run_step._expand_coord_path_by_repo(
                        coord,
                        path,
                        "dependency_source_dirs",
                        expand_all_inferred=expand_all,
                    ),
                    expected,
                )
        for inferred, coord, message in (
            (["g:a", "g:b"], "g:missing", "未能在源码仓库中匹配"),
            ([], "group", "无法映射到源码仓库"),
            ([], "", "未提供 coord"),
        ):
            with self.subTest(inferred=inferred, coord=coord), patch.object(
                run_step, "infer_maven_coords", return_value=inferred
            ), self.assertRaisesRegex(run_step.StepError, message):
                run_step._expand_coord_path_by_repo(
                    coord, path, "dependency_source_dirs"
                )

        hint_cases = (
            (["g:a", "g:b"], "x:no", "/", []),
            (["g:", "g:b"], "x:no", "/", []),
            (["g:beta-core", "g:beta-extra"], "x:no", "/repo/beta", []),
            (["g:alpha", "g:beta"], "x:no", "/repo/no", []),
        )
        for inferred, hint, source_path, expected in hint_cases:
            with self.subTest(inferred=inferred, source_path=source_path):
                self.assertEqual(
                    run_step._filter_inferred_coords_by_hint(
                        inferred, hint, source_path
                    ),
                    expected,
                )

        args = SimpleNamespace(step="done")
        all_current = {
            stage: {"status": "current"}
            for stage in ("step4", "step5", "step6")
        }
        with patch.object(
            run_step, "_startup_step4_recovery_target_hint", return_value="done"
        ), patch.object(
            run_step, "reconcile_current_release", return_value=all_current
        ), patch.object(
            run_step, "_downstream_gate_policy_is_current", return_value=True
        ):
            current = run_step._apply_downstream_release_startup_state(
                args=args,
                main_state={},
                report_dir="/tmp/report",
                structured_user_response={},
                has_structured_response=False,
            )
        self.assertEqual(current["forced_step_id"], "")
        self.assertEqual(current["release"], all_current)

        reset_calls = []
        with patch.object(
            run_step, "_startup_step4_recovery_target_hint", return_value="done"
        ), patch.object(
            run_step,
            "reconcile_current_release",
            return_value={"step4": {"status": "current"}},
        ), patch.object(
            run_step, "_downstream_gate_policy_is_current", return_value=False
        ), patch.object(
            run_step, "build_restore_context", return_value={"saved": True}
        ), patch.object(
            run_step,
            "reset_step_state_for_restart",
            side_effect=lambda *_args, **kwargs: reset_calls.append(kwargs),
        ), patch.object(run_step, "save_main_state"), patch.object(
            run_step, "clear_interaction_file"
        ):
            repaired = run_step._apply_downstream_release_startup_state(
                args=args,
                main_state={},
                report_dir="/tmp/report",
                structured_user_response={"action": "continue"},
                has_structured_response=True,
                manifest_steps={"step5": {}, "step6": {}},
            )
        self.assertEqual(repaired["forced_step_id"], "step5")
        self.assertTrue(repaired["discard_structured_response"])
        self.assertEqual(reset_calls[0]["preserve_current_input"], {"saved": True})

    def test_persistence_and_restart_boundary_exhaustive_matrix(self):
        state = run_step.new_main_state("/tmp/report")
        common_patches = (
            patch.object(run_step, "store_step_output"),
            patch.object(run_step, "seed_next_step_input"),
            patch.object(run_step, "save_main_state"),
            patch.object(run_step, "clear_interaction_file"),
            patch.object(run_step, "write_resume_snapshot"),
        )
        for manager in common_patches:
            manager.start()
        try:
            with patch.object(
                run_step, "build_final_completion_summary", return_value={"status": ""}
            ):
                summary = run_step.persist_completed_step(
                    state, "step6", "/tmp/report", {}
                )
            self.assertEqual(summary, {"status": ""})
            self.assertEqual(state["state"]["status"], "completed")
            with patch.object(
                run_step,
                "build_final_completion_summary",
                return_value={"status": "completed_with_limits"},
            ):
                run_step.persist_completed_step(state, "step6", "/tmp/report", {})
            self.assertEqual(state["state"]["status"], "completed_with_limits")
        finally:
            for manager in reversed(common_patches):
                manager.stop()

        updates = []
        interaction = {"status": "awaiting_user", "title": "Need input"}
        with patch.object(run_step, "previous_step_output", return_value={}), patch.object(
            run_step,
            "apply_interaction_protocol_enhancements",
            return_value=interaction,
        ), patch.object(
            run_step,
            "update_main_state_state",
            side_effect=lambda *_args, **kwargs: updates.append(kwargs),
        ), patch.object(run_step, "save_main_state"), patch.object(
            run_step, "save_interaction_file"
        ), patch.object(run_step, "write_resume_snapshot"):
            run_step.persist_interaction_required_error(
                {"state": {}, "step2": {"input": {"current": 1}}},
                "step2",
                "/tmp/report",
                interaction,
            )
        self.assertEqual(updates[-1]["blocking_reason"], "Need input")

        updates.clear()
        with patch.object(
            run_step,
            "update_main_state_state",
            side_effect=lambda *_args, **kwargs: updates.append(kwargs),
        ), patch.object(run_step, "save_main_state"), patch.object(
            run_step, "clear_interaction_file"
        ), patch.object(run_step, "write_resume_snapshot"):
            run_step.persist_step_error(
                {"state": {"completed_step": "step1"}},
                "step2",
                "/tmp/report",
                RuntimeError("failure"),
            )
            run_step.persist_step_error(
                {"state": {}},
                "step2",
                "/tmp/report",
                run_step.StepError("failure", reason_codes=["CODE"]),
            )
        self.assertEqual(updates[0]["completed_step"], "step1")
        self.assertEqual(updates[0]["blocking_reason_codes"], [])
        self.assertEqual(updates[1]["blocking_reason_codes"], ["CODE"])

        reset_inputs = []
        with patch.object(
            run_step,
            "reset_step_state_for_restart",
            side_effect=lambda *_args, **kwargs: reset_inputs.append(
                kwargs["preserve_current_input"]
            ),
        ), patch.object(run_step, "update_main_state_state"), patch.object(
            run_step, "save_main_state"
        ), patch.object(run_step, "clear_interaction_file"), patch.object(
            run_step, "write_resume_snapshot"
        ):
            run_step.persist_user_interrupt(
                {"step2": {"input": None}}, "step2", "/tmp/report"
            )
            run_step.persist_user_interrupt(
                {"step2": {"input": {"keep": 1}}}, "step2", "/tmp/report"
            )
        self.assertEqual(reset_inputs, [{}, {"keep": 1}])

        response_state = {"state": {}}
        run_step.record_last_user_response(response_state, None, "continue", None)
        self.assertEqual(response_state["state"]["last_user_response"]["step_id"], "")
        run_step.record_last_user_response(
            response_state,
            {"step_id": "step2"},
            "continue",
            {"__intent_patch": {"x": 1}, "__clear_fields": ["field"]},
        )
        stored = response_state["state"]["last_user_response"]
        self.assertEqual(stored["payload"]["intent_patch"], {"x": 1})
        self.assertEqual(stored["payload"]["clear"], ["field"])

        auto_args = SimpleNamespace(step="auto")
        with patch.object(
            run_step, "detect_integrity_repair_step", return_value="step2"
        ):
            self.assertEqual(
                run_step.prepare_main_state_for_step_execution(
                    auto_args, {}, "step2", "/tmp/report"
                ),
                "step2",
            )
        reset_inputs.clear()
        explicit_args = SimpleNamespace(step="step2")
        with patch.object(
            run_step, "should_reset_for_explicit_step_run", return_value=True
        ), patch.object(
            run_step,
            "reset_step_state_for_restart",
            side_effect=lambda *_args, **kwargs: reset_inputs.append(
                kwargs["preserve_current_input"]
            ),
        ), patch.object(run_step, "save_main_state"):
            self.assertEqual(
                run_step.prepare_main_state_for_step_execution(
                    explicit_args, {"step2": None}, "step2", "/tmp/report"
                ),
                "step2",
            )
        self.assertEqual(reset_inputs, [{}])

        self.assertFalse(
            run_step.should_auto_continue_success_review(
                "step2",
                {"options": None},
                {"step2": {"auto_continue_on_success": True}},
            )
        )

    def test_windows_compat_checkpoint_and_atomic_write_matrix(self):
        directory_mode = stat.S_IFDIR | 0o700
        observed = SimpleNamespace(st_mode=directory_mode, st_file_attributes=0)

        class NonCallableJunction:
            is_junction = None

        with patch.object(run_step.os, "lstat", return_value=observed), patch.object(
            run_step.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400, create=True
        ):
            self.assertIs(
                run_step._windows_cleanup_directory_stat(NonCallableJunction()),
                observed,
            )

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report"
            report.mkdir()
            for kind in ("file", "directory", "symlink"):
                target = report / "target"
                if kind == "file":
                    target.write_text("x", encoding="utf-8")
                elif kind == "directory":
                    target.mkdir()
                    (target / "value").write_text("x", encoding="utf-8")
                else:
                    source = report / "source"
                    source.write_text("x", encoding="utf-8")
                    try:
                        target.symlink_to(source)
                    except (OSError, NotImplementedError):
                        source.unlink()
                        continue
                with self.subTest(kind=kind):
                    self.assertTrue(
                        run_step._remove_step_output_windows_compat(
                            report, Path("target")
                        )
                    )
                    self.assertFalse(target.exists())
                source = report / "source"
                if source.exists():
                    source.unlink()
            if hasattr(os, "mkfifo"):
                fifo = report / "target"
                os.mkfifo(fifo)
                with self.assertRaisesRegex(OSError, "not a regular file"):
                    run_step._remove_step_output_windows_compat(
                        report, Path("target")
                    )
                fifo.unlink()

            windows_output = report / "windows.json"
            os_proxy = _AttributeProxy(run_step.os, name="nt")
            with patch.object(run_step, "Path", PosixPath), patch.object(
                run_step, "os", os_proxy
            ):
                run_step.write_json(windows_output, {"value": 1})
            self.assertEqual(json.loads(windows_output.read_text()), {"value": 1})

            posix_output = report / "posix.json"
            open_directory = Mock(side_effect=OSError("unsupported"))
            os_proxy = _AttributeProxy(run_step.os, open=open_directory)
            with patch.object(run_step, "os", os_proxy):
                run_step.write_json(posix_output, {"value": 2})
            self.assertEqual(json.loads(posix_output.read_text()), {"value": 2})

        checkpoint = PosixPath("/tmp/report") / run_step.BINARY_OUTPUT_RELATIVE_PATH / "binary_observability" / "validation_checkpoint.json"
        windows_os = _AttributeProxy(run_step.os, name="nt")
        with patch.object(run_step, "Path", PosixPath), patch.object(
            run_step, "os", windows_os
        ), patch.object(
            run_step, "_secure_step_output_cleanup_supported", return_value=False
        ), patch.object(
            run_step, "_step4_validation_checkpoint_path", return_value=checkpoint
        ), patch.object(
            run_step, "_read_private_step4_checkpoint", return_value=b"{}"
        ) as private_read:
            self.assertEqual(
                run_step._read_step4_validation_checkpoint("/tmp/report"), {}
            )
        private_read.assert_called_once_with(checkpoint)

        with patch.object(
            run_step, "_secure_step_output_cleanup_supported", return_value=True
        ), patch.object(
            run_step,
            "_read_step4_checkpoint_with_directory_descriptors",
            return_value=None,
        ):
            self.assertIsNone(
                run_step._read_step4_validation_checkpoint(
                    "/tmp/report", missing_ok=True
                )
            )
            with self.assertRaisesRegex(run_step.StepError, "不存在"):
                run_step._read_step4_validation_checkpoint(
                    "/tmp/report", missing_ok=False
                )

        with self.assertRaisesRegex(run_step.StepError, "fixed report location"):
            run_step._delete_step4_validation_checkpoint_durable(
                "/tmp/not-a-checkpoint.json"
            )
        with patch.object(run_step, "Path", PosixPath), patch.object(
            run_step, "os", windows_os
        ), patch.object(
            run_step, "_secure_step_output_cleanup_supported", return_value=False
        ), patch.object(
            run_step, "_remove_step_output_windows_compat", return_value=True
        ) as remove_windows:
            run_step._delete_step4_validation_checkpoint_durable(checkpoint)
        remove_windows.assert_called_once()

        with patch.object(
            run_step, "_secure_step_output_cleanup_supported", return_value=True
        ), patch.object(
            run_step,
            "_remove_step_output_with_directory_descriptors",
            return_value=False,
        ), self.assertRaisesRegex(run_step.StepError, "无法持久删除"):
            run_step._delete_step4_validation_checkpoint_durable(checkpoint)

    def test_worktree_recovery_activation_and_failure_record_matrix(self):
        args = SimpleNamespace(
            application_source="",
            dependency_source_dirs=None,
        )
        state = run_step.new_main_state("/tmp/report")
        state["step1"]["input"] = {"repo_path": "/repo/duplicate"}
        state["step2"]["input"] = None

        def repository_root(value):
            text = str(value)
            if "duplicate" in text or text == "/tmp/project":
                return Path("/repo/root")
            return None

        with patch.object(
            run_step, "filesystem_git_repository_root", side_effect=repository_root
        ):
            roots = run_step._startup_worktree_repository_roots(
                "/tmp/project", args, None, state
            )
        self.assertEqual(roots, [Path("/repo/root")])

        written = []
        with patch.object(
            run_step,
            "_startup_worktree_repository_roots",
            return_value=[Path("/repo/a"), Path("/repo/b")],
        ), patch.object(
            run_step,
            "recover_owned_stale_worktrees",
            side_effect=[{"removed": None}, {"removed": ["one"]}],
        ), patch.object(
            run_step,
            "write_json",
            side_effect=lambda _path, value: written.append(value),
        ):
            result = run_step.recover_worktrees_before_execution(
                "/tmp/project", "/tmp/report", args, None, state
            )
        self.assertEqual(result["removed_count"], 1)

        error = run_step.WorktreeRecoveryError("unsafe", None)
        with patch.object(
            run_step,
            "_startup_worktree_repository_roots",
            return_value=[Path("/repo/a")],
        ), patch.object(
            run_step, "recover_owned_stale_worktrees", side_effect=error
        ), patch.object(run_step, "write_json"), self.assertRaises(
            run_step.WorktreeRecoveryError
        ):
            run_step.recover_worktrees_before_execution(
                "/tmp/project", "/tmp/report", args, None, state
            )

        with patch.object(
            run_step, "_read_step4_validation_checkpoint", return_value=None
        ) as read_checkpoint:
            empty = run_step._step4_activation_binding("/tmp/report", None)
        self.assertEqual(empty["result_generation_identity"], "")
        read_checkpoint.assert_called_once()
        with patch.object(
            run_step,
            "_read_step4_validation_checkpoint",
            return_value={
                "result_generation_identity": "generation",
                "activation_identity": "activation",
            },
        ):
            from_checkpoint = run_step._step4_activation_binding(
                "/tmp/report", {"result_generation_identity": "generation"}
            )
        self.assertEqual(from_checkpoint["activation_identity"], "activation")
        with patch.object(run_step, "_read_step4_validation_checkpoint") as no_read:
            direct = run_step._step4_activation_binding(
                "/tmp/report",
                {
                    "result_generation_identity": "generation",
                    "activation_identity": "activation",
                },
            )
        no_read.assert_not_called()
        self.assertEqual(direct["activation_identity"], "activation")

        written_failures = []
        for structured in (
            {},
            {"traceback": "child trace", "failed_phase": "extract"},
        ):
            exc = run_step.StepError(
                "binary failed", diagnostic={"structured_result": structured}
            )
            with self.subTest(structured=structured), patch.object(
                run_step, "_attempt_bound_child_progress", return_value=(True, {})
            ), patch.object(
                run_step,
                "write_json",
                side_effect=lambda _path, value: written_failures.append(value),
            ):
                failure, _path = run_step._record_binary_failure(
                    "/tmp/report", "/tmp/config.json", exc
                )
            if structured:
                self.assertEqual(failure["failed_phase"], "extract")
                self.assertEqual(failure["traceback"], "child trace")
            else:
                self.assertEqual(failure["failed_phase"], "")

    def test_remaining_falsey_state_and_protocol_boundary_matrix(self):
        updates = []
        for state, interaction, expected_reason in (
            (
                {"state": {"completed_step": "step1"}},
                {"status": "awaiting_user", "title": "Confirm"},
                "Confirm",
            ),
            (
                {},
                {"status": "awaiting_user"},
                "step0",
            ),
        ):
            with self.subTest(interaction=interaction), patch.object(
                run_step,
                "apply_interaction_protocol_enhancements",
                return_value=interaction,
            ), patch.object(
                run_step,
                "update_main_state_state",
                side_effect=lambda *_args, **kwargs: updates.append(kwargs),
            ), patch.object(run_step, "save_main_state"), patch.object(
                run_step, "save_interaction_file"
            ), patch.object(run_step, "write_resume_snapshot"), patch.object(
                run_step, "print_interaction_to_streams"
            ), patch("sys.stderr", io.StringIO()):
                self.assertEqual(
                    run_step.persist_step0_confirmation_interaction(
                        state, "/tmp/report", interaction
                    ),
                    run_step.EXIT_AWAITING_USER,
                )
            self.assertEqual(updates[-1]["blocking_reason"], expected_reason)
        self.assertIsNone(
            run_step.persist_step0_confirmation_interaction(
                {"state": {}}, "/tmp/report", None
            )
        )

        interaction_updates = []
        interaction = {"status": "awaiting_user", "question": "Question"}
        with patch.object(
            run_step, "previous_step_output", return_value={"previous": 1}
        ), patch.object(
            run_step,
            "apply_interaction_protocol_enhancements",
            return_value=interaction,
        ), patch.object(
            run_step,
            "update_main_state_state",
            side_effect=lambda *_args, **kwargs: interaction_updates.append(kwargs),
        ), patch.object(run_step, "save_main_state"), patch.object(
            run_step, "save_interaction_file"
        ), patch.object(run_step, "write_resume_snapshot"):
            run_step.persist_interaction_required_error(
                {"state": {}, "step2": {"input": None}},
                "step2",
                "/tmp/report",
                interaction,
            )
        self.assertEqual(interaction_updates[0]["blocking_reason"], "Question")

        with patch.object(
            run_step, "build_final_completion_summary", return_value=None
        ), patch.object(run_step, "store_step_output"), patch.object(
            run_step, "seed_next_step_input"
        ), patch.object(run_step, "save_main_state"), patch.object(
            run_step, "clear_interaction_file"
        ), patch.object(run_step, "write_resume_snapshot"):
            state = run_step.new_main_state("/tmp/report")
            self.assertIsNone(
                run_step.persist_completed_step(
                    state, "step6", "/tmp/report", {}
                )
            )
        self.assertEqual(state["state"]["status"], "completed")

        preserved = []
        with patch.object(
            run_step,
            "reset_step_state_for_restart",
            side_effect=lambda *_args, **kwargs: preserved.append(
                kwargs["preserve_current_input"]
            ),
        ), patch.object(run_step, "update_main_state_state"), patch.object(
            run_step, "save_main_state"
        ), patch.object(run_step, "clear_interaction_file"), patch.object(
            run_step, "write_resume_snapshot"
        ):
            run_step.persist_user_interrupt(
                {"step2": None}, "step2", "/tmp/report"
            )
        self.assertEqual(preserved, [{}])

        self.assertEqual(
            run_step.build_user_runtime_message("start", None),
            ["正在分析：当前分析"],
        )
        self.assertIn(
            "安全暂停",
            run_step._resume_event_description("step1", "paused_by_user"),
        )

        self.assertEqual(
            run_step._filter_inferred_coords_by_prefix(None, "group"), []
        )
        self.assertEqual(
            run_step._filter_inferred_coords_by_hint(
                ["g:alpha", "g:alphabet"], "x:alp", "/repo/no"
            ),
            [],
        )
        self.assertEqual(
            run_step._filter_inferred_coords_by_hint(
                ["g:only"], "x:missing", "/repo/no"
            ),
            ["g:only"],
        )
        with patch.object(
            run_step, "infer_maven_coords", return_value=["g:a", "g:b"]
        ), patch.object(
            run_step, "_filter_inferred_coords_by_hint", return_value=[]
        ), self.assertRaises(run_step.StepError):
            run_step._expand_coord_path_by_repo(
                "g:missing", "/repo", "dependency_source_dirs"
            )

        with patch.object(
            run_step, "_binary_progress_file_snapshot", return_value=({"phase": "new"}, (1, 2))
        ):
            self.assertEqual(
                run_step._legacy_progress_after_baseline("progress", None),
                {"phase": "new"},
            )

        with patch.object(
            run_step,
            "read_csv_rows",
            return_value=[
                {"coord": "g:new", "old_version": "-", "new_version": "2"}
            ],
        ):
            self.assertEqual(
                run_step._collect_relevant_dependency_coords("/tmp/report"),
                ["g:new"],
            )

        environment_lines = run_step.build_environment_block_message(
            {"checks": [{"component": None, "status": "failed"}]}
        )
        self.assertIn("运行组件", "\n".join(environment_lines))

        findings = {
            "schema": "java-upgrade-analyzer.binary-findings.v2",
            "coverage": {"overall_status": "complete"},
            "analysis_scope": {"mode": "full", "validation_status": "valid"},
            "report_population": {
                "schema": "java-upgrade-analyzer.step6-report-population.v1",
                "apis": {
                    "total_count": 0,
                    "completed_count": 0,
                    "incomplete_count": 0,
                    "population_unconfirmed": False,
                },
                "dependencies": {"total_count": "invalid"},
            },
        }
        with patch.object(
            run_step, "report_uses_release_protocol", return_value=True
        ), patch.object(
            run_step,
            "load_consistent_step6_publication",
            return_value={"findings": findings},
        ):
            summary = run_step.build_final_completion_summary("/tmp/report")
        self.assertIn("对象数量合同缺失或无效", "；".join(summary["limitations"]))

        self.assertEqual(
            run_step.build_step_input_context(
                {"step1": {"output": {"previous": 1}}}, "step2"
            ),
            {"previous": 1},
        )

        with patch.object(
            run_step, "pending_interaction_needs_git_recheck", return_value=False
        ):
            self.assertFalse(
                run_step.clear_stale_git_interaction_for_recheck(
                    None, "/tmp/report", None
                )
            )

        normalized = run_step.ensure_main_state_structure(
            {
                "schema": run_step.MAIN_STATE_SCHEMA,
                "state": {"current_step": "step1", "status": None},
            },
            "/tmp/report",
        )
        self.assertIsNone(normalized["state"]["status"])

        full_state = {
            "step4": {"input": {"step5_selected_coords": ["g:a"]}},
            "step5": {"input": {}},
        }
        with patch.object(run_step, "save_main_state"), patch.object(
            run_step, "read_csv_rows", return_value=[]
        ), patch.object(
            run_step,
            "build_step5_selection_summary",
            return_value={
                "matched_rows": None,
                "available_target_count": 0,
                "matched_row_count": 0,
            },
        ), patch("sys.stderr", io.StringIO()):
            run_step.handle_step4_resume_followups(
                full_state, "/tmp/report", "step4", "continue"
            )

        error = run_step.WorktreeRecoveryError(
            "unsafe", {"errors": ["detail"]}
        )
        with patch.object(
            run_step,
            "_startup_worktree_repository_roots",
            return_value=[Path("/repo/a")],
        ), patch.object(
            run_step, "recover_owned_stale_worktrees", side_effect=error
        ), patch.object(run_step, "write_json"), self.assertRaises(
            run_step.WorktreeRecoveryError
        ):
            run_step.recover_worktrees_before_execution(
                "/tmp/project",
                "/tmp/report",
                SimpleNamespace(),
                None,
                {},
            )

        with patch.object(
            run_step,
            "resolve_step1_ref",
            return_value={
                "status": "resolved",
                "source_status": "remote_verified",
            },
        ):
            resolved, _interaction = run_step.resolve_step1_refs_for_execution(
                {"current_branch": "main"}, "/tmp/project"
            )
        self.assertEqual(
            resolved["current_ref_source_status"], "remote_verified"
        )

        valid_sha = "a" * 64
        with patch.object(
            run_step,
            "materialize_binary_pipeline_config",
            return_value={
                "base": {
                    "artifacts": [{"path": None, "content_sha256": valid_sha}]
                },
                "current": {"artifacts": []},
            },
        ), self.assertRaisesRegex(run_step.StepError, "摘要不一致"):
            run_step.validate_step1_runtime_inputs({}, "/tmp/report")

    def test_remaining_checkpoint_symlink_and_root_race_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root_file = base / "root-file"
            root_file.write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(OSError, "report root"):
                run_step._read_step4_checkpoint_with_directory_descriptors(
                    root_file, Path("checkpoint.json")
                )

            report = base / "report"
            report.mkdir()
            real_parent = report / "real-parent"
            real_parent.mkdir()
            try:
                linked_parent = report / "linked-parent"
                linked_parent.symlink_to(real_parent, target_is_directory=True)
            except (OSError, NotImplementedError):
                linked_parent = None
            if linked_parent is not None:
                with self.assertRaisesRegex(OSError, "checkpoint parent"):
                    run_step._read_step4_checkpoint_with_directory_descriptors(
                        report, Path("linked-parent/checkpoint.json")
                    )

            tree = report / "tree"
            tree.mkdir()
            source = report / "source.txt"
            source.write_text("x", encoding="utf-8")
            try:
                (tree / "link").symlink_to(source)
            except (OSError, NotImplementedError):
                pass
            else:
                root_fd = os.open(report, os.O_RDONLY)
                expected = os.stat("tree", dir_fd=root_fd, follow_symlinks=False)
                try:
                    run_step._remove_cleanup_directory_tree_at(
                        root_fd, "tree", expected
                    )
                finally:
                    os.close(root_fd)
                self.assertFalse(tree.exists())

            race = report / "race.txt"
            race.write_text("x", encoding="utf-8")
            path_proxy = _AttributeProxy(
                run_step.os.path,
                samestat=Mock(side_effect=[True, False]),
            )
            os_proxy = _AttributeProxy(run_step.os, path=path_proxy)
            with patch.object(run_step, "os", os_proxy), self.assertRaisesRegex(
                OSError, "report root changed"
            ):
                run_step._remove_step_output_with_directory_descriptors(
                    report, Path("race.txt")
                )

        observed = SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o700,
                st_file_attributes=0,
            )
        os_proxy = _AttributeProxy(
            run_step.os, lstat=Mock(return_value=observed)
        )
        with patch.object(
            run_step.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0, create=True
        ), patch.object(run_step, "os", os_proxy):
            result = run_step._windows_cleanup_directory_stat(
                SimpleNamespace(is_junction=None)
            )
        self.assertTrue(stat.S_ISDIR(result.st_mode))

        with patch.object(
            run_step, "_secure_step_output_cleanup_supported", return_value=False
        ), self.assertRaisesRegex(
            run_step.StepError, "secure descriptor-relative"
        ):
            run_step._read_step4_validation_checkpoint("/tmp/report")

        checkpoint = (
            Path("/tmp/report")
            / run_step.BINARY_OUTPUT_RELATIVE_PATH
            / "binary_observability"
            / "validation_checkpoint.json"
        )
        with patch.object(
            run_step, "_secure_step_output_cleanup_supported", return_value=False
        ), self.assertRaisesRegex(
            run_step.StepError, "secure descriptor-relative"
        ):
            run_step._delete_step4_validation_checkpoint_durable(checkpoint)

    def test_remaining_cli_inner_error_rendering_matrix(self):
        for error, diagnostic, expected_message in (
            (run_step.StepError("specific reason"), "", "specific reason"),
            (RuntimeError("unexpected"), "", "无法写入诊断文件"),
        ):
            stderr = io.StringIO()
            with self.subTest(error=type(error).__name__), patch.object(
                run_step,
                "_background_child_lease",
                return_value=_LockManager(enter_value=None),
            ), patch.object(run_step, "main", side_effect=error), patch.object(
                run_step, "finish_background_run", return_value=True
            ), patch.object(
                run_step, "_record_unexpected_cli_error", return_value=diagnostic
            ), patch("sys.stderr", stderr):
                self.assertEqual(run_step.cli_main([]), 1)
            self.assertIn(expected_message, stderr.getvalue())

    def test_final_local_branch_alternatives_matrix(self):
        commit = "a" * 40
        snapshot = {
            "schema": run_step.PINNED_SOURCE_SNAPSHOT_SCHEMA,
            "commit": commit,
            "project_path": ".",
            "target_module": "",
            "active_maven_profiles": [],
        }
        self.assertFalse(run_step._pinned_snapshot_matches_context(snapshot, None))
        self.assertFalse(
            run_step._pinned_snapshot_matches_context(
                {**snapshot, "commit": ""},
                {"current_resolved_commit": ""},
            )
        )
        self.assertFalse(
            run_step._pinned_snapshot_matches_context(
                snapshot, {"current_resolved_commit": ""}
            )
        )

        args = SimpleNamespace(
            application_source="/repo/app",
            dependency_source_dirs=["/repo/dependency"],
        )
        state = run_step.new_main_state("/tmp/report")
        state["step3"] = None
        with patch.object(
            run_step,
            "filesystem_git_repository_root",
            side_effect=lambda value: Path(str(value)),
        ):
            roots = run_step._startup_worktree_repository_roots(
                "/tmp/project", args, {"repo_path": "/repo/seed"}, state
            )
        self.assertIn(Path("/repo/dependency"), roots)

        empty_selection = run_step.build_step5_selection_summary(None)
        self.assertEqual(empty_selection["available_targets"], [])
        selected_empty = run_step.build_step5_selection_summary(
            None, selected_names=["a"]
        )
        self.assertEqual(selected_empty["unmatched_names"], ["a"])
        duplicate_names = run_step.build_step5_selection_summary(
            [{"coord": "g:a"}, {"coord": "h:a"}], selected_names=["a"]
        )
        self.assertEqual(duplicate_names["matched_names"], ["a"])
        self.assertEqual(duplicate_names["matched_row_count"], 2)

        all_counts = {
            "status": "completed_with_limits",
            "scope_mode": "partial",
            "included_dependency_count": 1,
            "available_dependency_count": 2,
            "dependency_total_count": 3,
            "dependency_completed_count": 2,
            "dependency_incomplete_count": 1,
            "dependency_probable_count": 1,
            "api_total_count": 4,
            "api_completed_count": 3,
            "api_incomplete_count": 1,
            "api_probable_count": 2,
        }
        rendered = "\n".join(
            run_step.build_user_runtime_message(
                "done", "step6", completion_summary=all_counts
            )
        )
        for value in ("1/2", "变化 3", "已完成分析 2", "可能影响 2"):
            self.assertIn(value, rendered)
        self.assertIn(
            "部分依赖（0/0）",
            "\n".join(
                run_step._landing_status_lines(
                    {
                        "state": {
                            "current_step": "done",
                            "status": "completed_with_limits",
                            "completion_summary": {
                                "scope_mode": "partial",
                                "included_dependency_count": None,
                                "available_dependency_count": None,
                            },
                        }
                    }
                )
            ),
        )

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            dep_dir = (
                run_step.step4_api_changes_dir(report)
                / run_step.PER_DEPENDENCY_DIRNAME
                / "g-a"
            )
            dep_dir.mkdir(parents=True)
            summary_path = dep_dir / run_step.PER_DEPENDENCY_SUMMARY_FILE
            summary_path.write_text(
                json.dumps({"step3": {"count": 1}, "artifacts": None}),
                encoding="utf-8",
            )
            run_step.cleanup_step3_candidate_outputs(report)
            self.assertFalse(summary_path.exists())

            if hasattr(os, "mkfifo"):
                tree = report / "tree"
                tree.mkdir()
                os.mkfifo(tree / "special")
                root_fd = os.open(report, os.O_RDONLY)
                expected = os.stat("tree", dir_fd=root_fd, follow_symlinks=False)
                try:
                    with self.assertRaisesRegex(OSError, "non-file"):
                        run_step._remove_cleanup_directory_tree_at(
                            root_fd, "tree", expected
                        )
                finally:
                    os.close(root_fd)
                    (tree / "special").unlink()
                    tree.rmdir()

        interaction = {"status": "awaiting_user", "question": "Question"}
        updates = []
        with patch.object(run_step, "previous_step_output", return_value={}), patch.object(
            run_step,
            "apply_interaction_protocol_enhancements",
            return_value=interaction,
        ), patch.object(
            run_step,
            "update_main_state_state",
            side_effect=lambda *_args, **kwargs: updates.append(kwargs),
        ), patch.object(run_step, "save_main_state"), patch.object(
            run_step, "save_interaction_file"
        ), patch.object(run_step, "write_resume_snapshot"):
            run_step.persist_interaction_required_error(
                {
                    "state": {"completed_step": "step1"},
                    "step2": {"input": {}},
                },
                "step2",
                "/tmp/report",
                interaction,
            )
        self.assertEqual(updates[0]["completed_step"], "step1")

        with patch.object(
            run_step,
            "resolve_step1_ref",
            return_value={
                "status": "",
                "source_status": "",
                "expected_commit": commit,
                "remote": "origin",
                "remote_ref": "refs/heads/main",
            },
        ):
            resolved, _ = run_step.resolve_step1_refs_for_execution(
                {"current_branch": "main"}, "/tmp/project"
            )
        self.assertEqual(
            resolved["current_ref_source_status"],
            "remote_expected_commit_unmaterializable",
        )

        self.assertFalse(
            run_step.should_auto_continue_success_review(
                "step4",
                {"options": [{"id": "continue"}]},
                {
                    "step4": {
                        "requires_scope_confirmation": True,
                        "auto_continue_on_success": True,
                    }
                },
            )
        )
        self.assertTrue(
            run_step.should_auto_continue_success_review(
                "step2",
                {"options": [{"id": "continue"}]},
                {
                    "step2": {
                        "requires_scope_confirmation": False,
                        "auto_continue_on_success": True,
                    }
                },
            )
        )
        self.assertEqual(
            run_step._filter_inferred_coords_by_hint(
                ["g:a", "g:b"], "missinggroup", "/"
            ),
            [],
        )
        self.assertIn(
            "状态已更新",
            run_step._resume_event_description("step2", "updated"),
        )

    def test_execute_step_unlocked_complete_state_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            report = Path(directory) / "report"
            project.mkdir()
            args = SimpleNamespace(
                project_dir=str(project),
                report_dir=str(report),
                strict_risk_gate=False,
            )
            manifest = {
                step: {"gate": f"gate-{step}"}
                for step in run_step.STEP_SEQUENCE
            }

            def rebuilt(_args, existing, *_rest, **_kwargs):
                return dict(existing)

            common = (
                patch.object(run_step, "cleanup_step_outputs"),
                patch.object(run_step, "ensure_exists"),
                patch.object(run_step, "validate_run_context_for_step"),
                patch.object(run_step, "build_run_context", side_effect=rebuilt),
                patch.object(run_step, "run_gate"),
                patch.object(
                    run_step,
                    "build_interaction_payload",
                    return_value={"interaction": True},
                ),
                patch.object(run_step, "run_python"),
                patch.object(run_step, "write_csv_rows"),
            )
            for manager in common:
                manager.start()
            try:
                with self.assertRaisesRegex(run_step.StepError, "尚未收到统一确认"):
                    run_step._execute_step_unlocked(
                        "step0", args, manifest, {}, main_state={}
                    )

                preflight_cases = (
                    (
                        {
                            "sides": {
                                "base": {"jdk": {"java_major": 17}},
                                "current": {"jdk": {}},
                            }
                        },
                        {"jdk_current": 21},
                        ("17", "21"),
                    ),
                    ({"sides": {}}, {}, ("", "")),
                    ({}, {"jdk_base": "11"}, ("11", "")),
                )
                for preflight, extra, expected in preflight_cases:
                    context = {
                        "step0_confirmation_acknowledged": True,
                        **extra,
                    }
                    with self.subTest(preflight=preflight), patch.object(
                        run_step, "validate_step0_context"
                    ), patch.object(
                        run_step, "run_step0_preflight", return_value=preflight
                    ), patch.object(
                        run_step,
                        "write_step0_confirmation_record",
                        return_value={"confirmed_at": "now"},
                    ):
                        result = run_step._execute_step_unlocked(
                            "step0", args, manifest, context, main_state={}
                        )
                    self.assertEqual(result, {"interaction": True})
                    self.assertEqual(
                        (context["jdk_base"], context["jdk_current"]), expected
                    )

                with self.assertRaisesRegex(run_step.StepError, "必须先完成 Step0"):
                    run_step._execute_step_unlocked(
                        "step1", args, manifest, {}, main_state={}
                    )

                invalid_step1 = (
                    (
                        {
                            "step0_confirmed": True,
                            "base_artifact_path": "/base.jar",
                        },
                        "必须同时提供",
                    ),
                    (
                        {
                            "step0_confirmed": True,
                            "current_artifact_path": "/current.jar",
                        },
                        "必须同时提供",
                    ),
                    (
                        {"step0_confirmed": True, "base_branch": "base"},
                        "需要二选一",
                    ),
                    ({"step0_confirmed": True}, "需要二选一"),
                )
                for context, message in invalid_step1:
                    with self.subTest(context=context), self.assertRaisesRegex(
                        run_step.StepError, message
                    ):
                        run_step._execute_step_unlocked(
                            "step1", args, manifest, context, main_state={}
                        )

                valid_step1 = (
                    {
                        "step0_confirmed": True,
                        "base_artifact_path": "/base.jar",
                        "current_artifact_path": "/current.jar",
                    },
                    {
                        "step0_confirmed": True,
                        "base_branch": "base",
                        "current_branch": "current",
                    },
                )
                for index, context in enumerate(valid_step1):
                    dependency_interaction = (
                        {"dependency": True} if index == 0 else None
                    )
                    with self.subTest(context=context), patch.object(
                        run_step,
                        "validate_step1_runtime_inputs",
                        return_value={"status": "passed"},
                    ), patch.object(
                        run_step,
                        "build_step1_dependency_source_interaction",
                        return_value=dependency_interaction,
                    ):
                        result = run_step._execute_step_unlocked(
                            "step1", args, manifest, context, main_state={}
                        )
                    self.assertEqual(
                        result,
                        dependency_interaction or {"interaction": True},
                    )

                for context, message in (
                    ({"artifact_input_mode": True}, "用户提供的编译产物路径"),
                    ({}, "需要基准分支和当前分支"),
                    (
                        {"base_branch": "base", "artifact_input_mode": False},
                        "需要基准分支和当前分支",
                    ),
                ):
                    with self.subTest(step2=context), self.assertRaisesRegex(
                        run_step.StepError, message
                    ):
                        run_step._execute_step_unlocked(
                            "step2", args, manifest, context, main_state={}
                        )

                valid_base = "a" * 40
                valid_current = "b" * 40
                for context, message in (
                    (
                        {
                            "base_branch": "base",
                            "current_branch": "current",
                            "base_resolved_commit": "",
                            "current_resolved_commit": valid_current,
                        },
                        "拒绝使用可移动",
                    ),
                    (
                        {
                            "base_branch": "base",
                            "current_branch": "current",
                            "base_resolved_commit": valid_base,
                            "current_resolved_commit": "short",
                        },
                        "拒绝使用可移动",
                    ),
                    (
                        {
                            "base_branch": "base",
                            "current_branch": "current",
                            "base_resolved_commit": valid_base,
                            "current_resolved_commit": valid_base,
                        },
                        "revision 相同",
                    ),
                ):
                    with self.subTest(step2_revision=context), self.assertRaisesRegex(
                        run_step.StepError, message
                    ):
                        run_step._execute_step_unlocked(
                            "step2", args, manifest, context, main_state={}
                        )
                self.assertEqual(
                    run_step._execute_step_unlocked(
                        "step2",
                        args,
                        manifest,
                        {
                            "base_branch": "base",
                            "current_branch": "current",
                            "base_resolved_commit": valid_base,
                            "current_resolved_commit": valid_current,
                        },
                        main_state={},
                    ),
                    {"interaction": True},
                )

                dep_current = run_step.step1_current_resolved_path(report)
                dep_changes = run_step.step1_dep_changes_path(report)
                dep_current.parent.mkdir(parents=True, exist_ok=True)

                step3_cases = (
                    {
                        "name": "no_business_source",
                        "context": {"current_jdk_home": ""},
                        "pinned": False,
                        "scan_roots": [],
                        "workspace": None,
                    },
                    {
                        "name": "pinned_without_roots",
                        "context": {
                            "source_dirs": ["src"],
                            "current_jdk_home": "/jdk",
                            "pinned_source_snapshot": {"id": 1},
                        },
                        "pinned": True,
                        "scan_roots": [],
                        "workspace": {
                            "project_root": project,
                            "source_dirs": [],
                            "resource_dirs": [],
                        },
                    },
                    {
                        "name": "pinned_with_roots",
                        "context": {
                            "source_dirs": ["src"],
                            "pinned_source_snapshot": {"id": 1},
                        },
                        "pinned": True,
                        "scan_roots": ["src"],
                        "workspace": {
                            "project_root": project,
                            "source_dirs": ["src"],
                            "resource_dirs": [],
                        },
                    },
                    {
                        "name": "unpinned_with_roots",
                        "context": {"source_dirs": ["src"]},
                        "pinned": False,
                        "scan_roots": ["src"],
                        "workspace": None,
                    },
                    {
                        "name": "unpinned_without_roots",
                        "context": {"source_dirs": ["src"]},
                        "pinned": False,
                        "scan_roots": [],
                        "workspace": None,
                    },
                )
                for index, case in enumerate(step3_cases):
                    if dep_current.exists():
                        dep_current.unlink()
                    if dep_changes.exists():
                        dep_changes.unlink()
                    if index == 1:
                        dep_current.write_text("x", encoding="utf-8")
                    elif index == 2:
                        dep_changes.write_text("x", encoding="utf-8")
                    workspace_manager = _LockManager(
                        enter_value=case["workspace"]
                    )
                    with self.subTest(case=case["name"]), patch.object(
                        run_step,
                        "_pinned_snapshot_matches_context",
                        return_value=case["pinned"],
                    ), patch.object(
                        run_step,
                        "materialize_pinned_source_workspace",
                        return_value=workspace_manager,
                    ), patch.object(
                        run_step,
                        "step3_business_scan_roots",
                        return_value=case["scan_roots"],
                    ):
                        self.assertEqual(
                            run_step._execute_step_unlocked(
                                "step3",
                                args,
                                manifest,
                                dict(case["context"]),
                                main_state={},
                            ),
                            {"interaction": True},
                        )

                step4_cases = (
                    (
                        {
                            "source_dirs": [],
                            "project_root": project,
                        },
                        {"pinned_source_snapshot": {}},
                    ),
                    (
                        {
                            "source_dirs": ["src"],
                            "project_root": project,
                        },
                        {
                            "pinned_source_snapshot": {
                                "project_scope": {"source_roots": ["src"]}
                            },
                            "strict_risk_gate": True,
                        },
                    ),
                )
                for workspace, context in step4_cases:
                    with self.subTest(workspace=workspace), patch.object(
                        run_step,
                        "materialize_pinned_source_workspace",
                        return_value=_LockManager(enter_value=workspace),
                    ), patch.object(
                        run_step,
                        "_materialize_project_scope_paths",
                        return_value={},
                    ), patch.object(
                        run_step,
                        "materialize_pinned_dependency_source_workspaces",
                        return_value=_LockManager(enter_value=dict(context)),
                    ), patch.object(run_step, "_run_binary_step4"):
                        self.assertEqual(
                            run_step._execute_step_unlocked(
                                "step4",
                                args,
                                manifest,
                                context,
                                main_state={},
                            ),
                            {"interaction": True},
                        )

                invalid_step5 = (
                    ({"step5_scope_mode": "partial"}, "部分分析必须包含"),
                    (
                        {
                            "step5_scope_mode": "full",
                            "step5_selected_coords": ["g:a"],
                        },
                        "全量分析不能同时",
                    ),
                )
                for context, message in invalid_step5:
                    with self.subTest(context=context), self.assertRaisesRegex(
                        run_step.StepError, message
                    ):
                        run_step._execute_step_unlocked(
                            "step5", args, manifest, context, main_state={}
                        )

                for context in (
                    {},
                    {"step5_scope_mode": "full"},
                    {
                        "step5_scope_mode": "partial",
                        "step5_selected_names": ["artifact"],
                    },
                    {
                        "step5_scope_mode": "partial",
                        "step5_selected_coords": ["g:a"],
                    },
                ):
                    with self.subTest(context=context), patch.object(
                        run_step,
                        "_run_downstream_report_publication",
                        return_value={"elapsed_seconds": 0.1},
                    ):
                        self.assertEqual(
                            run_step._execute_step_unlocked(
                                "step5",
                                args,
                                manifest,
                                context,
                                main_state={},
                            ),
                            {"interaction": True},
                        )

                with patch.object(
                    run_step,
                    "_run_downstream_report_publication",
                    return_value={"elapsed_seconds": 0.1},
                ):
                    self.assertEqual(
                        run_step._execute_step_unlocked(
                            "step6", args, manifest, {}, main_state={}
                        ),
                        {"interaction": True},
                    )
                with self.assertRaisesRegex(run_step.StepError, "未知 step"):
                    run_step._execute_step_unlocked(
                        "unknown", args, manifest, {}, main_state={}
                    )
            finally:
                for manager in reversed(common):
                    manager.stop()

    def test_main_startup_preflight_and_recovery_exception_matrix(self):
        with patch.object(
            run_step, "build_step0_static_contract", return_value={"schema": "test"}
        ), patch("sys.stdout", io.StringIO()) as stdout:
            self.assertEqual(
                run_step._main_with_workflow_lock_held(
                    ["--describe-step0-contract"]
                ),
                0,
            )
            self.assertEqual(
                run_step._main_with_workflow_lock_held(
                    [
                        "--describe-step0-contract",
                        "--active-maven-profile",
                        "prod",
                        "--active-maven-profile",
                        "prod",
                    ]
                ),
                0,
            )
        self.assertEqual(stdout.getvalue().count('"schema": "test"'), 2)

        with patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            run_step._main_with_workflow_lock_held([])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            report = root / "report"
            project.mkdir()

            warning_environment = {
                "status": "passed",
                "checks": [],
                "warnings": [
                    {
                        "reason": "python_version_not_ci_verified",
                        "observed": "Python test",
                    }
                ],
            }
            result, _mocks, _stdout, stderr, _state = self._invoke_main_case(
                project,
                report,
                skip_environment=False,
                overrides={
                    "contract_payload": {"return_value": warning_environment},
                },
            )
            self.assertEqual(result, 0)
            self.assertIn("Python test", stderr)

            missing_project = root / "missing"
            result, _mocks, _stdout, stderr, _state = self._invoke_main_case(
                missing_project, report
            )
            self.assertEqual(result, 1)
            self.assertIn("项目目录不存在", stderr)

            result, _mocks, _stdout, stderr, _state = self._invoke_main_case(
                project,
                report,
                overrides={
                    "recover_worktrees_before_execution": {
                        "return_value": {"removed_count": 2}
                    }
                },
            )
            self.assertEqual(result, 0)
            self.assertIn("已清理 2 个", stderr)

            class ReasonedFailure(RuntimeError):
                reason_code = "RECOVERY_REASON"

            for error in (
                run_step.StepError("downstream step error"),
                RuntimeError("downstream runtime error"),
                ReasonedFailure("downstream reasoned error"),
            ):
                with self.subTest(downstream_error=type(error).__name__):
                    result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                        project,
                        report,
                        overrides={
                            "recover_downstream_report_publications": {
                                "side_effect": error
                            }
                        },
                    )
                self.assertEqual(result, 1)
                mocks["persist_step_error"].assert_called_once()

            for error in (
                run_step.StepError("step4 recovery error"),
                RuntimeError("step4 runtime error"),
                ReasonedFailure("step4 reasoned error"),
            ):
                with self.subTest(step4_error=type(error).__name__):
                    result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                        project,
                        report,
                        overrides={
                            "_recover_and_apply_step4_startup_state": {
                                "side_effect": error
                            }
                        },
                    )
                self.assertEqual(result, 1)
                mocks["persist_step_error"].assert_called_once()

            for error in (
                run_step.StepError("release step error"),
                RuntimeError("release runtime error"),
                ReasonedFailure("release reasoned error"),
            ):
                with self.subTest(release_error=type(error).__name__):
                    result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                        project,
                        report,
                        overrides={
                            "_apply_downstream_release_startup_state": {
                                "side_effect": error
                            }
                        },
                    )
                self.assertEqual(result, 1)
                mocks["persist_step_error"].assert_called_once()

            recovery_argv = [
                "--step",
                "step1",
                "--project-dir",
                str(project),
                "--report-dir",
                str(report),
                "--response-json",
                '{"action":"continue"}',
            ]
            result, _mocks, _stdout, stderr, _state = self._invoke_main_case(
                project,
                report,
                argv=recovery_argv,
                overrides={
                    "recover_downstream_report_publications": {
                        "return_value": {
                            "actions": [
                                {"stage": "step5", "disposition": "rolled_back"}
                            ]
                        }
                    },
                    "_recover_and_apply_step4_startup_state": {
                        "return_value": {
                            "discard_structured_response": True,
                            "applied": True,
                            "action": run_step._STEP4_RELEASE_REPUBLISH,
                            "forced_step_id": "step4",
                        }
                    },
                    "_apply_downstream_release_startup_state": {
                        "return_value": {
                            "discard_structured_response": True,
                            "forced_step_id": "step5",
                        }
                    },
                },
            )
            self.assertEqual(result, 0)
            self.assertIn("重新生成并门禁当前报告", stderr)
            self.assertIn("step5:rolled_back", stderr)
            self.assertIn("将从 step5 重建", stderr)

            result, _mocks, _stdout, stderr, _state = self._invoke_main_case(
                project,
                report,
                overrides={
                    "_recover_and_apply_step4_startup_state": {
                        "return_value": {
                            "applied": True,
                            "action": "reset",
                        }
                    }
                },
            )
            self.assertEqual(result, 0)
            self.assertIn("未提交状态已收敛", stderr)

    def test_main_pending_response_done_and_forced_recovery_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            report = root / "report"
            project.mkdir()

            for pending, enhanced in (
                (
                    {"step_id": "", "title": "Pending"},
                    {"step_id": "", "title": "Pending"},
                ),
                (
                    {"step_id": "step2", "title": "Pending"},
                    {
                        "step_id": "step2",
                        "title": "Pending",
                        "schema": "enhanced",
                    },
                ),
            ):
                state = run_step.new_main_state(report)
                state["state"]["pending_interaction"] = pending
                result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                    project,
                    report,
                    state=state,
                    overrides={
                        "apply_interaction_protocol_enhancements": {
                            "return_value": enhanced
                        }
                    },
                )
                self.assertEqual(result, 0)
                self.assertTrue(
                    mocks["apply_interaction_protocol_enhancements"].called
                )

            auto_response_argv = [
                "--step",
                "auto",
                "--project-dir",
                str(project),
                "--report-dir",
                str(report),
                "--response-json",
                '{"action":"continue"}',
            ]

            def apply_auto_response(
                _args,
                _project,
                _report,
                current_state,
                _current_step,
                user_response=None,
            ):
                return {
                    "main_state": current_state,
                    "step_id": "step1",
                    "pending_interaction": None,
                    "resumed_interaction_step_id": "",
                    "response_action": "continue",
                    "user_response": dict(user_response or {}),
                    "early_exit_code": None,
                }

            result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                project,
                report,
                argv=auto_response_argv,
                overrides={
                    "apply_structured_user_response_if_present": {
                        "side_effect": apply_auto_response
                    },
                    "next_step_id_for": {"return_value": None},
                },
            )
            self.assertEqual(result, 0)
            mocks["clear_stale_git_interaction_for_recheck"].assert_not_called()

            auto_done_argv = [
                "--step",
                "auto",
                "--project-dir",
                str(project),
                "--report-dir",
                str(report),
            ]

            class ReasonedFailure(RuntimeError):
                reason_code = "FINAL_REASON"

            for error in (
                RuntimeError("final release invalid"),
                ReasonedFailure("final release reasoned"),
            ):
                state = run_step.new_main_state(report)
                state["state"]["current_step"] = "done"
                with self.subTest(final_error=type(error).__name__):
                    result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                        project,
                        report,
                        argv=auto_done_argv,
                        state=state,
                        overrides={
                            "require_current_release_stage": {
                                "side_effect": error
                            }
                        },
                    )
                self.assertEqual(result, 1)
                mocks["persist_step_error"].assert_called_once()

            state = run_step.new_main_state(report)
            state["state"]["current_step"] = "done"
            result, mocks, _stdout, stderr, _state = self._invoke_main_case(
                project,
                report,
                argv=auto_done_argv,
                state=state,
            )
            self.assertEqual(result, 0)
            self.assertIn("runtime-message", stderr)
            mocks["build_final_completion_summary"].assert_called_once()

            state = run_step.new_main_state(report)
            state["state"]["current_step"] = "done"
            result, mocks, _stdout, stderr, _state = self._invoke_main_case(
                project,
                report,
                argv=auto_done_argv,
                state=state,
                overrides={
                    "detect_integrity_repair_step": {"return_value": "step3"}
                },
            )
            self.assertEqual(result, 0)
            self.assertIn("自动重建", stderr)
            mocks["reset_step_state_for_restart"].assert_called_once()

            def early_response(
                _args,
                _project,
                _report,
                current_state,
                current_step,
                user_response=None,
            ):
                return {
                    "main_state": current_state,
                    "step_id": current_step,
                    "pending_interaction": None,
                    "resumed_interaction_step_id": "",
                    "response_action": "cancel",
                    "user_response": dict(user_response or {}),
                    "early_exit_code": 9,
                }

            result, _mocks, _stdout, _stderr, _state = self._invoke_main_case(
                project,
                report,
                overrides={
                    "apply_structured_user_response_if_present": {
                        "side_effect": early_response
                    }
                },
            )
            self.assertEqual(result, 9)

            def response_at(step_value):
                def apply(
                    _args,
                    _project,
                    _report,
                    current_state,
                    _current_step,
                    user_response=None,
                ):
                    return {
                        "main_state": current_state,
                        "step_id": step_value,
                        "pending_interaction": {"step_id": step_value},
                        "resumed_interaction_step_id": "",
                        "response_action": "",
                        "user_response": dict(user_response or {}),
                        "early_exit_code": None,
                    }

                return apply

            for response_step, expected_step in (
                ("step6", "step4"),
                ("step3", "step3"),
            ):
                with self.subTest(response_step=response_step):
                    result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                        project,
                        report,
                        overrides={
                            "_recover_and_apply_step4_startup_state": {
                                "return_value": {
                                    "forced_step_id": "step4",
                                }
                            },
                            "_apply_downstream_release_startup_state": {
                                "return_value": {
                                    "forced_step_id": "invalid",
                                }
                            },
                            "apply_structured_user_response_if_present": {
                                "side_effect": response_at(response_step)
                            },
                        },
                    )
                self.assertEqual(result, 0)
                self.assertEqual(
                    mocks["execute_step"].call_args.args[0], expected_step
                )

            result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                project,
                report,
                overrides={
                    "clear_stale_git_interaction_for_recheck": {
                        "return_value": True
                    }
                },
            )
            self.assertEqual(result, 0)
            mocks["clear_stale_git_interaction_for_recheck"].assert_called_once()

    def test_main_step0_step2_and_success_outcome_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            report = root / "report"
            project.mkdir()

            def argv_for(step):
                return [
                    "--step",
                    step,
                    "--project-dir",
                    str(project),
                    "--report-dir",
                    str(report),
                ]

            result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                project,
                report,
                argv=argv_for("step0"),
                overrides={
                    "prepare_step0_context": {
                        "side_effect": run_step.StepError("step0 preparation failed")
                    }
                },
            )
            self.assertEqual(result, 1)
            mocks["persist_step_error"].assert_called_once()

            step0_cases = (
                {
                    "name": "acknowledgement_required",
                    "context": {"step0_confirmation_acknowledged": False},
                    "confirmation": {
                        "required_fields": [],
                        "ref_resolution_requests": [],
                    },
                    "preflight_exit": run_step.EXIT_AWAITING_USER,
                    "expected": run_step.EXIT_AWAITING_USER,
                },
                {
                    "name": "required_fields_recovered_without_exit",
                    "context": {"step0_confirmation_acknowledged": True},
                    "confirmation": {
                        "required_fields": ["application_source"],
                        "ref_resolution_requests": [],
                    },
                    "preflight_exit": None,
                    "expected": 0,
                },
                {
                    "name": "ref_resolution_recovery",
                    "context": {"step0_confirmation_acknowledged": True},
                    "confirmation": {
                        "required_fields": [],
                        "ref_resolution_requests": [{"side": "base"}],
                    },
                    "preflight_exit": run_step.EXIT_AWAITING_USER,
                    "expected": run_step.EXIT_AWAITING_USER,
                },
                {
                    "name": "already_confirmed",
                    "context": {"step0_confirmation_acknowledged": True},
                    "confirmation": {
                        "required_fields": [],
                        "ref_resolution_requests": [],
                    },
                    "preflight_exit": None,
                    "expected": 0,
                },
            )
            for case in step0_cases:
                with self.subTest(case=case["name"]):
                    context = dict(case["context"])
                    result, _mocks, _stdout, _stderr, _state = self._invoke_main_case(
                        project,
                        report,
                        argv=argv_for("step0"),
                        overrides={
                            "build_run_context": {"return_value": context},
                            "prepare_step0_context": {
                                "return_value": (context, None)
                            },
                            "build_step0_confirmation_interaction": {
                                "return_value": case["confirmation"]
                            },
                            "persist_step0_confirmation_interaction": {
                                "return_value": case["preflight_exit"]
                            },
                        },
                    )
                self.assertEqual(result, case["expected"])

            commit = "a" * 40
            step2_context = {
                "current_resolved_commit": commit,
                "pinned_source_snapshot": {},
            }
            result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                project,
                report,
                argv=argv_for("step2"),
                overrides={
                    "build_run_context": {"return_value": step2_context},
                    "_pinned_snapshot_matches_context": {"return_value": False},
                    "rebuild_current_pinned_source_context": {
                        "return_value": {**step2_context, "rebuilt": True}
                    },
                },
            )
            self.assertEqual(result, 0)
            mocks["rebuild_current_pinned_source_context"].assert_called_once()

            result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                project,
                report,
                argv=argv_for("step2"),
                overrides={
                    "build_run_context": {"return_value": step2_context},
                    "_pinned_snapshot_matches_context": {"return_value": False},
                    "rebuild_current_pinned_source_context": {
                        "side_effect": run_step.StepError("rebuild failed")
                    },
                },
            )
            self.assertEqual(result, 1)
            mocks["persist_step_error"].assert_called_once()

            interaction = {"question": "Review", "options": []}
            result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                project,
                report,
                overrides={"execute_step": {"return_value": interaction}},
            )
            self.assertEqual(result, run_step.EXIT_AWAITING_USER)
            mocks["persist_step_interaction"].assert_called_once()

            step5_manifest = {
                step: {
                    "gate": f"gate-{step}",
                    "auto_continue_on_success": step == "step5",
                    "requires_scope_confirmation": False,
                }
                for step in run_step.STEP_SEQUENCE
            }
            result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                project,
                report,
                argv=argv_for("step5"),
                manifest_steps=step5_manifest,
                overrides={
                    "execute_step": {"return_value": interaction},
                    "should_auto_continue_success_review": {"return_value": True},
                    "build_informational_success_interaction": {
                        "return_value": {"informational": True}
                    },
                },
            )
            self.assertEqual(result, 0)
            mocks["build_informational_success_interaction"].assert_called_once()
            mocks["save_interaction_file"].assert_called_once()

            for scope_confirmation, expected_auto in ((False, True), (True, False)):
                manifest = {
                    step: {
                        "gate": f"gate-{step}",
                        "auto_continue_on_success": step == "step1",
                        "requires_scope_confirmation": (
                            scope_confirmation if step == "step1" else False
                        ),
                    }
                    for step in run_step.STEP_SEQUENCE
                }
                with self.subTest(scope_confirmation=scope_confirmation):
                    result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                        project,
                        report,
                        manifest_steps=manifest,
                    )
                self.assertEqual(result, 0)
                self.assertEqual(
                    mocks["print_auto_continue_success_review"].called,
                    expected_auto,
                )

            auto_state = run_step.new_main_state(report)
            auto_state["state"]["current_step"] = "step1"
            auto_manifest = {"auto_run_until_checkpoint": True}
            result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                project,
                report,
                argv=argv_for("auto"),
                state=auto_state,
                manifest_data=auto_manifest,
                overrides={
                    "next_step_id_for": {"return_value": "step2"},
                    "main": {"return_value": 7},
                },
            )
            self.assertEqual(result, 7)
            mocks["main"].assert_called_once()

            old_attempts = set(run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS)
            try:
                report_key = str(report.resolve())
                run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS.clear()
                run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS.update(
                    {
                        (report_key, "step4"),
                        (str((root / "other").resolve()), "step5"),
                    }
                )
                result, _mocks, _stdout, _stderr, _state = self._invoke_main_case(
                    project,
                    report,
                    argv=argv_for("step6"),
                )
                self.assertEqual(result, 0)
                self.assertEqual(
                    run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS,
                    {(str((root / "other").resolve()), "step5")},
                )
            finally:
                run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS.clear()
                run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS.update(
                    old_attempts
                )

    def test_main_execution_exception_and_internal_recovery_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            report = root / "report"
            project.mkdir()

            def argv_for(step):
                return [
                    "--step",
                    step,
                    "--project-dir",
                    str(project),
                    "--report-dir",
                    str(report),
                ]

            for interaction in (None, {"question": "Need input"}):
                error = run_step.StepInteractionRequired(interaction)
                with self.subTest(interaction=interaction):
                    result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                        project,
                        report,
                        overrides={"execute_step": {"side_effect": error}},
                    )
                self.assertEqual(result, run_step.EXIT_AWAITING_USER)
                mocks["persist_interaction_required_error"].assert_called_once()

            result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                project,
                report,
                overrides={
                    "execute_step": {
                        "side_effect": run_step.StepError("ordinary failure")
                    }
                },
            )
            self.assertEqual(result, 1)
            mocks["persist_step_error"].assert_called_once()

            old_attempts = set(run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS)
            try:
                run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS.clear()
                internal_error = run_step.StepError("internal input invalid")
                result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                    project,
                    report,
                    argv=argv_for("step6"),
                    overrides={
                        "execute_step": {"side_effect": internal_error},
                        "step6_internal_input_failure_owner_from_step_error": {
                            "return_value": "step5"
                        },
                        "main": {"return_value": 8},
                    },
                )
                self.assertEqual(result, 8)
                mocks["reset_step_state_for_restart"].assert_called_once()
                mocks["main"].assert_called_once()

                run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS.add(
                    (str(report.resolve()), "step5")
                )
                result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                    project,
                    report,
                    argv=argv_for("step6"),
                    overrides={
                        "execute_step": {"side_effect": internal_error},
                        "step6_internal_input_failure_owner_from_step_error": {
                            "return_value": "step5"
                        },
                    },
                )
                self.assertEqual(result, 1)
                mocks["persist_step_error"].assert_called_once()
            finally:
                run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS.clear()
                run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS.update(
                    old_attempts
                )

            result, mocks, _stdout, stderr, _state = self._invoke_main_case(
                project,
                report,
                overrides={"execute_step": {"side_effect": KeyboardInterrupt()}},
            )
            self.assertEqual(result, run_step.EXIT_INTERRUPTED)
            mocks["persist_user_interrupt"].assert_called_once()
            self.assertIn("已安全停止", stderr)

    def test_main_current_source_residual_condition_matrix(self):
        with patch.object(
            run_step, "build_step0_static_contract", return_value={"schema": "test"}
        ), patch.object(
            sys, "argv", ["run_step.py", "--describe-step0-contract"]
        ), patch("sys.stdout", io.StringIO()):
            self.assertEqual(run_step._main_with_workflow_lock_held(None), 0)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            report = root / "report"
            project.mkdir()

            failed_environment = {
                "status": "failed",
                "checks": [
                    {
                        "component": "tool:git",
                        "status": "failed",
                        "observed": "missing",
                        "expected": "available",
                    }
                ],
            }
            for empty_message in (False, True):
                overrides = {
                    "contract_payload": {"return_value": failed_environment}
                }
                if empty_message:
                    overrides["build_environment_block_message"] = {
                        "return_value": []
                    }
                with self.subTest(empty_message=empty_message):
                    result, _mocks, _stdout, stderr, _state = self._invoke_main_case(
                        project,
                        report,
                        skip_environment=False,
                        overrides=overrides,
                    )
                self.assertEqual(result, 1)
                if not empty_message:
                    self.assertIn("git", stderr)

            manifest_steps = {
                step: {
                    "gate": "" if step == "step4" else f"gate-{step}",
                    "auto_continue_on_success": False,
                    "requires_scope_confirmation": False,
                }
                for step in run_step.STEP_SEQUENCE
            }
            result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                project,
                report,
                manifest_steps=manifest_steps,
                overrides={
                    "build_restore_context": {
                        "return_value": {"strict_risk_gate": "true"}
                    }
                },
            )
            self.assertEqual(result, 0)
            recovery_call = mocks[
                "_recover_and_apply_step4_startup_state"
            ].call_args.kwargs
            self.assertTrue(recovery_call["strict_risk_gate"])
            self.assertEqual(recovery_call["gate_name"], "")

            def auto_argv(*, response=False):
                values = [
                    "--step",
                    "auto",
                    "--project-dir",
                    str(project),
                    "--report-dir",
                    str(report),
                ]
                if response:
                    values.extend(
                        ["--response-json", '{"action":"continue"}']
                    )
                return values

            for has_response in (False, True):
                state = run_step.new_main_state(report)
                state["state"]["current_step"] = "step1"
                state["state"]["pending_interaction"] = {
                    "step_id": "step1",
                    "title": "Pending",
                }
                with self.subTest(has_response=has_response):
                    result, _mocks, _stdout, _stderr, _state = self._invoke_main_case(
                        project,
                        report,
                        argv=auto_argv(response=has_response),
                        state=state,
                    )
                self.assertEqual(result, 0)

            state = run_step.new_main_state(report)
            state["state"]["current_step"] = ""
            result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                project,
                report,
                argv=auto_argv(),
                state=state,
                overrides={
                    "resolve_requested_step": {"return_value": "step1"}
                },
            )
            self.assertEqual(result, 0)
            mocks["resolve_requested_step"].assert_called_once()

            result, _mocks, _stdout, _stderr, _state = self._invoke_main_case(
                project,
                report,
                overrides={
                    "maybe_return_pending_interaction": {"return_value": 6}
                },
            )
            self.assertEqual(result, 6)

            commit = "a" * 40
            for context, pinned in (
                ({"current_resolved_commit": ""}, False),
                (
                    {
                        "current_resolved_commit": commit,
                        "pinned_source_snapshot": {"id": 1},
                    },
                    True,
                ),
            ):
                with self.subTest(context=context, pinned=pinned):
                    result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                        project,
                        report,
                        argv=[
                            "--step",
                            "step2",
                            "--project-dir",
                            str(project),
                            "--report-dir",
                            str(report),
                        ],
                        overrides={
                            "build_run_context": {"return_value": context},
                            "_pinned_snapshot_matches_context": {
                                "return_value": pinned
                            },
                            "rebuild_current_pinned_source_context": {
                                "return_value": context
                            },
                        },
                    )
                self.assertEqual(result, 0)
                mocks[
                    "rebuild_current_pinned_source_context"
                ].assert_not_called()

            result, mocks, _stdout, _stderr, _state = self._invoke_main_case(
                project,
                report,
                overrides={
                    "execute_step": {
                        "return_value": {"question": "Review"}
                    },
                    "should_auto_continue_success_review": {
                        "return_value": True
                    },
                },
            )
            self.assertEqual(result, 0)
            self.assertFalse(
                mocks["build_informational_success_interaction"].called
                if "build_informational_success_interaction" in mocks
                else False
            )


if __name__ == "__main__":
    unittest.main()
