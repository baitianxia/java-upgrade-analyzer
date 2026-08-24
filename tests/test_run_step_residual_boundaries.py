from __future__ import annotations

import io
from contextlib import ExitStack
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import run_step


class RunStepResidualBoundaryTest(unittest.TestCase):
    def assert_step_error(self, action):
        with self.assertRaises(run_step.StepError) as captured:
            action()
        return captured.exception

    def test_intent_patch_normalization_invalid_duplicate_clear_and_restart_matrix(self):
        for value in (None, [], "patch"):
            with self.subTest(non_object=value):
                self.assert_step_error(
                    lambda value=value: run_step.normalize_intent_patch(value)
                )

        for patch_value in (
            {"set": "invalid"},
            {"clear": "invalid"},
            {"unresolved_slots": "invalid"},
            {"set": {"unsupported": True}},
            {"clear": ["unsupported"]},
            {
                "restart_step_id": "step1",
                "set": {"restart_step_id": "step2"},
            },
        ):
            with self.subTest(invalid_patch=patch_value):
                self.assert_step_error(
                    lambda patch_value=patch_value: run_step.normalize_intent_patch(
                        patch_value
                    )
                )

        normalized = run_step.normalize_intent_patch({
            "action": " continue ",
            "set": {
                "restart_step_id": " step2 ",
                "base_branch": " main ",
            },
            "restart_step_id": "step2",
            "clear": [None, "", " base_branch ", "base_branch"],
            "unresolved_slots": [None, "", " branch "],
            "notes": " note ",
        })
        self.assertEqual(normalized["action"], "continue")
        self.assertEqual(normalized["restart_step_id"], "step2")
        self.assertEqual(normalized["clear"], ["base_branch"])
        self.assertEqual(normalized["unresolved_slots"], ["branch"])
        self.assertEqual(normalized["set"], {"base_branch": " main "})
        self.assertEqual(normalized["notes"], "note")

        nested_only = run_step.normalize_intent_patch({
            "set": {"restart_step_id": "step3"},
        })
        self.assertEqual(nested_only["restart_step_id"], "step3")
        self.assertEqual(
            run_step.normalize_intent_patch({"action": None})["action"], ""
        )

    def test_canonical_response_action_restart_notes_clear_and_conflict_matrix(self):
        for response in (None, {}, {"intent_patch": ""}):
            with self.subTest(missing_action=response):
                self.assert_step_error(
                    lambda response=response: run_step.build_canonical_user_response(
                        response
                    )
                )
        self.assertEqual(
            run_step.build_canonical_user_response({"action": " continue "}),
            {"action": "continue"},
        )

        invalid = (
            {
                "action": "continue", "business": True,
                "intent_patch": {"action": "continue"},
            },
            {
                "intent_patch": {
                    "action": "continue", "unresolved_slots": ["branch"],
                },
            },
            {
                "action": "continue",
                "intent_patch": {"action": "cancel"},
            },
            {"intent_patch": {}},
            {
                "action": "continue", "restart_step_id": "step1",
                "intent_patch": {
                    "action": "continue", "restart_step_id": "step2",
                },
            },
        )
        for response in invalid:
            with self.subTest(invalid=response):
                self.assert_step_error(
                    lambda response=response: run_step.build_canonical_user_response(
                        response
                    )
                )

        cases = (
            (
                {
                    "action": "continue",
                    "intent_patch": {
                        "set": {"base_branch": "main"},
                        "clear": ["current_branch"],
                    },
                },
                "continue", None, None,
            ),
            (
                {
                    "intent_patch": {
                        "action": "restart_from_step",
                        "restart_step_id": "step1",
                        "notes": "patch note",
                    },
                },
                "restart_from_step", "step1", "patch note",
            ),
            (
                {
                    "action": "restart_from_step",
                    "restart_step_id": "step2",
                    "notes": "top note",
                    "intent_patch": {"action": "restart_from_step"},
                },
                "restart_from_step", "step2", "top note",
            ),
            (
                {
                    "action": "continue", "restart_step_id": "step1",
                    "notes": "top",
                    "intent_patch": {
                        "action": "continue", "restart_step_id": "step1",
                        "notes": "patch",
                    },
                },
                "continue", "step1", "patch",
            ),
        )
        for response, action, restart, notes in cases:
            with self.subTest(response=response):
                result = run_step.build_canonical_user_response(response)
                self.assertEqual(result["action"], action)
                self.assertEqual(result.get("restart_step_id"), restart)
                self.assertEqual(result.get("notes"), notes)
        self.assertEqual(
            run_step.build_canonical_user_response(cases[0][0])["__clear_fields"],
            ["current_branch"],
        )

    def test_selection_option_key_alias_label_and_optional_projection_matrix(self):
        self.assertEqual(run_step.build_interaction_selection_options(None), [])
        options = run_step.build_interaction_selection_options([
            None,
            {},
            {"coord": " g:a:1 ", "aliases": None},
            {"name": " artifact-b ", "label": " B "},
            {
                "selection_key": "custom:C", "coord": "g:c:1",
                "name": "artifact-c", "label": " C ",
                "aliases": ["c", "C", ""],
                "api_count": 4, "high_risk_api_count": 2,
                "business_exact_referenced_api_count": "3",
                "business_candidate_referenced_api_count": 2,
                "business_reference_occurrence_count": 5,
                "business_bytecode_scan_status": " complete ",
                "dependency_source_status": " available ",
                "impact_priority_rank": "1",
                "recommendation_reason": " because ",
                "recommended": "true", "change_types": " REMOVED ",
                "detail": " detail.md ",
            },
            {
                "selection_key": "CUSTOM:c", "label": "duplicate",
            },
            {
                "selection_key": "fallback", "review_focus": " focus ",
                "recommendation_reason": "",
                "business_bytecode_scan_status": None,
                "dependency_source_status": None,
            },
        ])
        self.assertEqual(
            [item["selection_key"] for item in options],
            ["coord:g:a:1", "name:artifact-b", "custom:C", "fallback"],
        )
        self.assertEqual(options[0]["label"], "g:a:1")
        self.assertEqual(options[1]["label"], "B")
        self.assertEqual(options[2]["api_count"], 4)
        self.assertEqual(options[2]["business_exact_referenced_api_count"], 3)
        self.assertTrue(options[2]["recommended"])
        self.assertIn("c", [value.lower() for value in options[2]["aliases"]])
        self.assertEqual(options[3]["recommendation_reason"], "focus")
        self.assertEqual(options[3]["dependency_source_status"], "unknown")

    def test_landing_pending_card_scope_options_examples_and_review_links_matrix(self):
        self.assertEqual(run_step._landing_pending_interaction_lines("/report", None), [])
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory).resolve()
            with patch.object(
                run_step, "_decision_card_reply_examples", return_value=[],
            ):
                base_lines = run_step._landing_pending_interaction_lines(
                    report,
                    {"state": {"pending_interaction": {
                        "question": "Base",
                        "options": [{"id": "continue"}],
                    }}},
                )
            self.assertIn("Base", base_lines)
            changed = report / "changed_dependencies.md"
            other = report / "review.md"
            changed.write_text("changed", encoding="utf-8")
            other.write_text("review", encoding="utf-8")
            interaction = {
                "question": "Choose",
                "scope_preview": {
                    "available_dependency_count": 3,
                    "total_api_count": 0,
                    "high_risk_api_count": 2,
                    "partial_scope_effect": "custom effect",
                },
                "options": [
                    None,
                    {"id": "continue", "description": "go"},
                    {"id": "custom", "label": "Custom"},
                    {
                        "id": "restart_from_step", "label": "Restart",
                        "description": "back",
                    },
                    {"id": "restart_from_step"},
                ],
                "selection_options": [{"selection_key": "coord:g:a"}],
                "files_to_review": [None, "missing.md", changed, other],
            }
            state = {"state": {"pending_interaction": interaction}}
            with patch.object(
                run_step, "_decision_card_reply_examples",
                return_value=["分析全部", "只分析 g:a"],
            ):
                lines = run_step._landing_pending_interaction_lines(report, state)
            text = "\n".join(lines)
            self.assertIn("覆盖 3 个变化依赖、0 个变化 API", text)
            self.assertIn("custom effect", text)
            self.assertIn("继续", text)
            self.assertIn("Custom", text)
            self.assertIn("Restart：back", text)
            self.assertIn("完整依赖选择清单", text)
            self.assertIn("只分析 g:a", text)

            interaction = {
                "title": "Fallback title",
                "scope_preview": {
                    "available_dependency_count": 0,
                    "total_api_count": 1,
                    "high_risk_api_count": 0,
                    "partial_scope_effect": "",
                },
                "options": [],
                "selection_options": [],
                "files_to_review": [other],
            }
            with patch.object(
                run_step, "_decision_card_reply_examples", return_value=[],
            ):
                lines = run_step._landing_pending_interaction_lines(
                    report, {"state": {"pending_interaction": interaction}},
                )
            text = "\n".join(lines)
            self.assertIn("Fallback title", text)
            self.assertIn("部分分析会缩小最终报告", text)
            self.assertIn("确认前可核对", text)

    def test_git_recheck_step_reason_request_type_and_status_matrix(self):
        self.assertFalse(run_step.pending_interaction_needs_git_recheck(None))
        self.assertFalse(run_step.pending_interaction_needs_git_recheck({
            "step_id": "step2",
            "reason_code": "step1_remote_fetch_failed",
        }))
        self.assertTrue(run_step.pending_interaction_needs_git_recheck({
            "step_id": " step1 ",
            "reason_code": " STEP1_REMOTE_FETCH_FAILED ",
        }))
        self.assertFalse(run_step.pending_interaction_needs_git_recheck({
            "step_id": "step1",
        }))
        self.assertFalse(run_step.pending_interaction_needs_git_recheck({
            "step_id": "step0", "reason_code": "stable",
            "ref_resolution_requests": [None, "invalid", {}, {
                "source_status": "stable",
            }],
        }))
        self.assertTrue(run_step.pending_interaction_needs_git_recheck({
            "step_id": "step0", "reason_code": "stable",
            "ref_resolution_requests": [{
                "source_status": " REMOTE_QUERY_FAILED ",
            }],
        }))

    def test_scope_mode_empty_full_partial_and_invalid_matrix(self):
        self.assertEqual(run_step.normalize_step5_scope_mode(None), "")
        self.assertEqual(run_step.normalize_step5_scope_mode(" FULL "), "full")
        self.assertEqual(run_step.normalize_step5_scope_mode("partial"), "partial")
        self.assert_step_error(
            lambda: run_step.normalize_step5_scope_mode("", allow_empty=False)
        )
        self.assert_step_error(
            lambda: run_step.normalize_step5_scope_mode("unknown")
        )

    def test_step1_ref_confirmation_reason_checklist_and_local_permission_matrix(self):
        def request(**overrides):
            value = {
                "field": "base_branch", "side": "base",
                "status": "not_found", "source_status": "",
                "fingerprint": "fingerprint",
                "requested_ref": "release", "source_project_dir": "/source",
                "configured_remotes": ["origin"], "query_mode": "remote",
                "detected_ref": "HEAD", "detected_commit": "a" * 40,
                "candidates": [{"ref": "origin/release", "commit": "a" * 40}],
                "remote_failures": [
                    {"remote": "origin", "stage": "fetch", "reason": "denied"},
                    {},
                ],
                "local_candidate_commit": "b" * 40,
                "dirty": False,
            }
            value.update(overrides)
            return value

        cases = (
            (request(status="fetch_failed"), "step1_remote_fetch_failed"),
            (request(status="ref_moved"), "step1_remote_ref_moved"),
            (
                request(status="confirmation_required"),
                "step1_source_revision_confirmation_required",
            ),
            (request(status="ambiguous"), "ambiguous_step1_source_ref"),
            (
                request(source_status="repository_not_git"),
                "step1_source_directory_not_git",
            ),
            (
                request(source_status="remote_configuration_missing"),
                "step1_remote_configuration_missing",
            ),
            (
                request(
                    source_status="awaiting_dirty_local_source_confirmation",
                    dirty=True,
                ),
                "step1_dirty_local_source_confirmation_required",
            ),
            (
                request(source_status="awaiting_local_source_confirmation"),
                "step1_remote_source_unavailable",
            ),
            (request(), "step1_source_ref_not_found"),
        )
        for item, expected_reason in cases:
            with self.subTest(reason=expected_reason):
                interaction = run_step.build_step1_ref_confirmation_interaction(
                    {}, [item]
                )
                self.assertEqual(interaction["reason_code"], expected_reason)
                self.assertIn("base_branch", interaction["response_schema"]["properties"])

        empty = run_step.build_step1_ref_confirmation_interaction({}, None)
        self.assertEqual(empty["reason_code"], "step1_source_ref_not_found")
        no_side = run_step.build_step1_ref_confirmation_interaction({}, [
            request(
                field="current_branch", side=None, requested_ref="",
                configured_remotes=[],
            ),
            request(field="", side=None, status="not_found"),
        ])
        self.assertIn("current_branch", no_side["response_schema"]["properties"])

        mixed = run_step.build_step1_ref_confirmation_interaction({}, [
            request(
                status="fetch_failed", requested_ref="",
                source_project_dir="", configured_remotes=[], query_mode="",
                detected_commit="", candidates=[], remote_failures=[],
                local_candidate_commit="",
            ),
            request(
                field="current_branch", side="current", status="ambiguous",
                dirty=True,
            ),
            request(field="", side="current", status="fetch_failed"),
        ])
        self.assertEqual(mixed["reason_code"], "step1_remote_fetch_failed")
        self.assertIn("current_branch", mixed["required_fields"])
        local_fields = mixed["action_requirements"]["confirm_local_source"][
            "required_fields"
        ]
        self.assertIn("current_allow_dirty_local_source", local_fields)
        self.assertIn("当前侧", "\n".join(mixed["checklist_lines"]))

    def test_step0_confirmation_modes_candidates_ref_schema_and_origin_matrix(self):
        available = {
            field: {"type": "string"}
            for field in (
                "base_artifact_path", "current_artifact_path",
                "application_source", "base_branch", "current_branch",
                "target_module", "base_tool", "current_tool",
                "base_jdk_home", "current_jdk_home",
            )
        }

        def build(ctx, *, inferred_mode, pinned, ref=None):
            with patch.object(
                run_step, "infer_step1_mode_fields",
                return_value={"analysis_mode": inferred_mode},
            ), patch.object(
                run_step, "_pinned_snapshot_matches_context",
                return_value=pinned,
            ), patch.object(
                run_step, "build_step0_response_properties",
                return_value=available,
            ), patch.object(
                run_step, "_step0_dependency_source_display",
                return_value="dependency sources",
            ):
                return run_step.build_step0_confirmation_interaction(ctx, ref)

        empty = build(None, inferred_mode="source_build", pinned=False)
        self.assertNotIn("base_artifact_path", empty["required_fields"])
        self.assertIn("application_source", empty["required_fields"])
        self.assertEqual(empty["source_ref_decision_items"], [])
        overlap = build(
            {}, inferred_mode="", pinned=True,
            ref={
                "ref_resolution_requests": [
                    {"field": "base_branch", "side": "base"},
                ],
            },
        )
        self.assertEqual(
            [item["field"] for item in overlap["missing_inputs"]].count(
                "base_branch"
            ),
            1,
        )

        artifact_context = {
            "analysis_mode": "artifact_inputs",
            "base_artifact_path": "/artifacts/base.jar",
            "current_artifact_path": "/artifacts/current.jar",
            "application_source": "/src",
            "application_source_display": "Application Source",
            "base_branch": "main", "current_branch": "release",
            "target_module": "", "base_tool": "maven",
            "current_tool": "gradle", "base_jdk_home": "/jdk8",
            "current_jdk_home": "/jdk17",
            "input_origins": {"base_branch": "user"},
            "project_scope": {
                "candidate_modules": [f"module-{index}" for index in range(6)],
            },
            "pinned_source_snapshot": {"snapshot": True},
        }
        ref = {
            "ref_resolution_requests": [
                {"field": "base_branch", "side": "base"},
                {"field": "custom_ref", "side": "current"},
                {"field": "", "side": "current"},
            ],
            "source_ref_decision_items": [{"side": "base"}],
            "response_schema": {"properties": {
                "action": {"type": "string"},
                "notes": {"type": "string"},
                "source_ref_selections": {"type": "array"},
            }},
        }
        artifact = build(
            artifact_context, inferred_mode="artifact_inputs", pinned=True,
            ref=ref,
        )
        self.assertIn("custom_ref", artifact["required_fields"])
        ambiguous_fields = [
            item["field"] for item in artifact["missing_inputs"]
            if item["reason"].startswith("存在多个")
        ]
        self.assertEqual(ambiguous_fields.count("base_branch"), 1)
        self.assertIn("custom_ref", ambiguous_fields)
        target_input = next(
            item for item in artifact["missing_inputs"]
            if item["field"] == "target_module"
        )
        self.assertEqual(len(target_input["candidates"]), 6)
        self.assertIn(
            "source_ref_selections",
            artifact["response_schema"]["properties"],
        )
        final_artifact_row = artifact["confirmation_table"]["rows"][0]
        self.assertIn("base.jar", final_artifact_row["base"])

        short_candidates = {
            **artifact_context,
            "project_scope": {"candidate_modules": ["one", "two"]},
            "application_source_display": "",
        }
        short = build(
            short_candidates, inferred_mode="artifact_inputs", pinned=True,
        )
        target_row = next(
            row for row in short["confirmation_table"]["rows"]
            if row["label"] == "目标模块"
        )
        self.assertIn("one、two", target_row["base"])

        complete_target = {
            **artifact_context,
            "target_module": "module-1",
        }
        complete = build(
            complete_target, inferred_mode="", pinned=True,
            ref={"ref_resolution_requests": []},
        )
        self.assertNotIn("target_module", complete["required_fields"])

    def test_dependency_source_binding_confirm_skip_auto_and_ambiguity_matrix(self):
        self.assertIsNone(
            run_step.build_step1_dependency_source_interaction({}, "/report")
        )

        versions = {
            "g:confirmed": {"base": "1", "current": "2"},
            "g:auto": {"base": "1", "current": "1"},
            "g:multi": {"base": "1", "current": "2"},
            "g:amb": {"base": "amb", "current": "2"},
            "g:skip": {"base": "1", "current": "2"},
            "g:empty": {"base": "1", "current": "2"},
            "": {"base": "1", "current": "2"},
        }
        candidates = {
            "g:confirmed": {"/repo-confirmed": {"repo_path": "/repo-confirmed"}},
            "g:auto": {"/repo-auto": {"repo_path": "/repo-auto"}},
            "g:multi": {
                "/repo-one": {"repo_path": "/repo-one"},
                "/repo-two": {"repo_path": "/repo-two"},
            },
            "g:amb": {"/repo-amb": {"repo_path": "/repo-amb"}},
            "g:skip": {"/repo-skip": {"repo_path": "/repo-skip"}},
            "g:noversion": {"/repo-noversion": {"repo_path": "/repo-noversion"}},
            "g:empty": {},
            "": {"/repo-unbound": {"repo_path": "/repo-unbound"}},
        }

        def version_groups(_repo, version):
            if version == "amb":
                return {
                    "status": "ambiguous",
                    "candidates": [
                        {"ref": "tag/one", "commit": "1" * 40},
                        {"ref": "tag/two", "commit": "2" * 40},
                    ],
                }
            return {
                "status": "matched",
                "candidates": [{"ref": f"tag/{version}", "commit": version * 40}],
            }

        context = {
            "dependency_source_dirs": ["/sources"],
            "skip_dependency_source_coords": ["g:skip"],
            "dependency_source_ref_bindings": [
                None, {"coord": ""},
                {"coord": "g:confirmed", "selection_key": "confirmed"},
            ],
        }
        with patch.object(
            run_step, "_dependency_change_versions", return_value=versions,
        ), patch.object(
            run_step, "_dependency_repo_mapping_candidates",
            return_value=(
                {"unmatched_relevant_coords": ["g:unmatched"]}, candidates,
            ),
        ), patch.object(
            run_step, "_version_candidate_groups", side_effect=version_groups,
        ):
            interaction = run_step.build_step1_dependency_source_interaction(
                context, "/report"
            )
        self.assertIsNotNone(interaction)
        self.assertEqual(
            {item["coord"] for item in interaction["dependency_source_ambiguities"]},
            {"g:multi", "g:amb"},
        )
        self.assertIn(
            "g:auto",
            {item["coord"] for item in context["dependency_source_ref_bindings"]},
        )
        self.assertEqual(
            context["dependency_source_unmatched_coords"], ["g:unmatched"]
        )

        auto_context = {"dependency_source_dirs": ["/sources"]}
        with patch.object(
            run_step, "_dependency_change_versions",
            return_value={"g:auto": versions["g:auto"]},
        ), patch.object(
            run_step, "_dependency_repo_mapping_candidates",
            return_value=(
                {"unmatched_relevant_coords": []},
                {"g:auto": candidates["g:auto"]},
            ),
        ), patch.object(
            run_step, "_version_candidate_groups", side_effect=version_groups,
        ):
            self.assertIsNone(
                run_step.build_step1_dependency_source_interaction(
                    auto_context, "/report"
                )
            )
        self.assertEqual(
            auto_context["dependency_source_ref_bindings"][0]["coord"],
            "g:auto",
        )

    def test_non_pending_payload_presence_step_inference_and_resolution_matrix(self):
        for payload in (
            None,
            {"action": "continue", "notes": "note"},
            {"business": "   ", "__clear_fields": []},
        ):
            with self.subTest(absent_payload=payload):
                self.assertFalse(run_step.has_non_pending_intent_payload(payload))
        self.assertTrue(run_step.has_non_pending_intent_payload({
            "__clear_fields": ["base_branch"],
        }))
        self.assertTrue(run_step.has_non_pending_intent_payload({
            "business": "value",
        }))

        self.assertEqual(
            run_step.infer_non_pending_target_step_from_payload(
                {"selected_targets": []}
            ),
            "step5",
        )
        hints = (
            ("application_source", "step0"),
            ("manual_coord_overrides", "step1"),
            ("include_test_scope", "step3"),
            ("binary_pipeline_config", "step4"),
            ("strict_risk_gate", "step5"),
        )
        for field, expected in hints:
            with self.subTest(field=field):
                self.assertEqual(
                    run_step.infer_non_pending_target_step_from_payload(
                        {field: True}
                    ),
                    expected,
                )
                self.assertEqual(
                    run_step.infer_non_pending_target_step_from_payload(
                        {"__clear_fields": [field]}
                    ),
                    expected,
                )
        self.assertEqual(
            run_step.infer_non_pending_target_step_from_payload(None), ""
        )
        self.assertEqual(
            run_step.infer_non_pending_target_step_from_payload({
                "application_source": "", "__clear_fields": [],
            }),
            "",
        )
        self.assertEqual(
            run_step.infer_non_pending_target_step_from_payload({
                "__clear_fields": ["unknown"],
            }),
            "",
        )

        args = SimpleNamespace(step="auto")
        for response in (None, {"action": "invalid"}):
            with self.subTest(invalid_action=response):
                self.assert_step_error(
                    lambda response=response: run_step.resolve_non_pending_structured_response_step(
                        args, {}, response
                    )
                )
        self.assert_step_error(
            lambda: run_step.resolve_non_pending_structured_response_step(
                args, {}, {"action": "restart_from_step", "restart_step_id": "bad"}
            )
        )
        self.assertEqual(
            run_step.resolve_non_pending_structured_response_step(
                args, {}, {
                    "action": "restart_from_step",
                    "restart_step_id": "step2",
                }
            ),
            "step2",
        )
        self.assertEqual(
            run_step.resolve_non_pending_structured_response_step(
                SimpleNamespace(step="step3"), {}, {"action": "continue"}
            ),
            "step3",
        )
        self.assertEqual(
            run_step.resolve_non_pending_structured_response_step(
                args, {"state": {"current_step": "step4"}},
                {"action": "continue"},
            ),
            "step4",
        )
        self.assertEqual(
            run_step.resolve_non_pending_structured_response_step(
                SimpleNamespace(step=""),
                {"state": {"current_step": "step2"}},
                {"action": "continue"},
            ),
            "step2",
        )
        self.assertEqual(
            run_step.resolve_non_pending_structured_response_step(
                SimpleNamespace(step=None), {},
                {"action": "continue", "include_test_scope": True},
            ),
            "step3",
        )
        self.assertEqual(
            run_step.resolve_non_pending_structured_response_step(
                args, {"state": {"current_step": "invalid"}},
                {"action": "continue", "include_test_scope": True},
            ),
            "step3",
        )
        self.assert_step_error(
            lambda: run_step.resolve_non_pending_structured_response_step(
                args, {"state": {}}, {"action": "continue"}
            )
        )

    def test_apply_user_response_scope_restore_assignment_seed_and_unresolved_matrix(self):
        def state():
            return {
                **{
                    step: {"input": {}, "output": {}}
                    for step in run_step.STEP_SEQUENCE
                },
                "state": {},
            }

        missing = object()

        def invoke(
            *, pending=None, response=None, target="",
            selection_result=missing, scope_confirmation=False,
            restore=None, fallback_restore=None,
        ):
            main_state = state()
            seeded = []
            restore_calls = []

            def restore_context(_state, step):
                restore_calls.append(step)
                if len(restore_calls) > 1:
                    return dict(fallback_restore or {})
                return dict(restore or {})

            selected = (
                selection_result if selection_result is not missing else {}
            )
            with patch.object(
                run_step, "build_canonical_user_response",
                side_effect=lambda value: dict(value or {}),
            ), patch.object(
                run_step, "expand_step1_ref_selections",
                side_effect=lambda _pending, value: value,
            ), patch.object(
                run_step, "expand_dependency_source_ref_selections",
                side_effect=lambda _pending, value: value,
            ), patch.object(
                run_step, "resolve_selected_targets", return_value=selected,
            ), patch.object(
                run_step, "_is_step4_scope_confirmation",
                return_value=scope_confirmation,
            ), patch.object(
                run_step, "build_restore_context", side_effect=restore_context,
            ), patch.object(
                run_step, "merge_user_response_into_run_context",
                side_effect=lambda base, value, _project: {**base, **value},
            ), patch.object(
                run_step, "seed_next_step_input",
                side_effect=lambda *_args: seeded.append(True),
            ), patch.object(
                run_step, "record_last_user_response",
            ), patch.object(
                run_step, "update_main_state_state",
            ):
                result = run_step.apply_user_response_to_main_state(
                    main_state, pending, response or {}, "/project",
                    target_step_id=target,
                )
            return result, seeded, restore_calls

        result, seeded, calls = invoke(response={"action": "continue"})
        self.assertEqual(result[1], {})
        self.assertEqual(seeded, [])
        self.assertEqual(calls, [])

        result, _seeded, _calls = invoke(
            pending={"step_id": "step5", "kind": "input_request"},
            response={"action": "continue", "selected_targets": ["a"]},
            selection_result=None,
        )
        self.assertNotIn("step5_selected_coords", result[1])

        result, _seeded, _calls = invoke(
            pending={"step_id": "step5", "kind": "review"},
            response={"action": "continue", "selected_targets": ["a"]},
            selection_result={
                "step5_selected_coords": ["g:a"],
                "step5_selected_names": ["a"],
            },
        )
        self.assertEqual(result[1]["scope_mode"], "partial")
        self.assertEqual(result[1]["step5_selected_coords"], ["g:a"])

        result, _seeded, _calls = invoke(
            pending={
                "step_id": "step5", "kind": "review",
                "selection_resolution": {"options": [{"selection_key": "a"}]},
            },
            response={"action": "continue", "selected_targets": ["a"]},
            selection_result={"step5_selected_coords": ["g:a"]},
        )
        self.assertEqual(result[1]["step5_selected_coords"], ["g:a"])

        result, _seeded, _calls = invoke(
            pending=None, target="step5",
            response={"action": "continue", "selected_targets": ["a"]},
            selection_result={
                "step5_selected_coords": [],
                "step5_selected_names": ["a"],
            },
        )
        self.assertEqual(result[1]["step5_selected_names"], ["a"])

        invalid_cases = (
            (
                {"action": "continue"},
                {"step_id": "step4"}, True,
            ),
            (
                {"action": "continue", "scope_mode": "partial"},
                {"step_id": "step5"}, False,
            ),
            (
                {
                    "action": "continue", "scope_mode": "full",
                    "step5_selected_coords": ["g:a"],
                },
                {"step_id": "step5"}, False,
            ),
        )
        for response, pending, confirmation in invalid_cases:
            with self.subTest(response=response):
                self.assert_step_error(
                    lambda response=response, pending=pending,
                    confirmation=confirmation: invoke(
                        pending=pending, response=response,
                        scope_confirmation=confirmation,
                    )
                )

        result, seeded, _calls = invoke(
            pending={"step_id": "step4", "kind": "review"},
            response={"action": "continue", "scope_mode": "full"},
            restore={
                "step5_selected_coords": ["old"],
                "step5_selected_names": ["old"],
            },
        )
        self.assertNotIn("step5_selected_coords", result[1])
        self.assertEqual(seeded, [True])

        for response in (
            {"action": "cancel"},
            {
                "action": "continue", "scope_mode": "partial",
                "step5_selected_coords": ["g:a"],
            },
            {
                "action": "continue", "scope_mode": "partial",
                "step5_selected_names": ["a"],
            },
        ):
            with self.subTest(step4_condition=response):
                invoke(
                    pending={"step_id": "step4", "kind": "input_request"},
                    response=response,
                )

        result, _seeded, calls = invoke(
            pending={"step_id": "step4", "kind": "review"},
            response={"action": "restart_from_step"},
            target="step1", restore={"base": 1},
            fallback_restore={"current": 2},
        )
        self.assertEqual(result[1]["current"], 2)
        self.assertEqual(calls, ["step1", "step4"])
        result, _seeded, calls = invoke(
            pending={"step_id": "step4", "kind": "review"},
            response={"action": "restart_from_step"},
            target="step1", restore={"base": 1}, fallback_restore={},
        )
        self.assertEqual(result[1]["base"], 1)
        self.assertEqual(calls, ["step1", "step4"])
        _result, _seeded, calls = invoke(
            pending=None,
            response={"action": "restart_from_step"},
            target="step1",
        )
        self.assertEqual(calls, ["step1"])
        _result, _seeded, calls = invoke(
            pending={"step_id": "step1"},
            response={"action": "restart_from_step"},
            target="step1",
        )
        self.assertEqual(calls, ["step1"])

        result, _seeded, _calls = invoke(
            pending={"step_id": "step0", "kind": "input_request"},
            response={"action": "continue"},
        )
        self.assertTrue(result[1]["step0_confirmation_acknowledged"])
        result, _seeded, _calls = invoke(
            pending={"step_id": "step0", "kind": "input_request"},
            response={"action": "cancel"},
        )
        self.assertNotIn("step0_confirmation_acknowledged", result[1])
        result, _seeded, _calls = invoke(
            pending={"step_id": "step1", "kind": "input_request"},
            response={"action": "continue"}, target="step0",
        )
        self.assertNotIn("step0_confirmation_acknowledged", result[1])

        result, _seeded, _calls = invoke(
            pending={
                "step_id": "step1", "kind": "review",
                "unresolved_items": ["g:a"],
            },
            response={"action": "confirm_unresolved"},
        )
        self.assertEqual(
            result[0]["step1"]["input"]["confirmed_unresolved_items"],
            ["g:a"],
        )
        result, _seeded, _calls = invoke(
            pending={"step_id": "step2", "kind": "review"},
            response={"action": "confirm_unresolved"},
        )
        self.assertEqual(result[0]["step2"]["input"], {
            "action": "confirm_unresolved",
        })
        result, _seeded, _calls = invoke(
            pending=None, target="step2",
            response={"action": "confirm_unresolved"},
        )
        self.assertEqual(result[0]["step2"]["input"], {
            "action": "confirm_unresolved",
        })

    def test_restore_reset_and_non_pending_interaction_boundary_matrix(self):
        fallback = {"fallback": True}
        with patch.object(
            run_step, "build_step_input_context", return_value=fallback,
        ) as build_input:
            self.assertEqual(run_step.build_restore_context({}, "step2"), fallback)
            self.assertEqual(
                run_step.build_restore_context(
                    {"step2": {"output": {}, "input": {}}}, "step2"
                ),
                fallback,
            )
            self.assertEqual(
                run_step.build_restore_context(
                    {"step2": {"output": {"old": 1}, "input": {}}},
                    "step2",
                ),
                {"old": 1},
            )
            self.assertEqual(
                run_step.build_restore_context(
                    {
                        "step2": {
                            "output": None,
                            "input": {"new": 2},
                        }
                    },
                    "step2",
                ),
                {"new": 2},
            )
            self.assertEqual(
                run_step.build_restore_context(
                    {
                        "step2": {
                            "output": {"value": "old", "kept": True},
                            "input": {"value": "new"},
                        }
                    },
                    "step2",
                ),
                {"value": "new", "kept": True},
            )
        self.assertEqual(build_input.call_count, 2)

        state = {}
        with patch.object(run_step, "build_step_input_context") as build_input, \
             patch.object(run_step, "clear_steps_from") as clear_steps, \
             patch.object(run_step, "cleanup_step_outputs_from") as cleanup, \
             patch.object(run_step, "update_main_state_state") as update:
            preserved = run_step.reset_step_state_for_restart(
                state, "step0", "/report", preserve_current_input={"kept": 1}
            )
            self.assertEqual(preserved, {"kept": 1})
            build_input.assert_not_called()
            clear_steps.assert_called_once_with(
                state, "step0", preserve_current_input={"kept": 1}
            )
            cleanup.assert_called_once_with("step0", "/report")
            self.assertEqual(update.call_args.kwargs["completed_step"], "")

        with patch.object(
            run_step, "build_step_input_context", return_value={"fallback": 2},
        ) as build_input, patch.object(
            run_step, "clear_steps_from"
        ), patch.object(
            run_step, "cleanup_step_outputs_from"
        ), patch.object(
            run_step, "update_main_state_state"
        ) as update:
            preserved = run_step.reset_step_state_for_restart(
                state, "step2", "/report", preserve_current_input=None
            )
            self.assertEqual(preserved, {"fallback": 2})
            build_input.assert_called_once_with(
                state, "step2", fallback_existing={}
            )
            self.assertEqual(update.call_args.kwargs["completed_step"], "step1")

        self.assertEqual(
            run_step.build_non_pending_structured_response_interaction(
                "step2", "/report", {"action": "continue"}
            ),
            {
                "step_id": "step2",
                "kind": "non_pending_intent_bridge",
                "status": "ready",
            },
        )
        with patch.object(
            run_step, "build_report_dir_step5_selection_resolution",
            return_value={"options": None},
        ):
            self.assert_step_error(
                lambda: run_step.build_non_pending_structured_response_interaction(
                    "step5", "/report", {"selected_targets": []}
                )
            )
        resolution = {"options": [{"selection_key": "coord:g:a"}]}
        with patch.object(
            run_step, "build_report_dir_step5_selection_resolution",
            return_value=resolution,
        ):
            interaction = run_step.build_non_pending_structured_response_interaction(
                "step5", "/report", {"selected_targets": ["g:a"]}
            )
        self.assertIs(interaction["selection_resolution"], resolution)

    def test_apply_non_pending_cancel_payload_restart_selection_and_retention_matrix(self):
        missing = object()

        def invoke(
            response, *, state=missing, target="step2", payload=True,
            interaction=None,
        ):
            actual_state = (
                {"state": {"current_step": "step2", "completed_step": "step1"}}
                if state is missing else state
            )
            captured = {}

            def apply_response(
                supplied_state, supplied_interaction, supplied_response,
                supplied_project, **kwargs,
            ):
                captured["interaction"] = dict(supplied_interaction)
                captured["target_step_id"] = kwargs["target_step_id"]
                return supplied_state or {}, {"updated": True}

            with ExitStack() as stack:
                stack.enter_context(patch.object(
                    run_step, "has_non_pending_intent_payload",
                    return_value=payload,
                ))
                resolve = stack.enter_context(patch.object(
                    run_step, "resolve_non_pending_structured_response_step",
                    return_value=target,
                ))
                build = stack.enter_context(patch.object(
                    run_step, "build_non_pending_structured_response_interaction",
                    return_value=dict(interaction or {
                        "step_id": target,
                        "kind": "non_pending_intent_bridge",
                    }),
                ))
                validate = stack.enter_context(patch.object(
                    run_step, "validate_selected_targets_resolution",
                ))
                apply_mock = stack.enter_context(patch.object(
                    run_step, "apply_user_response_to_main_state",
                    side_effect=apply_response,
                ))
                reset = stack.enter_context(patch.object(
                    run_step, "reset_step_state_for_restart",
                ))
                save = stack.enter_context(patch.object(
                    run_step, "save_main_state",
                ))
                stderr = stack.enter_context(patch.object(
                    run_step.sys, "stderr", io.StringIO(),
                ))
                result = run_step.apply_non_pending_structured_response(
                    SimpleNamespace(step="auto"), "/project", "/report",
                    actual_state, response,
                )
                return result, captured, {
                    "resolve": resolve, "build": build,
                    "validate": validate, "apply": apply_mock,
                    "reset": reset, "save": save,
                    "stderr": stderr.getvalue(),
                }

        result, _captured, calls = invoke({"action": "cancel"}, payload=False)
        self.assertEqual(result["early_exit_code"], 0)
        calls["resolve"].assert_not_called()
        calls["apply"].assert_not_called()
        self.assertIn("保持不变", calls["stderr"])

        with self.assertRaises(run_step.StepError):
            invoke(None, payload=False)
        with self.assertRaises(run_step.StepError):
            invoke({"action": "continue"}, payload=False)

        result, captured, calls = invoke(
            {"action": "continue", "target_module": "app"},
            target="step0", payload=True,
        )
        self.assertEqual(result["step_id"], "step0")
        self.assertEqual(captured["target_step_id"], "step0")
        self.assertIn("不复用旧的正式分析产物", calls["stderr"])
        calls["reset"].assert_called_once_with(
            result["main_state"], "step0", "/report",
            preserve_current_input={"updated": True},
        )

        result, _captured, calls = invoke(
            {"action": "rerun_current_step"}, target="step2", payload=False,
        )
        self.assertEqual(result["step_id"], "step2")
        self.assertIn("之前的正式产物继续保留", calls["stderr"])

        restart_states = (
            (
                {"state": {"current_step": "step2", "completed_step": "step1"}},
                "step2",
            ),
            (
                {"state": {"current_step": "step5", "completed_step": "step4"}},
                "step5",
            ),
            (
                {"state": {"current_step": "done", "completed_step": "step4"}},
                "step4",
            ),
            (
                {"state": {"current_step": "done", "completed_step": "done"}},
                "step2",
            ),
            ({}, "step2"),
        )
        for state, expected_source in restart_states:
            with self.subTest(restart_state=state):
                _result, captured, _calls = invoke(
                    {
                        "action": "restart_from_step",
                        "restart_step_id": "step2",
                    },
                    state=state, target="step2", payload=False,
                )
                self.assertEqual(captured["interaction"]["step_id"], expected_source)

        for resolution in ({}, {"options": [{"selection_key": "g:a"}]}):
            with self.subTest(selection_resolution=resolution):
                _result, _captured, calls = invoke(
                    {
                        "action": "continue", "selected_targets": ["g:a"],
                    },
                    target="step5", payload=True,
                    interaction={
                        "step_id": "step5",
                        "selection_resolution": resolution,
                    },
                )
                calls["validate"].assert_called_once_with(
                    resolution, ["g:a"]
                )

    def test_apply_structured_pending_presence_action_and_restart_matrix(self):
        missing = object()

        def invoke(
            *, pending=missing, response=missing, response_json="",
            response_file="", available=(), resolved_response=None,
            resume_step="step2", paused_step="step2", after_pending=None,
            state_fields=None, target_input=missing,
        ):
            state_meta = dict(state_fields or {})
            if pending is not missing:
                state_meta["pending_interaction"] = pending
            main_state = {"state": state_meta}
            if target_input is not missing:
                main_state[resume_step] = {"input": target_input}
            args = SimpleNamespace(
                response_json=response_json, response_file=response_file,
            )
            supplied_response = None if response is missing else response
            delegated = {
                "main_state": main_state, "step_id": "delegated",
                "pending_interaction": None,
                "resumed_interaction_step_id": "",
                "response_action": "continue", "user_response": {},
                "early_exit_code": None,
            }

            def apply_response(*_args, **_kwargs):
                main_state.setdefault("state", {})["pending_interaction"] = after_pending
                return main_state, {"updated": True}

            with ExitStack() as stack:
                resolve = stack.enter_context(patch.object(
                    run_step, "resolve_user_response",
                    return_value=dict(resolved_response or {"action": "continue"}),
                ))
                options = stack.enter_context(patch.object(
                    run_step, "option_ids", return_value=set(available),
                ))
                validate = stack.enter_context(patch.object(
                    run_step, "validate_pending_interaction_response",
                ))
                current = stack.enter_context(patch.object(
                    run_step, "current_step_for_pending_interaction",
                    return_value=paused_step,
                ))
                update = stack.enter_context(patch.object(
                    run_step, "update_main_state_state",
                ))
                save = stack.enter_context(patch.object(
                    run_step, "save_main_state",
                ))
                resume = stack.enter_context(patch.object(
                    run_step, "resolve_resume_step_id", return_value=resume_step,
                ))
                apply_mock = stack.enter_context(patch.object(
                    run_step, "apply_user_response_to_main_state",
                    side_effect=apply_response,
                ))
                clear = stack.enter_context(patch.object(
                    run_step, "clear_interaction_file",
                ))
                reset = stack.enter_context(patch.object(
                    run_step, "reset_step_state_for_restart",
                ))
                delegate = stack.enter_context(patch.object(
                    run_step, "apply_non_pending_structured_response",
                    return_value=delegated,
                ))
                stderr = stack.enter_context(patch.object(
                    run_step.sys, "stderr", io.StringIO(),
                ))
                result = run_step.apply_structured_user_response_if_present(
                    args, "/project", "/report", main_state, "step4",
                    user_response=supplied_response,
                )
                return result, main_state, {
                    "resolve": resolve, "options": options,
                    "validate": validate, "current": current,
                    "update": update, "save": save, "resume": resume,
                    "apply": apply_mock, "clear": clear, "reset": reset,
                    "delegate": delegate, "stderr": stderr.getvalue(),
                }

        result, _state, calls = invoke()
        self.assertEqual(result["step_id"], "step4")
        calls["delegate"].assert_not_called()

        pending = {"step_id": "step3", "options": []}
        result, _state, calls = invoke(pending=pending)
        self.assertIs(result["pending_interaction"], pending)
        calls["options"].assert_not_called()

        result, _state, calls = invoke(
            response={}, response_file="response.json",
            resolved_response={"action": "continue"},
        )
        self.assertEqual(result["step_id"], "delegated")
        calls["resolve"].assert_called_once()
        calls["delegate"].assert_called_once()

        result, _state, calls = invoke(
            response={"action": "continue"}, response_json="{}",
        )
        self.assertEqual(result["step_id"], "delegated")
        calls["resolve"].assert_not_called()

        invalid_pending = {
            "step_id": "step3",
            "options": [
                None,
                {"id": "unavailable", "label": "skip"},
                {"id": "continue", "label": "Proceed"},
                {"id": "cancel"},
                {"id": "custom"},
            ],
        }
        result, _state, calls = invoke(
            pending=invalid_pending, response={"action": "invalid"},
            response_json="{}", available=("continue", "cancel", "custom"),
        )
        self.assertEqual(result["early_exit_code"], 1)
        self.assertIn("Proceed", calls["stderr"])
        self.assertIn("custom", calls["stderr"])
        calls["validate"].assert_not_called()

        for paused_step, current_step, expected_current in (
            ("step3", "step4", "step3"),
            ("", "step4", "step4"),
        ):
            with self.subTest(paused_step=paused_step):
                result, _state, calls = invoke(
                    pending={"step_id": "step3", "options": []},
                    response={"action": "cancel"}, response_json="{}",
                    available=(), paused_step=paused_step,
                    state_fields={
                        "current_step": current_step,
                        "completed_step": "step2",
                    },
                )
                self.assertEqual(result["early_exit_code"], 0)
                self.assertEqual(
                    calls["update"].call_args.kwargs["current_step"],
                    expected_current,
                )
                calls["save"].assert_called_once()

        result, _state, calls = invoke(
            pending={"step_id": "step3", "options": []},
            response={"action": "cancel"}, response_json="{}",
            available=("cancel",), paused_step="step3",
            state_fields={"current_step": "step4", "completed_step": "step2"},
        )
        self.assertEqual(result["early_exit_code"], 0)
        calls["validate"].assert_called_once()

        result, _state, calls = invoke(
            pending={"step_id": "step3", "options": []},
            response={}, response_json="{}", available=(),
            resolved_response={"action": "continue"}, after_pending={"next": 1},
        )
        self.assertEqual(result["response_action"], "continue")
        self.assertEqual(result["resumed_interaction_step_id"], "step3")
        self.assertEqual(result["pending_interaction"], {"next": 1})
        calls["resolve"].assert_called_once()
        calls["clear"].assert_called_once_with("/report")
        calls["reset"].assert_not_called()

        result, _state, calls = invoke(
            pending={"options": []},
            response={"action": "continue"}, response_json="{}",
            available=(), resume_step="step2", after_pending=None,
        )
        self.assertEqual(
            calls["apply"].call_args.kwargs["target_step_id"], "step2"
        )

        for target_input in ({"kept": 1}, {}, missing):
            with self.subTest(target_input=target_input):
                result, state, calls = invoke(
                    pending={"step_id": "step3", "options": []},
                    response={"action": "restart_from_step"},
                    response_json="{}", available=(), resume_step="step2",
                    target_input=target_input,
                )
                self.assertEqual(result["step_id"], "step2")
                expected = {} if target_input is missing else dict(target_input)
                calls["reset"].assert_called_once_with(
                    state, "step2", "/report", preserve_current_input=expected,
                )


if __name__ == "__main__":
    unittest.main()
