from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import run_step


class RunStepRemainingBoundaryTest(unittest.TestCase):
    def test_error_boolean_integer_and_explicit_value_contract_matrix(self):
        error = run_step.StepError(
            "failed",
            reason_codes=[None, "", " CODE ", "CODE", 7, " 7 "],
            diagnostic={"field": "value"},
        )
        self.assertEqual(str(error), "failed")
        self.assertEqual(error.reason_codes, ["None", "CODE", "7"])
        self.assertEqual(error.diagnostic, {"field": "value"})
        self.assertEqual(run_step.StepError("plain").reason_codes, [])

        interactions = (
            ({"question": "Question", "title": "Title"}, "Question"),
            ({"question": "", "title": "Title"}, "Title"),
            ({}, "需要用户补充信息"),
            (None, "需要用户补充信息"),
        )
        for interaction, expected in interactions:
            with self.subTest(interaction=interaction):
                raised = run_step.StepInteractionRequired(interaction)
                self.assertEqual(str(raised), expected)
                self.assertIs(raised.interaction, interaction)

        for value in (True, "1", " TRUE ", "yes", "Y", "on"):
            with self.subTest(true=value):
                self.assertIs(run_step.parse_bool_like(value, "flag"), True)
        for value in (False, "0", " FALSE ", "no", "N", "off"):
            with self.subTest(false=value):
                self.assertIs(run_step.parse_bool_like(value, "flag"), False)
        for value in (None, 1, "", "truth"):
            with self.subTest(invalid_bool=value), self.assertRaises(run_step.StepError):
                run_step.parse_bool_like(value, "flag")

        for value, expected in ((1, 1), (27, 27), ("1", 1), (" 42 ", 42)):
            with self.subTest(positive=value):
                self.assertEqual(
                    run_step.parse_positive_int_like(value, "count"), expected,
                )
        for value in (True, False, 0, -1, None, "", "0", "-1", "1.5"):
            with self.subTest(invalid_positive=value), self.assertRaises(run_step.StepError):
                run_step.parse_positive_int_like(value, "count")

        cases = (
            (" value ", None, None, "field", True),
            ("", {"field": " seed "}, None, "field", True),
            (None, {}, {"field": " previous "}, "field", True),
            (None, None, {"field_explicit": True}, "field", True),
            (None, {"field": ""}, None, "field", False),
            (None, None, None, "field", False),
            (None, {"field": []}, {"field": " "}, "field", False),
        )
        for cli, seed, previous, key, expected in cases:
            with self.subTest(cli=cli, seed=seed, previous=previous):
                self.assertIs(
                    run_step._has_explicit_string_value(
                        cli, seed, previous, key,
                    ),
                    expected,
                )

    def test_git_endpoint_clone_persistence_and_detection_matrix(self):
        self.assertEqual(run_step._artifact_name_from_coord(None), "")
        self.assertEqual(run_step._artifact_name_from_coord("group"), "")
        self.assertEqual(run_step._artifact_name_from_coord(" g : artifact : 1 "), "artifact")

        canonical_cases = (
            (None, ""),
            ("HTTPS://User:secret@Example.COM/repo.git?z=2&token=x&a=1#frag",
             "https://example.com/repo.git?a=1&z=2"),
            ("git@Example.COM:org/repo.git", "example.com:org/repo.git"),
            ("host:path/repo.git", "host:path/repo.git"),
            ("/local/repo", "/local/repo"),
        )
        for value, expected in canonical_cases:
            with self.subTest(canonical=value):
                self.assertEqual(run_step._canonical_git_endpoint(value), expected)

        clone_cases = (
            (None, ""),
            ("https://example/repo.git", "https://example/repo.git"),
            ("alice@example.com:repo.git", "alice@example.com:repo.git"),
            ("example.com:repo.git", "git@example.com:repo.git"),
            ("C:/repo", "C:/repo"),
            ("relative/repo", "relative/repo"),
        )
        for value, expected in clone_cases:
            with self.subTest(clone=value):
                self.assertEqual(run_step._git_clone_transport_url(value), expected)

        persisted_cases = (
            ("example.com:repo.git", "git@example.com:repo.git"),
            ("https://user:pw@example.com/repo?token=x&b=2", "https://example.com/repo?b=2"),
            ("ssh://alice:pw@example.com/repo?secret=x&a=1", "ssh://alice@example.com/repo?a=1"),
            ("ssh://:pw@example.com/repo", "ssh://example.com/repo"),
        )
        for value, expected in persisted_cases:
            with self.subTest(persisted=value):
                self.assertEqual(run_step._persistable_git_transport_url(value), expected)

        self.assertTrue(run_step._is_redacted_git_display_url("https://***@host/repo"))
        self.assertTrue(run_step._is_redacted_git_display_url("https://host/repo?access_token=***"))
        self.assertFalse(run_step._is_redacted_git_display_url("https://host/repo?token=visible"))
        self.assertFalse(run_step._is_redacted_git_display_url(None))
        self.assertEqual(run_step._normalized_secret_key(None), "")

        with patch.object(run_step, "run_cmd", return_value=("git@HOST:org/repo\n", "", 0)):
            self.assertEqual(
                run_step._git_repository_display("."), "host:org/repo",
            )
        with patch.object(run_step, "run_cmd", return_value=("", "fatal", 1)):
            self.assertEqual(
                run_step._git_repository_display("."), str(Path(".").resolve()),
            )
        with patch.object(run_step, "run_cmd", return_value=("", "", 0)):
            self.assertEqual(
                run_step._git_repository_display("."), str(Path(".").resolve()),
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = root / "host:repo"
            local.mkdir()
            values = (
                ("ordinary", False),
                ("https://example/repo.git", True),
                ("ssh://example/repo.git", True),
                ("git://example/repo.git", True),
                ("file:///tmp/repo.git", True),
                ("git@example.com:repo.git", True),
                ("alice@example.com:repo.git", True),
                ("example.com:repo.git", True),
                ("host:repo", False),
                ("missing:repo", True),
                ("/missing/repo.git", True),
            )
            for value, expected in values:
                with self.subTest(dependency_source=value):
                    self.assertIs(
                        run_step.is_dependency_source_git_url(value, root),
                        expected,
                    )
            self.assertFalse(run_step.is_dependency_source_git_url(None, root))
            self.assertTrue(run_step.is_dependency_source_git_url("missing.git", None))
            self.assertFalse(run_step.looks_like_remote_repo(None))
            self.assertTrue(run_step.looks_like_remote_repo("missing.git"))

        self.assertEqual(
            run_step._persistable_git_transport_url("ssh://example.com/repo"),
            "ssh://example.com/repo",
        )

    def test_cli_seed_artifact_and_pinned_path_matrix(self):
        self.assertEqual(run_step.flatten_cli_values(None), [])
        self.assertEqual(
            run_step.flatten_cli_values([
                None, " a ", ["b", "", None], (" c ",), 7,
            ]),
            ["a", "b", "c", "7"],
        )

        report = Path("report")
        self.assertEqual(run_step.artifact_path(report, "a/b"), report / "a/b")
        self.assertEqual(run_step.artifact_path(report, "a/b/"), report / "a/b")
        self.assertEqual(run_step.artifact_path(report, "/a/b"), Path("/a/b"))
        self.assertEqual(run_step.artifact_path(report, None), report)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed = root / "seed.json"
            seed.write_text(json.dumps({"value": 1}), encoding="utf-8")
            self.assertEqual(run_step.load_seed_json_arg(None, root), {})
            self.assertEqual(run_step.load_seed_json_arg("seed.json", root), {"value": 1})
            self.assertEqual(run_step.load_seed_json_arg(str(seed.resolve()), root), {"value": 1})
            self.assertEqual(run_step.load_seed_json_arg('{"value": 2}', root), {"value": 2})
            for value in ("not-json", "[]"):
                with self.subTest(seed=value), self.assertRaises(run_step.StepError):
                    run_step.load_seed_json_arg(value, root)

            project = root / "project"
            inside = project / "src" / "main"
            outside = root / "outside"
            inside.mkdir(parents=True)
            outside.mkdir()
            self.assertEqual(
                run_step._relative_path_inside(project, project, label="source"),
                ".",
            )
            self.assertEqual(
                run_step._relative_path_inside(project, inside, label="source"),
                "src/main",
            )
            with self.assertRaises(run_step.StepError) as captured:
                run_step._relative_path_inside(project, outside, label="source")
            self.assertEqual(
                captured.exception.reason_codes,
                ["PINNED_SOURCE_PATH_OUTSIDE_PROJECT"],
            )

        normalized = (
            (None, True, "."),
            ("./", False, ""),
            ("a//./b", True, "a/b"),
            ("././", True, ""),
            ("/absolute", True, ""),
            ("C:\\absolute", True, ""),
            ("a/../b", True, ""),
        )
        for value, allow_root, expected in normalized:
            with self.subTest(path=value, allow_root=allow_root):
                self.assertEqual(
                    run_step._normalized_pinned_relative_path(
                        value, allow_root=allow_root,
                    ),
                    expected,
                )

    def test_pending_interaction_and_user_field_projection_matrix(self):
        interactions = (
            ({"options": [{"id": "retry"}, {"id": "continue"}]}, "continue"),
            ({"options": [{"id": " retry "}, {"id": "cancel"}]}, "retry"),
            ({"options": []}, "continue"),
            ({"options": [None, "malformed", {"id": ""}]}, "continue"),
            (None, "continue"),
        )
        for interaction, expected in interactions:
            with self.subTest(default=interaction):
                self.assertEqual(
                    run_step.default_interaction_action(interaction), expected,
                )
        self.assertEqual(
            run_step.interaction_option_ids({
                "options": [None, "malformed", {"id": " continue "}, {"id": ""}, {}],
            }),
            {"continue"},
        )
        self.assertEqual(run_step.interaction_option_ids(None), set())
        self.assertEqual(run_step.interaction_option_ids({"options": None}), set())

        with patch.object(run_step, "next_step_id_for", return_value="step2"):
            self.assertEqual(
                run_step.current_step_for_pending_interaction(
                    "step1", {"kind": "input_request", "options": [{"id": "continue"}]},
                ),
                "step1",
            )
            self.assertEqual(
                run_step.current_step_for_pending_interaction(
                    "step1", {"type": "review", "options": [{"id": "retry"}]},
                ),
                "step1",
            )
            self.assertEqual(
                run_step.current_step_for_pending_interaction(
                    "step1", {"options": [{"id": "continue"}]},
                ),
                "step2",
            )
        with patch.object(run_step, "next_step_id_for", return_value=None):
            self.assertEqual(
                run_step.current_step_for_pending_interaction(
                    "step6", {"options": [{"id": "continue"}]},
                ),
                "step6",
            )
        self.assertEqual(
            run_step.current_step_for_pending_interaction("step1", None),
            "step1",
        )

        self.assertEqual(run_step._user_field_label("base_branch"), "基准分支")
        self.assertEqual(run_step._user_field_label(" custom "), "custom")
        self.assertEqual(run_step._user_field_label(None), "")
        self.assertEqual(
            run_step._user_field_description("target_module"),
            "要分析的业务模块。",
        )
        self.assertEqual(
            run_step._user_field_description("custom", {"description": " supplied "}),
            "supplied",
        )
        self.assertEqual(run_step._user_field_description("custom"), "")
        self.assertEqual(run_step._user_field_description(None), "")

    def test_response_example_schema_action_and_wrapping_matrix(self):
        self.assertEqual(run_step._response_example_value("target_module"), "app-module")
        self.assertEqual(
            run_step._response_example_value("choice", {"enum": [None, "", "first", "second"]}),
            "first",
        )
        for value_type, expected in (
            ("boolean", True), ("integer", 1), ("number", 1.0),
            ("array", ["<自定义>"]), ("string", "<自定义>"),
        ):
            with self.subTest(value_type=value_type):
                self.assertEqual(
                    run_step._response_example_value(
                        "自定义", {"type": value_type},
                    ),
                    expected,
                )
        self.assertEqual(
            run_step._response_example_value("", {"type": "array"}),
            ["<>"],
        )
        self.assertEqual(
            run_step._response_example_value("", {"type": "string"}),
            "<>",
        )

        wrapped = run_step._wrap_response_payload_as_intent_patch({
            "action": " continue ", "restart_step_id": " step2 ",
            "notes": " note ", "target_module": "app",
        })
        self.assertEqual(wrapped, {"intent_patch": {
            "action": "continue", "restart_step_id": "step2",
            "notes": "note", "set": {"target_module": "app"},
        }})
        self.assertEqual(
            run_step._wrap_response_payload_as_intent_patch(None),
            {"intent_patch": {"action": "", "set": {}}},
        )

        properties = {
            "action": {"type": "string"},
            "primary_module": {"type": "string"},
            "modules": {"type": "array"},
            "dependency_source_dirs": {"type": "array"},
            "base_branch": {"type": "string"},
            "current_branch": {"type": "string"},
            "source_dirs": {"type": "array"},
            "selected_targets": {"type": "array"},
            "step5_selected_coords": {"type": "array"},
            "step5_selected_names": {"type": "array"},
            "strict_risk_gate": {"type": "boolean"},
            "scope_mode": {"type": "string"},
            "notes": {"type": "string"},
            "custom": {"type": "integer"},
        }
        examples = (
            ("rerun_current_step", []),
            ("rerun_current_step", ["custom"]),
            ("restart_from_step", []),
            ("restart_from_step", ["custom"]),
            ("continue", []),
            ("continue", [
                "base_branch", "source_dirs", "dependency_source_dirs",
                "selected_targets", "strict_risk_gate", "custom",
            ]),
            ("continue", ["current_branch", "step5_selected_coords"]),
            ("continue", ["step5_selected_names"]),
            ("cancel", ["custom"]),
            ("custom_action", ["custom"]),
        )
        for action, required in examples:
            with self.subTest(payload_action=action, required=required):
                payload = run_step._response_payload_example(
                    action, required, properties, overrides={"override": True},
                )["intent_patch"]
                self.assertEqual(payload["action"], action)
                self.assertTrue(payload["set"]["override"])
                if "custom" in required:
                    self.assertIn("custom", payload["set"])

        action_examples = (
            ("rerun_current_step", []),
            ("rerun_current_step", ["custom"]),
            ("restart_from_step", []),
            ("restart_from_step", ["custom"]),
            ("continue", []),
            ("continue", ["base_branch", "source_dirs", "dependency_source_dirs", "selected_targets", "strict_risk_gate", "notes", "custom"]),
            ("continue", ["current_branch", "step5_selected_coords"]),
            ("cancel", ["custom"]),
            ("custom_action", ["custom"]),
        )
        for action, required in action_examples:
            with self.subTest(action_example=action, required=required):
                payload = run_step._response_payload_action_example(
                    action, properties, required,
                )["intent_patch"]
                self.assertEqual(payload["action"], action)
                if "custom" in required:
                    self.assertIn("custom", payload["set"])

        for action in ("rerun_current_step", "restart_from_step", "cancel"):
            with self.subTest(action_without_optional_properties=action):
                payload = run_step._response_payload_action_example(
                    action, {}, [],
                )["intent_patch"]
                self.assertEqual(payload["action"], action)
            with self.subTest(payload_without_optional_properties=action):
                payload = run_step._response_payload_example(
                    action, [], {},
                )["intent_patch"]
                self.assertEqual(payload["action"], action)

        no_scope = dict(properties)
        no_scope.pop("scope_mode")
        self.assertNotIn(
            "scope_mode",
            run_step._response_payload_action_example(
                "continue", no_scope, ["selected_targets"],
            )["intent_patch"]["set"],
        )
        self.assertNotIn(
            "scope_mode",
            run_step._response_payload_example(
                "continue", ["selected_targets"], no_scope,
            )["intent_patch"]["set"],
        )

        populated = {"already": "set", "action": "continue"}
        self.assertIs(
            run_step._populate_required_response_example(
                populated,
                [None, "", "action", "already", "custom"],
                properties,
            ),
            populated,
        )
        self.assertEqual(populated["custom"], 1)
        empty_properties = {}
        run_step._populate_required_response_example(
            empty_properties, ["custom"], None,
        )
        self.assertEqual(empty_properties["custom"], "<custom>")

        property_sets = (
            ("continue", {}),
            ("continue", {"base_branch": {}, "selected_targets": {}}),
            ("continue", {"source_dirs": {}, "step5_selected_coords": {}}),
            ("rerun_current_step", {}),
            ("rerun_current_step", {"dependency_source_dirs": {}}),
            ("restart_from_step", {}),
            ("cancel", {}),
            ("unknown", {}),
        )
        for action, action_properties in property_sets:
            with self.subTest(reply=action, properties=action_properties):
                replies = run_step._build_user_reply_examples(
                    action, action_properties,
                )
                self.assertTrue(replies)
                self.assertTrue(all(isinstance(item, str) and item for item in replies))

    def test_version_and_step1_ref_request_matrix(self):
        for version in (None, "", "-"):
            with self.subTest(version=version):
                self.assertEqual(
                    run_step._version_candidate_groups("repo", version),
                    {"status": "not_applicable", "candidates": []},
                )
        with patch.object(run_step, "match_remote_refs_by_version", return_value={"status": "unique"}) as match:
            self.assertEqual(
                run_step._version_candidate_groups("repo", "1.2.3"),
                {"status": "unique"},
            )
        match.assert_called_once_with("repo", "1.2.3")

        request = run_step._version_ref_request(
            "base", "1.0", {
                "candidates": [
                    {"ref": "v1", "commit": "a" * 40},
                    {"selection_key": "provided", "ref": "release", "commit": "b" * 40},
                ],
                "configured_remotes": ["origin"],
            },
            {"base_source_project_dir": "/repo", "base_artifact_path": "/base.jar"},
        )
        self.assertRegex(request["candidates"][0]["selection_key"], r"^s0ref:[0-9a-f]{16}$")
        self.assertEqual(request["candidates"][1]["selection_key"], "provided")
        empty_request = run_step._version_ref_request("base", "1.0", {}, {})
        self.assertEqual(empty_request["candidates"], [])
        self.assertEqual(empty_request["source_project_dir"], "")
        self.assertEqual(empty_request["artifact_path"], "")
        self.assertEqual(empty_request["configured_remotes"], [])

        resolution = {
            "candidates": [
                {"ref": "v1", "commit": "a" * 40},
                {"ref": "v2", "commit": "b" * 40, "selection_key": "will-be-replaced"},
            ],
            "requested_ref": None,
            "failures": [{"remote": "origin"}],
            "resolved_commit": "c" * 40,
            "resolved_ref": "HEAD~1",
            "repository_path": "",
        }
        ordinary = run_step._step1_ref_request(
            "current", "current_branch", "/repo", resolution,
        )
        self.assertEqual(ordinary["status"], "not_found")
        self.assertEqual(ordinary["remote_failures"], [{"remote": "origin"}])
        self.assertTrue(all(
            item["selection_key"].startswith("s1ref:")
            for item in ordinary["candidates"]
        ))
        confirmed = run_step._step1_ref_request(
            "current", "current_branch", "/repo", resolution,
            source_only=True, artifact_path="/current.jar",
        )
        self.assertEqual(confirmed["status"], "confirmation_required")
        self.assertEqual(confirmed["detected_ref"], "HEAD~1")
        self.assertRegex(
            confirmed["candidates"][0]["selection_key"],
            r"^s1ref:[0-9a-f]{16}$",
        )
        fallback_ref = run_step._step1_ref_request(
            "current", "current_branch", "/repo", {
                "local_candidate_commit": "c" * 40,
            }, source_only=True,
        )
        self.assertEqual(fallback_ref["detected_ref"], "HEAD")
        no_commit = run_step._step1_ref_request(
            "base", "base_branch", "", {
                "remote_failures": [{"remote": "upstream"}],
                "local_candidate_commit": "",
            }, source_only=True,
        )
        self.assertEqual(no_commit["repository_path"], "")
        self.assertEqual(no_commit["remote_failures"], [{"remote": "upstream"}])
        populated_resolution = {
            "candidates": [{"ref": "", "commit": ""}],
            "requested_ref": "release",
            "status": "ambiguous",
            "fingerprint": "fingerprint",
            "source_status": "remote",
            "remote_failures": [{"remote": "origin"}],
            "local_candidate_commit": "d" * 40,
            "dirty": True,
            "expected_commit": "e" * 40,
            "observed_commit": "f" * 40,
            "repository_path": "/explicit/repo",
            "configured_remotes": ["origin"],
            "query_mode": "remote",
        }
        populated_request = run_step._step1_ref_request(
            "base", "base_branch", "/source", populated_resolution,
            artifact_path="/base.jar",
        )
        self.assertEqual(populated_request["requested_ref"], "release")
        self.assertEqual(populated_request["repository_path"], "/explicit/repo")
        self.assertEqual(populated_request["configured_remotes"], ["origin"])

        project = Path("/project")
        self.assertEqual(
            run_step._step1_ref_repository(
                {"base_ref_binding": {"repo_dir": "/bound"}}, "base", project,
            ),
            Path("/bound").resolve(),
        )
        self.assertEqual(
            run_step._step1_ref_repository(
                {"base_ref_binding": "legacy", "base_source_project_dir": "/source"},
                "base", project,
            ),
            Path("/source").resolve(),
        )
        self.assertEqual(
            run_step._step1_ref_repository(
                {"base_ref_binding": {}, "base_source_project_dir": "/source"},
                "base", project,
            ),
            Path("/source").resolve(),
        )
        self.assertEqual(
            run_step._step1_ref_repository({}, "base", project),
            project.resolve(),
        )


if __name__ == "__main__":
    unittest.main()
