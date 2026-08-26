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


class RunStepBoundaryTest(unittest.TestCase):
    @staticmethod
    def _identity(version, entry="BOOT-INF/lib/demo.jar"):
        return {
            "side": "current",
            "lib_entry": entry,
            "group_id": "org.example",
            "artifact_id": "demo",
            "version": version,
            "classifier": "",
        }

    @staticmethod
    def _ref_candidate(
        key,
        ref,
        commit,
        *,
        canonical_ref="",
        display_ref="",
        remote="origin",
    ):
        return {
            "selection_key": key,
            "ref": ref,
            "canonical_ref": canonical_ref,
            "display_ref": display_ref,
            "remote": remote,
            "commit": commit,
        }

    @staticmethod
    def _ref_interaction(*items, step_id="step1"):
        return {
            "step_id": step_id,
            "source_ref_decision_items": list(items),
        }

    @staticmethod
    def _validation_interaction(
        *,
        step_id="step3",
        reason_code="",
        properties=None,
        required=None,
        action_requirements=None,
        ref_resolution_requests=None,
    ):
        response_properties = {
            "action": {
                "type": "string",
                "enum": [
                    "continue",
                    "cancel",
                    "confirm_local_source",
                    "rerun_current_step",
                ],
            },
        }
        response_properties.update(dict(properties or {}))
        interaction = {
            "step_id": step_id,
            "reason_code": reason_code,
            "response_schema": {
                "type": "object",
                "required": ["action"] if required is None else list(required),
                "properties": response_properties,
            },
            "action_requirements": dict(action_requirements or {}),
            "ref_resolution_requests": list(ref_resolution_requests or []),
        }
        return interaction

    @staticmethod
    def _run_context_args(project, report, **overrides):
        values = {
            "project_dir": str(project),
            "report_dir": str(report),
            "base_branch": None,
            "current_branch": None,
            "active_maven_profiles": None,
            "dependency_source_dirs": [],
            "dependency_source_clone_timeout": None,
            "base_artifact_path": "",
            "current_artifact_path": "",
            "application_source": "",
            "base_jdk_home": "",
            "current_jdk_home": "",
            "binary_pipeline_config": "",
            "include_test_scope": False,
            "strict_risk_gate": False,
            "target_module": "",
            "base_tool": "",
            "current_tool": "",
            "manual_coord_overrides": [],
            "allow_unresolved": None,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def _build_context(
        self,
        project,
        *,
        existing=None,
        seed=None,
        allow_external_seed=True,
        args_overrides=None,
        detected_tool="maven",
        auto_source=None,
        materialized_source=None,
        remembered_git_root=None,
        dependency_materialization=None,
        pinned=False,
        discovery=None,
        source_dir_plan=None,
        dependency_source_plan=None,
        relevant_coords=None,
        focus_coords=None,
    ):
        project = Path(project)
        report = project / "report"
        args = self._run_context_args(
            project, report, **dict(args_overrides or {}),
        )
        materialized_source = materialized_source or {
            "display": "materialized-source",
            "repo_path": str(project.resolve()),
            "origin": "test",
        }
        dependency_materialization = dependency_materialization or {
            "dependency_source_dirs": [],
            "dependency_source_git_urls": [],
            "dependency_source_git_materializations": [],
        }
        discovery = discovery or {"modules": []}
        source_dir_plan = source_dir_plan or {
            "source_dirs": [], "status": "missing",
        }
        dependency_source_plan = dependency_source_plan or {
            "ambiguous_coords": [],
            "dependency_repo_mappings": [],
            "dependency_source_mappings": [],
        }
        pinned_effect = (
            (lambda value, _root: value)
            if pinned
            else (lambda _value, _root: None)
        )
        with patch.object(
            run_step, "detect_build_tool", return_value=detected_tool,
        ), patch.object(
            run_step, "detect_application_source", return_value=auto_source,
        ), patch.object(
            run_step,
            "materialize_application_source",
            return_value=materialized_source,
        ), patch.object(
            run_step,
            "_git_repository_root",
            return_value=remembered_git_root,
        ), patch.object(
            run_step,
            "materialize_dependency_source_inputs",
            return_value=dependency_materialization,
        ), patch.object(
            run_step, "_apply_pinned_source_snapshot", side_effect=pinned_effect,
        ), patch.object(
            run_step,
            "build_project_scope",
            return_value={"status": "complete", "included_modules": ["app"]},
        ), patch.object(
            run_step, "discover_project_modules", return_value=discovery,
        ), patch.object(
            run_step, "_resolve_source_dirs_plan", return_value=source_dir_plan,
        ), patch.object(
            run_step,
            "_build_dependency_source_plan",
            return_value=dependency_source_plan,
        ), patch.object(
            run_step,
            "_collect_relevant_dependency_coords",
            return_value=list(relevant_coords or []),
        ), patch.object(
            run_step,
            "_collect_focus_dependency_coords",
            return_value=list(focus_coords or []),
        ):
            return run_step.build_run_context(
                args,
                existing,
                seed,
                allow_external_seed=allow_external_seed,
            )

    def test_merge_user_response_complete_positive_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            dependency_source = project / "dependency-source"
            dependency_source.mkdir()
            old_context = {
                "application_source": "old-source",
                "application_source_repo_path": "/old/repo",
                "application_source_materialization": {"status": "done"},
                "application_source_display": "old",
                "base_source_project_dir": "/old/base",
                "current_source_project_dir": "/old/current",
                "base_expected_commit": "a" * 40,
                "base_resolved_commit": "a" * 40,
                "current_expected_commit": "b" * 40,
                "current_resolved_commit": "b" * 40,
                "pinned_source_snapshot": {"commit": "b" * 40},
                "active_maven_profiles": ["old"],
                "source_dirs": ["old/src"],
                "source_dirs_status": "project_scope",
                "dependency_source_git_materializations": [{"url": "old"}],
                "dependency_repo_mappings": ["old:coord=/old/repo"],
                "dependency_source_mappings": ["old:coord=/old/src"],
                "manual_coord_overrides": ["old=org.example:old"],
                "manual_artifact_identities": [self._identity("1.0")],
                "obsolete": "remove-me",
                "input_origins": {},
            }
            response = {
                "__clear_fields": ["obsolete"],
                "__intent_patch": {"action": "continue"},
                "application_source": "https://example.invalid/application.git",
                "binary_pipeline_config": "config/binary.json",
                "base_branch": " main ",
                "current_branch": " upgrade ",
                "target_module": " app ",
                "base_tool": " maven ",
                "current_tool": " gradle ",
                "base_expected_commit": "c" * 40,
                "current_expected_commit": "d" * 40,
                "base_ref_binding": {"side": "base"},
                "current_ref_binding": {"side": "current"},
                "base_jdk_home": "jdks/base",
                "current_jdk_home": "jdks/current",
                "active_maven_profiles": [" prod ", "prod", ""],
                "dependency_source_dirs": [
                    str(dependency_source),
                    "https://example.invalid/dependency.git",
                ],
                "dependency_source_ref_selections": {"coord": "org.example:demo"},
                "step5_selected_coords": "org.example:demo",
                "step5_selected_names": ["Demo", "demo", ""],
                "scope_mode": "partial",
                "base_file": "artifacts/base.txt",
                "current_file": "artifacts/current.txt",
                "base_artifact_path": "artifacts/base.jar",
                "current_artifact_path": "artifacts/current.jar",
                "base_source_project_dir": "work/base",
                "current_source_project_dir": "work/current",
                "include_test_scope": "true",
                "strict_risk_gate": False,
                "base_allow_local_source": True,
                "base_allow_dirty_local_source": "false",
                "current_allow_local_source": True,
                "current_allow_dirty_local_source": False,
                "manual_coord_overrides": "demo=org.example:demo",
                "manual_artifact_identities": [
                    self._identity("2.0"),
                    self._identity("1.0", "BOOT-INF/lib/other.jar"),
                ],
                "action": "confirm_unresolved",
            }

            updated = run_step.merge_user_response_into_run_context(
                old_context, response, project,
            )

            self.assertEqual(
                updated["application_source"],
                "https://example.invalid/application.git",
            )
            self.assertEqual(
                updated["binary_pipeline_config"],
                str((project / "config/binary.json").resolve()),
            )
            self.assertEqual(updated["target_module"], "app")
            self.assertEqual(updated["primary_module"], "app")
            self.assertEqual(updated["modules"], ["app"])
            self.assertTrue(updated["tool_explicit"])
            self.assertTrue(updated["base_branch_explicit"])
            self.assertTrue(updated["current_branch_explicit"])
            self.assertEqual(updated["base_expected_commit"], "c" * 40)
            self.assertEqual(updated["current_expected_commit"], "d" * 40)
            self.assertEqual(updated["active_maven_profiles"], ["prod"])
            self.assertNotIn("source_dirs", updated)
            self.assertNotIn("source_dirs_status", updated)
            self.assertEqual(updated["step5_selected_coords"], ["org.example:demo"])
            self.assertEqual(updated["step5_selected_names"], ["Demo"])
            self.assertEqual(updated["step5_scope_mode"], "partial")
            self.assertTrue(updated["include_test_scope"])
            self.assertFalse(updated["strict_risk_gate"])
            self.assertTrue(updated["base_allow_local_source"])
            self.assertFalse(updated["base_allow_dirty_local_source"])
            self.assertTrue(updated["current_allow_local_source"])
            self.assertFalse(updated["current_allow_dirty_local_source"])
            self.assertEqual(
                updated["manual_coord_overrides"],
                ["old=org.example:old", "demo=org.example:demo"],
            )
            identities = {
                (item["lib_entry"], item["version"])
                for item in updated["manual_artifact_identities"]
            }
            self.assertEqual(
                identities,
                {
                    ("BOOT-INF/lib/demo.jar", "2.0"),
                    ("BOOT-INF/lib/other.jar", "1.0"),
                },
            )
            self.assertTrue(updated["allow_unresolved"])
            self.assertNotIn("obsolete", updated)
            self.assertNotIn("application_source_repo_path", updated)
            self.assertNotIn("application_source_materialization", updated)
            self.assertEqual(
                updated["input_origins"]["application_source"], "user",
            )
            self.assertEqual(
                updated["dependency_source_git_urls"],
                ["https://example.invalid/dependency.git"],
            )
            self.assertEqual(
                updated["dependency_source_ref_selections"],
                [{"coord": "org.example:demo"}],
            )

    def test_merge_bindings_and_skips_preserve_unrelated_coordinates(self):
        initial = {
            "dependency_source_ref_bindings": [
                {"coord": "keep:one", "repo_path": "/repos/keep"},
                {"coord": "change:one", "repo_path": "/repos/old"},
                {},
            ],
            "dependency_repo_mappings": [
                "keep:one=/repos/keep",
                "change:one=/repos/old",
            ],
            "dependency_source_mappings": [
                "keep:one=/repos/keep/src",
                "change:one=/repos/old/src",
            ],
        }
        response = {
            "dependency_source_ref_bindings": [
                {
                    "coord": " change:one ",
                    "repo_path": " /repos/new ",
                    "source_dirs": [" /repos/new/src ", ""],
                },
                {"coord": "new:one", "source_dirs": []},
            ]
        }

        merged = run_step.merge_user_response_into_run_context(
            initial, response, Path("/project"),
        )

        self.assertEqual(
            {item["coord"].strip() for item in merged["dependency_source_ref_bindings"]},
            {"keep:one", "change:one", "new:one"},
        )
        self.assertEqual(
            merged["dependency_repo_mappings"],
            ["keep:one=/repos/keep", "change:one=/repos/new"],
        )
        self.assertEqual(
            merged["dependency_source_mappings"],
            ["keep:one=/repos/keep/src", "change:one=/repos/new/src"],
        )

        skipped = run_step.merge_user_response_into_run_context(
            merged,
            {"skip_dependency_source_coords": [" change:one ", "", "change:one"]},
            Path("/project"),
        )
        self.assertEqual(skipped["skip_dependency_source_coords"], ["change:one"])
        self.assertEqual(
            {item["coord"] for item in skipped["dependency_source_ref_bindings"]},
            {"keep:one", "new:one"},
        )
        self.assertEqual(skipped["dependency_repo_mappings"], ["keep:one=/repos/keep"])
        self.assertEqual(
            skipped["dependency_source_mappings"], ["keep:one=/repos/keep/src"],
        )

        skipped_string = run_step.merge_user_response_into_run_context(
            skipped,
            {"skip_dependency_source_coords": "new:one"},
            Path("/project"),
        )
        self.assertEqual(skipped_string["skip_dependency_source_coords"], ["new:one"])

    def test_merge_noop_and_same_value_matrix(self):
        project = Path("/project")
        self.assertEqual(
            run_step.merge_user_response_into_run_context(None, None, project), {},
        )
        existing = {
            "application_source": "same",
            "base_artifact_path": "/project/base.jar",
            "current_source_project_dir": "/project/current",
            "active_maven_profiles": [],
            "pinned_source_snapshot": {"commit": "a" * 40},
        }
        response = {
            "__intent_patch": {},
            "application_source": "same",
            "binary_pipeline_config": " ",
            "base_branch": 1,
            "current_branch": " ",
            "target_module": None,
            "base_tool": [],
            "base_expected_commit": " ",
            "current_expected_commit": 1,
            "base_ref_binding": [],
            "current_ref_binding": None,
            "base_jdk_home": " ",
            "current_jdk_home": 1,
            "active_maven_profiles": [],
            "dependency_source_ref_selections": [],
            "dependency_source_ref_bindings": [],
            "skip_dependency_source_coords": [],
            "step5_selected_coords": [],
            "step5_selected_names": [],
            "scope_mode": "",
            "base_file": " ",
            "current_file": 1,
            "base_artifact_path": "/project/base.jar",
            "current_source_project_dir": "/project/current",
            "manual_coord_overrides": " ",
            "action": "continue",
        }

        updated = run_step.merge_user_response_into_run_context(
            existing, response, project,
        )

        self.assertEqual(updated["application_source"], "same")
        self.assertEqual(updated["base_artifact_path"], "/project/base.jar")
        self.assertEqual(updated["current_source_project_dir"], "/project/current")
        self.assertEqual(updated["active_maven_profiles"], [])
        self.assertIn("pinned_source_snapshot", updated)
        self.assertNotIn("allow_unresolved", updated)
        self.assertEqual(updated["dependency_source_ref_selections"], [])
        self.assertEqual(updated["dependency_source_ref_bindings"], [])
        self.assertEqual(updated["skip_dependency_source_coords"], [])

    def test_merge_falsy_values_and_degraded_prior_state(self):
        project = Path("/project")
        whitespace = run_step.merge_user_response_into_run_context(
            {"base_artifact_path": "/project/base.jar"},
            {
                "base_artifact_path": " ",
                "application_source": " ",
            },
            project,
        )
        self.assertEqual(whitespace["base_artifact_path"], "/project/base.jar")
        self.assertNotIn("application_source", whitespace)

        new_source = run_step.merge_user_response_into_run_context(
            {}, {"application_source": "new-source"}, project,
        )
        self.assertEqual(new_source["application_source"], "new-source")

        repaired = run_step.merge_user_response_into_run_context(
            {
                "dependency_source_ref_bindings": [
                    None,
                    "invalid",
                    {},
                    {"coord": None},
                    {"coord": "keep:one"},
                ],
            },
            {"dependency_source_ref_bindings": []},
            project,
        )
        self.assertEqual(
            repaired["dependency_source_ref_bindings"],
            [{"coord": "keep:one"}],
        )

        skipped = run_step.merge_user_response_into_run_context(
            {
                "dependency_source_ref_bindings": [
                    None,
                    "invalid",
                    {},
                    {"coord": None},
                    {"coord": "keep:one"},
                    {"coord": "skip:one"},
                ],
            },
            {"skip_dependency_source_coords": ["skip:one"]},
            project,
        )
        self.assertEqual(
            skipped["dependency_source_ref_bindings"],
            [{"coord": "keep:one"}],
        )

        list_overrides = run_step.merge_user_response_into_run_context(
            {},
            {"manual_coord_overrides": [" one ", "", "one", " two "]},
            project,
        )
        self.assertEqual(list_overrides["manual_coord_overrides"], ["one", "two"])

        entry_identity = self._identity("1.0")
        entry_identity["entry_id"] = entry_identity.pop("lib_entry")
        identities = run_step.merge_user_response_into_run_context(
            {}, {"manual_artifact_identities": [entry_identity]}, project,
        )
        self.assertEqual(
            identities["manual_artifact_identities"][0]["lib_entry"],
            "BOOT-INF/lib/demo.jar",
        )

    def test_merge_rejects_malformed_array_contracts(self):
        invalid_payloads = [
            {"active_maven_profiles": "prod"},
            {"active_maven_profiles": ["prod", 1]},
            {"dependency_source_ref_selections": "bad"},
            {"dependency_source_ref_selections": [1]},
            {"dependency_source_ref_bindings": {}},
            {"dependency_source_ref_bindings": [1]},
            {"dependency_source_ref_bindings": [{"coord": ""}]},
            {
                "dependency_source_ref_bindings": [
                    {"coord": "g:a", "source_dirs": "src/main/java"}
                ]
            },
            {
                "dependency_source_ref_bindings": [
                    {"coord": "g:a", "source_dirs": ["src", 1]}
                ]
            },
            {"skip_dependency_source_coords": 1},
            {"skip_dependency_source_coords": [{}]},
            {"manual_coord_overrides": 1},
            {"manual_coord_overrides": ["valid", 1]},
        ]
        for payload in invalid_payloads:
            with self.subTest(payload=payload), self.assertRaises(run_step.StepError):
                run_step.merge_user_response_into_run_context(
                    {}, payload, Path("/project"),
                )

    def test_expand_step1_ref_selection_noop_and_container_contracts(self):
        self.assertEqual(run_step.expand_step1_ref_selections(None, None), {})
        self.assertEqual(
            run_step.expand_step1_ref_selections(
                {"step_id": "step2"}, {"keep": True},
            ),
            {"keep": True},
        )
        invalid_calls = [
            ([], {}),
            ({}, []),
            ({"step_id": "step1", "source_ref_decision_items": {}}, {}),
            (self._ref_interaction(None), {}),
            (self._ref_interaction({"side": ""}), {}),
            (self._ref_interaction({"side": "other"}), {}),
            (
                self._ref_interaction(
                    {"side": "base"}, {"side": "base"},
                ),
                {},
            ),
            (self._ref_interaction({"side": "base", "candidates": {}}), {}),
            (self._ref_interaction({"side": "base", "candidates": [None]}), {}),
            (
                self._ref_interaction({
                    "side": "base",
                    "candidates": [
                        {"selection_key": "same"},
                        {"selection_key": " same "},
                    ],
                }),
                {},
            ),
        ]
        for interaction, response in invalid_calls:
            with self.subTest(interaction=interaction, response=response):
                with self.assertRaises(run_step.StepError):
                    run_step.expand_step1_ref_selections(interaction, response)

    def test_expand_step1_ref_selection_rejects_invalid_choices(self):
        commit = "a" * 40
        interaction = self._ref_interaction({
            "side": "current",
            "candidates": [
                self._ref_candidate("one", "origin/one", commit),
                self._ref_candidate("two", "origin/two", "b" * 40),
            ],
        })
        invalid_selections = [
            1,
            [None],
            {},
            {"side": "base", "selection_key": "one"},
            [
                {"side": "current", "selection_key": "one"},
                {"side": "current", "selection_key": "two"},
            ],
            {"side": "current", "selection_key": "missing"},
            {"side": "current"},
            {"side": "current", "option": True},
            {"side": "current", "option": 1.0},
            {"side": "current", "option": "one"},
            {"side": "current", "option": 0},
            {"side": "current", "option": 3},
        ]
        for selection in invalid_selections:
            with self.subTest(selection=selection), self.assertRaises(
                run_step.StepError
            ):
                run_step.expand_step1_ref_selections(
                    interaction, {"source_ref_selections": selection},
                )

        incomplete_candidates = [
            self._ref_candidate("missing-ref", "", commit),
            self._ref_candidate("missing-commit", "origin/main", ""),
        ]
        for candidate in incomplete_candidates:
            broken = self._ref_interaction({
                "side": "base", "candidates": [candidate],
            })
            with self.subTest(candidate=candidate), self.assertRaises(
                run_step.StepError
            ):
                run_step.expand_step1_ref_selections(
                    broken,
                    {
                        "source_ref_selections": {
                            "side": "base",
                            "selection_key": candidate["selection_key"],
                        }
                    },
                )

    def test_expand_step1_ref_selection_key_and_rank_bind_exact_candidates(self):
        base_commit = "a" * 40
        current_commit = "c" * 40
        interaction = self._ref_interaction(
            {
                "side": "base",
                "field": "base_custom_ref",
                "source_project_dir": "/repos/base",
                "artifact_path": "/artifacts/base.jar",
                "candidates": [self._ref_candidate(
                    "base-one",
                    "",
                    base_commit,
                    display_ref="origin/base",
                    canonical_ref="refs/heads/base",
                )],
            },
            {
                "side": "current",
                "source_project_dir": "/repos/current-card",
                "artifact_path": "/artifacts/current-card.jar",
                "candidates": [
                    self._ref_candidate(
                        "current-one", "origin/old", "b" * 40,
                    ),
                    self._ref_candidate(
                        "current-two",
                        "origin/current",
                        current_commit,
                        canonical_ref="refs/heads/current",
                    ),
                ],
            },
            step_id="step0",
        )
        response = run_step.expand_step1_ref_selections(
            interaction,
            {
                "source_ref_selections": [
                    {"side": "base", "selection_key": "base-one"},
                    {"side": "current", "rank": "2"},
                ],
                "current_source_project_dir": "/repos/current-response",
                "current_artifact_path": "/artifacts/current-response.jar",
            },
        )

        self.assertEqual(response["base_custom_ref"], "origin/base")
        self.assertEqual(response["base_expected_commit"], base_commit)
        self.assertEqual(response["current_branch"], "origin/current")
        self.assertEqual(response["current_expected_commit"], current_commit)
        self.assertEqual(
            response["base_ref_binding"]["repo_dir"], "/repos/base",
        )
        self.assertEqual(
            response["base_ref_binding"]["artifact_path"],
            "/artifacts/base.jar",
        )
        self.assertEqual(
            response["current_ref_binding"]["repo_dir"],
            "/repos/current-response",
        )
        self.assertEqual(
            response["current_ref_binding"]["artifact_path"],
            "/artifacts/current-response.jar",
        )

    def test_expand_step1_retry_remote_fetch_requires_unique_ref_and_commit(self):
        commit = "d" * 40
        eligible_statuses = (
            "remote_fetch_failed",
            "remote_query_failed",
            "remote_expected_commit_unmaterializable",
        )
        for status in eligible_statuses:
            interaction = self._ref_interaction({
                "side": "base",
                "source_status": status,
                "source_project_dir": "/repo",
                "candidates": [self._ref_candidate(
                    "one",
                    "origin/main",
                    commit,
                    canonical_ref="refs/heads/main",
                )],
            })
            with self.subTest(status=status):
                response = run_step.expand_step1_ref_selections(
                    interaction, {"retry_remote_fetch": True},
                )
                self.assertEqual(response["base_branch"], "origin/main")
                self.assertEqual(response["base_expected_commit"], commit)
                self.assertEqual(
                    response["base_ref_binding"]["expected_commit"], commit,
                )

        non_unique_candidates = [
            [],
            [self._ref_candidate("one", "origin/main", "")],
            [self._ref_candidate("one", "", commit)],
            [
                self._ref_candidate("one", "origin/main", commit),
                self._ref_candidate("two", "origin/main", "e" * 40),
            ],
            [
                self._ref_candidate("one", "origin/main", commit),
                self._ref_candidate("two", "origin/other", commit),
            ],
        ]
        for candidates in non_unique_candidates:
            interaction = self._ref_interaction({
                "side": "base",
                "source_status": "remote_fetch_failed",
                "candidates": candidates,
            })
            with self.subTest(candidates=candidates):
                response = run_step.expand_step1_ref_selections(
                    interaction, {"retry_remote_fetch": True},
                )
                self.assertNotIn("base_branch", response)
                self.assertNotIn("base_expected_commit", response)

        ignored = run_step.expand_step1_ref_selections(
            self._ref_interaction({
                "side": "current",
                "source_status": "resolved",
                "candidates": [self._ref_candidate(
                    "one", "origin/main", commit,
                )],
            }),
            {"retry_remote_fetch": True},
        )
        self.assertNotIn("current_branch", ignored)

    def test_expand_step1_manual_ref_binding_matrix(self):
        commit = "f" * 40
        candidate = self._ref_candidate(
            "one",
            "origin/release",
            commit,
            canonical_ref="refs/heads/release",
            display_ref="release",
        )
        interaction = self._ref_interaction({
            "side": "current",
            "source_project_dir": "/repo",
            "artifact_path": "/artifact.jar",
            "candidates": [candidate],
        })
        for selected_ref in (
            "origin/release", "refs/heads/release", "release",
        ):
            with self.subTest(selected_ref=selected_ref):
                response = run_step.expand_step1_ref_selections(
                    interaction,
                    {
                        "current_branch": selected_ref,
                        "current_expected_commit": " ",
                    },
                )
                self.assertEqual(response["current_expected_commit"], commit)
                self.assertEqual(
                    response["current_ref_binding"]["requested_ref"], selected_ref,
                )

        ambiguous = self._ref_interaction({
            "side": "base",
            "candidates": [
                self._ref_candidate("one", "shared", commit),
                self._ref_candidate("two", "shared", "1" * 40),
            ],
        })
        ambiguous_response = run_step.expand_step1_ref_selections(
            ambiguous, {"base_branch": "shared"},
        )
        self.assertNotIn("base_expected_commit", ambiguous_response)
        self.assertNotIn("base_ref_binding", ambiguous_response)

        duplicate_match = self._ref_interaction({
            "side": "base",
            "candidates": [
                self._ref_candidate("one", "shared", commit),
                self._ref_candidate("two", "shared", commit),
            ],
        })
        duplicate_response = run_step.expand_step1_ref_selections(
            duplicate_match, {"base_branch": "shared"},
        )
        self.assertEqual(duplicate_response["base_expected_commit"], commit)
        self.assertNotIn("base_ref_binding", duplicate_response)

        mismatched = run_step.expand_step1_ref_selections(
            interaction,
            {
                "current_branch": "origin/release",
                "current_expected_commit": "0" * 40,
            },
        )
        self.assertNotIn("current_ref_binding", mismatched)

        empty = run_step.expand_step1_ref_selections(
            interaction, {"current_branch": ""},
        )
        self.assertNotIn("current_expected_commit", empty)

    def test_expand_step1_sparse_candidate_boundaries(self):
        commit = "2" * 40
        sparse = self._ref_interaction({
            "side": "base",
            "candidates": [
                {
                    "selection_key": "",
                    "ref": "origin/ignored",
                    "commit": commit,
                },
                self._ref_candidate(
                    "chosen",
                    "origin/chosen",
                    commit,
                    canonical_ref="refs/heads/chosen",
                ),
            ],
        })
        chosen = run_step.expand_step1_ref_selections(
            sparse,
            {
                "source_ref_selections": {
                    "side": "base", "selection_key": "chosen",
                }
            },
        )
        self.assertEqual(chosen["base_branch"], "origin/chosen")

        empty_candidates = self._ref_interaction({"side": "base"})
        with self.assertRaises(run_step.StepError):
            run_step.expand_step1_ref_selections(
                empty_candidates,
                {
                    "source_ref_selections": {
                        "side": "base", "selection_key": "missing",
                    }
                },
            )

        no_status = run_step.expand_step1_ref_selections(
            empty_candidates, {"retry_remote_fetch": True},
        )
        self.assertNotIn("base_branch", no_status)

        custom_retry = run_step.expand_step1_ref_selections(
            self._ref_interaction({
                "side": "base",
                "field": "base_custom_ref",
                "source_status": "remote_fetch_failed",
                "candidates": [self._ref_candidate(
                    "one", "origin/main", commit,
                )],
            }),
            {"retry_remote_fetch": True},
        )
        self.assertEqual(custom_retry["base_custom_ref"], "origin/main")

        canonical_only = self._ref_interaction({
            "side": "base",
            "candidates": [{
                "selection_key": "canonical",
                "ref": "",
                "canonical_ref": "refs/heads/main",
                "display_ref": "",
                "commit": commit,
            }],
        })
        canonical = run_step.expand_step1_ref_selections(
            canonical_only, {"base_branch": "refs/heads/main"},
        )
        self.assertEqual(canonical["base_expected_commit"], commit)
        self.assertIn("base_ref_binding", canonical)

        missing_commit = self._ref_interaction({
            "side": "base",
            "candidates": [{
                "selection_key": "missing-commit",
                "ref": "origin/main",
                "commit": "",
            }],
        })
        unresolved = run_step.expand_step1_ref_selections(
            missing_commit, {"base_branch": "origin/main"},
        )
        self.assertNotIn("base_expected_commit", unresolved)
        no_final_match = run_step.expand_step1_ref_selections(
            missing_commit,
            {"base_branch": "origin/main", "base_expected_commit": commit},
        )
        self.assertNotIn("base_ref_binding", no_final_match)

        wrong_ref = run_step.expand_step1_ref_selections(
            self._ref_interaction({
                "side": "base",
                "candidates": [self._ref_candidate(
                    "one", "origin/main", commit,
                )],
            }),
            {"base_branch": "origin/other", "base_expected_commit": commit},
        )
        self.assertNotIn("base_ref_binding", wrong_ref)

        unknown_manual_ref = run_step.expand_step1_ref_selections(
            self._ref_interaction({
                "side": "base",
                "candidates": [self._ref_candidate(
                    "one", "origin/main", commit,
                )],
            }),
            {"base_branch": "origin/not-on-card"},
        )
        self.assertNotIn("base_expected_commit", unknown_manual_ref)

    def test_build_run_context_normalizes_seeded_contracts(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            dependency = project / "dependency"
            dependency.mkdir()
            identity = self._identity("1.0")
            context = self._build_context(
                project,
                seed={
                    "base_branch": "seed-base",
                    "current_branch": "seed-current",
                    "base_artifact_path": "artifacts/base.jar",
                    "current_artifact_path": "artifacts/current.jar",
                    "application_source": "https://example.invalid/app.git",
                    "base_jdk_home": "jdks/base",
                    "current_jdk_home": "jdks/current",
                    "base_tool": "maven",
                    "current_tool": "gradle",
                    "target_module": "app",
                    "active_maven_profiles": [" prod ", "", "prod"],
                    "manual_coord_overrides": "demo=org.example:demo",
                    "manual_artifact_identities": [identity],
                    "confirmed_unresolved_items": [{"entry_id": "one"}],
                    "dependency_source_ref_bindings": [{"coord": "g:a"}],
                    "skip_dependency_source_coords": " skip:one ",
                    "allow_unresolved": "true",
                    "include_test_scope": "true",
                    "strict_risk_gate": "false",
                    "dependency_source_clone_timeout": "7",
                    "dependency_source_git_urls": [
                        "https://user:secret@example.invalid/remembered.git"
                    ],
                    "input_origins": {"preserved": "runtime"},
                },
                args_overrides={
                    "base_branch": "cli-base",
                    "current_branch": "cli-current",
                },
                dependency_materialization={
                    "dependency_source_dirs": [str(dependency)],
                    "dependency_source_git_urls": [
                        "https://example.invalid/materialized.git"
                    ],
                    "dependency_source_git_materializations": [],
                },
                pinned=True,
            )

        self.assertEqual(context["base_branch"], "cli-base")
        self.assertEqual(context["current_branch"], "cli-current")
        self.assertEqual(context["active_maven_profiles"], ["prod"])
        self.assertEqual(
            context["manual_coord_overrides"], ["demo=org.example:demo"],
        )
        self.assertEqual(context["skip_dependency_source_coords"], ["skip:one"])
        self.assertEqual(
            context["dependency_source_ref_bindings"], [{"coord": "g:a"}],
        )
        self.assertEqual(
            context["confirmed_unresolved_items"], [{"entry_id": "one"}],
        )
        self.assertTrue(context["allow_unresolved"])
        self.assertTrue(context["include_test_scope"])
        self.assertFalse(context["strict_risk_gate"])
        self.assertTrue(context["artifact_input_mode"])
        self.assertEqual(context["target_module"], "app")
        self.assertEqual(context["modules"], ["app"])
        self.assertEqual(context["input_origins"]["preserved"], "runtime")
        self.assertEqual(context["input_origins"]["base_branch"], "user")
        self.assertEqual(
            context["dependency_source_git_urls"],
            [
                "https://example.invalid/materialized.git",
                "https://example.invalid/remembered.git",
            ],
        )

    def test_build_run_context_rejects_malformed_state_contracts(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            invalid_calls = [
                {"existing": []},
                {"seed": []},
                {"seed": {"manual_coord_overrides": 1}},
                {"seed": {"manual_coord_overrides": ["valid", 1]}},
                {"seed": {"active_maven_profiles": "prod"}},
                {"seed": {"active_maven_profiles": ["prod", 1]}},
                {"seed": {"confirmed_unresolved_items": {}}},
                {"seed": {"confirmed_unresolved_items": [1]}},
                {"seed": {"dependency_source_ref_bindings": {}}},
                {"seed": {"dependency_source_ref_bindings": [1]}},
                {"seed": {"skip_dependency_source_coords": 1}},
                {"seed": {"skip_dependency_source_coords": [1]}},
                {"seed": {"input_origins": []}},
                {"seed": {"base_artifact_path": 1}},
                {"seed": {"dependency_repo_mappings": ["g:a="]}},
                {"seed": {"dependency_source_mappings": ["g:a="]}},
            ]
            for call in invalid_calls:
                with self.subTest(call=call), self.assertRaises(run_step.StepError):
                    self._build_context(project, **call)

            ignored_seed = self._build_context(
                project,
                existing={"base_branch": "persisted"},
                seed=[],
                allow_external_seed=False,
                args_overrides={
                    "base_branch": "ignored-cli",
                    "active_maven_profiles": ["ignored"],
                    "manual_coord_overrides": ["ignored"],
                },
                pinned=True,
            )
        self.assertEqual(ignored_seed["base_branch"], "persisted")
        self.assertEqual(ignored_seed["active_maven_profiles"], [])
        self.assertEqual(ignored_seed["manual_coord_overrides"], [])

    def test_build_run_context_application_source_detection_and_reuse_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            detected_repo = project / "detected"
            detected_repo.mkdir()
            detected = self._build_context(
                project,
                seed={"base_source_project_dir": "/preserved/base"},
                auto_source={
                    "display": "detected-source",
                    "repo_path": detected_repo,
                },
                pinned=True,
            )
            self.assertEqual(detected["application_source"], "detected-source")
            self.assertEqual(
                detected["base_source_project_dir"], "/preserved/base",
            )
            self.assertEqual(
                detected["current_source_project_dir"], str(detected_repo),
            )
            self.assertEqual(
                detected["input_origins"]["application_source"], "detected",
            )

            remembered = project / "remembered"
            remembered.mkdir()
            reused = self._build_context(
                project,
                seed={
                    "application_source": "https://example.invalid/app.git",
                    "application_source_display": "remembered-display",
                    "application_source_repo_path": str(remembered),
                },
                remembered_git_root=remembered,
                pinned=True,
            )
            self.assertEqual(
                Path(reused["application_source_repo_path"]).resolve(),
                remembered.resolve(),
            )
            self.assertEqual(reused["application_source"], "remembered-display")
            self.assertEqual(
                reused["application_source_materialization"]["origin"],
                "remembered",
            )

            rematerialized = self._build_context(
                project,
                seed={
                    "application_source": "https://example.invalid/app.git",
                    "application_source_repo_path": str(project / "missing"),
                },
                materialized_source={
                    "display": "fresh-display",
                    "repo_path": str(project / "fresh"),
                    "origin": "user_git",
                },
                pinned=True,
            )
            self.assertEqual(rematerialized["application_source"], "fresh-display")
            self.assertEqual(
                rematerialized["application_source_materialization"]["origin"],
                "user_git",
            )

            nongit = project / "nongit"
            nongit.mkdir()
            rejected_remembered = self._build_context(
                project,
                seed={
                    "application_source": "local-source",
                    "application_source_repo_path": str(nongit),
                },
                remembered_git_root=None,
                pinned=True,
            )
            self.assertEqual(
                rejected_remembered["application_source"], "materialized-source",
            )

            inverse_detected = self._build_context(
                project,
                seed={"current_source_project_dir": "/preserved/current"},
                auto_source={
                    "display": "inverse-detected",
                    "repo_path": detected_repo,
                },
                pinned=True,
            )
            self.assertEqual(
                inverse_detected["base_source_project_dir"], str(detected_repo),
            )
            self.assertEqual(
                inverse_detected["current_source_project_dir"],
                "/preserved/current",
            )

            fallback_display = self._build_context(
                project,
                seed={
                    "application_source": "fallback-source",
                    "application_source_repo_path": str(remembered),
                },
                remembered_git_root=remembered,
                pinned=True,
            )
            self.assertEqual(fallback_display["application_source"], "fallback-source")

    def test_build_run_context_branch_and_tool_origin_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            same = self._build_context(
                project,
                existing={
                    "base_branch": "main",
                    "base_branch_explicit": True,
                    "base_expected_commit": "a" * 40,
                },
                args_overrides={"base_branch": "main"},
                pinned=True,
            )
            self.assertEqual(same["base_expected_commit"], "a" * 40)

            changed = self._build_context(
                project,
                existing={
                    "current_branch": "old",
                    "current_branch_explicit": True,
                    "current_expected_commit": "b" * 40,
                    "pinned_source_snapshot": {"commit": "b" * 40},
                },
                args_overrides={"current_branch": "new"},
                pinned=True,
            )
            self.assertEqual(changed["current_branch"], "new")
            self.assertNotIn("current_expected_commit", changed)
            self.assertNotIn("pinned_source_snapshot", changed)

            detected = self._build_context(
                project, detected_tool="gradle", pinned=True,
            )
            self.assertEqual(detected["base_tool"], "gradle")
            self.assertEqual(detected["current_tool"], "gradle")
            self.assertFalse(detected["tool_explicit"])
            self.assertEqual(detected["input_origins"]["base_tool"], "detected")

            seeded_tools = self._build_context(
                project,
                seed={"base_tool": "maven", "current_tool": "gradle"},
                pinned=True,
            )
            self.assertTrue(seeded_tools["tool_explicit"])
            self.assertEqual(seeded_tools["input_origins"]["base_tool"], "user")
            self.assertEqual(
                seeded_tools["input_origins"]["current_tool"], "user",
            )

            cli_base_tool = self._build_context(
                project,
                args_overrides={"base_tool": "maven"},
                pinned=True,
            )
            self.assertTrue(cli_base_tool["tool_explicit"])
            cli_current_tool = self._build_context(
                project,
                args_overrides={"current_tool": "gradle"},
                pinned=True,
            )
            self.assertTrue(cli_current_tool["tool_explicit"])
            restored_explicit = self._build_context(
                project,
                existing={"tool_explicit": True},
                pinned=True,
            )
            self.assertTrue(restored_explicit["tool_explicit"])

            list_boundaries = self._build_context(
                project,
                seed={
                    "manual_coord_overrides": [" one ", "", "one"],
                    "skip_dependency_source_coords": [" skip ", "", "skip"],
                    "target_module": "",
                    "base_artifact_path": " ",
                },
                pinned=True,
            )
            self.assertEqual(list_boundaries["manual_coord_overrides"], ["one"])
            self.assertEqual(
                list_boundaries["skip_dependency_source_coords"], ["skip"],
            )
            self.assertEqual(list_boundaries["base_artifact_path"], "")
            self.assertFalse(list_boundaries["artifact_input_mode"])

            fresh_cli_branch = self._build_context(
                project,
                args_overrides={"base_branch": "fresh"},
                pinned=True,
            )
            self.assertEqual(fresh_cli_branch["base_branch"], "fresh")

            current_artifact_only = self._build_context(
                project,
                seed={"current_artifact_path": "artifacts/current.jar"},
                pinned=True,
            )
            self.assertTrue(current_artifact_only["artifact_input_mode"])

    def test_build_run_context_binary_overlay_contract_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            config = project / "binary.json"
            config.write_text(json.dumps({
                "source_overlay": {
                    "source_sets": [
                        {
                            "owner_type": "business",
                            "source_dirs": ["src/main/java", "", "src/main/java"],
                        },
                        {"owner_type": "dependency", "source_dirs": []},
                        {"owner_type": "unknown"},
                    ]
                }
            }), encoding="utf-8")
            overlay = self._build_context(
                project,
                args_overrides={"binary_pipeline_config": str(config)},
            )
            self.assertTrue(overlay["source_overlay_config_provided"])
            self.assertTrue(overlay["source_overlay_business_provided"])
            self.assertTrue(overlay["source_overlay_dependency_provided"])
            self.assertEqual(
                overlay["source_dirs"],
                [str((project / "src/main/java").resolve())],
            )
            self.assertEqual(overlay["source_dirs_status"], "explicit")

            preserved = self._build_context(
                project,
                args_overrides={"binary_pipeline_config": str(config)},
                source_dir_plan={
                    "source_dirs": ["already-resolved"], "status": "project_scope",
                },
            )
            self.assertEqual(preserved["source_dirs"], ["already-resolved"])
            self.assertEqual(preserved["source_dirs_status"], "project_scope")

            empty_config = project / "empty.json"
            empty_config.write_text("{}", encoding="utf-8")
            empty = self._build_context(
                project,
                args_overrides={"binary_pipeline_config": str(empty_config)},
            )
            self.assertNotIn("source_overlay_config_provided", empty)

            dependency_only_config = project / "dependency-only.json"
            dependency_only_config.write_text(json.dumps({
                "source_overlay": {
                    "source_sets": [
                        {"owner_type": "dependency", "source_dirs": []},
                        {"source_dirs": []},
                    ]
                }
            }), encoding="utf-8")
            dependency_only = self._build_context(
                project,
                args_overrides={
                    "binary_pipeline_config": str(dependency_only_config),
                },
            )
            self.assertTrue(dependency_only["source_overlay_config_provided"])
            self.assertFalse(dependency_only["source_overlay_business_provided"])
            self.assertTrue(dependency_only["source_overlay_dependency_provided"])
            self.assertEqual(dependency_only["source_dirs"], [])

            missing_config = self._build_context(
                project,
                args_overrides={
                    "binary_pipeline_config": str(project / "missing.json"),
                },
            )
            self.assertNotIn("source_overlay_config_provided", missing_config)

    def test_build_run_context_rejects_malformed_binary_overlay_configs(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            payloads = [
                "{",
                "[]",
                "[1]",
                json.dumps({"source_overlay": []}),
                json.dumps({"source_overlay": {"source_sets": {}}}),
                json.dumps({"source_overlay": {"source_sets": [1]}}),
                json.dumps({
                    "source_overlay": {
                        "source_sets": [{
                            "owner_type": "business", "source_dirs": "src",
                        }]
                    }
                }),
                json.dumps({
                    "source_overlay": {
                        "source_sets": [{
                            "owner_type": "business", "source_dirs": ["src", 1],
                        }]
                    }
                }),
            ]
            for index, content in enumerate(payloads):
                config = project / f"invalid-{index}.json"
                config.write_text(content, encoding="utf-8")
                with self.subTest(content=content), self.assertRaises(
                    run_step.StepError
                ):
                    self._build_context(
                        project,
                        args_overrides={"binary_pipeline_config": str(config)},
                    )

    def test_build_run_context_dependency_plan_and_scope_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            dependency = project / "dependency"
            dependency.mkdir()
            source = dependency / "src/main/java"
            source.mkdir(parents=True)
            planned = self._build_context(
                project,
                seed={
                    "dependency_repo_mappings": [
                        f"g:a={dependency}",
                    ],
                    "dependency_source_mappings": [
                        f"keep:one={source}",
                    ],
                    "dependency_source_dirs": [str(dependency)],
                    "step5_selected_names": ["Demo"],
                },
                dependency_materialization={
                    "dependency_source_dirs": [str(dependency)],
                    "dependency_source_git_urls": [],
                    "dependency_source_git_materializations": [],
                },
                dependency_source_plan={
                    "ambiguous_coords": ["ambiguous:one"],
                    "dependency_repo_mappings": [
                        f"g:a={dependency}", f"derived:one={dependency}",
                    ],
                    "dependency_source_mappings": [
                        f"derived:one={source}",
                    ],
                },
                relevant_coords=["g:a", "derived:one"],
                focus_coords=["g:a", "missing:one"],
            )
            self.assertEqual(
                planned["dependency_source_mapping_conflicts"],
                ["ambiguous:one"],
            )
            repo_mapping = dict(
                run_step._split_dependency_repo_mapping_value(item)
                for item in planned["dependency_repo_mappings"]
            )
            source_mapping = dict(
                run_step._split_dependency_repo_mapping_value(item)
                for item in planned["dependency_source_mappings"]
            )
            self.assertEqual(
                Path(repo_mapping["derived:one"]).resolve(), dependency.resolve(),
            )
            self.assertEqual(
                Path(source_mapping["derived:one"]).resolve(), source.resolve(),
            )
            self.assertEqual(planned["unmapped_dependency_coords"], ["missing:one"])
            self.assertEqual(planned["step5_selected_names"], ["Demo"])

            targeted = self._build_context(
                project,
                seed={"target_module": "app"},
            )
            self.assertEqual(targeted["project_scope"]["status"], "complete")

            discovered = self._build_context(
                project,
                discovery={
                    "modules": [{"module": "one"}, {"artifact_id": "missing-name"}],
                },
            )
            self.assertEqual(
                discovered["project_scope"]["candidate_modules"],
                ["one", None],
            )

            empty_status = self._build_context(
                project,
                source_dir_plan={"source_dirs": [], "status": ""},
            )
            self.assertEqual(empty_status["source_dirs_status"], "missing")

            unmatched_path_mapping = self._build_context(
                project,
                seed={"dependency_repo_mappings": [str(dependency)]},
                dependency_source_plan={
                    "ambiguous_coords": [],
                    "dependency_repo_mappings": [
                        f"other:one={project / 'other'}",
                    ],
                    "dependency_source_mappings": [],
                },
            )
            self.assertEqual(
                unmatched_path_mapping["dependency_repo_mappings"],
                [f"other:one={project / 'other'}"],
            )

    def test_validate_pending_response_accepts_every_supported_schema_type(self):
        interaction = self._validation_interaction(properties={
            "text": {"type": "string"},
            "items": {"type": "array"},
            "mapping": {"type": "object"},
            "enabled": {"type": "boolean"},
            "count": {"type": "integer"},
            "ratio": {"type": "number"},
            "nothing": {"type": "null"},
            "mode": {"type": "string", "enum": ["safe", "fast"]},
            "untyped": {},
        })

        for response in (
            {
                "action": "continue",
                "text": "value",
                "items": ["one"],
                "mapping": {"key": "value"},
                "enabled": False,
                "count": 0,
                "ratio": 1.5,
                "nothing": None,
                "mode": "safe",
                "untyped": object(),
                "__intent_patch": {"action": "continue"},
            },
            {"action": "cancel", "ratio": 1},
        ):
            with self.subTest(response=response):
                run_step.validate_pending_interaction_response(
                    interaction, response,
                )

    def test_validate_pending_response_rejects_schema_type_and_enum_mismatches(self):
        interaction = self._validation_interaction(properties={
            "text": {"type": "string"},
            "items": {"type": "array"},
            "mapping": {"type": "object"},
            "enabled": {"type": "boolean"},
            "count": {"type": "integer"},
            "ratio": {"type": "number"},
            "nothing": {"type": "null"},
            "mode": {"type": "string", "enum": ["safe", "fast"]},
        })
        invalid_values = (
            ("text", 1, "string"),
            ("text", None, "string"),
            ("items", {}, "array"),
            ("mapping", [], "object"),
            ("enabled", 1, "boolean"),
            ("count", True, "integer"),
            ("ratio", True, "number"),
            ("nothing", "not-null", "null"),
            ("mode", "unknown", "允许范围"),
            ("action", "unknown", "允许范围"),
        )
        for field, value, message in invalid_values:
            with self.subTest(field=field, value=value), self.assertRaisesRegex(
                run_step.StepError, message,
            ):
                run_step.validate_pending_interaction_response(
                    interaction,
                    {"action": "continue", field: value},
                )

        malformed_enum = self._validation_interaction(properties={
            "mode": {"type": "string", "enum": "safe"},
        })
        with self.assertRaisesRegex(run_step.StepError, "enum 必须是数组"):
            run_step.validate_pending_interaction_response(
                malformed_enum,
                {"action": "continue", "mode": "safe"},
            )

    def test_validate_pending_response_rejects_malformed_containers_and_fields(self):
        valid = self._validation_interaction()
        malformed_cases = (
            ([], {"action": "continue"}, "待确认信息必须是 JSON 对象"),
            (valid, [], "用户答复必须是 JSON 对象"),
            (
                {"response_schema": []},
                {"action": "continue"},
                "response_schema 必须是 JSON 对象",
            ),
            (
                {"response_schema": {"properties": []}},
                {"action": "continue"},
                "response_schema.properties 必须是 JSON 对象",
            ),
            (
                {"response_schema": {"properties": {}, "required": "action"}},
                {"action": "continue"},
                "response_schema.required 必须是字符串数组",
            ),
            (
                {"response_schema": {"properties": {}, "required": [1]}},
                {"action": "continue"},
                "response_schema.required 必须是字符串数组",
            ),
            (
                {
                    "response_schema": {
                        "properties": {"action": []},
                        "required": ["action"],
                    },
                },
                {"action": "continue"},
                "字段 action 的 schema 必须是 JSON 对象",
            ),
            (
                {
                    "response_schema": {
                        "properties": {"action": {"type": "string"}},
                        "required": ["action"],
                    },
                    "action_requirements": [],
                },
                {"action": "continue"},
                "action_requirements 必须是 JSON 对象",
            ),
            (
                {
                    "response_schema": {
                        "properties": {"action": {"type": "string"}},
                        "required": ["action"],
                    },
                    "action_requirements": {"continue": []},
                },
                {"action": "continue"},
                "当前动作 continue 的要求必须是 JSON 对象",
            ),
            (
                {
                    "response_schema": {
                        "properties": {"action": {"type": "string"}},
                        "required": ["action"],
                    },
                    "ref_resolution_requests": {},
                },
                {"action": "continue"},
                "ref_resolution_requests 必须是对象数组",
            ),
            (
                {
                    "response_schema": {
                        "properties": {"action": {"type": "string"}},
                        "required": ["action"],
                    },
                    "ref_resolution_requests": ["invalid"],
                },
                {"action": "continue"},
                "ref_resolution_requests 必须是对象数组",
            ),
        )
        for pending, response, message in malformed_cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                run_step.StepError, message,
            ):
                run_step.validate_pending_interaction_response(
                    pending, response,
                )

        with self.assertRaisesRegex(run_step.StepError, "未定义的字段：extra"):
            run_step.validate_pending_interaction_response(
                valid,
                {"action": "continue", "extra": True},
            )
        run_step.validate_pending_interaction_response(
            None,
            {"action": "continue", "arbitrary": "legacy", "__private": 1},
        )

    def test_validate_pending_response_enforces_required_value_presence(self):
        interaction = self._validation_interaction(
            properties={"value": {}},
            required=["action", "value"],
        )
        for value in (None, "", "   ", [], {}):
            with self.subTest(value=value), self.assertRaisesRegex(
                run_step.StepError, "字段 value 必填",
            ):
                run_step.validate_pending_interaction_response(
                    interaction,
                    {"action": "continue", "value": value},
                )
        for value in (0, False, [0], {"present": False}):
            with self.subTest(value=value):
                run_step.validate_pending_interaction_response(
                    interaction,
                    {"action": "continue", "value": value},
                )

    def test_validate_pending_response_enforces_action_requirement_shapes(self):
        base_properties = {
            "first": {},
            "second": {},
        }
        malformed_requirements = (
            ({"required_fields": "first"}, "required_fields 必须是字符串数组"),
            ({"required_fields": [1]}, "required_fields 必须是字符串数组"),
            ({"at_least_one_of": "first"}, "at_least_one_of 必须是字符串数组"),
            ({"at_least_one_of": [1]}, "at_least_one_of 必须是字符串数组"),
        )
        for requirement, message in malformed_requirements:
            interaction = self._validation_interaction(
                properties=base_properties,
                action_requirements={"continue": requirement},
            )
            with self.subTest(requirement=requirement), self.assertRaisesRegex(
                run_step.StepError, message,
            ):
                run_step.validate_pending_interaction_response(
                    interaction, {"action": "continue"},
                )

        required = self._validation_interaction(
            properties=base_properties,
            action_requirements={
                "continue": {
                    "required_fields": ["", "first"],
                    "at_least_one_of": ["", "second"],
                },
            },
        )
        with self.assertRaisesRegex(run_step.StepError, "字段 first 必填"):
            run_step.validate_pending_interaction_response(
                required, {"action": "continue", "second": "present"},
            )
        with self.assertRaisesRegex(run_step.StepError, "至少需要提供"):
            run_step.validate_pending_interaction_response(
                required, {"action": "continue", "first": "present"},
            )
        run_step.validate_pending_interaction_response(
            required,
            {"action": "continue", "first": "present", "second": 0},
        )
        run_step.validate_pending_interaction_response(
            required,
            {"action": "cancel"},
        )

    def test_validate_pending_response_enforces_local_source_confirmation(self):
        interaction = self._validation_interaction(
            step_id="step1",
            properties={
                "base_allow_local_source": {"type": "boolean"},
                "base_allow_dirty_local_source": {"type": "boolean"},
                "notes": {"type": "string"},
            },
            action_requirements={
                "confirm_local_source": {
                    "required_fields": [
                        "base_allow_local_source",
                        "base_allow_dirty_local_source",
                        "notes",
                    ],
                },
            },
        )
        for field in (
            "base_allow_local_source",
            "base_allow_dirty_local_source",
        ):
            response = {
                "action": "confirm_local_source",
                "base_allow_local_source": True,
                "base_allow_dirty_local_source": True,
                "notes": "confirmed",
            }
            response[field] = False
            with self.subTest(field=field), self.assertRaisesRegex(
                run_step.StepError, f"{field}=true",
            ):
                run_step.validate_pending_interaction_response(
                    interaction, response,
                )
        run_step.validate_pending_interaction_response(
            interaction,
            {
                "action": "confirm_local_source",
                "base_allow_local_source": True,
                "base_allow_dirty_local_source": True,
                "notes": "confirmed",
            },
        )

    def test_validate_pending_response_remote_ref_retry_matrix(self):
        properties = {
            "base_branch": {"type": "string"},
            "current_branch": {"type": "string"},
            "base_source_project_dir": {"type": "string"},
            "current_source_project_dir": {"type": "string"},
            "retry_remote_fetch": {"type": "boolean"},
        }
        requests = [
            {
                "side": "base",
                "field": "base_branch",
                "status": "fetch_failed",
                "requested_ref": "main",
                "source_project_dir": "/old/base",
            },
            {
                "side": "current",
                "field": "current_branch",
                "status": "ambiguous",
                "requested_ref": "upgrade",
                "source_project_dir": "/old/current",
            },
        ]
        interaction = self._validation_interaction(
            step_id="step1",
            reason_code="STEP1_REMOTE_SOURCE_UNAVAILABLE",
            properties=properties,
            action_requirements={
                "continue": {
                    "required_fields": ["base_branch", "current_branch"],
                },
            },
            ref_resolution_requests=requests,
        )
        with self.assertRaisesRegex(run_step.StepError, "current_branch 必填"):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "continue", "retry_remote_fetch": True},
            )
        run_step.validate_pending_interaction_response(
            interaction,
            {
                "action": "continue",
                "retry_remote_fetch": True,
                "current_branch": "upgrade-v2",
            },
        )
        run_step.validate_pending_interaction_response(
            interaction,
            {
                "action": "continue",
                "retry_remote_fetch": True,
                "base_branch": "main",
                "current_branch": "upgrade-v2",
            },
        )
        with self.assertRaisesRegex(run_step.StepError, "base_branch 必填"):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "continue", "current_branch": "upgrade-v2"},
            )
        completeness_only = self._validation_interaction(
            step_id="step1",
            properties=properties,
            ref_resolution_requests=requests,
        )
        with self.assertRaisesRegex(run_step.StepError, "仍缺少：current_branch"):
            run_step.validate_pending_interaction_response(
                completeness_only,
                {"action": "continue", "retry_remote_fetch": True},
            )
        with self.assertRaisesRegex(run_step.StepError, "仍缺少：base_branch"):
            run_step.validate_pending_interaction_response(
                completeness_only,
                {"action": "continue", "current_branch": "upgrade-v2"},
            )
        with self.assertRaisesRegex(run_step.StepError, "完全相同的输入"):
            run_step.validate_pending_interaction_response(
                interaction,
                {
                    "action": "continue",
                    "base_branch": "main",
                    "current_branch": "upgrade-v2",
                },
            )
        for response in (
            {
                "action": "continue",
                "base_branch": "main-v2",
                "current_branch": "upgrade-v2",
            },
            {
                "action": "continue",
                "base_branch": "main",
                "base_source_project_dir": "/new/base",
                "current_branch": "upgrade-v2",
            },
        ):
            with self.subTest(response=response):
                run_step.validate_pending_interaction_response(
                    interaction, response,
                )

        no_retryable_failure = self._validation_interaction(
            step_id="step1",
            properties=properties,
            ref_resolution_requests=[{
                "side": "base",
                "field": "base_branch",
                "status": "ambiguous",
            }],
        )
        with self.assertRaisesRegex(run_step.StepError, "没有可显式重查"):
            run_step.validate_pending_interaction_response(
                no_retryable_failure,
                {
                    "action": "continue",
                    "base_branch": "new",
                    "retry_remote_fetch": True,
                },
            )

    def test_validate_pending_response_dependency_ambiguity_positive_matrix(self):
        interaction = self._dependency_ambiguity_interaction()
        for response in (
            {
                "action": "continue",
                "dependency_source_ref_selections": [
                    {"selection_key": "a-main"},
                    {"selection_key": "b-main"},
                ],
            },
            {
                "action": "continue",
                "dependency_source_ref_selections": {
                    "selection_key": "a-main",
                },
                "skip_dependency_source_coords": "g:b",
            },
            {
                "action": "continue",
                "skip_dependency_source_coords": ["g:a", "g:b", ""],
            },
            {
                "action": "cancel",
                "dependency_source_ref_selections": [],
            },
        ):
            with self.subTest(response=response):
                run_step.validate_pending_interaction_response(
                    interaction, response,
                )

    @classmethod
    def _dependency_ambiguity_interaction(cls):
        interaction = cls._validation_interaction(
            step_id="step1",
            reason_code="step1_dependency_source_ambiguity",
            properties={
                "dependency_source_ref_selections": {},
                "skip_dependency_source_coords": {},
            },
        )
        interaction["dependency_source_ambiguities"] = [
            {
                "coord": "g:a",
                "candidates": [
                    {"selection_key": "a-main"},
                    {"selection_key": "a-release"},
                ],
            },
            {
                "coord": "g:b",
                "candidates": [{"selection_key": "b-main"}],
            },
        ]
        return interaction

    def test_validate_pending_response_dependency_ambiguity_rejections(self):
        base = self._dependency_ambiguity_interaction()
        response_rejections = (
            ({"action": "continue"}, "尚未选择或明确跳过"),
            (
                {
                    "action": "continue",
                    "dependency_source_ref_selections": [
                        {"selection_key": "missing"},
                    ],
                    "skip_dependency_source_coords": ["g:a", "g:b"],
                },
                "不存在或已过期",
            ),
            (
                {
                    "action": "continue",
                    "dependency_source_ref_selections": [
                        {"selection_key": "a-main"},
                        {"selection_key": "a-release"},
                    ],
                    "skip_dependency_source_coords": ["g:b"],
                },
                "只能选择一个版本方案",
            ),
            (
                {
                    "action": "continue",
                    "skip_dependency_source_coords": ["unknown"],
                },
                "不存在的依赖源码",
            ),
            (
                {
                    "action": "continue",
                    "dependency_source_ref_selections": [
                        {"selection_key": "a-main"},
                    ],
                    "skip_dependency_source_coords": ["g:a", "g:b"],
                },
                "不能同时选择候选并跳过",
            ),
        )
        for response, message in response_rejections:
            with self.subTest(message=message), self.assertRaisesRegex(
                run_step.StepError, message,
            ):
                run_step.validate_pending_interaction_response(base, response)

        malformed_responses = (
            (
                {
                    "action": "continue",
                    "dependency_source_ref_selections": "a-main",
                },
                "必须是对象数组",
            ),
            (
                {
                    "action": "continue",
                    "dependency_source_ref_selections": [1],
                },
                "必须是对象数组",
            ),
            (
                {
                    "action": "continue",
                    "skip_dependency_source_coords": [1],
                },
                "必须是字符串数组",
            ),
        )
        for response, message in malformed_responses:
            with self.subTest(message=message), self.assertRaisesRegex(
                run_step.StepError, message,
            ):
                run_step.validate_pending_interaction_response(base, response)

    def test_validate_pending_response_dependency_ambiguity_card_rejections(self):
        mutations = (
            ({}, "dependency_source_ambiguities 必须是对象数组"),
            (["invalid"], "dependency_source_ambiguities 必须是对象数组"),
            (
                [{"coord": "", "candidates": []}],
                "每项必须包含 coord",
            ),
            (
                [
                    {"coord": "g:a", "candidates": []},
                    {"coord": "g:a", "candidates": []},
                ],
                "歧义项重复",
            ),
            (
                [{"coord": "g:a", "candidates": {}}],
                "candidates 必须是对象数组",
            ),
            (
                [{"coord": "g:a", "candidates": [1]}],
                "candidates 必须是对象数组",
            ),
            (
                [{"coord": "g:a", "candidates": [{}]}],
                "候选缺少 selection_key",
            ),
            (
                [
                    {
                        "coord": "g:a",
                        "candidates": [{"selection_key": "same"}],
                    },
                    {
                        "coord": "g:b",
                        "candidates": [{"selection_key": "same"}],
                    },
                ],
                "selection_key 重复",
            ),
        )
        for ambiguities, message in mutations:
            interaction = self._dependency_ambiguity_interaction()
            interaction["dependency_source_ambiguities"] = ambiguities
            with self.subTest(message=message), self.assertRaisesRegex(
                run_step.StepError, message,
            ):
                run_step.validate_pending_interaction_response(
                    interaction,
                    {
                        "action": "continue",
                        "skip_dependency_source_coords": [],
                    },
                )

        missing = self._dependency_ambiguity_interaction()
        missing.pop("dependency_source_ambiguities")
        run_step.validate_pending_interaction_response(
            missing,
            {"action": "continue"},
        )

    @staticmethod
    def _dependency_binding_interaction(*ambiguities):
        return {
            "reason_code": "STEP1_DEPENDENCY_SOURCE_AMBIGUITY",
            "dependency_source_ambiguities": list(ambiguities),
        }

    def test_expand_dependency_source_ref_selections_positive_matrix(self):
        candidate_a = {
            "selection_key": "a-main",
            "coord": "g:a",
            "base_ref": "v1",
            "current_ref": "v2",
        }
        candidate_b = {
            "selection_key": "b-main",
            "base_ref": "v3",
            "current_ref": "v4",
        }
        interaction = self._dependency_binding_interaction(
            {
                "kind": "display-only",
                "coord": "ignored",
                "candidates": "ignored",
            },
            {
                "kind": "binding",
                "coord": "g:a",
                "candidates": [candidate_a],
            },
            {
                "kind": "binding",
                "coord": "g:b",
                "candidates": [candidate_b],
            },
        )
        for raw, expected in (
            (
                {"selection_key": "a-main"},
                [candidate_a],
            ),
            (
                [
                    {"selection_key": "a-main"},
                    {"selection_key": "b-main"},
                ],
                [candidate_a, candidate_b],
            ),
        ):
            with self.subTest(raw=raw):
                result = run_step.expand_dependency_source_ref_selections(
                    interaction,
                    {
                        "action": "continue",
                        "dependency_source_ref_selections": raw,
                    },
                )
                self.assertEqual(
                    result["dependency_source_ref_bindings"], expected,
                )
                self.assertEqual(result["action"], "continue")

        for raw in (None, "", []):
            response = {"dependency_source_ref_selections": raw}
            with self.subTest(raw=raw):
                self.assertEqual(
                    run_step.expand_dependency_source_ref_selections(
                        interaction, response,
                    ),
                    response,
                )
        self.assertEqual(
            run_step.expand_dependency_source_ref_selections(None, None),
            {},
        )
        self.assertEqual(
            run_step.expand_dependency_source_ref_selections(
                {"reason_code": "other"}, {"unchanged": True},
            ),
            {"unchanged": True},
        )

    def test_expand_dependency_source_ref_selections_rejects_malformed_contracts(self):
        valid = self._dependency_binding_interaction({
            "kind": "binding",
            "coord": "g:a",
            "candidates": [{
                "selection_key": "a-main",
                "coord": "g:a",
            }],
        })
        cases = (
            (valid, [], "用户答复必须是 JSON 对象"),
            ([], {"dependency_source_ref_selections": "bad"}, "待确认信息必须是 JSON 对象"),
            (
                valid,
                {"dependency_source_ref_selections": "bad"},
                "必须是对象数组",
            ),
            (
                valid,
                {"dependency_source_ref_selections": [1]},
                "每项必须是对象",
            ),
            (
                {
                    "reason_code": "step1_dependency_source_ambiguity",
                    "dependency_source_ambiguities": {},
                },
                {"dependency_source_ref_selections": [{}]},
                "dependency_source_ambiguities 必须是对象数组",
            ),
            (
                {
                    "reason_code": "step1_dependency_source_ambiguity",
                    "dependency_source_ambiguities": [1],
                },
                {"dependency_source_ref_selections": [{}]},
                "dependency_source_ambiguities 必须是对象数组",
            ),
        )
        for pending, response, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                run_step.StepError, message,
            ):
                run_step.expand_dependency_source_ref_selections(
                    pending, response,
                )

    def test_expand_dependency_source_ref_selections_rejects_bad_cards_and_choices(self):
        card_cases = (
            (
                [{"kind": "binding", "coord": "", "candidates": []}],
                "必须包含 coord",
            ),
            (
                [
                    {"kind": "binding", "coord": "g:a", "candidates": []},
                    {"kind": "binding", "coord": "g:a", "candidates": []},
                ],
                "歧义项重复",
            ),
            (
                [{"kind": "binding", "coord": "g:a", "candidates": {}}],
                "candidates 必须是对象数组",
            ),
            (
                [{"kind": "binding", "coord": "g:a", "candidates": [1]}],
                "candidates 必须是对象数组",
            ),
            (
                [{"kind": "binding", "coord": "g:a", "candidates": [{}]}],
                "候选缺少 selection_key",
            ),
            (
                [
                    {
                        "kind": "binding",
                        "coord": "g:a",
                        "candidates": [{"selection_key": "same"}],
                    },
                    {
                        "kind": "binding",
                        "coord": "g:b",
                        "candidates": [{"selection_key": "same"}],
                    },
                ],
                "selection_key 重复",
            ),
            (
                [{
                    "kind": "binding",
                    "coord": "g:a",
                    "candidates": [{
                        "selection_key": "a-main",
                        "coord": "g:b",
                    }],
                }],
                "coord 与歧义项不一致",
            ),
        )
        for ambiguities, message in card_cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                run_step.StepError, message,
            ):
                run_step.expand_dependency_source_ref_selections(
                    self._dependency_binding_interaction(*ambiguities),
                    {"dependency_source_ref_selections": [{}]},
                )

        for interaction in (
            {"reason_code": "step1_dependency_source_ambiguity"},
            self._dependency_binding_interaction({
                "kind": "binding",
                "coord": "g:a",
            }),
        ):
            with self.subTest(interaction=interaction), self.assertRaisesRegex(
                run_step.StepError, "不存在或已过期：stale",
            ):
                run_step.expand_dependency_source_ref_selections(
                    interaction,
                    {
                        "dependency_source_ref_selections": {
                            "selection_key": "stale",
                        },
                    },
                )

        valid = self._dependency_binding_interaction({
            "kind": "binding",
            "coord": "g:a",
            "candidates": [
                {"selection_key": "a-main"},
                {"selection_key": "a-release"},
            ],
        })
        for selections, message in (
            ([{}], r"不存在或已过期：\(空\)"),
            ([{"selection_key": "stale"}], "不存在或已过期：stale"),
            (
                [
                    {"selection_key": "a-main"},
                    {"selection_key": "a-release"},
                ],
                "只能选择一个版本方案",
            ),
        ):
            with self.subTest(selections=selections), self.assertRaisesRegex(
                run_step.StepError, message,
            ):
                run_step.expand_dependency_source_ref_selections(
                    valid,
                    {"dependency_source_ref_selections": selections},
                )

    @staticmethod
    def _target_resolution_options():
        return {
            "enabled": True,
            "options": [
                {
                    "selection_key": "key-a",
                    "coord": "g:a",
                    "name": "artifact-a",
                    "aliases": ["Alpha", "alpha", "shared", ""],
                },
                {
                    "selection_key": "key-b",
                    "coord": "g:b",
                    "name": "artifact-b",
                    "aliases": ["Beta", "shared"],
                },
                {
                    "selection_key": "key-name",
                    "coord": "",
                    "name": "name-only-art",
                    "aliases": ["name-only"],
                },
                {
                    "selection_key": "key-duplicate-a",
                    "coord": "g:duplicate",
                    "name": "duplicate-a",
                },
                {
                    "selection_key": "key-duplicate-b",
                    "coord": "g:duplicate",
                    "name": "duplicate-b",
                    "aliases": None,
                },
                {
                    "selection_key": "key-same-name",
                    "coord": "g:other-artifact-b",
                    "name": "artifact-b",
                },
                {
                    "selection_key": "key-coord-only",
                    "coord": "g:coord-only",
                    "aliases": ["coord-only", "coord-only-again"],
                },
            ],
        }

    def test_resolve_selected_targets_all_identifier_modes(self):
        resolution = self._target_resolution_options()
        result = run_step.resolve_selected_targets(
            resolution,
            [
                "KEY-A",
                "g:b",
                "name:artifact-a",
                "artifact-b",
                "Beta",
                "name-only",
                "NAME:name-only-art",
                "key-a",
                "",
            ],
        )
        self.assertEqual(
            result["selected_targets"],
            [
                "KEY-A",
                "g:b",
                "name:artifact-a",
                "artifact-b",
                "Beta",
                "name-only",
                "NAME:name-only-art",
            ],
        )
        self.assertEqual(result["step5_selected_coords"], ["g:a", "g:b"])
        self.assertEqual(
            result["step5_selected_names"],
            ["artifact-a", "artifact-b", "name-only-art"],
        )
        self.assertEqual(result["unresolved"], [])
        self.assertEqual(result["ambiguous"], {})

        duplicate_alias = run_step.resolve_selected_targets(
            resolution, ["alpha"],
        )
        self.assertEqual(duplicate_alias["step5_selected_coords"], ["g:a"])
        same_name = run_step.resolve_selected_targets(
            resolution, ["name:artifact-b", "artifact-b"],
        )
        self.assertEqual(same_name["step5_selected_names"], ["artifact-b"])
        coord_only = run_step.resolve_selected_targets(
            resolution, ["coord-only", "coord-only-again"],
        )
        self.assertEqual(
            coord_only["step5_selected_coords"], ["g:coord-only"],
        )
        self.assertEqual(coord_only["step5_selected_names"], [])

    def test_resolve_selected_targets_reports_unresolved_and_ambiguous_values(self):
        resolution = self._target_resolution_options()
        result = run_step.resolve_selected_targets(
            resolution,
            ["unknown", "name:", "name:missing", "shared", "g:duplicate"],
        )
        self.assertEqual(
            result["unresolved"], ["unknown", "name:", "name:missing"],
        )
        self.assertEqual(
            result["ambiguous"],
            {
                "shared": ["key-a", "key-b"],
                "g:duplicate": ["key-duplicate-a", "key-duplicate-b"],
            },
        )

        with self.assertRaisesRegex(run_step.StepError, "存在歧义"):
            run_step.validate_selected_targets_resolution(
                resolution, ["shared", "g:duplicate"],
            )
        with self.assertRaisesRegex(run_step.StepError, "未命中当前候选"):
            run_step.validate_selected_targets_resolution(
                resolution, ["unknown"],
            )
        self.assertEqual(
            run_step.validate_selected_targets_resolution(resolution, None),
            {},
        )

    def test_resolve_selected_targets_rejects_malformed_resolution_contracts(self):
        self.assertIsNone(run_step.resolve_selected_targets([], None))
        malformed = (
            ([], ["a"], "selection_resolution 必须是 JSON 对象"),
            (None, ["a"], "不支持 selected_targets"),
            ({"options": {}}, ["a"], "options 必须是对象数组"),
            ({"options": [1]}, ["a"], "options 必须是对象数组"),
            (
                {"options": [{"coord": "g:a"}]},
                ["g:a"],
                "必须包含 selection_key",
            ),
            (
                {
                    "options": [
                        {"selection_key": "same", "coord": "g:a"},
                        {"selection_key": "SAME", "coord": "g:b"},
                    ],
                },
                ["same"],
                "selection_key 重复",
            ),
            (
                {"options": [{"selection_key": "empty"}]},
                ["empty"],
                "必须包含 coord 或 name",
            ),
            (
                {
                    "options": [{
                        "selection_key": "a",
                        "coord": "g:a",
                        "aliases": "alpha",
                    }],
                },
                ["a"],
                "aliases 必须是字符串数组",
            ),
            (
                {
                    "options": [{
                        "selection_key": "a",
                        "coord": "g:a",
                        "aliases": [1],
                    }],
                },
                ["a"],
                "aliases 必须是字符串数组",
            ),
        )
        for resolution, value, message in malformed:
            with self.subTest(message=message), self.assertRaisesRegex(
                run_step.StepError, message,
            ):
                run_step.resolve_selected_targets(resolution, value)

        with self.assertRaisesRegex(run_step.StepError, "仅支持字符串"):
            run_step.resolve_selected_targets(
                self._target_resolution_options(), 1,
            )
        empty = run_step.resolve_selected_targets(
            self._target_resolution_options(), [],
        )
        self.assertEqual(empty["selected_targets"], [])
        self.assertEqual(empty["step5_selected_coords"], [])
        self.assertEqual(empty["step5_selected_names"], [])

    def test_normalize_action_requirements_complete_matrix(self):
        normalized = run_step.normalize_action_requirements(
            {
                "": {"required_fields": ["ignored"]},
                "unknown": {"required_fields": ["ignored"]},
                "continue": {
                    "required_fields": [" first ", "first", ""],
                    "at_least_one_of": [" second ", "second", ""],
                    "recommended_fields": [" third ", "third", ""],
                    "description": " continue description ",
                },
                "cancel": None,
                "restart_from_step": {
                    "required_fields": ["custom", "restart_step_id"],
                    "at_least_one_of": [],
                    "recommended_fields": [],
                    "description": "custom restart",
                },
            },
            [
                {},
                {"id": ""},
                {"id": "continue"},
                {"id": "continue"},
                {"id": "cancel"},
                {"id": "restart_from_step"},
            ],
            required_fields=["global"],
        )
        self.assertEqual(set(normalized), {
            "continue", "cancel", "restart_from_step",
        })
        self.assertEqual(normalized["continue"], {
            "required_fields": ["first"],
            "at_least_one_of": ["second"],
            "recommended_fields": ["third"],
            "description": "continue description",
        })
        self.assertEqual(normalized["cancel"], {
            "required_fields": [],
            "at_least_one_of": [],
            "recommended_fields": [],
            "description": "",
        })
        self.assertEqual(normalized["restart_from_step"], {
            "required_fields": ["custom", "restart_step_id"],
            "at_least_one_of": [],
            "recommended_fields": [],
            "description": "custom restart",
        })

        fallback = run_step.normalize_action_requirements(
            {"continue": {}},
            [{"id": "continue"}],
            required_fields=[" required ", "required", ""],
        )
        self.assertEqual(fallback["continue"]["required_fields"], ["required"])
        generated = run_step.normalize_action_requirements(
            {},
            [{"id": "continue"}, {"id": "restart_from_step"}],
            required_fields=["required"],
        )
        self.assertEqual(generated["continue"]["required_fields"], ["required"])
        self.assertEqual(
            generated["restart_from_step"]["required_fields"],
            ["restart_step_id"],
        )
        self.assertTrue(generated["restart_from_step"]["description"])

        custom = run_step.normalize_action_requirements(
            {"custom": {}}, [], required_fields=None,
        )
        self.assertEqual(list(custom), ["custom"])
        self.assertEqual(
            run_step.normalize_action_requirements(None, None, required_fields=[]),
            {},
        )

    def test_normalize_action_requirements_rejects_malformed_contracts(self):
        malformed = (
            ([], [], None, "action_requirements 必须是 JSON 对象"),
            ({}, {}, None, "交互 options 必须是对象数组"),
            ({}, [1], None, "交互 options 必须是对象数组"),
            ({}, [], "required", "required_fields 必须是字符串数组"),
            ({}, [], [1], "required_fields 必须是字符串数组"),
            (
                {"continue": []},
                [{"id": "continue"}],
                None,
                "action_requirements.continue 必须是 JSON 对象",
            ),
            (
                {"continue": {"required_fields": "field"}},
                [{"id": "continue"}],
                None,
                "required_fields 必须是字符串数组",
            ),
            (
                {"continue": {"required_fields": [1]}},
                [{"id": "continue"}],
                None,
                "required_fields 必须是字符串数组",
            ),
            (
                {"continue": {"at_least_one_of": "field"}},
                [{"id": "continue"}],
                None,
                "at_least_one_of 必须是字符串数组",
            ),
            (
                {"continue": {"recommended_fields": [1]}},
                [{"id": "continue"}],
                None,
                "recommended_fields 必须是字符串数组",
            ),
        )
        for requirements, options, required_fields, message in malformed:
            with self.subTest(message=message), self.assertRaisesRegex(
                run_step.StepError, message,
            ):
                run_step.normalize_action_requirements(
                    requirements, options, required_fields=required_fields,
                )

    def test_build_input_normalization_contract_boundary_matrix(self):
        empty = run_step.build_input_normalization_contract(None, None, None)
        self.assertEqual(empty["allowed_actions"], [])
        self.assertEqual(empty["required_fields"], [])
        self.assertEqual(empty["field_hints"], {})
        self.assertEqual(empty["action_examples"], [])

        contract = run_step.build_input_normalization_contract(
            [
                {"id": ""},
                {
                    "id": "custom",
                    "label": "",
                    "description": "description",
                },
            ],
            ["required"],
            {
                "malformed": "not-an-object",
                "plain": {"description": "plain field"},
                "empty_enum": {"type": "string", "enum": []},
                "mode": {
                    "type": "string",
                    "description": "mode field",
                    "enum": ["safe"],
                },
            },
        )
        self.assertEqual(contract["allowed_actions"], ["custom"])
        self.assertEqual(contract["required_fields"], ["required"])
        self.assertEqual(contract["field_hints"]["malformed"], {
            "type": "string", "description": "",
        })
        self.assertNotIn("enum", contract["field_hints"]["empty_enum"])
        self.assertEqual(contract["field_hints"]["mode"]["enum"], ["safe"])
        self.assertEqual(contract["action_examples"][0]["label"], "custom")
        self.assertEqual(
            contract["action_examples"][0]["description"], "description",
        )

    def test_enrich_input_normalization_contract_idempotent_matrix(self):
        empty = run_step.enrich_input_normalization_contract(None)
        self.assertEqual(empty, {"rules": []})

        selection = {
            "enabled": True,
            "scope_mode_field": "scope_mode",
            "options": [{"selection_key": "a", "coord": "g:a"}],
        }
        enriched = run_step.enrich_input_normalization_contract(
            {"rules": ["existing"], "do_not": ["existing prohibition"]},
            action_requirements={"continue": {"required_fields": ["field"]}},
            selection_resolution=selection,
        )
        self.assertEqual(enriched["selection_resolution"], selection)
        self.assertIn("existing", enriched["rules"])
        self.assertIn("existing prohibition", enriched["do_not"])
        self.assertEqual(len(enriched["rules"]), 5)
        self.assertEqual(len(enriched["do_not"]), 3)

        repeated = run_step.enrich_input_normalization_contract(
            enriched,
            action_requirements=enriched["action_requirements"],
            selection_resolution=selection,
        )
        self.assertEqual(repeated["rules"], enriched["rules"])
        self.assertEqual(repeated["do_not"], enriched["do_not"])

        no_scope_mode = run_step.enrich_input_normalization_contract(
            {},
            selection_resolution={"enabled": True},
        )
        self.assertEqual(len(no_scope_mode["rules"]), 1)
        self.assertEqual(len(no_scope_mode["do_not"]), 2)
        disabled = run_step.enrich_input_normalization_contract(
            {"do_not": []},
            action_requirements={},
            selection_resolution={"enabled": False},
        )
        self.assertEqual(disabled, {"do_not": [], "rules": []})

    def test_apply_interaction_protocol_ref_resolution_scope_matrix(self):
        self.assertEqual(
            run_step.apply_interaction_protocol_enhancements(None, None),
            {},
        )
        step_unspecified = run_step.apply_interaction_protocol_enhancements(
            {"options": []}, None,
        )
        self.assertEqual(step_unspecified["response_schema"]["required"], ["action"])
        interaction = {
            "question": "请选择 ref。",
            "options": [{"id": "continue"}],
            "response_schema": {
                "required": ["action"],
                "properties": {"action": {"type": "string"}},
            },
            "ref_resolution_requests": [
                "ignored-malformed-request",
                {},
                {
                    "side": "base",
                    "field": "base_branch",
                    "artifact_path": "/artifacts/base.jar",
                    "source_project_dir": "/repos/base",
                },
                {
                    "side": "current",
                    "field": "current_branch",
                    "resolution_trigger": "manual",
                    "source_project_dir": "/repos/current",
                },
                {"side": "ignored"},
            ],
            "source_ref_decision_items": [
                None,
                {"side": "base"},
                {
                    "side": "current",
                    "source_project_dir": "preserved",
                    "resolution_trigger": "preserved",
                    "remote_query_scope": "preserved",
                },
                {"side": "unknown"},
            ],
        }
        enhanced = run_step.apply_interaction_protocol_enhancements(
            interaction, "step1",
        )
        scope = enhanced["ref_resolution_scope"]
        self.assertEqual(scope["queried_sides"], ["base"])
        self.assertEqual(scope["not_evaluated_sides"], ["current"])
        self.assertIn("基准侧", scope["note"])
        self.assertIn("当前侧", scope["note"])
        self.assertEqual(enhanced["checklist_lines"][0], scope["note"])
        self.assertTrue(enhanced["question"].endswith(scope["note"]))
        decisions = enhanced["source_ref_decision_items"]
        self.assertIsNone(decisions[0]["source_project_dir"])
        self.assertEqual(decisions[1]["source_project_dir"], "/repos/base")
        self.assertEqual(
            decisions[1]["resolution_trigger"],
            "artifact_coordinate_enrichment",
        )
        self.assertEqual(decisions[1]["remote_query_scope"], "base")
        self.assertEqual(decisions[2]["source_project_dir"], "preserved")
        self.assertIsNone(decisions[3]["source_project_dir"])
        self.assertIn(
            "base_source_project_dir",
            enhanced["response_schema"]["properties"],
        )
        self.assertIn(
            "current_source_project_dir",
            enhanced["response_schema"]["properties"],
        )

        repeated = run_step.apply_interaction_protocol_enhancements(
            enhanced, "step1",
        )
        self.assertEqual(repeated["checklist_lines"].count(scope["note"]), 1)
        self.assertEqual(repeated["question"].count(scope["note"]), 1)

        both_sides = run_step.apply_interaction_protocol_enhancements(
            {
                "options": [{"id": "continue"}],
                "ref_resolution_requests": [
                    {
                        "side": "base",
                        "resolution_trigger": "artifact_coordinate_enrichment",
                    },
                    {
                        "side": "current",
                        "artifact_path": "/artifacts/current.jar",
                    },
                ],
            },
            "step0",
        )
        self.assertEqual(
            both_sides["ref_resolution_scope"]["not_evaluated_sides"], [],
        )
        self.assertNotIn(
            "它不表示",
            both_sides["ref_resolution_scope"]["note"],
        )

    def test_apply_interaction_protocol_selection_and_requirement_matrix(self):
        selection_options = [
            {"coord": "g:a", "name": "a"},
            {"coord": "g:b", "name": "b"},
        ]
        interaction = {
            "options": [{}, {"id": "continue"}, {"id": "cancel"}],
            "required_fields": [
                "step5_selected_coords",
                "step5_selected_names",
                "other",
                "other",
            ],
            "response_schema": {
                "required": [
                    "action",
                    "step5_selected_coords",
                    "step5_selected_names",
                ],
                "properties": {
                    "action": {"type": "string"},
                    "selected_targets": {
                        "type": "array",
                        "description": "preserved",
                    },
                    "step5_selected_coords": {"type": "array"},
                    "step5_selected_names": {"type": "array"},
                },
            },
            "selection_options": selection_options,
            "action_requirements": {
                "continue": {
                    "required_fields": [
                        "step5_selected_coords",
                        "step5_selected_names",
                        "other",
                        "other",
                    ],
                    "recommended_fields": ["step5_selected_coords"],
                    "at_least_one_of": ["step5_selected_names"],
                },
                "cancel": {
                    "required_fields": [],
                    "recommended_fields": [],
                    "at_least_one_of": [],
                },
            },
            "input_normalization": {
                "rules": [
                    "可以将用户自然语言答复整理为符合 response_schema 的 JSON 对象。",
                    "custom rule",
                ],
                "do_not": ["custom prohibition"],
                "custom_key": "preserved",
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            enhanced = run_step.apply_interaction_protocol_enhancements(
                interaction,
                "step4",
                project_dir=project,
                report_dir=project / "report",
            )
        self.assertEqual(
            enhanced["required_fields"],
            ["selected_targets", "other", "scope_mode"],
        )
        properties = enhanced["response_schema"]["properties"]
        self.assertNotIn("step5_selected_coords", properties)
        self.assertNotIn("step5_selected_names", properties)
        self.assertEqual(properties["selected_targets"]["description"], "preserved")
        self.assertEqual(properties["scope_mode"]["enum"], ["full", "partial"])
        self.assertEqual(
            enhanced["response_schema"]["required"], ["action"],
        )
        requirements = enhanced["action_requirements"]
        self.assertEqual(
            requirements["continue"]["required_fields"],
            ["selected_targets", "other"],
        )
        self.assertEqual(
            requirements["continue"]["recommended_fields"],
            ["selected_targets"],
        )
        self.assertEqual(
            requirements["continue"]["at_least_one_of"],
            ["selected_targets"],
        )
        self.assertNotIn("required_fields", requirements["cancel"])
        self.assertNotIn("recommended_fields", requirements["cancel"])
        self.assertNotIn("at_least_one_of", requirements["cancel"])
        self.assertEqual(
            enhanced["input_normalization"]["custom_key"], "preserved",
        )
        self.assertEqual(
            enhanced["input_normalization"]["rules"].count("custom rule"), 1,
        )
        self.assertTrue(enhanced["resume_command_examples"])

        already_scoped = run_step.apply_interaction_protocol_enhancements(
            enhanced, "step4",
        )
        self.assertEqual(
            already_scoped["required_fields"].count("scope_mode"), 1,
        )

    def test_apply_interaction_protocol_step5_fallback_and_diagnostic_matrix(self):
        fallback_resolution = {
            "enabled": True,
            "options": [{
                "selection_key": "coord:g:a",
                "coord": "g:a",
                "name": "a",
            }],
        }
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report"
            with patch.object(
                run_step,
                "build_report_dir_step5_selection_resolution",
                return_value=fallback_resolution,
            ):
                enhanced = run_step.apply_interaction_protocol_enhancements(
                    {
                        "reason_code": "step1_source_ref_not_found",
                        "origin_step": "",
                        "options": [{"id": "cancel"}],
                        "response_schema": {"required": []},
                        "recommended_selection_options": [],
                    },
                    "step5",
                    report_dir=report,
                )
        self.assertEqual(enhanced["selection_resolution"], fallback_resolution)
        self.assertEqual(
            enhanced["selection_options"][0]["coord"], "g:a",
        )
        self.assertEqual(enhanced["response_schema"]["required"], ["action"])
        self.assertEqual(enhanced["origin_step"], "step5")
        self.assertEqual(
            enhanced["diagnostic_guidance_schema"],
            run_step.REASON_GUIDANCE_SCHEMA,
        )
        self.assertTrue(enhanced["diagnostic_guidance"])
        self.assertNotIn("resume_command_examples", enhanced)

        no_fallback = run_step.apply_interaction_protocol_enhancements(
            {
                "options": [],
                "selection_resolution": {"enabled": False},
                "input_normalization": {"rules": [], "do_not": []},
            },
            "step5",
            report_dir=None,
        )
        self.assertNotIn("selection_options", no_fallback)
        self.assertNotIn("diagnostic_guidance", no_fallback)

        enabled_without_options = run_step.apply_interaction_protocol_enhancements(
            {
                "options": [{"id": "cancel"}],
                "selection_resolution": {"enabled": True},
            },
            "step5",
        )
        self.assertEqual(enabled_without_options["selection_options"], [])

        with tempfile.TemporaryDirectory() as temporary:
            project_only = run_step.apply_interaction_protocol_enhancements(
                {"options": []},
                "step3",
                project_dir=Path(temporary),
                report_dir=None,
            )
        self.assertNotIn("resume_command_examples", project_only)

        blank_origin = run_step.apply_interaction_protocol_enhancements(
            {
                "reason_code": "step1_source_ref_not_found",
                "options": [],
            },
            "",
        )
        self.assertEqual(blank_origin["origin_step"], "")

    def test_build_interaction_payload_early_exit_and_default_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            report = project / "report"
            for step_id in ("step0", "step2"):
                with self.subTest(step_id=step_id):
                    self.assertIsNone(run_step.build_interaction_payload(
                        step_id, report, {}, project,
                    ))
            self.assertIsNone(run_step.build_interaction_payload(
                "step3",
                report,
                {"step3": {"interaction": None}},
                project,
            ))
            self.assertIsNone(run_step.build_interaction_payload(
                "step3",
                report,
                {"step3": {"confirm": False}},
                project,
            ))

            default = run_step.build_interaction_payload(
                "step3", report, {}, project,
            )
            self.assertEqual(default["step_id"], "step3")
            self.assertEqual(
                [item["id"] for item in default["options"]],
                ["continue", "cancel", "restart_from_step"],
            )
            self.assertEqual(default["files_to_review"], [])
            self.assertEqual(default["checklist_lines"], [])

            step5_default = run_step.build_interaction_payload(
                "step5",
                report,
                {"step5": {"interaction": None, "title": "Step5"}},
                project,
                run_context=None,
                main_state=None,
            )
            self.assertEqual(step5_default["step_id"], "step5")
            self.assertTrue(
                step5_default["files_to_review"][0].endswith("alerts.csv")
            )

            explicit = run_step.build_interaction_payload(
                "step1",
                report,
                {
                    "step1": {
                        "title": "Identity",
                        "outputs": ["one.json"],
                        "notes": ["review one"],
                        "interaction": {
                            "type": "decision",
                            "question": "",
                            "reason_code": "step1_source_ref_not_found",
                            "options": [
                                {},
                                {"id": "continue", "label": "Continue"},
                            ],
                            "required_fields": ["custom_field"],
                            "fallback_inputs": [{"field": "fallback"}],
                            "scope_preview": {"count": 1},
                            "recommended_selection_options": None,
                            "missing_inputs": [{"field": "missing"}],
                        },
                    },
                },
                project,
            )
            self.assertTrue(explicit["files_to_review"][0].endswith("one.json"))
            self.assertIn("review one", "\n".join(explicit["checklist_lines"]))
            self.assertIn("custom_field", explicit["response_schema"]["properties"])
            self.assertTrue(explicit["fallback_inputs"])
            self.assertEqual(explicit["scope_preview"], {"count": 1})
            self.assertNotIn("recommended_selection_options", explicit)
            self.assertEqual(explicit["missing_inputs"], [{"field": "missing"}])

    def test_build_interaction_payload_step4_scope_branch_matrix(self):
        targets = []
        for index in range(12):
            targets.append({
                "selection_key": "" if index == 1 else f"coord:g:lib-{index}",
                "coord": "" if index == 1 else f"g:lib-{index}",
                "name": f"lib-{index}",
                "api_count": index + 1,
                "high_risk_api_count": index % 2,
                "business_exact_referenced_api_count": index,
                "business_candidate_referenced_api_count": index + 2,
                "business_reference_occurrence_count": index + 3,
                "business_bytecode_scan_status": "complete",
                "dependency_source_status": "available",
                "impact_priority_rank": index + 1,
                "recommendation_reason": "reason" if index else "",
                "recommended": index < 2,
                "change_types": "REMOVED",
                "detail": "detail",
            })
        summary = {
            "available_target_count": 12,
            "available_targets": targets,
        }
        existing_selection = {
            "selected_coords": ["g:lib-0"],
            "selected_names": ["lib-1"],
            "matched_coords": ["g:lib-0"],
            "matched_row_count": 1,
            "unmatched_coords": ["g:missing"],
            "unmatched_names": ["missing"],
        }
        manifest = {
            "step4": {
                "title": "API changes",
                "requires_scope_confirmation": True,
                "scope_confirmation_min_candidates": 2,
                "interaction": {
                    "question": "Choose scope",
                    "options": [{"id": "continue"}, {"id": "cancel"}],
                },
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            report = project / "report"
            with patch.object(
                run_step, "read_csv_rows", return_value=[],
            ), patch.object(
                run_step,
                "build_step5_dependency_selection_summary",
                return_value=summary,
            ), patch.object(
                run_step,
                "build_step5_selection_summary",
                return_value=existing_selection,
            ):
                payload = run_step.build_interaction_payload(
                    "step4",
                    report,
                    manifest,
                    project,
                    run_context={
                        "step5_selected_coords": ["g:lib-0"],
                        "step5_selected_names": ["lib-1"],
                    },
                )
            self.assertEqual(
                payload["scope_preview"]["available_dependency_count"], 12,
            )
            self.assertEqual(
                payload["scope_preview"]["total_api_count"],
                sum(range(1, 13)),
            )
            self.assertEqual(len(payload["selection_options"]), 10)
            self.assertEqual(
                len(payload["selection_resolution"]["options"]), 12,
            )
            card = "\n".join(payload["checklist_lines"])
            self.assertIn("当前已选", card)

            with patch.object(
                run_step, "read_csv_rows", return_value=[{"api": "one"}],
            ), patch.object(
                run_step,
                "build_step5_dependency_selection_summary",
                return_value={
                    "available_target_count": 1,
                    "available_targets": targets[:1],
                },
            ):
                self.assertIsNone(run_step.build_interaction_payload(
                    "step4", report, manifest, project,
                ))

            non_scope_manifest = {
                "step4": {
                    "interaction": {
                        "options": [{"id": "continue"}],
                    },
                },
            }
            with patch.object(
                run_step, "read_csv_rows", return_value=[{"api": "one"}],
            ), patch.object(
                run_step,
                "build_step5_dependency_selection_summary",
                return_value={
                    "available_target_count": 2,
                    "available_targets": targets[:2],
                },
            ), patch.object(
                run_step,
                "build_step5_selection_summary",
                return_value={
                    "selected_coords": [],
                    "selected_names": [],
                    "matched_coords": [],
                    "matched_row_count": 0,
                    "unmatched_coords": [],
                    "unmatched_names": [],
                },
            ):
                one_row = run_step.build_interaction_payload(
                    "step4", report, non_scope_manifest, project,
                    run_context=None,
                )
            self.assertEqual(one_row["scope_preview"]["total_api_count"], 1)

            for existing in (
                {
                    "selected_coords": [],
                    "selected_names": ["lib-1"],
                    "matched_coords": [],
                    "matched_row_count": 0,
                    "unmatched_coords": [],
                    "unmatched_names": [],
                },
                {
                    "selected_coords": ["g:lib-0"],
                    "selected_names": [],
                    "matched_coords": [],
                    "matched_row_count": 0,
                    "unmatched_coords": [],
                    "unmatched_names": [],
                },
            ):
                with self.subTest(existing=existing), patch.object(
                    run_step, "read_csv_rows", return_value=[],
                ), patch.object(
                    run_step,
                    "build_step5_dependency_selection_summary",
                    return_value={
                        "available_target_count": 2,
                        "available_targets": targets[:2],
                    },
                ), patch.object(
                    run_step,
                    "build_step5_selection_summary",
                    return_value=existing,
                ):
                    self.assertIsNotNone(run_step.build_interaction_payload(
                        "step4", report, non_scope_manifest, project,
                    ))

    def test_build_interaction_payload_step5_four_state_matrix(self):
        manifest = {
            "step5": {
                "title": "Call chain",
                "outputs": ["evidence/call_chain/summary.json"],
                "interaction": {
                    "type": "review",
                    "question": "Review",
                    "options": [{"id": "continue"}],
                    "recommended_selection_options": [],
                    "recommended_candidate_count": 0,
                },
            },
        }
        variants = [
            {"api": "api.direct", "user_reason": "direct reason"},
            {"api_name": "api.fallback", "reason": "fallback reason"},
            {},
        ]
        rows = [
            {"severity": f"P{index + 1}", "coord": f"g:{index}", **item}
            for index, item in enumerate(variants)
        ]
        summary = {
            "reachable": 5,
            "uncertain": 4,
            "not_analyzed": 3,
            "not_found_in_static_analysis": 2,
            "user_conclusion_summary": {
                "probable_impact": 2,
                "inconclusive": 3,
            },
            "quality_gate": {"inconclusive": 1, "probable_impact": 1},
            "reachable_apis": rows,
            "uncertain_apis": rows,
            "not_analyzed_apis": rows,
            "not_found_apis": rows,
        }
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            report = project / "report"
            summary_path = run_step.step5_call_chain_dir(report) / "summary.json"
            run_step.write_json(summary_path, summary)
            state = run_step.new_main_state(report)
            state["step4"]["output"] = {
                "step5_selected_coords": ["g:from-step4"],
            }
            state["step5"]["input"] = {
                "step5_selected_names": ["from-step5-input"],
            }
            payload = run_step.build_interaction_payload(
                "step5",
                report,
                manifest,
                project,
                run_context={"step5_selected_coords": ["g:runtime"]},
                main_state=state,
            )
            checklist = "\n".join(payload["checklist_lines"])
            for expected in (
                "reachable（已确认静态触达）=5",
                "uncertain（存在候选证据或已知分析边界）=4",
                "本轮按坐标定向分析: g:runtime",
                "本轮按名称定向分析: from-step5-input",
                "api.direct",
                "api.fallback",
                "未知 API",
                "direct reason",
                "fallback reason",
                "未说明原因",
                "需要运行时验证",
                "当前静态范围未发现路径，不表示安全",
            ):
                self.assertIn(expected, checklist)

            summary["quality_gate"] = {"probable_impact": 1}
            summary["reachable_apis"] = []
            summary["uncertain_apis"] = []
            summary["not_analyzed_apis"] = []
            summary["not_found_apis"] = []
            run_step.write_json(summary_path, summary)
            probable = run_step.build_interaction_payload(
                "step5", report, manifest, project,
                run_context={}, main_state=run_step.new_main_state(report),
            )
            self.assertIn(
                "优先执行相关业务测试",
                "\n".join(probable["checklist_lines"]),
            )

            summary_path.unlink()
            missing_summary = run_step.build_interaction_payload(
                "step5", report, manifest, project,
                run_context=None, main_state=None,
            )
            self.assertIn(
                "reachable（已确认静态触达）=0",
                "\n".join(missing_summary["checklist_lines"]),
            )

            existing_resolution_manifest = {
                "step5": {
                    "interaction": {
                        "options": [{"id": "continue"}],
                        "selection_resolution": {
                            "enabled": True,
                            "options": [{
                                "selection_key": "coord:g:a",
                                "coord": "g:a",
                                "name": "a",
                            }],
                        },
                    },
                },
            }
            existing_resolution = run_step.build_interaction_payload(
                "step5",
                report,
                existing_resolution_manifest,
                project,
                main_state=run_step.new_main_state(report),
            )
            self.assertEqual(
                existing_resolution["selection_resolution"]["options"][0]["coord"],
                "g:a",
            )

            no_option_manifest = {
                "step5": {
                    "interaction": {"options": [{"id": "continue"}]},
                },
            }
            with patch.object(
                run_step,
                "build_report_dir_step5_selection_resolution",
                return_value={"enabled": True},
            ):
                no_options = run_step.build_interaction_payload(
                    "step5", report, no_option_manifest, project,
                )
            self.assertEqual(no_options["selection_options"], [])

    def test_augment_interaction_restart_keeps_all_declared_actions(self):
        augmented = run_step.augment_interaction_meta_with_restart_option(
            "step5",
            {
                "options": [
                    {"id": "rerun_current_step"},
                    {"id": "continue"},
                ],
            },
        )
        action_schema = augmented["response_schema"]["properties"]["action"]
        self.assertEqual(action_schema["type"], "string")
        self.assertEqual(
            action_schema["enum"],
            ["rerun_current_step", "continue", "restart_from_step"],
        )
        for action in action_schema["enum"]:
            with self.subTest(action=action):
                run_step.validate_pending_interaction_response(
                    augmented,
                    {
                        "action": action,
                        **(
                            {"restart_step_id": "step5"}
                            if action == "restart_from_step"
                            else {}
                        ),
                    },
                )

    def test_augment_interaction_restart_handles_empty_and_existing_contracts(self):
        empty = run_step.augment_interaction_meta_with_restart_option("", None)
        self.assertEqual(
            empty["options"],
            [{
                "id": "restart_from_step",
                "label": "从指定步骤重跑",
                "description": "通过对话指定 restart_step_id，从该步骤重新执行。",
            }],
        )
        self.assertEqual(
            empty["response_schema"]["properties"]["restart_step_id"]["enum"],
            run_step.STEP_SEQUENCE,
        )

        existing = run_step.augment_interaction_meta_with_restart_option(
            "step3",
            {
                "options": [
                    {},
                    {"id": "continue"},
                    {"id": "restart_from_step", "label": "existing"},
                ],
                "response_schema": {
                    "required": [],
                    "properties": {
                        "action": {
                            "type": "custom",
                            "description": "existing description",
                            "enum": [None, "", "continue", " continue "],
                        },
                        "restart_step_id": {
                            "type": "string",
                            "enum": ["step2"],
                        },
                    },
                },
            },
        )
        self.assertEqual(len(existing["options"]), 3)
        self.assertEqual(
            existing["response_schema"]["properties"]["action"],
            {
                "type": "custom",
                "description": "existing description",
                "enum": ["continue", "restart_from_step"],
            },
        )
        self.assertEqual(
            existing["response_schema"]["properties"]["restart_step_id"]["enum"],
            ["step2"],
        )
        self.assertEqual(existing["response_schema"]["required"], [])

    def test_validate_pending_response_short_circuit_boundaries(self):
        run_step.validate_pending_interaction_response(None, {})

        blank_request = self._validation_interaction(
            step_id="step1",
            reason_code="STEP1_REMOTE_SOURCE_UNAVAILABLE",
            ref_resolution_requests=[{
                "side": "",
                "field": "",
                "status": "fetch_failed",
                "requested_ref": "",
            }],
        )
        run_step.validate_pending_interaction_response(
            blank_request, {"action": "continue"},
        )

        no_previous_ref = self._validation_interaction(
            step_id="step1",
            reason_code="STEP1_SOURCE_REF_NOT_FOUND",
            properties={"base_branch": {"type": "string"}},
            ref_resolution_requests=[{
                "side": "base",
                "field": "base_branch",
                "status": "ambiguous",
                "requested_ref": "",
            }],
        )
        run_step.validate_pending_interaction_response(
            no_previous_ref,
            {"action": "continue", "base_branch": "main"},
        )
        run_step.validate_pending_interaction_response(
            no_previous_ref,
            {"action": "cancel"},
        )

        empty_selection = self._validation_interaction(properties={
            "selected_targets": {"type": "array"},
        })
        with self.assertRaisesRegex(
            run_step.StepError, "不支持 selected_targets",
        ):
            run_step.validate_pending_interaction_response(
                empty_selection,
                {"action": "continue", "selected_targets": []},
            )

        malformed_skip = self._dependency_ambiguity_interaction()
        with self.assertRaisesRegex(
            run_step.StepError, "skip_dependency_source_coords 必须是字符串数组",
        ):
            run_step.validate_pending_interaction_response(
                malformed_skip,
                {
                    "action": "continue",
                    "skip_dependency_source_coords": {},
                },
            )

        candidate_default = self._dependency_ambiguity_interaction()
        candidate_default["dependency_source_ambiguities"] = [
            {"coord": "g:a"},
        ]
        run_step.validate_pending_interaction_response(
            candidate_default,
            {
                "action": "continue",
                "skip_dependency_source_coords": "g:a",
            },
        )

        for selections, message in (
            ([{}], r"不存在或已过期：\(空\)"),
            (
                [
                    {"selection_key": "a-main"},
                    {"selection_key": "a-main"},
                ],
                "只能选择一个版本方案",
            ),
        ):
            response = {
                "action": "continue",
                "dependency_source_ref_selections": selections,
                "skip_dependency_source_coords": ["g:b"],
            }
            with self.subTest(selections=selections), self.assertRaisesRegex(
                run_step.StepError, message,
            ):
                run_step.validate_pending_interaction_response(
                    self._dependency_ambiguity_interaction(), response,
                )

    @staticmethod
    def _binary_config_payload(root, **overrides):
        base_jdk = root / "jdk-base"
        current_jdk = root / "jdk-current"
        base_jdk.mkdir(exist_ok=True)
        current_jdk.mkdir(exist_ok=True)
        payload = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"jdk_home": str(base_jdk), "artifacts": []},
            "current": {"jdk_home": str(current_jdk), "artifacts": []},
        }
        payload.update(overrides)
        return payload, {
            "base_jdk_home": str(base_jdk),
            "current_jdk_home": str(current_jdk),
        }

    def test_binary_pipeline_config_path_covers_explicit_and_materialized_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report"
            relative = root / "pipeline.json"
            relative.write_text("{}", encoding="utf-8")

            self.assertEqual(
                run_step._binary_pipeline_config_path(
                    {"binary_pipeline_config": "pipeline.json"}, root, report,
                ),
                relative.resolve(),
            )
            with self.assertRaisesRegex(run_step.StepError, "BINARY_PIPELINE_CONFIG_MISSING"):
                run_step._binary_pipeline_config_path(
                    {"binary_pipeline_config": "missing.json"}, root, report,
                )

            failure = run_step.BinaryRuntimeMaterializationError(
                "BINARY_RUNTIME_ARTIFACT_MISSING", "fixture failure",
            )
            with patch.object(
                run_step, "materialize_binary_pipeline_config", side_effect=failure,
            ), self.assertRaises(run_step.StepError) as raised:
                run_step._binary_pipeline_config_path({}, root, report)

            with patch.object(
                run_step,
                "materialize_binary_pipeline_config",
                return_value={"schema": "materialized"},
            ):
                none_context_path = run_step._binary_pipeline_config_path(
                    None, root, report,
                )
            self.assertTrue(none_context_path.is_file())
            with self.assertRaises(run_step.StepError) as context_error:
                run_step._binary_pipeline_config_path("invalid", root, report)
            self.assertEqual(
                context_error.exception.reason_codes,
                ["BINARY_PIPELINE_CONTEXT_INVALID"],
            )

        self.assertEqual(
            raised.exception.reason_codes,
            [
                "BINARY_RUNTIME_ARTIFACT_MISSING",
                "BINARY_RUNTIME_AUTO_MATERIALIZATION_FAILED",
            ],
        )

    def test_preflight_explicit_binary_config_rejects_invalid_document_shapes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(
                run_step._preflight_explicit_binary_config({}, root), ({}, None),
            )
            config_path = root / "pipeline.json"
            config_path.write_text("{}", encoding="utf-8")
            context = {"binary_pipeline_config": str(config_path)}

            read_failures = (
                OSError("unreadable"),
                UnicodeError("invalid encoding"),
                json.JSONDecodeError("invalid json", "{", 1),
            )
            for failure in read_failures:
                with self.subTest(read_failure=type(failure).__name__), patch.object(
                    run_step, "read_json", side_effect=failure,
                ), self.assertRaises(run_step.StepError) as raised:
                    run_step._preflight_explicit_binary_config(context, root)
                self.assertEqual(
                    raised.exception.reason_codes, ["STEP0_BINARY_CONFIG_INVALID"],
                )

            malformed_documents = (
                None,
                [],
                "not-an-object",
                7,
                {},
                {"schema": "unsupported"},
            )
            for document in malformed_documents:
                config_path.write_text(json.dumps(document), encoding="utf-8")
                with self.subTest(document=document), self.assertRaises(
                    run_step.StepError,
                ) as raised:
                    run_step._preflight_explicit_binary_config(context, root)
                self.assertEqual(
                    raised.exception.reason_codes, ["STEP0_BINARY_CONFIG_INVALID"],
                )

    def test_preflight_explicit_binary_config_rejects_nested_shape_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "pipeline.json"
            base, selected = self._binary_config_payload(root)
            selected["binary_pipeline_config"] = str(path)
            mutations = (
                ("base-side-missing", lambda payload: payload.pop("base"), "STEP0_BINARY_CONFIG_INVALID"),
                ("base-side-list", lambda payload: payload.update(base=[]), "STEP0_BINARY_CONFIG_INVALID"),
                ("current-side-string", lambda payload: payload.update(current="bad"), "STEP0_BINARY_CONFIG_INVALID"),
                (
                    "jdk-home-missing",
                    lambda payload: payload["base"].pop("jdk_home"),
                    "STEP0_BINARY_CONFIG_INVALID",
                ),
                (
                    "artifacts-missing",
                    lambda payload: payload["base"].pop("artifacts"),
                    "STEP0_BINARY_CONFIG_INVALID",
                ),
                (
                    "artifact-container-object",
                    lambda payload: payload["base"].update(artifacts={"path": "a.jar"}),
                    "STEP0_BINARY_CONFIG_INVALID",
                ),
                (
                    "artifact-container-string",
                    lambda payload: payload["base"].update(artifacts="a.jar"),
                    "STEP0_BINARY_CONFIG_INVALID",
                ),
                (
                    "artifact-item-string",
                    lambda payload: payload["base"].update(artifacts=["a.jar"]),
                    "STEP0_BINARY_CONFIG_INVALID",
                ),
                (
                    "artifact-item-list",
                    lambda payload: payload["base"].update(artifacts=[[]]),
                    "STEP0_BINARY_CONFIG_INVALID",
                ),
                (
                    "policy-list",
                    lambda payload: payload.update(tool_execution_policy=[]),
                    "STEP0_BINARY_CONFIG_TOOL_POLICY_INVALID",
                ),
                (
                    "policy-string",
                    lambda payload: payload.update(tool_execution_policy="invalid"),
                    "STEP0_BINARY_CONFIG_TOOL_POLICY_INVALID",
                ),
            )
            for label, mutate, reason_code in mutations:
                payload = json.loads(json.dumps(base))
                mutate(payload)
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.subTest(label=label), self.assertRaises(
                    run_step.StepError,
                ) as raised:
                    run_step._preflight_explicit_binary_config(selected, root)
                self.assertEqual(
                    raised.exception.reason_codes,
                    [reason_code],
                )

    def test_preflight_explicit_binary_config_artifact_identity_and_slot_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "pipeline.json"
            artifact = root / "artifact.jar"
            artifact.write_bytes(b"artifact")
            base, selected = self._binary_config_payload(root)
            selected["binary_pipeline_config"] = "pipeline.json"

            def write_artifacts(items):
                payload = json.loads(json.dumps(base))
                payload["base"]["artifacts"] = items
                path.write_text(json.dumps(payload), encoding="utf-8")

            record = {
                "path": str(artifact),
                "sha256": "a" * 64,
                "size_bytes": artifact.stat().st_size,
            }
            write_artifacts([{
                "path": "artifact.jar",
                "content_sha256": "A" * 64,
                "loader_realm": "application",
                "slot": 0,
            }])
            with patch.object(
                run_step, "_preflight_artifact_input", return_value=record,
            ) as preflight:
                result, asm = run_step._preflight_explicit_binary_config(selected, root)
            self.assertIsNone(asm)
            self.assertEqual(result["artifact_count"], 1)
            self.assertEqual(result["artifacts"][0]["side"], "base")
            preflight.assert_called_once_with(artifact.resolve(), side="base")

            write_artifacts([{
                "path": str(artifact),
                "content_sha256": "b" * 64,
                "loader_realm": "application",
                "slot": 0,
            }])
            with patch.object(
                run_step, "_preflight_artifact_input", return_value=record,
            ), self.assertRaises(run_step.StepError) as digest_error:
                run_step._preflight_explicit_binary_config(selected, root)
            self.assertEqual(
                digest_error.exception.reason_codes,
                ["STEP0_BINARY_CONFIG_ARTIFACT_DIGEST_MISMATCH"],
            )

            duplicate = {
                "path": str(artifact),
                "loader_realm": "application",
                "slot": 1,
            }
            write_artifacts([duplicate, duplicate])
            with patch.object(
                run_step, "_preflight_artifact_input", return_value=record,
            ), self.assertRaises(run_step.StepError) as duplicate_error:
                run_step._preflight_explicit_binary_config(selected, root)
            self.assertEqual(
                duplicate_error.exception.reason_codes,
                ["STEP0_BINARY_CONFIG_RUNTIME_SLOT_DUPLICATE"],
            )

            invalid_artifacts = (
                {"path": "", "loader_realm": "application", "slot": 0},
                {"path": str(artifact), "loader_realm": "", "slot": 0},
                {"path": str(artifact), "loader_realm": "application", "slot": True},
                {"path": str(artifact), "loader_realm": "application", "slot": "0"},
                {"path": str(artifact), "loader_realm": "application", "slot": -1},
            )
            for invalid_artifact in invalid_artifacts:
                write_artifacts([invalid_artifact])
                with self.subTest(invalid_artifact=invalid_artifact), patch.object(
                    run_step, "_preflight_artifact_input", return_value=record,
                ), self.assertRaises(run_step.StepError) as invalid_error:
                    run_step._preflight_explicit_binary_config(selected, root)
                self.assertEqual(
                    invalid_error.exception.reason_codes,
                    ["STEP0_BINARY_CONFIG_INVALID"],
                )

            write_artifacts([])
            missing_selected = dict(selected)
            missing_selected["base_jdk_home"] = ""
            with self.assertRaises(run_step.StepError) as selected_error:
                run_step._preflight_explicit_binary_config(missing_selected, root)
            self.assertEqual(
                selected_error.exception.reason_codes,
                ["STEP0_BINARY_CONFIG_JDK_MISMATCH"],
            )

            mismatched = json.loads(json.dumps(base))
            mismatched["current"]["jdk_home"] = str(root / "different-jdk")
            path.write_text(json.dumps(mismatched), encoding="utf-8")
            with self.assertRaises(run_step.StepError) as jdk_error:
                run_step._preflight_explicit_binary_config(selected, root)
            self.assertEqual(
                jdk_error.exception.reason_codes,
                ["STEP0_BINARY_CONFIG_JDK_MISMATCH"],
            )

    def test_preflight_explicit_binary_config_tool_policy_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "pipeline.json"
            base, selected = self._binary_config_payload(root)
            selected["binary_pipeline_config"] = str(path)

            path.write_text(json.dumps(base), encoding="utf-8")
            default_result, _ = run_step._preflight_explicit_binary_config(
                selected, root
            )
            self.assertEqual(
                default_result["tool_execution_policy"][
                    "oracle_compile_timeout_seconds"
                ],
                300.0,
            )
            self.assertEqual(
                default_result["tool_execution_policy"][
                    "oracle_javap_time_budget_seconds"
                ],
                3600.0,
            )

            valid_policy = {
                "oracle_compile_timeout_seconds": "0.01",
                "oracle_runtime_timeout_seconds": 300,
                "oracle_runtime_phase_time_budget_seconds": 1,
                "oracle_javap_time_budget_seconds": 7200,
                "oracle_max_attempts": "3",
            }
            payload = json.loads(json.dumps(base))
            payload["tool_execution_policy"] = valid_policy
            path.write_text(json.dumps(payload), encoding="utf-8")
            result, _ = run_step._preflight_explicit_binary_config(selected, root)
            self.assertEqual(
                result["tool_execution_policy"],
                {
                    "oracle_compile_timeout_seconds": 0.01,
                    "oracle_runtime_timeout_seconds": 300.0,
                    "oracle_runtime_phase_time_budget_seconds": 1.0,
                    "oracle_javap_time_budget_seconds": 7200.0,
                    "oracle_max_attempts": 3,
                },
            )

            invalid_policies = {
                "unknown": {"unexpected": 1},
                "compile-bool": {"oracle_compile_timeout_seconds": True},
                "runtime-bool": {"oracle_runtime_timeout_seconds": False},
                "phase-bool": {"oracle_runtime_phase_time_budget_seconds": True},
                "javap-bool": {"oracle_javap_time_budget_seconds": False},
                "attempts-bool": {"oracle_max_attempts": True},
                "attempts-float": {"oracle_max_attempts": 2.0},
                "compile-type": {"oracle_compile_timeout_seconds": []},
                "compile-low": {"oracle_compile_timeout_seconds": 0},
                "compile-high": {"oracle_compile_timeout_seconds": 301},
                "runtime-low": {"oracle_runtime_timeout_seconds": 0},
                "runtime-high": {"oracle_runtime_timeout_seconds": 301},
                "phase-low": {"oracle_runtime_phase_time_budget_seconds": 0},
                "phase-high": {"oracle_runtime_phase_time_budget_seconds": 7201},
                "javap-low": {"oracle_javap_time_budget_seconds": 0},
                "javap-high": {"oracle_javap_time_budget_seconds": 7201},
                "attempts-low": {"oracle_max_attempts": 0},
                "attempts-high": {"oracle_max_attempts": 4},
                "nan": {"oracle_runtime_timeout_seconds": "nan"},
            }
            for label, policy in invalid_policies.items():
                payload = json.loads(json.dumps(base))
                payload["tool_execution_policy"] = policy
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.subTest(label=label), self.assertRaises(
                    run_step.StepError,
                ) as raised:
                    run_step._preflight_explicit_binary_config(selected, root)
                self.assertEqual(
                    raised.exception.reason_codes,
                    ["STEP0_BINARY_CONFIG_TOOL_POLICY_INVALID"],
                )

    def test_preflight_explicit_binary_config_asm_resolution_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "pipeline.json"
            asm = root / "asm.jar"
            asm.write_bytes(b"asm")
            base, selected = self._binary_config_payload(root)
            selected["binary_pipeline_config"] = str(path)
            base["asm_jar"] = "asm.jar"
            path.write_text(json.dumps(base), encoding="utf-8")

            with patch.object(
                run_step, "resolve_asm_jar", return_value=asm.resolve(),
            ) as resolve:
                _result, resolved = run_step._preflight_explicit_binary_config(
                    selected, root,
                )
            self.assertEqual(resolved, asm.resolve())
            resolve.assert_called_once_with(asm.resolve())

            failure = run_step.BinaryAsmError("ASM_JAR_INVALID", "invalid asm")
            with patch.object(
                run_step, "resolve_asm_jar", side_effect=failure,
            ), self.assertRaises(run_step.StepError) as raised:
                run_step._preflight_explicit_binary_config(selected, root)
            self.assertEqual(
                raised.exception.reason_codes,
                ["STEP0_ASM_RESOURCE_PREFLIGHT_FAILED", "ASM_JAR_INVALID"],
            )

    def test_resolved_binary_config_rejects_malformed_overlay_and_context_shapes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report"
            path = root / "pipeline.json"
            context = {"binary_pipeline_config": str(path)}
            malformed = (
                (None, "document-none"),
                ([], "document-list"),
                ({"source_overlay": []}, "overlay-list"),
                ({"source_overlay": "invalid"}, "overlay-string"),
                ({"source_overlay": {"source_sets": []}}, "sets-empty"),
                ({"source_overlay": {"source_sets": {}}}, "sets-object"),
                ({"source_overlay": {"source_sets": ["bad"]}}, "set-string"),
            )
            for document, label in malformed:
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.subTest(label=label), self.assertRaises(run_step.StepError):
                    run_step._resolved_binary_pipeline_config_path(
                        context, root, report,
                    )

            valid = {"schema": "java-upgrade-analyzer.binary-pipeline-input.v1"}
            context_shapes = (
                ("dependency_source_snapshots", ["bad"]),
                ("dependency_source_snapshots", {"bad": "value"}),
                ("dependency_source_git_materializations", ["bad"]),
                ("dependency_source_git_materializations", {"bad": "value"}),
                ("pinned_source_snapshot", ["bad"]),
                ("source_dirs", "src/main/java"),
                ("dependency_source_mappings", {"g:a": "dependency"}),
                ("step0_preflight", "invalid"),
                ("step0_preflight", {"sides": "invalid"}),
                ("step0_preflight", {"sides": {"base": "invalid"}}),
                ("step0_preflight", {"sides": {"base": {"jdk": "invalid"}}}),
            )
            for key, value in context_shapes:
                path.write_text(json.dumps(valid), encoding="utf-8")
                malformed_context = {
                    "binary_pipeline_config": str(path),
                    "dependency_source_mappings": ["g:a=dependency/src/main/java"],
                    key: value,
                }
                with self.subTest(key=key, value=value), self.assertRaises(
                    run_step.StepError,
                ):
                    run_step._resolved_binary_pipeline_config_path(
                        malformed_context, root, report,
                    )

    def test_resolved_binary_config_rebuilds_business_source_identity_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report"
            source = root / "module" / "src" / "main" / "java"
            source.mkdir(parents=True)
            path = root / "pipeline.json"
            path.write_text(json.dumps({
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                "source_overlay": {
                    "source_sets": [{"owner_type": "business", "source_dirs": ["mutable"]}],
                },
            }), encoding="utf-8")
            commit = "a" * 40
            pinned = {
                "schema": run_step.PINNED_SOURCE_SNAPSHOT_SCHEMA,
                "commit": commit,
                "project_path": ".",
                "target_module": "module",
                "active_maven_profiles": [],
            }
            contexts = (
                (
                    "target-module-and-pinned",
                    {
                        "target_module": "module",
                        "current_resolved_commit": commit,
                        "pinned_source_snapshot": pinned,
                    },
                    "module",
                    commit,
                ),
                (
                    "primary-module-and-current",
                    {"primary_module": "primary", "current_resolved_commit": "B" * 40},
                    "primary",
                    "B" * 40,
                ),
                ("default-values", {}, "BUSINESS", "content-addressed-only"),
            )
            for label, extra, owner, revision in contexts:
                if label != "target-module-and-pinned":
                    path.write_text(json.dumps({
                        "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                    }), encoding="utf-8")
                context = {
                    "binary_pipeline_config": str(path),
                    "source_dirs": ["", str(source)],
                    **extra,
                }
                resolved_path = run_step._resolved_binary_pipeline_config_path(
                    context, root, report,
                )
                resolved = json.loads(resolved_path.read_text(encoding="utf-8"))
                source_set = resolved["source_overlay"]["source_sets"][0]
                with self.subTest(label=label):
                    self.assertEqual(source_set["owner_coord"], owner)
                    self.assertEqual(source_set["snapshot_revision"], revision)
                    self.assertEqual(source_set["source_dirs"], [str(source.resolve())])

            with patch.object(
                run_step.os.path, "commonpath", side_effect=ValueError("different drives"),
            ), self.assertRaises(run_step.StepError) as raised:
                run_step._resolved_binary_pipeline_config_path(
                    {
                        "binary_pipeline_config": str(path),
                        "source_dirs": [str(source)],
                    },
                    root,
                    report,
                )
            self.assertEqual(
                raised.exception.reason_codes,
                ["BINARY_SOURCE_COMMON_ROOT_REQUIRED"],
            )

    def test_resolved_binary_config_dependency_revision_precedence_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report"
            path = root / "pipeline.json"
            path.write_text(json.dumps({
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            }), encoding="utf-8")
            module = root / "dependency"
            source = module / "src" / "main" / "java"
            source.mkdir(parents=True)
            base_context = {
                "binary_pipeline_config": str(path),
                "dependency_source_mappings": [
                    "",
                    str(root / "unbound"),
                    "g:a=",
                    f"g:a={source}",
                    f"g:a={source}",
                ],
            }
            cases = (
                (
                    "snapshot",
                    {
                        "dependency_source_snapshots": [{"coord": "g:a", "commit": "A" * 40}],
                        "dependency_source_git_materializations": [{}],
                    },
                    "a" * 40,
                    "should-not-be-used",
                ),
                (
                    "materialization",
                    {
                        "dependency_source_snapshots": [{"coord": "", "commit": "ignored"}],
                        "dependency_source_git_materializations": [
                            {},
                            {"repo_path": str(root / "other"), "resolved_commit": "B" * 40},
                            {"repo_path": str(module), "resolved_commit": ""},
                            {"repo_path": str(module), "resolved_commit": "C" * 40},
                        ],
                    },
                    "c" * 40,
                    "should-not-be-used",
                ),
                ("local-head", {}, "d" * 40 + "+content-addressed-worktree", "d" * 40),
                ("content-only", {}, "content-addressed-only", ""),
            )
            for label, extra, expected, local_head in cases:
                with self.subTest(label=label), patch.object(
                    run_step, "_dependency_source_git_head", return_value=local_head,
                ) as head:
                    resolved_path = run_step._resolved_binary_pipeline_config_path(
                        {**base_context, **extra}, root, report,
                    )
                    resolved = json.loads(resolved_path.read_text(encoding="utf-8"))
                source_set = resolved["source_overlay"]["source_sets"][0]
                self.assertEqual(source_set["snapshot_revision"], expected)
                self.assertEqual(source_set["source_dirs"], [str(source.resolve())])
                self.assertEqual(
                    resolved["source_inputs"]["dependencies"],
                    {"status": "available", "origin": "provided"},
                )
                if label in {"snapshot", "materialization"}:
                    head.assert_not_called()

            with patch.object(
                run_step, "_guess_module_root_from_source_dir", return_value="/",
            ), patch.object(
                run_step, "_dependency_source_git_head", return_value="",
            ):
                resolved_path = run_step._resolved_binary_pipeline_config_path(
                    {
                        "binary_pipeline_config": str(path),
                        "dependency_source_mappings": [f"g:root={source}"],
                    },
                    root,
                    report,
                )
            resolved = json.loads(resolved_path.read_text(encoding="utf-8"))
            self.assertEqual(
                resolved["source_overlay"]["source_sets"][0]["module"],
                "g:root",
            )

    def test_resolved_binary_config_preserves_direct_overlay_and_injects_jdk_identities(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report"
            path = root / "pipeline.json"
            path.write_text(json.dumps({
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                "base": {"artifacts": []},
                "source_overlay": {"source_sets": [
                    {},
                    {"owner_type": "business", "source_dirs": ["business"]},
                    {"owner_type": "dependency", "source_dirs": ["dependency"]},
                    {"owner_type": "other", "source_dirs": ["other"]},
                ]},
            }), encoding="utf-8")
            context = {
                "binary_pipeline_config": str(path),
                "analysis_mode": "checkout_build",
                "step0_preflight": {"sides": {
                    "base": {"jdk": {"jdk_preflight_identity": "base-id"}},
                    "current": {"jdk": {"jdk_preflight_identity": "current-id"}},
                }},
            }
            resolved_path = run_step._resolved_binary_pipeline_config_path(
                context, root, report,
            )
            resolved = json.loads(resolved_path.read_text(encoding="utf-8"))

        self.assertEqual(
            resolved["source_inputs"]["business"],
            {"status": "available", "origin": "checkout_build"},
        )
        self.assertEqual(
            resolved["source_inputs"]["dependencies"],
            {"status": "available", "origin": "provided"},
        )
        self.assertEqual(resolved["base"]["jdk_preflight_identity"], "base-id")
        self.assertEqual(
            resolved["current"]["jdk_preflight_identity"], "current-id",
        )

    def test_resolved_binary_config_context_and_identity_shape_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report"
            path = root / "pipeline.json"
            path.write_text(json.dumps({
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            }), encoding="utf-8")

            with self.assertRaises(run_step.StepError) as non_object:
                run_step._resolved_binary_pipeline_config_path([], root, report)
            self.assertEqual(
                non_object.exception.reason_codes,
                ["BINARY_PIPELINE_CONTEXT_INVALID"],
            )
            with patch.object(
                run_step, "_binary_pipeline_config_path", return_value=path,
            ):
                resolved_path = run_step._resolved_binary_pipeline_config_path(
                    None, root, report,
                )
            self.assertTrue(resolved_path.is_file())

            path.write_text(json.dumps({
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                "base": "invalid",
            }), encoding="utf-8")
            with self.assertRaises(run_step.StepError) as side_error:
                run_step._resolved_binary_pipeline_config_path(
                    {
                        "binary_pipeline_config": str(path),
                        "step0_preflight": {"sides": {
                            "base": {"jdk": {"jdk_preflight_identity": "base-id"}},
                        }},
                    },
                    root,
                    report,
                )
            self.assertEqual(
                side_error.exception.reason_codes,
                ["BINARY_PIPELINE_CONFIG_INVALID"],
            )


if __name__ == "__main__":
    unittest.main()
