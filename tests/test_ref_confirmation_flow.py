import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import run_step  # noqa: E402
import s4_jar_compare as step4  # noqa: E402
import s2_context_from_deps as step2  # noqa: E402


class RefConfirmationFlowTest(unittest.TestCase):
    def test_step4_remote_commit_override_matches_live_remote_commit(self):
        commit = "a" * 40
        record = {
            "ref": "origin/release",
            "short_name": "release",
            "commit": commit,
            "canonical_ref": "refs/heads/release",
            "remote": "origin",
        }
        inventory = {
            "remotes": [record["ref"]],
            "remote_records": [record],
            "remote_failures": [],
            "heads": [],
            "tags": [],
        }
        with patch.object(step4, "_list_repo_refs", return_value=inventory), patch.object(
            step4, "resolve_local_source_ref"
        ) as local_resolver:
            resolved, reason, candidates = step4.resolve_repo_ref_for_version(
                "/repo",
                "1.0.0",
                selected_ref=commit[:12],
                expected_commit=commit,
            )

        self.assertEqual(resolved, "origin/release")
        self.assertIn("kind=remote_commit", reason)
        self.assertEqual(candidates[0]["commit"], commit)
        local_resolver.assert_not_called()

    def test_step4_remote_commit_override_materializes_as_remote_source(self):
        old_commit = "a" * 40
        new_commit = "b" * 40
        records = [
            {
                "ref": "origin/release-1",
                "short_name": "release-1",
                "commit": old_commit,
                "canonical_ref": "refs/heads/release-1",
                "remote": "origin",
            },
            {
                "ref": "origin/release-2",
                "short_name": "release-2",
                "commit": new_commit,
                "canonical_ref": "refs/heads/release-2",
                "remote": "origin",
            },
        ]
        inventory = {
            "remotes": [item["ref"] for item in records],
            "remote_records": records,
            "remote_failures": [],
            "heads": [],
            "tags": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".git").mkdir()
            with patch.object(step4, "_list_repo_refs", return_value=inventory), patch.object(
                step4,
                "materialize_remote_source_candidate",
                side_effect=[
                    {"status": "remote_source_resolved", "resolved_commit": old_commit},
                    {"status": "remote_source_resolved", "resolved_commit": new_commit},
                ],
            ):
                plan = step4.resolve_gitdiff_ref_plan_for_row(
                    {"coord": "com.acme:demo", "old_version": "1.0", "new_version": "2.0"},
                    {"repo_path": tmp, "module_path": tmp},
                    {},
                    {
                        "com.acme:demo": {
                            "old_ref": old_commit,
                            "new_ref": new_commit,
                            "expected_old_commit": old_commit,
                            "expected_new_commit": new_commit,
                        }
                    },
                )

        self.assertEqual(plan["status"], "matched")
        self.assertEqual(plan["old_source"]["status"], "remote_source_resolved")
        self.assertEqual(plan["new_source"]["status"], "remote_source_resolved")
        self.assertEqual(plan["base_ref"], old_commit)
        self.assertEqual(plan["cur_ref"], new_commit)

    def test_step4_unavailable_remote_keeps_local_candidate_as_metadata(self):
        local_commit = "b" * 40
        inventory = {
            "remotes": [],
            "remote_records": [],
            "remote_failures": [],
            "heads": [],
            "tags": [],
        }
        with patch.object(step4, "_list_repo_refs", return_value=inventory), patch.object(
            step4,
            "resolve_local_source_ref",
            return_value={
                "status": "awaiting_local_source_confirmation",
                "local_candidate_commit": local_commit,
                "dirty": False,
            },
        ) as local_resolver:
            resolved, reason, _candidates = step4.resolve_repo_ref_for_version(
                "/repo", "1.0.0", selected_ref=local_commit
            )

        self.assertIsNone(resolved)
        self.assertTrue(reason.startswith("remote_source_unavailable="))
        self.assertIn(f"local_fallback_available={local_commit}", reason)
        self.assertNotIn("user_confirmed_local_source", reason)
        self.assertFalse(local_resolver.call_args.kwargs["allow_local_source"])

    def test_step4_explicit_local_authorization_is_required_before_adoption(self):
        local_commit = "c" * 40
        inventory = {
            "remotes": [],
            "remote_records": [],
            "remote_failures": [],
            "heads": [],
            "tags": [],
        }
        with patch.object(step4, "_list_repo_refs", return_value=inventory), patch.object(
            step4,
            "resolve_local_source_ref",
            return_value={
                "status": "user_confirmed_local_source",
                "resolved_commit": local_commit,
                "dirty": False,
            },
        ) as local_resolver:
            resolved, reason, _candidates = step4.resolve_repo_ref_for_version(
                "/repo",
                "1.0.0",
                selected_ref=local_commit,
                allow_local_source=True,
            )

        self.assertEqual(resolved, local_commit)
        self.assertIn("user_confirmed_local_source", reason)
        self.assertTrue(local_resolver.call_args.kwargs["allow_local_source"])

    def test_step4_fetch_failure_exposes_local_fallback_without_adopting_it(self):
        old_candidate = {
            "ref": "origin/v1", "commit": "a" * 40,
            "canonical_ref": "refs/heads/v1", "remote": "origin",
        }
        new_candidate = {
            "ref": "origin/v2", "commit": "b" * 40,
            "canonical_ref": "refs/heads/v2", "remote": "origin",
        }
        local_commit = "d" * 40
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".git").mkdir()
            with patch.object(
                step4,
                "resolve_repo_ref_pair_for_versions",
                return_value=(
                    "origin/v1", "origin/v2", "matched-old", "matched-new",
                    [old_candidate], [new_candidate],
                ),
            ), patch.object(
                step4,
                "_materialize_resolved_remote_ref",
                side_effect=[
                    ({"status": "remote_fetch_failed"}, "old timeout"),
                    ({"status": "remote_source_resolved", "resolved_commit": "b" * 40}, ""),
                ],
            ), patch.object(
                step4,
                "resolve_local_source_ref",
                return_value={
                    "status": "awaiting_local_source_confirmation",
                    "local_candidate_commit": local_commit,
                    "dirty": False,
                },
            ) as local_resolver:
                plan = step4.resolve_gitdiff_ref_plan_for_row(
                    {"coord": "com.acme:demo", "old_version": "1", "new_version": "2"},
                    {"repo_path": tmp, "module_path": tmp},
                    {},
                    {},
                )
            interaction = step4.build_git_ref_confirmation_interaction(tmp, [plan])

        self.assertEqual(plan["pending_kind"], "fetch_failed")
        self.assertEqual(plan["old_source"]["status"], "remote_fetch_failed")
        self.assertEqual(
            plan["local_fallback_available"]["old"]["commit"], local_commit
        )
        self.assertNotEqual(plan["old_source"].get("status"), "user_confirmed_local_source")
        self.assertFalse(local_resolver.call_args.kwargs["allow_local_source"])
        decision = interaction["git_ref_decision_items"][0]
        self.assertEqual(
            decision["local_fallback_available"]["old"]["commit"], local_commit
        )
        self.assertIn("allow_local_source=true", interaction["question"])

    def test_step4_targeted_query_failure_uses_authorized_local_fallback(self):
        old_commit = "a" * 40
        new_commit = "b" * 40
        old_candidate = {
            "ref": "origin/v1", "commit": old_commit,
            "canonical_ref": "refs/heads/v1", "remote": "origin",
        }
        new_candidate = {
            "ref": "origin/v2", "commit": new_commit,
            "canonical_ref": "refs/heads/v2", "remote": "origin",
        }
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".git").mkdir()
            with patch.object(
                step4,
                "resolve_repo_ref_pair_for_versions",
                return_value=(
                    "origin/v1", "origin/v2", "matched-old", "matched-new",
                    [old_candidate], [new_candidate],
                ),
            ), patch.object(
                step4,
                "_materialize_resolved_remote_ref",
                side_effect=[
                    (
                        {
                            "status": "remote_fetch_failed",
                            "failure": {
                                "reason_code": "transient_network_failure",
                            },
                        },
                        "kex_exchange_identification: Connection closed",
                    ),
                    (
                        {
                            "status": "remote_source_resolved",
                            "resolved_commit": new_commit,
                        },
                        "",
                    ),
                ],
            ), patch.object(
                step4,
                "resolve_local_source_ref",
                return_value={
                    "status": "user_confirmed_local_source",
                    "resolved_commit": old_commit,
                    "dirty": False,
                },
            ) as local_resolver:
                plan = step4.resolve_gitdiff_ref_plan_for_row(
                    {
                        "coord": "com.acme:demo",
                        "old_version": "1",
                        "new_version": "2",
                    },
                    {"repo_path": tmp, "module_path": tmp},
                    {},
                    {
                        "com.acme:demo": {
                            "allow_local_source": True,
                        },
                    },
                )

        self.assertEqual(plan["status"], "matched")
        self.assertEqual(
            plan["old_source"]["status"],
            "user_confirmed_local_source",
        )
        self.assertEqual(plan["base_ref"], old_commit)
        self.assertTrue(local_resolver.call_args.kwargs["allow_local_source"])

    def test_canonical_remote_ref_with_different_remote_commits_is_ambiguous(self):
        records = [
            {
                "ref": "origin/release",
                "short_name": "release",
                "commit": "a" * 40,
                "canonical_ref": "refs/heads/release",
                "remote": "origin",
            },
            {
                "ref": "upstream/release",
                "short_name": "release",
                "commit": "b" * 40,
                "canonical_ref": "refs/heads/release",
                "remote": "upstream",
            },
        ]
        with patch.object(step4, "_list_repo_refs", return_value={
            "remotes": [item["ref"] for item in records],
            "remote_records": records,
            "heads": [],
            "tags": [],
        }):
            resolved, reason, _candidates = step4.resolve_repo_ref_for_version(
                "/repo",
                "1.0.0",
                selected_ref="refs/heads/release",
            )

        self.assertIsNone(resolved)
        self.assertEqual(reason, "ambiguous_explicit_remote_ref=refs/heads/release")

    def test_failed_remote_prevents_automatic_version_match(self):
        record = {
            "ref": "origin/release-1.0.0",
            "short_name": "release-1.0.0",
            "commit": "a" * 40,
            "canonical_ref": "refs/heads/release-1.0.0",
            "remote": "origin",
        }
        inventory = {
            "remotes": [record["ref"]],
            "remote_records": [record],
            "remote_failures": [{"remote": "upstream", "reason": "timed out"}],
            "heads": [],
            "tags": [],
        }
        with patch.object(step4, "_list_repo_refs", return_value=inventory):
            resolved, reason, _candidates = step4.resolve_repo_ref_for_version("/repo", "1.0.0")
            explicit, explicit_reason, _ = step4.resolve_repo_ref_for_version(
                "/repo", "1.0.0", selected_ref="origin/release-1.0.0"
            )

        self.assertIsNone(resolved)
        self.assertEqual(reason, "remote_query_failed=timed out")
        self.assertEqual(explicit, "origin/release-1.0.0")
        self.assertIn("selected_by_user", explicit_reason)

    def test_compact_step4_selection_preserves_expected_commits(self):
        pending_item = {
            "coord": "com.acme:demo",
            "repo_path": "/repo/demo",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
            "pending_kind": "ambiguous",
            "old_candidates": [{
                "ref": "origin/release-1.0.0",
                "commit": "a" * 40,
                "score": 140,
                "prefix": "release-",
                "remote_name": "origin",
                "branch_name": "release-1.0.0",
            }],
            "new_candidates": [{
                "ref": "origin/release-2.0.0",
                "commit": "b" * 40,
                "score": 140,
                "prefix": "release-",
                "remote_name": "origin",
                "branch_name": "release-2.0.0",
            }],
        }
        with tempfile.TemporaryDirectory() as tmp:
            interaction = step4.build_git_ref_confirmation_interaction(tmp, [pending_item])
        self.assertEqual(interaction["title"], "确认依赖源码版本")
        self.assertIn("选择不同方案会改变源码差异结果", interaction["question"])
        response = run_step.expand_dependency_git_ref_selections(interaction, {
            "action": "rerun_current_step",
            "dependency_git_ref_selections": [{"coord": "com.acme:demo", "option": 1}],
        })

        override = response["dependency_git_ref_overrides"][0]
        self.assertEqual(override["expected_old_commit"], "a" * 40)
        self.assertEqual(override["expected_new_commit"], "b" * 40)
        self.assertTrue(override["selection_key"].startswith("refpair:"))

    def test_fetch_failure_card_requires_retry_not_ref_selection(self):
        pending_item = {
            "coord": "com.acme:demo",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
            "pending_kind": "fetch_failed",
            "failed_sides": ["old", "new"],
            "selected_old_ref": "origin/v1",
            "selected_new_ref": "origin/v2",
            "old_candidates": [{"ref": "origin/v1", "commit": "a" * 40}],
            "new_candidates": [{"ref": "origin/v2", "commit": "b" * 40}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            interaction = step4.build_git_ref_confirmation_interaction(tmp, [pending_item])

        decision = interaction["git_ref_decision_items"][0]
        self.assertEqual(decision["pair_options"], [])
        self.assertFalse(decision["requires_choice"])
        response = {
            "action": "rerun_current_step",
            "retry_remote_fetch": True,
        }
        run_step.validate_pending_interaction_response(interaction, response)
        expanded = run_step.expand_dependency_git_ref_selections(interaction, response)
        self.assertEqual(expanded["dependency_git_ref_overrides"][0]["expected_old_commit"], "a" * 40)
        self.assertEqual(expanded["dependency_git_ref_overrides"][0]["expected_new_commit"], "b" * 40)

    def test_step1_compact_selection_binds_ref_and_commit(self):
        resolution = {
            "status": "ambiguous",
            "requested_ref": "release",
            "source_status": "remote_source_ambiguous",
            "candidates": [
                {"ref": "origin/release", "commit": "a" * 40},
                {"ref": "upstream/release", "commit": "b" * 40},
            ],
        }
        request = run_step._step1_ref_request("base", "base_branch", "/repo", resolution)
        interaction = run_step.build_step1_ref_confirmation_interaction({}, [request])
        response = run_step.expand_step1_ref_selections(interaction, {
            "action": "continue",
            "source_ref_selections": [{"side": "base", "option": 2}],
        })

        self.assertEqual(response["base_branch"], "upstream/release")
        self.assertEqual(response["base_expected_commit"], "b" * 40)
        run_step.validate_pending_interaction_response(interaction, response)

    def test_step2_uses_fixed_commits_but_keeps_branch_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            dep_changes = Path(tmp) / "deps.csv"
            output = Path(tmp) / "context.json"
            dep_changes.write_text(
                "coord,old_version,new_version,change_type\ncom.acme:demo,1.0.0,1.0.0,未变\n",
                encoding="utf-8",
            )
            argv = [
                "s2_context_from_deps.py",
                "--dep-changes", str(dep_changes),
                "--base-branch", "release",
                "--current-branch", "main",
                "--base-revision", "a" * 40,
                "--current-revision", "b" * 40,
                "--work-dir", tmp,
                "--output", str(output),
            ]
            with patch.object(sys, "argv", argv), patch.object(
                step2, "detect_build_tool", return_value="maven"
            ) as build_tool_mock, patch.object(
                step2, "auto_detect_source_dirs", return_value=[]
            ), patch.object(
                step2, "detect_jdk_versions", return_value=("8", "21")
            ) as jdk_mock, patch.object(
                step2, "detect_jvm_param_changes", return_value=[]
            ) as jvm_mock:
                step2.main()

            context = json.loads(output.read_text(encoding="utf-8"))

        build_tool_mock.assert_called_once_with("b" * 40, tmp)
        self.assertEqual(jdk_mock.call_args.args[:2], ("a" * 40, "b" * 40))
        self.assertEqual(jvm_mock.call_args.args[:2], ("a" * 40, "b" * 40))
        self.assertEqual(context["base_branch"], "release")
        self.assertEqual(context["current_branch"], "main")
        self.assertEqual(context["revision_source"], "resolved_commit")

    def test_step4_ref_movement_displays_observed_commit_for_reconfirmation(self):
        old_candidate = {
            "ref": "origin/v1",
            "commit": "a" * 40,
            "canonical_ref": "refs/heads/v1",
            "remote": "origin",
            "remote_name": "origin",
            "branch_name": "v1",
            "score": 140,
            "prefix": "v",
        }
        new_candidate = {
            "ref": "origin/v2",
            "commit": "b" * 40,
            "canonical_ref": "refs/heads/v2",
            "remote": "origin",
            "remote_name": "origin",
            "branch_name": "v2",
            "score": 140,
            "prefix": "v",
        }
        moved_commit = "c" * 40
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".git").mkdir()
            with patch.object(
                step4,
                "resolve_repo_ref_pair_for_versions",
                return_value=(
                    "origin/v1", "origin/v2", "matched-old", "matched-new",
                    [old_candidate], [new_candidate],
                ),
            ), patch.object(
                step4,
                "_materialize_resolved_remote_ref",
                side_effect=[
                    ({"status": "remote_ref_moved", "observed_commit": moved_commit}, "moved"),
                    ({"status": "remote_source_resolved", "resolved_commit": "b" * 40}, ""),
                ],
            ):
                plan = step4.resolve_gitdiff_ref_plan_for_row(
                    {"coord": "com.acme:demo", "old_version": "1", "new_version": "2"},
                    {"repo_path": tmp, "module_path": tmp},
                    {},
                    {},
                )
            interaction = step4.build_git_ref_confirmation_interaction(tmp, [plan])

        self.assertEqual(plan["pending_kind"], "remote_ref_moved")
        self.assertEqual(plan["old_candidates"][0]["commit"], moved_commit)
        self.assertEqual(
            interaction["git_ref_decision_items"][0]["pair_options"][0]["old_commit"],
            moved_commit,
        )

    def test_step4_collects_both_side_fetch_failures_in_one_checkpoint(self):
        old_candidate = {
            "ref": "origin/v1", "commit": "a" * 40,
            "canonical_ref": "refs/heads/v1", "remote": "origin",
        }
        new_candidate = {
            "ref": "origin/v2", "commit": "b" * 40,
            "canonical_ref": "refs/heads/v2", "remote": "origin",
        }
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".git").mkdir()
            with patch.object(
                step4,
                "resolve_repo_ref_pair_for_versions",
                return_value=(
                    "origin/v1", "origin/v2", "matched-old", "matched-new",
                    [old_candidate], [new_candidate],
                ),
            ), patch.object(
                step4,
                "_materialize_resolved_remote_ref",
                side_effect=[
                    ({"status": "remote_fetch_failed"}, "old timeout"),
                    ({"status": "remote_fetch_failed"}, "new timeout"),
                ],
            ) as materialize_mock:
                plan = step4.resolve_gitdiff_ref_plan_for_row(
                    {"coord": "com.acme:demo", "old_version": "1", "new_version": "2"},
                    {"repo_path": tmp, "module_path": tmp},
                    {},
                    {},
                )

        self.assertEqual(materialize_mock.call_count, 2)
        self.assertEqual(plan["failed_sides"], ["old", "new"])
        self.assertEqual(plan["pending_kind"], "fetch_failed")


if __name__ == "__main__":
    unittest.main()
