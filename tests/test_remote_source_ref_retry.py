import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import remote_source_refs as refs  # noqa: E402


class RemoteSourceRefRetryTest(unittest.TestCase):
    def setUp(self):
        self.commit = "a" * 40
        self.candidate = {
            "remote": "origin",
            "ref": "origin/release",
            "canonical_ref": "refs/heads/release",
            "short_name": "release",
            "kind": "branch",
            "commit": self.commit,
        }

    def test_transient_inventory_query_retries_then_succeeds(self):
        responses = [
            ("", "connection reset by peer", 1),
            ("", "operation timed out", 124),
            (f"{self.commit}\trefs/heads/release\n", "", 0),
        ]
        with patch.object(refs, "_remote_names", return_value=(["origin"], [])), patch.object(
            refs, "_git", side_effect=responses
        ) as git_mock, patch.object(refs.time, "sleep") as sleep_mock:
            result = refs.query_live_remote_refs("/repo", retry_delays=(1, 3))

        self.assertEqual(git_mock.call_count, 3)
        self.assertEqual(sleep_mock.call_count, 2)
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["refs"][0]["commit"], self.commit)

    def test_step1_exact_ref_uses_targeted_query_and_retries_transient_failure(self):
        responses = [
            ("", "kex_exchange_identification: Connection closed", 128),
            (f"{self.commit}\trefs/heads/release\n", "", 0),
        ]
        with patch.object(
            refs, "_remote_names", return_value=(["origin"], [])
        ), patch.object(
            refs, "_git", side_effect=responses
        ) as git_mock, patch.object(
            refs, "_materialize_targeted_commit", return_value={
                "status": "remote_source_resolved",
                "resolved_commit": self.commit,
                "expected_commit": self.commit,
                "resolution_mode": "live_remote",
                "attempts": [],
            }
        ), patch.object(refs.time, "sleep") as sleep_mock:
            result = refs.resolve_remote_source_ref("/repo", "release")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(git_mock.call_count, 2)
        command_args = git_mock.call_args_list[-1].args
        self.assertIn("refs/heads/release", command_args)
        self.assertIn("refs/tags/release", command_args)
        self.assertNotEqual(command_args[-1], "origin")
        sleep_mock.assert_called_once_with(1)

    def test_materialize_retries_only_transient_fetch_failures(self):
        git_responses = [
            ("", "connection reset by peer", 1),
            ("", "operation timed out", 124),
            ("", "", 0),
            (self.commit, "", 0),
        ]
        with patch.object(
            refs,
            "_query_remote_candidate_commit",
            return_value=(self.commit, "", 0),
        ), patch.object(refs, "_git", side_effect=git_responses) as git_mock, patch.object(
            refs.time, "sleep"
        ) as sleep_mock:
            result = refs.materialize_remote_source_candidate(
                "/repo",
                self.candidate,
                retry_delays=(1, 3),
            )

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], self.commit)
        self.assertEqual([item["status"] for item in result["attempts"]], [
            "transient_network_failure",
            "transient_network_failure",
            "success",
        ])
        self.assertEqual(git_mock.call_count, 4)
        self.assertEqual(sleep_mock.call_count, 2)

    def test_transient_targeted_ls_remote_ssh_failure_retries_then_succeeds(self):
        query_responses = [
            (
                "",
                "kex_exchange_identification: Connection closed by remote host",
                128,
            ),
            (self.commit, "", 0),
            (self.commit, "", 0),
        ]
        git_responses = [
            ("", "", 0),
            (self.commit, "", 0),
        ]
        with patch.object(
            refs,
            "_query_remote_candidate_commit",
            side_effect=query_responses,
        ) as query_mock, patch.object(
            refs,
            "_git",
            side_effect=git_responses,
        ), patch.object(refs.time, "sleep") as sleep_mock:
            result = refs.materialize_remote_source_candidate(
                "/repo",
                self.candidate,
                retry_delays=(1, 3),
            )

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], self.commit)
        self.assertEqual(query_mock.call_count, 3)
        self.assertEqual(
            [item["status"] for item in result["attempts"]],
            ["transient_network_failure", "success"],
        )
        sleep_mock.assert_called_once_with(1)

    def test_transient_targeted_ls_remote_exhaustion_is_not_ref_movement(self):
        ssh_failure = (
            "",
            "ssh_exchange_identification: Connection closed by remote host",
            128,
        )
        with patch.object(
            refs,
            "_query_remote_candidate_commit",
            side_effect=[ssh_failure, ssh_failure, ssh_failure],
        ) as query_mock, patch.object(
            refs,
            "_git",
        ) as git_mock, patch.object(refs.time, "sleep") as sleep_mock:
            result = refs.materialize_remote_source_candidate(
                "/repo",
                self.candidate,
                retry_delays=(1, 3),
            )

        self.assertEqual(result["status"], "remote_fetch_failed")
        self.assertEqual(
            result["failure"]["reason_code"],
            "transient_network_failure",
        )
        self.assertEqual(
            result["failure"]["stage"],
            "ls_remote_before_fetch",
        )
        self.assertTrue(result["failure"]["retryable"])
        self.assertEqual(query_mock.call_count, 3)
        git_mock.assert_not_called()
        self.assertEqual(sleep_mock.call_count, 2)

    def test_successful_targeted_ls_remote_without_ref_retries_and_reuses_pinned_object(self):
        absent = ("", "remote ref no longer exists", refs._REMOTE_REF_ABSENT_RC)
        with patch.object(
            refs,
            "_query_remote_candidate_commit",
            side_effect=[absent, absent, absent],
        ) as query_mock, patch.object(
            refs,
            "_verify_commit_object",
            side_effect=["", self.commit],
        ) as verify_mock, patch.object(
            refs,
            "_fetch_expected_commit",
            return_value={
                "status": "success",
                "target": self.commit,
                "failure_type": "",
                "reason": "",
                "retryable": False,
            },
        ) as fetch_mock, patch.object(refs.time, "sleep") as sleep_mock:
            result = refs.materialize_remote_source_candidate(
                "/repo",
                self.candidate,
                expected_commit=self.commit,
                retry_delays=(1, 3),
            )

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["expected_commit"], self.commit)
        self.assertEqual(result["observed_commit"], "")
        self.assertEqual(result["resolution_mode"], "live_remote_expected_commit")
        self.assertEqual(query_mock.call_count, 3)
        self.assertEqual(verify_mock.call_count, 2)
        fetch_mock.assert_called_once()
        self.assertEqual(sleep_mock.call_count, 2)

    def test_existing_pinned_object_does_not_require_a_second_remote_query(self):
        with patch.object(
            refs,
            "_verify_commit_object",
            return_value=self.commit,
        ), patch.object(
            refs,
            "_query_remote_candidate_commit",
        ) as query_mock, patch.object(
            refs,
            "_fetch_expected_commit",
        ) as fetch_mock:
            result = refs.materialize_remote_source_candidate(
                "/repo",
                self.candidate,
                expected_commit=self.commit,
            )

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], self.commit)
        self.assertEqual(
            result["resolution_mode"],
            "live_remote_expected_commit",
        )
        query_mock.assert_not_called()
        fetch_mock.assert_not_called()

    def test_authentication_failure_is_not_retried(self):
        with patch.object(
            refs,
            "_query_remote_candidate_commit",
            return_value=(self.commit, "", 0),
        ), patch.object(
            refs,
            "_git",
            return_value=("", "Authentication failed", 128),
        ) as git_mock, patch.object(refs.time, "sleep") as sleep_mock:
            result = refs.materialize_remote_source_candidate("/repo", self.candidate)

        self.assertEqual(result["status"], "remote_fetch_failed")
        self.assertEqual(result["failure"]["reason_code"], "authentication_failed")
        self.assertFalse(result["failure"]["retryable"])
        self.assertEqual(git_mock.call_count, 1)
        sleep_mock.assert_not_called()

    def test_remote_ref_movement_retries_then_materializes_original_snapshot(self):
        moved_commit = "b" * 40
        with patch.object(
            refs,
            "_query_remote_candidate_commit",
            side_effect=[
                (moved_commit, "", 0),
                (moved_commit, "", 0),
                (moved_commit, "", 0),
            ],
        ) as query_mock, patch.object(
            refs,
            "_verify_commit_object",
            side_effect=["", self.commit],
        ), patch.object(
            refs,
            "_fetch_expected_commit",
            return_value={
                "status": "success",
                "target": self.commit,
                "failure_type": "",
                "reason": "",
                "retryable": False,
            },
        ) as fetch_mock, patch.object(refs.time, "sleep"):
            result = refs.materialize_remote_source_candidate(
                "/repo",
                self.candidate,
                expected_commit=self.commit,
            )

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["expected_commit"], self.commit)
        self.assertEqual(result["observed_commit"], moved_commit)
        self.assertEqual(result["resolution_mode"], "live_remote_expected_commit")
        self.assertEqual(query_mock.call_count, 3)
        fetch_mock.assert_called_once_with(
            "/repo",
            self.candidate,
            self.commit,
            timeout=60,
        )

    def test_exact_pinned_commit_fetch_retries_transient_failures(self):
        moved_commit = "b" * 40
        transient = {
            "status": "remote_expected_commit_unmaterializable",
            "target": self.commit,
            "failure_type": "transient_network_failure",
            "reason": "connection reset by peer",
            "retryable": True,
        }
        success = {
            "status": "success",
            "target": self.commit,
            "failure_type": "",
            "reason": "",
            "retryable": False,
        }
        with patch.object(
            refs,
            "_query_remote_candidate_commit",
            side_effect=[
                (moved_commit, "", 0),
                (moved_commit, "", 0),
                (moved_commit, "", 0),
            ],
        ), patch.object(
            refs,
            "_verify_commit_object",
            side_effect=["", self.commit],
        ), patch.object(
            refs,
            "_fetch_expected_commit",
            side_effect=[transient, transient, success],
        ) as fetch_mock, patch.object(refs.time, "sleep") as sleep_mock:
            result = refs.materialize_remote_source_candidate(
                "/repo",
                self.candidate,
                expected_commit=self.commit,
                retry_delays=(1, 3),
            )

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(fetch_mock.call_count, 3)
        self.assertEqual(sleep_mock.call_count, 4)

    def test_ref_disappearing_during_canonical_fetch_falls_back_to_pinned_sha(self):
        with patch.object(
            refs,
            "_query_remote_candidate_commit",
            return_value=(self.commit, "", 0),
        ), patch.object(
            refs,
            "_verify_commit_object",
            side_effect=["", self.commit],
        ), patch.object(
            refs,
            "_git",
            return_value=("", "couldn't find remote ref release", 128),
        ), patch.object(
            refs,
            "_fetch_expected_commit",
            return_value={
                "status": "success",
                "target": self.commit,
                "failure_type": "",
                "reason": "",
                "retryable": False,
            },
        ) as exact_fetch:
            result = refs.materialize_remote_source_candidate(
                "/repo",
                self.candidate,
                expected_commit=self.commit,
            )

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], self.commit)
        exact_fetch.assert_called_once_with(
            "/repo",
            self.candidate,
            self.commit,
            timeout=60,
        )

    def test_bound_commit_is_materialized_without_requerying_moving_ref(self):
        materialized = {
            "status": "remote_source_resolved",
            "resolved_commit": "b" * 40,
            "expected_commit": "b" * 40,
            "resolution_mode": "pinned_commit",
            "attempts": [],
        }
        with patch.object(
            refs, "_remote_names"
        ) as remote_names, patch.object(
            refs, "_targeted_remote_ref_inventory"
        ) as targeted_query, patch.object(
            refs, "_materialize_targeted_commit", return_value=materialized
        ) as materialize_mock:
            result = refs.resolve_remote_source_ref(
                "/repo",
                "origin/release",
                expected_commit="b" * 40,
                expected_remote="origin",
                expected_remote_ref="refs/heads/release",
            )

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], "b" * 40)
        materialize_mock.assert_called_once()
        self.assertTrue(materialize_mock.call_args.kwargs["pinned"])
        remote_names.assert_not_called()
        targeted_query.assert_not_called()

    def test_bound_snapshot_is_materialized_when_current_inventory_has_no_ref(self):
        materialized = {
            "status": "remote_source_resolved",
            "resolved_commit": self.commit,
            "expected_commit": self.commit,
            "resolution_mode": "pinned_commit",
            "attempts": [],
        }
        with patch.object(
            refs,
            "_materialize_targeted_commit",
            return_value=materialized,
        ) as materialize_mock:
            result = refs.resolve_remote_source_ref(
                "/repo",
                "origin/release",
                expected_commit=self.commit,
                expected_remote="origin",
                expected_remote_ref="refs/heads/release",
            )

        self.assertEqual(result["status"], "remote_source_resolved")
        candidate = materialize_mock.call_args.args[1]
        self.assertEqual(candidate["remote"], "origin")
        self.assertEqual(candidate["canonical_ref"], "refs/heads/release")
        self.assertEqual(
            materialize_mock.call_args.args[2],
            self.commit,
        )

    def test_unmaterializable_expected_commit_is_not_reported_as_ref_movement(self):
        moved_commit = "b" * 40
        with patch.object(
            refs,
            "_query_remote_candidate_commit",
            side_effect=[
                (moved_commit, "", 0),
                (moved_commit, "", 0),
                (moved_commit, "", 0),
            ],
        ), patch.object(
            refs,
            "_verify_commit_object",
            return_value="",
        ), patch.object(
            refs,
            "_fetch_expected_commit",
            return_value={
                "status": "remote_expected_commit_unmaterializable",
                "target": self.commit,
                "failure_type": "remote_ref_not_found",
                "reason": "server does not allow fetching the pinned object",
                "retryable": False,
            },
        ), patch.object(refs.time, "sleep"):
            result = refs.materialize_remote_source_candidate(
                "/repo",
                self.candidate,
                expected_commit=self.commit,
            )

        self.assertEqual(
            result["status"],
            "remote_expected_commit_unmaterializable",
        )
        self.assertEqual(result["expected_commit"], self.commit)
        self.assertEqual(result["observed_commit"], moved_commit)
        self.assertNotEqual(result["status"], "remote_ref_moved")

    def test_unqualified_ref_queries_only_origin(self):
        inventory = {
            "queried_at": "now",
            "refs": [self.candidate],
            "failures": [],
            "remotes": ["origin"],
        }
        materialized = {
            "status": "remote_source_resolved",
            "resolved_commit": self.commit,
            "expected_commit": self.commit,
            "resolution_mode": "live_remote",
            "attempts": [],
        }
        with patch.object(
            refs, "_remote_names", return_value=(["origin", "upstream"], [])
        ), patch.object(
            refs, "_targeted_remote_ref_inventory", return_value=inventory
        ) as targeted_query, patch.object(
            refs, "_materialize_targeted_commit", return_value=materialized
        ):
            result = refs.resolve_remote_source_ref("/repo", "release")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["candidates"][0]["ref"], "origin/release")
        self.assertEqual(targeted_query.call_args.args[1], "origin")

    def test_explicit_successful_remote_ignores_unrelated_remote_failure(self):
        inventory = {
            "queried_at": "now",
            "refs": [self.candidate],
            "failures": [],
            "remotes": ["origin"],
        }
        materialized = {
            "status": "remote_source_resolved",
            "resolved_commit": self.commit,
            "expected_commit": self.commit,
            "remote": "origin",
            "remote_ref": "refs/heads/release",
        }
        with patch.object(
            refs, "_remote_names", return_value=(["origin", "upstream"], [])
        ), patch.object(
            refs, "_targeted_remote_ref_inventory", return_value=inventory
        ), patch.object(
            refs, "_materialize_targeted_commit", return_value=materialized
        ):
            result = refs.resolve_remote_source_ref("/repo", "origin/release")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], self.commit)

    def test_materialization_failure_keeps_selected_candidate_for_diagnostics(self):
        inventory = {
            "queried_at": "now",
            "refs": [self.candidate],
            "failures": [],
            "remotes": ["origin"],
        }
        moved = {
            "status": "remote_fetch_failed",
            "resolved_commit": "",
            "expected_commit": self.commit,
            "attempts": [],
            "failure": {
                "reason": "pinned object unavailable",
                "reason_code": "fetch_failed",
            },
        }
        with patch.object(
            refs, "_remote_names", return_value=(["origin"], [])
        ), patch.object(
            refs, "_targeted_remote_ref_inventory", return_value=inventory
        ), patch.object(
            refs, "_materialize_targeted_commit", return_value=moved
        ):
            result = refs.resolve_remote_source_ref("/repo", "origin/release")

        self.assertEqual(result["status"], "remote_fetch_failed")
        self.assertEqual(result["candidates"][0]["commit"], self.commit)


if __name__ == "__main__":
    unittest.main()
