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

    def test_successful_targeted_ls_remote_without_ref_is_ref_movement(self):
        with patch.object(
            refs,
            "_git",
            return_value=("", "", 0),
        ) as git_mock, patch.object(refs.time, "sleep") as sleep_mock:
            result = refs.materialize_remote_source_candidate(
                "/repo",
                self.candidate,
                expected_commit=self.commit,
            )

        self.assertEqual(result["status"], "remote_ref_moved")
        self.assertEqual(result["expected_commit"], self.commit)
        self.assertEqual(result["observed_commit"], "")
        self.assertEqual(git_mock.call_count, 1)
        sleep_mock.assert_not_called()

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

    def test_remote_ref_movement_stops_before_fetch(self):
        moved_commit = "b" * 40
        with patch.object(
            refs,
            "_query_remote_candidate_commit",
            return_value=(moved_commit, "", 0),
        ), patch.object(refs, "_git") as git_mock:
            result = refs.materialize_remote_source_candidate(
                "/repo",
                self.candidate,
                expected_commit=self.commit,
            )

        self.assertEqual(result["status"], "remote_ref_moved")
        self.assertEqual(result["expected_commit"], self.commit)
        self.assertEqual(result["observed_commit"], moved_commit)
        git_mock.assert_not_called()

    def test_expected_commit_mismatch_is_detected_before_materialization(self):
        inventory = {
            "queried_at": "now",
            "refs": [self.candidate],
            "failures": [],
            "remotes": ["origin"],
        }
        with patch.object(refs, "query_live_remote_refs", return_value=inventory), patch.object(
            refs, "materialize_remote_source_candidate"
        ) as materialize_mock:
            result = refs.resolve_remote_source_ref(
                "/repo",
                "origin/release",
                expected_commit="b" * 40,
            )

        self.assertEqual(result["status"], "remote_ref_moved")
        self.assertEqual(result["observed_commit"], self.commit)
        materialize_mock.assert_not_called()

    def test_failed_second_remote_prevents_unqualified_unique_claim(self):
        inventory = {
            "queried_at": "now",
            "refs": [self.candidate],
            "failures": [{
                "remote": "upstream",
                "stage": "ls_remote",
                "reason": "operation timed out",
                "reason_code": "transient_network_failure",
            }],
            "remotes": ["origin", "upstream"],
        }
        with patch.object(refs, "query_live_remote_refs", return_value=inventory), patch.object(
            refs, "materialize_remote_source_candidate"
        ) as materialize_mock:
            result = refs.resolve_remote_source_ref("/repo", "release")

        self.assertEqual(result["status"], "remote_query_failed")
        self.assertEqual(result["candidates"][0]["ref"], "origin/release")
        materialize_mock.assert_not_called()

    def test_explicit_successful_remote_ignores_unrelated_remote_failure(self):
        inventory = {
            "queried_at": "now",
            "refs": [self.candidate],
            "failures": [{"remote": "upstream", "stage": "ls_remote", "reason": "timed out"}],
            "remotes": ["origin", "upstream"],
        }
        materialized = {
            "status": "remote_source_resolved",
            "resolved_commit": self.commit,
            "expected_commit": self.commit,
            "remote": "origin",
            "remote_ref": "refs/heads/release",
        }
        with patch.object(refs, "query_live_remote_refs", return_value=inventory), patch.object(
            refs, "materialize_remote_source_candidate", return_value=materialized
        ):
            result = refs.resolve_remote_source_ref("/repo", "origin/release")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], self.commit)

    def test_moved_ref_refreshes_candidates_for_reconfirmation(self):
        moved_commit = "b" * 40
        inventory = {
            "queried_at": "now",
            "refs": [self.candidate],
            "failures": [],
            "remotes": ["origin"],
        }
        moved = {
            "status": "remote_ref_moved",
            "resolved_commit": "",
            "expected_commit": self.commit,
            "observed_commit": moved_commit,
            "attempts": [],
            "failure": {"reason": "moved", "reason_code": "remote_ref_moved"},
        }
        with patch.object(refs, "query_live_remote_refs", return_value=inventory), patch.object(
            refs, "materialize_remote_source_candidate", return_value=moved
        ):
            result = refs.resolve_remote_source_ref("/repo", "origin/release")

        self.assertEqual(result["status"], "remote_ref_moved")
        self.assertEqual(result["candidates"][0]["commit"], moved_commit)


if __name__ == "__main__":
    unittest.main()
