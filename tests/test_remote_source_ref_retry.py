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

    def test_transport_failure_classification_covers_common_transient_errors(self):
        reasons = (
            "The requested URL returned error: 429",
            "GnuTLS recv error (-110): The TLS connection was non-properly terminated",
            "RPC failed; curl 92 HTTP/2 stream 5 was not closed cleanly",
            "fetch-pack: unexpected disconnect while reading sideband packet; early EOF",
            "Could not resolve proxy: proxy.example.invalid",
            "fatal: Unable to create '/repo/.git/index.lock': File exists",
            "fatal: an unrecognized remote helper failure",
        )

        for reason in reasons:
            with self.subTest(reason=reason):
                _failure_type, retryable = refs.classify_fetch_failure(reason, 128)
                self.assertTrue(retryable)

    def test_authentication_and_missing_ref_failures_are_terminal(self):
        cases = (
            ("The requested URL returned error: 401", "authentication_failed"),
            ("Proxy Authentication Required (HTTP 407)", "authentication_failed"),
            ("fatal: couldn't find remote ref release", "remote_ref_not_found"),
            ("upload-pack: not our ref aaaaa", "remote_ref_not_found"),
        )

        for reason, expected_type in cases:
            with self.subTest(reason=reason):
                failure_type, retryable = refs.classify_fetch_failure(reason, 128)
                self.assertEqual(failure_type, expected_type)
                self.assertFalse(retryable)

    def test_empty_remote_listing_is_cross_checked_before_using_remote(self):
        responses = [
            ("", "", 0),
            ("origin", "", 0),
            ("remote.origin.url", "", 0),
        ]
        with patch.object(refs, "_git", side_effect=responses) as git_mock:
            names, failures = refs._remote_names("/repo")

        self.assertEqual(names, ["origin"])
        self.assertEqual(failures, [])
        self.assertEqual(git_mock.call_count, 3)

    def test_first_nonempty_remote_is_verified_against_local_config(self):
        responses = [
            ("origin", "", 0),
            ("remote.origin.url /repo/origin.git", "", 0),
        ]
        with patch.object(refs, "_git", side_effect=responses) as git_mock:
            names, failures = refs._remote_names("/repo")

        self.assertEqual(names, ["origin"])
        self.assertEqual(failures, [])
        self.assertEqual(git_mock.call_count, 2)
        self.assertEqual(
            git_mock.call_args.args[1:],
            (
                "config",
                "--local",
                "--includes",
                "--get-regexp",
                r"^remote\..*\.url$",
            ),
        )

    def test_transient_local_config_failure_is_retried_with_includes(self):
        responses = [
            ("origin", "", 0),
            ("", "fatal: transient config read failure", 128),
            ("remote.origin.url /repo/origin.git", "", 0),
        ]
        with patch.object(refs, "_git", side_effect=responses) as git_mock, patch.object(
            refs.time, "sleep"
        ) as sleep_mock:
            names, failures = refs._remote_names("/repo")

        self.assertEqual(names, ["origin"])
        self.assertEqual(failures, [])
        self.assertEqual(git_mock.call_count, 3)
        self.assertEqual(sleep_mock.call_count, 1)
        for config_call in git_mock.call_args_list[1:]:
            self.assertEqual(
                config_call.args[1:],
                (
                    "config",
                    "--local",
                    "--includes",
                    "--get-regexp",
                    r"^remote\..*\.url$",
                ),
            )

    def test_remote_configuration_missing_requires_consistent_empty_observations(self):
        responses = [
            ("", "", 0),
            ("", "", 0),
            ("", "", 1),
        ]
        with patch.object(refs, "_git", side_effect=responses) as git_mock:
            names, failures = refs._remote_names("/repo")

        self.assertEqual(names, [])
        self.assertEqual(failures, [])
        self.assertEqual(git_mock.call_count, 3)
        self.assertIn("--local", git_mock.call_args.args)

    def test_initial_remote_command_failure_recovers_from_two_successful_reads(self):
        responses = [
            ("", "fatal: transient config read failure", 128),
            ("origin", "", 0),
            ("remote.origin.url", "", 0),
        ]
        with patch.object(refs, "_git", side_effect=responses) as git_mock:
            names, failures = refs._remote_names("/repo")

        self.assertEqual(names, ["origin"])
        self.assertEqual(failures, [])
        self.assertEqual(git_mock.call_count, 3)

    def test_local_remote_config_repairs_empty_remote_observations(self):
        responses = [
            ("", "", 0),
            ("", "", 0),
            ("remote.origin.url", "", 0),
        ]
        with patch.object(refs, "_git", side_effect=responses):
            names, failures = refs._remote_names("/repo")

        self.assertEqual(names, ["origin"])
        self.assertEqual(failures, [])

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

    def test_unknown_inventory_failure_retries_by_default(self):
        responses = [
            ("", "fatal: unexpected remote helper failure", 128),
            (f"{self.commit}\trefs/heads/release\n", "", 0),
        ]
        with patch.object(refs, "_remote_names", return_value=(["origin"], [])), patch.object(
            refs, "_git", side_effect=responses
        ) as git_mock, patch.object(refs.time, "sleep"):
            result = refs.query_live_remote_refs("/repo")

        self.assertEqual(result["failures"], [])
        self.assertEqual(result["refs"][0]["commit"], self.commit)
        self.assertEqual(git_mock.call_count, 2)

    def test_multi_remote_inventory_shares_one_total_timeout(self):
        with patch.object(
            refs,
            "_remote_names",
            return_value=(["first", "second"], []),
        ), patch.object(
            refs,
            "_git",
            return_value=("", "connection reset by peer", 128),
        ) as git_mock, patch.object(
            refs.time,
            "monotonic",
            side_effect=[100.0, 100.0, 100.9, 101.0],
        ), patch.object(refs.time, "sleep") as sleep_mock:
            result = refs.query_live_remote_refs(
                "/repo",
                timeout=1,
                retry_delays=(1,),
            )

        self.assertEqual(git_mock.call_count, 1)
        self.assertEqual(git_mock.call_args.kwargs["timeout"], 1.0)
        sleep_mock.assert_not_called()
        self.assertEqual(
            [failure["remote"] for failure in result["failures"]],
            ["first", "second"],
        )
        self.assertTrue(all(
            failure["reason_code"] == refs._DEADLINE_FAILURE
            for failure in result["failures"]
        ))

    def test_broad_inventory_queries_origin_before_peer_remotes(self):
        with patch.object(
            refs,
            "_remote_names",
            return_value=(["backup", "origin", "upstream"], []),
        ), patch.object(
            refs,
            "_git",
            return_value=(f"{self.commit}\trefs/heads/release\n", "", 0),
        ) as git_mock:
            result = refs.query_live_remote_refs("/repo")

        self.assertEqual(
            [call.args[-1] for call in git_mock.call_args_list],
            ["origin", "backup", "upstream"],
        )
        self.assertEqual(result["remotes"], ["origin", "backup", "upstream"])

    def test_empty_targeted_result_must_repeat_before_not_found(self):
        with patch.object(
            refs,
            "_git",
            side_effect=[("", "", 0), ("", "", 0), ("", "", 0)],
        ) as git_mock, patch.object(refs.time, "sleep"):
            result = refs._targeted_remote_ref_inventory(
                "/repo",
                "origin",
                "release",
            )

        self.assertEqual(result["refs"], [])
        self.assertEqual(result["failures"], [])
        self.assertEqual(git_mock.call_count, 2)
        self.assertEqual(
            [attempt["status"] for attempt in result["attempts"]],
            ["remote_ref_observation_empty"] * 2,
        )

    def test_empty_targeted_result_retries_then_accepts_valid_ref(self):
        responses = [
            ("", "", 0),
            (f"{self.commit}\trefs/heads/release\n", "", 0),
        ]
        with patch.object(refs, "_git", side_effect=responses) as git_mock, patch.object(
            refs.time, "sleep"
        ):
            result = refs._targeted_remote_ref_inventory(
                "/repo",
                "origin",
                "release",
            )

        self.assertEqual(result["failures"], [])
        self.assertEqual(result["refs"][0]["commit"], self.commit)
        self.assertEqual(git_mock.call_count, 2)

    def test_malformed_targeted_result_retries_then_accepts_valid_ref(self):
        responses = [
            ("truncated-output", "", 0),
            (f"{self.commit}\trefs/heads/release\n", "", 0),
        ]
        with patch.object(refs, "_git", side_effect=responses) as git_mock, patch.object(
            refs.time, "sleep"
        ):
            result = refs._targeted_remote_ref_inventory(
                "/repo",
                "origin",
                "release",
            )

        self.assertEqual(result["failures"], [])
        self.assertEqual(result["refs"][0]["commit"], self.commit)
        self.assertEqual(git_mock.call_count, 2)

    def test_repeated_malformed_targeted_result_is_not_treated_as_not_found(self):
        with patch.object(
            refs,
            "_git",
            side_effect=[("truncated-output", "", 0)] * refs.DEFAULT_FETCH_ATTEMPTS,
        ), patch.object(refs.time, "sleep"):
            result = refs._targeted_remote_ref_inventory(
                "/repo",
                "origin",
                "release",
            )

        self.assertEqual(result["refs"], [])
        self.assertEqual(
            result["failures"][0]["reason_code"],
            "remote_ref_observation_malformed",
        )

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
        sleep_mock.assert_called_once()
        self.assertAlmostEqual(sleep_mock.call_args.args[0], 1.0333333333333334)

    def test_public_materializer_retries_canonical_fetch_with_one_deadline(self):
        with patch.object(
            refs,
            "_verify_commit_object",
            side_effect=["", self.commit],
        ), patch.object(
            refs,
            "_git",
            side_effect=[
                ("", "connection reset by peer", 128),
                ("", "", 0),
            ],
        ) as git_mock, patch.object(refs.time, "sleep") as sleep_mock:
            result = refs.materialize_remote_source_candidate(
                "/repo",
                self.candidate,
                retry_delays=(1, 3),
            )

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], self.commit)
        self.assertEqual(
            [item["status"] for item in result["attempts"]],
            ["transient_network_failure", "success"],
        )
        self.assertEqual(git_mock.call_count, 2)
        sleep_mock.assert_called_once()

    def test_materializer_does_not_verify_again_after_total_deadline(self):
        commands = []

        def fake_git(_repo, *args, **_kwargs):
            commands.append(args)
            if args[0] == "rev-parse":
                return "", "missing object", 128
            return "", "", 0

        with patch.object(
            refs.time,
            "monotonic",
            side_effect=[100.0, 100.0, 100.2, 101.1, 101.1],
        ), patch.object(refs, "_git", side_effect=fake_git):
            result = refs.materialize_remote_source_candidate(
                "/repo",
                self.candidate,
                timeout=1,
                retry_delays=(),
            )

        self.assertEqual(
            [command[0] for command in commands],
            ["rev-parse", "fetch"],
        )
        self.assertEqual(
            result["failure"]["reason_code"],
            refs._DEADLINE_FAILURE,
        )

    def test_existing_pinned_object_needs_no_network_or_ref_requery(self):
        with patch.object(
            refs,
            "_verify_commit_object",
            return_value=self.commit,
        ), patch.object(refs, "_git") as git_mock, patch.object(
            refs,
            "_fetch_expected_commit",
        ) as exact_fetch:
            result = refs.materialize_remote_source_candidate(
                "/repo",
                self.candidate,
                expected_commit=self.commit,
            )

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], self.commit)
        self.assertEqual(result["resolution_mode"], "pinned_commit")
        git_mock.assert_not_called()
        exact_fetch.assert_not_called()

    def test_authentication_failure_is_terminal_in_public_materializer(self):
        with patch.object(
            refs,
            "_verify_commit_object",
            return_value="",
        ), patch.object(
            refs,
            "_git",
            return_value=("", "Authentication failed", 128),
        ) as git_mock, patch.object(
            refs, "_fetch_expected_commit"
        ) as exact_fetch, patch.object(refs.time, "sleep") as sleep_mock:
            result = refs.materialize_remote_source_candidate("/repo", self.candidate)

        self.assertEqual(result["status"], "remote_fetch_failed")
        self.assertEqual(result["failure"]["reason_code"], "authentication_failed")
        self.assertFalse(result["failure"]["retryable"])
        self.assertEqual(git_mock.call_count, 1)
        exact_fetch.assert_not_called()
        sleep_mock.assert_not_called()

    def test_branch_movement_does_not_revoke_already_advertised_sha(self):
        with patch.object(
            refs,
            "_verify_commit_object",
            side_effect=["", "", self.commit],
        ), patch.object(
            refs,
            "_git",
            return_value=("", "", 0),
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
        self.assertEqual(result["observed_commit"], "")
        exact_fetch.assert_called_once()

    def test_exact_pinned_commit_fetch_retries_transient_failures(self):
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
            "_verify_commit_object",
            side_effect=["", self.commit],
        ), patch.object(
            refs,
            "_git",
            return_value=("", "couldn't find remote ref release", 128),
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
        self.assertEqual(sleep_mock.call_count, 2)

    def test_ref_disappearing_during_canonical_fetch_falls_back_to_pinned_sha(self):
        with patch.object(
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
        exact_fetch.assert_called_once()
        self.assertEqual(exact_fetch.call_args.args, (
            "/repo",
            self.candidate,
            self.commit,
        ))
        self.assertGreater(exact_fetch.call_args.kwargs["timeout"], 0)
        self.assertLessEqual(exact_fetch.call_args.kwargs["timeout"], 60)

    def test_step1_materialization_fetches_canonical_ref_before_raw_sha(self):
        with patch.object(
            refs,
            "_verify_commit_object",
            side_effect=["", self.commit],
        ), patch.object(
            refs,
            "_git",
            return_value=("", "", 0),
        ) as git_mock, patch.object(
            refs,
            "_fetch_expected_commit",
        ) as raw_fetch:
            result = refs._materialize_targeted_commit(
                "/repo",
                self.candidate,
                self.commit,
                retry_delays=(),
            )

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], self.commit)
        self.assertEqual(result["attempts"][0]["stage"], "fetch_canonical_ref")
        self.assertEqual(
            git_mock.call_args.args,
            (
                "/repo",
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                "origin",
                "refs/heads/release",
            ),
        )
        raw_fetch.assert_not_called()

    def test_step1_materialization_falls_back_to_raw_sha_after_verification_miss(self):
        raw_success = {
            "status": "success",
            "target": self.commit,
            "failure_type": "",
            "reason": "",
            "retryable": False,
        }
        with patch.object(
            refs,
            "_verify_commit_object",
            side_effect=["", "", self.commit],
        ), patch.object(
            refs,
            "_git",
            return_value=("", "", 0),
        ), patch.object(
            refs,
            "_fetch_expected_commit",
            return_value=raw_success,
        ) as raw_fetch:
            result = refs._materialize_targeted_commit(
                "/repo",
                self.candidate,
                self.commit,
                retry_delays=(),
            )

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(
            [attempt["stage"] for attempt in result["attempts"]],
            ["fetch_canonical_ref", "fetch_commit"],
        )
        raw_fetch.assert_called_once_with(
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

    def test_selected_ref_keeps_pinned_sha_after_live_branch_moves(self):
        observed_commit = "b" * 40
        moved_candidate = {
            **self.candidate,
            "commit": observed_commit,
        }
        inventory = {
            "queried_at": "now",
            "refs": [moved_candidate],
            "failures": [],
            "remotes": ["origin"],
            "attempts": [{
                "attempt": 1,
                "stage": "targeted_ls_remote",
                "status": "success",
            }],
        }
        exact_success = {
            "status": "success",
            "target": self.commit,
            "failure_type": "",
            "reason": "",
            "retryable": False,
        }
        with patch.object(
            refs, "_remote_names", return_value=(["origin", "upstream"], [])
        ), patch.object(
            refs, "_targeted_remote_ref_inventory", return_value=inventory
        ), patch.object(
            refs,
            "_verify_commit_object",
            side_effect=["", "", self.commit],
        ), patch.object(
            refs, "_git", return_value=("", "", 0)
        ), patch.object(
            refs, "_fetch_expected_commit", return_value=exact_success
        ) as exact_fetch:
            result = refs.resolve_remote_source_ref(
                "/repo",
                "origin/release",
                expected_commit=self.commit,
            )

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], self.commit)
        self.assertEqual(result["expected_commit"], self.commit)
        self.assertEqual(result["observed_commit"], observed_commit)
        self.assertEqual(result["resolution_mode"], "pinned_commit")
        self.assertEqual(
            [attempt["stage"] for attempt in result["attempts"]],
            ["fetch_canonical_ref", "fetch_commit"],
        )
        exact_fetch.assert_called_once()
        self.assertEqual(exact_fetch.call_args.args[2], self.commit)
        self.assertNotEqual(result["status"], "remote_ref_moved")

    def test_unmaterializable_expected_commit_is_not_reported_as_ref_movement(self):
        with patch.object(
            refs,
            "_verify_commit_object",
            return_value="",
        ), patch.object(
            refs,
            "_git",
            return_value=("", "couldn't find remote ref release", 128),
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
        self.assertEqual(result["observed_commit"], "")
        self.assertNotEqual(result["status"], "remote_ref_moved")

    def test_unqualified_ref_stops_after_successful_origin_tier(self):
        origin_inventory = {
            "queried_at": "origin-time",
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
            refs, "_targeted_remote_ref_inventory", return_value=origin_inventory
        ) as targeted_query, patch.object(
            refs, "_materialize_targeted_commit", return_value=materialized
        ):
            result = refs.resolve_remote_source_ref("/repo", "release")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["candidates"][0]["ref"], "origin/release")
        self.assertEqual(
            [call.args[1] for call in targeted_query.call_args_list],
            ["origin"],
        )
        self.assertNotIn("aliases", result["candidates"][0])

    def test_origin_candidate_survives_lower_priority_remote_failure(self):
        healthy_inventory = {
            "queried_at": "origin-time",
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
            refs,
            "_targeted_remote_ref_inventory",
            return_value=healthy_inventory,
        ) as targeted_query, patch.object(
            refs, "_materialize_targeted_commit", return_value=materialized
        ):
            result = refs.resolve_remote_source_ref("/repo", "release")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["remote"], "origin")
        self.assertEqual(result["resolved_commit"], self.commit)
        self.assertEqual(result["failures"], [])
        self.assertEqual(targeted_query.call_count, 1)

    def test_higher_priority_remote_failure_blocks_upstream_selection(self):
        failed_origin = {
            "queried_at": "origin-time",
            "refs": [],
            "failures": [{
                "remote": "origin",
                "stage": "targeted_ls_remote",
                "reason": "connection reset",
                "reason_code": "transient_network_failure",
            }],
            "remotes": ["origin"],
        }
        upstream_candidate = {
            **self.candidate,
            "remote": "upstream",
            "ref": "upstream/release",
        }
        healthy_upstream = {
            "queried_at": "upstream-time",
            "refs": [upstream_candidate],
            "failures": [],
            "remotes": ["upstream"],
        }
        with patch.object(
            refs, "_remote_names", return_value=(["origin", "upstream"], [])
        ), patch.object(
            refs,
            "_targeted_remote_ref_inventory",
            side_effect=[failed_origin, healthy_upstream],
        ) as targeted_query, patch.object(
            refs, "_materialize_targeted_commit"
        ) as materialize:
            result = refs.resolve_remote_source_ref("/repo", "release")

        self.assertEqual(result["status"], "remote_query_failed")
        self.assertTrue(result["selection_blocked_by_higher_priority_remote"])
        self.assertEqual(result["candidates"], [])
        self.assertEqual(
            [call.args[1] for call in targeted_query.call_args_list],
            ["origin"],
        )
        materialize.assert_not_called()

    def test_peer_failure_blocks_selection_symmetrically_without_origin(self):
        for failed_name, healthy_name in (
            ("aaa-failed", "zzz-healthy"),
            ("zzz-failed", "aaa-healthy"),
        ):
            remote_names = sorted([failed_name, healthy_name])
            inventories_by_remote = {
                healthy_name: {
                    "queried_at": "healthy-time",
                    "refs": [{
                        **self.candidate,
                        "remote": healthy_name,
                        "ref": f"{healthy_name}/release",
                    }],
                    "failures": [],
                    "remotes": [healthy_name],
                },
                failed_name: {
                    "queried_at": "failed-time",
                    "refs": [],
                    "failures": [{
                        "remote": failed_name,
                        "stage": "targeted_ls_remote",
                        "reason": "connection reset",
                        "reason_code": "transient_network_failure",
                    }],
                    "remotes": [failed_name],
                },
            }
            inventories = [inventories_by_remote[name] for name in remote_names]
            with self.subTest(failed_remote=failed_name), patch.object(
                refs, "_remote_names", return_value=(remote_names, [])
            ), patch.object(
                refs,
                "_targeted_remote_ref_inventory",
                side_effect=inventories,
            ), patch.object(
                refs, "_materialize_targeted_commit"
            ) as materialize:
                result = refs.resolve_remote_source_ref("/repo", "release")

            self.assertEqual(result["status"], "remote_query_failed")
            self.assertTrue(result["selection_blocked_by_peer_remote"])
            self.assertFalse(result["selection_blocked_by_higher_priority_remote"])
            materialize.assert_not_called()

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

    def test_local_explicit_commit_is_not_labeled_remote_without_remote_proof(self):
        failed_materialization = {
            "status": "remote_expected_commit_unmaterializable",
            "resolved_commit": "",
            "expected_commit": self.commit,
            "attempts": [],
            "failure": {
                "remote": "origin",
                "reason": "server rejected the object request",
                "reason_code": "remote_ref_not_found",
                "retryable": False,
            },
        }
        with patch.object(
            refs, "_remote_names", return_value=(["origin"], [])
        ), patch.object(
            refs,
            "_compat_advertised_commit_inventory",
            return_value={
                "queried_at": "now",
                "refs": [],
                "failures": [],
                "remotes": ["origin"],
            },
        ), patch.object(
            refs,
            "_materialize_explicit_commit_from_remote",
            return_value=failed_materialization,
        ) as materialize:
            result = refs.resolve_remote_source_ref("/repo", self.commit)

        self.assertEqual(
            result["status"],
            "remote_expected_commit_unmaterializable",
        )
        self.assertNotEqual(result["status"], "remote_source_resolved")
        materialize.assert_called_once()
        self.assertEqual(materialize.call_args.args, ("/repo", "origin", self.commit))
        self.assertEqual(materialize.call_args.kwargs["timeout"], 60)
        self.assertIn("deadline", materialize.call_args.kwargs)

    def test_full_commit_uses_raw_remote_proof_without_eager_ref_inventory(self):
        candidate = {
            "remote": "origin",
            "ref": self.commit,
            "canonical_ref": "",
            "short_name": self.commit,
            "kind": "commit",
            "commit": self.commit,
        }
        materialized = {
            "status": "remote_source_resolved",
            "resolved_commit": self.commit,
            "expected_commit": self.commit,
            "attempts": [],
            "candidate": candidate,
        }
        with patch.object(
            refs, "_remote_names", return_value=(["origin", "upstream"], [])
        ), patch.object(
            refs,
            "_materialize_explicit_commit_from_remote",
            return_value=materialized,
        ) as raw_proof, patch.object(
            refs, "_compat_advertised_commit_inventory"
        ) as compatibility_inventory, patch.object(
            refs, "query_live_remote_refs"
        ) as broad_inventory:
            result = refs.resolve_remote_source_ref("/repo", self.commit)

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["query_strategy"], "targeted_raw_commit")
        raw_proof.assert_called_once()
        self.assertEqual(raw_proof.call_args.args[1], "origin")
        compatibility_inventory.assert_not_called()
        broad_inventory.assert_not_called()

    def test_full_commit_hard_failure_stops_before_lower_remote_tier(self):
        failed = {
            "status": "remote_expected_commit_unmaterializable",
            "resolved_commit": "",
            "expected_commit": self.commit,
            "attempts": [],
            "candidate": {**self.candidate, "kind": "commit"},
            "failure": {
                "remote": "origin",
                "reason": "connection reset by peer",
                "reason_code": "transient_network_failure",
                "retryable": False,
            },
        }
        with patch.object(
            refs, "_remote_names", return_value=(["origin", "upstream"], [])
        ), patch.object(
            refs,
            "_materialize_explicit_commit_from_remote",
            return_value=failed,
        ) as raw_proof, patch.object(
            refs, "_compat_advertised_commit_inventory"
        ) as compatibility_inventory:
            result = refs.resolve_remote_source_ref("/repo", self.commit)

        self.assertEqual(result["status"], "remote_query_failed")
        self.assertTrue(result["selection_blocked_by_higher_priority_remote"])
        self.assertEqual(raw_proof.call_count, 1)
        self.assertEqual(raw_proof.call_args.args[1], "origin")
        compatibility_inventory.assert_not_called()

    def test_short_commit_requires_unique_full_remote_object(self):
        other_commit = "a" * 39 + "b"
        inventories = []
        for remote, commit in (("first", self.commit), ("second", other_commit)):
            inventories.append({
                "queried_at": "now",
                "refs": [{
                    **self.candidate,
                    "remote": remote,
                    "ref": f"{remote}/release",
                    "commit": commit,
                }],
                "failures": [],
                "remotes": [remote],
            })
        with patch.object(
            refs, "_remote_names", return_value=(["first", "second"], [])
        ), patch.object(
            refs,
            "_compat_advertised_commit_inventory",
            side_effect=inventories,
        ), patch.object(refs, "_materialize_targeted_commit") as materialize:
            result = refs.resolve_remote_source_ref("/repo", "a" * 7)

        self.assertEqual(result["status"], "remote_source_ambiguous")
        self.assertEqual(
            {item["commit"] for item in result["candidates"]},
            {self.commit, other_commit},
        )
        materialize.assert_not_called()

    def test_retry_does_not_sleep_or_start_another_query_past_deadline(self):
        with patch.object(
            refs,
            "_git",
            return_value=("", "connection reset by peer", 128),
        ) as git_mock, patch.object(
            refs.time,
            "monotonic",
            side_effect=[100.0, 100.9],
        ), patch.object(refs.time, "sleep") as sleep_mock:
            result = refs._targeted_remote_ref_inventory(
                "/repo",
                "origin",
                "release",
                timeout=30,
                retry_delays=(1,),
                deadline=101.0,
            )

        self.assertEqual(git_mock.call_count, 1)
        self.assertEqual(git_mock.call_args.kwargs["timeout"], 1.0)
        sleep_mock.assert_not_called()
        self.assertEqual(
            result["failures"][0]["reason_code"],
            refs._DEADLINE_FAILURE,
        )

    def test_resolve_passes_one_absolute_deadline_to_query_and_fetch(self):
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
            "attempts": [],
        }
        with patch.object(
            refs.time, "monotonic", return_value=100.0
        ), patch.object(
            refs, "_remote_names", return_value=(["origin"], [])
        ) as names, patch.object(
            refs, "_targeted_remote_ref_inventory", return_value=inventory
        ) as query, patch.object(
            refs, "_materialize_targeted_commit", return_value=materialized
        ) as fetch:
            result = refs.resolve_remote_source_ref(
                "/repo",
                "release",
                query_timeout=2,
                fetch_timeout=3,
            )

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(names.call_args.kwargs["deadline"], 105.0)
        self.assertEqual(query.call_args.kwargs["deadline"], 105.0)
        self.assertEqual(fetch.call_args.kwargs["deadline"], 105.0)

    def test_local_status_failure_blocks_even_confirmed_local_source(self):
        for allow_local in (False, True):
            with self.subTest(allow_local=allow_local), patch.object(
                refs,
                "_verify_local_commit_details",
                return_value=(self.commit, None),
            ), patch.object(
                refs,
                "_git",
                return_value=("", "fatal: status process failed", 128),
            ):
                result = refs.resolve_local_source_ref(
                    "/repo",
                    "release",
                    allow_local_source=allow_local,
                )

            self.assertEqual(result["status"], "local_status_unavailable")
            self.assertIsNone(result["dirty"])
            self.assertFalse(result["status_available"])
            self.assertEqual(
                result["failures"][0]["reason_code"],
                "local_status_unavailable",
            )

    def test_local_ref_process_failure_is_not_reported_as_missing_ref(self):
        failure = {
            "stage": "local_ref_resolution",
            "reason": "fatal: not a git repository",
            "reason_code": "local_ref_resolution_failed",
            "return_code": 128,
        }
        with patch.object(
            refs,
            "_verify_local_commit_details",
            return_value=("", failure),
        ), patch.object(refs, "_git", return_value=("", "", 0)):
            result = refs.resolve_local_source_ref(
                "/repo",
                "release",
                allow_local_source=True,
            )

        self.assertEqual(result["status"], "local_ref_resolution_failed")
        self.assertEqual(
            result["failures"][0]["reason_code"],
            "local_ref_resolution_failed",
        )

    def test_local_ref_probe_distinguishes_absence_from_process_failure(self):
        missing = ("", "fatal: Needed a single revision", 128)
        with patch.object(refs, "_git", side_effect=[missing, missing]):
            commit, failure = refs._verify_local_commit_details(
                "/repo",
                "missing-release",
            )

        self.assertEqual(commit, "")
        self.assertIsNone(failure)

        with patch.object(
            refs,
            "_git",
            return_value=("", "fatal: cannot spawn git helper", 128),
        ):
            commit, failure = refs._verify_local_commit_details(
                "/repo",
                "release",
            )

        self.assertEqual(commit, "")
        self.assertEqual(failure["reason_code"], "local_ref_resolution_failed")

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
