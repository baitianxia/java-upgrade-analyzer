import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import remote_source_refs as refs  # noqa: E402


class RemoteSourceRefBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.commit = "a" * 40
        self.other_commit = "b" * 40
        self.commit64 = "c" * 64
        self.candidate = {
            "remote": "origin",
            "ref": "origin/release",
            "canonical_ref": "refs/heads/release",
            "short_name": "release",
            "kind": "branch",
            "commit": self.commit,
            "score": 300,
        }

    def test_low_level_parsing_timing_and_failure_matrix(self):
        with patch.object(
            refs, "run_cmd", return_value=(None, None, 1),
        ) as command, tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(refs._git(tmp, "status", timeout=2), ("", "", 1))
            self.assertEqual(command.call_args.kwargs["timeout"], 2)
            self.assertEqual(
                command.call_args.kwargs["env"], {"GIT_TERMINAL_PROMPT": "0"},
            )

        first = refs._fingerprint(None, None, None)
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertEqual(first, refs._fingerprint("", [], []))
        self.assertNotEqual(
            first,
            refs._fingerprint(" release ", [{"commit": self.commit}], [{"x": 1}]),
        )

        valid = (
            f"{self.commit}\trefs/heads/release\n"
            f"{self.commit64} refs/tags/v1\n"
        )
        rows, malformed = refs._parse_remote_rows(
            "\ninvalid\n"
            + "z" * 40
            + " refs/heads/bad\n"
            + self.commit
            + " not-a-ref\n"
            + valid
        )
        self.assertEqual(rows, [
            (self.commit, "refs/heads/release"),
            (self.commit64, "refs/tags/v1"),
        ])
        self.assertEqual(len(malformed), 3)
        self.assertEqual(refs._parse_remote_rows(None), ([], []))

        self.assertEqual(
            refs._empty_observation_signature("\n value \n\n"),
            refs._empty_observation_signature("value"),
        )
        self.assertNotEqual(
            refs._empty_observation_signature(None),
            refs._empty_observation_signature("value"),
        )
        empty = {"status": "remote_ref_observation_empty", "signature": "same"}
        self.assertIsNone(refs._absence_observation_failure([empty, dict(empty)]))
        self.assertEqual(
            refs._absence_observation_failure(None)[0],
            "remote_ref_observation_unconfirmed",
        )
        self.assertEqual(
            refs._absence_observation_failure([
                {"status": "remote_ref_observation_malformed", "signature": "a"},
                empty,
            ])[0],
            "remote_ref_observation_malformed",
        )
        self.assertEqual(
            refs._absence_observation_failure([
                {"status": "remote_ref_observation_unexpected", "signature": "a"},
                empty,
            ])[0],
            "remote_ref_observation_unexpected",
        )
        self.assertEqual(
            refs._absence_observation_failure([
                empty,
                {"status": "remote_ref_observation_empty", "signature": "different"},
            ])[0],
            "inconsistent_remote_ref_observation",
        )

        self.assertEqual(refs._retry_delay((), 1), 0)
        self.assertEqual(refs._retry_delay((0,), 1), 0)
        self.assertEqual(refs._retry_delay((-1,), 1), 0)
        self.assertGreater(refs._retry_delay((1,), 5), 1)
        with patch.object(refs.time, "monotonic", return_value=10):
            self.assertEqual(refs._new_deadline(None, -2, 3), 13)
            self.assertEqual(refs._remaining_timeout(None, None), 0)
            self.assertEqual(refs._remaining_timeout(None, 4), 4)
            self.assertEqual(refs._remaining_timeout(9, 4), 0)
            self.assertEqual(refs._remaining_timeout(20, 4), 4)
            self.assertEqual(refs._remaining_timeout(12, 4), 2)
        with patch.object(refs, "_retry_delay", return_value=0), patch.object(
            refs.time, "sleep",
        ) as sleep:
            self.assertTrue(refs._sleep_before_retry((), 1))
            sleep.assert_not_called()
        with patch.object(refs, "_retry_delay", return_value=2), patch.object(
            refs, "_remaining_timeout", return_value=1,
        ), patch.object(refs.time, "sleep") as sleep:
            self.assertFalse(refs._sleep_before_retry((2,), 1, deadline=3))
            sleep.assert_not_called()
        with patch.object(refs, "_retry_delay", return_value=2), patch.object(
            refs, "_remaining_timeout", return_value=2,
        ), patch.object(refs.time, "sleep") as sleep:
            self.assertTrue(refs._sleep_before_retry((2,), 1, deadline=3))
            sleep.assert_called_once_with(2)

        self.assertEqual(refs._parse_remote_names(None), [])
        self.assertEqual(refs._parse_remote_names(""), [])
        self.assertEqual(refs._parse_remote_names(" z\na\na\n"), ["a", "z"])
        names, malformed = refs._parse_remote_url_keys(
            "\ninvalid\nremote..url value\n"
            "remote.origin.url /repo\nREMOTE.backup.URL /backup\n"
            "remote.origin.url duplicate\n"
        )
        self.assertEqual(names, ["backup", "origin"])
        self.assertEqual(malformed, ["invalid", "remote..url"])

    def test_failure_classification_and_result_shape_matrix(self):
        cases = (
            ("permission denied", 1, "authentication_failed", False),
            ("HTTP/2 403", 1, "authentication_failed", False),
            ("invalid refspec", 1, "remote_ref_not_found", False),
            ("anything", -1, "transient_network_failure", True),
            ("HTTP 408", 1, "transient_network_failure", True),
            ("network is unreachable", 1, "transient_network_failure", True),
            (None, None, "fetch_failed", True),
        )
        for reason, rc, kind, retryable in cases:
            self.assertEqual(
                refs.classify_fetch_failure(reason, rc), (kind, retryable),
            )

        for reason, code in (
            (None, "local_remote_discovery_failed"),
            ("the total remote resolution deadline ended", refs._DEADLINE_FAILURE),
            ("fatal: not a git repository", "repository_not_git"),
            ("这不是一个 git 仓库", "repository_not_git"),
            ("不是 git 仓库", "repository_not_git"),
        ):
            names, failures = refs._remote_discovery_failure(
                ".", reason, attempts=None, inconsistent=reason is None,
            )
            self.assertEqual(names, [])
            self.assertEqual(failures[0]["reason_code"], code)
            self.assertEqual(
                failures[0]["observation_status"],
                "inconsistent" if reason is None else "failed",
            )
        _names, failure = refs._remote_discovery_failure(
            ".", "failure", attempts=[{"attempt": 1}],
        )
        self.assertEqual(failure[0]["attempts"], [{"attempt": 1}])

        default = refs._base_result("missing", None)
        self.assertEqual(default["requested_ref"], "")
        self.assertTrue(default["queried_at"].endswith("Z"))
        supplied = refs._base_result(
            "failed", " ref ", [{"x": 1}], [{"y": 2}], "time",
        )
        self.assertEqual(supplied["requested_ref"], "ref")
        self.assertEqual(supplied["queried_at"], "time")

    def test_version_matching_remote_target_and_grouping_matrix(self):
        score_cases = (
            ("release", "no-version", 0),
            ("release-1.2", "1.2-SNAPSHOT", 120),
            ("x11.2-release-1.2", "1.2", 120),
            ("release-1.2x-release_1.2", "1.2", 120),
            ("release-11.2x", "1.2", 0),
            (None, "1.2", 0),
        )
        for candidate, requested, expected in score_cases:
            self.assertEqual(
                refs._version_boundary_score(candidate, requested), expected,
            )
        self.assertEqual(refs._version_boundary_score("", ""), 0)

        inventory = {
            "remotes": ["origin", "backup"],
            "refs": [
                {**self.candidate, "short_name": "release", "score": 1},
                {
                    **self.candidate,
                    "remote": "backup",
                    "ref": "backup/release",
                    "short_name": "release",
                    "kind": "tag",
                },
                {
                    **self.candidate,
                    "ref": "origin/release-1.2",
                    "short_name": "release-1.2",
                },
                {
                    **self.candidate,
                    "ref": "origin/unrelated",
                    "short_name": "unrelated",
                },
            ],
        }
        self.assertEqual(refs._matching_remote_candidates(inventory, ""), [])
        exact = refs._matching_remote_candidates(inventory, "release")
        self.assertEqual(len(exact), 2)
        explicit = refs._matching_remote_candidates(inventory, "backup/release")
        self.assertEqual([item["remote"] for item in explicit], ["backup"])
        version = refs._matching_remote_candidates(inventory, "1.2")
        self.assertEqual([item["short_name"] for item in version], ["release-1.2"])
        self.assertEqual(refs._matching_remote_candidates(inventory, "missing"), [])

        self.assertEqual(
            refs._requested_remote_targets(None, None), ([], "", ""),
        )
        self.assertEqual(
            refs._requested_remote_targets(["backup", "origin"], "refs/heads/release"),
            (["origin", "backup"], "release", "refs/heads/release"),
        )
        self.assertEqual(
            refs._requested_remote_targets(["origin"], "refs/tags/v1"),
            (["origin"], "v1", "refs/tags/v1"),
        )
        self.assertEqual(
            refs._requested_remote_targets(["origin", "backup"], "backup/release"),
            (["backup"], "release", ""),
        )
        self.assertEqual(
            refs._requested_remote_targets(["origin"], "missing/release"),
            (["origin"], "missing/release", ""),
        )
        self.assertEqual(
            refs._requested_remote_tiers(["origin", "backup"], "backup/release")[0],
            [["backup"]],
        )
        self.assertEqual(
            refs._requested_remote_tiers(["origin", "backup"], "release")[0],
            [["origin"], ["backup"]],
        )
        self.assertEqual(
            refs._requested_remote_tiers(["origin"], "release")[0],
            [["origin"]],
        )
        self.assertEqual(
            refs._requested_remote_tiers(["backup"], "release")[0],
            [["backup"]],
        )

        self.assertEqual(refs._candidate_sort_key(None), (True, "", True, "", ""))
        self.assertLess(
            refs._candidate_sort_key(self.candidate),
            refs._candidate_sort_key({
                **self.candidate,
                "remote": "backup",
                "kind": "tag",
                "canonical_ref": "refs/tags/v1",
                "ref": "backup/v1",
            }),
        )
        aliases = [
            self.candidate,
            {
                **self.candidate,
                "remote": "backup",
                "ref": "backup/release",
                "commit": self.commit.upper(),
            },
            {**self.candidate, "commit": ""},
        ]
        groups = refs._group_remote_candidates(aliases)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0][0], self.commit)
        self.assertEqual(len(groups[0][1]["aliases"]), 2)
        self.assertEqual(refs._group_remote_candidates(None), [])
        single = refs._group_remote_candidates([self.candidate])
        self.assertNotIn("aliases", single[0][1])

    def test_residual_matching_status_and_fallback_matrix(self):
        score_cases = (
            ("1.2", "1.2", 120),
            (".1.2", "1.2", 0),
            ("a1.2", "1.2", 120),
            ("1.2x", "1.2", 0),
            ("1.2-release", "1.2", 120),
        )
        for candidate, requested, expected in score_cases:
            self.assertEqual(
                refs._version_boundary_score(candidate, requested), expected,
            )

        inventory = {
            "remotes": None,
            "refs": [
                {**self.candidate, "short_name": "1.2", "ref": "origin/1.2"},
                {
                    **self.candidate,
                    "remote": "backup",
                    "short_name": "release-1.2",
                    "ref": "backup/release-1.2",
                },
            ],
        }
        matches = refs._matching_remote_candidates(inventory, "1.2")
        self.assertEqual([item["short_name"] for item in matches], ["1.2"])
        explicit_inventory = {
            "remotes": ["backup"],
            "refs": [
                {
                    **self.candidate,
                    "remote": "backup",
                    "short_name": "release",
                    "ref": "backup/release",
                },
                {
                    **self.candidate,
                    "remote": "backup",
                    "short_name": "other",
                    "ref": "backup/other",
                },
                self.candidate,
            ],
        }
        self.assertEqual(
            [item["short_name"] for item in refs._matching_remote_candidates(
                explicit_inventory, "backup/release",
            )],
            ["release"],
        )
        self.assertEqual(
            refs._matching_remote_candidates(explicit_inventory, "missing/release"),
            [],
        )

        inventories = (
            ({"refs": [self.candidate]}, "resolved"),
            ({
                "refs": [self.candidate, {**self.candidate, "commit": self.other_commit}],
                "queried_at": "time",
                "remotes": ["origin"],
            }, "ambiguous"),
            ({"refs": [], "failures": [{"reason": "failed"}]}, "query_failed"),
            ({}, "not_found"),
            ({"refs": [self.candidate], "failures": [{"reason": "partial"}]}, "query_failed"),
        )
        for inventory_result, expected_status in inventories:
            with patch.object(
                refs, "query_live_remote_refs", return_value=inventory_result,
            ):
                result = refs.match_remote_refs_by_version("/repo", "release")
            self.assertEqual(result["status"], expected_status)
        self.assertEqual(
            refs.match_remote_refs_by_version("/repo", None)["status"],
            "version_missing",
        )

        self.assertEqual(
            refs._requested_remote_tiers(
                ["origin", "backup"], "refs/heads/team/release",
            )[0],
            [["origin"], ["backup"]],
        )
        self.assertEqual(
            refs._requested_remote_tiers(None, "missing/release")[0],
            [[]],
        )
        self.assertEqual(refs._requested_remote_tiers(None, None)[0], [[]])

        sparse_aliases = [
            {"commit": self.commit},
            {
                "commit": self.commit.upper(),
                "remote": "origin",
                "ref": None,
                "canonical_ref": None,
            },
        ]
        groups = refs._group_remote_candidates(sparse_aliases)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0][1]["aliases"][1], {
            "remote": "",
            "ref": "",
            "canonical_ref": "",
        })

    def test_remote_name_discovery_observation_matrix(self):
        with patch.object(refs, "_remaining_timeout", return_value=0):
            names, failures = refs._remote_names("/repo", deadline=1)
        self.assertEqual(names, [])
        self.assertEqual(failures[0]["reason_code"], refs._DEADLINE_FAILURE)

        with patch.object(
            refs, "_remaining_timeout", side_effect=[10, 0],
        ), patch.object(refs, "_git", return_value=("origin", "", 0)):
            names, failures = refs._remote_names("/repo", deadline=1)
        self.assertEqual(names, [])
        self.assertEqual(failures[0]["reason_code"], refs._DEADLINE_FAILURE)

        responses = [
            ("origin", "", 0),
            ("remote.origin.url /repo\ninvalid", "", 0),
        ]
        with patch.object(refs, "_git", side_effect=responses), patch.object(
            refs, "_sleep_before_retry", return_value=False,
        ):
            names, failures = refs._remote_names("/repo")
        self.assertEqual(names, [])
        self.assertEqual(failures[0]["observation_status"], "failed")
        self.assertEqual(failures[0]["reason_code"], refs._DEADLINE_FAILURE)

        responses = [
            ("", "failure one", 2),
            ("", "failure two", 2),
            ("", "failure three", 2),
            ("", "", 1),
        ]
        with patch.object(refs, "_git", side_effect=responses), patch.object(
            refs, "_sleep_before_retry", return_value=True,
        ):
            names, failures = refs._remote_names("/repo")
        self.assertEqual(names, [])
        self.assertEqual(failures[0]["reason_code"], "local_remote_discovery_failed")
        self.assertIn("failure one", failures[0]["reason"])

        responses = [
            ("inherited", "", 0),
            ("", "", 1),
        ]
        with patch.object(refs, "_git", side_effect=responses):
            self.assertEqual(refs._remote_names("/repo"), ([], []))

        responses = [
            ("", "", 0),
            ("", "", 0),
            ("remote.origin.url /repo", "", 0),
        ]
        with patch.object(refs, "_git", side_effect=responses):
            self.assertEqual(refs._remote_names("/repo"), (["origin"], []))

        responses = [
            ("stdout failure", "", 2),
            ("", "", 2),
            ("", "stderr failure", 2),
            ("", "config stderr", 2),
            ("bad-key", "", 2),
            ("", "", 2),
        ]
        with patch.object(refs, "_git", side_effect=responses), patch.object(
            refs, "_sleep_before_retry", return_value=True,
        ):
            names, failures = refs._remote_names("/repo")
        self.assertEqual(names, [])
        self.assertEqual(failures[0]["observation_status"], "inconsistent")
        self.assertIn("git config exited with 2", failures[0]["reason"])

        responses = [
            ("", "", 0),
            ("", "", 0),
            ("", "config failed", 2),
            ("", "config failed", 2),
            ("", "config failed", 2),
        ]
        with patch.object(refs, "_git", side_effect=responses), patch.object(
            refs, "_sleep_before_retry", return_value=True,
        ):
            names, failures = refs._remote_names("/repo")
        self.assertEqual(names, [])
        self.assertEqual(failures[0]["observation_status"], "inconsistent")

    def test_broad_remote_inventory_branch_tag_and_failure_matrix(self):
        rows = (
            f"{self.commit}\trefs/heads/release\n"
            f"{self.other_commit}\trefs/tags/v1\n"
            f"{self.commit}\trefs/tags/v1^{{}}\n"
            f"{self.commit}\trefs/notes/ignored\n"
        )
        with patch.object(
            refs, "_remote_names", return_value=(["backup", "origin"], [{"seed": 1}]),
        ), patch.object(refs, "_git", side_effect=[(rows, "", 0), (rows, "", 0)]):
            result = refs.query_live_remote_refs("/repo")
        self.assertEqual(result["remotes"], ["origin", "backup"])
        self.assertEqual(len(result["refs"]), 4)
        tags = [item for item in result["refs"] if item["kind"] == "tag"]
        self.assertTrue(all(item["commit"] == self.commit for item in tags))
        self.assertEqual(result["failures"], [{"seed": 1}])

        with patch.object(refs, "_remote_names", return_value=(["origin"], [])), patch.object(
            refs, "_remaining_timeout", return_value=0,
        ):
            result = refs.query_live_remote_refs("/repo", deadline=1)
        self.assertEqual(result["failures"][0]["reason_code"], refs._DEADLINE_FAILURE)

        with patch.object(refs, "_remote_names", return_value=(["origin"], [])), patch.object(
            refs, "_git", side_effect=[("bad output", "", 0), ("bad output", "", 0)],
        ), patch.object(refs, "_sleep_before_retry", return_value=True):
            result = refs.query_live_remote_refs(
                "/repo", retry_attempts=2, retry_delays=None,
            )
        self.assertEqual(
            result["failures"][0]["reason_code"],
            "remote_ref_observation_malformed",
        )

        with patch.object(refs, "_remote_names", return_value=(["origin"], [])), patch.object(
            refs, "_git", side_effect=[("", "", 0), ("", "", 0)],
        ), patch.object(refs, "_sleep_before_retry", return_value=True):
            result = refs.query_live_remote_refs(
                "/repo", retry_attempts=2, retry_delays=(),
            )
        self.assertEqual(result["refs"], [])
        self.assertEqual(result["failures"], [])

        for response, expected_code in (
            (("", "permission denied", 1), "authentication_failed"),
            (("stdout failure", "", 1), "fetch_failed"),
            (("", "", 1), "fetch_failed"),
        ):
            with patch.object(
                refs, "_remote_names", return_value=(["origin"], []),
            ), patch.object(refs, "_git", return_value=response):
                result = refs.query_live_remote_refs(
                    "/repo", retry_attempts=1, retry_delays=(),
                )
            self.assertEqual(result["failures"][0]["reason_code"], expected_code)

        with patch.object(refs, "_remote_names", return_value=(["origin"], [])), patch.object(
            refs, "_git", return_value=("", "connection reset", 1),
        ), patch.object(refs, "_sleep_before_retry", return_value=False):
            result = refs.query_live_remote_refs(
                "/repo", retry_attempts=3, retry_delays=(1,),
            )
        self.assertEqual(result["failures"][0]["reason_code"], refs._DEADLINE_FAILURE)

        mixed = f"{self.commit}\trefs/heads/release\nmalformed\n"
        with patch.object(refs, "_remote_names", return_value=(["origin"], [])), patch.object(
            refs, "_git", side_effect=[(mixed, "", 0), (mixed, "", 0)],
        ), patch.object(refs, "_sleep_before_retry", return_value=True):
            result = refs.query_live_remote_refs(
                "/repo", retry_attempts=2, retry_delays=(),
            )
        self.assertEqual(
            result["failures"][0]["reason_code"],
            "remote_ref_observation_malformed",
        )

        for response in (("", "permission denied", 1), ("", "connection reset", 1)):
            with patch.object(
                refs, "_remote_names", return_value=(["origin"], []),
            ), patch.object(refs, "_git", return_value=response):
                result = refs.query_live_remote_refs(
                    "/repo", retry_attempts=0, retry_delays=None,
                )
            self.assertEqual(len(result["failures"]), 1)

    def test_targeted_inventory_exact_unexpected_and_tag_matrix(self):
        expected = f"{self.commit}\trefs/heads/release\n"
        unexpected = f"{self.other_commit}\trefs/heads/release.dev\n"
        with patch.object(refs, "_git", return_value=(expected + unexpected, "", 0)):
            result = refs._targeted_remote_ref_inventory(
                "/repo", "origin", "release", retry_attempts=1,
            )
        self.assertEqual(result["refs"][0]["kind"], "branch")
        self.assertEqual(
            result["attempts"][0]["ignored_unexpected_refs"],
            ["refs/heads/release.dev"],
        )

        tag_rows = (
            f"{self.other_commit}\trefs/tags/v1\n"
            f"{self.commit}\trefs/tags/v1^{{}}\n"
        )
        with patch.object(refs, "_git", return_value=(tag_rows, "", 0)):
            result = refs._targeted_remote_ref_inventory(
                "/repo",
                "origin",
                "v1",
                canonical_ref="refs/tags/v1",
                retry_attempts=1,
            )
        self.assertEqual(result["refs"][0]["commit"], self.commit)
        self.assertEqual(result["refs"][0]["kind"], "tag")

        for outputs, expected_code in (
            ([unexpected, unexpected], "remote_ref_observation_unexpected"),
            (["malformed", "malformed"], "remote_ref_observation_malformed"),
        ):
            with patch.object(
                refs, "_git", side_effect=[(item, "", 0) for item in outputs],
            ), patch.object(refs, "_sleep_before_retry", return_value=True):
                result = refs._targeted_remote_ref_inventory(
                    "/repo", "origin", "release", retry_attempts=2, retry_delays=(),
                )
            self.assertEqual(result["failures"][0]["reason_code"], expected_code)

        with patch.object(
            refs, "_git", side_effect=[("", "", 0), ("", "", 0)],
        ), patch.object(refs, "_sleep_before_retry", return_value=True):
            result = refs._targeted_remote_ref_inventory(
                "/repo", "origin", "release", retry_attempts=2, retry_delays=(),
            )
        self.assertEqual(result["refs"], [])
        self.assertEqual(result["failures"], [])

        with patch.object(refs, "_remaining_timeout", return_value=0):
            result = refs._targeted_remote_ref_inventory(
                "/repo", None, None, canonical_ref="refs/heads/release", deadline=1,
            )
        self.assertEqual(result["failures"][0]["reason_code"], refs._DEADLINE_FAILURE)

        with patch.object(refs, "_git", return_value=("", "connection reset", 1)), patch.object(
            refs, "_sleep_before_retry", return_value=False,
        ):
            result = refs._targeted_remote_ref_inventory(
                "/repo", "origin", "release", retry_attempts=3,
            )
        self.assertEqual(result["failures"][0]["reason_code"], refs._DEADLINE_FAILURE)

        for response, expected_code in (
            (("", "permission denied", 1), "authentication_failed"),
            (("stdout only", "", 2), "fetch_failed"),
            (("", "", 2), "fetch_failed"),
        ):
            with patch.object(refs, "_git", return_value=response):
                result = refs._targeted_remote_ref_inventory(
                    "/repo", "origin", "release", retry_attempts=0,
                )
            self.assertEqual(result["failures"][0]["reason_code"], expected_code)

        note = f"{self.commit}\trefs/notes/release\n"
        with patch.object(refs, "_git", return_value=(note, "", 0)):
            result = refs._targeted_remote_ref_inventory(
                "/repo",
                "origin",
                "release",
                canonical_ref="refs/notes/release",
                retry_attempts=1,
            )
        self.assertEqual(result["refs"], [])

        mixed = expected + "malformed\n"
        with patch.object(
            refs, "_git", side_effect=[(mixed, "", 0), (mixed, "", 0)],
        ), patch.object(refs, "_sleep_before_retry", return_value=True):
            result = refs._targeted_remote_ref_inventory(
                "/repo", "origin", "release", retry_attempts=2,
            )
        self.assertEqual(
            result["failures"][0]["reason_code"],
            "remote_ref_observation_malformed",
        )

    def test_compat_advertised_inventory_branch_tag_and_absence_matrix(self):
        rows = (
            f"{self.commit}\trefs/heads/release\n"
            f"{self.other_commit}\trefs/heads/other\n"
            f"{self.other_commit}\trefs/tags/v1\n"
            f"{self.commit}\trefs/tags/v1^{{}}\n"
            f"{self.commit}\trefs/notes/ignored\n"
        )
        with patch.object(refs, "_git", return_value=(rows, "", 0)):
            result = refs._compat_advertised_commit_inventory(
                "/repo", "origin", self.commit[:8], retry_attempts=1,
            )
        self.assertEqual({item["kind"] for item in result["refs"]}, {"branch", "tag"})
        self.assertTrue(all(
            item["commit"].startswith(self.commit[:8]) for item in result["refs"]
        ))

        with patch.object(
            refs, "_git", side_effect=[("", "", 0), ("", "", 0)],
        ), patch.object(refs, "_sleep_before_retry", return_value=True):
            result = refs._compat_advertised_commit_inventory(
                "/repo", "origin", self.commit, retry_attempts=2, retry_delays=(),
            )
        self.assertEqual(result["refs"], [])
        self.assertEqual(result["failures"], [])

        with patch.object(
            refs, "_git", side_effect=[("bad", "", 0), ("bad", "", 0)],
        ), patch.object(refs, "_sleep_before_retry", return_value=True):
            result = refs._compat_advertised_commit_inventory(
                "/repo", "origin", self.commit, retry_attempts=2, retry_delays=None,
            )
        self.assertEqual(
            result["failures"][0]["reason_code"],
            "remote_ref_observation_malformed",
        )

        with patch.object(refs, "_remaining_timeout", return_value=0):
            result = refs._compat_advertised_commit_inventory(
                "/repo", None, None, deadline=1,
            )
        self.assertEqual(result["failures"][0]["reason_code"], refs._DEADLINE_FAILURE)

        with patch.object(refs, "_git", return_value=("", "connection reset", 1)), patch.object(
            refs, "_sleep_before_retry", return_value=False,
        ):
            result = refs._compat_advertised_commit_inventory(
                "/repo", "origin", self.commit, retry_attempts=3,
            )
        self.assertEqual(result["failures"][0]["reason_code"], refs._DEADLINE_FAILURE)

        for response, expected_code in (
            (("", "permission denied", 1), "authentication_failed"),
            (("stdout only", "", 2), "fetch_failed"),
            (("", "", 2), "fetch_failed"),
        ):
            with patch.object(refs, "_git", return_value=response):
                result = refs._compat_advertised_commit_inventory(
                    "/repo", "origin", self.commit, retry_attempts=0,
                )
            self.assertEqual(result["failures"][0]["reason_code"], expected_code)

        mixed = f"{self.commit}\trefs/heads/release\nmalformed\n"
        with patch.object(
            refs, "_git", side_effect=[(mixed, "", 0), (mixed, "", 0)],
        ), patch.object(refs, "_sleep_before_retry", return_value=True):
            result = refs._compat_advertised_commit_inventory(
                "/repo", "origin", self.commit, retry_attempts=2,
            )
        self.assertEqual(
            result["failures"][0]["reason_code"],
            "remote_ref_observation_malformed",
        )

    def test_commit_verification_fetch_and_public_materialization_matrix(self):
        self.assertEqual(refs._verify_commit_object("/repo", None), "")
        with patch.object(refs, "_remaining_timeout", return_value=0):
            self.assertEqual(refs._verify_commit_object("/repo", self.commit, deadline=1), "")
        for response, expected in (
            ((f"noise\n{self.commit}", "", 0), self.commit),
            ((self.other_commit, "", 0), ""),
            (("", "", 0), ""),
            (("", "", 1), ""),
        ):
            with patch.object(refs, "_git", return_value=response):
                self.assertEqual(refs._verify_commit_object("/repo", self.commit), expected)

        missing_cases = (
            ({}, self.commit),
            ({"remote": "origin"}, ""),
            (None, None),
        )
        for candidate, expected in missing_cases:
            result = refs._fetch_expected_commit("/repo", candidate, expected)
            self.assertEqual(result["status"], "remote_expected_commit_unmaterializable")
        with patch.object(refs, "_git", return_value=("", "", 0)):
            self.assertEqual(
                refs._fetch_expected_commit("/repo", self.candidate, self.commit)["status"],
                "success",
            )
        for response, expected in (
            (("", "permission denied", 1), "authentication_failed"),
            (("stdout error", "", 1), "fetch_failed"),
            (("", "", 2), "fetch_failed"),
        ):
            with patch.object(refs, "_git", return_value=response):
                result = refs._fetch_expected_commit("/repo", self.candidate, self.commit)
            self.assertEqual(result["failure_type"], expected)

        with patch.object(refs, "_new_deadline", return_value=10), patch.object(
            refs,
            "_materialize_targeted_commit",
            return_value={
                "resolved_commit": self.commit,
                "resolution_mode": "",
                "expected_commit": "",
                "attempts": None,
            },
        ):
            result = refs.materialize_remote_source_candidate(
                "/repo", self.candidate, expected_commit=self.commit,
            )
        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolution_mode"], "live_remote")
        self.assertEqual(result["expected_commit"], self.commit)

        failures = (
            {},
            {"status": "custom_failed", "attempts": [{"stage": "custom"}]},
            {
                "status": "custom_failed",
                "expected_commit": self.commit,
                "attempts": [],
                "failure": {
                    "remote": "backup",
                    "stage": "stage",
                    "reason": "reason",
                    "reason_code": "code",
                    "retryable": True,
                },
            },
        )
        for materialized in failures:
            with patch.object(refs, "_materialize_targeted_commit", return_value=materialized):
                result = refs.materialize_remote_source_candidate("/repo", self.candidate)
            self.assertFalse(result["resolved_commit"])
            self.assertIn("reason_code", result["failure"])

        with patch.object(
            refs,
            "_materialize_targeted_commit",
            return_value={"resolved_commit": self.commit},
        ):
            result = refs.materialize_remote_source_candidate(
                "/repo", {}, expected_commit=None,
            )
        self.assertEqual(result["remote"], "")
        self.assertEqual(result["remote_ref"], "")
        self.assertEqual(result["resolved_ref"], "")

        with patch.object(
            refs, "_materialize_targeted_commit", return_value={},
        ):
            result = refs.materialize_remote_source_candidate("/repo", None)
        self.assertEqual(result["failure"]["remote"], "")

    def test_targeted_commit_materialization_state_machine_matrix(self):
        for pinned, mode in ((False, "live_remote"), (True, "pinned_commit")):
            with patch.object(
                refs, "_verify_commit_object", return_value=self.commit,
            ), patch.object(refs, "_git") as git_mock:
                result = refs._materialize_targeted_commit(
                    "/repo", self.candidate, self.commit, pinned=pinned,
                )
            self.assertEqual(result["resolution_mode"], mode)
            self.assertEqual(result["attempts"][0]["stage"], "verify_local_commit")
            git_mock.assert_not_called()

        with patch.object(
            refs, "_verify_commit_object", return_value="",
        ), patch.object(refs, "_remaining_timeout", return_value=0):
            result = refs._materialize_targeted_commit(
                "/repo", self.candidate, self.commit, deadline=1,
            )
        self.assertEqual(result["failure"]["reason_code"], refs._DEADLINE_FAILURE)
        self.assertEqual(
            [item["stage"] for item in result["attempts"]],
            ["fetch_canonical_ref", "fetch_commit"],
        )

        for pinned, expected_mode in ((False, "live_remote"), (True, "pinned_commit")):
            with patch.object(
                refs, "_verify_commit_object", side_effect=["", self.commit],
            ), patch.object(refs, "_git", return_value=("", "", 0)):
                result = refs._materialize_targeted_commit(
                    "/repo", self.candidate, self.commit, pinned=pinned,
                )
            self.assertEqual(result["resolution_mode"], expected_mode)

        for git_result in (
            ("", "Authentication failed", 128),
            ("stdout failure", "", 2),
            ("", "", 2),
        ):
            with patch.object(
                refs, "_verify_commit_object", return_value="",
            ), patch.object(refs, "_git", return_value=git_result), patch.object(
                refs,
                "_fetch_expected_commit",
                return_value={
                    "failure_type": "remote_ref_not_found",
                    "reason": "not found",
                    "retryable": False,
                },
            ) as exact_fetch:
                result = refs._materialize_targeted_commit(
                    "/repo", self.candidate, self.commit, retry_attempts=1,
                )
            if "Authentication" in git_result[1]:
                exact_fetch.assert_not_called()
                self.assertEqual(result["failure"]["reason_code"], "authentication_failed")
            else:
                exact_fetch.assert_called_once()

        with patch.object(
            refs, "_verify_commit_object", side_effect=["", self.commit],
        ), patch.object(
            refs,
            "_git",
            side_effect=[("", "connection reset", 2), ("", "", 0)],
        ), patch.object(refs, "_sleep_before_retry", return_value=True) as sleep:
            result = refs._materialize_targeted_commit(
                "/repo",
                self.candidate,
                self.commit,
                retry_attempts=2,
                retry_delays=None,
            )
        self.assertEqual(result["status"], "remote_source_resolved")
        sleep.assert_called_once()

        exact_failure = {
            "failure_type": "transient_network_failure",
            "reason": "temporary",
            "retryable": True,
        }
        with patch.object(
            refs, "_verify_commit_object", return_value="",
        ), patch.object(
            refs, "_git", return_value=("", "connection reset", 2),
        ), patch.object(
            refs, "_sleep_before_retry", side_effect=[False, False],
        ), patch.object(
            refs, "_fetch_expected_commit", return_value=exact_failure,
        ):
            result = refs._materialize_targeted_commit(
                "/repo", self.candidate, self.commit, retry_attempts=3,
            )
        self.assertEqual(result["failure"]["reason_code"], refs._DEADLINE_FAILURE)

        exact_success = {
            "status": "success",
            "failure_type": "",
            "reason": "",
            "retryable": False,
        }
        candidates = (
            None,
            {"canonical_ref": "refs/heads/release"},
            {"remote": "origin"},
        )
        for candidate in candidates:
            with patch.object(
                refs, "_verify_commit_object", side_effect=["", self.commit],
            ), patch.object(
                refs, "_fetch_expected_commit", return_value=exact_success,
            ):
                result = refs._materialize_targeted_commit(
                    "/repo", candidate, self.commit, retry_attempts=0,
                )
            self.assertEqual(result["status"], "remote_source_resolved")

        with patch.object(
            refs, "_verify_commit_object", side_effect=["", ""],
        ), patch.object(
            refs, "_fetch_expected_commit", return_value=exact_success,
        ):
            result = refs._materialize_targeted_commit(
                "/repo", None, self.commit, pinned=True,
            )
        self.assertEqual(result["status"], "remote_expected_commit_unmaterializable")
        self.assertEqual(result["failure"]["reason_code"], "commit_verification_failed")

        transient_then_success = [exact_failure, exact_success]
        with patch.object(
            refs, "_verify_commit_object", side_effect=["", self.commit],
        ), patch.object(
            refs, "_fetch_expected_commit", side_effect=transient_then_success,
        ), patch.object(refs, "_sleep_before_retry", return_value=True):
            result = refs._materialize_targeted_commit(
                "/repo", {"remote": "origin"}, self.commit, retry_attempts=2,
            )
        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(len(result["attempts"]), 2)

        for fetched in ({}, exact_failure, {
            "failure_type": "remote_ref_not_found",
            "reason": "missing",
            "retryable": False,
        }):
            with patch.object(
                refs, "_verify_commit_object", return_value="",
            ), patch.object(refs, "_fetch_expected_commit", return_value=fetched), patch.object(
                refs, "_sleep_before_retry", return_value=False,
            ):
                result = refs._materialize_targeted_commit(
                    "/repo", None, None, retry_attempts=1, retry_delays=(),
                )
            self.assertEqual(result["status"], "remote_fetch_failed")
            self.assertTrue(result["failure"]["reason"])

    def test_explicit_commit_materialization_state_machine_matrix(self):
        with patch.object(refs, "_remaining_timeout", return_value=0):
            result = refs._materialize_explicit_commit_from_remote(
                "/repo", None, None, retry_attempts=0, retry_delays=None,
                deadline=1,
            )
        self.assertEqual(result["failure"]["reason_code"], refs._DEADLINE_FAILURE)
        self.assertEqual(result["candidate"]["remote"], "")
        self.assertEqual(result["candidate"]["commit"], "")

        success = {
            "status": "success",
            "failure_type": "",
            "reason": "",
            "retryable": False,
        }
        with patch.object(
            refs, "_fetch_expected_commit", return_value=success,
        ), patch.object(refs, "_verify_commit_object", return_value=self.commit):
            result = refs._materialize_explicit_commit_from_remote(
                "/repo", "origin", self.commit,
            )
        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolution_mode"], "explicit_remote_commit")

        with patch.object(
            refs, "_fetch_expected_commit", return_value=success,
        ), patch.object(refs, "_verify_commit_object", return_value=""):
            result = refs._materialize_explicit_commit_from_remote(
                "/repo", "origin", self.commit,
            )
        self.assertEqual(result["failure"]["reason_code"], "commit_verification_failed")

        transient = {
            "failure_type": "transient_network_failure",
            "reason": "temporary",
            "retryable": True,
        }
        with patch.object(
            refs, "_fetch_expected_commit", side_effect=[transient, success],
        ), patch.object(
            refs, "_verify_commit_object", return_value=self.commit,
        ), patch.object(refs, "_sleep_before_retry", return_value=True) as sleep:
            result = refs._materialize_explicit_commit_from_remote(
                "/repo",
                "origin",
                self.commit,
                retry_attempts=2,
                retry_delays=(),
            )
        self.assertEqual(result["status"], "remote_source_resolved")
        sleep.assert_called_once()

        with patch.object(
            refs, "_fetch_expected_commit", return_value=transient,
        ), patch.object(refs, "_sleep_before_retry", return_value=False):
            result = refs._materialize_explicit_commit_from_remote(
                "/repo", "origin", self.commit, retry_attempts=3,
            )
        self.assertEqual(result["failure"]["reason_code"], refs._DEADLINE_FAILURE)

        for fetched in ({}, transient, {
            "failure_type": "authentication_failed",
            "reason": "denied",
            "retryable": False,
        }):
            with patch.object(
                refs, "_fetch_expected_commit", return_value=fetched,
            ), patch.object(refs, "_sleep_before_retry", return_value=True):
                result = refs._materialize_explicit_commit_from_remote(
                    "/repo", "origin", self.commit, retry_attempts=1,
                )
            self.assertEqual(result["status"], "remote_expected_commit_unmaterializable")
            self.assertTrue(result["failure"]["reason"])

    def test_pinned_selected_ref_orchestration_matrix(self):
        result = refs._resolve_pinned_selected_ref(
            "/repo",
            "backup/release",
            self.commit,
            ["origin"],
            expected_remote="backup",
            expected_remote_ref="refs/heads/release",
        )
        self.assertEqual(result["status"], "remote_expected_commit_unmaterializable")
        self.assertEqual(
            result["failures"][0]["reason_code"],
            "expected_remote_not_configured",
        )

        with patch.object(
            refs, "_requested_remote_tiers", return_value=([], "", ""),
        ):
            result = refs._resolve_pinned_selected_ref(
                "/repo", None, None, [], expected_remote=None,
                expected_remote_ref=None,
            )
        self.assertEqual(result["configured_remotes"], [])

        live_tag = {
            "remote": "origin",
            "ref": "origin/v1",
            "canonical_ref": "refs/tags/v1",
            "short_name": "v1",
            "kind": "tag",
            "commit": self.other_commit,
        }
        inventory = {
            "queried_at": "observed-time",
            "attempts": [{"stage": "targeted_ls_remote"}],
            "refs": [live_tag],
            "failures": [],
        }
        with patch.object(
            refs, "_targeted_remote_ref_inventory", return_value=inventory,
        ), patch.object(
            refs,
            "_materialize_targeted_commit",
            return_value={
                "resolved_commit": self.commit,
                "attempts": [{"stage": "fetch_commit"}],
            },
        ):
            result = refs._resolve_pinned_selected_ref(
                "/repo",
                "origin/v1",
                self.commit,
                ["origin"],
                expected_remote="origin",
                expected_remote_ref="refs/tags/v1",
            )
        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["observed_commit"], self.other_commit)
        self.assertEqual(result["observed_live_commits"], [self.other_commit])

        with patch.object(
            refs,
            "_targeted_remote_ref_inventory",
            return_value={"refs": [], "failures": [], "attempts": None},
        ), patch.object(
            refs,
            "_materialize_targeted_commit",
            return_value={"resolved_commit": self.commit, "attempts": None},
        ) as materialize:
            result = refs._resolve_pinned_selected_ref(
                "/repo",
                "origin/release",
                self.commit,
                ["origin"],
                expected_remote_ref="refs/custom/release",
            )
        self.assertEqual(result["status"], "remote_source_resolved")
        synthetic = materialize.call_args.args[1]
        self.assertEqual(synthetic["ref"], "origin/release")
        self.assertEqual(synthetic["short_name"], "refs/custom/release")
        self.assertEqual(synthetic["kind"], "branch")

        with patch.object(
            refs,
            "_requested_remote_tiers",
            return_value=([["backup"]], "v1", "refs/tags/v1"),
        ), patch.object(
            refs,
            "_targeted_remote_ref_inventory",
            return_value={"refs": [], "failures": []},
        ), patch.object(
            refs,
            "_materialize_targeted_commit",
            return_value={"resolved_commit": self.commit},
        ) as materialize:
            result = refs._resolve_pinned_selected_ref(
                "/repo", "origin/v1", self.commit, ["backup"],
            )
        self.assertEqual(result["status"], "remote_source_resolved")
        synthetic = materialize.call_args.args[1]
        self.assertEqual(synthetic["ref"], "backup/v1")
        self.assertEqual(synthetic["kind"], "tag")

        sparse_inventory = {
            "queried_at": "",
            "attempts": None,
            "refs": [{"commit": ""}],
            "failures": None,
        }
        with patch.object(
            refs, "_targeted_remote_ref_inventory", return_value=sparse_inventory,
        ), patch.object(
            refs,
            "_materialize_targeted_commit",
            return_value={"resolved_commit": self.commit},
        ):
            result = refs._resolve_pinned_selected_ref(
                "/repo", "release", self.commit, ["origin"],
            )
        self.assertEqual(result["resolved_ref"], "release")
        self.assertEqual(result["remote"], "")
        self.assertEqual(result["remote_ref"], "")
        self.assertEqual(result["observed_commit"], "")
        self.assertEqual(result["attempts"], [])

        inventories = [
            {
                "queried_at": "",
                "attempts": None,
                "refs": [],
                "failures": [{"reason_code": "remote_query_failed"}],
            },
            {
                "queried_at": "last-time",
                "attempts": [{"stage": "query"}],
                "refs": [
                    {"remote": "backup", "commit": self.commit},
                    {"remote": "backup", "commit": self.other_commit},
                ],
                "failures": [],
            },
        ]
        materialized = [
            {
                "failure": {
                    "remote": "origin",
                    "stage": "fetch_canonical_ref",
                    "reason": "first failure",
                    "reason_code": "remote_ref_not_found",
                },
                "attempts": [{"stage": "fetch_canonical_ref"}],
            },
            {},
            {"failure": {}, "attempts": None},
        ]
        with patch.object(
            refs,
            "_requested_remote_tiers",
            return_value=([["origin", "backup"]], "release", ""),
        ), patch.object(
            refs, "_targeted_remote_ref_inventory", side_effect=inventories,
        ), patch.object(
            refs, "_materialize_targeted_commit", side_effect=materialized,
        ):
            result = refs._resolve_pinned_selected_ref(
                "/repo", "origin/release", self.commit, ["origin", "backup"],
            )
        self.assertEqual(result["status"], "remote_expected_commit_unmaterializable")
        self.assertEqual(result["observed_commit"], "")
        self.assertEqual(
            result["observed_live_commits"],
            sorted([self.commit, self.other_commit]),
        )
        self.assertTrue(any(
            item.get("reason_code") == "remote_query_failed"
            for item in result["failures"]
        ))
        self.assertTrue(all(item["reason"] for item in result["failures"][:3]))

        one_observed = {
            "refs": [{"commit": self.other_commit}],
            "failures": [],
        }
        with patch.object(
            refs, "_targeted_remote_ref_inventory", return_value=one_observed,
        ), patch.object(
            refs,
            "_materialize_targeted_commit",
            return_value={
                "failure": {
                    "stage": "fetch_commit",
                    "reason": "failed",
                    "reason_code": "fetch_failed",
                },
                "attempts": [{"stage": "fetch_commit"}],
            },
        ):
            result = refs._resolve_pinned_selected_ref(
                "/repo", "release", self.commit, ["origin"],
            )
        self.assertEqual(result["observed_commit"], self.other_commit)

    def test_remote_resolution_binding_discovery_and_delegation_matrix(self):
        with patch.object(
            refs, "_materialize_targeted_commit", return_value={
                "resolved_commit": self.commit,
                "resolution_mode": "",
                "attempts": None,
            },
        ):
            result = refs.resolve_remote_source_ref(
                "/repo",
                "origin/v1",
                expected_commit=self.commit,
                expected_remote="origin",
                expected_remote_ref="refs/tags/v1",
            )
        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["remote_ref"], "refs/tags/v1")
        self.assertEqual(result["resolution_mode"], "pinned_commit")

        for materialized, expected_status in (
            ({}, "remote_expected_commit_unmaterializable"),
            ({
                "status": "custom_unmaterializable",
                "failure": {
                    "stage": "custom_stage",
                    "reason": "custom reason",
                    "reason_code": "custom_code",
                },
                "attempts": [{"stage": "custom_stage"}],
            }, "custom_unmaterializable"),
        ):
            with patch.object(
                refs, "_materialize_targeted_commit", return_value=materialized,
            ):
                result = refs.resolve_remote_source_ref(
                    "/repo",
                    "origin/custom",
                    expected_commit=self.commit,
                    expected_remote="origin",
                    expected_remote_ref="refs/custom/value",
                )
            self.assertEqual(result["status"], expected_status)
            self.assertTrue(result["failures"][0]["reason"])
            self.assertTrue(result["failures"][0]["reason_code"])

        for remote_failure, expected_status in (
            ({"reason_code": "repository_not_git"}, "repository_not_git"),
            ({"reason_code": ""}, "remote_query_failed"),
        ):
            with patch.object(
                refs, "_remote_names", return_value=([], [remote_failure]),
            ):
                result = refs.resolve_remote_source_ref("/repo", None)
            self.assertEqual(result["status"], expected_status)
            self.assertIn("repository_path", result["failures"][0])

        with patch.object(refs, "_remote_names", return_value=([], [])):
            result = refs.resolve_remote_source_ref("/repo", "release")
        self.assertEqual(result["status"], "remote_configuration_missing")

        delegated = {"status": "delegated"}
        with patch.object(
            refs, "_remote_names", return_value=(["origin"], []),
        ), patch.object(
            refs, "_resolve_pinned_selected_ref", return_value=delegated,
        ) as pinned:
            result = refs.resolve_remote_source_ref(
                "/repo",
                "release",
                expected_commit=self.commit,
                expected_remote=None,
                expected_remote_ref=None,
            )
        self.assertIs(result, delegated)
        pinned.assert_called_once()

    def test_explicit_commit_resolution_orchestration_matrix(self):
        success_candidate = {
            "remote": "origin",
            "ref": self.commit,
            "canonical_ref": "",
            "short_name": self.commit,
            "kind": "commit",
            "commit": self.commit,
        }
        with patch.object(
            refs, "_remote_names", return_value=(["origin"], []),
        ), patch.object(
            refs, "_requested_remote_tiers", return_value=([["origin"]], "", ""),
        ), patch.object(
            refs,
            "_materialize_explicit_commit_from_remote",
            return_value={
                "resolved_commit": self.commit,
                "candidate": {},
                "attempts": None,
            },
        ):
            result = refs.resolve_remote_source_ref("/repo", self.commit)
        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["remote"], "")
        self.assertEqual(result["attempts"], [])

        raw_results = [
            {
                "failure": {
                    "reason": "not advertised",
                    "reason_code": "remote_ref_not_found",
                },
                "attempts": [{"stage": "fetch_explicit_commit"}],
                "candidate": success_candidate,
            },
            {
                "resolved_commit": self.commit,
                "candidate": {**success_candidate, "remote": "backup"},
                "attempts": [{"stage": "fetch_explicit_commit"}],
            },
        ]
        with patch.object(
            refs, "_remote_names", return_value=(["origin", "backup"], []),
        ), patch.object(
            refs,
            "_requested_remote_tiers",
            return_value=([["origin"], ["backup"]], "", ""),
        ), patch.object(
            refs,
            "_materialize_explicit_commit_from_remote",
            side_effect=raw_results,
        ), patch.object(
            refs,
            "_compat_advertised_commit_inventory",
            return_value={"refs": [], "failures": [], "queried_at": "compat-time"},
        ):
            result = refs.resolve_remote_source_ref("/repo", self.commit)
        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["remote"], "backup")
        self.assertEqual(result["selected_remote_tier"], 1)
        self.assertTrue(result["failures"])

        with patch.object(
            refs, "_remote_names", return_value=(["origin", "backup"], []),
        ), patch.object(
            refs,
            "_requested_remote_tiers",
            return_value=([["origin"], ["backup"]], "", ""),
        ), patch.object(
            refs,
            "_materialize_explicit_commit_from_remote",
            return_value={"failure": {
                "reason": "denied",
                "reason_code": "authentication_failed",
            }},
        ):
            result = refs.resolve_remote_source_ref("/repo", self.commit)
        self.assertEqual(result["status"], "remote_query_failed")
        self.assertTrue(result["selection_blocked_by_higher_priority_remote"])

        ambiguous_rows = [
            {**self.candidate, "commit": self.commit},
            {**self.candidate, "remote": "backup", "commit": self.other_commit},
        ]
        with patch.object(
            refs, "_remote_names", return_value=(["origin"], []),
        ), patch.object(
            refs, "_requested_remote_tiers", return_value=([["origin"]], "", ""),
        ), patch.object(
            refs,
            "_materialize_explicit_commit_from_remote",
            return_value={"failure": {
                "reason_code": "remote_ref_not_found",
                "reason": "raw fetch unavailable",
            }},
        ), patch.object(
            refs,
            "_compat_advertised_commit_inventory",
            return_value={"refs": ambiguous_rows, "failures": [], "queried_at": "q"},
        ):
            result = refs.resolve_remote_source_ref("/repo", self.commit)
        self.assertEqual(result["status"], "remote_source_ambiguous")

        short_commit = self.commit[:8]
        short_candidate = {**self.candidate, "commit": self.commit}
        short_inventories = [
            {"refs": [short_candidate], "failures": [], "queried_at": "first"},
            {"refs": [], "failures": [{
                "remote": "backup",
                "reason": "query failed",
                "reason_code": "fetch_failed",
            }], "queried_at": ""},
        ]
        with patch.object(
            refs, "_remote_names", return_value=(["origin", "backup"], []),
        ), patch.object(
            refs,
            "_requested_remote_tiers",
            return_value=([["origin", "backup"]], "", ""),
        ), patch.object(
            refs,
            "_compat_advertised_commit_inventory",
            side_effect=short_inventories,
        ):
            result = refs.resolve_remote_source_ref("/repo", short_commit)
        self.assertEqual(result["status"], "remote_query_failed")
        self.assertTrue(result["selection_blocked_by_peer_remote"])

        alias_rows = [
            self.candidate,
            {
                "commit": self.commit,
                "remote": "backup",
                "ref": "backup/release",
                "canonical_ref": "",
                "kind": "tag",
            },
        ]
        with patch.object(
            refs, "_remote_names", return_value=(["origin"], []),
        ), patch.object(
            refs, "_requested_remote_tiers", return_value=([["origin"]], "", ""),
        ), patch.object(
            refs,
            "_compat_advertised_commit_inventory",
            return_value={"refs": alias_rows, "failures": []},
        ), patch.object(
            refs,
            "_materialize_targeted_commit",
            side_effect=[
                {"failure": {}, "attempts": None},
                {"resolved_commit": self.commit, "attempts": None},
            ],
        ):
            result = refs.resolve_remote_source_ref("/repo", short_commit)
        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["remote"], "backup")
        self.assertTrue(result["failures"])

        with patch.object(
            refs, "_remote_names", return_value=(["origin"], []),
        ), patch.object(
            refs, "_requested_remote_tiers", return_value=([["origin"]], "", ""),
        ), patch.object(
            refs,
            "_compat_advertised_commit_inventory",
            return_value={"refs": alias_rows, "failures": []},
        ), patch.object(
            refs,
            "_materialize_targeted_commit",
            side_effect=[
                {"failure": {
                    "stage": "fetch_commit",
                    "reason": "first",
                    "reason_code": "remote_ref_not_found",
                }, "attempts": [{"stage": "fetch_commit"}]},
                {},
            ],
        ):
            result = refs.resolve_remote_source_ref("/repo", short_commit)
        self.assertEqual(result["status"], "remote_expected_commit_unmaterializable")

        with patch.object(
            refs, "_remote_names", return_value=(["origin"], []),
        ), patch.object(
            refs, "_requested_remote_tiers", return_value=([["origin"]], "", ""),
        ), patch.object(
            refs, "_materialize_explicit_commit_from_remote", return_value={},
        ), patch.object(
            refs,
            "_compat_advertised_commit_inventory",
            return_value={"refs": [], "failures": []},
        ):
            result = refs.resolve_remote_source_ref(
                "/repo",
                self.commit,
                expected_commit=self.commit,
                expected_remote="origin",
                expected_remote_ref="",
            )
        self.assertEqual(result["status"], "remote_expected_commit_unmaterializable")
        self.assertEqual(result["failures"][0]["reason_code"], "fetch_failed")

        with patch.object(
            refs, "_remote_names", return_value=(["origin"], []),
        ), patch.object(
            refs, "_requested_remote_tiers", return_value=([["origin"]], "", ""),
        ), patch.object(
            refs,
            "_materialize_explicit_commit_from_remote",
            return_value={"failure": {
                "reason": "raw unavailable",
                "reason_code": "remote_ref_not_found",
            }},
        ), patch.object(
            refs,
            "_compat_advertised_commit_inventory",
            return_value={"refs": [self.candidate], "failures": []},
        ), patch.object(
            refs,
            "_materialize_targeted_commit",
            return_value={
                "resolved_commit": self.commit,
                "attempts": [{"stage": "fetch_commit"}],
            },
        ):
            result = refs.resolve_remote_source_ref("/repo", self.commit)
        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["remote_ref"], "refs/heads/release")
        self.assertEqual(len(result["attempts"]), 1)

        sparse_alias_rows = [self.candidate, {"commit": self.commit}]
        with patch.object(
            refs, "_remote_names", return_value=(["origin"], []),
        ), patch.object(
            refs, "_requested_remote_tiers", return_value=([["origin"]], "", ""),
        ), patch.object(
            refs,
            "_compat_advertised_commit_inventory",
            return_value={"refs": sparse_alias_rows, "failures": []},
        ), patch.object(
            refs,
            "_materialize_targeted_commit",
            side_effect=[
                {"failure": {
                    "reason": "first",
                    "reason_code": "remote_ref_not_found",
                }},
                {"resolved_commit": self.commit},
            ],
        ):
            result = refs.resolve_remote_source_ref("/repo", short_commit)
        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_ref"], short_commit)
        self.assertEqual(result["remote"], "")

        with patch.object(
            refs, "_remote_names", return_value=(["origin"], []),
        ), patch.object(
            refs, "_requested_remote_tiers", return_value=([["origin"]], "", ""),
        ), patch.object(
            refs,
            "_compat_advertised_commit_inventory",
            return_value={"refs": sparse_alias_rows, "failures": []},
        ), patch.object(
            refs,
            "_materialize_targeted_commit",
            side_effect=[
                {"failure": {
                    "reason": "first",
                    "reason_code": "remote_ref_not_found",
                }},
                {"failure": {
                    "reason": "second",
                    "reason_code": "remote_ref_not_found",
                }},
            ],
        ):
            result = refs.resolve_remote_source_ref("/repo", short_commit)
        self.assertEqual(result["status"], "remote_expected_commit_unmaterializable")
        self.assertTrue(result["failures"])

        with patch.object(
            refs, "_remote_names", return_value=(["origin"], []),
        ), patch.object(
            refs, "_requested_remote_tiers", return_value=([["origin"]], "", ""),
        ), patch.object(
            refs,
            "_compat_advertised_commit_inventory",
            return_value={"refs": [], "failures": []},
        ):
            result = refs.resolve_remote_source_ref("/repo", short_commit)
        self.assertEqual(result["status"], "remote_expected_commit_unmaterializable")

    def test_named_remote_ref_resolution_orchestration_matrix(self):
        query_failure = {
            "remote": "origin",
            "reason": "query failed",
            "reason_code": "fetch_failed",
        }
        for tiers, inventory, higher, peer in (
            (
                [["origin"], ["backup"]],
                {"refs": [self.candidate], "failures": [query_failure]},
                True,
                True,
            ),
            (
                [["origin"]],
                {"refs": [], "failures": [query_failure]},
                False,
                False,
            ),
        ):
            with patch.object(
                refs, "_remote_names", return_value=(["origin", "backup"], []),
            ), patch.object(
                refs, "_requested_remote_tiers", return_value=(tiers, "release", ""),
            ), patch.object(
                refs, "_targeted_remote_ref_inventory", return_value=inventory,
            ):
                result = refs.resolve_remote_source_ref("/repo", "release")
            self.assertEqual(result["status"], "remote_query_failed")
            self.assertIs(result["selection_blocked_by_higher_priority_remote"], higher)
            self.assertIs(result["selection_blocked_by_peer_remote"], peer)

        with patch.object(
            refs, "_remote_names", return_value=(["origin"], []),
        ), patch.object(
            refs,
            "_requested_remote_tiers",
            return_value=([["origin"]], "release", ""),
        ), patch.object(
            refs,
            "_targeted_remote_ref_inventory",
            return_value={
                "refs": [
                    self.candidate,
                    {**self.candidate, "commit": self.other_commit},
                ],
                "failures": [],
                "queried_at": "q",
            },
        ):
            result = refs.resolve_remote_source_ref("/repo", "release")
        self.assertEqual(result["status"], "remote_source_ambiguous")

        absence_inventories = [
            {"refs": [], "failures": [], "attempts": [{"stage": "query"}]},
            {"refs": None, "failures": None, "attempts": None, "queried_at": "q"},
        ]
        with patch.object(
            refs, "_remote_names", return_value=(["origin", "backup"], []),
        ), patch.object(
            refs,
            "_requested_remote_tiers",
            return_value=([["origin"], ["backup"]], "release", ""),
        ), patch.object(
            refs, "_targeted_remote_ref_inventory", side_effect=absence_inventories,
        ):
            result = refs.resolve_remote_source_ref("/repo", "release")
        self.assertEqual(result["status"], "remote_ref_not_found")
        self.assertEqual(len(result["failures"]), 2)

        aliases = [
            self.candidate,
            {
                **self.candidate,
                "remote": "backup",
                "ref": "backup/release",
                "canonical_ref": "refs/tags/release",
                "kind": "tag",
            },
        ]
        with patch.object(
            refs, "_remote_names", return_value=(["origin"], []),
        ), patch.object(
            refs,
            "_requested_remote_tiers",
            return_value=([["origin"]], "release", ""),
        ), patch.object(
            refs,
            "_targeted_remote_ref_inventory",
            return_value={"refs": aliases, "failures": [], "queried_at": "q"},
        ), patch.object(
            refs,
            "_materialize_targeted_commit",
            side_effect=[
                {"failure": {}, "attempts": None},
                {"resolved_commit": self.commit, "resolution_mode": "", "attempts": None},
            ],
        ):
            result = refs.resolve_remote_source_ref("/repo", "release")
        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["remote"], "backup")
        self.assertEqual(result["resolution_mode"], "live_remote")
        self.assertTrue(result["failures"])

        with patch.object(
            refs, "_remote_names", return_value=(["origin"], []),
        ), patch.object(
            refs,
            "_requested_remote_tiers",
            return_value=([["origin"]], "release", ""),
        ), patch.object(
            refs,
            "_targeted_remote_ref_inventory",
            return_value={"refs": aliases, "failures": []},
        ), patch.object(
            refs,
            "_materialize_targeted_commit",
            side_effect=[
                {"failure": {
                    "stage": "fetch_commit",
                    "reason": "first",
                    "reason_code": "remote_ref_not_found",
                }, "attempts": [{"stage": "fetch_commit"}]},
                {},
            ],
        ):
            result = refs.resolve_remote_source_ref("/repo", "release")
        self.assertEqual(result["status"], "remote_fetch_failed")
        self.assertTrue(result["expected_commit"])

        sparse_aliases = [self.candidate, {"commit": self.commit}]
        with patch.object(
            refs, "_remote_names", return_value=(["origin"], []),
        ), patch.object(
            refs,
            "_requested_remote_tiers",
            return_value=([["origin"]], "release", ""),
        ), patch.object(
            refs,
            "_targeted_remote_ref_inventory",
            return_value={"refs": sparse_aliases, "failures": []},
        ), patch.object(
            refs,
            "_materialize_targeted_commit",
            side_effect=[
                {"failure": {
                    "stage": "fetch_commit",
                    "reason": "first",
                    "reason_code": "remote_ref_not_found",
                }},
                {"attempts": [{"stage": "fetch_commit"}]},
            ],
        ):
            result = refs.resolve_remote_source_ref("/repo", "release")
        self.assertEqual(result["status"], "remote_fetch_failed")
        self.assertEqual(len(result["attempts"]), 1)
        self.assertEqual(result["failures"][-1]["remote"], "")

    def test_local_ref_verification_and_confirmation_matrix(self):
        for reason in (*refs._LOCAL_REF_ABSENT_PATTERNS, "unrelated"):
            self.assertIs(
                refs._is_local_ref_absence(reason.upper()),
                reason != "unrelated",
            )
        self.assertFalse(refs._is_local_ref_absence(None))

        with patch.object(refs, "_git", return_value=(self.commit, "", 0)):
            self.assertEqual(
                refs._verify_local_commit_details("/repo", "refs/heads/release"),
                (self.commit, None),
            )
        with patch.object(
            refs,
            "_git",
            side_effect=[
                ("", "fatal: bad revision", 128),
                (self.commit, "", 0),
            ],
        ):
            self.assertEqual(
                refs._verify_local_commit_details("/repo", "origin/release"),
                (self.commit, None),
            )
        with patch.object(refs, "_git", return_value=("", "process failed", 2)):
            commit, failure = refs._verify_local_commit_details("/repo", "release")
        self.assertEqual(commit, "")
        self.assertEqual(failure["reason_code"], "local_ref_resolution_failed")
        with patch.object(refs, "_git", return_value=("", "fatal: bad revision", 128)):
            self.assertEqual(
                refs._verify_local_commit_details("/repo", "HEAD"), ("", None),
            )

        local_cases = (
            (None, [("", "fatal: bad revision", 128)] * 2, ("", None)),
            (self.commit, [(self.commit, "", 0)], (self.commit, None)),
            ("release", [("", "stdout failure", 2)], "failed"),
            ("release", [("", "", 2)], "failed"),
            ("release", [("", "", 0)], "failed"),
        )
        for requested, responses, expected in local_cases:
            with patch.object(refs, "_git", side_effect=responses):
                result = refs._verify_local_commit_details("/repo", requested)
            if expected == "failed":
                self.assertEqual(result[1]["reason_code"], "local_ref_resolution_failed")
            else:
                self.assertEqual(result, expected)

        with patch.object(
            refs, "_verify_local_commit_details", return_value=(self.commit, None),
        ), patch.object(refs, "_git", return_value=("", "status failed", 2)):
            result = refs.resolve_local_source_ref("/repo", "release")
        self.assertEqual(result["status"], "local_status_unavailable")
        self.assertEqual(result["local_candidate_commit"], self.commit)

        scenarios = (
            (("", {"reason_code": "local_ref_resolution_failed"}), ("dirty", "", 0), {}, "local_ref_resolution_failed"),
            ((self.commit, None), ("", "", 0), {}, "awaiting_local_source_confirmation"),
            (("", None), ("", "", 0), {"allow_local_source": True}, "remote_source_unavailable"),
            ((self.commit, None), ("dirty", "", 0), {"allow_local_source": True}, "awaiting_dirty_local_source_confirmation"),
            ((self.commit, None), ("", "", 0), {"allow_local_source": True}, "user_confirmed_local_source"),
            ((self.commit, None), ("dirty", "", 0), {"allow_local_source": True, "allow_dirty_local_source": True}, "user_confirmed_local_source"),
        )
        for verify, status, kwargs, expected_status in scenarios:
            with patch.object(
                refs, "_verify_local_commit_details", return_value=verify,
            ), patch.object(refs, "_git", return_value=status):
                result = refs.resolve_local_source_ref("/repo", "release", **kwargs)
            self.assertEqual(result["status"], expected_status)

        for status_response in (("stdout status error", "", 2), ("", "", 2)):
            with patch.object(
                refs, "_verify_local_commit_details", return_value=(self.commit, None),
            ), patch.object(refs, "_git", return_value=status_response):
                result = refs.resolve_local_source_ref("/repo", "release")
            self.assertEqual(result["status"], "local_status_unavailable")

        with patch.object(
            refs, "_verify_local_commit_details", return_value=(self.commit, None),
        ), patch.object(refs, "_git", return_value=("", "", 0)):
            result = refs.resolve_local_source_ref(
                "/repo", None, allow_local_source=True,
            )
        self.assertEqual(result["resolved_ref"], "")


if __name__ == "__main__":
    unittest.main()
