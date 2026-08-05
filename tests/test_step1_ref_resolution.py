import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from step1_ref_resolution import resolve_step1_ref  # noqa: E402


class Step1RefResolutionTest(unittest.TestCase):
    def test_expected_commit_is_forwarded_to_remote_resolver(self):
        remote = {
            "status": "remote_source_resolved",
            "resolved_ref": "origin/release",
            "resolved_commit": "a" * 40,
        }
        with patch("step1_ref_resolution.resolve_remote_source_ref", return_value=remote) as resolver:
            result = resolve_step1_ref("/repo", "release", expected_commit="a" * 40)

        self.assertEqual(result["status"], "resolved")
        resolver.assert_called_once_with("/repo", "release", expected_commit="a" * 40)

    def test_remote_query_failure_does_not_fall_back_to_local(self):
        remote = {
            "status": "remote_query_failed",
            "requested_ref": "release",
            "failures": [{"stage": "ls_remote", "reason": "timed out"}],
        }
        with patch("step1_ref_resolution.resolve_remote_source_ref", return_value=remote), patch(
            "step1_ref_resolution.resolve_local_source_ref"
        ) as local_resolver:
            result = resolve_step1_ref("/repo", "release")

        self.assertEqual(result["status"], "fetch_failed")
        self.assertEqual(result["source_status"], "remote_query_failed")
        local_resolver.assert_not_called()

    def test_remote_query_failure_uses_explicitly_authorized_local_fallback(self):
        remote = {
            "status": "remote_query_failed",
            "requested_ref": "release",
            "failures": [{
                "stage": "ls_remote_before_fetch",
                "reason": "kex_exchange_identification: Connection closed",
            }],
        }
        local = {
            "status": "user_confirmed_local_source",
            "requested_ref": "release",
            "resolved_ref": "release",
            "resolved_commit": "c" * 40,
            "resolution_mode": "user_confirmed_local_source",
            "dirty": False,
        }
        with patch(
            "step1_ref_resolution.resolve_remote_source_ref",
            return_value=remote,
        ), patch(
            "step1_ref_resolution.resolve_local_source_ref",
            return_value=local,
        ) as local_resolver:
            result = resolve_step1_ref(
                "/repo",
                "release",
                allow_local_source=True,
            )

        self.assertEqual(result["status"], "resolved")
        self.assertEqual(
            result["source_status"],
            "user_confirmed_local_source",
        )
        self.assertEqual(result["resolved_commit"], "c" * 40)
        self.assertTrue(local_resolver.call_args.kwargs["allow_local_source"])

    def test_legacy_remote_ref_movement_is_a_system_error_not_a_checkpoint(self):
        remote = {
            "status": "remote_ref_moved",
            "requested_ref": "release",
            "expected_commit": "a" * 40,
            "observed_commit": "b" * 40,
        }
        with patch(
            "step1_ref_resolution.resolve_remote_source_ref",
            return_value=remote,
        ), patch(
            "step1_ref_resolution.resolve_local_source_ref",
        ) as local_resolver:
            result = resolve_step1_ref(
                "/repo",
                "release",
                allow_local_source=True,
            )

        self.assertEqual(result["status"], "fetch_failed")
        self.assertEqual(
            result["source_status"],
            "remote_expected_commit_unmaterializable",
        )
        self.assertEqual(result["legacy_source_status"], "remote_ref_moved")
        local_resolver.assert_not_called()

    def test_remote_resolution_is_exposed_as_resolved(self):
        remote = {
            "status": "remote_source_resolved",
            "requested_ref": "release",
            "resolved_ref": "origin/release",
            "resolved_commit": "a" * 40,
            "resolution_mode": "live_remote",
            "candidates": [{"ref": "origin/release", "commit": "a" * 40}],
            "fingerprint": "remote-fingerprint",
        }
        with patch("step1_ref_resolution.resolve_remote_source_ref", return_value=remote), patch(
            "step1_ref_resolution.resolve_local_source_ref"
        ) as local_resolver:
            result = resolve_step1_ref("/repo", "release")

        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["source_status"], "remote_source_resolved")
        self.assertEqual(result["resolved_ref"], "origin/release")
        local_resolver.assert_not_called()

    def test_remote_ambiguity_never_falls_back_to_local(self):
        remote = {
            "status": "remote_source_ambiguous",
            "requested_ref": "release",
            "resolved_ref": "",
            "resolved_commit": "",
            "candidates": [
                {"ref": "origin/release", "commit": "a" * 40},
                {"ref": "upstream/release", "commit": "b" * 40},
            ],
        }
        with patch("step1_ref_resolution.resolve_remote_source_ref", return_value=remote), patch(
            "step1_ref_resolution.resolve_local_source_ref"
        ) as local_resolver:
            result = resolve_step1_ref("/repo", "release", allow_local_source=True)

        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual(result["source_status"], "remote_source_ambiguous")
        local_resolver.assert_not_called()

    def test_remote_unavailable_does_not_create_local_fallback_checkpoint(self):
        remote = {
            "status": "remote_source_unavailable",
            "requested_ref": "release",
            "failures": [{"stage": "ls_remote", "reason": "offline"}],
        }
        with patch("step1_ref_resolution.resolve_remote_source_ref", return_value=remote), patch(
            "step1_ref_resolution.resolve_local_source_ref"
        ) as local_resolver:
            result = resolve_step1_ref("/repo", "release")

        self.assertEqual(result["status"], "not_found")
        self.assertEqual(result["source_status"], "remote_source_unavailable")
        self.assertEqual(result["local_candidate_commit"], "")
        local_resolver.assert_not_called()

    def test_missing_remote_configuration_remains_distinct(self):
        remote = {
            "status": "remote_configuration_missing",
            "requested_ref": "release",
            "repository_path": "/repo",
            "configured_remotes": [],
        }
        with patch(
            "step1_ref_resolution.resolve_remote_source_ref",
            return_value=remote,
        ), patch(
            "step1_ref_resolution.resolve_local_source_ref",
        ) as local_resolver:
            result = resolve_step1_ref("/repo", "release")

        self.assertEqual(result["status"], "not_found")
        self.assertEqual(
            result["source_status"],
            "remote_configuration_missing",
        )
        local_resolver.assert_not_called()

    def test_confirmed_local_fallback_is_explicit_in_provenance(self):
        remote = {
            "status": "remote_source_unavailable",
            "requested_ref": "release",
            "failures": [{"stage": "resolve", "reason": "missing"}],
        }
        local = {
            "status": "user_confirmed_local_source",
            "requested_ref": "release",
            "resolved_ref": "release",
            "resolved_commit": "d" * 40,
            "resolution_mode": "user_confirmed_local_source",
            "dirty": False,
        }
        with patch("step1_ref_resolution.resolve_remote_source_ref", return_value=remote), patch(
            "step1_ref_resolution.resolve_local_source_ref", return_value=local
        ) as local_resolver:
            result = resolve_step1_ref("/repo", "release", allow_local_source=True)

        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["source_status"], "user_confirmed_local_source")
        self.assertEqual(result["remote_failures"][0]["reason"], "missing")
        self.assertTrue(local_resolver.call_args.kwargs["allow_local_source"])

    def test_dirty_local_fallback_requires_second_confirmation(self):
        remote = {"status": "remote_source_unavailable", "requested_ref": "release"}
        local = {
            "status": "awaiting_dirty_local_source_confirmation",
            "local_candidate_commit": "e" * 40,
            "dirty": True,
        }
        with patch("step1_ref_resolution.resolve_remote_source_ref", return_value=remote), patch(
            "step1_ref_resolution.resolve_local_source_ref", return_value=local
        ):
            result = resolve_step1_ref("/repo", "release", allow_local_source=True)

        self.assertEqual(result["status"], "dirty_confirmation_required")
        self.assertTrue(result["dirty"])


if __name__ == "__main__":
    unittest.main()
