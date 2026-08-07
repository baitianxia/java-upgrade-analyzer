import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from remote_source_refs import resolve_local_source_ref, resolve_remote_source_ref  # noqa: E402


class RemoteSourceRefsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git(self.repo, "init")
        self.git(self.repo, "config", "user.email", "remote-source@example.com")
        self.git(self.repo, "config", "user.name", "Remote Source Test")
        (self.repo / "value.txt").write_text("base\n", encoding="utf-8")
        self.git(self.repo, "add", "value.txt")
        self.git(self.repo, "commit", "-m", "base")
        self.base_commit = self.git(self.repo, "rev-parse", "HEAD")
        (self.repo / "value.txt").write_text("current\n", encoding="utf-8")
        self.git(self.repo, "commit", "-am", "current")
        self.current_commit = self.git(self.repo, "rev-parse", "HEAD")

    def tearDown(self):
        self._tmp.cleanup()

    @staticmethod
    def git(repo, *args):
        completed = subprocess.run(
            ["git", *args],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return completed.stdout.strip()

    def add_remote(self, name, branches):
        bare = self.root / f"{name}.git"
        self.git(self.root, "init", "--bare", str(bare))
        self.git(self.repo, "remote", "add", name, str(bare))
        for branch, commit in branches.items():
            self.git(self.repo, "push", name, f"{commit}:refs/heads/{branch}")
        return bare

    def test_unqualified_ref_uses_live_remote_even_when_local_branch_differs(self):
        self.git(self.repo, "branch", "release", self.base_commit)
        self.add_remote("origin", {"release": self.current_commit})

        result = resolve_remote_source_ref(self.repo, "release")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_ref"], "origin/release")
        self.assertEqual(result["resolved_commit"], self.current_commit)
        self.assertEqual(result["resolution_mode"], "live_remote")

    def test_remote_resolution_ignores_inherited_git_repository_routing(self):
        self.add_remote("origin", {"release": self.current_commit})
        foreign = self.root / "foreign"
        foreign.mkdir()
        self.git(foreign, "init")

        with patch.dict(
            os.environ,
            {
                "GIT_DIR": str(foreign / ".git"),
                "GIT_WORK_TREE": str(foreign),
            },
            clear=False,
        ):
            result = resolve_remote_source_ref(self.repo, "release")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["remote"], "origin")
        self.assertEqual(result["resolved_commit"], self.current_commit)

    def test_base_and_current_refs_resolve_sequentially_from_same_repo(self):
        self.add_remote(
            "origin",
            {
                "nbs-base": self.base_commit,
                "nbs-mid26.07.22.DEV": self.current_commit,
            },
        )

        base = resolve_remote_source_ref(self.repo, "nbs-base")
        current = resolve_remote_source_ref(
            self.repo,
            "nbs-mid26.07.22.DEV",
        )

        self.assertEqual(base["status"], "remote_source_resolved")
        self.assertEqual(base["resolved_commit"], self.base_commit)
        self.assertEqual(current["status"], "remote_source_resolved")
        self.assertEqual(current["resolved_commit"], self.current_commit)
        self.assertEqual(current["remote"], "origin")

    def test_bound_snapshot_survives_remote_ref_movement_and_deletion(self):
        self.add_remote("origin", {"release": self.current_commit})
        selected = resolve_remote_source_ref(self.repo, "release")

        self.git(
            self.repo,
            "push",
            "--force",
            "origin",
            f"{self.base_commit}:refs/heads/release",
        )
        after_move = resolve_remote_source_ref(
            self.repo,
            selected["resolved_ref"],
            expected_commit=selected["resolved_commit"],
        )
        self.git(self.repo, "push", "origin", ":refs/heads/release")
        after_delete = resolve_remote_source_ref(
            self.repo,
            "release",
            expected_commit=selected["resolved_commit"],
            expected_remote=selected["remote"],
            expected_remote_ref=selected["remote_ref"],
        )

        self.assertEqual(after_move["status"], "remote_source_resolved")
        self.assertEqual(after_move["resolved_commit"], self.current_commit)
        self.assertEqual(after_move["observed_commit"], self.base_commit)
        self.assertEqual(after_move["resolution_mode"], "pinned_commit")
        self.assertEqual(after_delete["status"], "remote_source_resolved")
        self.assertEqual(after_delete["resolved_commit"], self.current_commit)
        self.assertEqual(
            after_delete["resolution_mode"],
            "pinned_commit",
        )

    def test_explicit_remote_ref_only_matches_requested_remote(self):
        self.add_remote("origin", {"release": self.base_commit})
        self.add_remote("upstream", {"release": self.current_commit})

        result = resolve_remote_source_ref(self.repo, "upstream/release")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["remote"], "upstream")
        self.assertEqual(result["resolved_commit"], self.current_commit)

    def test_multiple_remotes_without_origin_compare_remote_commits(self):
        self.add_remote("first", {"release": self.base_commit})
        self.add_remote("second", {"release": self.current_commit})

        result = resolve_remote_source_ref(self.repo, "release")

        self.assertEqual(result["status"], "remote_source_ambiguous")
        self.assertEqual(result["query_mode"], "targeted_exact")
        self.assertEqual(
            {candidate["commit"] for candidate in result["candidates"]},
            {self.base_commit, self.current_commit},
        )

    def test_peer_remotes_with_same_commit_are_merged_as_aliases(self):
        self.add_remote("first", {"release": self.current_commit})
        self.add_remote("second", {"release": self.current_commit})

        result = resolve_remote_source_ref(self.repo, "release")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], self.current_commit)
        self.assertEqual(
            {alias["remote"] for alias in result["candidates"][0]["aliases"]},
            {"first", "second"},
        )

    def test_repository_without_remote_has_precise_configuration_failure(self):
        result = resolve_remote_source_ref(self.repo, "release")

        self.assertEqual(result["status"], "remote_configuration_missing")
        self.assertEqual(result["configured_remotes"], [])
        self.assertEqual(
            result["failures"][0]["reason_code"],
            "remote_configuration_missing",
        )
        self.assertEqual(result["repository_path"], str(self.repo.resolve()))

    def test_non_git_directory_is_not_reported_as_missing_remote(self):
        plain_dir = self.root / "plain-source"
        plain_dir.mkdir()

        result = resolve_remote_source_ref(plain_dir, "release")

        self.assertEqual(result["status"], "repository_not_git")
        self.assertEqual(
            result["failures"][0]["reason_code"],
            "repository_not_git",
        )

    def test_explicit_local_commit_without_remote_is_not_remote_source(self):
        result = resolve_remote_source_ref(self.repo, self.current_commit)

        self.assertEqual(result["status"], "remote_configuration_missing")
        self.assertEqual(result["resolved_commit"], "")

    def test_explicit_commit_requires_and_records_remote_proof(self):
        self.add_remote("origin", {"release": self.current_commit})

        result = resolve_remote_source_ref(self.repo, self.current_commit)

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], self.current_commit)
        self.assertEqual(result["remote"], "origin")
        self.assertEqual(result["resolution_mode"], "explicit_remote_commit")
        self.assertEqual(result["query_mode"], "explicit_commit_remote")

    def test_annotated_remote_tag_resolves_to_peeled_commit(self):
        self.add_remote("origin", {"main": self.current_commit})
        self.git(self.repo, "tag", "-a", "v2.0.0", self.current_commit, "-m", "release")
        self.git(self.repo, "push", "origin", "refs/tags/v2.0.0")

        result = resolve_remote_source_ref(self.repo, "v2.0.0")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], self.current_commit)
        self.assertEqual(result["remote_ref"], "refs/tags/v2.0.0")

    def test_unqualified_ref_stops_after_successful_origin_tier(self):
        self.add_remote("origin", {"release": self.current_commit})
        self.add_remote("upstream", {"release": self.current_commit})

        result = resolve_remote_source_ref(self.repo, "release")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["remote"], "origin")
        self.assertEqual(len(result["candidates"]), 1)
        self.assertNotIn("aliases", result["candidates"][0])
        self.assertEqual(result["query_mode"], "targeted_exact")

    def test_origin_tier_wins_over_different_lower_tier_commit(self):
        self.add_remote("origin", {"release": self.base_commit})
        self.add_remote("upstream", {"release": self.current_commit})

        result = resolve_remote_source_ref(self.repo, "release")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["remote"], "origin")
        self.assertEqual(result["resolved_commit"], self.base_commit)

    def test_global_remote_config_does_not_count_as_repository_remote(self):
        global_config = self.root / "global.gitconfig"
        global_config.write_text(
            "[remote \"injected\"]\n\turl = /does/not/matter.git\n",
            encoding="utf-8",
        )

        with patch.dict(
            os.environ,
            {"GIT_CONFIG_GLOBAL": str(global_config)},
            clear=False,
        ):
            result = resolve_remote_source_ref(self.repo, "release")

        self.assertEqual(result["status"], "remote_configuration_missing")
        self.assertEqual(result["configured_remotes"], [])

    def test_repository_remote_from_included_local_config_is_discovered(self):
        bare = self.root / "included-origin.git"
        self.git(self.root, "init", "--bare", str(bare))
        self.git(
            self.repo,
            "push",
            str(bare),
            f"{self.current_commit}:refs/heads/release",
        )
        included_config = self.root / "repository-remotes.gitconfig"
        included_config.write_text(
            f'[remote "origin"]\n\turl = {bare}\n',
            encoding="utf-8",
        )
        self.git(
            self.repo,
            "config",
            "--local",
            "include.path",
            str(included_config),
        )

        result = resolve_remote_source_ref(self.repo, "release")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["remote"], "origin")
        self.assertEqual(result["resolved_commit"], self.current_commit)

    def test_sha256_length_commit_uses_remote_proof_path(self):
        sha256_commit = "b" * 64
        materialized = {
            "status": "remote_source_resolved",
            "resolved_commit": sha256_commit,
            "expected_commit": sha256_commit,
            "attempts": [],
            "resolution_mode": "explicit_remote_commit",
            "candidate": {
                "remote": "origin",
                "ref": sha256_commit,
                "canonical_ref": "",
                "kind": "commit",
                "commit": sha256_commit,
            },
        }
        with patch("remote_source_refs._remote_names", return_value=(["origin"], [])), patch(
            "remote_source_refs._materialize_explicit_commit_from_remote",
            return_value=materialized,
        ) as proof:
            result = resolve_remote_source_ref(self.repo, sha256_commit)

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], sha256_commit)
        proof.assert_called_once()

    def test_missing_remote_ref_does_not_fall_back_to_local(self):
        self.git(self.repo, "branch", "release", self.current_commit)
        self.add_remote("origin", {"other": self.current_commit})

        with patch("remote_source_refs.time.sleep"):
            result = resolve_remote_source_ref(self.repo, "release")

        self.assertEqual(result["status"], "remote_ref_not_found")
        self.assertEqual(result["resolved_commit"], "")

    def test_local_ref_requires_explicit_confirmation(self):
        self.git(self.repo, "branch", "release", self.current_commit)

        denied = resolve_local_source_ref(self.repo, "release")
        allowed = resolve_local_source_ref(self.repo, "release", allow_local_source=True)

        self.assertEqual(denied["status"], "awaiting_local_source_confirmation")
        self.assertEqual(allowed["status"], "user_confirmed_local_source")
        self.assertEqual(allowed["resolved_commit"], self.current_commit)

    def test_remote_tracking_ref_shorthand_requires_explicit_confirmation(self):
        self.git(self.repo, "update-ref", "refs/remotes/origin/release", self.current_commit)

        denied = resolve_local_source_ref(self.repo, "origin/release")
        allowed = resolve_local_source_ref(self.repo, "origin/release", allow_local_source=True)

        self.assertEqual(denied["status"], "awaiting_local_source_confirmation")
        self.assertEqual(denied["local_candidate_commit"], self.current_commit)
        self.assertEqual(allowed["status"], "user_confirmed_local_source")
        self.assertEqual(allowed["resolved_ref"], "origin/release")
        self.assertEqual(allowed["resolved_commit"], self.current_commit)
        self.assertEqual(allowed["resolution_mode"], "user_confirmed_local_source")

    def test_fully_qualified_remote_tracking_ref_remains_supported(self):
        canonical_ref = "refs/remotes/origin/release"
        self.git(self.repo, "update-ref", canonical_ref, self.current_commit)

        result = resolve_local_source_ref(self.repo, canonical_ref, allow_local_source=True)

        self.assertEqual(result["status"], "user_confirmed_local_source")
        self.assertEqual(result["resolved_ref"], canonical_ref)
        self.assertEqual(result["resolved_commit"], self.current_commit)

    def test_dirty_local_repository_requires_separate_confirmation(self):
        self.git(self.repo, "branch", "release", self.current_commit)
        (self.repo / "dirty.txt").write_text("dirty\n", encoding="utf-8")

        denied = resolve_local_source_ref(self.repo, "release", allow_local_source=True)
        allowed = resolve_local_source_ref(
            self.repo,
            "release",
            allow_local_source=True,
            allow_dirty_local_source=True,
        )

        self.assertEqual(denied["status"], "awaiting_dirty_local_source_confirmation")
        self.assertTrue(denied["dirty"])
        self.assertEqual(allowed["status"], "user_confirmed_local_source")
        self.assertTrue(allowed["dirty"])


if __name__ == "__main__":
    unittest.main()
