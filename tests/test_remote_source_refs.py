import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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
            "release",
            expected_commit=selected["resolved_commit"],
            expected_remote=selected["remote"],
            expected_remote_ref=selected["remote_ref"],
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
        self.assertEqual(after_delete["status"], "remote_source_resolved")
        self.assertEqual(after_delete["resolved_commit"], self.current_commit)
        self.assertEqual(
            after_delete["resolution_mode"],
            "live_remote_expected_commit",
        )

    def test_explicit_remote_ref_only_matches_requested_remote(self):
        self.add_remote("origin", {"release": self.base_commit})
        self.add_remote("upstream", {"release": self.current_commit})

        result = resolve_remote_source_ref(self.repo, "upstream/release")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["remote"], "upstream")
        self.assertEqual(result["resolved_commit"], self.current_commit)

    def test_annotated_remote_tag_resolves_to_peeled_commit(self):
        self.add_remote("origin", {"main": self.current_commit})
        self.git(self.repo, "tag", "-a", "v2.0.0", self.current_commit, "-m", "release")
        self.git(self.repo, "push", "origin", "refs/tags/v2.0.0")

        result = resolve_remote_source_ref(self.repo, "v2.0.0")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(result["resolved_commit"], self.current_commit)
        self.assertEqual(result["remote_ref"], "refs/tags/v2.0.0")

    def test_same_commit_on_multiple_remotes_resolves_and_keeps_all_candidates(self):
        self.add_remote("origin", {"release": self.current_commit})
        self.add_remote("upstream", {"release": self.current_commit})

        result = resolve_remote_source_ref(self.repo, "release")

        self.assertEqual(result["status"], "remote_source_resolved")
        self.assertEqual(len(result["candidates"]), 2)
        self.assertEqual({row["commit"] for row in result["candidates"]}, {self.current_commit})

    def test_different_commits_on_multiple_remotes_are_ambiguous(self):
        self.add_remote("origin", {"release": self.base_commit})
        self.add_remote("upstream", {"release": self.current_commit})

        result = resolve_remote_source_ref(self.repo, "release")

        self.assertEqual(result["status"], "remote_source_ambiguous")
        self.assertEqual(result["resolved_commit"], "")
        self.assertEqual({row["commit"] for row in result["candidates"]}, {self.base_commit, self.current_commit})

    def test_missing_remote_ref_does_not_fall_back_to_local(self):
        self.git(self.repo, "branch", "release", self.current_commit)
        self.add_remote("origin", {"other": self.current_commit})

        result = resolve_remote_source_ref(self.repo, "release")

        self.assertEqual(result["status"], "remote_source_unavailable")
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
