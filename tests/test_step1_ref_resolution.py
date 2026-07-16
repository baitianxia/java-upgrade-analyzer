import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from step1_ref_resolution import resolve_step1_ref  # noqa: E402


class Step1RefResolutionTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        self.git("init")
        self.git("config", "user.email", "step1@example.com")
        self.git("config", "user.name", "Step1 Test")
        (self.repo / "value.txt").write_text("base\n", encoding="utf-8")
        self.git("add", "value.txt")
        self.git("commit", "-m", "base")
        self.base_commit = self.git("rev-parse", "HEAD")
        self.git("branch", "base-release", self.base_commit)
        (self.repo / "value.txt").write_text("current\n", encoding="utf-8")
        self.git("commit", "-am", "current")
        self.current_commit = self.git("rev-parse", "HEAD")

    def tearDown(self):
        self._tmp.cleanup()

    def git(self, *args):
        completed = subprocess.run(
            ["git", *args],
            cwd=self.repo,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return completed.stdout.strip()

    def add_remote_ref(self, name, commit):
        self.git("update-ref", f"refs/remotes/{name}", commit)

    def add_local_ref(self, name, commit):
        self.git("update-ref", f"refs/heads/{name}", commit)

    def test_exact_ref_resolves_to_commit(self):
        result = resolve_step1_ref(self.repo, "base-release")

        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["resolution_mode"], "exact")
        self.assertEqual(result["resolved_ref"], "base-release")
        self.assertEqual(result["resolved_commit"], self.base_commit)

    def test_unique_remote_short_name_resolves_without_fetch(self):
        self.add_remote_ref("origin/release-2.0.0", self.current_commit)

        result = resolve_step1_ref(self.repo, "release-2.0.0")

        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["resolved_ref"], "origin/release-2.0.0")
        self.assertEqual(result["resolution_mode"], "unique_remote")
        self.assertEqual(result["resolved_commit"], self.current_commit)

    def test_same_short_name_on_two_different_remote_commits_is_ambiguous(self):
        self.add_remote_ref("origin/release-2.0.0", self.base_commit)
        self.add_remote_ref("upstream/release-2.0.0", self.current_commit)

        result = resolve_step1_ref(self.repo, "release-2.0.0")

        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual(
            {item["commit"] for item in result["candidates"]},
            {self.base_commit, self.current_commit},
        )

    def test_local_and_remote_refs_on_same_commit_are_not_ambiguous(self):
        self.add_local_ref("release-2.0.0", self.current_commit)
        self.add_remote_ref("origin/release-2.0.0", self.current_commit)

        result = resolve_step1_ref(self.repo, "release-2.0.0")

        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["resolved_ref"], "release-2.0.0")
        self.assertEqual(result["resolved_commit"], self.current_commit)

    def test_version_boundary_match_resolves_unique_remote_ref(self):
        self.add_remote_ref("origin/product-release-3.0.7-hotfix", self.current_commit)

        result = resolve_step1_ref(self.repo, "3.0.7")

        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["resolved_ref"], "origin/product-release-3.0.7-hotfix")

    def test_version_1_2_does_not_match_larger_numeric_versions(self):
        self.add_remote_ref("origin/release-11.2", self.base_commit)
        self.add_remote_ref("origin/release-1.20", self.current_commit)

        result = resolve_step1_ref(self.repo, "1.2")

        self.assertEqual(result["status"], "not_found")
        self.assertEqual(result["candidates"], [])

    def test_remote_head_is_never_a_candidate(self):
        self.add_remote_ref("origin/release-2.0.0", self.current_commit)
        self.git(
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/release-2.0.0",
        )

        result = resolve_step1_ref(self.repo, "release-2.0.0")

        self.assertEqual(
            [item["ref"] for item in result["candidates"]],
            ["origin/release-2.0.0"],
        )
        self.assertTrue(result["fingerprint"])


if __name__ == "__main__":
    unittest.main()
