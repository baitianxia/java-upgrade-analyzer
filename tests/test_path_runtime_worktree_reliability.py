import os
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import path_runtime  # noqa: E402


class PathRuntimeWorktreeReliabilityTest(unittest.TestCase):
    def test_add_retries_git_lock_contention_on_the_same_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree_root = root / "worktrees"
            add_targets = []

            def runner(command, cwd=None, timeout=None):
                if "rev-parse" in command:
                    return "a" * 40, "", 0
                if "ls-tree" in command:
                    return "tracked.txt\0", "", 0
                if "add" in command:
                    add_targets.append(command[-2])
                    if len(add_targets) < 3:
                        return (
                            "",
                            "fatal: Unable to create '/repo/.git/worktrees/x/index.lock': File exists.",
                            128,
                        )
                    return "", "", 0
                raise AssertionError(f"unexpected command: {command}")

            with patch.object(
                path_runtime,
                "short_temp_root_candidates",
                return_value=[worktree_root],
            ), patch.object(path_runtime.time, "sleep") as sleep:
                worktree = path_runtime.create_detached_worktree(
                    "abc123",
                    root,
                    runner=runner,
                    git_command=["git"],
                )

            self.assertEqual(3, len(add_targets))
            self.assertEqual(1, len(set(add_targets)))
            self.assertEqual(worktree_root, worktree.parent)
            self.assertEqual(2, sleep.call_count)

    def test_create_rejects_worktree_head_that_differs_from_pinned_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree_root = root / "worktrees"
            expected = "a" * 40
            cleanup_calls = []
            revision_calls = []

            def runner(command, cwd=None, timeout=None):
                if "rev-parse" in command:
                    revision_calls.append(str(cwd))
                    return (expected if len(revision_calls) == 1 else "b" * 40), "", 0
                if "ls-tree" in command:
                    return "tracked.txt\0", "", 0
                if "add" in command:
                    return "", "", 0
                if "remove" in command:
                    cleanup_calls.append(list(command))
                    return "", "", 0
                raise AssertionError(f"unexpected command: {command}")

            with patch.object(
                path_runtime,
                "short_temp_root_candidates",
                return_value=[worktree_root],
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "snapshot 完整性校验失败",
                ):
                    path_runtime.create_detached_worktree(
                        expected,
                        root,
                        runner=runner,
                        git_command=["git"],
                    )

            self.assertEqual(len(cleanup_calls), 1)

    def test_non_path_add_failure_does_not_retry_other_temp_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            expected = "a" * 40
            add_calls = []

            def runner(command, cwd=None, timeout=None):
                if "rev-parse" in command:
                    return expected, "", 0
                if "ls-tree" in command:
                    return "tracked.txt\0", "", 0
                if "add" in command:
                    add_calls.append(list(command))
                    return "", "fatal: invalid object database", 128
                if "remove" in command:
                    return "", "", 0
                raise AssertionError(f"unexpected command: {command}")

            with patch.object(
                path_runtime,
                "short_temp_root_candidates",
                return_value=[root / "first", root / "second"],
            ):
                with self.assertRaises(RuntimeError):
                    path_runtime.create_detached_worktree(
                        expected,
                        root,
                        runner=runner,
                        git_command=["git"],
                    )

            self.assertEqual(len(add_calls), 1)

    def test_lock_retries_share_one_deadline_and_do_not_start_after_expiry(self):
        now = [100.0]
        timeouts = []

        def monotonic():
            return now[0]

        def sleep(delay):
            now[0] += delay

        def runner(_command, cwd=None, timeout=None):
            timeouts.append(timeout)
            now[0] += min(0.7, float(timeout))
            return "", "fatal: could not lock config file", 128

        with patch.object(path_runtime.time, "monotonic", side_effect=monotonic), patch.object(
            path_runtime.time,
            "sleep",
            side_effect=sleep,
        ):
            _stdout, _stderr, rc, history = path_runtime._run_worktree_mutation(
                ["git", "worktree", "add"],
                repo_dir="/repo",
                runner=runner,
                timeout=2,
                deadline=102.0,
            )

        self.assertNotEqual(rc, 0)
        self.assertTrue(timeouts)
        self.assertTrue(all(value <= 2 for value in timeouts))
        self.assertLessEqual(now[0], 102.0)
        self.assertLessEqual(len(timeouts), 3)
        self.assertGreaterEqual(len(history), len(timeouts))

    def test_remove_retries_lock_contention_before_deleting_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = root / "worktree"
            worktree.mkdir()
            calls = []

            def runner(command, cwd=None, timeout=None):
                calls.append(list(command))
                if len(calls) < 3:
                    return "", "error: could not lock config file .git/config: File exists", 255
                return "", "", 0

            with patch.object(path_runtime.time, "sleep") as sleep:
                path_runtime.remove_detached_worktree(
                    worktree,
                    root,
                    runner=runner,
                    git_command=["git"],
                )

            self.assertEqual(3, len(calls))
            self.assertEqual(2, sleep.call_count)
            self.assertFalse(worktree.exists())

    def test_remove_recovers_only_when_exact_target_is_not_registered(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = root / "orphan"
            worktree.mkdir()
            repository = root / "repository"

            def runner(command, cwd=None, timeout=None):
                if "remove" in command:
                    return "", "fatal: is not a working tree", 128
                if "list" in command:
                    return f"worktree {repository}\0HEAD deadbeef\0\0", "", 0
                raise AssertionError(f"unexpected command: {command}")

            path_runtime.remove_detached_worktree(
                worktree,
                root,
                runner=runner,
                git_command=["git"],
            )

            self.assertFalse(worktree.exists())

    def test_remove_preserves_target_when_registration_is_still_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = root / "registered"
            worktree.mkdir()

            def runner(command, cwd=None, timeout=None):
                if "remove" in command:
                    return "", "fatal: permission denied", 128
                if "list" in command:
                    return f"worktree {worktree}\0HEAD deadbeef\0\0", "", 0
                raise AssertionError(f"unexpected command: {command}")

            with self.assertRaisesRegex(
                RuntimeError,
                r"attempts=1.*last_rc=128.*registered=True",
            ):
                path_runtime.remove_detached_worktree(
                    worktree,
                    root,
                    runner=runner,
                    git_command=["git"],
                )

            self.assertTrue(worktree.is_dir())

    def test_linked_worktree_uses_the_primary_repository_process_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = root / "repository"
            linked = root / "linked"
            admin = repository / ".git" / "worktrees" / "linked"
            admin.mkdir(parents=True)
            linked.mkdir()
            (linked / ".git").write_text(
                f"gitdir: {admin}\n",
                encoding="utf-8",
            )
            (admin / "commondir").write_text("../..\n", encoding="utf-8")

            primary_lock = path_runtime._worktree_repository_lock(repository)
            linked_lock = path_runtime._worktree_repository_lock(linked)

            self.assertIs(primary_lock, linked_lock)

    def test_create_recovers_only_a_dead_process_owned_worktree_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree_root = root / "worktrees"
            worktree_root.mkdir()
            orphan = worktree_root / "orphan"
            orphan.mkdir()
            lease = path_runtime._write_worktree_lease(root, orphan)
            payload = json.loads(lease.read_text(encoding="utf-8"))
            payload["pid"] = 999_999_999
            lease.write_text(json.dumps(payload), encoding="utf-8")
            expected = "a" * 40
            removed = []
            events = []

            def runner(command, cwd=None, timeout=None):
                if "rev-parse" in command:
                    events.append("rev-parse")
                    return expected, "", 0
                if "ls-tree" in command:
                    return "tracked.txt\0", "", 0
                if "remove" in command:
                    events.append("remove")
                    removed.append(Path(command[-1]).resolve())
                    return "", "", 0
                if "add" in command:
                    return "", "", 0
                raise AssertionError(f"unexpected command: {command}")

            with patch.object(
                path_runtime,
                "short_temp_root_candidates",
                return_value=[worktree_root],
            ):
                created = path_runtime.create_detached_worktree(
                    expected,
                    root,
                    runner=runner,
                    git_command=["git"],
                )

            self.assertEqual(removed, [orphan.resolve()])
            self.assertFalse(orphan.exists())
            self.assertFalse(lease.exists())
            self.assertTrue(created.is_dir())
            self.assertTrue(path_runtime._worktree_lease_path(created).is_file())
            self.assertLess(events.index("remove"), events.index("rev-parse"))

    def test_create_never_recovers_a_live_process_worktree_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree_root = root / "worktrees"
            worktree_root.mkdir()
            active = worktree_root / "active"
            active.mkdir()
            active_lease = path_runtime._write_worktree_lease(root, active)
            expected = "b" * 40
            removed = []

            def runner(command, cwd=None, timeout=None):
                if "rev-parse" in command:
                    return expected, "", 0
                if "ls-tree" in command:
                    return "tracked.txt\0", "", 0
                if "remove" in command:
                    removed.append(Path(command[-1]).resolve())
                    return "", "", 0
                if "add" in command:
                    return "", "", 0
                raise AssertionError(f"unexpected command: {command}")

            with patch.object(
                path_runtime,
                "short_temp_root_candidates",
                return_value=[worktree_root],
            ):
                created = path_runtime.create_detached_worktree(
                    expected,
                    root,
                    runner=runner,
                    git_command=["git"],
                )

            self.assertEqual(removed, [])
            self.assertTrue(active.is_dir())
            self.assertTrue(active_lease.is_file())
            self.assertTrue(created.is_dir())

    def test_startup_recovery_finds_owned_lease_from_registered_old_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = root / "repository"
            repository.mkdir()
            old_root = root / "old-root"
            old_root.mkdir()
            stale = old_root / "stale"
            stale.mkdir()
            lease = path_runtime._write_worktree_lease(repository, stale)
            payload = json.loads(lease.read_text(encoding="utf-8"))
            payload["pid"] = 999_999_999
            lease.write_text(json.dumps(payload), encoding="utf-8")
            new_root = root / "new-root"
            new_root.mkdir()
            removed = []

            def runner(command, cwd=None, timeout=None):
                if "list" in command:
                    return (
                        f"worktree {repository}\0HEAD {'a' * 40}\0\0"
                        f"worktree {stale}\0HEAD {'b' * 40}\0\0",
                        "",
                        0,
                    )
                if "remove" in command:
                    removed.append(Path(command[-1]).resolve())
                    return "", "", 0
                raise AssertionError(f"unexpected command: {command}")

            result = path_runtime.recover_owned_stale_worktrees(
                repository,
                roots=[new_root],
                runner=runner,
                git_command=["git"],
            )

            self.assertEqual(removed, [stale.resolve()])
            self.assertEqual(result["removed"], [str(stale.resolve())])
            self.assertFalse(stale.exists())
            self.assertFalse(lease.exists())

    def test_recovery_does_not_treat_a_reused_pid_as_the_lease_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = root / "repository"
            repository.mkdir()
            stale = root / "stale"
            stale.mkdir()
            lease = path_runtime._write_worktree_lease(repository, stale)
            payload = json.loads(lease.read_text(encoding="utf-8"))
            payload.update({"pid": 42, "process_start_token": "old-process"})
            lease.write_text(json.dumps(payload), encoding="utf-8")

            def runner(command, cwd=None, timeout=None):
                if "remove" in command:
                    return "", "", 0
                raise AssertionError(f"unexpected command: {command}")

            with patch.object(
                path_runtime, "_process_is_alive", return_value=True
            ), patch.object(
                path_runtime, "_process_start_token", return_value="new-process"
            ):
                result = path_runtime._recover_stale_worktree_leases(
                    ["git"],
                    repository,
                    [root],
                    runner,
                    deadline=path_runtime.time.monotonic() + 30,
                )

            self.assertEqual(result["removed"], [str(stale.resolve())])
            self.assertFalse(stale.exists())

    def test_cleanup_failure_blocks_create_before_revision_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = root / "repository"
            repository.mkdir()
            worktree_root = root / "worktrees"
            worktree_root.mkdir()
            stale = worktree_root / "stale"
            stale.mkdir()
            lease = path_runtime._write_worktree_lease(repository, stale)
            payload = json.loads(lease.read_text(encoding="utf-8"))
            payload["pid"] = 999_999_999
            lease.write_text(json.dumps(payload), encoding="utf-8")
            events = []

            def runner(command, cwd=None, timeout=None):
                if "remove" in command:
                    events.append("remove")
                    return "", "fatal: permission denied", 128
                if "list" in command:
                    events.append("list")
                    return f"worktree {stale}\0HEAD {'a' * 40}\0\0", "", 0
                if "rev-parse" in command:
                    events.append("rev-parse")
                    return "a" * 40, "", 0
                raise AssertionError(f"unexpected command: {command}")

            with patch.object(
                path_runtime,
                "short_temp_root_candidates",
                return_value=[worktree_root],
            ):
                with self.assertRaises(path_runtime.WorktreeRecoveryError):
                    path_runtime.create_detached_worktree(
                        "a" * 40,
                        repository,
                        runner=runner,
                        git_command=["git"],
                    )

            self.assertEqual(events, ["remove", "list"])
            self.assertTrue(stale.is_dir())
            self.assertTrue(lease.is_file())

    def test_startup_recovery_rejects_success_with_empty_worktree_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            repository = Path(tmp) / "repository"
            repository.mkdir()

            with self.assertRaisesRegex(
                path_runtime.WorktreeRecoveryError,
                "git_worktree_list_failed:rc=0:stderr=<empty>",
            ):
                path_runtime.recover_owned_stale_worktrees(
                    repository,
                    roots=[],
                    runner=lambda *args, **kwargs: ("", "", 0),
                    git_command=["git"],
                )

    def test_startup_recovery_never_removes_unleased_user_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = root / "repository"
            repository.mkdir()
            user_worktree = root / "user-worktree"
            user_worktree.mkdir()

            def runner(command, cwd=None, timeout=None):
                if "list" in command:
                    return (
                        f"worktree {repository}\0HEAD {'a' * 40}\0\0"
                        f"worktree {user_worktree}\0HEAD {'b' * 40}\0\0",
                        "",
                        0,
                    )
                if "remove" in command:
                    raise AssertionError("unleased worktree must not be removed")
                raise AssertionError(f"unexpected command: {command}")

            result = path_runtime.recover_owned_stale_worktrees(
                repository,
                roots=[],
                runner=runner,
                git_command=["git"],
            )

            self.assertEqual(result["removed"], [])
            self.assertTrue(user_worktree.is_dir())

    def test_real_worktree_round_trip_ignores_inherited_git_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = root / "repository"
            unrelated = root / "unrelated"
            worktree_root = root / "worktrees"
            repository.mkdir()
            unrelated.mkdir()

            def git(repo, *arguments):
                completed = subprocess.run(
                    ["git", *arguments],
                    cwd=repo,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True,
                )
                return completed.stdout.strip()

            for repo in (repository, unrelated):
                git(repo, "init", "-q")
                git(repo, "config", "user.email", "test@example.invalid")
                git(repo, "config", "user.name", "Worktree Test")
                (repo / "tracked.txt").write_text(str(repo), encoding="utf-8")
                git(repo, "add", "tracked.txt")
                git(repo, "commit", "-qm", "initial")

            expected = git(repository, "rev-parse", "HEAD")
            poisoned_environment = {
                "GIT_DIR": str(unrelated / ".git"),
                "GIT_WORK_TREE": str(unrelated),
            }
            with patch.dict(os.environ, poisoned_environment, clear=False), patch.object(
                path_runtime,
                "short_temp_root_candidates",
                return_value=[worktree_root],
            ):
                worktree = path_runtime.create_detached_worktree(
                    expected,
                    repository,
                )
                try:
                    actual, stderr, rc = path_runtime.run_cmd(
                        path_runtime.git_cmd() + ["rev-parse", "HEAD"],
                        cwd=str(worktree),
                        timeout=30,
                    )
                    self.assertEqual("", stderr)
                    self.assertEqual(0, rc)
                    self.assertEqual(
                        expected,
                        actual.strip(),
                    )
                finally:
                    path_runtime.remove_detached_worktree(worktree, repository)

            self.assertFalse(worktree.exists())


if __name__ == "__main__":
    unittest.main()
