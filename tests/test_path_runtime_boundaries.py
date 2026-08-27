import ctypes
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT_DIR / "scripts"))

import path_runtime as runtime  # noqa: E402


class PathRuntimeBoundaryTest(unittest.TestCase):
    def setUp(self):
        runtime._SHORT_TEMP_ROOT_CACHE.clear()

    def tearDown(self):
        runtime._SHORT_TEMP_ROOT_CACHE.clear()

    def test_component_and_filename_contract_matrix(self):
        self.assertEqual(runtime.WorktreeRecoveryError("x").result, {})
        self.assertEqual(
            runtime.WorktreeRecoveryError("x", {"errors": ["e"]}).result,
            {"errors": ["e"]},
        )
        self.assertEqual(runtime._digest(None), runtime._digest(""))
        self.assertNotEqual(runtime._digest("a"), runtime._digest("b"))
        self.assertEqual(runtime._sanitize_component(None), "item")
        self.assertEqual(runtime._sanitize_component("<>  a/b  "), "a_b")
        self.assertEqual(runtime._sanitize_component("CON.txt"), "_CON.txt")

        self.assertEqual(
            runtime.bounded_path_component("value", fallback="fallback"),
            "value",
        )
        self.assertEqual(
            runtime.bounded_path_component("", fallback="fallback"),
            "fallback",
        )
        hashed = runtime.bounded_path_component(
            "value", max_length=16, always_hash=True
        )
        self.assertLessEqual(len(hashed), 16)
        self.assertNotEqual(hashed, "value")
        collapsed = runtime.bounded_path_component(
            "........" + "x" * 100, max_length=16, default="fallback"
        )
        self.assertLessEqual(len(collapsed), 16)

        self.assertEqual(runtime.bounded_filename("short.jar"), "short.jar")
        self.assertEqual(runtime.bounded_filename(None), "artifact")
        with_suffix = runtime.bounded_filename("x" * 100 + ".archive.jar", 24)
        without_suffix = runtime.bounded_filename("x" * 100, 24)
        self.assertLessEqual(len(with_suffix), 24)
        self.assertTrue(with_suffix.endswith(".jar"))
        self.assertLessEqual(len(without_suffix), 24)
        defaulted = runtime.bounded_filename("." * 100, 20, default="artifact")
        self.assertLessEqual(len(defaulted), 20)
        minimum = runtime.bounded_filename(
            "x" * 100 + ".very-long-suffix", 1
        )
        self.assertLessEqual(len(minimum), 16)

    def test_windows_short_path_all_native_return_and_failure_shapes(self):
        path = Path(tempfile.gettempdir()).resolve()
        with patch.object(runtime, "IS_WINDOWS", False):
            self.assertEqual(runtime.windows_short_path(path), str(path))

        class Function:
            def __init__(self, values):
                self.values = iter(values)

            def __call__(self, _path, buffer, _size):
                value = next(self.values)
                if buffer is not None and isinstance(value, str):
                    buffer.value = value
                    return len(value)
                return value

        for values, expected in (
            ((0,), str(path)),
            ((20, 0), str(path)),
            ((20, "C:\\SHORT"), "C:\\SHORT"),
            ((20, 1), str(path)),
            ((20, ""), str(path)),
        ):
            function = Function(values)
            kernel = SimpleNamespace(GetShortPathNameW=function)
            with self.subTest(values=values), patch.object(
                runtime, "IS_WINDOWS", True
            ), patch.object(
                ctypes, "windll", SimpleNamespace(kernel32=kernel), create=True
            ):
                self.assertEqual(runtime.windows_short_path(path), expected)

        with patch.object(runtime, "IS_WINDOWS", True), patch.object(
            ctypes, "windll", property(lambda _self: None), create=True
        ):
            # A malformed native binding is a safe fall back, not a task failure.
            self.assertEqual(runtime.windows_short_path(path), str(path))

    def test_short_root_candidates_cover_configuration_workspace_windows_and_dedup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            configured = root / "configured"
            legacy = root / "legacy"
            workspace = root / "workspace"
            environment = {
                runtime.SHORT_TEMP_ROOT_ENV: str(configured),
                runtime.LEGACY_STEP1_WORKTREE_ROOT_ENV: str(legacy),
            }
            with patch.dict(os.environ, environment, clear=False), patch.object(
                runtime.tempfile, "gettempdir", return_value=str(root)
            ), patch.object(runtime, "IS_WINDOWS", False):
                candidates = runtime.short_temp_root_candidates(
                    preferred_root=configured, workspace=workspace
                )
            self.assertEqual(candidates.count(configured), 1)
            self.assertIn(legacy, candidates)
            self.assertIn(workspace.resolve() / ".worktrees", candidates)

            with patch.dict(os.environ, {}, clear=True), patch.object(
                runtime.tempfile, "gettempdir", return_value=str(root)
            ), patch.object(runtime, "IS_WINDOWS", True), patch.object(
                runtime, "windows_short_path", return_value=str(root / "SHORT")
            ):
                candidates = runtime.short_temp_root_candidates()
            self.assertEqual(candidates, [root / "SHORT", root.resolve()])

    def test_short_temp_directory_creation_cache_and_cleanup_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            created = runtime.make_short_temp_dir(
                prefix=None, preferred_root=root, strict_preferred=True
            )
            self.assertTrue(created.is_dir())
            runtime._remove_short_temp_dir(created)
            runtime._remove_short_temp_dir(created)

            errors = []
            with patch.object(
                runtime.tempfile, "mkdtemp", side_effect=OSError("denied")
            ):
                with self.assertRaises(OSError) as raised:
                    runtime.make_short_temp_dir(
                        preferred_root=root, strict_preferred=True
                    )
                errors.append(str(raised.exception))
            self.assertIn("denied", errors[0])

            with patch.object(
                runtime,
                "make_short_temp_dir",
                side_effect=(root / "probe-one", root / "probe-two"),
            ) as make, patch.object(runtime, "_remove_short_temp_dir"):
                (root / "probe-one").mkdir()
                (root / "probe-two").mkdir()
                first = runtime.short_temp_root(preferred_root=root)
                second = runtime.short_temp_root(preferred_root=root)
            self.assertEqual(first, root)
            self.assertEqual(second, root)
            self.assertEqual(make.call_count, 1)

            runtime._SHORT_TEMP_ROOT_CACHE.clear()
            stale = root / "stale"
            runtime._SHORT_TEMP_ROOT_CACHE[(
                str(root), "", "", "", tempfile.gettempdir(), runtime.IS_WINDOWS,
            )] = str(stale)
            with patch.object(runtime, "make_short_temp_dir", return_value=root / "probe"), \
                    patch.object(runtime, "_remove_short_temp_dir"):
                (root / "probe").mkdir(exist_ok=True)
                self.assertEqual(runtime.short_temp_root(preferred_root=root), root)

    def test_runtime_storage_and_git_long_path_platform_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report"
            with patch.object(runtime, "IS_WINDOWS", False):
                posix = runtime.runtime_storage_root(report, "name")
            self.assertEqual(posix, report / ".runtime" / "name")
            with patch.object(runtime, "IS_WINDOWS", True), patch.object(
                runtime, "short_temp_root", return_value=Path(tmp) / "short"
            ):
                windows = runtime.runtime_storage_root(report, "name")
            self.assertIn("jua-runtime", windows.parts)
            self.assertTrue(windows.is_dir())

        with patch.object(runtime, "IS_WINDOWS", False):
            self.assertEqual(runtime.git_with_long_paths(["git"]), ["git"])
        with patch.object(runtime, "IS_WINDOWS", True):
            self.assertEqual(
                runtime.git_with_long_paths(["git"]),
                ["git", "-c", "core.longpaths=true"],
            )
            existing = ["git", "-c", "core.longpaths=true"]
            self.assertEqual(runtime.git_with_long_paths(existing), existing)

    def test_filesystem_repository_discovery_and_linked_worktree_key_matrix(self):
        for value in (None, "", "https://example/repo.git", "git@example:repo"):
            self.assertIsNone(runtime.filesystem_git_repository_root(value))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            nested = repo / "a" / "b"
            nested.mkdir(parents=True)
            (repo / ".git").mkdir()
            file_path = nested / "file.txt"
            file_path.write_text("x", encoding="utf-8")
            self.assertEqual(
                runtime.filesystem_git_repository_root(file_path), repo.resolve()
            )
            self.assertEqual(runtime.filesystem_git_repository_root(nested), repo.resolve())
            self.assertIsNone(runtime.filesystem_git_repository_root(root / "missing"))

            linked = root / "linked"
            linked.mkdir()
            admin = root / "repo" / ".git" / "worktrees" / "linked"
            admin.mkdir(parents=True)
            (linked / ".git").write_text(
                "gitdir: ../repo/.git/worktrees/linked\n", encoding="utf-8"
            )
            (admin / "commondir").write_text("../..\n", encoding="utf-8")
            self.assertEqual(
                runtime._worktree_repository_key(linked),
                os.path.normcase(os.path.abspath(str((repo / ".git").resolve()))),
            )

            absolute = root / "absolute-linked"
            absolute.mkdir()
            (absolute / ".git").write_text(
                f"gitdir: {admin}\n", encoding="utf-8"
            )
            (admin / "commondir").unlink()
            self.assertEqual(
                runtime._worktree_repository_key(absolute),
                os.path.normcase(os.path.abspath(str(admin))),
            )

            broken = root / "broken"
            broken.mkdir()
            (broken / ".git").write_text("", encoding="utf-8")
            self.assertEqual(
                runtime._worktree_repository_key(broken),
                os.path.normcase(os.path.abspath(str((broken / ".git").resolve()))),
            )

            plain = root / "plain"
            plain.mkdir()
            (plain / ".git").write_text("not a gitdir pointer\n", encoding="utf-8")
            self.assertEqual(
                runtime._worktree_repository_key(plain),
                os.path.normcase(os.path.abspath(str((plain / ".git").resolve()))),
            )

            absolute_common = root / "absolute-common"
            absolute_common.mkdir()
            common = root / "common.git"
            common.mkdir()
            (absolute_common / ".git").write_text(
                f"gitdir: {admin}\n", encoding="utf-8"
            )
            (admin / "commondir").write_text(str(common), encoding="utf-8")
            self.assertEqual(
                runtime._worktree_repository_key(absolute_common),
                os.path.normcase(os.path.abspath(str(common))),
            )

    def test_process_liveness_start_tokens_and_lease_ownership_matrix(self):
        for pid in (None, "bad", 0, -1):
            self.assertFalse(runtime._process_is_alive(pid))
            self.assertEqual(runtime._process_start_token(pid), "")
        self.assertTrue(runtime._process_is_alive(os.getpid()))
        with patch.object(runtime, "IS_WINDOWS", True), patch.object(
            runtime, "_windows_process_is_alive", return_value=True
        ), patch.object(runtime, "_windows_process_start_token", return_value="win"):
            self.assertTrue(runtime._process_is_alive(12345))
            self.assertEqual(runtime._process_start_token(12345), "win")

        for error, expected in (
            (ProcessLookupError(), False),
            (PermissionError(), True),
            (OSError(), True),
        ):
            with self.subTest(error=type(error).__name__), patch.object(
                runtime, "IS_WINDOWS", False
            ), patch.object(runtime.os, "kill", side_effect=error):
                self.assertEqual(runtime._process_is_alive(12345), expected)

        proc_text = "123 (name with ) chars) " + " ".join(
            str(index) for index in range(3, 30)
        )
        with patch.object(runtime, "IS_WINDOWS", False), patch.object(
            Path, "read_text", return_value=proc_text
        ):
            self.assertTrue(runtime._process_start_token(12345).startswith("proc-start:"))
        with patch.object(runtime, "IS_WINDOWS", False), patch.object(
            Path, "read_text", side_effect=OSError("missing")
        ):
            self.assertEqual(runtime._process_start_token(12345), "")

        with patch.object(runtime, "_process_is_alive", return_value=False):
            self.assertFalse(runtime._lease_owner_is_alive(None))
        with patch.object(runtime, "_process_is_alive", return_value=True):
            self.assertTrue(runtime._lease_owner_is_alive({"pid": 1}))
        for observed, expected, alive in (
            ("", "token", True),
            ("token", "token", True),
            ("other", "token", False),
        ):
            with patch.object(runtime, "_process_is_alive", return_value=True), \
                    patch.object(runtime, "_process_start_token", return_value=observed):
                self.assertEqual(runtime._lease_owner_is_alive({
                    "pid": 1, "process_start_token": expected,
                }), alive)

    def test_lock_contention_timeout_and_mutation_retry_matrix(self):
        self.assertFalse(runtime._is_worktree_lock_contention(None, None))
        self.assertTrue(runtime._is_worktree_lock_contention("", "index.lock exists"))
        self.assertTrue(runtime._is_worktree_lock_contention(
            "cannot lock ref 'x': is at abc but expected def", ""
        ))
        with patch.object(runtime.time, "monotonic", return_value=10.0):
            self.assertEqual(runtime._remaining_timeout(9.0), 0)
            self.assertEqual(runtime._remaining_timeout(12.5), 2.5)

        calls = []
        responses = iter((
            ("", "index.lock exists", 1),
            ("ok", "", 0),
        ))

        def runner(*_args, **kwargs):
            calls.append(kwargs)
            return next(responses)

        with patch.object(runtime, "_WORKTREE_LOCK_RETRY_DELAYS", (0.01,)), \
                patch.object(runtime.time, "sleep"):
            stdout, stderr, rc, history = runtime._run_worktree_mutation(
                ["git"], repo_dir=".", runner=runner, timeout=5
            )
        self.assertEqual((stdout, stderr, rc), ("ok", "", 0))
        self.assertEqual(len(history), 2)
        self.assertTrue(calls)

        with patch.object(runtime, "_remaining_timeout", return_value=0):
            result = runtime._run_worktree_mutation(
                ["git"], repo_dir=".", runner=lambda *_a, **_k: None,
                timeout=0, deadline=1,
            )
        self.assertEqual(result[2], -1)
        self.assertEqual(len(result[3]), 1)

        for response in (("", "fatal", 1), ("", "index.lock exists", 1)):
            with patch.object(runtime, "_WORKTREE_LOCK_RETRY_DELAYS", ()), \
                    patch.object(runtime, "_remaining_timeout", return_value=1):
                result = runtime._run_worktree_mutation(
                    ["git"], repo_dir=".",
                    runner=lambda *_a, response=response, **_k: response,
                    timeout=1, deadline=2,
                )
            self.assertEqual(result[2], 1)

    def test_registration_commit_longest_path_and_diagnostics_matrix(self):
        self.assertEqual(runtime._mutation_diagnostic([]), "attempts=0")
        diagnostic = runtime._mutation_diagnostic([
            {"rc": 1, "stdout": None, "stderr": "index.lock exists"},
            {"rc": 2, "stdout": "out", "stderr": None},
        ])
        self.assertIn("attempts=2", diagnostic)
        self.assertIn("last_stdout=out", diagnostic)

        with patch.object(runtime, "_remaining_timeout", return_value=0):
            with self.assertRaises(RuntimeError):
                runtime._resolve_worktree_commit(["git"], ".", "HEAD", None, deadline=1)
            with self.assertRaises(RuntimeError):
                runtime._longest_tracked_path(["git"], ".", "HEAD", None, deadline=1)

        full = "a" * 40
        for response, succeeds in (
            ((full + "\n", "", 0), True),
            (("prefix\n" + full.upper() + "\n", "", 0), True),
            (("", "fatal", 1), False),
            (("short", "", 0), False),
        ):
            runner = lambda *_a, response=response, **_k: response
            with self.subTest(response=response), patch.object(
                runtime, "_remaining_timeout", return_value=1
            ):
                if succeeds:
                    self.assertEqual(
                        runtime._resolve_worktree_commit(
                            ["git"], ".", "HEAD", runner, deadline=2
                        ),
                        full,
                    )
                else:
                    with self.assertRaises(RuntimeError):
                        runtime._resolve_worktree_commit(
                            ["git"], ".", "HEAD", runner, deadline=2
                        )

        for response, expected in (
            (("a\0long/path\0", "", 0), ("long/path", 9)),
            (("", "", 0), ("", 0)),
        ):
            with patch.object(runtime, "_remaining_timeout", return_value=1):
                self.assertEqual(
                    runtime._longest_tracked_path(
                        ["git"], ".", "HEAD",
                        lambda *_a, response=response, **_k: response,
                        deadline=2,
                    ), expected,
                )
        with patch.object(runtime, "_remaining_timeout", return_value=1):
            with self.assertRaises(RuntimeError):
                runtime._longest_tracked_path(
                    ["git"], ".", "HEAD",
                    lambda *_a, **_k: ("", "fatal", 1), deadline=2,
                )

        with patch.object(runtime, "_remaining_timeout", return_value=0):
            self.assertEqual(
                runtime._worktree_registration_state(
                    ["git"], ".", "worktree", None, deadline=1
                )[0],
                None,
            )
        runner = lambda *_a, **_k: ("worktree /tmp/a\n", None, 0)
        with patch.object(runtime, "_remaining_timeout", return_value=1):
            registered, stderr, rc = runtime._worktree_registration_state(
                ["git"], ".", "/tmp/a", runner, deadline=2
            )
        self.assertTrue(registered)
        self.assertEqual((stderr, rc), ("", 0))

    def test_cleanup_failed_worktree_covers_registration_outcomes(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.mkdir()
            with patch.object(
                runtime,
                "_run_worktree_mutation",
                return_value=("", "", 0, []),
            ), patch.object(runtime.shutil, "rmtree") as remove:
                self.assertEqual(
                    runtime._cleanup_failed_worktree(
                        ["git"], tmp, target, None, deadline=None
                    ),
                    "",
                )
            remove.assert_called_once_with(target, ignore_errors=True)

            for registration, stderr, rc, expected_empty in (
                (False, "", 0, True),
                (True, "", 1, False),
                (None, "probe failed", 2, False),
            ):
                with self.subTest(registration=registration), patch.object(
                    runtime,
                    "_run_worktree_mutation",
                    return_value=(None, None, 1, [{"rc": 1}]),
                ), patch.object(
                    runtime,
                    "_worktree_registration_state",
                    return_value=(registration, stderr, rc),
                ):
                    result = runtime._cleanup_failed_worktree(
                        ["git"], tmp, target, None, deadline=1
                    )
                self.assertEqual(not result, expected_empty)
                if result:
                    self.assertIn(f"registered={registration}", result)

    def test_stale_lease_recovery_validates_every_ownership_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            repository = root / "repository"
            repository.mkdir()
            repository_key = runtime._worktree_repository_key(repository)

            def write_lease(target, **overrides):
                target.mkdir(exist_ok=True)
                lease = runtime._worktree_lease_path(target)
                payload = {
                    "schema_version": runtime._WORKTREE_LEASE_VERSION,
                    "repository_key": repository_key,
                    "worktree": str(target.resolve()),
                    "pid": 999_999_999,
                    "process_start_token": "dead",
                }
                payload.update(overrides)
                lease.write_text(json.dumps(payload), encoding="utf-8")
                return lease

            invalid_json = root / f"{runtime._WORKTREE_LEASE_PREFIX}invalid.json"
            invalid_json.write_text("{", encoding="utf-8")
            missing_path = root / f"{runtime._WORKTREE_LEASE_PREFIX}missing.json"
            missing_path.write_text(json.dumps({}), encoding="utf-8")

            missing_repository = root / "missing-repository"
            write_lease(missing_repository, repository_key="")
            wrong_name_target = root / "wrong-name-target"
            wrong_name_target.mkdir()
            wrong_name = root / f"{runtime._WORKTREE_LEASE_PREFIX}wrong-name.json"
            wrong_name.write_text(json.dumps({
                "schema_version": runtime._WORKTREE_LEASE_VERSION,
                "repository_key": repository_key,
                "worktree": str(wrong_name_target),
                "pid": 999_999_999,
            }), encoding="utf-8")

            other = root / "other"
            write_lease(other, repository_key="different")
            unsupported = root / "unsupported"
            write_lease(unsupported, schema_version=999)
            mismatched = root / "mismatched"
            mismatched_lease = write_lease(mismatched)
            mismatched_payload = json.loads(
                mismatched_lease.read_text(encoding="utf-8")
            )
            mismatched_payload["worktree"] = str(root / "elsewhere" / "mismatched")
            mismatched_lease.write_text(
                json.dumps(mismatched_payload), encoding="utf-8"
            )
            active = root / "active"
            write_lease(active, pid=os.getpid(), process_start_token="")
            cleanup_failure = root / "cleanup-failure"
            write_lease(cleanup_failure)
            removable = root / "removable"
            removable_lease = write_lease(removable)

            def cleanup(_git, _repo, target, _runner, *, deadline):
                if Path(target).name == "cleanup-failure":
                    return "still registered"
                runtime.shutil.rmtree(target, ignore_errors=True)
                return ""

            with patch.object(runtime, "_cleanup_failed_worktree", side_effect=cleanup):
                result = runtime._recover_stale_worktree_leases(
                    ["git"], repository, [root, root, root / "absent"], None,
                    deadline=runtime.time.monotonic() + 30,
                )

            self.assertEqual(result["checked_roots"], [str(root)])
            self.assertGreaterEqual(len(result["ignored_invalid"]), 2)
            self.assertEqual(result["ignored_other_repositories"], 2)
            self.assertIn(str(active.resolve()), result["active"])
            self.assertIn(str(removable.resolve()), result["removed"])
            self.assertFalse(removable_lease.exists())
            self.assertTrue(any("owned_lease_identity_invalid" in e for e in result["errors"]))
            self.assertTrue(any("cleanup_failed" in e for e in result["errors"]))

            self.assertEqual(
                runtime._recover_stale_worktree_leases(
                    ["git"], repository, None, None,
                    deadline=runtime.time.monotonic() + 30,
                )["checked_roots"],
                [],
            )

    def test_stale_lease_scan_is_not_truncated_and_reports_deadline_and_scan_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            repository = root / "repository"
            repository.mkdir()
            target = root / "target"
            target.mkdir()
            lease = runtime._worktree_lease_path(target)
            lease.write_text("{}", encoding="utf-8")
            second = root / f"{runtime._WORKTREE_LEASE_PREFIX}zz.json"
            second.write_text("{}", encoding="utf-8")

            with patch.object(runtime, "_remaining_timeout", return_value=0):
                result = runtime._recover_stale_worktree_leases(
                    ["git"], repository, [root], None, deadline=1
                )
            self.assertIn("lease_recovery_deadline_exceeded", result["errors"])

            with patch.object(runtime, "_remaining_timeout", return_value=1), patch.object(
                runtime, "_lease_owner_is_alive", return_value=True,
            ):
                result = runtime._recover_stale_worktree_leases(
                    ["git"], repository, [root], None, deadline=1
                )
            self.assertEqual(result["checked_leases"], 2)

            original_glob = Path.glob

            def failing_glob(path, pattern):
                if path == root:
                    raise OSError("scan denied")
                return original_glob(path, pattern)

            with patch.object(Path, "glob", failing_glob):
                result = runtime._recover_stale_worktree_leases(
                    ["git"], repository, [root], None,
                    deadline=runtime.time.monotonic() + 30,
                )
            self.assertTrue(any("lease_scan_failed" in e for e in result["errors"]))

    def test_legacy_recovery_preserves_current_leases_and_reports_cleanup_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            repository = root / "repository"
            repository.mkdir()
            leased = root / "jua-base-build"
            leased.mkdir()
            runtime._worktree_lease_path(leased).write_text("{}", encoding="utf-8")
            failing = root / "jua-current-build"
            failing.mkdir()
            ordinary = root / "jua-user"
            ordinary.mkdir()

            with patch.object(
                runtime, "_cleanup_failed_worktree", return_value="permission denied"
            ):
                result = runtime._recover_registered_legacy_worktrees(
                    ["git"], repository,
                    [repository, ordinary, leased, failing], [root], None,
                    deadline=1,
                )
            self.assertEqual(result["checked"], [str(failing.resolve())])
            self.assertEqual(result["removed"], [])
            self.assertTrue(any("cleanup_failed" in e for e in result["errors"]))
            runtime._raise_worktree_recovery_errors({"errors": []})
            with self.assertRaises(runtime.WorktreeRecoveryError) as raised:
                runtime._raise_worktree_recovery_errors(result)
            self.assertEqual(raised.exception.result, result)

    def test_recovery_wrapper_covers_default_roots_deadline_and_list_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            repository = Path(tmp).resolve()
            with patch.object(
                runtime, "short_temp_root_candidates", return_value=[]
            ) as candidates, patch.object(
                runtime, "_remaining_timeout", return_value=1
            ), patch.object(
                runtime,
                "_recover_stale_worktree_leases",
                return_value={"removed": [], "errors": []},
            ), patch.object(
                runtime,
                "_recover_registered_legacy_worktrees",
                return_value={
                    "checked": [], "removed": [],
                    "ignored_untrusted": [], "errors": [],
                },
            ):
                result = runtime.recover_owned_stale_worktrees(
                    repository,
                    roots=None,
                    runner=lambda *_a, **_k: (
                        f"worktree {repository}\n", "", 0
                    ),
                    git_command=["git"],
                    timeout=0,
                )
            candidates.assert_called_once_with(workspace=repository)
            self.assertEqual(result["registered_worktrees"], [str(repository)])

            with patch.object(runtime, "_remaining_timeout", return_value=0):
                with self.assertRaisesRegex(
                    runtime.WorktreeRecoveryError,
                    "worktree_recovery_deadline_exceeded",
                ):
                    runtime.recover_owned_stale_worktrees(
                        repository, roots=[], runner=None, git_command=["git"]
                    )

            for response, marker in (
                (("diagnostic stdout", "", 1), "diagnostic stdout"),
                ((f"worktree {repository}\n", None, 2), f"worktree {repository}"),
            ):
                with self.subTest(response=response), patch.object(
                    runtime, "_remaining_timeout", return_value=1
                ):
                    with self.assertRaises(runtime.WorktreeRecoveryError) as raised:
                        runtime.recover_owned_stale_worktrees(
                            repository, roots=[],
                            runner=lambda *_a, response=response, **_k: response,
                            git_command=["git"],
                        )
                self.assertIn(marker, str(raised.exception))

    def test_create_detached_worktree_failure_state_machine(self):
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            roots = [base / "long-root", base / "r"]
            for root in roots:
                root.mkdir()

            common = (
                patch.object(runtime, "short_temp_root_candidates", return_value=roots),
                patch.object(runtime, "_recover_stale_worktree_leases", return_value={"errors": []}),
                patch.object(runtime, "_resolve_worktree_commit", return_value=commit),
                patch.object(runtime, "_longest_tracked_path", return_value=("", 0)),
            )
            with common[0], common[1], common[2], common[3], patch.object(
                runtime, "IS_WINDOWS", True
            ), patch.object(
                runtime, "make_short_temp_dir", side_effect=OSError("denied")
            ) as make:
                with self.assertRaisesRegex(RuntimeError, "temp_create_failed"):
                    runtime.create_detached_worktree(
                        "HEAD", base, runner=None, git_command=["git"], timeout=0
                    )
            self.assertEqual(make.call_args_list[0].kwargs["preferred_root"], roots[1])

            target_one = roots[0] / "one"
            target_two = roots[1] / "two"
            target_one.mkdir()
            target_two.mkdir()
            with patch.object(runtime, "short_temp_root_candidates", return_value=roots), \
                    patch.object(runtime, "_recover_stale_worktree_leases", return_value={"errors": []}), \
                    patch.object(runtime, "_resolve_worktree_commit", return_value=commit), \
                    patch.object(runtime, "_longest_tracked_path", return_value=("", 0)), \
                    patch.object(runtime, "make_short_temp_dir", side_effect=[target_one, target_two]), \
                    patch.object(runtime, "_write_worktree_lease", side_effect=OSError("lease denied")):
                with self.assertRaisesRegex(RuntimeError, "lease_create_failed"):
                    runtime.create_detached_worktree(
                        "HEAD", base, runner=None, git_command=["git"]
                    )
            self.assertFalse(target_one.exists())
            self.assertFalse(target_two.exists())

    def test_create_verification_and_add_cleanup_failures(self):
        commit = "b" * 40
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            root = base / "root"
            root.mkdir()

            def invoke(target, mutation, cleanup, remaining, runner):
                target.mkdir(exist_ok=True)
                with patch.object(runtime, "short_temp_root_candidates", return_value=[root]), \
                        patch.object(runtime, "_recover_stale_worktree_leases", return_value={"errors": []}), \
                        patch.object(runtime, "_resolve_worktree_commit", return_value=commit), \
                        patch.object(runtime, "_longest_tracked_path", return_value=("", 0)), \
                        patch.object(runtime, "make_short_temp_dir", return_value=target), \
                        patch.object(runtime, "_write_worktree_lease"), \
                        patch.object(runtime, "_run_worktree_mutation", return_value=mutation), \
                        patch.object(runtime, "_cleanup_failed_worktree", return_value=cleanup), \
                        patch.object(runtime, "_remaining_timeout", return_value=remaining):
                    return runtime.create_detached_worktree(
                        "HEAD", base, runner=runner, git_command=["git"]
                    )

            for response, remaining, cleanup, expected in (
                (("", "", 0), 0, "", "deadline exceeded"),
                (("", "", 0), 1, "cleanup failed", "cleanup failed"),
                (("", "fatal", 1), 1, "cleanup failed", "无法安全清理"),
            ):
                target = root / runtime._digest((response, remaining, cleanup))
                runner = lambda *_a, response=response, **_k: ("", "verify failed", 1)
                with self.subTest(response=response, cleanup=cleanup):
                    with self.assertRaisesRegex(RuntimeError, expected):
                        invoke(
                            target,
                            (response[0], response[1], response[2], [{"rc": response[2]}]),
                            cleanup,
                            remaining,
                            runner,
                        )

            target = root / "path-retry"
            second = root / "path-retry-2"
            target.mkdir()
            second.mkdir()
            calls = []
            with patch.object(runtime, "short_temp_root_candidates", return_value=[root, base]), \
                    patch.object(runtime, "_recover_stale_worktree_leases", return_value={"errors": []}), \
                    patch.object(runtime, "_resolve_worktree_commit", return_value=commit), \
                    patch.object(runtime, "_longest_tracked_path", return_value=("x", 1)), \
                    patch.object(runtime, "make_short_temp_dir", side_effect=[target, second]), \
                    patch.object(runtime, "_write_worktree_lease"), \
                    patch.object(runtime, "_cleanup_failed_worktree", return_value=""), \
                    patch.object(runtime, "_remove_worktree_lease"), \
                    patch.object(runtime, "_remaining_timeout", return_value=1), \
                    patch.object(
                        runtime, "_run_worktree_mutation",
                        side_effect=[
                            ("", "filename too long", 1, [{"rc": 1}]),
                            ("", "permission denied", 1, [{"rc": 1}]),
                        ],
                    ):
                with self.assertRaises(RuntimeError) as raised:
                    runtime.create_detached_worktree(
                        "HEAD", base,
                        runner=lambda *_a, **_k: calls.append(1),
                        git_command=["git"],
                    )
            self.assertIn("predicted_longest_path", str(raised.exception))

    def test_remove_detached_worktree_directory_and_registration_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            target = root / "target"
            target.mkdir()
            with patch.object(
                runtime, "_run_worktree_mutation",
                return_value=("", "", 1, [{"rc": 1}]),
            ), patch.object(
                runtime, "_worktree_registration_state",
                return_value=(None, "", 2),
            ):
                with self.assertRaisesRegex(RuntimeError, "registered=None"):
                    runtime.remove_detached_worktree(
                        target, root, runner=None, git_command=["git"], timeout=0
                    )
            self.assertTrue(target.exists())

            with patch.object(
                runtime, "_run_worktree_mutation", return_value=("", "", 0, [])
            ), patch.object(runtime.shutil, "rmtree", side_effect=FileNotFoundError):
                runtime.remove_detached_worktree(
                    target, root, runner=None, git_command=["git"]
                )

            with patch.object(
                runtime, "_run_worktree_mutation", return_value=("", "", 0, [])
            ), patch.object(runtime.shutil, "rmtree", side_effect=OSError("busy")):
                with self.assertRaisesRegex(RuntimeError, "临时目录删除失败"):
                    runtime.remove_detached_worktree(
                        target, root, runner=None, git_command=["git"]
                    )

    def test_remaining_helper_boolean_and_iteration_boundaries(self):
        self.assertTrue(runtime._is_worktree_lock_contention(
            "Unable to create '/repo/.git/worktrees/a/locked.lock': File exists.",
            "",
        ))
        with patch.object(runtime, "_process_is_alive", return_value=True):
            self.assertTrue(runtime._lease_owner_is_alive(None))
        runtime._raise_worktree_recovery_errors(None)
        empty_legacy = runtime._recover_registered_legacy_worktrees(
            ["git"], ".", None, None, None, deadline=1
        )
        self.assertEqual(empty_legacy["checked"], [])

        with patch.object(runtime, "_remaining_timeout", return_value=1):
            with self.assertRaisesRegex(RuntimeError, "diagnostic stdout"):
                runtime._longest_tracked_path(
                    ["git"], ".", "HEAD",
                    lambda *_a, **_k: ("diagnostic stdout", "", 1),
                    deadline=2,
                )
            with self.assertRaises(RuntimeError):
                runtime._resolve_worktree_commit(
                    ["git"], ".", "HEAD",
                    lambda *_a, **_k: ("", "", 0),
                    deadline=2,
                )

            registered, stderr, rc = runtime._worktree_registration_state(
                ["git"], ".", "target",
                lambda *_a, **_k: ("", "list failed", 1),
                deadline=2,
            )
        self.assertEqual((registered, stderr, rc), (None, "list failed", 1))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            no_repository = root / "ordinary-directory"
            no_repository.mkdir()
            self.assertIsNone(runtime.filesystem_git_repository_root(no_repository))
            with patch.object(
                runtime, "short_temp_root_candidates", return_value=[root]
            ):
                created = runtime.make_short_temp_dir(
                    preferred_root=None, strict_preferred=True
                )
            self.assertTrue(created.is_dir())
            runtime._remove_short_temp_dir(created)

            with patch.object(runtime, "make_short_temp_dir", return_value=root / "p"), \
                    patch.object(runtime, "_remove_short_temp_dir"):
                (root / "p").mkdir()
                self.assertEqual(runtime.short_temp_root(workspace=root), root)

    def test_mutation_default_deadline_zero_timeout_and_zero_runner_timeout(self):
        with patch.object(runtime, "_remaining_timeout", return_value=1):
            result = runtime._run_worktree_mutation(
                ["git"], repo_dir=".",
                runner=lambda *_a, **_k: ("", "fatal", 1),
                timeout=0, deadline=None,
            )
        self.assertEqual(result[2], 1)
        with patch.object(runtime, "_remaining_timeout", return_value=0.5):
            timeouts = []

            def runner(_command, **kwargs):
                timeouts.append(kwargs["timeout"])
                return "", "fatal", 1

            runtime._run_worktree_mutation(
                ["git"], repo_dir=".", runner=runner,
                timeout=0, deadline=2,
            )
        self.assertEqual(timeouts, [0.5])

    def test_windows_process_start_token_native_matrix(self):
        class NativeFunction:
            def __init__(self, callback):
                self.callback = callback

            def __call__(self, *args):
                return self.callback(*args)

        closed = []

        def kernel(handle, times_result=True):
            def get_times(_handle, creation, *_rest):
                if times_result:
                    creation._obj.dwHighDateTime = 2
                    creation._obj.dwLowDateTime = 3
                return int(times_result)

            return SimpleNamespace(
                OpenProcess=NativeFunction(lambda *_a: handle),
                GetProcessTimes=NativeFunction(get_times),
                CloseHandle=NativeFunction(lambda value: closed.append(value) or 1),
            )

        for handle, times_result, expected in (
            (0, True, ""),
            (7, False, ""),
            (8, True, f"windows-filetime:{(2 << 32) | 3}"),
        ):
            with self.subTest(handle=handle, times_result=times_result), patch.object(
                ctypes, "WinDLL", return_value=kernel(handle, times_result), create=True
            ):
                self.assertEqual(runtime._windows_process_start_token(42), expected)
        self.assertEqual(closed, [7, 8])

    def test_short_temporary_directory_legacy_exception_note_paths(self):
        class LegacyError(Exception):
            add_note = None

        class ImmutableNotesError(LegacyError):
            def __setattr__(self, name, value):
                if name == "__notes__":
                    raise AttributeError("immutable")
                super().__setattr__(name, value)

        for error, expected_note_count in (
            (LegacyError("body"), 1),
            (LegacyError("body-with-note"), 2),
            (ImmutableNotesError("body"), 0),
        ):
            if "with-note" in str(error):
                error.__notes__ = ["existing"]
            with self.subTest(error=type(error).__name__, message=str(error)), \
                    patch.object(runtime, "make_short_temp_dir", return_value=Path("owned")), \
                    patch.object(runtime, "_remove_short_temp_dir", side_effect=OSError("busy")):
                with self.assertRaises(type(error)) as raised:
                    with runtime.short_temporary_directory():
                        raise error
            self.assertIs(raised.exception, error)
            self.assertEqual(len(getattr(error, "__notes__", ())), expected_note_count)

    def test_create_windows_within_budget_empty_verification_and_expired_retry(self):
        commit = "c" * 40
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            root = base / "r"
            root.mkdir()

            def run_case(longest, mutation, remaining_values, runner):
                target = root / runtime._digest((longest, mutation, remaining_values))
                target.mkdir(exist_ok=True)
                with patch.object(runtime, "IS_WINDOWS", True), \
                        patch.object(runtime, "short_temp_root_candidates", return_value=[root]), \
                        patch.object(runtime, "_recover_stale_worktree_leases", return_value={"errors": []}), \
                        patch.object(runtime, "_resolve_worktree_commit", return_value=commit), \
                        patch.object(runtime, "_longest_tracked_path", return_value=longest), \
                        patch.object(runtime, "make_short_temp_dir", return_value=target), \
                        patch.object(runtime, "_write_worktree_lease"), \
                        patch.object(runtime, "_run_worktree_mutation", return_value=mutation), \
                        patch.object(runtime, "_cleanup_failed_worktree", return_value=""), \
                        patch.object(runtime, "_remove_worktree_lease"), \
                        patch.object(runtime, "_remaining_timeout", side_effect=remaining_values):
                    return runtime.create_detached_worktree(
                        "HEAD", base, runner=runner, git_command=["git"]
                    )

            for longest in (("", 0), ("x", 1)):
                with self.subTest(longest=longest):
                    result = run_case(
                        longest,
                        ("", "", 0, []),
                        [1],
                        lambda *_a, **_k: (commit, "", 0),
                    )
                self.assertTrue(result.name)

            with self.assertRaisesRegex(RuntimeError, "actual=<empty>"):
                run_case(
                    ("x", 1),
                    ("", "", 0, []),
                    [1],
                    lambda *_a, **_k: ("", "", 0),
                )

            with self.assertRaises(RuntimeError):
                run_case(
                    ("", 0),
                    ("", "path too long", 1, [{"rc": 1}]),
                    [0],
                    lambda *_a, **_k: ("", "", 1),
                )

            with self.assertRaisesRegex(RuntimeError, "stderr="):
                run_case(
                    ("", 0),
                    ("", "", 1, [{"rc": 1}]),
                    [1],
                    lambda *_a, **_k: ("", "", 1),
                )

            with self.assertRaises(RuntimeError):
                run_case(
                    ("", 0),
                    ("path too long", "", 1, [{"rc": 1}]),
                    [1],
                    lambda *_a, **_k: ("", "", 1),
                )


if __name__ == "__main__":
    unittest.main()
