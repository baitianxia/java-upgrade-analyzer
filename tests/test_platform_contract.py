import ast
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import compat  # noqa: E402
import s1_dep_diff  # noqa: E402
import s4_contract  # noqa: E402
import path_runtime  # noqa: E402
from compat import run_cmd  # noqa: E402


class PlatformContractTest(unittest.TestCase):
    def setUp(self):
        compat._GIT_EXECUTABLE_CACHE.clear()

    def test_shared_path_policy_bounds_dynamic_components_without_collisions(self):
        first = "com.example:" + ("very-long-artifact-" * 20) + "one"
        second = "com.example:" + ("very-long-artifact-" * 20) + "two"

        first_component = path_runtime.bounded_path_component(first, max_length=48)
        second_component = path_runtime.bounded_path_component(second, max_length=48)
        first_filename = path_runtime.bounded_filename(first + ".jar", max_length=64)

        self.assertLessEqual(len(first_component), 48)
        self.assertLessEqual(len(second_component), 48)
        self.assertNotEqual(first_component, second_component)
        self.assertLessEqual(len(first_filename), 64)
        self.assertTrue(first_filename.endswith(".jar"))
        self.assertLessEqual(len(s4_contract.make_per_dependency_dirname(first)), 48)

    def test_windows_runtime_storage_uses_shared_short_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured_root = Path(tmp) / "w"
            long_report = Path(tmp) / (("deep-" * 20) + "report")
            with patch.object(path_runtime, "IS_WINDOWS", True), patch.dict(
                os.environ,
                {path_runtime.SHORT_TEMP_ROOT_ENV: str(configured_root)},
                clear=False,
            ):
                storage = path_runtime.runtime_storage_root(
                    long_report, "source_snapshots",
                )

        self.assertEqual(configured_root, storage.parents[2])
        self.assertNotIn(str(long_report), str(storage))

    def test_windows_git_policy_is_applied_at_the_shared_command_boundary(self):
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat, "find_executable", return_value=r"C:\Git\git.exe",
        ):
            command = compat.git_cmd()

        self.assertEqual(
            [r"C:\Git\git.exe", "-c", "core.longpaths=true"],
            command,
        )

    def test_windows_subprocess_policy_hides_every_console_child(self):
        self.assertEqual(
            compat.subprocess_platform_kwargs(platform_name="nt"),
            {"creationflags": 0x08000000},
        )
        self.assertEqual(
            compat.subprocess_platform_kwargs(
                new_process_group=True, platform_name="win32"
            ),
            {"creationflags": 0x08000000 | 0x00000200},
        )
        self.assertEqual(
            compat.subprocess_platform_kwargs(platform_name="posix"),
            {},
        )
        self.assertEqual(
            compat.subprocess_platform_kwargs(
                new_process_group=True, platform_name="posix"
            ),
            {"start_new_session": True},
        )

    def test_windows_run_cmd_hides_python_and_other_non_git_children(self):
        process = SimpleNamespace(
            stdin=None, stdout=None, stderr=None, returncode=0,
        )
        process.communicate = lambda input=None, timeout=None: (b"ok\n", b"")
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat.subprocess, "Popen", return_value=process,
        ) as popen:
            stdout, stderr, returncode = compat.run_cmd(
                ["python.exe", "--version"]
            )

        self.assertEqual((stdout, stderr, returncode), ("ok\n", "", 0))
        self.assertEqual(
            popen.call_args.kwargs["creationflags"], 0x08000000
        )

    def test_windows_job_assignment_failure_fails_closed_after_reaping_root(self):
        process = SimpleNamespace(pid=43210)
        self.addCleanup(compat.release_process_tree, process)
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat.subprocess, "Popen", return_value=process,
        ), patch.object(
            compat, "_attach_windows_managed_job",
            side_effect=OSError("nested job rejected"),
        ), patch.object(
            compat, "_terminate_subprocess",
        ) as terminate:
            _stdout, stderr, returncode = compat.run_cmd(
                [sys.executable, "-c", "pass"], timeout=1,
            )

        self.assertEqual(returncode, -1)
        self.assertIn("MANAGED_PROCESS_JOB_ASSIGNMENT_FAILED", stderr)
        self.assertIn("nested job rejected", stderr)
        terminate.assert_called_once_with(process, process_group=True)

    def test_windows_git_capture_uses_no_window_without_a_new_process_group(self):
        process = SimpleNamespace(returncode=0)
        process.communicate = lambda input=None, timeout=None: (b"a" * 40 + b"\n", b"")
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat, "find_executable", return_value=r"C:\Git\git.exe",
        ), patch.object(compat.subprocess, "Popen", return_value=process) as popen:
            stdout, stderr, returncode = compat.run_cmd(
                ["git", "rev-parse", "--verify", "HEAD^{commit}"],
                timeout=10,
            )

        self.assertEqual((stdout.strip(), stderr, returncode), ("a" * 40, "", 0))
        self.assertEqual(popen.call_args.kwargs["creationflags"], 0x08000000)
        self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertTrue(popen.call_args.kwargs["close_fds"])

    def test_git_required_stdout_retries_with_file_capture(self):
        primary = SimpleNamespace(returncode=0)
        primary.communicate = lambda input=None, timeout=None: (b"", b"")
        fallback = ("a" * 40 + "\n", "", 0)
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat, "find_executable", return_value=r"C:\Git\git.exe",
        ), patch.object(
            compat.subprocess, "Popen", return_value=primary,
        ), patch.object(
            compat, "_run_git_file_capture", return_value=fallback,
        ) as file_capture:
            stdout, stderr, returncode = compat.run_cmd(
                ["git", "rev-parse", "--verify", "HEAD^{commit}"],
                cwd=r"C:\worktree",
                timeout=10,
            )

        self.assertEqual((stdout.strip(), stderr, returncode), ("a" * 40, "", 0))
        file_capture.assert_called_once()

    def test_git_required_stdout_fails_closed_after_empty_file_capture(self):
        primary = SimpleNamespace(returncode=0)
        primary.communicate = lambda input=None, timeout=None: (b"", b"")
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat, "find_executable", return_value=r"C:\Git\git.exe",
        ), patch.object(
            compat.subprocess, "Popen", return_value=primary,
        ), patch.object(
            compat, "_run_git_file_capture", return_value=("", "", 0),
        ):
            stdout, stderr, returncode = compat.run_cmd(
                ["git", "worktree", "list", "--porcelain"],
                cwd=r"C:\repository",
                timeout=10,
            )

        self.assertEqual(stdout, "")
        self.assertEqual(returncode, -1)
        self.assertIn("GIT_REQUIRED_STDOUT_EMPTY", stderr)

    def test_git_file_capture_helper_reads_real_child_stdout(self):
        stdout, stderr, returncode = compat._run_git_file_capture(
            [sys.executable, "-c", "print('file-captured')"],
            cwd=None,
            timeout=10,
            input_bytes=None,
            env=os.environ.copy(),
            process_group_kwargs=compat.subprocess_platform_kwargs(),
        )

        self.assertEqual(returncode, 0, stderr)
        self.assertEqual(stdout.strip(), "file-captured")
        self.assertEqual(stderr, "")

    @unittest.skipUnless(os.name == "nt", "requires a real Windows GUI parent")
    def test_pythonw_parent_repeatedly_captures_real_git_stdout(self):
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        real_git = shutil.which("git")
        if not pythonw.is_file() or not real_git:
            self.skipTest("pythonw.exe and Git are required")
        with tempfile.TemporaryDirectory(prefix="jua pythonw git ") as tmp:
            root = Path(tmp)
            repository = root / "repository"
            repository.mkdir()
            for command in (
                [real_git, "init", "-q"],
                [real_git, "config", "user.email", "pythonw@example.invalid"],
                [real_git, "config", "user.name", "Pythonw Capture"],
            ):
                subprocess.run(
                    command,
                    cwd=repository,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            (repository / "tracked.txt").write_text("capture\n", encoding="utf-8")
            subprocess.run(
                [real_git, "add", "tracked.txt"],
                cwd=repository,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            subprocess.run(
                [real_git, "commit", "-qm", "capture fixture"],
                cwd=repository,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            probe = root / "probe.py"
            result_path = root / "result.json"
            probe.write_text(
                "\n".join((
                    "import json, sys",
                    "from pathlib import Path",
                    "sys.path.insert(0, sys.argv[1])",
                    "from compat import git_cmd, run_cmd",
                    "rows = []",
                    "for _ in range(25):",
                    "    out, err, rc = run_cmd(git_cmd() + "
                    "['rev-parse', '--verify', 'HEAD^{commit}'], "
                    "cwd=sys.argv[2], timeout=10)",
                    "    rows.append({'stdout': out.strip(), 'stderr': err, 'rc': rc})",
                    "Path(sys.argv[3]).write_text(json.dumps(rows), encoding='utf-8')",
                )) + "\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    str(pythonw),
                    str(probe),
                    str(ROOT / "scripts"),
                    str(repository),
                    str(result_path),
                ],
                timeout=60,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
            )
            rows = json.loads(result_path.read_text(encoding="utf-8"))

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(len(rows), 25)
        self.assertTrue(all(row["rc"] == 0 for row in rows))
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{40,64}", row["stdout"]) for row in rows))
        self.assertTrue(all(row["stderr"] == "" for row in rows))

    def test_product_subprocess_calls_expand_the_shared_platform_policy(self):
        missing = []
        for source_path in sorted((ROOT / "scripts").glob("*.py")):
            tree = ast.parse(source_path.read_text(encoding="utf-8"))
            managed_wrapper_lines = set()
            if source_path.name == "compat.py":
                for definition in tree.body:
                    if (
                        isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and definition.name == "managed_popen"
                    ):
                        managed_wrapper_lines.update(
                            range(definition.lineno, definition.end_lineno + 1)
                        )
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(
                    node.func, ast.Attribute
                ):
                    continue
                if not (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"
                    and node.func.attr in {"run", "Popen"}
                ):
                    continue
                if getattr(node, "lineno", 0) in managed_wrapper_lines:
                    continue
                expanded = [
                    keyword.value for keyword in node.keywords
                    if keyword.arg is None
                ]
                if not any(
                    (
                        isinstance(value, ast.Call)
                        and isinstance(value.func, ast.Name)
                        and value.func.id in {
                            "subprocess_platform_kwargs",
                            "_background_platform_kwargs",
                        }
                    )
                    or (
                        isinstance(value, ast.Name)
                        and value.id == "process_group_kwargs"
                    )
                    for value in expanded
                ):
                    missing.append(
                        f"{source_path.name}:{getattr(node, 'lineno', 0)}"
                    )

        self.assertEqual(missing, [])

    def test_every_managed_popen_caller_has_success_and_failure_cleanup(self):
        missing = []
        ownership_transfers = {
            ("final_artifact_edge_oracle.py", "_spawn_javap"),
        }
        observed_transfers = set()
        observed_transfer_callers = set()
        cleanup_names = {
            "_cancel_process",
            "_terminate_subprocess",
            "terminate_process_tree",
        }
        for source_path in sorted((ROOT / "scripts").glob("*.py")):
            tree = ast.parse(source_path.read_text(encoding="utf-8"))
            for definition in tree.body:
                if not isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                calls = [node for node in ast.walk(definition) if isinstance(node, ast.Call)]
                uses_managed_popen = any(
                    (
                        isinstance(call.func, ast.Name)
                        and call.func.id == "managed_popen"
                    )
                    or (
                        isinstance(call.func, ast.Attribute)
                        and call.func.attr == "managed_popen"
                    )
                    for call in calls
                )
                if not uses_managed_popen:
                    transfer_calls = {
                        call.func.id
                        for call in calls
                        if (
                            isinstance(call.func, ast.Name)
                            and call.func.id == "_spawn_javap"
                        )
                    }
                    if not transfer_calls:
                        continue
                    observed_transfer_callers.add(
                        (source_path.name, definition.name)
                    )
                called_names = {
                    call.func.id
                    for call in calls
                    if isinstance(call.func, ast.Name)
                } | {
                    call.func.attr
                    for call in calls
                    if isinstance(call.func, ast.Attribute)
                }
                owner = (source_path.name, definition.name)
                if uses_managed_popen and owner in ownership_transfers:
                    observed_transfers.add(owner)
                    continue
                if "release_process_tree" not in called_names:
                    missing.append(f"{source_path.name}:{definition.name}:success")
                if not (cleanup_names & called_names):
                    missing.append(f"{source_path.name}:{definition.name}:failure")

        self.assertEqual(missing, [])
        self.assertEqual(observed_transfers, ownership_transfers)
        self.assertEqual(observed_transfer_callers, {
            (
                "final_artifact_edge_oracle.py",
                "_parse_entry_group_with_javap_impl",
            ),
            ("final_artifact_edge_oracle.py", "_parse_entry_with_javap"),
        })

    def test_synchronous_product_commands_cannot_bypass_tree_management(self):
        """Only the deliberate background launcher may own a raw Popen."""
        allowed = {
            ("compat.py", "_detect_subprocess_encoding", "run"),
            ("compat.py", "managed_popen", "Popen"),
            ("compat.py", "_terminate_subprocess", "run"),
            ("run_step.py", "start_background_run", "Popen"),
        }
        observed = set()
        for source_path in sorted((ROOT / "scripts").glob("*.py")):
            tree = ast.parse(source_path.read_text(encoding="utf-8"))
            for definition in ast.walk(tree):
                if not isinstance(
                    definition, (ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    continue
                for node in ast.walk(definition):
                    if not (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "subprocess"
                        and node.func.attr in {"run", "Popen"}
                    ):
                        continue
                    identity = (
                        source_path.name, definition.name, node.func.attr,
                    )
                    observed.add(identity)
                    self.assertIn(
                        identity,
                        allowed,
                        f"synchronous subprocess bypasses managed tree: "
                        f"{source_path.name}:{node.lineno}",
                    )

        self.assertEqual(observed, allowed)

    def test_path_expanding_temporary_directories_cannot_bypass_shared_runtime(self):
        for path in sorted((ROOT / "scripts").glob("*.py")):
            if path.name == "path_runtime.py":
                continue
            source = path.read_text(encoding="utf-8")
            self.assertNotRegex(
                source,
                r"tempfile\.(?:TemporaryDirectory|mkdtemp)\s*\(",
                f"{path.name} bypasses the shared short-path runtime",
            )

    def test_step1_real_worktree_round_trip_uses_short_generated_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = root / "repository"
            repository.mkdir()

            def git(*arguments):
                completed = subprocess.run(
                    ["git", *arguments],
                    cwd=repository,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True,
                )
                return completed.stdout.strip()

            git("init")
            git("config", "user.email", "platform@example.invalid")
            git("config", "user.name", "Platform Contract")
            (repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            git("add", "tracked.txt")
            git("commit", "-m", "initial")
            commit = git("rev-parse", "HEAD")
            worktree_root = root / "w"

            with patch.dict(
                os.environ,
                {path_runtime.SHORT_TEMP_ROOT_ENV: str(worktree_root)},
                clear=False,
            ):
                worktree = s1_dep_diff.create_branch_worktree(
                    commit,
                    repository,
                    side="base",
                )
                try:
                    self.assertEqual(worktree_root, worktree.parent)
                    self.assertTrue(worktree.name.startswith("s1-b-"))
                    self.assertNotIn(commit, worktree.name)
                    self.assertEqual(
                        commit,
                        subprocess.run(
                            ["git", "rev-parse", "HEAD"],
                            cwd=worktree,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            check=True,
                        ).stdout.strip(),
                    )
                finally:
                    s1_dep_diff.remove_branch_worktree(worktree, repository)

            self.assertFalse(worktree.exists())
            self.assertNotIn(
                str(worktree),
                git("worktree", "list", "--porcelain"),
            )

    def test_platform_only_stdlib_imports_are_guarded(self):
        platform_only_modules = {
            "fcntl", "grp", "posix", "pty", "pwd", "resource",
            "syslog", "termios", "tty",
        }
        for path in sorted((ROOT / "scripts").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            parents = {
                child: parent
                for parent in ast.walk(tree)
                for child in ast.iter_child_nodes(parent)
            }
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported = {alias.name.split(".", 1)[0] for alias in node.names}
                elif isinstance(node, ast.ImportFrom):
                    imported = {(node.module or "").split(".", 1)[0]}
                else:
                    continue
                guarded_modules = imported & platform_only_modules
                if not guarded_modules:
                    continue
                ancestor = parents.get(node)
                protected = False
                while ancestor is not None:
                    if isinstance(ancestor, ast.Try):
                        caught = {
                            name.id
                            for handler in ancestor.handlers
                            for name in ast.walk(handler.type)
                            if isinstance(name, ast.Name)
                        }
                        if "ImportError" in caught:
                            protected = True
                            break
                    ancestor = parents.get(ancestor)
                self.assertTrue(
                    protected,
                    f"{path.relative_to(ROOT)}:{node.lineno} imports "
                    f"{sorted(guarded_modules)} without an ImportError fallback",
                )

    def test_git_resolution_prefers_working_user_install_over_broken_system_git(self):
        executable_name = "git.exe" if compat.IS_WINDOWS else "git"
        user_git = Path(os.path.abspath(
            str(Path("/Users/example/.local/bin") / executable_name)
        ))

        with patch.object(compat.Path, "home", return_value=Path("/Users/example")), \
                patch.object(compat.shutil, "which", return_value="/usr/bin/git"), \
                patch.object(
                    compat,
                    "_git_executable_works",
                    side_effect=lambda path: Path(path) == user_git,
                ), \
                patch.dict(os.environ, {"JUA_GIT_EXECUTABLE": ""}, clear=False):
            resolved = compat.find_executable("git")

        self.assertEqual(resolved, str(user_git))

    def test_git_resolution_prefers_explicit_executable_over_path(self):
        explicit_git = os.path.abspath("/opt/jua/git")
        path_git = os.path.abspath("/usr/bin/git")

        with patch.object(compat.shutil, "which", return_value=path_git), patch.object(
            compat,
            "_git_executable_works",
            return_value=True,
        ) as probe, patch.dict(
            os.environ,
            {"JUA_GIT_EXECUTABLE": explicit_git},
            clear=False,
        ):
            resolved = compat.find_executable("git")

        self.assertEqual(resolved, explicit_git)
        probe.assert_called_once_with(explicit_git)

    def test_git_resolution_prefers_current_path_over_platform_fallback(self):
        path_git = os.path.abspath("/custom/path/bin/git")
        fallback_git = os.path.abspath("/Users/example/.local/bin/git")

        with patch.object(compat.Path, "home", return_value=Path("/Users/example")), patch.object(
            compat.shutil,
            "which",
            return_value=path_git,
        ), patch.object(
            compat,
            "_git_executable_works",
            side_effect=lambda value: value in {path_git, fallback_git},
        ) as probe, patch.dict(
            os.environ,
            {"JUA_GIT_EXECUTABLE": ""},
            clear=False,
        ):
            resolved = compat.find_executable("git")

        self.assertEqual(resolved, path_git)
        probe.assert_called_once_with(path_git)

    def test_git_resolution_normalizes_relative_path_result_to_absolute(self):
        relative_git = str(Path("tool-bin") / ("git.exe" if compat.IS_WINDOWS else "git"))
        expected = os.path.abspath(relative_git)

        with patch.object(compat.shutil, "which", return_value=relative_git), patch.object(
            compat,
            "_git_executable_works",
            return_value=True,
        ), patch.dict(
            os.environ,
            {"JUA_GIT_EXECUTABLE": ""},
            clear=False,
        ):
            resolved = compat.find_executable("git")

        self.assertEqual(resolved, expected)
        self.assertTrue(os.path.isabs(resolved))

    def test_git_environment_sanitizer_preserves_authentication_transport(self):
        repository_keys = {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_NAMESPACE",
            "GIT_SHALLOW_FILE",
            "GIT_CONFIG",
            "GIT_CEILING_DIRECTORIES",
            "GIT_DISCOVERY_ACROSS_FILESYSTEM",
            "GIT_PREFIX",
            "GIT_IMPLICIT_WORK_TREE",
            "GIT_QUARANTINE_PATH",
            "GIT_REPLACE_REF_BASE",
            "GIT_GRAFT_FILE",
            "GIT_NO_REPLACE_OBJECTS",
            "GIT_EXEC_PATH",
            "GIT_TEMPLATE_DIR",
            "GIT_ATTR_NOSYSTEM",
            "GIT_ATTR_SOURCE",
            "GIT_EXTERNAL_DIFF",
        }
        environment = {key: "polluted" for key in repository_keys}
        environment.update({
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_0": "core.worktree",
            "GIT_CONFIG_VALUE_0": "/polluted/worktree",
            "GIT_CONFIG_KEY_1": "credential.username",
            "GIT_CONFIG_VALUE_1": "transport-user",
            "GIT_CONFIG_KEY_2": "http.proxy",
            "GIT_CONFIG_VALUE_2": "http://proxy.example.invalid:8080",
            "GIT_CONFIG_PARAMETERS": (
                "'core.repositoryFormatVersion'='99' "
                "'url.https://mirror.example.invalid/.insteadOf'='corp:' "
                "'safe.directory'='*' "
                "'protocol.file.allow'='always' "
                "'protocol.https.allow'='always'"
            ),
            "GIT_ASKPASS": "/auth/askpass",
            "GIT_SSH_COMMAND": "ssh -F /auth/config",
            "SSH_AUTH_SOCK": "/auth/agent.sock",
            "HTTPS_PROXY": "http://system-proxy.example.invalid:3128",
            "GIT_CONFIG_GLOBAL": "/auth/global.gitconfig",
            "GIT_CONFIG_SYSTEM": "/auth/system.gitconfig",
            "GIT_TRACE": "/tmp/git-trace-leak",
            "GIT_TRACE_PACKET": "1",
            "GIT_TRACE_REDACT": "0",
            "GIT_TERMINAL_PROMPT": "1",
            "LC_ALL": "user-locale",
        })

        compat._sanitize_git_environment(environment)

        self.assertTrue(repository_keys.isdisjoint(environment))
        self.assertNotIn("GIT_CONFIG_PARAMETERS", environment)
        self.assertEqual(environment["GIT_CONFIG_COUNT"], "4")
        self.assertEqual(environment["GIT_CONFIG_KEY_0"], "credential.username")
        self.assertEqual(environment["GIT_CONFIG_VALUE_0"], "transport-user")
        self.assertEqual(environment["GIT_CONFIG_KEY_1"], "http.proxy")
        self.assertEqual(
            environment["GIT_CONFIG_VALUE_1"],
            "http://proxy.example.invalid:8080",
        )
        self.assertEqual(
            environment["GIT_CONFIG_KEY_2"],
            "url.https://mirror.example.invalid/.insteadOf",
        )
        self.assertEqual(environment["GIT_CONFIG_VALUE_2"], "corp:")
        self.assertEqual(environment["GIT_CONFIG_KEY_3"], "protocol.https.allow")
        self.assertEqual(environment["GIT_CONFIG_VALUE_3"], "always")
        self.assertEqual(environment["GIT_ASKPASS"], "/auth/askpass")
        self.assertEqual(environment["GIT_SSH_COMMAND"], "ssh -F /auth/config")
        self.assertEqual(environment["SSH_AUTH_SOCK"], "/auth/agent.sock")
        self.assertEqual(
            environment["HTTPS_PROXY"],
            "http://system-proxy.example.invalid:3128",
        )
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "/auth/global.gitconfig")
        self.assertEqual(environment["GIT_CONFIG_SYSTEM"], "/auth/system.gitconfig")
        self.assertNotIn("GIT_TRACE", environment)
        self.assertNotIn("GIT_TRACE_PACKET", environment)
        self.assertEqual(environment["GIT_TRACE_REDACT"], "1")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GCM_INTERACTIVE"], "Never")
        self.assertEqual(environment["LC_ALL"], "C")
        self.assertEqual(environment["LANG"], "C")

    def test_git_executable_probe_uses_the_same_sanitized_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / ("git.exe" if compat.IS_WINDOWS else "git")
            candidate.touch()
            completed = subprocess.CompletedProcess(
                [str(candidate), "--version"], 0, b"git version test\n", b"",
            )
            with patch.dict(
                os.environ,
                {
                    "GIT_EXEC_PATH": "/polluted/git-core",
                    "GIT_TEMPLATE_DIR": "/polluted/templates",
                    "GIT_TRACE_PACKET": "1",
                    "GIT_TRACE_REDACT": "0",
                },
                clear=False,
            ), patch.object(
                compat,
                "run_managed_subprocess",
                return_value=completed,
            ) as runner:
                self.assertTrue(compat._git_executable_works(candidate))

        probe_environment = runner.call_args.kwargs["env"]
        self.assertNotIn("GIT_EXEC_PATH", probe_environment)
        self.assertNotIn("GIT_TEMPLATE_DIR", probe_environment)
        self.assertNotIn("GIT_TRACE_PACKET", probe_environment)
        self.assertEqual(probe_environment["GIT_TRACE_REDACT"], "1")

    @unittest.skipUnless(shutil.which("git"), "Git is required for environment isolation")
    def test_run_cmd_ignores_real_git_dir_pollution(self):
        real_git = os.path.abspath(shutil.which("git"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            pollution = root / "pollution"
            target.mkdir()
            pollution.mkdir()
            for repository in (target, pollution):
                subprocess.run(
                    [real_git, "init", "-q"],
                    cwd=repository,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            subprocess.run(
                [real_git, "remote", "add", "origin", "https://example.invalid/repo.git"],
                cwd=target,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            injected_config = root / "injected.config"
            injected_config.write_text(
                "[remote \"injected\"]\n\turl = https://example.invalid/injected.git\n",
                encoding="utf-8",
            )
            polluted_environment = {
                "JUA_GIT_EXECUTABLE": real_git,
                "GIT_DIR": str(pollution / ".git"),
                "GIT_WORK_TREE": str(pollution),
                "GIT_COMMON_DIR": str(pollution / ".git"),
                "GIT_INDEX_FILE": str(root / "polluted.index"),
                "GIT_OBJECT_DIRECTORY": str(pollution / ".git" / "objects"),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(target / ".git" / "objects"),
                "GIT_NAMESPACE": "polluted",
                "GIT_SHALLOW_FILE": str(root / "polluted.shallow"),
                "GIT_CONFIG": str(injected_config),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "remote.runtime-injected.url",
                "GIT_CONFIG_VALUE_0": "https://example.invalid/runtime.git",
            }
            with patch.dict(os.environ, polluted_environment, clear=False):
                stdout, stderr, returncode = compat.run_cmd(
                    ["git", "remote"],
                    cwd=target,
                    timeout=10,
                )

        self.assertEqual(returncode, 0, stderr)
        self.assertEqual(stdout.splitlines(), ["origin"])

    @unittest.skipUnless(shutil.which("git"), "Git is required for config isolation")
    def test_real_git_retains_only_transport_and_auth_process_config(self):
        real_git = os.path.abspath(shutil.which("git"))
        with tempfile.TemporaryDirectory() as tmp:
            repository = Path(tmp) / "repository"
            repository.mkdir()
            subprocess.run(
                [real_git, "init", "-q"],
                cwd=repository,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            inherited = {
                "JUA_GIT_EXECUTABLE": real_git,
                "GIT_CONFIG_COUNT": "6",
                "GIT_CONFIG_KEY_0": "credential.username",
                "GIT_CONFIG_VALUE_0": "auth-user",
                "GIT_CONFIG_KEY_1": "http.https://example.invalid/.extraHeader",
                "GIT_CONFIG_VALUE_1": "Authorization: Bearer count-secret",
                "GIT_CONFIG_KEY_2": "remote.origin.proxy",
                "GIT_CONFIG_VALUE_2": "http://proxy.example.invalid:8080",
                "GIT_CONFIG_KEY_3": "core.worktree",
                "GIT_CONFIG_VALUE_3": "/poisoned/worktree",
                "GIT_CONFIG_KEY_4": "safe.directory",
                "GIT_CONFIG_VALUE_4": "*",
                "GIT_CONFIG_KEY_5": "protocol.ext.allow",
                "GIT_CONFIG_VALUE_5": "always",
                "GIT_CONFIG_PARAMETERS": (
                    "'url.https://mirror.example.invalid/.insteadOf'='corp:' "
                    "'protocol.https.allow'='always' "
                    "'protocol.file.allow'='always' "
                    "'core.bare'='true'"
                ),
            }

            username = compat.run_cmd(
                ["git", "config", "--get", "credential.username"],
                cwd=repository,
                env=inherited,
                timeout=10,
            )
            header = compat.run_cmd(
                [
                    "git", "config", "--get",
                    "http.https://example.invalid/.extraHeader",
                ],
                cwd=repository,
                env=inherited,
                timeout=10,
            )
            rewrite = compat.run_cmd(
                [
                    "git", "config", "--get",
                    "url.https://mirror.example.invalid/.insteadOf",
                ],
                cwd=repository,
                env=inherited,
                timeout=10,
            )
            unsafe_worktree = compat.run_cmd(
                ["git", "config", "--get", "core.worktree"],
                cwd=repository,
                env=inherited,
                timeout=10,
            )
            unsafe_bare = compat.run_cmd(
                ["git", "config", "--get", "core.bare"],
                cwd=repository,
                env=inherited,
                timeout=10,
            )
            https_protocol = compat.run_cmd(
                ["git", "config", "--get", "protocol.https.allow"],
                cwd=repository,
                env=inherited,
                timeout=10,
            )
            unsafe_file_protocol = compat.run_cmd(
                ["git", "config", "--get", "protocol.file.allow"],
                cwd=repository,
                env=inherited,
                timeout=10,
            )
            unsafe_ext_protocol = compat.run_cmd(
                ["git", "config", "--get", "protocol.ext.allow"],
                cwd=repository,
                env=inherited,
                timeout=10,
            )
            unsafe_safe_directory = compat.run_cmd(
                ["git", "config", "--get", "safe.directory"],
                cwd=repository,
                env=inherited,
                timeout=10,
            )

        self.assertEqual(username, ("auth-user\n", "", 0))
        self.assertEqual(
            header,
            ("Authorization: Bearer count-secret\n", "", 0),
        )
        self.assertEqual(rewrite, ("corp:\n", "", 0))
        self.assertEqual(unsafe_worktree[2], 1, unsafe_worktree)
        # The repository's own core.bare=false remains authoritative; the
        # process-injected true value must not survive the boundary.
        self.assertEqual(unsafe_bare, ("false\n", "", 0))
        self.assertEqual(https_protocol, ("always\n", "", 0))
        self.assertEqual(unsafe_file_protocol[2], 1, unsafe_file_protocol)
        self.assertEqual(unsafe_ext_protocol[2], 1, unsafe_ext_protocol)
        self.assertEqual(unsafe_safe_directory[2], 1, unsafe_safe_directory)

    def test_git_config_filter_deduplicates_exact_pairs_but_keeps_distinct_headers(self):
        environment = {
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": "Authorization: Bearer one",
            "GIT_CONFIG_KEY_1": "HTTP.EXTRAHEADER",
            "GIT_CONFIG_VALUE_1": "Authorization: Bearer one",
            "GIT_CONFIG_KEY_2": "http.extraHeader",
            "GIT_CONFIG_VALUE_2": "X-Correlation-ID: two",
        }

        compat._sanitize_git_environment(environment)

        self.assertEqual(environment["GIT_CONFIG_COUNT"], "2")
        self.assertEqual(
            [environment[f"GIT_CONFIG_VALUE_{index}"] for index in range(2)],
            ["Authorization: Bearer one", "X-Correlation-ID: two"],
        )

    @unittest.skipUnless(shutil.which("git"), "Git is required for content integrity")
    def test_real_git_show_stdout_is_not_changed_by_diagnostic_redaction(self):
        real_git = os.path.abspath(shutil.which("git"))
        source = (
            "Authorization: Bearer source-token\n"
            "https://source-user:source-pass@example.invalid/repository.git\n"
            "http.extraHeader=Cookie: source-cookie\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            repository = Path(tmp) / "repository"
            repository.mkdir()

            def git(*arguments):
                return subprocess.run(
                    [real_git, *arguments],
                    cwd=repository,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

            git("init", "-q")
            git("config", "user.email", "content@example.invalid")
            git("config", "user.name", "Content Integrity")
            (repository / "source.txt").write_text(source, encoding="utf-8")
            git("add", "source.txt")
            git("commit", "-q", "-m", "content fixture")
            stdout, stderr, returncode = compat.run_cmd(
                ["git", "show", "HEAD:source.txt"],
                cwd=repository,
                env={"JUA_GIT_EXECUTABLE": real_git},
                timeout=10,
            )

        self.assertEqual(returncode, 0, stderr)
        self.assertEqual(stdout, source)
        self.assertEqual(stderr, "")

    @unittest.skipIf(os.name == "nt", "test double uses a POSIX executable script")
    def test_git_stream_relay_and_diagnostics_redact_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_git = Path(tmp) / "git"
            fake_git.write_text(
                """#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "git version test-double"
  exit 0
fi
echo "fetch https://alice:swordfish@example.invalid/repository.git"
echo "http.extraHeader=Cookie: stdout-cookie"
echo "Proxy-Authorization: Basic stderr-token" >&2
echo "remote https://bob:password@example.invalid/repository.git" >&2
echo "query https://example.invalid/repository.git?access_token=query-secret&depth=1" >&2
echo "scp deploy-token@example.invalid:team/repository.git" >&2
""",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            relayed = compat.io.StringIO()
            with patch.dict(
                os.environ,
                {"JUA_GIT_EXECUTABLE": str(fake_git)},
                clear=False,
            ), patch.object(compat.sys, "stderr", relayed):
                stdout, stderr, returncode = compat.run_cmd(
                    ["git", "show-secrets"],
                    stream_output=True,
                    timeout=10,
                )

        self.assertEqual(returncode, 0, stderr)
        self.assertIn("alice:swordfish", stdout)
        self.assertIn("stdout-cookie", stdout)
        self.assertNotIn("stderr-token", stderr)
        self.assertNotIn("bob:password", stderr)
        self.assertIn("Proxy-Authorization: <redacted>", stderr)
        self.assertIn("https://<redacted>@example.invalid/repository.git", stderr)
        relay_text = relayed.getvalue()
        for secret in (
            "alice", "swordfish", "stdout-cookie",
            "stderr-token", "bob", "password", "query-secret", "deploy-token",
        ):
            self.assertNotIn(secret, relay_text)
        self.assertIn("https://<redacted>@example.invalid/repository.git", relay_text)
        self.assertIn("http.extraHeader=<redacted>", relay_text)
        self.assertIn("Proxy-Authorization: <redacted>", relay_text)
        self.assertIn("access_token=<redacted>", relay_text)
        self.assertIn("<redacted>@example.invalid:team/repository.git", relay_text)

    @unittest.skipIf(os.name == "nt", "test double uses a POSIX executable script")
    def test_git_timeout_redacts_credentials_from_echoed_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_git = Path(tmp) / "git"
            fake_git.write_text(
                """#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "git version test-double"
  exit 0
fi
sleep 30
""",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            with patch.dict(
                os.environ,
                {"JUA_GIT_EXECUTABLE": str(fake_git)},
                clear=False,
            ):
                _stdout, stderr, returncode = compat.run_cmd(
                    [
                        "git",
                        "-c",
                        "http.extraHeader=Authorization: Bearer timeout-token",
                        "ls-remote",
                        "https://timeout-user:timeout-pass@example.invalid/repo.git?token=query-timeout-secret",
                    ],
                    timeout=0.1,
                )

        self.assertEqual(returncode, -1)
        self.assertIn("命令超时", stderr)
        for secret in (
            "timeout-token", "timeout-user", "timeout-pass", "query-timeout-secret",
        ):
            self.assertNotIn(secret, stderr)
        self.assertIn("<redacted>", stderr)

    @unittest.skipIf(os.name == "nt", "test double uses a POSIX executable script")
    def test_git_execution_exception_is_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_git = Path(tmp) / "git"
            fake_git.write_text(
                "#!/bin/sh\necho 'git version test-double'\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            with patch.dict(
                os.environ,
                {"JUA_GIT_EXECUTABLE": str(fake_git)},
                clear=False,
            ):
                self.assertEqual(compat.find_executable("git"), str(fake_git))
                with patch.object(
                    compat.subprocess,
                    "Popen",
                    side_effect=RuntimeError(
                        "Authorization: Bearer exception-token at "
                        "https://exception-user:exception-pass@example.invalid/repo.git"
                    ),
                ):
                    _stdout, stderr, returncode = compat.run_cmd(
                        ["git", "ls-remote", "origin"],
                        timeout=10,
                    )

        self.assertEqual(returncode, -1)
        self.assertIn("执行异常：RuntimeError", stderr)
        for secret in (
            "exception-token", "exception-user", "exception-pass",
        ):
            self.assertNotIn(secret, stderr)
        self.assertIn("Authorization: <redacted>", stderr)

    @unittest.skipIf(os.name == "nt", "POSIX process-group semantics only")
    def test_git_timeout_terminates_descendant_process_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_git = root / "git"
            child_pid_file = root / "child.pid"
            fake_git.write_text(
                """#!/usr/bin/env python3
import os
import subprocess
import sys
import time
from pathlib import Path

if "--version" in sys.argv:
    print("git version test-double")
    raise SystemExit(0)

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
Path(os.environ["JUA_CHILD_PID_FILE"]).write_text(str(child.pid), encoding="utf-8")
time.sleep(60)
""",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            with patch.dict(
                os.environ,
                {
                    "JUA_GIT_EXECUTABLE": str(fake_git),
                    "JUA_CHILD_PID_FILE": str(child_pid_file),
                },
                clear=False,
            ):
                _stdout, stderr, returncode = compat.run_cmd(
                    ["git", "hang"],
                    timeout=0.5,
                )

            self.assertEqual(returncode, -1)
            self.assertIn("命令超时", stderr)
            self.assertTrue(child_pid_file.is_file())
            child_pid = int(child_pid_file.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 3
            child_alive = True
            while time.monotonic() < deadline:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    child_alive = False
                    break
                proc_stat = Path(f"/proc/{child_pid}/stat")
                if proc_stat.is_file():
                    fields = proc_stat.read_text(encoding="utf-8").split()
                    if len(fields) > 2 and fields[2] == "Z":
                        child_alive = False
                        break
                time.sleep(0.05)

        self.assertFalse(child_alive, "timed-out Git descendant remained alive")

    @unittest.skipIf(os.name == "nt", "POSIX process-group semantics only")
    def test_non_git_timeout_terminates_descendant_after_root_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            helper = root / "foreground_parent.py"
            child_pid_file = root / "child.pid"
            helper.write_text(
                """import subprocess
import sys
import time
from pathlib import Path

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
Path(sys.argv[1]).write_text(str(child.pid), encoding="utf-8")
time.sleep(0.1)
""",
                encoding="utf-8",
            )
            _stdout, stderr, returncode = compat.run_cmd(
                [sys.executable, str(helper), str(child_pid_file)],
                timeout=0.5,
            )

            self.assertEqual(returncode, -1)
            self.assertIn("命令超时", stderr)
            self.assertTrue(child_pid_file.is_file())
            child_pid = int(child_pid_file.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 3
            child_alive = True
            while time.monotonic() < deadline:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    child_alive = False
                    break
                proc_stat = Path(f"/proc/{child_pid}/stat")
                if proc_stat.is_file():
                    fields = proc_stat.read_text(encoding="utf-8").split()
                    if len(fields) > 2 and fields[2] == "Z":
                        child_alive = False
                        break
                time.sleep(0.05)

        self.assertFalse(child_alive, "timed-out non-Git descendant remained alive")

    def test_non_git_pipe_failure_terminates_managed_process_tree(self):
        process = SimpleNamespace(
            pid=43210, stdin=None, stdout=None, stderr=None, returncode=None,
        )
        process.communicate = lambda input=None, timeout=None: (_ for _ in ()).throw(
            OSError("capture pipe failed")
        )
        with patch.object(compat, "managed_popen", return_value=process), patch.object(
            compat, "_terminate_subprocess",
        ) as terminate:
            _stdout, stderr, returncode = compat.run_cmd(
                [sys.executable, "-c", "pass"], timeout=1,
            )

        self.assertEqual(returncode, -1)
        self.assertIn("执行异常：OSError", stderr)
        terminate.assert_called_once_with(process, process_group=True)

    def test_managed_subprocess_timeout_preserves_exception_after_tree_cleanup(self):
        timeout_error = subprocess.TimeoutExpired(["worker"], 0.1)
        calls = []
        process = SimpleNamespace(returncode=None)

        def communicate(input=None, timeout=None):
            calls.append((input, timeout))
            if len(calls) == 1:
                raise timeout_error
            return b"partial-out", b"partial-error"

        process.communicate = communicate
        with patch.object(
            compat, "managed_popen", return_value=process,
        ), patch.object(
            compat, "terminate_process_tree",
        ) as terminate:
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                compat.run_managed_subprocess(
                    ["worker"], capture_output=True, timeout=0.1,
                )

        self.assertIs(raised.exception, timeout_error)
        self.assertEqual(raised.exception.output, b"partial-out")
        self.assertEqual(raised.exception.stderr, b"partial-error")
        terminate.assert_called_once_with(process)
        self.assertEqual(calls, [(None, 0.1), (None, 5)])

    @unittest.skipIf(os.name == "nt", "POSIX process-group semantics only")
    def test_managed_process_group_can_be_claimed_for_termination_only_once(self):
        process = SimpleNamespace(pid=43210, returncode=None)
        process.poll = lambda: None
        process.kill = lambda: None
        process.wait = lambda timeout=None: -9
        compat._register_managed_process_tree(process)
        self.addCleanup(compat._unregister_managed_process_tree, process)

        with patch.object(compat.os, "killpg") as kill_group:
            compat.terminate_process_tree(process)
            compat.terminate_process_tree(process)

        kill_group.assert_called_once_with(process.pid, signal.SIGKILL)
        self.assertNotIn(process.pid, compat._POSIX_MANAGED_PROCESS_GROUPS)

    def test_windows_released_token_cannot_target_reused_pid(self):
        def process(pid, returncode):
            item = SimpleNamespace(
                pid=pid, returncode=returncode,
                kill=lambda: None, wait=lambda timeout=None: returncode,
            )
            item.poll = lambda: item.returncode
            return item

        old = process(43210, 0)
        replacement = process(43210, None)
        setattr(old, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE, 101)
        setattr(replacement, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE, 202)

        def consume_job(item, *, terminate):
            self.assertTrue(
                getattr(item, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE, None)
            )
            delattr(item, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE)
            return terminate

        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat, "_release_windows_managed_job", side_effect=consume_job,
        ) as release_job, patch.object(
            compat.subprocess, "run",
        ) as taskkill:
            compat._register_managed_process_tree(old)
            compat.release_process_tree(old)
            compat._register_managed_process_tree(replacement)

            compat.terminate_process_tree(old)

            self.assertEqual(release_job.call_count, 1)
            compat.terminate_process_tree(replacement)

        self.assertEqual(release_job.call_count, 2)
        self.assertIs(release_job.call_args_list[0].args[0], old)
        self.assertEqual(
            release_job.call_args_list[0].kwargs, {"terminate": False}
        )
        self.assertIs(release_job.call_args_list[1].args[0], replacement)
        self.assertEqual(
            release_job.call_args_list[1].kwargs, {"terminate": True}
        )
        taskkill.assert_not_called()
        self.assertFalse(hasattr(old, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE))
        self.assertFalse(
            hasattr(replacement, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE)
        )
        self.assertFalse(
            hasattr(old, compat._MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE)
        )
        self.assertFalse(
            hasattr(replacement, compat._MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE)
        )

    def test_windows_release_and_terminate_race_consumes_one_owner(self):
        process = SimpleNamespace(pid=54321, returncode=0)
        process.poll = lambda: process.returncode
        process.kill = lambda: None
        process.wait = lambda timeout=None: process.returncode
        setattr(process, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE, 303)
        barrier = threading.Barrier(3)
        failures = []

        def invoke(action):
            try:
                barrier.wait(timeout=2)
                action(process)
            except BaseException as error:
                failures.append(error)

        def consume_job(item, *, terminate):
            self.assertTrue(
                getattr(item, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE, None)
            )
            delattr(item, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE)
            return terminate

        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat, "_release_windows_managed_job", side_effect=consume_job,
        ) as release_job, patch.object(
            compat.subprocess, "run",
        ) as taskkill:
            compat._register_managed_process_tree(process)
            releaser = threading.Thread(
                target=invoke, args=(compat.release_process_tree,)
            )
            terminator = threading.Thread(
                target=invoke, args=(compat.terminate_process_tree,)
            )
            releaser.start()
            terminator.start()
            barrier.wait(timeout=2)
            releaser.join(timeout=2)
            terminator.join(timeout=2)

        self.assertFalse(releaser.is_alive())
        self.assertFalse(terminator.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(release_job.call_count, 1)
        self.assertIn(
            release_job.call_args.kwargs,
            ({"terminate": False}, {"terminate": True}),
        )
        taskkill.assert_not_called()
        self.assertFalse(
            hasattr(process, compat._WINDOWS_JOB_HANDLE_ATTRIBUTE)
        )
        self.assertFalse(
            hasattr(process, compat._MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE)
        )
        self.assertNotIn(
            getattr(
                process, compat._MANAGED_PROCESS_TREE_TOKEN_ATTRIBUTE, None
            ),
            compat._MANAGED_PROCESS_TREES,
        )

    @unittest.skipIf(os.name == "nt", "POSIX ownership semantics only")
    def test_posix_same_pid_tokens_cannot_claim_another_process_object(self):
        old = SimpleNamespace(pid=65432)
        replacement = SimpleNamespace(pid=65432)
        with patch.object(
            compat, "_ensure_managed_sigterm_handler",
        ), patch.object(
            compat, "_restore_managed_sigterm_handler",
        ):
            compat._register_managed_process_tree(old)
            self.assertTrue(compat._unregister_managed_process_tree(old))
            compat._register_managed_process_tree(replacement)

            self.assertFalse(compat._claim_managed_process_tree(old))
            self.assertTrue(compat._claim_managed_process_tree(replacement))

        self.assertEqual(compat._POSIX_MANAGED_PROCESS_GROUPS, set())

    @unittest.skipIf(os.name == "nt", "POSIX signal semantics only")
    def test_sigterm_to_manager_terminates_isolated_foreground_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child_pid_path = root / "child.pid"
            parent_script = root / "command_parent.py"
            manager_script = root / "manager.py"
            parent_script.write_text(
                """import subprocess
import sys
import time
from pathlib import Path

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
Path(sys.argv[1]).write_text(str(child.pid), encoding="utf-8")
time.sleep(60)
""",
                encoding="utf-8",
            )
            manager_script.write_text(
                """import sys
sys.path.insert(0, sys.argv[1])
import compat
compat.run_cmd([sys.executable, sys.argv[2], sys.argv[3]], timeout=60)
""",
                encoding="utf-8",
            )
            manager = subprocess.Popen([
                sys.executable,
                str(manager_script),
                str(ROOT / "scripts"),
                str(parent_script),
                str(child_pid_path),
            ])
            child_pid = None
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and not child_pid_path.is_file():
                    time.sleep(0.05)
                self.assertTrue(child_pid_path.is_file(), "child PID was not published")
                child_pid = int(child_pid_path.read_text(encoding="utf-8"))
                os.kill(manager.pid, signal.SIGTERM)
                manager.wait(timeout=5)

                deadline = time.monotonic() + 3
                child_alive = True
                while time.monotonic() < deadline:
                    try:
                        os.kill(child_pid, 0)
                    except ProcessLookupError:
                        child_alive = False
                        break
                    proc_stat = Path(f"/proc/{child_pid}/stat")
                    if proc_stat.is_file():
                        fields = proc_stat.read_text(encoding="utf-8").split()
                        if len(fields) > 2 and fields[2] == "Z":
                            child_alive = False
                            break
                    time.sleep(0.05)
            finally:
                if manager.poll() is None:
                    manager.kill()
                    manager.wait(timeout=5)
                if child_pid is not None:
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

        self.assertLess(manager.returncode, 0)
        self.assertFalse(child_alive, "SIGTERM left managed descendant alive")

    @unittest.skipIf(os.name == "nt", "POSIX signal semantics only")
    def test_concurrent_managed_groups_restore_previous_sigterm_handler(self):
        previous = signal.getsignal(signal.SIGTERM)

        def custom_handler(_signum, _frame):
            return None

        first = second = None
        try:
            signal.signal(signal.SIGTERM, custom_handler)
            first = compat.managed_popen([
                sys.executable, "-c", "import time; time.sleep(0.2)",
            ])
            second = compat.managed_popen([
                sys.executable, "-c", "import time; time.sleep(0.2)",
            ])
            self.assertIs(signal.getsignal(signal.SIGTERM), compat._managed_sigterm_handler)
            self.assertEqual(
                compat._POSIX_MANAGED_PROCESS_GROUPS,
                {first.pid, second.pid},
            )

            first.wait(timeout=5)
            compat.release_process_tree(first)
            self.assertIs(signal.getsignal(signal.SIGTERM), compat._managed_sigterm_handler)
            self.assertEqual(compat._POSIX_MANAGED_PROCESS_GROUPS, {second.pid})

            second.wait(timeout=5)
            compat.release_process_tree(second)
            self.assertIs(signal.getsignal(signal.SIGTERM), custom_handler)
            self.assertEqual(compat._POSIX_MANAGED_PROCESS_GROUPS, set())
        finally:
            for process in (first, second):
                if process is not None and process.poll() is None:
                    compat.terminate_process_tree(process)
            signal.signal(signal.SIGTERM, previous)
            compat._MANAGED_SIGTERM_HANDLER_INSTALLED = False
            compat._PREVIOUS_SIGTERM_HANDLER = None
            compat._POSIX_MANAGED_PROCESS_GROUPS.clear()
            compat._MANAGED_PROCESS_TREES.clear()

    @unittest.skipIf(os.name == "nt", "POSIX signal semantics only")
    def test_parallel_process_cleanup_restores_signal_state_on_owner_thread(self):
        previous = signal.getsignal(signal.SIGTERM)
        process = None
        try:
            process = compat.managed_popen([
                sys.executable, "-c", "pass",
            ])
            process.wait(timeout=5)
            releaser = threading.Thread(
                target=compat.release_process_tree,
                args=(process,),
            )
            releaser.start()
            releaser.join(timeout=5)

            self.assertFalse(releaser.is_alive())
            self.assertEqual(compat._POSIX_MANAGED_PROCESS_GROUPS, set())
            self.assertIs(
                signal.getsignal(signal.SIGTERM),
                compat._managed_sigterm_handler,
            )

            compat.finalize_parallel_process_tree_cleanup()

            self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
            self.assertFalse(compat._MANAGED_SIGTERM_HANDLER_INSTALLED)
            self.assertIsNone(compat._PREVIOUS_SIGTERM_HANDLER)
        finally:
            if process is not None and process.poll() is None:
                compat.terminate_process_tree(process)
            compat.finalize_parallel_process_tree_cleanup()

    def test_bare_git_command_is_replaced_with_validated_absolute_path(self):
        with patch.object(
            compat, "find_executable", return_value="/Users/example/.local/bin/git"
        ):
            resolved = compat.resolve_command(["git", "status", "--short"])

        self.assertEqual(
            resolved,
            ["/Users/example/.local/bin/git", "status", "--short"],
        )

    def test_validated_git_is_cached_for_repeated_commands(self):
        compat._GIT_EXECUTABLE_CACHE.clear()
        with patch.object(compat.Path, "home", return_value=Path("/Users/cache-test")), \
                patch.object(compat.shutil, "which", return_value="/usr/bin/git"), \
                patch.object(compat, "_git_executable_works", return_value=True) as probe, \
                patch.dict(os.environ, {"JUA_GIT_EXECUTABLE": ""}, clear=False):
            first = compat.find_executable("git")
            second = compat.find_executable("git")

        self.assertEqual(first, second)
        probe.assert_called_once()

    def test_workflow_declares_mandatory_os_jdk_tool_and_evidence_matrix(self):
        workflow = ROOT / ".github" / "workflows" / "platform-contract.yml"
        text = workflow.read_text(encoding="utf-8")

        for value in (
            "ubuntu-latest", "macos-latest", "windows-2022", "windows-2025",
        ):
            self.assertIn(value, text)
        self.assertRegex(text, r'java:\s*\["11",\s*"17",\s*"21"\]')
        self.assertIn('java-version: "8"', text)
        self.assertIn('java-version: "17"', text)
        self.assertIn('echo "JAVA8_HOME=${JAVA_HOME}"', text)
        self.assertIn('echo "JAVA17_HOME=${JAVA_HOME}"', text)
        self.assertIn("gradle/actions/setup-gradle@v6", text)
        self.assertIn('gradle-version: "8.10.2"', text)
        self.assertIn("gradle --version", text)
        self.assertIn('python-version: "3.12"', text)
        self.assertIn("mvn -version", text)
        self.assertNotIn("cache: maven", text)
        self.assertIn("timeout-minutes:", text)
        self.assertIn("actions/upload-artifact@v4", text)
        self.assertIn("platform-contract.json", text)
        self.assertIn("test_suite_runner.py --suite windows", text)
        self.assertIn("windows-native-suite.json", text)
        self.assertIn("steps.windows_suite.outcome", text)
        self.assertIn("gate|windows-native-suite-report|missing", text)
        self.assertIn("gate|windows-native-suite|", text)
        self.assertIn("step|setup-windows-java8|", text)
        self.assertIn("step|setup-windows-java17|", text)
        self.assertIn("step|setup-windows-gradle|", text)
        self.assertIn("step|verify-windows-gradle|", text)
        self.assertIn('test "${#cell_files[@]}" -eq 12', text)
        self.assertIn('[[ "${MATRIX_OS}" == windows-* ]]', text)
        self.assertIn('sys.argv[4].startswith("windows-")', text)
        self.assertIn("push:", text)
        self.assertIn('- "main"', text)
        self.assertIn('- "codex/**"', text)
        self.assertIn("platform-evidence:", text)
        self.assertIn("needs: platform-contract", text)
        self.assertIn("always() && github.event_name == 'push'", text)
        self.assertIn("needs.platform-contract.result", text)
        self.assertIn("contents: write", text)
        self.assertIn("platform-contract-verified-${GITHUB_SHA}", text)
        self.assertIn("platform-contract-failed-${GITHUB_SHA}", text)
        self.assertIn("platform-contract-cell-${CELL_STATUS}-${MATRIX_OS}-jdk${MATRIX_JAVA}-${GITHUB_SHA}", text)
        self.assertIn("CELL_STATUS: ${{ job.status }}", text)
        self.assertIn("steps.quality_gate.outcome", text)
        self.assertIn("platform-contract-step-${STEP_OUTCOME}-${STEP_NAME}-${MATRIX_OS}-jdk${MATRIX_JAVA}-${GITHUB_SHA}", text)
        self.assertIn("platform-contract-gate-${GATE_STATUS}-${GATE_NAME}-${MATRIX_OS}-jdk${MATRIX_JAVA}-${GITHUB_SHA}", text)
        self.assertIn("platform-contract-benchmark-${BENCHMARK_STATUS}-${BENCHMARK_NAME}-${MATRIX_OS}-jdk${MATRIX_JAVA}-${GITHUB_SHA}", text)
        self.assertIn("steps.quality_gate.outcome == 'failure'", text)
        self.assertIn("steps.windows_suite.outcome == 'failure'", text)
        for diagnostic in (
            "steps.diag_artifact_facts.outcome",
            "steps.diag_runtime_bytecode.outcome",
            "steps.diag_runtime_reconciliation.outcome",
            "steps.diag_decision_projection.outcome",
        ):
            self.assertIn(diagnostic, text)
        self.assertIn("gate|quality-gate-report|missing", text)
        self.assertNotIn("jua-platform-contract", text)
        self.assertNotIn("platform-contract-smoke-", text)
        self.assertNotIn("continue-on-error", text)

    def test_run_cmd_preserves_unicode_space_and_metacharacter_arguments(self):
        with tempfile.TemporaryDirectory(prefix="jua 平台 ; ") as tmp:
            value = str(Path(tmp) / "参数 with spaces;not-shell")
            stdout, stderr, returncode = run_cmd(
                [sys.executable, "-c", "import sys; print(sys.argv[1])", value],
                timeout=10,
            )

        self.assertEqual(returncode, 0, stderr)
        self.assertEqual(stdout.strip(), value)

    def test_platform_workflow_has_no_shell_specific_absolute_tmp_path(self):
        text = (ROOT / ".github" / "workflows" / "platform-contract.yml").read_text(
            encoding="utf-8"
        )

        self.assertIsNone(re.search(r"(?:/tmp/|/private/tmp/|[A-Za-z]:\\\\)", text))


if __name__ == "__main__":
    unittest.main()
