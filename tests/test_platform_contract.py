import ast
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
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
                compat.subprocess,
                "run",
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

        for value in ("ubuntu-latest", "macos-latest", "windows-latest"):
            self.assertIn(value, text)
        self.assertRegex(text, r'java:\s*\["11",\s*"17",\s*"21"\]')
        self.assertIn('python-version: "3.12"', text)
        self.assertIn("mvn -version", text)
        self.assertNotIn("cache: maven", text)
        self.assertIn("timeout-minutes:", text)
        self.assertIn("actions/upload-artifact@v4", text)
        self.assertIn("platform-contract.json", text)
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
