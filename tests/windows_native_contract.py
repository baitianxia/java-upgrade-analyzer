"""Native Windows contracts loaded only by the governed Windows test suite.

The file deliberately does not match unittest's ``test*.py`` discovery
pattern. Non-Windows runs must not turn these contracts into reassuring skips;
``scripts/test_suite_runner.py --suite windows`` loads them explicitly and
fails closed unless it is executing on a native Windows host.
"""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import warnings
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import compat  # noqa: E402
import binary_artifact_diff  # noqa: E402
import binary_output  # noqa: E402
import binary_pipeline  # noqa: E402
import binary_report  # noqa: E402
import binary_validation_oracle  # noqa: E402
import path_runtime  # noqa: E402
import run_step  # noqa: E402
from binary_tool_execution import (  # noqa: E402
    execute_binary_tool,
    tool_failure_is_retryable,
)
from process_metrics import (  # noqa: E402
    system_available_memory_bytes,
    windows_current_process_usage,
)


class WindowsNativeContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.name != "nt" or sys.platform != "win32":
            raise AssertionError("WINDOWS_NATIVE_CONTRACT_REQUIRES_WINDOWS")
        cls.python = Path(sys.executable).with_name("python.exe")
        cls.pythonw = Path(sys.executable).with_name("pythonw.exe")
        cls.git = shutil.which("git")

    def setUp(self):
        compat._GIT_EXECUTABLE_CACHE.clear()

    def test_required_native_toolchain_is_available(self):
        missing = []
        for name, candidate in (
            ("python.exe", str(self.python) if self.python.is_file() else ""),
            ("pythonw.exe", str(self.pythonw) if self.pythonw.is_file() else ""),
            ("git.exe", self.git),
            ("java.exe", shutil.which("java")),
            ("javac.exe", shutil.which("javac")),
            ("mvn.cmd", shutil.which("mvn")),
            ("gradle.bat", shutil.which("gradle")),
        ):
            if not candidate:
                missing.append(name)

        for major in (8, 17):
            variable = f"JAVA{major}_HOME"
            home_value = os.environ.get(variable, "").strip()
            if not home_value:
                missing.append(variable)
                continue
            home = Path(home_value)
            release = home / "release"
            java = home / "bin" / "java.exe"
            javac = home / "bin" / "javac.exe"
            if not release.is_file() or not java.is_file() or not javac.is_file():
                missing.append(f"{variable}:invalid-jdk")
                continue
            version_line = next(
                (
                    line for line in release.read_text(
                        encoding="utf-8", errors="replace",
                    ).splitlines()
                    if line.startswith("JAVA_VERSION=")
                ),
                "",
            )
            version = version_line.split("=", 1)[-1].strip().strip('"')
            actual_major = (
                version.split(".", 2)[1]
                if version.startswith("1.")
                else version.split(".", 1)[0]
            )
            if actual_major != str(major):
                missing.append(f"{variable}:expected-{major}-got-{actual_major}")

        self.assertEqual(missing, [], f"WINDOWS_NATIVE_TOOLCHAIN_MISSING:{missing}")

    def test_native_process_metrics_report_cpu_and_peak_memory(self):
        usage = windows_current_process_usage()

        self.assertIsNotNone(usage)
        self.assertGreaterEqual(usage.user_seconds, 0)
        self.assertGreaterEqual(usage.system_seconds, 0)
        self.assertGreater(usage.peak_rss_bytes, 0)

    def test_native_available_memory_preflight_reports_physical_bytes(self):
        available = system_available_memory_bytes()

        self.assertIsInstance(available, int)
        self.assertGreater(available, 0)

    def test_native_generation_file_fsync_accepts_owned_file(self):
        with tempfile.TemporaryDirectory(prefix="jua fsync ") as tmp:
            target = Path(tmp) / "generation.json"
            target.write_text("{}\n", encoding="utf-8")

            binary_output._fsync_regular_file(target)

    def test_native_report_file_fsync_accepts_owned_file(self):
        with tempfile.TemporaryDirectory(prefix="jua report fsync ") as tmp:
            target = Path(tmp) / "report.json"
            content = b"{}\n"
            target.write_bytes(content)

            digest = binary_report._report_file_sha256(
                target, make_durable=True
            )

        self.assertEqual(digest, hashlib.sha256(content).hexdigest())

    def test_native_checkpoint_write_read_roundtrip_is_exact(self):
        with tempfile.TemporaryDirectory(prefix="jua checkpoint ") as tmp:
            output = Path(tmp) / "binary-output"
            payload = {
                "schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA,
                "status": "awaiting_independent_validation",
                "result_generation_identity": "a" * 64,
            }

            persisted = binary_pipeline._write_resume_checkpoint_roundtrip(
                output, payload
            )

        self.assertEqual(
            persisted["checkpoint_content_identity"],
            binary_pipeline._resume_checkpoint_content_identity(persisted),
        )
        self.assertEqual(persisted["schema"], payload["schema"])

    def test_run_step_native_checkpoint_dispatch_uses_windows_safe_leaf_operations(self):
        """Exercise callers whose POSIX branches rely on descriptor-relative APIs."""

        with tempfile.TemporaryDirectory(prefix="jua run-step checkpoint ") as tmp:
            report = Path(tmp).resolve()
            checkpoint = run_step._step4_validation_checkpoint_path(report)
            checkpoint.parent.mkdir(parents=True)
            payload = {"schema": "fixture", "status": "ready"}
            checkpoint.write_text(
                json.dumps(payload, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

            self.assertEqual(
                run_step._read_step4_validation_checkpoint(report), payload,
            )
            run_step._delete_step4_validation_checkpoint_durable(checkpoint)
            self.assertFalse(checkpoint.exists())

            ordinary = report / "evidence" / "owned.txt"
            ordinary.parent.mkdir(parents=True)
            ordinary.write_text("owned", encoding="utf-8")
            self.assertTrue(
                run_step._remove_step_output_without_following_parent_links(
                    report, ordinary,
                )
            )
            self.assertFalse(ordinary.exists())

    def test_native_path_and_descriptor_checkpoint_identity_match(self):
        with tempfile.TemporaryDirectory(prefix="jua checkpoint stat ") as tmp:
            target = Path(tmp) / "checkpoint.json"
            target.write_text("{}\n", encoding="utf-8")
            path_stat = os.lstat(target)
            descriptor = os.open(
                target, os.O_RDONLY | int(getattr(os, "O_BINARY", 0) or 0)
            )
            try:
                descriptor_stat = os.fstat(descriptor)
            finally:
                os.close(descriptor)

        self.assertEqual(
            binary_pipeline._checkpoint_stat_identity(path_stat),
            binary_pipeline._checkpoint_stat_identity(descriptor_stat),
        )
        self.assertEqual(
            run_step._step4_checkpoint_stat_identity(path_stat),
            run_step._step4_checkpoint_stat_identity(descriptor_stat),
        )

    def test_native_duplicate_maven_metadata_policy_is_symmetric(self):
        with tempfile.TemporaryDirectory(prefix="jua duplicate maven ") as tmp:
            artifact = Path(tmp) / "jmxmon.jar"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr(
                        "META-INF/maven/example/jmxmon/pom.xml", b"first"
                    )
                    archive.writestr(
                        "META-INF/maven/example/jmxmon/pom.xml", b"second"
                    )
            with zipfile.ZipFile(artifact) as archive:
                selected, _target_required = (
                    binary_artifact_diff.select_runtime_resource_entries(
                        archive, 17
                    )
                )
            inventory = binary_validation_oracle._archive_inventory(
                artifact, 17
            )

        self.assertEqual(selected, {})
        self.assertEqual(inventory["failures"], [])
        self.assertEqual(inventory["resources"], {})

    def test_native_tool_failures_are_typed_without_shell(self):
        cases = (
            (
                "missing",
                [str(Path(tempfile.gettempdir()) / "jua-missing-tool.exe")],
                1.0,
                True,
                "missing",
                False,
            ),
            (
                "nonzero",
                [str(self.python), "-c", "raise SystemExit(17)"],
                5.0,
                False,
                "nonzero_exit",
                False,
            ),
            (
                "timeout",
                [str(self.python), "-c", "import time; time.sleep(30)"],
                0.05,
                False,
                "timeout",
                True,
            ),
            (
                "empty",
                [str(self.python), "-c", "pass"],
                5.0,
                True,
                "output_empty",
                False,
            ),
        )
        for name, command, timeout, require_stdout, kind, retryable in cases:
            with self.subTest(name=name):
                result = execute_binary_tool(
                    command,
                    stage="windows-native",
                    reason_prefix="WINDOWS_NATIVE_TOOL",
                    timeout_seconds=timeout,
                    require_stdout=require_stdout,
                )

                self.assertFalse(result.succeeded)
                self.assertIsNotNone(result.failure)
                self.assertEqual(result.failure.failure_kind, kind)
                self.assertEqual(
                    tool_failure_is_retryable(result.failure), retryable
                )

    def test_pythonw_parent_captures_unicode_and_metacharacter_argument(self):
        self.assertTrue(self.python.is_file(), "python.exe is required")
        self.assertTrue(self.pythonw.is_file(), "pythonw.exe is required")
        value = "中文 path with spaces ; & | < > ^ % ! (literal)"
        with tempfile.TemporaryDirectory(prefix="jua pythonw 参数 ") as tmp:
            root = Path(tmp)
            probe = root / "gui_parent_probe.py"
            result_path = root / "result.json"
            probe.write_text(
                "\n".join((
                    "import json, sys",
                    "from pathlib import Path",
                    "sys.path.insert(0, sys.argv[1])",
                    "from compat import run_cmd",
                    "out, err, rc = run_cmd([",
                    "    sys.argv[2], '-c',",
                    "    'import sys; print(sys.argv[1])', sys.argv[4]",
                    "], timeout=20)",
                    "Path(sys.argv[3]).write_text(json.dumps({",
                    "    'stdout': out, 'stderr': err, 'returncode': rc",
                    "}, ensure_ascii=False), encoding='utf-8')",
                )) + "\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    str(self.pythonw), str(probe), str(ROOT / "scripts"),
                    str(self.python), str(result_path), value,
                ],
                timeout=60,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
            )
            self.assertEqual(completed.returncode, 0)
            self.assertTrue(result_path.is_file(), "pythonw probe produced no evidence")
            result = json.loads(result_path.read_text(encoding="utf-8"))

        self.assertEqual(result["returncode"], 0, result["stderr"])
        self.assertEqual(result["stderr"], "")
        self.assertEqual(result["stdout"].rstrip("\r\n"), value)

    def test_cmd_and_bat_wrappers_preserve_unicode_and_metacharacters(self):
        self.assertTrue(self.python.is_file(), "python.exe is required")
        value = "中文 path with spaces & | < > ^ ! 100% (literal)"
        with tempfile.TemporaryDirectory(prefix="jua wrapper 参数 ") as tmp:
            root = Path(tmp)
            probe = root / "wrapper_probe.py"
            probe.write_text(
                "import json, sys\n"
                "from pathlib import Path\n"
                "Path(sys.argv[1]).write_text(json.dumps({"
                "'value': sys.argv[2]}, ensure_ascii=False), encoding='utf-8')\n",
                encoding="utf-8",
            )
            for wrapper_name, command_factory in (
                ("mvnw.cmd", compat.mvn_cmd),
                ("gradlew.bat", compat.gradle_cmd),
            ):
                with self.subTest(wrapper=wrapper_name):
                    project = root / wrapper_name.replace(".", "-")
                    project.mkdir()
                    wrapper = project / wrapper_name
                    wrapper.write_text(
                        "@echo off\r\n"
                        '"%~1" "%~2" "%~3" "%~4"\r\n'
                        "exit /b %errorlevel%\r\n",
                        encoding="utf-8",
                        newline="",
                    )
                    result_path = project / "结果 with spaces.json"
                    command = command_factory(project) + [
                        str(self.python), str(probe), str(result_path), value,
                    ]
                    stdout, stderr, returncode = compat.run_cmd(
                        command, cwd=project, timeout=30,
                    )
                    self.assertEqual(returncode, 0, stderr or stdout)
                    self.assertEqual(
                        json.loads(result_path.read_text(encoding="utf-8")),
                        {"value": value},
                    )

    def test_near_limit_unicode_path_survives_git_and_atomic_json(self):
        self.assertTrue(self.git, "Git for Windows is required")
        with tempfile.TemporaryDirectory(prefix="jua path budget ") as tmp:
            repository = Path(tmp) / "仓库 with spaces"
            repository.mkdir()
            relative_parts = []
            target = repository / "状态.json"
            while len(str(target)) < 220:
                relative_parts.append(
                    f"路径-{len(relative_parts):02d}-" + ("x" * 10)
                )
                target = repository.joinpath(*relative_parts, "状态.json")
            self.assertGreaterEqual(len(str(target)), 220)
            self.assertLessEqual(
                len(str(target)), path_runtime.WINDOWS_SAFE_PATH_LENGTH,
            )
            target.parent.mkdir(parents=True)
            expected = {"路径": target.relative_to(repository).as_posix()}
            run_step.write_json(target, expected)

            def git(*arguments, required_stdout=False):
                stdout, stderr, returncode = compat.run_cmd(
                    compat.git_cmd() + ["-C", str(repository), *arguments],
                    timeout=30,
                )
                self.assertEqual(returncode, 0, stderr)
                if required_stdout:
                    self.assertTrue(stdout, arguments)
                return stdout

            git("init", "-q")
            git("config", "user.email", "windows@example.invalid")
            git("config", "user.name", "Windows Native Contract")
            relative = target.relative_to(repository).as_posix()
            git("add", "--", relative)
            git("commit", "-qm", "near-limit fixture")
            tracked = git("ls-files", "-z", required_stdout=True).rstrip("\0")
            actual = run_step.read_json(target)

        self.assertEqual(actual, expected)
        self.assertEqual(tracked, relative)

    def test_real_git_queries_keep_stdout_in_unicode_space_repository(self):
        self.assertTrue(self.git, "Git for Windows is required")
        with tempfile.TemporaryDirectory(prefix="jua Git 空格 ") as tmp:
            repository = Path(tmp) / "仓库 with spaces & literal"
            repository.mkdir()

            def git(*arguments, required_stdout=False):
                stdout, stderr, returncode = compat.run_cmd(
                    compat.git_cmd() + ["-C", str(repository), *arguments],
                    timeout=30,
                )
                self.assertEqual(returncode, 0, stderr)
                if required_stdout:
                    self.assertTrue(stdout.strip(), arguments)
                return stdout.strip()

            git("init", "-q")
            git("config", "user.email", "windows@example.invalid")
            git("config", "user.name", "Windows Native Contract")
            tracked = repository / "目录" / "文件 with spaces & literal.txt"
            tracked.parent.mkdir()
            tracked.write_text("Windows 原生路径\n", encoding="utf-8")
            git("add", "--", str(tracked.relative_to(repository)))
            git("commit", "-qm", "native fixture")
            git("remote", "add", "origin", "https://example.invalid/组织/仓库.git")
            expected_commit = git(
                "rev-parse", "--verify", "HEAD^{commit}", required_stdout=True,
            )
            for _index in range(20):
                self.assertEqual(
                    git(
                        "rev-parse", "--verify", "HEAD^{commit}",
                        required_stdout=True,
                    ),
                    expected_commit,
                )
                self.assertIn(
                    "worktree ",
                    git("worktree", "list", "--porcelain", required_stdout=True),
                )
                self.assertEqual(
                    git("remote", "get-url", "origin", required_stdout=True),
                    "https://example.invalid/组织/仓库.git",
                )

    def test_windows_process_tree_cleanup_terminates_descendant(self):
        self.assertTrue(self.python.is_file(), "python.exe is required")
        with tempfile.TemporaryDirectory(prefix="jua taskkill ") as tmp:
            root = Path(tmp)
            child_pid_path = root / "child.pid"
            helper = root / "parent.py"
            helper.write_text(
                "\n".join((
                    "import subprocess, sys, time",
                    "from pathlib import Path",
                    "flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)",
                    "child = subprocess.Popen([",
                    "    sys.executable, '-c', 'import time; time.sleep(120)'",
                    "], creationflags=flags)",
                    "Path(sys.argv[1]).write_text(str(child.pid), encoding='utf-8')",
                    # Let managed_popen assign the parent to its Job Object,
                    # then exit before the timeout while the child retains the
                    # captured standard handles.
                    "time.sleep(0.1)",
                )) + "\n",
                encoding="utf-8",
            )
            child_pid = None
            terminated = False
            try:
                _stdout, stderr, returncode = compat.run_cmd(
                    [str(self.python), str(helper), str(child_pid_path)],
                    timeout=1,
                )
                self.assertEqual(returncode, -1, stderr)
                self.assertIn("命令超时", stderr)
                self.assertTrue(child_pid_path.is_file(), "child PID was not published")
                child_pid = int(child_pid_path.read_text(encoding="utf-8"))
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if not run_step._windows_pid_is_running(child_pid):
                        terminated = True
                        break
                    time.sleep(0.05)
            finally:
                if child_pid and run_step._windows_pid_is_running(child_pid):
                    subprocess.run(
                        ["taskkill", "/PID", str(child_pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        **compat.subprocess_platform_kwargs(),
                    )

        self.assertTrue(terminated, "timed-out Windows descendant remained alive")

    def test_atomic_json_concurrency_never_exposes_partial_document(self):
        failures = []
        stop_reader = threading.Event()
        with tempfile.TemporaryDirectory(prefix="jua atomic 状态 ") as tmp:
            target = Path(tmp) / "共享 state.json"
            run_step.write_json(target, {"writer": -1, "sequence": -1})

            def read_repeatedly():
                while not stop_reader.is_set():
                    try:
                        payload = run_step.read_json(target)
                        if set(payload) != {"writer", "sequence"}:
                            failures.append(f"invalid payload keys: {payload!r}")
                    except Exception as error:  # noqa: BLE001 - record native race
                        failures.append(f"{type(error).__name__}: {error}")

            def write_repeatedly(writer):
                for sequence in range(30):
                    run_step.write_json(
                        target, {"writer": writer, "sequence": sequence},
                    )

            reader = threading.Thread(target=read_repeatedly, daemon=True)
            reader.start()
            try:
                with ThreadPoolExecutor(max_workers=4) as executor:
                    futures = [
                        executor.submit(write_repeatedly, writer)
                        for writer in range(4)
                    ]
                    for future in futures:
                        future.result()
            finally:
                stop_reader.set()
                reader.join(timeout=10)
            final_payload = run_step.read_json(target)

        self.assertEqual(failures, [])
        self.assertIn(final_payload["writer"], range(4))
        self.assertIn(final_payload["sequence"], range(30))


if __name__ == "__main__":
    unittest.main()
