"""Native Windows contracts loaded only by the governed Windows test suite.

The file deliberately does not match unittest's ``test*.py`` discovery
pattern. Non-Windows runs must not turn these contracts into reassuring skips;
``scripts/test_suite_runner.py --suite windows`` loads them explicitly and
fails closed unless it is executing on a native Windows host.
"""

from concurrent.futures import ThreadPoolExecutor
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import compat  # noqa: E402
import run_step  # noqa: E402
from process_metrics import windows_current_process_usage  # noqa: E402


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
        ):
            if not candidate:
                missing.append(name)

        self.assertEqual(missing, [], f"WINDOWS_NATIVE_TOOLCHAIN_MISSING:{missing}")

    def test_native_process_metrics_report_cpu_and_peak_memory(self):
        usage = windows_current_process_usage()

        self.assertIsNotNone(usage)
        self.assertGreaterEqual(usage.user_seconds, 0)
        self.assertGreaterEqual(usage.system_seconds, 0)
        self.assertGreater(usage.peak_rss_bytes, 0)

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
                    "time.sleep(120)",
                )) + "\n",
                encoding="utf-8",
            )
            parent = subprocess.Popen(
                [str(self.python), str(helper), str(child_pid_path)],
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
            )
            child_pid = None
            terminated = False
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and not child_pid_path.is_file():
                    time.sleep(0.05)
                self.assertTrue(child_pid_path.is_file(), "child PID was not published")
                child_pid = int(child_pid_path.read_text(encoding="utf-8"))
                self.assertTrue(run_step._windows_pid_is_running(child_pid))
                compat._terminate_subprocess(parent, process_group=True)
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if not run_step._windows_pid_is_running(child_pid):
                        terminated = True
                        break
                    time.sleep(0.05)
            finally:
                if parent.poll() is None:
                    compat._terminate_subprocess(parent, process_group=True)
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
