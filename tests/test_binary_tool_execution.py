import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import binary_tool_execution  # noqa: E402
from binary_tool_execution import (  # noqa: E402
    execute_binary_tool,
    tool_failure_is_retryable,
)


class BinaryToolExecutionTest(unittest.TestCase):
    @staticmethod
    def runner(stdout="ok", stderr="", returncode=0):
        def run(_command, **_kwargs):
            return SimpleNamespace(
                stdout=stdout, stderr=stderr, returncode=returncode
            )
        return run

    def test_success_and_required_output_are_typed(self):
        result = execute_binary_tool(
            ["javap", "-version"], stage="oracle.javap",
            reason_prefix="BINARY_JAVAP", timeout_seconds=10,
            require_stdout=True, runner=self.runner(stdout="21"),
        )
        self.assertTrue(result.succeeded)
        self.assertEqual(result.stdout, "21")

    def test_empty_argv_is_rejected_before_runner_selection(self):
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            execute_binary_tool(
                [],
                stage="binary.test",
                reason_prefix="BINARY_TOOL",
                timeout_seconds=1,
            )

    def test_timeout_missing_permission_nonzero_and_empty_fail_closed(self):
        def raising(error):
            def run(_command, **_kwargs):
                raise error
            return run

        cases = (
            (raising(subprocess.TimeoutExpired(["tool"], 1)), "BINARY_TOOL_TIMEOUT"),
            (raising(FileNotFoundError("missing")), "BINARY_TOOL_MISSING"),
            (raising(PermissionError("denied")), "BINARY_TOOL_PERMISSION_DENIED"),
            (self.runner(stderr="bad", returncode=9), "BINARY_TOOL_NONZERO_EXIT"),
            (self.runner(stdout=""), "BINARY_TOOL_OUTPUT_EMPTY"),
        )
        for runner, reason in cases:
            with self.subTest(reason=reason):
                result = execute_binary_tool(
                    ["tool"], stage="binary.test", reason_prefix="BINARY_TOOL",
                    timeout_seconds=1, require_stdout=True, runner=runner,
                )
                self.assertFalse(result.succeeded)
                self.assertEqual(result.failure.reason_code, reason)
                self.assertEqual(result.failure.stage, "binary.test")
                self.assertTrue(result.failure.blocking)
                self.assertEqual(
                    result.failure.to_mapping()["command"], ["tool"]
                )

    def test_start_exceptions_preserve_binary_empty_output_types(self):
        exception_cases = (
            subprocess.TimeoutExpired(["tool"], 1),
            FileNotFoundError("missing"),
            PermissionError("denied"),
            OSError("start failed"),
            TypeError("invalid runner arguments"),
            ValueError("invalid runner value"),
        )
        for error in exception_cases:
            for text, empty in ((True, ""), (False, b"")):
                with self.subTest(
                    error=type(error).__name__,
                    text=text,
                ):
                    result = execute_binary_tool(
                        ["tool"],
                        stage="binary.test",
                        reason_prefix="BINARY_TOOL",
                        timeout_seconds=1,
                        text=text,
                        runner=lambda *_args, _error=error, **_kwargs: (
                            (_ for _ in ()).throw(_error)
                        ),
                    )
                    self.assertEqual(result.stdout, empty)
                    self.assertEqual(result.stderr, empty)
                    self.assertEqual(result.returncode, -1)

    def test_completed_none_and_nonstandard_stdout_cover_normalization_boundaries(self):
        for text, empty in ((True, ""), (False, b"")):
            with self.subTest(text=text):
                result = execute_binary_tool(
                    ["tool"],
                    stage="binary.test",
                    reason_prefix="BINARY_TOOL",
                    timeout_seconds=1,
                    text=text,
                    runner=self.runner(stdout=None, stderr=None),
                )
                self.assertTrue(result.succeeded)
                self.assertEqual(result.stdout, empty)
                self.assertEqual(result.stderr, empty)

        result = execute_binary_tool(
            ["tool"],
            stage="binary.test",
            reason_prefix="BINARY_TOOL",
            timeout_seconds=1,
            require_stdout=True,
            runner=self.runner(stdout=[], stderr=""),
        )
        self.assertEqual(result.failure.failure_kind, "output_empty")

    def test_only_transient_process_failures_are_retryable(self):
        timeout = execute_binary_tool(
            ["tool"], stage="test", reason_prefix="TOOL", timeout_seconds=1,
            runner=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(["tool"], 1)
            ),
        )
        missing = execute_binary_tool(
            ["tool"], stage="test", reason_prefix="TOOL", timeout_seconds=1,
            runner=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                FileNotFoundError("missing")
            ),
        )

        self.assertTrue(tool_failure_is_retryable(timeout.failure))
        self.assertFalse(tool_failure_is_retryable(missing.failure))
        self.assertFalse(tool_failure_is_retryable(None))

    def test_bytes_input_and_output_preserve_protocol_payload(self):
        result = execute_binary_tool(
            ["java", "Helper"], stage="binary.protocol",
            reason_prefix="BINARY_PROTOCOL", timeout_seconds=2,
            input_data=b"\x00\x01", text=False, require_stdout=True,
            runner=self.runner(stdout=b"\x02", stderr=b""),
        )
        self.assertTrue(result.succeeded)
        self.assertEqual(result.stdout, b"\x02")

    def test_explicit_working_directory_is_forwarded_without_shell(self):
        observed = {}

        def runner(command, **kwargs):
            observed.update({"command": command, **kwargs})
            return SimpleNamespace(stdout="ok", stderr="", returncode=0)

        result = execute_binary_tool(
            ["mvn", "package"], stage="binary.build",
            reason_prefix="BINARY_BUILD", timeout_seconds=30,
            cwd=ROOT, runner=runner,
        )
        self.assertTrue(result.succeeded)
        self.assertEqual(observed["command"], ["mvn", "package"])
        self.assertEqual(observed["cwd"], str(ROOT.resolve()))

    def test_windows_no_window_policy_is_forwarded_to_typed_tools(self):
        observed = {}

        def runner(command, **kwargs):
            observed.update({"command": command, **kwargs})
            return SimpleNamespace(stdout="ok", stderr="", returncode=0)

        with patch.object(
            binary_tool_execution,
            "subprocess_platform_kwargs",
            return_value={"creationflags": 0x08000000},
        ):
            result = execute_binary_tool(
                ["python.exe", "worker.py"], stage="binary.worker",
                reason_prefix="BINARY_WORKER", timeout_seconds=30,
                runner=runner,
            )

        self.assertTrue(result.succeeded)
        self.assertEqual(observed["creationflags"], 0x08000000)

    @unittest.skipIf(os.name == "nt", "POSIX process-group semantics only")
    def test_default_timeout_terminates_non_git_descendant_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child_pid_path = root / "child.pid"
            helper = root / "tool_parent.py"
            helper.write_text(
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
            result = execute_binary_tool(
                [sys.executable, str(helper), str(child_pid_path)],
                stage="binary.test",
                reason_prefix="BINARY_TOOL",
                timeout_seconds=0.5,
            )

            self.assertFalse(result.succeeded)
            self.assertEqual(result.failure.failure_kind, "timeout")
            self.assertTrue(child_pid_path.is_file())
            child_pid = int(child_pid_path.read_text(encoding="utf-8"))
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

        self.assertFalse(child_alive, "timed-out binary tool descendant remained alive")


if __name__ == "__main__":
    unittest.main()
