import subprocess
import sys
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


if __name__ == "__main__":
    unittest.main()
