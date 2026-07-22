import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from tool_execution import (  # noqa: E402
    ExternalToolError,
    execute_external_tool,
)


class ToolExecutionTest(unittest.TestCase):
    def test_success_retains_stdout_without_failure(self):
        result = execute_external_tool(
            ["javap", "-version"],
            stage="step5.bytecode.javap",
            reason_prefix="STEP5_JAVAP",
            timeout_seconds=30,
            runner=lambda command, timeout: ("21", "", 0),
        )

        self.assertTrue(result.succeeded)
        self.assertEqual(result.stdout, "21")
        self.assertIs(result.require_success(), result)

    def test_timeout_missing_permission_and_nonzero_have_exact_reason_codes(self):
        cases = (
            (-1, "命令超时（30秒）", "STEP5_JAVAP_TIMEOUT"),
            (-1, "命令未找到：javap", "STEP5_JAVAP_MISSING"),
            (-1, "权限不足，无法执行：javap", "STEP5_JAVAP_PERMISSION_DENIED"),
            (7, "class parse failed", "STEP5_JAVAP_NONZERO_EXIT"),
        )
        for returncode, stderr, expected in cases:
            result = execute_external_tool(
                ["javap", "Example"],
                stage="step5.bytecode.javap",
                reason_prefix="STEP5_JAVAP",
                timeout_seconds=30,
                runner=lambda command, timeout, rc=returncode, err=stderr: ("", err, rc),
            )
            with self.subTest(expected=expected):
                self.assertEqual(result.failure.reason_code, expected)
                self.assertEqual(result.failure.stage, "step5.bytecode.javap")
                self.assertEqual(result.failure.command, ("javap", "Example"))
                self.assertEqual(result.failure.timeout_seconds, 30)
                self.assertEqual(result.failure.stderr, stderr)
                self.assertTrue(result.failure.blocking)
                with self.assertRaises(ExternalToolError):
                    result.require_success()

    def test_runner_exception_is_a_structured_start_failure(self):
        def fail(_command, timeout):
            raise OSError(f"spawn failed after {timeout}")

        result = execute_external_tool(
            ["javap", "Example"],
            stage="step5.bytecode.javap",
            reason_prefix="STEP5_JAVAP",
            timeout_seconds=12,
            runner=fail,
        )

        self.assertEqual(result.failure.reason_code, "STEP5_JAVAP_START_FAILED")
        self.assertEqual(result.failure.error_type, "OSError")
        self.assertIn("spawn failed", result.failure.stderr)

    def test_required_empty_stdout_is_a_structured_failure(self):
        result = execute_external_tool(
            ["javap", "Example"],
            stage="step5.bytecode.javap",
            reason_prefix="STEP5_JAVAP",
            timeout_seconds=30,
            require_stdout=True,
            runner=lambda command, timeout: ("", "", 0),
        )

        self.assertEqual(result.failure.reason_code, "STEP5_JAVAP_OUTPUT_EMPTY")
        self.assertTrue(result.failure.blocking)

    def test_empty_command_is_rejected_before_execution(self):
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            execute_external_tool(
                [], stage="step5", reason_prefix="STEP5", timeout_seconds=1
            )


if __name__ == "__main__":
    unittest.main()
