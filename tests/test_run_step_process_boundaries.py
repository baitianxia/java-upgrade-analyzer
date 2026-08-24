from __future__ import annotations

from contextlib import ExitStack
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import run_step


class RunStepProcessBoundaryTest(unittest.TestCase):
    def assert_step_error(self, action):
        with self.assertRaises(run_step.StepError) as captured:
            action()
        return captured.exception

    def test_print_output_empty_newline_and_stream_matrix(self):
        for stdout, stderr, expected_out, expected_err in (
            ("", "", "", ""),
            ("out", "", "out\n", ""),
            ("out\n", "", "out\n", ""),
            ("", "err", "", "err\n"),
            ("", "err\n", "", "err\n"),
            ("out", "err", "out\n", "err\n"),
        ):
            with self.subTest(stdout=stdout, stderr=stderr), patch.object(
                run_step.sys, "stdout", io.StringIO(),
            ) as output, patch.object(
                run_step.sys, "stderr", io.StringIO(),
            ) as error:
                run_step.print_output(stdout, stderr)
                self.assertEqual(output.getvalue(), expected_out)
                self.assertEqual(error.getvalue(), expected_err)

    def test_subprocess_failure_detail_filter_preference_redaction_and_limit_matrix(self):
        self.assertEqual(run_step._subprocess_failure_detail(None, None), "")
        boilerplate = "\n".join((
            "",
            "Picked up JAVA_TOOL_OPTIONS: -Xmx1g",
            "[ERROR]",
            "[FATAL]",
            "[ERROR] To see the full stack trace of the errors, re-run Maven",
            "[ERROR] Re-run Maven using the -X switch",
        ))
        self.assertEqual(
            run_step._subprocess_failure_detail(boilerplate, "actual stdout error"),
            "actual stdout error",
        )
        gradle = "\n".join((
            "FAILURE: Build failed with an exception.",
            "* What went wrong:",
            "root cause",
            "* Try:",
            "> Run with --stacktrace option",
            "> Get more help at https://help.gradle.org",
            "BUILD FAILED in 1s",
        ))
        self.assertEqual(
            run_step._subprocess_failure_detail(gradle, "ignored"),
            "root cause",
        )
        self.assertEqual(
            run_step._subprocess_failure_detail("stderr cause", "stdout cause"),
            "stderr cause",
        )
        self.assertEqual(
            run_step._subprocess_failure_detail(
                "FAILURE: Build failed with an exception.\n* Try:", ""
            ),
            "* Try:",
        )
        redacted = run_step._subprocess_failure_detail(
            "https://user:secret@example.com/repo.git failed", ""
        )
        self.assertNotIn("secret", redacted)
        self.assertEqual(
            run_step._subprocess_failure_detail("abcdef", "", limit=4),
            "abc…",
        )
        self.assertEqual(
            run_step._subprocess_failure_detail("abcdef", "", limit=0),
            "…",
        )

    @staticmethod
    def valid_binary_failure():
        return {
            "schema": run_step._BINARY_PIPELINE_FAILURE_SCHEMA,
            "status": "failed",
            "fail_closed": True,
            "reason_code": "BINARY_FAILED",
            "failure_type": "RuntimeError",
            "detail": "failed",
            "cause": None,
            "failed_phase": "validation",
            "last_progress": {},
            "attempt_identity": "a" * 64,
            "progress_bound_to_attempt": True,
            "core_transaction_status": "failed",
            "core_transaction_succeeded": False,
            "core_result_receipt": None,
        }

    def test_binary_failure_payload_every_contract_field_matrix(self):
        valid = self.valid_binary_failure()
        self.assertIs(
            run_step._binary_pipeline_failure_payload(valid), valid
        )
        succeeded = {
            **valid,
            "core_transaction_status": "succeeded",
            "core_transaction_succeeded": True,
            "core_result_receipt": {"identity": "receipt"},
        }
        self.assertIs(
            run_step._binary_pipeline_failure_payload(succeeded), succeeded
        )
        for candidate in (None, [], "failure", SimpleNamespace()):
            with self.subTest(non_exact_dict=type(candidate).__name__):
                self.assertIsNone(
                    run_step._binary_pipeline_failure_payload(candidate)
                )

        invalid_mutations = (
            {"schema": "wrong"},
            {"status": "passed"},
            {"fail_closed": 1},
            {"reason_code": 1},
            {"reason_code": "bad-code"},
            {"failure_type": 1},
            {"detail": 1},
            {"__remove__": "cause"},
            {"failed_phase": 1},
            {"last_progress": []},
            {"attempt_identity": 1},
            {"attempt_identity": "bad"},
            {"progress_bound_to_attempt": 1},
            {"core_transaction_status": "unknown"},
            {"core_transaction_succeeded": 0},
            {"core_transaction_succeeded": True},
            {"core_result_receipt": []},
        )
        for mutation in invalid_mutations:
            candidate = dict(valid)
            removed = mutation.get("__remove__")
            if removed:
                candidate.pop(removed)
            else:
                candidate.update(mutation)
            with self.subTest(mutation=mutation):
                self.assertIsNone(
                    run_step._binary_pipeline_failure_payload(candidate)
                )

    def test_binary_failure_stderr_and_bounded_result_file_matrix(self):
        valid = self.valid_binary_failure()
        self.assertIsNone(run_step._binary_pipeline_failure_from_stderr(None))
        self.assertIsNone(run_step._binary_pipeline_failure_from_stderr(" \n"))
        self.assertIsNone(
            run_step._binary_pipeline_failure_from_stderr("not json")
        )
        too_long = "x" * (
            run_step._BINARY_PIPELINE_STDERR_FAILURE_MAX_CHARS + 1
        )
        self.assertIsNone(
            run_step._binary_pipeline_failure_from_stderr(too_long)
        )
        parsed = run_step._binary_pipeline_failure_from_stderr(
            "progress\n" + json.dumps(valid)
        )
        self.assertEqual(parsed["reason_code"], "BINARY_FAILED")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIsNone(
                run_step._binary_pipeline_failure_from_result_path(
                    root / "missing.json"
                )
            )
            oversized = root / "oversized.json"
            oversized.write_bytes(
                b"x" * (
                    run_step._BINARY_PIPELINE_STDERR_FAILURE_MAX_CHARS + 1
                )
            )
            self.assertIsNone(
                run_step._binary_pipeline_failure_from_result_path(oversized)
            )
            invalid_utf8 = root / "invalid-utf8.json"
            invalid_utf8.write_bytes(b"\xff")
            self.assertIsNone(
                run_step._binary_pipeline_failure_from_result_path(invalid_utf8)
            )
            invalid_json = root / "invalid.json"
            invalid_json.write_text("{", encoding="utf-8")
            self.assertIsNone(
                run_step._binary_pipeline_failure_from_result_path(invalid_json)
            )
            result_path = root / "result.json"
            result_path.write_text(json.dumps(valid), encoding="utf-8")
            self.assertEqual(
                run_step._binary_pipeline_failure_from_result_path(result_path)[
                    "reason_code"
                ],
                "BINARY_FAILED",
            )

    def test_run_python_stream_heartbeat_output_and_interaction_matrix(self):
        created_threads = []

        class FakeThread:
            def __init__(self, **kwargs):
                self.kwargs = kwargs
                self.started = False
                self.joined = False
                created_threads.append(self)

            def start(self):
                self.started = True

            def join(self, timeout=None):
                self.joined = timeout

        def invoke(
            script, output, *, args=None, report=None, interval=None,
        ):
            environment = {}
            if interval is not None:
                environment["JUA_HEARTBEAT_INTERVAL_SECONDS"] = interval
            with patch.dict(
                run_step.os.environ, environment, clear=True,
            ), patch.object(
                run_step.threading, "Thread", FakeThread,
            ), patch.object(
                run_step, "run_cmd", return_value=output,
            ) as run, patch.object(
                run_step, "print_output",
            ) as print_output:
                result = run_step.run_python(
                    script, list(args or []), "/cwd",
                    report_dir=report, timeout=12,
                )
                return result, run, print_output

        result, run, output = invoke(
            "unknown.py", (None, None, 0), interval="invalid"
        )
        self.assertIsNone(result)
        self.assertNotIn("stream_output", run.call_args.kwargs)
        self.assertNotIn("UPGRADE_REPORT_DIR", run.call_args.kwargs["env"])
        output.assert_called_once_with("", "")

        result, run, output = invoke(
            "s1_dep_diff.py",
            ("line one\nline two\n", "streamed stderr", 0),
            report="/report", interval="-1",
        )
        self.assertIsNone(result)
        self.assertTrue(run.call_args.kwargs["stream_output"])
        self.assertFalse(run.call_args.kwargs["stream_stdout"])
        self.assertEqual(
            run.call_args.kwargs["env"]["UPGRADE_REPORT_DIR"],
            str(Path("/report").resolve()),
        )
        output.assert_called_once_with("line one\nline two\n", "")
        self.assertTrue(created_threads[-1].started)
        self.assertEqual(created_threads[-1].joined, 1)

        result, _run, output = invoke(
            "unknown.py", ("\ntext", "", 0)
        )
        self.assertIsNone(result)
        output.assert_called_once_with("\ntext", "")

        prefix = "JUA_STEP_INTERACTION_JSON:"
        with patch.object(
            run_step, "run_cmd",
            return_value=(
                "before\n"
                + prefix
                + json.dumps({"step_id": "step1"})
                + "\nafter\n",
                "", 0,
            ),
        ), patch.object(
            run_step.threading, "Thread", FakeThread,
        ), patch.object(run_step, "print_output"):
            with self.assertRaises(run_step.StepInteractionRequired) as captured:
                run_step.run_python("s1_dep_diff.py", [], "/cwd")
        self.assertEqual(captured.exception.interaction["step_id"], "step1")

        with patch.object(
            run_step, "run_cmd",
            return_value=(
                prefix + json.dumps({"step_id": "step2"}) + "\n",
                "", 0,
            ),
        ), patch.object(
            run_step.threading, "Thread", FakeThread,
        ), patch.object(run_step, "print_output"):
            with self.assertRaises(run_step.StepInteractionRequired):
                run_step.run_python("s1_dep_diff.py", [], "/cwd")

        with patch.object(
            run_step, "run_cmd", return_value=(prefix + "{", "", 0),
        ), patch.object(
            run_step.threading, "Thread", FakeThread,
        ), patch.object(run_step, "print_output"):
            self.assert_step_error(
                lambda: run_step.run_python("s1_dep_diff.py", [], "/cwd")
            )

    def test_run_python_failure_result_json_reason_and_diagnostic_matrix(self):
        class FakeThread:
            def __init__(self, **_kwargs):
                pass

            def start(self):
                pass

            def join(self, timeout=None):
                pass

        def invoke(
            script, args, output, *, read_value=None,
            read_error=None, binary_file_value=None,
            binary_stderr_value=None, detail="detail",
        ):
            with ExitStack() as stack:
                stack.enter_context(patch.object(
                    run_step.threading, "Thread", FakeThread,
                ))
                stack.enter_context(patch.object(
                    run_step, "run_cmd", return_value=output,
                ))
                stack.enter_context(patch.object(run_step, "print_output"))
                stack.enter_context(patch.object(
                    run_step, "_subprocess_failure_detail", return_value=detail,
                ))
                read = stack.enter_context(patch.object(
                    run_step, "read_json", side_effect=read_error,
                    return_value=read_value,
                ))
                from_file = stack.enter_context(patch.object(
                    run_step, "_binary_pipeline_failure_from_result_path",
                    return_value=binary_file_value,
                ))
                from_stderr = stack.enter_context(patch.object(
                    run_step, "_binary_pipeline_failure_from_stderr",
                    return_value=binary_stderr_value,
                ))
                stack.enter_context(patch.object(
                    run_step, "_binary_pipeline_failure_payload",
                    side_effect=lambda value: (
                        value if value and value.get("schema") ==
                        run_step._BINARY_PIPELINE_FAILURE_SCHEMA else None
                    ),
                ))
                stack.enter_context(patch.object(
                    run_step, "_sanitize_git_persistence_payload",
                    side_effect=lambda value: value,
                ))
                error = self.assert_step_error(
                    lambda: run_step.run_python(script, args, "/cwd")
                )
                return error, {
                    "read": read, "file": from_file,
                    "stderr": from_stderr,
                }

        error, mocks = invoke(
            "other.py", [], (None, None, 2), detail=""
        )
        self.assertIn("退出码=2", str(error))
        self.assertNotIn("：", str(error))
        self.assertEqual(error.reason_codes, [])
        mocks["read"].assert_not_called()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result_path = root / "result.json"
            result_path.touch()
            structured = {
                "reason_code": "TOP",
                "cause": {"reason_code": "CAUSE"},
            }
            error, mocks = invoke(
                "other.py", ["--result-json", str(result_path)],
                ("stdout", "stderr", 3), read_value=structured,
            )
            self.assertEqual(error.reason_codes, ["TOP", "CAUSE"])
            self.assertEqual(error.diagnostic["structured_result"], structured)
            mocks["read"].assert_called_once()

            for read_error in (
                OSError("io"), UnicodeError("unicode"),
                ValueError("value"), RecursionError("deep"),
            ):
                with self.subTest(read_error=type(read_error).__name__):
                    error, _mocks = invoke(
                        "other.py", ["--result-json", str(result_path)],
                        ("", "", 4), read_error=read_error,
                    )
                    self.assertEqual(error.reason_codes, [])

            error, _mocks = invoke(
                "other.py", ["--result-json", str(result_path)],
                ("", "", 4), read_value=["not", "object"],
            )
            self.assertEqual(error.diagnostic["structured_result"], {})

            valid = self.valid_binary_failure()
            error, mocks = invoke(
                "binary_pipeline.py",
                ["--result-json", str(result_path)],
                ("", "stderr", 5), binary_file_value=valid,
            )
            self.assertEqual(error.reason_codes, ["BINARY_FAILED"])
            mocks["file"].assert_called_once()
            mocks["stderr"].assert_not_called()

            error, mocks = invoke(
                "binary_pipeline.py",
                ["--result-json", str(result_path)],
                ("", "stderr", 6), binary_file_value=None,
                binary_stderr_value=valid,
            )
            self.assertEqual(error.reason_codes, ["BINARY_FAILED"])
            mocks["stderr"].assert_called_once_with("stderr")

            error, _mocks = invoke(
                "binary_pipeline.py", [], ("", "", 6),
                binary_file_value=None, binary_stderr_value=None,
            )
            self.assertEqual(error.reason_codes, [])

            error, mocks = invoke(
                "other.py", ["--result-json"], ("", "", 7)
            )
            self.assertEqual(error.reason_codes, [])
            mocks["read"].assert_not_called()

            missing_path = root / "missing.json"
            error, mocks = invoke(
                "other.py", ["--result-json", str(missing_path)],
                ("", "", 8),
            )
            self.assertEqual(error.reason_codes, [])
            mocks["read"].assert_not_called()

            error, _mocks = invoke(
                "other.py", ["--result-json", str(result_path)],
                ("", "", 9),
                read_value={"reason_code": None, "cause": "not-object"},
            )
            self.assertEqual(error.reason_codes, [])

            error, _mocks = invoke(
                "other.py", ["--result-json", str(result_path)],
                ("", "", 9),
                read_value={"reason_code": "TOP", "cause": {}},
            )
            self.assertEqual(error.reason_codes, ["TOP"])

    def test_run_gate_arguments_publication_and_jar_reason_enrichment_matrix(self):
        with patch.object(run_step, "run_python") as run:
            self.assertIsNone(run_step.run_gate("", "/report", "/cwd"))
            run.assert_not_called()

        with patch.object(run_step, "run_python") as run:
            run_step.run_gate(
                "basic", "/report", "/cwd", strict_risk_gate=True,
            )
        args = run.call_args.args[1]
        self.assertIn("--strict-risk-gate", args)

        with patch.object(
            run_step, "runtime_state_dir", return_value=Path("/state"),
        ), patch.object(
            run_step, "_prepare_fresh_subprocess_result",
        ) as prepare, patch.object(run_step, "run_python") as run:
            run_step.run_gate(
                "binary_final_report", "/report", "/cwd",
                publication_transaction={},
            )
        prepare.assert_called_once_with(Path("/state/binary_gate_step6_result.json"))
        args = run.call_args.args[1]
        self.assertIn("--result-json", args)
        self.assertIn("--publication-transaction-id", args)
        self.assertIn("{}", args)

        transaction = {
            "transaction_id": "tx",
            "binding": {"generation": "g"},
            "published_content_identity": "content",
        }
        with patch.object(run_step, "run_python") as run:
            run_step.run_gate(
                "basic", "/report", "/cwd",
                publication_transaction=transaction,
                candidate_activation_identity="activation",
            )
        args = run.call_args.args[1]
        self.assertIn("tx", args)
        self.assertIn("content", args)
        self.assertIn("activation", args)

        original = run_step.StepError(
            "gate failed", reason_codes=["ORIGINAL"], diagnostic={"x": 1}
        )
        with patch.object(run_step, "run_python", side_effect=original):
            error = self.assert_step_error(
                lambda: run_step.run_gate("basic", "/report", "/cwd")
            )
        self.assertEqual(error.reason_codes, ["ORIGINAL"])
        self.assertEqual(error.diagnostic, {"x": 1})

        with tempfile.TemporaryDirectory() as directory:
            coverage_dir = Path(directory)
            (coverage_dir / "s4_coverage.json").touch()
            coverage = {
                "invalid": [],
                "empty": {"reason_codes": None, "runs": None},
                "rich": {
                    "reason_codes": ["SECTION"],
                    "runs": [None, {}, {"reason_code": "RUN"}],
                },
            }
            with patch.object(
                run_step, "run_python", side_effect=run_step.StepError(
                    "jar failed", diagnostic=None,
                ),
            ), patch.object(
                run_step, "runtime_coverage_dir", return_value=coverage_dir,
            ), patch.object(
                run_step, "read_json", return_value=coverage,
            ):
                error = self.assert_step_error(
                    lambda: run_step.run_gate(
                        "jar_compare", "/report", "/cwd"
                    )
                )
            self.assertEqual(error.reason_codes, ["SECTION", "RUN"])
            self.assertEqual(error.diagnostic, {})

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(
                run_step, "run_python", side_effect=run_step.StepError("failed"),
            ), patch.object(
                run_step, "runtime_coverage_dir", return_value=Path(directory),
            ), patch.object(run_step, "read_json") as read:
                self.assert_step_error(
                    lambda: run_step.run_gate(
                        "jar_compare", "/report", "/cwd"
                    )
                )
            read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
