from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import progress_logging


class ProgressLoggingTest(unittest.TestCase):
    def test_interval_and_progress_decisions_cover_each_short_circuit(self):
        self.assertEqual(progress_logging.suggest_log_interval(None), 1)
        self.assertEqual(progress_logging.suggest_log_interval("bad", minimum=3), 3)
        self.assertEqual(progress_logging.suggest_log_interval(0, minimum=2), 2)
        self.assertEqual(progress_logging.suggest_log_interval(100, target_updates=0), 100)
        self.assertEqual(progress_logging.suggest_log_interval(100, target_updates=10), 10)

        self.assertTrue(progress_logging.should_log_progress(1, 100, 10))
        self.assertTrue(progress_logging.should_log_progress(100, 100, 10))
        self.assertTrue(progress_logging.should_log_progress(20, 100, 10))
        self.assertFalse(progress_logging.should_log_progress(21, 100, 10))
        self.assertFalse(progress_logging.should_log_progress("bad", 100, 10))

    def test_elapsed_formatting_covers_every_unit_boundary(self):
        cases = (
            (None, ""),
            (-1, "0.0s"),
            (0.25, "0.2s"),
            (1, "1.0s"),
            (59.9, "59.9s"),
            (60, "1m00.0s"),
            (3599, "59m59.0s"),
            (3600, "1h00m00.0s"),
        )
        for seconds, expected in cases:
            with self.subTest(seconds=seconds):
                self.assertEqual(progress_logging.format_elapsed(seconds), expected)

    def test_display_estimate_and_percentage_cover_all_boundary_classes(self):
        self.assertEqual(progress_logging._display_item(None), "")
        self.assertEqual(progress_logging._display_item(" short "), "short")
        rendered = progress_logging._display_item("x" * 10, limit=5)
        self.assertEqual(rendered, "…xxxx")

        for arguments in (("bad", 2, 1), (1, "bad", 1), (1, 2, "bad")):
            with self.subTest(estimate=arguments):
                self.assertIsNone(progress_logging._estimate_remaining(*arguments))
        for arguments in ((0, 2, 1), (2, 2, 1), (3, 2, 1), (1, 2, 0)):
            with self.subTest(estimate=arguments):
                self.assertIsNone(progress_logging._estimate_remaining(*arguments))
        self.assertEqual(progress_logging._estimate_remaining(2, 10, 4), 16)

        for arguments in (("bad", 2), (1, "bad"), (1, 0), (-1, 2), (3, 2)):
            with self.subTest(percentage=arguments):
                self.assertIsNone(progress_logging._progress_percentage(*arguments))
        self.assertEqual(progress_logging._progress_percentage(1, 4), 25)

    def test_progress_event_persistence_uses_argument_environment_and_fail_open(self):
        payload = {"event": "ok"}
        with patch.dict(os.environ, {}, clear=True):
            progress_logging._write_progress_event(payload)

        with tempfile.TemporaryDirectory() as temporary:
            progress_logging._write_progress_event(payload, report_dir=temporary)
            path = (
                Path(temporary).resolve()
                / ".runtime/observability/progress.jsonl"
            )
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), payload)

        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ,
            {"UPGRADE_REPORT_DIR": temporary},
            clear=True,
        ):
            progress_logging._write_progress_event({"event": "environment"})
            path = (
                Path(temporary).resolve()
                / ".runtime/observability/progress.jsonl"
            )
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8"))["event"],
                "environment",
            )

        with patch.object(Path, "resolve", side_effect=OSError("read only")):
            self.assertIsNone(
                progress_logging._write_progress_event(payload, report_dir="/tmp")
            )

    def test_emit_progress_renders_full_empty_current_only_and_unknown_forms(self):
        captured_payloads = []

        def capture(payload, report_dir=None):
            captured_payloads.append((payload, report_dir))

        stderr = io.StringIO()
        with patch.object(
            progress_logging,
            "_write_progress_event",
            side_effect=capture,
        ), redirect_stderr(stderr):
            progress_logging.emit_progress(
                "step1",
                "scan",
                "scanning",
                current=2,
                total=10,
                elapsed=4,
                item="x" * 140,
                report_dir="report",
            )
            progress_logging.emit_progress(
                None,
                None,
                None,
                estimate_remaining=False,
            )
            progress_logging.emit_progress(
                "custom",
                "custom-phase",
                "one",
                current=1,
                elapsed=0,
                item="",
            )
            progress_logging.emit_progress(
                "step2",
                "scan",
                "invalid percentage",
                current=-1,
                total=10,
                elapsed=1,
            )

        first = captured_payloads[0][0]
        self.assertEqual(first["percentage"], 20.0)
        self.assertEqual(first["estimated_remaining_sec"], 16.0)
        self.assertEqual(captured_payloads[0][1], "report")
        self.assertEqual(captured_payloads[1][0]["task"], "当前分析")
        self.assertEqual(captured_payloads[2][0]["task"], "custom")
        output = stderr.getvalue()
        self.assertIn("[2/10]", output)
        self.assertIn("预计剩余约", output)
        self.assertIn("[1]", output)
        self.assertIn("custom-phase", output)
        self.assertNotIn("[-1/10][-10.0%]", output)

    def test_phase_timer_reports_nonnegative_elapsed_time(self):
        with patch.object(progress_logging.time, "perf_counter", side_effect=(10, 12.5)):
            timer = progress_logging.PhaseTimer("step1", "scan")
            self.assertEqual(timer.elapsed(), 2.5)


if __name__ == "__main__":
    unittest.main()
