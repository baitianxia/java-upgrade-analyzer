import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import progress_logging  # noqa: E402
import confidence_weighted_tracer as tracer  # noqa: E402
import s3_scan as step3  # noqa: E402
import s5_call_chain_engine_integrated as step5  # noqa: E402


class ProgressLoggingTest(unittest.TestCase):
    def test_progress_interval_logs_first_middle_and_last(self):
        interval = progress_logging.suggest_log_interval(25, target_updates=10, minimum=1)
        self.assertEqual(interval, 2)
        self.assertTrue(progress_logging.should_log_progress(1, 25, interval))
        self.assertTrue(progress_logging.should_log_progress(2, 25, interval))
        self.assertTrue(progress_logging.should_log_progress(25, 25, interval))
        self.assertFalse(progress_logging.should_log_progress(3, 25, interval))

    def test_step3_emits_structured_progress_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_dir = Path(tmp) / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            (source_dir / "Demo.java").write_text("package com.example;\nclass Demo {}\n", encoding="utf-8")
            stderr = io.StringIO()

            original_scan_funcs = step3.SCAN_FUNCS
            step3.SCAN_FUNCS = {"fake": (lambda *_args, **_kwargs: 3, "fake.csv")}
            try:
                with patch.object(
                    sys,
                    "argv",
                    [
                        "s3_scan.py",
                        "--all",
                        "--source-dir",
                        str(source_dir),
                        "--output-dir",
                        tmp,
                    ],
                ), redirect_stderr(stderr):
                    step3.main()
            finally:
                step3.SCAN_FUNCS = original_scan_funcs

        output = stderr.getvalue()
        self.assertIn("[进度][兼容性线索][准备]", output)
        self.assertIn("[进度][兼容性线索][扫描]", output)
        self.assertIn("[进度][兼容性线索][完成]", output)

    def test_step5_tracer_emits_structured_progress_logs(self):
        stderr = io.StringIO()
        all_apis = [
            {"coord": "com.example:demo", "api_name": "com.example.Target.callA"},
            {"coord": "com.example:demo", "api_name": "com.example.Target.callB"},
            {"coord": "com.example:demo", "api_name": "com.example.Target.callC"},
        ]
        with patch.object(
            tracer,
            "trace_api_with_confidence_weighting",
            return_value=SimpleNamespace(analysis_status="reachable"),
        ), redirect_stderr(stderr):
            results = tracer.trace_all_apis_with_confidence_weighting(
                all_apis,
                graph=SimpleNamespace(),
                type_metadata={},
            )

        output = stderr.getvalue()
        self.assertEqual(len(results), 3)
        self.assertIn("[进度][系统触达证据][追踪系统触达]", output)
        self.assertIn("反向追踪完成", output)

    def test_step5_emits_structured_progress_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            output_dir = report_dir / "s5_call_chain"
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            output_dir.mkdir(parents=True)
            (report_dir / "s4_jar_compare").mkdir(parents=True)
            all_changed_apis = report_dir / "s4_jar_compare" / "all_changed_apis.csv"
            all_changed_apis.write_text("coord,api_name\ncom.example:demo,com.example.Target.call\n", encoding="utf-8")

            args = SimpleNamespace(
                report_dir=str(report_dir),
                output_dir=str(output_dir),
                all_changed_apis=str(all_changed_apis),
                source_dirs=[str(source_dir)],
                dependency_source_mappings=[],
                allow_degraded=False,
                jdk_scan_dir="",
                max_methods=None,
                max_depth=5,
            )
            stderr = io.StringIO()

            graph_result = {
                "graph": SimpleNamespace(reverse_edges={}, methods_by_id={}),
                "type_metadata": {},
                "stats": {
                    "parser_usage": {},
                    "parser_fallback_reasons": {},
                    "truncated": False,
                    "edge_cap_hits": 0,
                },
                "analysis_cache": [],
            }

            with patch.object(
                step5,
                "auto_discover_bridge_sources",
                return_value={"dependency_source_mappings": [], "matched_coords": []},
            ), patch.object(
                step5,
                "load_changed_apis",
                return_value=[{"coord": "com.example:demo", "api_name": "com.example.Target.call"}],
            ), patch.object(
                step5,
                "build_enhanced_source_graph",
                return_value=graph_result,
            ), patch.object(
                step5,
                "check_apis_that_need_bridge",
                return_value={},
            ), patch.object(
                step5,
                "build_jar_metadata_for_source_roots",
                return_value={"jar_paths": {}, "by_coord": {}, "by_class": {}},
            ), patch.object(
                step5,
                "trace_all_apis_with_confidence_weighting",
                return_value=[],
            ), patch.object(
                step5,
                "generate_enhanced_summary",
            ), redirect_stderr(stderr):
                exit_code = step5.step5_integrated_main(args)

        output = stderr.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("[进度][系统触达证据][准备]", output)
        self.assertIn("[进度][系统触达证据][构建调用图]", output)
        self.assertIn("[进度][系统触达证据][追踪系统触达]", output)
        self.assertIn("[进度][系统触达证据][完成]", output)

    def test_progress_is_persisted_without_exposing_internal_ids_to_human_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with patch.dict(os.environ, {"UPGRADE_REPORT_DIR": tmp}), redirect_stderr(stderr):
                progress_logging.emit_progress(
                    "step4",
                    "dependency",
                    "完成一个依赖",
                    current=1,
                    total=2,
                    elapsed=1.25,
                    item="com.acme:demo",
                )

            progress_path = Path(tmp) / ".runtime" / "observability" / "progress.jsonl"
            event = json.loads(progress_path.read_text(encoding="utf-8").splitlines()[0])

        self.assertIn("[进度][依赖 API 变化][处理依赖]", stderr.getvalue())
        self.assertIn("[1/2]", stderr.getvalue())
        self.assertNotIn("[step4]", stderr.getvalue())
        self.assertEqual(event["step_id"], "step4")
        self.assertEqual(event["phase"], "dependency")
        self.assertEqual(event["item"], "com.acme:demo")
        self.assertEqual(event["estimated_remaining_sec"], 1.25)
        self.assertIn("预计剩余约 1.2s", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
