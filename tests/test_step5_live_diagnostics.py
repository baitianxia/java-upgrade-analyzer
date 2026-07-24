import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import confidence_weighted_tracer as tracer
import run_step
import s5_call_chain_engine_integrated as step5
from step5_artifact_fact_store import Step5ArtifactFactStore
from step5_diagnostics import Step5DiagnosticRecorder
from step5_evidence_model import CollectorBatch, EvidenceFailure


class Step5LiveDiagnosticsTest(unittest.TestCase):
    def test_first_not_analyzed_reason_is_persisted_immediately(self):
        with tempfile.TemporaryDirectory() as tmp:
            recorder = Step5DiagnosticRecorder(tmp)
            result = SimpleNamespace(
                analysis_status="not_analyzed",
                reason_code="ARTIFACT_BYTECODE_COVERAGE_INCOMPLETE",
                api_name="com.acme.Target.call",
                api_signature="()",
            )

            recorder.record_trace_result(result, 1, 1972)
            events = [
                json.loads(line)
                for line in recorder.path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(len(events), 1)
        self.assertEqual(
            events[0]["reason_code"],
            "ARTIFACT_BYTECODE_COVERAGE_INCOMPLETE",
        )
        self.assertEqual(events[0]["current"], 1)
        self.assertEqual(events[0]["total"], 1972)
        self.assertEqual(events[0]["failure_count"], 1)

    def test_global_artifact_coverage_stops_on_first_affected_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            recorder = Step5DiagnosticRecorder(tmp)
            result = SimpleNamespace(
                analysis_status="not_analyzed",
                reason_code="ARTIFACT_BYTECODE_COVERAGE_INCOMPLETE",
                api_name="com.acme.Target.call",
                api_signature="()",
            )

            with self.assertRaises(step5.Step5GlobalCoverageBlocked):
                step5.record_trace_diagnostic_or_raise(
                    recorder,
                    result,
                    1,
                    1972,
                )

            events = recorder.path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(len(events), 1)

    def test_collector_failures_are_grouped_without_losing_scope(self):
        failures = (
            EvidenceFailure(
                stage="spring_aop_activation",
                reason_code="SPRING_RUNTIME_CLASS_AMBIGUOUS",
                blocking=True,
                class_name="demo.Config",
                scope="path",
            ),
            EvidenceFailure(
                stage="spring_transaction_proxy",
                reason_code="SPRING_RUNTIME_CLASS_AMBIGUOUS",
                blocking=True,
                class_name="demo.OtherConfig",
                scope="path",
            ),
        )
        batch = CollectorBatch(
            collector="spring",
            version="1",
            failures=failures,
        )
        with tempfile.TemporaryDirectory() as tmp:
            recorder = Step5DiagnosticRecorder(tmp)
            recorder.record_collector_failures(
                "evidence.framework_adapters",
                (batch,),
            )
            event = json.loads(
                recorder.path.read_text(encoding="utf-8").splitlines()[0]
            )

        self.assertEqual(event["reason_code"], "SPRING_RUNTIME_CLASS_AMBIGUOUS")
        self.assertEqual(event["scope"], "path")
        self.assertEqual(event["failure_count"], 2)
        self.assertEqual(len(event["samples"]), 2)

    def test_tracer_callback_receives_each_completed_result(self):
        callback_events = []
        api_rows = [{
            "coord": "com.acme:demo",
            "api_name": "com.acme.Target.call",
        }]
        result = SimpleNamespace(analysis_status="not_analyzed")
        graph = SimpleNamespace(runtime_dependency_catalog={})
        with patch.object(
            tracer,
            "trace_api_with_confidence_weighting",
            return_value=result,
        ):
            traced = tracer.trace_all_apis_with_confidence_weighting(
                api_rows,
                graph,
                {},
                diagnostic_callback=lambda item, current, total: (
                    callback_events.append((item, current, total))
                ),
            )

        self.assertEqual(traced, [result])
        self.assertEqual(callback_events, [(result, 1, 1)])

    def test_duplicate_archive_entry_is_a_pre_graph_inventory_blocker(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "duplicate.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("demo/Config.class", b"one")
                archive.writestr("demo/Config.class", b"two")
            digest = hashlib.sha256(jar_path.read_bytes()).hexdigest()
            entry = {
                "coord": "com.acme:duplicate",
                "jar_path": str(jar_path),
                "sha256": digest,
                "artifact_entry": "BOOT-INF/lib/duplicate.jar",
            }
            catalog = {
                "status": "complete",
                "entries": [entry],
                "by_coord": {entry["coord"]: entry},
            }
            store = Step5ArtifactFactStore.from_catalog(catalog)

            blockers = step5.runtime_artifact_inventory_blockers(store, catalog)

        self.assertEqual(len(blockers), 1)
        self.assertIn("artifact_duplicate_entries", blockers[0]["reason"])

    def test_artifact_wide_business_bytecode_failure_is_fatal(self):
        batch = CollectorBatch(
            collector="business_bytecode",
            version="1",
            failures=(EvidenceFailure(
                stage="business-bytecode",
                reason_code="CURRENT_FINAL_ARTIFACT_SHA_MISMATCH",
                blocking=True,
                scope="global",
            ),),
        )

        self.assertEqual(
            step5.fatal_business_bytecode_failures(batch),
            list(batch.failures),
        )

    def test_run_step_streams_step5_stderr_while_preserving_stdout_protocol(self):
        captured = {}

        def fake_run_cmd(_cmd, **kwargs):
            captured.update(kwargs)
            return "", "already relayed", 0

        with tempfile.TemporaryDirectory() as tmp, patch.object(
            run_step,
            "run_cmd",
            side_effect=fake_run_cmd,
        ):
            run_step.run_python(
                "s5_call_chain_engine_integrated.py",
                [],
                tmp,
                report_dir=tmp,
            )

        self.assertTrue(captured["stream_output"])
        self.assertFalse(captured["stream_stdout"])


if __name__ == "__main__":
    unittest.main()
