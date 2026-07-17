import contextlib
import csv
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import compat
import run_step
import s1_dep_diff
import s4_jar_compare
import step1_observability


class Step1ObservabilityTest(unittest.TestCase):
    def test_ref_resolution_event_records_requested_and_resolved_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            observer = step1_observability.Step1Observer(
                Path(tmp) / "evidence/dependencies/dep_changes.csv"
            )
            commit = "a" * 40
            event = observer.event(
                "ref_resolution",
                "completed",
                "当前侧源码版本已固定",
                side="current",
                details={
                    "requested_ref": "release-2.0.0",
                    "resolved_ref": "origin/release-2.0.0",
                    "resolved_commit": commit,
                    "resolution_mode": "unique_remote",
                    "candidate_count": 1,
                },
            )

            self.assertEqual(event["details"]["resolved_commit"], commit)
            persisted = json.loads(
                observer.progress_path.read_text(encoding="utf-8").splitlines()[-1]
            )
            self.assertEqual(persisted["details"]["requested_ref"], "release-2.0.0")
            self.assertEqual(persisted["details"]["candidate_count"], 1)

    def test_streaming_command_relays_output_and_still_returns_it(self):
        relayed = io.StringIO()
        command = [
            sys.executable,
            "-c",
            "import sys; print('maven-stdout', flush=True); print('maven-stderr', file=sys.stderr, flush=True)",
        ]

        with contextlib.redirect_stderr(relayed):
            stdout, stderr, rc = compat.run_cmd(command, stream_output=True)

        self.assertEqual(rc, 0)
        self.assertIn("maven-stdout", stdout)
        self.assertIn("maven-stderr", stderr)
        self.assertIn("maven-stdout", relayed.getvalue())
        self.assertIn("maven-stderr", relayed.getvalue())

    def test_run_python_streams_step1_child_output(self):
        captured = {}

        def fake_run_cmd(cmd, **kwargs):
            captured.update(kwargs)
            return "", "already relayed", 0

        with patch.object(run_step, "run_cmd", side_effect=fake_run_cmd):
            run_step.run_python("s1_dep_diff.py", [], "/tmp", report_dir="/tmp")

        self.assertTrue(captured["stream_output"])
        self.assertFalse(captured["stream_stdout"])

    def test_run_python_keeps_legacy_run_cmd_signature_for_other_steps(self):
        calls = []

        def fake_run_cmd(cmd, cwd=None, timeout=None, env=None):
            calls.append(list(cmd))
            return "", "", 0

        with patch.object(run_step, "run_cmd", side_effect=fake_run_cmd):
            run_step.run_python("s3_scan.py", [], "/tmp", report_dir="/tmp")

        self.assertEqual(len(calls), 1)

    def test_progress_and_timing_files_are_created_before_step1_finishes(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "evidence/dependencies/dep_changes.csv"
            output.parent.mkdir(parents=True)
            legacy_progress = output.parent / "step1_progress.jsonl"
            legacy_timing = output.parent / "step1_timing.csv"
            legacy_progress.write_text("stale\n", encoding="utf-8")
            legacy_timing.write_text("stale\n", encoding="utf-8")
            observer = step1_observability.Step1Observer(output)

            self.assertEqual(
                observer.progress_path,
                Path(tmp).resolve() / ".runtime/observability/step1_progress.jsonl",
            )
            self.assertEqual(
                observer.timing_path,
                Path(tmp).resolve() / ".runtime/observability/step1_timing.csv",
            )
            self.assertFalse(legacy_progress.exists())
            self.assertFalse(legacy_timing.exists())

            token = observer.start_phase(
                "maven_package",
                side="base",
                item="app-module",
                command="mvn -pl app-module -am -DskipTests package",
                message="开始构建基准侧",
            )

            progress_rows = [
                json.loads(line)
                for line in observer.progress_path.read_text(encoding="utf-8").splitlines()
            ]
            with observer.timing_path.open(encoding="utf-8", newline="") as handle:
                timing_rows_before_finish = list(csv.DictReader(handle))

            self.assertEqual(progress_rows[-1]["status"], "running")
            self.assertEqual(progress_rows[-1]["side"], "base")
            self.assertIn("mvn -pl app-module", progress_rows[-1]["command"])
            self.assertEqual(timing_rows_before_finish, [])

            observer.finish_phase(token, status="completed", message="基准侧构建完成")

            with observer.timing_path.open(encoding="utf-8", newline="") as handle:
                timing_rows = list(csv.DictReader(handle))
            self.assertEqual(len(timing_rows), 1)
            self.assertEqual(timing_rows[0]["phase"], "maven_package")
            self.assertEqual(timing_rows[0]["side"], "base")
            self.assertEqual(timing_rows[0]["status"], "completed")
            self.assertGreaterEqual(float(timing_rows[0]["elapsed_sec"]), 0.0)
            self.assertGreater(float(timing_rows[0]["peak_rss_mb"]), 0.0)

    def test_step1_timing_schema_records_peak_rss(self):
        self.assertIn("peak_rss_mb", step1_observability.TIMING_FIELDS)

    def test_step1_timing_records_cumulative_cache_counters(self):
        with tempfile.TemporaryDirectory() as tmp:
            observer = step1_observability.Step1Observer(
                Path(tmp) / "evidence/dependencies/dep_changes.csv"
            )
            observer.increment_counter("cache_hits", 2)
            observer.increment_counter("cache_misses", 1)
            with observer.phase("artifact_parse"):
                pass

            with observer.timing_path.open(encoding="utf-8", newline="") as handle:
                row = list(csv.DictReader(handle))[0]

        self.assertEqual(row["cache_hits"], "2")
        self.assertEqual(row["cache_misses"], "1")

    def test_maven_package_streams_and_records_side_specific_timing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "target/app.jar"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"placeholder")
            observer = step1_observability.Step1Observer(
                root / "report/evidence/dependencies/dep_changes.csv"
            )
            calls = []

            def fake_run_cmd(command, **kwargs):
                calls.append((list(command), dict(kwargs)))
                return "", "", 0

            packaged_raw = [{
                "entry_id": "1",
                "lib_entry": "BOOT-INF/lib/demo-1.0.jar",
                "lib_name": "demo-1.0.jar",
                "coord": "com.example:demo",
                "group_id": "com.example",
                "artifact_id": "demo",
                "version": "1.0",
                "classifier": "",
                "match_source": "embedded-pom",
                "read_error": "",
            }]
            with patch.object(s1_dep_diff, "run_cmd", side_effect=fake_run_cmd), \
                 patch.object(s1_dep_diff, "_resolve_module_dir_for_packaging", return_value=str(root)), \
                 patch.object(s1_dep_diff, "_discover_packaged_archives", return_value=[artifact]), \
                 patch.object(s1_dep_diff, "_detect_archive_packaging_type", return_value="boot_jar"), \
                 patch.object(s1_dep_diff, "_inspect_packaged_archive", return_value=packaged_raw):
                s1_dep_diff.collect_maven_deps_for_workspace(
                    str(root), observer=observer, side="base",
                )

            self.assertTrue(calls[0][1]["stream_output"])
            with observer.timing_path.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertTrue(any(
                row["phase"] == "maven_package"
                and row["side"] == "base"
                and row["status"] == "completed"
                for row in rows
            ))
            self.assertTrue(any(row["phase"] == "artifact_parse" for row in rows))
            self.assertTrue(any(
                row["phase"] == "artifact_coordinate_resolution" for row in rows
            ))

    def test_failed_phase_is_recorded_in_both_diagnostic_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            observer = step1_observability.Step1Observer(
                Path(tmp) / "evidence/dependencies/dep_changes.csv"
            )
            with self.assertRaisesRegex(RuntimeError, "broken artifact"):
                with observer.phase("artifact_parse", side="current"):
                    raise RuntimeError("broken artifact")

            progress = [
                json.loads(line)
                for line in observer.progress_path.read_text(encoding="utf-8").splitlines()
            ]
            with observer.timing_path.open(encoding="utf-8", newline="") as handle:
                timing = list(csv.DictReader(handle))
            self.assertEqual(progress[-1]["status"], "failed")
            self.assertEqual(timing[-1]["status"], "failed")
            self.assertIn("broken artifact", timing[-1]["message"])

    def test_step1_cleanup_contract_includes_observability_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = set(run_step.step_output_paths_for_cleanup("step1", tmp))

        observability = Path(tmp).resolve() / ".runtime/observability"
        self.assertIn(observability / "step1_progress.jsonl", paths)
        self.assertIn(observability / "step1_timing.csv", paths)

    def test_step4_and_step5_cleanup_contract_includes_observability_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            observability = Path(tmp).resolve() / ".runtime/observability"
            step4_paths = set(run_step.step_output_paths_for_cleanup("step4", tmp))
            step5_paths = set(run_step.step_output_paths_for_cleanup("step5", tmp))

        self.assertIn(observability / "step4_timing.csv", step4_paths)
        self.assertIn(observability / "step5_timing.csv", step5_paths)

    def test_step4_timing_records_resources_and_external_processes(self):
        with tempfile.TemporaryDirectory() as tmp:
            timing = s4_jar_compare.Step4TimingRecorder(tmp)
            timing.record(
                "dependency.japicmp",
                status="success",
                elapsed=0.25,
                external_process_count=1,
            )
            timing.flush()

            with Path(timing.path).open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(rows[0]["external_process_count"], "1")
        self.assertGreater(float(rows[0]["peak_rss_mb"]), 0.0)


if __name__ == "__main__":
    unittest.main()
