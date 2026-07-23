import csv
import importlib.util
import json
import os
import platform
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from real_project_regression import canonical_step5_result_fingerprint  # noqa: E402
import s5_call_chain_engine_integrated as step5_engine  # noqa: E402
import step5_evidence_ingestion as evidence_ingestion  # noqa: E402
import step5_memory_observer  # noqa: E402
import compat  # noqa: E402


class Step5ResultFingerprintTest(unittest.TestCase):
    def _write_report(self, root, *, status="reachable", generated_at="now", rss=100.0):
        call_chain = root / "evidence" / "call_chain"
        call_chain.mkdir(parents=True)
        (call_chain / "summary.json").write_text(
            json.dumps({
                "generated_at": generated_at,
                "reachable": 1 if status == "reachable" else 0,
                "not_analyzed": 1 if status == "not_analyzed" else 0,
                "meta": {
                    "graph_stats": {
                        "step5_perf": {"main": {"peak_rss_mb": rss}},
                    },
                },
            }, ensure_ascii=False),
            encoding="utf-8",
        )
        with (call_chain / "alerts.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=[
                "api_id", "api_status", "path_id", "path_text", "evidence_files",
            ])
            writer.writeheader()
            writer.writerow({
                "api_id": "API-1",
                "api_status": status,
                "path_id": "PATH-1",
                "path_text": "app.Entry.run() -> vendor.Target.call()",
                "evidence_files": str(root / "artifact.jar!/app/Entry.class"),
            })

    def test_ignores_only_volatile_runtime_values_and_report_root(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_root = Path(first)
            second_root = Path(second)
            self._write_report(first_root, generated_at="one", rss=100.0)
            self._write_report(second_root, generated_at="two", rss=250.0)

            self.assertEqual(
                canonical_step5_result_fingerprint(first_root),
                canonical_step5_result_fingerprint(second_root),
            )

    def test_changes_when_analysis_status_changes(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_root = Path(first)
            second_root = Path(second)
            self._write_report(first_root, status="reachable")
            self._write_report(second_root, status="not_analyzed")

            self.assertNotEqual(
                canonical_step5_result_fingerprint(first_root),
                canonical_step5_result_fingerprint(second_root),
            )

    def test_rejects_directory_without_step5_result_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                canonical_step5_result_fingerprint(Path(tmp))

    def test_normalizes_expanded_and_compact_failure_occurrences(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_root = Path(first)
            second_root = Path(second)
            self._write_report(first_root)
            self._write_report(second_root)
            first_summary = first_root / "evidence" / "call_chain" / "summary.json"
            second_summary = second_root / "evidence" / "call_chain" / "summary.json"
            common = {
                "collector": "business_bytecode",
                "reason_code": "BYTECODE_CALLER_UNRESOLVED",
                "blocking": True,
                "api_identity": "vendor.Target.call()",
            }
            legacy = json.loads(first_summary.read_text(encoding="utf-8"))
            legacy["meta"]["graph_stats"]["evidence_ingestion"] = {
                "failure_count": 1,
                "failures": [{
                    **common,
                    "artifact": str(first_root / "business.jar"),
                    "class_name": "app.Entry",
                    "detail": "1 occurrence",
                    "occurrences": [{
                        "artifact": str(first_root / "business.jar"),
                        "class_name": "app.Entry",
                        "detail": "detail",
                    }],
                }],
            }
            first_summary.write_text(json.dumps(legacy), encoding="utf-8")
            compact = json.loads(second_summary.read_text(encoding="utf-8"))
            compact["meta"]["graph_stats"]["evidence_ingestion"] = {
                "failure_count": 1,
                "failure_occurrence_fields": ["artifact", "class_name", "detail"],
                "failures": [{
                    **common,
                    "artifact": str(second_root / "business.jar"),
                    "class_name": "app.Entry",
                    "detail": "1 occurrence",
                    "occurrences": [[
                        str(second_root / "business.jar"), "app.Entry", "detail",
                    ]],
                }],
            }
            second_summary.write_text(json.dumps(compact), encoding="utf-8")

            self.assertEqual(
                canonical_step5_result_fingerprint(first_root),
                canonical_step5_result_fingerprint(second_root),
            )


class ReverseEdgeOverlayTest(unittest.TestCase):
    def test_reuses_untouched_base_lists_and_combines_only_overlay_keys(self):
        base_only = [SimpleNamespace(evidence_type="ast")]
        shared = [SimpleNamespace(evidence_type="source")]
        graph = SimpleNamespace(reverse_edges={"base": base_only, "shared": shared})
        batch = SimpleNamespace(edges=(
            SimpleNamespace(
                edge_kind="bytecode_reflection_method_invocation",
                callee_symbol="shared",
            ),
            SimpleNamespace(
                edge_kind="bytecode_reflection_class_lookup",
                callee_symbol="overlay",
            ),
            SimpleNamespace(edge_kind="bytecode_method_invocation", callee_symbol="ignored"),
        ))

        snapshot = step5_engine._graph_snapshot_with_bytecode_batch(graph, batch)

        self.assertIs(snapshot.reverse_edges["base"], base_only)
        self.assertEqual(
            [item.evidence_type for item in snapshot.reverse_edges["shared"]],
            ["source", "bytecode_reflection_method_invocation"],
        )
        self.assertEqual(
            [item.evidence_type for item in snapshot.reverse_edges["overlay"]],
            ["bytecode_reflection_class_lookup"],
        )
        self.assertNotIn("ignored", snapshot.reverse_edges)
        self.assertEqual(list(snapshot.reverse_edges), ["base", "shared", "overlay"])

    def test_overlay_mapping_is_read_only(self):
        overlay_type = step5_engine._ReverseEdgeOverlay
        overlay = overlay_type({"base": []}, {"overlay": (object(),)})

        with self.assertRaises(TypeError):
            overlay["new"] = []


class FrameworkSnapshotTest(unittest.TestCase):
    def test_copies_only_keys_used_by_framework_proxy_projection(self):
        relevant_edges = [SimpleNamespace(caller_symbol_id="app.Entry.run")]
        irrelevant_edges = [SimpleNamespace(caller_symbol_id="app.Other.run")]
        reverse_edges = {
            "com.acme.Mapper.find(java.lang.String)": relevant_edges,
            "com.acme.Mapper.other()": irrelevant_edges,
            **{f"unrelated.Type{index}.call()": [object()] for index in range(100)},
        }
        records = [
            (
                SimpleNamespace(collector="mybatis"),
                SimpleNamespace(edge_kind="mybatis_mapper_proxy_dispatch"),
                {
                    "source_owner": "com.acme.Mapper",
                    "source_member": "find",
                    "parameter_count": 1,
                },
            ),
        ]

        snapshot = evidence_ingestion._snapshot_framework_reverse_edges(
            reverse_edges, records,
        )

        self.assertEqual(
            list(snapshot), ["com.acme.Mapper.find(java.lang.String)"],
        )
        self.assertEqual(tuple(relevant_edges), snapshot["com.acme.Mapper.find(java.lang.String)"])
        self.assertIsInstance(snapshot["com.acme.Mapper.find(java.lang.String)"], tuple)


class Step5MemoryObserverTest(unittest.TestCase):
    def test_imports_and_runs_when_resource_module_is_unavailable(self):
        module_path = ROOT_DIR / "scripts" / "step5_memory_observer.py"
        spec = importlib.util.spec_from_file_location(
            "step5_memory_observer_without_resource", module_path,
        )
        module = importlib.util.module_from_spec(spec)
        real_import = __import__

        def import_without_resource(name, *args, **kwargs):
            if name == "resource":
                raise ImportError("resource is unavailable on Windows")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=import_without_resource):
            spec.loader.exec_module(module)

        observer = module.ProcessTreeObserver(
            platform_name="windows", interval_sec=1,
        ).start()
        metrics = observer.stop()

        self.assertFalse(metrics["process_tree_observer_supported"])
        self.assertGreaterEqual(metrics["self_cpu_sec"], 0.0)
        self.assertEqual(metrics["child_cpu_sec"], 0.0)
        self.assertEqual(module.peak_rss_mb(platform_name="windows"), 0.0)

    def test_reads_linux_current_rss_without_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            status = Path(tmp) / "status"
            status.write_text("Name:\tpython\nVmRSS:\t2048 kB\n", encoding="utf-8")

            self.assertEqual(
                step5_memory_observer.current_rss_mb(
                    platform_name="linux", linux_status_path=status,
                ),
                2.0,
            )

    def test_uses_injected_darwin_reader_and_never_raises(self):
        self.assertEqual(
            step5_memory_observer.current_rss_mb(
                platform_name="darwin", darwin_reader=lambda: 12.5,
            ),
            12.5,
        )
        self.assertEqual(
            step5_memory_observer.current_rss_mb(
                platform_name="darwin",
                darwin_reader=lambda: (_ for _ in ()).throw(OSError("failed")),
            ),
            0.0,
        )

    def test_records_graph_counts_without_mutating_graph(self):
        first = [object(), object()]
        second = [object()]
        graph = SimpleNamespace(
            methods_by_id={"a": object()},
            reverse_edges={"x": first, "y": second},
        )
        stats = {"step5_perf": {}}

        sample = step5_memory_observer.record_step5_memory(
            stats,
            "graph_ready",
            graph=graph,
            current_reader=lambda: 10.0,
            peak_reader=lambda: 20.0,
        )

        self.assertEqual(sample["method_count"], 1)
        self.assertEqual(sample["reverse_edge_key_count"], 2)
        self.assertEqual(sample["reverse_edge_count"], 3)
        self.assertIs(graph.reverse_edges["x"], first)
        self.assertEqual(
            stats["step5_perf"]["memory"]["graph_ready_current_rss_mb"],
            10.0,
        )

    def test_uses_graph_edge_count_without_rescanning_reverse_edge_buckets(self):
        class NoValues(dict):
            def values(self):
                raise AssertionError("reverse-edge buckets were rescanned")

        graph = SimpleNamespace(
            methods_by_id={},
            reverse_edges=NoValues({"x": [object()]}),
            reverse_edge_count=7,
        )

        sample = step5_memory_observer.record_step5_memory(
            {"step5_perf": {}}, "graph_ready", graph=graph,
            current_reader=lambda: 1.0, peak_reader=lambda: 2.0,
        )

        self.assertEqual(7, sample["reverse_edge_count"])

    def test_memory_metrics_are_written_to_step5_timing_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            timing_path = step5_engine._write_step5_timing_csv(
                tmp,
                {
                    "step5_perf": {
                        "memory": {
                            "graph_ready_current_rss_mb": 10.0,
                            "graph_ready_peak_rss_mb": 20.0,
                        },
                    },
                },
            )
            with Path(timing_path).open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))

        values = {(row["section"], row["metric"]): row["value"] for row in rows}
        self.assertEqual(
            values[("memory", "graph_ready_current_rss_mb")],
            "10.0",
        )

    def test_process_tree_observer_sums_descendants_without_retaining_processes(self):
        root_pid = os.getpid()
        process_table = {
            root_pid: {"ppid": 1, "rss_kb": 10 * 1024, "cpu_sec": 1.0},
            root_pid + 1: {"ppid": root_pid, "rss_kb": 5 * 1024, "cpu_sec": 0.2},
            root_pid + 2: {"ppid": root_pid + 1, "rss_kb": 3 * 1024, "cpu_sec": 0.1},
            root_pid + 3: {"ppid": 1, "rss_kb": 50 * 1024, "cpu_sec": 4.0},
        }
        observer = step5_memory_observer.ProcessTreeObserver(
            platform_name="linux",
            interval_sec=1,
            process_reader=lambda: process_table,
        ).start()
        metrics = observer.stop()

        self.assertEqual(metrics["process_tree_peak_rss_mb"], 18.0)
        self.assertEqual(metrics["child_process_peak_rss_mb"], 8.0)
        self.assertGreaterEqual(metrics["child_cpu_sec"], 0.3)
        self.assertGreaterEqual(metrics["process_tree_sample_count"], 2)

    def test_external_command_counts_and_wall_time_are_grouped_by_tool(self):
        observer = step5_memory_observer.ProcessTreeObserver(
            platform_name="linux",
            interval_sec=1,
            process_reader=lambda: {},
        ).start()
        first = observer.command_started(["/jdk/bin/javap", "-version"])
        second = observer.command_started(["javap", "Example"])
        time.sleep(0.01)
        observer.command_finished(first)
        observer.command_finished(second)
        metrics = observer.stop()

        self.assertEqual(metrics["external_process_count"], 2)
        self.assertEqual(metrics["external_process_peak_concurrency"], 2)
        self.assertEqual(metrics["external_process_counts_by_tool"], {"javap": 2})
        self.assertGreater(metrics["external_process_wall_sec"], 0.0)

    def test_temporary_file_high_water_is_recorded_as_bytes_and_mib(self):
        observer = step5_memory_observer.ProcessTreeObserver(
            platform_name="linux",
            interval_sec=1,
            process_reader=lambda: {},
            temporary_paths=("/tmp/step5-runtime",),
            temporary_size_reader=lambda _paths: 2 * 1024 * 1024,
        ).start()
        metrics = observer.stop()

        self.assertEqual(metrics["temporary_file_peak_bytes"], 2 * 1024 * 1024)
        self.assertEqual(metrics["temporary_file_peak_mb"], 2.0)

    def test_recorded_phase_flattens_tool_counts_for_timing_csv(self):
        observer = step5_memory_observer.ProcessTreeObserver(
            platform_name="linux",
            interval_sec=1,
            process_reader=lambda: {},
        ).start()
        token = observer.command_started(["/jdk/bin/jdeps", "artifact.jar"])
        observer.command_finished(token)
        previous = step5_memory_observer.set_active_process_tree_observer(observer)
        try:
            sample = step5_memory_observer.record_step5_memory(
                {"step5_perf": {}},
                "bytecode",
                current_reader=lambda: 1.0,
                peak_reader=lambda: 2.0,
            )
        finally:
            step5_memory_observer.set_active_process_tree_observer(previous)
            observer.stop()

        self.assertEqual(sample["external_process_count"], 1)
        self.assertEqual(sample["external_process_count_jdeps"], 1)

    def test_resource_budget_warns_then_blocks_on_process_tree_peak(self):
        warning = step5_memory_observer.evaluate_process_tree_budget(
            {"process_tree_peak_rss_mb": 128.0}, soft_limit_mb=64.0,
        )
        blocked = step5_memory_observer.evaluate_process_tree_budget(
            {"process_tree_peak_rss_mb": 128.0}, hard_limit_mb=96.0,
        )

        self.assertEqual(warning["status"], "warning")
        self.assertEqual(warning["reason_code"], "STEP5_PROCESS_TREE_RSS_SOFT_LIMIT_EXCEEDED")
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["reason_code"], "STEP5_PROCESS_TREE_RSS_HARD_LIMIT_EXCEEDED")

    def test_step5_hard_budget_fails_closed_at_observation_boundary(self):
        sample = {
            "current_rss_mb": 20.0,
            "peak_rss_mb": 30.0,
            "method_count": 1,
            "reverse_edge_count": 2,
            "process_tree_peak_rss_mb": 80.0,
        }
        with patch.dict(
            os.environ,
            {"JUA_STEP5_PROCESS_TREE_HARD_RSS_MB": "64"},
            clear=False,
        ), patch.object(step5_engine, "record_step5_memory", return_value=sample):
            with self.assertRaisesRegex(
                step5_memory_observer.Step5ResourceBudgetExceeded,
                "STEP5_PROCESS_TREE_RSS_HARD_LIMIT_EXCEEDED",
            ):
                step5_engine._observe_step5_memory({}, "graph_ready")

    def test_step5_soft_budget_reduces_workers_and_evicts_reloadable_bodies(self):
        method = SimpleNamespace(_body_text_cached="large method body")
        graph = SimpleNamespace(methods_by_id={"method": method})
        sample = {
            "current_rss_mb": 20.0,
            "peak_rss_mb": 30.0,
            "method_count": 1,
            "reverse_edge_count": 2,
            "process_tree_peak_rss_mb": 80.0,
        }
        with patch.dict(
            os.environ,
            {"JUA_STEP5_PROCESS_TREE_SOFT_RSS_MB": "64"},
            clear=False,
        ), patch.object(step5_engine, "record_step5_memory", return_value=sample):
            stats = {}
            step5_engine._observe_step5_memory(stats, "graph_ready", graph=graph)

        budget = stats["step5_perf"]["resource_budget"]
        self.assertEqual(budget["status"], "warning")
        self.assertEqual(budget["adaptive_javap_workers"], 1)
        self.assertEqual(budget["body_cache_evictions"], 1)
        self.assertEqual(method._body_text_cached, "")

    @unittest.skipUnless(platform.system() in {"Linux", "Darwin"}, "process tree sampling is Linux/macOS only")
    def test_real_child_pressure_is_observed_through_shared_command_wrapper(self):
        observer = step5_memory_observer.ProcessTreeObserver(interval_sec=0.02).start()
        previous = compat.set_process_observer(observer)
        try:
            _stdout, stderr, returncode = compat.run_cmd([
                sys.executable,
                "-c",
                "import time; payload=bytearray(16*1024*1024); time.sleep(0.25)",
            ], timeout=5)
        finally:
            compat.set_process_observer(previous)
            metrics = observer.stop()

        self.assertEqual((returncode, stderr), (0, ""))
        self.assertGreater(metrics["child_process_peak_rss_mb"], 8.0)
        self.assertEqual(metrics["external_process_count"], 1)
        self.assertEqual(metrics["external_process_counts_by_tool"], {Path(sys.executable).name: 1})
        pressure_budget = step5_memory_observer.evaluate_process_tree_budget(
            metrics, hard_limit_mb=1.0,
        )
        self.assertEqual(pressure_budget["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
