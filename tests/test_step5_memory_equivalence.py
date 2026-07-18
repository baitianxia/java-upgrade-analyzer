import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from real_project_regression import canonical_step5_result_fingerprint  # noqa: E402
import s5_call_chain_engine_integrated as step5_engine  # noqa: E402
import step5_evidence_ingestion as evidence_ingestion  # noqa: E402
import step5_memory_observer  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
