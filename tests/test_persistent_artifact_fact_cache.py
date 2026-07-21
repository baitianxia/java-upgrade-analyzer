import hashlib
import json
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import confidence_weighted_tracer as tracer  # noqa: E402


JAVAP_OUTPUT = """
public class com.example.TargetBridge {
  public void use(java.lang.String);
    descriptor: (Ljava/lang/String;)V
    Code:
       0: invokestatic #7 // Method com/vendor/Target.removed:(Ljava/lang/String;)V
}
"""


class PersistentArtifactFactCacheTest(unittest.TestCase):
    def setUp(self):
        tracer.clear_immutable_artifact_parse_cache()

    def tearDown(self):
        tracer.clear_immutable_artifact_parse_cache()

    @staticmethod
    def _graph(cache_dir):
        return SimpleNamespace(persistent_artifact_cache_dir=str(cache_dir))

    @staticmethod
    def _load(graph, artifact_sha256="a" * 64):
        return tracer._load_runtime_dependency_class_references(
            {},
            "com.vendor:target",
            "/tmp/target.jar",
            "com.example.TargetBridge",
            artifact_sha256=artifact_sha256,
            target_jdk="17",
            graph=graph,
            class_entry="com/example/TargetBridge.class",
        )

    @staticmethod
    def _fingerprint(value):
        encoded = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def test_hot_cache_preserves_fact_fingerprint_without_running_javap(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "facts"
            cold_graph = self._graph(cache_dir)
            hot_graph = self._graph(cache_dir)
            with patch.object(
                tracer, "_javap_tool_identity", return_value="javap:17.0.1"
            ), patch.object(
                tracer, "_run_javap_bytecode_dump", return_value=JAVAP_OUTPUT
            ) as mocked_javap:
                cold = self._load(cold_graph)
                tracer.clear_immutable_artifact_parse_cache()
                hot = self._load(hot_graph)

            cache_files = list(cache_dir.rglob("*.json"))
            hot_perf = tracer._finalize_step5_perf_stats(hot_graph)["bytecode_scan"]

            api_row = {
                "api_name": "com.vendor.Target.removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
            }
            cold_matches = tracer._match_runtime_dependency_references(api_row, cold)
            hot_matches = tracer._match_runtime_dependency_references(api_row, hot)

        self.assertEqual(self._fingerprint(cold), self._fingerprint(hot))
        self.assertEqual(cold, hot)
        self.assertEqual(self._fingerprint(cold_matches), self._fingerprint(hot_matches))
        self.assertEqual(len(hot_matches), 1)
        self.assertEqual(mocked_javap.call_count, 1)
        self.assertEqual(len(cache_files), 1)
        self.assertEqual(hot_perf["persistent_artifact_cache_hits"], 1)
        self.assertEqual(hot_perf.get("class_entries_parsed", 0), 0)

    def test_artifact_or_tool_change_cannot_reuse_stale_fact(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "facts"
            graph = self._graph(cache_dir)
            with patch.object(
                tracer, "_javap_tool_identity", return_value="javap:17.0.1"
            ), patch.object(
                tracer, "_run_javap_bytecode_dump", return_value=JAVAP_OUTPUT
            ) as mocked_javap:
                first = self._load(graph, artifact_sha256="a" * 64)
                tracer.clear_immutable_artifact_parse_cache()
                replaced_artifact = self._load(graph, artifact_sha256="b" * 64)

            tracer.clear_immutable_artifact_parse_cache()
            with patch.object(
                tracer, "_javap_tool_identity", return_value="javap:21.0.2"
            ), patch.object(
                tracer, "_run_javap_bytecode_dump", return_value=JAVAP_OUTPUT
            ) as upgraded_javap:
                upgraded_tool = self._load(graph, artifact_sha256="a" * 64)

            cache_files = list(cache_dir.rglob("*.json"))

        self.assertEqual(self._fingerprint(first), self._fingerprint(replaced_artifact))
        self.assertEqual(self._fingerprint(first), self._fingerprint(upgraded_tool))
        self.assertEqual(mocked_javap.call_count, 2)
        self.assertEqual(upgraded_javap.call_count, 1)
        self.assertEqual(len(cache_files), 3)

    def test_corrupt_cache_fails_open_and_is_rebuilt(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "facts"
            graph = self._graph(cache_dir)
            with patch.object(
                tracer, "_javap_tool_identity", return_value="javap:17.0.1"
            ), patch.object(
                tracer, "_run_javap_bytecode_dump", return_value=JAVAP_OUTPUT
            ) as mocked_javap:
                expected = self._load(graph)
                cache_file = next(cache_dir.rglob("*.json"))
                polluted = json.loads(cache_file.read_text(encoding="utf-8"))
                polluted["result"]["caller_owner"] = "polluted.Owner"
                cache_file.write_text(json.dumps(polluted), encoding="utf-8")
                tracer.clear_immutable_artifact_parse_cache()
                actual = self._load(graph)

            payload = json.loads(cache_file.read_text(encoding="utf-8"))
            perf = tracer._finalize_step5_perf_stats(graph)["bytecode_scan"]

        self.assertEqual(self._fingerprint(expected), self._fingerprint(actual))
        self.assertEqual(mocked_javap.call_count, 2)
        self.assertEqual(payload["schema"], tracer.ARTIFACT_FACT_CACHE_SCHEMA)
        self.assertEqual(perf["persistent_artifact_cache_invalid"], 1)

    def test_concurrent_loaders_share_one_parse_and_one_cache_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "facts"
            graph = self._graph(cache_dir)

            def load():
                return self._load(graph)

            def slow_javap(*_args, **_kwargs):
                time.sleep(0.05)
                return JAVAP_OUTPUT

            with patch.object(
                tracer, "_javap_tool_identity", return_value="javap:17.0.1"
            ), patch.object(
                tracer, "_run_javap_bytecode_dump", side_effect=slow_javap
            ) as mocked_javap:
                with ThreadPoolExecutor(max_workers=4) as executor:
                    results = list(executor.map(lambda _index: load(), range(4)))

            cache_files = list(cache_dir.rglob("*.json"))
            temporary_files = list(cache_dir.rglob("*.tmp"))
            payload = json.loads(cache_files[0].read_text(encoding="utf-8"))

        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual(mocked_javap.call_count, 1)
        self.assertEqual(len(cache_files), 1)
        self.assertEqual(temporary_files, [])
        self.assertEqual(payload["schema"], tracer.ARTIFACT_FACT_CACHE_SCHEMA)

    def test_concurrent_atomic_writers_leave_one_valid_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "facts"
            graph = self._graph(cache_dir)
            immutable_key = tracer._immutable_artifact_parse_cache_key(
                "d" * 64,
                "17",
                "com.example.TargetBridge",
                "base",
                class_entry="com/example/TargetBridge.class",
            )
            result = {
                "caller_owner": "com.example.TargetBridge",
                "method_refs": [],
                "field_refs": [],
                "class_refs": ["com.vendor.Target"],
                "class_instruction_refs": [],
            }

            def store():
                return tracer._store_persistent_artifact_fact(
                    graph,
                    "javap-runtime-references",
                    immutable_key,
                    "javap:17.0.1",
                    result,
                )

            with ThreadPoolExecutor(max_workers=8) as executor:
                writes = list(executor.map(lambda _index: store(), range(16)))

            cache_files = list(cache_dir.rglob("*.json"))
            temporary_files = list(cache_dir.rglob("*.tmp"))
            hit, loaded = tracer._load_persistent_artifact_fact(
                graph,
                "javap-runtime-references",
                immutable_key,
                "javap:17.0.1",
            )

        self.assertTrue(all(writes))
        self.assertEqual(len(cache_files), 1)
        self.assertEqual(temporary_files, [])
        self.assertTrue(hit)
        self.assertEqual(self._fingerprint(result), self._fingerprint(loaded))

    def test_failed_parse_is_not_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "facts"
            graph = self._graph(cache_dir)
            with patch.object(
                tracer, "_javap_tool_identity", return_value="javap:17.0.1"
            ), patch.object(
                tracer, "_run_javap_bytecode_dump", return_value=""
            ) as mocked_javap:
                first = self._load(graph)
                tracer.clear_immutable_artifact_parse_cache()
                second = self._load(graph)

        self.assertIsNone(first)
        self.assertIsNone(second)
        self.assertEqual(mocked_javap.call_count, 2)
        self.assertEqual(list(cache_dir.rglob("*.json")), [])

    def test_unknown_javap_identity_disables_persistent_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "facts"
            graph = self._graph(cache_dir)
            with patch.object(
                tracer, "_javap_tool_identity", return_value="javap:unavailable"
            ), patch.object(
                tracer, "_run_javap_bytecode_dump", return_value=JAVAP_OUTPUT
            ) as mocked_javap:
                first = self._load(graph)
                tracer.clear_immutable_artifact_parse_cache()
                second = self._load(graph)

        self.assertEqual(self._fingerprint(first), self._fingerprint(second))
        self.assertEqual(mocked_javap.call_count, 2)
        self.assertEqual(list(cache_dir.rglob("*.json")), [])

    def test_inprocess_classfile_facts_are_reused_without_reparsing(self):
        edge = {
            "evidence_type": "bytecode_method_invocation",
            "content": "opcode 0xb8",
            "line": 0,
            "callee_key": "com.vendor.Target.removed(String)",
            "caller_name": "use",
            "caller_descriptor": "(Ljava/lang/String;)V",
            "callee_descriptor": "(Ljava/lang/String;)V",
        }
        summary = {
            "has_dynamic_reference": False,
            "ref_members": [],
            "class_internal_names": {"com/vendor/Target"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "facts"
            graph = self._graph(cache_dir)
            arguments = (
                b"class-bytes",
                "c" * 64,
                "17",
                "com.example.TargetBridge",
            )
            keywords = {
                "multi_release_version": "base",
                "class_entry": "com/example/TargetBridge.class",
                "graph": graph,
            }
            with patch.object(
                tracer, "parse_classfile_calls", return_value=[edge]
            ) as mocked_parser, patch.object(
                tracer, "_parse_classfile_constant_pool_summary", return_value=summary
            ) as mocked_summary:
                cold = tracer._load_direct_classfile_references(*arguments, **keywords)

            tracer.clear_immutable_artifact_parse_cache()
            with patch.object(
                tracer,
                "parse_classfile_calls",
                side_effect=AssertionError("hot cache must bypass the parser"),
            ), patch.object(
                tracer,
                "_parse_classfile_constant_pool_summary",
                side_effect=AssertionError("hot cache must bypass the summary parser"),
            ):
                hot = tracer._load_direct_classfile_references(*arguments, **keywords)

        self.assertEqual(self._fingerprint(cold), self._fingerprint(hot))
        self.assertEqual(mocked_parser.call_count, 1)
        self.assertEqual(mocked_summary.call_count, 1)


if __name__ == "__main__":
    unittest.main()
