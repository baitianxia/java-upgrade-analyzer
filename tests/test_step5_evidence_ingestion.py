import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from step5_evidence_ingestion import ingest_collector_batches
from step5_evidence_model import (
    CollectedEdge,
    CollectorBatch,
    EvidenceAuthority,
    EvidenceFailure,
    EvidenceProvenance,
    ModuleScope,
)


class EvidenceIngestionTest(unittest.TestCase):
    def _edge(self, *, scope=ModuleScope.BUSINESS_CLASSES):
        return CollectedEdge(
            caller_symbol="com.acme.Application.run()",
            callee_symbol="com.vendor.Legacy.call()",
            edge_kind="bytecode_method_invocation",
            semantic=False,
            owner_scope=scope,
            owner_coord="__business__",
            provenance=EvidenceProvenance(
                authority=EvidenceAuthority.CURRENT_FINAL_ARTIFACT,
                artifact_path="/artifact/application.jar",
                artifact_sha256="a" * 64,
                artifact_entry="BOOT-INF/classes/com/acme/Application.class",
                parser="classfile",
                evidence_source="current_final_artifact",
                line=12,
            ),
        )

    def test_ingestion_merges_once_and_registers_exact_evidence(self):
        edge = self._edge()
        batch = CollectorBatch(
            collector="business_bytecode",
            version="1",
            edges=(edge, edge),
        )
        graph = SimpleNamespace(reverse_edges={})

        result = ingest_collector_batches(graph, (batch,))

        self.assertEqual(result.merged_edges, 1)
        self.assertEqual(result.duplicate_edges, 1)
        self.assertEqual(result.rejected_edges, 0)
        merged = graph.reverse_edges["com.vendor.Legacy.call()"]
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].evidence_source, "current_final_artifact")
        self.assertEqual(merged[0].artifact_sha256, "a" * 64)
        self.assertEqual(len(graph.step5_evidence_registry), 1)
        self.assertEqual(
            graph.step5_evidence_registry[0].callee_symbol,
            "com.vendor.Legacy.call()",
        )

    def test_ingestion_rejects_unknown_owner_scope(self):
        batch = CollectorBatch(
            collector="business_bytecode",
            version="1",
            edges=(self._edge(scope=ModuleScope.UNKNOWN),),
        )
        graph = SimpleNamespace(reverse_edges={})

        result = ingest_collector_batches(graph, (batch,))

        self.assertEqual(result.merged_edges, 0)
        self.assertEqual(result.rejected_edges, 1)
        self.assertEqual(graph.reverse_edges, {})
        self.assertEqual(result.failures[0].reason_code, "EVIDENCE_OWNER_SCOPE_UNKNOWN")

    def test_ingestion_is_deterministic_across_batch_order(self):
        first = CollectorBatch(
            collector="z_collector", version="1", edges=(self._edge(),)
        )
        second = CollectorBatch(
            collector="a_collector", version="1", edges=(self._edge(),)
        )
        signatures = []
        for batches in ((first, second), (second, first)):
            graph = SimpleNamespace(reverse_edges={})
            result = ingest_collector_batches(graph, batches)
            signatures.append((
                result.merged_edges,
                result.duplicate_edges,
                tuple(
                    (item.caller_symbol, item.callee_symbol, item.edge_kind)
                    for item in graph.step5_evidence_registry
                ),
            ))

        self.assertEqual(signatures[0], signatures[1])

    def test_ingestion_resolves_typed_bytecode_caller_hints_centrally(self):
        edge = CollectedEdge(
            caller_symbol="com.acme.Service.execute()",
            callee_symbol="com.vendor.Legacy.call()",
            edge_kind="bytecode_method_invocation",
            semantic=False,
            owner_scope=ModuleScope.BUSINESS_CLASSES,
            owner_coord="__business__",
            provenance=EvidenceProvenance(
                authority=EvidenceAuthority.CURRENT_FINAL_ARTIFACT,
                artifact_path="/artifact/application.jar",
                artifact_sha256="b" * 64,
                artifact_entry="com/acme/Service.class",
                parser="classfile",
            ),
            metadata=(
                ("caller_owner", "com.acme.Service"),
                ("caller_name", "execute"),
                ("caller_signature", "()"),
            ),
        )
        method = SimpleNamespace(
            symbol_id="source-id",
            qualified_key="com.acme.Service.execute()",
        )
        graph = SimpleNamespace(
            reverse_edges={},
            methods_by_id={"source-id": method},
            methods_by_qualified={"com.acme.Service.execute": ["source-id"]},
            lookup_keys_by_symbol={"source-id": ["com.acme.Service.execute()"]},
        )

        result = ingest_collector_batches(graph, (CollectorBatch(
            collector="business_bytecode", version="2", edges=(edge,),
        ),))

        self.assertEqual(result.merged_edges, 1)
        self.assertEqual(
            graph.reverse_edges["com.vendor.Legacy.call()"][0].caller_symbol_id,
            "source-id",
        )
        self.assertEqual(
            graph.reverse_edges["com.vendor.Legacy.call()"][0].file,
            "/artifact/application.jar!/com/acme/Service.class",
        )

    def test_ingestion_deduplicates_identical_class_lookup_keys(self):
        edge = CollectedEdge(
            caller_symbol="source-id",
            callee_symbol="class:com.vendor.Legacy",
            edge_kind="reflection_class_lookup",
            semantic=True,
            owner_scope=ModuleScope.BUSINESS_CLASSES,
            owner_coord="BUSINESS",
            provenance=EvidenceProvenance(
                authority=EvidenceAuthority.SOURCE_INDIRECT_INFERENCE,
                artifact_path="/src/Application.java",
                parser="indirect_usage_analyzer",
            ),
            metadata=(("callee_simple_key", "class:com.vendor.Legacy"),),
        )
        graph = SimpleNamespace(reverse_edges={})

        result = ingest_collector_batches(graph, (CollectorBatch(
            collector="indirect_usage", version="2", edges=(edge,),
        ),))

        self.assertEqual(result.merged_edges, 1)
        self.assertEqual(len(graph.step5_evidence_registry), 1)
        self.assertEqual(len(graph.reverse_edges["class:com.vendor.Legacy"]), 1)

    def test_ingestion_deduplicates_edge_already_present_in_bucket(self):
        edge = self._edge()
        existing = SimpleNamespace(
            caller_symbol_id=edge.caller_symbol,
            callee_key=edge.callee_symbol,
            evidence_type=edge.edge_kind,
        )
        graph = SimpleNamespace(
            reverse_edges={edge.callee_symbol: [existing]},
        )

        result = ingest_collector_batches(graph, (CollectorBatch(
            collector="business_bytecode", version="2", edges=(edge,),
        ),))

        self.assertEqual(result.merged_edges, 0)
        self.assertEqual(result.duplicate_edges, 1)
        self.assertEqual(graph.step5_evidence_registry, ())
        self.assertEqual(graph.reverse_edges[edge.callee_symbol], [existing])

    def test_ingestion_deduplicates_pending_legacy_bucket_identity(self):
        first = self._edge()
        second = CollectedEdge(
            caller_symbol=first.caller_symbol,
            callee_symbol=first.callee_symbol,
            edge_kind=first.edge_kind,
            semantic=first.semantic,
            owner_scope=first.owner_scope,
            owner_coord=first.owner_coord,
            provenance=EvidenceProvenance(
                authority=EvidenceAuthority.CURRENT_FINAL_ARTIFACT,
                artifact_path=first.provenance.artifact_path,
                artifact_sha256=first.provenance.artifact_sha256,
                artifact_entry=first.provenance.artifact_entry,
                parser="classfile",
                line=99,
            ),
        )
        graph = SimpleNamespace(reverse_edges={})

        result = ingest_collector_batches(graph, (CollectorBatch(
            collector="business_bytecode", version="2", edges=(first, second),
        ),))

        self.assertEqual(result.merged_edges, 1)
        self.assertEqual(result.duplicate_edges, 1)
        self.assertEqual(len(graph.step5_evidence_registry), 1)
        self.assertEqual(len(graph.reverse_edges[first.callee_symbol]), 1)

    def test_ingestion_preserves_legacy_business_call_edge_fields(self):
        edge = CollectedEdge(
            caller_symbol="com.acme.Service.execute()",
            callee_symbol="com.vendor.Flags.ENABLED",
            edge_kind="bytecode_field_access",
            semantic=False,
            owner_scope=ModuleScope.BUSINESS_CLASSES,
            owner_coord="__business__",
            provenance=EvidenceProvenance(
                authority=EvidenceAuthority.CURRENT_FINAL_ARTIFACT,
                artifact_path="/artifact/application.jar",
                artifact_sha256="e" * 64,
                artifact_entry="BOOT-INF/classes/com/acme/Service.class",
                parser="javap",
            ),
            metadata=(
                ("caller_owner", "com.acme.Service"),
                ("caller_name", "execute"),
                ("caller_signature", "()"),
                ("callee_simple_key", "field:ENABLED"),
            ),
        )
        method = SimpleNamespace(
            symbol_id="source-id", qualified_key="com.acme.Service.execute()",
            owner_type="business", owner_coord="BUSINESS", module="app", is_test=False,
        )
        graph = SimpleNamespace(
            reverse_edges={}, methods_by_id={"source-id": method},
            methods_by_qualified={"com.acme.Service.execute": ["source-id"]},
            lookup_keys_by_symbol={},
        )

        result = ingest_collector_batches(graph, (CollectorBatch(
            collector="business_bytecode", version="2", edges=(edge,),
        ),))

        self.assertEqual(result.merged_edges, 1)
        converted = graph.reverse_edges[edge.callee_symbol][0]
        self.assertEqual(
            (converted.owner_type, converted.owner_coord, converted.module, converted.is_test),
            ("business", "BUSINESS", "app", False),
        )
        self.assertEqual(converted.callee_param_types, [])
        self.assertTrue(converted.callee_fqcn_complete)
        self.assertTrue(converted.callee_signature_complete)
        self.assertEqual(converted.parser, "javap")

    def test_business_bytecode_conversion_keeps_legacy_non_test_edge_contract(self):
        edge = self._edge()
        method = SimpleNamespace(
            symbol_id=edge.caller_symbol,
            qualified_key=edge.caller_symbol,
            owner_type="business",
            owner_coord="BUSINESS",
            module="app",
            is_test=True,
        )
        graph = SimpleNamespace(
            reverse_edges={}, methods_by_id={edge.caller_symbol: method},
        )

        ingest_collector_batches(graph, (CollectorBatch(
            collector="business_bytecode", version="2", edges=(edge,),
        ),))

        converted = graph.reverse_edges[edge.callee_symbol][0]
        self.assertFalse(converted.is_test)

    def test_business_bytecode_coverage_is_partial_for_each_api_on_ingestion_failure(self):
        from s5_call_chain_engine_integrated import _build_business_bytecode_coverage
        from step5_evidence_ingestion import IngestionResult

        failure = EvidenceFailure(
            stage="evidence-ingestion",
            reason_code="BYTECODE_CALLER_UNRESOLVED",
            blocking=True,
        )
        batch = CollectorBatch(
            collector="business_bytecode",
            version="2",
            metrics=(("classes_scanned", 1), ("evidence_source", "current_final_artifact")),
        )
        result = IngestionResult(
            merged_edges=0,
            duplicate_edges=0,
            rejected_edges=1,
            failures=(failure,),
            failures_by_collector=(("business_bytecode", failure),),
        )

        coverage, status, reason_codes = _build_business_bytecode_coverage(
            batch, result, ("api:a", "api:b")
        )

        self.assertEqual(status, "partial")
        self.assertEqual(reason_codes, ["BYTECODE_CALLER_UNRESOLVED"])
        self.assertEqual([item.api_identity for item in coverage], ["api:a", "api:b"])
        self.assertTrue(all(item.applicable and item.status == "partial" for item in coverage))

    def test_business_bytecode_zero_scan_failure_is_insufficient_for_each_api(self):
        from s5_call_chain_engine_integrated import _build_business_bytecode_coverage
        from step5_evidence_ingestion import IngestionResult

        failure = EvidenceFailure(
            stage="business-bytecode",
            reason_code="CURRENT_FINAL_ARTIFACT_REQUIRED",
            blocking=True,
        )
        batch = CollectorBatch(
            collector="business_bytecode",
            version="2",
            metrics=(("classes_scanned", 0), ("evidence_source", "unavailable")),
        )
        result = IngestionResult(
            merged_edges=0,
            duplicate_edges=0,
            rejected_edges=0,
            failures=(failure,),
            failures_by_collector=(("business_bytecode", failure),),
        )

        coverage, status, reason_codes = _build_business_bytecode_coverage(
            batch, result, ("api:a", "api:b")
        )

        self.assertEqual(status, "insufficient")
        self.assertEqual(reason_codes, ["CURRENT_FINAL_ARTIFACT_REQUIRED"])
        self.assertTrue(all(
            item.applicable and item.status == "insufficient" for item in coverage
        ))

    def test_business_bytecode_empty_edge_invalid_sha_blocks_applicable_incomplete_coverage(self):
        from business_bytecode_graph import _business_bytecode_batch
        from s5_call_chain_engine_integrated import _build_business_bytecode_coverage

        for classes_scanned in (0, 1):
            for artifact_sha256 in ("", "not-a-sha"):
                batch = _business_bytecode_batch(
                    (),
                    {
                        "classes_scanned": classes_scanned,
                        "edges_found": 0,
                        "evidence_source": "current_final_artifact",
                        "artifact_sha256": artifact_sha256,
                    },
                    strict_final_artifact=True,
                )
                self.assertEqual(batch.edges, ())
                self.assertEqual(
                    [failure.reason_code for failure in batch.failures],
                    ["CURRENT_FINAL_ARTIFACT_SHA_INVALID"],
                )
                self.assertTrue(batch.failures[0].blocking)

                graph = SimpleNamespace(reverse_edges={})
                result = ingest_collector_batches(graph, (batch,))
                coverage, status, reason_codes = _build_business_bytecode_coverage(
                    batch, result, ("api:a", "api:b")
                )

                self.assertEqual(
                    status, "insufficient" if classes_scanned == 0 else "partial"
                )
                self.assertEqual(reason_codes, ["CURRENT_FINAL_ARTIFACT_SHA_INVALID"])
                self.assertTrue(all(item.applicable for item in coverage))
                self.assertTrue(all(item.status == status for item in coverage))

    def test_ingestion_preserves_indirect_occurrences_on_distinct_lines(self):
        first = CollectedEdge(
            caller_symbol="source-id",
            callee_symbol="com.vendor.Legacy.call()",
            edge_kind="reflection_method_invocation",
            semantic=True,
            owner_scope=ModuleScope.BUSINESS_CLASSES,
            provenance=EvidenceProvenance(
                authority=EvidenceAuthority.SOURCE_INDIRECT_INFERENCE,
                artifact_path="/src/Application.java",
                parser="indirect_usage_analyzer",
                line=12,
            ),
        )
        second = CollectedEdge(
            caller_symbol=first.caller_symbol,
            callee_symbol=first.callee_symbol,
            edge_kind=first.edge_kind,
            semantic=first.semantic,
            owner_scope=first.owner_scope,
            provenance=EvidenceProvenance(
                authority=EvidenceAuthority.SOURCE_INDIRECT_INFERENCE,
                artifact_path="/src/Application.java",
                parser="indirect_usage_analyzer",
                line=18,
            ),
        )
        graph = SimpleNamespace(reverse_edges={})

        result = ingest_collector_batches(graph, (CollectorBatch(
            collector="indirect_usage", version="2", edges=(first, second),
        ),))

        self.assertEqual(result.merged_edges, 2)
        self.assertEqual(result.duplicate_edges, 0)
        self.assertEqual(
            [edge.line for edge in graph.reverse_edges[first.callee_symbol]], [12, 18]
        )

    def test_ingestion_retains_blocking_failure_on_graph(self):
        batch = CollectorBatch(
            collector="business_bytecode",
            version="2",
            failures=(EvidenceFailure(
                stage="business-bytecode",
                reason_code="CURRENT_FINAL_ARTIFACT_SHA_INVALID",
                blocking=True,
            ),),
        )
        graph = SimpleNamespace(reverse_edges={})

        result = ingest_collector_batches(graph, (batch,))

        self.assertEqual(result.failures[0].reason_code, "CURRENT_FINAL_ARTIFACT_SHA_INVALID")
        self.assertEqual(
            graph.step5_evidence_failures[0].reason_code,
            "CURRENT_FINAL_ARTIFACT_SHA_INVALID",
        )

    def test_ingestion_keeps_unique_qualified_caller_without_lookup_keys(self):
        edge = CollectedEdge(
            caller_symbol="com.acme.Service.execute()",
            callee_symbol="com.vendor.Legacy.call()",
            edge_kind="bytecode_method_invocation",
            semantic=False,
            owner_scope=ModuleScope.BUSINESS_CLASSES,
            owner_coord="__business__",
            provenance=EvidenceProvenance(
                authority=EvidenceAuthority.CURRENT_FINAL_ARTIFACT,
                artifact_path="/artifact/application.jar",
                artifact_sha256="c" * 64,
                artifact_entry="BOOT-INF/classes/com/acme/Service.class",
                parser="classfile",
            ),
            metadata=(
                ("caller_owner", "com.acme.Service"),
                ("caller_name", "execute"),
                ("caller_signature", "()"),
            ),
        )
        method = SimpleNamespace(
            symbol_id="source-id",
            qualified_key="com.acme.Service.execute()",
        )
        graph = SimpleNamespace(
            reverse_edges={},
            methods_by_id={"source-id": method},
            methods_by_qualified={"com.acme.Service.execute": ["source-id"]},
            lookup_keys_by_symbol={},
        )

        result = ingest_collector_batches(graph, (CollectorBatch(
            collector="business_bytecode", version="2", edges=(edge,),
        ),))

        self.assertEqual(result.merged_edges, 1)
        self.assertEqual(
            graph.reverse_edges["com.vendor.Legacy.call()"][0].caller_symbol_id,
            "source-id",
        )
        self.assertEqual(
            graph.reverse_edges["com.vendor.Legacy.call()"][0].file,
            "/artifact/application.jar!/BOOT-INF/classes/com/acme/Service.class",
        )


if __name__ == "__main__":
    unittest.main()
