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


if __name__ == "__main__":
    unittest.main()
