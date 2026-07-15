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

    def _framework_edge(self, edge_kind, *, metadata, target="framework.Target.invoke()"):
        return CollectedEdge(
            caller_symbol=str(dict(metadata).get("framework_source") or "framework:dispatch"),
            callee_symbol=target,
            edge_kind=edge_kind,
            semantic=True,
            owner_scope=ModuleScope.BUSINESS_CLASSES,
            owner_coord="__business__",
            provenance=EvidenceProvenance(
                authority=EvidenceAuthority.FRAMEWORK_SEMANTIC,
                artifact_path="/artifact/application.jar",
                parser="framework_adapter",
                evidence_source="framework_semantic",
            ),
            metadata=tuple(metadata),
        )

    def _mybatis_framework_edge(self, target=None, **changes):
        target = target or (
            "org.apache.ibatis.binding.MapperProxy.invoke"
            "(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])"
        )
        target_stages = {
            "org.apache.ibatis.binding.MapperProxy.invoke"
            "(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])": "proxy_entry_dispatch",
            "org.apache.ibatis.binding.MapperMethod.execute"
            "(org.apache.ibatis.session.SqlSession,java.lang.Object[])": "plain_invoker_dispatch",
            "org.apache.ibatis.session.SqlSession.selectOne"
            "(java.lang.String,java.lang.Object)": "select_one_dispatch",
        }
        provenance = {
            "authority": "final_artifact_javap",
            "file": "/artifact/application.jar!/BOOT-INF/classes/com/acme/CityMapper.class",
            "binding_file": "/artifact/application.jar!/BOOT-INF/classes/mappers/CityMapper.xml",
            "final_artifact_sha256": "a" * 64,
            "mapper_registration": {
                "artifact_entry": "BOOT-INF/classes/com/acme/CityMapper.class",
                "artifact_sha256": "a" * 64,
                "authority": "current_final_artifact_classfile",
            },
            "binding_evidence": {
                "artifact_entry": "BOOT-INF/classes/mappers/CityMapper.xml",
                "artifact_sha256": "a" * 64,
                "authority": "current_final_artifact_resource",
            },
            "jar": "/artifact/mybatis.jar",
            "artifact_entry": "BOOT-INF/lib/mybatis.jar",
            "artifact_sha256": "b" * 64,
            "business_activation": [{
                "artifact_entry": "BOOT-INF/classes/com/acme/Application.class",
                "artifact_sha256": "a" * 64,
                "authority": "current_final_artifact_classfile",
            }],
            "verified_dispatch": {
                "proxy_entry_dispatch": True,
                "plain_invoker_dispatch": True,
                "select_one_dispatch": True,
            },
            "physical_target_evidence": {
                "target": target,
                "dispatch_stage": target_stages[target],
                "verified": True,
                "artifact_entry": "BOOT-INF/lib/mybatis.jar",
                "artifact_sha256": "b" * 64,
            },
        }
        metadata = {
            "framework_source": "com.acme.CityMapper.find",
            "framework_target": target,
            "source_owner": "com.acme.CityMapper",
            "source_member": "find",
            "parameter_count": 1,
            "runtime_activation": "active",
            "framework_provenance": provenance,
        }
        for key, value in changes.items():
            if key.startswith("provenance_"):
                provenance[key.removeprefix("provenance_")] = value
            else:
                metadata[key] = value
        return self._framework_edge(
            "mybatis_mapper_proxy_dispatch",
            metadata=tuple(metadata.items()),
            target=target,
        )

    def _proxy_graph(self, *, artifact_sha256="a" * 64, evidence_source="current_final_artifact"):
        caller = SimpleNamespace(
            caller_symbol_id="app-run",
            caller_qualified_key="com.acme.Application.run()",
            callee_key="com.acme.CityMapper.find(java.lang.String)",
            callee_simple_key="find(String)",
            evidence_type="bytecode_invokeinterface",
            evidence_source=evidence_source,
            evidence_authority=evidence_source,
            artifact_sha256=artifact_sha256,
            artifact_entry="BOOT-INF/classes/com/acme/Application.class",
            runtime_analyzer_hit=evidence_source != "current_final_artifact",
            confidence="high",
            file="/artifact/application.jar!/BOOT-INF/classes/com/acme/Application.class",
            line=21,
            content="invokeinterface CityMapper.find",
            owner_type="business",
            owner_coord="BUSINESS",
            module="app",
            is_test=False,
        )
        return SimpleNamespace(
            methods_by_id={},
            reverse_edges={"com.acme.CityMapper.find(java.lang.String)": [caller]},
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

    def test_mybatis_proxy_ingestion_preserves_caller_and_framework_authority_separately(self):
        graph = self._proxy_graph()
        edge = self._mybatis_framework_edge()

        result = ingest_collector_batches(graph, (CollectorBatch(
            collector="mybatis_mapper_proxy", version="2", edges=(edge,),
        ),))

        merged = graph.reverse_edges[edge.callee_symbol]
        self.assertEqual(
            getattr(result, "framework_mybatis_proxy_dispatch_edges", 0), 1
        )
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].caller_symbol_id, "app-run")
        self.assertEqual(merged[0].evidence_source, "framework_semantic")
        self.assertEqual(merged[0].caller_evidence_source, "current_final_artifact")
        self.assertEqual(merged[0].caller_artifact_sha256, "a" * 64)
        self.assertEqual(
            merged[0].framework_evidence_authority,
            EvidenceAuthority.FRAMEWORK_SEMANTIC.value,
        )
        self.assertTrue(merged[0].framework_final_artifact_verified)

    def test_mybatis_high_confidence_requires_one_sha_bound_complete_evidence_chain(self):
        mutations = {
            "registration_missing": {"provenance_mapper_registration": {}},
            "registration_sha_corrupt": {"provenance_mapper_registration": {
                "artifact_entry": "BOOT-INF/classes/com/acme/CityMapper.class",
                "artifact_sha256": "corrupt",
                "authority": "current_final_artifact_classfile",
            }},
            "binding_missing": {"provenance_binding_evidence": {}},
            "activation_missing": {"provenance_business_activation": []},
            "activation_sha_corrupt": {"provenance_business_activation": [{
                "artifact_entry": "BOOT-INF/classes/com/acme/Application.class",
                "artifact_sha256": "corrupt",
                "authority": "current_final_artifact_classfile",
            }]},
            "activation_entry_mismatch": {"provenance_business_activation": [{
                "artifact_entry": "BOOT-INF/classes/com/acme/Other.class",
                "artifact_sha256": "a" * 64,
                "authority": "current_final_artifact_classfile",
            }]},
            "final_artifact_sha_corrupt": {"provenance_final_artifact_sha256": "corrupt"},
            "runtime_sha_corrupt": {"provenance_artifact_sha256": "corrupt"},
            "dispatch_incomplete": {"provenance_verified_dispatch": {
                "proxy_entry_dispatch": True,
                "plain_invoker_dispatch": False,
                "select_one_dispatch": True,
            }},
            "target_identity_mismatch": {"framework_target": "wrong.Target.invoke()"},
            "physical_target_missing": {"provenance_physical_target_evidence": {}},
            "physical_target_identity_mismatch": {"provenance_physical_target_evidence": {
                "target": "wrong.Target.invoke()",
                "dispatch_stage": "proxy_entry_dispatch",
                "verified": True,
                "artifact_entry": "BOOT-INF/lib/mybatis.jar",
                "artifact_sha256": "b" * 64,
            }},
            "physical_target_sha_corrupt": {"provenance_physical_target_evidence": {
                "target": (
                    "org.apache.ibatis.binding.MapperProxy.invoke"
                    "(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])"
                ),
                "dispatch_stage": "proxy_entry_dispatch",
                "verified": True,
                "artifact_entry": "BOOT-INF/lib/mybatis.jar",
                "artifact_sha256": "corrupt",
            }},
        }
        for name, changes in mutations.items():
            with self.subTest(mutation=name):
                graph = self._proxy_graph()
                edge = self._mybatis_framework_edge(**changes)

                ingest_collector_batches(graph, (CollectorBatch(
                    collector="mybatis_mapper_proxy", version="2", edges=(edge,),
                ),))

                self.assertFalse(any(
                    item.evidence_type == "mybatis_mapper_proxy_dispatch"
                    and item.confidence == "high"
                    for item in graph.reverse_edges.get(edge.callee_symbol, ())
                ))

        graph = self._proxy_graph(artifact_sha256="c" * 64)
        caller = next(iter(graph.reverse_edges.values()))[0]
        caller.artifact_entry = "BOOT-INF/classes/com/acme/Other.class"
        edge = self._mybatis_framework_edge()
        ingest_collector_batches(graph, (CollectorBatch(
            collector="mybatis_mapper_proxy", version="2", edges=(edge,),
        ),))
        self.assertFalse(any(
            item.evidence_type == "mybatis_mapper_proxy_dispatch"
            and item.confidence == "high"
            for item in graph.reverse_edges.get(edge.callee_symbol, ())
        ))

    def test_mybatis_accepts_sha_verified_extracted_caller_for_same_final_class(self):
        graph = self._proxy_graph(artifact_sha256="c" * 64)
        caller = next(iter(graph.reverse_edges.values()))[0]
        caller.file = "/cache/business-classes.jar!/com/acme/Application.class"
        caller.artifact_entry = "com/acme/Application.class"
        edge = self._mybatis_framework_edge()

        ingest_collector_batches(graph, (CollectorBatch(
            collector="mybatis_mapper_proxy", version="2", edges=(edge,),
        ),))

        projected = graph.reverse_edges[edge.callee_symbol]
        self.assertTrue(any(
            item.evidence_type == "mybatis_mapper_proxy_dispatch"
            and item.confidence == "high"
            and item.framework_final_artifact_verified
            and item.caller_artifact_sha256 == "c" * 64
            for item in projected
        ))

    def test_mybatis_each_api_requires_its_exact_physical_target_evidence(self):
        targets = (
            (
                "org.apache.ibatis.binding.MapperProxy.invoke"
                "(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])"
            ),
            (
                "org.apache.ibatis.binding.MapperMethod.execute"
                "(org.apache.ibatis.session.SqlSession,java.lang.Object[])"
            ),
            (
                "org.apache.ibatis.session.SqlSession.selectOne"
                "(java.lang.String,java.lang.Object)"
            ),
        )
        for target in targets:
            with self.subTest(target=target):
                graph = self._proxy_graph()
                edge = self._mybatis_framework_edge(target=target)
                physical = dict(
                    dict(edge.metadata)["framework_provenance"]["physical_target_evidence"]
                )
                physical["dispatch_stage"] = "wrong_stage"
                edge = self._mybatis_framework_edge(
                    target=target,
                    provenance_physical_target_evidence=physical,
                )

                ingest_collector_batches(graph, (CollectorBatch(
                    collector="mybatis_mapper_proxy", version="2", edges=(edge,),
                ),))

                projected = graph.reverse_edges.get(target, ())
                self.assertFalse(any(
                    item.evidence_type == "mybatis_mapper_proxy_dispatch"
                    and item.confidence == "high"
                    for item in projected
                ))

    def test_transaction_proxy_keeps_runtime_observed_caller_authority(self):
        target = (
            "org.springframework.transaction.interceptor.TransactionInterceptor.invoke"
            "(org.aopalliance.intercept.MethodInvocation)"
        )
        edge = self._framework_edge(
            "spring_transaction_proxy_dispatch",
            target=target,
            metadata=(
                ("framework_source", "com.acme.BookingService.book/1"),
                ("framework_target", target),
                ("source_owner", "com.acme.BookingService"),
                ("source_member", "book"),
                ("parameter_count", 1),
                ("runtime_activation", "active"),
                ("framework_provenance", {
                    "authority": "final_artifact_javap",
                    "jar": "/artifact/spring-tx.jar",
                    "artifact_sha256": "b" * 64,
                    "business_artifact_sha256": "a" * 64,
                    "business_activation": [{"business_entry": "com.acme.Application.main"}],
                }),
            ),
        )
        caller = SimpleNamespace(
            **vars(next(iter(self._proxy_graph(
                evidence_source="runtime_observation", artifact_sha256=""
            ).reverse_edges.values()))[0]),
        )
        caller.callee_key = "com.acme.BookingService.book(java.lang.String)"
        graph = SimpleNamespace(
            methods_by_id={},
            reverse_edges={caller.callee_key: [caller]},
        )

        ingest_collector_batches(graph, (CollectorBatch(
            collector="spring_transaction_proxy", version="1", edges=(edge,),
        ),))

        merged = graph.reverse_edges[target][0]
        self.assertEqual(merged.evidence_source, "framework_semantic")
        self.assertEqual(merged.caller_evidence_source, "runtime_observation")
        self.assertEqual(
            merged.framework_evidence_authority,
            EvidenceAuthority.FRAMEWORK_SEMANTIC.value,
        )

    def test_composite_proxy_exposes_final_artifact_caller_without_claiming_its_authority(self):
        from confidence_weighted_tracer import _edge_allowed_for_trace

        target = (
            "org.springframework.transaction.interceptor.TransactionInterceptor.invoke"
            "(org.aopalliance.intercept.MethodInvocation)"
        )
        edge = self._framework_edge(
            "spring_transaction_proxy_dispatch",
            target=target,
            metadata=(
                ("framework_source", "com.acme.BookingService.book/1"),
                ("framework_target", target),
                ("source_owner", "com.acme.BookingService"),
                ("source_member", "book"),
                ("parameter_count", 1),
                ("runtime_activation", "active"),
                ("framework_provenance", {
                    "authority": "final_artifact_javap",
                    "artifact_sha256": "b" * 64,
                    "business_artifact_sha256": "a" * 64,
                    "business_activation": [{
                        "business_entry": "com.acme.Application.main"
                    }],
                }),
            ),
        )
        caller = next(iter(self._proxy_graph().reverse_edges.values()))[0]
        caller.callee_key = "com.acme.BookingService.book(java.lang.String)"
        graph = SimpleNamespace(
            methods_by_id={},
            reverse_edges={caller.callee_key: [caller]},
            require_current_final_artifact_business_edges=True,
        )

        ingest_collector_batches(graph, (CollectorBatch(
            collector="spring_transaction_proxy", version="1", edges=(edge,),
        ),))

        merged = graph.reverse_edges[target][0]
        self.assertEqual(merged.evidence_source, "framework_semantic")
        self.assertEqual(merged.caller_evidence_source, "current_final_artifact")
        self.assertEqual(merged.caller_evidence_authority, "current_final_artifact")
        self.assertEqual(
            merged.caller_evidence_file,
            "/artifact/application.jar!/BOOT-INF/classes/com/acme/Application.class",
        )
        self.assertEqual(merged.runtime_analyzer_hit["coord"], "__business__")
        self.assertEqual(merged.runtime_analyzer_hit["artifact_sha256"], "a" * 64)
        self.assertEqual(
            merged.runtime_analyzer_hit["artifact_entry"],
            "BOOT-INF/classes/com/acme/Application.class",
        )
        self.assertTrue(_edge_allowed_for_trace(merged, graph))

    def test_runtime_callback_activation_is_linked_only_from_typed_business_evidence(self):
        callback = SimpleNamespace(
            symbol_id="listener-receive",
            qualified_key="com.acme.Listener.receive",
            declared_qualified_key="com.acme.Listener.receive(java.lang.String)",
            declared_signature="(java.lang.String)",
            class_fqcn="com.acme.Listener",
            method_name="receive",
            owner_type="dependency",
            owner_coord="org.example:listener",
            module="listener",
            is_test=False,
        )
        activation = SimpleNamespace(
            symbol_id="app-main",
            qualified_key="com.acme.Application.main",
            declared_qualified_key="com.acme.Application.main(java.lang.String[])",
            declared_signature="(java.lang.String[])",
            class_fqcn="com.acme.Application",
            method_name="main",
            owner_type="business",
            owner_coord="BUSINESS",
            module="app",
            is_test=False,
        )
        target = "com.acme.Listener.receive"
        edge = self._framework_edge(
            "spring_runtime_registered_callback",
            target=target,
            metadata=(
                ("framework_source", "framework:spring-listener"),
                ("framework_target", target),
                ("runtime_activation", "active"),
                ("framework_provenance", {
                    "jar": "/artifact/listener.jar",
                    "business_activation": [{
                        "business_entry": "com.acme.Application.main"
                    }],
                }),
            ),
        )
        graph = SimpleNamespace(
            methods_by_id={callback.symbol_id: callback, activation.symbol_id: activation},
            reverse_edges={},
        )

        result = ingest_collector_batches(graph, (CollectorBatch(
            collector="spring_runtime_artifact", version="1", edges=(edge,),
        ),))

        self.assertEqual(getattr(result, "framework_activation_linked_methods", 0), 1)
        self.assertIn(callback.symbol_id, graph.framework_activation_linked_symbols)
        linked = graph.reverse_edges[callback.declared_qualified_key]
        self.assertEqual(linked[0].caller_symbol_id, activation.symbol_id)
        self.assertEqual(linked[0].framework_evidence_authority, "framework_semantic")


if __name__ == "__main__":
    unittest.main()
