import hashlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import step5_evidence_ingestion as ingestion_module
from step5_evidence_ingestion import ingest_collector_batches
from step5_evidence_model import (
    CollectedEdge,
    CollectorBatch,
    CoverageRecord,
    EvidenceAuthority,
    EvidenceConcern,
    EvidenceFailure,
    EvidenceProvenance,
    ModuleScope,
)


class EvidenceIngestionTest(unittest.TestCase):
    def _compile_mybatis_fixture_classes(
        self, root, *, misplaced_annotation=False, misplaced_activation=False,
        mapper_return_type="String",
    ):
        mapper_methods = (
            f"{mapper_return_type} find(String id); "
            f"@Select(\"select other\") {mapper_return_type} other(String id);"
            if misplaced_annotation
            else (
                "@Select(\"select name from city where id = #{id}\") "
                f"{mapper_return_type} find(String id);"
            )
        )
        application_methods = (
            "public static void main(String[] args) {} "
            "public static void unused(String[] args) { "
            "SpringApplication.run(Application.class, args); }"
            if misplaced_activation
            else (
                "public static void main(String[] args) { "
                "SpringApplication.run(Application.class, args); }"
            )
        )
        sources = {
            "org/springframework/boot/autoconfigure/SpringBootApplication.java": """
                package org.springframework.boot.autoconfigure;
                public @interface SpringBootApplication {}
            """,
            "org/springframework/boot/SpringApplication.java": """
                package org.springframework.boot;
                import org.springframework.context.ConfigurableApplicationContext;
                public final class SpringApplication {
                    public static ConfigurableApplicationContext run(
                        Class<?> type, String[] args
                    ) { return null; }
                }
            """,
            "org/springframework/context/ConfigurableApplicationContext.java": """
                package org.springframework.context;
                public interface ConfigurableApplicationContext {}
            """,
            "org/apache/ibatis/annotations/Mapper.java": """
                package org.apache.ibatis.annotations;
                public @interface Mapper {}
            """,
            "org/apache/ibatis/annotations/Select.java": """
                package org.apache.ibatis.annotations;
                public @interface Select { String[] value(); }
            """,
            "org/apache/ibatis/session/SqlSession.java": """
                package org.apache.ibatis.session;
                public interface SqlSession {
                    Object selectOne(String statement, Object parameter);
                }
            """,
            "org/apache/ibatis/binding/MapperMethod.java": """
                package org.apache.ibatis.binding;
                import org.apache.ibatis.session.SqlSession;
                public class MapperMethod {
                    public Object execute(SqlSession session, Object[] args) {
                        return session.selectOne("com.acme.CityMapper.find", args[0]);
                    }
                }
            """,
            "org/apache/ibatis/binding/MapperProxy.java": """
                package org.apache.ibatis.binding;
                import java.lang.reflect.Method;
                import org.apache.ibatis.session.SqlSession;
                public class MapperProxy {
                    interface MapperMethodInvoker {
                        Object invoke(Object proxy, Method method, Object[] args,
                                      SqlSession session);
                    }
                    static class PlainMethodInvoker implements MapperMethodInvoker {
                        private final MapperMethod mapperMethod = new MapperMethod();
                        public Object invoke(Object proxy, Method method, Object[] args,
                                             SqlSession session) {
                            return mapperMethod.execute(session, args);
                        }
                    }
                    public Object invoke(Object proxy, Method method, Object[] args) {
                        MapperMethodInvoker invoker = new PlainMethodInvoker();
                        return invoker.invoke(proxy, method, args, null);
                    }
                }
            """,
            "com/acme/CityMapper.java": f"""
                package com.acme;
                import org.apache.ibatis.annotations.Mapper;
                import org.apache.ibatis.annotations.Select;
                @Mapper
                public interface CityMapper {{
                    {mapper_methods}
                }}
            """,
            "com/acme/OtherMapper.java": """
                package com.acme;
                import org.apache.ibatis.annotations.Mapper;
                import org.apache.ibatis.annotations.Select;
                @Mapper
                public interface OtherMapper {
                    @Select("select wrong") String find(String id);
                }
            """,
            "com/acme/Application.java": f"""
                package com.acme;
                import org.springframework.boot.SpringApplication;
                import org.springframework.boot.autoconfigure.SpringBootApplication;
                @SpringBootApplication
                public class Application {{
                    private CityMapper mapper;
                    {application_methods}
                    public {mapper_return_type} run() {{ return mapper.find("1"); }}
                }}
            """,
        }
        source_root = Path(root) / "src"
        classes = Path(root) / "classes"
        for relative, content in sources.items():
            path = source_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        completed = subprocess.run(
            ["javac", "-d", str(classes), *map(str, source_root.rglob("*.java"))],
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return classes

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
        metadata_values = dict(metadata)
        framework_provenance = dict(
            metadata_values.get("framework_provenance") or {}
        )
        artifact_sha256 = str(framework_provenance.get("artifact_sha256") or "")
        if len(artifact_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in artifact_sha256
        ):
            artifact_sha256 = ""
        return CollectedEdge(
            caller_symbol=str(metadata_values.get("framework_source") or "framework:dispatch"),
            callee_symbol=target,
            edge_kind=edge_kind,
            semantic=True,
            owner_scope=ModuleScope.BUSINESS_CLASSES,
            owner_coord="__business__",
            provenance=EvidenceProvenance(
                authority=EvidenceAuthority.FRAMEWORK_SEMANTIC,
                artifact_path=str(
                    framework_provenance.get("jar")
                    or "/artifact/application.jar"
                ),
                artifact_sha256=artifact_sha256,
                artifact_entry=str(
                    framework_provenance.get("artifact_entry") or ""
                ),
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
            "command": "select",
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
            "source_parameters": ["java.lang.String"],
            "source_return_type": "java.lang.String",
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

    def _verified_mybatis_fixture(
        self, *, target=None, extracted_caller=False,
        binding_mode="xml", misplaced_annotation=False,
        misplaced_activation=False,
        caller_return_type=None,
    ):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        final_jar = Path(temp_dir.name) / "application.jar"
        caller_jar = Path(temp_dir.name) / "business-classes.jar"
        runtime_jar = Path(temp_dir.name) / "mybatis.jar"
        registration_entry = "BOOT-INF/classes/com/acme/CityMapper.class"
        binding_entry = "BOOT-INF/classes/mappers/CityMapper.xml"
        activation_entry = "BOOT-INF/classes/com/acme/Application.class"
        caller_entry = (
            "com/acme/Application.class" if extracted_caller else activation_entry
        )
        classes = self._compile_mybatis_fixture_classes(
            temp_dir.name,
            misplaced_annotation=misplaced_annotation,
            misplaced_activation=misplaced_activation,
        )
        caller_classes = classes
        if caller_return_type:
            caller_classes = self._compile_mybatis_fixture_classes(
                Path(temp_dir.name) / "caller",
                mapper_return_type=caller_return_type,
            )
        with zipfile.ZipFile(final_jar, "w") as archive:
            archive.write(classes / "com/acme/CityMapper.class", registration_entry)
            archive.write(
                classes / "com/acme/OtherMapper.class",
                "BOOT-INF/classes/com/acme/OtherMapper.class",
            )
            archive.write(classes / "com/acme/Application.class", activation_entry)
            if binding_mode == "xml":
                archive.writestr(
                    binding_entry,
                    b'<mapper namespace="com.acme.CityMapper">'
                    b'<select id="find">select name from city</select></mapper>',
                )
            else:
                binding_entry = registration_entry
        with zipfile.ZipFile(caller_jar, "w") as archive:
            archive.write(caller_classes / "com/acme/Application.class", caller_entry)
        runtime_classes = (
            "org/apache/ibatis/binding/MapperProxy.class",
            "org/apache/ibatis/binding/MapperMethod.class",
            "org/apache/ibatis/session/SqlSession.class",
        )
        with zipfile.ZipFile(runtime_jar, "w") as archive:
            for class_entry in runtime_classes:
                archive.write(classes / class_entry, class_entry)
            archive.write(
                classes / "org/apache/ibatis/binding/MapperProxy$PlainMethodInvoker.class",
                "org/apache/ibatis/binding/MapperProxy$PlainMethodInvoker.class",
            )
            archive.write(
                classes / "org/apache/ibatis/binding/MapperProxy$MapperMethodInvoker.class",
                "org/apache/ibatis/binding/MapperProxy$MapperMethodInvoker.class",
            )
        final_sha = hashlib.sha256(final_jar.read_bytes()).hexdigest()
        caller_sha = hashlib.sha256(caller_jar.read_bytes()).hexdigest()
        runtime_sha = hashlib.sha256(runtime_jar.read_bytes()).hexdigest()
        target = target or (
            "org.apache.ibatis.binding.MapperProxy.invoke"
            "(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])"
        )
        stage = {
            "org.apache.ibatis.binding.MapperProxy.invoke": "proxy_entry_dispatch",
            "org.apache.ibatis.binding.MapperMethod.execute": "plain_invoker_dispatch",
            "org.apache.ibatis.session.SqlSession.selectOne": "select_one_dispatch",
        }[target.split("(", 1)[0]]
        target_class_entry = (
            target.split("(", 1)[0].rsplit(".", 1)[0].replace(".", "/")
            + ".class"
        )
        graph = self._proxy_graph(artifact_sha256=caller_sha)
        caller = next(iter(graph.reverse_edges.values()))[0]
        caller.file = f"{caller_jar}!/{caller_entry}"
        caller.artifact_entry = caller_entry
        edge = self._mybatis_framework_edge(
            target=target,
            provenance_file=f"{final_jar}!/{registration_entry}",
            provenance_binding_file=f"{final_jar}!/{binding_entry}",
            provenance_final_artifact_path=str(final_jar),
            provenance_final_artifact_sha256=final_sha,
            provenance_mapper_registration={
                "artifact_path": str(final_jar),
                "artifact_entry": registration_entry,
                "artifact_sha256": final_sha,
                "authority": "current_final_artifact_classfile",
            },
            provenance_binding_evidence={
                "artifact_path": str(final_jar),
                "artifact_entry": binding_entry,
                "artifact_sha256": final_sha,
                "authority": (
                    "current_final_artifact_resource"
                    if binding_mode == "xml"
                    else "current_final_artifact_classfile"
                ),
            },
            provenance_jar=str(runtime_jar),
            provenance_artifact_sha256=runtime_sha,
            provenance_business_activation=[{
                "artifact_path": str(final_jar),
                "artifact_entry": activation_entry,
                "artifact_sha256": final_sha,
                "authority": "current_final_artifact_classfile",
            }],
            provenance_physical_target_evidence={
                "target": target,
                "dispatch_stage": stage,
                "verified": True,
                "artifact_entry": "BOOT-INF/lib/mybatis.jar",
                "artifact_sha256": runtime_sha,
                "class_or_resource_entry": target_class_entry,
            },
        )
        return graph, edge, caller_sha

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

    def test_incremental_ingestion_preserves_prior_diagnostics_and_coverage(self):
        graph = SimpleNamespace(reverse_edges={})
        first = CollectorBatch(
            collector="indirect_usage",
            version="1",
            failures=(EvidenceFailure(
                stage="indirect",
                reason_code="FIRST_FAILURE",
                blocking=True,
            ),),
            concerns=(EvidenceConcern(
                stage="indirect",
                reason_code="FIRST_CONCERN",
                detail="first concern",
            ),),
            coverage=(CoverageRecord(
                collector="indirect_usage",
                api_identity="indirect_usage",
                status="partial",
            ),),
        )
        second = CollectorBatch(
            collector="indirect_usage",
            version="1",
            coverage=(CoverageRecord(
                collector="indirect_usage",
                api_identity="vendor:demo|Target.call|()|method|REMOVED",
                status="complete",
            ),),
        )

        ingest_collector_batches(graph, (first,))
        ingest_collector_batches(graph, (second,))

        self.assertEqual(
            [item.reason_code for item in graph.step5_evidence_failures],
            ["FIRST_FAILURE"],
        )
        self.assertEqual(
            [item.reason_code for item in graph.step5_evidence_concerns],
            ["FIRST_CONCERN"],
        )
        self.assertEqual(
            [(item.api_identity, item.status) for item in graph.step5_collector_coverage],
            [
                ("indirect_usage", "partial"),
                ("vendor:demo|Target.call|()|method|REMOVED", "complete"),
            ],
        )

    def test_incremental_non_framework_batch_preserves_framework_projection(self):
        graph, edge, _caller_sha = self._verified_mybatis_fixture()
        ingest_collector_batches(graph, (CollectorBatch(
            collector="mybatis_mapper_proxy", version="2", edges=(edge,),
        ),))
        projected_edges = tuple(graph.framework_edges)
        projected_entries = tuple(graph.framework_entry_symbols)

        ingest_collector_batches(graph, (CollectorBatch(
            collector="business_bytecode", version="2", edges=(),
        ),))

        self.assertEqual(tuple(graph.framework_edges), projected_edges)
        self.assertEqual(tuple(graph.framework_entry_symbols), projected_entries)

    def test_framework_snapshot_replaces_old_diagnostics(self):
        graph = SimpleNamespace(reverse_edges={})
        ingest_collector_batches(graph, (CollectorBatch(
            collector="spring_runtime_artifact",
            version="1",
            failures=(EvidenceFailure(
                stage="framework", reason_code="OLD_FAILURE", blocking=True,
            ),),
            concerns=(EvidenceConcern(
                stage="framework", reason_code="OLD_CONCERN", detail="old",
            ),),
            coverage=(CoverageRecord(
                collector="spring_runtime_artifact",
                api_identity="spring_runtime_artifact",
                status="partial",
            ),),
        ),))

        ingest_collector_batches(graph, (CollectorBatch(
            collector="spring_runtime_artifact",
            version="2",
            coverage=(CoverageRecord(
                collector="spring_runtime_artifact",
                api_identity="spring_runtime_artifact",
                status="complete",
            ),),
        ),))

        self.assertEqual(graph.step5_evidence_failures, ())
        self.assertEqual(graph.step5_evidence_concerns, ())
        self.assertEqual(
            [(item.api_identity, item.status) for item in graph.step5_collector_coverage],
            [("spring_runtime_artifact", "complete")],
        )

    def test_new_framework_snapshot_replaces_and_invalidates_old_projection(self):
        graph, edge, _caller_sha = self._verified_mybatis_fixture()
        ingest_collector_batches(graph, (CollectorBatch(
            collector="mybatis_mapper_proxy", version="2", edges=(edge,),
        ),))
        self.assertTrue(any(
            getattr(item, "evidence_type", "") == "mybatis_mapper_proxy_dispatch"
            for item in graph.reverse_edges.get(edge.callee_symbol, ())
        ))

        ingest_collector_batches(graph, (CollectorBatch(
            collector="mybatis_mapper_proxy", version="3", edges=(),
        ),))

        self.assertEqual(graph.framework_edges, [])
        self.assertFalse(any(
            getattr(item, "evidence_type", "") == "mybatis_mapper_proxy_dispatch"
            for item in graph.reverse_edges.get(edge.callee_symbol, ())
        ))

    def test_framework_projection_uses_typed_identity_over_legacy_shadow(self):
        edge = self._framework_edge(
            "dynamic_proxy_callback",
            target="typed.Target.invoke()",
            metadata=(("legacy_edge", {
                "source": "legacy.Source.call",
                "target": "legacy.Target.invoke()",
                "edge_kind": "legacy_kind",
                "confidence": "low",
                "conditions": ["legacy"],
                "provenance": {"authority": "legacy"},
            }),),
        )

        projected = ingestion_module._framework_edge_mapping(
            CollectorBatch(collector="dynamic_proxy_basic", version="1", edges=(edge,)),
            edge,
        )

        self.assertEqual(projected["source"], edge.caller_symbol)
        self.assertEqual(projected["target"], "typed.Target.invoke()")
        self.assertEqual(projected["edge_kind"], "dynamic_proxy_callback")
        self.assertEqual(projected["confidence"], "high")
        self.assertNotEqual(projected["provenance"].get("authority"), "legacy")

    def test_distinct_physical_instruction_offsets_are_not_deduplicated(self):
        first = self._edge()
        second = replace(first, provenance=replace(
            first.provenance,
            instruction_offset=9,
        ))
        first = replace(first, provenance=replace(
            first.provenance,
            instruction_offset=1,
        ))
        graph = SimpleNamespace(methods_by_id={}, reverse_edges={})
        graph.methods_by_id["caller"] = SimpleNamespace(
            symbol_id="caller",
            qualified_key=first.caller_symbol,
            declared_qualified_key=first.caller_symbol,
            owner_type="business",
            owner_coord="__business__",
            module="app",
            is_test=False,
            file="/artifact/application.jar",
            line=12,
        )

        result = ingest_collector_batches(graph, (CollectorBatch(
            collector="business_bytecode", version="1", edges=(first, second),
        ),))

        self.assertEqual(result.merged_edges, 2)
        occurrences = graph.reverse_edges[first.callee_symbol]
        self.assertEqual(
            {item.instruction_offset for item in occurrences},
            {1, 9},
        )
        self.assertEqual(len(graph.step5_evidence_registry), 2)

    def test_same_callee_duplicate_detection_uses_linear_identity_index(self):
        base = self._edge()
        edges = tuple(
            replace(base, provenance=replace(base.provenance, instruction_offset=index))
            for index in range(400)
        )
        graph = SimpleNamespace(reverse_edges={})
        equality_calls = 0
        original_eq = CollectedEdge.__eq__

        def counted_eq(left, right):
            nonlocal equality_calls
            equality_calls += 1
            return original_eq(left, right)

        with patch.object(
            ingestion_module, "_call_edge_identity",
            wraps=ingestion_module._call_edge_identity,
        ) as identity, patch.object(CollectedEdge, "__eq__", counted_eq):
            result = ingest_collector_batches(graph, (CollectorBatch(
                collector="business_bytecode", version="1", edges=edges,
            ),))

        self.assertEqual(result.merged_edges, 400)
        self.assertEqual(len(graph.reverse_edges[base.callee_symbol]), 400)
        self.assertLess(identity.call_count, 2400)
        self.assertLess(equality_calls, 2400)

    def test_instruction_offset_zero_does_not_collapse_into_unknown_offset(self):
        edge = self._edge()
        zero = replace(edge, provenance=replace(edge.provenance, instruction_offset=0))
        unknown = replace(edge, provenance=replace(edge.provenance, instruction_offset=-1))
        graph = SimpleNamespace(methods_by_id={}, reverse_edges={})

        result = ingest_collector_batches(graph, (CollectorBatch(
            collector="business_bytecode", version="1", edges=(zero, unknown),
        ),))

        self.assertEqual(result.merged_edges, 2)
        self.assertEqual(
            {item.instruction_offset for item in graph.reverse_edges[edge.callee_symbol]},
            {-1, 0},
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

    def test_ingestion_keeps_typed_physical_edge_beside_unlocated_legacy_edge(self):
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

        self.assertEqual(result.merged_edges, 1)
        self.assertEqual(result.duplicate_edges, 0)
        self.assertEqual(len(graph.step5_evidence_registry), 1)
        self.assertEqual(len(graph.reverse_edges[edge.callee_symbol]), 2)

    def test_ingestion_keeps_distinct_physical_source_lines(self):
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

        self.assertEqual(result.merged_edges, 2)
        self.assertEqual(result.duplicate_edges, 0)
        self.assertEqual(len(graph.step5_evidence_registry), 2)
        self.assertEqual(len(graph.reverse_edges[first.callee_symbol]), 2)

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

    def test_business_bytecode_unrelated_rejection_does_not_poison_selected_api(self):
        from s5_call_chain_engine_integrated import _build_business_bytecode_coverage
        from step5_evidence_ingestion import IngestionResult

        failure = EvidenceFailure(
            stage="evidence-ingestion",
            reason_code="BYTECODE_CALLER_UNRESOLVED",
            blocking=True,
            api_identity="org.springframework.cache.CacheManager",
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
        selected = (
            "org.springframework.data:spring-data-commons|"
            "org.springframework.data.domain.Page.getContent|()|method|REMOVED"
        )

        coverage, status, reason_codes = _build_business_bytecode_coverage(
            batch, result, (selected,)
        )

        self.assertEqual(status, "complete")
        self.assertEqual(reason_codes, [])
        self.assertEqual(coverage[0].status, "complete")
        self.assertTrue(coverage[0].applicable)

    def test_business_bytecode_target_rejection_remains_partial(self):
        from s5_call_chain_engine_integrated import _build_business_bytecode_coverage
        from step5_evidence_ingestion import IngestionResult

        api_name = "org.springframework.data.domain.Page.getContent"
        selected = (
            "org.springframework.data:spring-data-commons|"
            f"{api_name}|()|method|REMOVED"
        )
        failure = EvidenceFailure(
            stage="evidence-ingestion",
            reason_code="BYTECODE_CALLER_UNRESOLVED",
            blocking=True,
            api_identity=f"{api_name}()",
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
            batch, result, (selected,)
        )

        self.assertEqual(status, "partial")
        self.assertEqual(reason_codes, ["BYTECODE_CALLER_UNRESOLVED"])
        self.assertEqual(coverage[0].status, "partial")
        self.assertEqual(coverage[0].reason_codes, ("BYTECODE_CALLER_UNRESOLVED",))

    def test_business_bytecode_rejection_does_not_poison_another_overload(self):
        from s5_call_chain_engine_integrated import _build_business_bytecode_coverage
        from step5_evidence_ingestion import IngestionResult

        api_name = "com.vendor.Target.call"
        selected = f"vendor:target|{api_name}|(String)|method|REMOVED"
        failure = EvidenceFailure(
            stage="evidence-ingestion",
            reason_code="BYTECODE_CALLER_UNRESOLVED",
            blocking=True,
            api_identity=f"{api_name}(Integer)",
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
            batch, result, (selected,)
        )

        self.assertEqual(status, "complete")
        self.assertEqual(reason_codes, [])
        self.assertEqual(coverage[0].status, "complete")

    def test_business_bytecode_failure_matches_nested_class_spelling(self):
        from s5_call_chain_engine_integrated import _build_business_bytecode_coverage
        from step5_evidence_ingestion import IngestionResult

        selected = (
            "vendor:target|com.vendor.Outer$Builder.call|"
            "(com.vendor.Outer$Arg)|method|REMOVED"
        )
        failure = EvidenceFailure(
            stage="evidence-ingestion",
            reason_code="BYTECODE_CALLER_UNRESOLVED",
            blocking=True,
            api_identity=(
                "com.vendor.Outer.Builder.call(com.vendor.Outer.Arg)"
            ),
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

        coverage, status, _reason_codes = _build_business_bytecode_coverage(
            batch, result, (selected,)
        )

        self.assertEqual(status, "partial")
        self.assertEqual(coverage[0].status, "partial")

    def test_business_bytecode_nested_signature_keeps_qualified_owner(self):
        from s5_call_chain_engine_integrated import _build_business_bytecode_coverage
        from step5_evidence_ingestion import IngestionResult

        selected = "vendor:target|com.vendor.Target.call|(x.Outer$Arg)|method|REMOVED"
        failure = EvidenceFailure(
            stage="evidence-ingestion",
            reason_code="BYTECODE_CALLER_UNRESOLVED",
            blocking=True,
            api_identity="com.vendor.Target.call(x.Other.Arg)",
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

        coverage, status, _reason_codes = _build_business_bytecode_coverage(
            batch, result, (selected,)
        )

        self.assertEqual(status, "complete")
        self.assertEqual(coverage[0].status, "complete")

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
        graph, edge, caller_sha = self._verified_mybatis_fixture()

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
        self.assertEqual(merged[0].caller_artifact_sha256, caller_sha)
        self.assertEqual(
            merged[0].framework_evidence_authority,
            EvidenceAuthority.FRAMEWORK_SEMANTIC.value,
        )
        self.assertTrue(merged[0].framework_final_artifact_verified)

    def test_mybatis_rejects_self_asserted_missing_artifacts(self):
        graph = self._proxy_graph()
        edge = self._mybatis_framework_edge()

        ingest_collector_batches(graph, (CollectorBatch(
            collector="mybatis_mapper_proxy", version="2", edges=(edge,),
        ),))

        self.assertFalse(any(
            item.framework_final_artifact_verified
            for item in graph.reverse_edges.get(edge.callee_symbol, ())
        ))

    def test_mybatis_rejects_same_named_entries_without_valid_semantics(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        final_jar = Path(temp_dir.name) / "fake-application.jar"
        caller_jar = Path(temp_dir.name) / "fake-caller.jar"
        runtime_jar = Path(temp_dir.name) / "fake-mybatis.jar"
        registration_entry = "BOOT-INF/classes/com/acme/CityMapper.class"
        binding_entry = "BOOT-INF/classes/mappers/CityMapper.xml"
        activation_entry = "BOOT-INF/classes/com/acme/Application.class"
        target_entry = "org/apache/ibatis/binding/MapperProxy.class"
        with zipfile.ZipFile(final_jar, "w") as archive:
            archive.writestr(registration_entry, b"mapper")
            archive.writestr(binding_entry, b"<mapper/>")
            archive.writestr(activation_entry, b"application")
        with zipfile.ZipFile(caller_jar, "w") as archive:
            archive.writestr(activation_entry, b"caller")
        with zipfile.ZipFile(runtime_jar, "w") as archive:
            archive.writestr(target_entry, b"runtime")
        final_sha = hashlib.sha256(final_jar.read_bytes()).hexdigest()
        caller_sha = hashlib.sha256(caller_jar.read_bytes()).hexdigest()
        runtime_sha = hashlib.sha256(runtime_jar.read_bytes()).hexdigest()
        graph = self._proxy_graph(artifact_sha256=caller_sha)
        caller = next(iter(graph.reverse_edges.values()))[0]
        caller.file = f"{caller_jar}!/{activation_entry}"
        edge = self._mybatis_framework_edge(
            provenance_final_artifact_path=str(final_jar),
            provenance_final_artifact_sha256=final_sha,
            provenance_mapper_registration={
                "artifact_path": str(final_jar), "artifact_entry": registration_entry,
                "artifact_sha256": final_sha,
                "authority": "current_final_artifact_classfile",
            },
            provenance_binding_evidence={
                "artifact_path": str(final_jar), "artifact_entry": binding_entry,
                "artifact_sha256": final_sha,
                "authority": "current_final_artifact_resource",
            },
            provenance_business_activation=[{
                "artifact_path": str(final_jar), "artifact_entry": activation_entry,
                "artifact_sha256": final_sha,
                "authority": "current_final_artifact_classfile",
            }],
            provenance_jar=str(runtime_jar),
            provenance_artifact_sha256=runtime_sha,
            provenance_physical_target_evidence={
                "target": (
                    "org.apache.ibatis.binding.MapperProxy.invoke"
                    "(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])"
                ),
                "dispatch_stage": "proxy_entry_dispatch",
                "verified": True,
                "artifact_entry": "BOOT-INF/lib/mybatis.jar",
                "artifact_sha256": runtime_sha,
                "class_or_resource_entry": target_entry,
            },
        )

        ingest_collector_batches(graph, (CollectorBatch(
            collector="mybatis_mapper_proxy", version="2", edges=(edge,),
        ),))

        self.assertFalse(any(
            item.evidence_type == "mybatis_mapper_proxy_dispatch"
            and item.confidence == "high"
            for item in graph.reverse_edges.get(edge.callee_symbol, ())
        ))

    def test_mybatis_rejects_mapper_descriptor_and_xml_command_mismatch(self):
        mutations = (
            {"provenance_command": "update"},
        )
        for changes in mutations:
            with self.subTest(changes=changes):
                graph, edge, _caller_sha = self._verified_mybatis_fixture()
                metadata = dict(edge.metadata)
                provenance = dict(metadata["framework_provenance"])
                if "provenance_command" in changes:
                    provenance["command"] = changes["provenance_command"]
                metadata["framework_provenance"] = provenance
                edge = replace(edge, metadata=tuple(metadata.items()))

                ingest_collector_batches(graph, (CollectorBatch(
                    collector="mybatis_mapper_proxy", version="2", edges=(edge,),
                ),))

                self.assertFalse(any(
                    item.evidence_type == "mybatis_mapper_proxy_dispatch"
                    and item.confidence == "high"
                    for item in graph.reverse_edges.get(edge.callee_symbol, ())
                ))

    def test_mybatis_annotation_binding_must_belong_to_exact_mapper_method(self):
        for misplaced in (False, True):
            with self.subTest(misplaced=misplaced):
                graph, edge, _caller_sha = self._verified_mybatis_fixture(
                    binding_mode="annotation", misplaced_annotation=misplaced
                )

                ingest_collector_batches(graph, (CollectorBatch(
                    collector="mybatis_mapper_proxy", version="2", edges=(edge,),
                ),))

                high = any(
                    item.evidence_type == "mybatis_mapper_proxy_dispatch"
                    and item.confidence == "high"
                    for item in graph.reverse_edges.get(edge.callee_symbol, ())
                )
                self.assertEqual(high, not misplaced)

    def test_mybatis_activation_call_must_belong_to_main_method(self):
        graph, edge, _caller_sha = self._verified_mybatis_fixture(
            misplaced_activation=True
        )

        ingest_collector_batches(graph, (CollectorBatch(
            collector="mybatis_mapper_proxy", version="2", edges=(edge,),
        ),))

        self.assertFalse(any(
            item.evidence_type == "mybatis_mapper_proxy_dispatch"
            and item.confidence == "high"
            for item in graph.reverse_edges.get(edge.callee_symbol, ())
        ))

    def test_mybatis_mapper_and_caller_return_descriptors_must_match(self):
        graph, edge, _caller_sha = self._verified_mybatis_fixture(
            caller_return_type="Object"
        )

        ingest_collector_batches(graph, (CollectorBatch(
            collector="mybatis_mapper_proxy", version="2", edges=(edge,),
        ),))

        self.assertFalse(any(
            item.evidence_type == "mybatis_mapper_proxy_dispatch"
            and item.confidence == "high"
            for item in graph.reverse_edges.get(edge.callee_symbol, ())
        ))

    def test_mybatis_registration_and_binding_must_match_mapper_owner(self):
        graph, edge, _caller_sha = self._verified_mybatis_fixture(
            binding_mode="annotation"
        )
        metadata = dict(edge.metadata)
        provenance = dict(metadata["framework_provenance"])
        wrong_entry = "BOOT-INF/classes/com/acme/OtherMapper.class"
        provenance["mapper_registration"] = {
            **dict(provenance["mapper_registration"]),
            "artifact_entry": wrong_entry,
        }
        provenance["binding_evidence"] = {
            **dict(provenance["binding_evidence"]),
            "artifact_entry": wrong_entry,
        }
        provenance["file"] = (
            provenance["final_artifact_path"] + "!/" + wrong_entry
        )
        provenance["binding_file"] = provenance["file"]
        metadata["framework_provenance"] = provenance
        edge = replace(edge, metadata=tuple(metadata.items()))

        ingest_collector_batches(graph, (CollectorBatch(
            collector="mybatis_mapper_proxy", version="2", edges=(edge,),
        ),))

        self.assertFalse(any(
            item.evidence_type == "mybatis_mapper_proxy_dispatch"
            and item.confidence == "high"
            for item in graph.reverse_edges.get(edge.callee_symbol, ())
        ))

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
        graph, edge, caller_sha = self._verified_mybatis_fixture(
            extracted_caller=True
        )

        ingest_collector_batches(graph, (CollectorBatch(
            collector="mybatis_mapper_proxy", version="2", edges=(edge,),
        ),))

        projected = graph.reverse_edges[edge.callee_symbol]
        self.assertTrue(any(
            item.evidence_type == "mybatis_mapper_proxy_dispatch"
            and item.confidence == "high"
            and item.framework_final_artifact_verified
            and item.caller_artifact_sha256 == caller_sha
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
                    "business_activation": [{
                        "business_entry": "com.acme.Application.main",
                        "artifact_entry": "BOOT-INF/classes/com/acme/Application.class",
                        "artifact_sha256": "a" * 64,
                        "authority": "current_final_artifact_classfile",
                    }],
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

        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        business_jar = Path(temp_dir.name) / "application.jar"
        framework_jar = Path(temp_dir.name) / "spring-tx.jar"
        with zipfile.ZipFile(business_jar, "w") as archive:
            archive.writestr(
                "BOOT-INF/classes/com/acme/Application.class", b"application"
            )
        framework_class = (
            "org/springframework/transaction/interceptor/"
            "TransactionInterceptor.class"
        )
        with zipfile.ZipFile(framework_jar, "w") as archive:
            archive.writestr(framework_class, b"transaction-interceptor")
        business_sha = hashlib.sha256(business_jar.read_bytes()).hexdigest()
        framework_sha = hashlib.sha256(framework_jar.read_bytes()).hexdigest()

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
                    "jar": str(framework_jar),
                    "artifact_entry": "BOOT-INF/lib/spring-tx.jar",
                    "artifact_sha256": framework_sha,
                    "class_or_resource_entry": framework_class,
                    "business_artifact_sha256": business_sha,
                    "business_activation": [{
                        "business_entry": "com.acme.Application.main",
                        "artifact_path": str(business_jar),
                        "artifact_entry": "BOOT-INF/classes/com/acme/Application.class",
                        "artifact_sha256": business_sha,
                        "authority": "current_final_artifact_classfile",
                    }],
                }),
            ),
        )
        caller = next(iter(self._proxy_graph().reverse_edges.values()))[0]
        caller.callee_key = "com.acme.BookingService.book(java.lang.String)"
        caller.artifact_sha256 = business_sha
        caller.file = (
            f"{business_jar}!/BOOT-INF/classes/com/acme/Application.class"
        )
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
            f"{business_jar}!/BOOT-INF/classes/com/acme/Application.class",
        )
        self.assertEqual(merged.runtime_analyzer_hit["coord"], "__business__")
        self.assertEqual(merged.runtime_analyzer_hit["artifact_sha256"], business_sha)
        self.assertEqual(
            merged.runtime_analyzer_hit["artifact_entry"],
            "BOOT-INF/classes/com/acme/Application.class",
        )
        self.assertTrue(_edge_allowed_for_trace(merged, graph))

    def test_transaction_proxy_rejects_unrelated_business_artifact_sha(self):
        target = "framework.TransactionInterceptor.invoke()"
        edge = self._framework_edge(
            "spring_transaction_proxy_dispatch",
            target=target,
            metadata=(
                ("framework_source", "com.acme.CityMapper.find/1"),
                ("source_owner", "com.acme.CityMapper"),
                ("source_member", "find"),
                ("parameter_count", 1),
                ("framework_provenance", {
                    "authority": "final_artifact_javap",
                    "artifact_sha256": "b" * 64,
                    "business_artifact_sha256": "d" * 64,
                    "business_activation": [{
                        "artifact_entry": "BOOT-INF/classes/com/acme/Application.class",
                        "artifact_sha256": "d" * 64,
                        "authority": "current_final_artifact_classfile",
                    }],
                }),
            ),
        )
        graph = self._proxy_graph(artifact_sha256="a" * 64)

        ingest_collector_batches(graph, (CollectorBatch(
            collector="spring_transaction_proxy", version="1", edges=(edge,),
        ),))

        projected = graph.reverse_edges[target][0]
        self.assertFalse(projected.framework_final_artifact_verified)
        self.assertNotEqual(projected.confidence, "high")

    def test_transaction_proxy_rejects_source_only_truthy_activation(self):
        target = "framework.TransactionInterceptor.invoke()"
        edge = self._framework_edge(
            "spring_transaction_proxy_dispatch",
            target=target,
            metadata=(
                ("framework_source", "com.acme.CityMapper.find/1"),
                ("source_owner", "com.acme.CityMapper"),
                ("source_member", "find"),
                ("parameter_count", 1),
                ("framework_provenance", {
                    "authority": "final_artifact_javap",
                    "artifact_entry": "BOOT-INF/lib/spring-tx.jar",
                    "artifact_sha256": "b" * 64,
                    "business_artifact_sha256": "a" * 64,
                    "business_activation": [{
                        "business_entry": "com.acme.Application.main",
                        "spring_application_run": True,
                    }],
                }),
            ),
        )
        graph = self._proxy_graph(artifact_sha256="a" * 64)

        ingest_collector_batches(graph, (CollectorBatch(
            collector="spring_transaction_proxy", version="1", edges=(edge,),
        ),))

        projected = graph.reverse_edges[target][0]
        self.assertFalse(projected.framework_final_artifact_verified)
        self.assertEqual(projected.confidence, "medium")

    def test_spring_data_proxy_rejects_source_only_truthy_activation(self):
        target = "org.springframework.data.jpa.repository.support.SimpleJpaRepository.find(String)"
        edge = self._framework_edge(
            "spring_data_repository_proxy_dispatch",
            target=target,
            metadata=(
                ("framework_source", "com.acme.CityMapper"),
                ("target_member", "find"),
                ("parameter_count", 1),
                ("repository_declared_method_count", 1),
                ("framework_provenance", {
                    "authority": "final_artifact_javap",
                    "artifact_sha256": "b" * 64,
                    "business_activation": [{
                        "business_entry": "com.acme.Application.main",
                        "spring_application_run": True,
                        "spring_boot_annotation": True,
                    }],
                }),
            ),
        )
        graph = self._proxy_graph(artifact_sha256="a" * 64)

        ingest_collector_batches(graph, (CollectorBatch(
            collector="spring_data_repository_proxy", version="1", edges=(edge,),
        ),))

        projected = graph.reverse_edges[target][0]
        self.assertFalse(projected.framework_final_artifact_verified)
        self.assertEqual(projected.confidence, "medium")

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
        self.assertEqual(linked[0].caller_evidence_source, "source_ast")
        self.assertFalse(linked[0].framework_final_artifact_verified)

        ingest_collector_batches(graph, (CollectorBatch(
            collector="spring_runtime_artifact", version="2", edges=(),
        ),))
        self.assertNotIn(callback.declared_qualified_key, graph.reverse_edges)
        self.assertEqual(graph.framework_edges, [])

    def test_runtime_callback_source_only_activation_is_not_linked_in_final_artifact_mode(self):
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
            owner_type="business",
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
                    "artifact_entry": "BOOT-INF/lib/listener.jar",
                    "artifact_sha256": "b" * 64,
                    "business_activation": [{
                        "business_entry": "com.acme.Application.main",
                        "spring_application_run": True,
                    }],
                }),
            ),
        )
        graph = SimpleNamespace(
            methods_by_id={callback.symbol_id: callback, activation.symbol_id: activation},
            reverse_edges={},
            require_current_final_artifact_business_edges=True,
        )

        result = ingest_collector_batches(graph, (CollectorBatch(
            collector="spring_runtime_artifact", version="1", edges=(edge,),
        ),))

        self.assertEqual(result.framework_activation_linked_methods, 0)
        self.assertNotIn(callback.declared_qualified_key, graph.reverse_edges)

    def test_runtime_callback_verified_activation_carries_traceable_composite_provenance(self):
        from confidence_weighted_tracer import _edge_allowed_for_trace

        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        business_jar = Path(temp_dir.name) / "application.jar"
        framework_jar = Path(temp_dir.name) / "listener.jar"
        with zipfile.ZipFile(business_jar, "w") as archive:
            archive.writestr(
                "BOOT-INF/classes/com/acme/Application.class", b"business-class"
            )
        with zipfile.ZipFile(framework_jar, "w") as archive:
            archive.writestr("BOOT-INF/lib/listener.jar", b"registration-evidence")
        business_sha = hashlib.sha256(business_jar.read_bytes()).hexdigest()
        framework_sha = hashlib.sha256(framework_jar.read_bytes()).hexdigest()

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
            owner_type="business",
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
                    "jar": str(framework_jar),
                    "artifact_entry": "BOOT-INF/lib/listener.jar",
                    "artifact_sha256": framework_sha,
                    "business_activation": [{
                        "business_entry": "com.acme.Application.main",
                        "artifact_path": str(business_jar),
                        "artifact_entry": "BOOT-INF/classes/com/acme/Application.class",
                        "artifact_sha256": business_sha,
                        "authority": "current_final_artifact_classfile",
                    }],
                }),
            ),
        )
        graph = SimpleNamespace(
            methods_by_id={callback.symbol_id: callback, activation.symbol_id: activation},
            reverse_edges={},
            require_current_final_artifact_business_edges=True,
        )

        result = ingest_collector_batches(graph, (CollectorBatch(
            collector="spring_runtime_artifact", version="1", edges=(edge,),
        ),))

        self.assertEqual(result.framework_activation_linked_methods, 1)
        linked = graph.reverse_edges[callback.declared_qualified_key][0]
        self.assertEqual(linked.caller_evidence_source, "current_final_artifact")
        self.assertEqual(linked.caller_artifact_sha256, business_sha)
        self.assertEqual(
            linked.caller_artifact_entry,
            "BOOT-INF/classes/com/acme/Application.class",
        )
        self.assertTrue(linked.framework_final_artifact_verified)
        self.assertTrue(_edge_allowed_for_trace(linked, graph))

    def test_runtime_activation_rejects_self_asserted_sha_without_artifact_bytes(self):
        from step5_evidence_ingestion import _activation_matches_business_artifact

        activation = {
            "business_entry": "com.acme.Application.main",
            "artifact_path": "/artifact/does-not-exist.jar",
            "artifact_entry": "BOOT-INF/classes/com/acme/Application.class",
            "artifact_sha256": "a" * 64,
            "authority": "current_final_artifact_classfile",
        }

        self.assertFalse(
            _activation_matches_business_artifact(activation, "a" * 64)
        )

    def test_proxy_verification_requires_framework_bytes_and_caller_class_entry(self):
        from step5_evidence_ingestion import _proxy_final_artifact_verified

        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        business_jar = Path(temp_dir.name) / "application.jar"
        framework_jar = Path(temp_dir.name) / "spring-tx.jar"
        with zipfile.ZipFile(business_jar, "w") as archive:
            archive.writestr(
                "BOOT-INF/classes/com/acme/Application.class", b"application"
            )
            archive.writestr(
                "BOOT-INF/classes/com/acme/MissingCaller.class", b"caller"
            )
        framework_class = (
            "org/springframework/transaction/interceptor/"
            "TransactionInterceptor.class"
        )
        with zipfile.ZipFile(framework_jar, "w") as archive:
            archive.writestr(framework_class, b"transaction-interceptor")
        business_sha = hashlib.sha256(business_jar.read_bytes()).hexdigest()
        framework_sha = hashlib.sha256(framework_jar.read_bytes()).hexdigest()
        activation = {
            "business_entry": "com.acme.Application.main",
            "artifact_path": str(business_jar),
            "artifact_entry": "BOOT-INF/classes/com/acme/Application.class",
            "artifact_sha256": business_sha,
            "authority": "current_final_artifact_classfile",
        }
        caller = SimpleNamespace(
            artifact_sha256=business_sha,
            artifact_entry="BOOT-INF/classes/com/acme/MissingCaller.class",
            file=(
                "/artifact/forged-business.jar!/"
                "BOOT-INF/classes/com/acme/MissingCaller.class"
            ),
        )
        provenance = {
            "authority": "final_artifact_javap",
            "jar": str(framework_jar),
            "artifact_sha256": framework_sha,
            "class_or_resource_entry": framework_class,
            "business_artifact_sha256": business_sha,
            "business_activation": [activation],
        }

        self.assertFalse(_proxy_final_artifact_verified(
            provenance, caller, require_business_sha=True,
        ))


if __name__ == "__main__":
    unittest.main()
