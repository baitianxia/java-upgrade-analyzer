import csv
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import io
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import confidence_weighted_tracer as tracer  # noqa: E402
import business_bytecode_graph  # noqa: E402
import enhanced_source_analyzer as source_analyzer  # noqa: E402
import enhanced_output_formatter as formatter  # noqa: E402
import framework_adapters  # noqa: E402
import gate  # noqa: E402
import s4_jar_compare  # noqa: E402
import s5_call_chain_engine_integrated as step5  # noqa: E402
import s6_report  # noqa: E402
from step5_evidence_ingestion import ingest_collector_batches  # noqa: E402
from step5_evidence_model import (  # noqa: E402
    CollectorBatch,
    CoverageRecord,
    EvidenceConcern,
    EvidenceFailure,
)
from pipeline_constants import PER_DEPENDENCY_DIRNAME  # noqa: E402
from s4_contract import make_per_dependency_dirname  # noqa: E402
from step5_artifact_fact_store import Step5ArtifactFactStore  # noqa: E402
from tests.retained_artifact_test_support import (  # noqa: E402
    retain_current_artifact_contract,
)


class Step5KeyMatchingTest(unittest.TestCase):
    def setUp(self):
        tracer.clear_immutable_artifact_parse_cache()

    def tearDown(self):
        tracer.clear_immutable_artifact_parse_cache()

    def _draft_from_result(self, result):
        values = {
            name: getattr(result, name)
            for name in tracer.TraceDraft.__dataclass_fields__
            if hasattr(result, name)
        }
        return tracer.TraceDraft(**values)

    def _exact_chain_fixture(self, hops, *, first_edge_confidence="high"):
        api_row = {
            "api_name": "com.vendor.Api.changed",
            "api_simple": "changed",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
            "coord": "com.vendor:api",
            "severity": "P0",
            "confirmed": "true",
            "source": "oracle_fixture",
            "analysis_scope": "method",
        }

        methods = {}
        callers = []
        for index in range(max(0, hops - 1)):
            method = SimpleNamespace(
                symbol_id=f"dep-{index}",
                qualified_key=f"com.example.dep.C{index}.call{index}",
                simple_key=f"method:call{index}",
                class_fqcn=f"com.example.dep.C{index}",
                class_name=f"C{index}",
                method_name=f"call{index}",
                param_types={},
                param_declared_types={},
                declared_signature="()",
                owner_type="dependency",
                owner_coord="com.example:dep",
                module="dep",
                is_test=False,
                annotations=[],
                class_annotations=[],
                modifiers=["public"],
                is_interface=False,
                file=f"/tmp/C{index}.java",
                line=index + 1,
            )
            methods[method.symbol_id] = method
            callers.append(method)

        entry = SimpleNamespace(
            symbol_id="business-entry",
            qualified_key="com.example.app.Controller.handle",
            simple_key="method:handle",
            class_fqcn="com.example.app.Controller",
            class_name="Controller",
            method_name="handle",
            param_types={},
            param_declared_types={},
            declared_signature="()",
            owner_type="business",
            owner_coord="BUSINESS",
            module="app",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=["RestController"],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Controller.java",
            line=100,
        )
        methods[entry.symbol_id] = entry
        callers.append(entry)

        reverse_edges = {}
        current_key = "com.vendor.Api.changed()"
        for index, caller in enumerate(callers):
            confidence = first_edge_confidence if index == 0 else "high"
            reverse_edges[current_key] = [SimpleNamespace(
                caller_symbol_id=caller.symbol_id,
                caller_qualified_key=caller.qualified_key,
                callee_key=current_key,
                callee_simple_key=current_key.rsplit(".", 1)[-1],
                confidence=confidence,
                evidence_type="ast_method_invocation",
                file=caller.file,
                line=caller.line,
                owner_type=caller.owner_type,
                owner_coord=caller.owner_coord,
                module=caller.module,
                is_test=False,
            )]
            current_key = f"{caller.qualified_key}()"

        graph = SimpleNamespace(
            methods_by_id=methods,
            reverse_edges=reverse_edges,
            reverse_edge_count=len(callers),
        )
        return api_row, graph

    def _shared_predecessor_batch_fixture(self, target_count):
        def method(symbol_id, qualified_key, owner_type):
            class_fqcn, method_name = qualified_key.rsplit(".", 1)
            return source_analyzer.MethodDef(
                symbol_id=symbol_id,
                qualified_key=qualified_key,
                simple_key=f"method:{method_name}",
                class_fqcn=class_fqcn,
                class_name=class_fqcn.rsplit(".", 1)[-1],
                method_name=method_name,
                return_type="void",
                file=f"/{symbol_id}.java",
                line=1,
                end_line=2,
                package_name=class_fqcn.rsplit(".", 1)[0],
                owner_type=owner_type,
                owner_coord=("BUSINESS" if owner_type == "business" else "com.example:bridge"),
                module=("app" if owner_type == "business" else "bridge"),
                source_root="/src/main/java",
                language="java",
                is_test=False,
                declared_signature="()",
                declared_qualified_key=f"{qualified_key}()",
                annotations=(['GetMapping'] if owner_type == "business" else []),
                class_annotations=(['RestController'] if owner_type == "business" else []),
                modifiers=['public'],
            )

        def edge(caller, callee_key):
            return source_analyzer.CallEdge(
                caller_symbol_id=caller.symbol_id,
                caller_qualified_key=caller.qualified_key,
                callee_key=callee_key,
                callee_simple_key=f"method:{callee_key.rsplit('.', 1)[-1]}",
                evidence_type="ast_method_invocation",
                confidence="high",
                file=caller.file,
                line=caller.line,
                content=callee_key,
                owner_type=caller.owner_type,
                owner_coord=caller.owner_coord,
                module=caller.module,
                is_test=False,
            )

        shared = method("shared", "com.example.bridge.Shared.route", "dependency")
        entry = method("entry", "com.example.app.BatchController.handle", "business")
        methods = {shared.symbol_id: shared, entry.symbol_id: entry}
        reverse_edges = {
            "com.example.bridge.Shared.route()": [
                edge(entry, "com.example.bridge.Shared.route()")
            ]
        }
        apis = []
        for index in range(target_count):
            leaf = method(
                f"leaf-{index}",
                f"com.example.bridge.Leaf{index}.call",
                "dependency",
            )
            methods[leaf.symbol_id] = leaf
            target_key = f"com.vendor.Target.api{index}()"
            reverse_edges[target_key] = [edge(leaf, target_key)]
            leaf_key = f"{leaf.qualified_key}()"
            reverse_edges[leaf_key] = [edge(shared, leaf_key)]
            apis.append({
                "coord": "com.vendor:target",
                "api_name": f"com.vendor.Target.api{index}",
                "api_simple": f"api{index}",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "severity": "P1",
                "confirmed": "true",
                "source": "performance-fixture",
                "analysis_scope": "method",
            })
        type_metadata = {
            method_def.class_fqcn: {"kind": "class", "annotations": []}
            for method_def in methods.values()
        }
        graph = SimpleNamespace(
            methods_by_id=methods,
            reverse_edges=reverse_edges,
            reverse_edge_count=sum(len(edges) for edges in reverse_edges.values()),
            type_metadata=type_metadata,
        )
        return apis, graph, type_metadata

    def test_malformed_context_cannot_fall_back_to_empty_source_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            context_path = Path(tmp) / "context.json"
            context_path.write_text('{"source_dirs": [', encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "STEP5_CONTEXT_PARSE_FAILED"):
                step5.load_context_source_dirs(context_path)

    def _verified_composite_framework_edge(self, **changes):
        artifact_entry = "BOOT-INF/classes/app/Application.class"
        framework_entry = "BOOT-INF/lib/spring-tx.jar"
        values = {
            "callee_key": (
                "org.springframework.transaction.interceptor.TransactionInterceptor."
                "invoke(org.aopalliance.intercept.MethodInvocation)"
            ),
            "evidence_source": "framework_semantic",
            "evidence_authority": "framework_semantic",
            "semantic": True,
            "framework_registration": True,
            "framework_final_artifact_verified": True,
            "framework_source": "app.BookingService.book/1",
            "framework_target": (
                "org.springframework.transaction.interceptor.TransactionInterceptor."
                "invoke(org.aopalliance.intercept.MethodInvocation)"
            ),
            "framework_evidence_source": "framework_semantic",
            "framework_evidence_authority": "framework_semantic",
            "framework_evidence_artifact_sha256": "b" * 64,
            "framework_evidence_artifact_entry": framework_entry,
            "artifact_sha256": "b" * 64,
            "artifact_entry": framework_entry,
            "collector": "spring_transaction_proxy",
            "caller_evidence_source": "current_final_artifact",
            "caller_evidence_authority": "current_final_artifact",
            "caller_artifact_sha256": "a" * 64,
            "caller_evidence_file": f"/artifact/application.jar!/{artifact_entry}",
            "caller_artifact_entry": artifact_entry,
            "owner_type": "business",
            "owner_coord": "BUSINESS",
            "is_test": False,
            "runtime_analyzer_hit": True,
        }
        values.update(changes)
        return SimpleNamespace(**values)

    def test_verified_final_artifact_framework_path_can_explain_static_scan_miss(self):
        edge = self._verified_composite_framework_edge()
        candidate = {"path": [edge]}
        graph = SimpleNamespace(
            require_current_final_artifact_business_edges=True,
            reverse_edges={edge.callee_key: [edge]},
        )
        api_row = {
            "api_name": edge.callee_key.split("(", 1)[0],
            "api_signature": "(org.aopalliance.intercept.MethodInvocation)",
        }

        self.assertTrue(tracer._edge_allowed_for_trace(edge, graph))
        self.assertTrue(
            tracer.has_verified_final_artifact_framework_path(candidate)
        )
        self.assertTrue(
            tracer._has_verified_final_artifact_framework_target(api_row, graph)
        )

    def test_composite_framework_trust_rejects_corrupt_nested_projection(self):
        mutations = {
            "framework_verification_missing": {
                "framework_final_artifact_verified": False,
            },
            "top_level_authority_upgraded": {
                "evidence_source": "current_final_artifact",
            },
            "caller_source_missing": {"caller_evidence_source": ""},
            "caller_authority_missing": {"caller_evidence_authority": ""},
            "caller_authority_invalid": {
                "caller_evidence_authority": "source_ast",
            },
            "caller_sha_missing": {"caller_artifact_sha256": ""},
            "caller_sha_invalid": {"caller_artifact_sha256": "corrupt"},
            "caller_path_missing": {"caller_evidence_file": ""},
            "caller_entry_missing": {"caller_artifact_entry": ""},
            "framework_source_invalid": {
                "framework_evidence_source": "current_final_artifact",
            },
            "framework_authority_missing": {
                "framework_evidence_authority": "",
            },
            "framework_authority_invalid": {
                "framework_evidence_authority": "current_final_artifact",
            },
            "framework_sha_missing": {
                "framework_evidence_artifact_sha256": "",
            },
            "framework_sha_mismatch": {
                "artifact_sha256": "c" * 64,
            },
            "framework_entry_mismatch": {
                "artifact_entry": "BOOT-INF/lib/other.jar",
            },
        }
        for name, changes in mutations.items():
            with self.subTest(mutation=name):
                edge = self._verified_composite_framework_edge(**changes)
                graph = SimpleNamespace(
                    require_current_final_artifact_business_edges=True,
                    reverse_edges={edge.callee_key: [edge]},
                )
                api_row = {
                    "api_name": edge.callee_key.split("(", 1)[0],
                    "api_signature": "(org.aopalliance.intercept.MethodInvocation)",
                }

                self.assertFalse(tracer._edge_allowed_for_trace(edge, graph))
                self.assertFalse(tracer.has_verified_final_artifact_framework_path({
                    "path": [edge],
                }))
                self.assertFalse(
                    tracer._has_verified_final_artifact_framework_target(api_row, graph)
                )

    def test_graph_field_edge_keeps_selected_changed_api_identity(self):
        api_row = {
            "coord": "jdk:java.base",
            "api_name": "java.lang.System.out",
            "api_simple": "out",
            "api_signature": "",
            "symbol_kind": "field",
            "change_type": "REMOVED",
        }
        edge = SimpleNamespace(
            callee_key="java.lang.System.out",
            evidence_type="bytecode_field_access",
            owner_coord="__business__",
        )

        matched = tracer._graph_edge_target_row(edge, [api_row])

        self.assertIs(matched, api_row)

    def test_graph_edge_owner_index_preserves_exact_first_match_semantics(self):
        unrelated = {
            "api_name": "other.Type.call",
            "api_simple": "call",
            "api_signature": "(String)",
            "symbol_kind": "method",
        }
        first_match = {
            "api_name": "example.Type.call",
            "api_simple": "call",
            "api_signature": "(java.lang.String)",
            "symbol_kind": "method",
        }
        duplicate_match = dict(first_match)
        rows = [unrelated, first_match, duplicate_match]
        edge = SimpleNamespace(
            callee_key="example.Type.call(String)",
            evidence_type="bytecode_method_invocation",
            owner_coord="__business__",
        )

        indexed = tracer._graph_edge_target_row(
            edge,
            rows,
            api_rows_by_owner=tracer._build_graph_edge_api_owner_index(rows),
        )
        unindexed = tracer._graph_edge_target_row(edge, rows)

        self.assertIs(indexed, first_match)
        self.assertIs(indexed, unindexed)

    def test_classfile_fast_path_preserves_dollar_in_nested_jvm_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            classes = self._compile_java_fixture(
                tmp,
                "fixture/Outer.java",
                """
                package fixture;
                public class Outer {
                    static class Inner { static void target() {} }
                    public void call() { Inner.target(); }
                }
                """,
            )
            edges = business_bytecode_graph.parse_classfile_calls(
                (classes / "fixture/Outer.class").read_bytes(), "fixture.Outer"
            )

        target_edge = next(
            edge for edge in edges
            if edge.get("caller_name") == "call" and "target(" in edge.get("callee_key", "")
        )
        self.assertEqual(target_edge["callee_jvm_owner"], "fixture.Outer$Inner")
        references = tracer._references_from_executable_classfile_edges(
            [target_edge], class_binary_name="fixture.Outer"
        )
        self.assertEqual(
            references["method_refs"][0]["jvm_owner"], "fixture.Outer$Inner"
        )

    def test_classfile_fast_path_normalizes_constructor_caller_to_jvm_init(self):
        references = tracer._references_from_executable_classfile_edges(
            [{
                "evidence_type": "bytecode_method_invocation",
                "content": "opcode 0xb8",
                "line": 5,
                "callee_key": "cn.hutool.core.collection.CollUtil.isNotEmpty(java.util.Collection)",
                "caller_name": "BoolArrayMatcher",
                "caller_descriptor": "(Ljava/util/List;)V",
                "callee_descriptor": "(Ljava/util/Collection;)Z",
            }],
            class_binary_name="cn.hutool.cron.pattern.matcher.BoolArrayMatcher",
        )

        self.assertEqual(
            references["method_refs"][0]["consumer_method"], "<init>"
        )

    def test_classfile_fast_path_uses_descriptor_for_nested_parameter_signature(self):
        references = tracer._references_from_executable_classfile_edges(
            [{
                "evidence_type": "bytecode_method_invocation",
                "content": "opcode 0xb8", "line": 4,
                "callee_key": "org.example.ScrollPosition.of(Map, Direction)",
                "caller_name": "forward", "caller_descriptor": "(Ljava/util/Map;)V",
                "callee_descriptor": (
                    "(Ljava/util/Map;Lorg/example/ScrollPosition$Direction;)"
                    "Lorg/example/ScrollPosition;"
                ),
            }],
            class_binary_name="org.example.ScrollPosition",
        )

        self.assertEqual(
            references["method_refs"][0]["signature"],
            "(Map, ScrollPosition$Direction)",
        )

    def test_exhaustive_runtime_closure_keeps_every_business_path_and_drops_unrelated_edges(self):
        api = {
            "coord": "vendor:target",
            "api_name": "vendor.Target.changed",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }

        def edge(coord, caller, callee, member="call", offset=1):
            caller_owner, caller_member = caller.rsplit(".", 1)
            callee_owner, callee_member = callee.rsplit(".", 1)
            return {
                "coord": coord,
                "caller_owner": caller_owner,
                "consumer_method": caller_member,
                "consumer_descriptor": "()V",
                "callee_owner": callee_owner,
                "callee_member": callee_member,
                "callee_descriptor": "()V",
                "opcode_family": "invokestatic",
                "instruction_offset": offset,
                "class_entry": caller_owner.replace(".", "/") + ".class",
                "jar_path": "/tmp/runtime.jar",
                "artifact_container_entry": "" if coord == "__business__" else "BOOT-INF/lib/target.jar",
            }

        edges = [
            edge("vendor:target", "vendor.Bridge.call", "vendor.Target.changed", offset=3),
            edge("vendor:target", "vendor.Middle.call", "vendor.Bridge.call", offset=5),
            edge("__business__", "app.First.run", "vendor.Middle.call", offset=7),
            edge("__business__", "app.Second.run", "vendor.Middle.call", offset=9),
            edge("vendor:target", "vendor.Middle.unrelated", "vendor.Other.call", offset=11),
        ]

        retained = tracer._retain_exhaustive_runtime_reference_edges([api], edges)

        self.assertEqual(len(retained), 4)
        self.assertEqual(
            {item["edge"]["caller_owner"] for item in retained},
            {"vendor.Bridge", "vendor.Middle", "app.First", "app.Second"},
        )
        self.assertTrue(all(item["api_row"] is api for item in retained))

    def test_source_graph_keeps_methods_declared_in_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "Target.java").write_text(
                "package com.acme;\nclass Target { static void changed() {} }\n",
                encoding="utf-8",
            )
            (source_root / "Event.java").write_text(
                "package com.acme;\nrecord Event(String id) { void run() { Target.changed(); } }\n",
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])

        self.assertIn("com.acme.Target.changed()", graph_result["graph"].reverse_edges)

    def test_source_graph_keeps_record_accessor_calls_as_exact_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "Event.java").write_text(
                "package com.acme;\npublic record Event(String id) {}\n",
                encoding="utf-8",
            )
            (source_root / "Use.java").write_text(
                "package com.acme;\nclass Use { String read(Event event) { return event.id(); } }\n",
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])

        self.assertIn("com.acme.Event.id()", graph_result["graph"].reverse_edges)

    def test_source_graph_keeps_sealed_interface_implementations(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "Shape.java").write_text(
                "package com.acme;\nsealed interface Shape permits Circle, Square {}\n",
                encoding="utf-8",
            )
            (source_root / "Circle.java").write_text(
                "package com.acme;\nfinal class Circle implements Shape {}\n",
                encoding="utf-8",
            )
            (source_root / "Square.java").write_text(
                "package com.acme;\nfinal class Square implements Shape {}\n",
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])

        self.assertEqual(
            ["com.acme.Circle", "com.acme.Square"],
            graph_result["type_metadata"]["com.acme.Shape"]["implementations"],
        )

    def test_source_graph_resolves_pattern_switch_receiver_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "Target.java").write_text(
                "package com.acme;\nclass Target { void changed() {} }\n",
                encoding="utf-8",
            )
            (source_root / "Use.java").write_text(
                "package com.acme;\nclass Use { void run(Object value) { switch (value) { case Target target -> target.changed(); default -> {} } } }\n",
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])

        self.assertIn("com.acme.Target.changed()", graph_result["graph"].reverse_edges)

    def test_source_graph_keeps_explicit_array_argument_for_varargs_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "Target.java").write_text(
                "package com.acme;\nclass Target { static void changed(Object... values) {} }\n",
                encoding="utf-8",
            )
            (source_root / "Use.java").write_text(
                "package com.acme;\nclass Use { void run() { Target.changed(new Object[] { \"value\" }); } }\n",
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])

        self.assertIn("com.acme.Target.changed(Object[])", graph_result["graph"].reverse_edges)

    def test_source_graph_resolves_dubbo_reference_interface_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "RemoteApi.java").write_text(
                "package com.acme;\ninterface RemoteApi { String changed(String value); }\n",
                encoding="utf-8",
            )
            (source_root / "Consumer.java").write_text(
                "package com.acme; import org.apache.dubbo.config.annotation.DubboReference; "
                "class Consumer { @DubboReference RemoteApi api; String run(String value) { return api.changed(value); } }\n",
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])

        self.assertIn("com.acme.RemoteApi.changed(String)", graph_result["graph"].reverse_edges)

    def test_source_graph_resolves_spring_data_derived_repository_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "UserRepository.java").write_text(
                "package com.acme;\ninterface UserRepository { Object findByUsernameAndEmail(String user, String email); }\n",
                encoding="utf-8",
            )
            (source_root / "UserService.java").write_text(
                "package com.acme;\nclass UserService { UserRepository repository; "
                "Object load(String user, String email) { return repository.findByUsernameAndEmail(user, email); } }\n",
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])

        self.assertIn(
            "com.acme.UserRepository.findByUsernameAndEmail(String, String)",
            graph_result["graph"].reverse_edges,
        )

    def test_annotation_default_member_change_is_not_silently_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "TargetAnno.java").write_text(
                "package com.acme;\npublic @interface TargetAnno { int timeout() default 10; }\n",
                encoding="utf-8",
            )
            (source_root / "Use.java").write_text(
                "package com.acme;\n@TargetAnno class Use { void run() {} }\n",
                encoding="utf-8",
            )
            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "com.acme:annotation-api",
                    "api_name": "com.acme.TargetAnno.timeout",
                    "api_simple": "timeout",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "SIGNATURE_CHANGED",
                    "severity": "P1",
                    "confirmed": "true",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
            )

        self.assertNotEqual("not_found_in_static_analysis", result.analysis_status)
        self.assertTrue(result.call_paths)
        self.assertEqual("annotation_default_usage", result.evidence_paths[0][0]["evidence_type"])

    def test_source_graph_keeps_reactive_method_reference_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "Use.java").write_text(
                "package com.acme;\n"
                "class Use {\n"
                "  String changed(String value) { return value; }\n"
                "  void run(reactor.core.publisher.Mono<String> mono) { mono.map(this::changed).subscribe(); }\n"
                "}\n",
                encoding="utf-8",
            )
            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])

        self.assertIn("com.acme.Use.changed(String)", graph_result["graph"].reverse_edges)

    def test_source_graph_keeps_executor_lambda_calls_on_submitter(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "Target.java").write_text(
                "package com.acme;\nclass Target { static void changed() {} }\n",
                encoding="utf-8",
            )
            (source_root / "Use.java").write_text(
                "package com.acme;\nimport java.util.concurrent.ExecutorService;\n"
                "class Use { void submit(ExecutorService executor) { executor.submit(() -> Target.changed()); } }\n",
                encoding="utf-8",
            )
            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])

        target_edges = graph_result["graph"].reverse_edges["com.acme.Target.changed()"]
        self.assertEqual(["com.acme.Use.submit"], [edge.caller_qualified_key for edge in target_edges])

    def test_source_graph_binds_hidden_static_method_to_declaring_subclass(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "Parent.java").write_text(
                "package com.acme;\nclass Parent { static void changed() {} }\n",
                encoding="utf-8",
            )
            (source_root / "Child.java").write_text(
                "package com.acme;\nclass Child extends Parent { static void changed() {} }\n",
                encoding="utf-8",
            )
            (source_root / "Use.java").write_text(
                "package com.acme;\nclass Use { void run() { Child.changed(); } }\n",
                encoding="utf-8",
            )
            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])

        graph = graph_result["graph"]
        self.assertIn("com.acme.Child.changed()", graph.reverse_edges)
        self.assertNotIn("com.acme.Parent.changed()", graph.reverse_edges)

    def test_low_confidence_direct_business_edge_is_not_silently_not_found(self):
        method = SimpleNamespace(
            symbol_id="business", qualified_key="com.acme.Use.run", owner_type="business",
            owner_coord="BUSINESS", is_test=False, file="Use.java", line=1,
            annotations=[], class_annotations=[], class_name="Use", class_fqcn="com.acme.Use",
            modifiers=["public"], is_interface=False,
        )
        edge = SimpleNamespace(
            caller_symbol_id="business", caller_qualified_key=method.qualified_key,
            callee_key="com.vendor.Target.changed()", callee_simple_key="method:changed()",
            confidence="low", evidence_type="unresolved_dynamic_receiver", file="Use.java", line=2,
            owner_type="business", owner_coord="BUSINESS", module="app", is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"business": method},
            reverse_edges={"com.vendor.Target.changed()": [edge]},
            runtime_dependency_catalog={},
        )
        result = tracer.trace_api_with_confidence_weighting(
            {
                "coord": "com.vendor:target", "api_name": "com.vendor.Target.changed",
                "api_simple": "changed", "api_signature": "()", "symbol_kind": "method",
                "change_type": "REMOVED", "severity": "P0", "confirmed": "true",
            },
            graph,
            {},
            max_total_cost=5,
        )

        self.assertNotEqual("not_found_in_static_analysis", result.analysis_status)

    def test_source_graph_keeps_optional_method_reference_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "Use.java").write_text(
                "package com.acme;\nimport java.util.Optional;\n"
                "class Use { void changed(String value) {} "
                "void run(String value) { Optional.ofNullable(value).ifPresent(this::changed); } }\n",
                encoding="utf-8",
            )
            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])

        self.assertIn("com.acme.Use.changed(String)", graph_result["graph"].reverse_edges)

    def test_source_graph_keeps_anonymous_inner_class_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "Target.java").write_text(
                "package com.acme;\nclass Target { static void changed() {} }\n",
                encoding="utf-8",
            )
            (source_root / "Use.java").write_text(
                "package com.acme;\nclass Use { void run() { Runnable task = new Runnable() { "
                "public void run() { Target.changed(); } }; task.run(); } }\n",
                encoding="utf-8",
            )
            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])

        self.assertIn("com.acme.Target.changed()", graph_result["graph"].reverse_edges)

    def test_source_graph_keeps_explicit_this_and_super_constructor_delegation(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "Base.java").write_text(
                "package com.acme;\nclass Base { Base(String value) {} }\n",
                encoding="utf-8",
            )
            (source_root / "Child.java").write_text(
                "package com.acme;\nclass Child extends Base { "
                "Child() { super(\"value\"); } Child(int ignored) { this(); } }\n",
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])
            graph = graph_result["graph"]

        self.assertIn("com.acme.Base.Base(String)", graph.reverse_edges)
        self.assertIn("com.acme.Child.Child()", graph.reverse_edges)

    def test_source_graph_normalizes_constructor_method_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "Target.java").write_text(
                "package com.acme;\nclass Target { Target() {} }\n", encoding="utf-8"
            )
            (source_root / "Use.java").write_text(
                "package com.acme;\nimport java.util.function.Supplier; "
                "class Use { Supplier<Target> create() { return Target::new; } }\n",
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])

        self.assertIn("com.acme.Target.Target()", graph_result["graph"].reverse_edges)

    def test_source_graph_resolves_outer_this_to_enclosing_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "Outer.java").write_text(
                "package com.acme;\nclass Outer { void target() {} "
                "class Inner { void run() { Outer.this.target(); } } }\n",
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_root.parent.parent.parent),
                "owner_type": "business", "owner_coord": "BUSINESS", "module": "app",
            }])

        self.assertIn("com.acme.Outer.target()", graph_result["graph"].reverse_edges)
    def test_exact_business_bytecode_call_beats_missing_runtime_dependency_jars(self):
        api_row = {
            "coord": "cn.hutool:hutool-all",
            "api_name": "cn.hutool.jwt.JWT.getPayloads",
            "api_simple": "getPayloads",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "severity": "P1",
            "confirmed": "true",
        }
        method = SimpleNamespace(
            symbol_id="business",
            qualified_key="app.JwtService.read",
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            file="JwtService.java",
            line=10,
            annotations=[],
            class_annotations=[],
            class_name="JwtService",
            class_fqcn="app.JwtService",
            modifiers=["public"],
        )
        edge = SimpleNamespace(
            caller_symbol_id="business",
            caller_qualified_key=method.qualified_key,
            callee_key="cn.hutool.jwt.JWT.getPayloads()",
            callee_simple_key="method:getPayloads()",
            confidence="high",
            evidence_type="bytecode_method_invocation",
            evidence_source="current_final_artifact",
            artifact_sha256="fixture-sha256",
            file="app.jar!/app/JwtService.class",
            line=20,
            owner_type="business",
            owner_coord="BUSINESS",
            module="app",
            is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"business": method},
            reverse_edges={"cn.hutool.jwt.JWT.getPayloads()": [edge]},
            runtime_dependency_catalog={},
            changed_api_overload_signatures={},
            framework_runtime_entry_methods={},
        )

        result = tracer.trace_api_with_confidence_weighting(
            api_row,
            graph,
            {},
            needs_bridge=True,
            has_dependency_source_mapping=False,
            has_packaged_bytecode_fallback=True,
            allow_degraded=True,
        )

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")
        self.assertIn("bytecode_method_invocation", str(result.evidence_paths))

    def test_target_classes_bytecode_cannot_beat_missing_final_artifact(self):
        api_row = {
            "coord": "g:a", "api_name": "dep.Api.call", "api_simple": "call",
            "api_signature": "()", "symbol_kind": "method", "change_type": "REMOVED",
            "severity": "P1", "confirmed": "true",
        }
        edge = SimpleNamespace(
            caller_symbol_id="business", caller_qualified_key="app.Service.run",
            callee_key="dep.Api.call()", callee_simple_key="method:call()",
            confidence="high", evidence_type="bytecode_method_invocation",
            evidence_source="build_directory_fallback", artifact_sha256="",
            file="target/classes/app/Service.class", line=1, owner_type="business",
            owner_coord="BUSINESS", module="app", is_test=False,
        )
        method = SimpleNamespace(
            symbol_id="business", qualified_key="app.Service.run", owner_type="business",
            owner_coord="BUSINESS", is_test=False, file="Service.java", line=1,
            annotations=[], class_annotations=[], class_name="Service",
            class_fqcn="app.Service", modifiers=["public"],
        )
        graph = SimpleNamespace(
            methods_by_id={"business": method}, reverse_edges={"dep.Api.call()": [edge]},
            runtime_dependency_catalog={}, changed_api_overload_signatures={},
            framework_runtime_entry_methods={},
        )

        result = tracer.trace_api_with_confidence_weighting(
            api_row, graph, {}, needs_bridge=True, has_dependency_source_mapping=False,
            has_packaged_bytecode_fallback=True, allow_degraded=True,
        )

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "RUNTIME_DEPENDENCY_JARS_UNAVAILABLE")

    def _call_chain_dir(self, report_dir):
        return Path(report_dir) / "evidence" / "call_chain"

    def _api_changes_dir(self, report_dir):
        return Path(report_dir) / "evidence" / "api_changes"

    def _dependencies_dir(self, report_dir):
        return Path(report_dir) / "evidence" / "dependencies"

    def _runtime_cache_dir(self, report_dir):
        return Path(report_dir) / ".runtime" / "cache"

    def _write_text(self, path, text, **kwargs):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path.write_text(text, **kwargs)

    def test_changed_dependencies_markdown_is_a_reviewable_selection_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "api_changes"
            rows = [
                {
                    "coord": "com.acme:alpha",
                    "api_name": "com.acme.Alpha.removed",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "severity": "P1",
                },
                {
                    "coord": "com.acme:beta",
                    "api_name": "com.acme.Beta.changed",
                    "symbol_kind": "class",
                    "change_type": "MODIFIED",
                    "severity": "P3",
                },
            ]

            s4_jar_compare.write_changed_dependencies(rows, output_dir)
            md_text = (output_dir / "changed_dependencies.md").read_text(encoding="utf-8")

        self.assertIn("展示 2 / 2 个依赖包", md_text)
        self.assertIn("## 如何选择定向分析范围", md_text)
        self.assertIn("复制“依赖包”列中的完整坐标", md_text)
        self.assertIn("完整 API 明细：`all_changed_apis.csv`", md_text)
        self.assertIn("依赖包明细目录：`s4_per_dependency/`", md_text)
        self.assertIn("| 部分分析优先项 | 依赖包 | 变化 API 数 | 高风险 API 数 | 为什么先看 | 主要变化类型 | 明细 |", md_text)
        self.assertIn("含高风险 API，优先做系统触达分析", md_text)

    def test_alerts_generation_does_not_write_low_value_summary_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "alerts.csv"
            results = [
                tracer.TraceResult(
                    coord="a:b",
                    api_name="com.acme.Api.reachable",
                    api_simple="reachable",
                    api_signature="()",
                    symbol_kind="method",
                    change_type="METHOD_CHANGED",
                    severity="P1",
                    confirmed=True,
                    source="japicmp",
                    analysis_scope="method",
                    analysis_status="reachable",
                    direct_callers=1,
                    is_reachable=True,
                    reachable_note="业务入口命中",
                    business_reach_depth=1,
                    dependency_chain_coords=[],
                    call_paths=["Service.run -> Api.reachable"],
                    evidence_paths=[],
                    reason_code="SYSTEM_CODE_REACHED",
                    verification_commands=[],
                    hops=[],
                    confidence_score=1.0,
                    critical_nodes_hit=[],
                ),
                tracer.TraceResult(
                    coord="a:b",
                    api_name="com.acme.Api.uncertain",
                    api_simple="uncertain",
                    api_signature="()",
                    symbol_kind="method",
                    change_type="METHOD_CHANGED",
                    severity="P1",
                    confirmed=True,
                    source="japicmp",
                    analysis_scope="method",
                    analysis_status="uncertain",
                    direct_callers=0,
                    is_reachable=None,
                    reachable_note="依赖字节码命中",
                    business_reach_depth=0,
                    dependency_chain_coords=["a:consumer"],
                    call_paths=[],
                    evidence_paths=[],
                    reason_code="RUNTIME_DEPENDENCY_USES_REMOVED_API",
                    verification_commands=[],
                    hops=[],
                    confidence_score=1.0,
                    critical_nodes_hit=[],
                ),
            ]

            formatter.generate_alerts_csv(results, output)
            summary_exists = (Path(tmp) / "summary.md").exists()

        self.assertFalse(summary_exists)

    def test_step5_blocks_as_system_error_before_regex_degrade_when_tree_sitter_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            output_dir = self._call_chain_dir(report_dir)
            source_dir = Path(tmp) / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            (source_dir / "Demo.java").write_text(
                "package demo; public class Demo { public void run() {} }\n",
                encoding="utf-8",
            )
            args = SimpleNamespace(
                report_dir=str(report_dir),
                output_dir=str(output_dir),
                all_changed_apis="",
                source_dirs=[str(source_dir)],
                dependency_source_mappings=[],
                # The production contract must ignore this stale/manual bypass
                # and still stop until tree-sitter is available.
                allow_degraded=True,
                jdk_scan_dir="",
                max_depth=5,
                max_methods=None,
                debug_analysis=False,
                debug_break=False,
            )
            stdout = io.StringIO()
            stderr = io.StringIO()

            with patch.object(step5, "ensure_tree_sitter_available", return_value=False), patch.object(
                step5,
                "tree_sitter_status",
                return_value={
                    "available": False,
                    "auto_install_attempted": True,
                    "auto_install_error": "pip_returncode=1",
                    "install_command": "python -m pip install tree-sitter tree-sitter-java",
                    "python_executable": "python",
                },
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                rc = step5.step5_integrated_main(args)

            self.assertEqual(rc, 1)
            self.assertNotIn(step5.STEP_INTERACTION_PREFIX, stdout.getvalue())
            self.assertIn("系统环境阻塞", stderr.getvalue())
            preflight_path = output_dir / "tree_sitter_preflight.json"
            self.assertTrue(preflight_path.exists())
            preflight = json.loads(preflight_path.read_text(encoding="utf-8"))
            self.assertEqual(
                preflight["reason_code"],
                "STEP5_TREE_SITTER_MISSING_NEED_RESOLUTION",
            )
            self.assertEqual(
                preflight["reason_code_aliases"],
                ["step5_tree_sitter_missing_need_resolution"],
            )
            self.assertEqual(preflight["origin_step"], "step5")

    def _compile_java_fixture(self, tmp, relative_path, source):
        if not shutil.which("javac"):
            self.skipTest("javac is required for this bytecode fixture")
        src_root = Path(tmp) / "src"
        classes_root = Path(tmp) / "classes"
        java_file = src_root / relative_path
        java_file.parent.mkdir(parents=True, exist_ok=True)
        classes_root.mkdir(parents=True, exist_ok=True)
        java_file.write_text(source, encoding="utf-8")
        result = subprocess.run(
            ["javac", "-d", str(classes_root), str(java_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            self.fail(f"javac failed: {result.stderr}")
        return classes_root

    def _jar_compiled_classes(self, jar_path, classes_root):
        with zipfile.ZipFile(jar_path, "w") as zf:
            for class_file in Path(classes_root).rglob("*.class"):
                zf.write(class_file, class_file.relative_to(classes_root).as_posix())

    def _compile_java_files(self, output_dir, java_files, classpath=None):
        if not shutil.which("javac"):
            self.skipTest("javac is required for this bytecode fixture")
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        command = ["javac"]
        if classpath:
            command.extend(["-cp", str(classpath)])
        command.extend(["-d", str(output_dir)])
        command.extend(str(item) for item in java_files)
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            self.fail(f"javac failed: {result.stderr}")
        return output_dir

    def _runtime_catalog(self, entries):
        return {
            "status": "complete",
            "by_coord": {
                coord: {
                    "coord": coord,
                    "version": "1",
                    "scope": "compile",
                    "jar_path": str(jar_path),
                }
                for coord, jar_path in entries
            },
        }

    def test_runtime_catalog_uses_only_boot_application_classpath(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / "report"
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("app/App.class", b"root-copy")
                archive.writestr("BOOT-INF/classes/app/App.class", b"runtime-copy")
            artifact_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self._write_text(
                self._dependencies_dir(report_dir) / "deps_current_resolved.csv",
                "coord,version,scope,lib_entry,resolution_status\n",
                encoding="utf-8",
            )
            self._write_text(
                self._dependencies_dir(report_dir) / "build_provenance.json",
                json.dumps({"sides": [{
                    "side": "current",
                    "artifact_path": str(artifact),
                    "artifact_sha256": artifact_sha256,
                }]}),
                encoding="utf-8",
            )
            retain_current_artifact_contract(report_dir, artifact)

            catalog = step5.build_runtime_dependency_catalog(report_dir)
            with zipfile.ZipFile(catalog["by_coord"]["__business__"]["jar_path"]) as business_jar:
                class_entries = [name for name in business_jar.namelist() if name.endswith(".class")]

        self.assertEqual(class_entries, ["app/App.class"])

    def test_runtime_catalog_business_jar_is_byte_deterministic_across_build_times(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / "report"
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/classes/app/App.class", b"runtime-copy")
            artifact_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self._write_text(
                self._dependencies_dir(report_dir) / "deps_current_resolved.csv",
                "coord,version,scope,lib_entry,resolution_status\n",
                encoding="utf-8",
            )
            self._write_text(
                self._dependencies_dir(report_dir) / "build_provenance.json",
                json.dumps({"sides": [{
                    "side": "current",
                    "artifact_path": str(artifact),
                    "artifact_sha256": artifact_sha256,
                }]}),
                encoding="utf-8",
            )

            with patch("zipfile.time.localtime", return_value=(2020, 1, 2, 3, 4, 6, 0, 0, -1)):
                retain_current_artifact_contract(report_dir, artifact)
                first = step5.build_runtime_dependency_catalog(report_dir)
            first_sha = first["by_coord"]["__business__"]["sha256"]
            second_report_dir = root / "report-second"
            self._write_text(
                self._dependencies_dir(second_report_dir) / "deps_current_resolved.csv",
                "coord,version,scope,lib_entry,resolution_status\n",
                encoding="utf-8",
            )
            with patch("zipfile.time.localtime", return_value=(2025, 6, 7, 8, 9, 10, 0, 0, -1)):
                retain_current_artifact_contract(second_report_dir, artifact)
                second = step5.build_runtime_dependency_catalog(second_report_dir)
            second_sha = second["by_coord"]["__business__"]["sha256"]

        self.assertEqual(first_sha, second_sha)

    def test_runtime_catalog_does_not_infer_internal_module_from_group_id(self):
        def nested_jar(group_id, artifact_id):
            payload = io.BytesIO()
            with zipfile.ZipFile(payload, "w") as archive:
                archive.writestr(
                    f"META-INF/maven/{group_id}/{artifact_id}/pom.properties",
                    f"groupId={group_id}\nartifactId={artifact_id}\nversion=1.0-SNAPSHOT\n",
                )
                archive.writestr(
                    artifact_id.replace("-", "/") + "/Module.class", b"class"
                )
            return payload.getvalue()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / "report"
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "META-INF/maven/com.acme/application/pom.properties",
                    "groupId=com.acme\nartifactId=application\nversion=1.0-SNAPSHOT\n",
                )
                archive.writestr("BOOT-INF/classes/app/App.class", b"class")
                archive.writestr(
                    "BOOT-INF/lib/library-1.0-SNAPSHOT.jar",
                    nested_jar("com.acme", "library"),
                )
                archive.writestr(
                    "BOOT-INF/lib/external-1.0.jar",
                    nested_jar("org.external", "external"),
                )
            artifact_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self._write_text(
                self._dependencies_dir(report_dir) / "deps_current_resolved.csv",
                "coord,version,scope,lib_entry,resolution_status\n"
                "com.acme:library,1.0-SNAPSHOT,runtime,"
                "BOOT-INF/lib/library-1.0-SNAPSHOT.jar,resolved\n",
                encoding="utf-8",
            )
            self._write_text(
                self._dependencies_dir(report_dir) / "build_provenance.json",
                json.dumps({"sides": [{
                    "side": "current", "artifact_path": str(artifact),
                    "artifact_sha256": artifact_sha256,
                }]}),
                encoding="utf-8",
            )
            retain_current_artifact_contract(report_dir, artifact)

            catalog = step5.build_runtime_dependency_catalog(report_dir)

        self.assertIn("com.acme:library", catalog["by_coord"])
        self.assertFalse(catalog["by_coord"]["com.acme:library"]["application_owned"])
        self.assertNotIn("ownership_evidence", catalog["by_coord"]["com.acme:library"])
        self.assertNotIn("org.external:external", catalog["by_coord"])
        self.assertEqual(catalog["metrics"]["application_owned_nested_dependencies"], 0)

    def _graph_with_business_edge(self, catalog, callee_key, root):
        business_method = SimpleNamespace(
            symbol_id="app_run",
            qualified_key="com.app.App.run",
            owner_type="business",
            owner_coord="__business__",
            is_test=False,
        )
        business_edge = source_analyzer.CallEdge(
            caller_symbol_id="app_run",
            caller_qualified_key="com.app.App.run",
            callee_key=callee_key,
            callee_simple_key=f"method:{callee_key.rsplit('.', 1)[-1]}",
            evidence_type="bytecode_method_invocation",
            confidence="high",
            file=str(Path(root) / "app.jar"),
            line=0,
            content="business bytecode calls runtime dependency",
            owner_type="business",
            owner_coord="__business__",
            module="app",
            is_test=False,
        )
        return SimpleNamespace(
            methods_by_id={"app_run": business_method},
            reverse_edges={callee_key: [business_edge]},
            runtime_dependency_catalog=catalog,
        )

    def _trace_packaged_fixture(self, api_row, graph):
        return tracer.trace_api_with_confidence_weighting(
            api_row,
            graph,
            {},
            max_total_cost=5,
            needs_bridge=True,
            has_dependency_source_mapping=False,
            has_packaged_bytecode_fallback=True,
            allow_degraded=True,
        )

    def _same_coordinate_bytecode_fixture(self, tmp, include_executable_call=True):
        src = Path(tmp) / "src"
        target = src / "com/vendor/Target.java"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            "package com.vendor; public class Target { "
            "public static String removed(String value) { return value; } }",
            encoding="utf-8",
        )
        java_files = [target]
        if include_executable_call:
            bridge = src / "com/vendor/InternalBridge.java"
            bridge.write_text(
                "package com.vendor; public class InternalBridge { "
                "public String use(String value) { return Target.removed(value); } }",
                encoding="utf-8",
            )
            java_files.append(bridge)
        classes = self._compile_java_files(Path(tmp) / "classes", java_files)
        jar_path = Path(tmp) / "target.jar"
        self._jar_compiled_classes(jar_path, classes)
        api_row = {
            "coord": "com.vendor:target",
            "api_name": "com.vendor.Target.removed",
            "api_simple": "removed",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
            "severity": "P1",
            "confirmed": "true",
        }
        return api_row, jar_path

    def _same_class_bridge_fixture(self, tmp):
        src = Path(tmp) / "src"
        target = src / "com/vendor/Target.java"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            "package com.vendor; public class Target { "
            "public static String changed(String value) { return value; } "
            "public static String entry(String value) { return changed(value); } }",
            encoding="utf-8",
        )
        classes = self._compile_java_files(Path(tmp) / "classes", [target])
        jar_path = Path(tmp) / "target.jar"
        self._jar_compiled_classes(jar_path, classes)
        return {
            "coord": "com.vendor:target",
            "api_name": "com.vendor.Target.changed",
            "api_simple": "changed",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
            "severity": "P1",
            "confirmed": "true",
        }, jar_path

    def _same_class_overloaded_bridge_fixture(self, tmp):
        src = Path(tmp) / "src"
        foo = src / "com/foo/Request.java"
        bar = src / "com/bar/Request.java"
        target = src / "com/vendor/Target.java"
        foo.parent.mkdir(parents=True, exist_ok=True)
        bar.parent.mkdir(parents=True, exist_ok=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        foo.write_text("package com.foo; public class Request {}", encoding="utf-8")
        bar.write_text("package com.bar; public class Request {}", encoding="utf-8")
        target.write_text(
            "package com.vendor; public class Target { "
            "public static Object changed(com.foo.Request value) { "
            "return changed(new com.bar.Request()); } "
            "public static Object changed(com.bar.Request value) { return value; } }",
            encoding="utf-8",
        )
        classes = self._compile_java_files(
            Path(tmp) / "classes", [foo, bar, target]
        )
        jar_path = Path(tmp) / "target.jar"
        self._jar_compiled_classes(jar_path, classes)
        return {
            "coord": "com.vendor:target",
            "api_name": "com.vendor.Target.changed",
            "api_simple": "changed",
            "api_signature": "(com.bar.Request)",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
            "severity": "P1",
            "confirmed": "true",
        }, jar_path

    def test_same_class_different_method_bridge_is_kept_by_single_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_class_bridge_fixture(tmp)
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={"force_single_scan": []},
                runtime_dependency_catalog=self._runtime_catalog(((api_row["coord"], jar_path),)),
            )

            with patch.object(
                tracer, "_build_packaged_runtime_dependency_scan_cache",
                return_value={},
            ):
                scan = tracer._scan_packaged_runtime_dependencies_for_api(
                    api_row, graph
                )

        self.assertEqual(scan["status"], "hit")
        self.assertTrue(any(
            hit["class_fqcn"] == "com.vendor.Target"
            and hit["consumer_method"] == "entry"
            for hit in scan["hits"]
        ))

    def test_same_class_different_method_bridge_is_kept_by_batch_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_class_bridge_fixture(tmp)
            graph = SimpleNamespace(
                methods_by_id={}, reverse_edges={},
                runtime_dependency_catalog=self._runtime_catalog(((api_row["coord"], jar_path),)),
            )

            scans = tracer._build_packaged_runtime_dependency_scan_cache(
                [api_row], graph
            )

        scan = scans[tracer.build_api_identity_key(api_row)]
        self.assertEqual(scan["status"], "hit")
        self.assertTrue(any(
            hit["class_fqcn"] == "com.vendor.Target"
            and hit["consumer_method"] == "entry"
            for hit in scan["hits"]
        ))

    def test_same_class_same_named_overload_with_different_fqcn_is_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_class_overloaded_bridge_fixture(tmp)
            graph = SimpleNamespace(
                methods_by_id={}, reverse_edges={},
                runtime_dependency_catalog=self._runtime_catalog(((api_row["coord"], jar_path),)),
            )

            scans = tracer._build_packaged_runtime_dependency_scan_cache(
                [api_row], graph
            )

        scan = scans[tracer.build_api_identity_key(api_row)]
        self.assertEqual(scan["status"], "hit")
        self.assertTrue(any(
            hit["consumer_descriptor"].startswith("(Lcom/foo/Request;)")
            and hit["callee_descriptor"].startswith("(Lcom/bar/Request;)")
            for hit in scan["hits"]
        ))

    def test_same_class_different_method_bridge_is_kept_by_runtime_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_class_bridge_fixture(tmp)
            catalog = self._runtime_catalog(((api_row["coord"], jar_path),))
            catalog["by_coord"][api_row["coord"]]["application_owned"] = False
            graph = SimpleNamespace(
                methods_by_id={}, reverse_edges={}, runtime_dependency_catalog=catalog,
            )

            expansion = tracer._ensure_runtime_dependency_callers_for_key(
                graph,
                "com.vendor.Target.changed(String)",
                excluded_provider_coord=api_row["coord"],
                excluded_self_owner="com.vendor.Target",
            )

        self.assertEqual(expansion["edges_added"], 1)
        self.assertTrue(any(
            "com.vendor.Target.entry" in edge.caller_qualified_key
            for edges in graph.reverse_edges.values()
            for edge in edges
        ))

    def test_runtime_closure_does_not_delete_preexisting_shared_graph_edges(self):
        preserved = SimpleNamespace(
            caller_qualified_key="com.vendor.Target.entry()",
            runtime_analyzer_hit=None,
        )
        graph = SimpleNamespace(
            methods_by_id={},
            reverse_edges={"com.vendor.Other.call()": [preserved]},
            reverse_edge_count=1,
            runtime_dependency_catalog={"status": "complete", "by_coord": {}},
        )

        tracer._ensure_runtime_dependency_callers_for_key(
            graph,
            "com.vendor.Target.changed(String)",
            excluded_self_owner="com.vendor.Target",
        )

        self.assertEqual(
            graph.reverse_edges["com.vendor.Other.call()"], [preserved]
        )
        self.assertEqual(graph.reverse_edge_count, 1)

    def test_same_coordinate_single_scan_retains_internal_bridge(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_coordinate_bytecode_fixture(tmp)
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={"force_javap_path": []},
                runtime_dependency_catalog=self._runtime_catalog(((api_row["coord"], jar_path),)),
            )

            with patch.object(tracer, "_build_packaged_runtime_dependency_scan_cache", return_value={}):
                scan = tracer._scan_packaged_runtime_dependencies_for_api(api_row, graph)

        self.assertEqual(scan["status"], "hit")
        bridge = next(hit for hit in scan["hits"] if hit["class_fqcn"] == "com.vendor.InternalBridge")
        self.assertEqual(bridge["edge_role"], "internal_bridge")
        self.assertFalse(bridge["direct_consumer"])

    def test_same_coordinate_batch_fast_path_retains_internal_bridge(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_coordinate_bytecode_fixture(tmp)
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog=self._runtime_catalog(((api_row["coord"], jar_path),)),
            )

            scans = tracer._build_packaged_runtime_dependency_scan_cache([api_row], graph)

        scan = scans[tracer.build_api_identity_key(api_row)]
        self.assertEqual(scan["status"], "hit")
        bridge = next(hit for hit in scan["hits"] if hit["class_fqcn"] == "com.vendor.InternalBridge")
        self.assertEqual(bridge["edge_role"], "internal_bridge")
        self.assertFalse(bridge["direct_consumer"])

    def test_member_index_batch_keeps_external_provider_same_coord_candidates(self):
        api_row = {
            "coord": "com.vendor:target",
            "api_name": "com.vendor.Target.removed",
            "api_simple": "removed",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
        }
        task = {
            "coord": api_row["coord"],
            "application_owned": False,
            "class_binary_name": "com.vendor.InternalBridge",
        }
        index = {
            "complete": True,
            "tasks": [task],
            "unparsed_tasks": [],
            "direct_by_owner_member": {("com.vendor.Target", "removed"): {0}},
            "direct_by_owner": {},
            "owner_string_ids": {},
            "member_string_ids": {},
            "reflection_ids": set(),
        }

        candidates = tracer._batch_candidates_from_runtime_member_index(
            index, {"com.vendor.Target": [api_row]},
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["candidate_owners"], ["com.vendor.Target"])

    def test_same_coordinate_external_provider_retains_other_class_internal_bridge(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_coordinate_bytecode_fixture(tmp)
            catalog = self._runtime_catalog(((api_row["coord"], jar_path),))
            catalog["by_coord"][api_row["coord"]]["application_owned"] = False
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog=catalog,
            )

            scans = tracer._build_packaged_runtime_dependency_scan_cache([api_row], graph)

        scan = scans[tracer.build_api_identity_key(api_row)]
        self.assertEqual(scan["status"], "hit")
        bridge = next(
            hit for hit in scan["hits"]
            if hit["class_fqcn"] == "com.vendor.InternalBridge"
        )
        self.assertEqual(bridge["edge_role"], "internal_bridge")
        self.assertFalse(bridge["direct_consumer"])
        self.assertFalse(any(
            hit["class_fqcn"] == "com.vendor.Target"
            for hit in scan["hits"]
        ))

    def test_duplicate_external_class_providers_are_not_consumers_of_each_other(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_coordinate_bytecode_fixture(tmp)
            catalog = self._runtime_catalog((
                ("com.vendor:target", jar_path),
                ("com.vendor:target-alias", jar_path),
            ))
            for item in catalog["by_coord"].values():
                item["application_owned"] = False
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog=catalog,
            )

            scans = tracer._build_packaged_runtime_dependency_scan_cache(
                [api_row], graph
            )

        scan = scans[tracer.build_api_identity_key(api_row)]
        self.assertTrue(scan.get("hits"))
        self.assertEqual(
            {hit["class_fqcn"] for hit in scan["hits"]},
            {"com.vendor.InternalBridge"},
        )
        self.assertEqual(
            {hit["coord"] for hit in scan["hits"]},
            {"com.vendor:target", "com.vendor:target-alias"},
        )

    def test_runtime_closure_expands_other_classes_in_external_target_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_coordinate_bytecode_fixture(tmp)
            catalog = self._runtime_catalog(((api_row["coord"], jar_path),))
            catalog["by_coord"][api_row["coord"]]["application_owned"] = False
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog=catalog,
            )

            expansion = tracer._ensure_runtime_dependency_callers_for_key(
                graph,
                "com.vendor.Target.removed(String)",
                excluded_provider_coord=api_row["coord"],
                excluded_self_owner="com.vendor.Target",
            )

        self.assertEqual(expansion["edges_added"], 1)
        callers = [
            edge.caller_qualified_key
            for edges in graph.reverse_edges.values()
            for edge in edges
        ]
        self.assertTrue(any("com.vendor.InternalBridge.use" in item for item in callers))
        self.assertFalse(any("com.vendor.Target.removed" in item for item in callers))

    def test_runtime_closure_never_materializes_target_self_recursion(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_coordinate_bytecode_fixture(tmp)
            catalog = self._runtime_catalog(((api_row["coord"], jar_path),))
            catalog["by_coord"][api_row["coord"]]["application_owned"] = False
            graph = SimpleNamespace(
                methods_by_id={}, reverse_edges={}, runtime_dependency_catalog=catalog,
            )

            first_expansion = tracer._ensure_runtime_dependency_callers_for_key(
                graph, "com.vendor.Target.removed(String)"
            )
            second_expansion = tracer._ensure_runtime_dependency_callers_for_key(
                graph,
                "com.vendor.Target.removed(String)",
                excluded_provider_coord=api_row["coord"],
                excluded_self_owner="com.vendor.Target",
            )

        self.assertTrue(first_expansion["expanded"])
        self.assertFalse(second_expansion["expanded"])
        callers = [
            edge.caller_qualified_key
            for edges in graph.reverse_edges.values()
            for edge in edges
        ]
        self.assertTrue(any("com.vendor.InternalBridge.use" in item for item in callers))
        self.assertFalse(any("com.vendor.Target.removed" in item for item in callers))

    def test_same_coordinate_batch_javap_retains_internal_bridge(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_coordinate_bytecode_fixture(tmp)
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={"force_javap_path": []},
                runtime_dependency_catalog=self._runtime_catalog(((api_row["coord"], jar_path),)),
            )

            scans = tracer._build_packaged_runtime_dependency_scan_cache([api_row], graph)

        scan = scans[tracer.build_api_identity_key(api_row)]
        self.assertEqual(scan["status"], "hit")
        bridge = next(hit for hit in scan["hits"] if hit["class_fqcn"] == "com.vendor.InternalBridge")
        self.assertEqual(bridge["edge_role"], "internal_bridge")
        self.assertFalse(bridge["direct_consumer"])

    def test_external_provider_retains_outer_class_call_to_nested_target_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            source = src / "org/example/Container.java"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(
                "package org.example; public class Container { "
                "public static class Nested { public String removed() { return null; } } "
                "public String bridge(Nested value) { return value.removed(); } }",
                encoding="utf-8",
            )
            classes = self._compile_java_files(Path(tmp) / "classes", [source])
            jar_path = Path(tmp) / "target.jar"
            self._jar_compiled_classes(jar_path, classes)
            api_row = {
                "coord": "org.example:target",
                "api_name": "org.example.Container.Nested.removed",
                "api_simple": "removed",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
                "severity": "P1",
                "confirmed": "true",
            }
            catalog = self._runtime_catalog(((api_row["coord"], jar_path),))
            catalog["by_coord"][api_row["coord"]]["application_owned"] = False
            graph = SimpleNamespace(
                methods_by_id={}, reverse_edges={}, runtime_dependency_catalog=catalog,
            )

            scans = tracer._build_packaged_runtime_dependency_scan_cache([api_row], graph)

        scan = scans[tracer.build_api_identity_key(api_row)]
        self.assertEqual(scan["status"], "hit")
        self.assertEqual(
            {hit["class_fqcn"] for hit in scan["hits"]},
            {"org.example.Container"},
        )

    def test_light_expansion_reuses_batch_classfile_parse_for_same_physical_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_coordinate_bytecode_fixture(tmp)
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog=self._runtime_catalog(((api_row["coord"], jar_path),)),
            )
            tracer.clear_immutable_artifact_parse_cache()

            tracer._build_packaged_runtime_dependency_scan_cache([api_row], graph)
            with patch.object(tracer, "run_cmd", side_effect=AssertionError("javap must be cached")):
                tracer._ensure_runtime_dependency_callers_for_key(
                    graph, "com.vendor.InternalBridge.use(java.lang.String)"
                )
            perf = tracer._finalize_step5_perf_stats(graph)["bytecode_scan"]

        self.assertEqual(perf["duplicate_class_scans"], 0)

    def test_packaged_executable_scan_records_exact_ledger_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_coordinate_bytecode_fixture(tmp)
            report_dir = Path(tmp) / "report"
            artifact = Path(tmp) / "application.jar"
            with zipfile.ZipFile(artifact, "w") as zf:
                zf.writestr("BOOT-INF/lib/target.jar", jar_path.read_bytes())
            artifact_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
            retained_sha256 = hashlib.sha256(jar_path.read_bytes()).hexdigest()
            self._write_text(
                report_dir / "evidence" / "dependencies" / "build_provenance.json",
                json.dumps({
                    "sides": [{
                        "side": "current",
                        "artifact_path": str(artifact),
                        "artifact_sha256": artifact_sha256,
                    }]
                }),
                encoding="utf-8",
            )
            graph = SimpleNamespace(
                report_dir=str(report_dir),
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "status": "complete",
                    "entries": [{
                        "coord": api_row["coord"],
                        "jar_path": str(jar_path),
                        "artifact_entry": "BOOT-INF/lib/target.jar",
                        "sha256": retained_sha256,
                        "evidence_source": "current_final_artifact",
                    }],
                    "by_coord": {
                        api_row["coord"]: {
                            "coord": api_row["coord"],
                            "jar_path": str(jar_path),
                            "artifact_entry": "BOOT-INF/lib/target.jar",
                            "sha256": retained_sha256,
                            "evidence_source": "current_final_artifact",
                        }
                    },
                },
            )

            tracer._build_packaged_runtime_dependency_scan_cache([api_row], graph)
            graph_stats = {}
            ledger_path = tracer.write_analyzer_edge_ledger(graph, graph_stats=graph_stats)
            with Path(ledger_path).open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))

        bridge = next(row for row in rows if row["caller_owner"] == "com.vendor.InternalBridge")
        self.assertEqual(bridge["artifact_sha256"], retained_sha256)
        self.assertEqual(
            bridge["artifact_entry"],
            "BOOT-INF/lib/target.jar!/com/vendor/InternalBridge.class",
        )
        self.assertEqual(bridge["caller_member"], "use")
        self.assertEqual(
            bridge["caller_descriptor"],
            "(Ljava/lang/String;)Ljava/lang/String;",
        )
        self.assertEqual(bridge["callee_owner"], "com.vendor.Target")
        self.assertEqual(bridge["callee_member"], "removed")
        self.assertEqual(
            bridge["callee_descriptor"],
            "(Ljava/lang/String;)Ljava/lang/String;",
        )
        self.assertEqual(bridge["opcode_family"], "invokestatic")
        self.assertTrue(bridge["instruction_offset"].isdigit())
        self.assertTrue(graph_stats["edge_ledger_complete"])

    def test_target_runtime_closure_records_every_internal_bridge_for_original_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src" / "com" / "vendor"
            src.mkdir(parents=True)
            sources = {
                "Adapter.java": (
                    "package com.vendor; interface Adapter<T> { Object unmarshal(T value); }"
                ),
                "Types.java": (
                    "package com.vendor; class Types { static class RequestDto { "
                    "final String value; RequestDto(String value) { this.value = value; } } }"
                ),
                "Target.java": (
                    "package com.vendor; public class Target { "
                    "public static String removed(String value) { return value; } }"
                ),
                "InternalBridge.java": (
                    "package com.vendor; public class InternalBridge "
                    "implements Adapter<Types.RequestDto> { "
                    "public String use(String value) { return Target.removed(value); } "
                    "public Object unmarshal(Types.RequestDto value) { "
                    "return use(value.value); } }"
                ),
                "OuterBridge.java": (
                    "package com.vendor; public class OuterBridge { "
                    "public String invoke(String value) { "
                    "return new InternalBridge().use(value); } }"
                ),
            }
            java_files = []
            for name, source in sources.items():
                path = src / name
                path.write_text(source, encoding="utf-8")
                java_files.append(path)
            classes = self._compile_java_files(root / "classes", java_files)
            runtime_jar = root / "target.jar"
            self._jar_compiled_classes(runtime_jar, classes)
            application_source = root / "business-src" / "app" / "Application.java"
            application_source.parent.mkdir(parents=True)
            application_source.write_text(
                "package app; public class Application { public String run(String value) { "
                "return new com.vendor.OuterBridge().invoke(value); } }",
                encoding="utf-8",
            )
            business_classes = self._compile_java_files(
                root / "business-classes", [application_source], classpath=runtime_jar
            )
            business_jar = root / "business.jar"
            self._jar_compiled_classes(business_jar, business_classes)
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/lib/target.jar", runtime_jar.read_bytes())
                archive.write(
                    business_classes / "app" / "Application.class",
                    "BOOT-INF/classes/app/Application.class",
                )
            report_dir = root / "report"
            self._write_text(
                report_dir / "evidence" / "dependencies" / "build_provenance.json",
                json.dumps({"sides": [{
                    "side": "current",
                    "artifact_path": str(artifact),
                    "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }]}),
                encoding="utf-8",
            )
            api_row = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.removed",
                "api_simple": "removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
            }
            item = {
                "coord": api_row["coord"],
                "jar_path": str(runtime_jar),
                "artifact_entry": "BOOT-INF/lib/target.jar",
                "sha256": hashlib.sha256(runtime_jar.read_bytes()).hexdigest(),
                "evidence_source": "current_final_artifact",
            }
            business_item = {
                "coord": "__business__",
                "jar_path": str(business_jar),
                "artifact_entry": "<business-classes>",
                "sha256": hashlib.sha256(business_jar.read_bytes()).hexdigest(),
                "evidence_source": "current_final_artifact",
            }
            application_method = SimpleNamespace(
                symbol_id="application_run",
                qualified_key="app.Application.run(java.lang.String)",
                class_fqcn="app.Application",
                method_name="run",
                owner_type="business",
                owner_coord="__business__",
                module="app",
                is_test=False,
            )
            graph = SimpleNamespace(
                report_dir=str(report_dir),
                methods_by_id={application_method.symbol_id: application_method},
                methods_by_qualified={
                    "app.Application.run": [application_method.symbol_id]
                },
                lookup_keys_by_symbol={application_method.symbol_id: [
                    application_method.qualified_key
                ]},
                reverse_edges={},
                runtime_dependency_catalog={
                    "status": "complete",
                    "entries": [item, business_item],
                    "by_coord": {
                        api_row["coord"]: item,
                        "__business__": business_item,
                    },
                    "target_jdk": "17",
                },
            )

            business_edges, _metrics = business_bytecode_graph.collect_business_bytecode_edges(
                [], artifact_catalog=graph.runtime_dependency_catalog
            )
            business_bytecode_graph.merge_business_bytecode_edges(graph, business_edges)
            self.assertIn(
                "com.vendor.OuterBridge.invoke(java.lang.String)", graph.reverse_edges
            )
            tracer._build_packaged_runtime_dependency_scan_cache([api_row], graph)
            added = tracer._collect_target_runtime_reference_closure(graph, [api_row])

        identity = tracer.build_api_identity_key(api_row)
        rows = [
            row for row in graph.analyzer_edges.values()
            if row["api_identity"] == identity
        ]
        self.assertGreaterEqual(added, 1)
        self.assertEqual(
            {row["caller_owner"] for row in rows},
            {"app.Application", "com.vendor.InternalBridge", "com.vendor.OuterBridge"},
        )
        self.assertEqual(len(rows), 5)
        self.assertTrue(any(
            row["caller_member"] == "unmarshal"
            and row["caller_descriptor"] == "(Ljava/lang/Object;)Ljava/lang/Object;"
            for row in rows
        ))
        perf = tracer._finalize_step5_perf_stats(graph)["bytecode_scan"]
        self.assertGreater(perf["class_parse_elapsed_sec"], 0)

    def test_perf_stats_preserve_submillisecond_parse_time(self):
        graph = SimpleNamespace()
        tracer._perf_add(graph, "bytecode_scan", "class_parse_elapsed_sec", 0.0004)

        stats = tracer._finalize_step5_perf_stats(graph)

        self.assertGreater(stats["bytecode_scan"]["class_parse_elapsed_sec"], 0)

    def test_same_coordinate_declaration_only_is_not_an_executable_edge(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_coordinate_bytecode_fixture(
                tmp, include_executable_call=False
            )
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog=self._runtime_catalog(((api_row["coord"], jar_path),)),
            )

            scans = tracer._build_packaged_runtime_dependency_scan_cache([api_row], graph)

        self.assertEqual(scans[tracer.build_api_identity_key(api_row)]["status"], "miss")

    def test_same_coordinate_internal_bridge_without_business_entry_is_not_reachable(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_coordinate_bytecode_fixture(tmp)
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog=self._runtime_catalog(((api_row["coord"], jar_path),)),
            )

            result = self._trace_packaged_fixture(api_row, graph)
            scan = graph.runtime_dependency_catalog["_packaged_api_scan_results"][
                tracer.build_api_identity_key(api_row)
            ]

        self.assertTrue(all(hit["edge_role"] == "internal_bridge" for hit in scan["hits"]))
        self.assertEqual(result.analysis_status, "uncertain")
        self.assertIsNone(result.is_reachable)
        self.assertEqual(result.reason_code, "PACKAGED_DEPENDENCY_BYTECODE_USAGE")

    def test_internal_bridge_hit_cannot_establish_removed_dependency_impact_without_business_entry(self):
        api_row = {
            "coord": "com.vendor:target",
            "new_version": "-",
            "api_name": "com.vendor.Target.removed",
            "api_simple": "removed",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
            "severity": "P1",
            "confirmed": "true",
        }
        graph = SimpleNamespace(methods_by_id={}, reverse_edges={})
        base_hit = {
            "coord": "com.vendor:target",
            "class_fqcn": "com.vendor.InternalBridge",
            "consumer_method": "use",
            "consumer_signature": "(String)",
            "target_display": "com.vendor.Target.removed(String)",
            "jar_path": "/tmp/target.jar",
            "evidence_type": "bytecode_method_invocation",
        }

        results = {}
        for role, direct_consumer in (
            ("external_consumer", True),
            ("internal_bridge", False),
        ):
            scan = {
                "status": "hit",
                "hits": [{**base_hit, "edge_role": role, "direct_consumer": direct_consumer}],
            }
            with patch.object(tracer, "_scan_packaged_runtime_dependencies_for_api", return_value=scan):
                results[role] = self._trace_packaged_fixture(api_row, graph)

        self.assertEqual(
            results["external_consumer"].reason_code,
            "RUNTIME_DEPENDENCY_USES_REMOVED_API",
        )
        internal = results["internal_bridge"]
        self.assertEqual(internal.analysis_status, "uncertain")
        self.assertIsNone(internal.is_reachable)
        self.assertEqual(internal.reason_code, "PACKAGED_DEPENDENCY_BYTECODE_USAGE")
        self.assertIn("com.vendor.InternalBridge.use(String)", internal.call_paths[0])
        self.assertEqual(internal.evidence_paths[0][0]["edge_role"], "internal_bridge")

    def _analyzer_edge_ledger_graph(self, tmp, include_provenance=True):
        report_dir = Path(tmp) / "report"
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as zf:
            zf.writestr("com/vendor/Bridge.class", b"bridge")
            zf.writestr("com/vendor/Outer$Bridge.class", b"nested-bridge")
        nested_path = Path(tmp) / "target.jar"
        nested_path.write_bytes(nested.getvalue())
        artifact = Path(tmp) / "application.jar"
        with zipfile.ZipFile(artifact, "w") as zf:
            zf.writestr("BOOT-INF/lib/target.jar", nested.getvalue())
        artifact_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if include_provenance:
            provenance = report_dir / "evidence" / "dependencies" / "build_provenance.json"
            self._write_text(
                provenance,
                json.dumps({
                    "sides": [{
                        "side": "current",
                        "artifact_path": str(artifact),
                        "artifact_sha256": artifact_sha256,
                    }]
                }),
                encoding="utf-8",
            )
        runtime_item = {
            "coord": "com.vendor:target",
            "jar_path": str(nested_path),
            "artifact_entry": "BOOT-INF/lib/target.jar",
            "sha256": hashlib.sha256(nested_path.read_bytes()).hexdigest(),
            "evidence_source": "current_final_artifact",
        }
        return SimpleNamespace(
            report_dir=str(report_dir),
            runtime_dependency_catalog={
                "status": "complete" if include_provenance else "insufficient",
                "final_artifact_sha256": artifact_sha256,
                "by_coord": {"com.vendor:target": runtime_item},
                "entries": [runtime_item],
            },
        ), artifact_sha256

    def test_corrupt_nested_final_artifact_is_incomplete_not_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / "report"
            corrupt = Path(tmp) / "corrupt.jar"
            corrupt.write_bytes(b"not-a-jar")
            item = {
                "coord": "com.vendor:corrupt",
                "jar_path": str(corrupt),
                "artifact_entry": "BOOT-INF/lib/corrupt.jar",
                "sha256": hashlib.sha256(corrupt.read_bytes()).hexdigest(),
            }
            graph = SimpleNamespace(
                report_dir=str(report_dir),
                runtime_dependency_catalog={
                    "status": "complete",
                    "entries": [item],
                    "by_coord": {"com.vendor:corrupt": item},
                },
            )

            verified = tracer._verified_final_artifact_provenance(graph)

        self.assertFalse(verified["complete"])
        self.assertIn("com.vendor:corrupt", verified["failures"][0])

    def test_analyzer_edge_reuses_transaction_verified_jar_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph, _artifact_sha256 = self._analyzer_edge_ledger_graph(tmp)
            evidence_jar = graph.runtime_dependency_catalog["by_coord"][
                "com.vendor:target"
            ]["jar_path"]
            provenance = tracer._verified_final_artifact_provenance(graph)
            verified = {
                os.path.realpath(evidence_jar): hashlib.sha256(
                    Path(evidence_jar).read_bytes()
                ).hexdigest(),
            }
            edge = {
                "artifact_container_entry": "BOOT-INF/lib/target.jar",
                "jar_path": evidence_jar,
                "class_entry": "com/vendor/Bridge.class",
            }

            with patch.object(
                Path, "read_bytes",
                side_effect=AssertionError("verified JAR must not be read per API hit"),
            ):
                matched = tracer._evidence_bytes_match_final_artifact(
                    edge,
                    provenance,
                    "BOOT-INF/lib/target.jar!/com/vendor/Bridge.class",
                    verified,
                )

        self.assertTrue(matched)

    def test_writes_complete_analyzer_edge_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph, _outer_artifact_sha256 = self._analyzer_edge_ledger_graph(tmp)
            base_api = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.call",
                "api_simple": "call",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
            }
            evidence_jar = graph.runtime_dependency_catalog["by_coord"][
                "com.vendor:target"
            ]["jar_path"]
            evidence_jar_sha256 = graph.runtime_dependency_catalog["by_coord"][
                "com.vendor:target"
            ]["sha256"]
            edges = [
                {
                    "coord": "com.vendor:target",
                    "artifact_container_entry": "BOOT-INF/lib/target.jar",
                    "edge_role": "internal_bridge",
                    "jar_path": evidence_jar,
                    "class_entry": "com/vendor/Bridge.class",
                    "class_fqcn": "com.vendor.Bridge",
                    "consumer_method": "use",
                    "consumer_descriptor": "(Ljava/lang/String;)V",
                    "callee_owner": "com.vendor.Target",
                    "callee_member": "call",
                    "callee_descriptor": "(Ljava/lang/String;)V",
                    "opcode_family": "invokevirtual",
                    "instruction_offset": 7,
                },
                {
                    "coord": "com.vendor:target",
                    "artifact_container_entry": "BOOT-INF/lib/target.jar",
                    "edge_role": "internal_bridge",
                    "jar_path": evidence_jar,
                    "class_entry": "com/vendor/Bridge.class",
                    "class_fqcn": "com.vendor.Bridge",
                    "consumer_method": "use",
                    "consumer_descriptor": "(Ljava/lang/String;)V",
                    "callee_owner": "com.vendor.Target",
                    "callee_member": "call",
                    "callee_descriptor": "(I)V",
                    "opcode_family": "invokevirtual",
                    "instruction_offset": 12,
                },
                {
                    "coord": "com.vendor:target",
                    "artifact_container_entry": "BOOT-INF/lib/target.jar",
                    "edge_role": "internal_bridge",
                    "jar_path": evidence_jar,
                    "class_entry": "com/vendor/Bridge.class",
                    "class_fqcn": "com.vendor.Bridge",
                    "consumer_method": "make",
                    "consumer_descriptor": "()V",
                    "callee_owner": "com.vendor.Target",
                    "callee_member": "<init>",
                    "callee_descriptor": "()V",
                    "opcode_family": "invokespecial",
                    "instruction_offset": 4,
                },
            ]
            int_overload = {**base_api, "api_signature": "(int)"}
            constructor = {
                **base_api,
                "api_name": "com.vendor.Target.Target",
                "api_simple": "Target",
                "api_signature": "()",
                "symbol_kind": "constructor",
            }

            with patch.dict(
                os.environ, {"JUA_ANALYZER_EDGE_MEMORY_LIMIT": "2"}
            ):
                tracer.record_analyzer_edge(graph, base_api, edges[0])
                tracer.record_analyzer_edge(graph, base_api, edges[0])
                tracer.record_analyzer_edge(
                    graph,
                    base_api,
                    {**edges[0], "instruction_offset": 2},
                )
                tracer.record_analyzer_edge(graph, int_overload, edges[1])
                tracer.record_analyzer_edge(graph, constructor, edges[2])
                self.assertIsInstance(
                    graph.analyzer_edges,
                    tracer._DiskBackedAnalyzerEdgeStore,
                )
            graph_stats = {}
            ledger_path = tracer.write_analyzer_edge_ledger(graph, graph_stats=graph_stats)

            with Path(ledger_path).open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 4)
        self.assertEqual(
            {row["artifact_sha256"] for row in rows},
            {evidence_jar_sha256},
        )
        self.assertEqual(
            {row["artifact_entry"] for row in rows},
            {"BOOT-INF/lib/target.jar!/com/vendor/Bridge.class"},
        )
        self.assertEqual({row["edge_role"] for row in rows}, {"internal_bridge"})
        self.assertEqual(
            {row["callee_descriptor"] for row in rows if row["callee_member"] == "call"},
            {"(Ljava/lang/String;)V", "(I)V"},
        )
        self.assertIn("<init>", {row["callee_member"] for row in rows})
        string_overload_offsets = {
            row["instruction_offset"]
            for row in rows
            if row["callee_descriptor"] == "(Ljava/lang/String;)V"
        }
        self.assertEqual(string_overload_offsets, {"2", "7"})
        self.assertEqual(
            rows,
            sorted(rows, key=tracer.canonical_analyzer_edge_sort_key),
        )
        self.assertEqual(graph_stats["analyzer_edge_count"], 4)
        self.assertEqual(graph_stats["duplicate_edge_count"], 1)
        self.assertEqual(graph_stats["edge_ledger_failure_count"], 0)
        self.assertTrue(graph_stats["edge_ledger_complete"])

    def test_analyzer_ledger_keeps_one_physical_edge_for_each_selected_api_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph, _artifact_sha256 = self._analyzer_edge_ledger_graph(tmp)
            evidence_jar = graph.runtime_dependency_catalog["by_coord"][
                "com.vendor:target"
            ]["jar_path"]
            edge = {
                "coord": "com.vendor:target",
                "artifact_container_entry": "BOOT-INF/lib/target.jar",
                "edge_role": "internal_bridge",
                "jar_path": evidence_jar,
                "class_entry": "com/vendor/Bridge.class",
                "class_fqcn": "com.vendor.Bridge",
                "consumer_method": "use",
                "consumer_descriptor": "()V",
                "callee_owner": "com.vendor.Target",
                "callee_member": "first",
                "callee_descriptor": "()V",
                "opcode_family": "invokestatic",
                "instruction_offset": 7,
            }
            first = {
                "coord": "com.vendor:target", "api_name": "com.vendor.Target.first",
                "api_signature": "()", "symbol_kind": "method", "change_type": "REMOVED",
            }
            second = {
                "coord": "com.vendor:target", "api_name": "com.vendor.Target.second",
                "api_signature": "()", "symbol_kind": "method", "change_type": "REMOVED",
            }

            tracer.record_analyzer_edge(graph, first, edge)
            tracer.record_analyzer_edge(graph, second, edge)

        self.assertEqual(len(graph.analyzer_edges), 2)
        self.assertEqual(
            {row["api_identity"] for row in graph.analyzer_edges.values()},
            {tracer.build_api_identity_key(first), tracer.build_api_identity_key(second)},
        )

    def test_analyzer_edge_ledger_is_incomplete_without_final_artifact_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph, _artifact_sha256 = self._analyzer_edge_ledger_graph(
                tmp, include_provenance=False
            )
            tracer.record_analyzer_edge(
                graph,
                {
                    "coord": "com.vendor:target",
                    "api_name": "com.vendor.Target.call",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "METHOD_REMOVED",
                },
                {
                    "coord": "com.vendor:target",
                    "edge_role": "internal_bridge",
                    "class_entry": "com/vendor/Bridge.class",
                    "class_fqcn": "com.vendor.Bridge",
                    "consumer_method": "use",
                    "consumer_descriptor": "()V",
                    "callee_owner": "com.vendor.Target",
                    "callee_member": "call",
                    "callee_descriptor": "()V",
                    "opcode_family": "invokestatic",
                },
            )
            graph_stats = {}
            tracer.write_analyzer_edge_ledger(graph, graph_stats=graph_stats)

        self.assertEqual(graph_stats["analyzer_edge_count"], 0)
        self.assertEqual(graph_stats["duplicate_edge_count"], 0)
        self.assertGreater(graph_stats["edge_ledger_failure_count"], 0)
        self.assertFalse(graph_stats["edge_ledger_complete"])

    def test_analyzer_edge_ledger_requires_offset_but_preserves_real_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph, _artifact_sha256 = self._analyzer_edge_ledger_graph(tmp)
            jar_path = graph.runtime_dependency_catalog["by_coord"][
                "com.vendor:target"
            ]["jar_path"]
            api_row = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.call",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
            }
            edge = {
                "coord": "com.vendor:target",
                "artifact_container_entry": "BOOT-INF/lib/target.jar",
                "jar_path": jar_path,
                "class_entry": "com/vendor/Bridge.class",
                "caller_owner": "com.vendor.Bridge",
                "consumer_method": "use",
                "consumer_descriptor": "()V",
                "callee_owner": "com.vendor.Target",
                "callee_member": "call",
                "callee_descriptor": "()V",
                "opcode_family": "invokestatic",
            }

            tracer.record_analyzer_edge(graph, api_row, {**edge, "instruction_offset": 0})
            tracer.record_analyzer_edge(graph, api_row, edge)
            graph_stats = {}
            ledger_path = tracer.write_analyzer_edge_ledger(graph, graph_stats=graph_stats)
            with Path(ledger_path).open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual([row["instruction_offset"] for row in rows], ["0"])
        self.assertGreater(graph_stats["edge_ledger_failure_count"], 0)
        self.assertFalse(graph_stats["edge_ledger_complete"])

    def test_invokedynamic_ledger_preserves_nested_bootstrap_owner(self):
        javap_output = """
public class com.vendor.Outer$Bridge {
  public void use();
    descriptor: ()V
    Code:
       0: invokedynamic #7,  0 // InvokeDynamic #0:call:()Ljava/lang/Runnable;
       5: return
BootstrapMethods:
  0: #20 REF_invokeStatic com/vendor/Outer$Target.call:()V
"""
        references = tracer._parse_javap_bytecode_references(
            javap_output, "com.vendor.Outer$Bridge"
        )
        api_row = {
            "coord": "com.vendor:target",
            "api_name": "com.vendor.Outer$Target.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
        }
        matched = tracer._match_runtime_dependency_references(api_row, references)[0]

        self.assertEqual(matched["callee_owner"], "com.vendor.Outer$Target")
        self.assertEqual(matched["opcode_family"], "invokedynamic")
        self.assertEqual(matched["instruction_offset"], 0)

    def test_analyzer_edge_rejects_tampered_nested_jar_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph, _artifact_sha256 = self._analyzer_edge_ledger_graph(tmp)
            tampered_jar = Path(tmp) / "tampered-target.jar"
            with zipfile.ZipFile(tampered_jar, "w") as zf:
                zf.writestr("com/vendor/Bridge.class", b"tampered")
            api_row = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.call",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
            }

            accepted = tracer.record_analyzer_edge(
                graph,
                api_row,
                {
                    "coord": "com.vendor:target",
                    "artifact_container_entry": "BOOT-INF/lib/target.jar",
                    "jar_path": str(tampered_jar),
                    "class_entry": "com/vendor/Bridge.class",
                    "caller_owner": "com.vendor.Bridge",
                    "consumer_method": "use",
                    "consumer_descriptor": "()V",
                    "callee_owner": "com.vendor.Target",
                    "callee_member": "call",
                    "callee_descriptor": "()V",
                    "opcode_family": "invokestatic",
                    "instruction_offset": 0,
                },
            )
            graph_stats = {}
            tracer.write_analyzer_edge_ledger(graph, graph_stats=graph_stats)

        self.assertIsNone(accepted)
        self.assertEqual(graph_stats["analyzer_edge_count"], 0)
        self.assertGreater(graph_stats["edge_ledger_failure_count"], 0)
        self.assertFalse(graph_stats["edge_ledger_complete"])

    def test_analyzer_edge_rejects_tampered_business_class_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / "report"
            artifact = Path(tmp) / "application.jar"
            with zipfile.ZipFile(artifact, "w") as zf:
                zf.writestr("BOOT-INF/classes/app/Service.class", b"expected")
            artifact_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self._write_text(
                report_dir / "evidence" / "dependencies" / "build_provenance.json",
                json.dumps({
                    "sides": [{
                        "side": "current",
                        "artifact_path": str(artifact),
                        "artifact_sha256": artifact_sha256,
                    }]
                }),
                encoding="utf-8",
            )
            stale_business_jar = Path(tmp) / "business-classes.jar"
            with zipfile.ZipFile(stale_business_jar, "w") as zf:
                zf.writestr("app/Service.class", b"stale")
            expected_business_jar = Path(tmp) / "expected-business-classes.jar"
            with zipfile.ZipFile(expected_business_jar, "w") as zf:
                zf.writestr("app/Service.class", b"expected")
            business_item = {
                "coord": "__business__",
                "jar_path": str(expected_business_jar),
                "artifact_entry": "<business-classes>",
                "sha256": hashlib.sha256(
                    expected_business_jar.read_bytes()
                ).hexdigest(),
            }
            graph = SimpleNamespace(
                report_dir=str(report_dir),
                runtime_dependency_catalog={
                    "status": "complete",
                    "final_artifact_sha256": artifact_sha256,
                    "by_coord": {"__business__": business_item},
                    "entries": [business_item],
                },
            )

            accepted = tracer.record_analyzer_edge(
                graph,
                {"api_name": "com.vendor.Target.call", "api_signature": "()"},
                {
                    "coord": "__business__",
                    "jar_path": str(stale_business_jar),
                    "class_entry": "app/Service.class",
                    "caller_owner": "app.Service",
                    "consumer_method": "run",
                    "consumer_descriptor": "()V",
                    "callee_owner": "com.vendor.Target",
                    "callee_member": "call",
                    "callee_descriptor": "()V",
                    "opcode_family": "invokestatic",
                    "instruction_offset": 0,
                },
            )
            graph_stats = {}
            tracer.write_analyzer_edge_ledger(graph, graph_stats=graph_stats)

        self.assertIsNone(accepted)
        self.assertGreater(graph_stats["edge_ledger_failure_count"], 0)
        self.assertFalse(graph_stats["edge_ledger_complete"])

    def test_analyzer_edge_accepts_matching_thin_jar_business_class_with_pseudo_container(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / "report"
            artifact = Path(tmp) / "application.jar"
            with zipfile.ZipFile(artifact, "w") as zf:
                zf.writestr("app/Service.class", b"matching-class-bytes")
            artifact_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self._write_text(
                report_dir / "evidence" / "dependencies" / "build_provenance.json",
                json.dumps({
                    "sides": [{
                        "side": "current",
                        "artifact_path": str(artifact),
                        "artifact_sha256": artifact_sha256,
                    }]
                }),
                encoding="utf-8",
            )
            business_jar = Path(tmp) / "business-classes.jar"
            with zipfile.ZipFile(business_jar, "w") as zf:
                zf.writestr("app/Service.class", b"matching-class-bytes")
            business_item = {
                "coord": "__business__",
                "jar_path": str(business_jar),
                "artifact_entry": "<business-classes>",
                "sha256": hashlib.sha256(business_jar.read_bytes()).hexdigest(),
            }
            graph = SimpleNamespace(
                report_dir=str(report_dir),
                runtime_dependency_catalog={
                    "status": "complete",
                    "final_artifact_sha256": artifact_sha256,
                    "by_coord": {"__business__": business_item},
                    "entries": [business_item],
                },
            )

            accepted = tracer.record_analyzer_edge(
                graph,
                {"api_name": "com.vendor.Target.call", "api_signature": "()"},
                {
                    "coord": "__business__",
                    "artifact_container_entry": "<business-classes>",
                    "jar_path": str(business_jar),
                    "class_entry": "app/Service.class",
                    "caller_owner": "app.Service",
                    "consumer_method": "run",
                    "consumer_descriptor": "()V",
                    "callee_owner": "com.vendor.Target",
                    "callee_member": "call",
                    "callee_descriptor": "()V",
                    "opcode_family": "invokestatic",
                    "instruction_offset": 0,
                },
            )
            graph_stats = {}
            tracer.write_analyzer_edge_ledger(graph, graph_stats=graph_stats)

        self.assertIsNotNone(accepted)
        self.assertEqual(accepted["artifact_entry"], "app/Service.class")
        self.assertEqual(graph_stats["edge_ledger_failure_count"], 0)
        self.assertTrue(graph_stats["edge_ledger_complete"])

    def test_absent_runtime_catalog_marks_edge_ledger_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph, _artifact_sha256 = self._analyzer_edge_ledger_graph(tmp)
            graph.runtime_dependency_catalog = {}
            graph.methods_by_id = {}
            graph.reverse_edges = {}

            tracer._build_packaged_runtime_dependency_scan_cache([{
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.call",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
            }], graph)
            graph_stats = {}
            tracer.write_analyzer_edge_ledger(graph, graph_stats=graph_stats)

        self.assertGreater(graph_stats["edge_ledger_failure_count"], 0)
        self.assertFalse(graph_stats["edge_ledger_complete"])

    def test_unknown_multi_release_target_marks_edge_ledger_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / "report"
            runtime_jar = Path(tmp) / "consumer.jar"
            with zipfile.ZipFile(runtime_jar, "w") as zf:
                zf.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\nMulti-Release: true\n",
                )
                zf.writestr("com/acme/Consumer.class", b"com/vendor/Target call")
                zf.writestr(
                    "META-INF/versions/11/com/acme/Consumer.class",
                    b"com/vendor/Target call",
                )
            artifact = Path(tmp) / "application.jar"
            with zipfile.ZipFile(artifact, "w") as zf:
                zf.writestr("BOOT-INF/lib/consumer.jar", runtime_jar.read_bytes())
            artifact_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self._write_text(
                report_dir / "evidence" / "dependencies" / "build_provenance.json",
                json.dumps({
                    "sides": [{
                        "side": "current",
                        "artifact_path": str(artifact),
                        "artifact_sha256": artifact_sha256,
                    }]
                }),
                encoding="utf-8",
            )
            item = {
                "coord": "com.acme:consumer",
                "jar_path": str(runtime_jar),
                "artifact_entry": "BOOT-INF/lib/consumer.jar",
                "evidence_source": "current_final_artifact",
            }
            graph = SimpleNamespace(
                report_dir=str(report_dir),
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "status": "complete",
                    "entries": [item],
                    "by_coord": {item["coord"]: item},
                },
            )
            api_row = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.call",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
            }

            scan = tracer._scan_packaged_runtime_dependencies_for_api(api_row, graph)
            graph_stats = {}
            tracer.write_analyzer_edge_ledger(graph, graph_stats=graph_stats)

        self.assertEqual(scan["reason"], "MULTI_RELEASE_TARGET_JDK_UNKNOWN")
        self.assertIn(
            "MULTI_RELEASE_TARGET_JDK_UNKNOWN",
            {failure[0] for failure in graph._analyzer_edge_failures},
        )
        self.assertGreater(graph_stats["edge_ledger_failure_count"], 0)
        self.assertFalse(graph_stats["edge_ledger_complete"])

    def test_analyzer_edge_ledger_preserves_nested_class_binary_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph, _artifact_sha256 = self._analyzer_edge_ledger_graph(tmp)
            tracer.record_analyzer_edge(
                graph,
                {
                    "coord": "com.vendor:target",
                    "api_name": "com.vendor.Outer$Target.call",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "METHOD_REMOVED",
                },
                {
                    "coord": "com.vendor:target",
                    "artifact_container_entry": "BOOT-INF/lib/target.jar",
                    "jar_path": graph.runtime_dependency_catalog["by_coord"][
                        "com.vendor:target"
                    ]["jar_path"],
                    "class_entry": "com/vendor/Outer$Bridge.class",
                    "caller_owner": "com.vendor.Outer$Bridge",
                    "consumer_method": "use",
                    "consumer_descriptor": "()V",
                    "callee_owner": "com.vendor.Outer$Target",
                    "callee_member": "call",
                    "callee_descriptor": "()V",
                    "opcode_family": "invokestatic",
                    "instruction_offset": 1,
                },
            )
            ledger_path = tracer.write_analyzer_edge_ledger(graph, graph_stats={})
            with Path(ledger_path).open(encoding="utf-8", newline="") as handle:
                row = next(csv.DictReader(handle))

        self.assertEqual(row["caller_owner"], "com.vendor.Outer$Bridge")
        self.assertEqual(row["callee_owner"], "com.vendor.Outer$Target")

    def test_analyzer_edge_ledger_marks_relevant_jar_scan_failure_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph, _artifact_sha256 = self._analyzer_edge_ledger_graph(tmp)
            missing_jar = Path(tmp) / "missing.jar"
            item = {
                "coord": "com.vendor:target",
                "jar_path": str(missing_jar),
                "artifact_entry": "BOOT-INF/lib/target.jar",
                "evidence_source": "current_final_artifact",
            }
            graph.methods_by_id = {}
            graph.reverse_edges = {}
            graph.runtime_dependency_catalog = {
                "status": "complete",
                "entries": [item],
                "by_coord": {item["coord"]: item},
            }
            api_row = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.call",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
            }

            tracer._build_packaged_runtime_dependency_scan_cache([api_row], graph)
            graph_stats = {}
            tracer.write_analyzer_edge_ledger(graph, graph_stats=graph_stats)

        self.assertEqual(graph_stats["analyzer_edge_count"], 0)
        self.assertGreater(graph_stats["edge_ledger_failure_count"], 0)
        self.assertFalse(graph_stats["edge_ledger_complete"])

    def test_analyzer_edge_ledger_analyzes_same_coordinate_bytes_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            api_row, jar_path = self._same_coordinate_bytecode_fixture(tmp)
            report_dir = Path(tmp) / "report"
            artifact = Path(tmp) / "application.jar"
            container_entries = (
                "BOOT-INF/lib/target-a.jar",
                "BOOT-INF/lib/target-b.jar",
            )
            with zipfile.ZipFile(artifact, "w") as zf:
                for entry in container_entries:
                    zf.writestr(entry, jar_path.read_bytes())
            artifact_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self._write_text(
                report_dir / "evidence" / "dependencies" / "build_provenance.json",
                json.dumps({
                    "sides": [{
                        "side": "current",
                        "artifact_path": str(artifact),
                        "artifact_sha256": artifact_sha256,
                    }]
                }),
                encoding="utf-8",
            )
            retained_sha256 = hashlib.sha256(jar_path.read_bytes()).hexdigest()
            entry = {
                "coord": api_row["coord"],
                "jar_path": str(jar_path),
                "artifact_entry": container_entries[0],
                "artifact_entries": list(container_entries),
                "sha256": retained_sha256,
                "evidence_source": "current_final_artifact",
            }
            graph = SimpleNamespace(
                report_dir=str(report_dir),
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "status": "complete",
                    "entries": [entry],
                    "by_coord": {api_row["coord"]: entry},
                },
            )

            tracer._build_packaged_runtime_dependency_scan_cache([api_row], graph)
            ledger_path = tracer.write_analyzer_edge_ledger(graph, graph_stats={})
            with Path(ledger_path).open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))

        bridge_entries = {
            row["artifact_entry"]
            for row in rows
            if row["caller_owner"] == "com.vendor.InternalBridge"
        }
        self.assertEqual(
            bridge_entries,
            {
                f"{container_entries[0]}!/com/vendor/InternalBridge.class"
            },
        )

    def test_collects_verified_business_reverse_edge_from_boot_inf_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            target = src / "com/vendor/Target.java"
            service = src / "app/Service.java"
            target.parent.mkdir(parents=True, exist_ok=True)
            service.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                "package com.vendor; public class Target { "
                "public static void call() {} }",
                encoding="utf-8",
            )
            service.write_text(
                "package app; public class Service { "
                "public void run() { com.vendor.Target.call(); } }",
                encoding="utf-8",
            )
            classes = self._compile_java_files(Path(tmp) / "classes", [target, service])
            business_jar = Path(tmp) / "business-classes.jar"
            with zipfile.ZipFile(business_jar, "w") as zf:
                zf.write(classes / "app" / "Service.class", "app/Service.class")
            artifact = Path(tmp) / "application.jar"
            with zipfile.ZipFile(artifact, "w") as zf:
                zf.write(
                    classes / "app" / "Service.class",
                    "BOOT-INF/classes/app/Service.class",
                )
            artifact_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
            report_dir = Path(tmp) / "report"
            self._write_text(
                report_dir / "evidence" / "dependencies" / "build_provenance.json",
                json.dumps({
                    "sides": [{
                        "side": "current",
                        "artifact_path": str(artifact),
                        "artifact_sha256": artifact_sha256,
                    }]
                }),
                encoding="utf-8",
            )
            method = SimpleNamespace(
                symbol_id="service_run",
                qualified_key="app.Service.run",
                class_fqcn="app.Service",
                method_name="run",
                owner_coord="__business__",
                module="app",
            )
            business_sha256 = hashlib.sha256(business_jar.read_bytes()).hexdigest()
            business_item = {
                "coord": "__business__",
                "jar_path": str(business_jar),
                "artifact_entry": "<business-classes>",
                "sha256": business_sha256,
                "evidence_source": "current_final_artifact",
            }
            graph = SimpleNamespace(
                report_dir=str(report_dir),
                methods_by_id={method.symbol_id: method},
                methods_by_qualified={method.qualified_key: [method.symbol_id]},
                lookup_keys_by_symbol={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "status": "complete",
                    "entries": [business_item],
                    "by_coord": {"__business__": business_item},
                    "target_jdk": "17",
                },
            )
            api_row = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.call",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
            }

            produced_edges, producer_metrics = business_bytecode_graph.collect_business_bytecode_edges(
                [], artifact_catalog=graph.runtime_dependency_catalog
            )
            merged_metrics = business_bytecode_graph.merge_business_bytecode_edges(
                graph, produced_edges
            )
            self.assertEqual(producer_metrics["failures"], [])
            self.assertGreater(merged_metrics["merged_edges"], 0)
            produced_edge = graph.reverse_edges["com.vendor.Target.call()"][0]
            self.assertEqual(produced_edge.artifact_sha256, business_sha256)
            self.assertNotEqual(produced_edge.artifact_sha256, artifact_sha256)

            with patch.object(
                tracer,
                "_load_runtime_dependency_class_references",
                wraps=tracer._load_runtime_dependency_class_references,
            ) as mocked_loader:
                tracer.collect_graph_analyzer_edges(graph, [api_row])
            mocked_loader.assert_not_called()
            bytecode_scan = tracer._finalize_step5_perf_stats(graph)["bytecode_scan"]
            self.assertEqual(bytecode_scan["artifact_cache_misses"], 1)
            self.assertEqual(bytecode_scan["class_entries_parsed"], 1)
            self.assertEqual(bytecode_scan.get("duplicate_class_scans", 0), 0)
            graph_stats = {}
            ledger_path = tracer.write_analyzer_edge_ledger(graph, graph_stats=graph_stats)
            with Path(ledger_path).open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))

        row = next(item for item in rows if item["caller_owner"] == "app.Service")
        self.assertEqual(row["artifact_sha256"], business_sha256)
        self.assertEqual(row["artifact_entry"], "app/Service.class")
        self.assertEqual(row["caller_descriptor"], "()V")
        self.assertEqual(row["callee_descriptor"], "()V")
        self.assertEqual(row["opcode_family"], "invokestatic")
        self.assertTrue(graph_stats["edge_ledger_complete"])

    def test_business_jar_is_not_required_without_business_bytecode_edges(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph, _artifact_sha256 = self._analyzer_edge_ledger_graph(tmp)
            graph.methods_by_id = {}
            graph.reverse_edges = {}

            tracer.collect_graph_analyzer_edges(graph, [])
            graph_stats = {}
            tracer.write_analyzer_edge_ledger(graph, graph_stats=graph_stats)

        self.assertEqual(graph_stats["edge_ledger_failure_count"], 0)
        self.assertTrue(graph_stats["edge_ledger_complete"])

    def test_collect_uses_target_closure_edges_without_rescanning_all_runtime_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph, _artifact_sha256 = self._analyzer_edge_ledger_graph(tmp)
            graph.methods_by_id = {}
            graph.reverse_edges = {}
            api_row = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.call",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
            }
            edge = {
                "coord": "com.vendor:target",
                "artifact_container_entry": "BOOT-INF/lib/target.jar",
                "jar_path": graph.runtime_dependency_catalog["by_coord"][
                    "com.vendor:target"
                ]["jar_path"],
                "class_entry": "com/vendor/Bridge.class",
                "caller_owner": "com.vendor.Bridge",
                "consumer_method": "run",
                "consumer_descriptor": "()V",
                "callee_owner": "com.vendor.Target",
                "callee_member": "call",
                "callee_descriptor": "()V",
                "opcode_family": "invokestatic",
                "instruction_offset": 1,
            }
            tracer.record_analyzer_edge(graph, api_row, edge)

            with patch.object(
                tracer,
                "_collect_exhaustive_runtime_reference_edges",
                side_effect=AssertionError("target closure must not trigger a full runtime rescan"),
            ):
                collected = tracer.collect_graph_analyzer_edges(graph, [api_row])

        self.assertEqual(collected, 0)
        self.assertEqual(len(graph.analyzer_edges), 1)

    def test_multimodule_project_root_cannot_add_non_artifact_business_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            application_source = root / "application-src" / "app" / "Application.java"
            library_source = root / "library-src" / "lib" / "LibraryBridge.java"
            application_source.parent.mkdir(parents=True)
            library_source.parent.mkdir(parents=True)
            application_source.write_text(
                "package app; public class Application { public void run() {} }",
                encoding="utf-8",
            )
            library_source.write_text(
                "package lib; public class LibraryBridge { public void hidden() {} }",
                encoding="utf-8",
            )
            classes = self._compile_java_files(
                root / "project" / "target" / "classes",
                [application_source, library_source],
            )
            business_jar = root / "business-classes.jar"
            with zipfile.ZipFile(business_jar, "w") as archive:
                archive.write(classes / "app" / "Application.class", "app/Application.class")
            catalog = {
                "by_coord": {"__business__": {
                    "jar_path": str(business_jar),
                    "sha256": hashlib.sha256(business_jar.read_bytes()).hexdigest(),
                }},
            }

            edges, metrics = business_bytecode_graph.collect_business_bytecode_edges(
                [root / "project"], artifact_catalog=catalog
            )

        self.assertEqual(metrics["classes_scanned"], 1)
        self.assertTrue(all(edge["caller_owner"] == "app.Application" for edge in edges))
        self.assertFalse(any(edge["caller_owner"] == "lib.LibraryBridge" for edge in edges))

    def test_user_output_documents_analyzer_edge_ledger_contract(self):
        text = (ROOT_DIR / "docs" / "user" / "outputs.md").read_text(encoding="utf-8")

        self.assertIn("analyzer_edges.csv", text)
        for field in tracer.ANALYZER_EDGE_FIELDS:
            self.assertIn(f"`{field}`", text)
        for metric in (
            "analyzer_edge_count",
            "duplicate_edge_count",
            "edge_ledger_failure_count",
            "edge_ledger_complete",
        ):
            self.assertIn(f"`{metric}`", text)
        self.assertIn("可执行字节码指令", text)
        self.assertIn("不会从 `alerts.csv`", text)
        self.assertIn("非负整数", text)
        self.assertIn("字节 SHA-256", text)
        self.assertIn("MULTI_RELEASE_TARGET_JDK_UNKNOWN", text)

    def test_runtime_dependency_caller_candidate_scan_is_reused_for_signature_variants(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            src.mkdir()
            bridge = src / "BridgeB.java"
            caller = src / "CallerA.java"
            bridge.write_text(
                "package com.depb; public class BridgeB { public static void use(String v) {} }",
                encoding="utf-8",
            )
            caller.write_text(
                "package com.depa; public class CallerA { public void entry(String v) { com.depb.BridgeB.use(v); } }",
                encoding="utf-8",
            )
            classes = self._compile_java_files(Path(tmp) / "classes", [bridge, caller])
            jar_path = Path(tmp) / "dep-a.jar"
            self._jar_compiled_classes(jar_path, classes)
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog=self._runtime_catalog((("com.example:dep-a", jar_path),)),
            )

            zip_open_count = 0
            original_zip_file = tracer.zipfile.ZipFile

            def counting_zip_file(*args, **kwargs):
                nonlocal zip_open_count
                zip_open_count += 1
                return original_zip_file(*args, **kwargs)

            with patch.object(tracer.zipfile, "ZipFile", side_effect=counting_zip_file):
                tracer._ensure_runtime_dependency_callers_for_key(
                    graph,
                    "com.depb.BridgeB.use(String)",
                )
                tracer._ensure_runtime_dependency_callers_for_key(
                    graph,
                    "com.depb.BridgeB.use(java.lang.String)",
                )

        self.assertEqual(zip_open_count, 1)
        self.assertIn(("com.depb.BridgeB", "use"), graph._runtime_dependency_caller_candidate_cache)

    def test_packaged_hit_business_path_lookup_is_cached_for_repeated_consumer_hits(self):
        hit = {
            "coord": "com.example:dep-b",
            "jar_path": "/tmp/dep-b.jar",
            "class_fqcn": "com.depb.BridgeB",
            "consumer_method": "use",
            "consumer_signature": "(String)",
            "target_display": "org.apache.commons.lang.StringUtils.isBlank(String)",
        }
        business_method = SimpleNamespace(
            symbol_id="app_run",
            qualified_key="com.app.App.run",
            owner_type="business",
            owner_coord="__business__",
            is_test=False,
        )
        edge = source_analyzer.CallEdge(
            caller_symbol_id="app_run",
            caller_qualified_key="com.app.App.run",
            callee_key="com.depb.BridgeB.use(String)",
            callee_simple_key="method:use",
            evidence_type="bytecode_method_invocation",
            confidence="high",
            file="/tmp/app.jar",
            line=0,
            content="business bytecode calls dep",
            owner_type="business",
            owner_coord="__business__",
            module="app",
            is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"app_run": business_method},
            reverse_edges={"com.depb.BridgeB.use(String)": [edge]},
            runtime_dependency_catalog={},
        )
        calls = 0

        def fake_expand(_graph, _lookup_key, **_kwargs):
            nonlocal calls
            calls += 1
            return {"expanded": True, "edges_added": 0, "javap_classes": 0, "visited_classes": 0}

        with patch.object(tracer, "_ensure_runtime_dependency_callers_for_key", side_effect=fake_expand):
            first = tracer._find_business_callers_for_packaged_hit(hit, graph)
            calls_after_first = calls
            second = tracer._find_business_callers_for_packaged_hit(hit, graph)

        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertEqual(calls, calls_after_first)

    def test_application_owned_internal_module_must_reach_real_business_entry(self):
        result = tracer.TraceResult(
            api_name="com.example.ServiceProperties.getMessage",
            api_simple="getMessage",
            api_signature="()",
            symbol_kind="method",
            change_type="REMOVED",
            coord="com.example:library",
            severity="P1",
            confirmed=True,
            source="test",
            analysis_scope="method",
            analysis_status="not_analyzed",
            direct_callers=0,
            is_reachable=False,
            reachable_note="",
            business_reach_depth=0,
            dependency_chain_coords=[],
            call_paths=[],
            evidence_paths=[],
            reason_code="",
            verification_commands=[],
            hops=[],
            confidence_score=1.0,
            critical_nodes_hit=[],
        )
        business_method = SimpleNamespace(
            symbol_id="app_home",
            qualified_key="com.example.DemoApplication.home",
            owner_type="business",
            is_test=False,
        )
        edge = source_analyzer.CallEdge(
            caller_symbol_id="app_home",
            caller_qualified_key="com.example.DemoApplication.home",
            callee_key="com.example.MyService.message()",
            callee_simple_key="method:message",
            evidence_type="bytecode_method_invocation",
            confidence="high",
            file="/tmp/application.jar!/BOOT-INF/classes/com/example/DemoApplication.class",
            line=0,
            content="business bytecode calls internal module",
            owner_type="business",
            owner_coord="__business__",
            module="application",
            is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"app_home": business_method},
            reverse_edges={"com.example.MyService.message()": [edge]},
            runtime_dependency_catalog={},
        )
        hit = {
            "coord": "com.example:library",
            "application_owned": True,
            "edge_role": "internal_bridge",
            "direct_consumer": False,
            "class_fqcn": "com.example.MyService",
            "consumer_method": "message",
            "consumer_signature": "()",
            "target_display": "com.example.ServiceProperties.getMessage()",
            "evidence_type": "bytecode_method_invocation",
            "jar_path": "/tmp/application.jar!/BOOT-INF/lib/library.jar",
        }

        draft = self._draft_from_result(result)
        tracer._build_packaged_dependency_hit_result(draft, [hit], graph)
        built = tracer._finalize_trace_draft(draft)

        self.assertEqual(built.analysis_status, "reachable")
        self.assertEqual(built.business_reach_depth, 2)
        self.assertIn(
            "com.example.DemoApplication.home -> "
            "com.example:library:com.example.MyService.message() -> "
            "com.example.ServiceProperties.getMessage()",
            built.call_paths,
        )
        self.assertFalse(built.path_details[0]["business_reachable"])
        self.assertTrue(built.path_details[-1]["business_reachable"])

    def test_artifact_hash_parse_cache_preserves_scope_and_target_internal_role(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "target.jar"
            source_root = Path(tmp) / "src"
            target_source = source_root / "com/vendor/Target.java"
            bridge_source = source_root / "com/example/TargetBridge.java"
            target_source.parent.mkdir(parents=True)
            bridge_source.parent.mkdir(parents=True)
            target_source.write_text(
                "package com.vendor; public class Target { "
                "public static void removed(String value) {} }",
                encoding="utf-8",
            )
            bridge_source.write_text(
                "package com.example; public class TargetBridge { "
                "public void use(String value) { com.vendor.Target.removed(value); } }",
                encoding="utf-8",
            )
            classes = self._compile_java_files(
                Path(tmp) / "classes", [target_source, bridge_source]
            )
            self._jar_compiled_classes(jar_path, classes)
            api_row = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.removed",
                "api_simple": "removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }

            def graph():
                item = {
                    "coord": api_row["coord"],
                    "jar_path": str(jar_path),
                    "artifact_entry": "BOOT-INF/lib/target.jar",
                }
                return SimpleNamespace(
                    methods_by_id={},
                    reverse_edges={"force_javap_path": []},
                    runtime_dependency_catalog={
                        "status": "complete",
                        "entries": [item],
                        "by_coord": {item["coord"]: item},
                        "target_jdk": "17",
                    },
                )

            javap_output = """
public class com.example.TargetBridge {
  public void use(java.lang.String);
    descriptor: (Ljava/lang/String;)V
    Code:
       0: invokestatic #7 // Method com/vendor/Target.removed:(Ljava/lang/String;)V
}
"""
            tracer.clear_immutable_artifact_parse_cache()
            first_graph = graph()
            second_graph = graph()
            with patch.object(tracer, "run_cmd", return_value=(javap_output, "", 0)) as mocked_run:
                tracer._build_packaged_runtime_dependency_scan_cache([api_row], first_graph)
                tracer._build_packaged_runtime_dependency_scan_cache([api_row], second_graph)

            first = first_graph.runtime_dependency_catalog["_packaged_api_scan_results"][
                tracer.build_api_identity_key(api_row)
            ]
            second = second_graph.runtime_dependency_catalog["_packaged_api_scan_results"][
                tracer.build_api_identity_key(api_row)
            ]
            first_perf = tracer._finalize_step5_perf_stats(first_graph)["bytecode_scan"]
            second_perf = tracer._finalize_step5_perf_stats(second_graph)["bytecode_scan"]

        self.assertEqual(mocked_run.call_count, 0)
        self.assertEqual(first["visited_classes"], second["visited_classes"])
        self.assertEqual(first["status"], second["status"])
        self.assertEqual(second["hits"][0]["edge_role"], "internal_bridge")
        self.assertFalse(second["hits"][0]["direct_consumer"])
        self.assertEqual(first_perf["class_entries_scoped"], second_perf["class_entries_scoped"])
        self.assertEqual(second_perf["artifact_cache_hits"], 2)
        self.assertEqual(second_perf["class_entries_parsed"], 0)
        self.assertEqual(second_perf["duplicate_class_scans"], 0)
        self.assertEqual(second_perf["direct_consumer_class_scans"], 0)
        self.assertEqual(second_perf["internal_bridge_class_scans"], 1)

    def test_artifact_hash_parse_cache_deduplicates_concurrent_class_parses(self):
        javap_output = """
public class com.example.TargetBridge {
  public void use(java.lang.String);
    descriptor: (Ljava/lang/String;)V
    Code:
       0: invokestatic #7 // Method com/vendor/Target.removed:(Ljava/lang/String;)V
}
"""
        graph = SimpleNamespace()
        tracer.clear_immutable_artifact_parse_cache()

        def load_references():
            return tracer._load_runtime_dependency_class_references(
                {}, "com.vendor:target", "/tmp/target.jar", "com.example.TargetBridge",
                artifact_sha256="a" * 64, target_jdk="17", graph=graph,
            )

        def slow_javap(*_args, **_kwargs):
            time.sleep(0.05)
            return javap_output

        with patch.object(tracer, "_run_javap_bytecode_dump", side_effect=slow_javap) as mocked_javap:
            with ThreadPoolExecutor(max_workers=2) as executor:
                first, second = [future.result() for future in (
                    executor.submit(load_references), executor.submit(load_references)
                )]

        self.assertEqual(mocked_javap.call_count, 1)
        self.assertEqual(first, second)
        self.assertGreaterEqual(
            tracer._finalize_step5_perf_stats(graph)["bytecode_scan"]["artifact_cache_hits"], 1
        )

    def test_artifact_hash_parse_cache_counts_only_actual_duplicate_parses(self):
        javap_output = """
public class com.example.TargetBridge {
  public void use(java.lang.String);
    descriptor: (Ljava/lang/String;)V
    Code:
       0: invokestatic #7 // Method com/vendor/Target.removed:(Ljava/lang/String;)V
}
"""
        graph = SimpleNamespace()
        artifact_sha256 = "a" * 64

        def load_references(catalog):
            return tracer._load_runtime_dependency_class_references(
                catalog, "com.vendor:target", "/tmp/target.jar", "com.example.TargetBridge",
                artifact_sha256=artifact_sha256, target_jdk="17", graph=graph,
            )

        tracer.clear_immutable_artifact_parse_cache()
        with patch.object(tracer, "_run_javap_bytecode_dump", return_value=javap_output) as mocked_javap:
            first = load_references({})
            second = load_references({})
            tracer.clear_immutable_artifact_parse_cache()
            third = load_references({})

        perf = tracer._finalize_step5_perf_stats(graph)["bytecode_scan"]
        self.assertEqual(first, second)
        self.assertEqual(first, third)
        self.assertEqual(mocked_javap.call_count, 2)
        self.assertEqual(perf["class_entries_parsed"], 2)
        self.assertEqual(perf["duplicate_class_scans"], 1)
        self.assertEqual(len(perf["duplicate_class_scan_samples"]), 1)
        self.assertEqual(
            perf["duplicate_class_scan_samples"][0]["class_binary_name"],
            "com.example.TargetBridge",
        )
        self.assertEqual(
            perf["duplicate_class_scan_samples"][0]["parser_kind"], "javap"
        )

    def test_artifact_cache_normalizes_missing_base_class_entry(self):
        graph = SimpleNamespace()
        artifact_sha256 = "b" * 64
        javap_output = "public class com.example.TargetBridge {}"
        tracer.clear_immutable_artifact_parse_cache()
        with patch.object(
            tracer, "_run_javap_bytecode_dump", return_value=javap_output
        ) as mocked_javap:
            tracer._load_runtime_dependency_class_references(
                {}, "com.vendor:target", "/tmp/target.jar",
                "com.example.TargetBridge", artifact_sha256=artifact_sha256,
                target_jdk="17", multi_release_version="base", graph=graph,
            )
            tracer._load_runtime_dependency_class_references(
                {}, "com.vendor:target", "/tmp/target.jar",
                "com.example.TargetBridge", artifact_sha256=artifact_sha256,
                target_jdk="17", multi_release_version="base", graph=graph,
                class_entry="com/example/TargetBridge.class",
            )

        self.assertEqual(mocked_javap.call_count, 1)
        perf = tracer._finalize_step5_perf_stats(graph)["bytecode_scan"]
        self.assertEqual(perf.get("duplicate_class_scans", 0), 0)

    def test_member_index_task_reuses_cached_classfile_fast_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            classes = self._compile_java_fixture(
                tmp, "fixture/Consumer.java", """
                package fixture;
                public class Consumer {
                    public void run() { System.nanoTime(); }
                }
                """,
            )
            jar_path = Path(tmp) / "consumer.jar"
            self._jar_compiled_classes(jar_path, classes)
            class_entry = "fixture/Consumer.class"
            class_binary_name = "fixture.Consumer"
            artifact_sha256 = hashlib.sha256(jar_path.read_bytes()).hexdigest()
            graph = SimpleNamespace()
            tracer.clear_immutable_artifact_parse_cache()
            with zipfile.ZipFile(jar_path) as archive:
                class_bytes = archive.read(class_entry)
            expected = tracer._load_direct_classfile_references(
                class_bytes, artifact_sha256, "17", class_binary_name,
                multi_release_version="base", class_entry=class_entry, graph=graph,
            )
            task = {
                "catalog": {}, "coord": "fixture:consumer",
                "jar_path": str(jar_path), "class_binary_name": class_binary_name,
                "class_entry": class_entry, "artifact_sha256": artifact_sha256,
                "target_jdk": "17", "multi_release_version": "base", "graph": graph,
            }

            with patch.object(
                tracer, "_run_javap_bytecode_dump",
                side_effect=AssertionError("cached classfile parse must be reused"),
            ), patch.object(
                tracer.zipfile, "ZipFile",
                side_effect=AssertionError("cache hit must avoid reopening the JAR"),
            ):
                _task, actual = tracer._load_runtime_dependency_class_references_for_task(task)

        self.assertEqual(actual, expected)
        perf = tracer._finalize_step5_perf_stats(graph)["bytecode_scan"]
        self.assertEqual(perf.get("duplicate_class_scans", 0), 0)

    def test_member_index_task_reuses_batch_runtime_reference_cache_before_jar_io(self):
        graph = SimpleNamespace()
        catalog = {}
        artifact_sha256 = "d" * 64
        class_name = "fixture.Consumer"
        class_entry = "fixture/Consumer.class"
        expected = {"method_refs": [{"owner": "java.lang.System", "name": "nanoTime"}]}
        immutable_key = tracer._immutable_artifact_parse_cache_key(
            artifact_sha256, "17", class_name, "base", class_entry=class_entry
        )
        cache_key = ("fixture:consumer", "/missing/consumer.jar", *immutable_key)
        catalog["_bytecode_reference_cache"] = {cache_key: expected}
        catalog["_bytecode_reference_cache_generations"] = {
            cache_key: tracer._IMMUTABLE_ARTIFACT_PARSE_CACHE_GENERATION
        }
        task = {
            "catalog": catalog,
            "coord": "fixture:consumer",
            "jar_path": "/missing/consumer.jar",
            "class_binary_name": class_name,
            "class_entry": class_entry,
            "artifact_sha256": artifact_sha256,
            "target_jdk": "17",
            "multi_release_version": "base",
            "graph": graph,
        }

        with patch.object(
            tracer.zipfile, "ZipFile",
            side_effect=AssertionError("batch cache hit must avoid reopening the JAR"),
        ):
            _task, actual = tracer._load_runtime_dependency_class_references_for_task(task)

        self.assertEqual(actual, expected)

    def test_artifact_hash_parse_cache_never_decodes_an_invalidated_none_value(self):
        graph = SimpleNamespace()
        artifact_sha256 = "a" * 64
        immutable_key = tracer._immutable_artifact_parse_cache_key(
            artifact_sha256, "17", "com.example.TargetBridge", None
        )
        tracer.clear_immutable_artifact_parse_cache()
        tracer._IMMUTABLE_ARTIFACT_PARSE_CACHE[immutable_key] = None
        try:
            with patch.object(
                tracer, "_run_javap_bytecode_dump", return_value="public class com.example.TargetBridge {}"
            ) as mocked_javap:
                references = tracer._load_runtime_dependency_class_references(
                    {}, "com.vendor:target", "/tmp/target.jar", "com.example.TargetBridge",
                    artifact_sha256=artifact_sha256, target_jdk="17", graph=graph,
                )
        finally:
            tracer.clear_immutable_artifact_parse_cache()

        self.assertEqual(references["class_refs"], [])
        self.assertEqual(mocked_javap.call_count, 1)

    def test_artifact_hash_parse_cache_clear_isolates_post_clear_waiters(self):
        javap_output = "public class com.example.TargetBridge {}"
        graph = SimpleNamespace()
        first_parse_started = threading.Event()
        second_parse_started = threading.Event()
        release_first_parse = threading.Event()
        release_second_parse = threading.Event()
        old_waiter_woken = threading.Event()
        release_old_waiter = threading.Event()
        created_events = []
        calls = 0

        class TrackingEvent:
            def __init__(self):
                self.event = threading.Event()
                self.sequence = len(created_events)
                created_events.append(self)

            def set(self):
                self.event.set()

            def wait(self, timeout=None):
                result = self.event.wait(timeout)
                if self.sequence == 0:
                    old_waiter_woken.set()
                    release_old_waiter.wait(timeout=1)
                return result

        def load_references():
            return tracer._load_runtime_dependency_class_references(
                {}, "com.vendor:target", "/tmp/target.jar", "com.example.TargetBridge",
                artifact_sha256="a" * 64, target_jdk="17", graph=graph,
            )

        def delayed_javap(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                first_parse_started.set()
                self.assertTrue(release_first_parse.wait(timeout=1))
            elif calls == 2:
                second_parse_started.set()
                self.assertTrue(release_second_parse.wait(timeout=1))
            return javap_output

        tracer.clear_immutable_artifact_parse_cache()
        executor = ThreadPoolExecutor(max_workers=4)
        try:
            with patch.object(tracer, "Event", TrackingEvent), patch.object(
                tracer, "_run_javap_bytecode_dump", side_effect=delayed_javap
            ):
                first_owner = executor.submit(load_references)
                self.assertTrue(first_parse_started.wait(timeout=1))
                old_waiter = executor.submit(load_references)
                deadline = time.time() + 1
                while len(created_events) < 1 and time.time() < deadline:
                    time.sleep(0.005)
                tracer.clear_immutable_artifact_parse_cache()
                self.assertTrue(old_waiter_woken.wait(timeout=1))

                post_clear_owner = executor.submit(load_references)
                self.assertTrue(second_parse_started.wait(timeout=1))
                post_clear_waiter = executor.submit(load_references)
                release_first_parse.set()
                first_owner.result(timeout=1)

                self.assertFalse(post_clear_waiter.done())
                release_old_waiter.set()
                release_second_parse.set()
                self.assertEqual(post_clear_owner.result(timeout=1), post_clear_waiter.result(timeout=1))
                old_waiter.result(timeout=1)
        finally:
            release_first_parse.set()
            release_second_parse.set()
            release_old_waiter.set()
            for event in created_events:
                event.set()
            executor.shutdown(wait=True)
            tracer.clear_immutable_artifact_parse_cache()

    def test_runtime_parse_cache_uses_javap_once_and_never_constant_pool(self):
        graph = SimpleNamespace()
        catalog = {}
        artifact_sha256 = "a" * 64
        javap_output = """
public class com.example.TargetBridge {
  public void use(java.lang.String);
    descriptor: (Ljava/lang/String;)V
    Code:
       0: invokestatic #7 // Method com/vendor/Target.removed:(Ljava/lang/String;)V
}
"""

        tracer.clear_immutable_artifact_parse_cache()
        try:
            with patch.object(
                tracer, "_run_javap_bytecode_dump", return_value=javap_output,
            ) as mocked_javap, patch.object(
                tracer, "_parse_classfile_constant_pool_summary",
                side_effect=AssertionError("constant pool must not be parsed for runtime evidence"),
            ):
                first = tracer._load_runtime_dependency_class_references(
                    catalog, "com.vendor:target", "/tmp/target.jar",
                    "com.example.TargetBridge", artifact_sha256=artifact_sha256,
                    target_jdk="17", graph=graph,
                )
                second = tracer._load_runtime_dependency_class_references(
                    catalog, "com.vendor:target", "/tmp/target.jar",
                    "com.example.TargetBridge", artifact_sha256=artifact_sha256,
                    target_jdk="17", graph=graph,
                )
        finally:
            tracer.clear_immutable_artifact_parse_cache()

        perf = tracer._finalize_step5_perf_stats(graph)["bytecode_scan"]
        self.assertEqual(first, second)
        self.assertEqual(mocked_javap.call_count, 1)
        self.assertEqual(perf["class_entries_parsed"], 1)
        self.assertEqual(perf.get("duplicate_class_scans", 0), 0)

    def test_catalog_parse_cache_varies_by_sha_jdk_and_procedure_at_same_path(self):
        graph = SimpleNamespace()
        catalog = {}
        jar_path = "/tmp/replaced-in-place.jar"
        class_name = "com.example.TargetBridge"

        def javap_for(owner):
            return f'''\npublic class {class_name} {{\n  public void use();\n    descriptor: ()V\n    Code:\n       0: checkcast #7 // class {owner.replace('.', '/')}\n}}\n'''

        outputs = [
            javap_for("com.vendor.First"),
            javap_for("com.vendor.Second"),
            javap_for("com.vendor.Third"),
            javap_for("com.vendor.Fourth"),
        ]

        tracer.clear_immutable_artifact_parse_cache()
        try:
            with patch.object(
                tracer, "_run_javap_bytecode_dump", side_effect=outputs,
            ) as mocked_javap:
                first = tracer._load_runtime_dependency_class_references(
                    catalog, "com.vendor:target", jar_path, class_name,
                    artifact_sha256="a" * 64, target_jdk="17", graph=graph,
                )
                second = tracer._load_runtime_dependency_class_references(
                    catalog, "com.vendor:target", jar_path, class_name,
                    artifact_sha256="b" * 64, target_jdk="17", graph=graph,
                )
                third = tracer._load_runtime_dependency_class_references(
                    catalog, "com.vendor:target", jar_path, class_name,
                    artifact_sha256="b" * 64, target_jdk="21", graph=graph,
                )
                with patch.object(
                    tracer, "ARTIFACT_PARSE_CACHE_PROCEDURE_VERSION",
                    tracer.ARTIFACT_PARSE_CACHE_PROCEDURE_VERSION + "-next",
                ):
                    fourth = tracer._load_runtime_dependency_class_references(
                        catalog, "com.vendor:target", jar_path, class_name,
                        artifact_sha256="b" * 64, target_jdk="21", graph=graph,
                    )
        finally:
            tracer.clear_immutable_artifact_parse_cache()

        self.assertEqual(mocked_javap.call_count, 4)
        self.assertEqual(
            [item["class_refs"][-1] for item in (first, second, third, fourth)],
            ["com.vendor.First", "com.vendor.Second", "com.vendor.Third", "com.vendor.Fourth"],
        )

    def test_declaration_only_javap_reference_does_not_match_but_instruction_does(self):
        api_row = {
            "api_name": "com.vendor.Target.removed",
            "api_signature": "(String)",
            "symbol_kind": "method",
        }
        declaration_only = """
Constant pool:
   #7 = Methodref #8.#9 // com/vendor/Target.removed:(Ljava/lang/String;)V
public class com.example.TargetBridge {
  public void use(java.lang.String);
    descriptor: (Ljava/lang/String;)V
}
"""
        executable = declaration_only.replace(
            "    descriptor: (Ljava/lang/String;)V\n}",
            "    descriptor: (Ljava/lang/String;)V\n    Code:\n"
            "       0: invokestatic #7 // Method com/vendor/Target.removed:(Ljava/lang/String;)V\n}",
        )

        declaration_refs = tracer._parse_javap_bytecode_references(
            declaration_only, "com.example.TargetBridge"
        )
        executable_refs = tracer._parse_javap_bytecode_references(
            executable, "com.example.TargetBridge"
        )

        self.assertEqual(tracer._match_runtime_dependency_references(api_row, declaration_refs), [])
        matches = tracer._match_runtime_dependency_references(api_row, executable_refs)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["opcode_family"], "invokestatic")
        self.assertEqual(matches[0]["instruction_offset"], 0)

    def test_runtime_member_matchers_reject_wrong_opcode_families(self):
        method = {
            "api_name": "com.vendor.Target.call",
            "api_signature": "()",
            "symbol_kind": "method",
        }
        field = {
            "api_name": "com.vendor.Target.value",
            "api_signature": "",
            "symbol_kind": "field",
        }
        bad_method = {
            "callee_owner": "com.vendor.Target", "callee_member": "call",
            "callee_descriptor": "()V", "opcode_family": "getstatic",
        }
        bad_field = {
            "callee_owner": "com.vendor.Target", "callee_member": "value",
            "callee_descriptor": "I", "opcode_family": "invokevirtual",
        }
        references = {
            "method_refs": [{
                "owner": "com.vendor.Target", "name": "call",
                "descriptor": "()V", "opcode_family": "getstatic",
                "instruction_offset": 0, "consumer_method": "run",
                "consumer_signature": "()",
            }],
        }

        self.assertFalse(tracer._runtime_reference_edge_matches_api(method, bad_method))
        self.assertFalse(tracer._runtime_reference_edge_matches_api(field, bad_field))
        self.assertEqual(tracer._match_runtime_dependency_references(method, references), [])

    def test_runtime_field_matcher_accepts_verified_reflection_invocation_opcode(self):
        field = {
            "api_name": "com.vendor.Target.value",
            "api_signature": "",
            "symbol_kind": "field",
        }
        references = {
            "field_refs": [{
                "owner": "com.vendor.Target", "name": "value",
                "descriptor": "", "opcode_family": "invokevirtual",
                "instruction_offset": 12, "consumer_method": "run",
                "consumer_signature": "()", "reference_kind": "reflection_field",
            }],
        }

        matches = tracer._match_runtime_dependency_references(field, references)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["evidence_type"], "bytecode_reflection_field_access")
        self.assertEqual(matches[0]["opcode_family"], "invokevirtual")

    def test_class_topology_requires_executable_type_instruction(self):
        api_row = {
            "api_name": "com.vendor.TargetType",
            "api_signature": "",
            "symbol_kind": "class",
            "analysis_scope": "class_usage",
        }
        declaration_only = '''
public class com.example.TargetBridge {
  public void use(com.vendor.TargetType);
    descriptor: (Lcom/vendor/TargetType;)V
}
'''
        executable = declaration_only.replace(
            "    descriptor: (Lcom/vendor/TargetType;)V\n}",
            "    descriptor: (Lcom/vendor/TargetType;)V\n    Code:\n"
            "       0: checkcast #7 // class com/vendor/TargetType\n}",
        )

        declaration_refs = tracer._parse_javap_bytecode_references(
            declaration_only, "com.example.TargetBridge"
        )
        executable_refs = tracer._parse_javap_bytecode_references(
            executable, "com.example.TargetBridge"
        )

        self.assertEqual(tracer._match_runtime_dependency_references(api_row, declaration_refs), [])
        matches = tracer._match_runtime_dependency_references(api_row, executable_refs)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["opcode_family"], "checkcast")
        self.assertEqual(matches[0]["instruction_offset"], 0)

    def test_class_topology_ignores_self_member_instructions(self):
        api_row = {
            "api_name": "com.vendor.TargetType",
            "api_signature": "",
            "symbol_kind": "class",
            "analysis_scope": "class_usage",
        }
        javap_output = '''
public class com.vendor.TargetType {
  private java.lang.Object value;
  public java.lang.Object read();
    descriptor: ()Ljava/lang/Object;
    Code:
       0: aload_0
       1: getfield #7 // Field value:Ljava/lang/Object;
       4: areturn
}
'''
        references = tracer._parse_javap_bytecode_references(
            javap_output, "com.vendor.TargetType"
        )

        self.assertEqual(
            tracer._match_runtime_dependency_references(api_row, references),
            [],
        )

    def test_external_class_constant_is_weak_usage_but_self_declaration_is_not(self):
        api_row = {
            "api_name": "com.vendor.TargetType",
            "api_signature": "",
            "symbol_kind": "class",
            "analysis_scope": "class_usage",
        }
        references = {"class_refs": {"com.vendor.TargetType"}}

        external = tracer._match_runtime_dependency_class_constants(
            api_row, references, caller_owner="com.consumer.Adapter"
        )
        self_reference = tracer._match_runtime_dependency_class_constants(
            api_row, references, caller_owner="com.vendor.TargetType"
        )

        self.assertEqual(len(external), 1)
        self.assertEqual(
            external[0]["evidence_type"], "bytecode_class_constant_reference"
        )
        self.assertTrue(external[0]["weak_reference"])
        self.assertEqual(self_reference, [])

    def test_only_exact_target_method_self_call_is_excluded(self):
        api_row = {
            "api_name": "com.vendor.Target.changed",
            "api_signature": "(String)",
            "symbol_kind": "method",
        }

        self.assertTrue(tracer._is_exact_target_self_reference(
            api_row,
            "com.vendor.Target",
            {
                "consumer_method": "changed",
                "consumer_descriptor": "(Ljava/lang/String;)Ljava/lang/String;",
                "callee_descriptor": "(Ljava/lang/String;)Ljava/lang/String;",
            },
        ))
        self.assertFalse(tracer._is_exact_target_self_reference(
            api_row,
            "com.vendor.Target",
            {
                "consumer_method": "entry",
                "consumer_descriptor": "(Ljava/lang/String;)Ljava/lang/String;",
                "callee_descriptor": "(Ljava/lang/String;)Ljava/lang/String;",
            },
        ))
        self.assertFalse(tracer._is_exact_target_self_reference(
            {**api_row, "api_name": "com.vendor.Target.value", "symbol_kind": "field"},
            "com.vendor.Target",
            {"consumer_method": "changed", "consumer_descriptor": "()V"},
        ))

    def test_same_named_fqcn_overload_and_constructor_delegate_are_not_self_recursion(self):
        overloaded = {
            "api_name": "com.vendor.Target.changed",
            "api_signature": "(com.bar.Request)",
            "symbol_kind": "method",
        }
        constructor = {
            "api_name": "com.vendor.Target.Target",
            "api_signature": "(com.bar.Request)",
            "symbol_kind": "constructor",
        }
        reference = {
            "consumer_method": "changed",
            "consumer_descriptor": "(Lcom/foo/Request;)Ljava/lang/Object;",
            "callee_descriptor": "(Lcom/bar/Request;)Ljava/lang/Object;",
        }

        self.assertFalse(tracer._is_exact_target_self_reference(
            overloaded, "com.vendor.Target", reference
        ))
        self.assertFalse(tracer._is_exact_target_self_reference(
            constructor,
            "com.vendor.Target",
            {
                "consumer_method": "<init>",
                "consumer_descriptor": "(Lcom/foo/Request;)V",
                "callee_descriptor": "(Lcom/bar/Request;)V",
            },
        ))

    def test_batch_runtime_scan_ignores_constant_pool_match_without_instruction(self):
        api_row = {
            "coord": "com.vendor:api",
            "api_name": "com.vendor.Target.removed",
            "api_simple": "removed",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        unsafe_summary = {
            "class_internal_names": {"com/vendor/Target"},
            "ref_internal_names": {"com/vendor/Target"},
            "ref_member_names": {"removed"},
            "ref_member_descriptors": {"(Ljava/lang/String;)V"},
            "ref_members": [{
                "tag": 10,
                "owner": "com/vendor/Target",
                "name": "removed",
                "descriptor": "(Ljava/lang/String;)V",
            }],
            "has_dynamic_reference": False,
            "utf8_values": set(),
        }
        declaration_only = """
Constant pool:
   #7 = Methodref #8.#9 // com/vendor/Target.removed:(Ljava/lang/String;)V
public class com.example.TargetBridge {
  public void use(java.lang.String);
    descriptor: (Ljava/lang/String;)V
}
"""

        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "consumer.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr(
                    "com/example/TargetBridge.class",
                    b"com/vendor/Target removed fixture-class-bytes",
                )
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog=self._runtime_catalog((("sample:consumer", jar_path),)),
            )

            tracer.clear_immutable_artifact_parse_cache()
            with patch.object(
                tracer, "_parse_classfile_constant_pool_summary", return_value=unsafe_summary,
            ) as mocked_constant_pool, patch.object(
                tracer, "_run_javap_bytecode_dump", return_value=declaration_only,
            ) as mocked_javap:
                scans = tracer._build_packaged_runtime_dependency_scan_cache([api_row], graph)

        self.assertEqual(scans[tracer.build_api_identity_key(api_row)]["status"], "miss")
        mocked_constant_pool.assert_not_called()
        mocked_javap.assert_called_once()
        perf = tracer._finalize_step5_perf_stats(graph)["bytecode_scan"]
        self.assertEqual(perf["class_entries_parsed"], 1)
        self.assertEqual(perf["duplicate_class_scans"], 0)

    def test_artifact_hash_parse_cache_clear_does_not_store_preclear_result_in_same_catalog(self):
        graph = SimpleNamespace()
        catalog = {}
        parse_started = threading.Event()
        release_first_parse = threading.Event()
        calls = 0

        def delayed_javap(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                parse_started.set()
                self.assertTrue(release_first_parse.wait(timeout=1))
            return "public class com.example.TargetBridge {}"

        def load_references():
            return tracer._load_runtime_dependency_class_references(
                catalog, "com.vendor:target", "/tmp/target.jar", "com.example.TargetBridge",
                artifact_sha256="a" * 64, target_jdk="17", graph=graph,
            )

        tracer.clear_immutable_artifact_parse_cache()
        executor = ThreadPoolExecutor(max_workers=1)
        try:
            with patch.object(tracer, "_run_javap_bytecode_dump", side_effect=delayed_javap):
                preclear_owner = executor.submit(load_references)
                self.assertTrue(parse_started.wait(timeout=1))
                tracer.clear_immutable_artifact_parse_cache()
                release_first_parse.set()
                preclear_owner.result(timeout=1)
                load_references()
        finally:
            release_first_parse.set()
            executor.shutdown(wait=True)
            tracer.clear_immutable_artifact_parse_cache()

        self.assertEqual(calls, 2)

    def test_duplicate_class_scans_requires_a_physical_artifact_identity(self):
        javap_output = """
public class com.example.TargetBridge {
  public void use(java.lang.String);
    descriptor: (Ljava/lang/String;)V
    Code:
       0: invokestatic #7 // Method com/vendor/Target.removed:(Ljava/lang/String;)V
}
"""
        graph = SimpleNamespace()

        def load_references(jar_path):
            return tracer._load_runtime_dependency_class_references(
                {}, "com.vendor:target", jar_path, "com.example.TargetBridge",
                target_jdk="17", graph=graph,
            )

        tracer.clear_immutable_artifact_parse_cache()
        with patch.object(tracer, "_run_javap_bytecode_dump", return_value=javap_output):
            load_references("/tmp/first.jar")
            load_references("/tmp/second.jar")

        perf = tracer._finalize_step5_perf_stats(graph)["bytecode_scan"]
        self.assertEqual(perf["class_entries_parsed"], 2)
        self.assertEqual(perf.get("duplicate_class_scans", 0), 0)

    def test_artifact_hash_parse_cache_clear_releases_inflight_waiters(self):
        javap_output = """
public class com.example.TargetBridge {
  public void use(java.lang.String);
    descriptor: (Ljava/lang/String;)V
    Code:
       0: invokestatic #7 // Method com/vendor/Target.removed:(Ljava/lang/String;)V
}
"""
        graph = SimpleNamespace()
        parse_started = threading.Event()
        release_first_parse = threading.Event()
        waiter_waiting = threading.Event()
        created_events = []
        calls = 0

        class TrackingEvent:
            def __init__(self):
                self.event = threading.Event()
                created_events.append(self)

            def set(self):
                self.event.set()

            def wait(self, timeout=None):
                waiter_waiting.set()
                return self.event.wait(timeout)

        def load_references():
            return tracer._load_runtime_dependency_class_references(
                {}, "com.vendor:target", "/tmp/target.jar", "com.example.TargetBridge",
                artifact_sha256="a" * 64, target_jdk="17", graph=graph,
            )

        def delayed_javap(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                parse_started.set()
                self.assertTrue(release_first_parse.wait(timeout=1))
            return javap_output

        tracer.clear_immutable_artifact_parse_cache()
        executor = ThreadPoolExecutor(max_workers=2)
        try:
            with patch.object(tracer, "Event", TrackingEvent), patch.object(
                tracer, "_run_javap_bytecode_dump", side_effect=delayed_javap
            ):
                first_future = executor.submit(load_references)
                self.assertTrue(parse_started.wait(timeout=1))
                second_future = executor.submit(load_references)
                self.assertTrue(waiter_waiting.wait(timeout=1))

                tracer.clear_immutable_artifact_parse_cache()
                release_first_parse.set()
                first = first_future.result(timeout=1)
                second = second_future.result(timeout=1)

            self.assertEqual(first, second)
        finally:
            release_first_parse.set()
            for event in created_events:
                event.set()
            executor.shutdown(wait=True)
            tracer.clear_immutable_artifact_parse_cache()

    def test_step5_perf_counters_are_thread_safe_and_tie_sorted_deterministically(self):
        graph = SimpleNamespace()
        worker_count = 8
        ready = threading.Barrier(worker_count)

        def update_counters(sequence):
            ready.wait(timeout=1)
            for _ in range(500):
                tracer._perf_add(graph, "bytecode_scan", "concurrent_updates", 1)
            tracer._perf_max(graph, "bytecode_scan", "concurrent_max", sequence)
            time.sleep((worker_count - sequence) * 0.01)
            tracer._perf_record_top(
                graph,
                "bytecode_scan",
                "equal_elapsed_items",
                {"sequence": sequence, "elapsed_sec": 1.0},
            )

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            list(executor.map(update_counters, range(worker_count)))

        perf = tracer._finalize_step5_perf_stats(graph)["bytecode_scan"]
        self.assertEqual(perf["concurrent_updates"], worker_count * 500)
        self.assertEqual(perf["concurrent_max"], worker_count - 1)
        self.assertEqual(
            [item["sequence"] for item in perf["equal_elapsed_items"]],
            list(range(worker_count)),
        )

    def test_scan_role_metrics_are_classified_for_each_matched_api_coordinate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "src"
            target_a = source_root / "com/vendor/TargetA.java"
            target_b = source_root / "com/other/TargetB.java"
            bridge = source_root / "com/example/TargetBridge.java"
            for source in (target_a, target_b, bridge):
                source.parent.mkdir(parents=True, exist_ok=True)
            target_a.write_text(
                "package com.vendor; public class TargetA { public static void removed() {} }",
                encoding="utf-8",
            )
            target_b.write_text(
                "package com.other; public class TargetB { public static void removed() {} }",
                encoding="utf-8",
            )
            bridge.write_text(
                "package com.example; public class TargetBridge { public void use() { "
                "com.vendor.TargetA.removed(); com.other.TargetB.removed(); } }",
                encoding="utf-8",
            )
            classes = self._compile_java_files(root / "classes", [target_a, target_b, bridge])
            jar_path = root / "targets.jar"
            self._jar_compiled_classes(jar_path, classes)
            api_a = {
                "coord": "com.vendor:target-a",
                "api_name": "com.vendor.TargetA.removed",
                "api_simple": "removed",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
            api_b = {
                "coord": "com.other:target-b",
                "api_name": "com.other.TargetB.removed",
                "api_simple": "removed",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
            item = {
                "coord": api_a["coord"],
                "jar_path": str(jar_path),
                "artifact_entry": "BOOT-INF/lib/targets.jar",
            }
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={"force_javap_path": []},
                runtime_dependency_catalog={
                    "status": "complete",
                    "entries": [item],
                    "by_coord": {item["coord"]: item},
                    "target_jdk": "17",
                },
            )
            javap_output = """
public class com.example.TargetBridge {
  public void use();
    descriptor: ()V
    Code:
       0: invokestatic #7 // Method com/vendor/TargetA.removed:()V
       3: invokestatic #9 // Method com/other/TargetB.removed:()V
}
"""

            def javap_for_class(_jar_path, class_binary_name, **_kwargs):
                if class_binary_name == "com.example.TargetBridge":
                    return javap_output
                return f"public class {class_binary_name} {{}}"

            tracer.clear_immutable_artifact_parse_cache()
            with patch.object(tracer, "_run_javap_bytecode_dump", side_effect=javap_for_class):
                results = tracer._build_packaged_runtime_dependency_scan_cache([api_a, api_b], graph)

        perf = tracer._finalize_step5_perf_stats(graph)["bytecode_scan"]
        self.assertEqual(results[tracer.build_api_identity_key(api_a)]["hits"][0]["edge_role"], "internal_bridge")
        self.assertEqual(results[tracer.build_api_identity_key(api_b)]["hits"][0]["edge_role"], "external_consumer")
        self.assertEqual(perf["internal_bridge_class_scans"], 1)
        self.assertEqual(perf["direct_consumer_class_scans"], 1)

    def test_many_packaged_hits_enable_runtime_member_index_preference(self):
        graph = SimpleNamespace(methods_by_id={}, reverse_edges={}, runtime_dependency_catalog={})
        result = tracer.TraceResult(
            api_name="org.apache.commons.lang.StringUtils.isBlank",
            api_simple="isBlank",
            api_signature="(String)",
            symbol_kind="method",
            change_type="REMOVED",
            coord="org.apache.commons:commons-lang",
            severity="P1",
            confirmed=True,
            source="unit",
            analysis_scope="method",
            analysis_status="",
            direct_callers=0,
            is_reachable=None,
            reachable_note="",
            business_reach_depth=0,
            dependency_chain_coords=[],
            call_paths=[],
            evidence_paths=[],
            reason_code="",
            verification_commands=[],
            hops=[],
            confidence_score=0.0,
            critical_nodes_hit=[],
        )
        hits = [
            {
                "coord": f"com.example:dep-{idx}",
                "jar_path": f"/tmp/dep-{idx}.jar",
                "class_fqcn": f"com.dep{idx}.Bridge",
                "consumer_method": "use",
                "consumer_signature": "(String)",
                "target_display": "org.apache.commons.lang.StringUtils.isBlank(String)",
            }
            for idx in range(8)
        ]

        draft = self._draft_from_result(result)
        tracer._build_packaged_dependency_hit_result(draft, hits, graph)

        self.assertTrue(graph._prefer_runtime_dependency_member_candidate_index)

    def test_analyze_file_ignores_fully_block_commented_java_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            java_file = Path(tmp) / "Demo.java"
            java_file.write_text(
                "\n".join(
                    [
                        "/*",
                        "package com.example;",
                        "public class Demo {",
                        "    public String foo() {",
                        '        return "x";',
                        "    }",
                        "}",
                        "*/",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            methods, parser_info = source_analyzer.analyze_file(
                str(java_file),
                {"root": tmp, "owner_type": "business", "owner_coord": "BUSINESS", "module": "app"},
                return_diagnostics=True,
            )

            self.assertEqual(methods, [])
            self.assertEqual(parser_info["actual_parser"], "skipped")
            self.assertTrue(parser_info["fallback_reason"].startswith("tree_sitter_runtime_error:"))

    def test_analyze_file_ignores_block_commented_structure_but_keeps_real_method(self):
        with tempfile.TemporaryDirectory() as tmp:
            java_file = Path(tmp) / "Demo.java"
            java_file.write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "/*",
                        "public class OldDemo {",
                        "    public String removed() {",
                        '        return "old";',
                        "    }",
                        "}",
                        "*/",
                        "public class Demo {",
                        "    public String live() {",
                        '        return "new";',
                        "    }",
                        "}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            methods, parser_info = source_analyzer.analyze_file(
                str(java_file),
                {"root": tmp, "owner_type": "business", "owner_coord": "BUSINESS", "module": "app"},
                return_diagnostics=True,
            )

            self.assertEqual(parser_info["actual_parser"], "tree_sitter")
            self.assertEqual(
                [(method.class_fqcn, method.method_name) for method in methods],
                [("com.example.Demo", "live")],
            )

    def test_analyze_file_uses_preinstalled_tree_sitter_without_runtime_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            java_file = Path(tmp) / "Demo.java"
            java_file.write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "public class Demo {",
                        "    public void run() {",
                        "    }",
                        "}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            sentinel_method = SimpleNamespace(method_name="run")

            class FakeTreeSitterAnalyzer:
                error_nodes = 0
                non_empty_source = True
                has_type_declarations = True

                def __init__(self, file_path, source_root):
                    self.file_path = file_path
                    self.source_root = source_root

                def analyze(self):
                    return [sentinel_method]

            def fake_ensure_tree_sitter_available():
                source_analyzer.TREE_SITTER_AVAILABLE = True
                return True

            with patch.object(source_analyzer, "TREE_SITTER_AVAILABLE", False), patch.object(
                source_analyzer,
                "TREE_SITTER_AUTO_INSTALL_ATTEMPTED",
                False,
            ), patch.object(
                source_analyzer,
                "TREE_SITTER_AUTO_INSTALL_ERROR",
                "",
            ), patch.object(
                source_analyzer,
                "_ensure_tree_sitter_available",
                side_effect=fake_ensure_tree_sitter_available,
            ) as ensure_mock, patch.object(
                source_analyzer,
                "TreeSitterAnalyzer",
                FakeTreeSitterAnalyzer,
            ):
                methods, parser_info = source_analyzer.analyze_file(
                    str(java_file),
                    {"root": tmp, "owner_type": "business", "owner_coord": "BUSINESS", "module": "app"},
                    return_diagnostics=True,
                )

            ensure_mock.assert_called_once()
            self.assertEqual(methods, [sentinel_method])
            self.assertEqual(parser_info["actual_parser"], "tree_sitter")
            self.assertTrue(parser_info["tree_sitter_available"])
            self.assertFalse(parser_info["tree_sitter_auto_install_attempted"])
            self.assertEqual(parser_info["tree_sitter_auto_install_error"], "")

    def test_analyze_file_records_missing_tree_sitter_without_runtime_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            java_file = Path(tmp) / "Demo.java"
            java_file.write_text(
                "package com.example; public class Demo { public void run() {} }\n",
                encoding="utf-8",
            )

            def fake_ensure_tree_sitter_available():
                return False

            with patch.object(source_analyzer, "TREE_SITTER_AVAILABLE", False), patch.object(
                source_analyzer,
                "TREE_SITTER_AUTO_INSTALL_ATTEMPTED",
                False,
            ), patch.object(
                source_analyzer,
                "TREE_SITTER_AUTO_INSTALL_ERROR",
                "",
            ), patch.object(
                source_analyzer,
                "_ensure_tree_sitter_available",
                side_effect=fake_ensure_tree_sitter_available,
            ) as ensure_mock:
                methods, parser_info = source_analyzer.analyze_file(
                    str(java_file),
                    {"root": tmp, "owner_type": "business", "owner_coord": "BUSINESS", "module": "app"},
                    return_diagnostics=True,
                )

            ensure_mock.assert_called_once()
            self.assertEqual(methods, [])
            self.assertEqual(parser_info["actual_parser"], "skipped")
            self.assertEqual(parser_info["fallback_reason"], "tree_sitter_unavailable")
            self.assertFalse(parser_info["tree_sitter_auto_install_attempted"])
            self.assertEqual(parser_info["tree_sitter_auto_install_error"], "")

    def test_format_call_chain_outputs_every_hop_in_forward_order(self):
        direct = SimpleNamespace(
            caller_qualified_key="com.dep.B.callC", caller_symbol_id="b",
            callee_key="com.changed.C.removed",
        )
        upstream = SimpleNamespace(
            caller_qualified_key="com.app.A.callB", caller_symbol_id="a",
            callee_key="com.dep.B.callC",
        )
        self.assertEqual(
            tracer.format_call_chain([direct, upstream], "com.changed.C.removed()"),
            "com.app.A.callB → com.dep.B.callC → com.changed.C.removed → 变更API: com.changed.C.removed()",
        )

    def test_format_call_chain_keeps_actual_callee_and_ends_with_changed_api(self):
        direct = SimpleNamespace(
            caller_qualified_key="org.apache.dubbo.metrics.model.MetricsSupport.getGroup",
            caller_symbol_id="m",
            callee_key="org.apache.dubbo.rpc.model.ServiceMetadata.getGroup()",
        )

        self.assertEqual(
            tracer.format_call_chain(
                [direct],
                "org.apache.dubbo.common.BaseServiceMetadata.getGroup()",
            ),
            (
                "org.apache.dubbo.metrics.model.MetricsSupport.getGroup"
                " → org.apache.dubbo.rpc.model.ServiceMetadata.getGroup()"
                " → 变更API: org.apache.dubbo.common.BaseServiceMetadata.getGroup()"
            ),
        )

    def test_inlined_constant_miss_remains_uncertain(self):
        draft = tracer._new_trace_draft({
            "api_name": "com.vendor.Flags.RETRY_LIMIT",
            "api_simple": "RETRY_LIMIT",
            "symbol_kind": "field",
            "change_type": "CONSTANT_VALUE_CHANGED",
            "coord": "com.vendor:flags",
        })
        tracer._build_inlined_constant_result(draft)
        updated = tracer._finalize_trace_draft(draft)
        self.assertEqual(updated.analysis_status, "uncertain")
        self.assertIsNone(updated.is_reachable)
        self.assertEqual(updated.reason_code, "INLINED_CONSTANT_USAGE_UNDETECTABLE")

    def test_field_type_change_is_not_treated_as_an_inlined_constant(self):
        self.assertFalse(tracer._is_inlined_constant_change({
            "api_name": "com.vendor.Dto.value",
            "symbol_kind": "field",
            "change_type": "DATA_FIELD_TYPE_CHANGED",
            "compatibility_flags": "DATA_CONTRACT_CHANGE",
            "old_value": "com.vendor.OldType",
            "new_value": "com.vendor.NewType",
        }))

    def test_complete_bytecode_miss_cannot_clear_changed_inlined_constant(self):
        api_row = {
            "coord": "com.vendor:flags",
            "api_name": "com.vendor.Flags.RETRY_LIMIT",
            "api_simple": "RETRY_LIMIT",
            "api_signature": "int",
            "symbol_kind": "field",
            "change_type": "CONSTANT_VALUE_CHANGED",
            "old_value": "3",
            "new_value": "5",
            "severity": "P1",
            "confirmed": "true",
        }
        graph = SimpleNamespace(methods_by_id={}, reverse_edges={})

        with patch.object(
            tracer,
            "_scan_packaged_runtime_dependencies_for_api",
            return_value={"status": "miss", "hits": []},
        ):
            result = tracer.trace_api_with_confidence_weighting(
                api_row,
                graph,
                {},
                has_packaged_bytecode_fallback=True,
            )

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertIsNone(result.is_reachable)
        self.assertEqual(result.reason_code, "INLINED_CONSTANT_USAGE_UNDETECTABLE")

    def test_path_dominance_keeps_longer_high_confidence_alternative(self):
        frontier = [(1, 0.35)]

        dominated, updated = tracer.update_path_frontier(
            frontier,
            cost=3,
            confidence=1.0,
        )

        self.assertFalse(dominated)
        self.assertEqual(updated, [(1, 0.35), (3, 1.0)])

    def test_path_dominance_rejects_strictly_worse_alternative(self):
        dominated, updated = tracer.update_path_frontier(
            [(2, 0.8)],
            cost=3,
            confidence=0.7,
        )

        self.assertTrue(dominated)
        self.assertEqual(updated, [(2, 0.8)])

    def test_jpa_lifecycle_entry_has_human_readable_kind(self):
        method_def = SimpleNamespace(
            annotations=["PrePersist"],
            class_annotations=["Entity"],
            owner_type="business",
        )

        kind = tracer.critical_node_entry_kind(method_def)

        self.assertEqual(kind, "jpa_lifecycle_callback")
        self.assertEqual(
            formatter._alert_entry_kind({"entry_kind": kind, "business_reachable": True}),
            "JPA 实体生命周期回调",
        )

    def test_is_system_code_touched_allows_business_service_impl(self):
        method_def = SimpleNamespace(
            owner_type="business",
            class_name="OrderServiceImpl",
            class_fqcn="com.example.OrderServiceImpl",
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            is_test=False,
        )

        self.assertTrue(tracer.is_system_code_touched(method_def, {}))

    def test_is_system_code_touched_allows_plain_business_impl(self):
        method_def = SimpleNamespace(
            owner_type="business",
            class_name="FooImpl",
            class_fqcn="com.example.FooImpl",
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            is_test=False,
        )

        self.assertTrue(tracer.is_system_code_touched(method_def, {}))

    def test_is_system_code_touched_excludes_test_code(self):
        method_def = SimpleNamespace(
            owner_type="business",
            class_name="OrderServiceTest",
            class_fqcn="com.example.OrderServiceTest",
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            is_test=True,
        )

        self.assertFalse(tracer.is_system_code_touched(method_def, {}))

    def test_build_api_target_keys_keeps_precise_fqcn_keys_without_simple_fallback(self):
        keys = tracer.build_api_target_keys(
            {
                "api_name": "com.example.service.OverloadService.target",
                "api_simple": "target",
                "symbol_kind": "method",
                "api_signature": "(java.lang.String)",
            }
        )

        self.assertEqual(
            keys,
            [
                "com.example.service.OverloadService.target(java.lang.String)",
                "com.example.service.OverloadService.target(String)",
                "com.example.service.OverloadService.target",
            ],
        )

    def test_get_symbol_kind_infers_method_from_signature_for_legacy_csv(self):
        self.assertEqual(
            tracer.get_symbol_kind(
                {
                    "api_name": "com.example.OwnerRepository.findById",
                    "api_simple": "findById",
                    "api_signature": "(Integer)",
                    "symbol_kind": "",
                }
            ),
            "method",
        )

    def test_get_symbol_kind_infers_class_from_capitalized_fqcn_without_signature(self):
        self.assertEqual(
            tracer.get_symbol_kind(
                {
                    "api_name": "com.example.OwnerController",
                    "api_simple": "",
                    "api_signature": "",
                    "symbol_kind": "",
                }
            ),
            "class",
        )

    def test_resolve_type_fqn_expands_imported_outer_inner_class(self):
        method_def = SimpleNamespace(
            class_name="NestedBridgeApp",
            class_fqcn="com.example.NestedBridgeApp",
            imports={"NestedAdapter": "com.example.adapter.NestedAdapter"},
            field_types={},
            param_types={},
            package_name="com.example",
        )

        self.assertEqual(
            source_analyzer.resolve_type_fqn("NestedAdapter.Inner", method_def),
            "com.example.adapter.NestedAdapter.Inner",
        )

    def test_get_lookup_keys_demotes_simple_key_to_last_fallback(self):
        method_def = SimpleNamespace(
            qualified_key="com.example.service.OverloadService.target",
            simple_key="method:target",
            class_fqcn="com.example.service.OverloadService",
            method_name="target",
            param_types={"value": "java.lang.String"},
            param_declared_types={"value": "String"},
        )
        type_metadata = {
            "com.example.service.OverloadService": {
                "extends": ["com.example.service.BaseService"],
                "implements": ["com.example.service.TargetApi"],
            }
        }

        keys = tracer.get_lookup_keys(method_def, type_metadata)

        self.assertEqual(keys[0], "com.example.service.OverloadService.target(String)")
        self.assertEqual(keys[1], "com.example.service.OverloadService.target")
        self.assertLess(keys.index("com.example.service.BaseService.target"), keys.index("method:target(String)"))
        self.assertLess(keys.index("com.example.service.TargetApi.target"), keys.index("method:target(String)"))
        self.assertEqual(keys[-2:], ["method:target(String)", "method:target"])

    def test_select_matching_keys_from_tiers_prefers_first_hit_tier(self):
        tiers = tracer.build_api_target_key_tiers(
            {
                "api_name": "com.example.service.OverloadService.target",
                "api_simple": "target",
                "symbol_kind": "method",
                "api_signature": "(String)",
            }
        )

        matched = tracer.select_matching_keys_from_tiers(
            tiers,
            {
                "com.example.service.OverloadService.target": [object()],
                "method:target(String)": [object()],
            },
        )

        self.assertEqual(matched, ["com.example.service.OverloadService.target"])

    def test_select_matching_keys_from_tiers_falls_back_to_simple_only_after_strict_miss(self):
        tiers = tracer.build_api_target_key_tiers(
            {
                "api_name": "com.example.service.OverloadService.target",
                "api_simple": "target",
                "symbol_kind": "method",
                "api_signature": "(String)",
            }
        )

        matched = tracer.select_matching_keys_from_tiers(
            tiers,
            {
                "method:target(String)": [object()],
            },
        )

        self.assertEqual(matched, [])

    def test_normalize_signature_for_lookup_keeps_nested_generics_together(self):
        normalized = tracer.normalize_signature_for_lookup(
            "(java.lang.String, java.util.List<java.util.Map<java.lang.String, java.lang.Integer>>, int[])"
        )

        self.assertEqual(normalized, "(String, List, int[])")

    def test_source_analyzer_normalize_signature_for_lookup_keeps_nested_generics_together(self):
        normalized = source_analyzer.normalize_signature_for_lookup(
            "(java.lang.String, java.util.List<java.util.Map<java.lang.String, java.lang.Integer>>, int[])"
        )

        self.assertEqual(normalized, "(String, List, int[])")

    def test_select_matching_key_groups_keeps_all_matching_tiers_with_provenance(self):
        groups = tracer.build_method_lookup_key_groups(
            SimpleNamespace(
                qualified_key="com.example.gateway.PaymentGateway.call",
                simple_key="method:call",
                class_fqcn="com.example.gateway.PaymentGateway",
                method_name="call",
                param_types={"value": "java.lang.String"},
                param_declared_types={"value": "String"},
            ),
            {
                "com.example.gateway.PaymentGateway": {
                    "extends": [],
                    "implements": [],
                    "implementations": ["com.example.gateway.PaymentGatewayImpl"],
                },
                "com.example.gateway.PaymentGatewayImpl": {
                    "extends": [],
                    "implements": ["com.example.gateway.PaymentGateway"],
                    "implementations": [],
                },
            },
        )

        matched_groups = tracer.select_matching_key_groups(
            groups,
            {
                "com.example.gateway.PaymentGateway.call": [object()],
                "com.example.gateway.PaymentGatewayImpl.call(String)": [object()],
                "method:call(String)": [object()],
            },
        )

        provenances = [group["provenance"] for group in matched_groups]
        self.assertEqual(provenances[0], "exact_name")
        self.assertIn("polymorphic", provenances)
        self.assertEqual(provenances[-1], "fallback_simple")
        self.assertEqual(matched_groups[0]["matched_keys"], ["com.example.gateway.PaymentGateway.call"])
        self.assertEqual(matched_groups[1]["matched_keys"], ["com.example.gateway.PaymentGatewayImpl.call(String)"])

    def test_get_cached_overload_signatures_reuses_index_results(self):
        reverse_edges = {"com.example.Service.call()": [object()]}
        trace_cache = {}

        with patch.object(
            tracer,
            "build_overload_signature_index",
            return_value={"com.example.Service.call": {"()"}},
        ) as mocked_build:
            first = tracer.get_cached_overload_signatures(
                "com.example.Service.call",
                reverse_edges,
                trace_cache=trace_cache,
            )
            second = tracer.get_cached_overload_signatures(
                "com.example.Service.call",
                reverse_edges,
                trace_cache=trace_cache,
            )

        self.assertEqual(first, {"()"})
        self.assertEqual(second, {"()"})
        mocked_build.assert_called_once_with(reverse_edges)

    def test_select_best_candidate_uses_stable_tiebreak_for_equal_scores(self):
        alpha_edge = SimpleNamespace(
            caller_qualified_key="com.example.Controller.alpha",
            callee_key="com.example.Target.call(String)",
            file="/tmp/Alpha.java",
            line=10,
        )
        beta_edge = SimpleNamespace(
            caller_qualified_key="com.example.Controller.beta",
            callee_key="com.example.Target.call(String)",
            file="/tmp/Beta.java",
            line=10,
        )
        alpha_candidate = {
            "confidence": 0.95,
            "provenance": "exact_signature",
            "cost": 1,
            "depth": 1,
            "path": [alpha_edge],
            "final_target": "com.example.Controller.alpha",
        }
        beta_candidate = {
            "confidence": 0.95,
            "provenance": "exact_signature",
            "cost": 1,
            "depth": 1,
            "path": [beta_edge],
            "final_target": "com.example.Controller.beta",
        }

        self.assertIs(
            tracer.select_best_candidate([alpha_candidate, beta_candidate]),
            beta_candidate,
        )
        self.assertIs(
            tracer.select_best_candidate([beta_candidate, alpha_candidate]),
            beta_candidate,
        )

    def test_collect_source_file_entries_returns_sorted_file_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            (root / "zeta").mkdir(parents=True)
            (root / "alpha").mkdir(parents=True)
            (root / "zeta" / "Zeta.java").write_text(
                "\n".join(
                    [
                        "package com.example.zeta;",
                        "",
                        "public class Zeta {",
                        "    public void call() {",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (root / "alpha" / "Alpha.java").write_text(
                "\n".join(
                    [
                        "package com.example.alpha;",
                        "",
                        "public class Alpha {",
                        "    public void call() {",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            entries, _ = step5._collect_source_file_entries(
                [
                    {
                        "root": str(root.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )

            file_paths = [entry["file_path"] for entry in entries]
            self.assertEqual(file_paths, sorted(file_paths))

    def test_trace_all_apis_reuses_method_lookup_resolution_for_shared_bridge_method(self):
        api_rows = [
            {
                "api_name": "com.vendor.TargetApi.call",
                "api_simple": "call",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "method_changed",
                "coord": "vendor:demo",
                "severity": "P1",
                "confirmed": "true",
                "source": "gitdiff",
                "analysis_scope": "method",
            },
            {
                "api_name": "com.vendor.TargetApi.fetch",
                "api_simple": "fetch",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "method_changed",
                "coord": "vendor:demo",
                "severity": "P1",
                "confirmed": "true",
                "source": "gitdiff",
                "analysis_scope": "method",
            },
        ]
        dependency_bridge = SimpleNamespace(
            symbol_id="dependency_bridge",
            qualified_key="com.example.Service.bridge",
            simple_key="method:bridge",
            class_fqcn="com.example.Service",
            class_name="Service",
            method_name="bridge",
            param_types={"value": "java.lang.String"},
            param_declared_types={"value": "String"},
            owner_type="dependency",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Service.java",
            line=20,
        )
        business_entry = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.example.Controller.handle",
            simple_key="method:handle",
            class_fqcn="com.example.Controller",
            class_name="Controller",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Controller.java",
            line=60,
        )
        graph = SimpleNamespace(
            methods_by_id={
                "dependency_bridge": dependency_bridge,
                "business_entry": business_entry,
            },
            reverse_edges={
                "com.vendor.TargetApi.call(String)": [
                    SimpleNamespace(
                        caller_symbol_id="dependency_bridge",
                        caller_qualified_key=dependency_bridge.qualified_key,
                        callee_key="com.vendor.TargetApi.call(String)",
                        callee_simple_key="method:call(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=dependency_bridge.file,
                        line=dependency_bridge.line,
                        owner_type="dependency",
                        owner_coord="vendor:bridge",
                        module="service",
                        is_test=False,
                    ),
                ],
                "com.vendor.TargetApi.fetch(String)": [
                    SimpleNamespace(
                        caller_symbol_id="dependency_bridge",
                        caller_qualified_key=dependency_bridge.qualified_key,
                        callee_key="com.vendor.TargetApi.fetch(String)",
                        callee_simple_key="method:fetch(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=dependency_bridge.file,
                        line=dependency_bridge.line,
                        owner_type="dependency",
                        owner_coord="vendor:bridge",
                        module="service",
                        is_test=False,
                    ),
                ],
                "com.example.Service.bridge(String)": [
                    SimpleNamespace(
                        caller_symbol_id="business_entry",
                        caller_qualified_key=business_entry.qualified_key,
                        callee_key="com.example.Service.bridge(String)",
                        callee_simple_key="method:bridge(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=business_entry.file,
                        line=business_entry.line,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
            },
        )

        with patch.object(
            tracer,
            "build_method_lookup_key_groups",
            wraps=tracer.build_method_lookup_key_groups,
        ) as mocked_builder:
            results = tracer.trace_all_apis_with_confidence_weighting(api_rows, graph, {}, max_total_cost=5)

        self.assertEqual([result.analysis_status for result in results], ["reachable", "reachable"])
        self.assertEqual(mocked_builder.call_count, 2)

    def test_trace_api_prefers_polymorphic_reachable_path_over_earlier_exact_name_dead_end(self):
        api_row = {
            "api_name": "com.vendor.TargetApi.call",
            "api_simple": "call",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "method_changed",
            "coord": "vendor:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        interface_method = SimpleNamespace(
            symbol_id="iface_method",
            qualified_key="com.example.gateway.PaymentGateway.call",
            simple_key="method:call",
            class_fqcn="com.example.gateway.PaymentGateway",
            class_name="PaymentGateway",
            method_name="call",
            param_types={"value": "java.lang.String"},
            param_declared_types={"value": "String"},
            owner_type="dependency",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=True,
            file="/tmp/PaymentGateway.java",
            line=10,
        )
        dependency_helper = SimpleNamespace(
            symbol_id="helper_method",
            qualified_key="com.example.gateway.GatewayClient.call",
            simple_key="method:call",
            class_fqcn="com.example.gateway.GatewayClient",
            class_name="GatewayClient",
            method_name="call",
            param_types={"value": "java.lang.String"},
            param_declared_types={"value": "String"},
            owner_type="dependency",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/GatewayClient.java",
            line=22,
        )
        service_method = SimpleNamespace(
            symbol_id="service_method",
            qualified_key="com.example.service.OrderService.submit",
            simple_key="method:submit",
            class_fqcn="com.example.service.OrderService",
            class_name="OrderService",
            method_name="submit",
            param_types={},
            param_declared_types={},
            owner_type="business",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/OrderService.java",
            line=35,
        )
        graph = SimpleNamespace(
            methods_by_id={
                "iface_method": interface_method,
                "helper_method": dependency_helper,
                "service_method": service_method,
            },
            reverse_edges={
                "com.vendor.TargetApi.call(String)": [
                    SimpleNamespace(
                        caller_symbol_id="iface_method",
                        caller_qualified_key=interface_method.qualified_key,
                        callee_key="com.vendor.TargetApi.call(String)",
                        callee_simple_key="method:call(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=interface_method.file,
                        line=interface_method.line,
                        owner_type="dependency",
                        owner_coord="vendor:bridge",
                        module="gateway",
                        is_test=False,
                    ),
                ],
                "com.example.gateway.PaymentGateway.call": [
                    SimpleNamespace(
                        caller_symbol_id="helper_method",
                        caller_qualified_key=dependency_helper.qualified_key,
                        callee_key="com.example.gateway.PaymentGateway.call",
                        callee_simple_key="method:call",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=dependency_helper.file,
                        line=dependency_helper.line,
                        owner_type="dependency",
                        owner_coord="vendor:bridge",
                        module="gateway",
                        is_test=False,
                    ),
                ],
                "com.example.gateway.PaymentGatewayImpl.call(String)": [
                    SimpleNamespace(
                        caller_symbol_id="service_method",
                        caller_qualified_key=service_method.qualified_key,
                        callee_key="com.example.gateway.PaymentGatewayImpl.call(String)",
                        callee_simple_key="method:call(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=service_method.file,
                        line=service_method.line,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
            },
        )
        type_metadata = {
            "com.example.gateway.PaymentGateway": {
                "kind": "interface",
                "extends": [],
                "implements": [],
                "implementations": ["com.example.gateway.PaymentGatewayImpl"],
                "annotations": [],
            },
            "com.example.gateway.PaymentGatewayImpl": {
                "kind": "class",
                "extends": [],
                "implements": ["com.example.gateway.PaymentGateway"],
                "implementations": [],
                "annotations": [],
            },
            "com.example.service.OrderService": {
                "kind": "class",
                "extends": [],
                "implements": [],
                "implementations": [],
                "annotations": [],
            },
            "com.example.gateway.GatewayClient": {
                "kind": "class",
                "extends": [],
                "implements": [],
                "implementations": [],
                "annotations": [],
            },
        }

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, type_metadata, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.match_provenance, "polymorphic")
        self.assertIn("OrderService.submit", result.call_paths[0])

    def test_behavior_changed_precise_signature_does_not_accept_fallback_simple_path(self):
        api_row = {
            "api_name": "org.example.TargetApi.call",
            "api_simple": "call",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "BEHAVIOR_CHANGED",
            "coord": "org.example:demo",
            "severity": "P2",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        dependency_bridge = SimpleNamespace(
            symbol_id="dependency_bridge",
            qualified_key="org.example.Service.bridge",
            simple_key="method:bridge",
            class_fqcn="org.example.Service",
            class_name="Service",
            method_name="bridge",
            param_types={"value": "java.lang.String"},
            param_declared_types={"value": "String"},
            owner_type="dependency",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Service.java",
            line=20,
        )
        business_entry = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="org.example.Controller.handle",
            simple_key="method:handle",
            class_fqcn="org.example.Controller",
            class_name="Controller",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Controller.java",
            line=60,
        )
        graph = SimpleNamespace(
            methods_by_id={
                "dependency_bridge": dependency_bridge,
                "business_entry": business_entry,
            },
            reverse_edges={
                "org.example.TargetApi.call(String)": [
                    SimpleNamespace(
                        caller_symbol_id="dependency_bridge",
                        caller_qualified_key=dependency_bridge.qualified_key,
                        callee_key="org.example.TargetApi.call(String)",
                        callee_simple_key="method:call(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=dependency_bridge.file,
                        line=dependency_bridge.line,
                        owner_type="dependency",
                        owner_coord="org.example:bridge",
                        module="service",
                        is_test=False,
                    ),
                ],
                "method:bridge(String)": [
                    SimpleNamespace(
                        caller_symbol_id="business_entry",
                        caller_qualified_key=business_entry.qualified_key,
                        callee_key="org.example.Service.bridge(String)",
                        callee_simple_key="method:bridge(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=business_entry.file,
                        line=business_entry.line,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "not_found_in_static_analysis")
        self.assertEqual(result.reason_code, "NO_STATIC_PATH")
        self.assertFalse(result.call_paths)
        self.assertFalse(result.evidence_paths)

    def test_method_api_without_fqcn_is_not_traced_by_simple_name(self):
        api_row = {
            "api_name": "",
            "api_simple": "call",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "org.example:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        business_entry = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="org.example.Controller.handle",
            simple_key="method:handle",
            class_fqcn="org.example.Controller",
            class_name="Controller",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Controller.java",
            line=60,
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_entry},
            reverse_edges={
                "method:call(String)": [
                    SimpleNamespace(
                        caller_symbol_id="business_entry",
                        caller_qualified_key=business_entry.qualified_key,
                        callee_key="method:call(String)",
                        callee_simple_key="method:call(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=business_entry.file,
                        line=business_entry.line,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual("not_analyzed", result.analysis_status)
        self.assertEqual("MISSING_API_NAME", result.reason_code)
        self.assertFalse(result.call_paths)
        self.assertFalse(result.evidence_paths)

    def test_behavior_changed_precise_signature_prefers_exact_name_over_better_fallback_simple(self):
        api_row = {
            "api_name": "org.example.TargetApi.call",
            "api_simple": "call",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "BEHAVIOR_CHANGED",
            "coord": "org.example:demo",
            "severity": "P2",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        dependency_bridge = SimpleNamespace(
            symbol_id="dependency_bridge",
            qualified_key="org.example.Service.bridge",
            simple_key="method:bridge",
            class_fqcn="org.example.Service",
            class_name="Service",
            method_name="bridge",
            param_types={"value": "java.lang.String"},
            param_declared_types={"value": "String"},
            owner_type="dependency",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Service.java",
            line=20,
        )
        business_entry = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="org.example.Controller.handle",
            simple_key="method:handle",
            class_fqcn="org.example.Controller",
            class_name="Controller",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Controller.java",
            line=60,
        )
        fallback_entry = SimpleNamespace(
            symbol_id="fallback_entry",
            qualified_key="org.example.FallbackController.handle",
            simple_key="method:handle",
            class_fqcn="org.example.FallbackController",
            class_name="FallbackController",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/FallbackController.java",
            line=80,
        )
        graph = SimpleNamespace(
            methods_by_id={
                "dependency_bridge": dependency_bridge,
                "business_entry": business_entry,
                "fallback_entry": fallback_entry,
            },
            reverse_edges={
                "org.example.TargetApi.call(String)": [
                    SimpleNamespace(
                        caller_symbol_id="dependency_bridge",
                        caller_qualified_key=dependency_bridge.qualified_key,
                        callee_key="org.example.TargetApi.call(String)",
                        callee_simple_key="method:call(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=dependency_bridge.file,
                        line=dependency_bridge.line,
                        owner_type="dependency",
                        owner_coord="org.example:bridge",
                        module="service",
                        is_test=False,
                    ),
                ],
                "org.example.Service.bridge": [
                    SimpleNamespace(
                        caller_symbol_id="business_entry",
                        caller_qualified_key=business_entry.qualified_key,
                        callee_key="org.example.Service.bridge(String)",
                        callee_simple_key="method:bridge(String)",
                        confidence="medium",
                        evidence_type="ast_method_invocation",
                        file=business_entry.file,
                        line=business_entry.line,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
                "method:bridge(String)": [
                    SimpleNamespace(
                        caller_symbol_id="fallback_entry",
                        caller_qualified_key=fallback_entry.qualified_key,
                        callee_key="org.example.Service.bridge(String)",
                        callee_simple_key="method:bridge(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=fallback_entry.file,
                        line=fallback_entry.line,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "BEHAVIOR_CHANGED_RUNTIME_VERIFICATION")
        self.assertEqual(result.match_provenance, "exact_name")
        self.assertIn("Controller.handle", result.call_paths[0])

    def test_method_changed_downgrades_fallback_simple_reachable_path(self):
        api_row = {
            "api_name": "org.example.TargetApi.call",
            "api_simple": "call",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "method_changed",
            "coord": "org.example:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        dependency_bridge = SimpleNamespace(
            symbol_id="dependency_bridge",
            qualified_key="org.example.Service.bridge",
            simple_key="method:bridge",
            class_fqcn="org.example.Service",
            class_name="Service",
            method_name="bridge",
            param_types={"value": "java.lang.String"},
            param_declared_types={"value": "String"},
            owner_type="dependency",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Service.java",
            line=20,
        )
        business_entry = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="org.example.Controller.handle",
            simple_key="method:handle",
            class_fqcn="org.example.Controller",
            class_name="Controller",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Controller.java",
            line=60,
        )
        graph = SimpleNamespace(
            methods_by_id={
                "dependency_bridge": dependency_bridge,
                "business_entry": business_entry,
            },
            reverse_edges={
                "org.example.TargetApi.call(String)": [
                    SimpleNamespace(
                        caller_symbol_id="dependency_bridge",
                        caller_qualified_key=dependency_bridge.qualified_key,
                        callee_key="org.example.TargetApi.call(String)",
                        callee_simple_key="method:call(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=dependency_bridge.file,
                        line=dependency_bridge.line,
                        owner_type="dependency",
                        owner_coord="org.example:bridge",
                        module="service",
                        is_test=False,
                    ),
                ],
                "method:bridge(String)": [
                    SimpleNamespace(
                        caller_symbol_id="business_entry",
                        caller_qualified_key=business_entry.qualified_key,
                        callee_key="org.example.Service.bridge(String)",
                        callee_simple_key="method:bridge(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=business_entry.file,
                        line=business_entry.line,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "not_found_in_static_analysis")
        self.assertEqual(result.reason_code, "NO_STATIC_PATH")
        self.assertFalse(result.call_paths)
        self.assertFalse(result.evidence_paths)

    def test_trace_does_not_stitch_business_call_to_dependency_method_by_simple_name(self):
        api_row = {
            "api_name": "org.apache.commons.lang.StringUtils.equals",
            "api_simple": "equals",
            "api_signature": "(String, String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "commons-lang:commons-lang",
            "severity": "P0",
            "confirmed": "true",
            "source": "old_jar",
            "analysis_scope": "method",
        }
        bclfs_send = SimpleNamespace(
            symbol_id="bclfs_send",
            qualified_key="com.unpacked.BclfsRmbService.sendAndReceiveRMBMessage",
            simple_key="method:sendAndReceiveRMBMessage",
            class_fqcn="com.unpacked.BclfsRmbService",
            class_name="BclfsRmbService",
            method_name="sendAndReceiveRMBMessage",
            param_types={"def": "RmbServiceDef", "map": "Map", "ctx": "SendMessageCtx"},
            param_declared_types={"def": "RmbServiceDef", "map": "Map", "ctx": "SendMessageCtx"},
            owner_type="dependency",
            owner_coord="pd-bcl-fs-online-common",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/BclfsRmbService.java",
            line=10,
        )
        bclfs_trace = SimpleNamespace(
            symbol_id="bclfs_trace",
            qualified_key="com.unpacked.BclfsSendCpsMsgLowerCaseTrace.regTrace",
            simple_key="method:regTrace",
            class_fqcn="com.unpacked.BclfsSendCpsMsgLowerCaseTrace",
            class_name="BclfsSendCpsMsgLowerCaseTrace",
            method_name="regTrace",
            param_types={},
            param_declared_types={},
            owner_type="dependency",
            owner_coord="pd-bcl-fs-online-common",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/BclfsSendCpsMsgLowerCaseTrace.java",
            line=20,
        )
        business_entry = SimpleNamespace(
            symbol_id="business_call_rmb",
            qualified_key="com.app.CallCpsRepayApplyAction.callRmb",
            simple_key="method:callRmb",
            class_fqcn="com.app.CallCpsRepayApplyAction",
            class_name="CallCpsRepayApplyAction",
            method_name="callRmb",
            param_types={},
            param_declared_types={},
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/CallCpsRepayApplyAction.java",
            line=30,
        )
        graph = SimpleNamespace(
            methods_by_id={
                "bclfs_send": bclfs_send,
                "bclfs_trace": bclfs_trace,
                "business_call_rmb": business_entry,
            },
            reverse_edges={
                "org.apache.commons.lang.StringUtils.equals(String, String)": [
                    SimpleNamespace(
                        caller_symbol_id="bclfs_trace",
                        caller_qualified_key=bclfs_trace.qualified_key,
                        callee_key="org.apache.commons.lang.StringUtils.equals(String, String)",
                        callee_simple_key="method:equals(String, String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=bclfs_trace.file,
                        line=bclfs_trace.line,
                        owner_type="dependency",
                        owner_coord="pd-bcl-fs-online-common",
                        module="unpacked-common",
                        is_test=False,
                    ),
                ],
                "com.unpacked.BclfsSendCpsMsgLowerCaseTrace.regTrace": [
                    SimpleNamespace(
                        caller_symbol_id="bclfs_send",
                        caller_qualified_key=bclfs_send.qualified_key,
                        callee_key="com.unpacked.BclfsSendCpsMsgLowerCaseTrace.regTrace",
                        callee_simple_key="method:regTrace",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=bclfs_send.file,
                        line=bclfs_send.line,
                        owner_type="dependency",
                        owner_coord="pd-bcl-fs-online-common",
                        module="unpacked-common",
                        is_test=False,
                    ),
                ],
                # This is the exact false-positive shape: business code was not
                # resolved to BclfsRmbService by type; only a bare simple method
                # name exists. Step5 must not stitch it into the dependency chain.
                "method:sendAndReceiveRMBMessage(RmbServiceDef, Map, SendMessageCtx)": [
                    SimpleNamespace(
                        caller_symbol_id="business_call_rmb",
                        caller_qualified_key=business_entry.qualified_key,
                        callee_key="method:sendAndReceiveRMBMessage(RmbServiceDef, Map, SendMessageCtx)",
                        callee_simple_key="method:sendAndReceiveRMBMessage(RmbServiceDef, Map, SendMessageCtx)",
                        confidence="low",
                        evidence_type="ast_method_invocation",
                        file=business_entry.file,
                        line=business_entry.line,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "not_found_in_static_analysis")
        self.assertEqual(result.reason_code, "NO_STATIC_PATH")
        self.assertFalse(result.call_paths)
        self.assertFalse(result.evidence_paths)

    def test_method_changed_prefers_exact_name_reachable_over_better_fallback_simple(self):
        api_row = {
            "api_name": "org.example.TargetApi.call",
            "api_simple": "call",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "method_changed",
            "coord": "org.example:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        dependency_bridge = SimpleNamespace(
            symbol_id="dependency_bridge",
            qualified_key="org.example.Service.bridge",
            simple_key="method:bridge",
            class_fqcn="org.example.Service",
            class_name="Service",
            method_name="bridge",
            param_types={"value": "java.lang.String"},
            param_declared_types={"value": "String"},
            owner_type="dependency",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Service.java",
            line=20,
        )
        business_entry = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="org.example.Controller.handle",
            simple_key="method:handle",
            class_fqcn="org.example.Controller",
            class_name="Controller",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Controller.java",
            line=60,
        )
        fallback_entry = SimpleNamespace(
            symbol_id="fallback_entry",
            qualified_key="org.example.FallbackController.handle",
            simple_key="method:handle",
            class_fqcn="org.example.FallbackController",
            class_name="FallbackController",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/FallbackController.java",
            line=80,
        )
        graph = SimpleNamespace(
            methods_by_id={
                "dependency_bridge": dependency_bridge,
                "business_entry": business_entry,
                "fallback_entry": fallback_entry,
            },
            reverse_edges={
                "org.example.TargetApi.call(String)": [
                    SimpleNamespace(
                        caller_symbol_id="dependency_bridge",
                        caller_qualified_key=dependency_bridge.qualified_key,
                        callee_key="org.example.TargetApi.call(String)",
                        callee_simple_key="method:call(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=dependency_bridge.file,
                        line=dependency_bridge.line,
                        owner_type="dependency",
                        owner_coord="org.example:bridge",
                        module="service",
                        is_test=False,
                    ),
                ],
                "org.example.Service.bridge": [
                    SimpleNamespace(
                        caller_symbol_id="business_entry",
                        caller_qualified_key=business_entry.qualified_key,
                        callee_key="org.example.Service.bridge(String)",
                        callee_simple_key="method:bridge(String)",
                        confidence="medium",
                        evidence_type="ast_method_invocation",
                        file=business_entry.file,
                        line=business_entry.line,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
                "method:bridge(String)": [
                    SimpleNamespace(
                        caller_symbol_id="fallback_entry",
                        caller_qualified_key=fallback_entry.qualified_key,
                        callee_key="org.example.Service.bridge(String)",
                        callee_simple_key="method:bridge(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=fallback_entry.file,
                        line=fallback_entry.line,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")
        self.assertEqual(result.match_provenance, "exact_name")
        self.assertIn("Controller.handle", result.call_paths[0])

    def test_method_changed_downgrades_same_artifact_internal_direct_consumer_path(self):
        api_row = {
            "api_name": "org.example.TargetApi.call",
            "api_simple": "call",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "method_changed",
            "coord": "org.example:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        dependency_bridge = SimpleNamespace(
            symbol_id="dependency_bridge",
            qualified_key="org.example.InternalFacade.call",
            simple_key="method:call",
            class_fqcn="org.example.InternalFacade",
            class_name="InternalFacade",
            method_name="call",
            param_types={"value": "java.lang.String"},
            param_declared_types={"value": "String"},
            owner_type="dependency",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/InternalFacade.java",
            line=20,
        )
        business_entry = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.example.Controller.handle",
            simple_key="method:handle",
            class_fqcn="com.example.Controller",
            class_name="Controller",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Controller.java",
            line=60,
        )
        graph = SimpleNamespace(
            methods_by_id={
                "dependency_bridge": dependency_bridge,
                "business_entry": business_entry,
            },
            reverse_edges={
                "org.example.TargetApi.call(String)": [
                    SimpleNamespace(
                        caller_symbol_id="dependency_bridge",
                        caller_qualified_key=dependency_bridge.qualified_key,
                        callee_key="org.example.TargetApi.call(String)",
                        callee_simple_key="method:call(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=dependency_bridge.file,
                        line=dependency_bridge.line,
                        owner_type="dependency",
                        owner_coord="org.example:demo",
                        module="core",
                        is_test=False,
                    ),
                ],
                "org.example.InternalFacade.call": [
                    SimpleNamespace(
                        caller_symbol_id="business_entry",
                        caller_qualified_key=business_entry.qualified_key,
                        callee_key="org.example.InternalFacade.call(String)",
                        callee_simple_key="method:call(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=business_entry.file,
                        line=business_entry.line,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "INTERNAL_ONLY_DIRECT_CONSUMER")
        self.assertEqual(result.match_provenance, "exact_name")
        self.assertTrue(result.evidence_paths)
        self.assertIn("Controller.handle", result.call_paths[0])

    def test_trace_api_downgrades_not_found_when_graph_is_incomplete(self):
        api_row = {
            "api_name": "com.vendor.TargetApi.call",
            "api_simple": "call",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "method_changed",
            "coord": "vendor:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        graph = SimpleNamespace(methods_by_id={}, reverse_edges={})
        type_metadata = {}

        with patch.object(
            tracer, "decide_envelope", wraps=tracer.decide_envelope,
        ) as decide, patch.object(
            tracer, "render_trace_result", wraps=tracer.render_trace_result,
        ) as render:
            result = tracer.trace_api_with_confidence_weighting(
                api_row,
                graph,
                type_metadata,
                max_total_cost=5,
                graph_stats={
                    "truncated": True,
                    "truncation_reasons": ["max_methods"],
                    "parser_fallback_reasons": {},
                    "edge_cap_hits": 0,
                },
            )

        decide.assert_called_once()
        render.assert_called_once()
        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "ANALYSIS_INCOMPLETE")
        self.assertIn("图构建被截断", result.reachable_note)

    def test_trace_api_consumes_partial_collector_coverage_from_graph(self):
        api_row = {
            "api_name": "com.vendor.TargetApi.call",
            "api_simple": "call",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "method_changed",
            "coord": "vendor:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        identity = tracer.indirect_api_key(api_row)
        global_partial = CoverageRecord(
            collector="spring_runtime_artifact",
            api_identity="spring_runtime_artifact",
            status="partial",
            reason_codes=("FRAMEWORK_SCAN_PARTIAL",),
        )
        per_api_complete = CoverageRecord(
            collector="spring_runtime_artifact",
            api_identity=identity,
            status="complete",
        )
        for records in (
            (global_partial, per_api_complete),
            (per_api_complete, global_partial),
        ):
            with self.subTest(order=[item.status for item in records]):
                graph = SimpleNamespace(
                    methods_by_id={},
                    reverse_edges={},
                    step5_collector_coverage=records,
                )
                with patch.object(
                    tracer, "_capability_coverage_for_api", return_value={},
                ):
                    result = tracer.trace_api_with_confidence_weighting(
                        api_row, graph, {}
                    )

                self.assertEqual(result.analysis_status, "not_analyzed")
                self.assertEqual(
                    result.reason_code, "INCOMPLETE_EVIDENCE_COVERAGE"
                )

    def test_collector_coverage_index_preserves_order_and_refreshes(self):
        first = CoverageRecord(
            collector="global", api_identity="global", status="partial",
        )
        second = CoverageRecord(
            collector="target", api_identity="api-1", status="complete",
        )
        graph = SimpleNamespace(step5_collector_coverage=(first, second))

        indexed = tracer._collector_coverage_records_for_api(
            graph, "api-1", include_self_scoped=True,
        )
        self.assertEqual(indexed, (first, second))

        third = CoverageRecord(
            collector="target", api_identity="api-2", status="insufficient",
        )
        graph.step5_collector_coverage = (third,)
        self.assertEqual(
            tracer._collector_coverage_records_for_api(graph, "api-2"),
            (third,),
        )

    def test_trace_api_ignores_path_scoped_framework_gap_unrelated_to_target(self):
        api_row = {
            "api_name": "org.springframework.data.domain.Page.getContent",
            "api_simple": "getContent",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "org.springframework.data:spring-data-commons",
            "severity": "P1",
            "confirmed": "true",
            "source": "final_artifact",
            "analysis_scope": "method",
        }
        identity = tracer.indirect_api_key(api_row)
        graph = SimpleNamespace(
            methods_by_id={},
            reverse_edges={},
            step5_collector_coverage=(
                CoverageRecord(
                    collector="business_bytecode",
                    api_identity=identity,
                    status="complete",
                ),
                CoverageRecord(
                    collector="spring_basic",
                    api_identity="spring_basic",
                    status="partial",
                    reason_codes=("spring_bean_method_unresolved",),
                    scope="path",
                ),
            ),
            step5_evidence_concerns=(EvidenceConcern(
                stage="spring_basic",
                reason_code="spring_bean_method_unresolved",
                detail="unresolved cache customizer",
                class_name=(
                    "org.springframework.samples.petclinic.system.CacheConfiguration."
                    "petclinicCacheConfigurationCustomizer"
                ),
            ),),
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {})

        self.assertEqual(result.analysis_status, "not_found_in_static_analysis")
        self.assertEqual(result.reason_code, "NO_STATIC_PATH")

    def test_trace_api_keeps_path_scoped_framework_gap_on_target_path(self):
        api_row = {
            "api_name": "org.springframework.data.domain.Page.getContent",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "org.springframework.data:spring-data-commons",
        }
        framework_coverage = CoverageRecord(
            collector="spring_basic",
            api_identity="spring_basic",
            status="partial",
            reason_codes=("spring_bean_method_unresolved",),
            scope="path",
        )
        graph = SimpleNamespace(
            reverse_edges={
                "org.springframework.data.domain.Page.getContent()": (
                    SimpleNamespace(
                        collector="spring_basic",
                        caller_symbol_id="app.Repository.findAll()",
                        caller_qualified_key="app.Repository.findAll()",
                    ),
                ),
            },
            step5_collector_coverage=(framework_coverage,),
            step5_evidence_concerns=(),
        )

        draft = tracer._new_trace_draft(api_row, graph)

        self.assertEqual(len(draft.envelope_coverage), 1)
        projected = draft.envelope_coverage[0]
        self.assertEqual(projected.collector, "spring_basic")
        self.assertEqual(projected.api_identity, tracer.build_api_identity_key(api_row))
        self.assertEqual(projected.status, "partial")
        self.assertEqual(projected.scope, "path")
        self.assertEqual(
            projected.reason_codes, ("spring_bean_method_unresolved",)
        )

    def test_path_scoped_framework_gap_does_not_cross_overloads(self):
        api_row = {
            "api_name": "com.vendor.Target.call",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "vendor:target",
        }
        graph = SimpleNamespace(
            reverse_edges={
                "com.vendor.Target.call(Integer)": (
                    SimpleNamespace(
                        collector="spring_basic",
                        caller_symbol_id="app.Config.integerCall()",
                        caller_qualified_key="app.Config.integerCall()",
                    ),
                ),
            },
            step5_collector_coverage=(CoverageRecord(
                collector="spring_basic",
                api_identity="spring_basic",
                status="partial",
                scope="path",
            ),),
            step5_evidence_concerns=(),
        )

        draft = tracer._new_trace_draft(api_row, graph)

        self.assertEqual(draft.envelope_coverage, ())

    def test_path_scope_traverses_beyond_ten_thousand_nodes(self):
        target = "com.vendor.Target.call()"
        reverse_edges = {}
        current = target
        for index in range(10002):
            caller = f"app.Chain.node{index}()"
            reverse_edges[current] = (SimpleNamespace(
                collector="spring_basic" if index == 10001 else "",
                caller_symbol_id=caller,
                caller_qualified_key=caller,
            ),)
            current = caller
        graph = SimpleNamespace(reverse_edges=reverse_edges)

        collectors, symbols = tracer._target_reverse_path_context(
            {"api_name": "com.vendor.Target.call", "api_signature": "()"}, graph
        )

        self.assertIn("spring_basic", collectors)
        self.assertIn("app.Chain.node10001", symbols)

    def test_path_scope_matches_nested_class_spelling(self):
        graph = SimpleNamespace(reverse_edges={
            "com.vendor.Outer.Builder.call(com.vendor.Outer.Arg)": (
                SimpleNamespace(
                    collector="spring_basic",
                    caller_symbol_id="app.Config.call()",
                    caller_qualified_key="app.Config.call()",
                ),
            ),
        })

        collectors, _symbols = tracer._target_reverse_path_context({
            "api_name": "com.vendor.Outer$Builder.call",
            "api_signature": "(com.vendor.Outer$Arg)",
        }, graph)

        self.assertEqual(collectors, {"spring_basic"})

    def test_path_scope_nested_signature_keeps_qualified_owner(self):
        graph = SimpleNamespace(reverse_edges={
            "com.vendor.Target.call(x.Other.Arg)": (
                SimpleNamespace(
                    collector="spring_basic",
                    caller_symbol_id="app.Config.call()",
                    caller_qualified_key="app.Config.call()",
                ),
            ),
        })

        collectors, _symbols = tracer._target_reverse_path_context({
            "api_name": "com.vendor.Target.call",
            "api_signature": "(x.Outer$Arg)",
        }, graph)

        self.assertEqual(collectors, set())

    def test_path_scope_observes_edges_added_after_first_lookup(self):
        target = "com.vendor.Target.call()"
        graph = SimpleNamespace(reverse_edges={
            target: [SimpleNamespace(
                collector="first",
                caller_symbol_id="app.First.call()",
                caller_qualified_key="app.First.call()",
            )],
        })
        api_row = {"api_name": "com.vendor.Target.call", "api_signature": "()"}

        first, _symbols = tracer._target_reverse_path_context(api_row, graph)
        graph.reverse_edges[target].append(SimpleNamespace(
            collector="second",
            caller_symbol_id="app.Second.call()",
            caller_qualified_key="app.Second.call()",
        ))
        second, _symbols = tracer._target_reverse_path_context(api_row, graph)

        self.assertEqual(first, {"first"})
        self.assertEqual(second, {"first", "second"})

    def test_missing_signature_is_rejected_before_positive_evidence_builders(self):
        api_row = {
            "api_name": "com.vendor.Target.call",
            "api_signature": "",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "vendor:target",
        }
        graph = SimpleNamespace(methods_by_id={}, reverse_edges={})
        with patch.object(
            tracer, "_build_runtime_symbol_preserved_result",
            side_effect=AssertionError("positive evidence builder must not run"),
        ):
            result = tracer.trace_api_with_confidence_weighting(api_row, graph, {})

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "MISSING_API_SIGNATURE")

    def test_trace_api_consumes_ingestion_failures_from_graph(self):
        api_row = {
            "api_name": "com.vendor.TargetApi.call",
            "api_simple": "call",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "method_changed",
            "coord": "vendor:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        graph = SimpleNamespace(
            methods_by_id={},
            reverse_edges={},
            step5_evidence_failures=(EvidenceFailure(
                stage="framework-ingestion",
                reason_code="FRAMEWORK_EDGE_REJECTED",
                blocking=True,
            ),),
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {})

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "FRAMEWORK_EDGE_REJECTED")

    def test_analyzer_collector_failure_blocks_a_negative_conclusion(self):
        api_row = {
            "api_name": "com.vendor.TargetApi.call",
            "api_simple": "call",
            "api_signature": "(java.lang.String)",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
            "coord": "vendor:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "japicmp",
            "analysis_scope": "method",
        }
        graph = SimpleNamespace(methods_by_id={}, reverse_edges={})

        tracer._record_analyzer_ledger_failure(
            graph,
            "BYTECODE_SCAN_FAILED",
            artifact="broken.jar",
            error_type="BadZipFile",
        )
        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {})

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "BYTECODE_SCAN_FAILED")
        self.assertEqual(
            graph.step5_evidence_failures[0].artifact,
            "broken.jar",
        )

    def test_analyzer_failure_buffer_preserves_all_api_failures_and_order(self):
        graph = SimpleNamespace()
        expected = [f"vendor:demo|com.vendor.Api.call{i}|()|method|" for i in range(2000)]

        for identity in expected:
            tracer._record_analyzer_ledger_failure(
                graph,
                "MULTI_RELEASE_TARGET_JDK_UNKNOWN",
                api_identity=identity,
            )
        tracer._record_analyzer_ledger_failure(
            graph,
            "MULTI_RELEASE_TARGET_JDK_UNKNOWN",
            api_identity=expected[-1],
        )

        failures = tuple(graph.step5_evidence_failures)
        self.assertEqual(len(failures), len(expected))
        self.assertEqual([failure.api_identity for failure in failures], expected)
        self.assertEqual(len(graph._step5_evidence_failure_index), len(expected))

    def test_evidence_failure_index_preserves_order_and_indexes_appends(self):
        failures = [
            EvidenceFailure("stage", "GLOBAL", True, api_identity=""),
            EvidenceFailure("stage", "API_A_1", True, api_identity="api-a"),
            EvidenceFailure("stage", "API_B", True, api_identity="api-b"),
        ]
        graph = SimpleNamespace(step5_evidence_failures=failures)

        first = tracer._evidence_failures_for_api(graph, "", "api-a")
        failures.append(EvidenceFailure(
            "stage", "API_A_2", True, api_identity="api-a"
        ))
        second = tracer._evidence_failures_for_api(graph, "", "api-a")

        self.assertEqual([item.reason_code for item in first], ["GLOBAL", "API_A_1"])
        self.assertEqual(
            [item.reason_code for item in second],
            ["GLOBAL", "API_A_1", "API_A_2"],
        )
        self.assertEqual(
            graph._step5_evidence_failures_by_identity_index["indexed_count"], 4
        )

    def test_path_scoped_framework_failure_only_reaches_related_api(self):
        affected_api = {
            "api_name": "com.vendor.Target.call",
            "api_signature": "(java.lang.String)",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
            "coord": "com.vendor:target",
        }
        unrelated_api = {
            **affected_api,
            "api_name": "com.vendor.Unrelated.call",
        }
        failure = EvidenceFailure(
            stage="spring_aop_activation",
            reason_code="SPRING_RUNTIME_CLASS_AMBIGUOUS",
            blocking=True,
            class_name="demo.Affected",
            scope="path",
        )
        graph = SimpleNamespace(
            reverse_edges={
                "com.vendor.Target.call(java.lang.String)": [
                    SimpleNamespace(
                        collector="source_ast",
                        caller_symbol_id="demo.Affected.run()",
                        caller_qualified_key="demo.Affected.run()",
                    ),
                ],
            },
            step5_evidence_failures=(failure,),
            step5_evidence_concerns=(),
            step5_collector_coverage=(
                CoverageRecord(
                    collector="spring_aop_activation",
                    api_identity="spring_aop_activation",
                    status="partial",
                    scope="path",
                ),
                CoverageRecord(
                    collector="business_bytecode",
                    api_identity=tracer.indirect_api_key(affected_api),
                    status="complete",
                ),
                CoverageRecord(
                    collector="business_bytecode",
                    api_identity=tracer.indirect_api_key(unrelated_api),
                    status="complete",
                ),
            ),
        )

        affected = tracer._new_trace_draft(affected_api, graph)
        unrelated = tracer._new_trace_draft(unrelated_api, graph)
        affected_result = tracer._finalize_trace_draft(affected)
        unrelated_result = tracer._finalize_trace_draft(unrelated)

        self.assertEqual((failure,), affected.envelope_failures)
        self.assertFalse(unrelated.envelope_failures)
        self.assertEqual(
            "SPRING_RUNTIME_CLASS_AMBIGUOUS",
            affected_result.reason_code,
        )
        self.assertEqual("not_analyzed", affected_result.analysis_status)
        self.assertEqual(
            "not_found_in_static_analysis",
            unrelated_result.analysis_status,
        )
        self.assertEqual("NO_STATIC_PATH", unrelated_result.reason_code)

    def test_mybatis_runtime_parse_failure_only_reaches_proxy_path(self):
        affected_api = {
            "api_name": "org.apache.ibatis.session.SqlSession.selectOne",
            "api_signature": "(java.lang.String,java.lang.Object)",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
            "coord": "org.mybatis:mybatis",
        }
        unrelated_api = {
            **affected_api,
            "api_name": "com.vendor.Unrelated.call",
        }
        failure = framework_adapters._framework_failure(
            "mybatis_mapper_proxy",
            (
                "/runtime/mybatis.jar:"
                "mybatis_runtime_artifact_parse_failed:"
                "mybatis_runtime:BadZipFile"
            ),
        )
        graph = SimpleNamespace(
            reverse_edges={
                (
                    "org.apache.ibatis.session.SqlSession.selectOne"
                    "(java.lang.String,java.lang.Object)"
                ): [
                    SimpleNamespace(
                        collector="source_ast",
                        caller_symbol_id=(
                            "org.apache.ibatis.binding.MapperProxy.invoke()"
                        ),
                        caller_qualified_key=(
                            "org.apache.ibatis.binding.MapperProxy.invoke()"
                        ),
                    ),
                ],
            },
            step5_evidence_failures=(failure,),
            step5_evidence_concerns=(),
            step5_collector_coverage=(
                CoverageRecord(
                    collector="mybatis_mapper_proxy",
                    api_identity="mybatis_mapper_proxy",
                    status="partial",
                    scope="path",
                ),
                CoverageRecord(
                    collector="business_bytecode",
                    api_identity=tracer.indirect_api_key(affected_api),
                    status="complete",
                ),
                CoverageRecord(
                    collector="business_bytecode",
                    api_identity=tracer.indirect_api_key(unrelated_api),
                    status="complete",
                ),
            ),
        )

        affected = tracer._new_trace_draft(affected_api, graph)
        unrelated = tracer._new_trace_draft(unrelated_api, graph)
        affected_result = tracer._finalize_trace_draft(affected)
        unrelated_result = tracer._finalize_trace_draft(unrelated)

        self.assertEqual((failure,), affected.envelope_failures)
        self.assertFalse(unrelated.envelope_failures)
        self.assertEqual(
            "MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED",
            affected_result.reason_code,
        )
        self.assertEqual("not_analyzed", affected_result.analysis_status)
        self.assertEqual(
            "not_found_in_static_analysis",
            unrelated_result.analysis_status,
        )

    def test_perf_top_filter_matches_full_canonical_sort(self):
        graph = SimpleNamespace()
        rows = [
            {"elapsed_sec": float(index % 7), "name": f"row-{index:03d}"}
            for index in range(100)
        ]
        expected = sorted(rows, key=lambda row: (
            -row["elapsed_sec"],
            json.dumps(row, sort_keys=True, default=str, ensure_ascii=True),
        ))[:20]

        for row in rows:
            tracer._perf_record_top(graph, "trace", "top", row)

        self.assertEqual(graph._step5_perf_stats["trace"]["top"], expected)

    def test_capability_coverage_looks_up_one_api_without_copying_global_map(self):
        api = {
            "coord": "vendor:demo", "api_name": "com.vendor.Api.call",
            "api_simple": "call", "api_signature": "()", "symbol_kind": "method",
        }
        identity = tracer.indirect_api_key(api)

        class LookupOnlyDict(dict):
            def keys(self):
                raise AssertionError("global by_api coverage must not be copied")

            def __iter__(self):
                raise AssertionError("global by_api coverage must not be iterated")

        graph = SimpleNamespace(indirect_analysis_coverage={
            "status": "complete",
            "by_api": LookupOnlyDict({identity: {
                "status": "complete", "reason_codes": [],
                "matrix": {"reflection_source": "complete"},
            }}),
        })

        actual = tracer._capability_coverage_for_api(api, graph)

        self.assertEqual(actual["status"], "complete")
        self.assertEqual(actual["analyzers"], {"reflection_source": "complete"})

    def test_trace_api_consumes_ingestion_concerns_from_graph(self):
        api_row = {
            "api_name": "com.vendor.TargetApi.call",
            "api_simple": "call",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "method_changed",
            "coord": "vendor:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        identity = tracer.indirect_api_key(api_row)
        graph = SimpleNamespace(methods_by_id={}, reverse_edges={})
        ingest_collector_batches(graph, (CollectorBatch(
            collector="indirect_usage",
            version="1",
            concerns=(EvidenceConcern(
                stage="dynamic-analysis",
                reason_code="DYNAMIC_GAP",
                detail="动态目标无法唯一解析",
                api_identity=identity,
            ),),
            coverage=(CoverageRecord(
                collector="indirect_usage",
                api_identity=identity,
                status="complete",
            ),),
        ),))

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {})

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "DYNAMIC_GAP")

    def test_assess_graph_completeness_fails_closed_for_kotlin_partial_capability(self):
        completeness = tracer.assess_graph_completeness(
            {
                "truncated": False,
                "parser_fallback_reasons": {"unsupported_language_kotlin": 3},
                "edge_cap_hits": 0,
            }
        )

        self.assertTrue(completeness["incomplete"])
        self.assertIn("unsupported_language_kotlin=3", completeness["reasons"][0])

    def test_kotlin_partial_capability_blocks_not_impacted_preservation_shortcut(self):
        with tempfile.TemporaryDirectory() as tmp:
            kotlin_source = Path(tmp) / "src/main/kotlin/com/acme/Consumer.kt"
            kotlin_source.parent.mkdir(parents=True)
            kotlin_source.write_text(
                "package com.acme\n"
                "import com.vendor.LegacyApi\n"
                "class Consumer { fun run(api: LegacyApi) = api.removed() }\n",
                encoding="utf-8",
            )
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                identical_current_class_providers={
                    ("com.vendor:legacy", "com.vendor.LegacyApi"): [{
                        "provider_coord": "com.vendor:replacement",
                        "provider_jar": str(Path(tmp) / "replacement.jar"),
                        "provider_class_entry": "com/vendor/LegacyApi.class",
                        "class_sha256": "a" * 64,
                        "old_jar": str(Path(tmp) / "legacy.jar"),
                        "old_class_entry": "com/vendor/LegacyApi.class",
                    }]
                },
            )
            api_row = {
                "coord": "com.vendor:legacy",
                "api_name": "com.vendor.LegacyApi.removed",
                "api_simple": "removed",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }

            result = tracer.trace_api_with_confidence_weighting(
                api_row,
                graph,
                {},
                graph_stats={
                    "parser_fallback_reasons": {"unsupported_language_kotlin": 1},
                    "parser_fallback_files": [{
                        "file": str(kotlin_source),
                        "reason": "unsupported_language_kotlin",
                    }],
                },
            )

        self.assertEqual("not_analyzed", result.analysis_status)
        self.assertEqual("PARTIAL_LANGUAGE_ANALYSIS", result.reason_code)

    def test_irrelevant_kotlin_partial_file_does_not_block_preservation_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            kotlin_source = Path(tmp) / "src/main/kotlin/com/acme/Unrelated.kt"
            kotlin_source.parent.mkdir(parents=True)
            kotlin_source.write_text(
                "package com.acme\nclass Unrelated { fun value() = 1 }\n",
                encoding="utf-8",
            )
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                identical_current_class_providers={
                    ("com.vendor:legacy", "com.vendor.LegacyApi"): [{
                        "provider_coord": "com.vendor:replacement",
                        "provider_jar": str(Path(tmp) / "replacement.jar"),
                        "provider_class_entry": "com/vendor/LegacyApi.class",
                        "class_sha256": "a" * 64,
                        "old_jar": str(Path(tmp) / "legacy.jar"),
                        "old_class_entry": "com/vendor/LegacyApi.class",
                    }]
                },
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "com.vendor:legacy",
                    "api_name": "com.vendor.LegacyApi.removed",
                    "api_simple": "removed",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                },
                graph,
                {},
                graph_stats={
                    "parser_fallback_reasons": {"unsupported_language_kotlin": 1},
                    "parser_fallback_files": [{
                        "file": str(kotlin_source),
                        "reason": "unsupported_language_kotlin",
                    }],
                },
            )

        self.assertEqual("not_impacted", result.analysis_status)

    def test_assess_graph_completeness_ignores_explicit_parser_disable(self):
        completeness = tracer.assess_graph_completeness(
            {
                "truncated": False,
                "parser_fallback_reasons": {"prefer_tree_sitter_disabled": 3919},
                "edge_cap_hits": 0,
            }
        )

        self.assertFalse(completeness["incomplete"])
        self.assertEqual(completeness["reasons"], [])

    def test_assess_graph_completeness_keeps_critical_parser_fallbacks(self):
        completeness = tracer.assess_graph_completeness(
            {
                "truncated": False,
                "parser_fallback_reasons": {"tree_sitter_unavailable": 2},
                "edge_cap_hits": 0,
            }
        )

        self.assertTrue(completeness["incomplete"])
        self.assertIn("tree_sitter_unavailable=2", completeness["reasons"][0])

    def test_assess_graph_completeness_keeps_business_bytecode_failure_codes(self):
        completeness = tracer.assess_graph_completeness({
            "truncated": False,
            "parser_fallback_reasons": {},
            "edge_cap_hits": 0,
            "business_bytecode": {
                "status": "partial",
                "reason_codes": ["BYTECODE_CALLER_UNRESOLVED"],
                "failures": ["BYTECODE_CALLER_UNRESOLVED"],
            },
        })

        self.assertTrue(completeness["incomplete"])
        self.assertEqual(completeness["reason_codes"], ["BYTECODE_CALLER_UNRESOLVED"])

    def test_business_bytecode_partial_coverage_prevents_static_not_found(self):
        api_row = {
            "api_name": "com.vendor.TargetApi.call", "api_simple": "call",
            "api_signature": "()", "symbol_kind": "method",
            "change_type": "REMOVED", "coord": "vendor:demo",
            "severity": "P1", "confirmed": "true", "source": "old_jar",
            "analysis_scope": "method",
        }
        graph = SimpleNamespace(methods_by_id={}, reverse_edges={})

        result = tracer.trace_api_with_confidence_weighting(
            api_row, graph, {}, has_packaged_bytecode_fallback=False,
            has_dependency_source_mapping=True,
            graph_stats={
                "business_bytecode": {
                    "status": "partial",
                    "reason_codes": ["CURRENT_FINAL_ARTIFACT_SHA_INVALID"],
                    "failures": ["CURRENT_FINAL_ARTIFACT_SHA_INVALID"],
                },
            },
        )

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertNotEqual(result.analysis_status, "not_found_in_static_analysis")
        self.assertIn("CURRENT_FINAL_ARTIFACT_SHA_INVALID", result.reachable_note)

    def test_assess_graph_completeness_ignores_unrelated_parser_fallback_files_for_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            unrelated = Path(tmp) / "generated" / "MySqlParser.java"
            unrelated.parent.mkdir(parents=True)
            unrelated.write_text(
                "package org.apache.seata.sqlparser.antlr.mysql.parser; class MySqlParser {}",
                encoding="utf-8",
            )

            completeness = tracer.assess_graph_completeness(
                {
                    "truncated": False,
                    "parser_fallback_reasons": {"tree_sitter_runtime_error:RecursionError": 1},
                    "parser_fallback_files": [
                        {
                            "file": str(unrelated),
                            "reason": "tree_sitter_runtime_error:RecursionError",
                        }
                    ],
                    "edge_cap_hits": 0,
                },
                api_row={
                    "api_name": "io.seata.common.util.StringUtils.isBlank",
                    "symbol_kind": "method",
                },
            )

        self.assertFalse(completeness["incomplete"])
        self.assertEqual(completeness["reasons"], [])

    def test_assess_graph_completeness_keeps_related_parser_fallback_files_for_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            related = Path(tmp) / "src" / "main" / "java" / "demo" / "Compat.java"
            related.parent.mkdir(parents=True)
            related.write_text(
                "\n".join(
                    [
                        "package demo;",
                        "import io.seata.common.util.StringUtils;",
                        "class Compat { boolean x(String v) { return StringUtils.isBlank(v); } }",
                    ]
                ),
                encoding="utf-8",
            )

            completeness = tracer.assess_graph_completeness(
                {
                    "truncated": False,
                    "parser_fallback_reasons": {"tree_sitter_runtime_error:RecursionError": 1},
                    "parser_fallback_files": [
                        {
                            "file": str(related),
                            "reason": "tree_sitter_runtime_error:RecursionError",
                        }
                    ],
                    "edge_cap_hits": 0,
                },
                api_row={
                    "api_name": "io.seata.common.util.StringUtils.isBlank",
                    "symbol_kind": "method",
                },
            )

        self.assertTrue(completeness["incomplete"])
        self.assertIn("tree_sitter_runtime_error:RecursionError=1", completeness["reasons"][0])

    def test_trace_api_accepts_precise_internal_dependency_consumer_when_path_reaches_business(self):
        api_row = {
            "api_name": "org.example.InternalConfig.message",
            "api_simple": "message",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "method_changed",
            "coord": "org.example:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        dependency_bridge = SimpleNamespace(
            symbol_id="dependency_bridge",
            qualified_key="org.example.InternalFacade.message",
            simple_key="method:message",
            class_fqcn="org.example.InternalFacade",
            class_name="InternalFacade",
            method_name="message",
            param_types={},
            param_declared_types={},
            owner_type="dependency",
            owner_coord="org.example:demo",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/InternalFacade.java",
            line=20,
        )
        business_entry = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.example.Controller.handle",
            simple_key="method:handle",
            class_fqcn="com.example.Controller",
            class_name="Controller",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Controller.java",
            line=60,
        )
        graph = SimpleNamespace(
            methods_by_id={
                "dependency_bridge": dependency_bridge,
                "business_entry": business_entry,
            },
            reverse_edges={
                "org.example.InternalConfig.message()": [
                    SimpleNamespace(
                        caller_symbol_id="dependency_bridge",
                        caller_qualified_key=dependency_bridge.qualified_key,
                        callee_key="org.example.InternalConfig.message()",
                        callee_simple_key="method:message()",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=dependency_bridge.file,
                        line=dependency_bridge.line,
                        owner_type="dependency",
                        owner_coord="org.example:demo",
                        module="core",
                        is_test=False,
                    ),
                ],
                "org.example.InternalFacade.message()": [
                    SimpleNamespace(
                        caller_symbol_id="business_entry",
                        caller_qualified_key=business_entry.qualified_key,
                        callee_key="org.example.InternalFacade.message()",
                        callee_simple_key="method:message()",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=business_entry.file,
                        line=business_entry.line,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")
        self.assertIn("Controller.handle", result.call_paths[0])

    def test_trace_api_blocks_overloaded_target_when_only_name_fallback_matches_wrong_overload(self):
        api_row = {
            "api_name": "org.example.VetRepository.findAll",
            "api_simple": "findAll",
            "api_signature": "(Pageable)",
            "symbol_kind": "method",
            "change_type": "method_changed",
            "coord": "org.example:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        show_resources = SimpleNamespace(
            symbol_id="show_resources",
            qualified_key="org.example.VetController.showResourcesVetList",
            simple_key="method:showResourcesVetList",
            class_fqcn="org.example.VetController",
            class_name="VetController",
            method_name="showResourcesVetList",
            param_types={},
            param_declared_types={},
            owner_type="business",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/VetController.java",
            line=70,
        )
        graph = SimpleNamespace(
            methods_by_id={"show_resources": show_resources},
            reverse_edges={
                "org.example.VetRepository.findAll": [
                    SimpleNamespace(
                        caller_symbol_id="show_resources",
                        caller_qualified_key=show_resources.qualified_key,
                        callee_key="org.example.VetRepository.findAll()",
                        callee_simple_key="method:findAll()",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=show_resources.file,
                        line=74,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
                "org.example.VetRepository.findAll()": [
                    SimpleNamespace(
                        caller_symbol_id="show_resources",
                        caller_qualified_key=show_resources.qualified_key,
                        callee_key="org.example.VetRepository.findAll()",
                        callee_simple_key="method:findAll()",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=show_resources.file,
                        line=74,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
                "org.example.VetRepository.findAll(Pageable)": [],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "OVERLOAD_AMBIGUOUS_TARGET")

    def test_trace_api_blocks_constructor_target_when_only_single_wrong_overload_is_observed(self):
        api_row = {
            "api_name": "org.springframework.web.servlet.ModelAndView.ModelAndView",
            "api_simple": "ModelAndView",
            "api_signature": "(java.lang.String, org.springframework.http.HttpStatus)",
            "symbol_kind": "constructor",
            "change_type": "REMOVED",
            "coord": "org.springframework:spring-webmvc",
            "severity": "P0",
            "confirmed": "true",
            "source": "japicmp",
            "analysis_scope": "api",
        }
        show_owner = SimpleNamespace(
            symbol_id="show_owner",
            qualified_key="org.springframework.samples.petclinic.owner.OwnerController.showOwner",
            simple_key="method:showOwner",
            class_fqcn="org.springframework.samples.petclinic.owner.OwnerController",
            class_name="OwnerController",
            method_name="showOwner",
            param_types={},
            param_declared_types={},
            owner_type="business",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/OwnerController.java",
            line=154,
        )
        graph = SimpleNamespace(
            methods_by_id={"show_owner": show_owner},
            reverse_edges={
                "org.springframework.web.servlet.ModelAndView.ModelAndView": [
                    SimpleNamespace(
                        caller_symbol_id="show_owner",
                        caller_qualified_key=show_owner.qualified_key,
                        callee_key="org.springframework.web.servlet.ModelAndView.ModelAndView(String)",
                        callee_simple_key="method:ModelAndView(String)",
                        confidence="high",
                        evidence_type="constructor_invocation",
                        file=show_owner.file,
                        line=show_owner.line,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
                "org.springframework.web.servlet.ModelAndView.ModelAndView(String)": [
                    SimpleNamespace(
                        caller_symbol_id="show_owner",
                        caller_qualified_key=show_owner.qualified_key,
                        callee_key="org.springframework.web.servlet.ModelAndView.ModelAndView(String)",
                        callee_simple_key="method:ModelAndView(String)",
                        confidence="high",
                        evidence_type="constructor_invocation",
                        file=show_owner.file,
                        line=show_owner.line,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "OVERLOAD_AMBIGUOUS_TARGET")

    def test_trace_api_reports_not_found_when_all_unsigned_edges_have_complete_incompatible_signatures(self):
        api_row = {
            "api_name": "org.slf4j.Logger.isDebugEnabled",
            "api_simple": "isDebugEnabled",
            "api_signature": "(org.slf4j.Marker)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "org.slf4j:slf4j-api",
            "severity": "P0",
            "confirmed": "true",
            "source": "japicmp",
            "analysis_scope": "method",
        }
        caller = SimpleNamespace(
            symbol_id="caller",
            qualified_key="com.vendor.LoggingAdapter.enabled",
            simple_key="method:enabled",
            class_fqcn="com.vendor.LoggingAdapter",
            class_name="LoggingAdapter",
            method_name="enabled",
            param_types={},
            param_declared_types={},
            owner_type="dependency",
            owner_coord="com.vendor:adapter",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/LoggingAdapter.java",
            line=10,
        )
        edge = SimpleNamespace(
            caller_symbol_id="caller",
            caller_qualified_key=caller.qualified_key,
            callee_key="org.slf4j.Logger.isDebugEnabled()",
            callee_simple_key="method:isDebugEnabled()",
            confidence="high",
            evidence_type="ast_method_invocation",
            file=caller.file,
            line=12,
            owner_type="dependency",
            owner_coord="com.vendor:adapter",
            module="runtime",
            is_test=False,
            callee_fqcn_complete=True,
            callee_signature_complete=True,
        )
        graph = SimpleNamespace(
            methods_by_id={"caller": caller},
            reverse_edges={
                "org.slf4j.Logger.isDebugEnabled": [edge],
                "org.slf4j.Logger.isDebugEnabled()": [edge],
            },
            runtime_dependency_catalog={},
        )

        with patch.object(
            tracer,
            "_scan_packaged_runtime_dependencies_for_api",
            return_value={"status": "miss", "hits": []},
        ):
            result = tracer.trace_api_with_confidence_weighting(
                api_row,
                graph,
                {},
                max_total_cost=5,
                has_packaged_bytecode_fallback=True,
            )

        self.assertEqual(result.analysis_status, "not_found_in_static_analysis")
        self.assertNotEqual(result.reason_code, "OVERLOAD_AMBIGUOUS_TARGET")

    def test_collect_overload_signatures_ignores_invalid_parser_noise(self):
        reverse_edges = {
            "org.example.Expression.write(StringBuilder, int)": [object()],
            "org.example.Expression.write(builder, values, sqlFlags).append()": [object()],
            "org.example.Expression.write(String>, int)": [object()],
        }

        signatures = tracer.collect_overload_signatures("org.example.Expression.write", reverse_edges)

        self.assertEqual(signatures, {"(StringBuilder, int)"})

    def test_trace_api_uses_unique_compatible_target_overload_signature(self):
        api_row = {
            "api_name": "org.example.TargetApi.call",
            "api_simple": "call",
            "api_signature": "(org.example.Session, org.example.DbObject)",
            "symbol_kind": "method",
            "change_type": "method_changed",
            "coord": "org.example:demo",
            "severity": "P0",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        business_entry = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="org.example.Controller.handle",
            simple_key="method:handle",
            class_fqcn="org.example.Controller",
            class_name="Controller",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Controller.java",
            line=18,
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_entry},
            reverse_edges={
                "org.example.TargetApi.call": [
                    SimpleNamespace(
                        caller_symbol_id="business_entry",
                        caller_qualified_key=business_entry.qualified_key,
                        callee_key="org.example.TargetApi.call(SessionLocal, DbObject)",
                        callee_simple_key="method:call(SessionLocal, DbObject)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=business_entry.file,
                        line=18,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
                "org.example.TargetApi.call(SessionLocal, DbObject)": [
                    SimpleNamespace(
                        caller_symbol_id="business_entry",
                        caller_qualified_key=business_entry.qualified_key,
                        callee_key="org.example.TargetApi.call(SessionLocal, DbObject)",
                        callee_simple_key="method:call(SessionLocal, DbObject)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=business_entry.file,
                        line=18,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
                "org.example.TargetApi.call(SessionLocal, String)": [],
            },
        )
        type_metadata = {
            "org.example.Session": {
                "kind": "interface",
                "extends": [],
                "implements": [],
                "implementations": ["org.example.SessionLocal"],
                "annotations": [],
            },
            "org.example.SessionLocal": {
                "kind": "class",
                "extends": [],
                "implements": ["org.example.Session"],
                "implementations": [],
                "annotations": [],
            },
            "org.example.DbObject": {
                "kind": "class",
                "extends": [],
                "implements": [],
                "implementations": [],
                "annotations": [],
            },
        }

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, type_metadata, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")
        self.assertEqual(result.match_provenance, "compatible_signature")

    def test_trace_api_uses_builtin_java_assignable_signature_for_target_overload(self):
        api_row = {
            "api_name": "org.apache.commons.lang3.StringUtils.isBlank",
            "api_simple": "isBlank",
            "api_signature": "(CharSequence)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "org.apache.commons:commons-lang3",
            "severity": "HIGH",
            "confirmed": "true",
            "source": "japicmp",
            "analysis_scope": "method",
        }
        business_entry = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="org.example.Controller.handle",
            simple_key="method:handle",
            class_fqcn="org.example.Controller",
            class_name="Controller",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Controller.java",
            line=18,
        )
        edge = SimpleNamespace(
            caller_symbol_id="business_entry",
            caller_qualified_key=business_entry.qualified_key,
            callee_key="org.apache.commons.lang3.StringUtils.isBlank(String)",
            callee_simple_key="method:isBlank(String)",
            confidence="high",
            evidence_type="ast_method_invocation",
            file=business_entry.file,
            line=18,
            owner_type="business",
            owner_coord="BUSINESS",
            module="app",
            is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_entry},
            reverse_edges={
                "org.apache.commons.lang3.StringUtils.isBlank": [edge],
                "org.apache.commons.lang3.StringUtils.isBlank(String)": [edge],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")
        self.assertEqual(result.match_provenance, "compatible_signature")

    def test_trace_api_uses_builtin_map_assignable_signature_for_target_overload(self):
        api_row = {
            "api_name": "org.apache.dubbo.common.utils.CollectionUtils.isEmptyMap",
            "api_simple": "isEmptyMap",
            "api_signature": "(Map)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "org.apache.dubbo:dubbo-common",
            "severity": "HIGH",
            "confirmed": "true",
            "source": "japicmp",
            "analysis_scope": "method",
        }
        business_entry = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="org.example.Controller.handle",
            simple_key="method:handle",
            class_fqcn="org.example.Controller",
            class_name="Controller",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Controller.java",
            line=18,
        )
        edge = SimpleNamespace(
            caller_symbol_id="business_entry",
            caller_qualified_key=business_entry.qualified_key,
            callee_key="org.apache.dubbo.common.utils.CollectionUtils.isEmptyMap(ConcurrentMap<Class<?>, Merger<?>>)",
            callee_simple_key="method:isEmptyMap(ConcurrentMap<Class<?>, Merger<?>>)",
            confidence="high",
            evidence_type="ast_method_invocation",
            file=business_entry.file,
            line=18,
            owner_type="business",
            owner_coord="BUSINESS",
            module="app",
            is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_entry},
            reverse_edges={
                "org.apache.dubbo.common.utils.CollectionUtils.isEmptyMap": [edge],
                "org.apache.dubbo.common.utils.CollectionUtils.isEmptyMap(ConcurrentMap<Class<?>, Merger<?>>)": [edge],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")
        self.assertEqual(result.match_provenance, "compatible_signature")

    def test_trace_api_uses_builtin_concurrent_hash_map_assignable_signature(self):
        api_row = {
            "api_name": "org.apache.dubbo.common.utils.CollectionUtils.isEmptyMap",
            "api_simple": "isEmptyMap",
            "api_signature": "(Map)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "org.apache.dubbo:dubbo-common",
            "severity": "HIGH",
            "confirmed": "true",
            "source": "japicmp",
            "analysis_scope": "method",
        }
        business_entry = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="org.example.Controller.handle",
            simple_key="method:handle",
            class_fqcn="org.example.Controller",
            class_name="Controller",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Controller.java",
            line=18,
        )
        edge = SimpleNamespace(
            caller_symbol_id="business_entry",
            caller_qualified_key=business_entry.qualified_key,
            callee_key="org.apache.dubbo.common.utils.CollectionUtils.isEmptyMap(ConcurrentHashMap<?, ConcurrentHashMap<T, AtomicLong>>)",
            callee_simple_key="method:isEmptyMap(ConcurrentHashMap<?, ConcurrentHashMap<T, AtomicLong>>)",
            confidence="high",
            evidence_type="ast_method_invocation",
            file=business_entry.file,
            line=18,
            owner_type="business",
            owner_coord="BUSINESS",
            module="app",
            is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_entry},
            reverse_edges={
                "org.apache.dubbo.common.utils.CollectionUtils.isEmptyMap": [edge],
                "org.apache.dubbo.common.utils.CollectionUtils.isEmptyMap(ConcurrentHashMap<?, ConcurrentHashMap<T, AtomicLong>>)": [edge],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")
        self.assertEqual(result.match_provenance, "compatible_signature")

    def test_select_compatible_overload_signatures_supports_varargs_target(self):
        compatible = tracer.select_compatible_overload_signatures(
            "(boolean, String, Object...)",
            {
                "(boolean, String)",
                "(boolean, String, int)",
                "(boolean, String, Object[])",
                "(boolean)",
                "(String, String)",
            },
            {},
        )

        self.assertEqual(
            set(compatible),
            {"(boolean, String)", "(boolean, String, int)", "(boolean, String, Object[])"},
        )

    def test_trace_api_uses_all_compatible_varargs_observed_signatures(self):
        api_row = {
            "api_name": "org.apache.commons.lang3.Validate.isTrue",
            "api_simple": "isTrue",
            "api_signature": "(boolean, String, Object...)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "org.apache.commons:commons-lang3",
            "severity": "P1",
            "confirmed": "true",
            "source": "varargs_fixture",
            "analysis_scope": "api",
        }
        two_arg_method = SimpleNamespace(
            symbol_id="two_arg",
            qualified_key="com.biz.TwoArg.call",
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            file="TwoArg.java",
            line=10,
        )
        three_arg_method = SimpleNamespace(
            symbol_id="three_arg",
            qualified_key="com.biz.ThreeArg.call",
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            file="ThreeArg.java",
            line=20,
        )
        graph = SimpleNamespace(
            methods_by_id={"two_arg": two_arg_method, "three_arg": three_arg_method},
            reverse_edges={
                "org.apache.commons.lang3.Validate.isTrue(boolean, String)": [
                    SimpleNamespace(
                        caller_symbol_id="two_arg",
                        caller_qualified_key=two_arg_method.qualified_key,
                        callee_key="org.apache.commons.lang3.Validate.isTrue(boolean, String)",
                        callee_simple_key="method:isTrue(boolean, String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=two_arg_method.file,
                        line=10,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    )
                ],
                "org.apache.commons.lang3.Validate.isTrue(boolean, String, int)": [
                    SimpleNamespace(
                        caller_symbol_id="three_arg",
                        caller_qualified_key=three_arg_method.qualified_key,
                        callee_key="org.apache.commons.lang3.Validate.isTrue(boolean, String, int)",
                        callee_simple_key="method:isTrue(boolean, String, int)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=three_arg_method.file,
                        line=20,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    )
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.match_provenance, "compatible_signature")
        path_texts = [item.get("path_text", "") for item in result.path_details]
        self.assertTrue(any("com.biz.TwoArg.call" in path for path in path_texts))
        self.assertTrue(any("com.biz.ThreeArg.call" in path for path in path_texts))

    def test_varargs_target_does_not_steal_exact_sibling_overload_call(self):
        api_row = {
            "api_name": "org.slf4j.Logger.info",
            "api_simple": "info",
            "api_signature": "(java.lang.String, java.lang.Object...)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "org.slf4j:slf4j-api",
            "severity": "P0",
            "confirmed": "true",
            "source": "old_jar",
        }
        business_method = SimpleNamespace(
            symbol_id="business",
            qualified_key="com.biz.App.run",
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            file="App.java",
            line=10,
        )
        edge = SimpleNamespace(
            caller_symbol_id="business",
            caller_qualified_key=business_method.qualified_key,
            callee_key="org.slf4j.Logger.info(String, Object)",
            callee_simple_key="method:info(String, Object)",
            confidence="high",
            evidence_type="bytecode_method_invocation",
            file="app.jar!/App.class",
            line=10,
            owner_type="business",
            owner_coord="BUSINESS",
            module="app",
            is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"business": business_method},
            reverse_edges={"org.slf4j.Logger.info(String, Object)": [edge]},
            changed_api_overload_signatures={
                "org.slf4j.Logger.info": frozenset({
                    "(java.lang.String, java.lang.Object)",
                    "(java.lang.String, java.lang.Object...)",
                })
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertNotEqual(result.analysis_status, "reachable")
        self.assertNotIn("String, Object) →", "\n".join(result.call_paths))

    def test_varargs_target_does_not_steal_call_applicable_to_fixed_sibling(self):
        graph = SimpleNamespace(
            changed_api_overload_signatures={
                "org.slf4j.Logger.info": frozenset({
                    "(java.lang.String, java.lang.Object)",
                    "(java.lang.String, java.lang.Object...)",
                })
            }
        )

        retained = tracer.exclude_signatures_owned_by_sibling_overloads(
            "org.slf4j.Logger.info",
            "(java.lang.String, java.lang.Object...)",
            ["(String, String)", "(String, Object[])"],
            graph,
            {},
        )

        self.assertEqual(retained, ["(String, Object[])"])

    def test_exact_packaged_bytecode_hit_survives_source_overload_ambiguity(self):
        api_row = {
            "api_name": "org.slf4j.Logger.info",
            "api_simple": "info",
            "api_signature": "(java.lang.String, java.lang.Object...)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "org.slf4j:slf4j-api",
            "new_version": "-",
            "severity": "P0",
            "confirmed": "true",
            "source": "old_jar",
        }
        identity = tracer.build_api_identity_key(api_row)
        dependency_hit = {
            "coord": "com.example:consumer",
            "jar_path": "/runtime/consumer.jar",
            "class_fqcn": "com.example.Consumer",
            "consumer_method": "run",
            "consumer_signature": "()",
            "evidence_type": "bytecode_method_invocation",
            "target_display": "org.slf4j.Logger.info(String, Object[])",
        }
        dependency_method = SimpleNamespace(
            symbol_id="dep",
            qualified_key="com.example.Consumer.run",
            owner_type="dependency",
            owner_coord="com.example:consumer",
            is_test=False,
            file="Consumer.java",
            line=10,
            annotations=[],
            class_annotations=[],
        )
        ambiguous_edge = SimpleNamespace(
            caller_symbol_id="dep",
            caller_qualified_key=dependency_method.qualified_key,
            callee_key="org.slf4j.Logger.info(String, String)",
            callee_simple_key="method:info(String, String)",
            confidence="high",
            evidence_type="ast_method_invocation",
            file="Consumer.java",
            line=10,
            owner_type="dependency",
            owner_coord="com.example:consumer",
            module="consumer",
            is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"dep": dependency_method},
            reverse_edges={"org.slf4j.Logger.info(String, String)": [ambiguous_edge]},
            runtime_dependency_catalog={
                "_packaged_api_scan_results": {
                    identity: {"status": "hit", "hits": [dependency_hit]}
                },
                "_packaged_api_scan_stat_snapshot": (
                    tracer._runtime_artifact_stat_snapshot([], None)
                ),
            },
            changed_api_overload_signatures={
                "org.slf4j.Logger.info": frozenset({
                    "(java.lang.String, java.lang.Object)",
                    "(java.lang.String, java.lang.Object...)",
                })
            },
            framework_runtime_entry_methods={},
        )

        result = tracer.trace_api_with_confidence_weighting(
            api_row,
            graph,
            {},
            max_total_cost=5,
            has_packaged_bytecode_fallback=True,
        )

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "RUNTIME_DEPENDENCY_USES_REMOVED_API")
        self.assertIn("com.example:consumer", result.call_paths[0])
        self.assertIn("Object[]", result.call_paths[0])

    def test_build_graph_infers_boolean_expression_for_varargs_validation_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import org.apache.commons.lang3.Validate;",
                        "",
                        "public class Demo {",
                        "    public void check(int upper, int lower) {",
                        "        Validate.isTrue(upper >= lower, \"upper must be >= lower\");",
                        "        Validate.isTrue(upper >= 0, \"upper %d is negative\", upper);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.commons.lang3.Validate.isTrue(boolean, String)", graph.reverse_edges)
            self.assertIn("org.apache.commons.lang3.Validate.isTrue(boolean, String, int)", graph.reverse_edges)

    def test_build_graph_infers_stringutils_boolean_return_for_validation_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import org.apache.commons.lang3.StringUtils;",
                        "import org.apache.commons.lang3.Validate;",
                        "",
                        "public class Demo {",
                        "    public void check(CharSequence text) {",
                        "        Validate.isTrue(StringUtils.isNotBlank(text), \"Invalid text\");",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.commons.lang3.Validate.isTrue(boolean, String)", graph.reverse_edges)
            self.assertNotIn("org.apache.commons.lang3.Validate.isTrue(StringUtils, String)", graph.reverse_edges)

    def test_build_graph_infers_chained_string_return_for_url_valueof(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import org.apache.dubbo.common.URL;",
                        "",
                        "public class Demo {",
                        "    public void handle(String msg) {",
                        "        URL.valueOf(msg.substring(\"REGISTER\".length()).trim());",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.dubbo.common.URL.valueOf(String)", graph.reverse_edges)

    def test_build_graph_infers_class_boolean_and_string_returns_for_varargs(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import org.apache.commons.lang3.Validate;",
                        "",
                        "public class Demo {",
                        "    public Demo(Class<?> listenerInterface) {",
                        "        Validate.isTrue(listenerInterface.isInterface(), \"Class %s is not an interface\", listenerInterface.getName());",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.commons.lang3.Validate.isTrue(boolean, String, String)", graph.reverse_edges)

    def test_trace_api_does_not_start_from_unrelated_simple_signature_target(self):
        api_row = {
            "api_name": "com.lib.Target.parse",
            "api_simple": "parse",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "lib:demo",
            "severity": "P0",
            "confirmed": "true",
            "source": "japicmp",
            "analysis_scope": "method",
        }
        business_entry = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.biz.Entry.handle",
            simple_key="method:handle",
            class_fqcn="com.biz.Entry",
            class_name="Entry",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Entry.java",
            line=12,
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_entry},
            reverse_edges={
                "method:parse(String)": [
                    SimpleNamespace(
                        caller_symbol_id="business_entry",
                        caller_qualified_key=business_entry.qualified_key,
                        callee_key="com.other.Helper.parse(String)",
                        callee_simple_key="method:parse(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=business_entry.file,
                        line=15,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "not_found_in_static_analysis")
        self.assertEqual(result.reason_code, "NO_STATIC_PATH")

    def test_trace_api_marks_low_confidence_edge_stop_separately_from_depth_limit(self):
        api_row = {
            "api_name": "com.lib.Target.parse",
            "api_simple": "parse",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "lib:demo",
            "severity": "P0",
            "confirmed": "true",
            "source": "japicmp",
            "analysis_scope": "method",
        }
        dependency_bridge = SimpleNamespace(
            symbol_id="dependency_bridge",
            qualified_key="com.lib.DependencyBridge.invoke",
            simple_key="method:invoke",
            class_fqcn="com.lib.DependencyBridge",
            class_name="DependencyBridge",
            method_name="invoke",
            param_types={},
            param_declared_types={},
            owner_type="dependency",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/DependencyBridge.java",
            line=22,
        )
        graph = SimpleNamespace(
            methods_by_id={"dependency_bridge": dependency_bridge},
            reverse_edges={
                "com.lib.Target.parse(String)": [
                    SimpleNamespace(
                        caller_symbol_id="dependency_bridge",
                        caller_qualified_key=dependency_bridge.qualified_key,
                        callee_key="com.lib.Target.parse(String)",
                        callee_simple_key="method:parse(String)",
                        confidence="low",
                        evidence_type="ast_method_invocation",
                        file=dependency_bridge.file,
                        line=dependency_bridge.line,
                        owner_type="dependency",
                        owner_coord="lib:bridge",
                        module="bridge",
                        is_test=False,
                    ),
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "LOW_CONFIDENCE_EDGE")

    def test_trace_api_marks_non_method_static_miss_as_call_graph_limitation(self):
        graph = SimpleNamespace(methods_by_id={}, reverse_edges={})

        cases = [
            {
                "api_name": "com.lib.TargetType",
                "api_simple": "",
                "api_signature": "",
                "symbol_kind": "class",
            },
            {
                "api_name": "com.lib.TargetType.FIELD",
                "api_simple": "FIELD",
                "api_signature": "",
                "symbol_kind": "field",
            },
        ]

        for case in cases:
            with self.subTest(symbol_kind=case["symbol_kind"]):
                api_row = {
                    "change_type": "REMOVED",
                    "coord": "lib:demo",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "japicmp",
                    "analysis_scope": "api",
                    **case,
                }

                result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

                self.assertEqual(result.analysis_status, "not_analyzed")
                self.assertEqual(result.reason_code, "CALL_GRAPH_LIMITATION_SYMBOL_KIND")
                self.assertIn(case["symbol_kind"], result.reachable_note)

    def test_trace_api_marks_class_usage_candidate_reachable_when_business_code_directly_uses_type(self):
        api_row = {
            "api_name": "com.lib.TargetType",
            "api_simple": "TargetType",
            "api_signature": "",
            "symbol_kind": "class",
            "change_type": "REMOVED",
            "coord": "lib:demo",
            "severity": "P1",
            "confirmed": "false",
            "source": "candidate_scan",
            "analysis_scope": "class_usage",
            "matched_class": "com.lib.TargetType",
        }
        business_method = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.biz.Entry.handle",
            simple_key="method:handle",
            class_fqcn="com.biz.Entry",
            class_name="Entry",
            method_name="handle",
            return_type="void",
            file="Entry.java",
            line=12,
            owner_type="business",
            is_test=False,
            param_types={},
            field_types={},
            local_var_types={},
            imports={"TargetType": "com.lib.TargetType"},
            static_imports={},
            get_body_text=lambda: "return TargetType.class;",
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_method},
            reverse_edges={},
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "DIRECT_CLASS_USAGE")
        self.assertIn("com.biz.Entry.handle", result.call_paths[0])
        self.assertIn("com.lib.TargetType", result.call_paths[0])

    def test_trace_api_keeps_all_distinct_direct_class_usage_entries_in_stable_order(self):
        api_row = {
            "api_name": "com.lib.TargetType",
            "api_simple": "TargetType",
            "api_signature": "",
            "symbol_kind": "class",
            "change_type": "REMOVED",
            "coord": "lib:demo",
            "severity": "P1",
            "confirmed": "false",
            "source": "candidate_scan",
            "analysis_scope": "class_usage",
            "matched_class": "com.lib.TargetType",
        }

        def method(symbol_id, qualified_key, line, *, is_test=False):
            class_name = qualified_key.rsplit(".", 2)[-2]
            return SimpleNamespace(
                symbol_id=symbol_id,
                qualified_key=qualified_key,
                class_fqcn=qualified_key.rsplit(".", 1)[0],
                method_name=qualified_key.rsplit(".", 1)[-1],
                return_type="void",
                file=f"/repo/{class_name.lower()}-app/src/main/java/com/biz/{class_name}.java",
                line=line,
                owner_type="business",
                is_test=is_test,
                param_types={},
                field_types={},
                local_var_types={"target": "com.lib.TargetType"},
                imports={},
                wildcard_imports=[],
                get_body_text=lambda: "",
            )

        second = method("second", "com.biz.Second.handle", 20)
        first = method("first", "com.biz.First.handle", 10)
        duplicate_first = method("first-alias", "com.biz.First.handle", 10)
        test_entry = method("test", "com.biz.TargetTypeTest.handle", 30, is_test=True)
        graph = SimpleNamespace(
            methods_by_id={
                "second": second,
                "test": test_entry,
                "first-alias": duplicate_first,
                "first": first,
            },
            reverse_edges={},
        )

        result = tracer.trace_api_with_confidence_weighting(
            api_row, graph, {}, max_total_cost=5
        )

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "DIRECT_CLASS_USAGE")
        self.assertEqual(result.direct_callers, 2)
        self.assertEqual(result.call_paths, [
            "com.biz.First.handle -> com.lib.TargetType",
            "com.biz.Second.handle -> com.lib.TargetType",
        ])
        self.assertEqual(len(result.evidence_paths), 2)
        self.assertEqual(len(result.path_details), 2)
        self.assertEqual(
            [detail["business_entry"] for detail in result.path_details],
            ["com.biz.First.handle", "com.biz.Second.handle"],
        )

        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "call_chain"
            formatter.generate_enhanced_summary([result], output_dir)
            output = output_dir / "alerts.csv"
            with output.open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            by_api_path = output_dir / "by_api" / (
                formatter.build_by_api_safe_filename(result) + ".txt"
            )
            by_api_text = by_api_path.read_text(encoding="utf-8")
            first_module = json.loads(
                (output_dir / "by_module" / "first-app_impacts.json").read_text(
                    encoding="utf-8"
                )
            )
            second_module = json.loads(
                (output_dir / "by_module" / "second-app_impacts.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(len(rows), 2)
        self.assertEqual(
            {(row["consumer_class"], row["consumer_method"]) for row in rows},
            {("com.biz.First", "handle"), ("com.biz.Second", "handle")},
        )
        self.assertIn("com.biz.First.handle -> com.lib.TargetType", by_api_text)
        self.assertIn("com.biz.Second.handle -> com.lib.TargetType", by_api_text)
        self.assertEqual(len(first_module["impacts"]), 1)
        self.assertEqual(len(second_module["impacts"]), 1)

    def test_trace_api_does_not_treat_fqcn_string_as_direct_class_usage(self):
        api_row = {
            "api_name": "com.lib.OptionalType",
            "api_simple": "OptionalType",
            "api_signature": "",
            "symbol_kind": "class",
            "change_type": "REMOVED",
            "coord": "lib:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "japicmp",
            "analysis_scope": "class_usage",
            "matched_class": "com.lib.OptionalType",
        }
        business_method = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.biz.Entry.configure",
            simple_key="method:configure",
            class_fqcn="com.biz.Entry",
            class_name="Entry",
            method_name="configure",
            return_type="void",
            file="Entry.java",
            line=12,
            owner_type="business",
            is_test=False,
            param_types={},
            field_types={},
            local_var_types={},
            imports={},
            wildcard_imports=[],
            static_imports={},
            get_body_text=lambda: (
                'loader.load("com.lib.OptionalType"); '
                '// com.lib.OptionalType\n'
                'String note = "com.lib.OptionalType";'
            ),
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_method},
            reverse_edges={},
        )

        result = tracer.trace_api_with_confidence_weighting(
            api_row, graph, {}, max_total_cost=5
        )

        self.assertNotEqual(result.reason_code, "DIRECT_CLASS_USAGE")
        self.assertNotEqual(result.analysis_status, "reachable")

    def test_trace_api_does_not_upgrade_class_usage_when_import_resolves_simple_name_to_other_type(self):
        api_row = {
            "api_name": "org.apache.commons.lang.time.StopWatch",
            "api_simple": "StopWatch",
            "api_signature": "",
            "symbol_kind": "class",
            "change_type": "REMOVED",
            "coord": "commons-lang:commons-lang",
            "severity": "P1",
            "confirmed": "false",
            "source": "candidate_scan",
            "analysis_scope": "class_usage",
            "matched_class": "org.apache.commons.lang.time.StopWatch",
        }
        business_method = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.biz.Entry.handle",
            simple_key="method:handle",
            class_fqcn="com.biz.Entry",
            class_name="Entry",
            method_name="handle",
            return_type="void",
            file="Entry.java",
            line=12,
            owner_type="business",
            is_test=False,
            param_types={},
            field_types={},
            local_var_types={},
            imports={"StopWatch": "org.springframework.util.StopWatch"},
            wildcard_imports=[],
            static_imports={},
            get_body_text=lambda: "StopWatch sw = new StopWatch(); sw.stop();",
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_method},
            reverse_edges={},
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "CLASS_USAGE_ONLY")

    def test_trace_api_keeps_fqcn_class_usage_reachable_even_when_simple_name_import_conflicts(self):
        api_row = {
            "api_name": "org.apache.commons.lang.time.StopWatch",
            "api_simple": "StopWatch",
            "api_signature": "",
            "symbol_kind": "class",
            "change_type": "REMOVED",
            "coord": "commons-lang:commons-lang",
            "severity": "P1",
            "confirmed": "false",
            "source": "candidate_scan",
            "analysis_scope": "class_usage",
            "matched_class": "org.apache.commons.lang.time.StopWatch",
        }
        business_method = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.biz.Entry.handle",
            simple_key="method:handle",
            class_fqcn="com.biz.Entry",
            class_name="Entry",
            method_name="handle",
            return_type="void",
            file="Entry.java",
            line=18,
            owner_type="business",
            is_test=False,
            param_types={},
            field_types={},
            local_var_types={},
            imports={"StopWatch": "org.springframework.util.StopWatch"},
            wildcard_imports=[],
            static_imports={},
            get_body_text=lambda: (
                "org.apache.commons.lang.time.StopWatch watch = "
                "new org.apache.commons.lang.time.StopWatch();"
            ),
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_method},
            reverse_edges={},
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "DIRECT_CLASS_USAGE")
        self.assertIn("org.apache.commons.lang.time.StopWatch", result.call_paths[0])

    def test_trace_api_keeps_class_usage_reachable_with_wildcard_import(self):
        api_row = {
            "api_name": "org.apache.commons.lang.time.StopWatch",
            "api_simple": "StopWatch",
            "api_signature": "",
            "symbol_kind": "class",
            "change_type": "REMOVED",
            "coord": "commons-lang:commons-lang",
            "severity": "P1",
            "confirmed": "false",
            "source": "candidate_scan",
            "analysis_scope": "class_usage",
            "matched_class": "org.apache.commons.lang.time.StopWatch",
        }
        business_method = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.biz.Entry.handle",
            simple_key="method:handle",
            class_fqcn="com.biz.Entry",
            class_name="Entry",
            method_name="handle",
            return_type="void",
            file="Entry.java",
            line=22,
            owner_type="business",
            is_test=False,
            param_types={},
            field_types={},
            local_var_types={},
            imports={},
            wildcard_imports=["org.apache.commons.lang.time"],
            static_imports={},
            get_body_text=lambda: "StopWatch watch = new StopWatch();",
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_method},
            reverse_edges={},
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "DIRECT_CLASS_USAGE")

    def test_direct_class_usage_covers_structured_java_type_syntaxes(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "TypeUses.java"
            source.write_text(
                """package com.example.app;
import com.vendor.Target;
import java.util.List;
import java.util.function.Supplier;
@Target class AnnotationUse { void use() {} }
class GenericUse { List<Target> use() { return null; } }
class InheritanceUse extends Target { void use() {} }
class ThrowsUse { void use() throws Target {} }
class ClassLiteralUse { Class<?> use() { return Target.class; } }
class InstanceofUse { boolean use(Object value) { return value instanceof Target; } }
class CastUse { Object use(Object value) { return (Target) value; } }
class ConstructorUse { Object use() { return new Target(); } }
class MethodReferenceUse { Runnable use() { return Target::make; } }
class StaticQualifiedUse { void use() { Target.make(); } }
class StaticFieldUse { int use() { return Target.FIELD; } }
""",
                encoding="utf-8",
            )
            graph_result = step5.build_enhanced_source_graph([{
                "root": tmp,
                "owner_type": "business",
                "owner_coord": "BUSINESS",
                "module": "app",
            }])
            graph = graph_result["graph"]
            usages = tracer._find_direct_business_class_usages({
                "api_name": "com.vendor.Target",
                "matched_class": "com.vendor.Target",
            }, graph)

        evidence_by_class = {
            method.class_name: evidence_type
            for method, evidence_type in usages
        }
        self.assertEqual(graph_result["stats"]["parser_usage"]["tree_sitter"], 1)
        self.assertEqual(evidence_by_class, {
            "AnnotationUse": "annotation_type",
            "GenericUse": "generic_or_declared_type",
            "InheritanceUse": "inheritance_type",
            "ThrowsUse": "throws_type",
            "ClassLiteralUse": "class_literal_type",
            "InstanceofUse": "instanceof_type",
            "CastUse": "cast_type",
            "ConstructorUse": "constructor_type",
            "MethodReferenceUse": "method_reference_type",
            "StaticQualifiedUse": "static_qualified_type",
            "StaticFieldUse": "static_qualified_type",
        })

    def test_structured_type_usage_rejects_same_simple_name_from_other_import(self):
        method = SimpleNamespace(
            class_fqcn="com.example.app.Use",
            package_name="com.example.app",
            return_type="java.util.List",
            param_types={},
            field_types={},
            local_var_types={},
            return_declared_type="List<Target>",
            param_declared_types={},
            field_declared_types={},
            ast_local_var_sites=[],
            annotations=["Target"],
            class_annotations=[],
            throws_declared_types=["Target"],
            ast_call_sites=[{
                "kind": "method_invocation",
                "receiver_expr": "Target",
            }],
            imports={"Target": "com.other.Target"},
            wildcard_imports=[],
            known_classes_by_simple={
                "Target": ("com.vendor.Target", "com.other.Target"),
            },
        )
        graph = SimpleNamespace(type_metadata={
            "com.example.app.Use": {
                "extends": ["com.other.Target"],
                "implements": [],
            },
        })

        evidence = tracer._find_structured_type_usage_evidence(
            method,
            "com.vendor.Target",
            graph,
        )

        self.assertEqual(evidence, "")

    def test_static_type_usage_rejects_a_value_that_shadows_the_type_name(self):
        method = SimpleNamespace(
            class_fqcn="com.example.app.Use",
            package_name="com.example.app",
            return_type="void",
            param_types={"Target": "java.lang.Object"},
            field_types={},
            local_var_types={},
            return_declared_type="void",
            param_declared_types={"Target": "Object"},
            field_declared_types={},
            ast_local_var_sites=[],
            annotations=[],
            class_annotations=[],
            throws_declared_types=[],
            ast_call_sites=[{
                "kind": "method_invocation",
                "receiver_expr": "Target",
                "scope_local_var_types": {},
            }],
            imports={"Target": "com.vendor.Target"},
            wildcard_imports=[],
        )

        evidence = tracer._find_structured_type_usage_evidence(
            method,
            "com.vendor.Target",
            SimpleNamespace(type_metadata={}),
        )

        self.assertEqual(evidence, "")

    def test_exact_high_confidence_tracing_covers_1_2_5_and_10_plus_hops(self):
        for hops in (1, 2, 5, 12):
            with self.subTest(hops=hops):
                api_row, graph = self._exact_chain_fixture(hops)
                result = tracer.trace_api_with_confidence_weighting(
                    api_row,
                    graph,
                    {},
                    max_total_cost=5,
                )

                self.assertEqual(result.analysis_status, "reachable")
                self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")
                self.assertTrue(any(
                    detail["depth"] == hops
                    for detail in result.path_details
                    if detail["path_status"] == "reachable"
                ))
                if hops > 5:
                    perf = tracer._finalize_step5_perf_stats(graph)["trace"]
                    self.assertGreater(perf["adaptive_exact_high_frontier_steps"], 0)
                    self.assertGreaterEqual(perf["adaptive_exact_high_cost_limit"], hops)

    def test_adaptive_budget_does_not_expand_a_medium_confidence_path(self):
        api_row, graph = self._exact_chain_fixture(
            12,
            first_edge_confidence="medium",
        )

        result = tracer.trace_api_with_confidence_weighting(
            api_row,
            graph,
            {},
            max_total_cost=5,
        )

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "DEPTH_LIMIT_REACHED")
        truncated = [
            detail for detail in result.path_details
            if detail["stop_reason"] == "DEPTH_LIMIT_REACHED"
        ]
        self.assertEqual(len(truncated), 1)
        self.assertEqual(truncated[0]["budget_limit"], 5)
        self.assertTrue(truncated[0]["truncated_target"])
        self.assertEqual(truncated[0]["truncated_candidate_count"], 1)
        perf = tracer._finalize_step5_perf_stats(graph)["trace"]
        self.assertEqual(perf.get("adaptive_exact_high_frontier_steps", 0), 0)

    def test_exact_path_reports_explicit_coverage_when_adaptive_cap_is_reached(self):
        api_row, graph = self._exact_chain_fixture(25)

        result = tracer.trace_api_with_confidence_weighting(
            api_row,
            graph,
            {},
            max_total_cost=5,
        )

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "DEPTH_LIMIT_REACHED")
        truncated = [
            detail for detail in result.path_details
            if detail["stop_reason"] == "DEPTH_LIMIT_REACHED"
        ]
        self.assertEqual(len(truncated), 1)
        self.assertEqual(truncated[0]["budget_limit"], 15)
        self.assertEqual(truncated[0]["depth"], 15)
        self.assertTrue(truncated[0]["truncated_target"])
        self.assertEqual(truncated[0]["truncated_candidate_count"], 1)
        alert_rows = formatter._alert_rows_for_result(result)
        self.assertIn("预算=15", alert_rows[0]["coverage_details"])
        self.assertIn("候选数=1", alert_rows[0]["coverage_details"])
        self.assertIn(truncated[0]["truncated_target"], alert_rows[0]["coverage_details"])

    def test_increasing_exact_path_budget_preserves_confirmed_evidence(self):
        api_row, base_graph = self._exact_chain_fixture(12)
        base = tracer.trace_api_with_confidence_weighting(
            api_row,
            base_graph,
            {},
            max_total_cost=5,
        )
        api_row, raised_graph = self._exact_chain_fixture(12)
        raised = tracer.trace_api_with_confidence_weighting(
            api_row,
            raised_graph,
            {},
            max_total_cost=8,
        )

        self.assertEqual(base.analysis_status, "reachable")
        self.assertEqual(raised.analysis_status, "reachable")
        self.assertEqual(base.reason_code, raised.reason_code)
        self.assertEqual(base.call_paths, raised.call_paths)
        self.assertEqual(base.evidence_paths, raised.evidence_paths)

    def test_trace_api_marks_field_static_import_usage_as_reachable(self):
        api_row = {
            "api_name": "com.lib.TargetType.FIELD",
            "api_simple": "FIELD",
            "api_signature": "",
            "symbol_kind": "field",
            "change_type": "REMOVED",
            "coord": "lib:demo",
            "severity": "P1",
            "confirmed": "false",
            "source": "candidate_scan",
            "analysis_scope": "api",
        }
        business_method = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.biz.Entry.handle",
            simple_key="method:handle",
            class_fqcn="com.biz.Entry",
            class_name="Entry",
            method_name="handle",
            return_type="void",
            file="Entry.java",
            line=18,
            owner_type="business",
            is_test=False,
            static_imports={"FIELD": "com.lib.TargetType.FIELD"},
            get_body_text=lambda: "return FIELD;",
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_method},
            reverse_edges={},
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "DIRECT_STATIC_IMPORT_USAGE")
        self.assertIn("com.lib.TargetType.FIELD", result.call_paths[0])

    def test_trace_api_respects_import_owner_for_simple_static_field_access(self):
        api_row = {
            "api_name": "io.seata.common.StringUtils.EMPTY",
            "api_simple": "EMPTY",
            "api_signature": "",
            "symbol_kind": "field",
            "change_type": "REMOVED",
            "coord": "io.seata:seata-common",
            "severity": "P1",
            "confirmed": "false",
            "source": "candidate_scan",
            "analysis_scope": "api",
        }
        business_method = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.biz.RppAssignFacility.handle",
            simple_key="method:handle",
            class_fqcn="com.biz.RppAssignFacility",
            class_name="RppAssignFacility",
            method_name="handle",
            return_type="void",
            file="RppAssignFacility.java",
            line=913,
            owner_type="business",
            is_test=False,
            imports={"StringUtils": "org.apache.commons.lang3.StringUtils"},
            wildcard_imports=[],
            static_imports={},
            get_body_text=lambda: "return StringUtils.EMPTY;",
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_method},
            reverse_edges={},
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertNotEqual(result.reason_code, "DIRECT_FIELD_USAGE")

    def test_trace_api_marks_imported_simple_static_field_access_as_reachable(self):
        api_row = {
            "api_name": "org.apache.commons.lang3.StringUtils.EMPTY",
            "api_simple": "EMPTY",
            "api_signature": "",
            "symbol_kind": "field",
            "change_type": "REMOVED",
            "coord": "org.apache.commons:commons-lang3",
            "severity": "P1",
            "confirmed": "false",
            "source": "candidate_scan",
            "analysis_scope": "api",
        }
        business_method = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.biz.RppAssignFacility.handle",
            simple_key="method:handle",
            class_fqcn="com.biz.RppAssignFacility",
            class_name="RppAssignFacility",
            method_name="handle",
            return_type="void",
            file="RppAssignFacility.java",
            line=913,
            owner_type="business",
            is_test=False,
            imports={"StringUtils": "org.apache.commons.lang3.StringUtils"},
            wildcard_imports=[],
            static_imports={},
            get_body_text=lambda: "return StringUtils.EMPTY;",
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_method},
            reverse_edges={},
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "DIRECT_FIELD_USAGE")
        self.assertIn("org.apache.commons.lang3.StringUtils.EMPTY", result.call_paths[0])

    def test_trace_api_marks_same_package_simple_static_field_access_as_reachable(self):
        api_row = {
            "api_name": "org.apache.commons.lang3.StringUtils.EMPTY",
            "api_simple": "EMPTY",
            "api_signature": "",
            "symbol_kind": "field",
            "change_type": "REMOVED",
            "coord": "org.apache.commons:commons-lang3",
            "severity": "P1",
            "confirmed": "false",
            "source": "candidate_scan",
            "analysis_scope": "api",
        }
        business_method = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="org.apache.commons.lang3.AnnotationUtils.toString",
            simple_key="method:toString",
            class_fqcn="org.apache.commons.lang3.AnnotationUtils",
            class_name="AnnotationUtils",
            method_name="toString",
            return_type="String",
            file="AnnotationUtils.java",
            line=87,
            owner_type="business",
            is_test=False,
            package_name="org.apache.commons.lang3",
            imports={},
            wildcard_imports=[],
            static_imports={},
            get_body_text=lambda: "return value.orElse(StringUtils.EMPTY);",
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_method},
            reverse_edges={},
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "DIRECT_FIELD_USAGE")
        self.assertIn("org.apache.commons.lang3.StringUtils.EMPTY", result.call_paths[0])

    def test_trace_api_keeps_all_imported_static_field_access_paths(self):
        api_row = {
            "api_name": "org.apache.commons.lang3.StringUtils.EMPTY",
            "api_simple": "EMPTY",
            "api_signature": "",
            "symbol_kind": "field",
            "change_type": "REMOVED",
            "coord": "org.apache.commons:commons-lang3",
            "severity": "P1",
            "confirmed": "false",
            "source": "candidate_scan",
            "analysis_scope": "api",
        }

        def method(symbol_id, qualified_key, line):
            return SimpleNamespace(
                symbol_id=symbol_id,
                qualified_key=qualified_key,
                simple_key=f"method:{qualified_key.rsplit('.', 1)[-1]}",
                class_fqcn=qualified_key.rsplit('.', 1)[0],
                class_name=qualified_key.rsplit('.', 2)[-2],
                method_name=qualified_key.rsplit('.', 1)[-1],
                return_type="void",
                file=f"{qualified_key.rsplit('.', 2)[-2]}.java",
                line=line,
                owner_type="business",
                is_test=False,
                imports={"StringUtils": "org.apache.commons.lang3.StringUtils"},
                wildcard_imports=[],
                static_imports={},
                get_body_text=lambda: "return StringUtils.EMPTY;",
            )

        first = method("first", "com.biz.First.handle", 10)
        second = method("second", "com.biz.Second.handle", 20)
        graph = SimpleNamespace(
            methods_by_id={"first": first, "second": second},
            reverse_edges={},
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "DIRECT_FIELD_USAGE")
        self.assertEqual(result.direct_callers, 2)
        self.assertEqual(len(result.call_paths), 2)
        self.assertEqual(len(result.path_details), 2)
        self.assertTrue(any("com.biz.First.handle" in path for path in result.call_paths))
        self.assertTrue(any("com.biz.Second.handle" in path for path in result.call_paths))

    def test_build_graph_indexes_field_initializer_method_invocations(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import org.slf4j.Logger;",
                        "import org.slf4j.LoggerFactory;",
                        "",
                        "public class Demo {",
                        "    private static final Logger LOGGER = LoggerFactory.getLogger(Demo.class);",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.slf4j.LoggerFactory.getLogger(Class)", graph.reverse_edges)
            edge = graph.reverse_edges["org.slf4j.LoggerFactory.getLogger(Class)"][0]
            self.assertEqual(edge.evidence_type, "initializer_invocation")
            self.assertEqual(edge.caller_qualified_key, "com.example.Demo.<class-init>")

            result = tracer.trace_api_with_confidence_weighting(
                {
                    "api_name": "org.slf4j.LoggerFactory.getLogger",
                    "api_simple": "getLogger",
                    "api_signature": "(Class)",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "coord": "org.slf4j:slf4j-api",
                    "severity": "P1",
                    "confirmed": "false",
                    "source": "initializer_fixture",
                    "analysis_scope": "api",
                },
                graph,
                {},
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertTrue(any("com.example.Demo.<class-init>" in path for path in result.call_paths))

    def test_build_graph_resolves_static_imported_method_invocation_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import static org.apache.dubbo.common.utils.StringUtils.isEmpty;",
                        "",
                        "public class Demo {",
                        "    public boolean check(String value) {",
                        "        return isEmpty(value);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.dubbo.common.utils.StringUtils.isEmpty(String)", graph.reverse_edges)
            edge = graph.reverse_edges["org.apache.dubbo.common.utils.StringUtils.isEmpty(String)"][0]
            self.assertEqual(edge.evidence_type, "ast_method_invocation")
            self.assertEqual(edge.caller_qualified_key, "com.example.Demo.check")

            result = tracer.trace_api_with_confidence_weighting(
                {
                    "api_name": "org.apache.dubbo.common.utils.StringUtils.isEmpty",
                    "api_simple": "isEmpty",
                    "api_signature": "(String)",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "coord": "org.apache.dubbo:dubbo-common",
                    "severity": "P1",
                    "confirmed": "false",
                    "source": "dubbo_static_import_fixture",
                    "analysis_scope": "api",
                },
                graph,
                {},
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertTrue(any("com.example.Demo.check" in path for path in result.call_paths))

    def test_build_graph_uses_runtime_jar_class_index_for_wildcard_import_static_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import com.vendor.*;",
                        "",
                        "public class Demo {",
                        "    public boolean check(String value) {",
                        "        return TargetApi.removed(value);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            jar_path = Path(tmp) / "vendor.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr("com/vendor/TargetApi.class", b"")
            jar_metadata = {
                "by_coord": {
                    "com.vendor:target": {
                        "coord": "com.vendor:target",
                        "version": "1.0.0",
                        "jar_path": str(jar_path),
                        "classes": {},
                    }
                },
                "by_class": {},
                "jar_paths": {"com.vendor:target": str(jar_path)},
                "all_class_fqcns": ["com.vendor.TargetApi"],
                "classes_by_simple": {"TargetApi": ["com.vendor.TargetApi"]},
            }

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ],
                jar_metadata=jar_metadata,
            )
            graph = graph_result["graph"]

            self.assertIn("com.vendor.TargetApi.removed(String)", graph.reverse_edges)
            self.assertNotIn("com.example.TargetApi.removed(String)", graph.reverse_edges)

    def test_build_graph_infers_argument_type_from_inherited_getter(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Base.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "public class Base {",
                        "    public String getPath() {",
                        "        return \"\";",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import org.apache.dubbo.common.utils.StringUtils;",
                        "",
                        "public class Demo extends Base {",
                        "    public boolean check() {",
                        "        return StringUtils.isEmpty(getPath());",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.dubbo.common.utils.StringUtils.isEmpty(String)", graph.reverse_edges)

    def test_build_graph_infers_argument_type_from_explicit_cast(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import org.apache.dubbo.common.utils.StringUtils;",
                        "",
                        "public class Demo {",
                        "    public boolean check(Object value) {",
                        "        return value instanceof String && StringUtils.isBlank((String) value);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.dubbo.common.utils.StringUtils.isBlank(String)", graph.reverse_edges)

    def test_build_graph_infers_argument_type_from_generic_map_get(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import java.util.Map;",
                        "import static org.apache.dubbo.common.utils.StringUtils.isEmpty;",
                        "",
                        "public class Demo {",
                        "    public boolean check(Map<String, String> parameters) {",
                        "        return isEmpty(parameters.get(\"protocol\"));",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.dubbo.common.utils.StringUtils.isEmpty(String)", graph.reverse_edges)

    def test_build_graph_parses_varargs_parameter_type_for_static_import_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import static org.apache.dubbo.common.utils.StringUtils.isBlank;",
                        "",
                        "public class Demo {",
                        "    public String build(String one, String... others) {",
                        "        for (String other : others) {",
                        "            return isBlank(other) ? one : other;",
                        "        }",
                        "        return one;",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.dubbo.common.utils.StringUtils.isBlank(String)", graph.reverse_edges)

    def test_build_graph_infers_varargs_array_element_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import org.apache.seata.common.util.StringUtils;",
                        "",
                        "public class Demo {",
                        "    public boolean check(String... authInfo) {",
                        "        return StringUtils.isBlank(authInfo[0]);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.seata.common.util.StringUtils.isBlank(String)", graph.reverse_edges)

    def test_trace_api_reaches_primitive_array_parameter_without_losing_array_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import org.apache.commons.lang3.ArrayUtils;",
                        "",
                        "public class Demo {",
                        "    public boolean check(final char[] delimiters) {",
                        "        return ArrayUtils.isEmpty(delimiters);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]
            api_row = {
                "api_name": "org.apache.commons.lang3.ArrayUtils.isEmpty",
                "api_simple": "isEmpty",
                "api_signature": "(char[])",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "coord": "org.apache.commons:commons-lang3",
                "severity": "P0",
                "confirmed": "true",
                "source": "unit",
            }

            self.assertIn("org.apache.commons.lang3.ArrayUtils.isEmpty(char[])", graph.reverse_edges)
            self.assertNotIn("org.apache.commons.lang3.ArrayUtils.isEmpty(char)", graph.reverse_edges)

            result = tracer.trace_api_with_confidence_weighting(api_row, graph, graph.type_metadata)

            self.assertEqual(result.analysis_status, "reachable")
            self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")

    def test_build_graph_parses_volatile_field_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import org.apache.seata.common.util.StringUtils;",
                        "",
                        "public class Demo {",
                        "    private volatile String distributedLockTable;",
                        "    public Demo() {",
                        "        if (StringUtils.isBlank(distributedLockTable)) {",
                        "            throw new IllegalStateException();",
                        "        }",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.seata.common.util.StringUtils.isBlank(String)", graph.reverse_edges)

    def test_build_graph_infers_dubbo_url_get_parameter_string_return(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "URL.java").write_text(
                "\n".join(
                    [
                        "package org.apache.dubbo.common;",
                        "",
                        "public class URL {",
                        "    public String getParameter(String key) {",
                        "        return \"\";",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import org.apache.dubbo.common.URL;",
                        "import org.apache.dubbo.common.utils.StringUtils;",
                        "",
                        "public class Demo {",
                        "    public boolean check(URL url) {",
                        "        return StringUtils.isEmpty(url.getParameter(\"k\"));",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.dubbo.common.utils.StringUtils.isEmpty(String)", graph.reverse_edges)

    def test_build_graph_infers_single_arg_get_parameter_string_return_in_lambda(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import java.util.Collection;",
                        "import org.apache.dubbo.common.utils.StringUtils;",
                        "",
                        "public class Demo {",
                        "    public boolean check(Collection<ServiceInfo> services) {",
                        "        return services.stream().anyMatch(serviceInfo -> StringUtils.isEmpty(serviceInfo.getParameter(\"extra\")));",
                        "    }",
                        "    static class ServiceInfo {",
                        "        String getParameter(String key) { return \"\"; }",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.dubbo.common.utils.StringUtils.isEmpty(String)", graph.reverse_edges)

    def test_build_graph_infers_imported_static_field_argument_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Constants.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "public interface Constants {",
                        "    String CLOSE = \"close!\";",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import org.apache.dubbo.common.utils.StringUtils;",
                        "",
                        "public class Demo {",
                        "    public boolean check(String result) {",
                        "        return StringUtils.isEquals(Constants.CLOSE, result);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.dubbo.common.utils.StringUtils.isEquals(String, String)", graph.reverse_edges)

    def test_trace_api_does_not_mix_in_raw_edges_from_other_overloads(self):
        api_row = {
            "api_name": "org.slf4j.LoggerFactory.getLogger",
            "api_simple": "getLogger",
            "api_signature": "(Class)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "org.slf4j:slf4j-api",
            "severity": "P1",
            "confirmed": "false",
            "source": "overload_safety_fixture",
            "analysis_scope": "api",
        }

        class_method = SimpleNamespace(
            symbol_id="class_hit",
            qualified_key="com.biz.ClassHit.<class-init>",
            simple_key="method:<class-init>",
            class_fqcn="com.biz.ClassHit",
            class_name="ClassHit",
            method_name="<class-init>",
            return_type="void",
            file="ClassHit.java",
            line=10,
            owner_type="business",
            is_test=False,
            imports={},
            wildcard_imports=[],
            static_imports={},
            get_body_text=lambda: "",
        )
        string_method = SimpleNamespace(
            symbol_id="string_hit",
            qualified_key="com.biz.StringHit.call",
            simple_key="method:call",
            class_fqcn="com.biz.StringHit",
            class_name="StringHit",
            method_name="call",
            return_type="void",
            file="StringHit.java",
            line=20,
            owner_type="business",
            is_test=False,
            imports={},
            wildcard_imports=[],
            static_imports={},
            get_body_text=lambda: "",
        )
        graph = SimpleNamespace(
            methods_by_id={"class_hit": class_method, "string_hit": string_method},
            reverse_edges={
                "org.slf4j.LoggerFactory.getLogger(Class)": [
                    SimpleNamespace(
                        caller_symbol_id="class_hit",
                        caller_qualified_key=class_method.qualified_key,
                        callee_key="org.slf4j.LoggerFactory.getLogger(Class)",
                        callee_simple_key="method:getLogger(Class)",
                        confidence="high",
                        evidence_type="initializer_invocation",
                        file=class_method.file,
                        line=10,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    )
                ],
                "org.slf4j.LoggerFactory.getLogger(String)": [
                    SimpleNamespace(
                        caller_symbol_id="string_hit",
                        caller_qualified_key=string_method.qualified_key,
                        callee_key="org.slf4j.LoggerFactory.getLogger(String)",
                        callee_simple_key="method:getLogger(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=string_method.file,
                        line=20,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    )
                ],
                "org.slf4j.LoggerFactory.getLogger": [
                    SimpleNamespace(
                        caller_symbol_id="string_hit",
                        caller_qualified_key=string_method.qualified_key,
                        callee_key="org.slf4j.LoggerFactory.getLogger(String)",
                        callee_simple_key="method:getLogger(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=string_method.file,
                        line=20,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    )
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        path_texts = [item.get("path_text", "") for item in result.path_details]
        self.assertTrue(any("com.biz.ClassHit.<class-init>" in path for path in path_texts))
        self.assertFalse(any("com.biz.StringHit.call" in path for path in path_texts))

    def test_trace_api_keeps_raw_edge_when_declared_target_has_single_signature(self):
        api_row = {
            "api_name": "org.example.Strings.isBlank",
            "api_simple": "isBlank",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "org.example:lib",
            "severity": "P1",
            "confirmed": "false",
            "source": "single_signature_raw_fixture",
            "analysis_scope": "api",
        }
        declared_method = SimpleNamespace(
            symbol_id="declared",
            qualified_key="org.example.Strings.isBlank",
            simple_key="method:isBlank",
            class_fqcn="org.example.Strings",
            method_name="isBlank",
            param_types={"value": "String"},
            param_declared_types={"value": "String"},
            owner_type="dependency",
            is_test=False,
            file="Strings.java",
            line=1,
        )
        exact_method = SimpleNamespace(
            symbol_id="exact_hit",
            qualified_key="com.biz.ExactHit.call",
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            file="ExactHit.java",
            line=10,
        )
        raw_method = SimpleNamespace(
            symbol_id="raw_hit",
            qualified_key="com.biz.RawHit.call",
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            file="RawHit.java",
            line=20,
        )
        graph = SimpleNamespace(
            methods_by_id={
                "declared": declared_method,
                "exact_hit": exact_method,
                "raw_hit": raw_method,
            },
            reverse_edges={
                "org.example.Strings.isBlank(String)": [
                    SimpleNamespace(
                        caller_symbol_id="exact_hit",
                        caller_qualified_key=exact_method.qualified_key,
                        callee_key="org.example.Strings.isBlank(String)",
                        callee_simple_key="method:isBlank(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file="ExactHit.java",
                        line=10,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    )
                ],
                "org.example.Strings.isBlank": [
                    SimpleNamespace(
                        caller_symbol_id="raw_hit",
                        caller_qualified_key=raw_method.qualified_key,
                        callee_key="org.example.Strings.isBlank",
                        callee_simple_key="method:isBlank",
                        confidence="medium",
                        evidence_type="ast_method_invocation",
                        file="RawHit.java",
                        line=20,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    )
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        path_texts = [item.get("path_text", "") for item in result.path_details]
        self.assertTrue(any("com.biz.ExactHit.call" in path for path in path_texts))
        self.assertTrue(any("com.biz.RawHit.call" in path for path in path_texts))

    def test_trace_api_still_blocks_raw_edge_when_target_has_multiple_declared_overloads(self):
        api_row = {
            "api_name": "org.example.Collections.isEmpty",
            "api_simple": "isEmpty",
            "api_signature": "(Map)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "org.example:lib",
            "severity": "P1",
            "confirmed": "false",
            "source": "multi_signature_raw_fixture",
            "analysis_scope": "api",
        }
        map_declared = SimpleNamespace(
            symbol_id="declared_map",
            qualified_key="org.example.Collections.isEmpty",
            simple_key="method:isEmpty",
            class_fqcn="org.example.Collections",
            method_name="isEmpty",
            param_types={"value": "Map"},
            param_declared_types={"value": "Map"},
            owner_type="dependency",
            is_test=False,
            file="Collections.java",
            line=1,
        )
        list_declared = SimpleNamespace(
            symbol_id="declared_list",
            qualified_key="org.example.Collections.isEmpty",
            simple_key="method:isEmpty",
            class_fqcn="org.example.Collections",
            method_name="isEmpty",
            param_types={"value": "List"},
            param_declared_types={"value": "List"},
            owner_type="dependency",
            is_test=False,
            file="Collections.java",
            line=2,
        )
        map_method = SimpleNamespace(
            symbol_id="map_hit",
            qualified_key="com.biz.MapHit.call",
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            file="MapHit.java",
            line=10,
        )
        raw_method = SimpleNamespace(
            symbol_id="raw_hit",
            qualified_key="com.biz.RawHit.call",
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            file="RawHit.java",
            line=20,
        )
        graph = SimpleNamespace(
            methods_by_id={
                "declared_map": map_declared,
                "declared_list": list_declared,
                "map_hit": map_method,
                "raw_hit": raw_method,
            },
            reverse_edges={
                "org.example.Collections.isEmpty(Map)": [
                    SimpleNamespace(
                        caller_symbol_id="map_hit",
                        caller_qualified_key=map_method.qualified_key,
                        callee_key="org.example.Collections.isEmpty(Map)",
                        callee_simple_key="method:isEmpty(Map)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file="MapHit.java",
                        line=10,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    )
                ],
                "org.example.Collections.isEmpty": [
                    SimpleNamespace(
                        caller_symbol_id="raw_hit",
                        caller_qualified_key=raw_method.qualified_key,
                        callee_key="org.example.Collections.isEmpty",
                        callee_simple_key="method:isEmpty",
                        confidence="medium",
                        evidence_type="ast_method_invocation",
                        file="RawHit.java",
                        line=20,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    )
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        path_texts = [item.get("path_text", "") for item in result.path_details]
        self.assertTrue(any("com.biz.MapHit.call" in path for path in path_texts))
        self.assertFalse(any("com.biz.RawHit.call" in path for path in path_texts))

    def test_build_graph_exposes_field_initializer_field_usage_to_tracer(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import org.apache.dubbo.common.utils.StringUtils;",
                        "",
                        "public class Demo {",
                        "    private String value = StringUtils.EMPTY_STRING;",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            result = tracer.trace_api_with_confidence_weighting(
                {
                    "api_name": "org.apache.dubbo.common.utils.StringUtils.EMPTY_STRING",
                    "api_simple": "EMPTY_STRING",
                    "api_signature": "",
                    "symbol_kind": "field",
                    "change_type": "REMOVED",
                    "coord": "org.apache.dubbo:dubbo-common",
                    "severity": "P1",
                    "confirmed": "false",
                    "source": "field_initializer_fixture",
                    "analysis_scope": "api",
                },
                graph,
                {},
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertTrue(any("com.example.Demo.<class-init>" in path for path in result.call_paths))

    def test_build_graph_infers_initializer_lambda_local_string_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import java.util.function.Function;",
                        "import org.apache.dubbo.common.utils.StringUtils;",
                        "",
                        "public class Demo {",
                        "    public static final Function<Object, String> KEY = value -> {",
                        "        String iName = value.toString();",
                        "        if (StringUtils.isBlank(iName)) {",
                        "            return \"\";",
                        "        }",
                        "        return iName;",
                        "    };",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.dubbo.common.utils.StringUtils.isBlank(String)", graph.reverse_edges)

    def test_build_graph_does_not_skip_main_package_named_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src" / "main" / "java" / "org" / "apache" / "dubbo" / "test" / "check"
            src_dir.mkdir(parents=True)
            (src_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package org.apache.dubbo.test.check;",
                        "",
                        "import org.apache.dubbo.common.utils.StringUtils;",
                        "",
                        "public class Demo {",
                        "    public boolean check(String directory) {",
                        "        return StringUtils.isEmpty(directory);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(Path(tmp)),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]

            self.assertIn("org.apache.dubbo.common.utils.StringUtils.isEmpty(String)", graph.reverse_edges)

    def test_trace_api_respects_wildcard_import_owner_for_simple_static_field_access(self):
        api_row = {
            "api_name": "io.seata.common.StringUtils.EMPTY",
            "api_simple": "EMPTY",
            "api_signature": "",
            "symbol_kind": "field",
            "change_type": "REMOVED",
            "coord": "io.seata:seata-common",
            "severity": "P1",
            "confirmed": "false",
            "source": "candidate_scan",
            "analysis_scope": "api",
        }
        business_method = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.biz.RppAssignFacility.handle",
            simple_key="method:handle",
            class_fqcn="com.biz.RppAssignFacility",
            class_name="RppAssignFacility",
            method_name="handle",
            return_type="void",
            file="RppAssignFacility.java",
            line=913,
            owner_type="business",
            is_test=False,
            imports={},
            wildcard_imports=["org.apache.commons.lang3"],
            static_imports={},
            get_body_text=lambda: "return StringUtils.EMPTY;",
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_method},
            reverse_edges={},
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertNotEqual(result.reason_code, "DIRECT_FIELD_USAGE")

    def test_trace_api_marks_wildcard_imported_simple_static_field_access_as_reachable(self):
        api_row = {
            "api_name": "org.apache.commons.lang3.StringUtils.EMPTY",
            "api_simple": "EMPTY",
            "api_signature": "",
            "symbol_kind": "field",
            "change_type": "REMOVED",
            "coord": "org.apache.commons:commons-lang3",
            "severity": "P1",
            "confirmed": "false",
            "source": "candidate_scan",
            "analysis_scope": "api",
        }
        business_method = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.biz.RppAssignFacility.handle",
            simple_key="method:handle",
            class_fqcn="com.biz.RppAssignFacility",
            class_name="RppAssignFacility",
            method_name="handle",
            return_type="void",
            file="RppAssignFacility.java",
            line=913,
            owner_type="business",
            is_test=False,
            imports={},
            wildcard_imports=["org.apache.commons.lang3"],
            static_imports={},
            get_body_text=lambda: "return StringUtils.EMPTY;",
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_method},
            reverse_edges={},
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "DIRECT_FIELD_USAGE")

    def test_trace_api_keeps_fqcn_static_field_access_reachable_despite_import_conflict(self):
        api_row = {
            "api_name": "io.seata.common.StringUtils.EMPTY",
            "api_simple": "EMPTY",
            "api_signature": "",
            "symbol_kind": "field",
            "change_type": "REMOVED",
            "coord": "io.seata:seata-common",
            "severity": "P1",
            "confirmed": "false",
            "source": "candidate_scan",
            "analysis_scope": "api",
        }
        business_method = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.biz.RppAssignFacility.handle",
            simple_key="method:handle",
            class_fqcn="com.biz.RppAssignFacility",
            class_name="RppAssignFacility",
            method_name="handle",
            return_type="void",
            file="RppAssignFacility.java",
            line=913,
            owner_type="business",
            is_test=False,
            imports={"StringUtils": "org.apache.commons.lang3.StringUtils"},
            wildcard_imports=[],
            static_imports={},
            get_body_text=lambda: "return io.seata.common.StringUtils.EMPTY;",
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_method},
            reverse_edges={},
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "DIRECT_FIELD_USAGE")

    def test_trace_api_respects_static_import_owner_for_field_access(self):
        api_row = {
            "api_name": "io.seata.common.StringUtils.EMPTY",
            "api_simple": "EMPTY",
            "api_signature": "",
            "symbol_kind": "field",
            "change_type": "REMOVED",
            "coord": "io.seata:seata-common",
            "severity": "P1",
            "confirmed": "false",
            "source": "candidate_scan",
            "analysis_scope": "api",
        }
        business_method = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.biz.RppAssignFacility.handle",
            simple_key="method:handle",
            class_fqcn="com.biz.RppAssignFacility",
            class_name="RppAssignFacility",
            method_name="handle",
            return_type="void",
            file="RppAssignFacility.java",
            line=913,
            owner_type="business",
            is_test=False,
            imports={},
            wildcard_imports=[],
            static_imports={"EMPTY": "org.apache.commons.lang3.StringUtils.EMPTY"},
            get_body_text=lambda: "return EMPTY;",
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_method},
            reverse_edges={},
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertNotEqual(result.reason_code, "DIRECT_STATIC_IMPORT_USAGE")

    def test_trace_api_allows_constructor_target_to_reach_business_code(self):
        api_row = {
            "api_name": "com.lib.TargetType.TargetType",
            "api_simple": "TargetType",
            "api_signature": "()",
            "symbol_kind": "constructor",
            "change_type": "REMOVED",
            "coord": "lib:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "japicmp",
            "analysis_scope": "api",
        }
        business_entry = SimpleNamespace(
            symbol_id="business_entry",
            qualified_key="com.biz.Entry.handle",
            simple_key="method:handle",
            class_fqcn="com.biz.Entry",
            class_name="Entry",
            method_name="handle",
            param_types={},
            param_declared_types={},
            owner_type="business",
            owner_coord="BUSINESS",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Entry.java",
            line=12,
        )
        graph = SimpleNamespace(
            methods_by_id={"business_entry": business_entry},
            reverse_edges={
                "com.lib.TargetType.TargetType()": [
                    SimpleNamespace(
                        caller_symbol_id="business_entry",
                        caller_qualified_key=business_entry.qualified_key,
                        callee_key="com.lib.TargetType.TargetType()",
                        callee_simple_key="method:TargetType()",
                        confidence="high",
                        evidence_type="constructor_invocation",
                        file=business_entry.file,
                        line=12,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")
        self.assertEqual(result.match_provenance, "exact_signature")

    def test_trace_api_blocks_overloaded_intermediate_method_when_only_name_fallback_matches(self):
        api_row = {
            "api_name": "org.example.TargetApi.call",
            "api_simple": "call",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "method_changed",
            "coord": "org.example:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        bridge_int = SimpleNamespace(
            symbol_id="bridge_int",
            qualified_key="org.example.Service.bridge",
            simple_key="method:bridge",
            class_fqcn="org.example.Service",
            class_name="Service",
            method_name="bridge",
            param_types={"value": "int"},
            param_declared_types={"value": "int"},
            owner_type="dependency",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Service.java",
            line=20,
        )
        wrong_controller = SimpleNamespace(
            symbol_id="wrong_controller",
            qualified_key="org.example.Controller.zero",
            simple_key="method:zero",
            class_fqcn="org.example.Controller",
            class_name="Controller",
            method_name="zero",
            param_types={},
            param_declared_types={},
            owner_type="business",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Controller.java",
            line=60,
        )
        graph = SimpleNamespace(
            methods_by_id={
                "bridge_int": bridge_int,
                "wrong_controller": wrong_controller,
            },
            reverse_edges={
                "org.example.TargetApi.call(String)": [
                    SimpleNamespace(
                        caller_symbol_id="bridge_int",
                        caller_qualified_key=bridge_int.qualified_key,
                        callee_key="org.example.TargetApi.call(String)",
                        callee_simple_key="method:call(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=bridge_int.file,
                        line=22,
                        owner_type="dependency",
                        owner_coord="vendor:demo",
                        module="service",
                        is_test=False,
                    ),
                ],
                "org.example.Service.bridge": [
                    SimpleNamespace(
                        caller_symbol_id="wrong_controller",
                        caller_qualified_key=wrong_controller.qualified_key,
                        callee_key="org.example.Service.bridge()",
                        callee_simple_key="method:bridge()",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=wrong_controller.file,
                        line=61,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
                "org.example.Service.bridge()": [
                    SimpleNamespace(
                        caller_symbol_id="wrong_controller",
                        caller_qualified_key=wrong_controller.qualified_key,
                        callee_key="org.example.Service.bridge()",
                        callee_simple_key="method:bridge()",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=wrong_controller.file,
                        line=61,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                        is_test=False,
                    ),
                ],
                "org.example.Service.bridge(int)": [],
            },
        )

        result = tracer.trace_api_with_confidence_weighting(api_row, graph, {}, max_total_cost=5)

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "OVERLOAD_AMBIGUOUS_INTERMEDIATE")

    def test_trace_api_selects_same_reachable_path_when_reverse_edges_order_changes(self):
        api_row = {
            "api_name": "com.example.Target.call",
            "api_simple": "call",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "com.example:demo",
            "severity": "P1",
            "confirmed": "true",
            "source": "gitdiff",
            "analysis_scope": "method",
        }
        alpha_method = SimpleNamespace(
            symbol_id="alpha",
            qualified_key="com.example.Controller.alpha",
            simple_key="method:alpha",
            class_fqcn="com.example.Controller",
            class_name="Controller",
            method_name="alpha",
            param_types={},
            param_declared_types={},
            owner_type="business",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Alpha.java",
            line=10,
        )
        beta_method = SimpleNamespace(
            symbol_id="beta",
            qualified_key="com.example.Controller.beta",
            simple_key="method:beta",
            class_fqcn="com.example.Controller",
            class_name="Controller",
            method_name="beta",
            param_types={},
            param_declared_types={},
            owner_type="business",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/Beta.java",
            line=20,
        )
        alpha_edge = SimpleNamespace(
            caller_symbol_id="alpha",
            caller_qualified_key=alpha_method.qualified_key,
            callee_key="com.example.Target.call(String)",
            callee_simple_key="method:call(String)",
            confidence="high",
            evidence_type="ast_method_invocation",
            file=alpha_method.file,
            line=alpha_method.line,
            owner_type="business",
            owner_coord="BUSINESS",
            module="app",
            is_test=False,
        )
        beta_edge = SimpleNamespace(
            caller_symbol_id="beta",
            caller_qualified_key=beta_method.qualified_key,
            callee_key="com.example.Target.call(String)",
            callee_simple_key="method:call(String)",
            confidence="high",
            evidence_type="ast_method_invocation",
            file=beta_method.file,
            line=beta_method.line,
            owner_type="business",
            owner_coord="BUSINESS",
            module="app",
            is_test=False,
        )

        def build_graph(edges):
            return SimpleNamespace(
                methods_by_id={"alpha": alpha_method, "beta": beta_method},
                reverse_edges={"com.example.Target.call(String)": edges},
            )

        first_result = tracer.trace_api_with_confidence_weighting(
            api_row,
            build_graph([alpha_edge, beta_edge]),
            {},
            max_total_cost=5,
        )
        second_result = tracer.trace_api_with_confidence_weighting(
            api_row,
            build_graph([beta_edge, alpha_edge]),
            {},
            max_total_cost=5,
        )

        self.assertEqual(first_result.analysis_status, "reachable")
        self.assertEqual(second_result.analysis_status, "reachable")
        self.assertEqual(first_result.call_paths[0], second_result.call_paths[0])
        self.assertIn("Controller.beta", first_result.call_paths[0])

    def test_trace_api_keeps_inherited_helper_overload_on_simple_key_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "dep"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Controller.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.dep.ApiResponse;",
                        "import com.example.dep.BaseController;",
                        "",
                        "public class Controller extends BaseController {",
                        "    public ApiResponse getUserById(Object user) {",
                        "        return success(user);",
                        "    }",
                        "",
                        "    public ApiResponse updateUser(Object user) {",
                        '        return success("updated", user);',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "BaseController.java").write_text(
                "\n".join(
                    [
                        "package com.example.dep;",
                        "",
                        "public class BaseController {",
                        "    protected ApiResponse success(Object data) {",
                        "        return ApiResponse.success(data);",
                        "    }",
                        "",
                        "    protected ApiResponse success(String message, Object data) {",
                        "        return ApiResponse.success(message, data);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ApiResponse.java").write_text(
                "\n".join(
                    [
                        "package com.example.dep;",
                        "",
                        "public class ApiResponse {",
                        "    public static ApiResponse success(Object data) {",
                        "        return new ApiResponse();",
                        "    }",
                        "",
                        "    public static ApiResponse success(String message, Object data) {",
                        "        return new ApiResponse();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:dep",
                        "module": "dep",
                    },
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:dep",
                    "api_name": "com.example.dep.ApiResponse.success",
                    "api_simple": "success",
                    "api_signature": "(String, Object)",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=6,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertIn("Controller.updateUser", result.call_paths[0])
            self.assertNotIn("Controller.getUserById", result.call_paths[0])

    def test_strict_gate_blocks_not_found_in_static_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            output_dir = self._call_chain_dir(report_dir)
            output_dir.mkdir(parents=True)
            (output_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "status": "done",
                        "reachable": 0,
                        "uncertain": 0,
                        "not_analyzed": 0,
                        "not_found_in_static_analysis": 2,
                        "not_found_apis": [
                            {"api": "com.example.Foo.bar", "reason": "静态分析未找到"},
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            with self.assertRaises(SystemExit) as ctx:
                gate.gate_call_chain(str(report_dir), strict_risk_gate=True)

        self.assertEqual(ctx.exception.code, 1)

    def test_summarize_user_facing_outcome_maps_to_simple_conclusions(self):
        reachable = SimpleNamespace(
            analysis_status="reachable",
            reason_code="SYSTEM_CODE_REACHABLE",
            change_type="method_changed",
            severity="P1",
            call_paths=["OrderServiceImpl.process -> FastThreadLocal.removeAll"],
            evidence_paths=[],
            dependency_chain_coords=[],
        )
        runtime_check = SimpleNamespace(
            analysis_status="not_analyzed",
            reason_code="BEHAVIOR_CHANGED_RUNTIME_VERIFICATION",
            change_type="behavior_changed",
            severity="P2",
            call_paths=["OrderServiceImpl.process -> Cache.refresh"],
            evidence_paths=[],
            dependency_chain_coords=[],
        )
        missing_input = SimpleNamespace(
            analysis_status="not_analyzed",
            reason_code="DEPENDENCY_SOURCE_MAPPING_MISSING",
            change_type="method_changed",
            severity="P1",
            call_paths=[],
            evidence_paths=[],
            dependency_chain_coords=["a:b"],
        )

        self.assertEqual(formatter.summarize_user_facing_outcome(reachable)["user_conclusion"], "已确认影响")
        self.assertEqual(formatter.summarize_user_facing_outcome(runtime_check)["user_conclusion"], "可能影响")
        self.assertEqual(formatter.summarize_user_facing_outcome(missing_input)["user_conclusion"], "需要补充输入")

    def test_reachable_key_evidence_prefers_confirmed_business_path(self):
        outcome = formatter.summarize_user_facing_outcome(SimpleNamespace(
            analysis_status="reachable",
            reason_code="RUNTIME_DEPENDENCY_USES_REMOVED_API",
            severity="P1",
            call_paths=[
                "library.Bridge.call() -> target.Api.removed()",
                "app.Entry.run() -> library.Bridge.call() -> target.Api.removed()",
            ],
            evidence_paths=[[], []],
            path_details=[
                {
                    "path_status": "uncertain",
                    "path_text": "library.Bridge.call() -> target.Api.removed()",
                },
                {
                    "path_status": "reachable",
                    "path_text": (
                        "app.Entry.run() -> library.Bridge.call() -> target.Api.removed()"
                    ),
                },
            ],
            dependency_chain_coords=["sample:library"],
        ))

        self.assertEqual(
            outcome["key_evidence"],
            "app.Entry.run() -> library.Bridge.call() -> target.Api.removed()",
        )

    def test_summarize_user_facing_outcome_treats_behavior_changed_fallback_simple_as_inconclusive(self):
        fallback_simple_runtime = SimpleNamespace(
            analysis_status="not_analyzed",
            reason_code="BEHAVIOR_CHANGED_PRECISE_TARGET_NOT_CONFIRMED",
            change_type="behavior_changed",
            severity="P1",
            call_paths=["OrderServiceImpl.process -> Cache.refresh"],
            evidence_paths=[],
            dependency_chain_coords=[],
        )

        summary = formatter.summarize_user_facing_outcome(fallback_simple_runtime)

        self.assertEqual(summary["user_conclusion"], "当前无法确认")
        self.assertIn("fallback_simple", summary["user_reason"])

    def test_summarize_user_facing_outcome_explains_target_overload_ambiguity(self):
        overload_ambiguous = SimpleNamespace(
            analysis_status="not_analyzed",
            reason_code="OVERLOAD_AMBIGUOUS_TARGET",
            change_type="method_changed",
            severity="P0",
            call_paths=[],
            evidence_paths=[],
            dependency_chain_coords=[],
        )

        summary = formatter.summarize_user_facing_outcome(overload_ambiguous)

        self.assertEqual(summary["user_conclusion"], "当前无法确认")
        self.assertIn("重载", summary["user_reason"])
        self.assertNotEqual(summary["user_reason"], "OVERLOAD_AMBIGUOUS_TARGET")

    def test_summarize_user_facing_outcome_explains_new_step5_precision_reason_codes(self):
        low_confidence = SimpleNamespace(
            analysis_status="uncertain",
            reason_code="LOW_CONFIDENCE_EDGE",
            change_type="method_changed",
            severity="P1",
            call_paths=["Bridge.invoke -> Target.parse"],
            evidence_paths=[],
            dependency_chain_coords=[],
        )
        symbol_limit = SimpleNamespace(
            analysis_status="not_analyzed",
            reason_code="CALL_GRAPH_LIMITATION_SYMBOL_KIND",
            change_type="REMOVED",
            severity="P1",
            call_paths=[],
            evidence_paths=[],
            dependency_chain_coords=[],
        )

        low_confidence_summary = formatter.summarize_user_facing_outcome(low_confidence)
        symbol_limit_summary = formatter.summarize_user_facing_outcome(symbol_limit)

        self.assertEqual(low_confidence_summary["user_conclusion"], "当前无法确认")
        self.assertIn("低置信度边", low_confidence_summary["user_reason"])
        self.assertEqual(symbol_limit_summary["user_conclusion"], "当前无法确认")
        self.assertIn("方法反向调用图", symbol_limit_summary["user_reason"])

    def test_summarize_user_facing_outcome_uses_direct_usage_reason_for_reachable_results(self):
        direct_field_usage = SimpleNamespace(
            analysis_status="reachable",
            reason_code="DIRECT_FIELD_USAGE",
            change_type="REMOVED",
            severity="P1",
            call_paths=["com.biz.Entry.handle -> com.lib.TargetType.FIELD"],
            evidence_paths=[],
            dependency_chain_coords=[],
        )

        summary = formatter.summarize_user_facing_outcome(direct_field_usage)

        self.assertEqual(summary["user_conclusion"], "已确认影响")
        self.assertIn("目标字段访问", summary["user_reason"])

    def test_user_facing_source_artifact_messages_are_readable(self):
        for reason_code in ("SOURCE_BYTECODE_EDGE_CONFLICT", "SOURCE_ARTIFACT_ALIGNMENT_UNVERIFIED"):
            result = SimpleNamespace(
                analysis_status="uncertain",
                reason_code=reason_code,
                change_type="method_changed",
                severity="P1",
                call_paths=[],
                evidence_paths=[],
                dependency_chain_coords=[],
            )

            summary = formatter.summarize_user_facing_outcome(result)
            combined = f"{summary.get('user_reason', '')}\n{summary.get('suggested_action', '')}"

            self.assertIn("源码", combined)
            self.assertIn("打包", combined)
            self.assertNotIn("源码图", combined)
            self.assertNotIn("最终制品", combined)
            self.assertNotIn("revision", combined)
            self.assertNotIn("profile", combined)

    def test_generate_enhanced_summary_outputs_user_conclusion_counts_without_low_value_text_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            results = [
                tracer.TraceResult(
                    coord="a:b",
                    api_name="com.example.OrderService.run",
                    api_simple="run",
                    api_signature="(String)",
                    symbol_kind="method",
                    change_type="method_changed",
                    severity="P1",
                    confirmed=True,
                    source="gitdiff",
                    analysis_scope="method",
                    analysis_status="reachable",
                    direct_callers=1,
                    is_reachable=True,
                    reachable_note="已找到调用链",
                    business_reach_depth=1,
                    dependency_chain_coords=[],
                    reason_code="SYSTEM_CODE_REACHABLE",
                    call_paths=["OrderService.run -> DemoApi.call"],
                    evidence_paths=[],
                    verification_commands=[],
                    hops=[],
                    confidence_score=0.95,
                    critical_nodes_hit=[],
                ),
                tracer.TraceResult(
                    coord="a:b",
                    api_name="com.example.OrderService.verify",
                    api_simple="verify",
                    api_signature="()",
                    symbol_kind="method",
                    change_type="behavior_changed",
                    severity="P2",
                    confirmed=False,
                    source="changelog",
                    analysis_scope="method",
                    analysis_status="not_analyzed",
                    direct_callers=0,
                    is_reachable=False,
                    reachable_note="",
                    business_reach_depth=0,
                    dependency_chain_coords=[],
                    call_paths=[],
                    reason_code="BEHAVIOR_CHANGED_RUNTIME_VERIFICATION",
                    evidence_paths=[],
                    verification_commands=[],
                    hops=[],
                    confidence_score=0.4,
                    critical_nodes_hit=[],
                ),
                tracer.TraceResult(
                    coord="a:b",
                    api_name="com.example.OrderService.blocked",
                    api_simple="blocked",
                    api_signature="(Long)",
                    symbol_kind="method",
                    change_type="method_changed",
                    severity="P1",
                    confirmed=False,
                    source="gitdiff",
                    analysis_scope="method",
                    analysis_status="not_analyzed",
                    direct_callers=0,
                    is_reachable=False,
                    reachable_note="",
                    business_reach_depth=0,
                    dependency_chain_coords=["a:b"],
                    call_paths=[],
                    reason_code="DEPENDENCY_SOURCE_MAPPING_MISSING",
                    evidence_paths=[],
                    verification_commands=[],
                    hops=[],
                    confidence_score=0.2,
                    critical_nodes_hit=[],
                ),
            ]

            summary_path, summary_json_path = formatter.generate_enhanced_summary(results, output_dir)
            summary = json.loads(Path(summary_json_path).read_text(encoding="utf-8"))
            by_api_text = next((output_dir / "by_api").glob("a_b_com_example_OrderService_run*.txt")).read_text(
                encoding="utf-8"
            )
            summary_txt_exists = (output_dir / "summary.txt").exists()
            enhanced_summary_exists = (output_dir / "s5_enhanced_summary.txt").exists()

        self.assertIsNone(summary_path)
        self.assertFalse(summary_txt_exists)
        self.assertFalse(enhanced_summary_exists)
        self.assertEqual(summary["user_conclusion_summary"]["已确认影响"], 1)
        self.assertEqual(summary["user_conclusion_summary"]["可能影响"], 1)
        self.assertEqual(summary["user_conclusion_summary"]["需要补充输入"], 1)
        self.assertEqual(summary["quality_gate"]["needs_input"], 1)
        self.assertLess(by_api_text.index("【结论】"), by_api_text.index("【变更信息】"))
        self.assertIn("【调用链路】", by_api_text)

    def test_generate_enhanced_summary_persists_step5_perf_report_stats(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            graph_stats = {
                "step5_perf": {
                    "main": {
                        "business_graph_elapsed_sec": 0.123,
                    }
                }
            }
            result = tracer.TraceResult(
                coord="a:b",
                api_name="com.example.OrderService.run",
                api_simple="run",
                api_signature="()",
                symbol_kind="method",
                change_type="method_changed",
                severity="P1",
                confirmed=True,
                source="gitdiff",
                analysis_scope="method",
                analysis_status="reachable",
                direct_callers=1,
                is_reachable=True,
                reachable_note="已找到调用链",
                business_reach_depth=1,
                dependency_chain_coords=[],
                reason_code="SYSTEM_CODE_REACHABLE",
                call_paths=["OrderService.run -> DemoApi.call"],
                evidence_paths=[],
                verification_commands=[],
                hops=[],
                confidence_score=0.95,
                critical_nodes_hit=[],
            )

            _, summary_json_path = formatter.generate_enhanced_summary([result], output_dir, graph_stats=graph_stats)
            summary = json.loads(Path(summary_json_path).read_text(encoding="utf-8"))

        perf = summary["meta"]["graph_stats"]["step5_perf"]
        self.assertEqual(perf["main"]["business_graph_elapsed_sec"], 0.123)
        self.assertIn("summary_text_elapsed_sec", perf["report"])
        self.assertIn("alerts_elapsed_sec", perf["report"])
        self.assertIn("summary_json_elapsed_sec", perf["report"])
        self.assertIn("by_module_elapsed_sec", perf["report"])
        self.assertIn("elapsed_sec", perf["report"])
        self.assertEqual(perf["report"]["by_api_count"], 1)

    def test_generate_enhanced_summary_patches_timings_without_reloading_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            graph_stats = {"step5_perf": {"main": {}}}
            result = tracer.TraceResult(
                coord="a:b",
                api_name="com.example.Service.run",
                api_simple="run",
                api_signature="()",
                symbol_kind="method",
                change_type="method_changed",
                severity="P1",
                confirmed=True,
                source="gitdiff",
                analysis_scope="method",
                analysis_status="reachable",
                direct_callers=1,
                is_reachable=True,
                reachable_note="已找到调用链",
                business_reach_depth=1,
                dependency_chain_coords=[],
                reason_code="SYSTEM_CODE_REACHABLE",
                call_paths=["Service.run -> Api.call"],
                evidence_paths=[],
                verification_commands=[],
                hops=[],
                confidence_score=1.0,
                critical_nodes_hit=[],
            )

            with patch.object(
                formatter.json,
                "load",
                side_effect=AssertionError("summary must not be loaded again"),
            ):
                _, summary_json_path = formatter.generate_enhanced_summary(
                    [result], output_dir, graph_stats=graph_stats
                )
            summary = json.loads(Path(summary_json_path).read_text(encoding="utf-8"))

        report = summary["meta"]["graph_stats"]["step5_perf"]["report"]
        self.assertIsInstance(report["summary_json_elapsed_sec"], float)
        self.assertIsInstance(report["elapsed_sec"], float)
        self.assertLess(report["summary_json_elapsed_sec"], 999998.0)
        self.assertLess(report["elapsed_sec"], 999998.0)

    def test_step5_timing_csv_includes_hotspot_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            graph_stats = {
                "step5_perf": {
                    "main": {
                        "business_graph_elapsed_sec": 0.123,
                        "indirect_usage_elapsed_sec": 24.0,
                        "indirect_usage_potential_legacy_method_target_pairs": 10205100,
                        "indirect_usage_owner_presence_scans": 17,
                    },
                    "trace": {
                        "elapsed_sec": 42.0,
                        "total_apis": 1972,
                        "frontier_pops": 12345,
                        "incoming_edges_scanned": 631208,
                        "incoming_edges_cache_hits": 100,
                        "incoming_edges_cache_misses": 25,
                        "critical_node_cache_hits": 200,
                        "critical_node_cache_misses": 30,
                        "critical_node_fast_none": 29,
                        "direct_class_usage_elapsed_sec": 1.5,
                        "direct_class_usage_scanned_methods": 26331,
                        "direct_class_usage_cache_hits": 10,
                        "direct_class_usage_cache_misses": 2,
                        "direct_field_usage_elapsed_sec": 2.5,
                        "direct_field_usage_scanned_methods": 52662,
                        "direct_field_usage_cache_hits": 20,
                        "direct_field_usage_cache_misses": 4,
                        "direct_source_fact_index_builds": 1,
                        "direct_source_fact_index_hits": 15,
                        "direct_source_fact_index_elapsed_sec": 0.75,
                        "direct_source_fact_index_scanned_methods": 26331,
                        "direct_source_fact_index_body_reads": 26331,
                        "direct_source_fact_index_body_cache_evictions": 12000,
                        "direct_source_fact_index_class_keys": 900,
                        "direct_source_fact_index_field_keys": 300,
                        "declared_signature_index_builds": 1,
                        "declared_signature_index_size": 1234,
                        "multi_target_group_count": 3,
                        "multi_target_target_count": 12,
                        "multi_target_shared_key_count": 7,
                        "multi_target_propagated_states": 31,
                        "reverse_transition_cache_builds": 8,
                        "reverse_transition_cache_hits": 21,
                        "reverse_transition_edges_materialized": 19,
                        "reverse_transition_edges_reused": 44,
                    },
                }
            }

            timing_path = step5._write_step5_timing_csv(output_dir, graph_stats)
            self.assertEqual(
                Path(timing_path),
                output_dir / ".runtime/observability/step5_timing.csv",
            )
            with Path(timing_path).open(encoding="utf-8-sig") as f:
                rows = list(csv.DictReader(f))

        values = {(row["section"], row["metric"]): row["value"] for row in rows}
        self.assertEqual(values[("main", "indirect_usage_elapsed_sec")], "24.0")
        self.assertEqual(
            values[("main", "indirect_usage_potential_legacy_method_target_pairs")],
            "10205100",
        )
        self.assertEqual(values[("main", "indirect_usage_owner_presence_scans")], "17")
        self.assertEqual(values[("trace", "elapsed_sec")], "42.0")
        self.assertEqual(values[("trace", "frontier_pops")], "12345")
        self.assertEqual(values[("trace", "incoming_edges_scanned")], "631208")
        self.assertEqual(values[("trace", "incoming_edges_cache_hits")], "100")
        self.assertEqual(values[("trace", "critical_node_cache_misses")], "30")
        self.assertEqual(values[("trace", "critical_node_fast_none")], "29")
        self.assertEqual(values[("trace", "direct_class_usage_cache_hits")], "10")
        self.assertEqual(values[("trace", "direct_field_usage_scanned_methods")], "52662")
        self.assertEqual(values[("trace", "direct_source_fact_index_builds")], "1")
        self.assertEqual(
            values[("trace", "direct_source_fact_index_scanned_methods")],
            "26331",
        )
        self.assertEqual(
            values[("trace", "direct_source_fact_index_body_cache_evictions")],
            "12000",
        )
        self.assertEqual(values[("trace", "declared_signature_index_builds")], "1")
        self.assertEqual(values[("trace", "declared_signature_index_size")], "1234")
        self.assertEqual(values[("trace", "multi_target_group_count")], "3")
        self.assertEqual(values[("trace", "multi_target_target_count")], "12")
        self.assertEqual(values[("trace", "multi_target_shared_key_count")], "7")
        self.assertEqual(values[("trace", "reverse_transition_cache_hits")], "21")
        self.assertEqual(
            values[("trace", "reverse_transition_edges_materialized")], "19"
        )

    def test_step5_timing_exposes_live_activity_and_keeps_it_with_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            timing = step5.Step5TimingRecorder(tmp)
            token = timing.start_phase(
                "graph.business_source",
                item="src/main/java",
                message="正在构建业务源码调用图",
            )

            with Path(timing.path).open(encoding="utf-8-sig", newline="") as handle:
                running_rows = list(csv.DictReader(handle))

            self.assertEqual(len(running_rows), 1)
            self.assertEqual(running_rows[0]["section"], "activity")
            self.assertEqual(running_rows[0]["metric"], "graph.business_source")
            self.assertEqual(running_rows[0]["status"], "running")
            self.assertEqual(running_rows[0]["item"], "src/main/java")
            self.assertIn("构建业务源码调用图", running_rows[0]["message"])

            timing.finish_phase(
                token,
                status="completed",
                message="业务源码调用图构建完成",
            )
            timing.write_metrics({
                "step5_perf": {
                    "main": {"business_graph_elapsed_sec": 1.25},
                },
            })
            with Path(timing.path).open(encoding="utf-8-sig", newline="") as handle:
                completed_rows = list(csv.DictReader(handle))

        activity = next(row for row in completed_rows if row["section"] == "activity")
        metric = next(
            row for row in completed_rows
            if row["section"] == "main"
            and row["metric"] == "business_graph_elapsed_sec"
        )
        self.assertEqual(activity["status"], "completed")
        self.assertTrue(activity["ended_at"])
        self.assertGreaterEqual(float(activity["elapsed_sec"]), 0.0)
        self.assertEqual(metric["value"], "1.25")

    def test_trace_cache_reuses_sorted_incoming_edges_and_critical_node_checks(self):
        trace_cache = tracer.ensure_trace_cache()
        edge_a = source_analyzer.CallEdge(
            caller_symbol_id="b",
            caller_qualified_key="B.call",
            callee_key="Target.call()",
            callee_simple_key="method:call()",
            evidence_type="source",
            confidence="medium",
            file="B.java",
            line=20,
            content="",
            owner_type="dependency",
            owner_coord="g:b",
            module="",
            is_test=False,
        )
        edge_b = source_analyzer.CallEdge(
            caller_symbol_id="a",
            caller_qualified_key="A.call",
            callee_key="Target.call()",
            callee_simple_key="method:call()",
            evidence_type="source",
            confidence="high",
            file="A.java",
            line=10,
            content="",
            owner_type="business",
            owner_coord="__business__",
            module="",
            is_test=False,
        )
        graph = SimpleNamespace(reverse_edges={"Target.call()": [edge_a, edge_b]})

        first_edges = tracer.get_cached_sorted_incoming_edges(
            graph.reverse_edges,
            "Target.call()",
            trace_cache=trace_cache,
            graph=graph,
        )
        second_edges = tracer.get_cached_sorted_incoming_edges(
            graph.reverse_edges,
            "Target.call()",
            trace_cache=trace_cache,
            graph=graph,
        )

        self.assertIs(first_edges, second_edges)
        self.assertEqual([edge.caller_symbol_id for edge in first_edges], ["a", "b"])
        perf = tracer._finalize_step5_perf_stats(graph)["trace"]
        self.assertEqual(perf["incoming_edges_cache_misses"], 1)
        self.assertEqual(perf["incoming_edges_cache_hits"], 1)

        method_def = SimpleNamespace(
            symbol_id="app_run",
            qualified_key="com.app.App.run",
            owner_type="business",
            is_test=False,
            file="App.java",
            line=7,
            class_fqcn="com.app.App",
            annotations=[],
        )
        first_node = tracer.get_cached_critical_node(method_def, graph, {}, trace_cache=trace_cache)
        second_node = tracer.get_cached_critical_node(method_def, graph, {}, trace_cache=trace_cache)

        self.assertIs(first_node, second_node)
        self.assertEqual(first_node["type"], "system_code_touched")
        perf = tracer._finalize_step5_perf_stats(graph)["trace"]
        self.assertEqual(perf["critical_node_cache_misses"], 1)
        self.assertEqual(perf["critical_node_cache_hits"], 1)

        dependency_method = SimpleNamespace(
            symbol_id="dep_call",
            qualified_key="com.dep.Lib.call",
            owner_type="dependency",
            is_test=False,
            file="Lib.java",
            line=1,
            class_fqcn="com.dep.Lib",
            class_name="Lib",
            annotations=[],
            class_annotations=[],
            is_interface=False,
        )
        self.assertIsNone(
            tracer.get_cached_critical_node(dependency_method, graph, {}, trace_cache=trace_cache)
        )
        perf = tracer._finalize_step5_perf_stats(graph)["trace"]
        self.assertEqual(perf["critical_node_fast_none"], 1)

    def test_concrete_dependency_interface_method_is_not_a_dynamic_proxy_boundary(self):
        graph = SimpleNamespace(
            methods_by_id={},
            framework_entry_symbols={},
            framework_runtime_entry_methods={},
            framework_activation_linked_symbols=set(),
        )
        type_metadata = {
            "org.apache.dubbo.common.utils.FieldUtils": {
                "kind": "interface",
                "implementations": [],
                "annotations": [],
            }
        }

        for symbol_id, is_static, modifiers in (
            ("static", True, ["public", "static"]),
            ("default", False, ["public", "default"]),
            ("private", False, ["private"]),
        ):
            with self.subTest(symbol_id=symbol_id):
                method_def = SimpleNamespace(
                    symbol_id=symbol_id,
                    qualified_key=f"org.apache.dubbo.common.utils.FieldUtils.{symbol_id}",
                    owner_type="dependency",
                    is_test=False,
                    file="FieldUtils.java",
                    line=1,
                    class_fqcn="org.apache.dubbo.common.utils.FieldUtils",
                    class_name="FieldUtils",
                    annotations=[],
                    class_annotations=[],
                    is_interface=True,
                    is_static=is_static,
                    modifiers=modifiers,
                )

                self.assertIsNone(
                    tracer.get_cached_critical_node(
                        method_def,
                        graph,
                        type_metadata,
                        trace_cache=tracer.ensure_trace_cache(),
                    )
                )

    def test_dependency_method_lookup_does_not_cross_into_unrelated_object_method(self):
        method_def = source_analyzer.MethodDef(
            symbol_id="annotation_get_class",
            qualified_key="com.vendor.AnnotationMeta.getClass",
            simple_key="method:getClass",
            class_fqcn="com.vendor.AnnotationMeta",
            class_name="AnnotationMeta",
            method_name="getClass",
            return_type="Class",
            file="/AnnotationMeta.java",
            line=1,
            end_line=2,
            package_name="com.vendor",
            owner_type="dependency",
            owner_coord="com.vendor:runtime",
            module="runtime",
            source_root="/src",
            language="java",
            is_test=False,
            param_types={"attributeName": "java.lang.String"},
            param_declared_types={"attributeName": "String"},
            declared_signature="(String)",
            declared_qualified_key="com.vendor.AnnotationMeta.getClass(String)",
        )
        object_edge = SimpleNamespace(
            caller_symbol_id="field_utils",
            caller_qualified_key="com.vendor.FieldUtils.findField",
            callee_key="java.lang.Object.getClass()",
            callee_simple_key="method:getClass()",
            evidence_type="ast_method_invocation",
            confidence="high",
            file="/FieldUtils.java",
            line=10,
            owner_type="dependency",
            owner_coord="com.vendor:runtime",
            module="runtime",
            is_test=False,
        )
        graph = SimpleNamespace(
            reverse_edges={
                "java.lang.Object.getClass()": [object_edge],
                "java.lang.Object.getClass": [object_edge],
            },
            methods_by_id={},
        )

        matched_groups, overload_block = tracer.get_cached_method_lookup_resolution(
            method_def,
            {"com.vendor.AnnotationMeta": {"kind": "class"}},
            graph,
            trace_cache=tracer.ensure_trace_cache(),
        )

        self.assertEqual(matched_groups, [])
        self.assertIsNone(overload_block)

    def test_declared_method_signature_index_is_built_once_for_many_api_filters(self):
        graph = SimpleNamespace(
            methods_by_id={
                f"m{i}": SimpleNamespace(
                    qualified_key=f"com.example.Api{i}.call",
                    method_name="call",
                    signature="()",
                    param_types=[],
                )
                for i in range(100)
            }
        )
        trace_cache = tracer.ensure_trace_cache()

        for i in range(20):
            signatures = tracer.collect_declared_method_signatures(
                f"com.example.Api{i}.call",
                graph,
                trace_cache=trace_cache,
            )
            self.assertIn("()", signatures)

        perf = tracer._finalize_step5_perf_stats(graph)["trace"]
        self.assertEqual(perf["declared_signature_index_builds"], 1)
        self.assertEqual(perf["declared_signature_index_size"], 100)

    def test_direct_business_usage_builds_one_source_fact_index_for_many_targets(self):
        cached_method = SimpleNamespace(
            symbol_id="second",
            owner_type="business",
            return_type="",
            param_types={},
            field_types={},
            local_var_types={"value": "com.changed.Target"},
            imports={"Flags": "com.changed.Flags"},
            wildcard_imports=[],
            static_imports={},
            package_name="com.app",
            body_text="",
            _body_text_cached="return Flags.ENABLED;",
        )
        cached_method.get_body_text = lambda: cached_method._body_text_cached
        methods = {
            "first": SimpleNamespace(
                symbol_id="first",
                owner_type="business",
                return_type="",
                param_types={},
                field_types={},
                local_var_types={},
                imports={},
                wildcard_imports=[],
                static_imports={},
                package_name="com.app",
                get_body_text=lambda: "",
            ),
            "second": cached_method,
        }
        graph = SimpleNamespace(methods_by_id=methods)
        trace_cache = tracer.ensure_trace_cache()

        class_api = {
            "api_name": "com.changed.Target",
            "matched_class": "com.changed.Target",
        }
        first_class_match = tracer._find_direct_business_class_usage(
            class_api,
            graph,
            trace_cache=trace_cache,
        )
        second_class_match = tracer._find_direct_business_class_usage(
            class_api,
            graph,
            trace_cache=trace_cache,
        )

        self.assertEqual(first_class_match[0].symbol_id, "second")
        self.assertIs(first_class_match, second_class_match)

        field_api = {
            "api_name": "com.changed.Flags.ENABLED",
            "api_simple": "ENABLED",
        }
        first_field_matches = tracer._find_direct_business_field_usages(
            field_api,
            graph,
            trace_cache=trace_cache,
        )
        second_field_matches = tracer._find_direct_business_field_usages(
            field_api,
            graph,
            trace_cache=trace_cache,
        )

        self.assertEqual([item[0].symbol_id for item in first_field_matches], ["second"])
        self.assertEqual([item[0].symbol_id for item in second_field_matches], ["second"])

        perf = tracer._finalize_step5_perf_stats(graph)["trace"]
        self.assertEqual(perf["direct_class_usage_cache_misses"], 1)
        self.assertEqual(perf["direct_class_usage_cache_hits"], 1)
        self.assertEqual(perf["direct_field_usage_cache_misses"], 1)
        self.assertEqual(perf["direct_field_usage_cache_hits"], 1)
        self.assertEqual(perf["direct_source_fact_index_builds"], 1)
        self.assertEqual(perf["direct_source_fact_index_scanned_methods"], 2)
        self.assertEqual(perf["direct_source_fact_index_body_reads"], 2)
        self.assertEqual(perf["direct_source_fact_index_body_cache_evictions"], 1)
        self.assertGreaterEqual(perf["direct_source_fact_index_hits"], 1)
        self.assertEqual(cached_method._body_text_cached, "")

    def test_source_fact_index_preserves_package_and_wildcard_type_candidates(self):
        method = SimpleNamespace(
            symbol_id="consumer",
            owner_type="business",
            local_var_types={"value": "Target"},
            imports={},
            wildcard_imports=["com.changed"],
            static_imports={},
            package_name="com.app",
            get_body_text=lambda: "",
        )
        graph = SimpleNamespace(methods_by_id={"consumer": method})
        trace_cache = tracer.ensure_trace_cache()

        for target_class in ("com.app.Target", "com.changed.Target"):
            matches = tracer._find_direct_business_class_usages(
                {"api_name": target_class, "matched_class": target_class},
                graph,
                trace_cache=trace_cache,
            )
            self.assertEqual([item[0].symbol_id for item in matches], ["consumer"])

        perf = tracer._finalize_step5_perf_stats(graph)["trace"]
        self.assertEqual(perf["direct_source_fact_index_builds"], 1)
        self.assertEqual(perf["direct_source_fact_index_scanned_methods"], 1)

    def test_source_fact_index_rejects_ambiguous_known_type_candidates(self):
        method = SimpleNamespace(
            symbol_id="consumer",
            owner_type="business",
            local_var_types={"value": "Target"},
            known_classes_by_simple={
                "Target": {"com.app.Target", "com.changed.Target"},
            },
            imports={},
            wildcard_imports=["com.changed"],
            static_imports={},
            package_name="com.app",
            get_body_text=lambda: "",
        )
        graph = SimpleNamespace(methods_by_id={"consumer": method})
        trace_cache = tracer.ensure_trace_cache()

        for target_class in ("com.app.Target", "com.changed.Target"):
            matches = tracer._find_direct_business_class_usages(
                {"api_name": target_class, "matched_class": target_class},
                graph,
                trace_cache=trace_cache,
            )
            self.assertEqual(matches, [])

    def test_trace_all_apis_merges_step5_perf_without_dropping_main_stats(self):
        graph = SimpleNamespace()
        graph_stats = {
            "step5_perf": {
                "main": {
                    "business_graph_elapsed_sec": 12.345,
                }
            }
        }

        results = tracer.trace_all_apis_with_confidence_weighting(
            [],
            graph,
            {},
            graph_stats=graph_stats,
        )

        self.assertEqual(results, [])
        perf = graph_stats["step5_perf"]
        self.assertEqual(perf["main"]["business_graph_elapsed_sec"], 12.345)
        self.assertIn("trace", perf)
        self.assertEqual(perf["trace"]["total_apis"], 0.0)
        self.assertEqual(perf["trace"]["calls"], 1.0)

    def test_step5_perf_records_top_slow_items_sorted_and_rounded(self):
        graph = SimpleNamespace()

        tracer._perf_record_top(graph, "trace", "slow_api_traces", {
            "api_name": "fast",
            "elapsed_sec": 0.0014,
        })
        tracer._perf_record_top(graph, "trace", "slow_api_traces", {
            "api_name": "slow",
            "elapsed_sec": 1.23456,
        })
        tracer._perf_record_top(graph, "trace", "slow_api_traces", {
            "api_name": "middle",
            "elapsed_sec": 0.5,
        })

        perf = tracer._finalize_step5_perf_stats(graph)

        self.assertEqual(
            [item["api_name"] for item in perf["trace"]["slow_api_traces"]],
            ["slow", "middle", "fast"],
        )
        self.assertEqual(perf["trace"]["slow_api_traces"][0]["elapsed_sec"], 1.235)

    def test_trace_all_apis_records_slow_api_trace_details(self):
        graph = SimpleNamespace()
        graph_stats = {}
        api_row = {
            "coord": "a:b",
            "api_name": "com.example.OrderService.run",
            "api_simple": "run",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "method_changed",
            "severity": "P1",
        }
        trace_result = tracer.TraceResult(
            coord="a:b",
            api_name="com.example.OrderService.run",
            api_simple="run",
            api_signature="()",
            symbol_kind="method",
            change_type="method_changed",
            severity="P1",
            confirmed=True,
            source="gitdiff",
            analysis_scope="method",
            analysis_status="reachable",
            direct_callers=1,
            is_reachable=True,
            reachable_note="已找到调用链",
            business_reach_depth=1,
            dependency_chain_coords=[],
            reason_code="SYSTEM_CODE_REACHABLE",
            call_paths=["OrderService.run -> DemoApi.call"],
            evidence_paths=[],
            verification_commands=[],
            hops=[],
            confidence_score=0.95,
            critical_nodes_hit=[],
        )

        with patch.object(tracer, "trace_api_with_confidence_weighting", return_value=trace_result):
            tracer.trace_all_apis_with_confidence_weighting([api_row], graph, {}, graph_stats=graph_stats)

        slow_apis = graph_stats["step5_perf"]["trace"]["slow_api_traces"]
        self.assertEqual(len(slow_apis), 1)
        self.assertEqual(slow_apis[0]["api_name"], "com.example.OrderService.run")
        self.assertEqual(slow_apis[0]["analysis_status"], "reachable")
        self.assertEqual(slow_apis[0]["reason_code"], "SYSTEM_CODE_REACHABLE")

    def test_large_runtime_catalog_prefers_member_index_without_light_scan(self):
        entries = [
            {
                "coord": f"com.example:dep-{idx}",
                "jar_path": f"/missing/dep-{idx}.jar",
            }
            for idx in range(50)
        ]
        graph = SimpleNamespace(
            runtime_dependency_catalog={
                "status": "complete",
                "entries": entries,
            }
        )
        fake_index = {
            "tasks": [],
            "unparsed_tasks": [],
            "direct_by_owner_member": {},
            "owner_string_ids": {},
            "member_string_ids": {},
            "reflection_ids": set(),
            "visited_classes": 1234,
            "parse_failures": 0,
        }

        with patch.object(tracer, "_get_runtime_dependency_member_candidate_index", return_value=fake_index) as mocked_index:
            result = tracer._ensure_runtime_dependency_callers_for_key(
                graph,
                "com.example.Target.run()",
            )

        self.assertTrue(result["expanded"])
        mocked_index.assert_called_once()
        perf = tracer._finalize_step5_perf_stats(graph)["bytecode_expand"]
        self.assertEqual(perf["member_index_auto_large_catalog"], 1.0)
        self.assertEqual(perf["member_index_candidate_queries"], 1.0)
        self.assertNotIn("light_scans", perf)
        self.assertEqual(perf["slow_runtime_lookups"][0]["candidate_source"], "member_index")

    def test_large_runtime_catalog_uses_lightweight_member_index_for_large_artifacts(self):
        entries = [
            {
                "coord": f"com.example:dep-{idx}",
                "jar_path": f"/missing/dep-{idx}.jar",
            }
            for idx in range(50)
        ]
        graph = SimpleNamespace(
            runtime_dependency_catalog={
                "status": "complete",
                "entries": entries,
            }
        )

        fake_index = {
            "complete": True, "failures": [], "tasks": [], "unparsed_tasks": [],
            "direct_by_owner_member": {}, "owner_string_ids": {},
            "member_string_ids": {}, "reflection_ids": set(), "visited_classes": 0,
        }
        with (
            patch.object(tracer.os.path, "getsize", return_value=1024 * 1024),
            patch.object(
                tracer, "_get_runtime_dependency_member_candidate_index", return_value=fake_index
            ) as mocked_index,
        ):
            result = tracer._ensure_runtime_dependency_callers_for_key(
                graph,
                "com.example.Target.run()",
            )

        self.assertTrue(result["expanded"])
        mocked_index.assert_called_once()
        perf = tracer._finalize_step5_perf_stats(graph)["bytecode_expand"]
        self.assertEqual(perf["member_index_large_artifact_catalog"], 1.0)
        self.assertNotIn("light_scans", perf)
        self.assertEqual(perf["slow_runtime_lookups"][0]["candidate_source"], "member_index")

    def test_large_real_jar_catalog_builds_member_index_once_for_many_lookups(self):
        with tempfile.TemporaryDirectory() as tmp:
            classes = self._compile_java_fixture(
                tmp,
                "com/example/Consumer.java",
                """
                package com.example;
                public class Consumer { public void call() { Target.run(); } }
                class Target { static void run() {} }
                """,
            )
            jar_path = Path(tmp) / "consumer.jar"
            self._jar_compiled_classes(jar_path, classes)
            entries = [{"coord": "com.example:consumer", "jar_path": str(jar_path)}]
            graph = SimpleNamespace(runtime_dependency_catalog={
                "status": "complete", "entries": entries,
            })

            with (
                patch.object(tracer, "_step5_runtime_member_index_min_jars", return_value=1),
                patch.object(tracer, "_step5_runtime_member_index_max_bytes", return_value=1),
            ):
                preferred, reason = tracer._should_prefer_runtime_member_candidate_index(
                    graph, entries
                )
                tracer._ensure_runtime_dependency_callers_for_key(
                    graph, "com.example.Target.run()"
                )
                tracer._ensure_runtime_dependency_callers_for_key(
                    graph, "com.example.Missing.first()"
                )
                tracer._ensure_runtime_dependency_callers_for_key(
                    graph, "com.example.Missing.second()"
                )

        self.assertTrue(preferred)
        self.assertTrue(reason.startswith("large_artifact_catalog:"))
        perf = tracer._finalize_step5_perf_stats(graph)["bytecode_expand"]
        self.assertEqual(perf["member_index_builds"], 1.0)
        self.assertEqual(perf["member_index_candidate_queries"], 3.0)
        self.assertNotIn("light_scans", perf)

    def test_alerts_csv_is_complete_path_ledger_with_explicit_consumers(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "alerts.csv"
            result = tracer.TraceResult(
                coord="commons-lang:commons-lang",
                api_name="org.apache.commons.lang.StringUtils.isBlank",
                api_simple="isBlank", api_signature="(String)", symbol_kind="method",
                change_type="REMOVED", severity="P0", confirmed=True, source="old_jar",
                analysis_scope="method", analysis_status="uncertain", direct_callers=0,
                is_reachable=None, reachable_note="依赖字节码命中", business_reach_depth=0,
                dependency_chain_coords=["a:consumer", "b:consumer"], call_paths=[],
                evidence_paths=[], reason_code="RUNTIME_DEPENDENCY_USES_REMOVED_API",
                verification_commands=[], hops=[], confidence_score=1.0, critical_nodes_hit=[],
                path_details=[
                    {
                        "path_status": "uncertain", "stop_reason": "BUSINESS_ENTRY_NOT_CONFIRMED",
                        "business_reachable": None, "consumer_coord": "a:consumer",
                        "consumer_class": "com.acme.Adapter", "consumer_method": "validate",
                        "consumer_signature": "(String)",
                        "path_text": "a:consumer:Adapter.validate -> StringUtils.isBlank",
                        "confidence": 1.0, "depth": 1,
                        "evidence": [{"evidence_type": "bytecode_method_invocation", "file": "/a.jar"}],
                    },
                    {
                        "path_status": "uncertain", "stop_reason": "BUSINESS_ENTRY_NOT_CONFIRMED",
                        "business_reachable": None, "consumer_coord": "b:consumer",
                        "consumer_class": "com.acme.Helper", "consumer_method": "convert",
                        "consumer_signature": "()",
                        "path_text": "b:consumer:Helper.convert -> StringUtils.isBlank",
                        "confidence": 1.0, "depth": 1,
                        "evidence": [{"evidence_type": "bytecode_method_invocation", "file": "/b.jar"}],
                    },
                ],
            )

            formatter.generate_alerts_csv([result], output)
            with output.open(encoding="utf-8-sig") as handle:
                rows = list(csv.DictReader(handle))
            original_path_ids = [row["path_id"] for row in rows]
            result.path_details[0]["evidence"][0]["file"] = "/different/run/a.jar"
            result.path_details[1]["evidence"][0]["file"] = "/different/run/b.jar"
            formatter.generate_alerts_csv([result], output)
            with output.open(encoding="utf-8") as handle:
                relocated_rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 2)
        self.assertEqual({row["consumer_coord"] for row in rows}, {"a:consumer", "b:consumer"})
        self.assertEqual({row["consumer_method"] for row in rows}, {"validate", "convert"})
        self.assertTrue(all(row["path_status"] == "uncertain" for row in rows))
        self.assertTrue(all(row["business_reachable"] == "unknown" for row in rows))
        self.assertTrue(all(row["api_identity"] and row["path_id"] for row in rows))
        self.assertTrue(all("尚缺少从业务入口" in row["review_reason"] for row in rows))
        self.assertEqual(original_path_ids, [row["path_id"] for row in relocated_rows])

    def test_alerts_csv_suppresses_only_suffix_paths_covered_by_longer_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "alerts.csv"
            result = tracer.TraceResult(
                coord="com.acme:target-lib",
                api_name="com.acme.Target.removed",
                api_simple="removed",
                api_signature="()",
                symbol_kind="method",
                change_type="METHOD_REMOVED",
                severity="P0",
                confirmed=True,
                source="japicmp",
                analysis_scope="method",
                analysis_status="reachable",
                direct_callers=3,
                is_reachable=True,
                reachable_note="已证明触达业务代码",
                business_reach_depth=2,
                dependency_chain_coords=["com.acme:consumer-lib"],
                call_paths=[],
                evidence_paths=[],
                reason_code="BUSINESS_ARTIFACT_BYTECODE_USAGE",
                verification_commands=[],
                hops=[],
                confidence_score=1.0,
                critical_nodes_hit=[],
                path_details=[
                    {
                        "path_status": "reachable",
                        "business_reachable": True,
                        "business_entry": "A.entry",
                        "consumer_coord": "com.acme:consumer-lib",
                        "path_text": "A.entry -> B.call -> C.removed",
                        "confidence": 1.0,
                        "depth": 2,
                        "evidence": [],
                    },
                    {
                        "path_status": "reachable",
                        "business_reachable": True,
                        "business_entry": "E.entry",
                        "consumer_coord": "com.acme:consumer-lib",
                        "path_text": "E.entry -> B.call -> C.removed",
                        "confidence": 1.0,
                        "depth": 2,
                        "evidence": [],
                    },
                    {
                        "path_status": "uncertain",
                        "stop_reason": "BUSINESS_ENTRY_NOT_CONFIRMED",
                        "business_reachable": None,
                        "consumer_coord": "com.acme:consumer-lib",
                        "path_text": "B.call -> C.removed",
                        "confidence": 1.0,
                        "depth": 1,
                        "evidence": [],
                    },
                    {
                        "path_status": "reachable",
                        "business_reachable": True,
                        "business_entry": "F.entry",
                        "consumer_coord": "__business__",
                        "path_text": "F.entry -> C.removed",
                        "confidence": 1.0,
                        "depth": 1,
                        "evidence": [],
                    },
                ],
            )

            formatter.generate_alerts_csv([result], output)
            with output.open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        path_texts = {row["path_text"] for row in rows}
        self.assertEqual(
            path_texts,
            {
                "A.entry -> B.call -> C.removed",
                "E.entry -> B.call -> C.removed",
                "F.entry -> C.removed",
            },
        )
        self.assertNotIn("B.call -> C.removed", path_texts)

    def test_alerts_csv_deduplicates_equivalent_paths_but_keeps_distinct_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "alerts.csv"
            result = tracer.TraceResult(
                coord="com.acme:target-lib",
                api_name="com.acme.Target.removed",
                api_simple="removed",
                api_signature="()",
                symbol_kind="method",
                change_type="METHOD_REMOVED",
                severity="P0",
                confirmed=True,
                source="japicmp",
                analysis_scope="method",
                analysis_status="reachable",
                direct_callers=3,
                is_reachable=True,
                reachable_note="已证明触达业务代码",
                business_reach_depth=1,
                dependency_chain_coords=["com.acme:consumer-lib"],
                call_paths=[],
                evidence_paths=[],
                reason_code="BUSINESS_ARTIFACT_BYTECODE_USAGE",
                verification_commands=[],
                hops=[],
                confidence_score=1.0,
                critical_nodes_hit=[],
                path_details=[
                    {
                        "path_status": "reachable",
                        "business_reachable": True,
                        "business_entry": "A.entry",
                        "consumer_coord": "com.acme:consumer-lib",
                        "path_text": "A.entry -> C.removed",
                        "confidence": 1.0,
                        "depth": 1,
                        "evidence": [
                            {
                                "caller_symbol": "A.entry",
                                "callee_key": "C.removed",
                                "evidence_type": "method_invocation",
                                "owner_coord": "com.acme:consumer-lib",
                                "file": "/src/A.java",
                            }
                        ],
                    },
                    {
                        "path_status": "reachable",
                        "business_reachable": True,
                        "business_entry": "A.entry",
                        "consumer_coord": "com.acme:consumer-lib",
                        "path_text": "A.entry -> C.removed",
                        "confidence": 1.0,
                        "depth": 1,
                        "evidence": [
                            {
                                "caller_symbol": "A.entry",
                                "callee_key": "C.removed",
                                "evidence_type": "method_invocation",
                                "owner_coord": "com.acme:consumer-lib",
                                "file": "/relocated/A.java",
                            }
                        ],
                    },
                    {
                        "path_status": "reachable",
                        "business_reachable": True,
                        "business_entry": "E.entry",
                        "consumer_coord": "com.acme:consumer-lib",
                        "path_text": "E.entry -> C.removed",
                        "confidence": 1.0,
                        "depth": 1,
                        "evidence": [],
                    },
                ],
            )

            formatter.generate_alerts_csv([result], output)
            with output.open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 2)
        counts = {row["path_text"]: row["path_occurrence_count"] for row in rows}
        self.assertEqual(counts["A.entry -> C.removed"], "2")
        self.assertEqual(counts["E.entry -> C.removed"], "1")

    def test_alerts_csv_writes_review_split_files_without_replacing_main_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "alerts.csv"
            results = []
            for status, api_name in [
                ("reachable", "com.acme.Api.reachable"),
                ("uncertain", "com.acme.Api.uncertain"),
                ("not_found_in_static_analysis", "com.acme.Api.notFound"),
                ("not_analyzed", "com.acme.Api.notAnalyzed"),
            ]:
                results.append(tracer.TraceResult(
                    coord="a:b",
                    api_name=api_name,
                    api_simple=api_name.rsplit(".", 1)[-1],
                    api_signature="()",
                    symbol_kind="method",
                    change_type="METHOD_CHANGED",
                    severity="P1",
                    confirmed=True,
                    source="japicmp",
                    analysis_scope="method",
                    analysis_status=status,
                    direct_callers=1 if status == "reachable" else 0,
                    is_reachable=True if status == "reachable" else None,
                    reachable_note=status,
                    business_reach_depth=1,
                    dependency_chain_coords=[],
                    call_paths=[f"{api_name}.caller -> {api_name}"],
                    evidence_paths=[],
                    reason_code="SYSTEM_CODE_REACHED" if status == "reachable" else "NO_STATIC_PATH",
                    verification_commands=[],
                    hops=[],
                    confidence_score=1.0,
                    critical_nodes_hit=[],
                ))

            formatter.generate_alerts_csv(results, output)

            with output.open(encoding="utf-8") as handle:
                main_rows = list(csv.DictReader(handle))
            split_files = {path.name for path in Path(tmp).glob("alerts_*.csv")}

        self.assertEqual(len(main_rows), 4)
        self.assertEqual(
            split_files,
            {
                "alerts_reachable.csv",
                "alerts_uncertain.csv",
                "alerts_not_found_in_static_analysis.csv",
                "alerts_not_analyzed.csv",
            },
        )

    def test_alerts_review_split_files_are_chunked_and_stale_files_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            stale = output_dir / "alerts_reachable_003.csv"
            stale.write_text("stale\n", encoding="utf-8")
            stale_uncertain = output_dir / "alerts_uncertain.csv"
            stale_uncertain.write_text("stale\n", encoding="utf-8")
            rows = [
                {
                    field: ""
                    for field in formatter.ALERTS_CSV_FIELDNAMES
                }
                for _ in range(5)
            ]
            for index, row in enumerate(rows):
                row.update({
                    "api_id": f"API-{index}",
                    "path_id": f"PATH-{index}",
                    "path_status": "reachable",
                    "conclusion_level": "confirmed",
                    "severity": "P1",
                })

            formatter.write_alerts_review_splits(rows, str(output_dir), max_rows=2)

            split_files = sorted(path.name for path in output_dir.glob("alerts_*.csv"))
            counts = {}
            for name in split_files:
                with (output_dir / name).open(encoding="utf-8") as handle:
                    counts[name] = len(list(csv.DictReader(handle)))
            stale_uncertain_exists = stale_uncertain.exists()

        self.assertEqual(
            split_files,
            ["alerts_reachable_001.csv", "alerts_reachable_002.csv", "alerts_reachable_003.csv"],
        )
        self.assertEqual(counts, {
            "alerts_reachable_001.csv": 2,
            "alerts_reachable_002.csv": 2,
            "alerts_reachable_003.csv": 1,
        })
        self.assertFalse(stale_uncertain_exists)

    def test_alert_row_uses_path_stop_reason_instead_of_api_reason(self):
        result = tracer.TraceResult(
            coord="a:b", api_name="com.acme.Api.changed", api_simple="changed",
            api_signature="()", symbol_kind="method", change_type="METHOD_CHANGED",
            severity="P1", confirmed=True, source="japicmp", analysis_scope="method",
            analysis_status="reachable", direct_callers=1, is_reachable=True,
            reachable_note="部分链路触达", business_reach_depth=2,
            dependency_chain_coords=[], call_paths=[], evidence_paths=[],
            reason_code="SYSTEM_CODE_REACHED", verification_commands=[], hops=[],
            confidence_score=0.9, critical_nodes_hit=[], path_details=[{
                "path_status": "uncertain", "stop_reason": "LOW_CONFIDENCE_EDGE",
                "business_reachable": None, "path_text": "A.call -> B.call",
                "confidence": 0.4, "depth": 1, "evidence": [],
            }],
        )

        row = formatter._alert_rows_for_result(result)[0]

        self.assertEqual("需要人工复核", row["conclusion"])
        self.assertEqual("依赖 a:b 变更了方法 com.acme.Api.changed()（严重级别 P1）", row["change_summary"])
        self.assertEqual("入口：A.call；终点：B.call；1 次调用（2 个节点）", row["chain_summary"])
        self.assertEqual("A.call", row["chain_entry"])
        self.assertEqual("B.call", row["chain_target"])
        self.assertEqual("1", row["chain_hop_count"])
        self.assertEqual("1. A.call -> 2. B.call", row["chain_detail"])
        self.assertEqual("核对这条候选链路是否真实会在运行时触发。", row["review_focus"])
        self.assertIn("低置信度边", row["reason"])
        self.assertIn("低置信度边", row["review_reason"])
        self.assertNotIn("已证明变更 API 触达系统代码", row["reason"])

    def test_alert_chain_target_strips_changed_api_marker(self):
        result = tracer.TraceResult(
            coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
            api_signature="()", symbol_kind="method", change_type="REMOVED",
            severity="P0", confirmed=True, source="japicmp", analysis_scope="method",
            analysis_status="reachable", direct_callers=1, is_reachable=True,
            reachable_note="触达", business_reach_depth=2,
            dependency_chain_coords=[],
            call_paths=["com.app.A.call → com.alt.Adapter.gone() → 变更API: com.acme.Api.gone()"],
            evidence_paths=[],
            reason_code="SYSTEM_CODE_REACHED", verification_commands=[], hops=[],
            confidence_score=0.9, critical_nodes_hit=[],
        )

        row = formatter._alert_rows_for_result(result)[0]

        self.assertEqual("com.acme.Api.gone()", row["chain_target"])
        self.assertIn("变更 API： com.acme.Api.gone()", row["chain_detail"])

    def test_removed_class_alert_explains_who_references_it_and_runtime_consequence(self):
        result = tracer.TraceResult(
            coord="org.slf4j:slf4j-api",
            api_name="org.slf4j.Logger",
            api_simple="Logger",
            api_signature="",
            symbol_kind="class",
            change_type="REMOVED",
            severity="P0",
            confirmed=True,
            source="old_jar",
            analysis_scope="class_usage",
            analysis_status="reachable",
            direct_callers=1,
            is_reachable=True,
            reachable_note="业务制品字节码引用",
            business_reach_depth=1,
            dependency_chain_coords=[],
            call_paths=["__business__:com.acme.Application.<class> -> org.slf4j.Logger"],
            evidence_paths=[],
            reason_code="BUSINESS_ARTIFACT_BYTECODE_USAGE",
            verification_commands=[],
            hops=[],
            confidence_score=1.0,
            critical_nodes_hit=[],
            path_details=[{
                "path_status": "reachable",
                "stop_reason": "BUSINESS_ARTIFACT_BYTECODE_USAGE",
                "business_reachable": True,
                "business_entry": "__business__:com.acme.Application.<class>",
                "consumer_coord": "__business__",
                "consumer_class": "com.acme.Application",
                "consumer_method": "<class>",
                "consumer_signature": "",
                "path_text": "__business__:com.acme.Application.<class> -> org.slf4j.Logger",
                "confidence": 1.0,
                "depth": 1,
                "evidence": [{
                    "caller_symbol": "__business__:com.acme.Application.<class>",
                    "callee_key": "org.slf4j.Logger",
                    "evidence_type": "bytecode_class_reference",
                    "owner_coord": "__business__",
                    "file": "/app.jar",
                }],
            }],
        )

        row = formatter._alert_rows_for_result(result)[0]

        self.assertEqual("已确认影响：业务制品直接引用了被删除的类", row["conclusion"])
        self.assertEqual(
            "依赖 org.slf4j:slf4j-api 删除了类 org.slf4j.Logger（严重级别 P0）",
            row["change_summary"],
        )
        self.assertIn("com.acme.Application", row["review_reason"])
        self.assertIn("NoClassDefFoundError", row["review_reason"])
        self.assertEqual("类型引用：业务制品：com.acme.Application（类加载/链接） 依赖 org.slf4j.Logger", row["chain_summary"])
        self.assertNotIn("__business__", json.dumps(row, ensure_ascii=False))
        self.assertNotIn("<class>", json.dumps(row, ensure_ascii=False))

    def test_alerts_csv_keeps_api_without_any_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "alerts.csv"
            result = tracer.TraceResult(
                coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
                api_signature="()", symbol_kind="method", change_type="REMOVED", severity="P0",
                confirmed=True, source="japicmp", analysis_scope="method",
                analysis_status="not_found_in_static_analysis", direct_callers=0,
                is_reachable=False, reachable_note="未找到", business_reach_depth=0,
                dependency_chain_coords=[], call_paths=[], evidence_paths=[], reason_code="NO_STATIC_PATH",
                verification_commands=[], hops=[], confidence_score=0.0, critical_nodes_hit=[],
            )
            formatter.generate_alerts_csv([result], output)
            with output.open(encoding="utf-8-sig") as handle:
                rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 1)
        self.assertEqual("未发现静态调用路径", rows[0]["conclusion"])
        self.assertEqual("依赖 a:b 删除了方法 com.acme.Api.gone()（严重级别 P0）", rows[0]["change_summary"])
        self.assertIn("静态分析未发现调用链", rows[0]["chain_summary"])
        self.assertEqual("完整静态分析未发现调用链", rows[0]["chain_detail"])
        self.assertEqual("com.acme.Api.gone()", rows[0]["chain_target"])
        self.assertEqual(rows[0]["path_status"], "not_found_in_static_analysis")
        self.assertEqual(rows[0]["path_text"], "")

    def test_alert_row_marks_absent_path_without_fake_entry_or_confidence(self):
        result = tracer.TraceResult(
            coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
            api_signature="()", symbol_kind="method", change_type="REMOVED", severity="P0",
            confirmed=True, source="japicmp", analysis_scope="method",
            analysis_status="not_analyzed", direct_callers=0, is_reachable=None,
            reachable_note="运行时依赖 jar 缺失", business_reach_depth=0,
            dependency_chain_coords=[], call_paths=[], evidence_paths=[],
            reason_code="RUNTIME_DEPENDENCY_JARS_UNAVAILABLE", verification_commands=[], hops=[],
            confidence_score=1.0, critical_nodes_hit=[],
        )

        row = formatter._alert_rows_for_result(result)[0]

        self.assertEqual("未完成分析", row["conclusion"])
        self.assertEqual("", row["chain_entry"])
        self.assertIn("本次分析未完成", row["chain_summary"])
        self.assertEqual("分析未完成，尚无法判断是否存在调用链", row["chain_detail"])
        self.assertNotIn("无已发现调用链", json.dumps(row, ensure_ascii=False))
        self.assertEqual("0.00", row["confidence"])
        self.assertEqual(-1, row["depth"])
        self.assertEqual(0, row["path_occurrence_count"])
        self.assertEqual("", row["path_id"])
        self.assertEqual("unknown", row["business_reachable"])

    def test_not_analyzed_alert_retains_known_consumer_coordinate(self):
        result = tracer.TraceResult(
            coord="target:api", api_name="com.acme.Api.gone", api_simple="gone",
            api_signature="()", symbol_kind="method", change_type="REMOVED", severity="P0",
            confirmed=True, source="japicmp", analysis_scope="method",
            analysis_status="not_analyzed", direct_callers=0, is_reachable=None,
            reachable_note="缺少业务入口", business_reach_depth=0,
            dependency_chain_coords=["consumer:bridge:1.0"], call_paths=[], evidence_paths=[],
            reason_code="RUNTIME_DEPENDENCY_JARS_UNAVAILABLE", verification_commands=[], hops=[],
            confidence_score=0.0, critical_nodes_hit=[],
        )

        row = formatter._alert_rows_for_result(result)[0]

        self.assertEqual("consumer:bridge:1.0", row["consumer_coord"])

    def test_summary_json_groups_not_analyzed_reasons_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = tracer.TraceResult(
                coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
                api_signature="()", symbol_kind="method", change_type="REMOVED", severity="P0",
                confirmed=True, source="japicmp", analysis_scope="method",
                analysis_status="not_analyzed", direct_callers=0, is_reachable=None,
                reachable_note="运行时依赖 jar 缺失", business_reach_depth=0,
                dependency_chain_coords=[], call_paths=[], evidence_paths=[],
                reason_code="RUNTIME_DEPENDENCY_JARS_UNAVAILABLE", verification_commands=[], hops=[],
                confidence_score=0.0, critical_nodes_hit=[],
            )
            summary_path = formatter.write_summary_json([result], tmp)
            summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))

        self.assertEqual(
            {"RUNTIME_DEPENDENCY_JARS_UNAVAILABLE": 1},
            summary["not_analyzed_reason_summary"],
        )
        self.assertEqual("step5", summary["origin_step"])
        self.assertEqual(
            "UPPER_SNAKE_CASE",
            summary["diagnostic_contract"]["reason_code_style"],
        )

    def test_summary_api_entry_hides_unmatched_internal_tier(self):
        entry = formatter.trace_result_to_api_entry(
            tracer.TraceResult(
                coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
                api_signature="()", symbol_kind="method", change_type="REMOVED", severity="P0",
                confirmed=True, source="japicmp", analysis_scope="method",
                analysis_status="not_analyzed", direct_callers=0, is_reachable=None,
                reachable_note="缺少输入", business_reach_depth=0,
                dependency_chain_coords=[], call_paths=[], evidence_paths=[], reason_code="INPUT_MISSING",
                verification_commands=[], hops=[], confidence_score=0.0, critical_nodes_hit=[], match_tier=-1,
            )
        )
        self.assertIsNone(entry["match_tier"])

    def test_alert_coverage_details_are_compact_human_readable_text(self):
        result = tracer.TraceResult(
            coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
            api_signature="()", symbol_kind="method", change_type="REMOVED", severity="P0",
            confirmed=True, source="japicmp", analysis_scope="method",
            analysis_status="not_analyzed", direct_callers=0, is_reachable=None,
            reachable_note="缺少输入", business_reach_depth=0,
            dependency_chain_coords=[], call_paths=[], evidence_paths=[], reason_code="INPUT_MISSING",
            verification_commands=[], hops=[], confidence_score=0.0, critical_nodes_hit=[],
            capability_coverage={
                "status": "partial",
                "analyzers": {"reflection_source": "partial", "resource_reference": "not_applicable"},
            },
        )
        row = formatter._alert_rows_for_result(result)[0]
        self.assertEqual("反射源码：partial", row["coverage_details"])

    def test_summary_api_entry_deduplicates_verification_commands(self):
        entry = formatter.trace_result_to_api_entry(
            tracer.TraceResult(
                coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
                api_signature="()", symbol_kind="method", change_type="REMOVED", severity="P0",
                confirmed=True, source="japicmp", analysis_scope="method",
                analysis_status="not_analyzed", direct_callers=0, is_reachable=None,
                reachable_note="缺少输入", business_reach_depth=0,
                dependency_chain_coords=[], call_paths=[], evidence_paths=[], reason_code="INPUT_MISSING",
                verification_commands=["补充 jar", "补充 jar", "重新运行"], hops=[],
                confidence_score=0.0, critical_nodes_hit=[],
            )
        )
        self.assertEqual(["补充 jar", "重新运行"], entry["verification_commands"])

    def test_not_analyzed_reason_is_human_readable_and_names_missing_dependency(self):
        result = tracer.TraceResult(
            coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
            api_signature="()", symbol_kind="method", change_type="REMOVED", severity="P0",
            confirmed=True, source="japicmp", analysis_scope="method",
            analysis_status="not_analyzed", direct_callers=0, is_reachable=None,
            reachable_note="运行时依赖 jar 缺失", business_reach_depth=0,
            dependency_chain_coords=["com.vendor:consumer-lib:1.2.3"], call_paths=[], evidence_paths=[],
            reason_code="RUNTIME_DEPENDENCY_JARS_UNAVAILABLE", verification_commands=[], hops=[],
            confidence_score=0.0, critical_nodes_hit=[],
        )

        entry = formatter.trace_result_to_api_entry(result)

        self.assertNotEqual("RUNTIME_DEPENDENCY_JARS_UNAVAILABLE", entry["user_reason"])
        self.assertIn("运行时依赖 JAR", entry["user_reason"])
        self.assertIn("com.vendor:consumer-lib:1.2.3", entry["key_evidence"])

    def test_alert_identifies_a_method_with_its_signature(self):
        result = tracer.TraceResult(
            coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
            api_signature="(java.lang.String, boolean)", symbol_kind="method", change_type="REMOVED", severity="P0",
            confirmed=True, source="japicmp", analysis_scope="method",
            analysis_status="not_found_in_static_analysis", direct_callers=0, is_reachable=False,
            reachable_note="未找到", business_reach_depth=0,
            dependency_chain_coords=[], call_paths=[], evidence_paths=[], reason_code="NO_STATIC_PATH",
            verification_commands=[], hops=[], confidence_score=0.0, critical_nodes_hit=[],
        )

        row = formatter._alert_rows_for_result(result)[0]

        self.assertEqual("com.acme.Api.gone(java.lang.String, boolean)", row["changed_symbol"])

    def test_alert_evidence_paths_are_relative_to_the_alert_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / "evidence" / "call_chain"
            report_dir.mkdir(parents=True)
            source_file = Path(tmp) / "project" / "src" / "App.java"
            source_file.parent.mkdir(parents=True)
            source_file.write_text("class App {}", encoding="utf-8")
            result = tracer.TraceResult(
                coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
                api_signature="()", symbol_kind="method", change_type="REMOVED", severity="P0",
                confirmed=True, source="japicmp", analysis_scope="method",
                analysis_status="reachable", direct_callers=1, is_reachable=True,
                reachable_note="已命中", business_reach_depth=1,
                dependency_chain_coords=[], call_paths=["com.acme.App.run() -> com.acme.Api.gone()"],
                evidence_paths=[[{
                    "caller_symbol": "com.acme.App.run()", "callee_key": "com.acme.Api.gone()",
                    "evidence_type": "ast_method_invocation", "owner_coord": "__business__",
                    "file": str(source_file),
                }]], reason_code="SYSTEM_CODE_REACHABLE", verification_commands=[], hops=[],
                confidence_score=1.0, critical_nodes_hit=[],
            )
            output = report_dir / "alerts.csv"
            formatter.generate_alerts_csv([result], output)
            with output.open(encoding="utf-8") as handle:
                row = next(csv.DictReader(handle))

        self.assertFalse(Path(row["evidence_files"]).is_absolute())
        self.assertEqual("../../project/src/App.java", row["evidence_files"])

    def test_summary_declares_all_primary_step5_review_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "evidence" / "call_chain"
            output.mkdir(parents=True)
            result = tracer.TraceResult(
                coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
                api_signature="()", symbol_kind="method", change_type="REMOVED", severity="P0",
                confirmed=True, source="japicmp", analysis_scope="method",
                analysis_status="not_found_in_static_analysis", direct_callers=0, is_reachable=False,
                reachable_note="未找到", business_reach_depth=0,
                dependency_chain_coords=[], call_paths=[], evidence_paths=[], reason_code="NO_STATIC_PATH",
                verification_commands=[], hops=[], confidence_score=0.0, critical_nodes_hit=[],
            )
            formatter.generate_enhanced_summary([result], str(output), graph_stats={})
            timing = Path(tmp) / ".runtime/observability/step5_timing.csv"
            timing.parent.mkdir(parents=True)
            timing.write_text("section,metric,value\n", encoding="utf-8")
            with patch.object(
                formatter, "_SUMMARY_ARTIFACT_STREAM_PATCH_MIN_BYTES", 1
            ), patch.object(
                formatter.json,
                "load",
                side_effect=AssertionError("large summary must not be loaded"),
            ):
                formatter.register_step5_summary_artifacts(str(output))
            summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))

        self.assertEqual("alerts.csv", summary["artifacts"]["alerts_csv"])
        self.assertEqual(
            ".runtime/observability/step5_timing.csv",
            summary["artifacts"]["timing_csv"],
        )
        self.assertEqual("by_api", summary["artifacts"]["api_detail_dir"])

    def test_alert_review_focus_names_the_missing_runtime_input(self):
        focus = formatter._alert_review_focus(
            "not_analyzed", "incomplete", "RUNTIME_DEPENDENCY_JARS_UNAVAILABLE"
        )
        self.assertIn("运行时依赖 JAR", focus)
        self.assertIn("Step5", focus)

    def test_alert_chain_keeps_maven_coordinate_out_of_java_symbol(self):
        result = tracer.TraceResult(
            coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
            api_signature="()", symbol_kind="method", change_type="REMOVED", severity="P0",
            confirmed=True, source="japicmp", analysis_scope="method",
            analysis_status="reachable", direct_callers=1, is_reachable=True,
            reachable_note="已命中", business_reach_depth=2,
            dependency_chain_coords=[],
            call_paths=["com.vendor:consumer:1.0:com.vendor.Bridge.call() -> com.acme.Api.gone()"],
            evidence_paths=[], reason_code="SYSTEM_CODE_REACHABLE", verification_commands=[], hops=[],
            confidence_score=1.0, critical_nodes_hit=[],
        )

        row = formatter._alert_rows_for_result(result)[0]

        self.assertEqual("com.vendor.Bridge.call()", row["chain_entry"])
        self.assertNotIn("com.vendor:consumer:1.0:com.vendor.Bridge", row["chain_detail"])

    def test_alert_target_coordinate_retains_compared_versions(self):
        result = tracer.TraceResult(
            coord="com.acme:library", api_name="com.acme.Api.gone", api_simple="gone",
            api_signature="()", symbol_kind="method", change_type="REMOVED", severity="P0",
            confirmed=True, source="japicmp", analysis_scope="method",
            analysis_status="not_found_in_static_analysis", direct_callers=0, is_reachable=False,
            reachable_note="未找到", business_reach_depth=0,
            dependency_chain_coords=[], call_paths=[], evidence_paths=[], reason_code="NO_STATIC_PATH",
            verification_commands=[], hops=[], confidence_score=0.0, critical_nodes_hit=[],
            old_version="1.0.0", new_version="2.0.0",
        )

        row = formatter._alert_rows_for_result(result)[0]

        self.assertEqual("com.acme:library（1.0.0 → 2.0.0）", row["target_coord"])

    def test_trace_keeps_malformed_api_rows_visible_as_not_analyzed(self):
        rows = [{
            "coord": "a:b", "api_name": "", "api_simple": "", "api_signature": "",
            "symbol_kind": "method", "change_type": "REMOVED", "severity": "P0",
        }]

        with patch.object(
            tracer, "decide_envelope", wraps=tracer.decide_envelope,
        ) as decide, patch.object(
            tracer, "render_trace_result", wraps=tracer.render_trace_result,
        ) as render, patch.object(tracer, "collect_graph_analyzer_edges"), \
             patch.object(tracer, "write_analyzer_edge_ledger"), \
             patch.object(tracer, "_emit_step5_perf_summary"):
            results = tracer.trace_all_apis_with_confidence_weighting(rows, None, {})

        decide.assert_called_once()
        render.assert_called_once()
        self.assertEqual(1, len(results))
        self.assertEqual("not_analyzed", results[0].analysis_status)
        self.assertEqual("MISSING_API_NAME", results[0].reason_code)

    def test_alert_signature_uses_one_consistent_parameter_separator(self):
        result = tracer.TraceResult(
            coord="a:b", api_name="com.acme.Api.call", api_simple="call",
            api_signature="(java.lang.String,java.lang.String...)", symbol_kind="method",
            change_type="REMOVED", severity="P0", confirmed=True, source="japicmp", analysis_scope="method",
            analysis_status="not_found_in_static_analysis", direct_callers=0, is_reachable=False,
            reachable_note="未找到", business_reach_depth=0, dependency_chain_coords=[],
            call_paths=[], evidence_paths=[], reason_code="NO_STATIC_PATH", verification_commands=[], hops=[],
            confidence_score=0.0, critical_nodes_hit=[],
        )

        row = formatter._alert_rows_for_result(result)[0]

        self.assertEqual("(java.lang.String, java.lang.String...)", row["api_signature"])
        self.assertEqual("com.acme.Api.call(java.lang.String, java.lang.String...)", row["changed_symbol"])

    def test_alert_action_type_is_a_reviewer_action_not_an_internal_state(self):
        self.assertEqual("修复并验证", formatter._path_conclusion("reachable")[1])
        self.assertEqual("人工复核", formatter._path_conclusion("uncertain")[1])
        self.assertEqual("补齐输入后重跑", formatter._path_conclusion("not_analyzed")[1])

    def test_unknown_reason_code_does_not_leak_into_user_reason(self):
        outcome = formatter.summarize_user_facing_outcome(SimpleNamespace(
            analysis_status="not_analyzed", reason_code="UNRECOGNIZED_INTERNAL_STOP",
            severity="P1", call_paths=[], evidence_paths=[], dependency_chain_coords=[],
        ))

        self.assertNotIn("UNRECOGNIZED_INTERNAL_STOP", outcome["user_reason"])
        self.assertIn("静态分析", outcome["user_reason"])

    def test_summary_preserves_graph_truncation_and_parser_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = tracer.TraceResult(
                coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
                api_signature="()", symbol_kind="method", change_type="REMOVED", severity="P0",
                confirmed=True, source="japicmp", analysis_scope="method",
                analysis_status="not_analyzed", direct_callers=0, is_reachable=None,
                reachable_note="图不完整", business_reach_depth=0, dependency_chain_coords=[],
                call_paths=[], evidence_paths=[], reason_code="ANALYSIS_INCOMPLETE",
                verification_commands=[], hops=[], confidence_score=0.0, critical_nodes_hit=[],
            )
            graph_stats = {
                "truncated": True,
                "truncation_reasons": ["max_methods"],
                "parser_usage": {"tree_sitter": 7, "regex": 2},
                "parser_fallback_reasons": {"unsupported_language_kotlin": 2},
            }
            path = formatter.write_summary_json([result], tmp, graph_stats=graph_stats)
            summary = json.loads(Path(path).read_text(encoding="utf-8"))

        self.assertEqual(["max_methods"], summary["meta"]["graph_stats"]["truncation_reasons"])
        self.assertEqual(2, summary["meta"]["graph_stats"]["parser_usage"]["regex"])

    def test_alerts_csv_is_a_focused_human_review_table(self):
        self.assertLessEqual(len(formatter.ALERTS_CSV_FIELDNAMES), 31)
        self.assertIn("chain_detail", formatter.ALERTS_CSV_FIELDNAMES)
        self.assertIn("path_text", formatter.ALERTS_CSV_FIELDNAMES)
        self.assertIn("api_signature", formatter.ALERTS_CSV_FIELDNAMES)
        self.assertIn("symbol_kind", formatter.ALERTS_CSV_FIELDNAMES)
        self.assertIn("compile_impact", formatter.ALERTS_CSV_FIELDNAMES)
        self.assertIn("runtime_link_impact", formatter.ALERTS_CSV_FIELDNAMES)
        self.assertNotIn("conclusion_level", formatter.ALERTS_CSV_FIELDNAMES)
        self.assertNotIn("action_type", formatter.ALERTS_CSV_FIELDNAMES)
        self.assertNotIn("coverage_details", formatter.ALERTS_CSV_FIELDNAMES)

    def test_business_entry_label_includes_declared_method_signature(self):
        method = SimpleNamespace(
            qualified_key="com.acme.DemoApplication.home",
            declared_signature="(java.lang.String)",
            param_declared_types={},
        )

        self.assertEqual(
            "com.acme.DemoApplication.home(java.lang.String)",
            tracer.critical_node_method_label(method),
        )

    def test_critical_node_entry_kind_recognizes_spring_web_annotation(self):
        method = SimpleNamespace(
            annotations=["GetMapping(path = \"/home\")"],
            class_annotations=["RestController"],
            owner_type="business",
        )

        self.assertEqual("spring_web_endpoint", tracer.critical_node_entry_kind(method))

    def test_structured_api_detail_keeps_evidence_file_and_type_per_hop(self):
        result = tracer.TraceResult(
            coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
            api_signature="()", symbol_kind="method", change_type="REMOVED", severity="P0",
            confirmed=True, source="japicmp", analysis_scope="method",
            analysis_status="reachable", direct_callers=1, is_reachable=True,
            reachable_note="已命中", business_reach_depth=2, dependency_chain_coords=[],
            call_paths=["A.run() -> B.call() -> com.acme.Api.gone()"],
            evidence_paths=[[
                {"caller_symbol": "A.run()", "callee_key": "B.call()", "evidence_type": "ast_method_invocation", "file": "A.java"},
                {"caller_symbol": "B.call()", "callee_key": "com.acme.Api.gone()", "evidence_type": "bytecode_method_invocation", "file": "b.jar!/B.class"},
            ]], reason_code="SYSTEM_CODE_REACHABLE", verification_commands=[], hops=[],
            confidence_score=1.0, critical_nodes_hit=[],
        )

        entry = formatter.trace_result_to_api_entry(result)

        self.assertEqual("A.java", entry["evidence_paths"][0][0]["file"])
        self.assertEqual("ast_method_invocation", entry["evidence_paths"][0][0]["evidence_type"])
        self.assertEqual("b.jar!/B.class", entry["evidence_paths"][0][1]["file"])
        self.assertEqual("bytecode_method_invocation", entry["evidence_paths"][0][1]["evidence_type"])

    def test_api_id_is_stable_across_runtime_paths_and_result_order(self):
        def make_result(path):
            return tracer.TraceResult(
                coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
                api_signature="(java.lang.String)", symbol_kind="method", change_type="REMOVED", severity="P0",
                confirmed=True, source="japicmp", analysis_scope="method",
                analysis_status="reachable", direct_callers=1, is_reachable=True,
                reachable_note="已命中", business_reach_depth=1, dependency_chain_coords=[],
                call_paths=["App.run() -> com.acme.Api.gone(java.lang.String)"],
                evidence_paths=[[{"caller_symbol": "App.run()", "callee_key": "com.acme.Api.gone(java.lang.String)", "evidence_type": "ast_method_invocation", "file": path}]],
                reason_code="SYSTEM_CODE_REACHABLE", verification_commands=[], hops=[],
                confidence_score=1.0, critical_nodes_hit=[],
            )

        first = formatter._alert_rows_for_result(make_result("/one/App.java"))[0]
        second = formatter._alert_rows_for_result(make_result("/other/App.java"))[0]

        self.assertEqual(first["api_id"], second["api_id"])

    def test_alert_distinguishes_framework_entry_and_indirect_reachability(self):
        result = tracer.TraceResult(
            coord="a:b", api_name="com.acme.Api.gone", api_simple="gone",
            api_signature="()", symbol_kind="method", change_type="REMOVED", severity="P0",
            confirmed=True, source="japicmp", analysis_scope="method",
            analysis_status="reachable", direct_callers=0, is_reachable=True,
            reachable_note="已命中", business_reach_depth=2, dependency_chain_coords=[],
            call_paths=[], evidence_paths=[], reason_code="SYSTEM_CODE_REACHED",
            verification_commands=[], hops=[], confidence_score=1.0, critical_nodes_hit=[],
            path_details=[{
                "path_status": "reachable", "stop_reason": "SYSTEM_CODE_REACHED",
                "business_reachable": True, "business_entry": "com.acme.Demo.home()",
                "entry_kind": "spring_web_endpoint",
                "path_text": "com.acme.Demo.home() -> com.acme.Library.message() -> com.acme.Api.gone()",
                "confidence": 1.0, "depth": 2, "evidence": [],
            }],
        )

        row = formatter._alert_rows_for_result(result)[0]

        self.assertEqual("Spring Web 业务入口", row["entry_kind"])
        self.assertEqual("间接调用", row["reach_kind"])

    def test_generate_enhanced_summary_writes_per_dependency_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            output_dir = self._call_chain_dir(report_dir)
            results = [
                tracer.TraceResult(
                    coord="a:b",
                    api_name="com.example.OrderService.run",
                    api_simple="run",
                    api_signature="(String)",
                    symbol_kind="method",
                    change_type="REMOVED",
                    severity="P0",
                    confirmed=True,
                    source="old_jar",
                    analysis_scope="method",
                    analysis_status="reachable",
                    direct_callers=1,
                    is_reachable=True,
                    reachable_note="已证明触达业务代码",
                    business_reach_depth=2,
                    dependency_chain_coords=["c:d"],
                    reason_code="SYSTEM_CODE_REACHED",
                    call_paths=["Business.run -> Dependency.call"],
                    evidence_paths=[],
                    verification_commands=[],
                    hops=[],
                    confidence_score=0.96,
                    critical_nodes_hit=[],
                    match_provenance="exact_signature",
                    match_tier=0,
                ),
                tracer.TraceResult(
                    coord="a:b",
                    api_name="com.example.OrderService.blocked",
                    api_simple="blocked",
                    api_signature="()",
                    symbol_kind="method",
                    change_type="REMOVED",
                    severity="P1",
                    confirmed=True,
                    source="old_jar",
                    analysis_scope="method",
                    analysis_status="not_analyzed",
                    direct_callers=0,
                    is_reachable=False,
                    reachable_note="",
                    business_reach_depth=0,
                    dependency_chain_coords=[],
                    reason_code="DEPENDENCY_SOURCE_MAPPING_MISSING",
                    call_paths=[],
                    evidence_paths=[],
                    verification_commands=[],
                    hops=[],
                    confidence_score=0.2,
                    critical_nodes_hit=[],
                    match_provenance="fallback_simple",
                    match_tier=2,
                ),
            ]

            formatter.generate_enhanced_summary(results, output_dir)
            per_dependency_summary = (
                self._api_changes_dir(report_dir)
                / PER_DEPENDENCY_DIRNAME
                / make_per_dependency_dirname("a:b")
                / "summary.json"
            )
            self.assertTrue(per_dependency_summary.exists())
            summary = json.loads(per_dependency_summary.read_text(encoding="utf-8"))

        self.assertEqual(summary["coord"], "a:b")
        self.assertTrue(summary["step5"]["reaches_system_source"])
        self.assertEqual(summary["step5"]["reachable"], 1)
        self.assertEqual(summary["step5"]["selected_api"], "com.example.OrderService.run")
        self.assertEqual(summary["step5"]["evidence_level"], "strong")

    def test_trace_result_to_api_entry_includes_match_provenance_metadata(self):
        entry = formatter.trace_result_to_api_entry(
            tracer.TraceResult(
                coord="a:b",
                api_name="com.example.OrderService.run",
                api_simple="run",
                api_signature="(String)",
                symbol_kind="method",
                change_type="method_changed",
                severity="P1",
                confirmed=True,
                source="gitdiff",
                analysis_scope="method",
                analysis_status="reachable",
                direct_callers=1,
                is_reachable=True,
                reachable_note="已找到调用链",
                business_reach_depth=1,
                dependency_chain_coords=[],
                reason_code="SYSTEM_CODE_REACHABLE",
                call_paths=["OrderService.run -> DemoApi.call"],
                evidence_paths=[],
                verification_commands=[],
                hops=[],
                confidence_score=0.95,
                critical_nodes_hit=[],
                match_provenance="polymorphic",
                match_tier=2,
            )
        )

        self.assertEqual(entry["match_provenance"], "polymorphic")
        self.assertEqual(entry["match_tier"], 2)
        self.assertEqual(entry["origin_step"], "step5")
        self.assertEqual(
            entry["diagnostic_schema"],
            "java-upgrade-analyzer.diagnostic.v1",
        )

    def test_is_system_code_touched_recognizes_formatter_callback_entry(self):
        method_def = SimpleNamespace(
            owner_type="business",
            class_name="PetTypeFormatter",
            class_fqcn="org.example.PetTypeFormatter",
            method_name="parse",
            annotations=[],
            class_annotations=["Component"],
            modifiers=["public"],
            is_interface=False,
        )
        type_metadata = {
            "org.example.PetTypeFormatter": {
                "kind": "class",
                "implements": ["org.springframework.format.Formatter"],
                "extends": [],
                "implementations": [],
                "annotations": ["Component"],
            }
        }

        self.assertTrue(tracer.is_system_code_touched(method_def, type_metadata))

    def test_is_system_code_touched_allows_configuration_hook_as_reachable(self):
        method_def = SimpleNamespace(
            owner_type="business",
            class_name="WebConfiguration",
            class_fqcn="org.example.WebConfiguration",
            method_name="addInterceptors",
            annotations=[],
            class_annotations=["Configuration"],
            modifiers=["public"],
            is_interface=False,
        )
        type_metadata = {
            "org.example.WebConfiguration": {
                "kind": "class",
                "implements": ["org.springframework.web.servlet.config.annotation.WebMvcConfigurer"],
                "extends": [],
                "implementations": [],
                "annotations": ["Configuration"],
            }
        }

        self.assertTrue(tracer.is_system_code_touched(method_def, type_metadata))

    def test_dependency_scheduled_entry_is_uncertain_without_activation_proof(self):
        scheduled_method = SimpleNamespace(
            symbol_id="dep_job",
            qualified_key="com.dep.CleanupJob.cleanup",
            simple_key="method:cleanup",
            class_fqcn="com.dep.CleanupJob",
            class_name="CleanupJob",
            method_name="cleanup",
            file="/repo/dep/src/main/java/com/dep/CleanupJob.java",
            line=7,
            owner_type="dependency",
            owner_coord="com.example:dep-job",
            module="dep-job",
            is_test=False,
            annotations=["Scheduled"],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
        )
        edge_to_removed_api = SimpleNamespace(
            caller_symbol_id="dep_job",
            caller_qualified_key="com.dep.CleanupJob.cleanup",
            callee_key="com.vendor.LegacyApi.removed()",
            callee_simple_key="method:removed()",
            evidence_type="ast_method_invocation",
            confidence="high",
            file=scheduled_method.file,
            line=8,
            owner_type="dependency",
            owner_coord="com.example:dep-job",
            module="dep-job",
            is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"dep_job": scheduled_method},
            reverse_edges={"com.vendor.LegacyApi.removed()": [edge_to_removed_api]},
            framework_entry_symbols={
                "dep_job": [
                    {
                        "adapter": "spring_basic",
                        "edge_kind": "spring_runtime_active_entry",
                        "provenance": {"annotation": "@Scheduled"},
                    }
                ]
            },
            runtime_dependency_catalog={},
        )

        result = tracer.trace_api_with_confidence_weighting(
            {
                "coord": "com.vendor:legacy",
                "api_name": "com.vendor.LegacyApi.removed",
                "api_simple": "removed",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "severity": "P1",
                "confirmed": "true",
                "source": "old_jar",
                "analysis_scope": "method",
            },
            graph,
            {},
            max_total_cost=5,
        )

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "FRAMEWORK_ACTIVATION_UNPROVEN")
        self.assertEqual(result.dependency_chain_coords, ["com.example:dep-job"])
        self.assertEqual(
            result.call_paths,
            ["com.dep.CleanupJob.cleanup → 变更API: com.vendor.LegacyApi.removed()"],
        )

    def test_packaged_spring_listener_requires_verified_runtime_registration(self):
        listener = SimpleNamespace(
            symbol_id="runtime:com.vendor:boot:com.vendor.RuntimeListener.onApplicationEvent(java.lang.Object)",
            qualified_key="com.vendor.RuntimeListener.onApplicationEvent(java.lang.Object)",
            simple_key="onApplicationEvent(java.lang.Object)",
            class_fqcn="com.vendor.RuntimeListener",
            class_name="RuntimeListener",
            method_name="onApplicationEvent",
            file="/runtime/boot.jar",
            line=0,
            owner_type="dependency",
            owner_coord="com.vendor:boot",
            module="",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=[],
            is_interface=False,
        )
        edge = SimpleNamespace(
            caller_symbol_id=listener.symbol_id,
            caller_qualified_key=listener.qualified_key,
            callee_key="com.vendor.LegacyApi.removed()",
            callee_simple_key="method:removed()",
            evidence_type="runtime_dependency_bytecode_invocation",
            confidence="high",
            file=listener.file,
            line=0,
            owner_type="dependency",
            owner_coord="com.vendor:boot",
            module="",
            is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={listener.symbol_id: listener},
            reverse_edges={"com.vendor.LegacyApi.removed()": [edge]},
            framework_entry_symbols={},
            framework_runtime_entry_methods={
                "com.vendor.RuntimeListener.onApplicationEvent": [{
                    "adapter": "spring_runtime_artifact",
                    "edge_kind": "spring_runtime_registered_callback",
                    "runtime_activation": "active",
                }],
            },
            runtime_dependency_catalog={},
        )

        result = tracer.trace_api_with_confidence_weighting(
            {
                "coord": "com.vendor:legacy",
                "api_name": "com.vendor.LegacyApi.removed",
                "api_simple": "removed",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "severity": "P1",
                "confirmed": "true",
                "source": "old_jar",
                "analysis_scope": "method",
            },
            graph,
            {},
            max_total_cost=5,
        )

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "FRAMEWORK_ACTIVATION_UNPROVEN")
        self.assertEqual(result.dependency_chain_coords, ["com.vendor:boot"])

    def test_source_claimed_active_spring_registration_without_artifact_proof_is_uncertain(self):
        def method_def(symbol_id, qualified_key, owner_type, owner_coord, method_name, params):
            class_fqcn = qualified_key.rsplit('.', 1)[0]
            signature = '(' + ', '.join(params) + ')'
            return source_analyzer.MethodDef(
                symbol_id=symbol_id,
                qualified_key=qualified_key,
                simple_key=f"method:{method_name}",
                class_fqcn=class_fqcn,
                class_name=class_fqcn.rsplit('.', 1)[-1],
                method_name=method_name,
                return_type="void",
                file=f"/{symbol_id}.java",
                line=1,
                end_line=2,
                package_name=class_fqcn.rsplit('.', 1)[0],
                owner_type=owner_type,
                owner_coord=owner_coord,
                module="app" if owner_type == "business" else "runtime",
                source_root="/src",
                language="java",
                is_test=False,
                param_types={f"p{idx}": value for idx, value in enumerate(params)},
                param_declared_types={f"p{idx}": value for idx, value in enumerate(params)},
                declared_signature=signature,
                declared_qualified_key=qualified_key + signature,
            )

        app = method_def(
            "app", "com.acme.Application.main", "business", "BUSINESS", "main", ["String[]"]
        )
        listener = method_def(
            "listener", "com.vendor.RuntimeListener.onApplicationEvent",
            "dependency", "com.vendor:runtime", "onApplicationEvent", ["Object"],
        )
        target_edge = source_analyzer.CallEdge(
            caller_symbol_id="listener",
            caller_qualified_key=listener.qualified_key,
            callee_key="com.vendor.LegacyApi.removed()",
            callee_simple_key="method:removed()",
            evidence_type="bytecode_method_invocation",
            confidence="high",
            file="/runtime.jar",
            line=1,
            content="",
            owner_type="dependency",
            owner_coord="com.vendor:runtime",
            module="runtime",
            is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"app": app, "listener": listener},
            reverse_edges={"com.vendor.LegacyApi.removed()": [target_edge]},
            runtime_dependency_catalog={},
        )
        framework_batch = framework_adapters._framework_batch(
            "spring_runtime_artifact",
            "1",
            "complete",
            (),
            ({
                "source": "framework:spring-factories:org.springframework.context.ApplicationListener",
                "target": "com.vendor.RuntimeListener.onApplicationEvent",
                "edge_kind": "spring_runtime_registered_callback",
                "confidence": "high",
                "runtime_activation": "active",
                "conditions": [],
                "ambiguity": False,
                "provenance": {
                    "jar": "/runtime.jar",
                    "line": 1,
                    "business_activation": [{
                        "business_entry": "com.acme.Application.main",
                        "file": "/app/Application.java",
                        "spring_application_run": True,
                    }],
                },
            },),
            (),
            (),
            {},
        )
        ingest_collector_batches(graph, (framework_batch,))

        result = tracer.trace_api_with_confidence_weighting(
            {
                "coord": "com.vendor:legacy",
                "api_name": "com.vendor.LegacyApi.removed",
                "api_simple": "removed",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "severity": "P0",
                "confirmed": "true",
                "source": "old_jar",
                "analysis_scope": "method",
            },
            graph,
            {},
            max_total_cost=5,
        )

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "FRAMEWORK_ACTIVATION_UNPROVEN")

    def test_conditional_dependency_framework_callback_is_not_confirmed_reachable(self):
        callback = SimpleNamespace(
            symbol_id="callback",
            qualified_key="com.vendor.OptionalAutoConfiguration.onApplicationEvent",
            simple_key="method:onApplicationEvent",
            class_fqcn="com.vendor.OptionalAutoConfiguration",
            class_name="OptionalAutoConfiguration",
            method_name="onApplicationEvent",
            file="/OptionalAutoConfiguration.java",
            line=1,
            owner_type="dependency",
            owner_coord="com.vendor:runtime",
            module="runtime",
            is_test=False,
            annotations=[],
            class_annotations=["Configuration"],
            modifiers=["public"],
            is_interface=False,
        )
        edge = SimpleNamespace(
            caller_symbol_id="callback",
            caller_qualified_key=callback.qualified_key,
            callee_key="com.vendor.LegacyApi.removed()",
            callee_simple_key="method:removed()",
            evidence_type="ast_method_invocation",
            confidence="high",
            file=callback.file,
            line=2,
            owner_type="dependency",
            owner_coord="com.vendor:runtime",
            module="runtime",
            is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"callback": callback},
            reverse_edges={"com.vendor.LegacyApi.removed()": [edge]},
            framework_entry_symbols={"callback": [{
                "adapter": "spring_basic",
                "edge_kind": "spring_framework_callback",
                "runtime_activation": "conditional",
                "conditions": ["ConditionalOnClass"],
                "ambiguity": False,
            }]},
            framework_runtime_entry_methods={},
            runtime_dependency_catalog={},
        )

        result = tracer.trace_api_with_confidence_weighting(
            {
                "coord": "com.vendor:legacy",
                "api_name": "com.vendor.LegacyApi.removed",
                "api_simple": "removed",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "severity": "P0",
                "confirmed": "true",
                "source": "old_jar",
                "analysis_scope": "method",
            },
            graph,
            {},
            max_total_cost=5,
        )

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "FRAMEWORK_BOUNDARY")
        self.assertNotEqual(result.analysis_status, "reachable")

    def test_packaged_hit_requires_verified_spring_callback_activation(self):
        graph = SimpleNamespace(
            methods_by_id={},
            reverse_edges={},
            framework_runtime_entry_methods={
                "com.vendor.RuntimeListener.onApplicationEvent": [{
                    "adapter": "spring_runtime_artifact",
                    "source": "framework:spring-factories:org.springframework.context.ApplicationListener",
                    "edge_kind": "spring_runtime_registered_callback",
                    "runtime_activation": "active",
                    "confidence": "high",
                    "provenance": {
                        "coord": "com.vendor:boot",
                        "jar": "/runtime/boot.jar",
                        "resource": "META-INF/spring.factories",
                        "line": 1,
                        "business_activation": [{
                            "business_entry": "com.acme.Application.main",
                            "file": "/app/Application.java",
                            "spring_application_run": True,
                        }],
                    },
                }],
            },
        )
        result = tracer.TraceResult(
            api_name="com.vendor.LegacyApi.removed",
            api_simple="removed",
            api_signature="()",
            symbol_kind="method",
            change_type="REMOVED",
            coord="com.vendor:legacy",
            severity="P1",
            confirmed=True,
            source="old_jar",
            analysis_scope="method",
            analysis_status="not_analyzed",
            direct_callers=0,
            is_reachable=False,
            reachable_note="",
            business_reach_depth=0,
            dependency_chain_coords=[],
            call_paths=[],
            evidence_paths=[],
            reason_code="",
            verification_commands=[],
            hops=[],
            confidence_score=1.0,
            critical_nodes_hit=[],
        )
        hit = {
            "coord": "com.vendor:boot",
            "jar_path": "/runtime/boot.jar",
            "class_fqcn": "com.vendor.RuntimeListener",
            "consumer_method": "onApplicationEvent",
            "consumer_signature": "(java.lang.Object)",
            "target_display": "com.vendor.LegacyApi.removed()",
            "evidence_type": "bytecode_method_invocation",
        }

        draft = self._draft_from_result(result)
        tracer._build_packaged_dependency_hit_result(draft, [hit], graph)
        built = tracer._finalize_trace_draft(draft)

        self.assertEqual(built.analysis_status, "uncertain")
        self.assertEqual(built.reason_code, "FRAMEWORK_ACTIVATION_UNPROVEN")
        self.assertIn("com.acme.Application.main -> Spring Boot框架注册", built.call_paths[-1])
        self.assertEqual(
            built.path_details[-1]["stop_reason"],
            "RUNTIME_FRAMEWORK_ENTRY_REACHED",
        )

        generic = tracer.replace(
            built,
            reason_code="SYSTEM_CODE_REACHED",
            call_paths=[
                "com.vendor.RuntimeListener.onApplicationEvent(java.lang.Object) "
                "→ 变更API: com.vendor.LegacyApi.removed()"
            ],
            evidence_paths=[[]],
            path_details=[{
                "path_status": "reachable",
                "stop_reason": "SYSTEM_CODE_REACHED",
                "business_reachable": True,
                "business_entry": "com.vendor.RuntimeListener.onApplicationEvent",
                "path_text": (
                    "com.vendor.RuntimeListener.onApplicationEvent(java.lang.Object) "
                    "→ 变更API: com.vendor.LegacyApi.removed()"
                ),
                "evidence": [],
            }],
        )
        merged_draft = self._draft_from_result(generic)
        tracer._apply_evidence_decision(
            merged_draft,
            paths=(tracer.ReachabilityPath(
                path_text=generic.call_paths[0],
                entry_scope=tracer.ModuleScope.BUSINESS_CLASSES,
                complete=True,
                reason_code="SYSTEM_CODE_REACHED",
                depth=1,
            ),),
        )
        tracer._merge_runtime_framework_paths(merged_draft, [hit], graph)
        merged = tracer._finalize_trace_draft(merged_draft)
        self.assertEqual(merged.reason_code, "SYSTEM_CODE_REACHED")
        self.assertFalse(any(
            "com.acme.Application.main -> Spring Boot框架注册" in item["path_text"]
            for item in merged.path_details
        ))

    def test_javap_parser_keeps_intra_class_method_and_field_owners(self):
        javap = """
  public void onApplicationEvent(java.lang.Object);
    descriptor: (Ljava/lang/Object;)V
    Code:
         0: aload_0
         1: invokevirtual #31                 // Method buildBannerText:()Ljava/lang/String;
         4: getstatic     #9                  // Field processed:Ljava/util/concurrent/atomic/AtomicBoolean;
         7: return

  java.lang.String buildBannerText();
    descriptor: ()Ljava/lang/String;
    Code:
         0: invokestatic  #61                 // Method com/vendor/LegacyApi.removed:()V
         3: aconst_null
         4: areturn
"""

        parsed = tracer._parse_javap_bytecode_references(
            javap,
            "com.vendor.RuntimeListener",
        )

        local_method = next(
            item for item in parsed["method_refs"]
            if item["name"] == "buildBannerText"
        )
        local_field = next(
            item for item in parsed["field_refs"]
            if item["name"] == "processed"
        )
        self.assertEqual(local_method["owner"], "com.vendor.RuntimeListener")
        self.assertEqual(local_method["consumer_method"], "onApplicationEvent")
        self.assertEqual(local_method["consumer_signature"], "(Object)")
        self.assertEqual(local_field["owner"], "com.vendor.RuntimeListener")

    def test_javap_parser_recognizes_package_private_nested_constructor(self):
        javap = """
org.example.Outer$Inner(org.example.Outer, java.lang.String);
  descriptor: (Lorg/example/Outer;Ljava/lang/String;)V
  Code:
       0: aload_0
       1: invokespecial #7 // Method java/lang/Object."<init>":()V
       4: invokestatic #8 // Method com/vendor/Target.call:()V
       7: return
"""

        parsed = tracer._parse_javap_bytecode_references(
            javap, "org.example.Outer$Inner"
        )
        target = next(
            item for item in parsed["method_refs"]
            if item["owner"] == "com.vendor.Target"
        )
        self.assertEqual(target["consumer_method"], "<init>")
        self.assertEqual(
            target["consumer_descriptor"],
            "(Lorg/example/Outer;Ljava/lang/String;)V",
        )

    def test_packaged_hit_reaches_registered_callback_through_intra_class_method(self):
        callback = tracer._runtime_method_def_for_packaged_caller(
            "com.vendor:boot",
            "/runtime/boot.jar",
            "com.vendor.RuntimeListener",
            "onApplicationEvent",
            "(java.lang.Object)",
        )
        bridge = tracer.CallEdge(
            caller_symbol_id=callback.symbol_id,
            caller_qualified_key=callback.qualified_key,
            callee_key="com.vendor.RuntimeListener.buildBannerText()",
            callee_simple_key="method:buildBannerText()",
            evidence_type="runtime_dependency_bytecode_invocation",
            confidence="high",
            file="/runtime/boot.jar",
            line=0,
            content="runtime dependency bytecode caller",
            owner_type="dependency",
            owner_coord="com.vendor:boot",
            module="",
            is_test=False,
            callee_param_types=[],
        )
        graph = SimpleNamespace(
            methods_by_id={callback.symbol_id: callback},
            reverse_edges={"com.vendor.RuntimeListener.buildBannerText()": [bridge]},
            framework_runtime_entry_methods={
                "com.vendor.RuntimeListener.onApplicationEvent": [{
                    "adapter": "spring_runtime_artifact",
                    "runtime_activation": "active",
                    "provenance": {
                        "business_activation": [{
                            "business_entry": "com.acme.Application.main",
                        }],
                    },
                }],
            },
        )
        hit = {
            "coord": "com.vendor:boot",
            "jar_path": "/runtime/boot.jar",
            "class_fqcn": "com.vendor.RuntimeListener",
            "consumer_method": "buildBannerText",
            "consumer_signature": "()",
        }

        paths = tracer._find_business_callers_for_packaged_hit(hit, graph)

        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0][0].qualified_key, callback.qualified_key)
        self.assertEqual(len(paths[0][1]), 1)
        self.assertTrue(paths[0][2])

    def test_removed_api_is_not_impacted_when_current_jar_keeps_identical_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / ".upgrade-report"
            dep_dir = report / "evidence" / "dependencies"
            old_dir = report / "evidence" / "api_changes" / "step4_artifact_jars" / "base"
            dep_dir.mkdir(parents=True)
            old_dir.mkdir(parents=True)
            dep_changes = dep_dir / "dep_changes.csv"
            dep_changes.write_text(
                "coord,old_version,new_version,change_type,scope,base_coord,current_coord,base_lib_entry,current_lib_entry\n"
                "com.vendor:legacy,1.0,-,移除,runtime,com.vendor:legacy,,BOOT-INF/lib/legacy-1.0.jar,\n",
                encoding="utf-8",
            )
            class_entry = "com/vendor/LegacyApi.class"
            class_bytes = b"identical-classfile-bytes"
            old_jar = old_dir / "BOOT-INF__lib__legacy-1.0.jar"
            current_jar = Path(tmp) / "aggregate.jar"
            for jar in (old_jar, current_jar):
                with zipfile.ZipFile(jar, "w") as zf:
                    zf.writestr(class_entry, class_bytes)
            api = {
                "coord": "com.vendor:legacy",
                "old_version": "1.0",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "com.vendor.LegacyApi.removed",
                "api_simple": "removed",
                "api_signature": "()",
                "symbol_kind": "method",
                "confirmed": "true",
                "severity": "P0",
                "source": "old_jar",
                "analysis_scope": "method",
            }
            graph = SimpleNamespace(
                report_dir=str(report),
                runtime_dependency_catalog={
                    "entries": [{
                        "coord": "com.vendor:aggregate",
                        "jar_path": str(current_jar),
                    }],
                },
            )

            providers = tracer._build_identical_current_class_provider_index([api], graph)
            result = tracer.trace_api_with_confidence_weighting(
                api,
                graph,
                {},
                has_packaged_bytecode_fallback=True,
            )
            call_chain_dir = report / "evidence" / "call_chain"
            summary_path, summary_json_path = formatter.generate_enhanced_summary([result], call_chain_dir)
            summary_payload = json.loads(Path(summary_json_path).read_text(encoding="utf-8"))
            with (call_chain_dir / "alerts.csv").open(encoding="utf-8") as alert_file:
                alert_rows = list(csv.DictReader(alert_file))
            findings = s6_report.collect_findings(str(report))
            final_report = s6_report.generate_report(findings)

        self.assertIsNone(summary_path)
        self.assertIn(("com.vendor:legacy", "com.vendor.LegacyApi"), providers)
        self.assertEqual(result.analysis_status, "not_impacted")
        self.assertEqual(result.reason_code, "RUNTIME_SYMBOL_PRESERVED_IDENTICALLY")
        self.assertIn("com.vendor:aggregate", result.call_paths[0])
        self.assertEqual(
            result.evidence_paths[0][0]["evidence_type"],
            "identical_current_class_provider",
        )
        self.assertEqual(summary_payload["not_impacted"], 1)
        self.assertEqual(alert_rows[0]["path_status"], "not_impacted")
        self.assertIn("已确认不受影响", final_report)
        self.assertIn("### 4.1 符号保留证据", final_report)
        self.assertIn("com.vendor:aggregate", final_report)
        self.assertIn("不包含被删除 JAR 中的 SPI 配置、资源文件、清单等非 API 内容", final_report)

    def test_removed_api_preservation_reads_step1_dependency_jar_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / ".upgrade-report"
            dep_dir = report / "evidence" / "dependencies"
            retained_dir = dep_dir / "s1_dependency_jars" / "base"
            retained_dir.mkdir(parents=True)
            entry = "BOOT-INF/lib/legacy-1.0.jar"
            (dep_dir / "dep_changes.csv").write_text(
                "coord,old_version,new_version,change_type,scope,base_coord,current_coord,base_lib_entry,current_lib_entry\n"
                f"com.vendor:legacy,1.0,-,移除,runtime,com.vendor:legacy,,{entry},\n",
                encoding="utf-8",
            )
            class_entry = "com/vendor/LegacyApi.class"
            class_bytes = b"identical-classfile-bytes"
            retained_jar = retained_dir / "legacy-1.0.jar"
            current_jar = Path(tmp) / "aggregate.jar"
            for jar in (retained_jar, current_jar):
                with zipfile.ZipFile(jar, "w") as zf:
                    zf.writestr(class_entry, class_bytes)
            retained_sha = hashlib.sha256(retained_jar.read_bytes()).hexdigest()
            (dep_dir / "dependency_jars.json").write_text(
                json.dumps(
                    {
                        "items": [{
                            "side": "base",
                            "coord": "com.vendor:legacy",
                            "lib_entry": entry,
                            "retained_path": str(retained_jar),
                            "nested_jar_sha256": retained_sha,
                        }],
                    }
                ),
                encoding="utf-8",
            )
            api = {
                "coord": "com.vendor:legacy",
                "old_version": "1.0",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "com.vendor.LegacyApi.removed",
            }
            graph = SimpleNamespace(
                report_dir=str(report),
                runtime_dependency_catalog={
                    "entries": [{
                        "coord": "com.vendor:aggregate",
                        "jar_path": str(current_jar),
                    }],
                },
            )

            providers = tracer._build_identical_current_class_provider_index([api], graph)

        self.assertIn(("com.vendor:legacy", "com.vendor.LegacyApi"), providers)
        self.assertEqual(
            providers[("com.vendor:legacy", "com.vendor.LegacyApi")][0]["old_jar"],
            str(retained_jar),
        )

    def test_same_class_name_with_different_bytecode_is_not_marked_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / ".upgrade-report"
            dep_dir = report / "evidence" / "dependencies"
            old_dir = report / "evidence" / "api_changes" / "step4_artifact_jars" / "base"
            dep_dir.mkdir(parents=True)
            old_dir.mkdir(parents=True)
            (dep_dir / "dep_changes.csv").write_text(
                "coord,old_version,new_version,change_type,scope,base_coord,current_coord,base_lib_entry,current_lib_entry\n"
                "com.vendor:legacy,1.0,-,移除,runtime,com.vendor:legacy,,BOOT-INF/lib/legacy-1.0.jar,\n",
                encoding="utf-8",
            )
            with zipfile.ZipFile(old_dir / "BOOT-INF__lib__legacy-1.0.jar", "w") as zf:
                zf.writestr("com/vendor/LegacyApi.class", b"old")
            current_jar = Path(tmp) / "aggregate.jar"
            with zipfile.ZipFile(current_jar, "w") as zf:
                zf.writestr("com/vendor/LegacyApi.class", b"different")
            api = {
                "coord": "com.vendor:legacy",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "com.vendor.LegacyApi.removed",
                "api_simple": "removed",
                "api_signature": "()",
                "symbol_kind": "method",
            }
            graph = SimpleNamespace(
                report_dir=str(report),
                runtime_dependency_catalog={"entries": [{
                    "coord": "com.vendor:aggregate",
                    "jar_path": str(current_jar),
                }]},
            )

            providers = tracer._build_identical_current_class_provider_index([api], graph)

        self.assertNotIn(("com.vendor:legacy", "com.vendor.LegacyApi"), providers)

    def test_unreadable_preservation_artifact_cannot_be_treated_as_no_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / ".upgrade-report"
            dep_dir = report / "evidence" / "dependencies"
            old_dir = report / "evidence" / "api_changes" / "step4_artifact_jars" / "base"
            dep_dir.mkdir(parents=True)
            old_dir.mkdir(parents=True)
            (dep_dir / "dep_changes.csv").write_text(
                "coord,base_lib_entry\n"
                "com.vendor:legacy,BOOT-INF/lib/legacy-1.0.jar\n",
                encoding="utf-8",
            )
            (old_dir / "BOOT-INF__lib__legacy-1.0.jar").write_bytes(b"not-a-jar")
            api = {
                "coord": "com.vendor:legacy",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "com.vendor.LegacyApi.removed",
                "api_signature": "()",
                "symbol_kind": "method",
            }
            graph = SimpleNamespace(
                report_dir=str(report),
                runtime_dependency_catalog={"entries": []},
            )

            tracer._build_identical_current_class_provider_index([api], graph)
            result = tracer.trace_api_with_confidence_weighting(api, graph, {})

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "PRESERVATION_BASE_ARTIFACT_UNREADABLE")

    def test_generate_enhanced_summary_cleans_stale_by_api_and_by_module_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            by_api_dir = output_dir / "by_api"
            by_module_dir = output_dir / "by_module"
            by_api_dir.mkdir(parents=True)
            by_module_dir.mkdir(parents=True)
            (by_api_dir / "stale.json").write_text("{}", encoding="utf-8")
            (by_api_dir / "stale.txt").write_text("old", encoding="utf-8")
            (by_module_dir / "stale_impacts.json").write_text("{}", encoding="utf-8")

            results = [
                tracer.TraceResult(
                    coord="a:b",
                    api_name="com.example.OrderService.run",
                    api_simple="run",
                    api_signature="(String)",
                    symbol_kind="method",
                    change_type="method_changed",
                    severity="P1",
                    confirmed=True,
                    source="gitdiff",
                    analysis_scope="method",
                    analysis_status="reachable",
                    direct_callers=1,
                    is_reachable=True,
                    reachable_note="已找到调用链",
                    business_reach_depth=1,
                    dependency_chain_coords=[],
                    reason_code="SYSTEM_CODE_REACHABLE",
                    call_paths=["OrderService.run -> DemoApi.call"],
                    evidence_paths=[[
                        {
                            "caller_symbol": "com.example.Controller.handle",
                            "callee_key": "com.example.OrderService.run(String)",
                            "file": "/tmp/sample-app/src/main/java/com/example/Controller.java",
                            "line": 12,
                            "evidence_type": "ast",
                            "confidence": "high",
                        }
                    ]],
                    verification_commands=[],
                    hops=[],
                    confidence_score=0.95,
                    critical_nodes_hit=[],
                ),
            ]

            formatter.generate_enhanced_summary(results, output_dir)

            self.assertFalse((by_api_dir / "stale.json").exists())
            self.assertFalse((by_api_dir / "stale.txt").exists())
            self.assertFalse((by_module_dir / "stale_impacts.json").exists())

    def test_generate_enhanced_summary_keeps_distinct_by_api_files_for_long_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            long_prefix = (
                "org.springframework.boot.autoconfigure.security.saml2."
                "Saml2RelyingPartyProperties$Identityprovider$Verification$Credential"
            )
            results = [
                tracer.TraceResult(
                    coord="a:b",
                    api_name=f"{long_prefix}.getCertificateLocation",
                    api_simple="getCertificateLocation",
                    api_signature="()",
                    symbol_kind="method",
                    change_type="method_changed",
                    severity="P1",
                    confirmed=True,
                    source="gitdiff",
                    analysis_scope="method",
                    analysis_status="not_found_in_static_analysis",
                    direct_callers=0,
                    is_reachable=False,
                    reachable_note="静态分析未找到调用路径",
                    business_reach_depth=0,
                    dependency_chain_coords=[],
                    reason_code="NO_STATIC_PATH",
                    call_paths=[],
                    evidence_paths=[],
                    verification_commands=[],
                    hops=[],
                    confidence_score=1.0,
                    critical_nodes_hit=[],
                ),
                tracer.TraceResult(
                    coord="a:b",
                    api_name=f"{long_prefix}.setCertificateLocation",
                    api_simple="setCertificateLocation",
                    api_signature="(String)",
                    symbol_kind="method",
                    change_type="method_changed",
                    severity="P1",
                    confirmed=True,
                    source="gitdiff",
                    analysis_scope="method",
                    analysis_status="not_found_in_static_analysis",
                    direct_callers=0,
                    is_reachable=False,
                    reachable_note="静态分析未找到调用路径",
                    business_reach_depth=0,
                    dependency_chain_coords=[],
                    reason_code="NO_STATIC_PATH",
                    call_paths=[],
                    evidence_paths=[],
                    verification_commands=[],
                    hops=[],
                    confidence_score=1.0,
                    critical_nodes_hit=[],
                ),
            ]

            formatter.generate_enhanced_summary(results, output_dir)

            by_api_files = sorted((output_dir / "by_api").glob("*.json"))
            self.assertEqual(len(by_api_files), 2)
            self.assertNotEqual(by_api_files[0].name, by_api_files[1].name)

    def test_s6_report_matches_by_api_using_signature_and_expands_not_found_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            s5_dir = report_dir / "evidence" / "call_chain"
            by_api_dir = s5_dir / "by_api"
            by_module_dir = s5_dir / "by_module"
            by_api_dir.mkdir(parents=True)
            by_module_dir.mkdir(parents=True)

            summary = {
                "status": "done",
                "reachable": 1,
                "uncertain": 0,
                "not_analyzed": 0,
                "not_found_in_static_analysis": 1,
                "user_conclusion_summary": {
                    "已确认影响": 1,
                    "当前无法确认": 1,
                },
                "reachable_apis": [
                    {
                        "coord": "a:b",
                        "api": "com.example.Demo.call",
                        "api_name": "com.example.Demo.call",
                        "api_signature": "(String)",
                        "symbol_kind": "method",
                        "change_type": "REMOVED",
                        "severity": "P1",
                        "reason_code": "SYSTEM_CODE_REACHED",
                        "call_paths": ["Service.run -> Demo.call"],
                    }
                ],
                "not_found_apis": [
                    {
                        "coord": "a:b",
                        "api": "com.example.Demo.call",
                        "api_name": "com.example.Demo.call",
                        "api_signature": "(Long)",
                        "symbol_kind": "method",
                        "change_type": "REMOVED",
                        "severity": "P1",
                        "reason_code": "NO_STATIC_PATH",
                        "reason": "静态分析未找到调用路径",
                        "verification": ["grep Demo.call"],
                        "user_conclusion": "当前无法确认",
                    }
                ],
            }
            (s5_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")

            reachable_payload = {
                "coord": "a:b",
                "api": "com.example.Demo.call",
                "api_name": "com.example.Demo.call",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "reachable_note": "命中了 String 重载",
                "evidence_paths": [[{"caller_symbol": "Service.run", "callee_key": "com.example.Demo.call(String)"}]],
            }
            not_found_payload = {
                "coord": "a:b",
                "api": "com.example.Demo.call",
                "api_name": "com.example.Demo.call",
                "api_signature": "(Long)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "reason_code": "NO_STATIC_PATH",
                "evidence_paths": [[{"caller_symbol": "Other.run", "callee_key": "com.example.Demo.call(Long)"}]],
            }
            (by_api_dir / "reachable.json").write_text(json.dumps(reachable_payload, ensure_ascii=False), encoding="utf-8")
            (by_api_dir / "not_found.json").write_text(json.dumps(not_found_payload, ensure_ascii=False), encoding="utf-8")
            (by_module_dir / "app_impacts.json").write_text(
                json.dumps(
                    {
                        "module": "app",
                        "impacts": [{"api": "com.example.Demo.call"}],
                        "p0_count": 0,
                        "p1_count": 1,
                        "p2_count": 0,
                        "uncertain_count": 0,
                        "not_analyzed_count": 0,
                        "not_found_in_static_analysis_count": 1,
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            findings = s6_report.collect_findings(str(report_dir))
            report_text = s6_report.generate_report(findings)
            s6_report.write_s6_detail_artifacts(str(report_dir), findings)
            not_found_md = (report_dir / "deliverables" / "s6_not_found_apis.md").read_text(encoding="utf-8")
            not_found_csv = (report_dir / "deliverables" / "s6_not_found_apis.csv").read_text(encoding="utf-8")

        self.assertEqual(findings["p1"][0]["reason"], "命中了 String 重载")
        self.assertEqual(
            findings["p1"][0]["evidence_paths"][0][0]["callee_key"],
            "com.example.Demo.call(String)",
        )
        self.assertEqual(len(findings["not_found"]), 1)
        self.assertEqual(findings["not_found"][0]["api_signature"], "(Long)")
        self.assertEqual(
            findings["not_found"][0]["evidence_paths"][0][0]["callee_key"],
            "com.example.Demo.call(Long)",
        )
        self.assertEqual(findings["not_found_reason_summary"]["NO_STATIC_PATH"], 1)
        self.assertEqual(findings["module_impacts"]["app"]["not_found"], 1)
        self.assertIn("未发现调用路径", report_text)
        self.assertIn("删除方法，call，参数：String，严重级别：P1", report_text)
        self.assertIn("删除方法，call，参数：Long，严重级别：P1", report_text)
        self.assertNotIn("REMOVED / method", report_text)
        self.assertNotIn("`REMOVED` / `method`", report_text)
        self.assertIn("| # | 依赖坐标 | 变更 API | 变化 | 结论 | 原因 |", not_found_md)
        self.assertNotIn("原因码", not_found_md)
        self.assertNotIn("NO_STATIC_PATH", not_found_md)
        self.assertIn("删除方法，call，参数：Long，严重级别：P1", not_found_md)
        self.assertIn("change_summary", not_found_csv)
        self.assertIn("conclusion", not_found_csv)
        self.assertIn("review_reason", not_found_csv)
        self.assertIn("chain_summary", not_found_csv)
        self.assertIn("chain_detail", not_found_csv)
        self.assertIn("未发现静态调用路径", not_found_csv)
        self.assertIn("入口：Other.run；终点：com.example.Demo.call(Long)；1 次调用（2 个节点）", not_found_csv)
        self.assertIn("删除方法，call，参数：Long，严重级别：P1", not_found_csv)

    def test_s6_report_starts_with_concrete_impact_overview_from_alerts(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            s5_dir = report_dir / "evidence" / "call_chain"
            s5_dir.mkdir(parents=True)
            summary = {
                "status": "done",
                "reachable": 1,
                "uncertain": 0,
                "not_analyzed": 0,
                "not_found_in_static_analysis": 0,
                "user_conclusion_summary": {"已确认影响": 1},
                "reachable_apis": [
                    {
                        "coord": "a:b",
                        "api": "com.vendor.LegacyApi.removed",
                        "api_name": "com.vendor.LegacyApi.removed",
                        "api_signature": "(String)",
                        "symbol_kind": "method",
                        "change_type": "REMOVED",
                        "severity": "P1",
                        "reason_code": "SYSTEM_CODE_REACHED",
                    }
                ],
            }
            (s5_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
            with (s5_dir / "alerts.csv").open("w", newline="", encoding="utf-8") as f:
                fieldnames = [
                    "target_coord", "changed_symbol", "api_signature", "symbol_kind",
                    "change_type", "api_status", "path_status", "conclusion_level",
                    "business_reachable", "business_entry", "consumer_coord",
                    "consumer_class", "consumer_method", "path_text", "stop_reason",
                    "reason", "action", "path_occurrence_count", "evidence_files",
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerow({
                    "target_coord": "a:b",
                    "changed_symbol": "com.vendor.LegacyApi.removed",
                    "api_signature": "(String)",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "api_status": "reachable",
                    "path_status": "reachable",
                    "conclusion_level": "confirmed",
                    "business_reachable": "true",
                    "business_entry": "com.acme.OrderService.submit",
                    "consumer_coord": "BUSINESS",
                    "consumer_class": "com.acme.OrderService",
                    "consumer_method": "submit",
                    "path_text": "com.acme.OrderService.submit -> com.vendor.LegacyApi.removed(String)",
                    "stop_reason": "SYSTEM_CODE_REACHED",
                    "reason": "已找到从系统代码到变更 API 的调用链",
                    "action": "优先按调用链定位受影响业务",
                    "path_occurrence_count": "2",
                    "evidence_files": "/repo/order/src/main/java/com/acme/OrderService.java",
                })

            findings = s6_report.collect_findings(str(report_dir))
            report_text = s6_report.generate_report(findings)

        self.assertEqual(len(findings["impact_overview"]["confirmed_apis"]), 1)
        self.assertIn("## 报告目录", report_text)
        self.assertIn("## 一、核心结论", report_text)
        self.assertIn("## 二、结论限制", report_text)
        self.assertIn("## 三、下一步复核顺序", report_text)
        self.assertIn("## 四、分析结果总表", report_text)
        self.assertIn("## 五、附录", report_text)
        self.assertIn("| 依赖坐标 | 变更 API | 变化 | 结论 | 证据摘要 / 未确认原因 |", report_text)
        self.assertNotIn("| 依赖坐标 | 变更 API | 变化 | 结论 | 关键证据 | 未确认原因 |", report_text)
        self.assertLess(
            report_text.index("## 一、核心结论"),
            report_text.index("## 二、结论限制"),
        )
        self.assertLess(
            report_text.index("## 二、结论限制"),
            report_text.index("## 四、分析结果总表"),
        )
        self.assertLess(
            report_text.index("## 四、分析结果总表"),
            report_text.index("## 五、附录"),
        )
        self.assertIn("com.vendor.LegacyApi.removed", report_text)
        self.assertIn("com.acme.OrderService.submit", report_text)
        self.assertIn("### 4.1 调用链证据", report_text)
        self.assertIn("已确认链路 2 条", report_text)
        self.assertIn("com.acme.OrderService.submit -> com.vendor.LegacyApi.removed(String)", report_text)

    def test_s6_report_does_not_mix_uncertain_paths_into_confirmed_api_evidence(self):
        confirmed_path = "com.acme.App.main -> com.vendor.LegacyApi.removed(String)"
        uncertain_path = "com.vendor:helper:com.vendor.Helper.call -> com.vendor.LegacyApi.removed(String)"
        alert_rows = [
            {
                "api_id": "API-exact-target",
                "target_coord": "a:b",
                "changed_symbol": "com.vendor.LegacyApi.removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "path_status": "reachable",
                "conclusion_level": "confirmed",
                "business_reachable": "true",
                "business_entry": "com.acme.App.main",
                "path_text": confirmed_path,
                "path_occurrence_count": "1",
            },
            {
                "api_id": "API-exact-target",
                "target_coord": "a:b",
                "changed_symbol": "com.vendor.LegacyApi.removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "path_status": "uncertain",
                "conclusion_level": "candidate",
                "business_reachable": "unknown",
                "consumer_coord": "com.vendor:helper",
                "consumer_class": "com.vendor.Helper",
                "consumer_method": "call",
                "path_text": uncertain_path,
                "path_occurrence_count": "1",
            },
        ]
        findings = {
            "impact_overview": s6_report.build_impact_overview(alert_rows),
            "p0": [{
                "coord": "a:b",
                "api": "com.vendor.LegacyApi.removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "user_conclusion": "已确认影响",
                # Step5 summary may carry mixed statuses; Step6 must prefer the
                # status-partitioned alerts paths instead of merging this list.
                "call_paths": [confirmed_path, uncertain_path],
            }],
            "p1": [], "p2": [], "probable_impact": [], "uncertain": [],
            "not_impacted": [], "needs_input": [], "not_analyzed": [], "not_found": [],
        }

        report_text = "\n".join(s6_report.render_api_result_table(findings))

        self.assertIn(confirmed_path, report_text)
        self.assertIn(uncertain_path, report_text)
        self.assertLess(
            report_text.index("**已确认链路（当前展示 1 条，共 1 条）**"),
            report_text.index(confirmed_path),
        )
        self.assertLess(
            report_text.index("**尚未回溯到业务入口的依赖引用（当前展示 1 条，共 1 条）**"),
            report_text.index(uncertain_path),
        )
        self.assertIn(
            "[已确认链路 1 条；另有 1 条依赖引用尚未回溯到业务入口。查看具体链路]"
            "(#api-api-exact-target)",
            report_text,
        )
        self.assertIn('<a id="api-api-exact-target"></a>', report_text)
        self.assertIn("筛选 `api_id = API-exact-target`", report_text)
        self.assertIn("`path_status = reachable` 是已确认链路", report_text)
        self.assertIn(
            "`path_status = uncertain` 是尚未回溯到业务入口的依赖引用",
            report_text,
        )
        self.assertNotIn("已确认/高风险影响；已确认影响", report_text)

    def test_s6_report_links_uncertain_evidence_by_exact_api_id(self):
        target = {
            "target_coord": "a:b",
            "changed_symbol": "com.vendor.LegacyApi.removed",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "api_id": "API-uncertain-target",
            "path_status": "uncertain",
            "conclusion_level": "candidate",
            "business_reachable": "unknown",
        }
        alert_rows = [
            dict(target, path_text="com.vendor.Helper.one -> com.vendor.LegacyApi.removed(String)"),
            dict(target, path_text="com.vendor.Helper.two -> com.vendor.LegacyApi.removed(String)"),
        ]
        findings = {
            "impact_overview": s6_report.build_impact_overview(alert_rows),
            "p0": [], "p1": [], "p2": [], "probable_impact": [],
            "uncertain": [{
                "coord": "a:b",
                "api": "com.vendor.LegacyApi.removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "user_conclusion": "当前无法确认",
            }],
            "not_impacted": [], "needs_input": [], "not_analyzed": [], "not_found": [],
        }

        report_text = "\n".join(s6_report.render_api_result_table(findings))

        self.assertIn(
            "| 依赖坐标 | 变更 API | 变化 | 结论 | 证据摘要 / 未确认原因 |",
            report_text,
        )
        self.assertIn(
            "[发现 2 条依赖引用，尚未回溯到业务入口。查看引用详情]"
            "(#api-api-uncertain-target)",
            report_text,
        )
        self.assertIn('<a id="api-api-uncertain-target"></a>', report_text)
        self.assertIn("筛选 `api_id = API-uncertain-target`", report_text)

    def test_s6_report_does_not_link_ambiguous_or_missing_api_id(self):
        base = {
            "target_coord": "a:b",
            "changed_symbol": "com.vendor.LegacyApi.removed",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "path_status": "uncertain",
            "conclusion_level": "candidate",
            "business_reachable": "unknown",
        }
        finding = {
            "coord": "a:b",
            "api": "com.vendor.LegacyApi.removed",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "user_conclusion": "当前无法确认",
        }
        empty_findings = {
            "p0": [], "p1": [], "p2": [], "probable_impact": [],
            "uncertain": [finding], "not_impacted": [], "needs_input": [],
            "not_analyzed": [], "not_found": [],
        }

        conflicting_rows = [
            dict(base, api_id="API-one", path_text="Helper.one -> LegacyApi.removed"),
            dict(base, api_id="API-two", path_text="Helper.two -> LegacyApi.removed"),
        ]
        conflicting_findings = dict(
            empty_findings,
            impact_overview=s6_report.build_impact_overview(conflicting_rows),
        )
        conflicting_report = "\n".join(s6_report.render_api_result_table(conflicting_findings))

        missing_findings = dict(
            empty_findings,
            impact_overview=s6_report.build_impact_overview([
                dict(base, path_text="Helper.missing -> LegacyApi.removed")
            ]),
        )
        missing_report = "\n".join(s6_report.render_api_result_table(missing_findings))

        for report_text, expected_count in (
            (conflicting_report, 2),
            (missing_report, 1),
        ):
            self.assertIn(f"发现 {expected_count} 条依赖引用", report_text)
            self.assertNotIn("(#api-", report_text)
            self.assertNotIn('<a id="api-', report_text)

    def test_s6_report_keeps_same_simple_names_in_separate_evidence_anchors(self):
        def alert(coord, owner, api_id, caller):
            return {
                "api_id": api_id,
                "target_coord": coord,
                "changed_symbol": f"{owner}.StringUtils.isEmpty",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "path_status": "reachable",
                "conclusion_level": "confirmed",
                "business_reachable": "true",
                "path_text": f"{caller} -> {owner}.StringUtils.isEmpty(String)",
            }

        alert_rows = [
            alert("a:b", "com.alpha", "API-alpha", "com.app.AlphaCaller.run"),
            alert("c:d", "com.beta", "API-beta", "com.app.BetaCaller.run"),
        ]
        p0 = []
        for coord, owner in (("a:b", "com.alpha"), ("c:d", "com.beta")):
            p0.append({
                "coord": coord,
                "api": f"{owner}.StringUtils.isEmpty",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "user_conclusion": "已确认影响",
            })
        findings = {
            "impact_overview": s6_report.build_impact_overview(alert_rows),
            "p0": p0, "p1": [], "p2": [], "probable_impact": [], "uncertain": [],
            "not_impacted": [], "needs_input": [], "not_analyzed": [], "not_found": [],
        }

        report_text = "\n".join(s6_report.render_api_result_table(findings))

        self.assertEqual(report_text.count("(#api-api-alpha)"), 1)
        self.assertEqual(report_text.count("(#api-api-beta)"), 1)
        self.assertEqual(report_text.count('<a id="api-api-alpha"></a>'), 1)
        self.assertEqual(report_text.count('<a id="api-api-beta"></a>'), 1)
        self.assertIn("com.app.AlphaCaller.run -> com.alpha.StringUtils.isEmpty(String)", report_text)
        self.assertIn("com.app.BetaCaller.run -> com.beta.StringUtils.isEmpty(String)", report_text)

    def test_s6_report_uses_not_analyzed_filter_for_incomplete_evidence(self):
        alert_rows = [{
            "api_id": "API-incomplete",
            "target_coord": "a:b",
            "changed_symbol": "com.vendor.DynamicApi.call",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "path_status": "not_analyzed",
            "conclusion_level": "incomplete",
            "business_reachable": "unknown",
            "path_text": "com.vendor.DynamicProxy.invoke -> com.vendor.DynamicApi.call(String)",
        }]
        findings = {
            "impact_overview": s6_report.build_impact_overview(alert_rows),
            "p0": [], "p1": [], "p2": [], "probable_impact": [], "uncertain": [],
            "not_impacted": [], "needs_input": [],
            "not_analyzed": [{
                "coord": "a:b",
                "api": "com.vendor.DynamicApi.call",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "user_conclusion": "本次未完成分析",
            }],
            "not_found": [],
        }

        report_text = "\n".join(s6_report.render_api_result_table(findings))

        self.assertIn(
            "[发现 1 条分析证据，但本项未完成有效分析。查看证据详情]"
            "(#api-api-incomplete)",
            report_text,
        )
        self.assertIn("`path_status = not_analyzed` 是本次未完成有效分析的证据", report_text)
        self.assertNotIn("`path_status = uncertain`", report_text)

    def test_s6_report_does_not_use_mixed_summary_paths_when_exact_alert_exists(self):
        alert_rows = [{
            "api_id": "API-exact-without-path",
            "target_coord": "a:b",
            "changed_symbol": "com.vendor.LegacyApi.removed",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "path_status": "uncertain",
            "conclusion_level": "candidate",
            "business_reachable": "unknown",
            "path_text": "",
        }]
        mixed_summary_path = "com.app.Unrelated.run -> com.vendor.OtherApi.call(String)"
        findings = {
            "impact_overview": s6_report.build_impact_overview(alert_rows),
            "p0": [], "p1": [], "p2": [], "probable_impact": [],
            "uncertain": [{
                "coord": "a:b",
                "api": "com.vendor.LegacyApi.removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "user_conclusion": "当前无法确认",
                "user_reason": "依赖引用存在，但当前记录没有可展示的完整路径。",
                "call_paths": [mixed_summary_path],
            }],
            "not_impacted": [], "needs_input": [], "not_analyzed": [], "not_found": [],
        }

        report_text = "\n".join(s6_report.render_api_result_table(findings))

        self.assertNotIn(mixed_summary_path, report_text)
        self.assertNotIn("(#api-api-exact-without-path)", report_text)
        self.assertIn("依赖引用存在，但当前记录没有可展示的完整路径。", report_text)

    def test_s6_report_uses_step5_graph_stats_as_coverage_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            s5_dir = report_dir / "evidence" / "call_chain"
            s5_dir.mkdir(parents=True)
            summary = {
                "status": "done",
                "reachable": 1,
                "uncertain": 0,
                "not_analyzed": 0,
                "not_found_in_static_analysis": 0,
                "user_conclusion_summary": {"已确认影响": 1},
                "meta": {
                    "graph_stats": {
                        "truncated": False,
                        "parser_fallback_reasons": {"unsupported_language_kotlin": 2},
                        "source_artifact_alignment": {
                            "status": "unverified",
                            "reason_codes": ["build_provenance_missing"],
                            "git_root": "/repo/app",
                        },
                        "indirect_usage": {
                            "status": "partial",
                            "reason_codes": ["reflection_source_partial"],
                        },
                    }
                },
                "reachable_apis": [
                    {
                        "coord": "a:b",
                        "api": "com.vendor.LegacyApi.removed",
                        "api_name": "com.vendor.LegacyApi.removed",
                        "api_signature": "(String)",
                        "symbol_kind": "method",
                        "change_type": "REMOVED",
                        "severity": "P1",
                        "reason_code": "SYSTEM_CODE_REACHED",
                    }
                ],
            }
            (s5_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")

            findings = s6_report.collect_findings(str(report_dir))
            report_text = s6_report.generate_report(findings)

        self.assertEqual(findings["coverage"]["source"], "step5_summary_fallback")
        self.assertEqual(findings["coverage"]["overall_status"], "partial")
        self.assertIn("分析完整度 | 部分完整", report_text)
        self.assertIn("源码与制品一致性", report_text)
        self.assertIn("动态调用可能漏报", report_text)

    def test_s6_report_prefers_formal_coverage_over_step5_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            s5_dir = report_dir / "evidence" / "call_chain"
            s5_dir.mkdir(parents=True)
            runtime_coverage_dir = report_dir / ".runtime" / "coverage"
            runtime_coverage_dir.mkdir(parents=True)
            summary = {
                "status": "done",
                "reachable": 0,
                "uncertain": 0,
                "not_analyzed": 0,
                "not_found_in_static_analysis": 0,
                "meta": {
                    "graph_stats": {
                        "truncated": True,
                        "truncation_reasons": ["max_methods"],
                    }
                },
            }
            coverage = {
                "schema": "java-upgrade-analyzer.coverage.v1",
                "overall_status": "complete",
                "critical_incomplete": [],
                "components": [],
            }
            (s5_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
            (runtime_coverage_dir / "coverage.json").write_text(json.dumps(coverage, ensure_ascii=False), encoding="utf-8")

            findings = s6_report.collect_findings(str(report_dir))
            report_text = s6_report.generate_report(findings)

        self.assertEqual(findings["coverage"]["overall_status"], "complete")
        self.assertNotEqual(findings["coverage"].get("source"), "step5_summary_fallback")
        self.assertIn("分析完整度 | 完整", report_text)

    def test_s6_report_summarizes_large_not_found_list_outside_main_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            s5_dir = report_dir / "evidence" / "call_chain"
            s5_dir.mkdir(parents=True)
            not_found_apis = [
                {
                    "coord": "a:b",
                    "api": f"com.example.Api{i}.removed",
                    "api_name": f"com.example.Api{i}.removed",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "severity": "P1",
                    "reason_code": "NO_STATIC_PATH",
                    "reason": "静态分析未找到调用路径",
                    "user_conclusion": "当前无法确认",
                }
                for i in range(100)
            ]
            summary = {
                "status": "done",
                "reachable": 0,
                "uncertain": 0,
                "not_analyzed": 0,
                "not_found_in_static_analysis": len(not_found_apis),
                "user_conclusion_summary": {"当前无法确认": len(not_found_apis)},
                "not_found_apis": not_found_apis,
            }
            (s5_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
            s4_dir = report_dir / "evidence" / "api_changes"
            s4_dir.mkdir(parents=True)
            changed_api_lines = ["coord,api_name,api_signature,symbol_kind,change_type,severity"]
            for i in range(s6_report.S6_CHANGED_API_SPLIT_ROWS + 1):
                changed_api_lines.append(f"a:b,com.example.Api{i}.removed,(),method,REMOVED,P1")
            (s4_dir / "all_changed_apis.csv").write_text(
                "\n".join(changed_api_lines) + "\n",
                encoding="utf-8",
            )
            coverage_dir = report_dir / ".runtime" / "coverage"
            coverage_dir.mkdir(parents=True)
            (coverage_dir / "coverage.json").write_text(json.dumps({
                "overall_status": "partial",
                "critical_incomplete": ["indirect_usage_matrix"],
                "components": [
                    {
                        "id": "indirect_usage_matrix",
                        "status": "partial",
                        "reason_codes": ["reflection_source_partial"],
                        "evidence": ["evidence/call_chain/alerts.csv"],
                    }
                ],
            }, ensure_ascii=False), encoding="utf-8")

            findings = s6_report.collect_findings(str(report_dir))
            findings.setdefault("artifacts", {}).update(
                s6_report.write_s6_detail_artifacts(str(report_dir), findings)
            )
            report_text = s6_report.generate_report(findings)

            not_found_csv = report_dir / findings["artifacts"]["not_found_csv"]
            not_found_md = report_dir / findings["artifacts"]["not_found_md"]
            self.assertTrue(not_found_csv.exists())
            self.assertTrue(not_found_md.exists())
            with not_found_csv.open(encoding="utf-8") as f:
                self.assertEqual(len(list(csv.DictReader(f))), 100)
            self.assertIn("## 四、分析结果总表", report_text)
            self.assertIn("本表共有 100 条 API 分析结果，当前展示 20 条，省略 80 条", report_text)
            self.assertIn("完整结果见[逐链路证据台账](../evidence/call_chain/alerts.csv)", report_text)
            self.assertIn("[未发现调用路径清单](s6_not_found_apis.md)", report_text)
            self.assertNotIn("s6_probable_impact_apis.md", report_text)
            self.assertIn("### 运行产物阅读分层", report_text)
            self.assertIn("#### 给用户看的产物", report_text)
            self.assertIn("#### 用户深入排查时看的产物", report_text)
            self.assertIn("#### 程序使用的产物", report_text)
            self.assertIn("| `deliverables/report.md` | 最终报告；优先阅读这一份 |", report_text)
            self.assertIn("| `evidence/static_scan/s3_*.csv/.txt` | JDK、Spring Boot、反射等静态扫描命中 |", report_text)
            self.assertIn("| `evidence/api_changes/changed_dependencies.md` | 依赖包维度的变化摘要；用于选择系统触达分析范围 |", report_text)
            self.assertIn("| `evidence/api_changes/changed_dependencies.csv` | 依赖包维度的结构化清单；供筛选和自动化使用 |", report_text)
            self.assertIn("| `evidence/api_changes/all_changed_apis.csv` | 依赖 API 变化全集 |", report_text)
            self.assertIn("| `evidence/api_changes/all_changed_apis_part_*.csv` | 依赖 API 变化拆分文件（每 500 条一份） |", report_text)
            self.assertNotIn("all_changed_apis_alerts.csv", report_text)
            self.assertIn("| `evidence/call_chain/alerts_<status>.csv` / `alerts_<status>_NNN.csv` | 按链路状态拆分的台账 |", report_text)
            self.assertNotIn("s6_probable_impact_apis.md", report_text)
            self.assertNotIn("s6_uncertain_apis.md", report_text)
            self.assertNotIn("s6_needs_input_apis.md", report_text)
            self.assertNotIn("s6_not_analyzed_apis.md", report_text)
            self.assertIn("| [未发现调用路径清单](s6_not_found_apis.md) | 未发现调用路径清单 |", report_text)
            self.assertNotIn("### 产物索引", report_text)
            self.assertIn("## 二、结论限制", report_text)
            self.assertIn("| 分析完整度 | 部分完整 |", report_text)
            self.assertIn("动态调用可能漏报", report_text)
            self.assertIn("反射调用可能漏报。", report_text)
            self.assertIn("排序：先按结论状态，再在已确认影响中按严重级别 P0、P1、P2 排序；严重级别不等于结论确定性。", report_text)
            self.assertIn("静态分析未找到调用路径", report_text)
            self.assertNotIn("NO_STATIC_PATH", report_text)
            self.assertNotIn("当前无法确认清单", report_text)
            self.assertNotIn("需要补充输入清单", report_text)
            self.assertNotIn("未覆盖/未分析清单", report_text)
            self.assertNotIn("静态未找到清单", report_text)
            self.assertNotIn("- 状态：部分完整", report_text)
            self.assertNotIn("整体状态：partial", report_text)
            self.assertNotIn("关键未完成维度", report_text)
            self.assertNotIn("dependency_source_mapping", report_text)
            self.assertNotIn("背景证据入口", report_text)
            self.assertNotIn("背景信号（未证明影响当前系统）", report_text)
            self.assertNotIn("背景文件数量倒推风险", report_text)
            self.assertNotIn("### 扫描统计", report_text)
            self.assertNotIn("### 依赖变更概览", report_text)
            self.assertNotIn("机器可消费", report_text)
            self.assertNotIn("scan_stats", report_text)
            self.assertIn("| `.runtime/findings/s6_findings.json` | 最终结构化结果；供程序读取，不作为人工优先阅读文件 |", report_text)
            self.assertIn("| `.runtime/observability/step*_timing.csv` / `step1_progress.jsonl` | 运行进度与分阶段耗时；供 Agent 监控和性能排查 |", report_text)
            self.assertIn("主报告按结论类型各展示前 20 条", report_text)
            self.assertIn("com.example.Api0.removed", report_text)
            self.assertNotIn("com.example.Api99.removed", report_text)
            self.assertEqual(report_text.count("### `com.example.Api"), 0)
            self.assertIn("com.example.Api99.removed", not_found_md.read_text(encoding="utf-8"))
            part_001 = s4_dir / "all_changed_apis_part_001.csv"
            part_002 = s4_dir / "all_changed_apis_part_002.csv"
            self.assertTrue(part_001.exists())
            self.assertTrue(part_002.exists())
            with part_001.open(encoding="utf-8") as f:
                self.assertEqual(len(list(csv.DictReader(f))), s6_report.S6_CHANGED_API_SPLIT_ROWS)
            with part_002.open(encoding="utf-8") as f:
                self.assertEqual(len(list(csv.DictReader(f))), 1)

    def test_s6_report_summarizes_large_review_buckets_outside_main_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            s5_dir = self._call_chain_dir(report_dir)
            s5_dir.mkdir(parents=True)

            uncertain_apis = [
                {
                    "coord": "a:b",
                    "api": f"com.example.Uncertain{i}.changed",
                    "api_name": f"com.example.Uncertain{i}.changed",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "severity": "P1",
                    "reason_code": "BYTECODE_HIT_BUSINESS_ENTRY_NOT_CONFIRMED",
                    "reason": "字节码命中但未确认回业务入口",
                    "user_conclusion": "当前无法确认",
                }
                for i in range(30)
            ]
            not_analyzed_apis = []
            for prefix, conclusion, reason_code in [
                ("Probable", "可能影响", "BEHAVIOR_CHANGED_RUNTIME_VERIFICATION"),
                ("NeedsInput", "需要补充输入", "DEPENDENCY_SOURCE_MAPPING_MISSING"),
                ("NotAnalyzed", "当前无法确认", "RESOURCE_OR_REFLECTION"),
            ]:
                for i in range(30):
                    not_analyzed_apis.append(
                        {
                            "coord": "a:b",
                            "api": f"com.example.{prefix}{i}.changed",
                            "api_name": f"com.example.{prefix}{i}.changed",
                            "api_signature": "()",
                            "symbol_kind": "method",
                            "change_type": "REMOVED",
                            "severity": "P1",
                            "reason_code": reason_code,
                            "reason": f"{prefix} reason",
                            "user_conclusion": conclusion,
                            "recommended_action": f"{prefix} action",
                        }
                    )
            summary = {
                "status": "done",
                "reachable": 0,
                "uncertain": len(uncertain_apis),
                "not_analyzed": len(not_analyzed_apis),
                "not_found_in_static_analysis": 0,
                "user_conclusion_summary": {
                    "可能影响": 30,
                    "需要补充输入": 30,
                    "当前无法确认": 60,
                },
                "uncertain_apis": uncertain_apis,
                "not_analyzed_apis": not_analyzed_apis,
            }
            (s5_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")

            findings = s6_report.collect_findings(str(report_dir))
            findings.setdefault("artifacts", {}).update(
                s6_report.write_s6_detail_artifacts(str(report_dir), findings)
            )
            report_text = s6_report.generate_report(findings)

            for key in [
                "uncertain_csv",
                "probable_impact_csv",
                "needs_input_csv",
                "not_analyzed_csv",
            ]:
                self.assertTrue((report_dir / findings["artifacts"][key]).exists())

            with (report_dir / findings["artifacts"]["not_analyzed_csv"]).open(encoding="utf-8") as f:
                self.assertEqual(len(list(csv.DictReader(f))), 30)
            self.assertIn("## 四、分析结果总表", report_text)
            self.assertIn("| 依赖坐标 | 变更 API | 变化 | 结论 | 证据摘要 / 未确认原因 |", report_text)
            self.assertIn("| 可能影响 | Probable reason |", report_text)
            self.assertIn("| 需人工复核 | 字节码命中但未确认回业务入口 |", report_text)
            self.assertIn("主报告按结论类型各展示前 20 条", report_text)
            self.assertIn("com.example.Uncertain0.changed", report_text)
            self.assertNotIn("com.example.Uncertain29.changed", report_text)
            self.assertEqual(report_text.count("### `com.example.Uncertain"), 0)
            self.assertIn(
                "com.example.Uncertain29.changed",
                (report_dir / findings["artifacts"]["uncertain_md"]).read_text(encoding="utf-8"),
            )

    def test_s6_detail_markdown_stays_readable_for_very_large_bucket(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            s5_dir = self._call_chain_dir(report_dir)
            s5_dir.mkdir(parents=True)
            not_found_apis = [
                {
                    "coord": f"g:dep-{i % 5}",
                    "api": f"com.example.Huge{i}.removed",
                    "api_name": f"com.example.Huge{i}.removed",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "severity": "P1",
                    "reason_code": "NO_STATIC_PATH" if i % 2 == 0 else "NO_CLASS_REFERENCE",
                    "reason": "静态分析未找到调用路径",
                    "user_conclusion": "当前无法确认",
                }
                for i in range(260)
            ]
            summary = {
                "status": "done",
                "reachable": 0,
                "uncertain": 0,
                "not_analyzed": 0,
                "not_found_in_static_analysis": len(not_found_apis),
                "user_conclusion_summary": {"当前无法确认": len(not_found_apis)},
                "not_found_apis": not_found_apis,
            }
            (s5_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")

            findings = s6_report.collect_findings(str(report_dir))
            findings.setdefault("artifacts", {}).update(
                s6_report.write_s6_detail_artifacts(str(report_dir), findings)
            )

            not_found_csv = report_dir / findings["artifacts"]["not_found_csv"]
            not_found_md = report_dir / findings["artifacts"]["not_found_md"]
            with not_found_csv.open(encoding="utf-8") as f:
                self.assertEqual(len(list(csv.DictReader(f))), 260)
            md_text = not_found_md.read_text(encoding="utf-8")
            self.assertIn("## 明细样例（前 50 条）", md_text)
            self.assertIn("## 附录：聚合统计", md_text)
            self.assertIn("### 原因分类", md_text)
            self.assertIn("### 依赖坐标分布", md_text)
            self.assertLess(md_text.index("## 明细样例（前 50 条）"), md_text.index("## 附录：聚合统计"))
            self.assertIn("完整全集请看 `deliverables/s6_not_found_apis.csv`", md_text)
            self.assertIn("com.example.Huge0.removed", md_text)
            self.assertNotIn("com.example.Huge259.removed", md_text)

    def test_s6_detail_writer_removes_stale_files_for_empty_bucket(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            deliverables = report_dir / "deliverables"
            deliverables.mkdir(parents=True)
            stale_csv = deliverables / "s6_not_analyzed_apis.csv"
            stale_md = deliverables / "s6_not_analyzed_apis.md"
            stale_csv.write_text("old result\n", encoding="utf-8")
            stale_md.write_text("old result\n", encoding="utf-8")

            findings = {bucket: [] for bucket in s6_report.S6_DETAIL_BUCKETS}
            artifacts = s6_report.write_s6_detail_artifacts(str(report_dir), findings)

            self.assertNotIn("not_analyzed_csv", artifacts)
            self.assertNotIn("not_analyzed_md", artifacts)
            self.assertFalse(stale_csv.exists())
            self.assertFalse(stale_md.exists())

    def test_s6_report_keeps_probable_impact_and_needs_input_out_of_uncovered_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            s5_dir = report_dir / "evidence" / "call_chain"
            s5_dir.mkdir(parents=True)
            by_module_dir = s5_dir / "by_module"
            by_module_dir.mkdir(parents=True)
            summary = {
                "status": "done",
                "reachable": 0,
                "uncertain": 0,
                "not_analyzed": 3,
                "not_found_in_static_analysis": 0,
                "user_conclusion_summary": {
                    "可能影响": 1,
                    "需要补充输入": 1,
                    "当前无法确认": 1,
                },
                "quality_gate": {
                    "confirmed_impact": 0,
                    "probable_impact": 1,
                    "inconclusive": 1,
                    "needs_input": 1,
                },
                "not_analyzed_apis": [
                    {
                        "coord": "a:b",
                        "api": "com.example.Demo.behavior",
                        "api_name": "com.example.Demo.behavior",
                        "api_signature": "()",
                        "symbol_kind": "method",
                        "change_type": "BEHAVIOR_CHANGED",
                        "severity": "P2",
                        "reason_code": "BEHAVIOR_CHANGED_RUNTIME_VERIFICATION",
                        "reason": "behavior changed",
                        "user_conclusion": "可能影响",
                        "recommended_action": "运行相关业务测试",
                    },
                    {
                        "coord": "a:b",
                        "api": "com.example.Demo.bridge",
                        "api_name": "com.example.Demo.bridge",
                        "api_signature": "()",
                        "symbol_kind": "method",
                        "change_type": "REMOVED",
                        "severity": "P1",
                        "reason_code": "DEPENDENCY_SOURCE_MAPPING_MISSING",
                        "reason": "缺失依赖源码映射",
                        "user_conclusion": "需要补充输入",
                        "recommended_action": "补 dependency_source_dirs",
                    },
                    {
                        "coord": "a:b",
                        "api": "com.example.Demo.unknown",
                        "api_name": "com.example.Demo.unknown",
                        "api_signature": "()",
                        "symbol_kind": "method",
                        "change_type": "REMOVED",
                        "severity": "P1",
                        "reason_code": "RESOURCE_OR_REFLECTION",
                        "reason": "资源或反射调用",
                        "user_conclusion": "当前无法确认",
                    },
                ],
            }
            (s5_dir / "summary.json").write_text(
                json.dumps(summary, ensure_ascii=False),
                encoding="utf-8",
            )
            (by_module_dir / "app_impacts.json").write_text(
                json.dumps(
                    {
                        "module": "app",
                        "impacts": [
                            {"api": "com.example.Demo.behavior"},
                            {"api": "com.example.Demo.bridge"},
                            {"api": "com.example.Demo.unknown"},
                        ],
                        "p0_count": 0,
                        "p1_count": 0,
                        "p2_count": 0,
                        "uncertain_count": 0,
                        "probable_impact_count": 1,
                        "needs_input_count": 1,
                        "not_analyzed_count": 1,
                        "not_found_in_static_analysis_count": 0,
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            findings = s6_report.collect_findings(str(report_dir))
            report_text = s6_report.generate_report(findings)

        self.assertEqual(len(findings["probable_impact"]), 1)
        self.assertEqual(findings["probable_impact"][0]["reason_code"], "BEHAVIOR_CHANGED_RUNTIME_VERIFICATION")
        self.assertEqual(len(findings["needs_input"]), 1)
        self.assertEqual(findings["needs_input"][0]["reason_code"], "DEPENDENCY_SOURCE_MAPPING_MISSING")
        self.assertEqual(len(findings["not_analyzed"]), 3)
        self.assertEqual(findings["impacted_dependencies"][0]["probable_impact"], 1)
        self.assertEqual(findings["impacted_dependencies"][0]["needs_input"], 1)
        self.assertEqual(findings["impacted_dependencies"][0]["not_analyzed"], 1)
        self.assertEqual(findings["module_impacts"]["app"]["probable_impact"], 1)
        self.assertEqual(findings["module_impacts"]["app"]["needs_input"], 1)
        self.assertEqual(findings["module_impacts"]["app"]["not_analyzed"], 1)
        self.assertIn("## 四、分析结果总表", report_text)
        self.assertIn("com.example.Demo.behavior", report_text)
        self.assertIn("com.example.Demo.bridge", report_text)
        self.assertIn("com.example.Demo.unknown", report_text)
        self.assertIn("| 可能影响 | 1 |", report_text)
        self.assertIn("| 缺少依赖源码/构建产物 | 1 |", report_text)
        self.assertIn("| 本次未完成分析 | 1 |", report_text)
        self.assertIn("可能影响", report_text)
        self.assertIn("缺少依赖源码/构建产物", report_text)
        self.assertIn("需人工复核", report_text)
        self.assertNotIn("### 5.4 未覆盖/未分析（3 项）", report_text)

    def test_s6_report_reads_per_dependency_summary_and_renders_dependency_conclusion_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            s5_dir = self._call_chain_dir(report_dir)
            per_dep_dir = self._api_changes_dir(report_dir) / PER_DEPENDENCY_DIRNAME / "a_b"
            s5_dir.mkdir(parents=True)
            per_dep_dir.mkdir(parents=True)
            self._write_text(
                self._dependencies_dir(report_dir) / "dep_changes.csv",
                "\n".join(
                    [
                        "coord,old_version,new_version,change_type,scope",
                        "a:b,1.0.0,-,移除,compile",
                    ]
                ),
                encoding="utf-8",
            )
            (s5_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "status": "done",
                        "reachable": 1,
                        "uncertain": 0,
                        "not_analyzed": 0,
                        "not_found_in_static_analysis": 0,
                        "user_conclusion_summary": {"已确认影响": 1},
                        "reachable_apis": [
                            {
                                "coord": "a:b",
                                "api": "com.example.Demo.call",
                                "api_name": "com.example.Demo.call",
                                "api_signature": "()",
                                "symbol_kind": "method",
                                "change_type": "REMOVED",
                                "severity": "P0",
                                "reason_code": "SYSTEM_CODE_REACHED",
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (per_dep_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "coord": "a:b",
                        "change_type": "移除",
                        "step5": {
                            "reaches_system_source": True,
                            "final_status": "reachable",
                            "blocked_at": "",
                            "blocked_reason": "",
                            "evidence_level": "strong",
                            "selected_api": "com.example.Demo.call",
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            findings = s6_report.collect_findings(str(report_dir))
            report_text = s6_report.generate_report(findings)

        self.assertEqual(findings["per_dependency_results"][0]["coord"], "a:b")
        self.assertTrue(findings["per_dependency_results"][0]["reaches_system_source"])
        self.assertEqual(findings["impacted_dependencies"][0]["change_type"], "移除")
        self.assertNotIn("单依赖包最终结论", report_text)
        self.assertIn("## 四、分析结果总表", report_text)
        self.assertIn("com.example.Demo.call", report_text)
        self.assertNotIn("| a:b | 移除 | 是 | reachable |  |  | strong | com.example.Demo.call |", report_text)

    def test_gate_allows_checkpoint_when_inputs_are_missing_without_strict_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            output_dir = self._call_chain_dir(report_dir)
            output_dir.mkdir(parents=True)
            (output_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "status": "done",
                        "reachable": 0,
                        "uncertain": 0,
                        "not_analyzed": 1,
                        "not_found_in_static_analysis": 0,
                        "user_conclusion_summary": {"需要补充输入": 1},
                        "quality_gate": {"needs_input": 1, "inconclusive": 0, "probable_impact": 0, "confirmed_impact": 0},
                        "not_analyzed_apis": [
                            {
                                "api": "com.example.Foo.bar",
                                "reason": "缺失依赖源码映射",
                                "user_conclusion": "需要补充输入",
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            gate.gate_call_chain(str(report_dir), strict_risk_gate=False)

    def test_bridge_precheck_does_not_force_dependency_mapping_when_business_graph_is_incomplete(self):
        requirements = step5.check_apis_that_need_bridge(
            [
                {
                    "coord": "com.example:demo",
                    "api_name": "com.example.Target.call",
                    "api_simple": "call",
                    "api_signature": "(String)",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                }
            ],
            report_dir=".",
            source_dirs=["src/main/java"],
            business_graph=SimpleNamespace(reverse_edges={}, methods_by_id={}),
            dependency_source_mappings=[],
            business_graph_stats={
                "truncated": True,
                "truncation_reasons": ["max_methods"],
                "parser_fallback_reasons": {},
                "edge_cap_hits": 0,
            },
        )

        info = next(iter(requirements.values()))
        self.assertFalse(info["needs_bridge"])
        self.assertEqual(info["reason"], "business_graph_precheck_incomplete")

    def test_bridge_precheck_fails_closed_for_kotlin_partial_capability(self):
        requirements = step5.check_apis_that_need_bridge(
            [
                {
                    "coord": "com.example:demo",
                    "api_name": "com.example.Target.call",
                    "api_simple": "call",
                    "api_signature": "(String)",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                }
            ],
            report_dir=".",
            source_dirs=["src/main/java"],
            business_graph=SimpleNamespace(reverse_edges={}, methods_by_id={}),
            dependency_source_mappings=[],
            business_graph_stats={
                "truncated": False,
                "parser_fallback_reasons": {"unsupported_language_kotlin": 3},
                "edge_cap_hits": 0,
            },
        )

        info = next(iter(requirements.values()))
        self.assertFalse(info["needs_bridge"])
        self.assertEqual(info["reason"], "business_graph_precheck_incomplete")

    def test_source_collection_includes_kts_and_standard_source_sets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            production = root / "src/main/kotlin/com/acme/ProductionTest.kt"
            test_source = root / "src/test/kotlin/com/acme/ActualSpec.kt"
            script = root / "src/main/kotlin/com/acme/Bootstrap.kts"
            for path in (production, test_source, script):
                path.parent.mkdir(parents=True, exist_ok=True)
            production.write_text(
                "package com.acme\n"
                "class ProductionTest {\n"
                "  fun run() = Unit\n"
                "}\n",
                encoding="utf-8",
            )
            test_source.write_text(
                "package com.acme\n"
                "class ActualSpec {\n"
                "  fun run() = Unit\n"
                "}\n",
                encoding="utf-8",
            )
            script.write_text(
                "package com.acme\n"
                "class Bootstrap {\n"
                "  fun run() = Unit\n"
                "}\n",
                encoding="utf-8",
            )

            entries, stats = step5._collect_source_file_entries([{
                "root": str(root),
                "owner_type": "business",
                "owner_coord": "BUSINESS",
                "module": "app",
            }])

        by_name = {Path(entry["file_path"]).name: entry for entry in entries}
        self.assertEqual(
            {"ProductionTest.kt", "ActualSpec.kt", "Bootstrap.kts"},
            set(by_name),
        )
        self.assertFalse(by_name["ProductionTest.kt"]["methods"][0].is_test)
        self.assertTrue(by_name["ActualSpec.kt"]["methods"][0].is_test)
        self.assertEqual("kotlin", by_name["Bootstrap.kts"]["methods"][0].language)
        self.assertEqual(3, stats["parser_fallback_reasons"]["unsupported_language_kotlin"])

    def test_mixed_java_kotlin_fixture_keeps_bidirectional_source_edges(self):
        fixture_root = ROOT_DIR / "tests/fixtures/step5_mixed_language"
        graph_result = step5.build_enhanced_source_graph([{
            "root": str(fixture_root),
            "owner_type": "business",
            "owner_coord": "BUSINESS",
            "module": "mixed",
        }])
        graph = graph_result["graph"]

        java_to_kotlin = graph.reverse_edges.get("com.acme.KotlinService.kotlinCall", [])
        kotlin_to_java = graph.reverse_edges.get(
            "com.acme.JavaCaller.javaCall()", []
        )
        self.assertTrue(java_to_kotlin, sorted(graph.reverse_edges)[:30])
        self.assertTrue(kotlin_to_java, sorted(graph.reverse_edges)[:30])
        test_methods = [
            method for method in graph.methods_by_id.values()
            if method.class_name == "KotlinServiceSpec"
        ]
        self.assertTrue(test_methods)
        self.assertTrue(all(method.is_test for method in test_methods))

    def test_mixed_language_source_scope_is_closed_by_final_business_classes(self):
        fixture_root = ROOT_DIR / "tests/fixtures/step5_mixed_language"
        source_roots = [{
            "root": str(fixture_root),
            "owner_type": "business",
            "owner_coord": "BUSINESS",
            "module": "mixed",
        }]

        complete_entries, complete_stats = step5._collect_source_file_entries(
            source_roots,
            allowed_business_classes={
                "com.acme.JavaCaller",
                "com.acme.KotlinService",
                "com.acme.KotlinServiceSpec",
            },
        )
        packaged_entries, packaged_stats = step5._collect_source_file_entries(
            source_roots,
            allowed_business_classes={"com.acme.JavaCaller"},
        )

        self.assertEqual(3, len(complete_entries))
        self.assertEqual(
            2,
            complete_stats["parser_fallback_reasons"]["unsupported_language_kotlin"],
        )
        self.assertEqual(
            ["JavaCaller.java"],
            [Path(entry["file_path"]).name for entry in packaged_entries],
        )
        self.assertEqual({}, packaged_stats["parser_fallback_reasons"])

    def test_multi_target_reverse_reuse_preserves_full_alerts_and_path_fingerprint(self):
        def run(enable_reuse):
            apis, graph, type_metadata = self._shared_predecessor_batch_fixture(4)
            graph_stats = {}
            with patch.object(
                tracer, "_build_packaged_runtime_dependency_scan_cache"
            ), patch.object(
                tracer, "_build_identical_current_class_provider_index", return_value={}
            ), patch.object(
                tracer, "collect_graph_analyzer_edges"
            ), patch.object(
                tracer, "write_analyzer_edge_ledger"
            ), patch.object(
                tracer, "_emit_step5_perf_summary"
            ):
                results = tracer.trace_all_apis_with_confidence_weighting(
                    apis,
                    graph,
                    type_metadata,
                    graph_stats=graph_stats,
                    enable_multi_target_reuse=enable_reuse,
                )
            return results, graph_stats

        baseline, baseline_stats = run(False)
        optimized, optimized_stats = run(True)

        semantic_fields = (
            "api_name", "api_signature", "analysis_status", "reason_code",
            "call_paths", "evidence_paths", "path_details", "hops",
            "confidence_score", "match_provenance", "match_tier",
        )
        baseline_fingerprint = [
            {field: getattr(result, field) for field in semantic_fields}
            for result in baseline
        ]
        optimized_fingerprint = [
            {field: getattr(result, field) for field in semantic_fields}
            for result in optimized
        ]
        self.assertEqual(baseline_fingerprint, optimized_fingerprint)
        self.assertTrue(all(result.analysis_status == "reachable" for result in optimized))

        with tempfile.TemporaryDirectory() as tmp:
            baseline_dir = Path(tmp) / "baseline"
            optimized_dir = Path(tmp) / "optimized"
            formatter.generate_enhanced_summary(baseline, baseline_dir)
            formatter.generate_enhanced_summary(optimized, optimized_dir)
            self.assertEqual(
                (baseline_dir / "alerts.csv").read_bytes(),
                (optimized_dir / "alerts.csv").read_bytes(),
            )

        baseline_perf = baseline_stats["step5_perf"]["trace"]
        optimized_perf = optimized_stats["step5_perf"]["trace"]
        self.assertEqual(1, optimized_perf["multi_target_group_count"])
        self.assertEqual(4, optimized_perf["multi_target_target_count"])
        self.assertGreaterEqual(optimized_perf["multi_target_shared_key_count"], 1)
        self.assertGreater(optimized_perf["reverse_transition_cache_hits"], 0)
        self.assertLess(
            optimized_perf["incoming_edges_scanned"],
            baseline_perf["incoming_edges_scanned"],
        )

    def test_multi_target_reverse_transition_work_scales_linearly_at_1x_2x_4x(self):
        observed = []
        for scale in (1, 2, 4):
            apis, graph, type_metadata = self._shared_predecessor_batch_fixture(scale)
            graph_stats = {}
            with patch.object(
                tracer, "_build_packaged_runtime_dependency_scan_cache"
            ), patch.object(
                tracer, "_build_identical_current_class_provider_index", return_value={}
            ), patch.object(
                tracer, "collect_graph_analyzer_edges"
            ), patch.object(
                tracer, "write_analyzer_edge_ledger"
            ), patch.object(
                tracer, "_emit_step5_perf_summary"
            ):
                results = tracer.trace_all_apis_with_confidence_weighting(
                    apis,
                    graph,
                    type_metadata,
                    graph_stats=graph_stats,
                )
            perf = graph_stats["step5_perf"]["trace"]
            observed.append((
                scale,
                perf["reverse_transition_edges_materialized"],
                perf.get("multi_target_shared_key_count", 0),
            ))
            self.assertEqual(scale, len(results))
            self.assertTrue(all(result.analysis_status == "reachable" for result in results))

        self.assertEqual([1, 2, 4], [item[0] for item in observed])
        self.assertEqual([3, 5, 9], [item[1] for item in observed])
        self.assertEqual(0, observed[0][2])
        self.assertGreaterEqual(observed[1][2], 1)
        self.assertGreaterEqual(observed[2][2], 1)

    def test_framework_api_requires_bridge_when_no_direct_business_usage_exists(self):
        requirements = step5.check_apis_that_need_bridge(
            [
                {
                    "coord": "org.springframework:spring-web",
                    "api_name": "org.springframework.web.method.support.HandlerMethodArgumentResolver.resolveArgument",
                    "api_simple": "resolveArgument",
                    "api_signature": "(MethodParameter, ModelAndViewContainer, NativeWebRequest, WebDataBinderFactory)",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                }
            ],
            report_dir=".",
            source_dirs=["src/main/java"],
            business_graph=SimpleNamespace(reverse_edges={}, methods_by_id={}),
            dependency_source_mappings=[],
            business_graph_stats={
                "truncated": False,
                "parser_fallback_reasons": {},
                "edge_cap_hits": 0,
            },
        )

        info = next(iter(requirements.values()))
        self.assertTrue(info["needs_bridge"])
        self.assertEqual(info["reason"], "no_direct_call_found")
        self.assertFalse(info["has_dependency_source_mapping"])

    def test_step5_main_reports_unhandled_exception_traceback(self):
        stderr = io.StringIO()
        with patch.object(step5, "step5_integrated_main", side_effect=RuntimeError("boom")):
            with patch.object(sys, "argv", ["step5"]):
                with redirect_stderr(stderr):
                    exit_code = step5.main()

        output = stderr.getvalue()
        self.assertEqual(exit_code, 1)
        self.assertIn("Step 5 执行失败：发生未捕获异常", output)
        self.assertIn("RuntimeError", output)
        self.assertIn("boom", output)
        self.assertIn("Traceback", output)

    def test_infer_step5_report_dir_prefers_all_changed_apis_parent(self):
        args = SimpleNamespace(
            report_dir="",
            all_changed_apis="/tmp/demo/.upgrade-report/evidence/api_changes/all_changed_apis.csv",
            output_dir="/tmp/other/evidence/call_chain",
        )

        self.assertEqual(
            step5.infer_step5_report_dir(args),
            "/tmp/demo/.upgrade-report",
        )

    def test_infer_step5_report_dir_falls_back_to_output_dir_parent(self):
        args = SimpleNamespace(
            report_dir="",
            all_changed_apis="",
            output_dir="/tmp/demo/.upgrade-report/evidence/call_chain",
        )

        self.assertEqual(
            step5.infer_step5_report_dir(args),
            "/tmp/demo/.upgrade-report",
        )

    def test_main_leaves_report_dir_empty_when_cli_omits_flag(self):
        captured = {}

        def fake_step5_main(args):
            captured["report_dir"] = args.report_dir
            return 0

        with patch.object(step5, "step5_integrated_main", side_effect=fake_step5_main):
            with patch.object(
                sys,
                "argv",
                [
                    "step5",
                    "--all-changed-apis",
                    "/tmp/demo/.upgrade-report/evidence/api_changes/all_changed_apis.csv",
                    "--output-dir",
                    "/tmp/demo/.upgrade-report/evidence/call_chain",
                    "--source-dirs",
                    "/tmp/demo/src/main/java",
                ],
            ):
                exit_code = step5.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(captured["report_dir"], "")

    def test_step5_auto_degrades_when_dependency_source_mapping_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            output_dir = self._call_chain_dir(report_dir)
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            output_dir.mkdir(parents=True)
            all_changed_apis = self._api_changes_dir(report_dir) / "all_changed_apis.csv"
            self._write_text(all_changed_apis, "coord,api_name\ncom.example:demo,com.example.Target.call\n", encoding="utf-8")

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
            stdout = io.StringIO()
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
            }

            with patch.object(step5, "auto_discover_bridge_sources", return_value={"dependency_source_mappings": []}), \
                 patch.object(step5, "load_changed_apis", return_value=[{"coord": "com.example:demo", "api_name": "com.example.Target.call"}]), \
                 patch.object(step5, "build_runtime_dependency_catalog", return_value={
                     "by_coord": {},
                     "entries": [],
                     "status": "complete",
                 }), \
                 patch.object(step5, "fatal_business_bytecode_failures", return_value=[]), \
                 patch.object(step5, "build_enhanced_source_graph", return_value=graph_result), \
                 patch.object(
                     step5,
                     "check_apis_that_need_bridge",
                     return_value={
                         "com.example:demo:com.example.Target.call": {
                             "needs_bridge": True,
                             "coord": "com.example:demo",
                             "has_dependency_source_mapping": False,
                         }
                     },
                ):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    exit_code = step5.step5_integrated_main(args)
                self.assertEqual(exit_code, 0)
                self.assertIn("缺失映射的依赖坐标：com.example:demo", stderr.getvalue())
                self.assertIn("不会要求用户批准降级", stderr.getvalue())

                stdout_lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
                self.assertFalse(
                    any(line.startswith(step5.STEP_INTERACTION_PREFIX) for line in stdout_lines)
                )

                details_path = output_dir / "missing_dependency_source_mappings.json"
                self.assertTrue(details_path.exists())
                details = json.loads(details_path.read_text(encoding="utf-8"))
                self.assertEqual(details.get("status"), "degraded")
                self.assertEqual(
                    details.get("reason_code"),
                    "STEP5_DEPENDENCY_SOURCE_MAPPING_MISSING",
                )
                self.assertEqual(
                    details.get("reason_code_aliases"),
                    ["step5_dependency_source_mapping_missing"],
                )
                self.assertEqual(details.get("origin_step"), "step5")
                self.assertEqual(
                    details.get("resolution"),
                    "continue_with_final_artifact_bytecode_and_restricted_conclusion",
                )
                self.assertEqual(details.get("missing_mapping_count"), 1)
                self.assertEqual(details.get("missing_mapping_coords"), ["com.example:demo"])

    def test_gate_allows_step4_timeout_in_standard_mode_and_blocks_strict_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            api_dir = self._api_changes_dir(report_dir)
            api_dir.mkdir(parents=True)
            (api_dir / "all_changed_apis.csv").write_text(
                "coord,api_name\ncom.example:demo,com.example.Api.run\n",
                encoding="utf-8",
            )
            (api_dir / "git_ref_matches.txt").write_text("complete\n", encoding="utf-8")
            (api_dir / "git_ref_matches.json").write_text("{}\n", encoding="utf-8")
            (api_dir / "git_ref_pending.json").write_text('{"items": []}\n', encoding="utf-8")
            (api_dir / "timeouts.json").write_text(
                json.dumps({"items": [{"coord": "com.example:demo", "stage": "japicmp"}]}),
                encoding="utf-8",
            )

            gate.gate_jar_compare(str(report_dir), strict_risk_gate=False)
            with self.assertRaises(SystemExit) as raised:
                gate.gate_jar_compare(str(report_dir), strict_risk_gate=True)

        self.assertEqual(raised.exception.code, 1)

    def test_step5_main_infers_report_dir_from_all_changed_apis(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            output_dir = self._call_chain_dir(report_dir)
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            output_dir.mkdir(parents=True)
            all_changed_apis = self._api_changes_dir(report_dir) / "all_changed_apis.csv"
            self._write_text(all_changed_apis, "coord,api_name\ncom.example:demo,com.example.Target.call\n", encoding="utf-8")
            self._write_text(
                self._dependencies_dir(report_dir) / "deps_current_resolved.csv",
                "coord,version,scope\nsample:consumer,1.0.0,packaged\n",
                encoding="utf-8",
            )

            args = SimpleNamespace(
                report_dir="",
                output_dir=str(output_dir),
                all_changed_apis=str(all_changed_apis),
                source_dirs=[str(source_dir)],
                dependency_source_mappings=[],
                allow_degraded=True,
                jdk_scan_dir="",
                max_methods=None,
                max_depth=1,
                debug_analysis=False,
                debug_break=False,
            )

            graph_result = {
                "graph": SimpleNamespace(reverse_edges={}, methods_by_id={}),
                "type_metadata": {},
                "stats": {
                    "parser_usage": {},
                    "parser_fallback_reasons": {},
                    "truncated": False,
                    "edge_cap_hits": 0,
                },
            }
            captured_bridge = {}

            def fake_check_bridge(*_args, **kwargs):
                captured_bridge["runtime_catalog"] = kwargs.get("runtime_dependency_catalog")
                return {
                    ("com.example:demo", "com.example.Target.call", "", "method", "REMOVED"): {
                        "needs_bridge": True,
                        "coord": "com.example:demo",
                        "has_dependency_source_mapping": False,
                        "has_packaged_bytecode_fallback": True,
                    }
                }

            fake_result = SimpleNamespace(
                api_name="com.example.Target.call",
                api_signature="",
                coord="com.example:demo",
                analysis_status="uncertain",
                reason_code="PACKAGED_DEPENDENCY_BYTECODE_USAGE",
                call_paths=[],
                evidence_paths=[],
                severity="P1",
                source="validation",
                change_type="REMOVED",
                api_simple="call",
                symbol_kind="method",
                confirmed=True,
                direct_callers=0,
                is_reachable=None,
                reachable_note="",
                business_reach_depth=0,
                dependency_chain_coords=["sample:consumer"],
                verification_commands=[],
                hops=[],
                confidence_score=1.0,
                critical_nodes_hit=[],
                match_provenance="",
                match_tier=-1,
            )

            with patch.object(step5, "auto_discover_bridge_sources", return_value={"dependency_source_mappings": []}), \
                 patch.object(step5, "load_changed_apis", return_value=[{
                     "coord": "com.example:demo",
                     "api_name": "com.example.Target.call",
                     "api_signature": "",
                     "symbol_kind": "method",
                     "change_type": "REMOVED",
                 }]), \
                 patch.object(step5, "build_enhanced_source_graph", return_value=graph_result), \
                 patch.object(step5, "check_apis_that_need_bridge", side_effect=fake_check_bridge), \
                 patch.object(step5, "build_runtime_dependency_catalog", return_value={
                     "by_coord": {
                         "sample:consumer": {
                             "coord": "sample:consumer",
                             "version": "1.0.0",
                             "scope": "packaged",
                             "jar_path": "/tmp/sample-consumer.jar",
                             "evidence_source": "current_final_artifact",
                         },
                     },
                     "entries": [],
                     "status": "complete",
                 }), \
                 patch.object(step5, "fatal_business_bytecode_failures", return_value=[]), \
                 patch.object(step5, "trace_all_apis_with_confidence_weighting", return_value=[fake_result]), \
                 patch.object(step5, "generate_enhanced_summary", return_value=None):
                exit_code = step5.step5_integrated_main(args)

            self.assertEqual(exit_code, 0)
            self.assertTrue(captured_bridge["runtime_catalog"]["by_coord"])
            self.assertIn("sample:consumer", captured_bridge["runtime_catalog"]["by_coord"])

    def test_step5_reuses_business_analysis_cache_when_building_full_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            output_dir = self._call_chain_dir(report_dir)
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            output_dir.mkdir(parents=True)
            dep_source_dir = project_dir / "deps" / "demo-lib" / "src" / "main" / "java"
            dep_source_dir.mkdir(parents=True)
            all_changed_apis = self._api_changes_dir(report_dir) / "all_changed_apis.csv"
            self._write_text(all_changed_apis, "coord,api_name\ncom.example:demo,com.example.Target.call\n", encoding="utf-8")

            args = SimpleNamespace(
                report_dir=str(report_dir),
                output_dir=str(output_dir),
                all_changed_apis=str(all_changed_apis),
                source_dirs=[str(source_dir)],
                dependency_source_mappings=[f"com.example:demo={dep_source_dir}"],
                allow_degraded=False,
                jdk_scan_dir="",
                max_methods=None,
                max_depth=5,
            )

            business_root = {
                "root": str(source_dir),
                "owner_type": "business",
                "owner_coord": "BUSINESS",
                "module": "java",
            }
            dependency_root = {
                "root": str(dep_source_dir),
                "owner_type": "dependency",
                "owner_coord": "com.example:demo",
                "module": "java",
            }
            business_graph_result = {
                "graph": SimpleNamespace(reverse_edges={}, methods_by_id={}),
                "type_metadata": {},
                "stats": {
                    "parser_usage": {},
                    "parser_fallback_reasons": {},
                    "truncated": False,
                    "edge_cap_hits": 0,
                },
                "analysis_cache": [{"file_path": str(source_dir / "App.java"), "root": business_root}],
            }
            full_graph_result = {
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
            build_calls = []

            def fake_build_graph(roots, **kwargs):
                build_calls.append((roots, kwargs))
                if len(build_calls) == 1:
                    return business_graph_result
                return full_graph_result

            with patch.object(step5, "auto_discover_bridge_sources"), \
                 patch.object(step5, "load_changed_apis", return_value=[{"coord": "com.example:demo", "api_name": "com.example.Target.call"}]), \
                 patch.object(step5, "build_runtime_dependency_catalog", return_value={
                     "by_coord": {},
                     "entries": [],
                     "status": "complete",
                 }), \
                 patch.object(step5, "fatal_business_bytecode_failures", return_value=[]), \
                 patch.object(step5, "align_dependency_source_mappings", return_value={
                     "mappings": [f"com.example:demo={dep_source_dir}"],
                     "allowed_classes_by_coord": {"com.example:demo": {"com.example.Target"}},
                     "records": [{"coord": "com.example:demo", "status": "aligned"}],
                     "evidence_path": str(output_dir / "dependency_source_alignment.json"),
                 }), \
                 patch.object(step5, "build_source_roots", side_effect=[[business_root], [business_root, dependency_root]]), \
                 patch.object(step5, "build_enhanced_source_graph", side_effect=fake_build_graph), \
                 patch.object(step5, "check_apis_that_need_bridge", return_value={}), \
                 patch.object(step5, "build_jar_metadata_for_source_roots", return_value={"jar_paths": {}, "by_coord": {}, "by_class": {}}), \
                 patch.object(step5, "trace_all_apis_with_confidence_weighting", return_value=[]), \
                 patch.object(step5, "generate_enhanced_summary"):
                exit_code = step5.step5_integrated_main(args)

            self.assertEqual(exit_code, 0)
            self.assertEqual(len(build_calls), 2)
            self.assertEqual(build_calls[0][0], [business_root])
            self.assertEqual(build_calls[1][0], [dependency_root])
            self.assertIs(build_calls[1][1].get("reused_analysis"), business_graph_result["analysis_cache"])
            self.assertTrue(build_calls[0][1].get("retain_analysis_cache"))
            self.assertFalse(build_calls[1][1].get("retain_analysis_cache"))
            self.assertEqual(
                build_calls[1][1].get("allowed_dependency_classes_by_coord"),
                {"com.example:demo": {"com.example.Target"}},
            )

    def test_step5_filters_dependency_sources_before_building_full_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            output_dir = self._call_chain_dir(report_dir)
            source_dir = project_dir / "src" / "main" / "java"
            used_dep_dir = project_dir / "deps" / "used" / "src" / "main" / "java"
            unused_dep_dir = project_dir / "deps" / "unused" / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            used_dep_dir.mkdir(parents=True)
            unused_dep_dir.mkdir(parents=True)
            output_dir.mkdir(parents=True)
            all_changed_apis = self._api_changes_dir(report_dir) / "all_changed_apis.csv"
            self._write_text(all_changed_apis, "coord,api_name\ncom.vendor:target,com.vendor.Target.call\n", encoding="utf-8")

            args = SimpleNamespace(
                report_dir=str(report_dir),
                output_dir=str(output_dir),
                all_changed_apis=str(all_changed_apis),
                source_dirs=[str(source_dir)],
                dependency_source_mappings=[
                    f"com.example:used={used_dep_dir}",
                    f"com.example:unused={unused_dep_dir}",
                ],
                allow_degraded=False,
                jdk_scan_dir="",
                max_methods=None,
                max_depth=5,
            )

            business_root = {
                "root": str(source_dir),
                "owner_type": "business",
                "owner_coord": "BUSINESS",
                "module": "java",
            }
            used_root = {
                "root": str(used_dep_dir),
                "owner_type": "dependency",
                "owner_coord": "com.example:used",
                "module": "java",
            }
            dependency_mapping_args = []
            business_graph_result = {
                "graph": SimpleNamespace(reverse_edges={}, methods_by_id={}),
                "type_metadata": {},
                "stats": {"parser_usage": {}, "parser_fallback_reasons": {}, "truncated": False, "edge_cap_hits": 0},
                "analysis_cache": [],
            }
            full_graph_result = {
                "graph": SimpleNamespace(reverse_edges={}, methods_by_id={}),
                "type_metadata": {},
                "stats": {"parser_usage": {}, "parser_fallback_reasons": {}, "truncated": False, "edge_cap_hits": 0},
                "analysis_cache": [],
            }

            def fake_build_source_roots(source_dirs_arg, dependency_mappings_arg):
                dependency_mapping_args.append(list(dependency_mappings_arg or []))
                if dependency_mappings_arg:
                    return [business_root, used_root]
                return [business_root]

            with patch.object(step5, "auto_discover_bridge_sources"), \
                 patch.object(step5, "load_changed_apis", return_value=[{"coord": "com.vendor:target", "api_name": "com.vendor.Target.call"}]), \
                 patch.object(step5, "build_runtime_dependency_catalog", return_value={
                     "by_coord": {
                         "com.example:used": {"coord": "com.example:used"}
                     },
                     "entries": [],
                     "status": "complete",
                 }), \
                 patch.object(step5, "fatal_business_bytecode_failures", return_value=[]), \
                 patch.object(step5, "align_dependency_source_mappings", return_value={
                     "mappings": [f"com.example:used={used_dep_dir}"],
                     "allowed_classes_by_coord": {"com.example:used": {"com.example.Used"}},
                     "records": [{"coord": "com.example:used", "status": "aligned"}],
                     "evidence_path": str(output_dir / "dependency_source_alignment.json"),
                 }), \
                 patch.object(step5, "build_source_roots", side_effect=fake_build_source_roots), \
                 patch.object(step5, "build_enhanced_source_graph", side_effect=[business_graph_result, full_graph_result]), \
                 patch.object(step5, "check_apis_that_need_bridge", return_value={}), \
                 patch.object(step5, "build_jar_metadata_for_source_roots", return_value={"jar_paths": {}, "by_coord": {}, "by_class": {}}), \
                 patch.object(step5, "trace_all_apis_with_confidence_weighting", return_value=[]), \
                 patch.object(step5, "generate_enhanced_summary"):
                exit_code = step5.step5_integrated_main(args)

            self.assertEqual(exit_code, 0)
            self.assertEqual(
                dependency_mapping_args,
                [
                    [],
                    [f"com.example:used={used_dep_dir}"],
                ],
            )

    def test_business_source_graph_excludes_classes_absent_from_final_business_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "checkout"
            app = source_root / "application" / "src" / "main" / "java" / "app" / "App.java"
            library = source_root / "library" / "src" / "main" / "java" / "library" / "Library.java"
            app.parent.mkdir(parents=True)
            library.parent.mkdir(parents=True)
            app.write_text("package app; public class App { void run() {} }", encoding="utf-8")
            library.write_text("package library; public class Library { void removed() {} }", encoding="utf-8")

            graph_result = step5.build_enhanced_source_graph(
                [{
                    "root": str(source_root),
                    "owner_type": "business",
                    "owner_coord": "BUSINESS",
                    "module": "checkout",
                }],
                allowed_business_classes={"app.App"},
            )

        classes = {method.class_fqcn for method in graph_result["graph"].methods_by_id.values()}
        self.assertEqual(classes, {"app.App"})

    def test_build_enhanced_source_graph_can_drop_analysis_cache_for_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example"
            business_dir.mkdir(parents=True)
            (business_dir / "App.java").write_text(
                "package com.example;\npublic class App { void call() {} }\n",
                encoding="utf-8",
            )
            business_root = {
                "root": str(business_dir.parent.parent.parent),
                "owner_type": "business",
                "owner_coord": "BUSINESS",
                "module": "app",
            }

            graph_result = step5.build_enhanced_source_graph(
                [business_root],
                retain_analysis_cache=False,
            )

            self.assertIn("graph", graph_result)
            self.assertIn("type_metadata", graph_result)
            self.assertEqual(graph_result["analysis_cache"], [])

    def test_build_enhanced_source_graph_shares_class_resolution_indexes_across_methods(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            source_dir.mkdir(parents=True)
            (source_dir / "App.java").write_text(
                "package com.example; public class App { void first() {} void second() {} }",
                encoding="utf-8",
            )
            graph_result = step5.build_enhanced_source_graph([{
                "root": str(source_dir.parent.parent.parent),
                "owner_type": "business",
                "owner_coord": "BUSINESS",
                "module": "app",
            }])
            methods = [
                method for method in graph_result["graph"].methods_by_id.values()
                if method.class_fqcn == "com.example.App"
            ]

            self.assertGreaterEqual(len(methods), 2)
            shared_simple_index = methods[0].known_classes_by_simple
            shared_fqcn_index = methods[0].known_class_fqcns
            self.assertTrue(all(method.known_classes_by_simple is shared_simple_index for method in methods[1:]))
            self.assertTrue(all(method.known_class_fqcns is shared_fqcn_index for method in methods[1:]))
            self.assertIsInstance(shared_simple_index["App"], tuple)
            self.assertIn("com.example.App", shared_simple_index["App"])

    def test_build_jar_metadata_for_source_roots_defers_javap_until_class_is_needed(self):
        source_roots = [
            {
                "root": "/tmp/demo",
                "owner_type": "dependency",
                "owner_coord": "com.example:demo",
                "module": "demo",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "demo.jar"
            with zipfile.ZipFile(jar_path, "w"):
                pass
            runtime_catalog = {"by_coord": {
                "com.example:demo": {
                    "coord": "com.example:demo",
                    "version": "1.0.0",
                    "jar_path": str(jar_path),
                    "evidence_source": "current_final_artifact",
                },
            }}
            with patch.object(step5, "_run_javap_for_class") as mocked_javap:
                metadata = step5.build_jar_metadata_for_source_roots(
                    source_roots,
                    ".",
                    runtime_dependency_catalog=runtime_catalog,
                )

        self.assertEqual(metadata["jar_paths"], {"com.example:demo": str(jar_path)})
        self.assertEqual(metadata["by_class"], {})
        self.assertEqual(metadata["by_coord"]["com.example:demo"]["classes"], {})
        mocked_javap.assert_not_called()

    def test_hydrate_jar_metadata_for_classes_loads_only_targeted_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "demo.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr("com/example/Target.class", b"")
                zf.writestr("com/example/Unused.class", b"")

            metadata = {
                "by_coord": {
                    "com.example:demo": {
                        "coord": "com.example:demo",
                        "version": "1.0.0",
                        "jar_path": str(jar_path),
                        "classes": {},
                    }
                },
                "by_class": {},
                "jar_paths": {"com.example:demo": str(jar_path)},
            }

            javap_output = "\n".join(
                [
                    'Compiled from "Target.java"',
                    "public interface com.example.Target {",
                    "  public abstract void call();",
                    "    descriptor: ()V",
                    "}",
                ]
            )

            with patch.object(step5, "_run_javap_for_class", return_value=javap_output) as mocked_javap:
                step5.hydrate_jar_metadata_for_classes(metadata, {"com.example.Target"})

            self.assertIn("com.example.Target", metadata["by_class"])
            self.assertNotIn("com.example.Unused", metadata["by_class"])
            mocked_javap.assert_called_once_with(str(jar_path), "com.example.Target")

    def test_hydrate_jar_metadata_maps_javap_failure_to_blocking_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "demo.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr("com/example/Target.class", b"")
            metadata = {
                "complete": True,
                "failures": [],
                "by_coord": {"com.example:demo": {
                    "coord": "com.example:demo",
                    "version": "1.0.0",
                    "jar_path": str(jar_path),
                    "classes": {},
                }},
                "by_class": {},
                "jar_paths": {"com.example:demo": str(jar_path)},
            }

            with patch.object(step5, "run_cmd", return_value=("", "javap failed", 7)):
                step5.hydrate_jar_metadata_for_classes(
                    metadata, {"com.example.Target"}
                )
            graph_result = step5.build_enhanced_source_graph([], jar_metadata=metadata)

        self.assertFalse(metadata["complete"])
        self.assertEqual(len(metadata["failures"]), 1)
        failure = metadata["failures"][0]
        self.assertEqual(
            failure["reason_code"], "STEP5_JAR_METADATA_JAVAP_NONZERO_EXIT"
        )
        self.assertEqual(failure["stage"], "step5.jar-metadata.javap")
        self.assertEqual(failure["command"][0], "javap")
        self.assertEqual(failure["timeout_seconds"], 30.0)
        self.assertEqual(failure["stderr"], "javap failed")
        self.assertTrue(failure["blocking"])
        self.assertEqual(
            graph_result["stats"]["parser_fallback_reasons"],
            {"jar_metadata_tool_failure": 1},
        )
        projected = graph_result["graph"].step5_evidence_failures[0]
        self.assertEqual(projected.reason_code, failure["reason_code"])
        self.assertEqual(projected.stage, failure["stage"])
        self.assertTrue(projected.blocking)

    def test_build_enhanced_source_graph_hydrates_only_referenced_jar_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            source_dir.mkdir(parents=True)
            (source_dir / "App.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import com.vendor.ExternalService;",
                        "",
                        "public class App {",
                        "    private ExternalService service;",
                        "",
                        "    public void run() {",
                        "        service.call();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            jar_path = Path(tmp) / "vendor.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr("com/vendor/ExternalService.class", b"")
                zf.writestr("com/vendor/Unused.class", b"")

            jar_metadata = {
                "by_coord": {
                    "com.vendor:demo": {
                        "coord": "com.vendor:demo",
                        "version": "1.0.0",
                        "jar_path": str(jar_path),
                        "classes": {},
                    }
                },
                "by_class": {},
                "jar_paths": {"com.vendor:demo": str(jar_path)},
            }
            source_roots = [
                {
                    "root": str(source_dir.parent.parent.parent),
                    "owner_type": "business",
                    "owner_coord": "BUSINESS",
                    "module": "app",
                }
            ]

            javap_output = "\n".join(
                [
                    'Compiled from "ExternalService.java"',
                    "public interface com.vendor.ExternalService {",
                    "  public abstract void call();",
                    "    descriptor: ()V",
                    "}",
                ]
            )

            with patch.object(step5, "_run_javap_for_class", return_value=javap_output) as mocked_javap:
                graph_result = step5.build_enhanced_source_graph(source_roots, jar_metadata=jar_metadata)

            self.assertTrue(graph_result["graph"].methods_by_id)
            self.assertIn("com.vendor.ExternalService", jar_metadata["by_class"])
            self.assertNotIn("com.vendor.Unused", jar_metadata["by_class"])
            mocked_javap.assert_called_once_with(str(jar_path), "com.vendor.ExternalService")

    def test_build_enhanced_source_graph_preserves_local_return_type_maps_per_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            source_dir.mkdir(parents=True)
            (source_dir / "Demo.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "public class Demo {",
                        "    public String foo(String value) {",
                        "        return value;",
                        "    }",
                        "",
                        "    public Integer foo(Integer value) {",
                        "        return value;",
                        "    }",
                        "",
                        "    public String bar() {",
                        "        return foo(\"x\");",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (source_dir / "Helper.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "public class Helper {",
                        "    public Long foo(Long value) {",
                        "        return value;",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            source_roots = [
                {
                    "root": str(source_dir.parent.parent.parent),
                    "owner_type": "business",
                    "owner_coord": "BUSINESS",
                    "module": "app",
                }
            ]

            graph_result = step5.build_enhanced_source_graph(source_roots)
            methods = list(graph_result["graph"].methods_by_id.values())
            demo_method = next(
                method for method in methods if method.class_fqcn == "com.example.Demo" and method.method_name == "bar"
            )
            helper_method = next(
                method for method in methods if method.class_fqcn == "com.example.Helper" and method.method_name == "foo"
            )

            self.assertEqual(
                demo_method.local_method_return_types["foo"],
                {
                    "(String)": "java.lang.String",
                    "(Integer)": "java.lang.Integer",
                },
            )
            self.assertEqual(demo_method.local_method_return_types["bar"], {"()": "java.lang.String"})
            self.assertEqual(helper_method.local_method_return_types["foo"], {"(Long)": "java.lang.Long"})
            self.assertNotIn("(Long)", demo_method.local_method_return_types["foo"])

    def test_build_enhanced_source_graph_prefers_tree_sitter_for_all_java_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example"
            dependency_dir = Path(tmp) / "dependency" / "com" / "vendor"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)
            (business_dir / "App.java").write_text("package com.example; public class App {}", encoding="utf-8")
            (dependency_dir / "Lib.java").write_text("package com.vendor; public class Lib {}", encoding="utf-8")
            source_roots = [
                {
                    "root": str(business_dir.parent.parent.parent),
                    "owner_type": "business",
                    "owner_coord": "BUSINESS",
                    "module": "app",
                },
                {
                    "root": str(dependency_dir.parent.parent),
                    "owner_type": "dependency",
                    "owner_coord": "com.vendor:lib",
                    "module": "lib",
                },
            ]
            calls = []

            def fake_analyze_file(file_path, root, prefer_tree_sitter=True, return_diagnostics=False):
                _ = return_diagnostics
                calls.append((Path(file_path).name, root["owner_type"], prefer_tree_sitter))
                return [], {"actual_parser": "regex", "fallback_reason": None}

            with patch.object(step5, "analyze_file", side_effect=fake_analyze_file):
                step5.build_enhanced_source_graph(source_roots)

            self.assertIn(("App.java", "business", True), calls)
            self.assertIn(("Lib.java", "dependency", True), calls)

    def test_build_enhanced_source_graph_reuses_cached_business_file_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "vendor"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)
            (business_dir / "App.java").write_text("package com.example; public class App {}", encoding="utf-8")
            (dependency_dir / "Lib.java").write_text("package com.vendor; public class Lib {}", encoding="utf-8")
            business_root = {
                "root": str(business_dir.parent.parent.parent),
                "owner_type": "business",
                "owner_coord": "BUSINESS",
                "module": "app",
            }
            dependency_root = {
                "root": str(dependency_dir.parent.parent.parent),
                "owner_type": "dependency",
                "owner_coord": "com.vendor:lib",
                "module": "lib",
            }
            calls = []

            def fake_analyze_file(file_path, root, prefer_tree_sitter=True, return_diagnostics=False):
                _ = return_diagnostics
                calls.append((Path(file_path).name, root["owner_type"], prefer_tree_sitter))
                return [], {"actual_parser": "regex", "fallback_reason": None}

            with patch.object(step5, "analyze_file", side_effect=fake_analyze_file):
                business_graph = step5.build_enhanced_source_graph([business_root])
                step5.build_enhanced_source_graph(
                    [dependency_root],
                    reused_analysis=business_graph["analysis_cache"],
                )

            self.assertEqual(calls, [("App.java", "business", True), ("Lib.java", "dependency", True)])

    def test_dependency_source_mappings_are_filtered_to_current_runtime_catalog(self):
        mappings = [
            "/broken/mapping",
            "com.example:used=/tmp/used-src",
            "com.example:unused=/tmp/unused-src",
            "com.example:native=/tmp/native-src",
            "com.example:native:osx-ppc64=/tmp/wrong-native-src",
        ]
        catalog = {
            "by_coord": {
                "__business__": {"coord": "__business__"},
                "com.example:used": {"coord": "com.example:used"},
                "com.example:native:osx-aarch_64": {
                    "coord": "com.example:native:osx-aarch_64",
                },
                "com.example:native:osx-x86_64": {
                    "coord": "com.example:native:osx-x86_64",
                },
            }
        }

        filtered, skipped = step5.filter_dependency_source_mappings_for_runtime(mappings, catalog)

        self.assertEqual(
            filtered,
            [
                "com.example:used=/tmp/used-src",
                "com.example:native:osx-aarch_64=/tmp/native-src",
                "com.example:native:osx-x86_64=/tmp/native-src",
            ],
        )
        self.assertEqual(
            [item["reason"] for item in skipped],
            [
                "invalid_mapping_format",
                "dependency_source_not_in_current_runtime_catalog",
                "dependency_source_classifier_not_in_current_runtime_catalog",
            ],
        )
        self.assertEqual(skipped[1]["coord"], "com.example:unused")
        self.assertEqual(
            skipped[2]["coord"], "com.example:native:osx-ppc64"
        )

    def test_dependency_source_graph_does_not_index_simple_method_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "unused"
            dependency_dir.mkdir(parents=True)
            (dependency_dir / "UnusedAdapter.java").write_text(
                "\n".join(
                    [
                        "package com.unused;",
                        "public class UnusedAdapter {",
                        "    public boolean call(String value) {",
                        "        return removed(value);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            source_roots = [{
                "root": str(dependency_dir.parent.parent.parent),
                "owner_type": "dependency",
                "owner_coord": "com.example:unused",
                "module": "unused",
            }]

            graph_result = step5.build_enhanced_source_graph(source_roots)

            self.assertIn(
                "com.unused.UnusedAdapter.removed(String)",
                graph_result["graph"].reverse_edges,
            )
            self.assertNotIn("method:removed(String)", graph_result["graph"].reverse_edges)
            self.assertNotIn("method:removed", graph_result["graph"].reverse_edges)

    def test_dependency_source_graph_excludes_classes_missing_from_same_coord_jar(self):
        with tempfile.TemporaryDirectory() as tmp:
            dependency_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example"
            dependency_dir.mkdir(parents=True)
            (dependency_dir / "Packaged.java").write_text(
                "package com.example; public class Packaged { public void kept() {} }\n",
                encoding="utf-8",
            )
            (dependency_dir / "Unpackaged.java").write_text(
                "package com.example; public class Unpackaged { public void leaked() {} }\n",
                encoding="utf-8",
            )
            source_roots = [{
                "root": str(dependency_dir.parent.parent.parent),
                "owner_type": "dependency",
                "owner_coord": "com.example:dep",
                "module": "dep",
            }]

            graph_result = step5.build_enhanced_source_graph(
                source_roots,
                allowed_dependency_classes_by_coord={
                    "com.example:dep": {"com.example.Packaged"},
                },
            )
            methods = list(graph_result["graph"].methods_by_id.values())

            self.assertTrue(any(method.class_fqcn == "com.example.Packaged" for method in methods))
            self.assertFalse(any(method.class_fqcn == "com.example.Unpackaged" for method in methods))
            self.assertFalse(any("Unpackaged" in key for key in graph_result["graph"].reverse_edges))

    def test_dependency_source_class_allowlist_is_scoped_by_coordinate(self):
        with tempfile.TemporaryDirectory() as tmp:
            alpha_dir = Path(tmp) / "alpha" / "src" / "main" / "java" / "com" / "shared"
            beta_dir = Path(tmp) / "beta" / "src" / "main" / "java" / "com" / "shared"
            alpha_dir.mkdir(parents=True)
            beta_dir.mkdir(parents=True)
            (alpha_dir / "StringUtils.java").write_text(
                "package com.shared; public class StringUtils { public void alphaOnly() {} }\n",
                encoding="utf-8",
            )
            (beta_dir / "StringUtils.java").write_text(
                "package com.shared; public class StringUtils { public void betaOnly() {} }\n",
                encoding="utf-8",
            )
            source_roots = [
                {
                    "root": str(alpha_dir.parent.parent.parent),
                    "owner_type": "dependency",
                    "owner_coord": "com.example:alpha",
                    "module": "alpha",
                },
                {
                    "root": str(beta_dir.parent.parent.parent),
                    "owner_type": "dependency",
                    "owner_coord": "com.example:beta",
                    "module": "beta",
                },
            ]

            graph_result = step5.build_enhanced_source_graph(
                source_roots,
                allowed_dependency_classes_by_coord={
                    "com.example:alpha": {"com.shared.StringUtils"},
                    "com.example:beta": {"com.other.StringUtils"},
                },
            )
            methods = list(graph_result["graph"].methods_by_id.values())

            self.assertTrue(any(method.method_name == "alphaOnly" for method in methods))
            self.assertFalse(any(method.method_name == "betaOnly" for method in methods))

    def test_source_graph_lookup_keys_include_declared_fqcn_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example"
            business_dir.mkdir(parents=True)
            (business_dir / "OrderService.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "public class OrderService {",
                        "    public void submit(String orderId) { }",
                        "    public void submit(Integer orderId) { }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph([{
                "root": str(business_dir.parent.parent.parent),
                "owner_type": "business",
                "owner_coord": "BUSINESS",
                "module": "app",
            }])
            graph = graph_result["graph"]
            methods = [
                method for method in graph.methods_by_id.values()
                if method.qualified_key == "com.example.OrderService.submit"
            ]

            declared_keys = {
                method.declared_qualified_key
                for method in methods
            }
            lookup_keys = {
                key
                for method in methods
                for key in graph.lookup_keys_by_symbol.get(method.symbol_id, [])
            }

            self.assertEqual(
                {
                    "com.example.OrderService.submit(String)",
                    "com.example.OrderService.submit(Integer)",
                },
                declared_keys,
            )
            self.assertIn("com.example.OrderService.submit(String)", lookup_keys)
            self.assertIn("com.example.OrderService.submit(Integer)", lookup_keys)
            self.assertIn("method:submit(String)", lookup_keys)
            self.assertIn("method:submit(Integer)", lookup_keys)

    def test_dependency_method_edge_without_signature_is_not_indexed_as_confirmed_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "vendor"
            dependency_dir.mkdir(parents=True)
            (dependency_dir / "Adapter.java").write_text(
                "\n".join(
                    [
                        "package com.vendor;",
                        "public class Adapter {",
                        "    public void run() {",
                        "        Runnable r = this::missing;",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph([{
                "root": str(dependency_dir.parent.parent.parent),
                "owner_type": "dependency",
                "owner_coord": "com.vendor:adapter",
                "module": "adapter",
            }])

            self.assertNotIn("com.vendor.Adapter.missing", graph_result["graph"].reverse_edges)
            self.assertGreaterEqual(
                graph_result["stats"].get("dependency_method_edges_skipped_without_signature", 0),
                1,
            )

    def test_build_enhanced_source_graph_does_not_hydrate_dependency_only_external_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example"
            dependency_dir = Path(tmp) / "dependency" / "com" / "vendor"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)
            (business_dir / "App.java").write_text(
                "\n".join(
                    [
                        "package com.example;",
                        "",
                        "import com.vendor.ExternalService;",
                        "",
                        "public class App {",
                        "    private ExternalService service;",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "Lib.java").write_text(
                "\n".join(
                    [
                        "package com.vendor;",
                        "",
                        "import com.vendor.DependencyOnlyType;",
                        "",
                        "public class Lib {",
                        "    private DependencyOnlyType type;",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            jar_path = Path(tmp) / "vendor.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr("com/vendor/ExternalService.class", b"")
                zf.writestr("com/vendor/DependencyOnlyType.class", b"")
            jar_metadata = {
                "by_coord": {
                    "com.vendor:demo": {
                        "coord": "com.vendor:demo",
                        "version": "1.0.0",
                        "jar_path": str(jar_path),
                        "classes": {},
                    }
                },
                "by_class": {},
                "jar_paths": {"com.vendor:demo": str(jar_path)},
            }
            source_roots = [
                {
                    "root": str(business_dir.parent.parent.parent),
                    "owner_type": "business",
                    "owner_coord": "BUSINESS",
                    "module": "app",
                },
                {
                    "root": str(dependency_dir.parent.parent),
                    "owner_type": "dependency",
                    "owner_coord": "com.vendor:demo",
                    "module": "demo",
                },
            ]

            javap_outputs = {
                "com.vendor.ExternalService": "\n".join(
                    [
                        'Compiled from "ExternalService.java"',
                        "public interface com.vendor.ExternalService {",
                        "}",
                    ]
                ),
                "com.vendor.DependencyOnlyType": "\n".join(
                    [
                        'Compiled from "DependencyOnlyType.java"',
                        "public interface com.vendor.DependencyOnlyType {",
                        "}",
                    ]
                ),
            }

            with patch.object(
                step5,
                "_run_javap_for_class",
                side_effect=lambda jar, binary: javap_outputs.get(binary, ""),
            ) as mocked_javap:
                step5.build_enhanced_source_graph(source_roots, jar_metadata=jar_metadata)

            mocked_javap.assert_not_called()
            self.assertNotIn("com.vendor.ExternalService", jar_metadata["by_class"])
            self.assertNotIn("com.vendor.DependencyOnlyType", jar_metadata["by_class"])

    def test_trace_api_reaches_dependency_impl_via_unique_interface_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "service"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "UserController.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.service.UserService;",
                        "import com.example.service.UserServiceImpl;",
                        "",
                        "public class UserController {",
                        "    private final UserService userService = new UserServiceImpl();",
                        "",
                        "    public java.util.List<String> getAllUsers() {",
                        "        return userService.getAllUsers();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "UserService.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public interface UserService {",
                        "    java.util.List<String> getAllUsers();",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "UserServiceImpl.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public class UserServiceImpl implements UserService {",
                        "    @Override",
                        "    public java.util.List<String> getAllUsers() {",
                        '        return java.util.List.of("demo");',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:service",
                        "module": "service",
                    },
                ]
            )
            graph = graph_result["graph"]
            type_metadata = graph_result["type_metadata"]

            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:service",
                    "api_name": "com.example.service.UserServiceImpl.getAllUsers",
                    "api_simple": "getAllUsers",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph,
                type_metadata,
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")
            self.assertIn("UserController.getAllUsers", result.call_paths[0])

    def test_business_field_interface_call_is_resolved_to_fqcn_not_simple_method_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "service"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "CallCpsRepayApplyAction.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.service.RmbService;",
                        "import com.example.service.RmbServiceDef;",
                        "import com.example.service.SendMessageCtx;",
                        "import java.util.Map;",
                        "",
                        "public class CallCpsRepayApplyAction {",
                        "    @javax.annotation.Resource",
                        "    private RmbService rmbService;",
                        "",
                        "    public void callRmb(RmbServiceDef def, Map map, SendMessageCtx ctx) {",
                        "        rmbService.sendAndReceiveRMBMessage(def, map, ctx);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "RmbService.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "import java.util.Map;",
                        "",
                        "public interface RmbService {",
                        "    void sendAndReceiveRMBMessage(RmbServiceDef def, Map map, SendMessageCtx ctx);",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "BclfsRmbService.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "import java.util.Map;",
                        "",
                        "public class BclfsRmbService implements RmbService {",
                        "    public void sendAndReceiveRMBMessage(RmbServiceDef def, Map map, SendMessageCtx ctx) {",
                        "        new BclfsSendCpsMsgLowerCaseTrace().regTrace();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "BclfsSendCpsMsgLowerCaseTrace.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "import org.apache.commons.lang.StringUtils;",
                        "",
                        "public class BclfsSendCpsMsgLowerCaseTrace {",
                        "    public void regTrace() {",
                        '        StringUtils.equals("a", "b");',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "RmbServiceDef.java").write_text(
                "package com.example.service; public class RmbServiceDef {}\n",
                encoding="utf-8",
            )
            (dependency_dir / "SendMessageCtx.java").write_text(
                "package com.example.service; public class SendMessageCtx {}\n",
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:rmb-service",
                        "module": "rmb-service",
                    },
                ]
            )
            graph = graph_result["graph"]
            interface_call_key = (
                "com.example.service.RmbService."
                "sendAndReceiveRMBMessage(RmbServiceDef, Map, SendMessageCtx)"
            )

            self.assertIn(interface_call_key, graph.reverse_edges)
            business_edges = [
                edge
                for edge in graph.reverse_edges[interface_call_key]
                if edge.caller_qualified_key == "com.example.app.CallCpsRepayApplyAction.callRmb"
            ]
            self.assertEqual(1, len(business_edges))
            self.assertEqual("high", business_edges[0].confidence)
            self.assertEqual(interface_call_key, business_edges[0].callee_key)
            self.assertEqual(
                "method:sendAndReceiveRMBMessage(RmbServiceDef, Map, SendMessageCtx)",
                business_edges[0].callee_simple_key,
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "commons-lang:commons-lang",
                    "api_name": "org.apache.commons.lang.StringUtils.equals",
                    "api_simple": "equals",
                    "api_signature": "(String, String)",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "severity": "P0",
                    "confirmed": "true",
                    "source": "old_jar",
                    "analysis_scope": "method",
                },
                graph,
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual("reachable", result.analysis_status)
            self.assertEqual("SYSTEM_CODE_REACHED", result.reason_code)
            joined_paths = "\n".join(result.call_paths)
            self.assertIn("CallCpsRepayApplyAction.callRmb", joined_paths)
            self.assertIn("RmbService.sendAndReceiveRMBMessage", joined_paths)
            self.assertIn("BclfsRmbService.sendAndReceiveRMBMessage", joined_paths)
            self.assertIn("BclfsSendCpsMsgLowerCaseTrace.regTrace", joined_paths)
            self.assertIn("StringUtils.equals", joined_paths)

    def test_trace_api_keeps_upstream_business_chain_after_first_system_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example" / "chain"
            source_dir.mkdir(parents=True)

            (source_dir / "A.java").write_text(
                "\n".join(
                    [
                        "package com.example.chain;",
                        "",
                        "public class A {",
                        "    public String start() {",
                        "        B b = new B();",
                        "        return b.callB();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (source_dir / "B.java").write_text(
                "\n".join(
                    [
                        "package com.example.chain;",
                        "",
                        "public class B {",
                        "    public String callB() {",
                        "        C c = new C();",
                        "        return c.callC();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (source_dir / "C.java").write_text(
                "\n".join(
                    [
                        "package com.example.chain;",
                        "",
                        "public class C {",
                        "    public String callC() {",
                        "        D d = new D();",
                        "        return d.changed();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (source_dir / "D.java").write_text(
                "\n".join(
                    [
                        "package com.example.chain;",
                        "",
                        "public class D {",
                        "    public String changed() {",
                        '        return "changed";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(source_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]
            type_metadata = graph_result["type_metadata"]

            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:chain",
                    "api_name": "com.example.chain.D.changed",
                    "api_simple": "changed",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph,
                type_metadata,
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertTrue(
                any(
                    "com.example.chain.A.start" in item.get("path_text", "")
                    and "com.example.chain.B.callB" in item.get("path_text", "")
                    and "com.example.chain.C.callC" in item.get("path_text", "")
                    and "com.example.chain.D.changed" in item.get("path_text", "")
                    for item in getattr(result, "path_details", [])
                ),
                getattr(result, "path_details", []),
            )

    def test_trace_api_reaches_parent_method_via_super_and_skips_bridge_requirement(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example" / "people"
            source_dir.mkdir(parents=True)

            (source_dir / "Person.java").write_text(
                "\n".join(
                    [
                        "package com.example.people;",
                        "",
                        "public interface Person {",
                        "    String getName();",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (source_dir / "PersonBase.java").write_text(
                "\n".join(
                    [
                        "package com.example.people;",
                        "",
                        "public class PersonBase implements Person {",
                        "    public String getName() {",
                        '        return "base";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (source_dir / "Professor.java").write_text(
                "\n".join(
                    [
                        "package com.example.people;",
                        "",
                        "public class Professor extends PersonBase {",
                        "    @Override",
                        "    public String getName() {",
                        '        return "Prof-" + super.getName();',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (source_dir / "MainEntryClass.java").write_text(
                "\n".join(
                    [
                        "package com.example.people;",
                        "",
                        "public class MainEntryClass {",
                        "    public String run() {",
                        "        Person person = new Professor();",
                        "        return person.getName();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(source_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]
            type_metadata = graph_result["type_metadata"]
            api_row = {
                "coord": "sample:inheritance",
                "api_name": "com.example.people.PersonBase.getName",
                "api_simple": "getName",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "method_changed",
                "severity": "P1",
                "confirmed": "true",
                "source": "validation",
                "analysis_scope": "method",
            }

            result = tracer.trace_api_with_confidence_weighting(api_row, graph, type_metadata, max_total_cost=5)
            bridge_info = step5.check_apis_that_need_bridge([api_row], tmp, business_graph=graph)

            self.assertEqual(result.analysis_status, "reachable")
            self.assertEqual(bridge_info[tracer.build_api_identity_key(api_row)]["needs_bridge"], False)
            self.assertIn("Professor.getName", result.call_paths[0])

    def test_trace_api_reaches_inherited_parent_method_via_subclass_receiver(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example" / "inheritance"
            source_dir.mkdir(parents=True)

            (source_dir / "ParentService.java").write_text(
                "\n".join(
                    [
                        "package com.example.inheritance;",
                        "",
                        "public class ParentService {",
                        "    public String run() {",
                        '        return "ok";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (source_dir / "ChildService.java").write_text(
                "\n".join(
                    [
                        "package com.example.inheritance;",
                        "",
                        "public class ChildService extends ParentService {",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (source_dir / "MainEntryClass.java").write_text(
                "\n".join(
                    [
                        "package com.example.inheritance;",
                        "",
                        "public class MainEntryClass {",
                        "    public String run() {",
                        "        ChildService service = new ChildService();",
                        "        return service.run();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(source_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            graph = graph_result["graph"]
            type_metadata = graph_result["type_metadata"]

            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:inheritance",
                    "api_name": "com.example.inheritance.ParentService.run",
                    "api_simple": "run",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph,
                type_metadata,
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertIn("MainEntryClass.run", result.call_paths[0])

    def test_trace_api_reaches_fully_qualified_static_dependency_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "org" / "example" / "lib"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Client.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "public class Client {",
                        "    public int convert() {",
                        "        return org.example.lib.Converter.getFeet(10);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "Converter.java").write_text(
                "\n".join(
                    [
                        "package org.example.lib;",
                        "",
                        "public class Converter {",
                        "    public static int getFeet(int centimeters) {",
                        "        return centimeters / 30;",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:lib",
                        "module": "lib",
                    },
                ]
            )
            graph = graph_result["graph"]
            type_metadata = graph_result["type_metadata"]

            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:lib",
                    "api_name": "org.example.lib.Converter.getFeet",
                    "api_simple": "getFeet",
                    "api_signature": "(int)",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph,
                type_metadata,
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertIn("Client.convert", result.call_paths[0])

    def test_trace_api_reaches_dependency_method_when_local_variable_uses_lombok_val(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "app"
            base_dir = Path(tmp) / "base" / "src" / "main" / "java" / "base"
            common_dir = Path(tmp) / "common" / "src" / "main" / "java" / "common"
            business_dir.mkdir(parents=True)
            base_dir.mkdir(parents=True)
            common_dir.mkdir(parents=True)

            (business_dir / "Main.java").write_text(
                "\n".join(
                    [
                        "package app;",
                        "",
                        "import lombok.val;",
                        "",
                        "public class Main {",
                        "    public void main() {",
                        "        val app = new MyApp();",
                        "        app.doSomeProcess();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (business_dir / "MyApp.java").write_text(
                "\n".join(
                    [
                        "package app;",
                        "",
                        "import base.MyBase;",
                        "",
                        "public class MyApp extends MyBase {",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (base_dir / "MyBase.java").write_text(
                "\n".join(
                    [
                        "package base;",
                        "",
                        "import common.MyLibrary;",
                        "",
                        "public class MyBase {",
                        "    public void doSomeProcess() {",
                        "        MyLibrary.doSomeProcess();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (common_dir / "MyLibrary.java").write_text(
                "\n".join(
                    [
                        "package common;",
                        "",
                        "public class MyLibrary {",
                        "    public static void doSomeProcess() {",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(base_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:base",
                        "module": "base",
                    },
                    {
                        "root": str(common_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:common",
                        "module": "common",
                    },
                ]
            )
            graph = graph_result["graph"]
            type_metadata = graph_result["type_metadata"]

            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:common",
                    "api_name": "common.MyLibrary.doSomeProcess",
                    "api_simple": "doSomeProcess",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph,
                type_metadata,
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")
            self.assertIn("Main.main", result.call_paths[0])

    def test_trace_api_reaches_interface_target_when_multiple_implementations_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "service"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "UserController.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.service.UserService;",
                        "import com.example.service.UserServiceImplA;",
                        "",
                        "public class UserController {",
                        "    private final UserService userService = new UserServiceImplA();",
                        "",
                        "    public java.util.List<String> getAllUsers() {",
                        "        return userService.getAllUsers();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "UserService.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public interface UserService {",
                        "    java.util.List<String> getAllUsers();",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "UserServiceImplA.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public class UserServiceImplA implements UserService {",
                        "    @Override",
                        "    public java.util.List<String> getAllUsers() {",
                        '        return java.util.List.of("A");',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "UserServiceImplB.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public class UserServiceImplB implements UserService {",
                        "    @Override",
                        "    public java.util.List<String> getAllUsers() {",
                        '        return java.util.List.of("B");',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:service",
                        "module": "service",
                    },
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:service",
                    "api_name": "com.example.service.UserService.getAllUsers",
                    "api_simple": "getAllUsers",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertIn("UserController.getAllUsers", result.call_paths[0])

    def test_trace_api_does_not_attribute_interface_call_to_specific_impl_when_multiple_implementations_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "service"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "UserController.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.service.UserService;",
                        "import com.example.service.UserServiceImplA;",
                        "",
                        "public class UserController {",
                        "    private final UserService userService = new UserServiceImplA();",
                        "",
                        "    public java.util.List<String> getAllUsers() {",
                        "        return userService.getAllUsers();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "UserService.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public interface UserService {",
                        "    java.util.List<String> getAllUsers();",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "UserServiceImplA.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public class UserServiceImplA implements UserService {",
                        "    @Override",
                        "    public java.util.List<String> getAllUsers() {",
                        '        return java.util.List.of("A");',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "UserServiceImplB.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public class UserServiceImplB implements UserService {",
                        "    @Override",
                        "    public java.util.List<String> getAllUsers() {",
                        '        return java.util.List.of("B");',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:service",
                        "module": "service",
                    },
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:service",
                    "api_name": "com.example.service.UserServiceImplA.getAllUsers",
                    "api_simple": "getAllUsers",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "not_found_in_static_analysis")
            self.assertEqual(result.reason_code, "NO_STATIC_PATH")

    def test_check_apis_that_need_bridge_keeps_impl_target_on_ambiguous_interface_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            business_dir.mkdir(parents=True)
            (business_dir / "UserController.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.service.UserService;",
                        "",
                        "public class UserController {",
                        "    private UserService userService;",
                        "",
                        "    public java.util.List<String> getAllUsers() {",
                        "        return userService.getAllUsers();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            business_graph = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )["graph"]
            api_row = {
                "coord": "sample:service",
                "api_name": "com.example.service.UserServiceImplA.getAllUsers",
                "api_simple": "getAllUsers",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "method_changed",
                "severity": "P1",
                "confirmed": "true",
                "source": "validation",
                "analysis_scope": "method",
            }

            bridge_info = step5.check_apis_that_need_bridge([api_row], tmp, business_graph=business_graph)

            self.assertTrue(bridge_info[tracer.build_api_identity_key(api_row)]["needs_bridge"])
            self.assertFalse(bridge_info[tracer.build_api_identity_key(api_row)]["has_dependency_source_mapping"])

    def test_trace_api_does_not_reach_parent_method_when_child_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example" / "overridecase"
            source_dir.mkdir(parents=True)

            (source_dir / "ParentService.java").write_text(
                "\n".join(
                    [
                        "package com.example.overridecase;",
                        "",
                        "public class ParentService {",
                        "    public String run() {",
                        '        return "parent";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (source_dir / "ChildService.java").write_text(
                "\n".join(
                    [
                        "package com.example.overridecase;",
                        "",
                        "public class ChildService extends ParentService {",
                        "    @Override",
                        "    public String run() {",
                        '        return "child";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (source_dir / "MainEntryClass.java").write_text(
                "\n".join(
                    [
                        "package com.example.overridecase;",
                        "",
                        "public class MainEntryClass {",
                        "    public String run() {",
                        "        ChildService service = new ChildService();",
                        "        return service.run();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(source_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:inheritance",
                    "api_name": "com.example.overridecase.ParentService.run",
                    "api_simple": "run",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "not_found_in_static_analysis")
            self.assertEqual(result.reason_code, "NO_STATIC_PATH")

    def test_trace_api_reaches_parent_method_when_variable_declares_parent_type_and_child_does_not_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_dir = Path(tmp) / "src" / "main" / "java" / "com" / "example" / "parenttype"
            source_dir.mkdir(parents=True)

            (source_dir / "ParentService.java").write_text(
                "\n".join(
                    [
                        "package com.example.parenttype;",
                        "",
                        "public class ParentService {",
                        "    public String run() {",
                        '        return "ok";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (source_dir / "ChildService.java").write_text(
                "\n".join(
                    [
                        "package com.example.parenttype;",
                        "",
                        "public class ChildService extends ParentService {",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (source_dir / "MainEntryClass.java").write_text(
                "\n".join(
                    [
                        "package com.example.parenttype;",
                        "",
                        "public class MainEntryClass {",
                        "    public String run() {",
                        "        ParentService service = new ChildService();",
                        "        return service.run();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(source_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:inheritance",
                    "api_name": "com.example.parenttype.ParentService.run",
                    "api_simple": "run",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertIn("MainEntryClass.run", result.call_paths[0])

    def test_trace_api_does_not_misattribute_fully_qualified_static_call_to_sibling_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "org" / "example" / "lib"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Client.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "public class Client {",
                        "    public int convert() {",
                        "        return org.example.lib.Converter.getFeet(10);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "Converter.java").write_text(
                "\n".join(
                    [
                        "package org.example.lib;",
                        "",
                        "public class Converter {",
                        "    public static int getFeet(int centimeters) {",
                        "        return centimeters / 30;",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "OtherConverter.java").write_text(
                "\n".join(
                    [
                        "package org.example.lib;",
                        "",
                        "public class OtherConverter {",
                        "    public static int getFeet(int centimeters) {",
                        "        return centimeters;",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:lib",
                        "module": "lib",
                    },
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:lib",
                    "api_name": "org.example.lib.OtherConverter.getFeet",
                    "api_simple": "getFeet",
                    "api_signature": "(int)",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "not_found_in_static_analysis")
            self.assertEqual(result.reason_code, "NO_STATIC_PATH")

    def test_trace_api_reaches_dependency_method_via_this_field_receiver(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "dep"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Controller.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.dep.Worker;",
                        "",
                        "public class Controller {",
                        "    private final Worker worker = new Worker();",
                        "",
                        "    public String handle() {",
                        "        return this.worker.run();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "Worker.java").write_text(
                "\n".join(
                    [
                        "package com.example.dep;",
                        "",
                        "public class Worker {",
                        "    public String run() {",
                        '        return "ok";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:dep",
                        "module": "dep",
                    },
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:dep",
                    "api_name": "com.example.dep.Worker.run",
                    "api_simple": "run",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertIn("Controller.handle", result.call_paths[0])

    def test_trace_api_reaches_constructor_target_from_source_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "dep"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Controller.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.dep.TargetType;",
                        "",
                        "public class Controller {",
                        "    public String handle() {",
                        "        TargetType target = new TargetType();",
                        "        return target.render();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "TargetType.java").write_text(
                "\n".join(
                    [
                        "package com.example.dep;",
                        "",
                        "public class TargetType {",
                        "    public TargetType() {",
                        "    }",
                        "",
                        "    public String render() {",
                        '        return "ok";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:dep",
                        "module": "dep",
                    },
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:dep",
                    "api_name": "com.example.dep.TargetType.TargetType",
                    "api_simple": "TargetType",
                    "api_signature": "()",
                    "symbol_kind": "constructor",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertIn("Controller.handle", result.call_paths[0])

    def test_trace_api_blocks_unobserved_constructor_overload_from_source_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            business_dir.mkdir(parents=True)

            (business_dir / "UserService.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "public class UserService {",
                        "    public void getUserById(String id) {",
                        '        throw new UserNotFoundException("missing: " + id);',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (business_dir / "UserNotFoundException.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "public class UserNotFoundException extends RuntimeException {",
                        "    public UserNotFoundException(String message) {",
                        "        super(message);",
                        "    }",
                        "",
                        "    public UserNotFoundException(String message, Throwable cause) {",
                        "        super(message, cause);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    }
                ]
            )

            positive_result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "BUSINESS",
                    "api_name": "com.example.app.UserNotFoundException.UserNotFoundException",
                    "api_simple": "UserNotFoundException",
                    "api_signature": "(String)",
                    "symbol_kind": "constructor",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(positive_result.analysis_status, "reachable")
            self.assertIn("UserService.getUserById", positive_result.call_paths[0])

            for signature, source in [
                ("(String, Throwable)", "gitdiff"),
                ("(java.lang.String, java.lang.Throwable)", "japicmp"),
            ]:
                result = tracer.trace_api_with_confidence_weighting(
                    {
                        "coord": "BUSINESS",
                        "api_name": "com.example.app.UserNotFoundException.UserNotFoundException",
                        "api_simple": "UserNotFoundException",
                        "api_signature": signature,
                        "symbol_kind": "constructor",
                        "change_type": "REMOVED",
                        "severity": "P0",
                        "confirmed": "true",
                        "source": source,
                        "analysis_scope": "method",
                    },
                    graph_result["graph"],
                    graph_result["type_metadata"],
                    max_total_cost=5,
                )

                self.assertEqual(
                    result.analysis_status,
                    "not_analyzed",
                    msg=f"signature={signature} source={source}",
                )
                self.assertEqual(
                    result.reason_code,
                    "OVERLOAD_AMBIGUOUS_TARGET",
                    msg=f"signature={signature} source={source}",
                )

    def test_trace_api_reaches_dependency_method_via_method_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "dep"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Action.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "public interface Action {",
                        "    void execute();",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (business_dir / "Controller.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.dep.Worker;",
                        "",
                        "public class Controller {",
                        "    public void handle() {",
                        "        Worker worker = new Worker();",
                        "        Action action = worker::run;",
                        "        action.execute();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "Worker.java").write_text(
                "\n".join(
                    [
                        "package com.example.dep;",
                        "",
                        "public class Worker {",
                        "    public void run() {",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:dep",
                        "module": "dep",
                    },
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:dep",
                    "api_name": "com.example.dep.Worker.run",
                    "api_simple": "run",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertIn("Controller.handle", result.call_paths[0])

    def test_trace_api_method_reference_indexes_unique_declared_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "dep"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "StringAction.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "public interface StringAction {",
                        "    void accept(String value);",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (business_dir / "Controller.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.dep.Worker;",
                        "",
                        "public class Controller {",
                        "    public void handle() {",
                        "        Worker worker = new Worker();",
                        "        StringAction action = worker::run;",
                        '        action.accept("a");',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "Worker.java").write_text(
                "\n".join(
                    [
                        "package com.example.dep;",
                        "",
                        "public class Worker {",
                        "    public void run(String value) {",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:dep",
                        "module": "dep",
                    },
                ]
            )
            reverse_edges = graph_result["graph"].reverse_edges
            self.assertIn("com.example.dep.Worker.run(String)", reverse_edges)
            self.assertIn("method:run(String)", reverse_edges)
            self.assertEqual(
                [edge.caller_qualified_key for edge in reverse_edges["com.example.dep.Worker.run(String)"]],
                ["com.example.app.Controller.handle"],
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:dep",
                    "api_name": "com.example.dep.Worker.run",
                    "api_simple": "run",
                    "api_signature": "(String)",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertEqual(result.match_provenance, "exact_signature")
            self.assertIn("Controller.handle", result.call_paths[0])

    def test_trace_api_reaches_parent_interface_method_via_child_interface_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "service"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Controller.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.service.ChildService;",
                        "import com.example.service.ChildServiceImpl;",
                        "",
                        "public class Controller {",
                        "    private final ChildService service = new ChildServiceImpl();",
                        "",
                        "    public String handle() {",
                        "        return service.process();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ParentService.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public interface ParentService {",
                        "    String process();",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ChildService.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public interface ChildService extends ParentService {",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ChildServiceImpl.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public class ChildServiceImpl implements ChildService {",
                        "    @Override",
                        "    public String process() {",
                        '        return "ok";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:service",
                        "module": "service",
                    },
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:service",
                    "api_name": "com.example.service.ParentService.process",
                    "api_simple": "process",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertIn("Controller.handle", result.call_paths[0])

    def test_trace_api_reaches_parent_interface_method_via_concrete_impl_receiver(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "service"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Controller.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.service.ChildServiceImpl;",
                        "",
                        "public class Controller {",
                        "    private final ChildServiceImpl service = new ChildServiceImpl();",
                        "",
                        "    public String handle() {",
                        "        return service.process();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ParentService.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public interface ParentService {",
                        "    String process();",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ChildService.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public interface ChildService extends ParentService {",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ChildServiceImpl.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public class ChildServiceImpl implements ChildService {",
                        "    @Override",
                        "    public String process() {",
                        '        return "ok";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:service",
                        "module": "service",
                    },
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:service",
                    "api_name": "com.example.service.ParentService.process",
                    "api_simple": "process",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertIn("Controller.handle", result.call_paths[0])

    def test_trace_api_does_not_attribute_parent_interface_call_to_specific_impl_in_hierarchy_with_multiple_impls(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "service"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Controller.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.service.ParentService;",
                        "import com.example.service.ChildServiceImplA;",
                        "",
                        "public class Controller {",
                        "    private final ParentService service = new ChildServiceImplA();",
                        "",
                        "    public String handle() {",
                        "        return service.process();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ParentService.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public interface ParentService {",
                        "    String process();",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ChildService.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public interface ChildService extends ParentService {",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ChildServiceImplA.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public class ChildServiceImplA implements ChildService {",
                        "    @Override",
                        "    public String process() {",
                        '        return "A";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ChildServiceImplB.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public class ChildServiceImplB implements ChildService {",
                        "    @Override",
                        "    public String process() {",
                        '        return "B";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:service",
                        "module": "service",
                    },
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:service",
                    "api_name": "com.example.service.ChildServiceImplA.process",
                    "api_simple": "process",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "not_found_in_static_analysis")
            self.assertEqual(result.reason_code, "NO_STATIC_PATH")

    def test_trace_api_reaches_dependency_method_via_this_zero_arg_factory_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "dep"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Controller.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.dep.Worker;",
                        "",
                        "public class Controller {",
                        "    public String handle() {",
                        "        return this.worker().run();",
                        "    }",
                        "",
                        "    private Worker worker() {",
                        "        return new Worker();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "Worker.java").write_text(
                "\n".join(
                    [
                        "package com.example.dep;",
                        "",
                        "public class Worker {",
                        "    public String run() {",
                        '        return "ok";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:dep",
                        "module": "dep",
                    },
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:dep",
                    "api_name": "com.example.dep.Worker.run",
                    "api_simple": "run",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertIn("Controller.handle", result.call_paths[0])

    def test_trace_api_does_not_misattribute_overload_with_similar_factory_receiver(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "dep"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Controller.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.dep.Worker;",
                        "",
                        "public class Controller {",
                        "    public String handle() {",
                        "        return this.worker().run(\"ok\");",
                        "    }",
                        "",
                        "    private Worker worker() {",
                        "        return new Worker();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "Worker.java").write_text(
                "\n".join(
                    [
                        "package com.example.dep;",
                        "",
                        "public class Worker {",
                        "    public String run() {",
                        '        return "no-arg";',
                        "    }",
                        "",
                        "    public String run(String value) {",
                        "        return value;",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:dep",
                        "module": "dep",
                    },
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:dep",
                    "api_name": "com.example.dep.Worker.run",
                    "api_simple": "run",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "not_analyzed")
            self.assertIn(
                result.reason_code,
                {"OVERLOAD_AMBIGUOUS_TARGET", "OVERLOAD_AMBIGUOUS_INTERMEDIATE"},
            )

    def test_trace_api_reaches_parent_interface_method_via_child_factory_receiver(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "service"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Controller.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.service.ChildService;",
                        "import com.example.service.ChildServiceImpl;",
                        "",
                        "public class Controller {",
                        "    public String handle() {",
                        "        return child().process();",
                        "    }",
                        "",
                        "    private ChildService child() {",
                        "        return new ChildServiceImpl();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ParentService.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public interface ParentService {",
                        "    String process();",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ChildService.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public interface ChildService extends ParentService {",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ChildServiceImpl.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public class ChildServiceImpl implements ChildService {",
                        "    @Override",
                        "    public String process() {",
                        '        return "ok";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:service",
                        "module": "service",
                    },
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:service",
                    "api_name": "com.example.service.ParentService.process",
                    "api_simple": "process",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertIn("Controller.handle", result.call_paths[0])

    def test_trace_api_does_not_misattribute_parent_interface_target_with_child_factory_overload(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "service"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Controller.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.service.ChildService;",
                        "import com.example.service.ChildServiceImpl;",
                        "",
                        "public class Controller {",
                        "    public String handle() {",
                        "        return child().process(\"ok\");",
                        "    }",
                        "",
                        "    private ChildService child() {",
                        "        return new ChildServiceImpl();",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ParentService.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public interface ParentService {",
                        "    String process();",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ChildService.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public interface ChildService extends ParentService {",
                        "    String process(String value);",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "ChildServiceImpl.java").write_text(
                "\n".join(
                    [
                        "package com.example.service;",
                        "",
                        "public class ChildServiceImpl implements ChildService {",
                        "    @Override",
                        "    public String process() {",
                        '        return "no-arg";',
                        "    }",
                        "",
                        "    @Override",
                        "    public String process(String value) {",
                        "        return value;",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:service",
                        "module": "service",
                    },
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:service",
                    "api_name": "com.example.service.ParentService.process",
                    "api_simple": "process",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "not_analyzed")
            self.assertIn(
                result.reason_code,
                {"OVERLOAD_AMBIGUOUS_TARGET", "OVERLOAD_AMBIGUOUS_INTERMEDIATE"},
            )

    def test_infer_param_type_from_chained_tostring_call(self):
        method_def = SimpleNamespace(
            class_fqcn="com.example.Service",
            class_name="Service",
            package_name="com.example",
            param_types={},
            field_types={},
            local_var_types={"savedUser": "com.example.User"},
            local_method_return_types={},
            known_method_return_types={},
            known_method_return_types_by_signature={
                "com.example.User": {
                    "getId": {
                        "()": "java.lang.Long",
                    }
                }
            },
            imports={},
        )

        inferred = source_analyzer.infer_param_type_from_expression(
            "savedUser.getId().toString()",
            method_def,
            local_var_types={"savedUser": "com.example.User"},
        )

        self.assertEqual(inferred, "String")

    def test_trace_api_reaches_overload_target_with_object_param_from_chained_tostring_and_subtype(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "dep"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Controller.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.dep.EventPublisher;",
                        "import com.example.dep.User;",
                        "import com.example.dep.UserCreatedEvent;",
                        "",
                        "public class Controller {",
                        "    private final EventPublisher publisher = new EventPublisher();",
                        "    private static final String TOPIC = \"user-events\";",
                        "",
                        "    public void handle(User savedUser) {",
                        "        UserCreatedEvent event = new UserCreatedEvent();",
                        "        publisher.publishEvent(TOPIC, savedUser.getId().toString(), event);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "EventPublisher.java").write_text(
                "\n".join(
                    [
                        "package com.example.dep;",
                        "",
                        "public class EventPublisher {",
                        "    public void publishEvent(String topic, String key, Object event) {",
                        "    }",
                        "",
                        "    public void publishEvent(String topic, Object event) {",
                        "        publishEvent(topic, null, event);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "User.java").write_text(
                "\n".join(
                    [
                        "package com.example.dep;",
                        "",
                        "public class User {",
                        "    private Long id;",
                        "",
                        "    public Long getId() {",
                        "        return id;",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "UserCreatedEvent.java").write_text(
                "\n".join(
                    [
                        "package com.example.dep;",
                        "",
                        "public class UserCreatedEvent {",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:dep",
                        "module": "dep",
                    },
                ]
            )
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:dep",
                    "api_name": "com.example.dep.EventPublisher.publishEvent",
                    "api_simple": "publishEvent",
                    "api_signature": "(String, String, Object)",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")
            self.assertIn("Controller.handle", result.call_paths[0])

    def test_partial_argument_hints_resolve_unique_overload_signature_for_reverse_edges(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "sdk"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Caller.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.sdk.UnifiedParameterFacility;",
                        "import com.example.sdk.TxnServiceAttribute;",
                        "",
                        "public class Caller {",
                        "    private final UnifiedParameterFacility facility = new UnifiedParameterFacility();",
                        "",
                        "    public void run(Object key) {",
                        "        facility.retrieveParameterObject(key, TxnServiceAttribute.class);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "UnifiedParameterFacility.java").write_text(
                "\n".join(
                    [
                        "package com.example.sdk;",
                        "",
                        "public class UnifiedParameterFacility {",
                        "    private final CacheManageFacility cacheManageFacility = new CacheManageFacility();",
                        "",
                        "    public <T> T retrieveParameterObject(Object key, Class<T> clazz) {",
                        "        return (T) cacheManageFacility.retrieveParameterObject(key == null ? null : String.valueOf(key), clazz.getCanonicalName());",
                        "    }",
                        "",
                        "    public <T> T retrieveParameterObject(Class<T> clazz) {",
                        "        return null;",
                        "    }",
                        "",
                        "    public String retrieveParameterObject(String key) {",
                        '        return "";',
                        "    }",
                        "",
                        "    public String retrieveParameterObject(String key, String typeName) {",
                        '        return "";',
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "CacheManageFacility.java").write_text(
                "\n".join(
                    [
                        "package com.example.sdk;",
                        "",
                        "public class CacheManageFacility {",
                        "    public Object retrieveParameterObject(String key, String typeName) {",
                        "        return null;",
                        "    }",
                        "",
                        "    public Object retrieveParameterObject(String key) {",
                        "        return null;",
                        "    }",
                        "",
                        "    public Object retrieveParameterObject(Class<?> clazz) {",
                        "        return null;",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "TxnServiceAttribute.java").write_text(
                "\n".join(
                    [
                        "package com.example.sdk;",
                        "",
                        "public class TxnServiceAttribute {",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:sdk",
                        "module": "sdk",
                    },
                ]
            )

            self.assertIn(
                "com.example.sdk.CacheManageFacility.retrieveParameterObject(String, String)",
                graph_result["graph"].reverse_edges,
            )

            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "sample:sdk",
                    "api_name": "com.example.sdk.CacheManageFacility.retrieveParameterObject",
                    "api_simple": "retrieveParameterObject",
                    "api_signature": "(String, String)",
                    "symbol_kind": "method",
                    "change_type": "method_changed",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "validation",
                    "analysis_scope": "method",
                },
                graph_result["graph"],
                graph_result["type_metadata"],
                max_total_cost=5,
            )

            self.assertEqual(result.analysis_status, "reachable")
            self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")
            self.assertIn("Caller.run", result.call_paths[0])

    def test_debug_logging_emits_overload_block_details_when_enabled(self):
        graph = SimpleNamespace(
            methods_by_id={
                "m1": SimpleNamespace(
                    symbol_id="m1",
                    qualified_key="com.example.Service.call",
                    simple_key="method:call",
                    class_fqcn="com.example.Service",
                    method_name="call",
                    param_types={"value": "java.lang.String"},
                    param_declared_types={"value": "String"},
                )
            },
            reverse_edges={},
        )
        type_metadata = {"com.example.Service": {"extends": [], "implements": [], "implementations": []}}

        with patch.dict("os.environ", {"JUA_STEP5_DEBUG": "1"}, clear=False):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                tracer.get_cached_method_lookup_resolution(
                    graph.methods_by_id["m1"],
                    type_metadata,
                    graph,
                    trace_cache={},
                )

        output = stderr.getvalue()
        self.assertIn('"topic": "method_lookup_resolution"', output)
        self.assertIn("no precise lookup groups matched reverse edges", output)

    def test_debug_logging_emits_trace_lifecycle_details_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_dir = Path(tmp) / "business" / "src" / "main" / "java" / "com" / "example" / "app"
            dependency_dir = Path(tmp) / "dependency" / "src" / "main" / "java" / "com" / "example" / "dep"
            business_dir.mkdir(parents=True)
            dependency_dir.mkdir(parents=True)

            (business_dir / "Controller.java").write_text(
                "\n".join(
                    [
                        "package com.example.app;",
                        "",
                        "import com.example.dep.EventPublisher;",
                        "import com.example.dep.User;",
                        "import com.example.dep.UserCreatedEvent;",
                        "",
                        "public class Controller {",
                        "    private final EventPublisher publisher = new EventPublisher();",
                        "    private static final String TOPIC = \"user-events\";",
                        "",
                        "    public void handle(User savedUser) {",
                        "        UserCreatedEvent event = new UserCreatedEvent();",
                        "        publisher.publishEvent(TOPIC, savedUser.getId().toString(), event);",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "EventPublisher.java").write_text(
                "\n".join(
                    [
                        "package com.example.dep;",
                        "",
                        "public class EventPublisher {",
                        "    public void publishEvent(String topic, String key, Object event) {",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "User.java").write_text(
                "\n".join(
                    [
                        "package com.example.dep;",
                        "",
                        "public class User {",
                        "    private Long id;",
                        "    public Long getId() {",
                        "        return id;",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (dependency_dir / "UserCreatedEvent.java").write_text(
                "\n".join(
                    [
                        "package com.example.dep;",
                        "public class UserCreatedEvent {}",
                    ]
                ),
                encoding="utf-8",
            )

            graph_result = step5.build_enhanced_source_graph(
                [
                    {
                        "root": str(business_dir.parent.parent.parent),
                        "owner_type": "business",
                        "owner_coord": "BUSINESS",
                        "module": "app",
                    },
                    {
                        "root": str(dependency_dir.parent.parent.parent),
                        "owner_type": "dependency",
                        "owner_coord": "sample:dep",
                        "module": "dep",
                    },
                ]
            )

            api_row = {
                "coord": "sample:dep",
                "api_name": "com.example.dep.EventPublisher.publishEvent",
                "api_simple": "publishEvent",
                "api_signature": "(String, String, Object)",
                "symbol_kind": "method",
                "change_type": "method_changed",
                "severity": "P1",
                "confirmed": "true",
                "source": "validation",
                "analysis_scope": "method",
            }

            with patch.dict("os.environ", {"JUA_STEP5_DEBUG": "1"}, clear=False):
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    tracer.trace_api_with_confidence_weighting(
                        api_row,
                        graph_result["graph"],
                        graph_result["type_metadata"],
                        max_total_cost=5,
                    )

            output = stderr.getvalue()
            self.assertIn('"topic": "trace_api_start"', output)
            self.assertIn('"topic": "target_key_groups"', output)
            self.assertIn('"topic": "trace_frontier_seed"', output)
            self.assertIn('"topic": "trace_api_result"', output)

    def test_step5_main_debug_logs_full_process_topics(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            report_dir.mkdir(parents=True)
            source_dir = Path(tmp) / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            api_csv = report_dir / "apis.csv"
            api_csv.write_text("coord,api_name\nsample:dep,com.example.Api.call\n", encoding="utf-8")

            fake_graph = SimpleNamespace(methods_by_id={}, reverse_edges={})
            fake_graph_result = {
                "graph": fake_graph,
                "type_metadata": {},
                "stats": {
                    "parser_usage": {"tree_sitter": 0, "regex": 0},
                    "parser_fallback_reasons": {},
                    "truncated": False,
                },
                "analysis_cache": [],
            }
            fake_result = SimpleNamespace(
                api_name="com.example.Api.call",
                analysis_status="reachable",
                reason_code="SYSTEM_CODE_REACHED",
                match_provenance="exact_signature",
            )
            args = SimpleNamespace(
                report_dir=str(report_dir),
                output_dir="",
                all_changed_apis=str(api_csv),
                jdk_scan_dir="",
                source_dirs=[str(source_dir)],
                dependency_source_mappings=[],
                allow_degraded=False,
                max_methods=None,
                max_depth=5,
                debug_analysis=True,
                debug_break=False,
            )

            query_index_edge_counts = []

            def fake_trace(*_args, **_kwargs):
                fake_graph.reverse_edges["runtime.Target.call()"] = [SimpleNamespace()]
                return [fake_result]

            def fake_write_query_index(graph, path, graph_stats=None):
                query_index_edge_counts.append(len(graph.reverse_edges))
                return path

            with patch.object(step5, "auto_discover_bridge_sources", return_value={
                "dependency_source_mappings": [],
                "matched_coords": [],
                "provided_dependency_source_dirs": [],
                "source_dirs_detected_without_coord": [],
                "unresolved_dependency_source_dirs": [],
                "discovery_log": [],
            }), patch.object(step5, "load_changed_apis", return_value=[{
                "coord": "sample:dep",
                "api_name": "com.example.Api.call",
                "api_signature": "()",
                "symbol_kind": "method",
            }]), patch.object(
                step5,
                "build_runtime_dependency_catalog",
                return_value={
                    "by_coord": {},
                    "entries": [],
                    "status": "complete",
                },
            ), patch.object(step5, "build_enhanced_source_graph", return_value=fake_graph_result), patch.object(
                step5, "fatal_business_bytecode_failures", return_value=[]
            ), patch.object(
                step5,
                "check_apis_that_need_bridge",
                return_value={"sample:dep:com.example.Api.call": {"needs_bridge": False, "has_dependency_source_mapping": True, "reason": ""}},
            ), patch.object(step5, "build_jar_metadata_for_source_roots", return_value={"by_class": {}, "jar_paths": {}}), patch.object(
                step5,
                "trace_all_apis_with_confidence_weighting",
                side_effect=fake_trace,
            ), patch.object(step5, "write_query_index", side_effect=fake_write_query_index), patch.object(
                step5, "generate_enhanced_summary", return_value=None
            ):
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    exit_code = step5.step5_integrated_main(args)

            self.assertEqual(exit_code, 0)
            output = stderr.getvalue()
            self.assertIn('"topic": "step5_inputs"', output)
            self.assertIn('"topic": "dependency_mapping_resolution"', output)
            self.assertIn('"topic": "bridge_check_summary"', output)
            self.assertIn('"topic": "graph_summary"', output)
            self.assertIn('"topic": "trace_batch_summary"', output)
            self.assertIn('"topic": "step5_done"', output)
            self.assertFalse(os.environ.get("JUA_STEP5_DEBUG"))
            self.assertEqual(query_index_edge_counts, [1])

    def test_trace_api_uses_packaged_bytecode_fallback_when_dependency_source_mapping_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "consumer.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr(
                    "com/example/consumer/Adapter.class",
                    b"org/apache/commons/lang/StringUtils isBlank",
                )

            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "by_coord": {
                        "sample:consumer": {
                            "coord": "sample:consumer",
                            "version": "1.0.0",
                            "scope": "compile",
                            "jar_path": str(jar_path),
                        }
                    }
                },
            )
            api_row = {
                "coord": "commons-lang:commons-lang",
                "api_name": "org.apache.commons.lang.StringUtils.isBlank",
                "api_simple": "isBlank",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "severity": "P1",
                "confirmed": "true",
                "source": "old_jar",
            }

            javap_output = """
Compiled from "Adapter.java"
public class com.example.consumer.Adapter {
  public void use();
    descriptor: ()V
    Code:
       0: aload_1
       1: invokestatic  #7 // Method org/apache/commons/lang/StringUtils.isBlank:(Ljava/lang/String;)Z
       4: pop
       5: return
}
"""

            with patch.object(tracer, "run_cmd", return_value=(javap_output, "", 0)):
                result = tracer.trace_api_with_confidence_weighting(
                    api_row,
                    graph,
                    {},
                    max_total_cost=5,
                    needs_bridge=True,
                    has_dependency_source_mapping=False,
                    has_packaged_bytecode_fallback=True,
                    allow_degraded=True,
                )

            self.assertEqual(result.analysis_status, "uncertain")
            self.assertEqual(result.reason_code, "PACKAGED_DEPENDENCY_BYTECODE_USAGE")
            self.assertEqual(result.dependency_chain_coords, ["sample:consumer"])
            self.assertIn("sample:consumer", result.call_paths[0])
            self.assertEqual(result.path_details[0]["consumer_method"], "use")
            self.assertEqual(result.path_details[0]["consumer_signature"], "()")

    def test_removed_dependency_scans_runtime_consumers_even_when_target_source_mapping_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "consumer.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr(
                    "com/example/consumer/Adapter.class",
                    b"org/apache/commons/lang/StringUtils isBlank",
                )
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "by_coord": {
                        "sample:consumer": {
                            "coord": "sample:consumer", "version": "1", "scope": "compile",
                            "jar_path": str(jar_path),
                        }
                    }
                },
            )
            api_row = {
                "coord": "commons-lang:commons-lang",
                "old_version": "2.6",
                "new_version": "-",
                "api_name": "org.apache.commons.lang.StringUtils.isBlank",
                "api_simple": "isBlank",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "severity": "P0",
                "confirmed": "true",
                "source": "old_jar",
            }
            javap_output = """
public class com.example.consumer.Adapter {
  public void use();
    descriptor: ()V
    Code:
       1: invokestatic #7 // Method org/apache/commons/lang/StringUtils.isBlank:(Ljava/lang/String;)Z
}
"""
            with patch.object(tracer, "run_cmd", return_value=(javap_output, "", 0)):
                result = tracer.trace_api_with_confidence_weighting(
                    api_row, graph, {}, max_total_cost=5,
                    needs_bridge=True,
                    has_dependency_source_mapping=True,
                    has_packaged_bytecode_fallback=True,
                    allow_degraded=False,
                )

            self.assertEqual(result.analysis_status, "uncertain")
            self.assertEqual(result.reason_code, "RUNTIME_DEPENDENCY_USES_REMOVED_API")
            self.assertEqual(result.dependency_chain_coords, ["sample:consumer"])
            self.assertIn("NoClassDefFoundError", result.reachable_note)

    def test_packaged_bytecode_keeps_every_consuming_method_for_manual_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "consumer.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr(
                    "com/example/consumer/Adapter.class",
                    b"org/apache/commons/lang/StringUtils isBlank",
                )
            graph = SimpleNamespace(runtime_dependency_catalog={
                "status": "complete",
                "by_coord": {"sample:consumer": {"coord": "sample:consumer", "jar_path": str(jar_path)}},
            })
            api_row = {
                "coord": "commons-lang:commons-lang",
                "api_name": "org.apache.commons.lang.StringUtils.isBlank",
                "api_simple": "isBlank", "api_signature": "(String)",
                "symbol_kind": "method", "change_type": "REMOVED",
            }
            javap_output = """
public class com.example.consumer.Adapter {
  public void validate();
    descriptor: ()V
    Code:
       1: invokestatic #7 // Method org/apache/commons/lang/StringUtils.isBlank:(Ljava/lang/String;)Z
  public boolean convert(java.lang.String);
    descriptor: (Ljava/lang/String;)Z
    Code:
       1: invokestatic #7 // Method org/apache/commons/lang/StringUtils.isBlank:(Ljava/lang/String;)Z
}
"""
            with patch.object(tracer, "run_cmd", return_value=(javap_output, "", 0)):
                scan = tracer._scan_packaged_runtime_dependencies_for_api(api_row, graph)

        self.assertEqual(scan["status"], "hit")
        self.assertEqual({item["consumer_method"] for item in scan["hits"]}, {"validate", "convert"})

    def test_indirect_business_finding_is_migrated_to_typed_semantic_path(self):
        api_row = {
            "coord": "com.vendor:security",
            "api_name": "com.vendor.RemovedType",
            "api_simple": "RemovedType",
            "api_signature": "",
            "symbol_kind": "class",
            "change_type": "REMOVED",
            "analysis_scope": "class_usage",
        }
        key = tracer.indirect_api_key(api_row)
        graph = SimpleNamespace(
            reverse_edges={},
            indirect_usage_findings={key: [{
                "caller_symbol": "com.acme.SecurityModule.setup",
                "evidence_type": "reflection_class_lookup",
                "reason_code": "REFLECTION_CLASS_LOOKUP",
                "owner_coord": "业务制品",
                "file": "/src/SecurityModule.java",
                "line": 12,
            }]},
            indirect_usage_unresolved={},
            indirect_analysis_coverage={},
            step5_collector_coverage=(),
            step5_evidence_concerns=(),
            step5_evidence_failures=(EvidenceFailure(
                stage="analyzer-edge-collection",
                reason_code="PRESERVATION_MANIFEST_UNREADABLE",
                blocking=True,
            ),),
        )
        draft = tracer._new_trace_draft(api_row, graph)

        tracer._build_indirect_usage_result(draft, api_row, graph)
        result = tracer._finalize_trace_draft(draft)

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "REFLECTION_CLASS_LOOKUP")
        self.assertEqual(len(draft.envelope_paths), 1)
        self.assertTrue(draft.envelope_paths[0].evidence[0].semantic)

    def test_batch_packaged_bytecode_scan_reuses_javap_across_apis(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "consumer.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr(
                    "com/example/consumer/Adapter.class",
                    b"org/apache/commons/lang/StringUtils isBlank isEmpty",
                )
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "status": "complete",
                    "entries": [{
                        "coord": "sample:consumer",
                        "version": "1",
                        "scope": "compile",
                        "jar_path": str(jar_path),
                        "artifact_entry": "BOOT-INF/lib/consumer.jar",
                        "sha256": hashlib.sha256(jar_path.read_bytes()).hexdigest(),
                        "evidence_source": "current_final_artifact",
                    }],
                },
            )
            graph.runtime_dependency_catalog["by_coord"] = {
                "sample:consumer": graph.runtime_dependency_catalog["entries"][0]
            }
            apis = [
                {
                    "coord": "commons-lang:commons-lang",
                    "api_name": "org.apache.commons.lang.StringUtils.isBlank",
                    "api_simple": "isBlank",
                    "api_signature": "(String)",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                },
                {
                    "coord": "commons-lang:commons-lang",
                    "api_name": "org.apache.commons.lang.StringUtils.isEmpty",
                    "api_simple": "isEmpty",
                    "api_signature": "(String)",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                },
            ]
            javap_output = """
public class com.example.consumer.Adapter {
  public void validate();
    descriptor: ()V
    Code:
       1: invokestatic #7 // Method org/apache/commons/lang/StringUtils.isBlank:(Ljava/lang/String;)Z
}
"""
            with patch.object(tracer, "run_cmd", return_value=(javap_output, "", 0)) as mocked_run:
                results = tracer.trace_all_apis_with_confidence_weighting(
                    apis,
                    graph,
                    {},
                    max_total_cost=5,
                    api_bridge_requirements={
                        tracer.build_api_identity_key(item): {
                            "needs_bridge": True,
                            "has_dependency_source_mapping": False,
                            "has_packaged_bytecode_fallback": True,
                        }
                        for item in apis
                    },
                    allow_degraded=True,
                    graph_stats={"truncated": False, "parser_fallback_reasons": {}},
                )

            self.assertEqual(mocked_run.call_count, 1)
            self.assertEqual(
                [item.analysis_status for item in results],
                ["uncertain", "not_found_in_static_analysis"],
            )

    def test_batch_packaged_bytecode_scan_rejects_artifact_changed_during_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "consumer.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr(
                    "com/example/Consumer.class",
                    b"com/vendor/Target removed",
                )
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "status": "complete",
                    "entries": [{
                        "coord": "sample:consumer",
                        "jar_path": str(jar_path),
                    }],
                },
            )
            api = {
                "coord": "com.vendor:api",
                "api_name": "com.vendor.Target.removed",
                "api_simple": "removed",
                "api_signature": "",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }

            def mutating_parse(task):
                with zipfile.ZipFile(jar_path, "a") as archive:
                    archive.writestr("mutation-marker", b"changed")
                return task, {
                    "class_refs": {"com.vendor.Target"},
                    "method_refs": [{
                        "owner": "com.vendor.Target",
                        "name": "removed",
                        "signature": "()",
                        "descriptor": "()V",
                        "consumer_method": "call",
                        "consumer_signature": "()",
                        "consumer_descriptor": "()V",
                        "opcode_family": "invokevirtual",
                        "instruction_offset": 1,
                    }],
                    "field_refs": [],
                }

            with patch.object(
                tracer,
                "_load_runtime_dependency_class_references_for_task",
                side_effect=mutating_parse,
            ):
                cached = tracer._build_packaged_runtime_dependency_scan_cache(
                    [api], graph
                )

        result = cached[tracer.build_api_identity_key(api)]
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["reason"], "BYTECODE_SCAN_INPUT_CHANGED")
        self.assertEqual(graph.reverse_edges, {})

    def test_batch_packaged_bytecode_scan_rolls_back_when_artifact_changes_during_edge_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "consumer.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr(
                    "com/example/Consumer.class", b"com/vendor/Target removed"
                )
            graph = SimpleNamespace(
                methods_by_id={}, reverse_edges={},
                runtime_dependency_catalog={
                    "status": "complete",
                    "entries": [{"coord": "sample:consumer", "jar_path": str(jar_path)}],
                },
            )
            api = {
                "coord": "com.vendor:api", "api_name": "com.vendor.Target.removed",
                "api_simple": "removed", "api_signature": "", "symbol_kind": "method",
                "change_type": "REMOVED",
            }
            references = {
                "class_refs": {"com.vendor.Target"},
                "method_refs": [{
                    "owner": "com.vendor.Target", "name": "removed", "signature": "()",
                    "descriptor": "()V", "consumer_method": "call",
                    "consumer_signature": "()", "consumer_descriptor": "()V",
                    "opcode_family": "invokevirtual", "instruction_offset": 1,
                }],
                "field_refs": [],
            }
            original_record = tracer.record_analyzer_edge
            mutated = False

            def mutating_record(current_graph, current_api, hit):
                nonlocal mutated
                row = original_record(current_graph, current_api, hit)
                if not mutated:
                    mutated = True
                    with zipfile.ZipFile(jar_path, "w") as archive:
                        archive.writestr("com/example/Replacement.class", b"unrelated")
                return row

            with patch.object(
                tracer, "_load_runtime_dependency_class_references_for_task",
                side_effect=lambda task: (task, references),
            ), patch.object(
                tracer, "record_analyzer_edge", side_effect=mutating_record
            ):
                cached = tracer._build_packaged_runtime_dependency_scan_cache([api], graph)

        result = cached[tracer.build_api_identity_key(api)]
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["reason"], "BYTECODE_SCAN_INPUT_CHANGED")
        self.assertEqual(getattr(graph, "analyzer_edges", {}), {})

    def test_batch_packaged_bytecode_scan_rolls_back_analyzer_ledger_on_commit_exception(self):
        graph = SimpleNamespace(
            analyzer_edges={},
            _analyzer_edge_discovery_count=7,
            _analyzer_edge_incomplete_count=2,
            _analyzer_edge_failures={('before', ())},
            step5_evidence_failures=("before",),
        )
        api = {
            "coord": "com.vendor:api", "api_name": "com.vendor.Target.removed",
            "api_simple": "removed", "api_signature": "", "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        hit = {"coord": "sample:consumer", "jar_path": "/tmp/consumer.jar"}

        def insert_then_raise(current_graph, _api, _hit):
            current_graph.analyzer_edges["partial"] = {"api_identity": "partial"}
            current_graph._analyzer_edge_discovery_count = 8
            current_graph._analyzer_edge_incomplete_count = 3
            current_graph._analyzer_edge_failures.add(('during', ()))
            current_graph.step5_evidence_failures += ("during",)
            raise RuntimeError("commit failed")

        with patch.object(
            tracer, "_get_runtime_dependency_catalog", return_value={
                "status": "complete",
                "_packaged_api_scan_results": {},
            }
        ), patch.object(
            tracer, "_runtime_artifact_stat_snapshot", return_value=("17", ())
        ), patch.object(
            tracer, "_artifact_sha256", return_value="a" * 64
        ), patch.object(
            tracer, "record_analyzer_edge", side_effect=insert_then_raise
        ), patch.object(
            tracer, "_deduplicate_physical_packaged_hits", return_value=[hit]
        ):
            catalog = tracer._get_runtime_dependency_catalog(graph)
            catalog["entries"] = []
            catalog["_packaged_api_scan_results"] = {}
            with self.assertRaisesRegex(RuntimeError, "commit failed"):
                # Seed the hit at the point immediately before the commit loop.
                with patch.object(
                    tracer, "_match_runtime_dependency_references", return_value=[]
                ):
                    tracer._commit_packaged_analyzer_edges_transaction(
                        graph, [(api, hit)]
                    )

        self.assertEqual(graph.analyzer_edges, {})
        self.assertEqual(graph._analyzer_edge_discovery_count, 7)
        self.assertEqual(graph._analyzer_edge_incomplete_count, 2)
        self.assertEqual(graph._analyzer_edge_failures, {('before', ())})
        self.assertEqual(graph.step5_evidence_failures, ("before",))

    def test_packaged_scan_input_change_invalidates_cached_and_new_api_results(self):
        api_a = {
            "coord": "com.vendor:api", "api_name": "com.vendor.Target.first",
            "api_simple": "first", "api_signature": "", "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        api_b = {**api_a, "api_name": "com.vendor.Target.second", "api_simple": "second"}
        key_a = tracer.build_api_identity_key(api_a)
        key_b = tracer.build_api_identity_key(api_b)
        existing = {key_a: {"status": "hit", "hits": [{"old": True}]}}

        tracer._mark_packaged_scan_input_changed(
            existing, [api_a, api_b],
            [{"reason": "BYTECODE_SCAN_INPUT_CHANGED"}], 3, 10,
        )

        self.assertEqual(set(existing), {key_a, key_b})
        self.assertEqual(existing[key_a]["status"], "unavailable")
        self.assertEqual(existing[key_b]["status"], "unavailable")

    def test_packaged_api_scan_cache_invalidates_after_runtime_jar_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "consumer.jar"

            def write_jar(content):
                with zipfile.ZipFile(jar_path, "w") as archive:
                    archive.writestr("com/example/Consumer.class", content)

            write_jar(b"com/vendor/Target removed")
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "status": "complete",
                    "entries": [{
                        "coord": "sample:consumer",
                        "jar_path": str(jar_path),
                    }],
                },
            )
            api = {
                "coord": "com.vendor:api",
                "api_name": "com.vendor.Target.removed",
                "api_simple": "removed",
                "api_signature": "",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
            references = {
                "class_refs": {"com.vendor.Target"},
                "method_refs": [{
                    "owner": "com.vendor.Target",
                    "name": "removed",
                    "signature": "()",
                    "descriptor": "()V",
                    "consumer_method": "call",
                    "consumer_signature": "()",
                    "consumer_descriptor": "()V",
                    "opcode_family": "invokevirtual",
                    "instruction_offset": 1,
                }],
                "field_refs": [],
            }
            with patch.object(
                tracer,
                "_load_runtime_dependency_class_references_for_task",
                side_effect=lambda task: (task, references),
            ):
                first = tracer._scan_packaged_runtime_dependencies_for_api(
                    api, graph
                )

            write_jar(b"unrelated-content")
            second = tracer._scan_packaged_runtime_dependencies_for_api(api, graph)

        self.assertEqual(first["status"], "hit")
        self.assertEqual(second["status"], "miss")

    def test_batch_packaged_bytecode_skips_javap_for_string_only_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            classes_root = self._compile_java_fixture(
                tmp,
                "com/example/consumer/StringOnly.java",
                """
package com.example.consumer;

public class StringOnly {
    private static final String OWNER_INTERNAL = "com/vendor/Target";
    private static final String OWNER_DOTTED = "com.vendor.Target";
    private static final String METHOD = "removed";

    public String describe() {
        return OWNER_INTERNAL + OWNER_DOTTED + METHOD;
    }
}
""",
            )
            jar_path = Path(tmp) / "consumer.jar"
            self._jar_compiled_classes(jar_path, classes_root)
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "status": "complete",
                    "by_coord": {
                        "sample:consumer": {
                            "coord": "sample:consumer",
                            "version": "1",
                            "scope": "compile",
                            "jar_path": str(jar_path),
                        }
                    },
                },
            )
            apis = [{
                "coord": "com.vendor:api",
                "api_name": "com.vendor.Target.removed",
                "api_simple": "removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }]

            javap_output = """
public class com.example.consumer.StringOnly {
  public java.lang.String describe();
    descriptor: ()Ljava/lang/String;
    Code:
       0: ldc #7 // String com/vendor/Targetcom.vendor.Targetremoved
       2: areturn
}
"""
            with patch.object(
                tracer, "run_cmd", return_value=(javap_output, "", 0)
            ) as mocked_javap:
                tracer._build_packaged_runtime_dependency_scan_cache(apis, graph)

            cached = graph.runtime_dependency_catalog["_packaged_api_scan_results"]
            self.assertEqual(cached[tracer.build_api_identity_key(apis[0])]["status"], "miss")
            # A valid direct classfile parse proves this is only a string
            # literal, so the constant-pool fast path must avoid javap.
            mocked_javap.assert_not_called()

    def test_batch_packaged_bytecode_skips_owner_and_member_string_constants_without_reflection(self):
        with tempfile.TemporaryDirectory() as tmp:
            classes_root = self._compile_java_fixture(
                tmp,
                "com/example/consumer/StringOnly.java",
                """
package com.example.consumer;

public class StringOnly {
    private static final String OWNER_INTERNAL = "com/vendor/Target";
    private static final String OWNER_DOTTED = "com.vendor.Target";
    private static final String METHOD = "removed";

    public String describe() {
        return OWNER_INTERNAL + OWNER_DOTTED + METHOD;
    }
}
""",
            )
            jar_path = Path(tmp) / "consumer.jar"
            self._jar_compiled_classes(jar_path, classes_root)
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "status": "complete",
                    "by_coord": {
                        "sample:consumer": {
                            "coord": "sample:consumer",
                            "version": "1",
                            "scope": "compile",
                            "jar_path": str(jar_path),
                        }
                    },
                },
            )
            apis = [{
                "coord": "com.vendor:api",
                "api_name": "com.vendor.Target.removed",
                "api_simple": "removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }]

            with patch.object(tracer, "run_cmd", side_effect=AssertionError("javap should be skipped")):
                tracer._build_packaged_runtime_dependency_scan_cache(apis, graph)

            cached = graph.runtime_dependency_catalog["_packaged_api_scan_results"]
            self.assertEqual(cached[tracer.build_api_identity_key(apis[0])]["status"], "miss")

    def test_constant_pool_does_not_require_javap_for_non_lookup_class_method(self):
        summary = {
            "has_dynamic_reference": False,
            "ref_members": [{"owner": "java/lang/Class", "name": "getName"}],
        }

        self.assertFalse(tracer._constant_pool_requires_javap(summary))

    def test_constant_pool_requires_javap_for_reflective_member_lookup(self):
        summary = {
            "has_dynamic_reference": False,
            "ref_members": [{
                "owner": "java/lang/Class", "name": "getDeclaredMethod",
            }],
        }

        self.assertTrue(tracer._constant_pool_requires_javap(summary))

    def test_batch_packaged_bytecode_keeps_reflection_string_candidates_for_javap(self):
        with tempfile.TemporaryDirectory() as tmp:
            classes_root = self._compile_java_fixture(
                tmp,
                "com/example/consumer/ReflectiveCall.java",
                """
package com.example.consumer;

public class ReflectiveCall {
    public Object invoke(String value) throws Exception {
        return Class.forName("com.vendor.Target")
            .getMethod("removed", String.class)
            .invoke(null, value);
    }
}
""",
            )
            jar_path = Path(tmp) / "consumer.jar"
            self._jar_compiled_classes(jar_path, classes_root)
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "status": "complete",
                    "by_coord": {
                        "sample:consumer": {
                            "coord": "sample:consumer",
                            "version": "1",
                            "scope": "compile",
                            "jar_path": str(jar_path),
                        }
                    },
                },
            )
            apis = [{
                "coord": "com.vendor:api",
                "api_name": "com.vendor.Target.removed",
                "api_simple": "removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }]
            javap_output = """
public class com.example.consumer.ReflectiveCall {
  public java.lang.Object invoke(java.lang.String) throws java.lang.Exception;
    descriptor: (Ljava/lang/String;)Ljava/lang/Object;
    Code:
       0: ldc           #7                  // String com.vendor.Target
       2: invokestatic  #9                  // Method java/lang/Class.forName:(Ljava/lang/String;)Ljava/lang/Class;
       5: ldc           #15                 // String removed
       7: iconst_1
       8: anewarray     #10                 // class java/lang/Class
      11: dup
      12: iconst_0
      13: ldc           #17                 // class java/lang/String
      15: aastore
      16: invokevirtual #19                 // Method java/lang/Class.getMethod:(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
      19: aconst_null
      20: iconst_1
      21: anewarray     #2                  // class java/lang/Object
      24: invokevirtual #23                 // Method java/lang/reflect/Method.invoke:(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
}
"""

            with patch.object(tracer, "run_cmd", return_value=(javap_output, "", 0)) as mocked_run:
                tracer._build_packaged_runtime_dependency_scan_cache(apis, graph)

            cached = graph.runtime_dependency_catalog["_packaged_api_scan_results"]
            self.assertEqual(mocked_run.call_count, 1)
            self.assertEqual(cached[tracer.build_api_identity_key(apis[0])]["status"], "hit")

    def test_batch_packaged_bytecode_javap_failure_does_not_poison_unrelated_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "consumer.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr(
                    "com/example/consumer/Broken.class",
                    b"com/vendor/BrokenTarget missing",
                )
                zf.writestr(
                    "com/example/consumer/Clean.class",
                    b"com/vendor/CleanTarget",
                )
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "status": "complete",
                    "by_coord": {
                        "sample:consumer": {
                            "coord": "sample:consumer",
                            "version": "1",
                            "scope": "compile",
                            "jar_path": str(jar_path),
                        }
                    },
                },
            )
            apis = [
                {
                    "coord": "com.vendor:api",
                    "api_name": "com.vendor.BrokenTarget.missing",
                    "api_simple": "missing",
                    "api_signature": "(String)",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                },
                {
                    "coord": "com.vendor:api",
                    "api_name": "com.vendor.UnrelatedTarget.missing",
                    "api_simple": "missing",
                    "api_signature": "(String)",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                },
            ]

            with patch.object(tracer, "run_cmd", return_value=("", "javap failed", 1)):
                tracer._build_packaged_runtime_dependency_scan_cache(apis, graph)

            cached = graph.runtime_dependency_catalog["_packaged_api_scan_results"]
            self.assertEqual(
                cached[tracer.build_api_identity_key(apis[0])]["status"],
                "unavailable",
            )
            self.assertEqual(
                cached[tracer.build_api_identity_key(apis[1])]["status"],
                "miss",
            )
            tool_failure = next(
                item for item in graph.step5_evidence_failures
                if item.reason_code == "STEP5_JAVAP_NONZERO_EXIT"
            )
            self.assertEqual(tool_failure.stage, "step5.bytecode.javap")
            self.assertTrue(tool_failure.blocking)
            self.assertIn("command=['javap'", tool_failure.detail)
            self.assertIn("stderr=javap failed", tool_failure.detail)
            self.assertIn("timeout_seconds=30", tool_failure.detail)

    def test_packaged_dependency_hit_is_reachable_when_business_bytecode_calls_consumer(self):
        result = tracer.TraceResult(
            api_name="com.acme.target.LegacyApi.removed",
            api_simple="removed",
            api_signature="(String)",
            symbol_kind="method",
            change_type="METHOD_REMOVED",
            coord="com.acme:target-lib",
            severity="P1",
            confirmed=True,
            source="japicmp",
            analysis_scope="method",
            analysis_status="unknown",
            direct_callers=0,
            is_reachable=False,
            reachable_note="",
            business_reach_depth=0,
            dependency_chain_coords=[],
            call_paths=[],
            evidence_paths=[],
            reason_code="",
            verification_commands=[],
            hops=[],
            confidence_score=1.0,
            critical_nodes_hit=[],
        )
        business_method = SimpleNamespace(
            symbol_id="app_entry",
            qualified_key="com.acme.app.App.entry",
            owner_type="business",
            is_test=False,
        )
        edge = SimpleNamespace(
            caller_symbol_id="app_entry",
            caller_qualified_key="com.acme.app.App.entry",
            callee_key="com.acme.consumer.ConsumerFacade.use(java.lang.String)",
            evidence_type="bytecode_method_invocation",
            confidence="high",
            file="/tmp/business-classes.jar",
            line=0,
            owner_type="business",
            owner_coord="__business__",
            module="app",
        )
        graph = SimpleNamespace(
            methods_by_id={"app_entry": business_method},
            reverse_edges={
                "com.acme.consumer.ConsumerFacade.use(java.lang.String)": [edge],
            },
        )
        hit = {
            "coord": "com.acme:consumer-lib",
            "class_fqcn": "com.acme.consumer.ConsumerFacade",
            "consumer_method": "use",
            "consumer_signature": "(String)",
            "target_display": "com.acme.target.LegacyApi.removed(String)",
            "evidence_type": "bytecode_method_invocation",
            "jar_path": "/tmp/consumer-lib.jar",
        }

        draft = self._draft_from_result(result)
        tracer._build_packaged_dependency_hit_result(draft, [hit], graph)
        built = tracer._finalize_trace_draft(draft)

        self.assertEqual(built.analysis_status, "reachable")
        self.assertEqual(built.reason_code, "BUSINESS_ARTIFACT_BYTECODE_USAGE")
        self.assertTrue(any(
            "com.acme.app.App.entry -> com.acme:consumer-lib:com.acme.consumer.ConsumerFacade.use(String)"
            in path
            for path in built.call_paths
        ))
        self.assertTrue(any(detail.get("business_reachable") for detail in built.path_details))
        self.assertEqual(built.direct_callers, 0)
        self.assertEqual(built.business_reach_depth, 2)
        self.assertEqual(built.dependency_chain_coords, ["com.acme:consumer-lib"])

    def test_runtime_dependency_bytecode_graph_connects_business_to_transitive_packaged_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_src = root / "target-src" / "com" / "vendor" / "Target.java"
            target_src.parent.mkdir(parents=True)
            target_src.write_text(
                "package com.vendor; public class Target { "
                "public static boolean removed(String s) { return s == null; } }",
                encoding="utf-8",
            )
            target_classes = self._compile_java_files(root / "target-classes", [target_src])
            target_jar = root / "target.jar"
            self._jar_compiled_classes(target_jar, target_classes)

            dep_b_src = root / "dep-b-src" / "com" / "depb" / "BridgeB.java"
            dep_b_src.parent.mkdir(parents=True)
            dep_b_src.write_text(
                "package com.depb; public class BridgeB { "
                "public boolean use(String s) { return com.vendor.Target.removed(s); } }",
                encoding="utf-8",
            )
            dep_b_classes = self._compile_java_files(root / "dep-b-classes", [dep_b_src], classpath=target_jar)
            dep_b_jar = root / "dep-b.jar"
            self._jar_compiled_classes(dep_b_jar, dep_b_classes)

            dep_a_src = root / "dep-a-src" / "com" / "depa" / "FacadeA.java"
            dep_a_src.parent.mkdir(parents=True)
            dep_a_src.write_text(
                "package com.depa; public class FacadeA { "
                "public boolean entry(String s) { return new com.depb.BridgeB().use(s); } }",
                encoding="utf-8",
            )
            classpath = os.pathsep.join([str(dep_b_jar), str(target_jar)])
            dep_a_classes = self._compile_java_files(root / "dep-a-classes", [dep_a_src], classpath=classpath)
            dep_a_jar = root / "dep-a.jar"
            self._jar_compiled_classes(dep_a_jar, dep_a_classes)

            api_row = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.removed",
                "api_simple": "removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
            catalog = {
                "status": "complete",
                "by_coord": {
                    "com.example:dep-a": {
                        "coord": "com.example:dep-a",
                        "version": "1",
                        "scope": "compile",
                        "jar_path": str(dep_a_jar),
                    },
                    "com.example:dep-b": {
                        "coord": "com.example:dep-b",
                        "version": "1",
                        "scope": "compile",
                        "jar_path": str(dep_b_jar),
                    },
                },
            }
            business_method = SimpleNamespace(
                symbol_id="app_run",
                qualified_key="com.app.App.run",
                owner_type="business",
                owner_coord="__business__",
                is_test=False,
            )
            business_to_a = source_analyzer.CallEdge(
                caller_symbol_id="app_run",
                caller_qualified_key="com.app.App.run",
                callee_key="com.depa.FacadeA.entry(java.lang.String)",
                callee_simple_key="method:entry(java.lang.String)",
                evidence_type="bytecode_method_invocation",
                confidence="high",
                file=str(root / "app.jar"),
                line=0,
                content="business bytecode calls dep-a",
                owner_type="business",
                owner_coord="__business__",
                module="app",
                is_test=False,
            )
            graph_with_business_edge = SimpleNamespace(
                methods_by_id={"app_run": business_method},
                reverse_edges={
                    "com.depa.FacadeA.entry(java.lang.String)": [business_to_a],
                },
                runtime_dependency_catalog=catalog,
            )
            reachable = tracer.trace_api_with_confidence_weighting(
                api_row,
                graph_with_business_edge,
                {},
                max_total_cost=5,
                needs_bridge=True,
                has_dependency_source_mapping=False,
                has_packaged_bytecode_fallback=True,
                allow_degraded=True,
            )
            self.assertEqual(reachable.analysis_status, "reachable")

            graph_with_runtime_edges_only = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog=catalog,
            )
            still_uncertain = tracer.trace_api_with_confidence_weighting(
                api_row,
                graph_with_runtime_edges_only,
                {},
                max_total_cost=5,
                needs_bridge=True,
                has_dependency_source_mapping=False,
                has_packaged_bytecode_fallback=True,
                allow_degraded=True,
            )
            self.assertEqual(still_uncertain.analysis_status, "uncertain")

        self.assertEqual(reachable.analysis_status, "reachable")
        self.assertEqual(reachable.reason_code, "BUSINESS_ARTIFACT_BYTECODE_USAGE")
        self.assertEqual(
            reachable.dependency_chain_coords,
            ["com.example:dep-b", "com.example:dep-a"],
        )
        self.assertTrue(any(
            "com.app.App.run -> com.example:dep-a:com.depa.FacadeA.entry(String) -> "
            "com.example:dep-b:com.depb.BridgeB.use(String) -> com.vendor.Target.removed(String)"
            in path
            for path in reachable.call_paths
        ))

    def test_runtime_dependency_bytecode_graph_connects_three_hop_packaged_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_src = root / "target-src" / "com" / "vendor" / "Target.java"
            target_src.parent.mkdir(parents=True)
            target_src.write_text(
                "package com.vendor; public class Target { "
                "public static boolean removed(String s) { return s == null; } }",
                encoding="utf-8",
            )
            target_classes = self._compile_java_files(root / "target-classes", [target_src])
            target_jar = root / "target.jar"
            self._jar_compiled_classes(target_jar, target_classes)

            dep_c_src = root / "dep-c-src" / "com" / "depc" / "LeafC.java"
            dep_c_src.parent.mkdir(parents=True)
            dep_c_src.write_text(
                "package com.depc; public class LeafC { "
                "public boolean use(String s) { return com.vendor.Target.removed(s); } }",
                encoding="utf-8",
            )
            dep_c_classes = self._compile_java_files(root / "dep-c-classes", [dep_c_src], classpath=target_jar)
            dep_c_jar = root / "dep-c.jar"
            self._jar_compiled_classes(dep_c_jar, dep_c_classes)

            dep_b_src = root / "dep-b-src" / "com" / "depb" / "MiddleB.java"
            dep_b_src.parent.mkdir(parents=True)
            dep_b_src.write_text(
                "package com.depb; public class MiddleB { "
                "public boolean call(String s) { return new com.depc.LeafC().use(s); } }",
                encoding="utf-8",
            )
            dep_b_cp = os.pathsep.join([str(dep_c_jar), str(target_jar)])
            dep_b_classes = self._compile_java_files(root / "dep-b-classes", [dep_b_src], classpath=dep_b_cp)
            dep_b_jar = root / "dep-b.jar"
            self._jar_compiled_classes(dep_b_jar, dep_b_classes)

            dep_a_src = root / "dep-a-src" / "com" / "depa" / "FacadeA.java"
            dep_a_src.parent.mkdir(parents=True)
            dep_a_src.write_text(
                "package com.depa; public class FacadeA { "
                "public boolean entry(String s) { return new com.depb.MiddleB().call(s); } }",
                encoding="utf-8",
            )
            dep_a_cp = os.pathsep.join([str(dep_b_jar), str(dep_c_jar), str(target_jar)])
            dep_a_classes = self._compile_java_files(root / "dep-a-classes", [dep_a_src], classpath=dep_a_cp)
            dep_a_jar = root / "dep-a.jar"
            self._jar_compiled_classes(dep_a_jar, dep_a_classes)

            api_row = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.removed",
                "api_simple": "removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
            catalog = self._runtime_catalog([
                ("com.example:dep-a", dep_a_jar),
                ("com.example:dep-b", dep_b_jar),
                ("com.example:dep-c", dep_c_jar),
            ])
            graph = self._graph_with_business_edge(
                catalog,
                "com.depa.FacadeA.entry(java.lang.String)",
                root,
            )

            reachable = self._trace_packaged_fixture(api_row, graph)

        self.assertEqual(reachable.analysis_status, "reachable")
        self.assertEqual(reachable.reason_code, "BUSINESS_ARTIFACT_BYTECODE_USAGE")
        self.assertEqual(
            reachable.dependency_chain_coords,
            ["com.example:dep-c", "com.example:dep-b", "com.example:dep-a"],
        )
        self.assertTrue(any(
            "com.app.App.run -> com.example:dep-a:com.depa.FacadeA.entry(String) -> "
            "com.example:dep-b:com.depb.MiddleB.call(String) -> com.example:dep-c:com.depc.LeafC.use(String) -> "
            "com.vendor.Target.removed(String)"
            in path
            for path in reachable.call_paths
        ))

    def test_deleted_commons_lang_many_runtime_jars_reaches_business_via_dependency_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            commons_src = root / "commons-src" / "org" / "apache" / "commons" / "lang" / "StringUtils.java"
            commons_src.parent.mkdir(parents=True)
            commons_src.write_text(
                "package org.apache.commons.lang; public class StringUtils { "
                "public static boolean isBlank(String s) { return s == null || s.trim().isEmpty(); } "
                "public static final String EMPTY = \"\"; }",
                encoding="utf-8",
            )
            commons_classes = self._compile_java_files(root / "commons-classes", [commons_src])
            commons_jar = root / "commons-lang.jar"
            self._jar_compiled_classes(commons_jar, commons_classes)

            dep_b_src = root / "dep-b-src" / "com" / "consumer" / "BridgeB.java"
            dep_b_src.parent.mkdir(parents=True)
            dep_b_src.write_text(
                "package com.consumer; public class BridgeB { "
                "public boolean use(String s) { return org.apache.commons.lang.StringUtils.isBlank(s); } }",
                encoding="utf-8",
            )
            dep_b_classes = self._compile_java_files(root / "dep-b-classes", [dep_b_src], classpath=commons_jar)
            dep_b_jar = root / "dep-b.jar"
            self._jar_compiled_classes(dep_b_jar, dep_b_classes)

            dep_a_src = root / "dep-a-src" / "com" / "consumer" / "FacadeA.java"
            dep_a_src.parent.mkdir(parents=True)
            dep_a_src.write_text(
                "package com.consumer; public class FacadeA { "
                "public boolean entry(String s) { return new com.consumer.BridgeB().use(s); } }",
                encoding="utf-8",
            )
            dep_a_cp = os.pathsep.join([str(dep_b_jar), str(commons_jar)])
            dep_a_classes = self._compile_java_files(root / "dep-a-classes", [dep_a_src], classpath=dep_a_cp)
            dep_a_jar = root / "dep-a.jar"
            self._jar_compiled_classes(dep_a_jar, dep_a_classes)

            dummy_entries = []
            for idx in range(60):
                dummy_jar = root / f"dummy-{idx}.jar"
                with zipfile.ZipFile(dummy_jar, "w") as zf:
                    zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
                dummy_entries.append((f"com.example:dummy-{idx}", dummy_jar))

            api_row = {
                "coord": "commons-lang:commons-lang",
                "api_name": "org.apache.commons.lang.StringUtils.isBlank",
                "api_simple": "isBlank",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
            catalog = self._runtime_catalog([
                ("com.example:dep-a", dep_a_jar),
                ("com.example:dep-b", dep_b_jar),
                *dummy_entries,
            ])
            graph = self._graph_with_business_edge(
                catalog,
                "com.consumer.FacadeA.entry(java.lang.String)",
                root,
            )

            reachable = self._trace_packaged_fixture(api_row, graph)
            all_perf = tracer._finalize_step5_perf_stats(graph)
            perf = all_perf["bytecode_expand"]

        self.assertEqual(reachable.analysis_status, "reachable")
        self.assertEqual(reachable.reason_code, "BUSINESS_ARTIFACT_BYTECODE_USAGE")
        self.assertEqual(
            reachable.dependency_chain_coords,
            ["com.example:dep-b", "com.example:dep-a"],
        )
        self.assertTrue(any(
            "com.app.App.run -> com.example:dep-a:com.consumer.FacadeA.entry(String) -> "
            "com.example:dep-b:com.consumer.BridgeB.use(String) -> "
            "org.apache.commons.lang.StringUtils.isBlank(String)"
            in path
            for path in reachable.call_paths
        ))
        self.assertGreaterEqual(perf["member_index_auto_large_catalog"], 1.0)
        self.assertGreaterEqual(perf["member_index_builds"], 1.0)
        self.assertGreaterEqual(perf["member_index_candidate_queries"], 1.0)
        self.assertNotIn("light_scans", perf)
        self.assertTrue(any(
            item.get("candidate_source") == "member_index"
            for item in perf.get("slow_runtime_lookups", [])
        ))
        self.assertGreater(all_perf["bytecode_scan"]["class_entries_parsed"], 0)
        self.assertEqual(all_perf["bytecode_scan"]["duplicate_class_scans"], 0)

    def test_packaged_runtime_scan_javap_handles_base_classes_without_multi_release_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_src = root / "target-src" / "com" / "vendor" / "Target.java"
            target_src.parent.mkdir(parents=True)
            target_src.write_text(
                "package com.vendor; public class Target { "
                "public static String removed(String s) { return s == null ? \"\" : s; } }",
                encoding="utf-8",
            )
            target_classes = self._compile_java_files(root / "target-classes", [target_src])
            target_jar = root / "target.jar"
            self._jar_compiled_classes(target_jar, target_classes)

            consumer_src = root / "consumer-src" / "com" / "consumer" / "UsesTarget.java"
            consumer_src.parent.mkdir(parents=True)
            consumer_src.write_text(
                "package com.consumer; public class UsesTarget { "
                "public String call(String s) { return com.vendor.Target.removed(s); } }",
                encoding="utf-8",
            )
            consumer_classes = self._compile_java_files(root / "consumer-classes", [consumer_src], classpath=target_jar)
            consumer_jar = root / "consumer.jar"
            self._jar_compiled_classes(consumer_jar, consumer_classes)

            api_row = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.removed",
                "api_simple": "removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
            catalog = self._runtime_catalog([
                ("com.vendor:target", target_jar),
                ("com.example:consumer", consumer_jar),
            ])
            graph = SimpleNamespace(
                runtime_dependency_catalog=catalog,
                reverse_edges={"force_javap_path": []},
            )

            result = tracer._scan_packaged_runtime_dependencies_for_api(api_row, graph)

        self.assertEqual(result["status"], "hit")
        self.assertEqual(result["hits"][0]["coord"], "com.example:consumer")
        self.assertEqual(result["hits"][0]["consumer_method"], "call")
        self.assertEqual(
            result["hits"][0]["target_display"],
            "com.vendor.Target.removed(String)",
        )

    def test_runtime_dependency_bytecode_graph_does_not_infer_unconnected_packaged_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_src = root / "target-src" / "com" / "vendor" / "Target.java"
            target_src.parent.mkdir(parents=True)
            target_src.write_text(
                "package com.vendor; public class Target { "
                "public static boolean removed(String s) { return s == null; } }",
                encoding="utf-8",
            )
            target_classes = self._compile_java_files(root / "target-classes", [target_src])
            target_jar = root / "target.jar"
            self._jar_compiled_classes(target_jar, target_classes)

            dep_b_src = root / "dep-b-src" / "com" / "depb" / "BridgeB.java"
            dep_b_src.parent.mkdir(parents=True)
            dep_b_src.write_text(
                "package com.depb; public class BridgeB { "
                "public boolean use(String s) { return com.vendor.Target.removed(s); } }",
                encoding="utf-8",
            )
            dep_b_classes = self._compile_java_files(root / "dep-b-classes", [dep_b_src], classpath=target_jar)
            dep_b_jar = root / "dep-b.jar"
            self._jar_compiled_classes(dep_b_jar, dep_b_classes)

            dep_a_src = root / "dep-a-src" / "com" / "depa" / "FacadeA.java"
            dep_a_src.parent.mkdir(parents=True)
            dep_a_src.write_text(
                "package com.depa; public class FacadeA { "
                "public boolean entry(String s) { return s != null; } }",
                encoding="utf-8",
            )
            dep_a_classes = self._compile_java_files(root / "dep-a-classes", [dep_a_src])
            dep_a_jar = root / "dep-a.jar"
            self._jar_compiled_classes(dep_a_jar, dep_a_classes)

            api_row = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.removed",
                "api_simple": "removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
            catalog = self._runtime_catalog([
                ("com.example:dep-a", dep_a_jar),
                ("com.example:dep-b", dep_b_jar),
            ])
            graph = self._graph_with_business_edge(
                catalog,
                "com.depa.FacadeA.entry(java.lang.String)",
                root,
            )

            result = self._trace_packaged_fixture(api_row, graph)

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "PACKAGED_DEPENDENCY_BYTECODE_USAGE")
        self.assertEqual(result.dependency_chain_coords, ["com.example:dep-b"])
        self.assertFalse(any(detail.get("business_reachable") for detail in result.path_details))

    def test_runtime_dependency_bytecode_graph_does_not_cross_wrong_overload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_src = root / "target-src" / "com" / "vendor" / "Target.java"
            target_src.parent.mkdir(parents=True)
            target_src.write_text(
                "package com.vendor; public class Target { "
                "public static boolean removed(String s) { return s == null; } }",
                encoding="utf-8",
            )
            target_classes = self._compile_java_files(root / "target-classes", [target_src])
            target_jar = root / "target.jar"
            self._jar_compiled_classes(target_jar, target_classes)

            dep_b_src = root / "dep-b-src" / "com" / "depb" / "BridgeB.java"
            dep_b_src.parent.mkdir(parents=True)
            dep_b_src.write_text(
                "package com.depb; public class BridgeB { "
                "public boolean use(String s) { return com.vendor.Target.removed(s); } "
                "public boolean use(Integer value) { return value != null; } }",
                encoding="utf-8",
            )
            dep_b_classes = self._compile_java_files(root / "dep-b-classes", [dep_b_src], classpath=target_jar)
            dep_b_jar = root / "dep-b.jar"
            self._jar_compiled_classes(dep_b_jar, dep_b_classes)

            dep_a_src = root / "dep-a-src" / "com" / "depa" / "FacadeA.java"
            dep_a_src.parent.mkdir(parents=True)
            dep_a_src.write_text(
                "package com.depa; public class FacadeA { "
                "public boolean entry() { return new com.depb.BridgeB().use(Integer.valueOf(1)); } }",
                encoding="utf-8",
            )
            dep_a_cp = os.pathsep.join([str(dep_b_jar), str(target_jar)])
            dep_a_classes = self._compile_java_files(root / "dep-a-classes", [dep_a_src], classpath=dep_a_cp)
            dep_a_jar = root / "dep-a.jar"
            self._jar_compiled_classes(dep_a_jar, dep_a_classes)

            api_row = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.removed",
                "api_simple": "removed",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
            catalog = self._runtime_catalog([
                ("com.example:dep-a", dep_a_jar),
                ("com.example:dep-b", dep_b_jar),
            ])
            graph = self._graph_with_business_edge(catalog, "com.depa.FacadeA.entry()", root)

            result = self._trace_packaged_fixture(api_row, graph)

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "PACKAGED_DEPENDENCY_BYTECODE_USAGE")
        self.assertEqual(result.dependency_chain_coords, ["com.example:dep-b"])
        self.assertFalse(any(
            "com.app.App.run" in path and "BridgeB.use(String)" in path
            for path in result.call_paths
        ))

    def test_runtime_dependency_bytecode_graph_connects_business_to_changed_field_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_src = root / "target-src" / "com" / "vendor" / "Target.java"
            target_src.parent.mkdir(parents=True)
            target_src.write_text(
                "package com.vendor; public class Target { "
                "public static String REMOVED_FIELD = \"legacy\"; }",
                encoding="utf-8",
            )
            target_classes = self._compile_java_files(root / "target-classes", [target_src])
            target_jar = root / "target.jar"
            self._jar_compiled_classes(target_jar, target_classes)

            dep_b_src = root / "dep-b-src" / "com" / "depb" / "BridgeB.java"
            dep_b_src.parent.mkdir(parents=True)
            dep_b_src.write_text(
                "package com.depb; public class BridgeB { "
                "public String use() { return com.vendor.Target.REMOVED_FIELD; } }",
                encoding="utf-8",
            )
            dep_b_classes = self._compile_java_files(root / "dep-b-classes", [dep_b_src], classpath=target_jar)
            dep_b_jar = root / "dep-b.jar"
            self._jar_compiled_classes(dep_b_jar, dep_b_classes)

            dep_a_src = root / "dep-a-src" / "com" / "depa" / "FacadeA.java"
            dep_a_src.parent.mkdir(parents=True)
            dep_a_src.write_text(
                "package com.depa; public class FacadeA { "
                "public String entry() { return new com.depb.BridgeB().use(); } }",
                encoding="utf-8",
            )
            dep_a_cp = os.pathsep.join([str(dep_b_jar), str(target_jar)])
            dep_a_classes = self._compile_java_files(root / "dep-a-classes", [dep_a_src], classpath=dep_a_cp)
            dep_a_jar = root / "dep-a.jar"
            self._jar_compiled_classes(dep_a_jar, dep_a_classes)

            api_row = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.REMOVED_FIELD",
                "api_simple": "REMOVED_FIELD",
                "api_signature": "java.lang.String",
                "symbol_kind": "field",
                "change_type": "REMOVED",
            }
            catalog = self._runtime_catalog([
                ("com.example:dep-a", dep_a_jar),
                ("com.example:dep-b", dep_b_jar),
            ])
            graph = self._graph_with_business_edge(catalog, "com.depa.FacadeA.entry()", root)

            reachable = self._trace_packaged_fixture(api_row, graph)

        self.assertEqual(reachable.analysis_status, "reachable")
        self.assertEqual(reachable.reason_code, "BUSINESS_ARTIFACT_BYTECODE_USAGE")
        self.assertEqual(
            reachable.dependency_chain_coords,
            ["com.example:dep-b", "com.example:dep-a"],
        )
        self.assertTrue(any(
            "com.app.App.run -> com.example:dep-a:com.depa.FacadeA.entry() -> "
            "com.example:dep-b:com.depb.BridgeB.use() -> com.vendor.Target.REMOVED_FIELD"
            in path
            for path in reachable.call_paths
        ))

    def test_version_upgrade_scans_runtime_consumers_even_when_target_source_mapping_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "consumer.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr(
                    "com/example/consumer/Adapter.class",
                    b"com/vendor/Client removedMethod",
                )
            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "status": "complete",
                    "by_coord": {
                        "sample:consumer": {
                            "coord": "sample:consumer", "version": "1", "scope": "packaged",
                            "jar_path": str(jar_path),
                        }
                    },
                },
            )
            api_row = {
                "coord": "com.vendor:client",
                "old_version": "1.0", "new_version": "2.0",
                "api_name": "com.vendor.Client.removedMethod",
                "api_simple": "removedMethod", "api_signature": "(String)",
                "symbol_kind": "method", "change_type": "METHOD_REMOVED",
                "severity": "P0", "confirmed": "true",
            }
            javap_output = """
public class com.example.consumer.Adapter {
  public void use();
    descriptor: ()V
    Code:
       1: invokevirtual #7 // Method com/vendor/Client.removedMethod:(Ljava/lang/String;)V
}
"""
            with patch.object(tracer, "run_cmd", return_value=(javap_output, "", 0)):
                result = tracer.trace_api_with_confidence_weighting(
                    api_row, graph, {}, max_total_cost=5,
                    needs_bridge=False,
                    has_dependency_source_mapping=True,
                    has_packaged_bytecode_fallback=True,
                    allow_degraded=False,
                )

            self.assertEqual(result.analysis_status, "uncertain")
            self.assertEqual(result.reason_code, "PACKAGED_DEPENDENCY_BYTECODE_USAGE")
            self.assertEqual(result.dependency_chain_coords, ["sample:consumer"])

    def test_trace_api_keeps_following_source_path_after_packaged_dependency_hit(self):
        api_row = {
            "coord": "com.example:repository",
            "api_name": "com.example.multimodule.repository.UserRepository.findByEmail",
            "api_simple": "findByEmail",
            "api_signature": "(String)",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
            "severity": "P1",
            "confirmed": "true",
            "analysis_scope": "method",
        }
        service_method = SimpleNamespace(
            symbol_id="service_method",
            qualified_key="com.example.multimodule.services.impl.UserServiceImpl.getUserByEmail",
            simple_key="method:getUserByEmail",
            class_fqcn="com.example.multimodule.services.impl.UserServiceImpl",
            class_name="UserServiceImpl",
            method_name="getUserByEmail",
            param_types={"email": "java.lang.String"},
            param_declared_types={"email": "String"},
            owner_type="dependency",
            is_test=False,
            annotations=[],
            class_annotations=[],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/UserServiceImpl.java",
            line=38,
        )
        controller_method = SimpleNamespace(
            symbol_id="controller_method",
            qualified_key="com.example.multimodule.controller.UserController.getUserByEmail",
            simple_key="method:getUserByEmail",
            class_fqcn="com.example.multimodule.controller.UserController",
            class_name="UserController",
            method_name="getUserByEmail",
            param_types={"email": "java.lang.String"},
            param_declared_types={"email": "String"},
            owner_type="business",
            is_test=False,
            annotations=["GetMapping"],
            class_annotations=["RestController"],
            modifiers=["public"],
            is_interface=False,
            file="/tmp/UserController.java",
            line=26,
        )
        graph = SimpleNamespace(
            methods_by_id={
                "service_method": service_method,
                "controller_method": controller_method,
            },
            reverse_edges={
                "com.example.multimodule.repository.UserRepository.findByEmail(String)": [
                    SimpleNamespace(
                        caller_symbol_id="service_method",
                        caller_qualified_key=service_method.qualified_key,
                        callee_key="com.example.multimodule.repository.UserRepository.findByEmail(String)",
                        callee_simple_key="method:findByEmail(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=service_method.file,
                        line=service_method.line,
                        owner_type="dependency",
                        owner_coord="com.example:services",
                        module="services",
                        is_test=False,
                    ),
                ],
                "com.example.multimodule.services.impl.UserServiceImpl.getUserByEmail(String)": [
                    SimpleNamespace(
                        caller_symbol_id="controller_method",
                        caller_qualified_key=controller_method.qualified_key,
                        callee_key="com.example.multimodule.services.impl.UserServiceImpl.getUserByEmail(String)",
                        callee_simple_key="method:getUserByEmail(String)",
                        confidence="high",
                        evidence_type="ast_method_invocation",
                        file=controller_method.file,
                        line=controller_method.line,
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="controller",
                        is_test=False,
                    ),
                ],
            },
        )

        packaged_scan_hit = {
            "status": "hit",
            "hits": [{
                "coord": "com.example:services",
                "class_fqcn": "com.example.multimodule.services.impl.UserServiceImpl",
                "consumer_method": "getUserByEmail",
                "consumer_signature": "(String)",
                "target_display": "com.example.multimodule.repository.UserRepository.findByEmail(String)",
                "jar_path": "/tmp/services.jar",
                "evidence_type": "bytecode_method_invocation",
            }],
        }

        with patch.object(tracer, "_scan_packaged_runtime_dependencies_for_api", return_value=packaged_scan_hit):
            result = tracer.trace_api_with_confidence_weighting(
                api_row,
                graph,
                {},
                max_total_cost=5,
                needs_bridge=True,
                has_dependency_source_mapping=True,
                has_packaged_bytecode_fallback=True,
                allow_degraded=False,
            )

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")
        self.assertIn("UserController.getUserByEmail", result.call_paths[0])
        self.assertIn("UserServiceImpl.getUserByEmail", result.call_paths[0])
        self.assertEqual(result.dependency_chain_coords, ["com.example:services"])

    def test_trace_api_keeps_packaged_bytecode_result_for_class_usage(self):
        api_row = {
            "coord": "sample:consumer",
            "api_name": "com.vendor.TargetType",
            "api_simple": "TargetType",
            "api_signature": "",
            "symbol_kind": "class",
            "change_type": "CLASS_REMOVED",
            "severity": "P1",
            "confirmed": "true",
            "analysis_scope": "class_usage",
            "matched_class": "com.vendor.TargetType",
        }
        graph = SimpleNamespace(methods_by_id={}, reverse_edges={})
        packaged_scan_hit = {
            "status": "hit",
            "hits": [{
                "coord": "sample:consumer",
                "class_fqcn": "com.example.consumer.Adapter",
                "consumer_method": "use",
                "consumer_signature": "()",
                "target_display": "com.vendor.TargetType",
                "jar_path": "/tmp/consumer.jar",
                "evidence_type": "bytecode_class_reference",
            }],
        }

        with patch.object(tracer, "_scan_packaged_runtime_dependencies_for_api", return_value=packaged_scan_hit):
            result = tracer.trace_api_with_confidence_weighting(
                api_row,
                graph,
                {},
                max_total_cost=5,
                needs_bridge=False,
                has_dependency_source_mapping=False,
                has_packaged_bytecode_fallback=True,
                allow_degraded=False,
            )

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "PACKAGED_DEPENDENCY_BYTECODE_USAGE")
        self.assertNotEqual(result.reason_code, "CLASS_USAGE_ONLY")

    def test_packaged_consumer_scan_continues_after_one_javap_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            broken_jar = Path(tmp) / "broken.jar"
            hit_jar = Path(tmp) / "hit.jar"
            for path, entry in (
                (broken_jar, "com/acme/Broken.class"),
                (hit_jar, "com/acme/Hit.class"),
            ):
                with zipfile.ZipFile(path, "w") as zf:
                    zf.writestr(entry, b"org/apache/commons/lang/StringUtils isBlank")
            graph = SimpleNamespace(runtime_dependency_catalog={
                "by_coord": {
                    "a:broken": {"jar_path": str(broken_jar)},
                    "b:hit": {"jar_path": str(hit_jar)},
                }
            })
            api_row = {
                "coord": "commons-lang:commons-lang",
                "api_name": "org.apache.commons.lang.StringUtils.isBlank",
                "api_simple": "isBlank", "api_signature": "(String)", "symbol_kind": "method",
            }
            refs = {
                "method_refs": [{
                    "owner": "org.apache.commons.lang.StringUtils", "name": "isBlank",
                    "signature": "(String)", "descriptor": "(Ljava/lang/String;)Z",
                    "opcode_family": "invokestatic", "instruction_offset": 0,
                }],
                "field_refs": [], "class_refs": [],
            }

            def load_references(_catalog, coord, *_args, **_kwargs):
                return None if coord == "a:broken" else refs

            with patch.object(
                tracer,
                "_load_runtime_dependency_class_references",
                side_effect=load_references,
            ):
                scan = tracer._scan_packaged_runtime_dependencies_for_api(api_row, graph)

            self.assertEqual(scan["status"], "hit")
            self.assertEqual(scan["hits"][0]["coord"], "b:hit")
            self.assertEqual(len(scan["scan_failures"]), 1)

    def test_packaged_consumer_scan_does_not_report_miss_when_any_candidate_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            broken_jar = Path(tmp) / "broken.jar"
            clean_jar = Path(tmp) / "clean.jar"
            for path, entry in (
                (broken_jar, "com/acme/Broken.class"),
                (clean_jar, "com/acme/Clean.class"),
            ):
                with zipfile.ZipFile(path, "w") as zf:
                    zf.writestr(entry, b"com/vendor/Target call")
            graph = SimpleNamespace(runtime_dependency_catalog={
                "status": "complete",
                "by_coord": {
                    "a:broken": {"jar_path": str(broken_jar)},
                    "b:clean": {"jar_path": str(clean_jar)},
                },
            })
            api_row = {
                "coord": "com.vendor:target", "api_name": "com.vendor.Target.call",
                "api_simple": "call", "api_signature": "()", "symbol_kind": "method",
            }
            no_match = {"method_refs": [], "field_refs": [], "class_refs": []}
            with patch.object(
                tracer,
                "_load_runtime_dependency_class_references",
                side_effect=[None, no_match],
            ):
                scan = tracer._scan_packaged_runtime_dependencies_for_api(api_row, graph)

            self.assertEqual(scan["status"], "unavailable")
            self.assertEqual(scan["reason"], "BYTECODE_JAVAP_FAILED")

    def test_trace_api_uses_packaged_bytecode_fallback_for_constructor_with_quoted_javap_init(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "consumer.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr(
                    "com/example/consumer/Adapter.class",
                    b"com/example/consumer/Adapter org/apache/commons/lang/NotImplementedException",
                )

            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "by_coord": {
                        "sample:consumer": {
                            "coord": "sample:consumer",
                            "version": "1.0.0",
                            "scope": "compile",
                            "jar_path": str(jar_path),
                        }
                    }
                },
            )
            api_row = {
                "coord": "commons-lang:commons-lang",
                "api_name": "org.apache.commons.lang.NotImplementedException.NotImplementedException",
                "api_simple": "NotImplementedException",
                "api_signature": "()",
                "symbol_kind": "constructor",
                "change_type": "REMOVED",
                "severity": "P1",
                "confirmed": "true",
                "source": "old_jar",
            }

            javap_output = """
Compiled from "Adapter.java"
public class com.example.consumer.Adapter {
  public void use();
    descriptor: ()V
    Code:
       0: new           #7 // class org/apache/commons/lang/NotImplementedException
       3: dup
       4: invokespecial #8 // Method org/apache/commons/lang/NotImplementedException."<init>":()V
       7: pop
       8: return
}
"""

            with patch.object(tracer, "run_cmd", return_value=(javap_output, "", 0)):
                result = tracer.trace_api_with_confidence_weighting(
                    api_row,
                    graph,
                    {},
                    max_total_cost=5,
                    needs_bridge=True,
                    has_dependency_source_mapping=False,
                    has_packaged_bytecode_fallback=True,
                    allow_degraded=True,
                )

            self.assertEqual(result.analysis_status, "uncertain")
            self.assertEqual(result.reason_code, "PACKAGED_DEPENDENCY_BYTECODE_USAGE")
            self.assertEqual(result.dependency_chain_coords, ["sample:consumer"])
            self.assertIn("org.apache.commons.lang.NotImplementedException.<init>()", result.call_paths[0])

    def test_trace_api_reports_not_found_after_packaged_bytecode_scan_miss(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "consumer.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr(
                    "com/example/consumer/Adapter.class",
                    b"com/example/consumer/Adapter",
                )

            graph = SimpleNamespace(
                methods_by_id={},
                reverse_edges={},
                runtime_dependency_catalog={
                    "by_coord": {
                        "sample:consumer": {
                            "coord": "sample:consumer",
                            "version": "1.0.0",
                            "scope": "compile",
                            "jar_path": str(jar_path),
                        }
                    }
                },
            )
            api_row = {
                "coord": "commons-lang:commons-lang",
                "api_name": "org.apache.commons.lang.StringUtils.isBlank",
                "api_simple": "isBlank",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "severity": "P1",
                "confirmed": "true",
                "source": "old_jar",
            }

            result = tracer.trace_api_with_confidence_weighting(
                api_row,
                graph,
                {},
                max_total_cost=5,
                needs_bridge=True,
                has_dependency_source_mapping=False,
                has_packaged_bytecode_fallback=True,
                allow_degraded=True,
            )

            self.assertEqual(result.analysis_status, "not_found_in_static_analysis")
            self.assertEqual(result.reason_code, "NO_STATIC_PATH")

    def test_check_apis_that_need_bridge_marks_packaged_bytecode_fallback(self):
        requirements = step5.check_apis_that_need_bridge(
            [
                {
                    "coord": "commons-lang:commons-lang",
                    "api_name": "org.apache.commons.lang.StringUtils.isBlank",
                    "api_signature": "(String)",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                }
            ],
            str(ROOT_DIR),
            source_dirs=[],
            business_graph=None,
            dependency_source_mappings=[],
            runtime_dependency_catalog={
                "by_coord": {
                    "sample:consumer": {
                        "coord": "sample:consumer",
                        "jar_path": "/tmp/consumer.jar",
                    }
                },
                "status": "complete",
            },
        )

        info = requirements[
            tracer.build_api_identity_key(
                {
                    "coord": "commons-lang:commons-lang",
                    "api_name": "org.apache.commons.lang.StringUtils.isBlank",
                    "api_signature": "(String)",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                }
            )
        ]
        self.assertTrue(info["needs_bridge"])
        self.assertFalse(info["has_dependency_source_mapping"])
        self.assertTrue(info["has_packaged_bytecode_fallback"])

    def test_runtime_reference_signature_rejects_ambiguous_unqualified_imported_type(self):
        reference = {
            "signature": "(com.wrong.Request)",
            "descriptor": "(Lcom/wrong/Request;)V",
        }

        self.assertFalse(
            tracer._runtime_reference_signature_matches("(com.right.Request)", reference)
        )
        self.assertFalse(
            tracer._runtime_reference_signature_matches(
                "(Request)", reference, "com.right.Target"
            )
        )
        self.assertTrue(
            tracer._runtime_reference_signature_matches(
                "(Request)", reference, "com.wrong.Target"
            )
        )

        matches = tracer._match_runtime_dependency_references(
            {
                "api_name": "com.right.Target.call",
                "api_signature": "(Request)",
                "symbol_kind": "method",
            },
            {"method_refs": [{
                **reference,
                "owner": "com.right.Target",
                "name": "call",
                "consumer_method": "invoke",
                "consumer_signature": "()",
                "opcode_family": "invokevirtual",
                "instruction_offset": 1,
                "reference_kind": "classfile_methodref",
            }]},
        )
        self.assertEqual(len(matches), 1)
        self.assertTrue(matches[0]["signature_ambiguous"])

    def test_packaged_ambiguous_unqualified_signature_cannot_confirm_impact(self):
        result = tracer.TraceResult(
            api_name="com.right.Target.call", api_simple="call", api_signature="(Request)",
            symbol_kind="method", change_type="REMOVED", coord="com.right:target",
            severity="P1", confirmed=True, source="git_diff", analysis_scope="method",
            analysis_status="not_analyzed", direct_callers=0, is_reachable=False,
            reachable_note="", business_reach_depth=0, dependency_chain_coords=[],
            call_paths=[], evidence_paths=[], reason_code="", verification_commands=[],
            hops=[], confidence_score=1.0, critical_nodes_hit=[],
        )
        hit = {
            "coord": "__business__", "class_fqcn": "app.Entry",
            "consumer_method": "run", "consumer_signature": "()",
            "target_display": "com.right.Target.call(com.shared.Request)",
            "signature_ambiguous": True, "evidence_type": "bytecode_method_invocation",
        }

        draft = self._draft_from_result(result)
        tracer._build_packaged_dependency_hit_result(draft, [hit])
        built = tracer._finalize_trace_draft(draft)

        self.assertEqual(built.analysis_status, "uncertain")
        self.assertIsNone(built.is_reachable)
        self.assertEqual(built.reason_code, "UNQUALIFIED_SIGNATURE_TYPE_AMBIGUOUS")
        user_view = formatter.summarize_user_facing_outcome(built)
        self.assertIn("简写参数类型", user_view["user_reason"])
        self.assertIn("限定包名", user_view["recommended_action"])

    def test_packaged_application_owned_module_hit_without_entry_is_uncertain(self):
        result = tracer.TraceResult(
            api_name="com.example.LibraryApi.changed", api_simple="changed",
            api_signature="()", symbol_kind="method", change_type="REMOVED",
            coord="com.example:library", severity="P1", confirmed=True,
            source="git_diff", analysis_scope="method",
            analysis_status="not_analyzed", direct_callers=0,
            is_reachable=False, reachable_note="", business_reach_depth=0,
            dependency_chain_coords=[], call_paths=[], evidence_paths=[],
            reason_code="", verification_commands=[], hops=[],
            confidence_score=1.0, critical_nodes_hit=[],
        )
        hit = {
            "coord": "com.example:library",
            "application_owned": True,
            "ownership_evidence": {
                "authority": "reactor_coordinate_and_final_artifact_entry",
                "reactor_coord": "com.example:library",
                "artifact_entry": "BOOT-INF/lib/library.jar",
                "final_artifact_sha256": "a" * 64,
            },
            "edge_role": "internal_bridge",
            "class_fqcn": "com.example.LibraryCaller",
            "consumer_method": "run",
            "consumer_signature": "()",
            "target_display": "com.example.LibraryApi.changed()",
            "evidence_type": "bytecode_method_invocation",
            "jar_path": "app.jar!/BOOT-INF/lib/library.jar",
        }

        draft = self._draft_from_result(result)
        tracer._build_packaged_dependency_hit_result(draft, [hit])
        built = tracer._finalize_trace_draft(draft)

        self.assertEqual(built.analysis_status, "uncertain")
        self.assertIsNone(built.is_reachable)
        self.assertFalse(built.path_details[0]["business_reachable"])
        self.assertEqual(
            draft.envelope_paths[0].entry_scope,
            tracer.ModuleScope.INTERNAL_MODULE,
        )

    def test_packaged_application_owned_class_hit_uses_verified_framework_entry(self):
        result = tracer.TraceResult(
            api_name="com.example.LibraryApi", api_simple="LibraryApi",
            api_signature="", symbol_kind="class", change_type="SIGNATURE_CHANGED",
            coord="com.example:library", severity="P1", confirmed=True,
            source="classfile_contract", analysis_scope="class_usage",
            analysis_status="not_analyzed", direct_callers=0,
            is_reachable=False, reachable_note="", business_reach_depth=0,
            dependency_chain_coords=[], call_paths=[], evidence_paths=[],
            reason_code="", verification_commands=[], hops=[],
            confidence_score=1.0, critical_nodes_hit=[],
        )
        hit = {
            "coord": "com.example:library",
            "application_owned": True,
            "edge_role": "internal_bridge",
            "class_fqcn": "com.example.RegisteredService",
            "consumer_method": "<class-constant>",
            "consumer_signature": "",
            "target_display": "com.example.LibraryApi",
            "evidence_type": "bytecode_class_constant_reference",
            "jar_path": "app.jar!/BOOT-INF/lib/library.jar",
        }
        graph = SimpleNamespace(framework_runtime_entry_classes={
            "com.example.RegisteredService": [{
                "source": "framework:spring-autoconfiguration",
                "target": "com.example.RegisteredService",
                "edge_kind": "spring_runtime_autoconfiguration_registration",
                "confidence": "high",
                "activation_verified": True,
                "provenance": {
                    "coord": "com.example:library",
                    "jar": "app.jar!/BOOT-INF/lib/library.jar",
                    "artifact_sha256": "a" * 64,
                    "resource": (
                        "META-INF/spring/org.springframework.boot.autoconfigure."
                        "AutoConfiguration.imports"
                    ),
                    "business_activation": [{
                        "business_entry": "com.example.Application.main",
                    }],
                },
            }],
        })

        draft = self._draft_from_result(result)
        tracer._build_packaged_dependency_hit_result(draft, [hit], graph)
        built = tracer._finalize_trace_draft(draft)

        self.assertEqual(built.analysis_status, "reachable")
        self.assertTrue(built.is_reachable)
        self.assertIn("com.example.Application.main", built.call_paths[1])
        self.assertEqual(
            built.path_details[1]["stop_reason"],
            "RUNTIME_FRAMEWORK_ENTRY_REACHED",
        )

    def test_external_provider_same_owner_field_access_is_not_project_usage(self):
        result = tracer.TraceResult(
            api_name="vendor.Settings.enabled", api_simple="enabled",
            api_signature="", symbol_kind="field", change_type="DATA_FIELD_ADDED",
            coord="vendor:api", severity="P1", confirmed=True,
            source="classfile_contract", analysis_scope="field",
            analysis_status="not_analyzed", direct_callers=0,
            is_reachable=False, reachable_note="", business_reach_depth=0,
            dependency_chain_coords=[], call_paths=[], evidence_paths=[],
            reason_code="", verification_commands=[], hops=[],
            confidence_score=1.0, critical_nodes_hit=[],
        )
        hit = {
            "coord": "vendor:api",
            "application_owned": False,
            "edge_role": "internal_bridge",
            "class_fqcn": "vendor.Settings",
            "consumer_method": "enabled",
            "consumer_signature": "()",
            "target_display": "vendor.Settings.enabled",
            "evidence_type": "bytecode_field_access",
            "jar_path": "/tmp/vendor-api.jar",
        }

        draft = self._draft_from_result(result)
        tracer._build_packaged_dependency_hit_result(draft, [hit])
        built = tracer._finalize_trace_draft(draft)

        self.assertEqual(built.analysis_status, "not_found_in_static_analysis")
        self.assertEqual(built.call_paths, [])
        self.assertEqual(built.evidence_paths, [])

    def test_packaged_weak_class_constant_in_business_code_is_not_reachable(self):
        result = tracer.TraceResult(
            api_name="com.vendor.TargetType", api_simple="TargetType",
            api_signature="", symbol_kind="class", change_type="REMOVED",
            coord="com.vendor:api", severity="P1", confirmed=True,
            source="git_diff", analysis_scope="class_usage",
            analysis_status="not_analyzed", direct_callers=0,
            is_reachable=False, reachable_note="", business_reach_depth=0,
            dependency_chain_coords=[], call_paths=[], evidence_paths=[],
            reason_code="", verification_commands=[], hops=[],
            confidence_score=1.0, critical_nodes_hit=[],
        )
        hit = {
            "coord": "__business__", "class_fqcn": "app.Entry",
            "consumer_method": "<class-constant>", "consumer_signature": "",
            "target_display": "com.vendor.TargetType",
            "evidence_type": "bytecode_class_constant_reference",
            "weak_reference": True, "instruction_offset": None,
        }

        draft = self._draft_from_result(result)
        tracer._build_packaged_dependency_hit_result(draft, [hit])
        built = tracer._finalize_trace_draft(draft)

        self.assertEqual(built.analysis_status, "uncertain")
        self.assertIsNone(built.is_reachable)
        self.assertEqual(built.reason_code, "WEAK_CLASS_REFERENCE_ONLY")
        self.assertFalse(built.path_details[0]["business_reachable"])

    def test_ambiguous_business_hit_cannot_promote_exact_internal_hit(self):
        result = tracer.TraceResult(
            api_name="com.right.Target.call", api_simple="call", api_signature="(Request)",
            symbol_kind="method", change_type="REMOVED", coord="com.right:target",
            severity="P1", confirmed=True, source="git_diff", analysis_scope="method",
            analysis_status="not_analyzed", direct_callers=0, is_reachable=False,
            reachable_note="", business_reach_depth=0, dependency_chain_coords=[],
            call_paths=[], evidence_paths=[], reason_code="", verification_commands=[],
            hops=[], confidence_score=1.0, critical_nodes_hit=[],
        )
        hits = [
            {
                "coord": "com.right:target", "class_fqcn": "com.right.Internal",
                "consumer_method": "bridge", "consumer_signature": "()",
                "target_display": "com.right.Target.call(com.right.Request)",
                "signature_ambiguous": False, "evidence_type": "bytecode_method_invocation",
            },
            {
                "coord": "__business__", "class_fqcn": "app.Entry",
                "consumer_method": "run", "consumer_signature": "()",
                "target_display": "com.right.Target.call(com.shared.Request)",
                "signature_ambiguous": True, "evidence_type": "bytecode_method_invocation",
            },
        ]

        draft = self._draft_from_result(result)
        tracer._build_packaged_dependency_hit_result(draft, hits)
        built = tracer._finalize_trace_draft(draft)

        self.assertEqual(built.analysis_status, "uncertain")
        self.assertIsNone(built.is_reachable)
        self.assertEqual(built.reason_code, "UNQUALIFIED_SIGNATURE_TYPE_AMBIGUOUS")

    def test_packaged_business_hit_output_is_deterministic_for_parallel_hit_order(self):
        def build(hits):
            result = tracer.TraceResult(
                api_name="com.vendor.Target.call", api_simple="call", api_signature="()",
                symbol_kind="method", change_type="REMOVED", coord="com.vendor:target",
                old_version="1", new_version="2", severity="P1", confirmed=True,
                source="git_diff", analysis_scope="method", analysis_status="not_analyzed",
                direct_callers=0, is_reachable=False, reachable_note="",
                business_reach_depth=0, dependency_chain_coords=[], call_paths=[],
                evidence_paths=[], reason_code="", verification_commands=[], hops=[],
                confidence_score=1.0, critical_nodes_hit=[],
            )
            draft = self._draft_from_result(result)
            tracer._build_packaged_dependency_hit_result(draft, hits)
            return tracer._finalize_trace_draft(draft)

        hits = [
            {
                "coord": "__business__", "class_fqcn": "app.Zeta",
                "consumer_method": "run", "consumer_signature": "()",
                "target_display": "com.vendor.Target.call()",
                "evidence_type": "bytecode_method_invocation", "instruction_offset": 8,
            },
            {
                "coord": "__business__", "class_fqcn": "app.Alpha",
                "consumer_method": "run", "consumer_signature": "()",
                "target_display": "com.vendor.Target.call()",
                "evidence_type": "bytecode_method_invocation", "instruction_offset": 4,
            },
        ]

        forward = build(hits)
        reverse = build(list(reversed(hits)))

        self.assertEqual(forward.call_paths, reverse.call_paths)
        self.assertEqual(forward.evidence_paths, reverse.evidence_paths)

    def test_packaged_hit_deduplication_selects_same_physical_edge_for_any_input_order(self):
        def build(hits):
            result = tracer.TraceResult(
                api_name="com.vendor.Target.call", api_simple="call", api_signature="()",
                symbol_kind="method", change_type="REMOVED", coord="com.vendor:target",
                old_version="1", new_version="2", severity="P1", confirmed=True,
                source="git_diff", analysis_scope="method", analysis_status="not_analyzed",
                direct_callers=0, is_reachable=False, reachable_note="",
                business_reach_depth=0, dependency_chain_coords=[], call_paths=[],
                evidence_paths=[], reason_code="", verification_commands=[], hops=[],
                confidence_score=1.0, critical_nodes_hit=[],
            )
            draft = self._draft_from_result(result)
            tracer._build_packaged_dependency_hit_result(draft, hits)
            return tracer._finalize_trace_draft(draft)

        base = {
            "coord": "__business__", "class_fqcn": "app.Entry",
            "consumer_method": "run", "consumer_signature": "()",
            "target_display": "com.vendor.Target.call()",
            "evidence_type": "bytecode_method_invocation",
            "multi_release_version": "base", "jar_path": "/tmp/business.jar",
        }
        hits = [
            {**base, "instruction_offset": 18},
            {**base, "instruction_offset": 6},
        ]

        forward = build(hits)
        reverse = build(list(reversed(hits)))

        self.assertEqual(forward.call_paths, reverse.call_paths)
        self.assertEqual(forward.evidence_paths, reverse.evidence_paths)
        self.assertEqual(len(forward.evidence_paths), 1)
        self.assertEqual(forward.evidence_paths[0][0]["instruction_offset"], 6)

    def test_packaged_hit_decision_checks_all_physical_edges_before_display_dedup(self):
        result = tracer.TraceResult(
            api_name="com.vendor.Target.call", api_simple="call", api_signature="()",
            symbol_kind="method", change_type="REMOVED", coord="com.vendor:target",
            old_version="1", new_version="2", severity="P1", confirmed=True,
            source="git_diff", analysis_scope="method", analysis_status="not_analyzed",
            direct_callers=0, is_reachable=False, reachable_note="",
            business_reach_depth=0, dependency_chain_coords=[], call_paths=[],
            evidence_paths=[], reason_code="", verification_commands=[], hops=[],
            confidence_score=1.0, critical_nodes_hit=[],
        )
        base = {
            "coord": "com.example:bridge", "class_fqcn": "com.example.Bridge",
            "consumer_method": "use", "consumer_signature": "()",
            "consumer_descriptor": "()V", "callee_descriptor": "()V",
            "target_display": "com.vendor.Target.call()",
            "evidence_type": "bytecode_method_invocation",
            "edge_role": "external_consumer", "instruction_offset": 4,
        }
        hits = [
            {**base, "jar_path": "/tmp/a-unreachable.jar"},
            {**base, "jar_path": "/tmp/z-reachable.jar"},
        ]
        business_entry = SimpleNamespace(qualified_key="app.Entry.run()")

        def runtime_entry(hit, _graph):
            if hit.get("jar_path") == "/tmp/z-reachable.jar":
                return business_entry, []
            return None, []

        draft = self._draft_from_result(result)
        with patch.object(
            tracer, "_packaged_hit_runtime_framework_entry",
            side_effect=runtime_entry,
        ):
            tracer._build_packaged_dependency_hit_result(
                draft, hits, SimpleNamespace()
            )

        finalized = tracer._finalize_trace_draft(draft)
        self.assertEqual(finalized.analysis_status, "reachable")
        self.assertTrue(any(
            detail.get("business_reachable") is True
            for detail in finalized.path_details
        ))

    def test_packaged_business_lookup_honors_five_edge_trace_budget(self):
        methods = {}
        reverse_edges = {}
        for index in range(1, 6):
            symbol_id = f"m{index}"
            qualified = "app.Entry.run" if index == 5 else f"lib.Bridge{index}.call"
            methods[symbol_id] = SimpleNamespace(
                symbol_id=symbol_id, qualified_key=qualified,
                owner_type="business" if index == 5 else "dependency",
                is_test=False,
            )
            callee = "lib.Consumer.use()" if index == 1 else f"lib.Bridge{index - 1}.call"
            reverse_edges[callee] = [source_analyzer.CallEdge(
                caller_symbol_id=symbol_id, caller_qualified_key=qualified,
                callee_key=callee, callee_simple_key="method:call",
                evidence_type="bytecode_method_invocation", confidence="high",
                file="/tmp/app.jar", line=0, content="call",
                owner_type=methods[symbol_id].owner_type, owner_coord="", module="", is_test=False,
            )]
        graph = SimpleNamespace(methods_by_id=methods, reverse_edges=reverse_edges)
        hit = {
            "coord": "sample:lib", "class_fqcn": "lib.Consumer",
            "consumer_method": "use", "consumer_signature": "()",
        }

        paths = tracer._find_business_callers_for_packaged_hit(hit, graph)

        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0][0].qualified_key, "app.Entry.run")
        graph._trace_max_total_cost = 1
        self.assertEqual(tracer._find_business_callers_for_packaged_hit(hit, graph), [])

    def test_member_index_selects_dotted_reflection_owner_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            classes = self._compile_java_fixture(
                tmp, "com/example/Reflective.java", """
                package com.example;
                public class Reflective {
                    public void call() throws Exception {
                        Class.forName("com.vendor.Target").getDeclaredMethod("removed");
                    }
                }
                """,
            )
            jar_path = Path(tmp) / "reflective.jar"
            self._jar_compiled_classes(jar_path, classes)
            graph = SimpleNamespace()
            index = tracer._build_runtime_dependency_member_candidate_index(
                graph, [{"coord": "sample:reflective", "jar_path": str(jar_path)}], 17
            )

        candidates = tracer._candidate_tasks_from_runtime_member_index(
            index, "com.vendor.Target", "removed"
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["class_fqcn"], "com.example.Reflective")
        self.assertNotIn("graph", index["tasks"][0])
        self.assertNotIn("catalog", index["tasks"][0])
        self.assertIs(index["graph"], graph)

    def test_member_index_shared_class_facts_preserve_exact_serialized_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_root = Path(tmp) / "src"
            caller = source_root / "com/example/Caller.java"
            target = source_root / "com/vendor/Target.java"
            caller.parent.mkdir(parents=True, exist_ok=True)
            target.parent.mkdir(parents=True, exist_ok=True)
            caller.write_text("""
                package com.example;
                public class Caller {
                    public void direct() { com.vendor.Target.removed(); }
                    public void reflective() throws Exception {
                        Class.forName("com.vendor.Target").getDeclaredMethod("removed");
                    }
                }
                """, encoding="utf-8")
            target.write_text("""
                package com.vendor;
                public class Target { public static void removed() {} }
                """, encoding="utf-8")
            classes = Path(tmp) / "classes"
            self._compile_java_files(classes, [caller, target])
            jar_path = Path(tmp) / "caller.jar"
            self._jar_compiled_classes(jar_path, classes)
            digest = hashlib.sha256(jar_path.read_bytes()).hexdigest()
            entry = {
                "coord": "sample:caller", "jar_path": str(jar_path),
                "sha256": digest,
            }
            legacy = tracer._build_runtime_dependency_member_candidate_index(
                SimpleNamespace(), [entry], 17,
            )
            shared_graph = SimpleNamespace(
                step5_artifact_fact_store=Step5ArtifactFactStore.from_catalog({
                    "target_jdk": "17", "entries": [entry],
                })
            )
            shared = tracer._build_runtime_dependency_member_candidate_index(
                shared_graph, [entry], 17,
            )

        self.assertEqual(
            tracer._runtime_member_index_serializable(legacy),
            tracer._runtime_member_index_serializable(shared),
        )

    def test_runtime_member_index_persists_complete_candidate_set_across_graphs(self):
        with tempfile.TemporaryDirectory() as tmp:
            classes = self._compile_java_fixture(
                tmp, "com/example/Reflective.java", """
                package com.example;
                public class Reflective {
                    public void call() throws Exception {
                        Class.forName("com.vendor.Target").getDeclaredMethod("removed");
                    }
                }
                """,
            )
            jar_path = Path(tmp) / "reflective.jar"
            self._jar_compiled_classes(jar_path, classes)
            catalog = [{"coord": "sample:reflective", "jar_path": str(jar_path)}]
            first_graph = SimpleNamespace(report_dir=str(Path(tmp) / "report"))
            first = tracer._get_runtime_dependency_member_candidate_index(
                first_graph, catalog, 17
            )
            first_candidates = tracer._candidate_tasks_from_runtime_member_index(
                first, "com.vendor.Target", "removed"
            )

            second_graph = SimpleNamespace(report_dir=str(Path(tmp) / "report"))
            with patch.object(
                tracer,
                "_build_runtime_dependency_member_candidate_index",
                side_effect=AssertionError("valid persistent index should avoid rebuild"),
            ):
                second = tracer._get_runtime_dependency_member_candidate_index(
                    second_graph, catalog, 17
                )
            second_candidates = tracer._candidate_tasks_from_runtime_member_index(
                second, "com.vendor.Target", "removed"
            )

        self.assertEqual(first_candidates, second_candidates)
        self.assertEqual(len(second_candidates), 1)
        self.assertIs(second["graph"], second_graph)

    def test_runtime_member_index_rebuilds_when_artifact_changes_during_cache_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            classes = self._compile_java_fixture(
                tmp, "com/example/Caller.java", """
                package com.example;
                public class Caller {
                    public void call() throws Exception {
                        Class.forName("com.vendor.Target").getDeclaredMethod("removed");
                    }
                }
                """,
            )
            jar_path = Path(tmp) / "caller.jar"
            self._jar_compiled_classes(jar_path, classes)
            catalog = [{"coord": "sample:caller", "jar_path": str(jar_path)}]
            report_dir = Path(tmp) / "report"
            tracer._get_runtime_dependency_member_candidate_index(
                SimpleNamespace(report_dir=str(report_dir)), catalog, 17
            )
            original_load = tracer._load_runtime_member_index_cache
            original_build = tracer._build_runtime_dependency_member_candidate_index

            def mutating_load(path, identity, graph):
                cached = original_load(path, identity, graph)
                with zipfile.ZipFile(jar_path, "a") as archive:
                    archive.writestr("mutation-marker", b"changed")
                return cached

            graph = SimpleNamespace(report_dir=str(report_dir))
            with patch.object(
                tracer, "_load_runtime_member_index_cache",
                side_effect=mutating_load,
            ), patch.object(
                tracer, "_build_runtime_dependency_member_candidate_index",
                wraps=original_build,
            ) as rebuilt:
                index = tracer._get_runtime_dependency_member_candidate_index(
                    graph, catalog, 17
                )

        self.assertEqual(rebuilt.call_count, 1)
        self.assertTrue(index["complete"])
        self.assertTrue(tracer._candidate_tasks_from_runtime_member_index(
            index, "com.vendor.Target", "removed"
        ))

    def test_runtime_member_index_rebuilds_when_graph_cached_artifact_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            classes = self._compile_java_fixture(
                tmp, "com/example/Caller.java", """
                package com.example;
                public class Caller {
                    public void call() throws Exception {
                        Class.forName("com.vendor.Target").getDeclaredMethod("removed");
                    }
                }
                """,
            )
            jar_path = Path(tmp) / "caller.jar"
            self._jar_compiled_classes(jar_path, classes)
            catalog = [{"coord": "sample:caller", "jar_path": str(jar_path)}]
            graph = SimpleNamespace(report_dir=str(Path(tmp) / "report"))
            first = tracer._get_runtime_dependency_member_candidate_index(
                graph, catalog, 17
            )
            with zipfile.ZipFile(jar_path, "a") as archive:
                archive.writestr("mutation-marker", b"changed")
            original_build = tracer._build_runtime_dependency_member_candidate_index
            with patch.object(
                tracer, "_build_runtime_dependency_member_candidate_index",
                wraps=original_build,
            ) as rebuilt:
                second = tracer._get_runtime_dependency_member_candidate_index(
                    graph, catalog, 17
                )

        self.assertIsNot(first, second)
        self.assertEqual(rebuilt.call_count, 1)
        self.assertTrue(second["complete"])

    def test_runtime_member_index_graph_cache_hit_does_not_rehash_unchanged_jars(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "fixture.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("p/Caller.class", b"com/vendor/Target removed")
            catalog = [{"coord": "sample:fixture", "jar_path": str(jar_path)}]
            graph = SimpleNamespace(report_dir=str(Path(tmp) / "report"))

            with patch.object(
                tracer, "_artifact_sha256", wraps=tracer._artifact_sha256
            ) as digest:
                first = tracer._get_runtime_dependency_member_candidate_index(
                    graph, catalog, 17
                )
                hashes_after_build = digest.call_count
                second = tracer._get_runtime_dependency_member_candidate_index(
                    graph, catalog, 17
                )

        self.assertIs(first, second)
        self.assertGreater(hashes_after_build, 0)
        self.assertEqual(digest.call_count, hashes_after_build)

    def test_runtime_member_index_trace_lease_avoids_per_lookup_stat_scans(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "fixture.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("p/Caller.class", b"com/vendor/Target removed")
            catalog = [{"coord": "sample:fixture", "jar_path": str(jar_path)}]
            graph = SimpleNamespace(
                report_dir=str(Path(tmp) / "report"),
                _active_packaged_scan_trace_serial=7,
            )
            first = tracer._get_runtime_dependency_member_candidate_index(
                graph, catalog, 17
            )

            with patch.object(
                tracer, "_runtime_artifact_stat_snapshot",
                side_effect=AssertionError("active trace lease must avoid repeated stat scans"),
            ):
                second = tracer._get_runtime_dependency_member_candidate_index(
                    graph, catalog, 17
                )

        self.assertIs(first, second)
        self.assertEqual(first["_validated_trace_serial"], 7)

    def test_runtime_member_index_trace_lease_final_sha_detects_artifact_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "fixture.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("p/Caller.class", b"first")
            catalog = [{"coord": "sample:fixture", "jar_path": str(jar_path)}]
            graph = SimpleNamespace(
                report_dir=str(Path(tmp) / "report"),
                runtime_dependency_catalog={"entries": catalog, "target_jdk": 17},
                _active_packaged_scan_trace_serial=11,
            )
            tracer._get_runtime_dependency_member_candidate_index(graph, catalog, 17)
            with zipfile.ZipFile(jar_path, "a") as archive:
                archive.writestr("mutation-marker", b"changed")

            valid = tracer._validate_runtime_member_index_trace_lease(graph)

        self.assertFalse(valid)
        self.assertTrue(any(
            failure.reason_code == "BYTECODE_MEMBER_INDEX_INPUT_CHANGED"
            for failure in graph.step5_evidence_failures
        ))

    def test_runtime_member_index_rejects_change_between_final_identity_and_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "fixture.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("p/Caller.class", b"first")
            catalog = [{"coord": "sample:fixture", "jar_path": str(jar_path)}]
            graph = SimpleNamespace(report_dir=str(Path(tmp) / "report"))
            original_identity = tracer._runtime_member_index_cache_identity
            calls = 0

            def mutating_identity(entries, target_jdk):
                nonlocal calls
                calls += 1
                identity = original_identity(entries, target_jdk)
                if calls == 2:
                    with zipfile.ZipFile(jar_path, "a") as archive:
                        archive.writestr("p/Changed.class", b"second")
                return identity

            with patch.object(
                tracer, "_runtime_member_index_cache_identity",
                side_effect=mutating_identity,
            ):
                first = tracer._get_runtime_dependency_member_candidate_index(
                    graph, catalog, 17
                )
            original_build = tracer._build_runtime_dependency_member_candidate_index
            with patch.object(
                tracer, "_build_runtime_dependency_member_candidate_index",
                wraps=original_build,
            ) as rebuilt:
                second = tracer._get_runtime_dependency_member_candidate_index(
                    graph, catalog, 17
                )

        self.assertFalse(first["complete"])
        self.assertIsNot(first, second)
        self.assertEqual(rebuilt.call_count, 1)

    def test_runtime_member_index_rejects_artifact_changed_during_cache_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "fixture.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("p/Caller.class", b"first")
            catalog = [{"coord": "sample:fixture", "jar_path": str(jar_path)}]
            graph = SimpleNamespace(report_dir=str(Path(tmp) / "report"))
            original_write = tracer._write_runtime_member_index_cache

            def mutating_write(path, identity, index):
                original_write(path, identity, index)
                with zipfile.ZipFile(jar_path, "a") as archive:
                    archive.writestr("p/Changed.class", b"second")

            with patch.object(
                tracer, "_write_runtime_member_index_cache",
                side_effect=mutating_write,
            ):
                index = tracer._get_runtime_dependency_member_candidate_index(
                    graph, catalog, 17
                )

        self.assertFalse(index["complete"])
        self.assertEqual(
            index["failures"][-1]["reason"],
            "BYTECODE_MEMBER_INDEX_INPUT_CHANGED",
        )

    def test_trace_batch_clears_scan_serial_when_api_trace_raises(self):
        api = {
            "coord": "com.vendor:api", "api_name": "com.vendor.Target.removed",
            "api_simple": "removed", "api_signature": "", "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        graph = SimpleNamespace(
            runtime_dependency_catalog={"status": "complete", "entries": []},
        )

        with patch.object(
            tracer, "_build_identical_current_class_provider_index", return_value={}
        ), patch.object(
            tracer, "_build_packaged_runtime_dependency_scan_cache", return_value={}
        ), patch.object(
            tracer, "trace_api_with_confidence_weighting",
            side_effect=RuntimeError("trace failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "trace failed"):
                tracer.trace_all_apis_with_confidence_weighting(
                    [api], graph, {}, allow_degraded=True
                )

        self.assertEqual(graph._active_packaged_scan_trace_serial, 0)
        self.assertEqual(
            graph.runtime_dependency_catalog.get(
                "_packaged_api_scan_validated_trace_serial", 0
            ),
            0,
        )

    def test_trace_batch_clears_scan_serial_when_provider_discovery_raises(self):
        api = {
            "coord": "com.vendor:api", "api_name": "com.vendor.Target.removed",
            "api_simple": "removed", "api_signature": "", "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        graph = SimpleNamespace(runtime_dependency_catalog={
            "status": "complete", "entries": [],
            "_packaged_api_scan_validated_trace_serial": 1,
        })

        with patch.object(
            tracer, "_build_identical_current_class_provider_index",
            side_effect=RuntimeError("provider failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "provider failed"):
                tracer.trace_all_apis_with_confidence_weighting(
                    [api], graph, {}, allow_degraded=True
                )

        self.assertEqual(graph._active_packaged_scan_trace_serial, 0)
        self.assertEqual(
            graph.runtime_dependency_catalog[
                "_packaged_api_scan_validated_trace_serial"
            ],
            0,
        )

    def test_trace_batch_freezes_input_changed_results_for_all_per_api_queries(self):
        apis = [{
            "coord": "com.vendor:api", "api_name": f"com.vendor.Target.call{index}",
            "api_simple": f"call{index}", "api_signature": "", "symbol_kind": "method",
            "change_type": "REMOVED",
        } for index in range(2)]
        graph = SimpleNamespace(runtime_dependency_catalog={
            "status": "complete", "entries": [],
        })
        build_calls = 0

        def build_results(rows, current_graph):
            nonlocal build_calls
            build_calls += 1
            catalog = current_graph.runtime_dependency_catalog
            status = "unavailable" if build_calls == 1 else "hit"
            catalog["_packaged_api_scan_results"] = {
                tracer.build_api_identity_key(row): {
                    "status": status,
                    "reason": "BYTECODE_SCAN_INPUT_CHANGED" if status == "unavailable" else "",
                    "hits": [] if status == "unavailable" else [{"stale": True}],
                }
                for row in apis
            }
            catalog["_packaged_api_scan_stat_snapshot"] = None
            return catalog["_packaged_api_scan_results"]

        def trace_one(row, current_graph, *_args, **_kwargs):
            scanned = tracer._scan_packaged_runtime_dependencies_for_api(
                row, current_graph
            )
            return SimpleNamespace(
                analysis_status=scanned["status"], direct_callers=0,
                business_reach_depth=None, confidence_score=0,
                reason_code=scanned.get("reason", ""),
            )

        with patch.object(
            tracer, "_build_identical_current_class_provider_index", return_value={}
        ), patch.object(
            tracer, "_build_packaged_runtime_dependency_scan_cache",
            side_effect=build_results,
        ), patch.object(
            tracer, "trace_api_with_confidence_weighting", side_effect=trace_one,
        ), patch.object(tracer, "collect_graph_analyzer_edges"), patch.object(
            tracer, "write_analyzer_edge_ledger"
        ):
            results = tracer.trace_all_apis_with_confidence_weighting(
                apis, graph, {}, allow_degraded=True
            )

        self.assertEqual(build_calls, 1)
        self.assertEqual(
            [result.analysis_status for result in results],
            ["unavailable", "unavailable"],
        )

    def test_packaged_scan_batch_validation_avoids_per_api_stat_scans(self):
        api = {
            "coord": "com.vendor:api", "api_name": "com.vendor.Target.removed",
            "api_simple": "removed", "api_signature": "", "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        identity = tracer.build_api_identity_key(api)
        catalog = {
            "_packaged_api_scan_results": {identity: {"status": "miss"}},
            "_packaged_api_scan_stat_snapshot": tracer._runtime_artifact_stat_snapshot([], None),
            "_packaged_api_scan_validated_trace_serial": 7,
        }
        graph = SimpleNamespace(
            runtime_dependency_catalog=catalog,
            _active_packaged_scan_trace_serial=7,
        )

        with patch.object(
            tracer, "_runtime_artifact_stat_snapshot",
            side_effect=AssertionError("batch cache hit must not rescan every jar per API"),
        ):
            result = tracer._scan_packaged_runtime_dependencies_for_api(api, graph)

        self.assertEqual(result["status"], "miss")

    def test_runtime_member_index_marks_missing_catalog_jar_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing_jar = Path(tmp) / "missing.jar"
            classes = self._compile_java_fixture(
                tmp, "com/acme/TargetBridge.java", """
                package com.acme;
                public class TargetBridge {
                    public static void removed() {}
                }
                class Caller {
                    public static void caller() { TargetBridge.removed(); }
                }
                """,
            )
            valid_jar = Path(tmp) / "valid.jar"
            self._jar_compiled_classes(valid_jar, classes)
            catalog = [
                {"coord": "com.acme:missing", "jar_path": str(missing_jar)},
                {"coord": "com.acme:valid", "jar_path": str(valid_jar)},
            ]
            graph = SimpleNamespace(
                report_dir=str(Path(tmp) / "report"),
                runtime_dependency_catalog={
                    "status": "complete",
                    "entries": catalog,
                    "target_jdk": 17,
                },
                _prefer_runtime_dependency_member_candidate_index=True,
            )

            index = tracer._get_runtime_dependency_member_candidate_index(
                graph, catalog, 17,
            )

            self.assertFalse(index["complete"])
            self.assertEqual(
                index["failures"][0]["reason"],
                "BYTECODE_MEMBER_INDEX_ARTIFACT_MISSING",
            )
            self.assertFalse(
                Path(
                    tmp, "report", ".runtime", "cache",
                    "s5_runtime_member_candidate_index.json",
                ).exists()
            )
            expansion = tracer._ensure_runtime_dependency_callers_for_key(
                graph, "com.acme.TargetBridge.removed()"
            )
            perf = tracer._finalize_step5_perf_stats(graph)["bytecode_expand"]

        self.assertTrue(expansion["expanded"])
        self.assertGreaterEqual(expansion["edges_added"], 1)
        self.assertEqual(perf["light_scans"], 1.0)
        self.assertEqual(
            perf["slow_runtime_lookups"][0]["candidate_source"], "light_scan"
        )
        self.assertTrue(any(
            "BYTECODE_MEMBER_INDEX_ARTIFACT_MISSING" in str(failure)
            for failure in graph._analyzer_edge_failures
        ))

    def test_runtime_member_index_rejects_artifact_changed_during_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "fixture.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("p/Caller.class", b"first")
            graph = SimpleNamespace(report_dir=str(Path(tmp) / "report"))
            catalog = [{"coord": "sample:fixture", "jar_path": str(jar_path)}]

            def mutating_build(current_graph, _catalog, _target_jdk):
                with zipfile.ZipFile(jar_path, "a") as archive:
                    archive.writestr("p/Changed.class", b"second")
                return {
                    "graph": current_graph,
                    "catalog": _catalog,
                    "tasks": [],
                    "unparsed_tasks": [],
                    "direct_by_owner_member": {},
                    "owner_string_ids": {},
                    "member_string_ids": {},
                    "reflection_ids": set(),
                    "visited_classes": 1,
                    "parse_failures": 0,
                    "complete": True,
                    "failures": [],
                }

            with patch.object(
                tracer, "_build_runtime_dependency_member_candidate_index",
                side_effect=mutating_build,
            ):
                index = tracer._get_runtime_dependency_member_candidate_index(
                    graph, catalog, 17
                )

            cache_path = Path(
                tmp, "report", ".runtime", "cache",
                "s5_runtime_member_candidate_index.json",
            )
            cache_exists = cache_path.exists()

        self.assertFalse(index["complete"])
        self.assertEqual(
            index["failures"][-1]["reason"],
            "BYTECODE_MEMBER_INDEX_INPUT_CHANGED",
        )
        self.assertFalse(cache_exists)

    def test_runtime_member_index_identity_changes_with_artifact_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "fixture.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("p/A.class", b"first")
            catalog = [{"coord": "sample:fixture", "jar_path": str(jar_path)}]
            first = tracer._runtime_member_index_cache_identity(catalog, 17)
            with zipfile.ZipFile(jar_path, "a") as archive:
                archive.writestr("p/B.class", b"second")
            second = tracer._runtime_member_index_cache_identity(catalog, 17)

        self.assertNotEqual(first, second)

    def test_runtime_member_index_corruption_falls_back_to_full_rebuild(self):
        with tempfile.TemporaryDirectory() as tmp:
            classes = self._compile_java_fixture(
                tmp, "com/example/Caller.java", """
                package com.example;
                public class Caller {
                    public void call() throws Exception {
                        Class.forName("com.vendor.Target").getDeclaredMethod("removed");
                    }
                }
                """,
            )
            jar_path = Path(tmp) / "caller.jar"
            self._jar_compiled_classes(jar_path, classes)
            catalog = [{"coord": "sample:caller", "jar_path": str(jar_path)}]
            report_dir = Path(tmp) / "report"
            tracer._get_runtime_dependency_member_candidate_index(
                SimpleNamespace(report_dir=str(report_dir)), catalog, 17
            )
            cache_path = (
                report_dir / ".runtime" / "cache" /
                "s5_runtime_member_candidate_index.json"
            )
            cache_path.write_text("{broken", encoding="utf-8")
            graph = SimpleNamespace(report_dir=str(report_dir))
            original = tracer._build_runtime_dependency_member_candidate_index
            with patch.object(tracer, "_build_runtime_dependency_member_candidate_index", wraps=original) as rebuilt:
                index = tracer._get_runtime_dependency_member_candidate_index(
                    graph, catalog, 17
                )

        self.assertEqual(rebuilt.call_count, 1)
        self.assertTrue(index["complete"])
        self.assertTrue(tracer._candidate_tasks_from_runtime_member_index(
            index, "com.vendor.Target", "removed"
        ))

    def test_runtime_member_index_cache_load_streams_integrity_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "member-index.json"
            identity = {"schema": "fixture", "artifacts": []}
            index = {
                "tasks": [{"class_fqcn": "p.Caller"}],
                "unparsed_tasks": [],
                "direct_by_owner_member": {("p.Target", "removed"): {0}},
                "owner_string_ids": {},
                "member_string_ids": {},
                "reflection_ids": set(),
                "visited_classes": 1,
                "parse_failures": 0,
                "complete": True,
                "failures": [],
            }
            tracer._write_runtime_member_index_cache(path, identity, index)

            with patch.object(
                tracer,
                "_runtime_member_index_canonical_bytes",
                side_effect=AssertionError("cache load must not materialize canonical bytes"),
            ):
                loaded = tracer._load_runtime_member_index_cache(
                    path, identity, SimpleNamespace()
                )

        self.assertEqual(loaded["tasks"], index["tasks"])
        self.assertTrue(loaded["complete"])

    def test_runtime_member_index_deserialization_reuses_large_task_lists(self):
        tasks = [{"class_fqcn": f"p.Caller{index}"} for index in range(100)]
        unparsed_tasks = [{"class_fqcn": "p.Unparsed"}]
        payload = {
            "tasks": tasks,
            "unparsed_tasks": unparsed_tasks,
            "direct_by_owner_member": [
                {"owner": "p.Target", "member": "removed", "task_ids": [0, 1]}
            ],
            "owner_string_ids": {"p.Target": [0, 1]},
            "member_string_ids": {"removed": [0, 1]},
            "reflection_ids": [0, 1],
            "visited_classes": 101,
            "parse_failures": 0,
            "complete": True,
            "failures": [],
        }

        loaded = tracer._runtime_member_index_from_serializable(
            payload, SimpleNamespace()
        )

        self.assertIs(loaded["tasks"], tasks)
        self.assertIs(loaded["unparsed_tasks"], unparsed_tasks)
        self.assertNotIn("direct_by_owner_member", payload)
        self.assertEqual(
            loaded["direct_by_owner_member"][("p.Target", "removed")], (0, 1)
        )
        self.assertEqual(loaded["owner_string_ids"]["p.Target"], (0, 1))
        self.assertEqual(loaded["member_string_ids"]["removed"], (0, 1))

    def test_runtime_member_index_deserialization_deduplicates_artifact_strings(self):
        def duplicate(value):
            return value.encode("utf-8").decode("utf-8")

        tasks = [
            {
                "coord": duplicate("com.example:large-artifact"),
                "jar_path": duplicate("/tmp/large-artifact.jar"),
                "artifact_sha256": duplicate("a" * 64),
                "target_jdk": duplicate("17"),
                "class_binary_name": f"p.Caller{index}",
                "class_fqcn": f"p.Caller{index}",
            }
            for index in range(2)
        ]
        payload = {
            "tasks": tasks,
            "unparsed_tasks": [],
            "direct_by_owner_member": [
                {"owner": "p.Target", "member": "removed", "task_ids": [0]}
            ],
            "owner_string_ids": {"p.Target": [0]},
            "member_string_ids": {"removed": [0]},
            "reflection_ids": [],
            "visited_classes": 2,
            "parse_failures": 0,
            "complete": True,
            "failures": [],
        }

        loaded = tracer._runtime_member_index_from_serializable(
            payload, SimpleNamespace()
        )

        for key in ("coord", "jar_path", "artifact_sha256", "target_jdk"):
            self.assertIs(loaded["tasks"][0][key], loaded["tasks"][1][key])
        self.assertEqual(
            loaded["direct_by_owner_member"][("p.Target", "removed")], 0
        )
        self.assertEqual(loaded["owner_string_ids"]["p.Target"], 0)
        self.assertEqual(loaded["member_string_ids"]["removed"], 0)
        self.assertIs(
            loaded["tasks"][0]["class_binary_name"],
            loaded["tasks"][0]["class_fqcn"],
        )

    def test_runtime_member_index_adds_singletons_without_allocating_sets(self):
        buckets = {}

        tracer._add_runtime_member_task_id(buckets, "target", 7)
        self.assertEqual(buckets["target"], 7)

        tracer._add_runtime_member_task_id(buckets, "target", 7)
        self.assertEqual(buckets["target"], 7)

        tracer._add_runtime_member_task_id(buckets, "target", 9)
        self.assertEqual(buckets["target"], {7, 9})

    def test_runtime_member_index_omits_string_buckets_for_non_reflective_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "caller.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("p/Caller.class", b"fixture")
            summary = {
                "ref_members": [],
                "utf8_values": {
                    "com/vendor/Target", "removed", "ordinaryLiteral"
                },
                "has_dynamic_reference": False,
            }
            with patch.object(
                tracer, "_parse_classfile_constant_pool_summary",
                return_value=summary,
            ):
                index = tracer._build_runtime_dependency_member_candidate_index(
                    SimpleNamespace(),
                    [{"coord": "sample:caller", "jar_path": str(jar_path)}],
                    17,
                )

        self.assertEqual(index["reflection_ids"], set())
        self.assertEqual(dict(index["owner_string_ids"]), {})
        self.assertEqual(dict(index["member_string_ids"]), {})

    def test_runtime_member_index_keeps_package_annotation_class_references(self):
        target = "org.checkerframework.framework.qual.DefaultQualifier"
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "caller.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("org/postgresql/package-info.class", b"fixture")
            summary = {
                "class_internal_names": {
                    "org/checkerframework/framework/qual/DefaultQualifier",
                },
                "ref_members": [],
                "utf8_values": set(),
                "has_dynamic_reference": False,
            }
            with patch.object(
                tracer, "_parse_classfile_constant_pool_summary",
                return_value=summary,
            ):
                index = tracer._build_runtime_dependency_member_candidate_index(
                    SimpleNamespace(),
                    [{"coord": "org.postgresql:postgresql", "jar_path": str(jar_path)}],
                    17,
                )

        tasks = tracer._batch_candidates_from_runtime_member_index(
            index,
            {target: [{
                "coord": "org.checkerframework:checker-qual",
                "api_name": target,
                "symbol_kind": "class",
            }]},
        )
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["class_entry"], "org/postgresql/package-info.class")

    def test_runtime_reference_signature_resolves_nested_type_from_owner_package(self):
        range_reference = {
            "signature": "(Bound)",
            "descriptor": "(Lorg/springframework/data/domain/Range$Bound;)V",
        }
        direction_reference = {
            "signature": "(Map, Direction)",
            "descriptor": "(Ljava/util/Map;Lorg/springframework/data/domain/ScrollPosition$Direction;)V",
        }

        self.assertTrue(tracer._runtime_reference_signature_matches(
            "(Range$Bound)", range_reference,
            "org.springframework.data.domain.Range$RangeBuilder",
        ))
        self.assertTrue(tracer._runtime_reference_signature_matches(
            "(java.util.Map,ScrollPosition$Direction)", direction_reference,
            "org.springframework.data.domain.KeysetScrollPosition",
        ))
        matches = tracer._match_runtime_dependency_references(
            {
                "api_name": "org.springframework.data.domain.KeysetScrollPosition.of",
                "api_simple": "of",
                "api_signature": (
                    "(java.util.Map,"
                    "org.springframework.data.domain.ScrollPosition$Direction)"
                ),
                "symbol_kind": "method",
            },
            {"method_refs": [{
                **direction_reference,
                "owner": "org.springframework.data.domain.KeysetScrollPosition",
                "name": "of",
                "consumer_method": "forward",
                "consumer_descriptor": "()V",
                "opcode_family": "invokestatic",
                "instruction_offset": 4,
                "reference_kind": "classfile_methodref",
            }]},
        )
        self.assertEqual(len(matches), 1)

    def test_member_index_archive_failure_is_recorded_and_not_queried_as_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "broken.jar"
            broken.write_bytes(b"not-a-zip")
            graph = SimpleNamespace()

            index = tracer._build_runtime_dependency_member_candidate_index(
                graph,
                [{"coord": "com.acme:broken", "jar_path": str(broken)}],
                17,
            )

        self.assertFalse(index["complete"])
        self.assertTrue(index["failures"])
        self.assertIsNone(
            tracer._candidate_tasks_from_runtime_member_index(index, "com.acme.Api", "call")
        )
        self.assertTrue(graph._analyzer_edge_failures)

    def test_member_index_late_archive_failure_invalidates_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "late-broken.jar"
            jar_path.write_bytes(b"not-a-zip")
            graph = SimpleNamespace()
            index = {
                "complete": True,
                "failures": [],
                "tasks": [],
                "unparsed_tasks": [{
                    "coord": "com.acme:late-broken",
                    "jar_path": str(jar_path),
                    "class_entry": "com/acme/Caller.class",
                    "graph": graph,
                }],
            }

            candidates = tracer._candidate_tasks_from_runtime_member_index(
                index, "com.acme.Api", "call"
            )

        self.assertIsNone(candidates)
        self.assertFalse(index["complete"])
        self.assertEqual(
            index["failures"][0]["reason"],
            "BYTECODE_MEMBER_INDEX_LATE_ARCHIVE_FAILED",
        )
        self.assertTrue(graph._analyzer_edge_failures)

    def test_final_artifact_trace_filters_source_business_edges(self):
        source_edge = tracer.CallEdge(
            caller_symbol_id="source", caller_qualified_key="app.App.run",
            callee_key="lib.Api.call()", callee_simple_key="method:call()",
            evidence_type="ast_method_invocation", confidence="high",
            file="App.java", line=1, content="call", owner_type="business",
            owner_coord="", module="", is_test=False,
        )
        bytecode_edge = tracer.CallEdge(
            caller_symbol_id="bytecode", caller_qualified_key="app.App.run",
            callee_key="lib.Api.call()", callee_simple_key="method:call()",
            evidence_type="bytecode_method_invocation", confidence="high",
            file="business.jar!/app/App.class", line=0, content="call",
            owner_type="business", owner_coord="", module="", is_test=False,
        )
        bytecode_edge.evidence_source = "current_final_artifact"
        graph = SimpleNamespace(require_current_final_artifact_business_edges=True)

        incoming = tracer.get_cached_sorted_incoming_edges(
            {"lib.Api.call()": [source_edge, bytecode_edge]},
            "lib.Api.call()",
            graph=graph,
        )

        self.assertEqual(incoming, (bytecode_edge,))

    def test_partial_business_bytecode_failure_keeps_final_artifact_purity_enabled(self):
        stats = {
            "evidence_source": "current_final_artifact",
            "classes_scanned": 12,
            "failures": [{"class_entry": "app/Broken.class"}],
        }

        self.assertTrue(step5._requires_current_final_artifact_edges(stats))

    def test_final_artifact_miss_preserves_stale_source_conflict_signal(self):
        method = SimpleNamespace(
            symbol_id="source", qualified_key="app.App.run", owner_type="business",
            owner_coord="__business__", is_test=False, file="App.java", line=4,
            annotations=[], class_annotations=[], class_name="App", class_fqcn="app.App",
            modifiers=["public"], is_interface=False,
        )
        source_edge = tracer.CallEdge(
            caller_symbol_id="source", caller_qualified_key=method.qualified_key,
            callee_key="lib.Api.call()", callee_simple_key="method:call()",
            evidence_type="ast_method_invocation", confidence="high",
            file="App.java", line=5, content="Api.call()", owner_type="business",
            owner_coord="__business__", module="app", is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"source": method},
            reverse_edges={"lib.Api.call()": [source_edge]},
            runtime_dependency_catalog={},
            require_current_final_artifact_business_edges=True,
            source_artifact_alignment={
                "status": "conflict",
                "reason_codes": ["source_worktree_has_unbuilt_changes"],
            },
        )
        api_row = {
            "coord": "lib:api", "api_name": "lib.Api.call", "api_simple": "call",
            "api_signature": "()", "symbol_kind": "method", "change_type": "REMOVED",
            "severity": "P0", "confirmed": "true",
        }

        with patch.object(
            tracer, "_scan_packaged_runtime_dependencies_for_api", return_value={"status": "miss"}
        ):
            result = tracer.trace_api_with_confidence_weighting(
                api_row,
                graph,
                {},
                has_packaged_bytecode_fallback=True,
            )

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "SOURCE_BYTECODE_EDGE_CONFLICT")
        self.assertIsNone(result.is_reachable)
        self.assertTrue(result.call_paths)
        self.assertEqual(result.direct_callers, 1)
        self.assertEqual(result.evidence_paths[0][0]["evidence_type"], "ast_method_invocation")

    def test_final_artifact_miss_with_source_constant_usage_reports_inlining_uncertainty(self):
        method = SimpleNamespace(
            symbol_id="source", qualified_key="app.App.run", owner_type="business",
            owner_coord="__business__", is_test=False, file="App.java", line=4,
            annotations=[], class_annotations=[], class_name="App", class_fqcn="app.App",
            modifiers=["public"], is_interface=False,
        )
        source_edge = tracer.CallEdge(
            caller_symbol_id="source", caller_qualified_key=method.qualified_key,
            callee_key="lib.Flags.EMPTY", callee_simple_key="field:EMPTY",
            evidence_type="field_access", confidence="high",
            file="App.java", line=5, content="Flags.EMPTY", owner_type="business",
            owner_coord="__business__", module="app", is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"source": method},
            reverse_edges={"lib.Flags.EMPTY": [source_edge]},
            runtime_dependency_catalog={},
            require_current_final_artifact_business_edges=True,
            source_artifact_alignment={"status": "aligned"},
        )
        api_row = {
            "coord": "lib:flags", "api_name": "lib.Flags.EMPTY", "api_simple": "EMPTY",
            "api_signature": "", "symbol_kind": "field", "change_type": "REMOVED",
            "compatibility_flags": "CONSTANT_REMOVED", "old_value": "",
            "constant_field_evidence_json": json.dumps({
                "owner": "lib.Flags", "field_name": "EMPTY",
                "descriptor": "Ljava/lang/String;", "has_constant_value": True,
                "constant_value": "", "artifact_sha256": "a" * 64,
                "artifact_entry": "lib/Flags.class", "status": "complete",
                "failures": [],
            }),
            "severity": "P0", "confirmed": "true",
        }

        with patch.object(
            tracer, "_scan_packaged_runtime_dependencies_for_api", return_value={"status": "miss"}
        ):
            result = tracer.trace_api_with_confidence_weighting(
                api_row,
                graph,
                {},
                has_packaged_bytecode_fallback=True,
            )

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "INLINED_CONSTANT_USAGE_UNDETECTABLE")
        self.assertIsNone(result.is_reachable)
        self.assertTrue(result.call_paths)
        self.assertEqual(result.evidence_paths[0][0]["evidence_type"], "field_access")
        self.assertEqual(result.compile_impact, "recompile_break")
        self.assertEqual(result.runtime_link_impact, "inlined_no_link")
        self.assertEqual(
            result.constant_impact_evidence["old_field"]["artifact_entry"],
            "lib/Flags.class",
        )
        rendered = formatter.trace_result_to_api_entry(result)
        self.assertEqual(rendered["compile_impact"], "recompile_break")
        self.assertEqual(rendered["runtime_link_impact"], "inlined_no_link")

    def test_constant_field_bytecode_hit_reports_runtime_link_present(self):
        api_row = {
            "coord": "lib:flags", "api_name": "lib.Flags.VALUE", "api_simple": "VALUE",
            "api_signature": "", "symbol_kind": "field", "change_type": "REMOVED",
            "compatibility_flags": "CONSTANT_REMOVED",
            "old_field_has_constant_value": "true",
            "severity": "P0", "confirmed": "true",
        }
        graph = SimpleNamespace(
            methods_by_id={}, reverse_edges={},
            source_artifact_alignment={"status": "unverified"},
        )
        hit = {
            "status": "hit",
            "hits": [{
                "coord": "__business__",
                "class_fqcn": "app.App",
                "consumer_method": "run",
                "consumer_signature": "()",
                "target_display": "lib.Flags.VALUE",
                "evidence_type": "bytecode_field_access",
            }],
        }

        with patch.object(
            tracer, "_scan_packaged_runtime_dependencies_for_api", return_value=hit
        ):
            result = tracer.trace_api_with_confidence_weighting(
                api_row, graph, {}, has_packaged_bytecode_fallback=True,
            )

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.runtime_link_impact, "runtime_link_present")
        self.assertEqual(result.compile_impact, "unverified")
        alert = formatter._alert_rows_for_result(result)[0]
        self.assertEqual(alert["runtime_link_impact"], "runtime_link_present")
        self.assertEqual(alert["compile_impact"], "unverified")

    def test_external_dependency_constant_field_hit_reports_runtime_link_present(self):
        api_row = {
            "coord": "lib:flags", "api_name": "lib.Flags.VALUE", "api_simple": "VALUE",
            "api_signature": "", "symbol_kind": "field", "change_type": "REMOVED",
            "compatibility_flags": "CONSTANT_REMOVED",
            "old_field_has_constant_value": "true",
            "severity": "P0", "confirmed": "true",
        }
        graph = SimpleNamespace(
            methods_by_id={}, reverse_edges={},
            source_artifact_alignment={"status": "unverified"},
        )
        hit = {
            "status": "hit",
            "hits": [{
                "coord": "app:internal-library",
                "class_fqcn": "app.bridge.InternalBridge",
                "consumer_method": "run",
                "consumer_signature": "()",
                "target_display": "lib.Flags.VALUE",
                "evidence_type": "bytecode_field_access",
            }],
        }

        with patch.object(
            tracer, "_scan_packaged_runtime_dependencies_for_api", return_value=hit
        ):
            result = tracer.trace_api_with_confidence_weighting(
                api_row, graph, {}, has_packaged_bytecode_fallback=True,
            )

        self.assertEqual(result.runtime_link_impact, "runtime_link_present")
        self.assertEqual(result.compile_impact, "unverified")

    def test_direct_usage_with_external_constant_field_hit_reports_runtime_link_present(self):
        api_row = {
            "coord": "lib:flags", "api_name": "lib.Flags.VALUE", "api_simple": "VALUE",
            "api_signature": "", "symbol_kind": "field", "change_type": "REMOVED",
            "compatibility_flags": "CONSTANT_REMOVED",
            "old_field_has_constant_value": "true",
            "severity": "P0", "confirmed": "true",
        }
        graph = SimpleNamespace(
            methods_by_id={}, reverse_edges={}, runtime_dependency_catalog={},
            source_artifact_alignment={"status": "aligned"},
        )
        hit = {
            "status": "hit",
            "hits": [{
                "coord": "app:internal-library",
                "class_fqcn": "app.bridge.InternalBridge",
                "consumer_method": "run",
                "consumer_signature": "()",
                "target_display": "lib.Flags.VALUE",
                "evidence_type": "bytecode_field_access",
            }],
        }

        def direct_usage(_api_row, draft, _graph, trace_cache=None):
            draft.call_paths = ["app.App.run -> lib.Flags.VALUE"]
            draft.evidence_paths = [[{"evidence_type": "field_access"}]]
            return draft

        with (
            patch.object(
                tracer, "_scan_packaged_runtime_dependencies_for_api", return_value=hit,
            ),
            patch.object(tracer, "_try_build_direct_usage_result", side_effect=direct_usage),
        ):
            result = tracer.trace_api_with_confidence_weighting(
                api_row, graph, {}, has_packaged_bytecode_fallback=True,
            )

        self.assertEqual(result.runtime_link_impact, "runtime_link_present")
        self.assertEqual(result.compile_impact, "recompile_break")

    def test_direct_source_constant_usage_uses_inlining_decision_before_early_return(self):
        api_row = {
            "coord": "lib:flags", "api_name": "lib.Flags.EMPTY", "api_simple": "EMPTY",
            "api_signature": "", "symbol_kind": "field", "change_type": "REMOVED",
            "compatibility_flags": "CONSTANT_REMOVED", "severity": "P0", "confirmed": "true",
        }
        graph = SimpleNamespace(
            methods_by_id={}, reverse_edges={}, runtime_dependency_catalog={},
            source_artifact_alignment={"status": "aligned"},
        )

        def direct_usage(_api_row, draft, _graph, trace_cache=None):
            draft.call_paths = ["app.App.run -> lib.Flags.EMPTY"]
            draft.evidence_paths = [[{"evidence_type": "field_access"}]]
            draft.path_details = [{
                "path_status": "reachable", "business_reachable": True,
                "business_entry": "app.App.run", "path_text": draft.call_paths[0],
                "depth": 1, "evidence": draft.evidence_paths[0],
            }]
            return draft

        with (
            patch.object(
                tracer, "_scan_packaged_runtime_dependencies_for_api",
                return_value={"status": "miss"},
            ),
            patch.object(tracer, "_try_build_direct_usage_result", side_effect=direct_usage),
        ):
            result = tracer.trace_api_with_confidence_weighting(
                api_row, graph, {}, has_packaged_bytecode_fallback=True,
            )

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "INLINED_CONSTANT_USAGE_UNDETECTABLE")
        self.assertEqual(result.call_paths, ["app.App.run -> lib.Flags.EMPTY"])
        self.assertEqual(result.path_details[0]["path_status"], "uncertain")

    def test_source_artifact_miss_replaces_prior_complete_source_paths(self):
        api_row = {
            "coord": "lib:api", "api_name": "lib.Api.FLAG", "api_simple": "FLAG",
            "api_signature": "", "symbol_kind": "field", "change_type": "REMOVED",
            "severity": "P0", "confirmed": "true",
        }
        graph = SimpleNamespace(source_artifact_alignment={"status": "unverified"})
        method = SimpleNamespace(
            symbol_id="source", qualified_key="app.App.run", owner_type="business",
            owner_coord="__business__", is_test=False, file="App.java", line=4,
            class_fqcn="app.App", method_name="run",
        )
        draft = tracer._new_trace_draft(api_row)
        tracer._build_direct_usage_results(
            draft,
            [(method, "field_access")],
            "DIRECT_FIELD_USAGE",
            "source field usage",
            "lib.Api.FLAG",
        )

        tracer._apply_source_artifact_miss(draft, graph, "final artifact miss")
        result = tracer._finalize_trace_draft(draft)

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "SOURCE_ARTIFACT_ALIGNMENT_UNVERIFIED")
        self.assertFalse(any(path.complete for path in draft.envelope_paths))

    def test_target_runtime_closure_continues_upstream_from_field_consumer(self):
        api_row = {
            "coord": "com.vendor:target",
            "api_name": "com.vendor.Target.FLAG",
            "api_simple": "FLAG",
            "api_signature": "",
            "symbol_kind": "field",
        }
        identity = tracer.build_api_identity_key(api_row)
        caller = SimpleNamespace(
            symbol_id="outer", qualified_key="com.vendor.Outer.invoke()"
        )
        edge = tracer.CallEdge(
            caller_symbol_id=caller.symbol_id,
            caller_qualified_key=caller.qualified_key,
            callee_key="com.vendor.InternalBridge.use()",
            callee_simple_key="method:use()",
            evidence_type="bytecode_method_invocation", confidence="high",
            file="target.jar", line=0, content="invoke", owner_type="dependency",
            owner_coord="com.vendor:target", module="", is_test=False,
        )
        edge.runtime_analyzer_hit = {"coord": "com.vendor:target", "caller_owner": "com.vendor.Outer"}
        graph = SimpleNamespace(
            methods_by_id={caller.symbol_id: caller},
            reverse_edges={"com.vendor.InternalBridge.use()": [edge]},
            runtime_dependency_catalog={
                "_packaged_api_scan_results": {
                    identity: {
                        "status": "hit",
                        "hits": [{
                            "coord": "com.vendor:target",
                            "class_fqcn": "com.vendor.InternalBridge",
                            "consumer_method": "use",
                            "consumer_signature": "()",
                        }],
                    }
                }
            },
        )

        with patch.object(tracer, "_ensure_runtime_dependency_callers_for_key"), patch.object(
            tracer, "record_analyzer_edge", return_value={"recorded": True}
        ) as record:
            added = tracer._collect_target_runtime_reference_closure(graph, [api_row])

        self.assertEqual(added, 1)
        self.assertEqual(record.call_args.args[1], api_row)

    def test_target_runtime_closure_continues_upstream_from_class_consumer(self):
        api_row = {
            "coord": "com.vendor:target",
            "api_name": "com.vendor.RemovedType",
            "api_simple": "RemovedType",
            "api_signature": "",
            "symbol_kind": "class",
            "analysis_scope": "class_usage",
        }
        identity = tracer.build_api_identity_key(api_row)
        caller = SimpleNamespace(
            symbol_id="outer", qualified_key="com.vendor.Outer.invoke()"
        )
        edge = tracer.CallEdge(
            caller_symbol_id=caller.symbol_id,
            caller_qualified_key=caller.qualified_key,
            callee_key="com.vendor.InternalBridge.use()",
            callee_simple_key="method:use()",
            evidence_type="bytecode_method_invocation", confidence="high",
            file="target.jar", line=0, content="invoke", owner_type="dependency",
            owner_coord="com.vendor:target", module="", is_test=False,
        )
        edge.runtime_analyzer_hit = {
            "coord": "com.vendor:target", "caller_owner": "com.vendor.Outer"
        }
        graph = SimpleNamespace(
            methods_by_id={caller.symbol_id: caller},
            reverse_edges={"com.vendor.InternalBridge.use()": [edge]},
            runtime_dependency_catalog={
                "_packaged_api_scan_results": {
                    identity: {
                        "status": "hit",
                        "hits": [{
                            "coord": "com.vendor:target",
                            "class_fqcn": "com.vendor.InternalBridge",
                            "consumer_method": "use",
                            "consumer_signature": "()",
                        }],
                    }
                }
            },
        )

        with patch.object(tracer, "_ensure_runtime_dependency_callers_for_key"), patch.object(
            tracer, "record_analyzer_edge", return_value={"recorded": True}
        ) as record:
            added = tracer._collect_target_runtime_reference_closure(graph, [api_row])

        self.assertEqual(added, 1)
        self.assertEqual(record.call_args.args[1], api_row)

    def test_verified_final_artifact_inner_bridge_is_confirmable(self):
        internal = tracer.CallEdge(
            caller_symbol_id="bridge", caller_qualified_key="lib.Bridge.call()",
            callee_key="lib.Target.changed()", callee_simple_key="method:changed()",
            evidence_type="bytecode_method_invocation", confidence="high",
            file="target.jar!/lib/Bridge.class", line=0, content="invoke",
            owner_type="dependency", owner_coord="com.acme:library", module="",
            is_test=False,
        )
        internal.runtime_analyzer_hit = {"coord": "com.acme:library"}
        business = tracer.CallEdge(
            caller_symbol_id="app", caller_qualified_key="app.Application.run()",
            callee_key="lib.Bridge.call()", callee_simple_key="method:call()",
            evidence_type="bytecode_method_invocation", confidence="high",
            file="business.jar!/app/Application.class", line=0, content="invoke",
            owner_type="business", owner_coord="__business__", module="",
            is_test=False,
        )
        business.evidence_source = "current_final_artifact"
        business.runtime_analyzer_hit = {"coord": "__business__"}
        candidate = {
            "path": [internal, business], "provenance": "exact_name",
            "confidence": 1.0, "depth": 2,
        }
        result = SimpleNamespace(coord="com.acme:library")

        confirmed, fallback, reason = tracer.select_confirmable_reachable_candidate(
            result, [candidate]
        )

        self.assertIs(confirmed, candidate)
        self.assertIsNone(fallback)
        self.assertEqual(reason, "")

    def test_dependency_source_inner_bridge_cannot_confirm_final_artifact_path(self):
        internal_source = tracer.CallEdge(
            caller_symbol_id="bridge", caller_qualified_key="lib.Bridge.call()",
            callee_key="lib.Target.changed()", callee_simple_key="method:changed()",
            evidence_type="ast_method_invocation", confidence="high",
            file="Bridge.java", line=5, content="changed()",
            owner_type="dependency", owner_coord="com.acme:library", module="library",
            is_test=False,
        )
        business = tracer.CallEdge(
            caller_symbol_id="app", caller_qualified_key="app.Application.run()",
            callee_key="lib.Bridge.call()", callee_simple_key="method:call()",
            evidence_type="bytecode_method_invocation", confidence="high",
            file="business.jar!/app/Application.class", line=0, content="invoke",
            owner_type="business", owner_coord="__business__", module="app",
            is_test=False,
        )
        business.evidence_source = "current_final_artifact"
        candidate = {
            "path": [internal_source, business], "provenance": "exact_signature",
            "confidence": 1.0, "depth": 2,
        }

        self.assertFalse(tracer._edge_allowed_for_trace(
            internal_source,
            SimpleNamespace(require_current_final_artifact_business_edges=True),
        ))
        incoming = tracer.get_cached_sorted_incoming_edges(
            {"lib.Target.changed()": [internal_source]},
            "lib.Target.changed()",
            graph=SimpleNamespace(require_current_final_artifact_business_edges=True),
        )
        self.assertEqual(incoming, ())

    def test_runtime_reverse_edges_preserve_distinct_instruction_offsets(self):
        graph = SimpleNamespace(methods_by_id={}, reverse_edges={})
        matched = {
            "consumer_method": "run", "consumer_signature": "()",
            "evidence_type": "bytecode_method_invocation",
        }
        for offset in (6, 18):
            tracer._add_runtime_dependency_caller_edge(
                graph, "com.vendor.Target.call()", "com.acme:consumer",
                "/tmp/consumer.jar", "com.acme.Consumer", matched,
                analyzer_hit={"instruction_offset": offset},
            )

        edges = graph.reverse_edges["com.vendor.Target.call()"]
        self.assertEqual(len(edges), 2)
        self.assertEqual(
            {edge.runtime_analyzer_hit["instruction_offset"] for edge in edges},
            {6, 18},
        )

    def test_runtime_reverse_edges_preserve_bridge_descriptors_at_same_offset(self):
        graph = SimpleNamespace(methods_by_id={}, reverse_edges={})
        matched = {
            "consumer_method": "apply", "consumer_signature": "(java.lang.Object)",
            "evidence_type": "bytecode_method_invocation",
        }
        for descriptor in (
            "(Ljava/lang/Object;)Ljava/lang/Object;",
            "(Ljava/lang/Object;)Ljava/lang/String;",
        ):
            tracer._add_runtime_dependency_caller_edge(
                graph, "com.vendor.Target.call()", "com.acme:consumer",
                "/tmp/consumer.jar", "com.acme.Consumer", matched,
                analyzer_hit={
                    "instruction_offset": 2,
                    "consumer_descriptor": descriptor,
                    "callee_descriptor": "()V",
                },
            )

        edges = graph.reverse_edges["com.vendor.Target.call()"]
        self.assertEqual(len(edges), 2)
        self.assertEqual(
            {edge.runtime_analyzer_hit["consumer_descriptor"] for edge in edges},
            {
                "(Ljava/lang/Object;)Ljava/lang/Object;",
                "(Ljava/lang/Object;)Ljava/lang/String;",
            },
        )

    def test_runtime_reverse_edges_preserve_distinct_multi_release_variants(self):
        graph = SimpleNamespace(methods_by_id={}, reverse_edges={})
        matched = {
            "consumer_method": "run", "consumer_signature": "()",
            "consumer_descriptor": "()V", "callee_descriptor": "()V",
            "evidence_type": "bytecode_method_invocation",
        }
        base_hit = {
            "jar_path": "/tmp/consumer.jar",
            "artifact_container_entry": "BOOT-INF/lib/consumer.jar",
            "class_entry": "com/acme/Consumer.class",
            "instruction_offset": 6,
        }
        versioned_hit = {
            **base_hit,
            "class_entry": "META-INF/versions/11/com/acme/Consumer.class",
            "multi_release_version": 11,
        }
        for hit in (versioned_hit, base_hit, versioned_hit, base_hit):
            tracer._add_runtime_dependency_caller_edge(
                graph, "com.vendor.Target.call()", "com.acme:consumer",
                "/tmp/consumer.jar", "com.acme.Consumer", matched,
                analyzer_hit=hit,
            )

        edges = graph.reverse_edges["com.vendor.Target.call()"]
        self.assertEqual(len(edges), 2)
        self.assertEqual(
            {
                edge.runtime_analyzer_hit["class_entry"]
                for edge in edges
            },
            {
                "com/acme/Consumer.class",
                "META-INF/versions/11/com/acme/Consumer.class",
            },
        )

    def test_runtime_constructor_caller_keeps_jvm_init_lookup_key(self):
        caller = tracer._runtime_method_def_for_packaged_caller(
            "com.acme:consumer", "/tmp/consumer.jar", "com.acme.Widget",
            "<init>", "(java.lang.String)",
        )

        self.assertEqual(
            caller.qualified_key,
            "com.acme.Widget.<init>(java.lang.String)",
        )
        self.assertEqual(caller.method_name, "<init>")

    def test_runtime_caller_expansion_scans_final_artifact_business_jar(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_source = root / "target-src/com/vendor/Target.java"
            target_source.parent.mkdir(parents=True)
            target_source.write_text(
                "package com.vendor; public class Target { public static void call() {} }",
                encoding="utf-8",
            )
            target_classes = self._compile_java_files(
                root / "target-classes", [target_source]
            )
            target_jar = root / "target.jar"
            self._jar_compiled_classes(target_jar, target_classes)

            app_source = root / "app-src/app/Application.java"
            app_source.parent.mkdir(parents=True)
            app_source.write_text(
                "package app; public class Application { "
                "public void run() { com.vendor.Target.call(); } }",
                encoding="utf-8",
            )
            app_classes = self._compile_java_files(
                root / "app-classes", [app_source], classpath=target_jar
            )
            business_jar = root / "business-classes.jar"
            self._jar_compiled_classes(business_jar, app_classes)
            graph = SimpleNamespace(
                methods_by_id={}, reverse_edges={},
                runtime_dependency_catalog={
                    "status": "complete", "target_jdk": 17,
                    "by_coord": {
                        "__business__": {
                            "coord": "__business__", "version": "current",
                            "scope": "runtime", "jar_path": str(business_jar),
                            "artifact_entry": "<business-classes>",
                            "evidence_source": "current_final_artifact",
                        },
                    },
                },
            )

            result = tracer._ensure_runtime_dependency_callers_for_key(
                graph, "com.vendor.Target.call()"
            )

        self.assertEqual(result["edges_added"], 1)
        edge = graph.reverse_edges["com.vendor.Target.call()"][0]
        self.assertEqual(edge.owner_type, "business")
        self.assertEqual(edge.runtime_analyzer_hit["coord"], "__business__")
        self.assertEqual(edge.runtime_analyzer_hit["artifact_container_entry"], "")
        self.assertEqual(edge.runtime_analyzer_hit["caller_owner"], "app.Application")

    def test_batch_runtime_scan_matches_nested_owner_dollar_and_dot_forms(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "src/com/acme/Target.java"
            consumer = root / "src/com/acme/Consumer.java"
            target.parent.mkdir(parents=True)
            target.write_text(
                "package com.acme; public class Target { public static class Nested { "
                "public void call() {} } }",
                encoding="utf-8",
            )
            consumer.write_text(
                "package com.acme; public class Consumer { public void run() { "
                "new Target.Nested().call(); } }",
                encoding="utf-8",
            )
            classes = self._compile_java_files(root / "classes", [target, consumer])
            jar_path = root / "runtime.jar"
            self._jar_compiled_classes(jar_path, classes)
            api_row = {
                "coord": "com.acme:target", "api_name": "com.acme.Target$Nested.call",
                "api_simple": "call", "api_signature": "()", "symbol_kind": "method",
            }
            graph = SimpleNamespace(
                runtime_dependency_catalog=self._runtime_catalog((("com.acme:target", jar_path),))
            )

            scans = tracer._build_packaged_runtime_dependency_scan_cache([api_row], graph)

        scan = scans[tracer.build_api_identity_key(api_row)]
        self.assertEqual(scan["status"], "hit")
        self.assertTrue(any(hit["class_fqcn"] == "com.acme.Consumer" for hit in scan["hits"]))


if __name__ == "__main__":
    unittest.main()
