import csv
import json
import io
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import confidence_weighted_tracer as tracer  # noqa: E402
import enhanced_source_analyzer as source_analyzer  # noqa: E402
import enhanced_output_formatter as formatter  # noqa: E402
import framework_adapters  # noqa: E402
import gate  # noqa: E402
import s5_call_chain_engine_integrated as step5  # noqa: E402
import s6_report  # noqa: E402
from pipeline_constants import PER_DEPENDENCY_DIRNAME  # noqa: E402


class Step5KeyMatchingTest(unittest.TestCase):
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

    def test_step5_emits_tree_sitter_missing_checkpoint_before_regex_degrade(self):
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
                allow_degraded=False,
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

            self.assertEqual(rc, step5.EXIT_AWAITING_USER)
            payload = json.loads(stdout.getvalue().split(step5.STEP_INTERACTION_PREFIX, 1)[1].strip())
            self.assertEqual(payload["reason_code"], "step5_tree_sitter_missing_need_resolution")
            self.assertIn("allow_degraded", payload["response_schema"]["properties"])
            self.assertIn("tree_sitter_installed", payload["response_schema"]["properties"])
            self.assertTrue((output_dir / "tree_sitter_preflight.json").exists())

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

        def fake_expand(_graph, _lookup_key):
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

        tracer._build_packaged_dependency_hit_result(result, hits, graph)

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
            self.assertEqual(parser_info["actual_parser"], "regex")
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

    def test_analyze_file_auto_installs_tree_sitter_before_regex_fallback(self):
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
                source_analyzer.TREE_SITTER_AUTO_INSTALL_ATTEMPTED = True
                source_analyzer.TREE_SITTER_AUTO_INSTALL_ERROR = ""
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
            self.assertTrue(parser_info["tree_sitter_auto_install_attempted"])
            self.assertEqual(parser_info["tree_sitter_auto_install_error"], "")

    def test_analyze_file_records_tree_sitter_auto_install_failure_before_degrading(self):
        with tempfile.TemporaryDirectory() as tmp:
            java_file = Path(tmp) / "Demo.java"
            java_file.write_text(
                "package com.example; public class Demo { public void run() {} }\n",
                encoding="utf-8",
            )

            def fake_ensure_tree_sitter_available():
                source_analyzer.TREE_SITTER_AUTO_INSTALL_ATTEMPTED = True
                source_analyzer.TREE_SITTER_AUTO_INSTALL_ERROR = "pip_returncode=1"
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
            self.assertIsInstance(methods, list)
            self.assertEqual(parser_info["actual_parser"], "regex")
            self.assertEqual(parser_info["fallback_reason"], "tree_sitter_unavailable")
            self.assertTrue(parser_info["tree_sitter_auto_install_attempted"])
            self.assertEqual(parser_info["tree_sitter_auto_install_error"], "pip_returncode=1")

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
        result = SimpleNamespace(
            analysis_status="not_found_in_static_analysis", is_reachable=False,
            reason_code="NO_STATIC_PATH", reachable_note="", verification_commands=[],
        )
        updated = tracer._build_inlined_constant_result(result)
        self.assertEqual(updated.analysis_status, "uncertain")
        self.assertIsNone(updated.is_reachable)
        self.assertEqual(updated.reason_code, "INLINED_CONSTANT_USAGE_UNDETECTABLE")

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

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "ANALYSIS_INCOMPLETE")
        self.assertIn("图构建被截断", result.reachable_note)

    def test_assess_graph_completeness_ignores_kotlin_only_fallbacks(self):
        completeness = tracer.assess_graph_completeness(
            {
                "truncated": False,
                "parser_fallback_reasons": {"unsupported_language_kotlin": 3},
                "edge_cap_hits": 0,
            }
        )

        self.assertFalse(completeness["incomplete"])
        self.assertEqual(completeness["reasons"], [])

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
                }
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

    def test_generate_enhanced_summary_outputs_user_conclusion_counts(self):
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
            summary_text = Path(summary_path).read_text(encoding="utf-8")
            by_api_text = next((output_dir / "by_api").glob("a_b_com_example_OrderService_run*.txt")).read_text(
                encoding="utf-8"
            )

        self.assertEqual(summary["user_conclusion_summary"]["已确认影响"], 1)
        self.assertEqual(summary["user_conclusion_summary"]["可能影响"], 1)
        self.assertEqual(summary["user_conclusion_summary"]["需要补充输入"], 1)
        self.assertEqual(summary["quality_gate"]["needs_input"], 1)
        self.assertLess(summary_text.index("一、结论总览"), summary_text.index("附：内部状态统计"))
        self.assertIn("二、已确认影响（优先处理）", summary_text)
        self.assertIn("四、需要补充输入（建议先补齐后重跑）", summary_text)
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
                        "declared_signature_index_builds": 1,
                        "declared_signature_index_size": 1234,
                    },
                }
            }

            timing_path = step5._write_step5_timing_csv(output_dir, graph_stats)
            with Path(timing_path).open(encoding="utf-8") as f:
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
        self.assertEqual(values[("trace", "declared_signature_index_builds")], "1")
        self.assertEqual(values[("trace", "declared_signature_index_size")], "1234")

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

    def test_direct_business_usage_scans_are_cached_per_target(self):
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
            "second": SimpleNamespace(
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
                get_body_text=lambda: "return Flags.ENABLED;",
            ),
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
        self.assertEqual(perf["direct_class_usage_scanned_methods"], 2)
        self.assertEqual(perf["direct_field_usage_cache_misses"], 1)
        self.assertEqual(perf["direct_field_usage_cache_hits"], 1)
        self.assertEqual(perf["direct_field_usage_scanned_methods"], 2)

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
            with output.open(encoding="utf-8") as handle:
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
        self.assertTrue(all(row["conclusion_level"] == "candidate" for row in rows))
        self.assertTrue(all(row["business_reachable"] == "unknown" for row in rows))
        self.assertTrue(all(row["api_id"] and row["path_id"] for row in rows))
        self.assertTrue(all("尚未证明" in row["reason"] for row in rows))
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
        self.assertEqual("入口：A.call；终点：B.call；1 跳", row["chain_summary"])
        self.assertEqual("A.call", row["chain_entry"])
        self.assertEqual("B.call", row["chain_target"])
        self.assertEqual("1", row["chain_hop_count"])
        self.assertEqual("1. A.call -> 2. B.call", row["chain_detail"])
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
            with output.open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 1)
        self.assertEqual("未发现静态调用路径", rows[0]["conclusion"])
        self.assertEqual("依赖 a:b 删除了方法 com.acme.Api.gone()（严重级别 P0）", rows[0]["change_summary"])
        self.assertIn("未形成完整链路", rows[0]["chain_summary"])
        self.assertEqual("com.acme.Api.gone", rows[0]["chain_target"])
        self.assertEqual(rows[0]["conclusion_level"], "no_static_path")
        self.assertEqual(rows[0]["path_text"], "")

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
            per_dependency_summary = self._api_changes_dir(report_dir) / PER_DEPENDENCY_DIRNAME / "a_b" / "summary.json"
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

    def test_dependency_scheduled_entry_is_reachable_without_business_source_caller(self):
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

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "RUNTIME_DEPENDENCY_ENTRY_REACHED")
        self.assertEqual(result.dependency_chain_coords, ["com.example:dep-job"])
        self.assertEqual(
            result.call_paths,
            ["com.dep.CleanupJob.cleanup → 变更API: com.vendor.LegacyApi.removed()"],
        )

    def test_packaged_spring_listener_is_reachable_from_runtime_registration(self):
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

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "RUNTIME_DEPENDENCY_ENTRY_REACHED")
        self.assertEqual(result.dependency_chain_coords, ["com.vendor:boot"])

    def test_active_spring_registration_produces_complete_business_to_callback_chain(self):
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
        framework_adapters.attach_framework_edges_to_graph(graph, {"adapters": [{
            "adapter": "spring_runtime_artifact",
            "version": "1",
            "edges": [{
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
            }],
        }]})

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

        self.assertEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "SYSTEM_CODE_REACHED")
        self.assertIn(
            "com.acme.Application.main → Spring Boot框架注册 → "
            "com.vendor.RuntimeListener.onApplicationEvent → 变更API: com.vendor.LegacyApi.removed()",
            result.call_paths,
        )

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

    def test_packaged_hit_is_reachable_when_consumer_is_registered_spring_callback(self):
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

        built = tracer._build_packaged_dependency_hit_result(result, [hit], graph)

        self.assertEqual(built.analysis_status, "reachable")
        self.assertEqual(built.reason_code, "RUNTIME_FRAMEWORK_ENTRY_REACHED")
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
        merged = tracer._merge_runtime_framework_paths(generic, [hit], graph)
        self.assertEqual(merged.reason_code, "RUNTIME_FRAMEWORK_ENTRY_REACHED")
        self.assertTrue(any(
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
            summary_text = Path(summary_path).read_text(encoding="utf-8")
            with (call_chain_dir / "alerts.csv").open(encoding="utf-8") as alert_file:
                alert_rows = list(csv.DictReader(alert_file))
            findings = s6_report.collect_findings(str(report))
            final_report = s6_report.generate_report(findings)

        self.assertIn(("com.vendor:legacy", "com.vendor.LegacyApi"), providers)
        self.assertEqual(result.analysis_status, "not_impacted")
        self.assertEqual(result.reason_code, "RUNTIME_SYMBOL_PRESERVED_IDENTICALLY")
        self.assertIn("com.vendor:aggregate", result.call_paths[0])
        self.assertEqual(
            result.evidence_paths[0][0]["evidence_type"],
            "identical_current_class_provider",
        )
        self.assertEqual(summary_payload["not_impacted"], 1)
        self.assertEqual(alert_rows[0]["api_status"], "not_impacted")
        self.assertEqual(alert_rows[0]["conclusion_level"], "confirmed_no_impact")
        self.assertIn("已确认不受影响", summary_text)
        self.assertIn("### 3.1 符号保留证据", final_report)
        self.assertIn("com.vendor:aggregate", final_report)
        self.assertIn("不包含被删除 JAR 中的 SPI 配置、资源文件、清单等非 API 内容", final_report)

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
        self.assertIn("入口：Other.run；终点：com.example.Demo.call(Long)；1 跳", not_found_csv)
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
        self.assertIn("## 三、分析结果总表", report_text)
        self.assertIn("## 四、附录", report_text)
        self.assertIn("| 依赖坐标 | 变更 API | 变化 | 结论 | 证据摘要 / 未确认原因 |", report_text)
        self.assertNotIn("| 依赖坐标 | 变更 API | 变化 | 结论 | 关键证据 | 未确认原因 |", report_text)
        self.assertLess(
            report_text.index("## 一、核心结论"),
            report_text.index("## 二、结论限制"),
        )
        self.assertLess(
            report_text.index("## 二、结论限制"),
            report_text.index("## 三、分析结果总表"),
        )
        self.assertLess(
            report_text.index("## 三、分析结果总表"),
            report_text.index("## 四、附录"),
        )
        self.assertIn("com.vendor.LegacyApi.removed", report_text)
        self.assertIn("com.acme.OrderService.submit", report_text)
        self.assertIn("### 3.1 调用链证据", report_text)
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
            self.assertIn("## 三、分析结果总表", report_text)
            self.assertIn("本表共有 100 条 API 分析结果，当前展示 20 条，省略 80 条", report_text)
            self.assertIn("完整逐链路台账见 `evidence/call_chain/alerts.csv`", report_text)
            self.assertIn("`deliverables/s6_not_found_apis.csv/md`", report_text)
            self.assertNotIn("`deliverables/s6_probable_impact_apis.csv/md`", report_text)
            self.assertIn("### 运行产物阅读分层", report_text)
            self.assertIn("#### 给用户看的产物", report_text)
            self.assertIn("#### 用户深入排查时看的产物", report_text)
            self.assertIn("#### 程序使用的产物", report_text)
            self.assertIn("| `deliverables/report.md` | 最终报告；优先阅读这一份 |", report_text)
            self.assertIn("| `evidence/static_scan/s3_*.csv/.txt` | JDK、Spring Boot、反射等静态扫描命中 |", report_text)
            self.assertIn("| `evidence/api_changes/changed_dependencies.md` | 依赖包维度的 Step4 变化摘要；用于选择 Step5 分析范围 |", report_text)
            self.assertIn("| `evidence/api_changes/changed_dependencies.csv` | 依赖包维度的结构化清单；供筛选和自动化使用 |", report_text)
            self.assertIn("| `evidence/api_changes/all_changed_apis.csv` | 依赖 API 变化全集 |", report_text)
            self.assertIn("| `evidence/api_changes/all_changed_apis_part_*.csv` | 依赖 API 变化拆分文件（每 500 条一份） |", report_text)
            self.assertNotIn("all_changed_apis_alerts.csv", report_text)
            self.assertIn("| `evidence/call_chain/alerts_<status>.csv` / `alerts_<status>_NNN.csv` | 按链路状态拆分的台账 |", report_text)
            self.assertNotIn("| `deliverables/s6_probable_impact_apis.csv/md` |", report_text)
            self.assertNotIn("| `deliverables/s6_uncertain_apis.csv/md` |", report_text)
            self.assertNotIn("| `deliverables/s6_needs_input_apis.csv/md` |", report_text)
            self.assertNotIn("| `deliverables/s6_not_analyzed_apis.csv/md` |", report_text)
            self.assertIn("| `deliverables/s6_not_found_apis.csv/md` | 未发现调用路径清单 |", report_text)
            self.assertNotIn("### 产物索引", report_text)
            self.assertIn("## 二、结论限制", report_text)
            self.assertIn("| 分析完整度 | 部分完整 |", report_text)
            self.assertIn("动态调用可能漏报", report_text)
            self.assertIn("反射调用可能漏报。", report_text)
            self.assertIn("排序：已确认/高风险、可能影响、需人工复核、已确认不受影响、缺少依赖源码/构建产物，无法回溯调用链、本次未完成分析、未发现调用路径。", report_text)
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
            self.assertIn("| `.runtime/findings/s6_findings.json` | Step6 结构化结果；供程序读取，不作为人工优先阅读文件 |", report_text)
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
            self.assertIn("## 三、分析结果总表", report_text)
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
            self.assertIn("## 原因分类", md_text)
            self.assertIn("## 依赖坐标分布", md_text)
            self.assertIn("## 明细样例（前 50 条）", md_text)
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
        self.assertIn("## 三、分析结果总表", report_text)
        self.assertIn("com.example.Demo.behavior", report_text)
        self.assertIn("com.example.Demo.bridge", report_text)
        self.assertIn("com.example.Demo.unknown", report_text)
        self.assertIn("| 可能影响 | 1 |", report_text)
        self.assertIn("| 缺少依赖源码/构建产物，无法回溯调用链 | 1 |", report_text)
        self.assertIn("| 本次未完成分析 | 1 |", report_text)
        self.assertIn("可能影响", report_text)
        self.assertIn("缺少依赖源码/构建产物，无法回溯调用链", report_text)
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
        self.assertIn("## 三、分析结果总表", report_text)
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

    def test_bridge_precheck_ignores_kotlin_only_parser_fallbacks(self):
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
        self.assertTrue(info["needs_bridge"])
        self.assertEqual(info["reason"], "no_direct_call_found")

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

    def test_step5_requires_interaction_when_dependency_source_mapping_is_missing(self):
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
                self.assertEqual(exit_code, step5.EXIT_AWAITING_USER)
                self.assertIn("缺失映射的依赖坐标：com.example:demo", stderr.getvalue())

                stdout_lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
                self.assertTrue(stdout_lines)
                self.assertTrue(stdout_lines[-1].startswith(step5.STEP_INTERACTION_PREFIX))
                interaction = json.loads(stdout_lines[-1][len(step5.STEP_INTERACTION_PREFIX):])
                action_ids = {item.get("id") for item in interaction.get("options", [])}
                properties = (interaction.get("response_schema") or {}).get("properties", {})

                self.assertEqual(interaction.get("step_id"), "step5")
                self.assertEqual(interaction.get("status"), "awaiting_user_input")
                self.assertEqual(interaction.get("reason_code"), "step5_dependency_source_mapping_missing")
                self.assertIn("rerun_current_step", action_ids)
                self.assertIn("restart_from_step", action_ids)
                self.assertIn("dependency_source_dirs", properties)
                self.assertIn("allow_degraded", properties)

                details_path = output_dir / "missing_dependency_source_mappings.json"
                self.assertTrue(details_path.exists())
                details = json.loads(details_path.read_text(encoding="utf-8"))
                self.assertEqual(details.get("missing_mapping_count"), 1)
                self.assertEqual(details.get("missing_mapping_coords"), ["com.example:demo"])

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
                 patch.object(step5, "_find_maven_jar", return_value="/tmp/sample-consumer.jar"), \
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
                 patch.object(step5, "build_runtime_dependency_catalog", return_value={"by_coord": {"com.example:used": {"coord": "com.example:used"}}}), \
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
        with patch.object(
            step5,
            "_load_coord_versions",
            return_value={"com.example:demo": {"new_version": "1.0.0"}},
        ), patch.object(step5, "_find_maven_jar", return_value="/tmp/demo.jar"), patch.object(
            step5,
            "_run_javap_for_class",
        ) as mocked_javap:
            metadata = step5.build_jar_metadata_for_source_roots(source_roots, ".")

        self.assertEqual(metadata["jar_paths"], {"com.example:demo": "/tmp/demo.jar"})
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
            "com.example:versioned:jar:tests=/tmp/versioned-src",
        ]
        catalog = {
            "by_coord": {
                "__business__": {"coord": "__business__"},
                "com.example:used": {"coord": "com.example:used"},
                "com.example:versioned": {"coord": "com.example:versioned"},
            }
        }

        filtered, skipped = step5.filter_dependency_source_mappings_for_runtime(mappings, catalog)

        self.assertEqual(
            filtered,
            [
                "com.example:used=/tmp/used-src",
                "com.example:versioned:jar:tests=/tmp/versioned-src",
            ],
        )
        self.assertEqual(
            [item["reason"] for item in skipped],
            ["invalid_mapping_format", "dependency_source_not_in_current_runtime_catalog"],
        )
        self.assertEqual(skipped[1]["coord"], "com.example:unused")

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
            }]), patch.object(step5, "build_enhanced_source_graph", return_value=fake_graph_result), patch.object(
                step5,
                "check_apis_that_need_bridge",
                return_value={"sample:dep:com.example.Api.call": {"needs_bridge": False, "has_dependency_source_mapping": True, "reason": ""}},
            ), patch.object(step5, "build_jar_metadata_for_source_roots", return_value={"by_class": {}, "jar_paths": {}}), patch.object(
                step5,
                "trace_all_apis_with_confidence_weighting",
                return_value=[fake_result],
            ), patch.object(step5, "generate_enhanced_summary", return_value=None):
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
            self.assertEqual([item.analysis_status for item in results], ["uncertain", "not_found_in_static_analysis"])
            self.assertEqual(results[0].reason_code, "PACKAGED_DEPENDENCY_BYTECODE_USAGE")

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

        built = tracer._build_packaged_dependency_hit_result(result, [hit], graph)

        self.assertEqual(built.analysis_status, "reachable")
        self.assertEqual(built.reason_code, "BUSINESS_ARTIFACT_BYTECODE_USAGE")
        self.assertTrue(any(
            "com.acme.app.App.entry -> com.acme:consumer-lib:com.acme.consumer.ConsumerFacade.use(String)"
            in path
            for path in built.call_paths
        ))
        self.assertTrue(any(detail.get("business_reachable") for detail in built.path_details))

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
            perf = tracer._finalize_step5_perf_stats(graph)["bytecode_expand"]

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
                }],
                "field_refs": [], "class_refs": [],
            }
            with patch.object(
                tracer,
                "_load_runtime_dependency_class_references",
                side_effect=[None, refs],
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
                }
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


if __name__ == "__main__":
    unittest.main()
