import json
import io
import os
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
import gate  # noqa: E402
import s5_call_chain_engine_integrated as step5  # noqa: E402
import s6_report  # noqa: E402


class Step5KeyMatchingTest(unittest.TestCase):
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
        self.assertEqual(mocked_builder.call_count, 1)

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

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "BEHAVIOR_CHANGED_PRECISE_TARGET_NOT_CONFIRMED")
        self.assertEqual(result.match_provenance, "fallback_simple")

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

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "FALLBACK_SIMPLE_PATH_UNCONFIRMED")
        self.assertEqual(result.match_provenance, "fallback_simple")
        self.assertTrue(result.evidence_paths)
        self.assertIn("Controller.handle", result.call_paths[0])

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
            output_dir = report_dir / "s5_call_chain"
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

            _, summary_json_path = formatter.generate_enhanced_summary(results, output_dir)
            summary = json.loads(Path(summary_json_path).read_text(encoding="utf-8"))

        self.assertEqual(summary["user_conclusion_summary"]["已确认影响"], 1)
        self.assertEqual(summary["user_conclusion_summary"]["可能影响"], 1)
        self.assertEqual(summary["user_conclusion_summary"]["需要补充输入"], 1)
        self.assertEqual(summary["quality_gate"]["needs_input"], 1)

    def test_generate_enhanced_summary_writes_per_dependency_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            output_dir = report_dir / "s5_call_chain"
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
            per_dependency_summary = report_dir / "per_dependency" / "a_b" / "summary.json"
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
            s5_dir = report_dir / "s5_call_chain"
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
        self.assertIn("| app | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 1 |", report_text)

    def test_s6_report_keeps_probable_impact_and_needs_input_out_of_uncovered_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            s5_dir = report_dir / "s5_call_chain"
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
        self.assertIn("## 十一、可能影响（1 项）", report_text)
        self.assertIn("## 十二、需要补充输入（1 项）", report_text)
        self.assertIn("## 十三、未覆盖/未分析（1 项）", report_text)
        self.assertIn("| a:b |  | 否 |  |  | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 3 |", report_text)
        self.assertIn("| app | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 3 |", report_text)
        self.assertNotIn("## 十一、未覆盖/未分析（3 项）", report_text)

    def test_s6_report_reads_per_dependency_summary_and_renders_dependency_conclusion_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            s5_dir = report_dir / "s5_call_chain"
            per_dep_dir = report_dir / "per_dependency" / "a_b"
            s5_dir.mkdir(parents=True)
            per_dep_dir.mkdir(parents=True)
            (report_dir / "s1_dep_changes.csv").write_text(
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
        self.assertIn("### 单依赖包最终结论", report_text)
        self.assertIn("| a:b | 移除 | 是 | reachable |  |  | strong | com.example.Demo.call |", report_text)

    def test_gate_allows_checkpoint_when_inputs_are_missing_without_strict_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            output_dir = report_dir / "s5_call_chain"
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
            all_changed_apis="/tmp/demo/.upgrade-report/s4_jar_compare/all_changed_apis.csv",
            output_dir="/tmp/other/s5_call_chain",
        )

        self.assertEqual(
            step5.infer_step5_report_dir(args),
            "/tmp/demo/.upgrade-report",
        )

    def test_infer_step5_report_dir_falls_back_to_output_dir_parent(self):
        args = SimpleNamespace(
            report_dir="",
            all_changed_apis="",
            output_dir="/tmp/demo/.upgrade-report/s5_call_chain_recheck",
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
                    "/tmp/demo/.upgrade-report/s4_jar_compare/all_changed_apis.csv",
                    "--output-dir",
                    "/tmp/demo/.upgrade-report/s5_call_chain",
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
            output_dir = report_dir / "s5_call_chain"
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            output_dir.mkdir(parents=True)
            (report_dir / "s4_jar_compare").mkdir(parents=True)
            all_changed_apis = report_dir / "s4_jar_compare" / "all_changed_apis.csv"
            all_changed_apis.write_text("coord,api_name\ncom.example:demo,com.example.Target.call\n", encoding="utf-8")

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
            output_dir = report_dir / "s5_call_chain"
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            output_dir.mkdir(parents=True)
            (report_dir / "s4_jar_compare").mkdir(parents=True)
            all_changed_apis = report_dir / "s4_jar_compare" / "all_changed_apis.csv"
            all_changed_apis.write_text("coord,api_name\ncom.example:demo,com.example.Target.call\n", encoding="utf-8")
            (report_dir / "s1_deps_current_resolved.csv").write_text(
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
            output_dir = report_dir / "s5_call_chain"
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            output_dir.mkdir(parents=True)
            dep_source_dir = project_dir / "deps" / "demo-lib" / "src" / "main" / "java"
            dep_source_dir.mkdir(parents=True)
            (report_dir / "s4_jar_compare").mkdir(parents=True)
            all_changed_apis = report_dir / "s4_jar_compare" / "all_changed_apis.csv"
            all_changed_apis.write_text("coord,api_name\ncom.example:demo,com.example.Target.call\n", encoding="utf-8")

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
        self.assertIn("no lookup groups matched reverse edges", output)

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
