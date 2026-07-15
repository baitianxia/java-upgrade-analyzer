import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import confidence_weighted_tracer as tracer
import enhanced_output_formatter as formatter
import indirect_usage_analyzer as indirect_module
from enhanced_source_analyzer import MethodDef
from indirect_usage_analyzer import (
    analyze_and_merge_indirect_usages,
    collect_indirect_usage_batch,
    parse_javap_indirect_references,
)


def api_row():
    return {
        "coord": "commons-lang:commons-lang",
        "api_name": "org.apache.commons.lang.StringUtils.isBlank",
        "api_simple": "isBlank", "api_signature": "(String)",
        "symbol_kind": "method", "change_type": "REMOVED",
        "severity": "P0", "confirmed": "true", "source": "old_jar",
        "analysis_scope": "method",
    }


def api_row_for(owner, member="removed", signature="()"):
    return {
        "coord": "com.example:large-lib",
        "api_name": f"{owner}.{member}",
        "api_simple": member,
        "api_signature": signature,
        "symbol_kind": "method",
        "change_type": "REMOVED",
        "severity": "P1",
        "confirmed": "true",
        "source": "old_jar",
        "analysis_scope": "method",
    }


def business_method(body):
    return MethodDef(
        symbol_id="m1", qualified_key="com.acme.OrderService.check(String)",
        simple_key="method:check(String)", class_fqcn="com.acme.OrderService",
        class_name="OrderService", method_name="check", return_type="boolean",
        file="/project/src/main/java/com/acme/OrderService.java", line=10, end_line=30,
        package_name="com.acme", owner_type="business", owner_coord="",
        module="app", source_root="/project/src/main/java", language="java",
        is_test=False, param_types={"value": "java.lang.String"},
        param_declared_types={"value": "String"}, imports={}, static_imports={},
        body_text=body,
    )


def business_method_with_id(symbol_id, body, imports=None):
    method = business_method(body)
    method.symbol_id = symbol_id
    method.qualified_key = f"com.acme.OrderService.{symbol_id}()"
    method.imports = imports or {}
    return method


def business_method_with_params(symbol_id, method_name, params, body):
    method = business_method_with_id(symbol_id, body)
    method.method_name = method_name
    method.qualified_key = f"com.acme.OrderService.{method_name}()"
    method.param_types = dict(params)
    method.param_declared_types = dict(params)
    return method


def graph_for(method):
    return SimpleNamespace(
        methods_by_id={method.symbol_id: method}, reverse_edges={},
        lookup_keys_by_symbol={method.symbol_id: [method.qualified_key]},
        type_metadata={}, runtime_dependency_catalog={},
    )


class IndirectUsageAnalyzerTest(unittest.TestCase):
    def test_collect_indirect_usage_batch_returns_exact_reflection_as_edge_and_concern(self):
        method = business_method('''
            return (Boolean) Class.forName("org.apache.commons.lang.StringUtils")
                .getMethod("isBlank", String.class).invoke(null, value);
        ''')
        graph = graph_for(method)

        batch = collect_indirect_usage_batch(graph, [api_row()], [])

        self.assertEqual(len(batch.edges), 1)
        self.assertEqual(batch.edges[0].edge_kind, "reflection_method_invocation")
        self.assertEqual(batch.edges[0].provenance.authority.value, "source_indirect_inference")
        self.assertEqual(batch.concerns[0].reason_code, "REFLECTION_METHOD_INVOCATION")
        self.assertEqual(batch.coverage[0].api_identity, indirect_module.api_key(api_row()))

    def test_collect_indirect_usage_batch_reports_dynamic_member_as_concern(self):
        method = business_method('''
            Class<?> type = Class.forName("org.apache.commons.lang.StringUtils");
            Method target = type.getMethod(methodName, String.class);
            return (Boolean) target.invoke(null, value);
        ''')

        batch = collect_indirect_usage_batch(graph_for(method), [api_row()], [])

        self.assertEqual(batch.edges, ())
        self.assertEqual(batch.concerns[0].reason_code, "REFLECTION_OVERLOAD_UNRESOLVED")

    def test_collect_indirect_usage_batch_reports_resource_read_failure_as_evidence_failure(self):
        method = business_method("return false;")
        with tempfile.TemporaryDirectory() as tmp:
            java_root = Path(tmp) / "src/main/java"
            resource_root = Path(tmp) / "src/main/resources"
            java_root.mkdir(parents=True)
            resource_root.mkdir(parents=True)
            resource = resource_root / "broken.xml"
            resource.write_text("x", encoding="utf-8")
            original = Path.read_text
            Path.read_text = lambda path, *args, **kwargs: (_ for _ in ()).throw(OSError("denied")) if path.name == "broken.xml" else original(path, *args, **kwargs)
            try:
                batch = collect_indirect_usage_batch(
                    graph_for(method), [api_row()], [{"root": str(java_root)}]
                )
            finally:
                Path.read_text = original

        self.assertEqual(batch.failures[0].reason_code, "RESOURCE_READ_FAILED")

    def test_collect_indirect_usage_batch_returns_resource_reference_as_concern(self):
        method = business_method("return false;")
        with tempfile.TemporaryDirectory() as tmp:
            java_root = Path(tmp) / "src/main/java"
            resource_root = Path(tmp) / "src/main/resources"
            java_root.mkdir(parents=True)
            resource_root.mkdir(parents=True)
            (resource_root / "handler.properties").write_text(
                "target=org.apache.commons.lang.StringUtils#isBlank\n",
                encoding="utf-8",
            )

            batch = collect_indirect_usage_batch(
                graph_for(method), [api_row()], [{"root": str(java_root)}]
            )

        self.assertEqual(batch.edges, ())
        self.assertEqual(batch.concerns[0].reason_code, "RESOURCE_TARGET_REFERENCE")

    def test_collect_indirect_usage_batch_covers_method_handle_expression_and_resource_per_api(self):
        method = business_method('''
            MethodHandles.lookup().findStatic(StringUtils.class, "isBlank", MethodType.methodType(boolean.class, String.class)).invokeExact(value);
            parser.parseExpression("T(org.apache.commons.lang.StringUtils).isBlank(#value)");
        ''')
        method.imports["StringUtils"] = "org.apache.commons.lang.StringUtils"

        batch = collect_indirect_usage_batch(graph_for(method), [api_row()], [])

        coverage = batch.coverage[0]
        self.assertEqual(coverage.status, "partial")
        self.assertIn("method_handle_source_partial", coverage.reason_codes)
        self.assertIn("expression_language_partial", coverage.reason_codes)
    def test_exact_reflection_chain_becomes_reachable_step5_edge(self):
        method = business_method('''
            return (Boolean) Class.forName("org.apache.commons.lang.StringUtils")
                .getMethod("isBlank", String.class)
                .invoke(null, value);
        ''')
        graph = graph_for(method)
        stats = analyze_and_merge_indirect_usages(graph, [api_row()], [])

        result = tracer.trace_api_with_confidence_weighting(
            api_row(), graph, {}, has_packaged_bytecode_fallback=False,
            has_dependency_source_mapping=True,
        )

        self.assertEqual(stats["merged_edges"], 1)
        self.assertEqual(result.analysis_status, "reachable")
        self.assertTrue(any(
            evidence["evidence_type"] == "reflection_method_invocation"
            for path in result.evidence_paths for evidence in path
        ))

    def test_large_step4_api_set_without_indirect_markers_skips_owner_scan(self):
        methods = {
            f"m{i}": business_method_with_id(
                f"m{i}",
                "int value = input.length(); return value > 0;"
            )
            for i in range(250)
        }
        graph = SimpleNamespace(
            methods_by_id=methods,
            reverse_edges={},
            lookup_keys_by_symbol={},
            type_metadata={},
            runtime_dependency_catalog={},
        )
        rows = [
            api_row_for(f"com.example.removed.Type{i // 4}", f"method{i}")
            for i in range(1200)
        ]
        original = indirect_module._owners_present_in_source_body
        calls = {"count": 0}

        def counted(*args, **kwargs):
            calls["count"] += 1
            return original(*args, **kwargs)

        indirect_module._owners_present_in_source_body = counted
        try:
            stats = analyze_and_merge_indirect_usages(graph, rows, [])
        finally:
            indirect_module._owners_present_in_source_body = original

        self.assertEqual(calls["count"], 0)
        self.assertEqual(stats["merged_edges"], 0)
        self.assertEqual(stats["source_methods_scanned"], 250)
        self.assertEqual(stats["target_count"], 1200)
        self.assertEqual(stats["potential_legacy_method_target_pairs"], 250 * 1200)
        self.assertEqual(stats["owner_presence_scans"], 0)
        self.assertIn("elapsed_sec", stats)

    def test_large_step4_api_set_with_reflection_scans_owners_once_per_method(self):
        methods = {
            "m1": business_method_with_id(
                "m1",
                '''
                Class<?> type = Class.forName("com.example.removed.Type7");
                Method target = type.getMethod("method28");
                return target.invoke(null);
                '''
            )
        }
        graph = SimpleNamespace(
            methods_by_id=methods,
            reverse_edges={},
            lookup_keys_by_symbol={},
            type_metadata={},
            runtime_dependency_catalog={},
        )
        rows = [
            api_row_for(f"com.example.removed.Type{i // 4}", f"method{i}")
            for i in range(1200)
        ]
        original = indirect_module._owners_present_in_source_body
        calls = {"count": 0}

        def counted(*args, **kwargs):
            calls["count"] += 1
            return original(*args, **kwargs)

        indirect_module._owners_present_in_source_body = counted
        try:
            stats = analyze_and_merge_indirect_usages(graph, rows, [])
        finally:
            indirect_module._owners_present_in_source_body = original

        self.assertEqual(calls["count"], 1)
        self.assertEqual(stats["merged_edges"], 1)
        self.assertEqual(stats["owner_presence_scans"], 1)
        self.assertEqual(stats["source_methods_with_indirect_markers"], 1)

    def test_local_variables_are_correlated_for_reflection(self):
        method = business_method('''
            Class<?> type = Class.forName("org.apache.commons.lang.StringUtils");
            Method target = type.getMethod("isBlank", String.class);
            return (Boolean) target.invoke(null, value);
        ''')
        graph = graph_for(method)

        stats = analyze_and_merge_indirect_usages(graph, [api_row()], [])

        self.assertEqual(stats["merged_edges"], 1)

    def test_class_utils_for_name_is_a_reflective_class_usage(self):
        method = business_method('''
            return ClassUtils.forName(
                "org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal",
                getClass().getClassLoader());
        ''')
        target = {
            "coord": "org.springframework.security:spring-security-oauth2-core",
            "api_name": "org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal",
            "api_simple": "OAuth2AuthenticatedPrincipal",
            "api_signature": "",
            "symbol_kind": "class",
            "change_type": "REMOVED",
            "analysis_scope": "class_usage",
        }
        graph = graph_for(method)

        stats = analyze_and_merge_indirect_usages(graph, [target], [])

        self.assertEqual(stats["merged_edges"], 1)
        edge = graph.reverse_edges[
            "class:org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal"
        ][0]
        self.assertEqual(edge.evidence_type, "reflection_class_lookup")

    def test_reflective_class_name_flows_through_local_wrapper_methods(self):
        methods = [
            business_method_with_params(
                "setup", "setup", {},
                'register("com.vendor.OptionalSecurityType", Object.class);',
            ),
            business_method_with_params(
                "register", "register",
                {"className": "String", "mixin": "Class"},
                "loadIfPresent(className);",
            ),
            business_method_with_params(
                "load", "loadIfPresent", {"className": "String"},
                "return ClassUtils.forName(className, getClass().getClassLoader());",
            ),
        ]
        graph = SimpleNamespace(
            methods_by_id={method.symbol_id: method for method in methods},
            reverse_edges={}, lookup_keys_by_symbol={}, type_metadata={},
            runtime_dependency_catalog={},
        )
        target = {
            "coord": "com.vendor:security-api",
            "api_name": "com.vendor.OptionalSecurityType",
            "api_simple": "OptionalSecurityType",
            "api_signature": "",
            "symbol_kind": "class",
            "change_type": "REMOVED",
            "analysis_scope": "class_usage",
        }

        stats = analyze_and_merge_indirect_usages(graph, [target], [])

        self.assertEqual(stats["merged_edges"], 1)
        edge = graph.reverse_edges["class:com.vendor.OptionalSecurityType"][0]
        self.assertEqual(edge.caller_symbol_id, "setup")
        self.assertEqual(edge.evidence_type, "reflection_class_lookup")

        graph.require_current_final_artifact_business_edges = True
        result = tracer.trace_api_with_confidence_weighting(
            target, graph, {}, has_packaged_bytecode_fallback=False,
            has_dependency_source_mapping=True,
        )
        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "REFLECTION_CLASS_LOOKUP")
        user_view = formatter.summarize_user_facing_outcome(result)
        self.assertIn("反射", user_view["user_reason"])
        self.assertNotIn("未记录", user_view["user_reason"])

    def test_dynamic_member_for_known_owner_is_uncertain_not_static_miss(self):
        method = business_method('''
            Class<?> type = Class.forName("org.apache.commons.lang.StringUtils");
            Method target = type.getMethod(methodName, String.class);
            return (Boolean) target.invoke(null, value);
        ''')
        graph = graph_for(method)
        analyze_and_merge_indirect_usages(graph, [api_row()], [])

        result = tracer.trace_api_with_confidence_weighting(
            api_row(), graph, {}, has_packaged_bytecode_fallback=False,
            has_dependency_source_mapping=True,
        )

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "REFLECTION_OVERLOAD_UNRESOLVED")

    def test_exact_resource_target_is_candidate_not_reachable(self):
        with tempfile.TemporaryDirectory() as tmp:
            java_root = Path(tmp) / "src/main/java"
            resource_root = Path(tmp) / "src/main/resources"
            java_root.mkdir(parents=True)
            resource_root.mkdir(parents=True)
            (resource_root / "handler.properties").write_text(
                "target=org.apache.commons.lang.StringUtils#isBlank\n", encoding="utf-8"
            )
            method = business_method("return false;")
            graph = graph_for(method)
            analyze_and_merge_indirect_usages(
                graph, [api_row()], [{"root": str(java_root), "owner_type": "business"}]
            )

            result = tracer.trace_api_with_confidence_weighting(
                api_row(), graph, {}, has_packaged_bytecode_fallback=False,
                has_dependency_source_mapping=True,
            )

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "RESOURCE_TARGET_REFERENCE")
        alert = formatter._alert_rows_for_result(result)[0]
        self.assertEqual(alert["coverage_status"], "complete")
        self.assertIn("资源引用", alert["coverage_details"])

    def test_partial_target_specific_coverage_blocks_static_not_found(self):
        method = business_method('''
            String owner = "org.apache.commons.lang.StringUtils";
            MethodHandles.lookup();
            return false;
        ''')
        graph = graph_for(method)
        analyze_and_merge_indirect_usages(graph, [api_row()], [])

        result = tracer.trace_api_with_confidence_weighting(
            api_row(), graph, {}, has_packaged_bytecode_fallback=False,
            has_dependency_source_mapping=True,
        )

        self.assertEqual(result.analysis_status, "not_analyzed")
        self.assertEqual(result.reason_code, "INDIRECT_ANALYSIS_INCOMPLETE")
        self.assertEqual(result.capability_coverage["status"], "partial")

    def test_unrelated_indirect_mechanisms_do_not_block_static_not_found(self):
        method = business_method('''
            Class.forName("com.example.Unrelated").getMethod("run").invoke(null);
            return false;
        ''')
        graph = graph_for(method)
        analyze_and_merge_indirect_usages(graph, [api_row()], [])

        result = tracer.trace_api_with_confidence_weighting(
            api_row(), graph, {}, has_packaged_bytecode_fallback=False,
            has_dependency_source_mapping=True,
        )

        self.assertEqual(result.analysis_status, "not_found_in_static_analysis")

    def test_javap_reflection_tracks_multiple_local_method_objects(self):
        javap = '''
  public void f();
    descriptor: ()V
    Code:
       0: ldc           #1                  // String com.example.A
       2: invokestatic  #2                  // Method java/lang/Class.forName:(Ljava/lang/String;)Ljava/lang/Class;
       5: astore_1
       6: aload_1
       7: ldc           #3                  // String x
       9: iconst_0
      10: anewarray     #4                  // class java/lang/Class
      13: invokevirtual #5                  // Method java/lang/Class.getMethod:(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
      16: astore_2
      17: ldc           #6                  // String com.example.B
      19: invokestatic  #2                  // Method java/lang/Class.forName:(Ljava/lang/String;)Ljava/lang/Class;
      22: astore_3
      23: aload_3
      24: ldc           #7                  // String y
      26: iconst_0
      27: anewarray     #4                  // class java/lang/Class
      30: invokevirtual #5                  // Method java/lang/Class.getMethod:(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
      33: astore        4
      35: aload_2
      36: aconst_null
      37: iconst_0
      38: anewarray     #8                  // class java/lang/Object
      41: invokevirtual #9                  // Method java/lang/reflect/Method.invoke:(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
'''
        references = parse_javap_indirect_references(javap)

        method_refs = [item for item in references if item["kind"] == "method"]
        class_refs = {item["owner"] for item in references if item["kind"] == "class"}
        self.assertEqual([(item["owner"], item["name"]) for item in method_refs], [("com.example.A", "x")])
        self.assertEqual(class_refs, {"com.example.A", "com.example.B"})

    def test_javap_reflection_preserves_originating_invocation_opcode_and_offset(self):
        javap = '''
  public void f();
    descriptor: ()V
    Code:
       0: ldc           #1                  // String com.example.Target
       2: invokestatic  #2                  // Method java/lang/Class.forName:(Ljava/lang/String;)Ljava/lang/Class;
       5: ldc           #3                  // String removed
       7: iconst_0
       8: anewarray     #4                  // class java/lang/Class
      11: invokevirtual #5                  // Method java/lang/Class.getMethod:(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
      14: aconst_null
      15: iconst_0
      16: anewarray     #6                  // class java/lang/Object
      19: invokevirtual #7                  // Method java/lang/reflect/Method.invoke:(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
'''

        references = parse_javap_indirect_references(javap)

        class_ref = next(item for item in references if item["kind"] == "class")
        method_ref = next(item for item in references if item["kind"] == "method")
        self.assertEqual((class_ref["opcode_family"], class_ref["instruction_offset"]), ("invokestatic", 2))
        self.assertEqual((method_ref["opcode_family"], method_ref["instruction_offset"]), ("invokevirtual", 19))

    def test_javap_class_utils_for_name_emits_reflective_class_reference(self):
        javap = '''
  private java.lang.Class<?> load(java.lang.String);
    descriptor: (Ljava/lang/String;)Ljava/lang/Class;
    Code:
       0: aload_1
       1: aload_0
       2: invokevirtual #1                  // Method java/lang/Object.getClass:()Ljava/lang/Class;
       5: invokevirtual #2                  // Method java/lang/Class.getClassLoader:()Ljava/lang/ClassLoader;
       8: invokestatic  #3                  // Method org/apache/dubbo/common/utils/ClassUtils.forName:(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/Class;
      11: areturn
'''

        references = parse_javap_indirect_references(
            javap.replace("aload_1", "ldc #4 // String com.example.DynamicTarget")
        )

        class_ref = next(item for item in references if item["kind"] == "class")
        self.assertEqual(class_ref["owner"], "com.example.DynamicTarget")
        self.assertEqual(class_ref["reference_kind"], "reflection_class")
        self.assertEqual(class_ref["instruction_offset"], 8)

    def test_javap_class_utils_does_not_reuse_a_discarded_string_constant(self):
        javap = '''
  private java.lang.Class<?> load(java.lang.String);
    descriptor: (Ljava/lang/String;)Ljava/lang/Class;
    Code:
       0: ldc           #1                  // String com.example.Unrelated
       2: pop
       3: aload_1
       4: aload_0
       5: invokevirtual #2                  // Method java/lang/Object.getClass:()Ljava/lang/Class;
       8: invokevirtual #3                  // Method java/lang/Class.getClassLoader:()Ljava/lang/ClassLoader;
      11: invokestatic  #4                  // Method org/apache/dubbo/common/utils/ClassUtils.forName:(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/Class;
      14: areturn
'''

        references = parse_javap_indirect_references(javap)

        self.assertFalse(any(item["kind"] == "class" for item in references))

    def test_incomplete_reflection_reference_cannot_emit_runtime_hit(self):
        target = api_row_for("com.example.Target", signature="()")
        references = {
            "method_refs": [{
                "owner": "com.example.Target",
                "name": "removed",
                "signature": "()",
                "signature_resolved": True,
                "reference_kind": "reflection_method",
                "consumer_method": "f",
            }],
        }

        self.assertEqual(tracer._match_runtime_dependency_references(target, references), [])

    def test_static_method_handle_is_merged_when_target_is_exact(self):
        method = business_method('''
            return (boolean) MethodHandles.lookup()
                .findStatic(StringUtils.class, "isBlank", MethodType.methodType(boolean.class, String.class))
                .invokeExact(value);
        ''')
        method.imports["StringUtils"] = "org.apache.commons.lang.StringUtils"
        graph = graph_for(method)

        stats = analyze_and_merge_indirect_usages(graph, [api_row()], [])

        self.assertEqual(stats["merged_edges"], 1)
        edge = graph.reverse_edges["org.apache.commons.lang.StringUtils.isBlank(String)"][0]
        self.assertEqual(edge.evidence_type, "method_handle_invocation")

    def test_method_handle_variable_tracks_constructor_and_field_targets(self):
        method = business_method('''
            MethodHandles.Lookup lookup = MethodHandles.lookup();
            MethodHandle constructor = lookup.findConstructor(Widget.class, MethodType.methodType(void.class, String.class));
            Object widget = constructor.invokeWithArguments(value);
            MethodHandle state = lookup.findGetter(Widget.class, "STATE", String.class);
            return state.invokeExact(widget);
        ''')
        method.imports["Widget"] = "com.vendor.Widget"
        constructor = {
            "coord": "com.vendor:widget", "api_name": "com.vendor.Widget.Widget",
            "api_simple": "Widget", "api_signature": "(String)",
            "symbol_kind": "constructor", "change_type": "REMOVED",
        }
        field = {
            "coord": "com.vendor:widget", "api_name": "com.vendor.Widget.STATE",
            "api_simple": "STATE", "api_signature": "",
            "symbol_kind": "field", "change_type": "REMOVED",
        }
        graph = graph_for(method)

        stats = analyze_and_merge_indirect_usages(graph, [constructor, field], [])

        self.assertEqual(stats["merged_edges"], 2)
        self.assertEqual(
            graph.reverse_edges["com.vendor.Widget.Widget(String)"][0].evidence_type,
            "method_handle_invocation",
        )
        self.assertEqual(
            graph.reverse_edges["com.vendor.Widget.STATE"][0].evidence_type,
            "method_handle_field_access",
        )

    def test_method_handle_find_special_is_merged_when_target_is_exact(self):
        method = business_method('''
            return (boolean) MethodHandles.lookup()
                .findSpecial(StringUtils.class, "isBlank", MethodType.methodType(boolean.class, String.class), OrderService.class)
                .invokeWithArguments(value);
        ''')
        method.imports["StringUtils"] = "org.apache.commons.lang.StringUtils"
        graph = graph_for(method)

        stats = analyze_and_merge_indirect_usages(graph, [api_row()], [])

        self.assertEqual(stats["merged_edges"], 1)
        edge = graph.reverse_edges["org.apache.commons.lang.StringUtils.isBlank(String)"][0]
        self.assertEqual(edge.evidence_type, "method_handle_invocation")

    def test_reflection_constructor_and_field_are_normalized_to_step4_targets(self):
        method = business_method('''
            Class<?> type = Class.forName("com.vendor.Widget");
            Constructor<?> constructor = type.getConstructor(String.class);
            Object widget = constructor.newInstance(value);
            Field state = type.getDeclaredField("STATE");
            return state.get(widget);
        ''')
        constructor = {
            "coord": "com.vendor:widget", "api_name": "com.vendor.Widget.Widget",
            "api_simple": "Widget", "api_signature": "(String)",
            "symbol_kind": "constructor", "change_type": "REMOVED",
        }
        field = {
            "coord": "com.vendor:widget", "api_name": "com.vendor.Widget.STATE",
            "api_simple": "STATE", "api_signature": "",
            "symbol_kind": "field", "change_type": "REMOVED",
        }
        graph = graph_for(method)

        stats = analyze_and_merge_indirect_usages(graph, [constructor, field], [])

        self.assertEqual(stats["merged_edges"], 2)
        self.assertEqual(
            graph.reverse_edges["com.vendor.Widget.Widget(String)"][0].evidence_type,
            "reflection_constructor_invocation",
        )
        self.assertEqual(
            graph.reverse_edges["com.vendor.Widget.STATE"][0].evidence_type,
            "reflection_field_access",
        )

    def test_expression_language_reference_is_uncertain_and_recorded_in_coverage(self):
        method = business_method('''
            parser.parseExpression("T(org.apache.commons.lang.StringUtils).isBlank(#value)");
            return false;
        ''')
        graph = graph_for(method)

        stats = analyze_and_merge_indirect_usages(graph, [api_row()], [])
        result = tracer.trace_api_with_confidence_weighting(
            api_row(), graph, {}, has_packaged_bytecode_fallback=False,
            has_dependency_source_mapping=True,
        )

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "EXPRESSION_TARGET_REFERENCE")
        self.assertEqual(stats["analyzers"]["expression_language"], "partial")
        self.assertEqual(stats["matrix"]["method"]["expression_language"], "partial")

    def test_expression_language_resource_ognl_style_reference_is_uncertain(self):
        with tempfile.TemporaryDirectory() as tmp:
            java_root = Path(tmp) / "src/main/java"
            resource_root = Path(tmp) / "src/main/resources"
            java_root.mkdir(parents=True)
            resource_root.mkdir(parents=True)
            (resource_root / "rules.xml").write_text(
                '<if test="@org.apache.commons.lang.StringUtils@isBlank(name)">x</if>',
                encoding="utf-8",
            )
            method = business_method("return false;")
            graph = graph_for(method)
            analyze_and_merge_indirect_usages(
                graph, [api_row()], [{"root": str(java_root), "owner_type": "business"}]
            )

            result = tracer.trace_api_with_confidence_weighting(
                api_row(), graph, {}, has_packaged_bytecode_fallback=False,
                has_dependency_source_mapping=True,
            )

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "EXPRESSION_TARGET_REFERENCE")


if __name__ == "__main__":
    unittest.main()
