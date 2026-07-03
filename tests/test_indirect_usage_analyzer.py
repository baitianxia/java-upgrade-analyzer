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
from enhanced_source_analyzer import MethodDef
from indirect_usage_analyzer import analyze_and_merge_indirect_usages, parse_javap_indirect_references


def api_row():
    return {
        "coord": "commons-lang:commons-lang",
        "api_name": "org.apache.commons.lang.StringUtils.isBlank",
        "api_simple": "isBlank", "api_signature": "(String)",
        "symbol_kind": "method", "change_type": "REMOVED",
        "severity": "P0", "confirmed": "true", "source": "old_jar",
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


def graph_for(method):
    return SimpleNamespace(
        methods_by_id={method.symbol_id: method}, reverse_edges={},
        lookup_keys_by_symbol={method.symbol_id: [method.qualified_key]},
        type_metadata={}, runtime_dependency_catalog={},
    )


class IndirectUsageAnalyzerTest(unittest.TestCase):
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

    def test_local_variables_are_correlated_for_reflection(self):
        method = business_method('''
            Class<?> type = Class.forName("org.apache.commons.lang.StringUtils");
            Method target = type.getMethod("isBlank", String.class);
            return (Boolean) target.invoke(null, value);
        ''')
        graph = graph_for(method)

        stats = analyze_and_merge_indirect_usages(graph, [api_row()], [])

        self.assertEqual(stats["merged_edges"], 1)

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
        self.assertIn("resource_reference", alert["coverage_details"])

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
