import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import confidence_weighted_tracer as tracer
from enhanced_source_analyzer import MethodDef
from indirect_usage_analyzer import analyze_and_merge_indirect_usages


def contract_row(owner="com.vendor.dto.CustomerDTO", field="status"):
    return {
        "coord": "com.vendor:customer-api",
        "old_version": "1.0.0",
        "new_version": "2.0.0",
        "api_name": f"{owner}.{field}",
        "api_simple": field,
        "api_signature": "",
        "symbol_kind": "field",
        "change_type": "DATA_FIELD_ADDED",
        "severity": "P2",
        "confirmed": "true",
        "source": "classfile_contract",
        "analysis_scope": "data_contract",
    }


def method_def(*, symbol_id="load", return_type="void", param_types=None,
               annotations=None, owner_type="business", owner_coord=""):
    return MethodDef(
        symbol_id=symbol_id,
        qualified_key=f"com.acme.Job.{symbol_id}()",
        simple_key=f"method:{symbol_id}()",
        class_fqcn="com.acme.Job",
        class_name="Job",
        method_name=symbol_id,
        return_type=return_type,
        file="/project/src/main/java/com/acme/Job.java",
        line=10,
        end_line=20,
        package_name="com.acme",
        owner_type=owner_type,
        owner_coord=owner_coord,
        module="app",
        source_root="/project/src/main/java",
        language="java",
        is_test=False,
        param_types=param_types or {},
        param_declared_types=param_types or {},
        imports={"CustomerDTO": "com.vendor.dto.CustomerDTO"},
        static_imports={},
        annotations=annotations or [],
        body_text="return;",
    )


def graph_for(method):
    return SimpleNamespace(
        methods_by_id={method.symbol_id: method},
        reverse_edges={},
        lookup_keys_by_symbol={method.symbol_id: [method.qualified_key]},
        type_metadata={},
        runtime_dependency_catalog={},
    )


class DataContractTraceTest(unittest.TestCase):
    def trace(self, row, graph):
        analyze_and_merge_indirect_usages(graph, [row], [])
        return tracer.trace_api_with_confidence_weighting(
            row,
            graph,
            {},
            has_packaged_bytecode_fallback=False,
            has_dependency_source_mapping=True,
        )

    def test_exact_dto_parameter_reaches_business_runtime(self):
        row = contract_row()
        graph = graph_for(method_def(param_types={"customer": "com.vendor.dto.CustomerDTO"}))

        result = self.trace(row, graph)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertTrue(any(
            evidence.get("evidence_type") == "data_contract_owner_reachability"
            for path in result.evidence_paths
            for evidence in path
        ))

    def test_same_simple_name_from_other_package_does_not_match(self):
        row = contract_row()
        graph = graph_for(method_def(param_types={"customer": "com.other.dto.CustomerDTO"}))

        result = self.trace(row, graph)

        self.assertNotEqual(result.analysis_status, "reachable")
        self.assertNotIn(row["api_name"], graph.reverse_edges)

    def test_scheduled_dependency_method_without_artifact_activation_is_uncertain(self):
        row = contract_row()
        method = method_def(
            symbol_id="refreshCustomers",
            return_type="com.vendor.dto.CustomerDTO",
            annotations=["org.springframework.scheduling.annotation.Scheduled"],
            owner_type="dependency",
            owner_coord="com.acme:scheduled-customer-job",
        )
        graph = graph_for(method)
        analyze_and_merge_indirect_usages(graph, [row], [])
        graph.framework_runtime_entry_methods = {
            method.qualified_key.split("(", 1)[0]: [{
                "adapter": "spring_scheduled",
                "edge_kind": "spring_scheduled_entry",
                "runtime_activation": "active",
            }]
        }

        result = tracer.trace_api_with_confidence_weighting(
            row,
            graph,
            {},
            has_packaged_bytecode_fallback=False,
            has_dependency_source_mapping=True,
        )

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.reason_code, "FRAMEWORK_ACTIVATION_UNPROVEN")

    def test_current_final_artifact_type_reference_remains_authoritative(self):
        row = contract_row()
        method = method_def(param_types={"customer": "com.vendor.dto.CustomerDTO"})
        graph = graph_for(method)
        graph.require_current_final_artifact_business_edges = True
        graph.reverse_edges["com.vendor.dto.CustomerDTO"] = [SimpleNamespace(
            caller_symbol_id=method.symbol_id,
            caller_qualified_key=method.qualified_key,
            callee_key="com.vendor.dto.CustomerDTO",
            callee_simple_key="class:CustomerDTO",
            evidence_type="bytecode_class_reference",
            confidence="high",
            file="/project/target/app.jar!/com/acme/Job.class",
            line=0,
            owner_type="business",
            owner_coord="",
            module="app",
            is_test=False,
            evidence_authority="current_final_artifact",
            evidence_source="current_final_artifact",
            artifact_sha256="a" * 64,
            artifact_entry="com/acme/Job.class",
            instruction_offset=0,
            parser="classfile",
            semantic=False,
        )]

        result = self.trace(row, graph)

        self.assertEqual(result.analysis_status, "reachable")
        contract_edges = graph.reverse_edges[row["api_name"]]
        self.assertTrue(any(
            edge.evidence_type == "data_contract_owner_reachability"
            and edge.evidence_authority == "current_final_artifact"
            for edge in contract_edges
        ))

    def test_conditional_framework_callback_is_not_confirmed_reachable(self):
        row = contract_row()
        method = method_def(
            symbol_id="afterLoad",
            return_type="com.vendor.dto.CustomerDTO",
            owner_type="dependency",
            owner_coord="com.acme:conditional-extension",
        )
        graph = graph_for(method)
        analyze_and_merge_indirect_usages(graph, [row], [])
        graph.framework_entry_symbols = {method.symbol_id: [{
            "adapter": "jpa_lifecycle",
            "edge_kind": "jpa_lifecycle_callback",
            "runtime_activation": "conditional",
            "conditions": ["entity-managed"],
        }]}

        result = tracer.trace_api_with_confidence_weighting(
            row,
            graph,
            {},
            has_packaged_bytecode_fallback=False,
            has_dependency_source_mapping=True,
        )

        self.assertNotEqual(result.analysis_status, "reachable")
        self.assertEqual(result.reason_code, "FRAMEWORK_BOUNDARY")


if __name__ == "__main__":
    unittest.main()
