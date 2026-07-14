import ast
import inspect
import sys
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from step5_evidence_model import (
    AnalysisDecision,
    EvidenceConcern,
    EvidenceFailure,
    ModuleScope,
    PreservationEvidence,
    ReachabilityPath,
    classify_module_scope,
    decide_analysis,
    decision_to_trace_patch,
)
import confidence_weighted_tracer as tracer


class EvidenceModelTest(unittest.TestCase):
    def test_module_scope_classification(self):
        cases = [
            ({"coord": "__business__"}, ModuleScope.BUSINESS_CLASSES),
            (
                {"coord": "com.example:library", "application_owned": True},
                ModuleScope.INTERNAL_MODULE,
            ),
            ({"coord": "org.example:external"}, ModuleScope.EXTERNAL_DEPENDENCY),
            ({"coord": ""}, ModuleScope.UNKNOWN),
            ({}, ModuleScope.UNKNOWN),
            (None, ModuleScope.UNKNOWN),
        ]

        for item, expected in cases:
            with self.subTest(item=item):
                self.assertEqual(classify_module_scope(item), expected)

    def test_business_coordinate_takes_precedence_over_application_owned_flag(self):
        self.assertEqual(
            classify_module_scope({"coord": "__business__", "application_owned": True}),
            ModuleScope.BUSINESS_CLASSES,
        )

    def test_complete_business_path_is_reachable(self):
        decision = decide_analysis((ReachabilityPath(
            path_text="App.run -> Library.call -> Removed.api",
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=True,
            depth=3,
        ),))

        self.assertEqual(decision.analysis_status, "reachable")
        self.assertIs(decision.is_reachable, True)
        self.assertEqual(decision.reason_code, "BUSINESS_ARTIFACT_BYTECODE_USAGE")
        self.assertEqual(decision.business_reach_depth, 3)
        self.assertEqual(decision.direct_callers, 0)

    def test_framework_activated_path_is_reachable(self):
        decision = decide_analysis((ReachabilityPath(
            path_text="Application.main -> Spring registration -> Listener.receive -> API",
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=True,
            stop_reason="RUNTIME_FRAMEWORK_ENTRY_REACHED",
            depth=4,
        ),))

        self.assertEqual(decision.analysis_status, "reachable")
        self.assertEqual(decision.reason_code, "RUNTIME_FRAMEWORK_ENTRY_REACHED")

    def test_reachable_path_can_preserve_evidence_specific_conclusion_text(self):
        decision = decide_analysis((ReachabilityPath(
            path_text="App.run -> Removed.api",
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=True,
            reason_code="SYSTEM_CODE_REACHED",
            note="触达系统代码（置信度1.00）",
            depth=1,
        ),))

        self.assertEqual(decision.analysis_status, "reachable")
        self.assertEqual(decision.reason_code, "SYSTEM_CODE_REACHED")
        self.assertEqual(decision.reachable_note, "触达系统代码（置信度1.00）")

    def test_internal_only_path_is_uncertain_not_reachable(self):
        decision = decide_analysis((ReachabilityPath(
            path_text="internal:Library.call -> Removed.api",
            entry_scope=ModuleScope.INTERNAL_MODULE,
            complete=False,
            stop_reason="BUSINESS_ENTRY_NOT_CONFIRMED",
            depth=1,
        ),))

        self.assertEqual(decision.analysis_status, "uncertain")
        self.assertIsNone(decision.is_reachable)
        self.assertEqual(decision.reason_code, "PACKAGED_DEPENDENCY_BYTECODE_USAGE")

    def test_ambiguous_path_never_becomes_reachable(self):
        decision = decide_analysis((ReachabilityPath(
            path_text="App.run -> Candidate.overload",
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=True,
            ambiguous=True,
            depth=2,
        ),))

        self.assertEqual(decision.analysis_status, "uncertain")
        self.assertIsNone(decision.is_reachable)
        self.assertEqual(decision.reason_code, "UNQUALIFIED_SIGNATURE_TYPE_AMBIGUOUS")
        self.assertEqual(decision.direct_callers, 0)
        self.assertEqual(decision.business_reach_depth, 0)

    def test_truncated_business_candidate_does_not_count_as_confirmed_usage(self):
        decision = decide_analysis((ReachabilityPath(
            path_text="App.run -> ... -> Removed.api",
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=False,
            truncated=True,
            stop_reason="MAX_DEPTH_REACHED",
            depth=1,
        ),))

        self.assertEqual(decision.direct_callers, 0)
        self.assertEqual(decision.business_reach_depth, 0)

    def test_specific_packaged_risk_wins_regardless_of_path_order(self):
        internal = ReachabilityPath(
            path_text="Internal.bridge -> Removed.api",
            entry_scope=ModuleScope.INTERNAL_MODULE,
            complete=False,
        )
        external = ReachabilityPath(
            path_text="External.call -> Removed.api",
            entry_scope=ModuleScope.EXTERNAL_DEPENDENCY,
            complete=False,
            reason_code="RUNTIME_DEPENDENCY_USES_REMOVED_API",
            note="linkage risk",
        )

        for paths in ((internal, external), (external, internal)):
            with self.subTest(paths=paths):
                decision = decide_analysis(paths)
                self.assertEqual(
                    decision.reason_code, "RUNTIME_DEPENDENCY_USES_REMOVED_API"
                )
                self.assertEqual(decision.reachable_note, "linkage risk")

    def test_blocking_failure_prevents_a_negative_conclusion(self):
        decision = decide_analysis((), failures=(EvidenceFailure(
            stage="javap",
            reason_code="BYTECODE_PARSE_FAILED",
            blocking=True,
            artifact="broken.jar",
        ),), complete_scan=True)

        self.assertEqual(decision.analysis_status, "not_analyzed")
        self.assertIsNone(decision.is_reachable)
        self.assertEqual(decision.reason_code, "BYTECODE_PARSE_FAILED")

    def test_uncertain_concern_is_decided_by_policy(self):
        decision = decide_analysis((), concerns=(EvidenceConcern(
            stage="source-artifact-reconciliation",
            reason_code="SOURCE_BYTECODE_EDGE_CONFLICT",
            detail="源码调用与最终制品字节码不一致",
        ),))

        self.assertEqual(decision.analysis_status, "uncertain")
        self.assertIsNone(decision.is_reachable)
        self.assertEqual(decision.reason_code, "SOURCE_BYTECODE_EDGE_CONFLICT")
        self.assertEqual(decision.reachable_note, "源码调用与最终制品字节码不一致")

    def test_truncated_path_is_not_analyzed_instead_of_uncertain(self):
        decision = decide_analysis((ReachabilityPath(
            path_text="App.run -> ... -> Removed.api",
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=False,
            truncated=True,
            stop_reason="MAX_DEPTH_REACHED",
        ),), complete_scan=True)

        self.assertEqual(decision.analysis_status, "not_analyzed")
        self.assertIsNone(decision.is_reachable)
        self.assertEqual(decision.reason_code, "MAX_DEPTH_REACHED")

    def test_complete_scan_without_paths_is_a_static_miss(self):
        decision = decide_analysis((), complete_scan=True)

        self.assertEqual(decision.analysis_status, "not_found_in_static_analysis")
        self.assertIs(decision.is_reachable, False)
        self.assertEqual(decision.reason_code, "NO_STATIC_PATH")

    def test_preserved_api_is_not_impacted(self):
        decision = decide_analysis((), preserved=True)

        self.assertEqual(decision.analysis_status, "not_impacted")
        self.assertIs(decision.is_reachable, False)
        self.assertEqual(decision.reason_code, "API_PRESERVED")

    def test_preservation_evidence_keeps_exact_runtime_reason(self):
        decision = decide_analysis((), preservation=PreservationEvidence(
            reason_code="RUNTIME_SYMBOL_PRESERVED_IDENTICALLY",
            detail="当前制品仍提供字节码完全一致的目标 class",
        ))

        self.assertEqual(decision.analysis_status, "not_impacted")
        self.assertIs(decision.is_reachable, False)
        self.assertEqual(decision.reason_code, "RUNTIME_SYMBOL_PRESERVED_IDENTICALLY")
        self.assertEqual(decision.reachable_note, "当前制品仍提供字节码完全一致的目标 class")

    def test_non_blocking_failure_does_not_override_complete_positive_evidence(self):
        path = ReachabilityPath(
            path_text="App.run -> Removed.api",
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=True,
            depth=1,
        )
        failure = EvidenceFailure(
            stage="optional-source-enrichment",
            reason_code="SOURCE_NOT_AVAILABLE",
            blocking=False,
        )

        decision = decide_analysis((path,), failures=(failure,))

        self.assertEqual(decision.analysis_status, "reachable")
        self.assertEqual(decision.direct_callers, 1)

    def test_decision_patch_is_schema_compatible(self):
        decision = decide_analysis((ReachabilityPath(
            path_text="App.run -> Removed.api",
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=True,
            depth=1,
        ),))

        patch = decision_to_trace_patch(decision)

        self.assertEqual(set(patch), {
            "analysis_status", "is_reachable", "reason_code", "reachable_note",
            "direct_callers", "business_reach_depth",
        })
        self.assertEqual(patch["analysis_status"], "reachable")

    def test_packaged_result_conclusion_comes_from_evidence_policy(self):
        result = tracer.TraceResult(
            api_name="com.vendor.Legacy.removed",
            api_simple="removed",
            api_signature="()",
            symbol_kind="method",
            change_type="REMOVED",
            coord="com.vendor:legacy",
            severity="P0",
            confirmed=True,
            source="fixture",
            analysis_scope="api",
            analysis_status="not_analyzed",
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
            confidence_score=1.0,
            critical_nodes_hit=[],
        )
        hit = {
            "coord": "__business__",
            "jar_path": "/artifact/application.jar",
            "class_fqcn": "com.acme.Application",
            "consumer_method": "run",
            "consumer_signature": "()",
            "target_display": "com.vendor.Legacy.removed()",
            "evidence_type": "bytecode_method_invocation",
        }
        policy_decision = AnalysisDecision(
            analysis_status="policy_status",
            is_reachable=None,
            reason_code="POLICY_REASON",
            reachable_note="policy note",
            direct_callers=7,
            business_reach_depth=9,
        )

        with patch.object(tracer, "decide_analysis", return_value=policy_decision) as decide:
            built = tracer._build_packaged_dependency_hit_result(result, [hit])

        decide.assert_called_once()
        self.assertEqual(built.analysis_status, "policy_status")
        self.assertIsNone(built.is_reachable)
        self.assertEqual(built.reason_code, "POLICY_REASON")
        self.assertEqual(built.reachable_note, "policy note")
        self.assertEqual(built.direct_callers, 7)
        self.assertEqual(built.business_reach_depth, 9)

    def test_packaged_result_builder_has_no_direct_conclusion_assignments(self):
        tree = ast.parse(textwrap.dedent(inspect.getsource(
            tracer._build_packaged_dependency_hit_result
        )))
        protected_fields = {"analysis_status", "is_reachable", "reason_code"}
        assignments = []
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            elif isinstance(node, ast.AugAssign):
                targets = [node.target]
            for target in targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "result"
                    and target.attr in protected_fields
                ):
                    assignments.append(target.attr)

        self.assertEqual(assignments, [])

    def test_trace_result_conclusions_have_one_policy_write_boundary(self):
        source_path = Path(inspect.getsourcefile(tracer))
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        protected_fields = {
            "analysis_status", "is_reachable", "reason_code", "reachable_note",
            "direct_callers", "business_reach_depth",
        }
        violations = []
        for function in (
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            if function.name == "_apply_evidence_decision":
                continue
            for node in ast.walk(function):
                targets = []
                if isinstance(node, ast.Assign):
                    targets = node.targets
                elif isinstance(node, ast.AnnAssign):
                    targets = [node.target]
                elif isinstance(node, ast.AugAssign):
                    targets = [node.target]
                for target in targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and target.attr in protected_fields
                    ):
                        violations.append((function.name, target.attr, node.lineno))

                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "setattr"
                    and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value in protected_fields
                ):
                    violations.append((function.name, node.args[1].value, node.lineno))

            for node in ast.walk(function):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "TraceResult"
                ):
                    continue
                status = next(
                    (keyword.value for keyword in node.keywords if keyword.arg == "analysis_status"),
                    None,
                )
                if not (
                    isinstance(status, ast.Constant)
                    and status.value == "pending"
                ):
                    violations.append((function.name, "TraceResult.analysis_status", node.lineno))

        self.assertEqual(violations, [])

    def test_policy_write_boundary_applies_only_policy_patch_fields(self):
        result = tracer.TraceResult(
            api_name="A.m", api_simple="m", api_signature="()",
            symbol_kind="method", change_type="REMOVED", coord="g:a",
            severity="P1", confirmed=True, source="fixture", analysis_scope="api",
            analysis_status="pending", direct_callers=0, is_reachable=None,
            reachable_note="", business_reach_depth=0, dependency_chain_coords=[],
            call_paths=[], evidence_paths=[], reason_code="", verification_commands=[],
            hops=[], confidence_score=1.0, critical_nodes_hit=[],
        )
        policy_decision = AnalysisDecision(
            analysis_status="policy_status", is_reachable=None,
            reason_code="POLICY_REASON", reachable_note="policy note",
            direct_callers=3, business_reach_depth=4,
        )

        with patch.object(tracer, "decide_analysis", return_value=policy_decision) as decide:
            tracer._apply_evidence_decision(result, complete_scan=True)

        decide.assert_called_once()
        self.assertEqual(result.analysis_status, "policy_status")
        self.assertEqual(result.reason_code, "POLICY_REASON")
        self.assertEqual(result.direct_callers, 3)

    def test_source_artifact_downgrade_preserves_direct_usage_metrics_without_details(self):
        result = tracer.TraceResult(
            api_name="A.FIELD", api_simple="FIELD", api_signature="",
            symbol_kind="field", change_type="REMOVED", coord="g:a",
            severity="P1", confirmed=True, source="fixture", analysis_scope="api",
            analysis_status="reachable", direct_callers=1, is_reachable=True,
            reachable_note="direct", business_reach_depth=1,
            dependency_chain_coords=[], call_paths=["App.run -> A.FIELD"],
            evidence_paths=[[]], reason_code="DIRECT_FIELD_USAGE",
            verification_commands=[], hops=[], confidence_score=1.0,
            critical_nodes_hit=[], path_details=[],
        )
        graph = type("Graph", (), {
            "source_artifact_alignment": {"status": "conflict"},
        })()

        tracer._apply_source_artifact_miss(result, graph, "源码与制品冲突")

        self.assertEqual(result.analysis_status, "uncertain")
        self.assertEqual(result.direct_callers, 1)
        self.assertEqual(result.business_reach_depth, 1)

    def test_registered_business_callback_keeps_framework_activation_path(self):
        result = tracer.TraceResult(
            api_name="java.util.concurrent.CountDownLatch.countDown",
            api_simple="countDown",
            api_signature="()",
            symbol_kind="method",
            change_type="REMOVED",
            coord="jdk:java.base",
            severity="P1",
            confirmed=True,
            source="fixture",
            analysis_scope="api",
            analysis_status="not_analyzed",
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
            confidence_score=1.0,
            critical_nodes_hit=[],
        )
        hit = {
            "coord": "__business__",
            "jar_path": "/artifact/application.jar",
            "class_fqcn": "com.example.Receiver",
            "consumer_method": "receiveMessage",
            "consumer_signature": "(String)",
            "target_display": "java.util.concurrent.CountDownLatch.countDown()",
            "evidence_type": "bytecode_method_invocation",
        }
        graph = type("Graph", (), {})()
        graph.framework_runtime_entry_methods = {
            "com.example.Receiver.receiveMessage": [{
                "adapter": "spring_runtime_artifact",
                "source": "framework:spring-amqp-message-listener-adapter",
                "edge_kind": "spring_runtime_registered_callback",
                "runtime_activation": "active",
                "confidence": "high",
                "provenance": {
                    "coord": "__business__",
                    "jar": "/artifact/application.jar",
                    "line": 7,
                    "business_activation": [{
                        "business_entry": "com.example.Application.main",
                        "spring_application_run": True,
                    }],
                },
            }],
        }

        built = tracer._build_packaged_dependency_hit_result(result, [hit], graph)

        self.assertEqual(built.analysis_status, "reachable")
        self.assertEqual(built.reason_code, "RUNTIME_FRAMEWORK_ENTRY_REACHED")
        self.assertTrue(any(
            "com.example.Application.main -> Spring Boot框架注册" in path
            and "com.example.Receiver.receiveMessage(String)" in path
            for path in built.call_paths
        ))


if __name__ == "__main__":
    unittest.main()
