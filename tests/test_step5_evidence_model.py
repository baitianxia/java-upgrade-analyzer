import ast
import inspect
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from step5_evidence_model import (
    ActivationEvidence,
    AnalysisDecision,
    AnalysisOutcome,
    CollectedEdge,
    CollectorBatch,
    CoverageRecord,
    EvidenceAuthority,
    EvidenceConcern,
    EvidenceEnvelope,
    EvidenceFailure,
    EvidenceProvenance,
    ModuleScope,
    PhysicalCallEdge,
    PreservationEvidence,
    ReachabilityPath,
    TraceSeed,
    classify_module_scope,
    decide_analysis,
    decide_envelope,
    freeze_evidence_value,
)
import confidence_weighted_tracer as tracer
import enhanced_output_formatter as formatter


class EvidenceModelTest(unittest.TestCase):
    def _draft_from_result(self, result):
        values = {
            name: getattr(result, name)
            for name in tracer.TraceDraft.__dataclass_fields__
            if hasattr(result, name)
        }
        return tracer.TraceDraft(**values)

    def _final_artifact_edge(
        self, *, semantic=False, authority=None, activation_verified=False
    ):
        return CollectedEdge(
            caller_symbol="com.acme.Application.run()",
            callee_symbol="com.vendor.Legacy.call()",
            edge_kind=(
                "framework_proxy_dispatch" if semantic
                else "bytecode_method_invocation"
            ),
            semantic=semantic,
            activation_verified=activation_verified,
            activation_evidence=((ActivationEvidence(
                authority=EvidenceAuthority.RUNTIME_OBSERVATION,
                proof_kind="business_entry_activation",
                source="application.jar!/Application.class#main",
                artifact_sha256="a" * 64,
            ),) if activation_verified else ()),
            owner_scope=ModuleScope.BUSINESS_CLASSES,
            provenance=EvidenceProvenance(
                authority=authority or (
                    EvidenceAuthority.FRAMEWORK_SEMANTIC
                    if semantic else EvidenceAuthority.CURRENT_FINAL_ARTIFACT
                ),
                artifact_path="/artifact/application.jar",
                artifact_sha256="a" * 64,
                artifact_entry="BOOT-INF/classes/com/acme/Application.class",
                parser="classfile",
            ),
        )

    def test_high_volume_evidence_records_use_compact_slots(self):
        edge = self._final_artifact_edge()
        failure = EvidenceFailure(
            stage="ingestion",
            reason_code="BYTECODE_CALLER_UNRESOLVED",
            blocking=True,
        )
        batch = CollectorBatch(
            collector="business_bytecode",
            version="1",
            edges=(edge,),
            failures=(failure,),
        )

        self.assertFalse(hasattr(edge, "__dict__"))
        self.assertFalse(hasattr(edge.provenance, "__dict__"))
        self.assertFalse(hasattr(failure, "__dict__"))
        self.assertEqual(
            batch.to_mapping()["failures"][0]["reason_code"],
            "BYTECODE_CALLER_UNRESOLVED",
        )

    def test_collector_batch_requires_identity_and_valid_sha(self):
        with self.assertRaisesRegex(ValueError, "collector identity"):
            CollectorBatch(collector="", version="1")

        with self.assertRaisesRegex(ValueError, "SHA-256"):
            EvidenceProvenance(
                authority=EvidenceAuthority.CURRENT_FINAL_ARTIFACT,
                artifact_sha256="bad",
            )

    def test_semantic_edge_cannot_claim_physical_bytecode_authority(self):
        with self.assertRaisesRegex(ValueError, "semantic edge authority"):
            self._final_artifact_edge(
                semantic=True,
                authority=EvidenceAuthority.CURRENT_FINAL_ARTIFACT,
            )

    def test_semantic_indirect_inference_has_its_own_authority(self):
        edge = self._final_artifact_edge(
            semantic=True,
            authority=EvidenceAuthority.SOURCE_INDIRECT_INFERENCE,
        )

        self.assertEqual(
            edge.provenance.authority,
            EvidenceAuthority.SOURCE_INDIRECT_INFERENCE,
        )

    def test_collected_activation_proof_is_typed_and_serialized(self):
        edge = self._final_artifact_edge(
            semantic=True,
            authority=EvidenceAuthority.SOURCE_INDIRECT_INFERENCE,
            activation_verified=True,
        )

        mapping = CollectorBatch(
            collector="indirect_usage",
            version="1",
            edges=(edge,),
        ).to_mapping()

        self.assertTrue(mapping["edges"][0]["activation_verified"])
        self.assertEqual(
            mapping["edges"][0]["activation_evidence"][0]["proof_kind"],
            "business_entry_activation",
        )
        with self.assertRaisesRegex(ValueError, "only valid for semantic edges"):
            self._final_artifact_edge(activation_verified=True)

    def test_activation_boolean_without_typed_proof_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "typed activation evidence"):
            PhysicalCallEdge(
                caller_symbol="Application.main",
                callee_key="Listener.receive",
                evidence_type="spring_callback",
                semantic=True,
                activation_verified=True,
            )

    def test_collector_batch_serialization_is_deterministic(self):
        batch = CollectorBatch(
            collector="business_bytecode",
            version="1",
            edges=(self._final_artifact_edge(),),
            coverage=(CoverageRecord(
                collector="business_bytecode",
                api_identity="com.vendor.Legacy.call()",
                status="complete",
            ),),
            metrics=(("visited_classes", 3),),
        )

        first = batch.to_mapping()
        second = batch.to_mapping()

        self.assertEqual(first, second)
        self.assertEqual(first["collector"], "business_bytecode")
        self.assertEqual(first["edges"][0]["provenance"]["artifact_sha256"], "a" * 64)

    def test_coverage_scope_is_validated_and_serialized(self):
        coverage = CoverageRecord(
            collector="spring_basic",
            api_identity="spring_basic",
            status="partial",
            scope="path",
        )
        batch = CollectorBatch(
            collector="spring_basic",
            version="1",
            coverage=(coverage,),
        )

        self.assertEqual(batch.to_mapping()["coverage"][0]["scope"], "path")
        with self.assertRaisesRegex(ValueError, "unsupported coverage scope"):
            CoverageRecord(
                collector="spring_basic",
                api_identity="spring_basic",
                status="partial",
                scope="unknown",
            )

    def test_observed_target_concern_precedes_partial_coverage_gap(self):
        target = "com.vendor.Legacy.call()"
        decision = decide_envelope(EvidenceEnvelope(
            target_identity=target,
            concerns=(EvidenceConcern(
                stage="indirect-usage-analysis",
                reason_code="REFLECTION_OVERLOAD_UNRESOLVED",
                api_identity=target,
                detail="dynamic member name",
            ),),
            coverage=(CoverageRecord(
                collector="indirect_usage:reflection_source",
                api_identity=target,
                status="partial",
                reason_codes=("reflection_source_partial",),
            ),),
        ))

        self.assertEqual(decision.analysis_status, "uncertain")
        self.assertEqual(decision.reason_code, "REFLECTION_OVERLOAD_UNRESOLVED")

    def test_input_validation_failure_precedes_collector_failure_regardless_of_order(self):
        collector_failure = EvidenceFailure(
            stage="business-bytecode",
            reason_code="CURRENT_FINAL_ARTIFACT_REQUIRED",
            blocking=True,
        )
        input_failure = EvidenceFailure(
            stage="input-validation",
            reason_code="MISSING_API_SIGNATURE",
            blocking=True,
        )
        for failures in (
            (collector_failure, input_failure),
            (input_failure, collector_failure),
        ):
            with self.subTest(order=[item.stage for item in failures]):
                decision = decide_analysis((), failures)
                self.assertEqual(decision.analysis_status, "not_analyzed")
                self.assertEqual(decision.reason_code, "MISSING_API_SIGNATURE")

    def test_input_validation_failure_precedes_positive_evidence(self):
        failure = EvidenceFailure(
            stage="input-validation",
            reason_code="MISSING_API_SIGNATURE",
            blocking=True,
        )
        path = ReachabilityPath(
            path_text="Application.run -> Legacy.call",
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=True,
        )
        preservation = PreservationEvidence(
            reason_code="API_PRESERVED",
            detail="symbol still exists",
        )
        for kwargs in ({"paths": (path,)}, {"preservation": preservation}):
            with self.subTest(evidence=next(iter(kwargs))):
                decision = decide_analysis(
                    kwargs.get("paths", ()),
                    failures=(failure,),
                    preservation=kwargs.get("preservation"),
                )
                self.assertEqual(decision.analysis_status, "not_analyzed")
                self.assertEqual(decision.reason_code, "MISSING_API_SIGNATURE")

    def test_collector_failure_does_not_erase_independent_reachable_path(self):
        decision = decide_analysis(
            (ReachabilityPath(
                path_text="Application.run -> Legacy.call",
                entry_scope=ModuleScope.BUSINESS_CLASSES,
                complete=True,
            ),),
            failures=(EvidenceFailure(
                stage="business-bytecode",
                reason_code="CURRENT_FINAL_ARTIFACT_REQUIRED",
                blocking=True,
            ),),
        )

        self.assertEqual(decision.analysis_status, "reachable")
        self.assertEqual(decision.reason_code, "BUSINESS_ARTIFACT_BYTECODE_USAGE")

    def test_collector_failure_does_not_erase_independent_uncertain_semantic_path(self):
        decision = decide_analysis(
            (ReachabilityPath(
                path_text="Module.setup -> Class.forName -> RemovedType",
                entry_scope=ModuleScope.BUSINESS_CLASSES,
                complete=True,
                depth=1,
                evidence=(PhysicalCallEdge(
                    caller_symbol="Module.setup",
                    callee_key="RemovedType",
                    evidence_type="reflection_class_lookup",
                    owner_scope=ModuleScope.BUSINESS_CLASSES,
                    semantic=True,
                    activation_verified=False,
                ),),
            ),),
            failures=(EvidenceFailure(
                stage="analyzer-edge-collection",
                reason_code="PRESERVATION_MANIFEST_UNREADABLE",
                blocking=True,
            ),),
        )

        self.assertEqual(decision.analysis_status, "uncertain")
        self.assertEqual(decision.reason_code, "FRAMEWORK_ACTIVATION_UNPROVEN")

    def test_collector_failure_blocks_nonsemantic_dependency_path(self):
        decision = decide_analysis(
            (ReachabilityPath(
                path_text="runtime.jar:Adapter.call -> RemovedApi.call",
                entry_scope=ModuleScope.EXTERNAL_DEPENDENCY,
                complete=False,
                depth=1,
                evidence=(PhysicalCallEdge(
                    caller_symbol="Adapter.call",
                    callee_key="RemovedApi.call",
                    evidence_type="bytecode_method_invocation",
                    owner_scope=ModuleScope.EXTERNAL_DEPENDENCY,
                ),),
            ),),
            failures=(EvidenceFailure(
                stage="analyzer-edge-collection",
                reason_code="FINAL_ARTIFACT_PROVENANCE_UNREADABLE",
                blocking=True,
            ),),
        )

        self.assertEqual(decision.analysis_status, "not_analyzed")
        self.assertEqual(
            decision.reason_code, "FINAL_ARTIFACT_PROVENANCE_UNREADABLE"
        )

    def test_boundary_failure_blocks_the_incomplete_path_that_created_it(self):
        decision = decide_analysis(
            (ReachabilityPath(
                path_text="OptionalCallback.call -> RemovedApi.call",
                entry_scope=ModuleScope.EXTERNAL_DEPENDENCY,
                complete=False,
                stop_reason="FRAMEWORK_BOUNDARY",
                reason_code="FRAMEWORK_BOUNDARY",
            ),),
            failures=(EvidenceFailure(
                stage="call-graph-boundary",
                reason_code="FRAMEWORK_BOUNDARY",
                blocking=True,
            ),),
        )

        self.assertEqual(decision.analysis_status, "not_analyzed")
        self.assertEqual(decision.reason_code, "FRAMEWORK_BOUNDARY")

    def test_unrelated_concern_does_not_override_partial_target_coverage(self):
        target = "com.vendor.Legacy.call()"
        coverage = (CoverageRecord(
            collector="business_bytecode",
            api_identity=target,
            status="partial",
            reason_codes=("BYTECODE_CALLER_UNRESOLVED",),
        ),)
        for concern_identity in ("", "com.other.Api.call()"):
            with self.subTest(concern_identity=concern_identity):
                decision = decide_envelope(EvidenceEnvelope(
                    target_identity=target,
                    concerns=(EvidenceConcern(
                        stage="source-analysis",
                        reason_code="UNRELATED_CONCERN",
                        api_identity=concern_identity,
                        detail="unrelated",
                    ),),
                    coverage=coverage,
                ))
                self.assertEqual(decision.analysis_status, "not_analyzed")
                self.assertEqual(decision.reason_code, "INCOMPLETE_EVIDENCE_COVERAGE")

    def test_concern_selection_is_deterministic(self):
        concerns = (
            EvidenceConcern(stage="z-stage", reason_code="Z_REASON", detail="z"),
            EvidenceConcern(stage="a-stage", reason_code="A_REASON", detail="a"),
        )
        decisions = [
            decide_analysis((), concerns=ordered)
            for ordered in (concerns, tuple(reversed(concerns)))
        ]

        self.assertEqual([item.reason_code for item in decisions], ["A_REASON", "A_REASON"])

    def test_typed_evidence_recursively_copies_mutable_input_containers(self):
        edge = self._final_artifact_edge()
        reason_codes = ["partial-scan"]
        edges = [edge]
        nested_metadata = {"locations": [{"offset": 7}]}
        coverage = CoverageRecord(
            collector="business_bytecode",
            api_identity="com.vendor.Legacy.call()",
            status="partial",
            reason_codes=reason_codes,
        )
        physical = tracer.PhysicalCallEdge(
            caller_symbol="com.acme.Application.run()",
            callee_key="com.vendor.Legacy.call()",
            evidence_type="bytecode_method_invocation",
            metadata=(("details", nested_metadata),),
        )
        path_evidence = [physical]
        path = ReachabilityPath(
            path_text="Application.run -> Legacy.call",
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=True,
            evidence=path_evidence,
        )
        paths = [path]
        batch = CollectorBatch(
            collector="business_bytecode",
            version="1",
            edges=edges,
            coverage=[coverage],
        )
        envelope = EvidenceEnvelope(
            target_identity="com.vendor.Legacy.call()",
            paths=paths,
            coverage=[coverage],
        )

        reason_codes.append("mutated")
        edges.clear()
        nested_metadata["locations"][0]["offset"] = 99
        path_evidence.clear()
        paths.clear()

        self.assertEqual(coverage.reason_codes, ("partial-scan",))
        self.assertEqual(batch.edges, (edge,))
        self.assertEqual(len(batch.coverage), 1)
        self.assertEqual(len(envelope.paths), 1)
        self.assertEqual(len(envelope.coverage), 1)
        self.assertEqual(len(path.evidence), 1)
        self.assertEqual(
            physical.metadata[0][1]["locations"][0]["offset"],
            7,
        )

        with self.assertRaises((AttributeError, TypeError)):
            batch.edges.clear()
        with self.assertRaises((AttributeError, TypeError)):
            coverage.reason_codes.append("mutated-again")
        with self.assertRaises((AttributeError, TypeError)):
            physical.metadata[0][1]["locations"][0]["offset"] = 100

    def test_coverage_rejects_non_string_reason_codes(self):
        with self.assertRaisesRegex(ValueError, "reason codes"):
            CoverageRecord(
                collector="business_bytecode",
                api_identity="com.vendor.Legacy.call()",
                status="partial",
                reason_codes=({"nested": ["mutable"]},),
            )

    def test_evidence_envelope_rejects_untyped_members(self):
        invalid_values = {
            "paths": ({"path_text": "forged"},),
            "failures": ({"reason_code": "forged"},),
            "concerns": ({"reason_code": "forged"},),
            "coverage": ({"status": "complete"},),
            "preservation": {"reason_code": "forged"},
        }
        for field_name, value in invalid_values.items():
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(ValueError, field_name):
                    EvidenceEnvelope(
                        target_identity="com.vendor.Legacy.call()",
                        **{field_name: value},
                    )

    def test_incomplete_applicable_coverage_blocks_static_miss(self):
        envelope = EvidenceEnvelope(
            target_identity="com.vendor.Legacy.call()",
            coverage=(CoverageRecord(
                collector="framework_adapters",
                api_identity="com.vendor.Legacy.call()",
                status="partial",
                reason_codes=("framework_scan_incomplete",),
            ),),
        )

        decision = decide_envelope(envelope)

        self.assertEqual(decision.analysis_status, "not_analyzed")
        self.assertEqual(decision.reason_code, "INCOMPLETE_EVIDENCE_COVERAGE")

    def test_module_scope_classification(self):
        cases = [
            ({"coord": "__business__"}, ModuleScope.BUSINESS_CLASSES),
            (
                {
                    "coord": "com.example:library",
                    "application_owned": True,
                    "ownership_evidence": {
                        "authority": "reactor_coordinate_and_final_artifact_entry",
                        "reactor_coord": "com.example:library",
                        "artifact_entry": "BOOT-INF/lib/library.jar",
                        "final_artifact_sha256": "a" * 64,
                    },
                },
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
            evidence=(PhysicalCallEdge(
                caller_symbol="Application.main",
                callee_key="Listener.receive",
                evidence_type="spring_runtime_registered_callback",
                owner_scope=ModuleScope.BUSINESS_CLASSES,
                semantic=True,
                activation_verified=True,
                activation_evidence=(ActivationEvidence(
                    authority=EvidenceAuthority.CURRENT_FINAL_ARTIFACT,
                    proof_kind="packaged_business_entry",
                    source="application.jar!/Application.class#main",
                    artifact_sha256="a" * 64,
                ),),
            ),),
        ),))

        self.assertEqual(decision.analysis_status, "reachable")
        self.assertEqual(decision.reason_code, "RUNTIME_FRAMEWORK_ENTRY_REACHED")

    def test_framework_label_without_typed_activation_proof_is_uncertain(self):
        decision = decide_analysis((ReachabilityPath(
            path_text="Application.main -> Spring registration -> Listener.receive -> API",
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=True,
            stop_reason="RUNTIME_FRAMEWORK_ENTRY_REACHED",
            depth=4,
        ),))

        self.assertEqual(decision.analysis_status, "uncertain")
        self.assertEqual(decision.reason_code, "FRAMEWORK_ACTIVATION_UNPROVEN")

    def test_framework_evidence_state_transitions_are_explicit(self):
        target = "com.vendor.Legacy.call()"
        coverage = (CoverageRecord(
            collector="framework",
            api_identity=target,
            status="complete",
        ),)
        absent = decide_envelope(EvidenceEnvelope(
            target_identity=target,
            coverage=coverage,
        ))
        candidate = decide_envelope(EvidenceEnvelope(
            target_identity=target,
            coverage=coverage,
            paths=(ReachabilityPath(
                path_text="Application.main -> callback -> API",
                entry_scope=ModuleScope.BUSINESS_CLASSES,
                complete=True,
                evidence=(PhysicalCallEdge(
                    caller_symbol="Application.main",
                    callee_key="Listener.receive",
                    evidence_type="spring_callback",
                    semantic=True,
                ),),
            ),),
        ))
        activated = decide_envelope(EvidenceEnvelope(
            target_identity=target,
            coverage=coverage,
            paths=(ReachabilityPath(
                path_text="Application.main -> callback -> API",
                entry_scope=ModuleScope.BUSINESS_CLASSES,
                complete=True,
                evidence=(PhysicalCallEdge(
                    caller_symbol="Application.main",
                    callee_key="Listener.receive",
                    evidence_type="spring_callback",
                    semantic=True,
                    activation_verified=True,
                    activation_evidence=(ActivationEvidence(
                        authority=EvidenceAuthority.CURRENT_FINAL_ARTIFACT,
                        proof_kind="packaged_business_entry",
                        source="application.jar!/Application.class#main",
                        artifact_sha256="a" * 64,
                    ),),
                ),),
            ),),
        ))

        self.assertEqual(
            [absent.analysis_status, candidate.analysis_status, activated.analysis_status],
            ["not_found_in_static_analysis", "uncertain", "reachable"],
        )

    def test_semantic_edge_without_independent_activation_is_uncertain(self):
        decision = decide_analysis((ReachabilityPath(
            path_text="Service.call -> Mapper.proxy -> API",
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=True,
            depth=3,
            evidence=(PhysicalCallEdge(
                caller_symbol="Service.call",
                callee_key="Mapper.proxy",
                evidence_type="mybatis_mapper_proxy",
                owner_scope=ModuleScope.BUSINESS_CLASSES,
                semantic=True,
                activation_verified=False,
            ),),
        ),))

        self.assertEqual(decision.analysis_status, "uncertain")
        self.assertEqual(decision.reason_code, "FRAMEWORK_ACTIVATION_UNPROVEN")

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

    def test_envelope_with_only_not_applicable_coverage_is_not_analyzed(self):
        decision = decide_envelope(EvidenceEnvelope(
            target_identity="com.vendor.Legacy.call()",
            coverage=(CoverageRecord(
                collector="spring_runtime_artifact",
                api_identity="com.vendor.Legacy.call()",
                status="not_applicable",
                applicable=False,
            ),),
        ))

        self.assertEqual(decision.analysis_status, "not_analyzed")
        self.assertEqual(decision.reason_code, "INCOMPLETE_EVIDENCE")

    def test_not_applicable_coverage_is_structurally_non_applicable(self):
        coverage = CoverageRecord(
            collector="spring_runtime_artifact",
            api_identity="com.vendor.Legacy.call()",
            status="not_applicable",
        )

        self.assertFalse(coverage.applicable)

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

    def test_terminal_renderer_preserves_trace_result_contract(self):
        seed = TraceSeed(
            api_name="com.vendor.Legacy.removed",
            api_simple="removed",
            api_signature="(String)",
            symbol_kind="method",
            change_type="REMOVED",
            coord="com.vendor:legacy",
            severity="P0",
            confirmed=True,
            source="fixture",
            analysis_scope="api",
            old_version="1.0",
            new_version="2.0",
        )
        outcome = AnalysisOutcome(
            decision=AnalysisDecision(
                analysis_status="reachable",
                is_reachable=True,
                reason_code="BUSINESS_ARTIFACT_BYTECODE_USAGE",
                reachable_note="final artifact proves the path",
                direct_callers=1,
                business_reach_depth=2,
            ),
            dependency_chain_coords=("com.acme:application", "com.vendor:legacy"),
            call_paths=("Application.run -> Legacy.removed",),
            evidence_paths=(({"evidence_type": "bytecode_method_invocation"},),),
            path_details=({"path_status": "reachable", "stop_reason": ""},),
            verification_commands=("javap -c Application",),
            hops=({"from": "Application.run", "to": "Legacy.removed"},),
            confidence_score=0.95,
            critical_nodes_hit=({"type": "system_code_touched"},),
            match_provenance="descriptor-exact",
            match_tier=0,
            capability_coverage=(("business_bytecode", "complete"),),
        )

        result = tracer.render_trace_result(seed, outcome)

        self.assertEqual(result.analysis_status, "reachable")
        self.assertIs(result.is_reachable, True)
        self.assertEqual(result.reason_code, "BUSINESS_ARTIFACT_BYTECODE_USAGE")
        self.assertEqual(result.direct_callers, 1)
        self.assertEqual(result.business_reach_depth, 2)
        self.assertEqual(result.old_version, "1.0")
        self.assertEqual(result.new_version, "2.0")
        self.assertEqual(result.dependency_chain_coords, [
            "com.acme:application", "com.vendor:legacy",
        ])
        self.assertEqual(result.evidence_paths[0][0]["evidence_type"], "bytecode_method_invocation")
        self.assertEqual(result.path_details[0]["path_status"], "reachable")
        self.assertEqual(result.verification_commands, ["javap -c Application"])
        self.assertEqual(result.match_provenance, "descriptor-exact")
        self.assertEqual(result.match_tier, 0)
        self.assertEqual(result.capability_coverage, {"business_bytecode": "complete"})

    def test_analysis_outcome_freezes_nested_rendering_evidence(self):
        detail = {"path_status": "reachable", "evidence": [{"line": 7}]}
        outcome = AnalysisOutcome(
            decision=AnalysisDecision(
                analysis_status="reachable", is_reachable=True,
                reason_code="EXACT", reachable_note="exact",
            ),
            path_details=(detail,),
        )

        detail["path_status"] = "uncertain"
        detail["evidence"][0]["line"] = 99
        rendered = tracer.render_trace_result(
            TraceSeed(
                api_name="A.m", api_simple="m", api_signature="()",
                symbol_kind="method", change_type="REMOVED", coord="g:a",
                severity="P1", confirmed=True, source="fixture",
                analysis_scope="api",
            ),
            outcome,
        )

        self.assertEqual(rendered.path_details[0]["path_status"], "reachable")
        self.assertEqual(rendered.path_details[0]["evidence"][0]["line"], 7)

    def test_summary_output_thaws_immutable_graph_statistics(self):
        graph_stats = {
            "framework_adapters": freeze_evidence_value({
                "indirect_usage": {"analyzers": [{"name": "reflection"}]},
            }),
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = formatter.write_summary_json([], tmp, graph_stats=graph_stats)
            payload = json.loads(Path(path).read_text(encoding="utf-8"))

        self.assertEqual(
            payload["meta"]["graph_stats"]["framework_adapters"]
            ["indirect_usage"]["analyzers"][0]["name"],
            "reflection",
        )

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

        draft = self._draft_from_result(result)
        with patch.object(tracer, "decide_envelope", return_value=policy_decision) as decide:
            tracer._build_packaged_dependency_hit_result(draft, [hit])
            built = tracer._finalize_trace_draft(draft)

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

    def test_packaged_physical_evidence_preserves_instruction_offset_to_terminal_output(self):
        draft = tracer._new_trace_draft({
            "api_name": "com.vendor.Legacy.removed",
            "api_simple": "removed",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "com.vendor:legacy",
        })
        hit = {
            "coord": "__business__",
            "jar_path": "/artifact/application.jar",
            "class_fqcn": "com.acme.Application",
            "consumer_method": "run",
            "consumer_signature": "()",
            "target_display": "com.vendor.Legacy.removed()",
            "evidence_type": "bytecode_method_invocation",
            "instruction_offset": 17,
        }

        with patch.object(
            tracer, "decide_envelope", wraps=tracer.decide_envelope,
        ) as decide:
            tracer._build_packaged_dependency_hit_result(draft, [hit])
            result = tracer._finalize_trace_draft(draft)

        envelope = decide.call_args.args[0]
        self.assertEqual(envelope.paths[0].evidence[-1].instruction_offset, 17)
        self.assertEqual(result.evidence_paths[0][0]["instruction_offset"], 17)

    def test_bfs_physical_evidence_preserves_instruction_offset(self):
        edge = type("Edge", (), {
            "caller_symbol_id": "app-run",
            "caller_qualified_key": "com.acme.Application.run()",
            "callee_key": "com.vendor.Legacy.removed()",
            "confidence": "high",
            "evidence_type": "bytecode_method_invocation",
            "file": "/artifact/application.jar",
            "line": 0,
            "instruction_offset": 23,
            "owner_coord": "BUSINESS",
            "module": "app",
        })()
        draft = tracer._new_trace_draft({
            "api_name": "com.vendor.Legacy.removed",
            "api_simple": "removed",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "coord": "com.vendor:legacy",
        })
        candidate = {
            "path": [edge],
            "entry_point": {"method": "com.acme.Application.run()"},
            "depth": 1,
        }

        path = tracer._candidate_reachability_path(
            draft, candidate, True, "SYSTEM_CODE_REACHED", "reached"
        )
        rendered = tracer.edge_to_evidence(edge)

        self.assertEqual(path.evidence[0].instruction_offset, 23)
        self.assertEqual(rendered["instruction_offset"], 23)

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
                    function.name == "render_trace_result"
                    or (
                        isinstance(status, ast.Constant)
                        and status.value == "pending"
                    )
                ):
                    violations.append((function.name, "TraceResult.analysis_status", node.lineno))

        self.assertEqual(violations, [])

    def test_public_tracer_rejects_non_draft_collector_results(self):
        with patch.object(
            tracer,
            "_collect_trace_api_with_confidence_weighting",
            return_value=object(),
        ):
            with self.assertRaisesRegex(TypeError, "TraceDraft"):
                tracer.trace_api_with_confidence_weighting({}, None, {})

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

        draft = self._draft_from_result(result)
        tracer._apply_evidence_decision(draft, complete_scan=True)
        envelope = EvidenceEnvelope(
            target_identity=tracer._trace_target_identity(draft),
            coverage=draft.envelope_coverage,
        )
        with patch.object(tracer, "decide_envelope", return_value=policy_decision) as decide:
            built = tracer._finalize_trace_draft(draft)

        decide.assert_called_once()
        self.assertEqual(envelope.coverage[0].collector, "legacy_complete_scan")
        self.assertEqual(envelope.coverage[0].status, "complete")
        self.assertEqual(built.analysis_status, "policy_status")
        self.assertEqual(built.reason_code, "POLICY_REASON")
        self.assertEqual(built.direct_callers, 3)

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

        draft = self._draft_from_result(result)
        tracer._apply_source_artifact_miss(draft, graph, "源码与制品冲突")
        built = tracer._finalize_trace_draft(draft)

        self.assertEqual(built.analysis_status, "uncertain")
        self.assertEqual(built.direct_callers, 1)
        self.assertEqual(built.business_reach_depth, 1)

    def test_direct_business_bytecode_reach_does_not_need_framework_activation(self):
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

        draft = self._draft_from_result(result)
        tracer._build_packaged_dependency_hit_result(draft, [hit], graph)
        built = tracer._finalize_trace_draft(draft)

        self.assertEqual(built.analysis_status, "reachable")
        self.assertEqual(built.reason_code, "BUSINESS_ARTIFACT_BYTECODE_USAGE")
        self.assertTrue(any(
            "com.example.Application.main -> Spring Boot框架注册" in path
            and "com.example.Receiver.receiveMessage(String)" in path
            for path in built.call_paths
        ))


if __name__ == "__main__":
    unittest.main()
