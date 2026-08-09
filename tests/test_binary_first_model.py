import sys
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from binary_first_contract import BinaryFirstContractError  # noqa: E402
from binary_first_model import (  # noqa: E402
    ActiveSnapshot,
    AnalysisContext,
    AnalysisScope,
    ArtifactInstance,
    BuildIdentityBundle,
    CrossVersionArtifactPairing,
    Decision,
    DispatchResolution,
    FactBuildInputSlice,
    ProjectionAssessment,
    ProviderBinding,
    ResultGeneration,
    RuntimeComparison,
    RuntimeProfile,
    build_projection_obligations,
    validate_decision_conservation,
    validate_projection_conservation,
    validate_snapshot_supersession,
)


def runtime_profile_payload(*, content="a" * 64, logical_location="lib/api.jar"):
    required = RuntimeProfile.REQUIRED_FIELDS
    payload = {
        "target_jvm": {"vendor": "temurin", "major": 21},
        "runtime_platform_image_identity": "platform-21",
        "target_os": "linux",
        "target_arch": "amd64",
        "container_and_launcher_kind": "java-classpath",
        "ordered_runtime_path_entry_descriptors": [{
            "logical_location": logical_location,
            "content_sha256": content,
            "path_kind": "classpath",
            "slot": 0,
            "loader_realm": "application",
        }],
        "loader_topology": {"application": {"parent": "platform"}},
        "runtime_code_source_origin_mapping_identity": "origins-1",
        "runtime_security_and_package_sealing_policy_identity": "security-1",
        "active_profile_identities": ["profile-default"],
        "external_config_snapshot_identities": [],
        "agent_transformer_plugin_profile_identities": [],
        "business_entrypoint_profile": {"main_class": "com.acme.Main"},
        "runtime_class_closure_coverage_status": "complete",
        "resource_selection_coverage_status": "complete",
        "field_coverage": {key: "known" for key in required},
    }
    return payload


def analysis_scope_payload():
    required = AnalysisScope.REQUIRED_FIELDS
    return {
        "analysis_observability_scope": "static-binary-v1",
        "artifact_diff_support_manifest_identity": "artifact-support-1",
        "runtime_loader_support_manifest_identity": "loader-support-1",
        "class_definition_support_manifest_identity": "definition-support-1",
        "runtime_fact_semantic_capability_identity": "semantic-none",
        "runtime_fact_dynamic_capability_identity": "dynamic-asm-v1",
        "runtime_fact_transformer_capability_identity": "transformer-none",
        "environment_equivalence_capability_identity": "equivalence-none",
        "field_coverage": {key: "known" for key in required},
    }


class RuntimeAndArtifactIdentityTest(unittest.TestCase):
    def test_runtime_identity_is_stable_and_content_sensitive(self):
        first = RuntimeProfile(runtime_profile_payload())
        second = RuntimeProfile(runtime_profile_payload())
        changed = RuntimeProfile(runtime_profile_payload(content="b" * 64))

        self.assertEqual(first.identity, second.identity)
        self.assertEqual(first.policy_identity, changed.policy_identity)
        self.assertNotEqual(first.identity, changed.identity)
        self.assertTrue(first.complete)

    def test_runtime_profile_rejects_temporary_absolute_location(self):
        with self.assertRaises(BinaryFirstContractError) as error:
            RuntimeProfile(runtime_profile_payload(logical_location="/tmp/api.jar"))

        self.assertEqual(error.exception.reason_code, "RUNTIME_PROFILE_PATH_NOT_REPRODUCIBLE")

    def test_runtime_profile_requires_explicit_field_coverage(self):
        payload = runtime_profile_payload()
        del payload["field_coverage"]["target_os"]

        with self.assertRaises(BinaryFirstContractError) as error:
            RuntimeProfile(payload)

        self.assertEqual(error.exception.reason_code, "BINARY_FIELD_COVERAGE_INVALID")

    def test_same_deployment_comparison_rejects_policy_change(self):
        base = RuntimeProfile(runtime_profile_payload())
        payload = runtime_profile_payload()
        payload["target_arch"] = "arm64"
        current = RuntimeProfile(payload)

        with self.assertRaises(BinaryFirstContractError) as error:
            RuntimeComparison(
                base,
                current,
                "same_deployment_profile",
                "v1",
                ("target_arch",),
                ("dependency-artifacts",),
                (),
            )

        self.assertEqual(error.exception.reason_code, "RUNTIME_PROFILE_CORRESPONDENCE_INVALID")

    def test_release_snapshot_keeps_pair_and_analysis_scope_separate(self):
        base = RuntimeProfile(runtime_profile_payload())
        current = RuntimeProfile(runtime_profile_payload(content="b" * 64))
        comparison = RuntimeComparison(
            base,
            current,
            "release_snapshot",
            "v1",
            ("target_jvm",),
            ("dependency-artifacts",),
            (),
        )
        scope = AnalysisScope(analysis_scope_payload())
        context = AnalysisContext(comparison, scope)

        self.assertNotEqual(context.identity, comparison.identity)
        self.assertNotEqual(context.identity, scope.identity)

    def test_analysis_scope_rejects_runtime_or_oracle_domains(self):
        for forbidden in ("runtime_profile_identity", "oracle_support_manifest_identity"):
            payload = analysis_scope_payload()
            payload[forbidden] = "must-not-participate"
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(BinaryFirstContractError) as error:
                    AnalysisScope(payload)
                self.assertEqual(error.exception.reason_code, "ANALYSIS_SCOPE_DOMAIN_VIOLATION")

    def test_artifact_instances_preserve_physical_runtime_slot(self):
        values = dict(
            outer_artifact_sha256="a" * 64,
            container_entry="BOOT-INF/lib/api.jar",
            content_sha256="b" * 64,
            runtime_profile_identity="runtime-1",
            path_owner_loader_realm_identity="app-loader",
            runtime_path_kind="nested_runtime",
            container_loader_policy_version="spring-boot-v1",
            runtime_code_source_origin_identity="origin-1",
            coord="com.acme:api:1",
        )
        first = ArtifactInstance(runtime_classpath_index=1, **values)
        second = ArtifactInstance(runtime_classpath_index=2, **values)

        self.assertNotEqual(first.identity, second.identity)

    def test_pairing_status_enforces_cardinality_and_evidence(self):
        exact = CrossVersionArtifactPairing(
            "exact", "com.acme:api", "base-runtime", "current-runtime",
            ({"rule": "coord-lineage"},), "v1", "base-instance", "current-instance",
        )
        self.assertTrue(exact.identity)

        with self.assertRaises(BinaryFirstContractError) as error:
            CrossVersionArtifactPairing(
                "base_only", "com.acme:api", "base-runtime", "current-runtime",
                ({"rule": "coord-lineage"},), "v1", "base-instance", "current-instance",
            )
        self.assertEqual(error.exception.reason_code, "ARTIFACT_PAIRING_CARDINALITY_INVALID")

    def test_provided_artifact_never_claims_analyzer_build(self):
        bundle = BuildIdentityBundle({}, {}, {
            "input_mode": "provided_artifact",
            "build_executed_by_system": False,
            "build_execution_status": "not_executed",
        })
        self.assertTrue(bundle.provenance_identity)

        with self.assertRaises(BinaryFirstContractError) as error:
            BuildIdentityBundle({}, {}, {
                "input_mode": "provided_artifact",
                "build_executed_by_system": True,
                "build_execution_status": "success",
            })
        self.assertEqual(error.exception.reason_code, "PROVIDED_ARTIFACT_BUILD_EXECUTION_INVALID")

    def test_fact_build_input_slice_keeps_provenance_profile_and_parser_separate(self):
        first = FactBuildInputSlice(
            "provenance-1", ("content-1",), "profile-1", "parser-1"
        )
        second = FactBuildInputSlice(
            "provenance-1", ("content-1",), "profile-2", "parser-1"
        )
        self.assertNotEqual(first.identity, second.identity)
        with self.assertRaises(BinaryFirstContractError):
            FactBuildInputSlice("", ("content-1",), "profile-1", "parser-1")


class BindingDecisionAndSnapshotTest(unittest.TestCase):
    def test_nonresolved_provider_cannot_select_physical_instance(self):
        with self.assertRaises(BinaryFirstContractError) as error:
            ProviderBinding({
                "class_provider_status": "ambiguous",
                "selected_artifact_instance_identity": "artifact-1",
            })
        self.assertEqual(error.exception.reason_code, "CLASS_PROVIDER_SELECTION_INVALID")

    def test_runtime_equivalent_provider_uses_equivalence_set_only(self):
        binding = ProviderBinding({
            "class_provider_status": "runtime_equivalent",
            "provider_equivalence_set_identity": "equivalent-set-1",
        })
        self.assertTrue(binding.identity)

    def test_dispatch_certainty_and_coverage_are_conserved(self):
        partial = DispatchResolution(
            "edge-1", "partial_possible_set", ("impl-1",), "partial",
            {"uncovered": ["dynamic-subclasses"]},
        )
        self.assertTrue(partial.identity)

        with self.assertRaises(BinaryFirstContractError) as error:
            DispatchResolution(
                "edge-1", "no_concrete_implementation", (), "partial", {"hierarchy": "all"}
            )
        self.assertEqual(error.exception.reason_code, "DISPATCH_COVERAGE_INVALID")

    def test_each_disposition_obligation_has_exactly_one_owner(self):
        first = Decision("delta-1", "context-1", "authoritative", {
            "change_fact_status": "confirmed",
        })
        second = Decision("delta-2", "context-1", "diagnostic", {
            "candidate_fact_status": "candidate",
        })
        self.assertTrue(validate_decision_conservation(
            disposition_obligation_identities=(first.obligation_identity, second.obligation_identity),
            decisions=(first, second),
        ))

        duplicate = Decision("delta-1", "context-1", "excluded", {
            "exclusion_status": "excluded",
        })
        with self.assertRaises(BinaryFirstContractError) as error:
            validate_decision_conservation(
                disposition_obligation_identities=(first.obligation_identity,),
                decisions=(first, duplicate),
            )
        self.assertEqual(error.exception.reason_code, "DISPOSITION_OBLIGATION_CONSERVATION_FAILED")

    def test_projection_obligations_are_complete_and_unique(self):
        obligations = build_projection_obligations(
            projection_rule_contract_identity="rule-1",
            targets_by_required_edge_family={"method": ("target-2", "target-1")},
        )
        assessment = ProjectionAssessment(
            "decision-1", "targetable", "complete", ("target-1", "target-2"),
            obligations, (),
        )
        self.assertTrue(validate_projection_conservation(
            assessment=assessment,
            projection_obligation_keys=obligations,
        ))

        with self.assertRaises(BinaryFirstContractError) as error:
            validate_projection_conservation(
                assessment=assessment,
                projection_obligation_keys=obligations[:1],
            )
        self.assertEqual(error.exception.reason_code, "PROJECTION_OBLIGATION_CONSERVATION_FAILED")

    def test_snapshot_validation_accepts_generator_and_rejects_cross_context_chain(self):
        parent = ActiveSnapshot("decision", "context-1", ("decision-1",))
        child = ActiveSnapshot(
            "decision", "context-1", ("decision-2",), parent.identity
        )
        self.assertTrue(validate_snapshot_supersession(item for item in (parent, child)))

        wrong_context = ActiveSnapshot(
            "decision", "context-2", ("decision-3",), parent.identity
        )
        with self.assertRaises(BinaryFirstContractError) as error:
            validate_snapshot_supersession((parent, wrong_context))
        self.assertEqual(error.exception.reason_code, "ACTIVE_SNAPSHOT_SUPERSESSION_DOMAIN_INVALID")

    def test_result_generation_requires_four_context_bound_snapshots(self):
        snapshots = {
            layer: ActiveSnapshot(layer, "context-1", ())
            for layer in ActiveSnapshot.VALID_LAYERS
        }
        generation = ResultGeneration(
            "context-1", "shadow", snapshots, "trace-set-1",
            {"binary_facts": "content-sha-1"}, {"diff": "policy-1"},
        )
        self.assertTrue(generation.identity)

        with self.assertRaises(BinaryFirstContractError) as error:
            ResultGeneration(
                "context-1", "shadow", {"decision": snapshots["decision"]},
                "trace-set-1", {}, {},
            )
        self.assertEqual(error.exception.reason_code, "RESULT_GENERATION_SNAPSHOT_SET_INVALID")


if __name__ == "__main__":
    unittest.main()
