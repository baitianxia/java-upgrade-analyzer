import sys
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from binary_first_contract import BinaryFirstContractError  # noqa: E402
from binary_validation_oracle import (  # noqa: E402
    _RUNTIME_PROFILE_IDENTITY_FIELDS,
)
import binary_first_model as model  # noqa: E402
from binary_first_model import (  # noqa: E402
    ActiveSnapshot,
    AnalysisContext,
    AnalysisScope,
    ArtifactInstance,
    BuildIdentityBundle,
    ClassDefinitionResolution,
    CrossVersionArtifactPairing,
    Decision,
    DispatchResolution,
    FactBuildInputSlice,
    MemberResolution,
    ProjectionAssessment,
    ProviderBinding,
    ResultGeneration,
    RuntimeComparison,
    RuntimeProfile,
    _class_definition_resolution_identity_native,
    _dispatch_resolution_identity_native,
    _member_resolution_identity_native,
    _provider_binding_identity_native,
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
        "resolved_configuration_properties": {},
        "runtime_configuration_coverage_status": "complete",
        "runtime_configuration_coverage_gaps": [],
        "external_config_snapshot_identities": [],
        "agent_transformer_plugin_profile_identities": [],
        "business_entrypoint_profile": {"main_class": "com.acme.Main"},
        "entrypoint_discovery_coverage_gaps": [],
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

    def test_runtime_semantic_inputs_are_bound_to_policy_and_snapshot_identity(self):
        base = RuntimeProfile(runtime_profile_payload())
        mutations = {
            "resolved_configuration_properties": {"feature.enabled": "true"},
            "runtime_configuration_coverage_status": "partial",
            "runtime_configuration_coverage_gaps": ["config-source-unreadable"],
            "entrypoint_discovery_coverage_gaps": ["main-class-unresolved"],
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                payload = runtime_profile_payload()
                payload[field] = value
                changed = RuntimeProfile(payload)
                self.assertNotEqual(base.policy_identity, changed.policy_identity)
                self.assertNotEqual(base.identity, changed.identity)
                with self.assertRaises(BinaryFirstContractError) as error:
                    RuntimeComparison(
                        base,
                        changed,
                        "same_deployment_profile",
                        "v1",
                        (field,),
                        ("dependency-artifacts",),
                        (),
                    )
                self.assertEqual(
                    error.exception.reason_code,
                    "RUNTIME_PROFILE_CORRESPONDENCE_INVALID",
                )

    def test_multi_release_jvm_policy_is_already_bound_via_loader_topology(self):
        first_payload = runtime_profile_payload()
        first_payload["loader_topology"] = {
            "multi_release_jar_runtime_policy": {
                "policy_identity": "openjdk-jarfile-default-properties-v1",
                "target_runtime_feature": 21,
                "jdk.util.jar.enableMultiRelease": "true",
            }
        }
        second_payload = runtime_profile_payload()
        second_payload["loader_topology"] = {
            "multi_release_jar_runtime_policy": {
                "policy_identity": "openjdk-jarfile-default-properties-v1",
                "target_runtime_feature": 17,
                "jdk.util.jar.enableMultiRelease": "true",
            }
        }

        first = RuntimeProfile(first_payload)
        second = RuntimeProfile(second_payload)

        self.assertNotEqual(first.policy_identity, second.policy_identity)
        self.assertNotEqual(first.identity, second.identity)

    def test_independent_oracle_binds_the_same_runtime_profile_fields(self):
        self.assertEqual(
            tuple(RuntimeProfile.IDENTITY_FIELDS),
            tuple(_RUNTIME_PROFILE_IDENTITY_FIELDS),
        )

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

    def test_runtime_profile_rejects_malformed_semantic_inputs_early(self):
        cases = (
            (
                "business_entrypoint_profile", [],
                "RUNTIME_PROFILE_ENTRYPOINT_PROFILE_INVALID",
            ),
            (
                "resolved_configuration_properties", [],
                "RUNTIME_PROFILE_CONFIGURATION_PROPERTIES_INVALID",
            ),
            (
                "runtime_configuration_coverage_status", "unknown",
                "RUNTIME_PROFILE_CONFIGURATION_COVERAGE_STATUS_INVALID",
            ),
            (
                "runtime_configuration_coverage_gaps", {"not-json"},
                "RUNTIME_PROFILE_SEQUENCE_INVALID",
            ),
            (
                "active_profile_identities", "prod",
                "RUNTIME_PROFILE_SEQUENCE_INVALID",
            ),
        )
        for field, value, reason_code in cases:
            with self.subTest(field=field):
                payload = runtime_profile_payload()
                payload[field] = value
                with self.assertRaises(BinaryFirstContractError) as error:
                    RuntimeProfile(payload)
                self.assertEqual(error.exception.reason_code, reason_code)

        for nested_field, value, reason_code in (
            (
                "coverage_status", "unknown",
                "RUNTIME_PROFILE_ENTRYPOINT_COVERAGE_STATUS_INVALID",
            ),
            (
                "coverage_gaps", {"not-json"},
                "RUNTIME_PROFILE_SEQUENCE_INVALID",
            ),
            (
                "activated_classes", "demo.App",
                "RUNTIME_PROFILE_SEQUENCE_INVALID",
            ),
            (
                "activated_entity_classes", [""],
                "RUNTIME_PROFILE_SEQUENCE_INVALID",
            ),
            (
                "activated_resource_names", {"application.xml"},
                "RUNTIME_PROFILE_SEQUENCE_INVALID",
            ),
            (
                "activated_component_scan_packages", "demo",
                "RUNTIME_PROFILE_SEQUENCE_INVALID",
            ),
            (
                "activated_frameworks", "spring_boot",
                "RUNTIME_PROFILE_SEQUENCE_INVALID",
            ),
            (
                "methods", "demo.App#main",
                "RUNTIME_PROFILE_ENTRYPOINT_METHODS_INVALID",
            ),
            (
                "main_class", ["demo.App"],
                "RUNTIME_PROFILE_ENTRYPOINT_MAIN_CLASS_INVALID",
            ),
        ):
            with self.subTest(nested_field=nested_field):
                payload = runtime_profile_payload()
                payload["business_entrypoint_profile"][nested_field] = value
                with self.assertRaises(BinaryFirstContractError) as error:
                    RuntimeProfile(payload)
                self.assertEqual(error.exception.reason_code, reason_code)

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
    def test_internal_native_reconciliation_identities_match_public_contract(self):
        provider_payload = {
            "runtime_profile_identity": "profile-1",
            "initiating_loader_realm_identity": "application",
            "class_name": "example/Service",
            "class_provider_status": "resolved",
            "selected_defining_loader_realm_identity": "application",
            "selected_artifact_instance_identity": "artifact-1",
            "selected_class_variant_identity": "variant-1",
            "selection_evidence": {"candidate_count": 1},
        }
        provider = ProviderBinding(provider_payload)
        self.assertEqual(
            _provider_binding_identity_native(provider_payload), provider.identity
        )

        definition_evidence = {
            "target_class_major": 65,
            "target_jvm_verification": {"status": "definition_ready"},
        }
        definition = ClassDefinitionResolution(
            provider.identity, "variant-1", "definition_ready", definition_evidence
        )
        self.assertEqual(
            _class_definition_resolution_identity_native(
                provider.identity, "variant-1", "definition_ready", definition_evidence
            ),
            definition.identity,
        )

        member_payload = {
            "member_resolution_status": "resolved",
            "direct_edge_identity": "edge-1",
            "resolved_member_identity": "member-1",
            "resolution_evidence": {"owner": "example/Service"},
        }
        member = MemberResolution(member_payload)
        self.assertEqual(
            _member_resolution_identity_native(member_payload), member.identity
        )

        dispatch_evidence = {
            "member_resolution_identity": member.identity,
            "hierarchy_coverage_complete": True,
        }
        dispatch = DispatchResolution(
            "edge-1", "exact", ("member-1",), "complete", dispatch_evidence
        )
        self.assertEqual(
            _dispatch_resolution_identity_native(
                "edge-1", "exact", ("member-1",), "complete", dispatch_evidence
            ),
            dispatch.identity,
        )

    def test_internal_native_reconciliation_identity_keeps_validation_contract(self):
        with self.assertRaises(BinaryFirstContractError) as public_error:
            ProviderBinding({
                "class_provider_status": "ambiguous",
                "selected_artifact_instance_identity": "artifact-1",
            })
        with self.assertRaises(BinaryFirstContractError) as internal_error:
            _provider_binding_identity_native({
                "class_provider_status": "ambiguous",
                "selected_artifact_instance_identity": "artifact-1",
            })
        self.assertEqual(internal_error.exception.reason_code, public_error.exception.reason_code)

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
            "context-1", snapshots, "trace-set-1",
            {"binary_facts": "content-sha-1"}, {"diff": "policy-1"},
        )
        self.assertTrue(generation.identity)

        with self.assertRaises(BinaryFirstContractError) as error:
            ResultGeneration(
                "context-1", {"decision": snapshots["decision"]},
                "trace-set-1", {}, {},
            )
        self.assertEqual(error.exception.reason_code, "RESULT_GENERATION_SNAPSHOT_SET_INVALID")


class ModelBoundaryContractTest(unittest.TestCase):
    def assert_reason(self, reason, callback):
        with self.assertRaises(BinaryFirstContractError) as raised:
            callback()
        self.assertEqual(raised.exception.reason_code, reason)

    @staticmethod
    def artifact_values(**overrides):
        values = {
            "outer_artifact_sha256": "a" * 64,
            "container_entry": "BOOT-INF/lib/api.jar",
            "content_sha256": "b" * 64,
            "runtime_profile_identity": "runtime-1",
            "path_owner_loader_realm_identity": "app-loader",
            "runtime_path_kind": "nested_runtime",
            "runtime_classpath_index": 0,
            "container_loader_policy_version": "spring-boot-v1",
            "runtime_code_source_origin_identity": "origin-1",
        }
        values.update(overrides)
        return values

    def test_required_text_and_field_coverage_boundary_matrix(self):
        self.assertEqual(model._required_text({"field": " value "}, "field"), "value")
        for value in (None, "", "   "):
            with self.subTest(value=value):
                self.assert_reason(
                    "BINARY_IDENTITY_FIELD_MISSING",
                    lambda value=value: model._required_text(
                        {"field": value}, "field"
                    ),
                )

        for payload, reason in (
            ({}, "BINARY_FIELD_COVERAGE_MISSING"),
            ({"field_coverage": []}, "BINARY_FIELD_COVERAGE_MISSING"),
            ({"field_coverage": {"a": "known"}}, "BINARY_FIELD_COVERAGE_INVALID"),
            ({"field_coverage": {"a": "known", "b": None}},
             "BINARY_FIELD_COVERAGE_INVALID"),
        ):
            with self.subTest(payload=payload):
                self.assert_reason(
                    reason, lambda payload=payload: model._coverage(payload, ("a", "b"))
                )
        self.assertEqual(
            model._coverage(
                {"field_coverage": {"a": "known", "b": "not_applicable"}},
                ("a", "b"),
            ),
            {"a": "known", "b": "not_applicable"},
        )

    def test_runtime_profile_semantic_optional_and_sequence_shape_matrix(self):
        for payload in (None, {}):
            with self.subTest(empty_payload=payload):
                self.assert_reason(
                    "BINARY_FIELD_COVERAGE_MISSING",
                    lambda payload=payload: RuntimeProfile(payload),
                )
        valid_mutations = (
            ("resolved_configuration_properties", None),
            ("runtime_configuration_coverage_status", None),
            ("active_profile_identities", None),
            ("active_profile_identities", ("profile",)),
            ("runtime_configuration_coverage_gaps", []),
            ("business_entrypoint_profile", None),
        )
        for field, value in valid_mutations:
            payload = runtime_profile_payload()
            payload[field] = value
            with self.subTest(field=field, value=value):
                self.assertTrue(RuntimeProfile(payload).identity)

        nested_valid = (
            ("coverage_status", None),
            ("coverage_status", "partial"),
            ("coverage_gaps", []),
            ("methods", None),
            ("methods", []),
            ("methods", ({"owner": "demo/App"},)),
            ("main_class", None),
            ("main_class", "demo.App"),
        )
        for field, value in nested_valid:
            payload = runtime_profile_payload()
            payload["business_entrypoint_profile"][field] = value
            with self.subTest(nested_field=field, value=value):
                self.assertTrue(RuntimeProfile(payload).identity)

        sequence_invalid = (
            ("external_config_snapshot_identities", [1]),
            ("agent_transformer_plugin_profile_identities", [" "]),
            ("entrypoint_discovery_coverage_gaps", object()),
        )
        for field, value in sequence_invalid:
            payload = runtime_profile_payload()
            payload[field] = value
            with self.subTest(field=field):
                self.assert_reason(
                    "RUNTIME_PROFILE_SEQUENCE_INVALID",
                    lambda payload=payload: RuntimeProfile(payload),
                )

        payload = runtime_profile_payload()
        payload["business_entrypoint_profile"]["methods"] = [1]
        self.assert_reason(
            "RUNTIME_PROFILE_ENTRYPOINT_METHODS_INVALID",
            lambda: RuntimeProfile(payload),
        )

    def test_runtime_profile_path_matrix_includes_windows_and_unc_absolutes(self):
        invalid_locations = (
            "",
            "   ",
            "/opt/api.jar",
            "~/api.jar",
            "C:\\runtime\\api.jar",
            "C:/runtime/api.jar",
            "\\\\server\\share\\api.jar",
        )
        for location in invalid_locations:
            with self.subTest(location=location):
                self.assert_reason(
                    "RUNTIME_PROFILE_PATH_NOT_REPRODUCIBLE",
                    lambda location=location: RuntimeProfile(
                        runtime_profile_payload(logical_location=location)
                    ),
                )

        payload = runtime_profile_payload()
        payload["ordered_runtime_path_entry_descriptors"] = ()
        self.assert_reason(
            "RUNTIME_PROFILE_PATH_INVALID", lambda: RuntimeProfile(payload)
        )
        payload = runtime_profile_payload()
        payload["ordered_runtime_path_entry_descriptors"] = ["api.jar"]
        self.assert_reason(
            "RUNTIME_PROFILE_PATH_INVALID", lambda: RuntimeProfile(payload)
        )
        for field, reason in (
            ("content_sha256", "BINARY_IDENTITY_FIELD_MISSING"),
            ("path_kind", "BINARY_IDENTITY_FIELD_MISSING"),
            ("slot", "RUNTIME_PROFILE_PATH_SLOT_MISSING"),
        ):
            payload = runtime_profile_payload()
            payload["ordered_runtime_path_entry_descriptors"][0].pop(field)
            with self.subTest(field=field):
                self.assert_reason(reason, lambda payload=payload: RuntimeProfile(payload))

        empty_path_payload = runtime_profile_payload()
        empty_path_payload["ordered_runtime_path_entry_descriptors"] = []
        self.assertTrue(RuntimeProfile(empty_path_payload).identity)

    def test_runtime_profile_complete_reflects_unknown_and_missing_coverage(self):
        payload = runtime_profile_payload()
        profile = RuntimeProfile(payload)
        payload["field_coverage"][RuntimeProfile.REQUIRED_FIELDS[-1]] = "unknown"
        self.assertFalse(profile.complete)
        payload.pop("field_coverage")
        self.assertFalse(profile.complete)

    def test_runtime_comparison_covers_intent_and_same_deployment_short_circuits(self):
        base = RuntimeProfile(runtime_profile_payload())
        self.assert_reason(
            "RUNTIME_COMPARISON_INTENT_INVALID",
            lambda: RuntimeComparison(base, base, "other", "v1", (), (), ()),
        )
        self.assertTrue(RuntimeComparison(
            base, base, "same_deployment_profile", "v1", (), (), ()
        ).identity)
        self.assert_reason(
            "RUNTIME_PROFILE_CORRESPONDENCE_INVALID",
            lambda: RuntimeComparison(
                base, base, "same_deployment_profile", "v1", (), (), ("unknown",)
            ),
        )
        self.assertTrue(RuntimeComparison(
            base, base, "release_snapshot", "v1", (), (), ("changed",)
        ).identity)

    def test_analysis_scope_empty_payload_and_all_forbidden_domains(self):
        self.assert_reason(
            "BINARY_FIELD_COVERAGE_MISSING", lambda: AnalysisScope(None)
        )
        for forbidden in (
            "runtime_profile_identity",
            "runtime_comparison_identity",
            "oracle_support_manifest_identity",
            "projection_registry_identity",
            "validation_policy_identity",
        ):
            payload = analysis_scope_payload()
            payload[forbidden] = "identity"
            with self.subTest(forbidden=forbidden):
                self.assert_reason(
                    "ANALYSIS_SCOPE_DOMAIN_VIOLATION",
                    lambda payload=payload: AnalysisScope(payload),
                )

    def test_artifact_instance_rejects_kind_slot_type_and_every_empty_field(self):
        self.assert_reason(
            "ARTIFACT_INSTANCE_PATH_KIND_INVALID",
            lambda: ArtifactInstance(**self.artifact_values(runtime_path_kind="other")),
        )
        for value in (-1, True, 1.5, "1"):
            with self.subTest(slot=value):
                self.assert_reason(
                    "ARTIFACT_INSTANCE_SLOT_INVALID",
                    lambda value=value: ArtifactInstance(
                        **self.artifact_values(runtime_classpath_index=value)
                    ),
                )
        for field in (
            "outer_artifact_sha256",
            "container_entry",
            "content_sha256",
            "runtime_profile_identity",
            "path_owner_loader_realm_identity",
            "container_loader_policy_version",
            "runtime_code_source_origin_identity",
        ):
            for missing in (None, "", "   "):
                with self.subTest(field=field, missing=missing):
                    self.assert_reason(
                        "ARTIFACT_INSTANCE_FIELD_MISSING",
                        lambda field=field, missing=missing: ArtifactInstance(
                            **self.artifact_values(**{field: missing})
                        ),
                    )
        self.assertTrue(ArtifactInstance(**self.artifact_values()).identity)

    def test_pairing_all_statuses_invalid_status_and_evidence_boundary(self):
        common = ("lineage", "base-runtime", "current-runtime")
        cases = (
            ("exact", "base", "current"),
            ("base_only", "base", ""),
            ("current_only", "", "current"),
            ("ambiguous", "", ""),
        )
        for status, base, current in cases:
            with self.subTest(status=status):
                self.assertTrue(CrossVersionArtifactPairing(
                    status, *common, ({"rule": "test"},), "v1", base, current
                ).identity)
        self.assert_reason(
            "ARTIFACT_PAIRING_STATUS_INVALID",
            lambda: CrossVersionArtifactPairing(
                "other", *common, ({"rule": "test"},), "v1"
            ),
        )
        self.assert_reason(
            "ARTIFACT_PAIRING_EVIDENCE_MISSING",
            lambda: CrossVersionArtifactPairing(
                "ambiguous", *common, (), "v1"
            ),
        )

    def test_build_identity_bundle_state_machine_and_empty_identity_sources(self):
        valid = {
            "input_mode": "provided_artifact",
            "build_executed_by_system": False,
            "build_execution_status": "not_executed",
        }
        for environment, build_input in ((None, None), ({}, {}), ({"jdk": 21}, {"pom": "x"})):
            with self.subTest(environment=environment, build_input=build_input):
                self.assertTrue(
                    BuildIdentityBundle(environment, build_input, valid).provenance_identity
                )
        for forbidden in ("source_revision", "source_state_identity"):
            self.assert_reason(
                "BUILD_ENVIRONMENT_DOMAIN_VIOLATION",
                lambda forbidden=forbidden: BuildIdentityBundle(
                    {forbidden: "value"}, {}, valid
                ),
            )
        for mode in (None, "", "other"):
            provenance = dict(valid, input_mode=mode)
            with self.subTest(mode=mode):
                self.assert_reason(
                    "BUILD_INPUT_MODE_INVALID",
                    lambda provenance=provenance: BuildIdentityBundle({}, {}, provenance),
                )
        for provenance in (None, {}):
            with self.subTest(provenance=provenance):
                self.assert_reason(
                    "BUILD_INPUT_MODE_INVALID",
                    lambda provenance=provenance: BuildIdentityBundle(
                        {}, {}, provenance
                    ),
                )
        self.assert_reason(
            "PROVIDED_ARTIFACT_BUILD_EXECUTION_INVALID",
            lambda: BuildIdentityBundle({}, {}, {
                "input_mode": "provided_artifact",
                "build_executed_by_system": False,
                "build_execution_status": None,
            }),
        )
        self.assert_reason(
            "PROVIDED_ARTIFACT_BUILD_EXECUTION_INVALID",
            lambda: BuildIdentityBundle({}, {}, dict(
                valid, build_execution_status="failed"
            )),
        )
        self.assert_reason(
            "CHECKOUT_BUILD_EXECUTION_MISSING",
            lambda: BuildIdentityBundle({}, {}, {
                "input_mode": "checkout_build",
                "build_executed_by_system": False,
                "build_execution_status": "not_executed",
            }),
        )
        self.assertTrue(BuildIdentityBundle({}, {}, {
            "input_mode": "checkout_build",
            "build_executed_by_system": True,
            "build_execution_status": "success",
        }).provenance_identity)

    def test_fact_build_slice_rejects_each_missing_identity(self):
        values = ["provenance", ("content",), "runtime", "parser"]
        for index in range(len(values)):
            invalid = list(values)
            invalid[index] = () if index == 1 else ""
            with self.subTest(index=index):
                self.assert_reason(
                    "FACT_BUILD_INPUT_SLICE_INCOMPLETE",
                    lambda invalid=invalid: FactBuildInputSlice(*invalid),
                )
        self.assertTrue(FactBuildInputSlice(*values).identity)

    def test_provider_binding_status_and_selection_matrix(self):
        selected = {
            "selected_defining_loader_realm_identity": "loader",
            "selected_artifact_instance_identity": "artifact",
            "selected_class_variant_identity": "variant",
        }
        resolved = {"class_provider_status": "resolved", **selected}
        self.assertTrue(ProviderBinding(resolved).identity)
        for field in selected:
            payload = dict(resolved)
            payload[field] = ""
            with self.subTest(resolved_missing=field):
                self.assert_reason(
                    "BINARY_IDENTITY_FIELD_MISSING",
                    lambda payload=payload: ProviderBinding(payload),
                )
        self.assert_reason(
            "CLASS_PROVIDER_EQUIVALENCE_INVALID",
            lambda: ProviderBinding(dict(
                resolved, provider_equivalence_set_identity="equivalent"
            )),
        )

        equivalent = {
            "class_provider_status": "runtime_equivalent",
            "provider_equivalence_set_identity": "equivalent",
        }
        self.assertTrue(ProviderBinding(equivalent).identity)
        self.assert_reason(
            "BINARY_IDENTITY_FIELD_MISSING",
            lambda: ProviderBinding({"class_provider_status": "runtime_equivalent"}),
        )
        for field in selected:
            with self.subTest(equivalent_selection=field):
                self.assert_reason(
                    "CLASS_PROVIDER_SELECTION_INVALID",
                    lambda field=field: ProviderBinding({
                        **equivalent, field: "selected",
                    }),
                )

        for status in model.PROVIDER_STATUSES - {"resolved", "runtime_equivalent"}:
            with self.subTest(status=status):
                self.assertTrue(ProviderBinding({
                    "class_provider_status": status,
                }).identity)
                self.assert_reason(
                    "CLASS_PROVIDER_SELECTION_INVALID",
                    lambda status=status: ProviderBinding({
                        "class_provider_status": status,
                        "selected_class_variant_identity": "variant",
                    }),
                )
        for payload in (None, {}, {"class_provider_status": "other"}):
            with self.subTest(payload=payload):
                self.assert_reason(
                    "CLASS_PROVIDER_STATUS_INVALID",
                    lambda payload=payload: ProviderBinding(payload),
                )

    def test_definition_member_and_dispatch_resolution_state_matrices(self):
        self.assert_reason(
            "CLASS_DEFINITION_STATUS_INVALID",
            lambda: ClassDefinitionResolution("provider", "target", "other", {"e": 1}),
        )
        for evidence in (None, {}):
            self.assert_reason(
                "CLASS_DEFINITION_EVIDENCE_MISSING",
                lambda evidence=evidence: ClassDefinitionResolution(
                    "provider", "target", "definition_ready", evidence
                ),
            )
        for status in model.CLASS_DEFINITION_STATUSES:
            with self.subTest(definition_status=status):
                self.assertTrue(ClassDefinitionResolution(
                    "provider", "target", status, {"source": "probe"}
                ).identity)

        valid_members = (
            {"member_resolution_status": "resolved",
             "resolved_member_identity": "member"},
            {"member_resolution_status": "runtime_equivalent",
             "member_equivalence_set_identity": "set"},
            {"member_resolution_status": "no_such_member"},
        )
        for payload in valid_members:
            with self.subTest(member=payload):
                self.assertTrue(MemberResolution(payload).identity)
        invalid_members = (
            ({}, "MEMBER_RESOLUTION_STATUS_INVALID"),
            ({"member_resolution_status": "other"},
             "MEMBER_RESOLUTION_STATUS_INVALID"),
            ({"member_resolution_status": "resolved"},
             "MEMBER_RESOLUTION_TARGET_INVALID"),
            ({"member_resolution_status": "resolved",
              "resolved_member_identity": "member",
              "member_equivalence_set_identity": "set"},
             "MEMBER_RESOLUTION_TARGET_INVALID"),
            ({"member_resolution_status": "runtime_equivalent"},
             "MEMBER_RESOLUTION_TARGET_INVALID"),
            ({"member_resolution_status": "runtime_equivalent",
              "resolved_member_identity": "member",
              "member_equivalence_set_identity": "set"},
             "MEMBER_RESOLUTION_TARGET_INVALID"),
            ({"member_resolution_status": "ambiguous",
              "resolved_member_identity": "member"},
             "MEMBER_RESOLUTION_TARGET_INVALID"),
            ({"member_resolution_status": "ambiguous",
              "member_equivalence_set_identity": "set"},
             "MEMBER_RESOLUTION_TARGET_INVALID"),
        )
        for payload, reason in invalid_members:
            with self.subTest(member=payload):
                self.assert_reason(
                    reason, lambda payload=payload: MemberResolution(payload)
                )

        valid_dispatches = (
            ("not_applicable", (), "unknown"),
            ("unresolved", (), "partial"),
            ("no_concrete_implementation", (), "complete"),
            ("exact", ("target",), "complete"),
            ("proven_receiver", ("target",), "complete"),
            ("possible", ("target",), "complete"),
            ("partial_possible_set", ("target",), "partial"),
        )
        for status, targets, coverage in valid_dispatches:
            with self.subTest(dispatch=status):
                self.assertTrue(DispatchResolution(
                    "edge", status, targets, coverage, {}
                ).identity)
        invalid_dispatches = (
            (("other", (), "complete"), "DISPATCH_STATUS_INVALID"),
            (("unresolved", ("target",), "complete"),
             "DISPATCH_TARGET_COUNT_INVALID"),
            (("exact", (), "complete"), "DISPATCH_TARGET_COUNT_INVALID"),
            (("partial_possible_set", ("target",), "complete"),
             "DISPATCH_COVERAGE_INVALID"),
            (("no_concrete_implementation", (), "partial"),
             "DISPATCH_COVERAGE_INVALID"),
        )
        for (status, targets, coverage), reason in invalid_dispatches:
            with self.subTest(dispatch=status, reason=reason):
                self.assert_reason(
                    reason,
                    lambda status=status, targets=targets, coverage=coverage:
                    DispatchResolution("edge", status, targets, coverage, {}),
                )

    def test_decision_channel_payload_and_overlap_matrix(self):
        valid = (
            ("authoritative", {"change_fact_status": "confirmed"}),
            ("diagnostic", {"candidate_fact_status": "candidate"}),
            ("diagnostic", {"candidate_fact_status": "incomplete"}),
            ("excluded", {"exclusion_status": "excluded"}),
        )
        for channel, payload in valid:
            with self.subTest(channel=channel, payload=payload):
                self.assertTrue(Decision("delta", "context", channel, payload).identity)
        self.assert_reason(
            "DECISION_CHANNEL_INVALID",
            lambda: Decision("delta", "context", "other", {}),
        )
        invalid = (
            ("authoritative", None, "DECISION_CHANNEL_PAYLOAD_INVALID"),
            ("authoritative", {"change_fact_status": "candidate"},
             "DECISION_CHANNEL_PAYLOAD_INVALID"),
            ("diagnostic", {"candidate_fact_status": "other"},
             "DECISION_CHANNEL_PAYLOAD_INVALID"),
            ("excluded", {"exclusion_status": "other"},
             "DECISION_CHANNEL_PAYLOAD_INVALID"),
            ("authoritative", {
                "change_fact_status": "confirmed",
                "candidate_fact_status": "candidate",
            }, "DECISION_CHANNEL_OVERLAP"),
            ("diagnostic", {
                "candidate_fact_status": "candidate",
                "exclusion_status": "excluded",
            }, "DECISION_CHANNEL_OVERLAP"),
            ("excluded", {
                "exclusion_status": "excluded",
                "change_fact_status": "confirmed",
            }, "DECISION_CHANNEL_OVERLAP"),
        )
        for channel, payload, reason in invalid:
            with self.subTest(channel=channel, reason=reason):
                self.assert_reason(
                    reason,
                    lambda channel=channel, payload=payload: Decision(
                        "delta", "context", channel, payload
                    ),
                )

    def test_projection_assessment_complete_state_matrix(self):
        valid = (
            ("unsupported", "unsupported", (), (), ()),
            ("targetable", "complete", ("target",), ("obligation",), ()),
            ("targetable", "partial", ("target",), ("obligation",), ("gap",)),
        )
        for values in valid:
            with self.subTest(values=values):
                self.assertTrue(ProjectionAssessment("decision", *values).identity)
        invalid = (
            (("other", "unsupported", (), (), ()),
             "PROJECTION_ASSESSMENT_STATUS_INVALID"),
            (("unsupported", "complete", (), (), ()),
             "UNSUPPORTED_PROJECTION_ASSESSMENT_INVALID"),
            (("unsupported", "unsupported", ("target",), (), ()),
             "UNSUPPORTED_PROJECTION_ASSESSMENT_INVALID"),
            (("unsupported", "unsupported", (), ("obligation",), ()),
             "UNSUPPORTED_PROJECTION_ASSESSMENT_INVALID"),
            (("targetable", "unsupported", ("target",), ("obligation",), ()),
             "TARGETABLE_PROJECTION_COVERAGE_INVALID"),
            (("targetable", "complete", (), ("obligation",), ()),
             "TARGETABLE_PROJECTION_OBLIGATION_MISSING"),
            (("targetable", "complete", ("target",), (), ()),
             "TARGETABLE_PROJECTION_OBLIGATION_MISSING"),
            (("targetable", "partial", ("target",), ("obligation",), ()),
             "PARTIAL_PROJECTION_SCOPE_MISSING"),
            (("targetable", "complete", ("target",), ("obligation",), ("gap",)),
             "COMPLETE_PROJECTION_HAS_PARTIAL_SCOPE"),
        )
        for values, reason in invalid:
            with self.subTest(values=values):
                self.assert_reason(
                    reason,
                    lambda values=values: ProjectionAssessment("decision", *values),
                )

    def test_active_snapshot_layer_members_and_supersession_graph_matrix(self):
        self.assert_reason(
            "ACTIVE_SNAPSHOT_LAYER_INVALID",
            lambda: ActiveSnapshot("other", "context", ()),
        )
        self.assert_reason(
            "ACTIVE_SNAPSHOT_MEMBER_DUPLICATE",
            lambda: ActiveSnapshot("decision", "context", ("a", "a")),
        )
        parent = ActiveSnapshot("decision", "context", ("a",))
        child = ActiveSnapshot("decision", "context", ("b",), parent.identity)
        external = ActiveSnapshot("decision", "context", ("c",), "outside")
        self.assertTrue(validate_snapshot_supersession(()))
        self.assertTrue(validate_snapshot_supersession((parent, child, external)))

        duplicate = ActiveSnapshot("decision", "context", ("a",))
        self.assert_reason(
            "ACTIVE_SNAPSHOT_IDENTITY_DUPLICATE",
            lambda: validate_snapshot_supersession((parent, duplicate)),
        )

        first = ActiveSnapshot("decision", "context", ("first",))
        second = ActiveSnapshot("decision", "context", ("second",))
        object.__setattr__(first, "supersedes_snapshot_identity", second.identity)
        object.__setattr__(second, "supersedes_snapshot_identity", first.identity)
        self.assert_reason(
            "ACTIVE_SNAPSHOT_SUPERSESSION_CYCLE",
            lambda: validate_snapshot_supersession((first, second)),
        )

        wrong_layer = ActiveSnapshot(
            "assessment", "context", ("assessment",), parent.identity
        )
        self.assert_reason(
            "ACTIVE_SNAPSHOT_SUPERSESSION_DOMAIN_INVALID",
            lambda: validate_snapshot_supersession((parent, wrong_layer)),
        )
        wrong_context = ActiveSnapshot(
            "decision", "other-context", ("other",), parent.identity
        )
        self.assert_reason(
            "ACTIVE_SNAPSHOT_SUPERSESSION_DOMAIN_INVALID",
            lambda: validate_snapshot_supersession((parent, wrong_context)),
        )

    @staticmethod
    def generation_snapshots(context="context"):
        return {
            layer: ActiveSnapshot(layer, context, ())
            for layer in ActiveSnapshot.VALID_LAYERS
        }

    def test_result_generation_snapshot_and_sidecar_matrix(self):
        snapshots = self.generation_snapshots()
        self.assertTrue(ResultGeneration(
            "context", snapshots, "trace", {"facts": "sha"}, {"policy": "id"}
        ).identity)

        wrong_layer = dict(snapshots)
        wrong_layer["decision"] = ActiveSnapshot("assessment", "context", ())
        self.assert_reason(
            "RESULT_GENERATION_SNAPSHOT_CONTEXT_INVALID",
            lambda: ResultGeneration("context", wrong_layer, "trace", {}, {}),
        )
        wrong_context = dict(snapshots)
        wrong_context["decision"] = ActiveSnapshot("decision", "other", ())
        self.assert_reason(
            "RESULT_GENERATION_SNAPSHOT_CONTEXT_INVALID",
            lambda: ResultGeneration("context", wrong_context, "trace", {}, {}),
        )
        invalid_sidecars = (
            {"": "sha"},
            {"facts": ""},
            {"facts": None},
            {"facts": "/tmp/facts.json"},
            {"facts": "~/facts.json"},
        )
        for sidecars in invalid_sidecars:
            with self.subTest(sidecars=sidecars):
                self.assert_reason(
                    "RESULT_GENERATION_SIDECAR_IDENTITY_INVALID",
                    lambda sidecars=sidecars: ResultGeneration(
                        "context", snapshots, "trace", sidecars, {}
                    ),
                )

    def test_decision_conservation_all_duplicate_owner_and_extra_paths(self):
        decision = Decision(
            "delta", "context", "authoritative",
            {"change_fact_status": "confirmed"},
        )
        obligation = decision.obligation_identity
        self.assertTrue(validate_decision_conservation(
            disposition_obligation_identities=(obligation,),
            decisions=(decision,),
        ))
        self.assertTrue(validate_decision_conservation(
            disposition_obligation_identities=("audit",),
            decisions=(),
            audit_only_obligation_identities=("audit",),
        ))
        cases = (
            ({
                "disposition_obligation_identities": (obligation, obligation),
                "decisions": (decision,),
            }, "DISPOSITION_OBLIGATION_DUPLICATE"),
            ({
                "disposition_obligation_identities": ("audit",),
                "decisions": (),
                "audit_only_obligation_identities": ("audit", "audit"),
            }, "AUDIT_ONLY_OBLIGATION_DUPLICATE"),
            ({
                "disposition_obligation_identities": ("missing",),
                "decisions": (),
            }, "DISPOSITION_OBLIGATION_CONSERVATION_FAILED"),
            ({
                "disposition_obligation_identities": (obligation,),
                "decisions": (decision,),
                "audit_only_obligation_identities": (obligation,),
            }, "DISPOSITION_OBLIGATION_CONSERVATION_FAILED"),
            ({
                "disposition_obligation_identities": (),
                "decisions": (decision,),
            }, "DISPOSITION_OWNER_WITHOUT_OBLIGATION"),
            ({
                "disposition_obligation_identities": (),
                "decisions": (),
                "audit_only_obligation_identities": ("extra",),
            }, "DISPOSITION_OWNER_WITHOUT_OBLIGATION"),
        )
        for arguments, reason in cases:
            with self.subTest(reason=reason, arguments=arguments):
                self.assert_reason(
                    reason,
                    lambda arguments=arguments: validate_decision_conservation(
                        **arguments
                    ),
                )

    def test_projection_conservation_unsupported_duplicate_and_targetable_matrix(self):
        unsupported = ProjectionAssessment(
            "decision", "unsupported", "unsupported", (), (), ()
        )
        self.assertTrue(validate_projection_conservation(
            assessment=unsupported, projection_obligation_keys=()
        ))
        self.assert_reason(
            "UNSUPPORTED_PROJECTION_PRESENT",
            lambda: validate_projection_conservation(
                assessment=unsupported,
                projection_obligation_keys=("unexpected",),
            ),
        )
        targetable = ProjectionAssessment(
            "decision", "targetable", "complete", ("target",),
            ("obligation",), (),
        )
        self.assertTrue(validate_projection_conservation(
            assessment=targetable,
            projection_obligation_keys=("obligation",),
        ))
        self.assert_reason(
            "PROJECTION_OBLIGATION_DUPLICATE",
            lambda: validate_projection_conservation(
                assessment=targetable,
                projection_obligation_keys=("obligation", "obligation"),
            ),
        )
        self.assert_reason(
            "PROJECTION_OBLIGATION_CONSERVATION_FAILED",
            lambda: validate_projection_conservation(
                assessment=targetable,
                projection_obligation_keys=("extra",),
            ),
        )


if __name__ == "__main__":
    unittest.main()
