#!/usr/bin/env python3
"""Immutable identities and ledgers for the binary-first analysis pipeline.

The binary pipeline keeps runtime facts, analysis capabilities, decisions,
projections, traces, and report generations in separate identity domains.  The
validators in this module are deliberately storage-agnostic so the same rules
can guard JSON sidecars, SQLite rows, and tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from binary_first_contract import (
    BinaryFirstContractError,
    analysis_context_identity,
    canonical_identity,
    disposition_obligation_identity,
    projection_obligation_key,
)


UNKNOWN = "unknown"
ABSENT = "ABSENT"

PAIRING_STATUSES = frozenset({"exact", "base_only", "current_only", "ambiguous"})
DECISION_CHANNELS = frozenset({"authoritative", "diagnostic", "excluded"})
PROVIDER_STATUSES = frozenset({
    "resolved",
    "equivalent_code_only",
    "runtime_equivalent",
    "ambiguous",
    "missing",
    "unresolved",
})
CLASS_DEFINITION_STATUSES = frozenset({
    "definition_ready",
    "runtime_equivalent",
    "unsupported_class_version",
    "class_format_error",
    "verification_failed",
    "dependency_linkage_failed",
    "module_access_failed",
    "security_failed",
    "ambiguous",
    "unsupported",
})
MEMBER_RESOLUTION_STATUSES = frozenset({
    "resolved",
    "runtime_equivalent",
    "no_class_definition",
    "class_definition_failed",
    "no_such_member",
    "illegal_access",
    "incompatible_class_change",
    "ambiguous",
    "unsupported",
})
DISPATCH_STATUSES = frozenset({
    "not_applicable",
    "exact",
    "proven_receiver",
    "possible",
    "partial_possible_set",
    "no_concrete_implementation",
    "unresolved",
})
MEMBERSHIP_STATUSES = frozenset({
    "traversal_eligible",
    "shadowed",
    "definition_failed",
    "ambiguous",
    "unsupported",
})


def _required_text(payload: Mapping[str, Any], key: str) -> str:
    value = str(payload.get(key) or "").strip()
    if not value:
        raise BinaryFirstContractError(
            "BINARY_IDENTITY_FIELD_MISSING",
            f"{key} is required",
        )
    return value


def _coverage(payload: Mapping[str, Any], required_fields: Iterable[str]) -> dict[str, str]:
    raw = payload.get("field_coverage")
    if not isinstance(raw, Mapping):
        raise BinaryFirstContractError(
            "BINARY_FIELD_COVERAGE_MISSING",
            "field_coverage must explicitly describe every required identity field",
        )
    coverage = {str(key): str(value or "").strip() for key, value in raw.items()}
    missing = sorted(set(required_fields) - set(coverage))
    invalid = sorted(
        key for key, value in coverage.items()
        if value not in {"known", "unknown", "not_applicable"}
    )
    if missing or invalid:
        raise BinaryFirstContractError(
            "BINARY_FIELD_COVERAGE_INVALID",
            f"missing={missing}; invalid={invalid}",
        )
    return coverage


def _identity(namespace: str, payload: Mapping[str, Any], version: str = "1") -> str:
    return canonical_identity(namespace, dict(payload), schema_version=version)


@dataclass(frozen=True)
class RuntimeProfile:
    payload: Mapping[str, Any]
    policy_identity: str = field(init=False)
    identity: str = field(init=False)

    REQUIRED_FIELDS = (
        "target_jvm",
        "runtime_platform_image_identity",
        "target_os",
        "target_arch",
        "container_and_launcher_kind",
        "ordered_runtime_path_entry_descriptors",
        "loader_topology",
        "runtime_code_source_origin_mapping_identity",
        "runtime_security_and_package_sealing_policy_identity",
        "active_profile_identities",
        "external_config_snapshot_identities",
        "agent_transformer_plugin_profile_identities",
        "business_entrypoint_profile",
        "runtime_class_closure_coverage_status",
        "resource_selection_coverage_status",
    )

    def __post_init__(self):
        payload = dict(self.payload or {})
        coverage = _coverage(payload, self.REQUIRED_FIELDS)
        path_entries = payload.get("ordered_runtime_path_entry_descriptors")
        if not isinstance(path_entries, list):
            raise BinaryFirstContractError(
                "RUNTIME_PROFILE_PATH_INVALID",
                "ordered runtime path entries must be a list",
            )
        for item in path_entries:
            if not isinstance(item, Mapping):
                raise BinaryFirstContractError(
                    "RUNTIME_PROFILE_PATH_INVALID", "runtime path entry must be an object"
                )
            location = str(item.get("logical_location") or "").strip()
            if not location or location.startswith(("/", "~")) or ":\\" in location:
                raise BinaryFirstContractError(
                    "RUNTIME_PROFILE_PATH_NOT_REPRODUCIBLE",
                    "runtime path logical locations must be relative and reproducible",
                )
            _required_text(item, "content_sha256")
            _required_text(item, "path_kind")
            if "slot" not in item:
                raise BinaryFirstContractError(
                    "RUNTIME_PROFILE_PATH_SLOT_MISSING", "runtime path slot is required"
                )
        policy_payload = {
            key: payload.get(key)
            for key in self.REQUIRED_FIELDS
            if key != "ordered_runtime_path_entry_descriptors"
        }
        policy_payload["ordered_runtime_path_roles"] = [
            {
                "logical_location": item.get("logical_location"),
                "path_kind": item.get("path_kind"),
                "slot": item.get("slot"),
                "loader_realm": item.get("loader_realm"),
            }
            for item in path_entries
        ]
        policy_payload["field_coverage"] = coverage
        object.__setattr__(
            self,
            "policy_identity",
            _identity("runtime_profile_policy_identity", policy_payload),
        )
        snapshot_payload = {
            **{key: payload.get(key) for key in self.REQUIRED_FIELDS},
            "field_coverage": coverage,
            "runtime_profile_policy_identity": self.policy_identity,
        }
        object.__setattr__(
            self,
            "identity",
            _identity("runtime_profile_identity", snapshot_payload),
        )

    @property
    def complete(self) -> bool:
        coverage = dict(self.payload.get("field_coverage") or {})
        return all(coverage.get(key) in {"known", "not_applicable"} for key in self.REQUIRED_FIELDS)


@dataclass(frozen=True)
class RuntimeComparison:
    base: RuntimeProfile
    current: RuntimeProfile
    comparison_intent: str
    profile_correspondence_policy_version: str
    controlled_profile_fields: tuple[str, ...]
    declared_upgrade_payload_scope: tuple[str, ...]
    changed_or_unknown_profile_fields: tuple[str, ...]
    identity: str = field(init=False)

    def __post_init__(self):
        if self.comparison_intent not in {"same_deployment_profile", "release_snapshot"}:
            raise BinaryFirstContractError(
                "RUNTIME_COMPARISON_INTENT_INVALID", self.comparison_intent
            )
        if (
            self.comparison_intent == "same_deployment_profile"
            and (
                self.base.policy_identity != self.current.policy_identity
                or self.changed_or_unknown_profile_fields
            )
        ):
            raise BinaryFirstContractError(
                "RUNTIME_PROFILE_CORRESPONDENCE_INVALID",
                "same_deployment_profile requires identical known policy fields",
            )
        payload = {
            "base_runtime_profile_identity": self.base.identity,
            "current_runtime_profile_identity": self.current.identity,
            "comparison_intent": self.comparison_intent,
            "profile_correspondence_policy_version": self.profile_correspondence_policy_version,
            "controlled_profile_fields": list(self.controlled_profile_fields),
            "declared_upgrade_payload_scope": list(self.declared_upgrade_payload_scope),
            "changed_or_unknown_profile_fields": list(self.changed_or_unknown_profile_fields),
        }
        object.__setattr__(self, "identity", _identity("runtime_comparison_identity", payload))


@dataclass(frozen=True)
class AnalysisScope:
    payload: Mapping[str, Any]
    identity: str = field(init=False)

    REQUIRED_FIELDS = (
        "analysis_observability_scope",
        "artifact_diff_support_manifest_identity",
        "runtime_loader_support_manifest_identity",
        "class_definition_support_manifest_identity",
        "runtime_fact_semantic_capability_identity",
        "runtime_fact_dynamic_capability_identity",
        "runtime_fact_transformer_capability_identity",
        "environment_equivalence_capability_identity",
    )

    def __post_init__(self):
        payload = dict(self.payload or {})
        coverage = _coverage(payload, self.REQUIRED_FIELDS)
        forbidden = {
            "runtime_profile_identity",
            "runtime_comparison_identity",
            "oracle_support_manifest_identity",
            "projection_registry_identity",
            "validation_policy_identity",
        }
        present = sorted(forbidden & set(payload))
        if present:
            raise BinaryFirstContractError(
                "ANALYSIS_SCOPE_DOMAIN_VIOLATION",
                f"analysis scope contains forbidden identity domains: {present}",
            )
        identity_payload = {
            key: payload.get(key) for key in self.REQUIRED_FIELDS
        }
        identity_payload["field_coverage"] = coverage
        object.__setattr__(self, "identity", _identity("analysis_scope_identity", identity_payload))


@dataclass(frozen=True)
class AnalysisContext:
    runtime_comparison: RuntimeComparison
    analysis_scope: AnalysisScope
    identity: str = field(init=False)

    def __post_init__(self):
        object.__setattr__(
            self,
            "identity",
            analysis_context_identity(
                self.runtime_comparison.identity,
                self.analysis_scope.identity,
            ),
        )


@dataclass(frozen=True)
class ArtifactInstance:
    outer_artifact_sha256: str
    container_entry: str
    content_sha256: str
    runtime_profile_identity: str
    path_owner_loader_realm_identity: str
    runtime_path_kind: str
    runtime_classpath_index: int
    container_loader_policy_version: str
    runtime_code_source_origin_identity: str
    coord: str = ""
    identity: str = field(init=False)

    def __post_init__(self):
        if self.runtime_path_kind not in {
            "business_classes", "classpath", "module_path", "nested_runtime"
        }:
            raise BinaryFirstContractError(
                "ARTIFACT_INSTANCE_PATH_KIND_INVALID", self.runtime_path_kind
            )
        if self.runtime_classpath_index < 0:
            raise BinaryFirstContractError(
                "ARTIFACT_INSTANCE_SLOT_INVALID", "runtime classpath index must be non-negative"
            )
        payload = {
            "outer_artifact_sha256": self.outer_artifact_sha256,
            "container_entry": self.container_entry,
            "content_sha256": self.content_sha256,
            "runtime_profile_identity": self.runtime_profile_identity,
            "path_owner_loader_realm_identity": self.path_owner_loader_realm_identity,
            "runtime_path_kind": self.runtime_path_kind,
            "runtime_classpath_index": self.runtime_classpath_index,
            "container_loader_policy_version": self.container_loader_policy_version,
            "runtime_code_source_origin_identity": self.runtime_code_source_origin_identity,
        }
        for key, value in payload.items():
            if value in {None, ""}:
                raise BinaryFirstContractError(
                    "ARTIFACT_INSTANCE_FIELD_MISSING", f"{key} is required"
                )
        object.__setattr__(self, "identity", _identity("artifact_instance_identity", payload))


@dataclass(frozen=True)
class CrossVersionArtifactPairing:
    status: str
    logical_dependency_lineage: str
    base_runtime_scope_identity: str
    current_runtime_scope_identity: str
    pairing_evidence: tuple[Mapping[str, Any], ...]
    pairing_policy_version: str
    base_artifact_instance_identity: str = ""
    current_artifact_instance_identity: str = ""
    identity: str = field(init=False)

    def __post_init__(self):
        if self.status not in PAIRING_STATUSES:
            raise BinaryFirstContractError("ARTIFACT_PAIRING_STATUS_INVALID", self.status)
        base_present = bool(self.base_artifact_instance_identity)
        current_present = bool(self.current_artifact_instance_identity)
        expected = {
            "exact": (True, True),
            "base_only": (True, False),
            "current_only": (False, True),
            "ambiguous": (False, False),
        }[self.status]
        if (base_present, current_present) != expected:
            raise BinaryFirstContractError(
                "ARTIFACT_PAIRING_CARDINALITY_INVALID",
                f"{self.status} requires base/current presence {expected}",
            )
        if not self.pairing_evidence:
            raise BinaryFirstContractError(
                "ARTIFACT_PAIRING_EVIDENCE_MISSING", "pairing evidence is required"
            )
        payload = {
            "pairing_status": self.status,
            "logical_dependency_lineage": self.logical_dependency_lineage,
            "base_runtime_scope_identity": self.base_runtime_scope_identity,
            "current_runtime_scope_identity": self.current_runtime_scope_identity,
            "base_artifact_instance_identity": self.base_artifact_instance_identity or ABSENT,
            "current_artifact_instance_identity": self.current_artifact_instance_identity or ABSENT,
            "pairing_evidence": list(self.pairing_evidence),
            "pairing_policy_version": self.pairing_policy_version,
        }
        object.__setattr__(self, "identity", _identity("cross_version_artifact_pairing", payload))


@dataclass(frozen=True)
class BuildIdentityBundle:
    build_environment: Mapping[str, Any]
    build_input_manifest: Mapping[str, Any]
    artifact_build_provenance: Mapping[str, Any]
    environment_identity: str = field(init=False)
    input_identity: str = field(init=False)
    provenance_identity: str = field(init=False)

    def __post_init__(self):
        environment = dict(self.build_environment or {})
        build_input = dict(self.build_input_manifest or {})
        provenance = dict(self.artifact_build_provenance or {})
        if "source_revision" in environment or "source_state_identity" in environment:
            raise BinaryFirstContractError(
                "BUILD_ENVIRONMENT_DOMAIN_VIOLATION",
                "source revision/state belongs to provenance or declared semantic input",
            )
        environment_identity = _identity("build_environment_identity", environment)
        input_identity = _identity("build_input_manifest_identity", build_input)
        input_mode = str(provenance.get("input_mode") or "").strip()
        if input_mode not in {"checkout_build", "provided_artifact"}:
            raise BinaryFirstContractError("BUILD_INPUT_MODE_INVALID", input_mode)
        executed = bool(provenance.get("build_executed_by_system"))
        status = str(provenance.get("build_execution_status") or "").strip()
        if input_mode == "provided_artifact" and (executed or status != "not_executed"):
            raise BinaryFirstContractError(
                "PROVIDED_ARTIFACT_BUILD_EXECUTION_INVALID",
                "provided artifacts must not claim analyzer build execution",
            )
        if input_mode == "checkout_build" and not executed:
            raise BinaryFirstContractError(
                "CHECKOUT_BUILD_EXECUTION_MISSING",
                "checkout build provenance must record analyzer execution",
            )
        provenance_payload = {
            **provenance,
            "build_environment_identity": (
                environment_identity if environment else UNKNOWN
            ),
            "build_input_manifest_identity": (
                input_identity if build_input else UNKNOWN
            ),
        }
        object.__setattr__(self, "environment_identity", environment_identity)
        object.__setattr__(self, "input_identity", input_identity)
        object.__setattr__(
            self,
            "provenance_identity",
            _identity("artifact_build_provenance_identity", provenance_payload),
        )


@dataclass(frozen=True)
class FactBuildInputSlice:
    artifact_build_provenance_identity: str
    artifact_content_identities: tuple[str, ...]
    runtime_profile_identity: str
    parser_identity: str
    derivation_policy_version: str = "binary-fact-build-input-slice-v1"
    identity: str = field(init=False)

    def __post_init__(self):
        if (
            not self.artifact_build_provenance_identity
            or not self.artifact_content_identities
            or not self.runtime_profile_identity
            or not self.parser_identity
        ):
            raise BinaryFirstContractError(
                "FACT_BUILD_INPUT_SLICE_INCOMPLETE",
                "provenance, artifact content, runtime profile and parser identities are required",
            )
        object.__setattr__(self, "identity", _identity(
            "fact_build_input_slice_identity",
            {
                "artifact_build_provenance_identity": self.artifact_build_provenance_identity,
                "artifact_content_identities": list(self.artifact_content_identities),
                "runtime_profile_identity": self.runtime_profile_identity,
                "parser_identity": self.parser_identity,
                "derivation_policy_version": self.derivation_policy_version,
            },
        ))


@dataclass(frozen=True)
class ProviderBinding:
    payload: Mapping[str, Any]
    identity: str = field(init=False)

    def __post_init__(self):
        payload = dict(self.payload or {})
        status = str(payload.get("class_provider_status") or "")
        if status not in PROVIDER_STATUSES:
            raise BinaryFirstContractError("CLASS_PROVIDER_STATUS_INVALID", status)
        selected_fields = (
            "selected_defining_loader_realm_identity",
            "selected_artifact_instance_identity",
            "selected_class_variant_identity",
        )
        if status == "resolved":
            for key in selected_fields:
                _required_text(payload, key)
            if payload.get("provider_equivalence_set_identity"):
                raise BinaryFirstContractError(
                    "CLASS_PROVIDER_EQUIVALENCE_INVALID",
                    "resolved provider cannot also use an equivalence set",
                )
        elif status == "runtime_equivalent":
            _required_text(payload, "provider_equivalence_set_identity")
            if any(payload.get(key) for key in selected_fields):
                raise BinaryFirstContractError(
                    "CLASS_PROVIDER_SELECTION_INVALID",
                    "runtime-equivalent provider must not choose a physical instance",
                )
        elif any(payload.get(key) for key in selected_fields):
            raise BinaryFirstContractError(
                "CLASS_PROVIDER_SELECTION_INVALID",
                f"{status} provider must not choose a physical instance",
            )
        object.__setattr__(self, "identity", _identity("class_provider_binding", payload))


@dataclass(frozen=True)
class ClassDefinitionResolution:
    provider_binding_identity: str
    target_identity: str
    status: str
    evidence: Mapping[str, Any]
    identity: str = field(init=False)

    def __post_init__(self):
        if self.status not in CLASS_DEFINITION_STATUSES:
            raise BinaryFirstContractError("CLASS_DEFINITION_STATUS_INVALID", self.status)
        if not self.evidence:
            raise BinaryFirstContractError(
                "CLASS_DEFINITION_EVIDENCE_MISSING", "class definition evidence is required"
            )
        payload = {
            "class_provider_binding_identity": self.provider_binding_identity,
            "class_definition_target_identity": self.target_identity,
            "class_definition_status": self.status,
            "evidence": dict(self.evidence),
        }
        object.__setattr__(self, "identity", _identity("class_definition_resolution", payload))


@dataclass(frozen=True)
class MemberResolution:
    payload: Mapping[str, Any]
    identity: str = field(init=False)

    def __post_init__(self):
        payload = dict(self.payload or {})
        status = str(payload.get("member_resolution_status") or "")
        if status not in MEMBER_RESOLUTION_STATUSES:
            raise BinaryFirstContractError("MEMBER_RESOLUTION_STATUS_INVALID", status)
        resolved = payload.get("resolved_member_identity")
        equivalent = payload.get("member_equivalence_set_identity")
        if status == "resolved" and (not resolved or equivalent):
            raise BinaryFirstContractError(
                "MEMBER_RESOLUTION_TARGET_INVALID", "resolved requires exactly one member"
            )
        if status == "runtime_equivalent" and (not equivalent or resolved):
            raise BinaryFirstContractError(
                "MEMBER_RESOLUTION_TARGET_INVALID",
                "runtime_equivalent requires a member equivalence set",
            )
        if status not in {"resolved", "runtime_equivalent"} and (resolved or equivalent):
            raise BinaryFirstContractError(
                "MEMBER_RESOLUTION_TARGET_INVALID", f"{status} cannot select a member"
            )
        object.__setattr__(self, "identity", _identity("member_resolution", payload))


@dataclass(frozen=True)
class DispatchResolution:
    direct_edge_identity: str
    status: str
    implementation_target_identities: tuple[str, ...]
    coverage_status: str
    evidence: Mapping[str, Any]
    identity: str = field(init=False)

    def __post_init__(self):
        if self.status not in DISPATCH_STATUSES:
            raise BinaryFirstContractError("DISPATCH_STATUS_INVALID", self.status)
        target_count = len(self.implementation_target_identities)
        if self.status in {"unresolved", "no_concrete_implementation", "not_applicable"}:
            if target_count:
                raise BinaryFirstContractError(
                    "DISPATCH_TARGET_COUNT_INVALID", f"{self.status} requires zero targets"
                )
        elif target_count == 0:
            raise BinaryFirstContractError(
                "DISPATCH_TARGET_COUNT_INVALID", f"{self.status} requires targets"
            )
        if self.status == "partial_possible_set" and self.coverage_status != "partial":
            raise BinaryFirstContractError(
                "DISPATCH_COVERAGE_INVALID", "partial_possible_set requires partial coverage"
            )
        if self.status == "no_concrete_implementation" and self.coverage_status != "complete":
            raise BinaryFirstContractError(
                "DISPATCH_COVERAGE_INVALID",
                "no_concrete_implementation requires complete hierarchy coverage",
            )
        payload = {
            "direct_edge_identity": self.direct_edge_identity,
            "dispatch_status": self.status,
            "implementation_target_identities": list(self.implementation_target_identities),
            "coverage_status": self.coverage_status,
            "evidence": dict(self.evidence),
        }
        object.__setattr__(self, "identity", _identity("dispatch_resolution", payload))


@dataclass(frozen=True)
class Decision:
    observed_delta_identity: str
    analysis_context_identity: str
    channel: str
    payload: Mapping[str, Any]
    obligation_identity: str = field(init=False)
    identity: str = field(init=False)

    def __post_init__(self):
        if self.channel not in DECISION_CHANNELS:
            raise BinaryFirstContractError("DECISION_CHANNEL_INVALID", self.channel)
        payload = dict(self.payload or {})
        channel_fields = {
            "authoritative": ("change_fact_status", "confirmed"),
            "diagnostic": ("candidate_fact_status", {"candidate", "incomplete"}),
            "excluded": ("exclusion_status", "excluded"),
        }
        key, expected = channel_fields[self.channel]
        value = payload.get(key)
        if (isinstance(expected, set) and value not in expected) or (
            not isinstance(expected, set) and value != expected
        ):
            raise BinaryFirstContractError(
                "DECISION_CHANNEL_PAYLOAD_INVALID", f"{self.channel} requires {key}={expected}"
            )
        forbidden = {
            "authoritative": {"candidate_fact_status", "exclusion_status"},
            "diagnostic": {"change_fact_status", "exclusion_status"},
            "excluded": {"change_fact_status", "candidate_fact_status"},
        }[self.channel]
        if forbidden & set(payload):
            raise BinaryFirstContractError(
                "DECISION_CHANNEL_OVERLAP", f"{self.channel} payload crosses decision channels"
            )
        obligation = disposition_obligation_identity(
            self.observed_delta_identity,
            self.analysis_context_identity,
        )
        object.__setattr__(self, "obligation_identity", obligation)
        object.__setattr__(
            self,
            "identity",
            _identity(
                f"{self.channel}_decision_identity",
                {
                    "disposition_obligation_identity": obligation,
                    "payload": payload,
                },
            ),
        )


@dataclass(frozen=True)
class ProjectionAssessment:
    decision_identity: str
    status: str
    coverage_status: str
    target_identities: tuple[str, ...]
    obligation_keys: tuple[str, ...]
    uncovered_scopes: tuple[str, ...]
    identity: str = field(init=False)

    def __post_init__(self):
        if self.status not in {"targetable", "unsupported"}:
            raise BinaryFirstContractError("PROJECTION_ASSESSMENT_STATUS_INVALID", self.status)
        if self.status == "unsupported":
            if self.coverage_status != "unsupported" or self.target_identities or self.obligation_keys:
                raise BinaryFirstContractError(
                    "UNSUPPORTED_PROJECTION_ASSESSMENT_INVALID",
                    "unsupported assessment cannot contain targets or obligations",
                )
        else:
            if self.coverage_status not in {"complete", "partial"}:
                raise BinaryFirstContractError(
                    "TARGETABLE_PROJECTION_COVERAGE_INVALID", self.coverage_status
                )
            if not self.target_identities or not self.obligation_keys:
                raise BinaryFirstContractError(
                    "TARGETABLE_PROJECTION_OBLIGATION_MISSING",
                    "targetable assessment requires targets and obligations",
                )
            if self.coverage_status == "partial" and not self.uncovered_scopes:
                raise BinaryFirstContractError(
                    "PARTIAL_PROJECTION_SCOPE_MISSING", "partial assessment needs uncovered scopes"
                )
            if self.coverage_status == "complete" and self.uncovered_scopes:
                raise BinaryFirstContractError(
                    "COMPLETE_PROJECTION_HAS_PARTIAL_SCOPE", "complete assessment has uncovered scopes"
                )
        payload = {
            "decision_identity": self.decision_identity,
            "analysis_projection_status": self.status,
            "projection_coverage_status": self.coverage_status,
            "target_identities": list(self.target_identities),
            "projection_obligation_keys": list(self.obligation_keys),
            "uncovered_scopes": list(self.uncovered_scopes),
        }
        object.__setattr__(self, "identity", _identity("projection_assessment", payload))


def build_projection_obligations(
    *,
    projection_rule_contract_identity: str,
    targets_by_required_edge_family: Mapping[str, Iterable[str]],
) -> tuple[str, ...]:
    obligations = []
    for edge_family, targets in sorted(targets_by_required_edge_family.items()):
        for target in sorted(set(targets)):
            obligations.append(projection_obligation_key(
                projection_rule_contract_identity,
                target,
                edge_family,
            ))
    return tuple(obligations)


@dataclass(frozen=True)
class ActiveSnapshot:
    layer: str
    analysis_context_identity: str
    member_identities: tuple[str, ...]
    supersedes_snapshot_identity: str = ""
    identity: str = field(init=False)
    member_digest: str = field(init=False)

    VALID_LAYERS = frozenset({
        "decision",
        "assessment",
        "formal_projection",
        "candidate_projection",
    })

    def __post_init__(self):
        if self.layer not in self.VALID_LAYERS:
            raise BinaryFirstContractError("ACTIVE_SNAPSHOT_LAYER_INVALID", self.layer)
        members = tuple(sorted(set(self.member_identities)))
        if len(members) != len(self.member_identities):
            raise BinaryFirstContractError(
                "ACTIVE_SNAPSHOT_MEMBER_DUPLICATE", f"duplicate member in {self.layer} snapshot"
            )
        member_digest = _identity(
            f"{self.layer}_snapshot_members", {"members": list(members)}
        )
        payload = {
            "layer": self.layer,
            "analysis_context_identity": self.analysis_context_identity,
            "member_digest": member_digest,
            "member_count": len(members),
            "supersedes_snapshot_identity": self.supersedes_snapshot_identity or ABSENT,
        }
        object.__setattr__(self, "member_digest", member_digest)
        object.__setattr__(self, "identity", _identity("active_snapshot_identity", payload))


def validate_snapshot_supersession(snapshots: Iterable[ActiveSnapshot]) -> bool:
    snapshot_items = tuple(snapshots)
    by_identity = {item.identity: item for item in snapshot_items}
    if len(by_identity) != len(snapshot_items):
        raise BinaryFirstContractError(
            "ACTIVE_SNAPSHOT_IDENTITY_DUPLICATE", "snapshot identities must be unique"
        )
    for snapshot in by_identity.values():
        seen = {snapshot.identity}
        parent = snapshot.supersedes_snapshot_identity
        while parent:
            if parent in seen:
                raise BinaryFirstContractError(
                    "ACTIVE_SNAPSHOT_SUPERSESSION_CYCLE", "snapshot supersession must be acyclic"
                )
            seen.add(parent)
            parent_snapshot = by_identity.get(parent)
            if parent_snapshot is None:
                break
            if (
                parent_snapshot.layer != snapshot.layer
                or parent_snapshot.analysis_context_identity
                != snapshot.analysis_context_identity
            ):
                raise BinaryFirstContractError(
                    "ACTIVE_SNAPSHOT_SUPERSESSION_DOMAIN_INVALID",
                    "snapshot supersession cannot cross layer or analysis context",
                )
            parent = parent_snapshot.supersedes_snapshot_identity
    return True


@dataclass(frozen=True)
class ResultGeneration:
    analysis_context_identity: str
    snapshots: Mapping[str, ActiveSnapshot]
    trace_result_set_digest: str
    sidecar_content_identities: Mapping[str, str]
    policy_identities: Mapping[str, str]
    identity: str = field(init=False)

    def __post_init__(self):
        required_layers = ActiveSnapshot.VALID_LAYERS
        if set(self.snapshots) != required_layers:
            raise BinaryFirstContractError(
                "RESULT_GENERATION_SNAPSHOT_SET_INVALID",
                f"required={sorted(required_layers)} actual={sorted(self.snapshots)}",
            )
        for layer, snapshot in self.snapshots.items():
            if snapshot.layer != layer or snapshot.analysis_context_identity != self.analysis_context_identity:
                raise BinaryFirstContractError(
                    "RESULT_GENERATION_SNAPSHOT_CONTEXT_INVALID",
                    f"snapshot {layer} belongs to another layer/context",
                )
        for name, value in self.sidecar_content_identities.items():
            if not name or not value or str(value).startswith(("/", "~")):
                raise BinaryFirstContractError(
                    "RESULT_GENERATION_SIDECAR_IDENTITY_INVALID",
                    "sidecars must be bound by stable content identity, never temporary path",
                )
        payload = {
            "analysis_context_identity": self.analysis_context_identity,
            "authority": "binary_first",
            "snapshot_identities": {
                layer: snapshot.identity for layer, snapshot in sorted(self.snapshots.items())
            },
            "trace_result_set_digest": self.trace_result_set_digest,
            "sidecar_content_identities": dict(self.sidecar_content_identities),
            "policy_identities": dict(self.policy_identities),
        }
        object.__setattr__(self, "identity", _identity("result_generation_identity", payload))


def validate_decision_conservation(
    *,
    disposition_obligation_identities: Iterable[str],
    decisions: Iterable[Decision],
    audit_only_obligation_identities: Iterable[str] = (),
) -> bool:
    obligations = tuple(disposition_obligation_identities)
    if len(set(obligations)) != len(obligations):
        raise BinaryFirstContractError(
            "DISPOSITION_OBLIGATION_DUPLICATE", "disposition obligations must be unique"
        )
    decision_owners: dict[str, list[str]] = {}
    for decision in decisions:
        decision_owners.setdefault(decision.obligation_identity, []).append(decision.identity)
    audit = tuple(audit_only_obligation_identities)
    if len(set(audit)) != len(audit):
        raise BinaryFirstContractError(
            "AUDIT_ONLY_OBLIGATION_DUPLICATE", "audit-only obligations must be unique"
        )
    for obligation in obligations:
        owner_count = len(decision_owners.get(obligation, ())) + int(obligation in audit)
        if owner_count != 1:
            raise BinaryFirstContractError(
                "DISPOSITION_OBLIGATION_CONSERVATION_FAILED",
                f"{obligation} has {owner_count} active owners",
            )
    extras = (set(decision_owners) | set(audit)) - set(obligations)
    if extras:
        raise BinaryFirstContractError(
            "DISPOSITION_OWNER_WITHOUT_OBLIGATION", f"unknown obligations: {sorted(extras)}"
        )
    return True


def validate_projection_conservation(
    *,
    assessment: ProjectionAssessment,
    projection_obligation_keys: Iterable[str],
) -> bool:
    projected = tuple(projection_obligation_keys)
    if len(projected) != len(set(projected)):
        raise BinaryFirstContractError(
            "PROJECTION_OBLIGATION_DUPLICATE", "one projection per obligation is required"
        )
    expected = set(assessment.obligation_keys)
    if assessment.status == "unsupported":
        if projected:
            raise BinaryFirstContractError(
                "UNSUPPORTED_PROJECTION_PRESENT", "unsupported assessment has projections"
            )
    elif set(projected) != expected:
        raise BinaryFirstContractError(
            "PROJECTION_OBLIGATION_CONSERVATION_FAILED",
            f"missing={sorted(expected - set(projected))}; extra={sorted(set(projected) - expected)}",
        )
    return True


__all__ = [
    "ABSENT",
    "ActiveSnapshot",
    "AnalysisContext",
    "AnalysisScope",
    "ArtifactInstance",
    "BuildIdentityBundle",
    "FactBuildInputSlice",
    "ClassDefinitionResolution",
    "CrossVersionArtifactPairing",
    "Decision",
    "DispatchResolution",
    "MemberResolution",
    "ProjectionAssessment",
    "ProviderBinding",
    "ResultGeneration",
    "RuntimeComparison",
    "RuntimeProfile",
    "build_projection_obligations",
    "validate_decision_conservation",
    "validate_projection_conservation",
    "validate_snapshot_supersession",
]
