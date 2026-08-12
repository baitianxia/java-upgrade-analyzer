#!/usr/bin/env python3
"""Reconcile artifact observations into immutable decisions and projections."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from binary_artifact_diff import _mr_class_scope
from binary_fact_store import BinaryFactStore
from binary_first_contract import (
    BinaryFirstContractError,
    canonical_identity,
    observed_delta_identity,
)
from binary_first_model import (
    ActiveSnapshot,
    Decision,
    ProjectionAssessment,
    build_projection_obligations,
    validate_decision_conservation,
    validate_projection_conservation,
)
from binary_runtime_reconciler import RuntimeReconciliationResult


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


@dataclass(frozen=True)
class ProjectionRule:
    fact_kind: str
    required_edge_family: str
    implementation_version: str = "binary-projection-v1"
    identity: str = ""

    def __post_init__(self):
        if not self.identity:
            object.__setattr__(self, "identity", _identity(
                "projection_rule_contract_identity",
                {
                    "fact_kind": self.fact_kind,
                    "required_edge_family": self.required_edge_family,
                    "implementation_version": self.implementation_version,
                },
            ))


DEFAULT_RULES = {
    "method": ProjectionRule("method", "method"),
    "field": ProjectionRule("field", "field"),
    "class": ProjectionRule("class", "type"),
    "provider_topology": ProjectionRule("provider_topology", "type"),
    "class_definition": ProjectionRule("class_definition", "type"),
    "member_resolution": ProjectionRule("member_resolution", "method"),
}


@dataclass(frozen=True)
class BinaryDecisionBundle:
    analysis_context_identity: str
    authoritative_decisions: tuple[dict[str, Any], ...]
    diagnostic_decisions: tuple[dict[str, Any], ...]
    excluded_decisions: tuple[dict[str, Any], ...]
    projection_assessments: tuple[dict[str, Any], ...]
    formal_projections: tuple[dict[str, Any], ...]
    candidate_projection_plans: tuple[dict[str, Any], ...]
    active_snapshots: Mapping[str, ActiveSnapshot]
    coverage_status: str
    coverage_gaps: tuple[str, ...]
    identity: str


class BinaryDecisionEngine:
    def __init__(
        self,
        *,
        analysis_context_identity: str,
        runtime_comparison_identity: str,
        base_store: BinaryFactStore,
        current_store: BinaryFactStore,
        base_reconciliation: RuntimeReconciliationResult,
        current_reconciliation: RuntimeReconciliationResult,
        artifact_local_diffs: Iterable[Mapping[str, Any]],
        projection_rules: Mapping[str, ProjectionRule] | None = None,
    ):
        self.context = str(analysis_context_identity or "")
        self.runtime_comparison_identity = str(runtime_comparison_identity or "")
        self.base_store = base_store
        self.current_store = current_store
        self.base_runtime = base_reconciliation
        self.current_runtime = current_reconciliation
        self.artifact_diffs = tuple(dict(item) for item in artifact_local_diffs)
        self.rules = dict(projection_rules or DEFAULT_RULES)
        self.authoritative = []
        self.diagnostic = []
        self.excluded = []
        self.assessments = []
        self.projections = []
        self.candidate_plans = []
        self.obligations = []
        self._obligation_origins = {}
        self.coverage_gaps = set()
        self._base_artifact_lineages = self._artifact_lineages(
            "base_artifact_instance_identity"
        )
        self._current_artifact_lineages = self._artifact_lineages(
            "current_artifact_instance_identity"
        )
        self._base_providers = self._records_by_key(
            base_reconciliation.provider_bindings,
            duplicate_code="PROVIDER_BINDING_SCOPE_DUPLICATE",
            identity_field="provider_binding_identity",
        )
        self._current_providers = self._records_by_key(
            current_reconciliation.provider_bindings,
            duplicate_code="PROVIDER_BINDING_SCOPE_DUPLICATE",
            identity_field="provider_binding_identity",
        )
        self._base_definitions = self._records_by_key(
            base_reconciliation.class_definitions,
            duplicate_code="CLASS_DEFINITION_SCOPE_DUPLICATE",
            identity_field="class_definition_resolution_identity",
        )
        self._current_definitions = self._records_by_key(
            current_reconciliation.class_definitions,
            duplicate_code="CLASS_DEFINITION_SCOPE_DUPLICATE",
            identity_field="class_definition_resolution_identity",
        )
        self._base_resources = self._resource_records_by_key(
            base_reconciliation.resource_selections
        )
        self._current_resources = self._resource_records_by_key(
            current_reconciliation.resource_selections
        )

    @staticmethod
    def _semantic_member_edges(
        store: BinaryFactStore,
        reconciliation: RuntimeReconciliationResult,
        artifact_lineages: Mapping[str, str],
    ) -> dict[tuple[Any, ...], tuple[dict[str, Any], dict[str, Any], dict[str, Any]]]:
        resolutions = BinaryDecisionEngine._unique_index(
            reconciliation.member_resolutions,
            ("direct_edge_identity",),
            duplicate_code="MEMBER_RESOLUTION_EDGE_DUPLICATE",
            identity_field="member_resolution_identity",
        )
        providers = BinaryDecisionEngine._unique_index(
            reconciliation.provider_bindings,
            ("initiating_loader_realm_identity", "class_name"),
            duplicate_code="PROVIDER_BINDING_SCOPE_DUPLICATE",
            identity_field="provider_binding_identity",
        )
        output = {}
        for raw in store.connection.execute(
            """
            SELECT edge.direct_edge_identity,edge.caller_member_identity,
                   edge.caller_artifact_instance_identity,
                   edge.instruction_index,edge.bytecode_offset,edge.edge_kind,
                   edge.opcode,edge.symbolic_owner,edge.symbolic_name,
                   edge.symbolic_descriptor,
                   caller.class_name AS caller_class_name,
                   caller.member_name AS caller_member_name,
                   caller.descriptor AS caller_descriptor,
                   caller.class_variant_identity AS caller_class_variant_identity,
                   artifact.runtime_path_kind,
                   artifact.runtime_classpath_index
            FROM direct_edges AS edge
            JOIN members AS caller
              ON caller.member_identity=edge.caller_member_identity
            JOIN artifact_instances AS artifact
              ON artifact.artifact_instance_identity=
                 edge.caller_artifact_instance_identity
            WHERE edge.edge_kind='method'
            ORDER BY edge.rowid
            """
        ):
            edge = {
                key: raw[key] for key in (
                    "direct_edge_identity", "caller_member_identity",
                    "caller_artifact_instance_identity", "instruction_index",
                    "bytecode_offset", "edge_kind", "opcode",
                    "symbolic_owner", "symbolic_name", "symbolic_descriptor",
                )
            }
            resolution = resolutions.get((edge["direct_edge_identity"],))
            if not resolution:
                continue
            initiating_realm = str(
                resolution.get("initiating_loader_realm_identity") or ""
            )
            provider = providers.get(
                (initiating_realm, str(raw["caller_class_name"] or ""))
            )
            # The fact store contains edges from shadowed class variants too.
            # Only the provider selected by this loader realm is executable.
            if (
                not provider
                or provider.get("class_provider_status") != "resolved"
                or provider.get("selected_class_variant_identity")
                != raw["caller_class_variant_identity"]
            ):
                continue
            artifact = {
                "artifact_instance_identity": edge[
                    "caller_artifact_instance_identity"
                ],
                "logical_dependency_lineage": artifact_lineages.get(
                    edge["caller_artifact_instance_identity"], ""
                ),
                "runtime_path_kind": raw["runtime_path_kind"],
                "runtime_classpath_index": raw["runtime_classpath_index"],
            }
            lineage = str(artifact.get("logical_dependency_lineage") or "")
            if not lineage:
                lineage = (
                    f"runtime-slot:{artifact['runtime_path_kind']}:"
                    f"{artifact['runtime_classpath_index']}"
                )
            key = (
                lineage,
                str(artifact.get("runtime_path_kind") or ""),
                str(raw["caller_class_name"] or ""),
                str(raw["caller_member_name"] or ""),
                str(raw["caller_descriptor"] or ""),
                int(edge.get("instruction_index") or 0),
                int(edge.get("bytecode_offset") or 0),
                int(edge.get("opcode") or 0),
                str(edge.get("symbolic_owner") or ""),
                str(edge.get("symbolic_name") or ""),
                str(edge.get("symbolic_descriptor") or ""),
                initiating_realm,
            )
            if key in output:
                first = output[key][0]["direct_edge_identity"]
                raise BinaryFirstContractError(
                    "SEMANTIC_MEMBER_EDGE_KEY_DUPLICATE",
                    f"lineage={lineage}; first={first}; "
                    f"duplicate={edge['direct_edge_identity']}",
                )
            output[key] = (edge, resolution, artifact)
        return output

    def _artifact_lineages(self, identity_field: str) -> dict[str, str]:
        output = {}
        for artifact_diff in self.artifact_diffs:
            artifact_identity = str(artifact_diff.get(identity_field) or "")
            if not artifact_identity or artifact_identity.startswith("ABSENT:"):
                continue
            lineage = str(
                artifact_diff.get("logical_dependency_lineage") or ""
            ).strip()
            previous = output.get(artifact_identity)
            if previous is not None and previous != lineage:
                raise BinaryFirstContractError(
                    "ARTIFACT_LINEAGE_IDENTITY_CONFLICT",
                    f"artifact={artifact_identity}; first={previous}; "
                    f"duplicate={lineage}",
                )
            output[artifact_identity] = lineage
        return output

    @staticmethod
    def _upstream_observed_identity(
        record: Mapping[str, Any], *, label: str
    ) -> str:
        identity = str(record.get("observed_delta_identity") or "").strip()
        if not identity:
            raise BinaryFirstContractError(
                "ARTIFACT_OBSERVED_DELTA_IDENTITY_MISSING", label
            )
        return identity

    @staticmethod
    def _unique_index(
        records: Iterable[Mapping[str, Any]],
        key_fields: tuple[str, ...],
        *,
        duplicate_code: str,
        identity_field: str,
    ) -> dict[tuple[Any, ...], Mapping[str, Any]]:
        output = {}
        for item in records:
            key = tuple(item.get(field) for field in key_fields)
            previous = output.get(key)
            if previous is not None:
                raise BinaryFirstContractError(
                    duplicate_code,
                    f"key={key}; first={previous.get(identity_field)}; "
                    f"duplicate={item.get(identity_field)}",
                )
            output[key] = item
        return output

    @staticmethod
    def _records_by_key(
        records: Iterable[Mapping[str, Any]],
        *,
        duplicate_code: str,
        identity_field: str,
    ) -> dict[tuple[Any, ...], Mapping[str, Any]]:
        return BinaryDecisionEngine._unique_index(
            records,
            ("initiating_loader_realm_identity", "class_name"),
            duplicate_code=duplicate_code,
            identity_field=identity_field,
        )

    @staticmethod
    def _resource_records_by_key(records):
        return BinaryDecisionEngine._unique_index(
            records,
            (
                "initiating_loader_realm_identity",
                "resource_name",
                "resource_mechanism",
            ),
            duplicate_code="RESOURCE_SELECTION_SCOPE_DUPLICATE",
            identity_field="resource_selection_identity",
        )

    @staticmethod
    def _resource_fingerprint(record: Mapping[str, Any] | None) -> str:
        if not record:
            return "ABSENT"
        category = str(record.get("resource_category") or "unknown")
        selected = []
        for item in record.get("selected_resources") or ():
            semantic_digest = (
                item.get("normalized_resource_digest")
                if category in {"runtime_topology", "distribution_metadata", "build_metadata"}
                else item.get("content_sha256")
            )
            selected.append({
                "runtime_classpath_index": item.get("runtime_classpath_index"),
                "runtime_code_source_origin_identity": item.get(
                    "runtime_code_source_origin_identity"
                ),
                "semantic_digest": semantic_digest,
            })
        return _identity("resource_selection_outcome_fingerprint", {
            "resource_selection_status": record.get("resource_selection_status"),
            "resource_name": record.get("resource_name"),
            "resource_category": category,
            "resource_mechanism": record.get("resource_mechanism"),
            "selected_resources": selected,
        })

    @staticmethod
    def _class_name(entry_name: str) -> str:
        logical, _version = _mr_class_scope(entry_name)
        return logical.removesuffix(".class")

    def _provider_fingerprint(
        self,
        store: BinaryFactStore,
        record: Mapping[str, Any] | None,
    ) -> str:
        if not record:
            return "ABSENT"
        status = record.get("class_provider_status")
        if status != "resolved":
            return _identity("provider_outcome_fingerprint", {
                "status": status,
                "evidence": record.get("selection_evidence") or {},
            })
        variant = record.get("selected_class_variant_identity")
        rows = store.rows(
            "classes", where="class_variant_identity=?", parameters=(variant,),
            include_class_bytes=False, include_class_facts=False,
        )
        if rows:
            class_row = rows[0]
            artifact_rows = store.rows(
                "artifact_instances",
                where="artifact_instance_identity=?",
                parameters=(record.get("selected_artifact_instance_identity"),),
            )
            artifact = artifact_rows[0] if artifact_rows else {}
            payload = {
                "status": "resolved",
                "class_name": class_row["class_name"],
                "multi_release_version": class_row["multi_release_version"],
                "defining_loader_realm_identity": record.get("selected_defining_loader_realm_identity"),
                "runtime_path_kind": artifact.get("runtime_path_kind"),
                "runtime_classpath_index": artifact.get("runtime_classpath_index"),
                "runtime_code_source_origin_identity": artifact.get("runtime_code_source_origin_identity"),
            }
        else:
            payload = {
                "status": "resolved",
                "platform_class_variant_identity": variant,
                "selected_artifact_instance_identity": record.get("selected_artifact_instance_identity"),
                "defining_loader_realm_identity": record.get("selected_defining_loader_realm_identity"),
            }
        return _identity("provider_outcome_fingerprint", payload)

    def _decision(
        self,
        *,
        observed_identity: str,
        channel: str,
        reason_code: str,
        fact_kind: str,
        fact_scope: Mapping[str, Any],
        target_identity: str = "",
        coverage_gaps: Iterable[str] = (),
        evidence: Mapping[str, Any] | None = None,
        dependency_artifacts: Iterable[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "reason_code": reason_code,
            "fact_kind": fact_kind,
            "fact_scope": dict(fact_scope),
            "decision_policy_version": "binary-runtime-decision-v1",
            "coverage_gaps": sorted(set(coverage_gaps)),
            "evidence": dict(evidence or {}),
            "dependency_artifacts": [dict(item) for item in dependency_artifacts],
        }
        if target_identity:
            payload["analysis_target_identity"] = target_identity
        if channel == "authoritative":
            payload["change_fact_status"] = "confirmed"
        elif channel == "diagnostic":
            payload["candidate_fact_status"] = "incomplete" if payload["coverage_gaps"] else "candidate"
        else:
            payload["exclusion_status"] = "excluded"
        decision = Decision(observed_identity, self.context, channel, payload)
        change_fact_identity = (
            _identity("runtime_effective_change_fact_identity", {
                "decision_identity": decision.identity,
                "fact_kind": fact_kind,
                "fact_scope": dict(fact_scope),
            }) if channel == "authoritative" else ""
        )
        record = {
            "observed_delta_identity": observed_identity,
            "disposition_obligation_identity": decision.obligation_identity,
            "decision_identity": decision.identity,
            "decision_channel": channel,
            "change_fact_identity": change_fact_identity,
            **payload,
        }
        origin = {
            "reason_code": reason_code,
            "fact_kind": fact_kind,
            "fact_scope": dict(fact_scope),
            "dependency_lineages": sorted({
                str(item.get("logical_dependency_lineage") or "")
                for item in payload["dependency_artifacts"]
                if item.get("logical_dependency_lineage")
            }),
        }
        previous_origin = self._obligation_origins.get(
            decision.obligation_identity
        )
        if previous_origin is not None:
            raise BinaryFirstContractError(
                "DISPOSITION_OBLIGATION_DUPLICATE",
                f"obligation={decision.obligation_identity}; "
                f"first={previous_origin}; duplicate={origin}",
            )
        self._obligation_origins[decision.obligation_identity] = origin
        self.obligations.append(decision.obligation_identity)
        if channel == "authoritative":
            self.authoritative.append(record)
            self._assess(record)
        elif channel == "diagnostic":
            self.diagnostic.append(record)
            self._candidate_plan(record)
        else:
            self.excluded.append(record)
        return record

    def _artifact_reference(
        self,
        side: str,
        artifact_identity: str,
        *,
        lineage: str = "",
    ) -> dict[str, Any] | None:
        if not artifact_identity or artifact_identity.startswith("ABSENT:"):
            return None
        if artifact_identity.startswith("platform-image:"):
            module_name = artifact_identity.rsplit(":", 1)[-1]
            return {
                "side": side,
                "logical_dependency_lineage": "JDK_PLATFORM",
                "artifact_instance_identity": artifact_identity,
                "coord": f"JDK_PLATFORM:{module_name}",
                "runtime_path_kind": "platform_module",
                "runtime_classpath_index": -1,
                "runtime_code_source_origin_identity": artifact_identity,
            }
        store = self.base_store if side == "base" else self.current_store
        rows = store.rows(
            "artifact_instances",
            where="artifact_instance_identity=?",
            parameters=(artifact_identity,),
        )
        if not rows:
            return None
        row = rows[0]
        return {
            "side": side,
            "logical_dependency_lineage": lineage,
            "artifact_instance_identity": artifact_identity,
            "coord": str(row.get("coord") or ""),
            "runtime_path_kind": str(row.get("runtime_path_kind") or ""),
            "runtime_classpath_index": row.get("runtime_classpath_index"),
            "runtime_code_source_origin_identity": str(
                row.get("runtime_code_source_origin_identity") or ""
            ),
        }

    def _dependency_artifacts(
        self,
        base_identity: str = "",
        current_identity: str = "",
        *,
        lineage: str = "",
    ) -> tuple[dict[str, Any], ...]:
        return tuple(
            item for item in (
                self._artifact_reference("base", base_identity, lineage=lineage),
                self._artifact_reference("current", current_identity, lineage=lineage),
            )
            if item is not None
        )

    def _resource_dependency_artifacts(
        self,
        base: Mapping[str, Any] | None,
        current: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], ...]:
        output = []
        seen = set()
        for side, record in (("base", base), ("current", current)):
            for selected in (record or {}).get("selected_resources") or ():
                artifact_identity = str(selected.get("artifact_instance_identity") or "")
                reference = self._artifact_reference(side, artifact_identity)
                if reference is None:
                    continue
                key = (reference["side"], reference["artifact_instance_identity"])
                if key not in seen:
                    seen.add(key)
                    output.append(reference)
        return tuple(output)

    def _assess(self, decision: Mapping[str, Any]) -> None:
        fact_kind = decision["fact_kind"]
        rule = self.rules.get(fact_kind)
        target = str(decision.get("analysis_target_identity") or "")
        if not rule or not target:
            assessment = ProjectionAssessment(
                decision["decision_identity"], "unsupported", "unsupported", (), (), ()
            )
            record = {
                "projection_assessment_identity": assessment.identity,
                "decision_identity": decision["decision_identity"],
                "change_fact_identity": decision["change_fact_identity"],
                "analysis_projection_status": "unsupported",
                "projection_coverage_status": "unsupported",
                "target_identities": [],
                "projection_obligation_keys": [],
                "partial_projection_scopes": [],
            }
            validate_projection_conservation(assessment=assessment, projection_obligation_keys=())
            self.assessments.append(record)
            return
        obligations = build_projection_obligations(
            projection_rule_contract_identity=rule.identity,
            targets_by_required_edge_family={rule.required_edge_family: (target,)},
        )
        partial = tuple(decision.get("coverage_gaps") or ())
        assessment = ProjectionAssessment(
            decision["decision_identity"],
            "targetable",
            "partial" if partial else "complete",
            (target,),
            obligations,
            partial,
        )
        assessment_record = {
            "projection_assessment_identity": assessment.identity,
            "decision_identity": decision["decision_identity"],
            "change_fact_identity": decision["change_fact_identity"],
            "analysis_projection_status": "targetable",
            "projection_coverage_status": assessment.coverage_status,
            "target_identities": [target],
            "projection_obligation_keys": list(obligations),
            "partial_projection_scopes": list(partial),
        }
        self.assessments.append(assessment_record)
        created = []
        for obligation in obligations:
            projection_identity = _identity("binary_change_projection_identity", {
                "projection_assessment_identity": assessment.identity,
                "projection_obligation_key": obligation,
                "projection_rule_contract_identity": rule.identity,
                "projection_rule_implementation_version": rule.implementation_version,
                "target_identity": target,
            })
            self.projections.append({
                "projection_identity": projection_identity,
                "projection_assessment_identity": assessment.identity,
                "projection_obligation_key": obligation,
                "projection_rule_contract_identity": rule.identity,
                "projection_rule_implementation_version": rule.implementation_version,
                "change_fact_identity": decision["change_fact_identity"],
                "target_identity": target,
                "required_edge_family": rule.required_edge_family,
            })
            created.append(obligation)
        validate_projection_conservation(
            assessment=assessment, projection_obligation_keys=created
        )

    def _candidate_plan(self, decision: Mapping[str, Any]) -> None:
        rule = self.rules.get(decision["fact_kind"])
        target = str(decision.get("analysis_target_identity") or "")
        obligations = (
            build_projection_obligations(
                projection_rule_contract_identity=rule.identity,
                targets_by_required_edge_family={rule.required_edge_family: (target,)},
            ) if rule and target else ()
        )
        status = "targetable" if obligations else "unbound"
        plan_identity = _identity("candidate_projection_plan_identity", {
            "decision_identity": decision["decision_identity"],
            "planning_status": status,
            "target_identity": target or "ABSENT",
            "projection_obligation_keys": list(obligations),
            "unbound_reasons": list(decision.get("coverage_gaps") or (decision["reason_code"],)),
        })
        self.candidate_plans.append({
            "candidate_projection_plan_identity": plan_identity,
            "decision_identity": decision["decision_identity"],
            "planning_status": status,
            "target_identities": [target] if target else [],
            "projection_obligation_keys": list(obligations),
            "candidate_projection_count": len(obligations),
            "unbound_reasons": list(decision.get("coverage_gaps") or (decision["reason_code"],)),
        })

    def _member_target(self, realm: str, class_name: str, member_scope: Mapping[str, Any]) -> str:
        return _identity("binary_analysis_member_target_identity", {
            "runtime_comparison_identity": self.runtime_comparison_identity,
            "analysis_context_identity": self.context,
            "initiating_loader_realm_identity": realm,
            "class_name": class_name,
            "member_kind": member_scope["member_kind"],
            "member_name": member_scope["member_name"],
            "descriptor": member_scope["descriptor"],
        })

    def _process_artifact_diffs(self) -> None:
        for artifact_diff in self.artifact_diffs:
            base_artifact = artifact_diff["base_artifact_instance_identity"]
            current_artifact = artifact_diff["current_artifact_instance_identity"]
            lineage = str(artifact_diff.get("logical_dependency_lineage") or "")
            dependency_artifacts = self._dependency_artifacts(
                base_artifact, current_artifact, lineage=lineage
            )
            comparison_complete = (
                artifact_diff.get(
                    "class_comparison_coverage_status",
                    artifact_diff.get("comparison_coverage_status"),
                )
                == "complete"
            )
            for entry in artifact_diff.get("entry_deltas") or ():
                if entry.get("runtime_effective_analysis") is False:
                    continue
                if entry["entry_scope"].get("entry_kind") != "class":
                    self._process_resource_delta(
                        entry, comparison_complete, dependency_artifacts
                    )
                    continue
                class_name = self._class_name(entry["entry_scope"]["entry_name"])
                keys = sorted({
                    key for key in set(self._base_providers) | set(self._current_providers)
                    if key[1] == class_name
                })
                member_deltas = entry.get("member_deltas") or ()
                if not member_deltas:
                    member_deltas = ({
                        "member_scope": {
                            **entry["entry_scope"],
                            "member_kind": "class",
                            "member_name": "<class>",
                            "descriptor": f"L{class_name};",
                        },
                        "member_change_kind": entry.get("class_change_category"),
                        "base_member_fingerprint": entry["base_content_sha256"],
                        "current_member_fingerprint": entry["current_content_sha256"],
                        "observed_delta_identity": entry.get(
                            "observed_delta_identity"
                        ),
                    },)
                for realm, _ in keys:
                    base_provider = self._base_providers.get((realm, class_name))
                    current_provider = self._current_providers.get((realm, class_name))
                    base_selected = (
                        (base_provider or {}).get("selected_artifact_instance_identity") == base_artifact
                    )
                    current_selected = (
                        (current_provider or {}).get("selected_artifact_instance_identity") == current_artifact
                    )
                    for member_delta in member_deltas:
                        upstream_observed = self._upstream_observed_identity(
                            member_delta,
                            label=(
                                f"lineage={lineage}; class={class_name}; "
                                f"member={member_delta.get('member_scope')}"
                            ),
                        )
                        scope = {
                            **member_delta["member_scope"],
                            "initiating_loader_realm_identity": realm,
                            "class_name": class_name,
                            "member_change_kind": member_delta["member_change_kind"],
                        }
                        # Lift the pairing-bound Step4A observation into the
                        # realm-specific decision scope without dropping its
                        # artifact identity.
                        observed = observed_delta_identity(
                            delta_source_kind="artifact_local",
                            comparison_or_runtime_scope={
                                "runtime_comparison_identity": self.runtime_comparison_identity,
                                "initiating_loader_realm_identity": realm,
                                "artifact_observed_delta_identity": upstream_observed,
                            },
                            fact_or_mechanism_scope=scope,
                            base_fingerprint=member_delta.get("base_member_fingerprint") or "ABSENT",
                            current_fingerprint=member_delta.get("current_member_fingerprint") or "ABSENT",
                        )
                        fact_kind = (
                            member_delta["member_scope"]["member_kind"]
                            if member_delta["member_scope"]["member_kind"] in {"method", "field"}
                            else "class"
                        )
                        target = self._member_target(realm, class_name, member_delta["member_scope"])
                        if not base_selected and not current_selected:
                            self._decision(
                                observed_identity=observed,
                                channel="excluded",
                                reason_code="ARTIFACT_CLASS_SHADOWED_IN_BOTH_RUNTIME_VIEWS",
                                fact_kind=fact_kind,
                                fact_scope=scope,
                                evidence={
                                    "upstream_artifact_observed_delta_identity": (
                                        upstream_observed
                                    ),
                                    "base_provider": base_provider,
                                    "current_provider": current_provider,
                                },
                                dependency_artifacts=dependency_artifacts,
                            )
                            continue
                        gaps = []
                        if not comparison_complete or entry.get("class_change_category") == "incomplete":
                            gaps.append("artifact_local_comparison_incomplete")
                        if self.base_runtime.coverage_status != "complete":
                            gaps.extend(self.base_runtime.coverage_gaps)
                        if self.current_runtime.coverage_status != "complete":
                            gaps.extend(self.current_runtime.coverage_gaps)
                        if base_selected:
                            definition = self._base_definitions.get((realm, class_name))
                            if not definition or definition["class_definition_status"] != "definition_ready":
                                gaps.append("base_class_definition_not_ready")
                        if current_selected:
                            definition = self._current_definitions.get((realm, class_name))
                            if not definition or definition["class_definition_status"] != "definition_ready":
                                gaps.append("current_class_definition_not_ready")
                        change_kind = member_delta["member_change_kind"]
                        counterpart_is_definitive_absence = (
                            change_kind == "removed"
                            and base_selected
                            and (current_provider is None or current_provider.get("class_provider_status") == "missing")
                        ) or (
                            change_kind == "added"
                            and current_selected
                            and (base_provider is None or base_provider.get("class_provider_status") == "missing")
                        )
                        if base_selected != current_selected and not counterpart_is_definitive_absence:
                            gaps.append("artifact_delta_provider_correspondence_changed")
                        self._decision(
                            observed_identity=observed,
                            channel="diagnostic" if gaps else "authoritative",
                            reason_code=(
                                "RUNTIME_EFFECTIVE_MEMBER_CHANGE_CONFIRMED"
                                if not gaps else "RUNTIME_EFFECTIVE_MEMBER_CHANGE_INCOMPLETE"
                            ),
                            fact_kind=fact_kind,
                            fact_scope=scope,
                            target_identity=target,
                            coverage_gaps=gaps,
                            evidence={
                                "upstream_artifact_observed_delta_identity": (
                                    upstream_observed
                                ),
                                "base_provider_binding_identity": (base_provider or {}).get("provider_binding_identity"),
                                "current_provider_binding_identity": (current_provider or {}).get("provider_binding_identity"),
                                "base_member_fingerprint": member_delta.get("base_member_fingerprint"),
                                "current_member_fingerprint": member_delta.get("current_member_fingerprint"),
                                "base_contract": member_delta.get("base_contract"),
                                "current_contract": member_delta.get("current_contract"),
                            },
                            dependency_artifacts=dependency_artifacts,
                        )

    def _process_resource_delta(
        self,
        entry: Mapping[str, Any],
        comparison_complete: bool,
        dependency_artifacts: Iterable[Mapping[str, Any]],
    ) -> None:
        scope = dict(entry["entry_scope"])
        # The Step4A identity already binds the artifact pairing. Rebuilding
        # it from a common resource name/content pair would merge dependencies.
        observed = self._upstream_observed_identity(
            entry,
            label=f"resource={scope}",
        )
        self._decision(
            observed_identity=observed,
            channel="excluded",
            reason_code="ARTIFACT_RESOURCE_OBSERVATION_RECONCILED_BY_SELECTION_VIEW",
            fact_kind="resource",
            fact_scope=scope,
            evidence={
                "resource_change_category": entry.get("resource_change_category"),
                "artifact_comparison_coverage_status": (
                    "complete" if comparison_complete else "partial"
                ),
                "runtime_authority": "resource_selection_delta",
            },
            dependency_artifacts=dependency_artifacts,
        )

    def _process_resource_outcome_deltas(self) -> None:
        keys = sorted(set(self._base_resources) | set(self._current_resources))
        for realm, name, mechanism in keys:
            base = self._base_resources.get((realm, name, mechanism))
            current = self._current_resources.get((realm, name, mechanism))
            old_fp = self._resource_fingerprint(base)
            new_fp = self._resource_fingerprint(current)
            if old_fp == new_fp:
                continue
            category = str(
                (current or base or {}).get("resource_category") or "unknown"
            )
            scope = {
                "initiating_loader_realm_identity": realm,
                "resource_name": name,
                "resource_mechanism": mechanism,
                "resource_category": category,
            }
            observed = observed_delta_identity(
                delta_source_kind="resource_selection",
                comparison_or_runtime_scope={
                    "runtime_comparison_identity": self.runtime_comparison_identity,
                    "initiating_loader_realm_identity": realm,
                },
                fact_or_mechanism_scope=scope,
                base_fingerprint=old_fp,
                current_fingerprint=new_fp,
            )
            gaps = []
            for side, record in (("base", base), ("current", current)):
                if record and record.get("coverage_status") != "complete":
                    gaps.extend(
                        f"{side}:{gap}" for gap in record.get("coverage_gaps") or ()
                    )
            if self.base_runtime.coverage_status != "complete":
                gaps.extend(self.base_runtime.coverage_gaps)
            if self.current_runtime.coverage_status != "complete":
                gaps.extend(self.current_runtime.coverage_gaps)
            outside_semantic_scope = category in {
                "build_metadata", "distribution_metadata"
            }
            if outside_semantic_scope and not gaps:
                channel = "excluded"
                reason = "RESOURCE_SELECTION_CHANGE_OUTSIDE_RUNTIME_SEMANTIC_SCOPE"
            elif gaps:
                channel = "diagnostic"
                reason = "RUNTIME_RESOURCE_SELECTION_CHANGE_INCOMPLETE"
            else:
                channel = "authoritative"
                reason = "RUNTIME_RESOURCE_SELECTION_CHANGE_CONFIRMED_UNPROJECTABLE"
            self._decision(
                observed_identity=observed,
                channel=channel,
                reason_code=reason,
                fact_kind="resource",
                fact_scope=scope,
                coverage_gaps=gaps,
                evidence={"base_selection": base, "current_selection": current},
                dependency_artifacts=self._resource_dependency_artifacts(base, current),
            )

    def _process_runtime_outcome_deltas(self) -> None:
        all_keys = sorted(set(self._base_providers) | set(self._current_providers))
        for realm, class_name in all_keys:
            base = self._base_providers.get((realm, class_name))
            current = self._current_providers.get((realm, class_name))
            old_fp = self._provider_fingerprint(self.base_store, base)
            new_fp = self._provider_fingerprint(self.current_store, current)
            scope = {
                "initiating_loader_realm_identity": realm,
                "class_name": class_name,
                "mechanism": "class_provider",
            }
            gaps = []
            if self.base_runtime.coverage_status != "complete":
                gaps.extend(self.base_runtime.coverage_gaps)
            if self.current_runtime.coverage_status != "complete":
                gaps.extend(self.current_runtime.coverage_gaps)
            if (base or {}).get("class_provider_status") in {"ambiguous", "unresolved"}:
                gaps.append("base_provider_unresolved")
            if (current or {}).get("class_provider_status") in {"ambiguous", "unresolved"}:
                gaps.append("current_provider_unresolved")
            target = _identity("binary_analysis_class_target_identity", {
                "runtime_comparison_identity": self.runtime_comparison_identity,
                "analysis_context_identity": self.context,
                "initiating_loader_realm_identity": realm,
                "class_name": class_name,
            })
            if old_fp != new_fp:
                observed = observed_delta_identity(
                    delta_source_kind="provider_topology",
                    comparison_or_runtime_scope={"runtime_comparison_identity": self.runtime_comparison_identity},
                    fact_or_mechanism_scope=scope,
                    base_fingerprint=old_fp,
                    current_fingerprint=new_fp,
                )
                self._decision(
                    observed_identity=observed,
                    channel="diagnostic" if gaps else "authoritative",
                    reason_code=("CLASS_PROVIDER_CHANGED" if not gaps else "CLASS_PROVIDER_CHANGE_INCOMPLETE"),
                    fact_kind="provider_topology",
                    fact_scope=scope,
                    target_identity=target,
                    coverage_gaps=gaps,
                    evidence={"base_provider": base, "current_provider": current},
                    dependency_artifacts=self._dependency_artifacts(
                        str((base or {}).get("selected_artifact_instance_identity") or ""),
                        str((current or {}).get("selected_artifact_instance_identity") or ""),
                    ),
                )

            base_definition = self._base_definitions.get((realm, class_name))
            current_definition = self._current_definitions.get((realm, class_name))
            old_status = (base_definition or {}).get("class_definition_status", "ABSENT")
            new_status = (current_definition or {}).get("class_definition_status", "ABSENT")
            if old_status == new_status:
                continue
            definition_scope = {**scope, "mechanism": "class_definition"}
            definition_observed = observed_delta_identity(
                delta_source_kind="class_definition",
                comparison_or_runtime_scope={"runtime_comparison_identity": self.runtime_comparison_identity},
                fact_or_mechanism_scope=definition_scope,
                base_fingerprint=old_status,
                current_fingerprint=new_status,
            )
            definite = {old_status, new_status}.isdisjoint({"ambiguous", "unsupported", "ABSENT"})
            self._decision(
                observed_identity=definition_observed,
                channel="authoritative" if definite and not gaps else "diagnostic",
                reason_code=(
                    "CLASS_DEFINITION_OUTCOME_CHANGED"
                    if definite and not gaps else "CLASS_DEFINITION_CHANGE_INCOMPLETE"
                ),
                fact_kind="class_definition",
                fact_scope=definition_scope,
                target_identity=target,
                coverage_gaps=gaps if gaps else (() if definite else ("definition_outcome_not_definite",)),
                evidence={"base_definition": base_definition, "current_definition": current_definition},
                dependency_artifacts=self._dependency_artifacts(
                    str((base or {}).get("selected_artifact_instance_identity") or ""),
                    str((current or {}).get("selected_artifact_instance_identity") or ""),
                ),
            )
        self._process_resource_outcome_deltas()

    def _process_member_resolution_deltas(self) -> None:
        base_edges = self._semantic_member_edges(
            self.base_store,
            self.base_runtime,
            self._base_artifact_lineages,
        )
        current_edges = self._semantic_member_edges(
            self.current_store,
            self.current_runtime,
            self._current_artifact_lineages,
        )
        for key in sorted(set(base_edges).intersection(current_edges)):
            base_edge, base_resolution, _base_caller_artifact = base_edges[key]
            current_edge, current_resolution, _current_caller_artifact = current_edges[key]
            if (
                base_resolution.get("member_resolution_status") != "resolved"
                or current_resolution.get("member_resolution_status") != "resolved"
            ):
                continue
            base_owner = str(base_resolution.get("resolved_owner") or "")
            current_owner = str(current_resolution.get("resolved_owner") or "")
            base_realm = str(
                base_resolution.get("resolved_defining_loader_realm_identity") or ""
            )
            current_realm = str(
                current_resolution.get("resolved_defining_loader_realm_identity") or ""
            )
            if (base_owner, base_realm) == (current_owner, current_realm):
                continue
            realm = str(
                current_resolution.get("initiating_loader_realm_identity")
                or base_resolution.get("initiating_loader_realm_identity")
                or ""
            )
            owner = str(current_edge.get("symbolic_owner") or "")
            scope = {
                "initiating_loader_realm_identity": realm,
                "class_name": owner,
                "member_kind": "method",
                "member_name": str(current_edge.get("symbolic_name") or ""),
                "descriptor": str(current_edge.get("symbolic_descriptor") or ""),
                "member_change_kind": "resolution_changed",
                "mechanism": "member_resolution",
            }
            observed = observed_delta_identity(
                delta_source_kind="member_resolution",
                comparison_or_runtime_scope={
                    "runtime_comparison_identity": self.runtime_comparison_identity,
                    "initiating_loader_realm_identity": realm,
                },
                fact_or_mechanism_scope={
                    **scope,
                    "caller_lineage": key[0],
                    "caller_class": key[2],
                    "caller_member": key[3],
                    "caller_descriptor": key[4],
                    "instruction_index": key[5],
                },
                base_fingerprint=_identity("member_resolution_outcome", {
                    "status": "resolved", "owner": base_owner, "realm": base_realm,
                }),
                current_fingerprint=_identity("member_resolution_outcome", {
                    "status": "resolved", "owner": current_owner, "realm": current_realm,
                }),
            )
            base_provider = self._base_providers.get((realm, owner))
            current_provider = self._current_providers.get((realm, owner))
            target = self._member_target(realm, owner, scope)
            self._decision(
                observed_identity=observed,
                channel="authoritative",
                reason_code="RUNTIME_MEMBER_RESOLUTION_CHANGED",
                fact_kind="member_resolution",
                fact_scope=scope,
                target_identity=target,
                evidence={
                    "semantic_caller_edge": {
                        "logical_dependency_lineage": key[0],
                        "caller_class": key[2],
                        "caller_member": key[3],
                        "caller_descriptor": key[4],
                        "instruction_index": key[5],
                        "bytecode_offset": key[6],
                    },
                    "base_direct_edge_identity": base_edge["direct_edge_identity"],
                    "current_direct_edge_identity": current_edge["direct_edge_identity"],
                    "base_resolution": base_resolution,
                    "current_resolution": current_resolution,
                },
                dependency_artifacts=self._dependency_artifacts(
                    str((base_provider or {}).get("selected_artifact_instance_identity") or ""),
                    str((current_provider or {}).get("selected_artifact_instance_identity") or ""),
                ),
            )

    def build(self) -> BinaryDecisionBundle:
        self._process_artifact_diffs()
        # The reconciliation identity binds every provider, definition,
        # member, dispatch, type, initialization, linkage and resource outcome.
        # Equal identities therefore prove that both runtime-derived delta
        # passes are empty. Artifact-local deltas still run above because a
        # changed but shadowed artifact can legitimately produce an exclusion.
        if self.base_runtime.identity != self.current_runtime.identity:
            self._process_member_resolution_deltas()
            self._process_runtime_outcome_deltas()
        decision_objects = []
        for record in (*self.authoritative, *self.diagnostic, *self.excluded):
            payload = {
                key: value for key, value in record.items()
                if key not in {
                    "observed_delta_identity", "disposition_obligation_identity", "decision_identity",
                    "decision_channel", "change_fact_identity",
                }
            }
            decision_objects.append(Decision(
                record["observed_delta_identity"], self.context, record["decision_channel"], payload
            ))
        validate_decision_conservation(
            disposition_obligation_identities=self.obligations,
            decisions=decision_objects,
        )
        snapshots = {
            "decision": ActiveSnapshot(
                "decision", self.context,
                tuple(record["decision_identity"] for record in (*self.authoritative, *self.diagnostic, *self.excluded)),
            ),
            "assessment": ActiveSnapshot(
                "assessment", self.context,
                tuple(record["projection_assessment_identity"] for record in self.assessments),
            ),
            "formal_projection": ActiveSnapshot(
                "formal_projection", self.context,
                tuple(record["projection_identity"] for record in self.projections),
            ),
            "candidate_projection": ActiveSnapshot(
                "candidate_projection", self.context,
                tuple(record["candidate_projection_plan_identity"] for record in self.candidate_plans),
            ),
        }
        gaps = tuple(sorted(self.coverage_gaps | {
            gap for record in self.diagnostic for gap in record.get("coverage_gaps") or ()
        }))
        coverage = "complete" if not self.diagnostic else "partial"
        payload = {
            "analysis_context_identity": self.context,
            "decision_snapshot_identity": snapshots["decision"].identity,
            "assessment_snapshot_identity": snapshots["assessment"].identity,
            "formal_projection_snapshot_identity": snapshots["formal_projection"].identity,
            "candidate_projection_snapshot_identity": snapshots["candidate_projection"].identity,
            "coverage_status": coverage,
            "coverage_gaps": list(gaps),
        }
        return BinaryDecisionBundle(
            analysis_context_identity=self.context,
            authoritative_decisions=tuple(self.authoritative),
            diagnostic_decisions=tuple(self.diagnostic),
            excluded_decisions=tuple(self.excluded),
            projection_assessments=tuple(self.assessments),
            formal_projections=tuple(self.projections),
            candidate_projection_plans=tuple(self.candidate_plans),
            active_snapshots=snapshots,
            coverage_status=coverage,
            coverage_gaps=gaps,
            identity=_identity("binary_decision_bundle_identity", payload),
        )
__all__ = [
    "BinaryDecisionBundle",
    "BinaryDecisionEngine",
    "DEFAULT_RULES",
    "ProjectionRule",
]
