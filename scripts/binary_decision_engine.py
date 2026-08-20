#!/usr/bin/env python3
"""Reconcile artifact observations into immutable decisions and projections."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import count
import json
import sqlite3
from typing import Any, Iterable, Iterator, Mapping
import zlib

from binary_artifact_diff import _mr_class_scope
from binary_fact_store import BinaryFactStore
from binary_first_contract import (
    BinaryFirstContractError,
    canonical_identity_native_json,
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
    return canonical_identity_native_json(
        namespace, payload, schema_version="1"
    )


def _same_json_value(left: Any, right: Any) -> bool:
    """Compare canonical JSON values without Python's bool/int coercion."""
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return (
            left.keys() == right.keys()
            and all(
                _same_json_value(value, right[key])
                for key, value in left.items()
            )
        )
    if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
        return len(left) == len(right) and all(
            _same_json_value(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    return type(left) is type(right) and left == right


_MISSING_DECISION_VALUE = object()
_COMPACT_DECISION_INDEXES: dict[tuple[str, ...], dict[str, int]] = {}
_TEMP_TABLE_IDS = count()


class _CompactDecisionRecord(Mapping[str, Any]):
    """Tuple-backed reconciliation view used by the cross-side decision pass."""

    __slots__ = ("_fields", "_values", "_extras", "_index", "_length")

    def __init__(
        self,
        row: Mapping[str, Any],
        fields: tuple[str, ...],
        *,
        excluded_fields: frozenset[str] = frozenset(),
    ):
        self._fields = fields
        index = _COMPACT_DECISION_INDEXES.get(fields)
        if index is None:
            index = {field: offset for offset, field in enumerate(fields)}
            _COMPACT_DECISION_INDEXES[fields] = index
        self._index = index
        self._values = tuple(
            row[field] if field in row else _MISSING_DECISION_VALUE
            for field in fields
        )
        self._extras = tuple(
            (key, value) for key, value in row.items()
            if key not in self._index and key not in excluded_fields
        )
        self._length = sum(
            value is not _MISSING_DECISION_VALUE for value in self._values
        ) + len(self._extras)

    def __getitem__(self, key: str) -> Any:
        index = self._index.get(key)
        if index is not None:
            value = self._values[index]
            if value is _MISSING_DECISION_VALUE:
                raise KeyError(key)
            return value
        for extra_key, value in self._extras:
            if extra_key == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        for key, value in zip(self._fields, self._values):
            if value is not _MISSING_DECISION_VALUE:
                yield key
        for key, _value in self._extras:
            yield key

    def __len__(self) -> int:
        return self._length


_PROVIDER_DECISION_FIELDS = (
    "initiating_loader_realm_identity",
    "class_name",
    "class_provider_status",
    "provider_binding_identity",
    "runtime_profile_identity",
    "selected_artifact_instance_identity",
    "selected_class_variant_identity",
    "selected_defining_loader_realm_identity",
    "selection_evidence",
)
_DEFINITION_DECISION_FIELDS = (
    "initiating_loader_realm_identity",
    "class_name",
    "class_definition_status",
    "class_load_status",
    "class_definition_resolution_identity",
    "provider_binding_identity",
)


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
        shared_runtime_evidence: bool = False,
    ):
        self._validate_shared_runtime_evidence(
            shared_runtime_evidence=shared_runtime_evidence,
            base_store=base_store,
            current_store=current_store,
            base_reconciliation=base_reconciliation,
            current_reconciliation=current_reconciliation,
        )
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
        base_provider_records = self._reconciliation_records(
            base_store, base_reconciliation, "provider_bindings",
            "provider_binding",
        )
        self._base_providers = self._compact_records_by_key(
            base_provider_records,
            _PROVIDER_DECISION_FIELDS,
            duplicate_code="PROVIDER_BINDING_SCOPE_DUPLICATE",
            identity_field="provider_binding_identity",
        )
        if shared_runtime_evidence:
            self._current_providers = self._base_providers
        else:
            current_provider_records = self._reconciliation_records(
                current_store, current_reconciliation, "provider_bindings",
                "provider_binding",
            )
            self._current_providers = self._compact_records_by_key(
                current_provider_records,
                _PROVIDER_DECISION_FIELDS,
                duplicate_code="PROVIDER_BINDING_SCOPE_DUPLICATE",
                identity_field="provider_binding_identity",
            )
        base_definition_records = self._reconciliation_records(
            base_store, base_reconciliation, "class_definitions",
            "class_definition",
        )
        self._base_definitions = self._compact_records_by_key(
            base_definition_records,
            _DEFINITION_DECISION_FIELDS,
            duplicate_code="CLASS_DEFINITION_SCOPE_DUPLICATE",
            identity_field="class_definition_resolution_identity",
            excluded_fields=(
                frozenset()
                if base_reconciliation.class_definitions
                else frozenset({"evidence"})
            ),
        )
        if shared_runtime_evidence:
            self._current_definitions = self._base_definitions
        else:
            current_definition_records = self._reconciliation_records(
                current_store, current_reconciliation, "class_definitions",
                "class_definition",
            )
            self._current_definitions = self._compact_records_by_key(
                current_definition_records,
                _DEFINITION_DECISION_FIELDS,
                duplicate_code="CLASS_DEFINITION_SCOPE_DUPLICATE",
                identity_field="class_definition_resolution_identity",
                excluded_fields=(
                    frozenset()
                    if current_reconciliation.class_definitions
                    else frozenset({"evidence"})
                ),
            )
        self._base_resources = self._resource_records_by_key(
            self._reconciliation_records(
                base_store, base_reconciliation, "resource_selections",
                "resource_selection",
            )
        )
        if shared_runtime_evidence:
            self._current_resources = self._base_resources
        else:
            self._current_resources = self._resource_records_by_key(
                self._reconciliation_records(
                    current_store, current_reconciliation,
                    "resource_selections", "resource_selection",
                )
            )
        self._shared_runtime_evidence = shared_runtime_evidence
        self._base_full_definitions = None
        self._current_full_definitions = None
        self._paired_semantic_member_outcome_deltas_cache = None
        self._removed_member_consumer_edges_cache = None
        # Provider comparison touches every runtime class, while artifact
        # placement has only one row per classpath slot.  Cache that tiny table
        # so the hot loop does not issue the same artifact query per class.
        self._provider_artifact_metadata: dict[
            BinaryFactStore, dict[str, tuple[str, int]]
        ] = {}
        self._current_hierarchy_parent_cache: dict[
            tuple[str, str], tuple[str, ...]
        ] = {}

    @staticmethod
    def _reconciliation_chunk_manifest(
        store: BinaryFactStore,
    ) -> tuple[tuple[int, bytes, int], ...]:
        """Return the content-addressed persisted reconciliation inventory."""
        return tuple(
            (int(row[0]), bytes(row[1]), int(row[2]))
            for row in store.connection.execute(
                """
                SELECT record_kind,chunk_identity,record_count
                FROM reconciliation_records
                ORDER BY record_kind,chunk_identity
                """
            )
        )

    @classmethod
    def _validate_shared_runtime_evidence(
        cls,
        *,
        shared_runtime_evidence: bool,
        base_store: BinaryFactStore,
        current_store: BinaryFactStore,
        base_reconciliation: RuntimeReconciliationResult,
        current_reconciliation: RuntimeReconciliationResult,
    ) -> None:
        """Fail closed before aliasing immutable identical-side indexes."""
        if type(shared_runtime_evidence) is not bool:
            raise BinaryFirstContractError(
                "BINARY_DECISION_SHARED_RUNTIME_EVIDENCE_FLAG_INVALID",
                repr(shared_runtime_evidence),
            )
        if not shared_runtime_evidence:
            return
        if base_reconciliation is not current_reconciliation:
            raise BinaryFirstContractError(
                "BINARY_DECISION_SHARED_RUNTIME_RECONCILIATION_NOT_IDENTICAL",
                "shared runtime evidence requires one reconciliation object",
            )
        if (
            base_store is current_store
            or base_store.connection is current_store.connection
        ):
            raise BinaryFirstContractError(
                "BINARY_DECISION_SHARED_RUNTIME_STORE_ALIAS",
                "shared runtime evidence requires two independently owned stores",
            )
        if (
            base_store.connection.in_transaction
            or current_store.connection.in_transaction
        ):
            raise BinaryFirstContractError(
                "BINARY_DECISION_SHARED_RUNTIME_STORE_UNCOMMITTED",
                "shared runtime evidence requires committed stores",
            )
        if cls._reconciliation_chunk_manifest(
            base_store
        ) != cls._reconciliation_chunk_manifest(current_store):
            raise BinaryFirstContractError(
                "BINARY_DECISION_SHARED_RUNTIME_BACKUP_UNPROVEN",
                "persisted reconciliation chunk inventories differ",
            )

    @staticmethod
    def _reconciliation_records(
        store: BinaryFactStore,
        reconciliation: RuntimeReconciliationResult,
        attribute: str,
        record_kind: str,
    ) -> Iterable[Mapping[str, Any]]:
        records = getattr(reconciliation, attribute)
        return records if records else store.reconciliation_payloads(record_kind)

    @staticmethod
    def _compact_records_by_key(
        records: Iterable[Mapping[str, Any]],
        fields: tuple[str, ...],
        *,
        duplicate_code: str,
        identity_field: str,
        excluded_fields: frozenset[str] = frozenset(),
    ) -> dict[tuple[Any, ...], Mapping[str, Any]]:
        compact_records = (
            _CompactDecisionRecord(
                record, fields, excluded_fields=excluded_fields
            )
            for record in records
        )
        return BinaryDecisionEngine._records_by_key(
            compact_records,
            duplicate_code=duplicate_code,
            identity_field=identity_field,
        )

    @staticmethod
    def _member_resolution_payloads(
        store: BinaryFactStore,
        reconciliation: RuntimeReconciliationResult,
    ) -> Iterable[Mapping[str, Any]]:
        records = reconciliation.member_resolutions
        return records if records else store.reconciliation_payloads(
            "member_resolution"
        )

    def _definition_payload(
        self, side: str, key: tuple[str, str]
    ) -> Mapping[str, Any] | None:
        compact = (
            self._base_definitions if side == "base"
            else self._current_definitions
        ).get(key)
        if compact is None:
            return None
        if "evidence" in compact:
            return dict(compact)
        cache_name = (
            "_base_full_definitions"
            if side == "base" else "_current_full_definitions"
        )
        cache = getattr(self, cache_name)
        if cache is None:
            store = self.base_store if side == "base" else self.current_store
            cache = self._records_by_key(
                store.reconciliation_payloads("class_definition"),
                duplicate_code="CLASS_DEFINITION_SCOPE_DUPLICATE",
                identity_field="class_definition_resolution_identity",
            )
            setattr(self, cache_name, cache)
        return cache.get(key)

    @staticmethod
    def _provider_payload(
        record: Mapping[str, Any] | None,
    ) -> dict[str, Any] | None:
        return dict(record) if record is not None else None

    @staticmethod
    def _iter_semantic_member_edges(
        store: BinaryFactStore,
        reconciliation: RuntimeReconciliationResult,
        artifact_lineages: Mapping[str, str],
        providers: Mapping[tuple[Any, ...], Mapping[str, Any]],
    ):
        """Yield executable member edges in the historical semantic-key order.

        Member-resolution evidence is persisted in compressed chunks.  The old
        comparison expanded all chunks into a 300k-entry Python dictionary and
        then built another 300k-entry edge dictionary for each side.  A TEMP
        table keeps the exact join and duplicate checks while bounding Python
        residency to the current rows.  TEMP state never enters the immutable
        generation database.
        """
        connection = store.connection
        table_id = next(_TEMP_TABLE_IDS)
        resolution_table = f"binary_decision_member_resolution_index_{table_id}"
        lineage_table = f"binary_decision_artifact_lineage_{table_id}"
        connection.execute(f"DROP TABLE IF EXISTS temp.{resolution_table}")
        connection.execute(f"DROP TABLE IF EXISTS temp.{lineage_table}")
        connection.execute(
            f"""
            CREATE TEMP TABLE {resolution_table} (
                direct_edge_identity TEXT PRIMARY KEY,
                member_resolution_status TEXT NOT NULL,
                resolved_owner TEXT NOT NULL,
                resolved_realm TEXT NOT NULL,
                initiating_realm TEXT NOT NULL
            ) WITHOUT ROWID
            """
        )
        pending = []
        try:
            for resolution in BinaryDecisionEngine._member_resolution_payloads(
                store, reconciliation
            ):
                pending.append((
                    str(resolution.get("direct_edge_identity") or ""),
                    str(resolution.get("member_resolution_status") or ""),
                    str(resolution.get("resolved_owner") or ""),
                    str(
                        resolution.get(
                            "resolved_defining_loader_realm_identity"
                        ) or ""
                    ),
                    str(
                        resolution.get("initiating_loader_realm_identity") or ""
                    ),
                ))
                if len(pending) >= 2_000:
                    connection.executemany(
                        f"INSERT INTO {resolution_table} VALUES(?,?,?,?,?)",
                        pending,
                    )
                    pending.clear()
            if pending:
                connection.executemany(
                    f"INSERT INTO {resolution_table} VALUES(?,?,?,?,?)",
                    pending,
                )
                pending.clear()
        except sqlite3.IntegrityError as error:
            raise BinaryFirstContractError(
                "MEMBER_RESOLUTION_EDGE_DUPLICATE", str(error)
            ) from error

        connection.execute(
            f"""
            CREATE TEMP TABLE {lineage_table} (
                artifact_instance_identity TEXT PRIMARY KEY,
                logical_dependency_lineage TEXT NOT NULL
            ) WITHOUT ROWID
            """
        )
        lineage_rows = []
        for artifact in store.connection.execute(
            """
            SELECT artifact_instance_identity,runtime_path_kind,
                   runtime_classpath_index
            FROM artifact_instances
            """
        ):
            artifact_identity = str(artifact["artifact_instance_identity"])
            lineage_rows.append((
                artifact_identity,
                str(artifact_lineages.get(artifact_identity) or (
                    f"runtime-slot:{artifact['runtime_path_kind']}:"
                    f"{artifact['runtime_classpath_index']}"
                )),
            ))
        connection.executemany(
            f"INSERT INTO {lineage_table} VALUES(?,?)", lineage_rows
        )

        previous_key = None
        rows = None
        try:
            rows = connection.execute(
                f"""
                SELECT edge.direct_edge_identity,edge.caller_member_identity,
                       edge.caller_artifact_instance_identity,
                       edge.instruction_index,edge.bytecode_offset,
                       edge.edge_kind,edge.opcode,edge.symbolic_owner,
                       edge.symbolic_name,edge.symbolic_descriptor,
                       caller.class_name AS caller_class_name,
                       caller.member_name AS caller_member_name,
                       caller.descriptor AS caller_descriptor,
                       caller.class_variant_identity AS caller_class_variant_identity,
                       artifact.runtime_path_kind,
                       lineage.logical_dependency_lineage,
                       resolution.member_resolution_status,
                       resolution.resolved_owner,resolution.resolved_realm,
                       resolution.initiating_realm
                FROM direct_edges AS edge
                JOIN members AS caller
                  ON caller.member_identity=edge.caller_member_identity
                JOIN artifact_instances AS artifact
                  ON artifact.artifact_instance_identity=
                     edge.caller_artifact_instance_identity
                JOIN temp.{resolution_table} AS resolution
                  ON resolution.direct_edge_identity=edge.direct_edge_identity
                JOIN temp.{lineage_table} AS lineage
                  ON lineage.artifact_instance_identity=
                     edge.caller_artifact_instance_identity
                WHERE edge.edge_kind IN ('method', 'field')
                ORDER BY lineage.logical_dependency_lineage,
                         artifact.runtime_path_kind,
                         caller.class_name,caller.member_name,caller.descriptor,
                         edge.instruction_index,edge.bytecode_offset,edge.opcode,
                         edge.symbolic_owner,edge.symbolic_name,
                         edge.symbolic_descriptor,resolution.initiating_realm
                """
            )
            for raw in rows:
                initiating_realm = str(raw["initiating_realm"] or "")
                provider = providers.get(
                    (initiating_realm, str(raw["caller_class_name"] or ""))
                )
                # The fact store also contains edges from shadowed variants.
                if (
                    not provider
                    or provider.get("class_provider_status") != "resolved"
                    or provider.get("selected_class_variant_identity")
                    != raw["caller_class_variant_identity"]
                ):
                    continue
                key = (
                    str(raw["logical_dependency_lineage"] or ""),
                    str(raw["runtime_path_kind"] or ""),
                    str(raw["caller_class_name"] or ""),
                    str(raw["caller_member_name"] or ""),
                    str(raw["caller_descriptor"] or ""),
                    int(raw["instruction_index"] or 0),
                    int(raw["bytecode_offset"] or 0),
                    int(raw["opcode"] or 0),
                    str(raw["symbolic_owner"] or ""),
                    str(raw["symbolic_name"] or ""),
                    str(raw["symbolic_descriptor"] or ""),
                    initiating_realm,
                )
                if key == previous_key:
                    raise BinaryFirstContractError(
                        "SEMANTIC_MEMBER_EDGE_KEY_DUPLICATE",
                        f"key={key}; duplicate={raw['direct_edge_identity']}",
                    )
                previous_key = key
                edge = {
                    field: raw[field]
                    for field in (
                        "direct_edge_identity", "caller_member_identity",
                        "caller_artifact_instance_identity",
                        "instruction_index", "bytecode_offset", "edge_kind",
                        "opcode", "symbolic_owner", "symbolic_name",
                        "symbolic_descriptor",
                    )
                }
                outcome = (
                    str(raw["member_resolution_status"] or ""),
                    str(raw["resolved_owner"] or ""),
                    str(raw["resolved_realm"] or ""),
                )
                yield key, edge, outcome
        finally:
            if rows is not None:
                rows.close()
            connection.execute(f"DROP TABLE IF EXISTS temp.{resolution_table}")
            connection.execute(f"DROP TABLE IF EXISTS temp.{lineage_table}")

    @staticmethod
    def _resolution_payloads_for_edges(
        store: BinaryFactStore,
        reconciliation: RuntimeReconciliationResult,
        edge_identities: set[str],
    ) -> dict[str, Mapping[str, Any]]:
        if not edge_identities:
            return {}
        output = {}
        for resolution in BinaryDecisionEngine._member_resolution_payloads(
            store, reconciliation
        ):
            edge_identity = str(resolution.get("direct_edge_identity") or "")
            if edge_identity not in edge_identities:
                continue
            if edge_identity in output:
                raise BinaryFirstContractError(
                    "MEMBER_RESOLUTION_EDGE_DUPLICATE", edge_identity
                )
            output[edge_identity] = resolution
        missing = sorted(edge_identities - set(output))
        if missing:
            raise BinaryFirstContractError(
                "MEMBER_RESOLUTION_EDGE_MISSING", str(missing[:10])
            )
        return output

    def _paired_semantic_member_outcome_deltas(self):
        cached = getattr(
            self, "_paired_semantic_member_outcome_deltas_cache", None
        )
        if cached is not None:
            return cached
        legacy = getattr(self, "_paired_semantic_member_edges_cache", None)
        if legacy is not None:
            base_edges, current_edges = legacy
            cached = tuple(
                (
                    key,
                    base_edges[key][0],
                    base_edges[key][1],
                    current_edges[key][0],
                    current_edges[key][1],
                )
                for key in sorted(set(base_edges).intersection(current_edges))
                if (
                    str(base_edges[key][1].get("member_resolution_status") or ""),
                    str(base_edges[key][1].get("resolved_owner") or ""),
                    str(base_edges[key][1].get(
                        "resolved_defining_loader_realm_identity"
                    ) or ""),
                ) != (
                    str(current_edges[key][1].get("member_resolution_status") or ""),
                    str(current_edges[key][1].get("resolved_owner") or ""),
                    str(current_edges[key][1].get(
                        "resolved_defining_loader_realm_identity"
                    ) or ""),
                )
            )
            self._paired_semantic_member_outcome_deltas_cache = cached
            return cached
        base_rows = iter(self._iter_semantic_member_edges(
            self.base_store,
            self.base_runtime,
            self._base_artifact_lineages,
            self._base_providers,
        ))
        current_rows = iter(self._iter_semantic_member_edges(
            self.current_store,
            self.current_runtime,
            self._current_artifact_lineages,
            self._current_providers,
        ))
        compact_deltas = []
        try:
            base = next(base_rows, None)
            current = next(current_rows, None)
            while base is not None and current is not None:
                if base[0] < current[0]:
                    base = next(base_rows, None)
                    continue
                if current[0] < base[0]:
                    current = next(current_rows, None)
                    continue
                if base[2] != current[2]:
                    compact_deltas.append((base[0], base[1], current[1]))
                base = next(base_rows, None)
                current = next(current_rows, None)
        finally:
            close = getattr(base_rows, "close", None)
            if close is not None:
                close()
            close = getattr(current_rows, "close", None)
            if close is not None:
                close()
        base_edge_ids = {
            str(item[1]["direct_edge_identity"]) for item in compact_deltas
        }
        current_edge_ids = {
            str(item[2]["direct_edge_identity"]) for item in compact_deltas
        }
        base_resolutions = self._resolution_payloads_for_edges(
            self.base_store, self.base_runtime, base_edge_ids
        )
        current_resolutions = self._resolution_payloads_for_edges(
            self.current_store, self.current_runtime, current_edge_ids
        )
        cached = tuple(
            (
                key,
                base_edge,
                base_resolutions[str(base_edge["direct_edge_identity"])],
                current_edge,
                current_resolutions[str(current_edge["direct_edge_identity"])],
            )
            for key, base_edge, current_edge in compact_deltas
        )
        self._paired_semantic_member_outcome_deltas_cache = cached
        return cached

    @staticmethod
    def _semantic_member_edges(
        store: BinaryFactStore,
        reconciliation: RuntimeReconciliationResult,
        artifact_lineages: Mapping[str, str],
    ) -> dict[tuple[Any, ...], tuple[dict[str, Any], dict[str, Any], dict[str, Any]]]:
        """Compatibility helper retained for focused external tests/callers."""
        resolutions = BinaryDecisionEngine._unique_index(
            BinaryDecisionEngine._member_resolution_payloads(store, reconciliation),
            ("direct_edge_identity",),
            duplicate_code="MEMBER_RESOLUTION_EDGE_DUPLICATE",
            identity_field="member_resolution_identity",
        )
        providers = BinaryDecisionEngine._unique_index(
            BinaryDecisionEngine._reconciliation_records(
                store, reconciliation, "provider_bindings", "provider_binding"
            ),
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
            WHERE edge.edge_kind IN ('method', 'field')
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

    def _removed_member_consumer_edges(self) -> Mapping[tuple[str, ...], tuple[str, ...]]:
        """Bind current unresolved edges to the member resolved on the base side.

        A JVM reference may name a child while member resolution selects a
        declaration inherited from a parent.  Once that parent declaration is
        removed, the current-side edge has only the child symbolic owner and a
        ``no_such_member`` status.  Preserve the paired base resolution here so
        tracing can attribute the failing edge to the declaration that changed.
        """

        cached = self._removed_member_consumer_edges_cache
        if cached is not None:
            return cached
        grouped: dict[tuple[str, ...], set[str]] = {}
        for (
            _semantic_key,
            base_edge,
            base_resolution,
            current_edge,
            current_resolution,
        ) in self._paired_semantic_member_outcome_deltas():
            if (
                base_resolution.get("member_resolution_status") != "resolved"
                or current_resolution.get("member_resolution_status")
                != "no_such_member"
            ):
                continue
            owner = str(base_resolution.get("resolved_owner") or "")
            realm = str(
                current_resolution.get("initiating_loader_realm_identity")
                or base_resolution.get("initiating_loader_realm_identity")
                or ""
            )
            kind = "field" if base_edge.get("edge_kind") == "field" else "method"
            target = (
                realm,
                owner,
                kind,
                str(base_edge.get("symbolic_name") or ""),
                str(base_edge.get("symbolic_descriptor") or ""),
            )
            grouped.setdefault(target, set()).add(
                str(current_edge["direct_edge_identity"])
            )
        cached = {
            key: tuple(sorted(edge_ids)) for key, edge_ids in grouped.items()
        }
        self._removed_member_consumer_edges_cache = cached
        return cached

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

    def _artifact_runtime_metadata(
        self, store: BinaryFactStore
    ) -> dict[str, tuple[str, int]]:
        cached = self._provider_artifact_metadata.get(store)
        if cached is None:
            cached = {
                str(row[0]): (str(row[1]), int(row[2]))
                for row in store.connection.execute(
                    """
                    SELECT artifact_instance_identity,runtime_path_kind,
                           runtime_classpath_index
                    FROM artifact_instances
                    """
                )
            }
            self._provider_artifact_metadata[store] = cached
        return cached

    def _provider_outcome_payload(
        self,
        store: BinaryFactStore,
        record: Mapping[str, Any] | None,
        artifact_lineages: Mapping[str, str],
    ) -> dict[str, Any] | None:
        if not record:
            return None
        status = record.get("class_provider_status")
        if status != "resolved":
            return {
                "status": status,
                "evidence": record.get("selection_evidence") or {},
            }
        variant = record.get("selected_class_variant_identity")
        class_row = store.connection.execute(
            """
            SELECT class_name,multi_release_version
            FROM classes WHERE class_variant_identity=?
            """,
            (variant,),
        ).fetchone()
        if class_row is not None:
            artifact_identity = str(
                record.get("selected_artifact_instance_identity") or ""
            )
            artifact = self._artifact_runtime_metadata(store).get(
                artifact_identity
            )
            runtime_path_kind = artifact[0] if artifact is not None else None
            runtime_classpath_index = (
                artifact[1] if artifact is not None else None
            )
            lineage = str(artifact_lineages.get(artifact_identity) or "")
            if not lineage:
                # A content-addressed extraction path is provenance, not JVM
                # provider topology.  When no explicit cross-version lineage
                # exists, the stable runtime slot is the only safe comparable
                # provider identity.
                lineage = (
                    f"runtime-slot:{runtime_path_kind}:"
                    f"{runtime_classpath_index}"
                )
            payload = {
                "status": "resolved",
                "class_name": class_row[0],
                "multi_release_version": class_row[1],
                "defining_loader_realm_identity": record.get("selected_defining_loader_realm_identity"),
                "runtime_path_kind": runtime_path_kind,
                "runtime_classpath_index": runtime_classpath_index,
                "logical_dependency_lineage": lineage,
            }
        else:
            payload = {
                "status": "resolved",
                "platform_class_variant_identity": variant,
                "selected_artifact_instance_identity": record.get("selected_artifact_instance_identity"),
                "defining_loader_realm_identity": record.get("selected_defining_loader_realm_identity"),
            }
        return payload

    def _provider_fingerprint(
        self,
        store: BinaryFactStore,
        record: Mapping[str, Any] | None,
        artifact_lineages: Mapping[str, str],
    ) -> str:
        payload = self._provider_outcome_payload(
            store, record, artifact_lineages
        )
        return (
            "ABSENT"
            if payload is None
            else _identity("provider_outcome_fingerprint", payload)
        )

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
                                    "base_provider": self._provider_payload(
                                        base_provider
                                    ),
                                    "current_provider": self._provider_payload(
                                        current_provider
                                    ),
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
                        evidence = {
                            "upstream_artifact_observed_delta_identity": (
                                upstream_observed
                            ),
                            "base_provider_binding_identity": (base_provider or {}).get("provider_binding_identity"),
                            "current_provider_binding_identity": (current_provider or {}).get("provider_binding_identity"),
                            "base_member_fingerprint": member_delta.get("base_member_fingerprint"),
                            "current_member_fingerprint": member_delta.get("current_member_fingerprint"),
                            "base_contract": member_delta.get("base_contract"),
                            "current_contract": member_delta.get("current_contract"),
                        }
                        if change_kind == "removed" and fact_kind in {"method", "field"}:
                            unresolved_edges = self._removed_member_consumer_edges().get((
                                realm,
                                class_name,
                                fact_kind,
                                str(scope.get("member_name") or ""),
                                str(scope.get("descriptor") or ""),
                            ), ())
                            if unresolved_edges:
                                evidence["current_unresolved_direct_edge_identities"] = list(
                                    unresolved_edges
                                )
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
                            evidence=evidence,
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
            base_provider_payload = self._provider_outcome_payload(
                self.base_store, base, self._base_artifact_lineages
            )
            current_provider_payload = self._provider_outcome_payload(
                self.current_store, current, self._current_artifact_lineages
            )
            provider_changed = not _same_json_value(
                base_provider_payload, current_provider_payload
            )
            base_definition = self._base_definitions.get((realm, class_name))
            current_definition = self._current_definitions.get((realm, class_name))
            old_status = (base_definition or {}).get(
                "class_definition_status", "ABSENT"
            )
            new_status = (current_definition or {}).get(
                "class_definition_status", "ABSENT"
            )
            definition_changed = old_status != new_status
            if not provider_changed and not definition_changed:
                continue
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
            if provider_changed:
                old_fp = (
                    "ABSENT"
                    if base_provider_payload is None
                    else _identity(
                        "provider_outcome_fingerprint", base_provider_payload
                    )
                )
                new_fp = (
                    "ABSENT"
                    if current_provider_payload is None
                    else _identity(
                        "provider_outcome_fingerprint", current_provider_payload
                    )
                )
                base_identity = str(
                    (base or {}).get("selected_artifact_instance_identity") or ""
                )
                current_identity = str(
                    (current or {}).get("selected_artifact_instance_identity") or ""
                )
                base_lineage = str(
                    self._base_artifact_lineages.get(base_identity) or ""
                )
                current_lineage = str(
                    self._current_artifact_lineages.get(current_identity) or ""
                )
                lineage = (
                    base_lineage
                    if base_lineage and base_lineage == current_lineage
                    else ""
                )
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
                    evidence={
                        "base_provider": self._provider_payload(base),
                        "current_provider": self._provider_payload(current),
                    },
                    dependency_artifacts=self._dependency_artifacts(
                        base_identity,
                        current_identity,
                        lineage=lineage,
                    ),
                )

            if not definition_changed:
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
            base_definition_payload = self._definition_payload(
                "base", (realm, class_name)
            )
            current_definition_payload = self._definition_payload(
                "current", (realm, class_name)
            )
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
                evidence={
                    "base_definition": base_definition_payload,
                    "current_definition": current_definition_payload,
                },
                dependency_artifacts=self._dependency_artifacts(
                    str((base or {}).get("selected_artifact_instance_identity") or ""),
                    str((current or {}).get("selected_artifact_instance_identity") or ""),
                ),
            )
        self._process_resource_outcome_deltas()

    def _process_member_resolution_deltas(self) -> None:
        for (
            key,
            base_edge,
            base_resolution,
            current_edge,
            current_resolution,
        ) in self._paired_semantic_member_outcome_deltas():
            base_status = str(
                base_resolution.get("member_resolution_status") or ""
            )
            current_status = str(
                current_resolution.get("member_resolution_status") or ""
            )
            base_owner = str(base_resolution.get("resolved_owner") or "")
            current_owner = str(current_resolution.get("resolved_owner") or "")
            base_realm = str(
                base_resolution.get("resolved_defining_loader_realm_identity") or ""
            )
            current_realm = str(
                current_resolution.get("resolved_defining_loader_realm_identity") or ""
            )
            base_outcome = (base_status, base_owner, base_realm)
            current_outcome = (current_status, current_owner, current_realm)
            if base_outcome == current_outcome:
                continue
            realm = str(
                current_resolution.get("initiating_loader_realm_identity")
                or base_resolution.get("initiating_loader_realm_identity")
                or ""
            )
            symbolic_owner = str(current_edge.get("symbolic_owner") or "")
            # A reference may name Child.m while JVM resolution selected the
            # declaration Parent.m on the base side.  If that declaration is
            # removed, the public changed-API identity is Parent.m; emitting a
            # second synthetic Child.m change creates a false positive and
            # breaks path continuity between the artifact delta and runtime
            # resolution evidence.
            owner = (
                base_owner
                if (
                    base_status == "resolved"
                    and current_status == "no_such_member"
                    and base_owner
                    and self._current_hierarchy_contains(
                        realm, symbolic_owner, base_owner
                    )
                )
                else symbolic_owner
            )
            scope = {
                "initiating_loader_realm_identity": realm,
                "class_name": owner,
                "member_kind": (
                    "field" if current_edge.get("edge_kind") == "field" else "method"
                ),
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
                    "status": base_status, "owner": base_owner,
                    "realm": base_realm,
                }),
                current_fingerprint=_identity("member_resolution_outcome", {
                    "status": current_status, "owner": current_owner,
                    "realm": current_realm,
                }),
            )
            base_provider = self._base_providers.get((realm, owner))
            current_provider = self._current_providers.get((realm, owner))
            target = self._member_target(realm, owner, scope)
            definite = {base_status, current_status}.issubset({
                "resolved", "no_such_member",
            })
            self._decision(
                observed_identity=observed,
                channel="authoritative" if definite else "diagnostic",
                reason_code=(
                    "RUNTIME_MEMBER_RESOLUTION_CHANGED"
                    if definite else
                    "RUNTIME_MEMBER_RESOLUTION_CHANGE_INCOMPLETE"
                ),
                fact_kind="member_resolution",
                fact_scope=scope,
                target_identity=target,
                coverage_gaps=(
                    () if definite else ("member_resolution_outcome_not_definite",)
                ),
                evidence={
                    "symbolic_owner": symbolic_owner,
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

    def _current_hierarchy_contains(
        self, realm: str, child: str, ancestor: str,
    ) -> bool:
        """Whether the selected current runtime hierarchy still contains ancestor."""
        if not child or not ancestor:
            return False
        if child == ancestor:
            return True
        pending = [child]
        visited = set()
        while pending:
            candidate = pending.pop()
            if candidate in visited:
                continue
            visited.add(candidate)
            for parent in self._current_class_parents(realm, candidate):
                if not parent:
                    continue
                if parent == ancestor:
                    return True
                if parent not in visited:
                    pending.append(parent)
        return False

    def _current_class_parents(
        self, realm: str, class_name: str,
    ) -> tuple[str, ...]:
        """Read parents from the exact class variant selected for this realm.

        Target-JVM verification proves that definition succeeds, but its public
        observation intentionally does not duplicate the parsed hierarchy.  The
        selected variant's immutable ASM fact is therefore the authoritative
        source for superclass and interface traversal.
        """
        cache = getattr(self, "_current_hierarchy_parent_cache", None)
        if cache is None:
            cache = {}
            self._current_hierarchy_parent_cache = cache
        key = (realm, class_name)
        if key in cache:
            return cache[key]

        parents: tuple[str, ...] = ()
        provider = self._current_providers.get(key) or {}
        variant = str(provider.get("selected_class_variant_identity") or "")
        if variant:
            row = self.current_store.connection.execute(
                "SELECT fact_zlib FROM classes WHERE class_variant_identity=?",
                (variant,),
            ).fetchone()
            if row is not None:
                compressed = row["fact_zlib"] if hasattr(row, "keys") else row[0]
                fact = json.loads(zlib.decompress(compressed).decode("utf-8"))
                parents = tuple(
                    str(value)
                    for value in (
                        fact.get("super_name"),
                        *(fact.get("interfaces") or ()),
                    )
                    if value
                )

        # Keep compatibility with richer verifier implementations without
        # relying on hierarchy fields that are absent from today's protocol.
        if not parents:
            definition = self._definition_payload("current", key) or {}
            observation = (
                (definition.get("evidence") or {}).get(
                    "target_jvm_verification"
                )
                or {}
            )
            parents = tuple(
                str(value)
                for value in (
                    observation.get("super_name"),
                    *(observation.get("interfaces") or ()),
                )
                if value
            )
        cache[key] = parents
        return parents

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
