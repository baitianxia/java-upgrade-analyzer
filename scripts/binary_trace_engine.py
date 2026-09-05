#!/usr/bin/env python3
"""Trace formal and diagnostic binary projections over the effective JVM graph."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterator
from dataclasses import dataclass
import json
from typing import Any, Mapping

from binary_decision_engine import BinaryDecisionBundle
from binary_entrypoint_discovery import (
    BinaryEntrypointDiscoveryResult,
    discover_binary_entrypoints,
)
from binary_fact_store import BinaryFactStore
from binary_first_contract import canonical_identity, derive_formal_result_state
from binary_first_model import RuntimeProfile
from binary_runtime_reconciler import (
    RuntimeReconciliationResult,
    hydrate_runtime_reconciliation,
)


ACC_PUBLIC = 0x0001
ACC_PRIVATE = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC = 0x0008
ACC_FINAL = 0x0010
ACC_ABSTRACT = 0x0400


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


def _loads(value: str) -> Any:
    return json.loads(value or "{}")


def _visibility_rank(access: Any) -> int:
    flags = int(access or 0)
    if flags & ACC_PUBLIC:
        return 3
    if flags & ACC_PROTECTED:
        return 2
    if flags & ACC_PRIVATE:
        return 0
    return 1


def _contract_change_linkage_reasons(
    decision: Mapping[str, Any],
) -> frozenset[str]:
    scope = decision.get("fact_scope") or {}
    if scope.get("member_change_kind") != "contract_changed":
        return frozenset()
    evidence = decision.get("evidence") or {}
    base = evidence.get("base_contract")
    current = evidence.get("current_contract")
    if not isinstance(base, Mapping) or not isinstance(current, Mapping):
        return frozenset()
    base_access = int(base.get("access") or 0)
    current_access = int(current.get("access") or 0)
    reasons = set()
    if _visibility_rank(current_access) < _visibility_rank(base_access):
        reasons.add("access_reduced")
    if bool(base_access & ACC_STATIC) != bool(current_access & ACC_STATIC):
        reasons.add("static_instance_changed")
    if (
        not bool(base_access & ACC_ABSTRACT)
        and bool(current_access & ACC_ABSTRACT)
    ):
        reasons.add("became_abstract")
    if (
        scope.get("member_kind") == "method"
        and not bool(base_access & ACC_FINAL)
        and bool(current_access & ACC_FINAL)
    ):
        reasons.add("became_final")
    return frozenset(reasons)


def _contract_change_breaks_linkage(decision: Mapping[str, Any]) -> bool:
    return bool(_contract_change_linkage_reasons(decision))


def _access_reduction_is_legal_on_observed_paths(
    decision: Mapping[str, Any],
    *,
    has_path: bool,
    resolution_statuses: set[str],
    linkage_statuses: set[str],
    caller_definition_statuses: set[str],
) -> bool:
    """Allow the target-runtime access check to refine a visibility delta.

    A public member becoming protected is not universally incompatible: a
    selected call from a valid subclass (or from the same runtime package) is
    still legal.  Artifact-local visibility rank cannot decide that question;
    only the reconciled caller/provider path can.  Other contract changes such
    as static/instance, abstract, or final transitions are never discharged by
    this refinement.
    """
    return (
        _contract_change_linkage_reasons(decision) == {"access_reduced"}
        and has_path
        and resolution_statuses == {"resolved"}
        and linkage_statuses.issubset({"resolved"})
        and caller_definition_statuses == {"definition_ready"}
    )


def _unresolved_edge_certainty(
    status: str, *, paired_artifact_change: bool = False,
) -> str:
    return (
        "exact"
        if status == "no_such_member"
        or (
            paired_artifact_change
            and status in {"no_class_definition", "class_definition_failed"}
        )
        else "possible"
    )


class _ExecutableResolutionRow(Mapping[str, Any]):
    """One state object shared by member, dispatch, and linkage indexes."""

    __slots__ = (
        "direct_edge_identity", "member_resolution_status",
        "resolved_member_identity", "member_resolution_identity",
        "initiating_loader_realm_identity", "dispatch_status",
        "implementation_target_identities", "dispatch_resolution_identity",
        "linkage_status",
    )
    FIELDS = __slots__
    FIELD_SET = frozenset(FIELDS)

    def __init__(self, direct_edge_identity: str) -> None:
        self.direct_edge_identity = direct_edge_identity
        self.member_resolution_status = ""
        self.resolved_member_identity = ""
        self.member_resolution_identity = ""
        self.initiating_loader_realm_identity = ""
        self.dispatch_status = ""
        self.implementation_target_identities = ()
        self.dispatch_resolution_identity = ""
        self.linkage_status = ""

    def __getitem__(self, key: str) -> Any:
        if key not in self.FIELD_SET:
            raise KeyError(key)
        return getattr(self, key)

    def __iter__(self) -> Iterator[str]:
        return iter(self.FIELDS)

    def __len__(self) -> int:
        return len(self.FIELDS)


class _IncomingTraceEdge(Mapping[str, Any]):
    """Compact reverse edge with private linkage facts for selected paths."""

    __slots__ = (
        "caller_member_identity", "direct_edge_identity", "certainty",
        "member_resolution_identity", "dispatch_resolution_identity",
        "class_initialization_resolution_identity", "inline_overlay_identity",
        "semantic_edge_identity", "resolution_status", "linkage_status",
        "initiating_loader_realm_identity",
    )
    REQUIRED_FIELDS = (
        "caller_member_identity", "direct_edge_identity", "certainty",
        "member_resolution_identity", "dispatch_resolution_identity",
    )
    OPTIONAL_FIELDS = (
        "class_initialization_resolution_identity", "inline_overlay_identity",
        "semantic_edge_identity",
    )

    def __init__(
        self,
        *,
        caller_member_identity: str,
        direct_edge_identity: str,
        certainty: str,
        member_resolution_identity: str = "",
        dispatch_resolution_identity: str = "",
        class_initialization_resolution_identity: str = "",
        inline_overlay_identity: str = "",
        semantic_edge_identity: str = "",
        resolution_status: str = "",
        linkage_status: str = "",
        initiating_loader_realm_identity: str = "",
    ) -> None:
        self.caller_member_identity = caller_member_identity
        self.direct_edge_identity = direct_edge_identity
        self.certainty = certainty
        self.member_resolution_identity = member_resolution_identity
        self.dispatch_resolution_identity = dispatch_resolution_identity
        self.class_initialization_resolution_identity = (
            class_initialization_resolution_identity
        )
        self.inline_overlay_identity = inline_overlay_identity
        self.semantic_edge_identity = semantic_edge_identity
        self.resolution_status = resolution_status
        self.linkage_status = linkage_status
        self.initiating_loader_realm_identity = initiating_loader_realm_identity

    def __getitem__(self, key: str) -> Any:
        if key not in self.REQUIRED_FIELDS and key not in self.OPTIONAL_FIELDS:
            raise KeyError(key)
        value = getattr(self, key)
        if key in self.OPTIONAL_FIELDS and not value:
            raise KeyError(key)
        return value

    def __iter__(self) -> Iterator[str]:
        yield from self.REQUIRED_FIELDS
        for key in self.OPTIONAL_FIELDS:
            if getattr(self, key):
                yield key

    def __len__(self) -> int:
        return len(self.REQUIRED_FIELDS) + sum(
            bool(getattr(self, key)) for key in self.OPTIONAL_FIELDS
        )


_EDGE_COLUMNS = (
    "direct_edge_identity", "caller_member_identity",
    "caller_artifact_instance_identity", "instruction_index",
    "bytecode_offset", "edge_kind", "opcode", "symbolic_owner",
    "symbolic_name", "symbolic_descriptor", "edge_json",
)
_MEMBER_COLUMNS = (
    "member_identity", "class_name", "member_name", "descriptor",
)
_GRAPH_EDGE_COLUMNS = (
    "direct_edge_identity", "caller_member_identity", "edge_kind",
    "symbolic_owner", "symbolic_name", "symbolic_descriptor",
)


class _SQLiteTraceRowLookup(Mapping[str, Mapping[str, Any]]):
    """Lazy fact lookup; complete table scans are explicit streaming iterators."""

    __slots__ = ("connection", "table", "identity_column", "columns", "_cache")
    CACHE_LIMIT = 16_384

    def __init__(self, connection, table, identity_column, columns) -> None:
        self.connection = connection
        self.table = table
        self.identity_column = identity_column
        self.columns = tuple(columns)
        self._cache: dict[str, dict[str, Any]] = {}

    @property
    def _projection(self) -> str:
        return ",".join(self.columns)

    def __getitem__(self, identity: str) -> Mapping[str, Any]:
        key = str(identity)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        row = self.connection.execute(
            f"SELECT {self._projection} FROM {self.table} "
            f"WHERE {self.identity_column}=?",
            (key,),
        ).fetchone()
        if row is None:
            raise KeyError(key)
        value = dict(row)
        if len(self._cache) >= self.CACHE_LIMIT:
            self._cache.clear()
        self._cache[key] = value
        return value

    def __iter__(self) -> Iterator[str]:
        for row in self.connection.execute(
            f"SELECT {self.identity_column} FROM {self.table}"
        ):
            yield str(row[0])

    def __len__(self) -> int:
        return int(self.connection.execute(
            f"SELECT COUNT(*) FROM {self.table}"
        ).fetchone()[0])

    def iter_graph_items(
        self,
        columns: tuple[str, ...] | None = None,
    ) -> Iterator[tuple[str, Mapping[str, Any]]]:
        projection = (
            self._projection
            if columns is None else ",".join(str(column) for column in columns)
        )
        for row in self.connection.execute(
            f"SELECT {projection} FROM {self.table}"
        ):
            # The narrow graph projection is consumed immediately by the
            # reverse-graph builder. Retain sqlite3.Row there instead of
            # copying every scanned edge into a temporary dict; the default
            # full projection keeps the historical mapping contract.
            value = row if columns is not None else dict(row)
            yield str(row[self.identity_column]), value

    def iter_matching_items(
        self, identities: tuple[str, ...]
    ) -> Iterator[tuple[str, Mapping[str, Any]]]:
        # Auxiliary resolution payloads already contain their symbolic facts;
        # only the caller is absent. Avoid fetching edge_json and the other
        # nine columns through millions of random primary-key probes.
        projection = f"{self.identity_column},caller_member_identity"
        for offset in range(0, len(identities), 400):
            chunk = identities[offset:offset + 400]
            placeholders = ",".join("?" for _value in chunk)
            for row in self.connection.execute(
                f"SELECT {projection} FROM {self.table} "
                f"WHERE {self.identity_column} IN ({placeholders})",
                chunk,
            ):
                yield str(row[self.identity_column]), dict(row)

    def iter_service_activation_rows(
        self, service_owners: tuple[str, ...]
    ) -> Iterator[Mapping[str, Any]]:
        if self.table != "direct_edges":
            return
        # The ServiceLoader call shape is shared by every service type.
        for row in self.connection.execute(
            f"""
            SELECT {self._projection} FROM direct_edges
            WHERE edge_kind='method'
              AND symbolic_owner='java/util/ServiceLoader'
              AND symbolic_name='load'
              AND symbolic_descriptor GLOB '(Ljava/lang/Class;*'
            """
        ):
            yield dict(row)
        # SQLite builds use different variable limits. Keep each indexed IN
        # probe comfortably below the historical 999-parameter floor.
        for offset in range(0, len(service_owners), 400):
            chunk = service_owners[offset:offset + 400]
            placeholders = ",".join("?" for _value in chunk)
            for row in self.connection.execute(
                f"""
                SELECT {self._projection} FROM direct_edges
                WHERE edge_kind='type'
                  AND symbolic_owner IN ({placeholders})
                """,
                chunk,
            ):
                yield dict(row)


@dataclass(frozen=True)
class _TraceRuntimeView:
    coverage_gaps: tuple[str, ...]
    identity: str = ""


@dataclass(frozen=True)
class BinaryTraceBundle:
    analysis_context_identity: str
    formal_results: tuple[dict[str, Any], ...]
    candidate_results: tuple[dict[str, Any], ...]
    trace_result_set_digest: str
    coverage_status: str
    coverage_gaps: tuple[str, ...]
    identity: str
    graph_stats: Mapping[str, Any] | None = None
    resource_activation_results: tuple[dict[str, Any], ...] = ()
    entrypoint_discovery_identity: str = ""
    entrypoint_records: tuple[dict[str, Any], ...] = ()
    entrypoint_coverage_status: str = "complete"
    entrypoint_coverage_gaps: tuple[str, ...] = ()


class BinaryTraceEngine:
    def __init__(
        self,
        store: BinaryFactStore,
        runtime_profile: RuntimeProfile,
        reconciliation: RuntimeReconciliationResult,
        decisions: BinaryDecisionBundle,
        *,
        entrypoint_discovery: BinaryEntrypointDiscoveryResult | None = None,
        inline_overlay: Any | None = None,
        semantic_overlay: Any | None = None,
        max_visited_nodes: int = 1_000_000,
        max_paths_per_target: int = 20,
        materialize_graph: bool = True,
    ):
        self.store = store
        self.profile = runtime_profile
        self.runtime = _TraceRuntimeView(
            tuple(getattr(reconciliation, "coverage_gaps", ())),
            str(getattr(reconciliation, "identity", "") or ""),
        )
        self.decisions = decisions
        self.max_visited_nodes = max_visited_nodes
        self.max_paths_per_target = max_paths_per_target
        self.inline_overlay = inline_overlay
        self.semantic_overlay = semantic_overlay
        self.entrypoint_discovery = entrypoint_discovery or discover_binary_entrypoints(
            store, runtime_profile, reconciliation
        )
        (
            self.exact_entrypoints,
            self.possible_entrypoints,
            self.entrypoint_gaps,
        ) = self._entrypoints()
        self.entrypoints = self.exact_entrypoints | self.possible_entrypoints
        self.entrypoint_records_by_member: dict[
            str, list[dict[str, Any]]
        ] = defaultdict(list)
        for item in self.entrypoint_discovery.records:
            self.entrypoint_records_by_member[item["member_identity"]].append(item)
        self.providers = {
            (item["initiating_loader_realm_identity"], item["class_name"]): item
            for item in reconciliation.provider_bindings
        }
        self.paired_artifact_missing_targets = {
            self._symbolic_target(
                str(scope.get("class_name") or "").replace(".", "/"),
                str(scope.get("member_name") or ""),
                str(scope.get("descriptor") or ""),
                str(scope.get("member_kind") or decision.get("fact_kind") or ""),
            )
            for decision in decisions.authoritative_decisions
            for scope in [decision.get("fact_scope") or {}]
            if scope.get("member_change_kind") == "removed"
            and (scope.get("member_kind") or decision.get("fact_kind"))
            in {"method", "field"}
            and {"base", "current"}.issubset({
                str(artifact.get("side") or "")
                for artifact in decision.get("dependency_artifacts") or ()
            })
        }
        self.unresolved_edge_alias_targets: dict[str, set[str]] = defaultdict(set)
        for decision in (
            *decisions.authoritative_decisions,
            *decisions.diagnostic_decisions,
        ):
            scope = decision.get("fact_scope") or {}
            kind = str(scope.get("member_kind") or decision.get("fact_kind") or "")
            if kind not in {"method", "field"}:
                continue
            target = self._symbolic_target(
                str(scope.get("class_name") or "").replace(".", "/"),
                str(scope.get("member_name") or ""),
                str(scope.get("descriptor") or ""),
                kind,
            )
            for edge_id in (
                (decision.get("evidence") or {}).get(
                    "current_unresolved_direct_edge_identities"
                )
                or ()
            ):
                self.unresolved_edge_alias_targets[str(edge_id)].add(target)
        self.reverse: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        self._trace_cache: dict[
            tuple[str, ...], tuple[list[dict[str, Any]], list[str]]
        ] = {}
        self._path_outcomes: dict[str, tuple[str, str, str]] = {}
        if materialize_graph:
            self.members = _SQLiteTraceRowLookup(
                store.connection, "members", "member_identity", _MEMBER_COLUMNS
            )
            self.edges = _SQLiteTraceRowLookup(
                store.connection,
                "direct_edges",
                "direct_edge_identity",
                _EDGE_COLUMNS,
            )
            self.semantic_edges = {
                row["semantic_edge_identity"]: row
                for row in getattr(semantic_overlay, "rows", ())
            }
            self._node_identity_pool: dict[str, str] = {}
            self._load_compact_resolution_indexes(reconciliation)
            self.class_definition_statuses = {
                (
                    str(item.get("initiating_loader_realm_identity") or ""),
                    str(item.get("class_name") or ""),
                ): str(item.get("class_definition_status") or "")
                for item in reconciliation.class_definitions
            }
            self._stream_auxiliary_resolutions = True
            self._release_resolution_indexes_after_build = True
            self._build_reverse_graph()
            self._prepare_batch_graph()
        else:
            if self.entrypoints:
                raise ValueError(
                    "graph-free trace construction requires an empty entrypoint set"
                )
            self.members = {}
            self.edges = {}
            self.semantic_edges = {}
            self.member_resolutions = {}
            self.dispatch = {}
            self.type_resolutions = {}
            self.class_initializations = {}
            self.linkage_resolutions = {}
            self.class_definition_statuses = {}
            self._stream_auxiliary_resolutions = False
            self._release_resolution_indexes_after_build = False
            self.exact_reachable_nodes = set()
            self.possible_reachable_nodes = set()
            self.possible_path_nodes = set()
            self.graph_stats = {
                "batch_transition_build": "skipped_no_entrypoints_v1",
                "graph_materialization_status": "not_required_empty_root_set",
                "node_count": 0,
                "effective_edge_count": 0,
                "possible_edge_count": 0,
                "runtime_semantic_edge_count": len(
                    getattr(semantic_overlay, "rows", ())
                ),
                "runtime_semantic_overlay_identity": str(
                    getattr(semantic_overlay, "identity", "") or ""
                ),
                "entrypoint_count": 0,
                "exact_entrypoint_count": 0,
                "possible_entrypoint_count": 0,
                "entrypoint_discovery_identity": self.entrypoint_discovery.identity,
                "exact_reachable_node_count": 0,
                "possible_reachable_node_count": 0,
                "exact_scc_count": 0,
                "exact_largest_scc_size": 0,
                "possible_scc_count": 0,
                "possible_largest_scc_size": 0,
                "path_enumeration": "not_required_empty_root_set_v1",
            }
            self.batch_graph_identity = _identity(
                "binary_batch_trace_graph_identity", self.graph_stats
            )
        self.decision_by_identity = {
            item["decision_identity"]: item
            for item in (
                *decisions.authoritative_decisions,
                *decisions.diagnostic_decisions,
                *decisions.excluded_decisions,
            )
        }
        self.assessment_by_identity = {
            item["projection_assessment_identity"]: item
            for item in decisions.projection_assessments
        }

    @staticmethod
    def _shared_value(pool: dict[str, str], value: Any) -> str:
        normalized = str(value or "")
        return pool.setdefault(normalized, normalized)

    def _resolution_records(
        self,
        reconciliation: RuntimeReconciliationResult,
        attribute: str,
        record_kind: str,
    ):
        retained = getattr(reconciliation, attribute, ())
        if retained:
            return iter(retained)
        reader = getattr(self.store, "reconciliation_payloads", None)
        return reader(record_kind) if callable(reader) else iter(())

    def _node_identity(self, value: Any) -> str:
        pool = getattr(self, "_node_identity_pool", None)
        if pool is None:
            return str(value or "")
        return self._shared_value(pool, value)

    def _load_compact_resolution_indexes(
        self, reconciliation: RuntimeReconciliationResult
    ) -> None:
        status_pool: dict[str, str] = {}
        realm_pool: dict[str, str] = {}

        executable: dict[str, _ExecutableResolutionRow] = {}
        for item in self._resolution_records(
            reconciliation, "member_resolutions", "member_resolution"
        ):
            edge_id = str(item.get("direct_edge_identity") or "")
            state = executable.get(edge_id)
            if state is None:
                state = executable[edge_id] = _ExecutableResolutionRow(edge_id)
            state.member_resolution_status = self._shared_value(
                status_pool, item.get("member_resolution_status")
            )
            state.resolved_member_identity = self._node_identity(
                item.get("resolved_member_identity")
            )
            state.member_resolution_identity = str(
                item.get("member_resolution_identity") or ""
            )
            state.initiating_loader_realm_identity = self._shared_value(
                realm_pool, item.get("initiating_loader_realm_identity")
            )

        for item in self._resolution_records(
            reconciliation, "dispatch_resolutions", "dispatch_resolution"
        ):
            edge_id = str(item.get("direct_edge_identity") or "")
            state = executable.get(edge_id)
            if state is None:
                state = executable[edge_id] = _ExecutableResolutionRow(edge_id)
            state.dispatch_status = self._shared_value(
                status_pool, item.get("dispatch_status")
            )
            state.implementation_target_identities = tuple(
                self._node_identity(value)
                for value in item.get("implementation_target_identities") or ()
                if value
            )
            state.dispatch_resolution_identity = str(
                item.get("dispatch_resolution_identity") or ""
            )

        # The three public names intentionally share one dictionary.  A direct
        # edge has one executable resolution state; three dictionaries would
        # repeat millions of keys and hash-table slots without adding facts.
        self.member_resolutions = executable
        self.dispatch = executable
        self.linkage_resolutions = executable
        for item in self._resolution_records(
            reconciliation, "linkage_resolutions", "linkage_resolution"
        ):
            edge_id = str(item.get("direct_edge_identity") or "")
            state = executable.get(edge_id)
            if state is not None:
                state.linkage_status = self._shared_value(
                    status_pool, item.get("linkage_status")
                )

        # Type and class-initialization records apply to disjoint edge kinds.
        # They are joined back to direct edges in bounded batches while the
        # reverse graph is built, instead of becoming two more global maps.
        self.type_resolutions = {}
        self.class_initializations = {}
        self._trace_reconciliation = reconciliation

    def _iter_graph_edge_items(
        self,
    ) -> Iterator[tuple[str, Mapping[str, Any]]]:
        iterator = getattr(self.edges, "iter_graph_items", None)
        if callable(iterator):
            try:
                yield from iterator(_GRAPH_EDGE_COLUMNS)
            except TypeError:
                # Compatibility adapters may expose the pre-optimisation
                # zero-argument iterator. Their complete rows remain valid;
                # only the SQL-backed path uses the narrow projection.
                yield from iterator()
            return
        for edge_id, edge in self.edges.items():
            yield str(edge_id), edge

    def _matching_resolution_edges(
        self, resolutions: Mapping[str, Mapping[str, Any]]
    ) -> Iterator[tuple[Mapping[str, Any], Mapping[str, Any]]]:
        identities = tuple(resolutions)
        matcher = getattr(self.edges, "iter_matching_items", None)
        if callable(matcher):
            for edge_id, edge in matcher(identities):
                resolution = resolutions.get(edge_id)
                if resolution is not None:
                    yield resolution, edge
            return
        for edge_id, resolution in resolutions.items():
            edge = self.edges.get(edge_id)
            if edge is not None:
                if not resolution.get("direct_edge_identity"):
                    resolution = {
                        **resolution,
                        "direct_edge_identity": edge_id,
                    }
                yield resolution, edge

    def _iter_resolution_edge_batches(
        self, records
    ) -> Iterator[tuple[Mapping[str, Any], Mapping[str, Any]]]:
        pending: dict[str, Mapping[str, Any]] = {}
        for resolution in records:
            edge_id = str(resolution.get("direct_edge_identity") or "")
            if edge_id:
                pending[edge_id] = resolution
            if len(pending) >= 2_000:
                yield from self._matching_resolution_edges(pending)
                pending.clear()
        if pending:
            yield from self._matching_resolution_edges(pending)

    def _build_reverse_graph(self) -> None:
        shared_executable_index = (
            self.dispatch is self.member_resolutions
            and self.linkage_resolutions is self.member_resolutions
        )
        for scanned_edge_id, edge in self._iter_graph_edge_items():
            resolution = self.member_resolutions.get(scanned_edge_id)
            if not resolution or not resolution.get("member_resolution_status"):
                continue
            edge_id = str(
                resolution.get("direct_edge_identity") or scanned_edge_id
            )
            edge_kind = str(edge["edge_kind"] or "")
            dynamic_handle = (
                edge_kind.startswith("invokedynamic_handle_")
                or edge_kind.startswith("ldc_bootstrap_handle_")
            )
            executable_linkage = edge_kind in {
                "invokedynamic_bootstrap",
                "ldc_constant_dynamic_bootstrap",
                "ldc_handle",
            } or dynamic_handle
            if edge_kind not in {"method", "field"} and not executable_linkage:
                continue
            caller = self._node_identity(edge["caller_member_identity"])
            status = resolution["member_resolution_status"]
            dispatch = (
                resolution
                if shared_executable_index
                else self.dispatch.get(edge_id) or {}
            )
            linkage_status = (
                resolution.get("linkage_status")
                if shared_executable_index
                else (
                    self.linkage_resolutions.get(edge_id) or {}
                ).get("linkage_status")
            )
            loading_constraint_blocked = linkage_status in {
                "loader_constraint_violation",
                "loading_constraint_deferred_conflict",
                "loading_constraint_unresolved",
            }
            targets = dispatch.get("implementation_target_identities") or ()
            dispatch_status = dispatch.get("dispatch_status")
            if (
                not targets
                and status == "resolved"
                and resolution.get("resolved_member_identity")
            ):
                targets = (resolution["resolved_member_identity"],)
            certainty = (
                "possible"
                if dispatch_status in {"possible", "partial_possible_set"}
                or executable_linkage
                or loading_constraint_blocked
                else "exact"
            )
            for target in targets:
                target = self._node_identity(target)
                self.reverse[target].append(_IncomingTraceEdge(
                    caller_member_identity=caller,
                    direct_edge_identity=edge_id,
                    certainty=certainty,
                    member_resolution_identity=str(
                        resolution.get("member_resolution_identity") or ""
                    ),
                    dispatch_resolution_identity=str(
                        dispatch.get("dispatch_resolution_identity", "")
                    ),
                    resolution_status=str(status),
                    linkage_status=str(linkage_status or ""),
                    initiating_loader_realm_identity=str(
                        resolution.get("initiating_loader_realm_identity") or ""
                    ),
                ))
            if status != "resolved":
                symbolic = self._node_identity(self._symbolic_target(
                    edge["symbolic_owner"], edge["symbolic_name"], edge["symbolic_descriptor"],
                    "field" if edge["edge_kind"] == "field" else "method",
                ))
                symbolic_targets = {
                    symbolic,
                    *self.unresolved_edge_alias_targets.get(edge_id, ()),
                }
                for symbolic_target in sorted(symbolic_targets):
                    symbolic_target = self._node_identity(symbolic_target)
                    self.reverse[symbolic_target].append(_IncomingTraceEdge(
                        caller_member_identity=caller,
                        direct_edge_identity=edge_id,
                        certainty=_unresolved_edge_certainty(
                            status,
                            paired_artifact_change=(
                                symbolic_target in self.paired_artifact_missing_targets
                            ),
                        ),
                        member_resolution_identity=str(
                            resolution.get("member_resolution_identity") or ""
                        ),
                        dispatch_resolution_identity=str(
                            dispatch.get("dispatch_resolution_identity", "")
                        ),
                        resolution_status=str(status),
                        linkage_status=str(linkage_status or ""),
                        initiating_loader_realm_identity=str(
                            resolution.get(
                                "initiating_loader_realm_identity"
                            ) or ""
                        ),
                    ))

        if getattr(self, "_release_resolution_indexes_after_build", False):
            # All outcome facts needed by a selected path now live on its
            # compact incoming transition. Drop the multi-million-entry join
            # index before adding the much smaller auxiliary edge families.
            self.member_resolutions.clear()

        # Type observations are admitted only after provider/definition
        # resolution; raw shadowed or definition-failed observations never enter
        # the effective graph.
        if getattr(self, "_stream_auxiliary_resolutions", False):
            type_pairs = self._iter_resolution_edge_batches(
                resolution
                for resolution in self._resolution_records(
                    self._trace_reconciliation, "type_resolutions", "type_resolution"
                )
                if resolution.get("type_resolution_status") in {
                    "resolved", "primitive_or_array_type"
                }
            )
        else:
            type_pairs = (
                (
                    type_resolution
                    if type_resolution.get("direct_edge_identity")
                    else {
                        **type_resolution,
                        "direct_edge_identity": edge_id,
                    },
                    edge,
                )
                for edge_id, edge in self._iter_graph_edge_items()
                for type_resolution in [self.type_resolutions.get(edge_id)]
                if type_resolution is not None
            )
        for type_resolution, edge in type_pairs:
            if type_resolution.get("type_resolution_status") not in {
                "resolved", "primitive_or_array_type"
            }:
                continue
            edge_id = str(type_resolution["direct_edge_identity"])
            symbolic = self._node_identity(self._symbolic_target(
                str(
                    type_resolution.get("symbolic_owner")
                    or edge["symbolic_owner"]
                    or ""
                ),
                "<class>",
                str(
                    type_resolution.get("symbolic_descriptor")
                    or edge["symbolic_descriptor"]
                    or ""
                ),
                "class",
            ))
            self.reverse[symbolic].append(_IncomingTraceEdge(
                caller_member_identity=self._node_identity(
                    edge["caller_member_identity"]
                ),
                direct_edge_identity=edge_id,
                certainty="exact",
            ))

        if getattr(self, "_stream_auxiliary_resolutions", False):
            initialization_pairs = self._iter_resolution_edge_batches(
                resolution
                for resolution in self._resolution_records(
                    self._trace_reconciliation,
                    "class_initialization_resolutions",
                    "class_initialization_resolution",
                )
                if resolution.get("class_initialization_status") == "resolved"
                and resolution.get("initializer_target_identities")
            )
        else:
            initialization_pairs = self._matching_resolution_edges(
                self.class_initializations
            )
        for resolution, edge in initialization_pairs:
            if resolution.get("class_initialization_status") != "resolved":
                continue
            edge_id = str(resolution["direct_edge_identity"])
            for target in resolution.get("initializer_target_identities") or ():
                target = self._node_identity(target)
                self.reverse[target].append(_IncomingTraceEdge(
                    caller_member_identity=self._node_identity(
                        edge["caller_member_identity"]
                    ),
                    direct_edge_identity=edge_id,
                    certainty="exact",
                    class_initialization_resolution_identity=str(
                        resolution.get(
                            "class_initialization_resolution_identity"
                        ) or ""
                    ),
                ))
        for record in getattr(self.inline_overlay, "rows", ()):
            if record.get("consumption_state") != "changed_with_source":
                continue
            certainty = record.get("binding_certainty")
            if certainty not in {"proven", "possible"}:
                continue
            consumer = str(record.get("consumer_member_identity") or "")
            target = str(record.get("changed_field_member_identity") or "")
            if not consumer or not target:
                continue
            self.reverse[self._node_identity(target)].append(_IncomingTraceEdge(
                caller_member_identity=self._node_identity(consumer),
                direct_edge_identity=str(record["inline_overlay_identity"]),
                certainty="exact" if certainty == "proven" else "possible",
                inline_overlay_identity=str(record["inline_overlay_identity"]),
            ))
        for record in self.semantic_edges.values():
            caller = str(record.get("caller_member_identity") or "")
            target = str(record.get("target_member_identity") or "")
            if not caller or not target:
                continue
            self.reverse[self._node_identity(target)].append(_IncomingTraceEdge(
                caller_member_identity=self._node_identity(caller),
                direct_edge_identity=str(record["semantic_edge_identity"]),
                certainty=(
                    "exact" if record.get("path_certainty") == "exact" else "possible"
                ),
                semantic_edge_identity=str(record["semantic_edge_identity"]),
            ))
        for target in self.reverse:
            self.reverse[target].sort(
                key=lambda item: (
                    item.caller_member_identity,
                    item.certainty,
                    item.direct_edge_identity,
                ) if isinstance(item, _IncomingTraceEdge) else (
                    item["caller_member_identity"],
                    item["certainty"],
                    item["direct_edge_identity"],
                )
            )
        if getattr(self, "_release_resolution_indexes_after_build", False):
            self.dispatch = {}
            self.linkage_resolutions = {}
            self.type_resolutions = {}
            self.class_initializations = {}
            self._node_identity_pool.clear()
            self._trace_reconciliation = None

    @staticmethod
    def _reachable(entrypoints, adjacency):
        reached = set(entrypoints)
        queue = deque(sorted(entrypoints))
        while queue:
            node = queue.popleft()
            for target in adjacency.get(node, ()):
                if target not in reached:
                    reached.add(target)
                    queue.append(target)
        return reached

    @staticmethod
    def _scc_count(nodes, adjacency):
        """Deterministic iterative Kosaraju, including isolated nodes."""
        def ordered_targets(node):
            targets = adjacency.get(node, ())
            return (
                targets
                if isinstance(targets, (list, tuple))
                else tuple(sorted(targets))
            )

        seen = set()
        finish = []
        for root in sorted(nodes):
            if root in seen:
                continue
            seen.add(root)
            stack = [(root, 0, ordered_targets(root))]
            while stack:
                node, index, targets = stack[-1]
                if index < len(targets):
                    target = targets[index]
                    stack[-1] = (node, index + 1, targets)
                    if target not in seen:
                        seen.add(target)
                        stack.append((
                            target, 0, ordered_targets(target)
                        ))
                else:
                    finish.append(node)
                    stack.pop()
        transpose = defaultdict(list)
        for caller, targets in adjacency.items():
            for target in targets:
                transpose[target].append(caller)
        assigned = set()
        count = 0
        largest = 0
        for root in reversed(finish):
            if root in assigned:
                continue
            count += 1
            size = 0
            assigned.add(root)
            stack = [root]
            while stack:
                node = stack.pop()
                size += 1
                for target in transpose.get(node, ()):
                    if target not in assigned:
                        assigned.add(target)
                        stack.append(target)
            largest = max(largest, size)
        return count, largest

    def _prepare_batch_graph(self):
        exact = defaultdict(list)
        possible = defaultdict(list)
        all_edges = defaultdict(list)
        nodes = set(self.entrypoints)
        effective_edge_count = 0
        possible_edge_count = 0
        for target, incoming_rows in self.reverse.items():
            nodes.add(target)
            for incoming in incoming_rows:
                if isinstance(incoming, _IncomingTraceEdge):
                    caller = incoming.caller_member_identity
                    certainty = incoming.certainty
                else:
                    caller = incoming["caller_member_identity"]
                    certainty = incoming["certainty"]
                nodes.add(caller)
                all_edges[caller].append(target)
                effective_edge_count += 1
                if certainty == "exact":
                    exact[caller].append(target)
                else:
                    possible[caller].append(target)
                    possible_edge_count += 1
        # Reachability and SCCs care about transitions, not how many bytecode
        # call sites induce the same caller -> target pair. Sort and compact
        # each list in place, avoiding the per-entry overhead of Python sets.
        for adjacency in (exact, possible, all_edges):
            for targets in adjacency.values():
                targets.sort()
                write = 0
                previous = None
                for target in targets:
                    if write and target == previous:
                        continue
                    targets[write] = target
                    write += 1
                    previous = target
                del targets[write:]
        self.exact_reachable_nodes = self._reachable(self.exact_entrypoints, exact)
        self.possible_reachable_nodes = self._reachable(self.entrypoints, all_edges)
        certainty_states = {
            (root, False) for root in self.exact_entrypoints
        }
        certainty_states.update(
            (root, True) for root in self.possible_entrypoints
        )
        certainty_queue = deque(sorted(certainty_states))
        while certainty_queue:
            node, contains_possible = certainty_queue.popleft()
            for target in exact.get(node, ()):
                state = (target, contains_possible)
                if state not in certainty_states:
                    certainty_states.add(state)
                    certainty_queue.append(state)
            for target in possible.get(node, ()):
                state = (target, True)
                if state not in certainty_states:
                    certainty_states.add(state)
                    certainty_queue.append(state)
        self.possible_path_nodes = {
            node for node, contains_possible in certainty_states
            if contains_possible
        }
        del certainty_states, certainty_queue, possible
        exact_scc_count, exact_largest = self._scc_count(nodes, exact)
        del exact
        possible_scc_count, possible_largest = self._scc_count(nodes, all_edges)
        self.graph_stats = {
            "batch_transition_build": "shared_target_independent_v1",
            "node_count": len(nodes),
            "effective_edge_count": effective_edge_count,
            "possible_edge_count": possible_edge_count,
            "runtime_semantic_edge_count": len(self.semantic_edges),
            "runtime_semantic_overlay_identity": str(
                getattr(self.semantic_overlay, "identity", "") or ""
            ),
            "entrypoint_count": len(self.entrypoints),
            "exact_entrypoint_count": len(self.exact_entrypoints),
            "possible_entrypoint_count": len(self.possible_entrypoints),
            "entrypoint_discovery_identity": self.entrypoint_discovery.identity,
            "exact_reachable_node_count": len(self.exact_reachable_nodes),
            "possible_reachable_node_count": len(self.possible_reachable_nodes),
            "exact_scc_count": exact_scc_count,
            "exact_largest_scc_size": exact_largest,
            "possible_scc_count": possible_scc_count,
            "possible_largest_scc_size": possible_largest,
            "path_enumeration": "shared-reachability-bounded-complete-consumer-bfs-v3",
        }
        self.batch_graph_identity = _identity(
            "binary_batch_trace_graph_identity", self.graph_stats
        )

    @staticmethod
    def _symbolic_target(owner: str, name: str, descriptor: str, kind: str) -> str:
        return _identity("binary_symbolic_trace_target", {
            "owner": owner,
            "name": name,
            "descriptor": descriptor,
            "member_kind": kind,
        })

    def _entrypoints(self) -> tuple[set[str], set[str], tuple[str, ...]]:
        return (
            set(self.entrypoint_discovery.exact_member_identities),
            set(self.entrypoint_discovery.possible_member_identities),
            tuple(self.entrypoint_discovery.coverage_gaps),
        )

    def _target_nodes(self, decision: Mapping[str, Any]) -> tuple[str, ...]:
        scope = decision.get("fact_scope") or {}
        if decision.get("fact_kind") == "member_resolution":
            current_resolution = (decision.get("evidence") or {}).get(
                "current_resolution"
            ) or {}
            resolved = str(current_resolution.get("resolved_member_identity") or "")
            if resolved:
                return (resolved,)
        realm = str(scope.get("initiating_loader_realm_identity") or "")
        owner = str(scope.get("class_name") or "").replace(".", "/")
        kind = str(scope.get("member_kind") or "class")
        name = str(scope.get("member_name") or "<class>")
        descriptor = str(scope.get("descriptor") or f"L{owner};")
        if kind in {"method", "field"}:
            provider = self.providers.get((realm, owner))
            if provider and provider.get("class_provider_status") == "resolved":
                rows = self.store.rows(
                    "members",
                    where=(
                        "class_variant_identity=? AND member_kind=? "
                        "AND member_name=? AND descriptor=?"
                    ),
                    parameters=(
                        provider["selected_class_variant_identity"], kind, name, descriptor,
                    ),
                )
                if len(rows) == 1:
                    return (rows[0]["member_identity"],)
            return (self._symbolic_target(owner, name, descriptor, kind),)
        return (self._symbolic_target(owner, "<class>", f"L{owner};", "class"),)

    def _trace(self, target_nodes: tuple[str, ...]) -> tuple[list[dict[str, Any]], list[str]]:
        target_nodes = tuple(sorted(set(target_nodes)))
        cached = self._trace_cache.get(target_nodes)
        if cached is not None:
            return cached
        paths = []
        gaps = []
        if not any(node in self.possible_reachable_nodes for node in target_nodes):
            result = (paths, gaps)
            self._trace_cache[target_nodes] = result
            return result
        def materialize_path(node, suffix, recorded_certainty):
            root_certainty = (
                "possible" if node in self.possible_entrypoints else "exact"
            )
            root_records = [
                item for item in self.entrypoint_records_by_member.get(node, ())
                if item.get("path_certainty") == root_certainty
            ]
            path_edges = []
            for item in reversed(suffix):
                if isinstance(item, _IncomingTraceEdge):
                    self._path_outcomes[item.direct_edge_identity] = (
                        item.resolution_status,
                        item.linkage_status,
                        item.initiating_loader_realm_identity,
                    )
                edge = (
                    self.edges.get(item["direct_edge_identity"])
                    or self.semantic_edges.get(item["direct_edge_identity"])
                    or {}
                )
                caller = self.members.get(item["caller_member_identity"]) or {}
                path_edges.append({
                    **item,
                    "caller_class_name": str(caller.get("class_name") or ""),
                    "caller_member_name": str(caller.get("member_name") or ""),
                    "caller_descriptor": str(caller.get("descriptor") or ""),
                    "caller_artifact_instance_identity": str(
                        edge.get("caller_artifact_instance_identity") or ""
                    ),
                    "edge_kind": str(
                        edge.get("edge_kind")
                        or edge.get("semantic_edge_kind")
                        or ""
                    ),
                    "bytecode_offset": edge.get("bytecode_offset"),
                    "symbolic_owner": str(edge.get("symbolic_owner") or ""),
                    "symbolic_name": str(edge.get("symbolic_name") or ""),
                    "symbolic_descriptor": str(
                        edge.get("symbolic_descriptor") or ""
                    ),
                    "semantic_evidence": dict(edge.get("evidence") or {}),
                    "target_dependency_coord": str(
                        edge.get("target_dependency_coord") or ""
                    ),
                })
            path_identity = _identity("binary_trace_path_identity", {
                "entrypoint_member_identity": node,
                "entrypoint_record_identities": [
                    item["entrypoint_record_identity"] for item in root_records
                ],
                "target_nodes": list(target_nodes),
                "edge_identities": [
                    item["direct_edge_identity"] for item in path_edges
                ],
                "path_certainty": recorded_certainty,
            })
            return {
                "path_identity": path_identity,
                "entrypoint_member_identity": node,
                "entrypoint_records": [dict(item) for item in root_records],
                "target_nodes": list(target_nodes),
                "path_certainty": recorded_certainty,
                "edges": path_edges,
            }

        def enumerate_paths(*, exact_only, limit):
            if limit <= 0:
                return [], False
            queue = deque((target, [], "exact") for target in target_nodes)
            queued_states = {
                target if exact_only else (target, "exact")
                for target in target_nodes
            }
            found = []
            visited_states = 0
            while queue and len(found) < limit:
                node, suffix, certainty = queue.popleft()
                visited_states += 1
                if visited_states > self.max_visited_nodes:
                    gaps.append("trace_node_limit_exceeded")
                    break
                if node in self.entrypoints:
                    root_certainty = (
                        "possible"
                        if node in self.possible_entrypoints
                        else "exact"
                    )
                    recorded_certainty = (
                        "possible"
                        if "possible" in {certainty, root_certainty}
                        else "exact"
                    )
                    if (
                        (exact_only and recorded_certainty == "exact")
                        or (not exact_only and recorded_certainty == "possible")
                    ):
                        found.append(materialize_path(
                            node, suffix, recorded_certainty
                        ))
                for incoming in self.reverse.get(node, ()):
                    if isinstance(incoming, _IncomingTraceEdge):
                        incoming_certainty = incoming.certainty
                        caller = incoming.caller_member_identity
                    else:
                        incoming_certainty = incoming["certainty"]
                        caller = incoming["caller_member_identity"]
                    if exact_only and incoming_certainty != "exact":
                        continue
                    next_certainty = (
                        "possible"
                        if certainty == "possible"
                        or incoming_certainty == "possible"
                        else "exact"
                    )
                    state = caller if exact_only else (caller, next_certainty)
                    if state in queued_states:
                        continue
                    queued_states.add(state)
                    queue.append((
                        caller, suffix + [incoming], next_certainty,
                    ))
            return found, bool(queue)

        if any(node in self.exact_reachable_nodes for node in target_nodes):
            exact_paths, exact_incomplete = enumerate_paths(
                exact_only=True, limit=self.max_paths_per_target,
            )
            paths.extend(exact_paths)
            if exact_incomplete:
                gaps.append("trace_path_enumeration_limit_exceeded")
        remaining = self.max_paths_per_target - len(paths)
        if (
            remaining > 0
            and any(node in self.possible_path_nodes for node in target_nodes)
        ):
            possible_paths, possible_incomplete = enumerate_paths(
                exact_only=False, limit=remaining,
            )
            paths.extend(possible_paths)
            if possible_incomplete:
                gaps.append("trace_path_enumeration_limit_exceeded")
        paths.sort(key=lambda item: (
            item["path_certainty"],
            item["entrypoint_member_identity"],
            tuple(edge["direct_edge_identity"] for edge in item["edges"]),
        ))
        result = (paths, sorted(set(gaps)))
        self._trace_cache[target_nodes] = result
        return result

    def _path_edge_outcome(
        self, edge: Mapping[str, Any]
    ) -> tuple[str | None, str | None, str]:
        edge_id = str(edge.get("direct_edge_identity") or "")
        compact = getattr(self, "_path_outcomes", {}).get(edge_id)
        if compact is not None:
            resolution_status, linkage_status, realm = compact
            return (
                resolution_status or None,
                linkage_status or None,
                realm,
            )
        resolution = (self.member_resolutions.get(edge_id) or {})
        linkage = (self.linkage_resolutions.get(edge_id) or {})
        return (
            resolution.get("member_resolution_status"),
            linkage.get("linkage_status"),
            str(resolution.get("initiating_loader_realm_identity") or ""),
        )

    def _result_for(
        self,
        *,
        projection_identity: str,
        decision: Mapping[str, Any],
        assessment_identity: str,
        diagnostic: bool,
    ) -> dict[str, Any]:
        target_nodes = self._target_nodes(decision)
        paths, trace_gaps = self._trace(target_nodes)
        exact = any(path["path_certainty"] == "exact" for path in paths)
        possible = any(path["path_certainty"] == "possible" for path in paths)
        gaps = sorted(set(
            trace_gaps
            + list(self.entrypoint_gaps)
            + list(self.runtime.coverage_gaps)
            + list(decision.get("coverage_gaps") or ())
        ))
        path_set_complete = not gaps
        if exact:
            reachability = "reachable"
        elif possible:
            reachability = "uncertain"
        elif path_set_complete:
            reachability = "not_found_in_static_analysis"
        else:
            reachability = "not_analyzed"
        formal_state = derive_formal_result_state(
            reachability,
            possible_path_exists=possible if reachability in {"reachable", "uncertain"} else False,
        )
        edge_outcomes = [
            (edge, self._path_edge_outcome(edge))
            for path in paths
            for edge in path["edges"]
        ]
        resolution_statuses = {
            outcome[0] for _edge, outcome in edge_outcomes
        }
        linkage_statuses = {
            outcome[1] for _edge, outcome in edge_outcomes
        }
        resolution_statuses.discard(None)
        linkage_statuses.discard(None)
        caller_definition_statuses = set()
        for edge, outcome in edge_outcomes:
            caller_class_name = str(edge.get("caller_class_name") or "")
            if not caller_class_name:
                caller_class_name = str((self.members.get(
                    edge["caller_member_identity"]
                ) or {}).get("class_name") or "")
            caller_definition_statuses.add(
                self.class_definition_statuses.get((
                    outcome[2], caller_class_name,
                )) or "missing"
            )
        change_kind = str(
            (decision.get("fact_scope") or {}).get("member_change_kind") or ""
        )
        incompatible_statuses = {
            "no_such_member", "incompatible_class_change", "illegal_access",
            "no_class_definition", "class_definition_failed",
            "loader_constraint_violation",
        }
        unresolved_statuses = {
            "ambiguous", "unresolved", "unsupported",
            "loading_constraint_deferred_conflict",
            "loading_constraint_unresolved",
        }
        # Removing a declaration is not necessarily a JVM linkage break.  A
        # symbolic reference to the old owner may resolve to an inherited
        # method with the exact same name and descriptor on the current side.
        # Only a concrete, fully resolved path can override the conservative
        # artifact-local removal classification.
        removed_member_rebound = (
            change_kind == "removed"
            and resolution_statuses == {"resolved"}
            and linkage_statuses.issubset({"resolved"})
        )
        access_reduction_proven_legal = (
            _access_reduction_is_legal_on_observed_paths(
                decision,
                has_path=bool(paths),
                resolution_statuses=resolution_statuses,
                linkage_statuses=linkage_statuses,
                caller_definition_statuses=caller_definition_statuses,
            )
        )
        if (
            (
                change_kind in {
                    "removed", "descriptor_changed", "access_changed",
                }
                and not removed_member_rebound
            )
            or (
                _contract_change_breaks_linkage(decision)
                and not access_reduction_proven_legal
            )
            or resolution_statuses.intersection(incompatible_statuses)
            or linkage_statuses.intersection(incompatible_statuses)
        ):
            static_linkage_status = "incompatible_if_executed"
        elif (
            resolution_statuses.intersection(unresolved_statuses)
            or linkage_statuses.intersection(unresolved_statuses)
            or decision.get("fact_kind") in {"provider_topology", "class_definition"}
        ):
            static_linkage_status = "undetermined"
        else:
            static_linkage_status = "compatible_or_not_applicable"
        payload = {
            "projection_identity": projection_identity,
            "decision_identity": decision["decision_identity"],
            "change_fact_identity": decision.get("change_fact_identity", ""),
            "projection_assessment_identity": assessment_identity,
            "analysis_context_identity": self.decisions.analysis_context_identity,
            "runtime_profile_identity": self.profile.identity,
            "target_nodes": list(target_nodes),
            "paths": paths,
            "exact_path_exists": exact,
            "possible_path_exists": possible,
            "path_set_complete": path_set_complete,
            "trace_coverage_gaps": gaps,
            "result_channel": "diagnostic" if diagnostic else "formal",
            "batch_graph_identity": self.batch_graph_identity,
            "static_linkage_status": static_linkage_status,
            "member_resolution_statuses": sorted(resolution_statuses),
            "linkage_resolution_statuses": sorted(linkage_statuses),
            **formal_state,
        }
        if diagnostic:
            payload.pop("change_fact_status", None)
            payload["candidate_fact_status"] = decision.get(
                "candidate_fact_status", "candidate"
            )
            payload["impact_conclusion"] = "inconclusive"
            payload["decision_bucket"] = "diagnostic_inconclusive"
        payload["trace_result_identity"] = _identity(
            "binary_trace_result_identity",
            payload,
        )
        return payload

    def _service_activation_results(self) -> list[dict[str, Any]]:
        prefix = "META-INF/services/"
        service_decisions = []
        for decision in self.decisions.authoritative_decisions:
            if decision.get("fact_kind") != "resource":
                continue
            scope = decision.get("fact_scope") or {}
            resource_name = str(scope.get("resource_name") or "")
            if resource_name.startswith(prefix):
                service_decisions.append((decision, scope, resource_name))
        if not service_decisions:
            return []

        results = []
        edges_by_caller: dict[str, list[dict[str, Any]]] = defaultdict(list)
        service_owners = tuple(sorted({
            resource_name[len(prefix):].replace(".", "/")
            for _decision, _scope, resource_name in service_decisions
        }))
        filtered_rows = getattr(
            self.edges, "iter_service_activation_rows", None
        )
        edge_rows = (
            filtered_rows(service_owners)
            if callable(filtered_rows)
            else self.edges.values()
        )
        for edge in edge_rows:
            edges_by_caller[edge["caller_member_identity"]].append(edge)
        for rows in edges_by_caller.values():
            rows.sort(key=lambda item: (
                int(item.get("instruction_index") or 0),
                str(item.get("edge_kind") or ""),
            ))

        for decision, scope, resource_name in service_decisions:
            service_owner = resource_name[len(prefix):].replace(".", "/")
            candidates = []
            for caller_identity, rows in edges_by_caller.items():
                literals = [
                    edge for edge in rows
                    if edge.get("edge_kind") == "type"
                    and edge.get("symbolic_owner") == service_owner
                    and (_loads(edge.get("edge_json") or "{}").get("type_use_kind") == "class_literal")
                ]
                loads = [
                    edge for edge in rows
                    if edge.get("edge_kind") == "method"
                    and edge.get("symbolic_owner") == "java/util/ServiceLoader"
                    and edge.get("symbolic_name") == "load"
                    and str(edge.get("symbolic_descriptor") or "").startswith("(Ljava/lang/Class;")
                ]
                for literal in literals:
                    load = next((
                        edge for edge in loads
                        if 0 <= int(edge.get("instruction_index") or 0)
                        - int(literal.get("instruction_index") or 0) <= 2
                    ), None)
                    if load is None:
                        continue
                    if caller_identity in self.exact_reachable_nodes:
                        certainty = "exact"
                    elif caller_identity in self.possible_reachable_nodes:
                        certainty = "possible"
                    else:
                        certainty = "not_reached"
                    caller = self.members.get(caller_identity) or {}
                    paths, path_gaps = self._trace((caller_identity,))
                    candidates.append({
                        "caller_member_identity": caller_identity,
                        "caller_class_name": str(caller.get("class_name") or ""),
                        "caller_member_name": str(caller.get("member_name") or ""),
                        "caller_descriptor": str(caller.get("descriptor") or ""),
                        "path_certainty": certainty,
                        "class_literal_edge_identity": literal["direct_edge_identity"],
                        "service_loader_edge_identity": load["direct_edge_identity"],
                        "paths": paths,
                        "trace_coverage_gaps": path_gaps,
                    })
            exact = [item for item in candidates if item["path_certainty"] == "exact"]
            possible = [item for item in candidates if item["path_certainty"] == "possible"]
            gaps = sorted(set(
                self.entrypoint_gaps
                + self.runtime.coverage_gaps
                + tuple(
                    gap for item in candidates
                    for gap in item.get("trace_coverage_gaps") or ()
                )
            ))
            if exact:
                status = "reachable"
            elif possible:
                status = "uncertain"
            elif gaps:
                status = "not_analyzed"
            else:
                status = "not_found_in_static_analysis"
            payload = {
                "decision_identity": decision["decision_identity"],
                "change_fact_identity": decision.get("change_fact_identity", ""),
                "resource_name": resource_name,
                "resource_mechanism": str(scope.get("resource_mechanism") or ""),
                "service_type": service_owner,
                "activation_status": status,
                "path_set_complete": not gaps,
                "activation_callers": candidates,
                "trace_coverage_gaps": gaps,
                "dependency_artifacts": list(decision.get("dependency_artifacts") or ()),
                "reason_code": (
                    "SERVICE_RESOURCE_CHANGE_REACHABLE"
                    if status == "reachable"
                    else "SERVICE_RESOURCE_ACTIVATION_" + status.upper()
                ),
            }
            payload["resource_activation_result_identity"] = _identity(
                "binary_resource_activation_result_identity", payload
            )
            results.append(payload)
        return sorted(results, key=lambda item: (
            item["resource_name"], item["decision_identity"]
        ))

    def build(self) -> BinaryTraceBundle:
        formal = []
        for projection in self.decisions.formal_projections:
            assessment = self.assessment_by_identity[projection["projection_assessment_identity"]]
            decision = self.decision_by_identity[assessment["decision_identity"]]
            formal.append(self._result_for(
                projection_identity=projection["projection_identity"],
                decision=decision,
                assessment_identity=assessment["projection_assessment_identity"],
                diagnostic=False,
            ))
        candidate = []
        for plan in self.decisions.candidate_projection_plans:
            if plan["planning_status"] != "targetable":
                continue
            decision = self.decision_by_identity[plan["decision_identity"]]
            for obligation in plan["projection_obligation_keys"]:
                candidate_identity = _identity("candidate_projection_identity", {
                    "candidate_projection_plan_identity": plan["candidate_projection_plan_identity"],
                    "projection_obligation_key": obligation,
                })
                candidate.append(self._result_for(
                    projection_identity=candidate_identity,
                    decision=decision,
                    assessment_identity="",
                    diagnostic=True,
                ))
        resource_results = self._service_activation_results()
        all_results = [*formal, *candidate]
        digest = _identity("binary_trace_result_set_digest", {
            "entrypoint_discovery_identity": self.entrypoint_discovery.identity,
            "runtime_semantic_overlay_identity": str(
                getattr(self.semantic_overlay, "identity", "") or ""
            ),
            "formal_result_identities": [item["trace_result_identity"] for item in formal],
            "candidate_result_identities": [item["trace_result_identity"] for item in candidate],
            "resource_activation_result_identities": [
                item["resource_activation_result_identity"] for item in resource_results
            ],
        })
        gaps = tuple(sorted(set(
            self.entrypoint_gaps
            + self.runtime.coverage_gaps
            + tuple(getattr(self.semantic_overlay, "coverage_gaps", ()))
            + tuple(gap for item in all_results for gap in item["trace_coverage_gaps"])
        )))
        coverage = "complete" if not gaps else "partial"
        identity = _identity("binary_trace_bundle_identity", {
            "analysis_context_identity": self.decisions.analysis_context_identity,
            "trace_result_set_digest": digest,
            "coverage_status": coverage,
            "coverage_gaps": list(gaps),
            "batch_graph_identity": self.batch_graph_identity,
            "graph_stats": self.graph_stats,
        })
        return BinaryTraceBundle(
            analysis_context_identity=self.decisions.analysis_context_identity,
            formal_results=tuple(formal),
            candidate_results=tuple(candidate),
            trace_result_set_digest=digest,
            coverage_status=coverage,
            coverage_gaps=gaps,
            identity=identity,
            graph_stats=self.graph_stats,
            resource_activation_results=tuple(resource_results),
            entrypoint_discovery_identity=self.entrypoint_discovery.identity,
            entrypoint_records=tuple(self.entrypoint_discovery.records),
            entrypoint_coverage_status=getattr(
                self.entrypoint_discovery,
                "coverage_status",
                "partial"
                if self.entrypoint_discovery.coverage_gaps
                else "complete",
            ),
            entrypoint_coverage_gaps=tuple(
                self.entrypoint_discovery.coverage_gaps
            ),
        )

def build_binary_traces(
    store: BinaryFactStore,
    runtime_profile: RuntimeProfile,
    reconciliation: RuntimeReconciliationResult,
    decisions: BinaryDecisionBundle,
    *,
    inline_overlay: Any | None = None,
    semantic_overlay: Any | None = None,
    max_visited_nodes: int = 1_000_000,
    max_paths_per_target: int = 20,
) -> BinaryTraceBundle:
    """Build traces without materializing a graph that has no consumers.

    A graph is observable only through formal/candidate projections or service
    resource activation decisions. Entrypoint discovery remains mandatory and
    is still persisted independently, but when none of those consumers exists
    every possible trace result is provably empty. Building hundreds of
    thousands of edge dictionaries and SCC indexes in that case only creates a
    transient memory spike.
    """

    entrypoint_discovery = discover_binary_entrypoints(
        store, runtime_profile, reconciliation
    )
    targetable_candidate = any(
        item.get("planning_status") == "targetable"
        for item in decisions.candidate_projection_plans
    )
    service_activation = any(
        item.get("fact_kind") == "resource"
        and str((item.get("fact_scope") or {}).get("resource_name") or "").startswith(
            "META-INF/services/"
        )
        for item in decisions.authoritative_decisions
    )
    has_trace_results = bool(
        decisions.formal_projections or targetable_candidate
    )
    if has_trace_results and not (
        entrypoint_discovery.exact_member_identities
        or entrypoint_discovery.possible_member_identities
        or service_activation
    ):
        # Even an empty-root formal result must bind its changed target to the
        # selected physical member. Definitions and graph-edge resolutions are
        # unnecessary here, but omitting providers would silently replace that
        # member with a symbolic target and change the analysis result.
        selected = hydrate_runtime_reconciliation(
            store, reconciliation, ("provider_binding",)
        )
        return BinaryTraceEngine(
            store,
            runtime_profile,
            selected,
            decisions,
            entrypoint_discovery=entrypoint_discovery,
            inline_overlay=inline_overlay,
            semantic_overlay=semantic_overlay,
            max_visited_nodes=max_visited_nodes,
            max_paths_per_target=max_paths_per_target,
            materialize_graph=False,
        ).build()
    if has_trace_results or service_activation:
        selected = hydrate_runtime_reconciliation(
            store,
            reconciliation,
            ("provider_binding", "class_definition"),
        )
        return BinaryTraceEngine(
            store,
            runtime_profile,
            selected,
            decisions,
            entrypoint_discovery=entrypoint_discovery,
            inline_overlay=inline_overlay,
            semantic_overlay=semantic_overlay,
            max_visited_nodes=max_visited_nodes,
            max_paths_per_target=max_paths_per_target,
        ).build()

    exact_entrypoints = set(entrypoint_discovery.exact_member_identities)
    possible_entrypoints = set(entrypoint_discovery.possible_member_identities)
    graph_stats = {
        "batch_transition_build": "skipped_no_trace_targets_v1",
        "graph_materialization_status": "not_required",
        "node_count": 0,
        "effective_edge_count": 0,
        "possible_edge_count": 0,
        "runtime_semantic_edge_count": len(
            getattr(semantic_overlay, "rows", ())
        ),
        "runtime_semantic_overlay_identity": str(
            getattr(semantic_overlay, "identity", "") or ""
        ),
        "entrypoint_count": len(exact_entrypoints | possible_entrypoints),
        "exact_entrypoint_count": len(exact_entrypoints),
        "possible_entrypoint_count": len(possible_entrypoints),
        "entrypoint_discovery_identity": entrypoint_discovery.identity,
        "exact_reachable_node_count": len(exact_entrypoints),
        "possible_reachable_node_count": len(
            exact_entrypoints | possible_entrypoints
        ),
        "exact_scc_count": 0,
        "exact_largest_scc_size": 0,
        "possible_scc_count": 0,
        "possible_largest_scc_size": 0,
        "path_enumeration": "not_required_no_trace_targets_v1",
    }
    batch_graph_identity = _identity(
        "binary_batch_trace_graph_identity", graph_stats
    )
    trace_result_set_digest = _identity(
        "binary_trace_result_set_digest",
        {
            "entrypoint_discovery_identity": entrypoint_discovery.identity,
            "runtime_semantic_overlay_identity": str(
                getattr(semantic_overlay, "identity", "") or ""
            ),
            "formal_result_identities": [],
            "candidate_result_identities": [],
            "resource_activation_result_identities": [],
        },
    )
    gaps = tuple(sorted(set(
        tuple(entrypoint_discovery.coverage_gaps)
        + tuple(reconciliation.coverage_gaps)
        + tuple(getattr(semantic_overlay, "coverage_gaps", ()))
    )))
    coverage = "complete" if not gaps else "partial"
    identity = _identity(
        "binary_trace_bundle_identity",
        {
            "analysis_context_identity": decisions.analysis_context_identity,
            "trace_result_set_digest": trace_result_set_digest,
            "coverage_status": coverage,
            "coverage_gaps": list(gaps),
            "batch_graph_identity": batch_graph_identity,
            "graph_stats": graph_stats,
        },
    )
    return BinaryTraceBundle(
        analysis_context_identity=decisions.analysis_context_identity,
        formal_results=(),
        candidate_results=(),
        trace_result_set_digest=trace_result_set_digest,
        coverage_status=coverage,
        coverage_gaps=gaps,
        identity=identity,
        graph_stats=graph_stats,
        resource_activation_results=(),
        entrypoint_discovery_identity=entrypoint_discovery.identity,
        entrypoint_records=tuple(entrypoint_discovery.records),
        entrypoint_coverage_status=getattr(
            entrypoint_discovery,
            "coverage_status",
            "partial" if entrypoint_discovery.coverage_gaps else "complete",
        ),
        entrypoint_coverage_gaps=tuple(entrypoint_discovery.coverage_gaps),
    )


__all__ = ["BinaryTraceBundle", "BinaryTraceEngine", "build_binary_traces"]
