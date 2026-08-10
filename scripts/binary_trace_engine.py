#!/usr/bin/env python3
"""Trace formal and diagnostic binary projections over the effective JVM graph."""

from __future__ import annotations

from collections import defaultdict, deque
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
from binary_runtime_reconciler import RuntimeReconciliationResult


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


def _loads(value: str) -> Any:
    return json.loads(value or "{}")


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
    ):
        self.store = store
        self.profile = runtime_profile
        self.runtime = reconciliation
        self.decisions = decisions
        self.max_visited_nodes = max_visited_nodes
        self.max_paths_per_target = max_paths_per_target
        self.inline_overlay = inline_overlay
        self.semantic_overlay = semantic_overlay
        self.members = {row["member_identity"]: row for row in store.rows("members")}
        self.edges = {row["direct_edge_identity"]: row for row in store.rows("direct_edges")}
        self.semantic_edges = {
            row["semantic_edge_identity"]: row
            for row in getattr(semantic_overlay, "rows", ())
        }
        self.providers = {
            (item["initiating_loader_realm_identity"], item["class_name"]): item
            for item in reconciliation.provider_bindings
        }
        self.member_resolutions = {
            item["direct_edge_identity"]: item for item in reconciliation.member_resolutions
        }
        self.dispatch = {
            item["direct_edge_identity"]: item for item in reconciliation.dispatch_resolutions
        }
        self.type_resolutions = {
            item["direct_edge_identity"]: item
            for item in reconciliation.type_resolutions
        }
        self.class_initializations = {
            item["direct_edge_identity"]: item
            for item in reconciliation.class_initialization_resolutions
        }
        self.linkage_resolutions = {
            item["direct_edge_identity"]: item
            for item in reconciliation.linkage_resolutions
        }
        self.reverse: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._build_reverse_graph()
        self.entrypoint_discovery = entrypoint_discovery or discover_binary_entrypoints(
            store, runtime_profile, reconciliation
        )
        (
            self.exact_entrypoints,
            self.possible_entrypoints,
            self.entrypoint_gaps,
        ) = self._entrypoints()
        self.entrypoints = self.exact_entrypoints | self.possible_entrypoints
        self.entrypoint_records_by_member: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in self.entrypoint_discovery.records:
            self.entrypoint_records_by_member[item["member_identity"]].append(item)
        self._trace_cache: dict[
            tuple[str, ...], tuple[list[dict[str, Any]], list[str]]
        ] = {}
        self._prepare_batch_graph()
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

    def _build_reverse_graph(self) -> None:
        for edge_id, resolution in self.member_resolutions.items():
            edge = self.edges.get(edge_id)
            if not edge:
                continue
            edge_kind = str(edge.get("edge_kind") or "")
            executable_linkage = edge_kind in {
                "invokedynamic_bootstrap",
                "ldc_constant_dynamic_bootstrap",
            }
            if edge_kind not in {"method", "field"} and not executable_linkage:
                continue
            caller = edge["caller_member_identity"]
            status = resolution["member_resolution_status"]
            dispatch = self.dispatch.get(edge_id) or {}
            targets = list(dispatch.get("implementation_target_identities") or ())
            dispatch_status = dispatch.get("dispatch_status")
            if not targets and status == "resolved" and resolution.get("resolved_member_identity"):
                targets = [resolution["resolved_member_identity"]]
            certainty = (
                "possible"
                if dispatch_status in {"possible", "partial_possible_set"}
                or executable_linkage
                else "exact"
            )
            for target in targets:
                self.reverse[target].append({
                    "caller_member_identity": caller,
                    "direct_edge_identity": edge_id,
                    "certainty": certainty,
                    "member_resolution_identity": resolution["member_resolution_identity"],
                    "dispatch_resolution_identity": dispatch.get("dispatch_resolution_identity", ""),
                })
            if status != "resolved":
                symbolic = self._symbolic_target(
                    edge["symbolic_owner"], edge["symbolic_name"], edge["symbolic_descriptor"],
                    "field" if edge["edge_kind"] == "field" else "method",
                )
                self.reverse[symbolic].append({
                    "caller_member_identity": caller,
                    "direct_edge_identity": edge_id,
                    "certainty": "exact" if status == "no_such_member" else "possible",
                    "member_resolution_identity": resolution["member_resolution_identity"],
                    "dispatch_resolution_identity": dispatch.get("dispatch_resolution_identity", ""),
                })
        # Type observations are admitted only after provider/definition
        # resolution; raw shadowed or definition-failed observations never enter
        # the effective graph.
        for edge in self.edges.values():
            if edge["edge_kind"] != "type":
                continue
            type_resolution = self.type_resolutions.get(edge["direct_edge_identity"])
            if not type_resolution or type_resolution.get("type_resolution_status") not in {
                "resolved", "primitive_or_array_type"
            }:
                continue
            symbolic = self._symbolic_target(
                edge["symbolic_owner"], "<class>", edge["symbolic_descriptor"], "class"
            )
            self.reverse[symbolic].append({
                "caller_member_identity": edge["caller_member_identity"],
                "direct_edge_identity": edge["direct_edge_identity"],
                "certainty": "exact",
                "member_resolution_identity": "",
                "dispatch_resolution_identity": "",
            })
        for edge_id, resolution in self.class_initializations.items():
            if resolution.get("class_initialization_status") != "resolved":
                continue
            edge = self.edges.get(edge_id)
            if not edge:
                continue
            for target in resolution.get("initializer_target_identities") or ():
                self.reverse[target].append({
                    "caller_member_identity": edge["caller_member_identity"],
                    "direct_edge_identity": edge_id,
                    "certainty": "exact",
                    "member_resolution_identity": "",
                    "dispatch_resolution_identity": "",
                    "class_initialization_resolution_identity": resolution[
                        "class_initialization_resolution_identity"
                    ],
                })
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
            self.reverse[target].append({
                "caller_member_identity": consumer,
                "direct_edge_identity": record["inline_overlay_identity"],
                "certainty": "exact" if certainty == "proven" else "possible",
                "member_resolution_identity": "",
                "dispatch_resolution_identity": "",
                "inline_overlay_identity": record["inline_overlay_identity"],
            })
        for record in self.semantic_edges.values():
            caller = str(record.get("caller_member_identity") or "")
            target = str(record.get("target_member_identity") or "")
            if not caller or not target:
                continue
            self.reverse[target].append({
                "caller_member_identity": caller,
                "direct_edge_identity": record["semantic_edge_identity"],
                "certainty": (
                    "exact" if record.get("path_certainty") == "exact" else "possible"
                ),
                "member_resolution_identity": "",
                "dispatch_resolution_identity": "",
                "semantic_edge_identity": record["semantic_edge_identity"],
            })
        for target in self.reverse:
            self.reverse[target].sort(
                key=lambda item: (
                    item["caller_member_identity"],
                    item["certainty"],
                    item["direct_edge_identity"],
                )
            )

    @staticmethod
    def _reachable(entrypoints, adjacency):
        reached = set(entrypoints)
        queue = deque(sorted(entrypoints))
        while queue:
            node = queue.popleft()
            for target in sorted(adjacency.get(node, ())):
                if target not in reached:
                    reached.add(target)
                    queue.append(target)
        return reached

    @staticmethod
    def _scc_count(nodes, adjacency):
        """Deterministic iterative Kosaraju, including isolated nodes."""
        seen = set()
        finish = []
        for root in sorted(nodes):
            if root in seen:
                continue
            seen.add(root)
            stack = [(root, 0, tuple(sorted(adjacency.get(root, ()))))]
            while stack:
                node, index, targets = stack[-1]
                if index < len(targets):
                    target = targets[index]
                    stack[-1] = (node, index + 1, targets)
                    if target not in seen:
                        seen.add(target)
                        stack.append((
                            target, 0, tuple(sorted(adjacency.get(target, ())))
                        ))
                else:
                    finish.append(node)
                    stack.pop()
        transpose = defaultdict(set)
        for caller, targets in adjacency.items():
            for target in targets:
                transpose[target].add(caller)
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
                for target in sorted(transpose.get(node, ()), reverse=True):
                    if target not in assigned:
                        assigned.add(target)
                        stack.append(target)
            largest = max(largest, size)
        return count, largest

    def _prepare_batch_graph(self):
        exact = defaultdict(set)
        all_edges = defaultdict(set)
        forward_rows = defaultdict(list)
        nodes = set(self.entrypoints)
        effective_edge_count = 0
        possible_edge_count = 0
        for target, incoming_rows in self.reverse.items():
            nodes.add(target)
            for incoming in incoming_rows:
                caller = incoming["caller_member_identity"]
                nodes.add(caller)
                all_edges[caller].add(target)
                effective_edge_count += 1
                if incoming["certainty"] == "exact":
                    exact[caller].add(target)
                else:
                    possible_edge_count += 1
                forward_rows[caller].append({
                    **incoming,
                    "target_member_identity": target,
                })
        for caller in forward_rows:
            forward_rows[caller].sort(key=lambda item: (
                item["target_member_identity"],
                item["certainty"],
                item["direct_edge_identity"],
            ))
        self.path_state_predecessor = {}
        self.path_state_root = {}
        queue = deque()
        for root in sorted(self.exact_entrypoints):
            state = (root, False)
            self.path_state_predecessor[state] = None
            self.path_state_root[state] = (root, False)
            queue.append(state)
        for root in sorted(self.possible_entrypoints):
            state = (root, True)
            self.path_state_predecessor[state] = None
            self.path_state_root[state] = (root, True)
            queue.append(state)
        while queue:
            state = queue.popleft()
            node, contains_possible = state
            for transition in forward_rows.get(node, ()):
                next_state = (
                    transition["target_member_identity"],
                    contains_possible or transition["certainty"] == "possible",
                )
                if next_state in self.path_state_predecessor:
                    continue
                self.path_state_predecessor[next_state] = (state, transition)
                self.path_state_root[next_state] = self.path_state_root[state]
                queue.append(next_state)
        self.exact_reachable_nodes = self._reachable(self.exact_entrypoints, exact)
        self.possible_reachable_nodes = self._reachable(self.entrypoints, all_edges)
        exact_scc_count, exact_largest = self._scc_count(nodes, exact)
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
            "path_enumeration": "shared_two-certainty-shortest-path-forest-v2",
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
        states = [
            (target, contains_possible)
            for target in target_nodes
            for contains_possible in (False, True)
            if (target, contains_possible) in self.path_state_predecessor
        ]
        if len(states) > self.max_paths_per_target:
            states = states[:self.max_paths_per_target]
            gaps.append("trace_path_enumeration_limit_exceeded")
        for state in states:
            root, root_possible = self.path_state_root[state]
            transitions = []
            cursor = state
            while self.path_state_predecessor[cursor] is not None:
                predecessor, transition = self.path_state_predecessor[cursor]
                transitions.append(transition)
                cursor = predecessor
            transitions.reverse()
            root_certainty = "possible" if root_possible else "exact"
            root_records = [
                item for item in self.entrypoint_records_by_member.get(root, ())
                if item.get("path_certainty") == root_certainty
            ]
            recorded_certainty = "possible" if state[1] else "exact"
            path_edges = []
            for item in transitions:
                edge = (
                    self.edges.get(item["direct_edge_identity"])
                    or self.semantic_edges.get(item["direct_edge_identity"])
                    or {}
                )
                caller = self.members.get(item["caller_member_identity"]) or {}
                path_edges.append({
                    **{key: value for key, value in item.items()
                       if key != "target_member_identity"},
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
                    "symbolic_descriptor": str(edge.get("symbolic_descriptor") or ""),
                    "semantic_evidence": dict(edge.get("evidence") or {}),
                    "target_dependency_coord": str(
                        edge.get("target_dependency_coord") or ""
                    ),
                })
            path_identity = _identity("binary_trace_path_identity", {
                "entrypoint_member_identity": root,
                "entrypoint_record_identities": [
                    item["entrypoint_record_identity"] for item in root_records
                ],
                "target_nodes": list(target_nodes),
                "edge_identities": [
                    item["direct_edge_identity"] for item in path_edges
                ],
                "path_certainty": recorded_certainty,
            })
            paths.append({
                "path_identity": path_identity,
                "entrypoint_member_identity": root,
                "entrypoint_records": [dict(item) for item in root_records],
                "target_nodes": list(target_nodes),
                "path_certainty": recorded_certainty,
                "edges": path_edges,
            })
        paths.sort(key=lambda item: (
            item["path_certainty"],
            item["entrypoint_member_identity"],
            tuple(edge["direct_edge_identity"] for edge in item["edges"]),
        ))
        result = (paths, sorted(set(gaps)))
        self._trace_cache[target_nodes] = result
        return result

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
        resolution_statuses = {
            (self.member_resolutions.get(edge["direct_edge_identity"]) or {}).get(
                "member_resolution_status"
            )
            for path in paths
            for edge in path["edges"]
        }
        linkage_statuses = {
            (self.linkage_resolutions.get(edge["direct_edge_identity"]) or {}).get(
                "linkage_status"
            )
            for path in paths
            for edge in path["edges"]
        }
        resolution_statuses.discard(None)
        linkage_statuses.discard(None)
        change_kind = str(
            (decision.get("fact_scope") or {}).get("member_change_kind") or ""
        )
        incompatible_statuses = {
            "no_such_member", "incompatible_class_change", "illegal_access",
            "no_class_definition", "class_definition_failed",
        }
        unresolved_statuses = {"ambiguous", "unresolved", "unsupported"}
        if (
            change_kind in {"removed", "descriptor_changed", "access_changed"}
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
            {key: value for key, value in payload.items() if key != "trace_result_identity"},
        )
        return payload

    def _service_activation_results(self) -> list[dict[str, Any]]:
        results = []
        edges_by_caller: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for edge in self.edges.values():
            edges_by_caller[edge["caller_member_identity"]].append(edge)
        for rows in edges_by_caller.values():
            rows.sort(key=lambda item: (
                int(item.get("instruction_index") or 0),
                str(item.get("edge_kind") or ""),
            ))

        for decision in self.decisions.authoritative_decisions:
            if decision.get("fact_kind") != "resource":
                continue
            scope = decision.get("fact_scope") or {}
            resource_name = str(scope.get("resource_name") or "")
            prefix = "META-INF/services/"
            if not resource_name.startswith(prefix):
                continue
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
        )


__all__ = ["BinaryTraceBundle", "BinaryTraceEngine"]
