#!/usr/bin/env python3
"""Single validated ingestion boundary for post-source Step5 evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Tuple

from enhanced_source_analyzer import CallEdge
from step5_evidence_model import (
    CollectedEdge,
    CollectorBatch,
    EvidenceFailure,
    ModuleScope,
)


@dataclass(frozen=True)
class IngestionResult:
    merged_edges: int
    duplicate_edges: int
    rejected_edges: int
    failures: Tuple[EvidenceFailure, ...]
    merged_by_collector: Tuple[Tuple[str, int], ...] = ()
    duplicate_by_collector: Tuple[Tuple[str, int], ...] = ()
    rejected_by_collector: Tuple[Tuple[str, int], ...] = ()
    failures_by_collector: Tuple[Tuple[str, EvidenceFailure], ...] = ()


def _edge_identity(edge: CollectedEdge):
    return (
        edge.caller_symbol,
        edge.callee_symbol,
        edge.edge_kind,
        edge.semantic,
        edge.provenance.artifact_sha256,
        edge.provenance.artifact_entry,
        edge.provenance.line,
        edge.provenance.instruction_offset,
    )


def _callee_simple_key(symbol: str) -> str:
    prefix = str(symbol or "").split("(", 1)[0]
    member = prefix.rsplit(".", 1)[-1]
    if "(" in str(symbol or ""):
        parameters = str(symbol).split("(", 1)[1]
        return f"method:{member}({parameters}"
    return f"field:{member}"


def _owner_type(scope: ModuleScope) -> str:
    if scope == ModuleScope.BUSINESS_CLASSES:
        return "business"
    if scope in {ModuleScope.INTERNAL_MODULE, ModuleScope.EXTERNAL_DEPENDENCY}:
        return "dependency"
    return "unknown"


def _edge_metadata(edge: CollectedEdge):
    return dict(edge.metadata)


def _call_edge_identity(edge, collector):
    identity = (
        str(getattr(edge, "caller_symbol_id", "") or ""),
        str(getattr(edge, "callee_key", "") or ""),
        str(getattr(edge, "evidence_type", "") or ""),
    )
    if collector == "indirect_usage":
        return (*identity, int(getattr(edge, "line", 0) or 0))
    return identity


def _resolve_caller(graph, edge: CollectedEdge):
    metadata = _edge_metadata(edge)
    if not (
        metadata.get("caller_resolution_required")
        or (metadata.get("caller_owner") and metadata.get("caller_name"))
    ):
        method = (getattr(graph, "methods_by_id", {}) or {}).get(edge.caller_symbol)
        return (
            edge.caller_symbol,
            str(metadata.get("caller_qualified_key") or edge.caller_symbol),
            method,
        )
    owner = str(metadata.get("caller_owner") or "").strip()
    name = str(metadata.get("caller_name") or "").strip()
    signature = str(metadata.get("caller_signature") or "").strip()
    qualified = f"{owner}.{name}" if owner and name else edge.caller_symbol
    raw_candidates = list(
        (getattr(graph, "methods_by_qualified", {}) or {}).get(qualified) or []
    )
    candidates = []
    methods_by_id = getattr(graph, "methods_by_id", {}) or {}
    for candidate in raw_candidates:
        method = candidate if hasattr(candidate, "symbol_id") else methods_by_id.get(candidate)
        if method is not None:
            candidates.append(method)
    if len(candidates) == 1:
        candidate = candidates[0]
        return candidate.symbol_id, getattr(candidate, "qualified_key", "") or qualified, candidate
    if signature and len(candidates) > 1:
        candidates = [
            candidate for candidate in candidates
            if any(
                str(key).endswith(signature)
                for key in (getattr(graph, "lookup_keys_by_symbol", {}) or {}).get(
                    candidate.symbol_id, ()
                )
            )
        ]
    if len(candidates) != 1:
        return None, qualified, None
    candidate = candidates[0]
    return candidate.symbol_id, getattr(candidate, "qualified_key", "") or qualified, candidate


def _to_call_edge(
    edge: CollectedEdge,
    collector: str,
    *,
    caller_symbol: str,
    caller_qualified_key: str,
    caller_method=None,
) -> CallEdge:
    metadata = _edge_metadata(edge)
    evidence_path = edge.provenance.artifact_path or edge.provenance.artifact_entry
    if edge.provenance.artifact_path and edge.provenance.artifact_entry:
        evidence_path = (
            f"{edge.provenance.artifact_path}!/{edge.provenance.artifact_entry}"
        )
    owner_type = str(metadata.get("owner_type") or "")
    owner_coord = str(metadata.get("owner_coord") or "")
    module = str(metadata.get("module") or "")
    is_test = bool(metadata.get("is_test", False))
    if caller_method is not None:
        owner_type = str(getattr(caller_method, "owner_type", "") or owner_type)
        owner_coord = str(getattr(caller_method, "owner_coord", "") or owner_coord)
        module = str(getattr(caller_method, "module", "") or module)
        is_test = bool(getattr(caller_method, "is_test", is_test))
    if collector == "business_bytecode":
        is_test = False
    owner_type = owner_type or _owner_type(edge.owner_scope)
    owner_coord = owner_coord or edge.owner_coord
    callee_key = str(edge.callee_symbol or "")
    callee_simple_key = (
        str(metadata.get("callee_simple_key") or "")
        or _callee_simple_key(callee_key)
    )
    method_like = (
        callee_simple_key.startswith("method:")
        or "method" in edge.edge_kind
        or "constructor" in edge.edge_kind
    )
    fqcn_complete = bool(
        callee_key.startswith("class:")
        or (
            "." in callee_key.split("(", 1)[0]
            and not callee_key.startswith(("method:", "field:", "invokedynamic:"))
        )
    )
    signature_complete = bool(
        not method_like or ("(" in callee_key and callee_key.endswith(")"))
    )
    if fqcn_complete and signature_complete:
        resolution_note = "调用目标已解析到全限定名和签名"
    elif not fqcn_complete:
        resolution_note = "缺少调用目标所属类全限定名"
    else:
        resolution_note = "缺少调用目标方法参数签名"
    converted = CallEdge(
        caller_symbol_id=caller_symbol,
        caller_qualified_key=caller_qualified_key,
        callee_key=callee_key,
        callee_simple_key=callee_simple_key,
        evidence_type=edge.edge_kind,
        confidence=edge.confidence,
        file=evidence_path,
        line=max(int(edge.provenance.line or 0), 0),
        content=str(metadata.get("content") or ""),
        owner_type=owner_type,
        owner_coord=owner_coord,
        module=module,
        is_test=is_test,
        callee_param_types=list(metadata.get("callee_param_types") or ()),
        callee_signature_complete=signature_complete,
        callee_fqcn_complete=fqcn_complete,
        callee_resolution_note=resolution_note,
    )
    converted.evidence_source = edge.provenance.evidence_source
    converted.artifact_sha256 = edge.provenance.artifact_sha256
    if not converted.artifact_sha256:
        converted.artifact_sha256 = str(metadata.get("artifact_sha256") or "")
    converted.artifact_entry = edge.provenance.artifact_entry
    converted.evidence_authority = edge.provenance.authority.value
    converted.semantic = edge.semantic
    converted.collector = collector
    converted.evidence_registry_identity = _edge_identity(edge)
    converted.activation_conditions = list(edge.activation_conditions)
    converted.ambiguity = edge.ambiguous
    converted.parser = edge.provenance.parser
    return converted


@dataclass(frozen=True)
class EvidenceRegistry:
    batches: Tuple[CollectorBatch, ...]

    @classmethod
    def from_batches(cls, batches: Iterable[CollectorBatch]):
        return cls(tuple(sorted(
            tuple(batches), key=lambda item: (item.collector, item.version)
        )))

    def ingest_into(self, graph) -> IngestionResult:
        if not hasattr(graph, "reverse_edges") or graph.reverse_edges is None:
            graph.reverse_edges = {}
        accepted = []
        pending_identities = set()
        failures = []
        failures_by_collector = []
        seen = set()
        duplicates = 0
        rejected = 0
        merged_by_collector = {}
        duplicate_by_collector = {}
        rejected_by_collector = {}
        for batch in self.batches:
            failures.extend(batch.failures)
            failures_by_collector.extend((batch.collector, failure) for failure in batch.failures)
            for edge in sorted(batch.edges, key=_edge_identity):
                if edge.owner_scope == ModuleScope.UNKNOWN:
                    rejected += 1
                    rejected_by_collector[batch.collector] = rejected_by_collector.get(batch.collector, 0) + 1
                    failure = EvidenceFailure(
                        stage="evidence-ingestion",
                        reason_code="EVIDENCE_OWNER_SCOPE_UNKNOWN",
                        blocking=True,
                        artifact=edge.provenance.artifact_path,
                        detail=f"证据边所有权未知：{edge.caller_symbol} -> {edge.callee_symbol}",
                    )
                    failures.append(failure)
                    failures_by_collector.append((batch.collector, failure))
                    continue
                caller_symbol, caller_qualified_key, caller_method = _resolve_caller(graph, edge)
                if caller_symbol is None:
                    rejected += 1
                    rejected_by_collector[batch.collector] = rejected_by_collector.get(batch.collector, 0) + 1
                    failure = EvidenceFailure(
                        stage="evidence-ingestion",
                        reason_code="BYTECODE_CALLER_UNRESOLVED",
                        blocking=True,
                        api_identity=edge.callee_symbol,
                        artifact=edge.provenance.artifact_path,
                        class_name=str(_edge_metadata(edge).get("caller_owner") or ""),
                        detail=f"无法将字节码调用方映射到源码方法：{caller_qualified_key}",
                    )
                    failures.append(failure)
                    failures_by_collector.append((batch.collector, failure))
                    continue
                identity = _edge_identity(edge)
                if identity in seen:
                    duplicates += 1
                    duplicate_by_collector[batch.collector] = duplicate_by_collector.get(batch.collector, 0) + 1
                    continue
                seen.add(identity)
                converted = _to_call_edge(
                    edge,
                    batch.collector,
                    caller_symbol=caller_symbol,
                    caller_qualified_key=caller_qualified_key,
                    caller_method=caller_method,
                )
                converted_identity = _call_edge_identity(converted, batch.collector)
                keys = tuple(dict.fromkeys((converted.callee_key, converted.callee_simple_key)))
                if converted_identity in pending_identities or any(
                    _call_edge_identity(existing, batch.collector) == converted_identity
                    for key in keys
                    for existing in graph.reverse_edges.get(key, ())
                ):
                    duplicates += 1
                    duplicate_by_collector[batch.collector] = duplicate_by_collector.get(batch.collector, 0) + 1
                    continue
                accepted.append((batch.collector, edge, converted, keys))
                pending_identities.add(converted_identity)

        for collector, edge, converted, keys in accepted:
            merged_by_collector[collector] = merged_by_collector.get(collector, 0) + 1
            for key in keys:
                bucket = graph.reverse_edges.setdefault(key, [])
                bucket.append(converted)

        graph.step5_evidence_registry = tuple(edge for _collector, edge, _converted, _keys in accepted)
        graph.step5_evidence_failures = tuple(failures)
        graph.step5_evidence_failures_by_collector = tuple(failures_by_collector)
        graph.step5_collector_coverage = tuple(
            coverage
            for batch in self.batches
            for coverage in batch.coverage
        )
        return IngestionResult(
            merged_edges=len(accepted),
            duplicate_edges=duplicates,
            rejected_edges=rejected,
            failures=tuple(failures),
            merged_by_collector=tuple(sorted(merged_by_collector.items())),
            duplicate_by_collector=tuple(sorted(duplicate_by_collector.items())),
            rejected_by_collector=tuple(sorted(rejected_by_collector.items())),
            failures_by_collector=tuple(failures_by_collector),
        )


def ingest_collector_batches(graph, batches: Iterable[CollectorBatch]) -> IngestionResult:
    """Validate and merge all post-source evidence through one boundary."""
    return EvidenceRegistry.from_batches(batches).ingest_into(graph)


__all__ = [
    "EvidenceRegistry",
    "IngestionResult",
    "ingest_collector_batches",
]
