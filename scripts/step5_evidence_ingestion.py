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


def _to_call_edge(edge: CollectedEdge, collector: str) -> CallEdge:
    converted = CallEdge(
        caller_symbol_id=edge.caller_symbol,
        caller_qualified_key=edge.caller_symbol,
        callee_key=edge.callee_symbol,
        callee_simple_key=_callee_simple_key(edge.callee_symbol),
        evidence_type=edge.edge_kind,
        confidence=edge.confidence,
        file=edge.provenance.artifact_path or edge.provenance.artifact_entry,
        line=max(int(edge.provenance.line or 0), 0),
        content="",
        owner_type=_owner_type(edge.owner_scope),
        owner_coord=edge.owner_coord,
        module="",
        is_test=False,
        callee_param_types=[],
        callee_signature_complete="(" in edge.callee_symbol,
        callee_fqcn_complete="." in edge.callee_symbol.split("(", 1)[0],
        callee_resolution_note="统一证据摄取已验证调用目标和来源",
    )
    converted.evidence_source = edge.provenance.evidence_source
    converted.artifact_sha256 = edge.provenance.artifact_sha256
    converted.artifact_entry = edge.provenance.artifact_entry
    converted.evidence_authority = edge.provenance.authority.value
    converted.semantic = edge.semantic
    converted.collector = collector
    converted.evidence_registry_identity = _edge_identity(edge)
    converted.activation_conditions = list(edge.activation_conditions)
    converted.ambiguity = edge.ambiguous
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
        failures = []
        seen = set()
        duplicates = 0
        rejected = 0
        for batch in self.batches:
            failures.extend(batch.failures)
            for edge in sorted(batch.edges, key=_edge_identity):
                if edge.owner_scope == ModuleScope.UNKNOWN:
                    rejected += 1
                    failures.append(EvidenceFailure(
                        stage="evidence-ingestion",
                        reason_code="EVIDENCE_OWNER_SCOPE_UNKNOWN",
                        blocking=True,
                        artifact=edge.provenance.artifact_path,
                        detail=f"证据边所有权未知：{edge.caller_symbol} -> {edge.callee_symbol}",
                    ))
                    continue
                identity = _edge_identity(edge)
                if identity in seen:
                    duplicates += 1
                    continue
                seen.add(identity)
                accepted.append((batch.collector, edge))

        for collector, edge in accepted:
            converted = _to_call_edge(edge, collector)
            for key in (converted.callee_key, converted.callee_simple_key):
                bucket = graph.reverse_edges.setdefault(key, [])
                bucket.append(converted)

        graph.step5_evidence_registry = tuple(edge for _collector, edge in accepted)
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
        )


def ingest_collector_batches(graph, batches: Iterable[CollectorBatch]) -> IngestionResult:
    """Validate and merge all post-source evidence through one boundary."""
    return EvidenceRegistry.from_batches(batches).ingest_into(graph)


__all__ = [
    "EvidenceRegistry",
    "IngestionResult",
    "ingest_collector_batches",
]
