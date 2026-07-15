"""Typed evidence and pure conclusion policy for Step 5 call-chain analysis."""

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Iterable, Mapping, Optional, Tuple


class ModuleScope(str, Enum):
    BUSINESS_CLASSES = "business_classes"
    INTERNAL_MODULE = "internal_module"
    EXTERNAL_DEPENDENCY = "external_dependency"
    UNKNOWN = "unknown"


class EvidenceAuthority(str, Enum):
    SOURCE_AST = "source_ast"
    SOURCE_INDIRECT_INFERENCE = "source_indirect_inference"
    CURRENT_FINAL_ARTIFACT = "current_final_artifact"
    PACKAGED_RUNTIME = "packaged_runtime"
    FRAMEWORK_SEMANTIC = "framework_semantic"
    RESOURCE_CONFIGURATION = "resource_configuration"
    RUNTIME_OBSERVATION = "runtime_observation"


@dataclass(frozen=True)
class EvidenceProvenance:
    authority: EvidenceAuthority
    artifact_path: str = ""
    artifact_sha256: str = ""
    artifact_entry: str = ""
    class_or_resource_entry: str = ""
    parser: str = ""
    evidence_source: str = ""
    line: int = 0
    instruction_offset: int = -1

    def __post_init__(self):
        digest = str(self.artifact_sha256 or "")
        if digest and not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("artifact SHA-256 must contain 64 lowercase hex characters")
        if self.authority in {
            EvidenceAuthority.CURRENT_FINAL_ARTIFACT,
            EvidenceAuthority.PACKAGED_RUNTIME,
        } and not digest:
            raise ValueError("final-artifact evidence requires artifact SHA-256")


@dataclass(frozen=True)
class CollectedEdge:
    caller_symbol: str
    callee_symbol: str
    edge_kind: str
    semantic: bool
    owner_scope: ModuleScope
    provenance: EvidenceProvenance
    owner_coord: str = ""
    confidence: str = "high"
    ambiguous: bool = False
    activation_conditions: Tuple[str, ...] = field(default_factory=tuple)
    metadata: Tuple[Tuple[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self):
        if not self.caller_symbol or not self.callee_symbol or not self.edge_kind:
            raise ValueError("collected edge requires caller, callee, and edge kind")
        if self.semantic and self.provenance.authority not in {
            EvidenceAuthority.SOURCE_AST,
            EvidenceAuthority.FRAMEWORK_SEMANTIC,
            EvidenceAuthority.RESOURCE_CONFIGURATION,
            EvidenceAuthority.RUNTIME_OBSERVATION,
            EvidenceAuthority.SOURCE_INDIRECT_INFERENCE,
        }:
            raise ValueError("semantic edge authority must be semantic or runtime evidence")


@dataclass(frozen=True)
class CoverageRecord:
    collector: str
    api_identity: str
    status: str
    reason_codes: Tuple[str, ...] = field(default_factory=tuple)
    applicable: bool = True

    def __post_init__(self):
        if not self.collector or not self.api_identity:
            raise ValueError("coverage requires collector and API identity")
        if self.status not in {"complete", "partial", "insufficient", "not_applicable"}:
            raise ValueError(f"unsupported coverage status: {self.status}")


@dataclass(frozen=True)
class CollectorBatch:
    collector: str
    version: str
    edges: Tuple[CollectedEdge, ...] = field(default_factory=tuple)
    failures: Tuple["EvidenceFailure", ...] = field(default_factory=tuple)
    concerns: Tuple["EvidenceConcern", ...] = field(default_factory=tuple)
    coverage: Tuple[CoverageRecord, ...] = field(default_factory=tuple)
    metrics: Tuple[Tuple[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self):
        if not str(self.collector or "").strip() or not str(self.version or "").strip():
            raise ValueError("collector identity and version are required")
        for edge in self.edges:
            if not isinstance(edge, CollectedEdge):
                raise ValueError("collector edges must be CollectedEdge values")
        for failure in self.failures:
            if not isinstance(failure, EvidenceFailure):
                raise ValueError("collector failures must be EvidenceFailure values")
        for concern in self.concerns:
            if not isinstance(concern, EvidenceConcern):
                raise ValueError("collector concerns must be EvidenceConcern values")
        for coverage in self.coverage:
            if not isinstance(coverage, CoverageRecord):
                raise ValueError("collector coverage must be CoverageRecord values")

    def to_mapping(self) -> Mapping[str, Any]:
        def provenance_mapping(item):
            return {
                "authority": item.authority.value,
                "artifact_path": item.artifact_path,
                "artifact_sha256": item.artifact_sha256,
                "artifact_entry": item.artifact_entry,
                "class_or_resource_entry": item.class_or_resource_entry,
                "parser": item.parser,
                "evidence_source": item.evidence_source,
                "line": item.line,
                "instruction_offset": item.instruction_offset,
            }

        return {
            "collector": self.collector,
            "version": self.version,
            "edges": [{
                "caller_symbol": edge.caller_symbol,
                "callee_symbol": edge.callee_symbol,
                "edge_kind": edge.edge_kind,
                "semantic": edge.semantic,
                "owner_scope": edge.owner_scope.value,
                "owner_coord": edge.owner_coord,
                "confidence": edge.confidence,
                "ambiguous": edge.ambiguous,
                "activation_conditions": list(edge.activation_conditions),
                "provenance": provenance_mapping(edge.provenance),
                "metadata": dict(edge.metadata),
            } for edge in self.edges],
            "failures": [failure.__dict__ for failure in self.failures],
            "concerns": [concern.__dict__ for concern in self.concerns],
            "coverage": [{
                "collector": item.collector,
                "api_identity": item.api_identity,
                "status": item.status,
                "reason_codes": list(item.reason_codes),
                "applicable": item.applicable,
            } for item in self.coverage],
            "metrics": dict(self.metrics),
        }


@dataclass(frozen=True)
class EvidenceFailure:
    stage: str
    reason_code: str
    blocking: bool
    api_identity: str = ""
    artifact: str = ""
    class_name: str = ""
    detail: str = ""


@dataclass(frozen=True)
class EvidenceConcern:
    stage: str
    reason_code: str
    detail: str
    api_identity: str = ""
    artifact: str = ""
    class_name: str = ""


@dataclass(frozen=True)
class PreservationEvidence:
    reason_code: str
    detail: str
    api_identity: str = ""
    artifact: str = ""


@dataclass(frozen=True)
class PhysicalCallEdge:
    caller_symbol: str
    callee_key: str
    evidence_type: str
    owner_scope: ModuleScope = ModuleScope.UNKNOWN
    owner_coord: str = ""
    artifact: str = ""
    confidence: str = "high"
    metadata: Tuple[Tuple[str, Any], ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ReachabilityPath:
    path_text: str
    entry_scope: ModuleScope
    complete: bool
    ambiguous: bool = False
    truncated: bool = False
    stop_reason: str = ""
    reason_code: str = ""
    note: str = ""
    depth: int = 0
    evidence: Tuple[PhysicalCallEdge, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class EvidenceEnvelope:
    target_identity: str
    paths: Tuple[ReachabilityPath, ...] = field(default_factory=tuple)
    failures: Tuple[EvidenceFailure, ...] = field(default_factory=tuple)
    concerns: Tuple[EvidenceConcern, ...] = field(default_factory=tuple)
    preservation: Optional[PreservationEvidence] = None
    coverage: Tuple[CoverageRecord, ...] = field(default_factory=tuple)

    def __post_init__(self):
        if not str(self.target_identity or "").strip():
            raise ValueError("evidence envelope requires target identity")
        if any(
            item.api_identity != self.target_identity
            for item in self.coverage
            if item.applicable
        ):
            raise ValueError("coverage API identity must match envelope target")


@dataclass(frozen=True)
class AnalysisDecision:
    analysis_status: str
    is_reachable: Optional[bool]
    reason_code: str
    reachable_note: str
    direct_callers: int = 0
    business_reach_depth: int = 0


def classify_module_scope(item: Optional[Mapping[str, Any]]) -> ModuleScope:
    """Classify artifact ownership without treating internal modules as entries."""
    if not item:
        return ModuleScope.UNKNOWN
    coord = str(item.get("coord") or "").strip()
    if coord == "__business__":
        return ModuleScope.BUSINESS_CLASSES
    if bool(item.get("application_owned")):
        return ModuleScope.INTERNAL_MODULE
    if coord and ":" in coord:
        return ModuleScope.EXTERNAL_DEPENDENCY
    return ModuleScope.UNKNOWN


def decide_analysis(
    paths: Iterable[ReachabilityPath],
    failures: Iterable[EvidenceFailure] = (),
    *,
    concerns: Iterable[EvidenceConcern] = (),
    preservation: Optional[PreservationEvidence] = None,
    preserved: bool = False,
    complete_scan: bool = False,
) -> AnalysisDecision:
    """Derive one conclusion from immutable path and failure evidence."""
    path_items = tuple(paths)
    failure_items = tuple(failures)
    concern_items = tuple(concerns)
    business_depths = tuple(
        max(path.depth, 1)
        for path in path_items
        if path.entry_scope == ModuleScope.BUSINESS_CLASSES
        and not path.ambiguous
        and not path.truncated
    )
    direct_callers = sum(1 for depth in business_depths if depth == 1)
    business_reach_depth = min(business_depths, default=0)
    if preservation is not None or preserved:
        return AnalysisDecision(
            analysis_status="not_impacted",
            is_reachable=False,
            reason_code=(
                preservation.reason_code if preservation is not None else "API_PRESERVED"
            ),
            reachable_note=(
                preservation.detail
                if preservation is not None
                else "目标 API 在当前版本中仍然存在"
            ),
            direct_callers=direct_callers,
            business_reach_depth=business_reach_depth,
        )

    reachable_paths = tuple(
        path for path in path_items
        if (
            path.entry_scope == ModuleScope.BUSINESS_CLASSES
            and path.complete
            and not path.ambiguous
            and not path.truncated
        )
    )
    if reachable_paths:
        primary_path = next(
            (path for path in reachable_paths if path.reason_code),
            reachable_paths[0],
        )
        framework_reached = any(
            path.stop_reason == "RUNTIME_FRAMEWORK_ENTRY_REACHED"
            for path in reachable_paths
        )
        return AnalysisDecision(
            analysis_status="reachable",
            is_reachable=True,
            reason_code=primary_path.reason_code or (
                "RUNTIME_FRAMEWORK_ENTRY_REACHED"
                if framework_reached
                else "BUSINESS_ARTIFACT_BYTECODE_USAGE"
            ),
            reachable_note=primary_path.note or (
                "已通过业务启动代码、最终制品框架注册和依赖字节码确认目标符号会进入运行时调用路径"
                if framework_reached
                else "已在当前最终制品中确认业务 class 可到达目标符号引用"
            ),
            direct_callers=direct_callers,
            business_reach_depth=business_reach_depth,
        )

    blocking_failure = next((failure for failure in failure_items if failure.blocking), None)
    if blocking_failure is not None:
        return AnalysisDecision(
            analysis_status="not_analyzed",
            is_reachable=None,
            reason_code=blocking_failure.reason_code,
            reachable_note=blocking_failure.detail or "关键证据采集失败，无法形成可靠结论",
            direct_callers=direct_callers,
            business_reach_depth=business_reach_depth,
        )

    if concern_items:
        concern = concern_items[0]
        return AnalysisDecision(
            analysis_status="uncertain",
            is_reachable=None,
            reason_code=concern.reason_code,
            reachable_note=concern.detail,
            direct_callers=direct_callers,
            business_reach_depth=business_reach_depth,
        )

    if any(path.ambiguous for path in path_items):
        return AnalysisDecision(
            analysis_status="uncertain",
            is_reachable=None,
            reason_code="UNQUALIFIED_SIGNATURE_TYPE_AMBIGUOUS",
            reachable_note=(
                "目标签名包含无法解析包名的简写类型；存在同名候选，但不能据此确认具体重载"
            ),
            direct_callers=direct_callers,
            business_reach_depth=business_reach_depth,
        )

    if any(path.truncated for path in path_items):
        truncated_path = next(path for path in path_items if path.truncated)
        return AnalysisDecision(
            analysis_status="not_analyzed",
            is_reachable=None,
            reason_code=truncated_path.stop_reason or "EVIDENCE_PATH_TRUNCATED",
            reachable_note=(
                truncated_path.note
                or "调用路径证据被截断，无法形成可靠的静态未命中结论"
            ),
            direct_callers=direct_callers,
            business_reach_depth=business_reach_depth,
        )

    physical_paths = tuple(
        path for path in path_items
        if path.entry_scope in {ModuleScope.INTERNAL_MODULE, ModuleScope.EXTERNAL_DEPENDENCY}
    )
    if physical_paths:
        primary_path = next(
            (path for path in physical_paths if path.reason_code),
            physical_paths[0],
        )
        return AnalysisDecision(
            analysis_status="uncertain",
            is_reachable=None,
            reason_code=primary_path.reason_code or "PACKAGED_DEPENDENCY_BYTECODE_USAGE",
            reachable_note=primary_path.note or (
                "已在当前最终制品的运行时依赖字节码中确认对目标符号的稳定引用，"
                "但当前尚未证明这些依赖是否回到系统业务入口"
            ),
            direct_callers=direct_callers,
            business_reach_depth=business_reach_depth,
        )

    if complete_scan:
        return AnalysisDecision(
            analysis_status="not_found_in_static_analysis",
            is_reachable=False,
            reason_code="NO_STATIC_PATH",
            reachable_note="完整静态证据扫描未发现目标 API 的调用路径",
            direct_callers=direct_callers,
            business_reach_depth=business_reach_depth,
        )

    return AnalysisDecision(
        analysis_status="not_analyzed",
        is_reachable=None,
        reason_code="INCOMPLETE_EVIDENCE",
        reachable_note="证据采集未完成，无法形成可靠结论",
        direct_callers=direct_callers,
        business_reach_depth=business_reach_depth,
    )


def decide_envelope(envelope: EvidenceEnvelope) -> AnalysisDecision:
    """Derive one decision after enforcing applicable per-API coverage."""
    incomplete = tuple(
        item for item in envelope.coverage
        if item.applicable and item.status not in {"complete", "not_applicable"}
    )
    failures = envelope.failures
    if incomplete:
        detail = ", ".join(
            f"{item.collector}:{item.status}"
            for item in sorted(incomplete, key=lambda row: row.collector)
        )
        failures += (EvidenceFailure(
            stage="coverage",
            reason_code="INCOMPLETE_EVIDENCE_COVERAGE",
            blocking=True,
            api_identity=envelope.target_identity,
            detail=f"适用的证据采集覆盖不完整：{detail}",
        ),)
    complete_scan = bool(envelope.coverage) and not incomplete
    return decide_analysis(
        envelope.paths,
        failures,
        concerns=envelope.concerns,
        preservation=envelope.preservation,
        complete_scan=complete_scan,
    )


def decision_to_trace_patch(decision: AnalysisDecision) -> Mapping[str, Any]:
    """Expose the legacy TraceResult conclusion fields during incremental migration."""
    return {
        "analysis_status": decision.analysis_status,
        "is_reachable": decision.is_reachable,
        "reason_code": decision.reason_code,
        "reachable_note": decision.reachable_note,
        "direct_callers": decision.direct_callers,
        "business_reach_depth": decision.business_reach_depth,
    }
