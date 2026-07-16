"""Typed evidence and pure conclusion policy for Step 5 call-chain analysis."""

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Iterable, Mapping, Optional, Tuple


class FrozenMapping(Mapping):
    """Small recursively immutable mapping used inside frozen evidence records."""

    __slots__ = ("_items", "_values")

    def __init__(self, items=()):
        normalized = tuple(sorted(items, key=lambda item: str(item[0])))
        self._items = normalized
        self._values = dict(normalized)

    def __getitem__(self, key):
        return self._values[key]

    def __iter__(self):
        return (key for key, _value in self._items)

    def __len__(self):
        return len(self._items)

    def __repr__(self):
        return f"FrozenMapping({self._items!r})"


def freeze_evidence_value(value):
    if isinstance(value, Mapping):
        return FrozenMapping(
            (key, freeze_evidence_value(item)) for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return tuple(freeze_evidence_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return tuple(sorted(
            (freeze_evidence_value(item) for item in value),
            key=repr,
        ))
    return value


def thaw_evidence_value(value):
    if isinstance(value, Mapping):
        return {
            key: thaw_evidence_value(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return [thaw_evidence_value(item) for item in value]
    return value


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
    activation_verified: bool = False
    activation_conditions: Tuple[Any, ...] = field(default_factory=tuple)
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
        if self.activation_verified and not self.semantic:
            raise ValueError("activation verification is only valid for semantic edges")
        object.__setattr__(self, "activation_conditions", tuple(
            freeze_evidence_value(item)
            for item in tuple(self.activation_conditions or ())
        ))
        object.__setattr__(self, "metadata", tuple(sorted(
            (key, freeze_evidence_value(value))
            for key, value in tuple(self.metadata or ())
        )))


@dataclass(frozen=True)
class CoverageRecord:
    collector: str
    api_identity: str
    status: str
    reason_codes: Tuple[str, ...] = field(default_factory=tuple)
    applicable: bool = True
    scope: str = "api"

    def __post_init__(self):
        reason_codes = tuple(self.reason_codes or ())
        if any(not isinstance(item, str) for item in reason_codes):
            raise ValueError("coverage reason codes must be strings")
        object.__setattr__(self, "reason_codes", reason_codes)
        if not self.collector or not self.api_identity:
            raise ValueError("coverage requires collector and API identity")
        if self.status not in {"complete", "partial", "insufficient", "not_applicable"}:
            raise ValueError(f"unsupported coverage status: {self.status}")
        if self.scope not in {"api", "global", "path"}:
            raise ValueError(f"unsupported coverage scope: {self.scope}")
        if self.status == "not_applicable":
            object.__setattr__(self, "applicable", False)


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
        for field_name in ("edges", "failures", "concerns", "coverage"):
            object.__setattr__(self, field_name, tuple(getattr(self, field_name) or ()))
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
        object.__setattr__(self, "metrics", tuple(sorted(
            (key, freeze_evidence_value(value))
            for key, value in tuple(self.metrics or ())
        )))

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
                "activation_verified": edge.activation_verified,
                "activation_conditions": thaw_evidence_value(edge.activation_conditions),
                "provenance": provenance_mapping(edge.provenance),
                "metadata": thaw_evidence_value(dict(edge.metadata)),
            } for edge in self.edges],
            "failures": [failure.__dict__ for failure in self.failures],
            "concerns": [concern.__dict__ for concern in self.concerns],
            "coverage": [{
                "collector": item.collector,
                "api_identity": item.api_identity,
                "status": item.status,
                "reason_codes": list(item.reason_codes),
                "applicable": item.applicable,
                "scope": item.scope,
            } for item in self.coverage],
            "metrics": thaw_evidence_value(dict(self.metrics)),
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
    instruction_offset: int = -1
    semantic: bool = False
    activation_verified: bool = False
    metadata: Tuple[Tuple[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self):
        if (
            isinstance(self.instruction_offset, bool)
            or not isinstance(self.instruction_offset, int)
            or self.instruction_offset < -1
        ):
            raise ValueError("physical instruction offset must be an integer >= -1")
        if self.activation_verified and not self.semantic:
            raise ValueError("activation verification is only valid for semantic edges")
        object.__setattr__(self, "metadata", tuple(sorted(
            (key, freeze_evidence_value(value))
            for key, value in tuple(self.metadata or ())
        )))


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

    def __post_init__(self):
        evidence = tuple(self.evidence or ())
        if any(not isinstance(item, PhysicalCallEdge) for item in evidence):
            raise ValueError("reachability path evidence must be PhysicalCallEdge values")
        object.__setattr__(self, "evidence", evidence)


@dataclass(frozen=True)
class EvidenceEnvelope:
    target_identity: str
    paths: Tuple[ReachabilityPath, ...] = field(default_factory=tuple)
    failures: Tuple[EvidenceFailure, ...] = field(default_factory=tuple)
    concerns: Tuple[EvidenceConcern, ...] = field(default_factory=tuple)
    preservation: Optional[PreservationEvidence] = None
    coverage: Tuple[CoverageRecord, ...] = field(default_factory=tuple)

    def __post_init__(self):
        expected_types = {
            "paths": ReachabilityPath,
            "failures": EvidenceFailure,
            "concerns": EvidenceConcern,
            "coverage": CoverageRecord,
        }
        for field_name, expected_type in expected_types.items():
            values = tuple(getattr(self, field_name) or ())
            if any(not isinstance(item, expected_type) for item in values):
                raise ValueError(
                    f"evidence envelope {field_name} must contain "
                    f"{expected_type.__name__} values"
                )
            object.__setattr__(self, field_name, values)
        if self.preservation is not None and not isinstance(
            self.preservation, PreservationEvidence
        ):
            raise ValueError(
                "evidence envelope preservation must be PreservationEvidence"
            )
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


@dataclass(frozen=True)
class TraceSeed:
    """Stable API identity and comparison context for one trace operation."""
    api_name: str
    api_simple: str
    api_signature: str
    symbol_kind: str
    change_type: str
    coord: str
    severity: str
    confirmed: bool
    source: str
    analysis_scope: str
    old_version: str = ""
    new_version: str = ""


@dataclass(frozen=True)
class AnalysisOutcome:
    """Immutable policy decision plus renderer-owned compatibility evidence."""
    decision: AnalysisDecision
    dependency_chain_coords: Tuple[str, ...] = field(default_factory=tuple)
    call_paths: Tuple[str, ...] = field(default_factory=tuple)
    evidence_paths: Tuple[Any, ...] = field(default_factory=tuple)
    path_details: Tuple[Any, ...] = field(default_factory=tuple)
    verification_commands: Tuple[str, ...] = field(default_factory=tuple)
    hops: Tuple[Any, ...] = field(default_factory=tuple)
    confidence_score: float = 1.0
    critical_nodes_hit: Tuple[Any, ...] = field(default_factory=tuple)
    match_provenance: str = ""
    match_tier: int = -1
    capability_coverage: Tuple[Tuple[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self):
        if not isinstance(self.decision, AnalysisDecision):
            raise ValueError("analysis outcome requires an AnalysisDecision")
        for field_name in (
            "dependency_chain_coords", "call_paths", "evidence_paths",
            "path_details", "verification_commands", "hops",
            "critical_nodes_hit", "capability_coverage",
        ):
            object.__setattr__(
                self,
                field_name,
                tuple(
                    freeze_evidence_value(item)
                    for item in tuple(getattr(self, field_name) or ())
                ),
            )


def classify_module_scope(item: Optional[Mapping[str, Any]]) -> ModuleScope:
    """Classify artifact ownership without treating internal modules as entries."""
    if not item:
        return ModuleScope.UNKNOWN
    coord = str(item.get("coord") or "").strip()
    if coord == "__business__":
        return ModuleScope.BUSINESS_CLASSES
    if bool(item.get("application_owned")):
        evidence = item.get("ownership_evidence")
        if not isinstance(evidence, Mapping):
            return ModuleScope.UNKNOWN
        authority = str(evidence.get("authority") or "").strip()
        reactor_coord = str(evidence.get("reactor_coord") or "").strip()
        artifact_entry = str(evidence.get("artifact_entry") or "").strip()
        artifact_sha = str(evidence.get("final_artifact_sha256") or "").strip()
        if (
            authority == "reactor_coordinate_and_final_artifact_entry"
            and reactor_coord == coord
            and artifact_entry.endswith(".jar")
            and re.fullmatch(r"[0-9a-f]{64}", artifact_sha)
        ):
            return ModuleScope.INTERNAL_MODULE
        return ModuleScope.UNKNOWN
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
    blocking_failures = tuple(failure for failure in failure_items if failure.blocking)
    blocking_failure = min(
        blocking_failures,
        key=lambda failure: (
            0 if failure.stage == "input-validation" else
            2 if failure.stage == "coverage" else 1,
            failure.stage,
            failure.reason_code,
        ),
        default=None,
    )
    if blocking_failure is not None and blocking_failure.stage == "input-validation":
        return AnalysisDecision(
            analysis_status="not_analyzed",
            is_reachable=None,
            reason_code=blocking_failure.reason_code,
            reachable_note=blocking_failure.detail or "关键证据采集失败，无法形成可靠结论",
            direct_callers=direct_callers,
            business_reach_depth=business_reach_depth,
        )

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

    def activation_unproven(path):
        semantic_edges = tuple(edge for edge in path.evidence if edge.semantic)
        framework_claim = path.stop_reason in {
            "RUNTIME_FRAMEWORK_ENTRY_REACHED",
            "RUNTIME_DEPENDENCY_ENTRY_REACHED",
        }
        return bool(
            (framework_claim and not semantic_edges)
            or any(not edge.activation_verified for edge in semantic_edges)
        )

    reachable_paths = tuple(
        path for path in path_items
        if (
            path.entry_scope == ModuleScope.BUSINESS_CLASSES
            and path.complete
            and not path.ambiguous
            and not path.truncated
            and not activation_unproven(path)
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
        concern = min(
            concern_items,
            key=lambda item: (
                item.stage, item.reason_code, item.api_identity,
                item.artifact, item.class_name, item.detail,
            ),
        )
        return AnalysisDecision(
            analysis_status="uncertain",
            is_reachable=None,
            reason_code=concern.reason_code,
            reachable_note=concern.detail,
            direct_callers=direct_callers,
            business_reach_depth=business_reach_depth,
        )

    if any(activation_unproven(path) for path in path_items):
        return AnalysisDecision(
            analysis_status="uncertain",
            is_reachable=None,
            reason_code="FRAMEWORK_ACTIVATION_UNPROVEN",
            reachable_note=(
                "已发现框架、代理、反射或回调语义路径，但没有独立证据证明该语义边会由业务入口激活"
            ),
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
    applicable = tuple(item for item in envelope.coverage if item.applicable)
    incomplete = tuple(
        item for item in applicable
        if item.status != "complete"
    )
    failures = envelope.failures
    target_concerns = tuple(
        concern for concern in envelope.concerns
        if concern.api_identity == envelope.target_identity
    )
    # Coverage gaps make an absence conclusion unsafe. They must not erase
    # target-specific evidence that was actually observed; that evidence still
    # supports reachable/uncertain while explicit collector failures remain
    # independently blocking.
    has_observed_evidence = bool(
        envelope.paths or target_concerns or envelope.preservation is not None
    )
    if incomplete and not has_observed_evidence:
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
    complete_scan = bool(applicable) and not incomplete
    return decide_analysis(
        envelope.paths,
        failures,
        concerns=target_concerns,
        preservation=envelope.preservation,
        complete_scan=complete_scan,
    )
