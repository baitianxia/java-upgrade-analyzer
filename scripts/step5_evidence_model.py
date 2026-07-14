"""Typed evidence and pure conclusion policy for Step 5 call-chain analysis."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping, Optional, Tuple


class ModuleScope(str, Enum):
    BUSINESS_CLASSES = "business_classes"
    INTERNAL_MODULE = "internal_module"
    EXTERNAL_DEPENDENCY = "external_dependency"
    UNKNOWN = "unknown"


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
