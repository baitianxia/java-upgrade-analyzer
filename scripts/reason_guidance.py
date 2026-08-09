#!/usr/bin/env python3
"""Small user-facing guidance layer for structured diagnostics.

Binary engine failures already carry their generation, scope and evidence path.
This module intentionally does not reconstruct source-first collector semantics;
it only turns a stable reason code into a consistent action boundary.
"""

from __future__ import annotations

from diagnostic_contract import (
    DEPENDENCY_COORDINATES_UNRESOLVED,
    DIAGNOSTIC_CONTRACT_SCHEMA,
    canonical_reason_code,
    diagnostic_contract_metadata,
    reason_code_aliases,
)


REASON_GUIDANCE_SCHEMA = "java-upgrade-analyzer.reason-guidance.v4"
_VALID_ORIGIN_STEPS = {"step1", "step2", "step3", "step4", "step5", "step6"}


def _origin(value):
    normalized = str(value or "").strip().lower()
    return normalized if normalized in _VALID_ORIGIN_STEPS else ""


def guidance_for_reason_code(reason_code, *, origin_step=""):
    code = canonical_reason_code(reason_code)
    origin = _origin(origin_step)
    if code == DEPENDENCY_COORDINATES_UNRESOLVED:
        title = "依赖坐标仍未解析"
        summary = "最终制品中的运行时条目尚未安全绑定到唯一依赖坐标。"
        semantic_impact = "依赖身份不完整会阻止可靠配对和后续 binary generation。"
        repair_actions = [
            "核对最终制品内 Maven 元数据、构建工具 artifact inventory 和人工坐标映射。",
            "补齐坐标后重新执行 Step1，并确认 dependency_jars.json 已绑定实际条目和 SHA-256。",
        ]
        verification_steps = [
            "原因码消失，且相关容器条目具有唯一 coord、lineage 和 physical identity。"
        ]
        category = "analysis_input"
        decision = "provide_missing_artifact_identity"
    else:
        title = "分析诊断需要处理"
        summary = "系统记录了会限制当前结论的结构化诊断。"
        semantic_impact = "受影响范围不能被解释为完整、无变化或无影响。"
        repair_actions = [
            "按诊断中的 generation、scope、artifact 和 evidence path 定位缺口。",
            "修复输入或环境后重跑；binary generation 不会调用旧引擎补算。",
        ]
        verification_steps = [
            "同一 scope 的原因码消失，或 support manifest 明确将其判定为不适用。"
        ]
        category = "analysis_diagnostic"
        decision = "repair_and_rerun_affected_scope"
    return {
        "schema": REASON_GUIDANCE_SCHEMA,
        "reason_code": code,
        "reason_code_aliases": reason_code_aliases(code),
        "origin_step": origin,
        "diagnostic_schema": DIAGNOSTIC_CONTRACT_SCHEMA,
        "diagnostic_contract": diagnostic_contract_metadata(),
        "title": title,
        "category": category,
        "summary": summary,
        "semantic_impact": semantic_impact,
        "recommended_decision": decision,
        "decision_text": "修复证据缺口后重跑受影响阶段，不批准降级或扩大结论。",
        "repair_actions": repair_actions,
        "verification_steps": verification_steps,
    }


def build_catalog_guidance(
    reason_codes,
    *,
    origin_step="",
    observed_scope="step",
    source_components=None,
):
    """Build report-ready guidance without coupling it to an engine collector."""
    rows = []
    for reason_code in sorted({
        canonical_reason_code(value)
        for value in (reason_codes or ())
        if str(value or "").strip()
    }):
        definition = guidance_for_reason_code(
            reason_code,
            origin_step=origin_step,
        )
        rows.append({
            **definition,
            "blocking": True,
            "observed_scope": observed_scope,
            "scope_explanation": "该诊断限制对应步骤或覆盖范围，不代表所有 API 都受到影响。",
            "affected_api_count": 0,
            "affected_api_count_semantics": "not_available_at_step_scope",
            "primary_reason_api_count": 0,
            "potentially_affected_api_count": 0,
            "affected_status_counts": {},
            "observed_failure_count": 1,
            "failure_record_count": 1,
            "failure_occurrence_count": 0,
            "collectors": [],
            "affected_classes": [],
            "affected_artifacts": [],
            "affected_artifact_entries": [],
            "evidence_file": "",
            "evidence_files": [],
            "candidate_evidence": [],
            "sample_apis": [],
            "failure_detail_summaries": [],
            "source_components": list(source_components or ()),
        })
    return rows


def build_diagnostic_guidance_from_summary(summary):
    """Project binary summary reason codes into the established report model."""
    payload = dict(summary or {})
    items = [
        *list(payload.get("uncertain_apis") or ()),
        *list(payload.get("not_analyzed_apis") or ()),
    ]
    grouped = {}
    for item in items:
        reason_code = canonical_reason_code(
            (item or {}).get("reason_code") or "UNKNOWN"
        )
        row = grouped.setdefault(reason_code, {
            **guidance_for_reason_code(
                reason_code,
                origin_step=payload.get("origin_step") or "step5",
            ),
            "blocking": True,
            "observed_scope": "api",
            "affected_api_count": 0,
            "affected_status_counts": {},
            "sample_apis": [],
            "evidence_files": [],
        })
        row["affected_api_count"] += 1
        status = str((item or {}).get("analysis_status") or "unknown")
        row["affected_status_counts"][status] = (
            row["affected_status_counts"].get(status, 0) + 1
        )
        api = str((item or {}).get("api") or "").strip()
        if api and api not in row["sample_apis"]:
            row["sample_apis"].append(api)
    return sorted(grouped.values(), key=lambda item: item["reason_code"])
