#!/usr/bin/env python3
"""User-facing guidance for Step5 diagnostic reason codes.

Reason codes remain stable machine identifiers. This module adds the decision
context that a reader otherwise has to reconstruct from collector source:
trigger, semantic impact, observed scope, repair actions and verification.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping


REASON_GUIDANCE_SCHEMA = "java-upgrade-analyzer.reason-guidance.v1"
_SAMPLE_LIMIT = 5
_EVIDENCE_LIMIT = 10


_REASON_GUIDANCE = {
    "SPRING_PACKAGED_CLASS_AMBIGUOUS": {
        "title": "Spring 运行时类选择歧义",
        "category": "runtime_classpath",
        "summary": (
            "最终制品中同一逻辑类存在多个字节码不同的运行时可见定义，"
            "且没有可信类路径顺序可以证明 JVM 最终会加载哪一个。"
        ),
        "trigger_condition": (
            "Spring 适配器定位业务类或连接点类时，同一二进制类名命中多个物理条目；"
            "候选字节码不同，并且 BOOT-INF/classpath.idx 等权威顺序不能唯一选中候选。"
            "完全相同的重复字节码会自动折叠，不会触发此原因。"
        ),
        "semantic_impact": (
            "只应阻断调用链经过歧义类的 Spring 隐式调用证据；"
            "无关 API 和不经过该类的路径不应被降级。"
        ),
        "recommended_decision": "fix_before_relying_on_affected_results",
        "decision_text": (
            "受影响 API 的结论不可直接用于发布决策。应消除重复类，"
            "或提供可验证的运行时类路径顺序后重跑。"
        ),
        "ignore_when": (
            "仅当能够证明候选类及其所在依赖不会进入本次部署运行时，"
            "或本条 API 的实际路径不经过该歧义类时，才可在该范围外忽略；"
            "不能因为多个候选“看起来相似”而忽略。"
        ),
        "repair_actions": [
            "用依赖树和最终部署包核对重复类来源，优先排除不应打包的 JAR、错误 shading 或重复内嵌模块。",
            "若运行时确实依赖先后顺序，确保最终制品保留 BOOT-INF/classpath.idx 等可审计顺序，并确认其唯一选中预期 JAR。",
            "重新构建最终制品并重跑 Step1、Step5，避免只修改源码依赖声明而未更新实际部署包。",
        ],
        "verification_steps": [
            "同一逻辑类只剩一个运行时可见定义，或重复定义的 class 字节码完全一致。",
            "若依赖类路径顺序解决，报告应记录 selected_by_classpath_order，并指出被选中的物理条目。",
            "重跑后该原因码消失，受影响 API 获得新的可判定结论；无关 API 不再被该原因降级。",
        ],
    },
    "MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED": {
        "title": "MyBatis 运行时制品解析失败",
        "category": "artifact_integrity",
        "summary": (
            "MyBatis 适配器无法读取当前最终制品保留的一个运行时制品，"
            "因此不能验证 Mapper 代理到 SqlSession 的运行时分派链。"
        ),
        "trigger_condition": (
            "读取 SHA-256 绑定的候选运行时 JAR/内嵌制品清单时发生 ZIP、I/O 或共享制品事实解析错误；"
            "适配器无法确认 MyBatis 代理运行时类是否完整存在。"
        ),
        "semantic_impact": (
            "MyBatis Mapper 的隐式代理调用证据不完整。语义上只影响依赖 MyBatis Mapper/代理路径的结论；"
            "若旧结果把失败记录为 global，报告会如实显示它曾保守阻断所有 API，"
            "以便识别过度传播。"
        ),
        "recommended_decision": "fix_if_mybatis_is_in_scope",
        "decision_text": (
            "部署中使用 MyBatis 时必须修复制品并重跑；否则 Mapper 相关 API 不能判定。"
            "若系统不使用 MyBatis，应先用依赖、Mapper 注册和最终包证据证明该适配器不适用，"
            "而不是直接把全局 not_analyzed 当成可忽略。"
        ),
        "ignore_when": (
            "只有最终部署依赖中没有 MyBatis 运行时，且源码/资源中没有 @Mapper、@MapperScan 或 Mapper XML "
            "等注册证据时，才可将 MyBatis 适配器标记为 not_applicable 后忽略。"
        ),
        "repair_actions": [
            "对报告列出的制品执行 ZIP/JAR 完整性检查，并核对其 SHA-256 是否与 Step1 留存清单一致。",
            "若制品损坏、截断或复制不完整，清理构建缓存后重新构建并重新留存最终部署制品。",
            "确认 MyBatis 核心运行时类只来自预期版本，再重跑 Step5 的框架适配分析。",
        ],
        "verification_steps": [
            "报告列出的每个 JAR 都能完整读取，且哈希与留存清单一致。",
            "MyBatis 适配器状态变为 complete，或在确无 MyBatis 使用证据时变为 not_applicable。",
            "重跑后该原因码消失，原受影响 API 被重新分类。",
        ],
    },
}


def _generic_guidance(reason_code):
    code = str(reason_code or "UNKNOWN").strip() or "UNKNOWN"
    if code.endswith("_AMBIGUOUS"):
        return {
            "title": "候选对象存在歧义",
            "category": "resolution_ambiguity",
            "summary": "分析器找到多个互不等价的候选，无法证明运行时会选择哪一个。",
            "trigger_condition": "同一逻辑目标匹配到多个候选，现有签名、类路径或注册证据不足以唯一解析。",
            "semantic_impact": "仅能确认存在候选，不能把任一候选路径当成已确认影响或已确认无影响。",
            "recommended_decision": "review_or_fix_before_relying_on_affected_results",
            "decision_text": "先补齐唯一性证据或消除重复候选，再使用受影响结果做发布决策。",
            "ignore_when": "只有能证明全部候选均不在本次部署或业务路径中时才可忽略。",
            "repair_actions": [
                "核对报告中的候选类、制品、签名和注册信息，确认歧义来源。",
                "消除重复候选或补充可以唯一选择候选的运行时证据后重跑。",
            ],
            "verification_steps": [
                "同一逻辑目标能够唯一解析，且重跑后该原因码消失。",
            ],
        }
    if code.endswith("_PARSE_FAILED"):
        return {
            "title": "分析输入解析失败",
            "category": "artifact_parse",
            "summary": "分析器无法解析完成该能力所需的源码、资源或制品输入。",
            "trigger_condition": "读取或解析输入时发生格式、ZIP、I/O、编码或工具错误。",
            "semantic_impact": "依赖该输入的分析能力不完整；相关未命中不能解释为无影响。",
            "recommended_decision": "fix_before_relying_on_affected_results",
            "decision_text": "修复报告所列输入并重跑后，才能使用受影响结论做发布决策。",
            "ignore_when": "只有能够证明对应分析能力与本次技术栈和业务路径无关时才可忽略。",
            "repair_actions": [
                "检查报告列出的文件是否存在、完整、可读且与留存哈希一致。",
                "修复或重新生成输入后重跑对应分析步骤。",
            ],
            "verification_steps": [
                "输入可被完整解析，适配器状态恢复为 complete 或有证据地标记为 not_applicable。",
            ],
        }
    return {
        "title": "分析诊断需要处理",
        "category": "analysis_diagnostic",
        "summary": "静态分析器记录了一个会限制当前结论的诊断状态。",
        "trigger_condition": "具体触发证据见本条的制品、类、采集器和原始诊断摘要。",
        "semantic_impact": "受影响 API 的当前结论存在证据缺口，不能把未完成或未确认解释为无影响。",
        "recommended_decision": "review_before_relying_on_affected_results",
        "decision_text": "按本条证据补齐输入或完成复核，再决定是否需要代码或制品修复。",
        "ignore_when": "只有能够证明该诊断能力与本次部署和受影响 API 均无关时才可忽略。",
        "repair_actions": [
            "根据本条列出的采集器、制品、类和 API 样例定位证据缺口。",
            "补齐输入或修复分析环境后重跑，并确认原因码消失或被明确标记为不适用。",
        ],
        "verification_steps": [
            "受影响 API 获得可判定结论，或该能力有证据地标记为 not_applicable。",
        ],
    }


def guidance_for_reason_code(reason_code):
    """Return a detached guidance definition for one stable reason code."""
    code = str(reason_code or "UNKNOWN").strip() or "UNKNOWN"
    definition = _REASON_GUIDANCE.get(code)
    return {
        "reason_code": code,
        "catalog_match": "exact" if definition is not None else "family_fallback",
        **dict(definition or _generic_guidance(code)),
    }


def _get(item, name, default=None):
    if isinstance(item, Mapping):
        return item.get(name, default)
    return getattr(item, name, default)


def _api_identity(item):
    explicit = str(_get(item, "api_identity", "") or "").strip()
    if explicit:
        return explicit
    coord = str(_get(item, "coord", "") or "").strip()
    api = str(
        _get(item, "api_name", "") or _get(item, "api", "") or ""
    ).strip()
    signature = str(_get(item, "api_signature", "") or "").strip()
    symbol_kind = str(_get(item, "symbol_kind", "") or "").strip()
    pieces = [value for value in (coord, api + signature, symbol_kind) if value]
    return " | ".join(pieces)


def _unique(values, limit=_EVIDENCE_LIMIT):
    result = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in result:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def _failure_rows(graph_stats):
    ingestion = dict((graph_stats or {}).get("evidence_ingestion") or {})
    occurrence_fields = list(ingestion.get("failure_occurrence_fields") or ())
    rows = []
    for raw in ingestion.get("failures") or ():
        if not isinstance(raw, Mapping):
            continue
        row = dict(raw)
        occurrences = []
        for occurrence in row.get("occurrences") or ():
            if isinstance(occurrence, Mapping):
                occurrences.append(dict(occurrence))
            elif occurrence_fields and isinstance(occurrence, (list, tuple)):
                occurrences.append(dict(zip(occurrence_fields, occurrence)))
        row["occurrences"] = occurrences
        rows.append(row)
    return rows


def _detail_mapping(detail):
    if isinstance(detail, Mapping):
        return dict(detail)
    text = str(detail or "").strip()
    if not text.startswith("{"):
        return {}
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return dict(parsed) if isinstance(parsed, Mapping) else {}


def _observed_scope(scopes):
    normalized = sorted({
        str(scope or "api").strip() or "api" for scope in scopes
    })
    if not normalized:
        return "api"
    return normalized[0] if len(normalized) == 1 else "mixed"


def _detail_summary(detail):
    parsed = _detail_mapping(detail)
    if parsed:
        pieces = []
        for key in ("reason_code", "class_name", "resolution", "error_type"):
            value = str(parsed.get(key) or "").strip()
            if value:
                pieces.append(f"{key}={value}")
        candidates = list(parsed.get("candidates") or ())
        if candidates:
            pieces.append(f"candidate_count={len(candidates)}")
        return "; ".join(pieces) or "structured_diagnostic"
    text = str(detail or "").strip()
    return text[:500] + ("…" if len(text) > 500 else "")


def _scope_explanation(scope, affected_api_count):
    count_text = (
        f"本轮 {affected_api_count} 个 API 以该原因为主原因；"
        if affected_api_count
        else "本轮没有 API 以该原因为主原因，但 failure ledger 已记录此诊断；"
    )
    if scope == "global":
        return f"{count_text}该失败被分析器记录为全局阻断。"
    if scope == "path":
        return f"{count_text}失败只应作用于经过相关类或采集器的调用路径。"
    if scope == "mixed":
        return f"{count_text}本轮同时观察到多种传播作用域，需按证据逐项核对。"
    if scope == "unknown":
        return f"{count_text}旧摘要未保留 typed failure 的实际传播作用域。"
    return f"{count_text}失败按目标 API 隔离。"


def build_diagnostic_guidance(results, graph_stats=None):
    """Aggregate result reasons and typed failure evidence into user guidance."""
    grouped_results = defaultdict(list)
    status_counts = defaultdict(lambda: defaultdict(int))
    for item in results or ():
        status = str(_get(item, "analysis_status", "") or "").strip()
        reason_code = str(_get(item, "reason_code", "") or "UNKNOWN").strip()
        if status not in {"uncertain", "not_analyzed"}:
            continue
        grouped_results[reason_code].append(item)
        status_counts[reason_code][status] += 1

    grouped_failures = defaultdict(list)
    for failure in _failure_rows(graph_stats or {}):
        reason_code = str(failure.get("reason_code") or "UNKNOWN").strip()
        if failure.get("blocking") or reason_code in grouped_results:
            grouped_failures[reason_code].append(failure)

    guidance = []
    reason_codes = set(grouped_results) | set(grouped_failures)
    for reason_code in reason_codes:
        definition = guidance_for_reason_code(reason_code)
        result_items = grouped_results.get(reason_code, ())
        failures = grouped_failures.get(reason_code, ())
        scopes = [
            failure.get("scope") or "global" for failure in failures
        ] or ["unknown"]
        occurrences = [
            occurrence
            for failure in failures
            for occurrence in failure.get("occurrences") or ()
        ]
        detail_mappings = [
            _detail_mapping(failure.get("detail")) for failure in failures
        ]
        candidate_rows = [
            candidate
            for detail in detail_mappings
            for candidate in detail.get("candidates") or ()
            if isinstance(candidate, Mapping)
        ]
        candidate_evidence = []
        for candidate in candidate_rows:
            row = {
                "coord": str(candidate.get("coord") or ""),
                "artifact": str(candidate.get("artifact_path") or ""),
                "artifact_entry": str(candidate.get("artifact_entry") or ""),
                "bytecode_sha256": str(candidate.get("bytecode_sha256") or ""),
            }
            if row not in candidate_evidence:
                candidate_evidence.append(row)
            if len(candidate_evidence) >= _EVIDENCE_LIMIT:
                break
        artifacts = _unique([
            *[failure.get("artifact") for failure in failures],
            *[occurrence.get("artifact") for occurrence in occurrences],
            *[candidate.get("artifact_path") for candidate in candidate_rows],
        ])
        artifact_entries = _unique([
            *[occurrence.get("artifact_entry") for occurrence in occurrences],
            *[candidate.get("artifact_entry") for candidate in candidate_rows],
        ])
        classes = _unique([
            *[failure.get("class_name") for failure in failures],
            *[occurrence.get("class_name") for occurrence in occurrences],
            *[detail.get("class_name") for detail in detail_mappings],
        ])
        collectors = _unique([
            failure.get("collector") or failure.get("stage")
            for failure in failures
        ])
        detail_summaries = _unique([
            _detail_summary(failure.get("detail")) for failure in failures
        ], limit=3)
        affected_api_count = len(result_items)
        scope = _observed_scope(scopes)
        guidance.append({
            **definition,
            "blocking": any(bool(failure.get("blocking")) for failure in failures),
            "observed_scope": scope,
            "scope_explanation": _scope_explanation(scope, affected_api_count),
            "affected_api_count": affected_api_count,
            "affected_api_count_semantics": "primary_reason",
            "affected_status_counts": dict(sorted(status_counts[reason_code].items())),
            "observed_failure_count": len(failures),
            "collectors": collectors,
            "affected_classes": classes,
            "affected_artifacts": artifacts,
            "affected_artifact_entries": artifact_entries,
            "candidate_evidence": candidate_evidence,
            "sample_apis": _unique(
                (_api_identity(item) for item in result_items),
                limit=_SAMPLE_LIMIT,
            ),
            "failure_detail_summaries": detail_summaries,
        })
    return sorted(
        guidance,
        key=lambda item: (
            not item.get("blocking"),
            -int(item.get("affected_api_count") or 0),
            item.get("reason_code") or "",
        ),
    )


def build_diagnostic_guidance_from_summary(summary):
    """Build guidance for old or synthetic summaries that lack the new field."""
    payload = dict(summary or {})
    results = [
        *list(payload.get("uncertain_apis") or ()),
        *list(payload.get("not_analyzed_apis") or ()),
    ]
    graph_stats = dict((payload.get("meta") or {}).get("graph_stats") or {})
    return build_diagnostic_guidance(results, graph_stats)
