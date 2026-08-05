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

from diagnostic_contract import (
    DEPENDENCY_COORDINATES_UNRESOLVED,
    DEPENDENCY_SOURCE_REF_UNAVAILABLE,
    DIAGNOSTIC_CONTRACT_SCHEMA,
    JAPICMP_EXECUTION_FAILED,
    JAPICMP_TIMEOUT,
    MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED,
    SPRING_RUNTIME_CLASS_AMBIGUOUS,
    canonical_reason_code,
    diagnostic_contract_metadata,
    reason_code_aliases,
)
from signature_utils import (
    canonical_api_identity,
    normalize_signature_for_identity,
    signatures_match_identity,
)

REASON_GUIDANCE_SCHEMA = "java-upgrade-analyzer.reason-guidance.v3"
_SAMPLE_LIMIT = 5
_EVIDENCE_LIMIT = 10
_VALID_ORIGIN_STEPS = {
    "step1", "step2", "step3", "step4", "step5", "step6",
}


def _normalized_origin_step(value, default=""):
    normalized = str(value or "").strip().lower()
    if normalized in _VALID_ORIGIN_STEPS:
        return normalized
    fallback = str(default or "").strip().lower()
    return fallback if fallback in _VALID_ORIGIN_STEPS else ""


_REASON_GUIDANCE = {
    DEPENDENCY_COORDINATES_UNRESOLVED: {
        "title": "依赖坐标仍未解析",
        "origin_step": "step1",
        "domain": "dependency",
        "subject": "coordinates",
        "condition": "unresolved",
        "category": "analysis_input",
        "summary": (
            "Step1 已使用构建产物、分支、源码目录和已有人工补充信息尝试识别依赖，"
            "但仍有嵌套 JAR 无法安全映射到唯一 Maven 坐标。"
        ),
        "trigger_condition": (
            "最终制品中的嵌套 JAR 缺少可信 Maven 坐标，且 enrichment 后仍无法根据 "
            "pom.properties、构建工具输出、分支或源码信息唯一补全。"
        ),
        "semantic_impact": (
            "未解析依赖无法进入可靠的升级前后配对；后续 API 对比和调用链分析会跳过这些依赖，"
            "因此可能漏掉真实兼容性风险。"
        ),
        "default_blocking": True,
        "recommended_decision": "provide_input_or_explicitly_accept_gap",
        "decision_text": (
            "优先补充模块、源码或人工坐标映射后重跑 Step1；"
            "只有明确接受覆盖缺口时才确认保留 unresolved。"
        ),
        "ignore_when": (
            "只有能够证明该嵌套 JAR 不属于本次部署运行时，或明确接受后续步骤跳过它造成的漏报风险时，"
            "才可确认继续。"
        ),
        "repair_actions": [
            "补充正确的 primary_module、升级前后源码目录或 branch/tag/commit。",
            "对仍无法识别的条目提供 artifact:version -> group:artifact 人工坐标映射。",
            "重新运行 Step1，并检查依赖变更清单中不再存在对应 unresolved 行。",
        ],
        "verification_steps": [
            "Step1 不再输出该原因码，或用户已明确确认接受列出的 unresolved 覆盖缺口。",
            "相关依赖具有稳定坐标并进入升级前后配对与后续分析范围。",
        ],
    },
    DEPENDENCY_SOURCE_REF_UNAVAILABLE: {
        "title": "依赖源码版本不可用",
        "origin_step": "step4",
        "domain": "dependency",
        "subject": "source_ref",
        "condition": "unavailable",
        "category": "source_evidence",
        "summary": (
            "Step4 无法把依赖版本可靠固定到源码仓库中的 old/new commit，"
            "因此跳过源码行为差异辅助分析。"
        ),
        "trigger_condition": (
            "依赖源码 ref 未找到、远端不可用、拉取失败、分支漂移，"
            "或没有形成可安全采用的唯一提交范围。"
        ),
        "semantic_impact": (
            "源码行为差异证据缺失；最终制品 JAR 的二进制和方法字节码分析仍可继续，"
            "但若 JAR 兜底也失败，签名不变的实现变化可能漏报。"
        ),
        "default_blocking": False,
        "recommended_decision": "verify_binary_fallback_or_restore_source_ref",
        "decision_text": (
            "先确认对应依赖的最终 JAR 方法字节码兜底已完成；"
            "若未完成，应修复源码 ref 或制品输入后重跑 Step4。"
        ),
        "ignore_when": (
            "仅当同一依赖的最终 JAR 行为差异分析状态为 complete，"
            "且本次决策不依赖源码级结构信息时，才可接受该源码证据缺口。"
        ),
        "repair_actions": [
            "核对依赖源码仓库地址、版本标签和 old/new commit，并修复网络或权限问题。",
            "需要使用本地源码兜底时显式授权并记录固定 commit，避免直接采用漂移中的工作区。",
            "重跑 Step4，或确认最终 JAR 方法字节码兜底已覆盖该依赖。",
        ],
        "verification_steps": [
            "源码 old/new ref 被固定到可复现 commit，或对应 JAR 行为差异兜底状态为 complete。",
            "Step4 覆盖文件中该依赖不再属于 behavior_diff 未覆盖集合。",
        ],
    },
    JAPICMP_EXECUTION_FAILED: {
        "title": "JApiCmp 依赖对比执行失败",
        "origin_step": "step4",
        "domain": "japicmp",
        "subject": "execution",
        "condition": "failed",
        "category": "binary_api_diff",
        "summary": (
            "JApiCmp 已针对某个依赖启动，但进程非正常退出或没有形成可验证的对比结果。"
        ),
        "trigger_condition": (
            "单个依赖的 JApiCmp 进程返回非零退出码，或执行结果无法作为二进制 API 差异证据采用。"
        ),
        "semantic_impact": (
            "该依赖的 API 变化数据不可用；all_changed_apis.csv 中没有该依赖的记录，"
            "不能解释为该依赖确实没有 API 变化。其他成功依赖的结果仍然有效。"
        ),
        "default_blocking": True,
        "recommended_decision": "repair_and_rerun_failed_dependency",
        "decision_text": (
            "查看逐依赖状态台账和原始 JApiCmp 输出，修复该依赖的工具、JDK、JAR 或资源问题后重跑 Step4。"
        ),
        "ignore_when": (
            "仅当能够证明该依赖不属于本次最终运行时，或已明确接受该依赖全部 API 风险未知时，"
            "才可排除；不能因 all_changed_apis.csv 中没有记录而忽略。"
        ),
        "repair_actions": [
            "打开 dependency_analysis_status.json 中该依赖的 api_comparison_failure_reason 和 api_comparison_evidence_path。",
            "检查 old/new 最终制品 JAR、Java/JDK 兼容性、JApiCmp stderr 与进程资源。",
            "修复后重跑 Step4；无需把失败伪造成一条 API 变化记录。",
        ],
        "verification_steps": [
            "逐依赖状态从 failed 变为 changes_detected 或 no_api_change。",
            "Step4 binary_api_diff 覆盖状态不再因该依赖处于 partial/insufficient。",
        ],
    },
    JAPICMP_TIMEOUT: {
        "title": "JApiCmp 依赖对比超时",
        "origin_step": "step4",
        "domain": "japicmp",
        "subject": "execution",
        "condition": "timeout",
        "category": "binary_api_diff",
        "summary": "单个依赖的 JApiCmp 对比超过配置时限，未形成可判定结果。",
        "trigger_condition": "JApiCmp 子进程在 step4_japicmp_timeout 到期前没有完成。",
        "semantic_impact": (
            "该依赖的 API 变化数据不可用，不能归入“成功对比且无 API 变化”。"
        ),
        "default_blocking": True,
        "recommended_decision": "increase_timeout_or_reduce_contention_and_rerun",
        "decision_text": (
            "结合原始输出评估耗时，适当增加 step4_japicmp_timeout，"
            "或降低 step4_workers 后重跑失败依赖。"
        ),
        "ignore_when": (
            "仅当该依赖已被证明确认不在最终运行时范围内时可以排除；否则应恢复完整对比。"
        ),
        "repair_actions": [
            "增加 step4_japicmp_timeout，或降低 step4_workers 以减少 CPU/内存争用。",
            "确认 old/new JAR 可读且没有异常膨胀、损坏或重复嵌套。",
            "重跑 Step4 并检查逐依赖状态台账。",
        ],
        "verification_steps": [
            "该依赖状态变为 changes_detected 或 no_api_change。",
            "timeouts.json 与 Step4 覆盖结果不再记录该依赖超时。",
        ],
    },
    SPRING_RUNTIME_CLASS_AMBIGUOUS: {
        "title": "Spring 运行时类选择歧义",
        "origin_step": "step5",
        "domain": "spring",
        "subject": "runtime_class",
        "condition": "ambiguous",
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
        "default_blocking": True,
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
    MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED: {
        "title": "MyBatis 运行时制品解析失败",
        "origin_step": "step5",
        "domain": "mybatis",
        "subject": "runtime_artifact",
        "condition": "parse_failed",
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
        "default_blocking": True,
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


def guidance_for_reason_code(reason_code, *, origin_step=""):
    """Return a detached guidance definition for one stable reason code."""
    input_code = str(reason_code or "UNKNOWN").strip() or "UNKNOWN"
    code = canonical_reason_code(input_code)
    definition = _REASON_GUIDANCE.get(code)
    return {
        "reason_code": code,
        "reason_code_aliases": reason_code_aliases(code),
        "input_reason_code": input_code,
        "matched_via": "canonical" if input_code == code else "legacy_alias",
        "diagnostic_schema": DIAGNOSTIC_CONTRACT_SCHEMA,
        "diagnostic_contract": diagnostic_contract_metadata(),
        "catalog_match": "exact" if definition is not None else "family_fallback",
        "origin_step": str(
            (definition or {}).get("origin_step")
            or origin_step
            or "unknown"
        ),
        "domain": str((definition or {}).get("domain") or "analysis"),
        "subject": str((definition or {}).get("subject") or "diagnostic"),
        "condition": str((definition or {}).get("condition") or "requires_review"),
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


def _canonical_result_identity(item):
    row = {
        "coord": _get(item, "coord", ""),
        "api_name": _get(item, "api_name", "") or _get(item, "api", ""),
        "api_signature": _get(item, "api_signature", ""),
        "symbol_kind": _get(item, "symbol_kind", ""),
        "change_type": _get(item, "change_type", ""),
    }
    if not any(str(value or "").strip() for value in row.values()):
        return ""
    return canonical_api_identity(row)


def _compact_identity(value):
    return "".join(str(value or "").replace("$", ".").split())


def _failure_matches_result(failure, item):
    scope = str(failure.get("scope") or "global").strip()
    if scope == "global":
        return True
    failure_identity = str(failure.get("api_identity") or "").strip()
    if not failure_identity:
        return False

    compact_failure = _compact_identity(failure_identity)
    explicit_identity = str(_get(item, "api_identity", "") or "").strip()
    result_identities = {
        _compact_identity(explicit_identity),
        _compact_identity(_canonical_result_identity(item)),
    }
    result_identities.discard("")
    if compact_failure in result_identities:
        return True

    canonical_identity = _canonical_result_identity(item)
    canonical_parts = canonical_identity.split("|")
    api_name = str(
        _get(item, "api_name", "") or _get(item, "api", "") or ""
    ).strip().replace("$", ".")
    result_signature = (
        canonical_parts[2]
        if len(canonical_parts) > 2
        else normalize_signature_for_identity(
            str(_get(item, "api_signature", "") or "").replace("$", ".")
        )
    )
    api_names = {
        _compact_identity(api_name),
        _compact_identity(canonical_parts[1] if len(canonical_parts) > 1 else ""),
    }
    api_names.discard("")
    for compact_api_name in api_names:
        if compact_failure == compact_api_name:
            return True
        if not compact_failure.startswith(compact_api_name + "("):
            continue
        failure_signature = compact_failure[len(compact_api_name):]
        if result_signature and signatures_match_identity(
            failure_signature,
            result_signature,
        ):
            return True
    return False


def _result_failure_lookup_keys(item):
    canonical_identity = _canonical_result_identity(item)
    canonical_parts = canonical_identity.split("|")
    explicit_identity = str(_get(item, "api_identity", "") or "").strip()
    raw_api_name = str(
        _get(item, "api_name", "") or _get(item, "api", "") or ""
    ).strip()
    api_names = {
        _compact_identity(raw_api_name),
        _compact_identity(canonical_parts[1] if len(canonical_parts) > 1 else ""),
    }
    api_names.discard("")
    signature = _compact_identity(
        canonical_parts[2] if len(canonical_parts) > 2 else ""
    )
    exact_identities = {
        _compact_identity(explicit_identity),
        _compact_identity(canonical_identity),
        *api_names,
    }
    if signature:
        exact_identities.update(api_name + signature for api_name in api_names)
    exact_identities.discard("")
    return exact_identities, api_names


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


def _scope_explanation(
    scope,
    affected_api_count,
    primary_reason_api_count,
    blocking,
):
    if affected_api_count:
        count_text = f"本轮 {affected_api_count} 个 API 位于该诊断的传播范围内；"
    else:
        count_text = "该 failure ledger 记录未关联到本轮任何目标 API；"
    if primary_reason_api_count:
        count_text += f"其中 {primary_reason_api_count} 个 API 以该原因为主原因；"
    if scope == "global":
        return f"{count_text}该失败被分析器记录为全局阻断。"
    if scope == "path":
        return f"{count_text}失败只应作用于经过相关类或采集器的调用路径。"
    if scope == "mixed":
        return f"{count_text}本轮同时观察到多种传播作用域，需按证据逐项核对。"
    if scope == "unknown":
        return f"{count_text}旧摘要未保留 typed failure 的实际传播作用域。"
    if blocking:
        return f"{count_text}失败按目标 API 隔离，并限制这些 API 的结论。"
    return f"{count_text}失败按目标 API 隔离，不限制本轮其他 API 的结论。"


def build_diagnostic_guidance(
    results,
    graph_stats=None,
    *,
    origin_step="step5",
):
    """Aggregate result reasons and typed failure evidence into user guidance."""
    all_results = list(results or ())
    indexed_results = [
        (_canonical_result_identity(item) or f"__result_{index}", item)
        for index, item in enumerate(all_results)
    ]
    result_keys_by_object_id = {
        id(item): identity for identity, item in indexed_results
    }
    result_items_by_key = {}
    result_keys_by_failure_identity = defaultdict(set)
    result_keys_by_api_name = defaultdict(set)
    for identity, item in indexed_results:
        result_items_by_key.setdefault(identity, item)
        exact_identities, api_names = _result_failure_lookup_keys(item)
        for exact_identity in exact_identities:
            result_keys_by_failure_identity[exact_identity].add(identity)
        for api_name in api_names:
            result_keys_by_api_name[api_name].add(identity)
    all_result_keys = set(result_items_by_key)
    failure_match_cache = {}

    def matching_result_keys(failure):
        scope = str(failure.get("scope") or "global").strip()
        if scope == "global":
            return all_result_keys
        compact_failure = _compact_identity(failure.get("api_identity"))
        if not compact_failure:
            return set()
        cache_key = (scope, compact_failure)
        if cache_key in failure_match_cache:
            return failure_match_cache[cache_key]
        candidates = set(
            result_keys_by_failure_identity.get(compact_failure, ())
        )
        if "(" in compact_failure and "|" not in compact_failure:
            api_name = compact_failure.split("(", 1)[0]
            candidates.update(result_keys_by_api_name.get(api_name, ()))
        matched = {
            identity
            for identity in candidates
            if _failure_matches_result(failure, result_items_by_key[identity])
        }
        failure_match_cache[cache_key] = matched
        return matched
    grouped_results = defaultdict(list)
    status_counts = defaultdict(lambda: defaultdict(int))
    for item in all_results:
        status = str(_get(item, "analysis_status", "") or "").strip()
        reason_code = canonical_reason_code(
            _get(item, "reason_code", "") or "UNKNOWN"
        )
        if status not in {"uncertain", "not_analyzed"}:
            continue
        grouped_results[reason_code].append(item)
        status_counts[reason_code][status] += 1

    grouped_failures = defaultdict(list)
    for failure in _failure_rows(graph_stats or {}):
        reason_code = canonical_reason_code(
            failure.get("reason_code") or "UNKNOWN"
        )
        if failure.get("blocking") or reason_code in grouped_results:
            grouped_failures[reason_code].append(failure)

    guidance = []
    reason_codes = set(grouped_results) | set(grouped_failures)
    for reason_code in reason_codes:
        result_items = grouped_results.get(reason_code, ())
        failures = grouped_failures.get(reason_code, ())
        explicit_origins = {
            normalized
            for normalized in [
                *[
                    _normalized_origin_step(_get(item, "origin_step", ""))
                    for item in result_items
                ],
                *[
                    _normalized_origin_step(failure.get("origin_step"))
                    for failure in failures
                ],
            ]
            if normalized
        }
        observed_origin = (
            next(iter(explicit_origins))
            if len(explicit_origins) == 1
            else _normalized_origin_step(origin_step, "step5")
        )
        definition = guidance_for_reason_code(
            reason_code,
            origin_step=observed_origin or "step5",
        )
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
        primary_reason_keys = {
            result_keys_by_object_id.get(id(item), _canonical_result_identity(item))
            for item in result_items
        }
        primary_reason_keys.discard("")
        potentially_affected_keys = set(primary_reason_keys)
        relevant_blocking_failure_count = 0
        for failure in failures:
            matched_keys = matching_result_keys(failure)
            potentially_affected_keys.update(matched_keys)
            if not failure.get("blocking"):
                continue
            scope_value = str(failure.get("scope") or "global").strip()
            if scope_value != "api" or matched_keys or primary_reason_keys:
                relevant_blocking_failure_count += 1
        potentially_affected_items = [
            item
            for identity, item in indexed_results
            if identity in potentially_affected_keys
        ]
        affected_api_count = len(potentially_affected_keys)
        primary_reason_api_count = len(primary_reason_keys)
        blocking = bool(relevant_blocking_failure_count)
        failure_occurrence_count = sum(
            len(failure.get("occurrences") or ())
            for failure in failures
        )
        scope = _observed_scope(scopes)
        guidance.append({
            **definition,
            "blocking": blocking,
            "blocking_semantics": "effective_for_current_result_set",
            "raw_blocking_failure_count": sum(
                bool(failure.get("blocking")) for failure in failures
            ),
            "relevant_blocking_failure_count": relevant_blocking_failure_count,
            "observed_scope": scope,
            "scope_explanation": _scope_explanation(
                scope,
                affected_api_count,
                primary_reason_api_count,
                blocking,
            ),
            "affected_api_count": affected_api_count,
            "affected_api_count_semantics": "primary_reason_or_failure_scope",
            "primary_reason_api_count": primary_reason_api_count,
            "potentially_affected_api_count": affected_api_count,
            "affected_status_counts": dict(sorted(status_counts[reason_code].items())),
            "observed_failure_count": len(failures),
            "observed_failure_count_semantics": "failure_records",
            "failure_record_count": len(failures),
            "failure_occurrence_count": failure_occurrence_count,
            "failure_occurrence_count_semantics": "physical_occurrence_rows",
            "collectors": collectors,
            "affected_classes": classes,
            "affected_artifacts": artifacts,
            "affected_artifact_entries": artifact_entries,
            "candidate_evidence": candidate_evidence,
            "sample_apis": _unique(
                (_api_identity(item) for item in potentially_affected_items),
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


def build_catalog_guidance(
    reason_codes,
    *,
    origin_step="",
    observed_scope="step",
    source_components=None,
):
    """Build self-service guidance for step/coverage codes without API results."""
    guidance = []
    for reason_code in sorted({
        canonical_reason_code(value)
        for value in (reason_codes or ())
        if str(value or "").strip()
    }):
        definition = guidance_for_reason_code(reason_code)
        if definition.get("catalog_match") != "exact":
            continue
        if (
            origin_step
            and str(definition.get("origin_step") or "") != str(origin_step)
        ):
            continue
        guidance.append({
            **definition,
            "blocking": bool(definition.get("default_blocking")),
            "observed_scope": observed_scope,
            "scope_explanation": (
                "该诊断限制对应步骤或覆盖组件，不代表所有 API 都受到影响。"
            ),
            "affected_api_count": 0,
            "affected_api_count_semantics": "not_available_at_step_scope",
            "primary_reason_api_count": 0,
            "potentially_affected_api_count": 0,
            "affected_status_counts": {},
            "observed_failure_count": 1,
            "observed_failure_count_semantics": "failure_records",
            "failure_record_count": 1,
            "failure_occurrence_count": 0,
            "failure_occurrence_count_semantics": "not_available_at_step_scope",
            "collectors": [],
            "affected_classes": [],
            "affected_artifacts": [],
            "affected_artifact_entries": [],
            "candidate_evidence": [],
            "sample_apis": [],
            "failure_detail_summaries": [],
            "source_components": list(source_components or ()),
        })
    return guidance


def build_diagnostic_guidance_from_summary(summary):
    """Build guidance for old or synthetic summaries that lack the new field."""
    payload = dict(summary or {})
    results = [
        *list(payload.get("uncertain_apis") or ()),
        *list(payload.get("not_analyzed_apis") or ()),
    ]
    graph_stats = dict((payload.get("meta") or {}).get("graph_stats") or {})
    return build_diagnostic_guidance(
        results,
        graph_stats,
        origin_step=_normalized_origin_step(
            payload.get("origin_step"),
            "step5",
        ),
    )
