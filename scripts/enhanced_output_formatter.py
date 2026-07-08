#!/usr/bin/env python3
"""
enhanced_output_formatter.py

增强型输出格式化器

核心改进：
  ✓ 可读调用链格式（不再是边列表）
  ✓ 明确三态分类说明
  ✓ 人工审查指引（具体action）
  ✓ 业务上下文展示（入口方法、调用意图）
  ✓ 置信度/深度信息展示

解决用户痛点：
  - 看不出完整链路 → 改为树状展示
  - reason_code难理解 → 改为明确action
  - 缺业务上下文 → 新增入口方法标记
"""

import hashlib
import json
import os
import re
import sys
import csv
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    from s4_contract import PER_DEPENDENCY_SUMMARY_FILE, get_per_dependency_dir
except ImportError:
    current_dir = os.path.dirname(__file__)
    if current_dir and current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    from s4_contract import PER_DEPENDENCY_SUMMARY_FILE, get_per_dependency_dir


# ══════════════════════════════════════════════════════════════════
# 可读调用链格式化
# ══════════════════════════════════════════════════════════════════

ALERTS_CSV_FIELDNAMES = [
    'api_id', 'path_id', 'target_coord', 'changed_symbol', 'api_signature',
    'symbol_kind', 'change_type', 'severity', 'api_status', 'path_status',
    'conclusion_level', 'action_type', 'business_reachable', 'business_entry',
    'consumer_coord', 'consumer_class', 'consumer_method', 'consumer_signature',
    'path_text', 'stop_reason', 'reason', 'action', 'confidence', 'depth',
    'path_occurrence_count', 'coverage_status', 'coverage_details',
    'evidence_types', 'evidence_files', 'detail_file',
]

ALERTS_SPLIT_MAX_ROWS = 50000

ALERTS_REVIEW_BUCKETS = [
    ('reachable', {'reachable'}),
    ('uncertain', {'uncertain'}),
    ('not_found_in_static_analysis', {'not_found_in_static_analysis', 'not_reachable'}),
    ('not_analyzed', {'not_analyzed'}),
]


def trace_result_to_api_entry(r):
    """
    将 TraceResult 转换为 s6_report.py 需要的契约格式

    关键修复：确保字段名与 s6_report.py 兼容。
    s6_report.py:L162-174 和 L185-223 读取：
      api (不是 api_name)
      reason (不是 reachable_note)
      verification (不是 verification_commands)
      caller_symbol / callee_key (不是 caller / callee)
    """
    def _edges_for_s6(evidence_paths):
        """Pass through evidence edges (no conversion needed)

        confidence_weighted_tracer.py already writes caller_symbol/callee_key,
        which matches s6_report.py:L603-628 expectations.
        """
        # No conversion needed - tracer already writes correct field names
        return evidence_paths or []


    user_view = summarize_user_facing_outcome(r)

    return {
        'coord':               r.coord,
        'api':                 r.api_name,
        'api_name':            r.api_name,
        'api_simple':          r.api_simple,
        'api_signature':       getattr(r, 'api_signature', '') or '',
        'symbol_kind':         getattr(r, 'symbol_kind', '') or '',
        'severity':            r.severity,
        'change_type':         r.change_type,
        'confirmed':           str(r.confirmed).lower() if r.confirmed is not None else '',
        'source':              r.source,
        'analysis_status':     r.analysis_status,
        'reason_code':         r.reason_code,
        'reason':              r.reachable_note,
        'reachable_note':      r.reachable_note,
        'direct_callers':      r.direct_callers,
        'business_reach_depth': r.business_reach_depth,
        'dependency_chain_coords':  r.dependency_chain_coords or [],
        'call_paths':          r.call_paths or [],
        'evidence_paths':      _edges_for_s6(r.evidence_paths),
        'path_details':        getattr(r, 'path_details', []) or [],
        'verification':        r.verification_commands or [],
        'verification_commands': r.verification_commands or [],
        'confidence_score':    round(r.confidence_score, 3),
        'match_provenance':    getattr(r, 'match_provenance', '') or '',
        'match_tier':          getattr(r, 'match_tier', -1),
        'critical_nodes_hit':  r.critical_nodes_hit or [],
        'user_conclusion':     user_view['user_conclusion'],
        'decision_bucket':     user_view['decision_bucket'],
        'user_reason':         user_view['user_reason'],
        'recommended_action':  user_view['recommended_action'],
        'key_evidence':        user_view['key_evidence'],
    }


def _load_json_if_exists(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _per_dependency_status_rank(status):
    return {
        'reachable': 0,
        'uncertain': 1,
        'not_analyzed': 2,
        'not_found_in_static_analysis': 3,
        'not_reachable': 3,
    }.get(str(status or '').strip(), 9)


def _pick_per_dependency_representative(entries):
    def entry_rank(item):
        severity_rank = {'P0': 0, 'P1': 1, 'P2': 2}.get(str(item.get('severity') or '').strip(), 9)
        return (
            _per_dependency_status_rank(item.get('analysis_status')),
            severity_rank,
            -int(item.get('business_reach_depth') or 0),
            item.get('api') or item.get('api_name') or '',
        )

    return sorted(entries or [], key=entry_rank)[0] if entries else {}


def _infer_blocked_at(entry):
    entry = entry or {}
    if str(entry.get('analysis_status') or '').strip() == 'reachable':
        return 'system_source'
    if str(entry.get('reason_code') or '').strip() in {
        'DEPENDENCY_SOURCE_MAPPING_MISSING',
        'PACKAGED_DEPENDENCY_BYTECODE_USAGE',
        'RUNTIME_DEPENDENCY_USES_REMOVED_API',
        'ARTIFACT_BYTECODE_COVERAGE_INCOMPLETE',
    }:
        return 'dependency_without_source'
    if entry.get('dependency_chain_coords'):
        return 'dependency_with_source'
    return 'system_source'


def _infer_evidence_level(entry):
    entry = entry or {}
    status = str(entry.get('analysis_status') or '').strip()
    provenance = str(entry.get('match_provenance') or '').strip()
    tier = int(entry.get('match_tier', -1) or -1)
    if status == 'reachable':
        if provenance.startswith('exact') or tier in (0, 1):
            return 'strong'
        return 'medium'
    if status == 'uncertain':
        return 'medium' if entry.get('dependency_chain_coords') else 'weak'
    return 'weak'


def write_per_dependency_summaries(all_results, report_dir):
    grouped = defaultdict(list)
    for result in all_results or []:
        coord = str(getattr(result, 'coord', '') or '').strip()
        if coord:
            grouped[coord].append(trace_result_to_api_entry(result))

    for coord, entries in grouped.items():
        per_dependency_dir = get_per_dependency_dir(report_dir, coord)
        os.makedirs(per_dependency_dir, exist_ok=True)
        summary_path = per_dependency_dir / PER_DEPENDENCY_SUMMARY_FILE
        existing_summary = _load_json_if_exists(summary_path)

        reachable_entries = [item for item in entries if item.get('analysis_status') == 'reachable']
        uncertain_entries = [item for item in entries if item.get('analysis_status') == 'uncertain']
        not_analyzed_entries = [item for item in entries if item.get('analysis_status') == 'not_analyzed']
        not_found_entries = [
            item for item in entries
            if item.get('analysis_status') in ('not_found_in_static_analysis', 'not_reachable')
        ]
        representative = _pick_per_dependency_representative(entries)
        reaches_system_source = bool(reachable_entries)

        step5_summary = {
            'status': 'done',
            'total_targets': len(entries),
            'reachable': len(reachable_entries),
            'uncertain': len(uncertain_entries),
            'not_analyzed': len(not_analyzed_entries),
            'not_found_in_static_analysis': len(not_found_entries),
            'reaches_system_source': reaches_system_source,
            'final_status': str(representative.get('analysis_status') or '').strip(),
            'blocked_at': '' if reaches_system_source else _infer_blocked_at(representative),
            'blocked_reason': '' if reaches_system_source else str(representative.get('reason_code') or '').strip(),
            'evidence_level': _infer_evidence_level(representative),
            'selected_status': str(representative.get('analysis_status') or '').strip(),
            'selected_api': str(representative.get('api') or representative.get('api_name') or '').strip(),
            'selected_reason': str(representative.get('reason') or representative.get('reachable_note') or '').strip(),
            'sample_results': entries[:20],
        }

        summary = dict(existing_summary) if isinstance(existing_summary, dict) else {}
        artifacts = dict(summary.get('artifacts') or {})
        artifacts['summary_json'] = str(summary_path)
        summary['coord'] = coord
        summary['artifacts'] = artifacts
        summary['step5'] = step5_summary

        with open(summary_path, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)


def api_changes_dir_for_step5_output(output_dir):
    output_path = Path(output_dir).resolve()
    if output_path.name == 'call_chain' and output_path.parent.name == 'evidence':
        return output_path.parent / 'api_changes'
    return output_path.parent


def format_single_path_tree(path_str, trace_result, max_depth):
    """
    格式化单条路径为树状结构

    示例：
      [1] Controller.handleRequest() → Controller.java:30
        [2] Service.process() → Service.java:20
          [3] Foo.changedMethod() → Foo.java:15 [CHANGED]
    """
    lines = []

    # 解析路径（假设格式：A → B → C）
    if ' → ' in path_str:
        steps = path_str.split(' → ')
    else:
        steps = [path_str]

    # 检查是否有证据路径
    has_evidence = bool(trace_result.evidence_paths)

    for idx, step in enumerate(steps[:max_depth], 1):
        indent = '  ' * (idx - 1)

        step_display = step
        if idx == len(steps):
            step_display = f"{step} [CHANGE POINT]"

        file_info = ""
        if has_evidence and idx <= len(trace_result.evidence_paths[0]):
            evidence = trace_result.evidence_paths[0][idx - 1]
            file_key = evidence.get('file') or evidence.get('caller_symbol', '')
            file_info = f" -> {extract_file_name(file_key)}:{evidence.get('line', '')}"

        lines.append(f"{indent}[{idx}] {step_display}{file_info}")

    return lines


def extract_file_name(file_path):
    """提取文件名（简化路径）"""
    return os.path.basename(file_path)


def infer_module_name_from_file_path(file_path):
    normalized = str(file_path or "").strip()
    if not normalized:
        return ""
    parts = [part for part in re.split(r"[\\/]+", normalized) if part]
    source_markers = (
        ("src", "main", "java"),
        ("src", "main", "kotlin"),
    )
    for marker in source_markers:
        marker_len = len(marker)
        for idx in range(len(parts) - marker_len + 1):
            if tuple(parts[idx:idx + marker_len]) == marker and idx >= 1:
                return parts[idx - 1]
    return ""


def format_evidence_line(evidence):
    """格式化单条证据"""
    confidence_map = {
        'high': '✓',
        'medium': '❓',
        'low': '⚠️'
    }
    conf_icon = confidence_map.get(evidence['confidence'], '')

    file_name = extract_file_name(evidence['file'])
    return f"{conf_icon} {file_name}:{evidence['line']} | {evidence['evidence_type']} | conf={evidence['confidence']}"


def format_critical_node(node):
    """格式化关键节点"""
    if node['type'] == 'system_code_touched':
        return f"✓ System Code Reached: {node['method']} ({extract_file_name(node['file'])}:{node['line']})"
    elif node['type'] == 'framework_boundary':
        return f"⊘ Framework Boundary: {node['method']} ({node['reason']})"
    else:
        return f"? {node['type']}: {node.get('method', 'unknown')}"


# ��═════════════════════════════════════════════════════════════════
# Reason Code说明（改进：明确action）
# ══════════════════════════════════════════════════════════════════

REASON_CODE_EXPLANATIONS = {
    'SYSTEM_CODE_REACHED': {
        'reason': '已证明变更 API 触达系统代码（业务层）',
        'action': None  # 无需action，已确认
    },
    # 向后兼容旧 reason_code（已废弃）
    'BUSINESS_ENTRY_FOUND': {
        'reason': '已证明变更 API 触达系统代码（业务层）',
        'action': None
    },
    'DEPTH_LIMIT_REACHED': {
        'reason': '达到最大追踪深度限制',
        'action': '检查深度限制配置，或手动审查最后一跳的调用上下文'
    },
    'LOW_CONFIDENCE_EDGE': {
        'reason': '候选链路在低置信度边处停止，当前证据不足以继续安全追踪',
        'action': '优先审查最后一跳低置信度边的类型推断、接收者解析和调用点上下文'
    },
    'BUSINESS_ENTRY_NOT_CONFIRMED': {
        'reason': '已确认运行时依赖使用了变更 API，但尚未证明该依赖链路触达系统业务入口',
        'action': '按 consumer_coord、consumer_class 和 consumer_method 定位直接消费者，再核对业务代码或框架入口是否调用它'
    },
    'REFLECTION_OVERLOAD_UNRESOLVED': {
        'reason': '已关联到变更类型和反射成员，但参数类型不足以唯一确定重载目标',
        'action': '核对 getMethod/getDeclaredMethod 的参数类型来源，确认实际目标重载'
    },
    'REFLECTION_TARGET_DYNAMIC': {
        'reason': '已发现与变更范围相关的反射调用，但类名或成员名由运行时动态决定',
        'action': '检查配置、字符串拼接和运行时入参，并通过相关业务测试确认真实反射目标'
    },
    'RESOURCE_TARGET_REFERENCE': {
        'reason': '资源或配置文件同时引用了变更类型及成员，当前尚不能证明它会形成可执行调用',
        'action': '核对读取该资源的框架或业务代码，确认该配置是否会解析并调用目标 API'
    },
    'CONFIDENCE_DECAYED': {
        'reason': '链路置信度衰减至阈值以下',
        'action': '审查链路中的低置信度边，确认类型推断是否正确'
    },
    'BEHAVIOR_CHANGED_RUNTIME_VERIFICATION': {
        'reason': '签名未变但方法体变化，需运行时测试验证',
        'action': '执行相关单元测试或集成测试，确认运行时行为是否受影响'
    },
    'BEHAVIOR_CHANGED_PRECISE_TARGET_NOT_CONFIRMED': {
        'reason': '已找到调用链，但命中依赖 fallback_simple 回退，暂不足以安全确认目标 API',
        'action': '补全中间调用点的类型/签名推断，或人工复核是否串到了同名 sibling 方法'
    },
    'FALLBACK_SIMPLE_PATH_UNCONFIRMED': {
        'reason': '已找到候选调用链，但其中依赖 fallback_simple 回退，暂不足以安全确认命中的就是目标 API',
        'action': '补全中间调用点的类型/签名推断，并核对是否真的命中了目标 API；若目标属于 SPI/回调接口，还需确认业务代码是否实现、注册或显式引用了该类型'
    },
    'INTERNAL_ONLY_DIRECT_CONSUMER': {
        'reason': '已找到候选调用链，但变更 API 的直接调用者仍位于同一依赖内部，暂不足以证明外部消费者真实依赖了该 API',
        'action': '优先确认业务代码或其他依赖是否直接调用了该变更 API；若当前只命中目标依赖内部自调用链路，不应直接判定为已确认影响'
    },
    'DIRECT_CLASS_USAGE': {
        'reason': '已在系统源码中直接命中目标类型引用',
        'action': '优先打开命中的业务方法，确认该类型对应的具体受影响成员或行为'
    },
    'DIRECT_FIELD_USAGE': {
        'reason': '已在系统源码中直接命中目标字段访问',
        'action': '优先核对字段访问点的业务语义，并评估字段删除或行为变化的影响'
    },
    'DIRECT_STATIC_IMPORT_USAGE': {
        'reason': '已在系统源码中通过 static import 直接命中目标字段',
        'action': '优先核对 static import 对应字段的用途，并评估删除或变更后的影响'
    },
    'FRAMEWORK_BOUNDARY': {
        'reason': '遇到框架边界（动态代理/接口注入）',
        'action': '审查框架配置（Spring/MyBatis），确认实际注入的实现类'
    },
    'NO_CALLERS': {
        'reason': '未找到方法的调用者',
        'action': '检查方法是否被反射调用或框架回调'
    },
    'NO_PATH_FOUND': {
        'reason': '在当前源码图中未找到调用路径',
        'action': '检查源码路径配置，或确认API是否被使用'
    },
    'NO_STATIC_PATH': {
        'reason': '在当前源码图中未找到调用路径',
        'action': '检查源码路径配置，或确认API是否被使用'
    },
    'CALL_GRAPH_LIMITATION_SYMBOL_KIND': {
        'reason': '当前 Step5 主要基于方法反向调用图，对该符号类型的静态证明能力有限',
        'action': '结合类型引用、字段访问、构造调用、配置与反射证据继续复核，不要把它当成静态未命中'
    },
    'DEPENDENCY_SOURCE_MAPPING_MISSING': {
        'reason': '缺少可用的依赖源码映射',
        'action': '补充 dependency_source_dirs 中的依赖源码路径后重跑 Step5'
    },
    'PACKAGED_DEPENDENCY_BYTECODE_USAGE': {
        'reason': '已在最终制品的运行时依赖字节码中稳定命中目标符号引用，但尚未证明是否回到系统源码',
        'action': '优先审查命中的无源码依赖及其入口；若需继续回溯到系统源码，请补充 dependency_source_dirs'
    },
    'BUSINESS_ARTIFACT_BYTECODE_USAGE': {
        'reason': '已在当前最终制品的业务 class 中确认目标符号引用',
        'action': '依据命中的业务 class 和方法定位受影响入口，并执行对应回归测试'
    },
    'ARTIFACT_BYTECODE_COVERAGE_INCOMPLETE': {
        'reason': '最终制品业务 class 或运行时依赖 JAR 未被完整扫描',
        'action': '修复制品留存、嵌套 JAR 提取或 javap 环境后重跑；当前未命中不能解释为无影响'
    },
    'SOURCE_BYTECODE_EDGE_CONFLICT': {
        'reason': '源码调用图与当前最终制品字节码扫描结果冲突',
        'action': '核对制品 SHA、源码 revision、构建 profile、生成源码和目标模块后重新构建分析'
    },
    'SOURCE_ARTIFACT_ALIGNMENT_UNVERIFIED': {
        'reason': '源码与当前最终制品尚未证明来自同一 revision、模块和构建配置',
        'action': '使用由 Step1 留存制品对应的源码 revision/profile 重跑；当前字节码未命中不能证明无影响'
    },
    'INLINED_CONSTANT_USAGE_UNDETECTABLE': {
        'reason': '编译期常量可能已内联到调用方，class 中不会保留字段访问指令',
        'action': '结合源码引用、旧新常量值和业务回归测试确认，不能以字节码字段未命中判定未使用'
    },
    'RUNTIME_DEPENDENCY_USES_REMOVED_API': {
        'reason': '当前最终制品中的其他运行时依赖字节码仍引用被删除依赖的目标符号',
        'action': '优先检查命中的消费依赖及其业务入口，并执行覆盖该路径的启动/集成测试；存在 NoClassDefFoundError/NoSuchMethodError 风险'
    },
    'MISSING_API_SIGNATURE': {
        'reason': '方法级变更缺少参数签名，无法精确区分重载方法',
        'action': '回到 Step 4 重新生成包含 api_signature 的变更 API 清单'
    },
    'MISSING_SYMBOL_KIND': {
        'reason': '变更清单缺少 symbol_kind，无法判断当前符号是方法、字段、类还是构造器',
        'action': '回到 Step 4 重新生成包含 symbol_kind 的变更 API 清单'
    },
    'CLASS_USAGE_ONLY': {
        'reason': '类级候选，只能证明类型使用',
        'action': '审查类的具体方法调用，确认实际受影响的API'
    },
    'METHOD_OVERLOAD_AMBIGUOUS': {
        'reason': '方法重载歧义，无法确定具体调用',
        'action': '审查调用位置的参数类型，确认实际调用的重载方法'
    },
    'OVERLOAD_AMBIGUOUS_TARGET': {
        'reason': '目标 API 存在重载，当前只命中了无签名回退键，无法安全确认具体目标签名',
        'action': '优先核对 api_signature 与目标调用点的参数类型；若仍无法唯一确认，请人工复核真实重载'
    },
    'OVERLOAD_AMBIGUOUS_INTERMEDIATE': {
        'reason': '中间方法存在重载，当前路径只命中了无签名回退键，无法安全继续反向追踪',
        'action': '审查中间调用点的参数类型，确认是否命中了正确重载后再继续分析'
    },
    'INTERFACE_IMPLEMENTATION': {
        'reason': '接口多态调用，无法确定实现类',
        'action': '审查接口的所有实现类，确认实际运行时的实现'
    },
    'LAMBDA_CALL': {
        'reason': 'Lambda表达式调用，执行路径不确定',
        'action': '审查Lambda的执行上下文（Stream API、事件回调等）'
    },
    'METHOD_REFERENCE': {
        'reason': '方法引用，执行路径不确定',
        'action': '审查方法引用的实际执行场景（函数式接口实现）'
    },
    'REFLECTION_CALL': {
        'reason': '反射调用，无法静态分析',
        'action': '审查反射调用代码，确认实际调用的方法名'
    },
    'MYBATIS_DYNAMIC_PROXY': {
        'reason': 'MyBatis Mapper动态代理',
        'action': '审查Mapper.xml配置，确认SQL实现'
    },
    'SPRING_BEAN_INJECTION': {
        'reason': 'Spring Bean动态注入',
        'action': '审查Spring配置，确认实际注入的Bean类型'
    }
}

INPUT_REQUIRED_REASON_CODES = {
    'DEPENDENCY_SOURCE_MAPPING_MISSING',
    'MISSING_API_SIGNATURE',
    'MISSING_SYMBOL_KIND',
    'ANALYSIS_INCOMPLETE',
    'NO_TARGET_KEYS',
}


def _get_trace_attr(obj, name, default=None):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def build_key_evidence(call_paths=None, evidence_paths=None):
    call_paths = list(call_paths or [])
    if call_paths:
        return call_paths[0]
    evidence_paths = list(evidence_paths or [])
    if evidence_paths and evidence_paths[0]:
        edge = evidence_paths[0][0]
        caller = edge.get('caller_symbol', '?')
        callee = edge.get('callee_key', '?')
        return f"{caller} -> {callee}"
    return ""


def summarize_user_facing_outcome(trace_like):
    analysis_status = str(_get_trace_attr(trace_like, 'analysis_status', '') or '').strip()
    reason_code = str(_get_trace_attr(trace_like, 'reason_code', '') or '').strip()
    severity = str(_get_trace_attr(trace_like, 'severity', '') or '').strip()
    call_paths = _get_trace_attr(trace_like, 'call_paths', []) or []
    evidence_paths = _get_trace_attr(trace_like, 'evidence_paths', []) or []
    explanation = explain_reason_code(reason_code, trace_like)

    if analysis_status == 'reachable':
        conclusion = '已确认影响'
        decision_bucket = 'confirmed_impact'
        if reason_code in {'DIRECT_CLASS_USAGE', 'DIRECT_FIELD_USAGE', 'DIRECT_STATIC_IMPORT_USAGE'}:
            user_reason = explanation.get('reason') or '已在系统源码中直接命中目标引用。'
            recommended_action = explanation.get('action') or '优先打开命中的业务方法，确认影响范围。'
        else:
            user_reason = '已找到从系统代码到变更 API 的调用链。'
            recommended_action = '优先按调用链定位受影响业务，并安排修复或验证。'
    elif reason_code in INPUT_REQUIRED_REASON_CODES:
        conclusion = '需要补充输入'
        decision_bucket = 'input_required'
        user_reason = explanation.get('reason') or '当前缺少完成分析所需的关键输入。'
        recommended_action = explanation.get('action') or '先补齐关键输入后重跑当前步骤。'
    elif reason_code == 'BEHAVIOR_CHANGED_RUNTIME_VERIFICATION':
        conclusion = '可能影响'
        decision_bucket = 'probable_impact'
        user_reason = '已找到调用链，但这是行为变更，静态分析不能单独确认运行时结果。'
        recommended_action = explanation.get('action') or '执行相关业务测试，确认运行时行为是否受影响。'
    elif analysis_status in ('uncertain', 'not_found_in_static_analysis', 'not_reachable', 'not_analyzed'):
        conclusion = '当前无法确认'
        decision_bucket = 'inconclusive'
        user_reason = explanation.get('reason') or '当前证据不足，无法确认是否影响系统。'
        recommended_action = explanation.get('action') or '优先补充证据或人工抽查关键调用链。'
    else:
        conclusion = '当前无法确认'
        decision_bucket = 'inconclusive'
        user_reason = explanation.get('reason') or '当前证据不足，无法确认是否影响系统。'
        recommended_action = explanation.get('action') or '补充证据后重新分析。'

    if conclusion == '当前无法确认' and severity in ('P0', 'P1'):
        recommended_action = '优先人工复核这条高风险项；必要时补输入后重跑分析。'

    return {
        'user_conclusion': conclusion,
        'decision_bucket': decision_bucket,
        'user_reason': user_reason,
        'recommended_action': recommended_action,
        'key_evidence': build_key_evidence(call_paths=call_paths, evidence_paths=evidence_paths),
    }


def explain_reason_code(reason_code, trace_result):
    """
    解释reason_code并提供明确action

    Args:
        reason_code: 原因代码
        trace_result: TraceResult对象（补充上下文）

    Returns:
        {'reason': str, 'action': str}
    """
    explanation = dict(REASON_CODE_EXPLANATIONS.get(reason_code, {
        'reason': reason_code,
        'action': '未知原因，需人工审查'
    }))

    # 补充上下文信息
    if reason_code == 'DEPENDENCY_SOURCE_MAPPING_MISSING':
        dependency_coords = _get_trace_attr(trace_result, 'dependency_chain_coords', []) or []
        if dependency_coords:
            coords_str = ', '.join(dependency_coords[:3])
            explanation['action'] = f"补充 dependency_source_dirs 中这些依赖源码后重跑 Step5：{coords_str}"

    return explanation


def format_call_chain_readable(trace_result):
    """
    将 TraceResult 格式化为人类可读的调用链报告

    用于生成 by_api/*.txt 文件，让开发者能快速理解：
      1. API是��么
      2. 为什么被标记为这个状态
      3. 需要做什么
      4. 完整的证据链路

    Args:
        trace_result: TraceResult 对象

    Returns:
        str: 格式化的报告文本
    """
    lines = []

    # 标题
    lines.append("=" * 70)
    lines.append(f"API: {trace_result.api_name}")
    lines.append(f"依赖: {trace_result.coord}")
    lines.append("=" * 70)
    lines.append("")

    # 基本信息
    lines.append("【基本信息】")
    lines.append(f"  变更类型: {trace_result.change_type}")
    lines.append(f"  严重程度: {trace_result.severity}")
    lines.append(f"  分析状态: {trace_result.analysis_status}")
    lines.append(f"  原因代码: {trace_result.reason_code}")
    lines.append("")

    # 状态说明
    explanation = explain_reason_code(trace_result.reason_code, trace_result)
    user_view = summarize_user_facing_outcome(trace_result)
    lines.append("【结论】")
    lines.append(f"  结论: {user_view['user_conclusion']}")
    lines.append(f"  原因: {user_view['user_reason']}")
    lines.append(f"  推荐动作: {user_view['recommended_action']}")
    if user_view.get('key_evidence'):
        lines.append(f"  关键证据: {user_view['key_evidence']}")
    lines.append("")

    lines.append("【状态说明】")
    lines.append(f"  原因: {explanation['reason']}")
    if explanation.get('action'):
        lines.append(f"  建议动作: {explanation['action']}")
    lines.append("")

    # 追踪质量指标
    lines.append("【追踪质量】")
    lines.append(f"  置信度: {trace_result.confidence_score:.2f}")
    lines.append(f"  业务触达深度: {trace_result.business_reach_depth} 跳")
    if trace_result.dependency_chain_coords:
        lines.append(f"  跨依赖边界: {' -> '.join(trace_result.dependency_chain_coords)}")
    lines.append("")

    # 调用链路
    if trace_result.call_paths:
        lines.append("【调用链路】")
        for idx, path in enumerate(trace_result.call_paths, 1):
            lines.append(f"  路径 {idx}: {path}")
        lines.append("")

    # 证据详情（原始边）
    if trace_result.evidence_paths:
        lines.append("【证据详情】")
        for path_idx, path in enumerate(trace_result.evidence_paths, 1):
            if path_idx > 1:
                break  # 只显示第一条路径
            lines.append(f"  路径 {path_idx}:")
            for edge_idx, edge in enumerate(path[:10], 1):  # 最多显示10条边
                caller = edge.get('caller_symbol', edge.get('caller', '?'))
                callee = edge.get('callee_key', edge.get('callee', '?'))
                conf = edge.get('confidence', '?')
                evidence_type = edge.get('evidence_type', '?')
                file_name = extract_file_name(edge.get('file', '?'))
                line = edge.get('line', '?')

                lines.append(f"    [{edge_idx}] {caller} -> {callee}")
                lines.append(f"        类型: {evidence_type}, 置信度: {conf}")
                lines.append(f"        位置: {file_name}:{line}")
            if len(path) > 10:
                lines.append(f"    ... (还有 {len(path) - 10} 条边)")
        lines.append("")

    # 验证命令
    if trace_result.verification_commands:
        lines.append("【验证命令】")
        for cmd in trace_result.verification_commands:
            lines.append(f"  $ {cmd}")
        lines.append("")

    # 关键节点
    if trace_result.critical_nodes_hit:
        lines.append("【关键节点】")
        for node in trace_result.critical_nodes_hit:
            lines.append(f"  {format_critical_node(node)}")
        lines.append("")

    return '\n'.join(lines)


def build_by_api_safe_filename(result):
    coord_safe = result.coord.replace(':', '_').replace('.', '_')[:50]
    api_safe = result.api_name.replace('.', '_').replace(':', '_')[:80]
    signature_safe = re.sub(
        r'[^A-Za-z0-9._-]+',
        '_',
        (getattr(result, 'api_signature', '') or '').strip(),
    )[:60]
    symbol_kind_safe = re.sub(
        r'[^A-Za-z0-9._-]+',
        '_',
        (getattr(result, 'symbol_kind', '') or '').strip(),
    )[:20]
    unique_identity = "|".join(
        [
            result.coord or "",
            result.api_name or "",
            getattr(result, 'api_signature', '') or "",
            getattr(result, 'symbol_kind', '') or "",
        ]
    )
    unique_suffix = hashlib.sha1(unique_identity.encode('utf-8')).hexdigest()[:12]

    identity_parts = [coord_safe, api_safe]
    if signature_safe:
        identity_parts.append(signature_safe)
    if symbol_kind_safe:
        identity_parts.append(symbol_kind_safe)
    identity_parts.append(unique_suffix)
    return "_".join(identity_parts)


# ══════════════════════════════════════════════════════════════════
# 批量输出格式化
# ══════════════════════════════════════���═══════════════════════════


def aggregate_by_module(all_results, output_dir):
    """
    Aggregate impacts by module (restored from old engine)

    Generates: evidence/call_chain/by_module/*_impacts.json
    """
    from collections import defaultdict
    module_data = defaultdict(
        lambda: {
            "module": "",
            "impacts": [],
            "p0_count": 0,
            "p1_count": 0,
            "p2_count": 0,
            "uncertain_count": 0,
            "probable_impact_count": 0,
            "needs_input_count": 0,
            "not_analyzed_count": 0,
            "not_found_in_static_analysis_count": 0,
        }
    )

    for result in all_results:
        # Extract module from evidence_paths (simplified)
        modules_hit = set()
        for path in result.evidence_paths or []:
            for edge in path:
                file_path = edge.get('file', '')
                module_hint = infer_module_name_from_file_path(file_path)
                if module_hint:
                    modules_hit.add(module_hint)

        for module in modules_hit:
            bucket = module_data[module]
            bucket["module"] = module
            user_view = summarize_user_facing_outcome(result)
            bucket["impacts"].append({
                "api": result.api_name,
                "change_type": result.change_type,
                "severity": result.severity,
                "analysis_status": result.analysis_status,
                "is_reachable": result.is_reachable,
                "reason_code": result.reason_code,
                "user_conclusion": user_view["user_conclusion"],
                "decision_bucket": user_view["decision_bucket"],
                "call_paths": result.call_paths[:3] if result.call_paths else [],
            })
            if result.analysis_status in ("not_reachable", "not_found_in_static_analysis"):
                bucket["not_found_in_static_analysis_count"] += 1
            elif result.analysis_status == "uncertain":
                bucket["uncertain_count"] += 1
            elif result.analysis_status == "not_analyzed":
                if user_view["user_conclusion"] == "可能影响":
                    bucket["probable_impact_count"] += 1
                elif user_view["user_conclusion"] == "需要补充输入":
                    bucket["needs_input_count"] += 1
                else:
                    bucket["not_analyzed_count"] += 1
            elif result.severity == "P0":
                bucket["p0_count"] += 1
            elif result.severity == "P1":
                bucket["p1_count"] += 1
            else:
                bucket["p2_count"] += 1

    module_dir = os.path.join(output_dir, "by_module")
    os.makedirs(module_dir, exist_ok=True)
    for module, data in sorted(module_data.items()):
        safe_name = module.replace('/', '_').replace('.', '_')
        path = os.path.join(module_dir, f"{safe_name}_impacts.json")
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    return dict(module_data)


def cleanup_generated_output_dir(dir_path, allowed_suffixes=None):
    """删除上一轮生成的同类产物，避免新旧结果混杂。"""
    if not os.path.isdir(dir_path):
        return
    suffixes = tuple(allowed_suffixes or [])
    for name in os.listdir(dir_path):
        path = os.path.join(dir_path, name)
        if not os.path.isfile(path):
            continue
        if suffixes and not name.endswith(suffixes):
            continue
        os.remove(path)


def generate_enhanced_summary(all_results, output_dir, graph_stats=None):
    """
    生成增强型摘要报告

    输出文件：
      - s5_enhanced_summary.txt：人类可读摘要
      - alerts.csv：完整逐链路人工台账
      - by_api/*.txt：每个API的详细分析报告
    """
    report_started_at = time.perf_counter()
    report_perf = None
    if graph_stats is not None:
        report_perf = graph_stats.setdefault('step5_perf', {}).setdefault('report', {})
    os.makedirs(output_dir, exist_ok=True)

    # 分类统计（支持新状态名）
    reachable = [r for r in all_results if r.analysis_status == 'reachable']
    uncertain = [r for r in all_results if r.analysis_status == 'uncertain']
    not_analyzed = [r for r in all_results if r.analysis_status == 'not_analyzed']
    # 兼容新旧状态名
    not_found = [r for r in all_results if r.analysis_status in ('not_reachable', 'not_found_in_static_analysis')]
    user_views = [summarize_user_facing_outcome(r) for r in all_results]
    user_conclusion_summary = defaultdict(int)
    decision_bucket_summary = defaultdict(int)
    for item in user_views:
        user_conclusion_summary[item['user_conclusion']] += 1
        decision_bucket_summary[item['decision_bucket']] += 1

    # 生成摘要文本
    summary_lines = [
        "=== Step 5 调用链分析摘要（增强版）===",
        f"generated_at: {datetime.now().isoformat()}",
        "",
        "面向用户的结论：",
        f"  - 已确认影响: {user_conclusion_summary.get('已确认影响', 0)}",
        f"  - 可能影响: {user_conclusion_summary.get('可能影响', 0)}",
        f"  - 当前无法确认: {user_conclusion_summary.get('当前无法确认', 0)}",
        f"  - 需要补充输入: {user_conclusion_summary.get('需要补充输入', 0)}",
        "",
        "内部状态统计：",
        f"  总API数：{len(all_results)}",
        f"  ✓ reachable: {len(reachable)}",
        f"  ❓ uncertain: {len(uncertain)}",
        f"  ⊘ not_analyzed: {len(not_analyzed)}",
        f"  ✗ not_found_in_static_analysis: {len(not_found)}",
        "",
    ]

    # Reachable Top 20
    if reachable:
        summary_lines.append("已确认影响（优先处理）：")
        reachable_sorted = sorted(
            reachable,
            key=lambda r: (
                severity_rank(r.severity),
                -r.business_reach_depth,
                -r.confidence_score
            )
        )

        for idx, r in enumerate(reachable_sorted[:20], 1):
            api_short = r.api_name.rsplit('.', 1)[-1] if '.' in r.api_name else r.api_name
            entry_method = ""
            if r.critical_nodes_hit:
                entry = r.critical_nodes_hit[0]
                entry_method = entry.get('method', '').rsplit('.', 1)[-1]

            summary_lines.append(
                f"  [{idx}] [{r.severity}] {api_short} → {entry_method} "
                f"(depth={r.business_reach_depth}, conf={r.confidence_score:.2f})"
            )

        summary_lines.append("")

    # Uncertain Top 20
    probable = [r for r in all_results if summarize_user_facing_outcome(r)['user_conclusion'] == '可能影响']
    inconclusive = [r for r in all_results if summarize_user_facing_outcome(r)['user_conclusion'] == '当前无法确认']
    input_required = [r for r in all_results if summarize_user_facing_outcome(r)['user_conclusion'] == '需要补充输入']

    if probable:
        summary_lines.append("可能影响（优先做验证）：")
        for idx, r in enumerate(sorted(probable, key=lambda r: severity_rank(r.severity))[:20], 1):
            api_short = r.api_name.rsplit('.', 1)[-1] if '.' in r.api_name else r.api_name
            view = summarize_user_facing_outcome(r)
            summary_lines.append(f"  [{idx}] [{r.severity}] {api_short} | {view['recommended_action'][:60]}")
        summary_lines.append("")

    if inconclusive:
        summary_lines.append("当前无法确认（需要人工复核或补证据）：")
        for idx, r in enumerate(sorted(inconclusive, key=lambda r: severity_rank(r.severity))[:20], 1):
            api_short = r.api_name.rsplit('.', 1)[-1] if '.' in r.api_name else r.api_name
            view = summarize_user_facing_outcome(r)
            summary_lines.append(f"  [{idx}] [{r.severity}] {api_short} | {view['user_reason'][:60]}")
        summary_lines.append("")

    if input_required:
        summary_lines.append("需要补充输入（建议先补输入再继续）：")
        for idx, r in enumerate(sorted(input_required, key=lambda r: severity_rank(r.severity))[:20], 1):
            api_short = r.api_name.rsplit('.', 1)[-1] if '.' in r.api_name else r.api_name
            view = summarize_user_facing_outcome(r)
            summary_lines.append(f"  [{idx}] [{r.severity}] {api_short} | {view['recommended_action'][:60]}")
        summary_lines.append("")

    # 保存摘要
    # 关键修复：同时生成 summary.txt（文档承诺的合约）和 s5_enhanced_summary.txt
    summary_path = os.path.join(output_dir, 'summary.txt')
    summary_text_timer = time.perf_counter()
    with open(summary_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(summary_lines))

    # 也生成增强版摘要（向后兼容）
    enhanced_summary_path = os.path.join(output_dir, 's5_enhanced_summary.txt')
    with open(enhanced_summary_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(summary_lines))
    if report_perf is not None:
        report_perf['summary_text_elapsed_sec'] = round(time.perf_counter() - summary_text_timer, 3)

    print(f"  摘要报告 → {summary_path}", file=sys.stderr)

    # 生成每个API的详细报告
    by_api_timer = time.perf_counter()
    api_dir = os.path.join(output_dir, 'by_api')
    os.makedirs(api_dir, exist_ok=True)
    cleanup_generated_output_dir(api_dir, allowed_suffixes=('.json', '.txt'))

    for result in all_results:
        api_report = format_call_chain_readable(result)

        # 保存为txt文件（人类可读）
        # 文件名包含完整 API 身份，避免重载方法/不同符号类型互相覆盖。
        safe_filename = build_by_api_safe_filename(result)
        report_path = os.path.join(api_dir, f"{safe_filename}.txt")

        with open(report_path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(api_report)

        # 关键修复：同时生成.json文件（s6_report.py依赖）
        json_path = os.path.join(api_dir, f"{safe_filename}.json")
        json_payload = trace_result_to_api_entry(result)
        with open(json_path, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(json_payload, f, ensure_ascii=False, indent=2)
    if report_perf is not None:
        report_perf['by_api_elapsed_sec'] = round(time.perf_counter() - by_api_timer, 3)
        report_perf['by_api_count'] = len(all_results)

    print(f"  API详细报告 → {api_dir}/", file=sys.stderr)

    # 生成alerts.csv（文档承诺的合约）
    alerts_timer = time.perf_counter()
    alerts_path = os.path.join(output_dir, 'alerts.csv')
    generate_alerts_csv(all_results, alerts_path)
    if report_perf is not None:
        report_perf['alerts_elapsed_sec'] = round(time.perf_counter() - alerts_timer, 3)
    alert_split_files = sorted(
        name for name in os.listdir(output_dir)
        if name.startswith('alerts_') and name.endswith('.csv')
    )

    # 旧版重复文件不再生成，避免人工在两个相同清单之间切换。
    enhanced_alerts_path = os.path.join(output_dir, 's5_enhanced_alerts.csv')
    if os.path.isfile(enhanced_alerts_path):
        os.remove(enhanced_alerts_path)

    print(f"  完整链路台账 → {alerts_path}", file=sys.stderr)
    if alert_split_files:
        print(
            "  人工阅读拆分 → "
            + ", ".join(os.path.join(output_dir, name) for name in alert_split_files),
            file=sys.stderr,
        )

    # 生成 summary.json（s6_report.py 需要的契约格式）
    summary_json_timer = time.perf_counter()
    summary_json_path = write_summary_json(all_results, output_dir, graph_stats=graph_stats)
    if report_perf is not None:
        report_perf['summary_json_elapsed_sec'] = round(time.perf_counter() - summary_json_timer, 3)

    # Key fix: generate by_module aggregation (document promise)
    by_module_timer = time.perf_counter()
    module_dir = os.path.join(output_dir, "by_module")
    os.makedirs(module_dir, exist_ok=True)
    cleanup_generated_output_dir(module_dir, allowed_suffixes=('.json',))
    aggregate_by_module(all_results, output_dir)
    if report_perf is not None:
        report_perf['by_module_elapsed_sec'] = round(time.perf_counter() - by_module_timer, 3)
        report_perf['elapsed_sec'] = round(time.perf_counter() - report_started_at, 3)
        try:
            with open(summary_json_path, 'r', encoding='utf-8') as f:
                summary_payload = json.load(f)
            summary_payload.setdefault('meta', {})['graph_stats'] = graph_stats or {}
            with open(summary_json_path, 'w', encoding='utf-8', newline='\n') as f:
                json.dump(summary_payload, f, ensure_ascii=False, indent=2)
        except (OSError, json.JSONDecodeError):
            pass

    return summary_path, summary_json_path


def write_summary_json(all_results, output_dir, graph_stats=None):
    """
    生成 evidence/call_chain/summary.json（s6_report.py 契约格式）

    契约字段（当前主语义）：
      status, skip_reason, reachable/not_found_in_static_analysis/uncertain/not_analyzed,
      reachable_apis[], uncertain_apis[], not_analyzed_apis[], not_found_apis[],
      uncertain_reason_summary{}, deprecated_aliases{}, meta{}
    """
    reachable       = [r for r in all_results if r.analysis_status == 'reachable']
    uncertain       = [r for r in all_results if r.analysis_status == 'uncertain']
    not_analyzed    = [r for r in all_results if r.analysis_status == 'not_analyzed']
    # 兼容新旧状态名
    not_found       = [r for r in all_results if r.analysis_status in ('not_reachable', 'not_found_in_static_analysis')]
    user_conclusion_summary = defaultdict(int)
    decision_bucket_summary = defaultdict(int)
    for r in all_results:
        user_view = summarize_user_facing_outcome(r)
        user_conclusion_summary[user_view['user_conclusion']] += 1
        decision_bucket_summary[user_view['decision_bucket']] += 1

    # uncertain 原因分类
    uncertain_reason_summary = defaultdict(int)
    for r in uncertain:
        uncertain_reason_summary[r.reason_code] += 1
    uncertain_reason_summary = dict(sorted(
        uncertain_reason_summary.items(),
        key=lambda x: -x[1]
    ))

    summary = {
        'meta': {
            'generated_at': datetime.now().isoformat(),
            'total_apis':   len(all_results),
            'reachable':    len(reachable),
            'uncertain':    len(uncertain),
            'not_analyzed': len(not_analyzed),
            'not_found_in_static_analysis': len(not_found),
            'tool':         's5_call_chain_engine_integrated.py (enhanced)',
            'graph_stats':  graph_stats or {},
        },
        'status':           'done',
        'skip_reason':      '',
        'total_apis':       len(all_results),
        'reachable':        len(reachable),
        'not_found_in_static_analysis': len(not_found),
        'uncertain':        len(uncertain),
        'not_analyzed':     len(not_analyzed),
        'reachable_apis':     [trace_result_to_api_entry(r) for r in reachable],
        'uncertain_apis':     [trace_result_to_api_entry(r) for r in uncertain],
        'not_analyzed_apis':  [trace_result_to_api_entry(r) for r in not_analyzed],
        'not_found_apis':     [trace_result_to_api_entry(r) for r in not_found],
        'uncertain_reason_summary': uncertain_reason_summary,
        'user_conclusion_summary': dict(sorted(user_conclusion_summary.items(), key=lambda x: x[0])),
        'quality_gate': {
            'confirmed_impact': decision_bucket_summary.get('confirmed_impact', 0),
            'probable_impact': decision_bucket_summary.get('probable_impact', 0),
            'inconclusive': decision_bucket_summary.get('inconclusive', 0),
            'needs_input': decision_bucket_summary.get('input_required', 0),
            'high_risk_inconclusive': sum(
                1
                for r in all_results
                if summarize_user_facing_outcome(r)['decision_bucket'] == 'inconclusive' and r.severity in ('P0', 'P1')
            ),
        },
        'deprecated_aliases': {
            'not_reachable': {
                'replacement': 'not_found_in_static_analysis',
                'scope': 'count',
            },
            'not_reachable_apis': {
                'replacement': 'not_found_apis',
                'scope': 'api_list',
            },
        },
    }

    summary_json_path = os.path.join(output_dir, 'summary.json')
    with open(summary_json_path, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    write_per_dependency_summaries(all_results, str(api_changes_dir_for_step5_output(output_dir)))

    print(f"  汇总 JSON → {summary_json_path}", file=sys.stderr)
    return summary_json_path


def generate_alerts_csv(all_results, output_path):
    """生成完整、无抽样的人工链路台账；每个 API 至少一行，每条链路独立一行。"""
    rows = []
    for result in all_results:
        rows.extend(_alert_rows_for_result(result))
    rows.sort(key=lambda row: (
        {'confirmed': 0, 'candidate': 1, 'incomplete': 2, 'no_static_path': 3}.get(
            row['conclusion_level'], 9
        ),
        severity_rank(row['severity']), row['target_coord'], row['changed_symbol'], row['path_id'],
    ))

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=ALERTS_CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    write_alerts_review_splits(rows, os.path.dirname(os.path.abspath(output_path)))


def write_alerts_review_splits(rows, output_dir, max_rows=None):
    """Write non-authoritative review-oriented alert CSV splits next to alerts.csv."""
    cleanup_alerts_review_splits(output_dir)
    if max_rows is None:
        max_rows = _alerts_split_max_rows()
    buckets = {name: [] for name, _statuses in ALERTS_REVIEW_BUCKETS}
    other_rows = []
    status_to_bucket = {
        status: name
        for name, statuses in ALERTS_REVIEW_BUCKETS
        for status in statuses
    }
    for row in rows or []:
        bucket = status_to_bucket.get(str(row.get('path_status') or ''))
        if bucket:
            buckets[bucket].append(row)
        else:
            other_rows.append(row)
    for name, bucket_rows in buckets.items():
        _write_alerts_review_bucket(output_dir, name, bucket_rows, max_rows)
    _write_alerts_review_bucket(output_dir, 'other', other_rows, max_rows)


def cleanup_alerts_review_splits(output_dir):
    if not output_dir or not os.path.isdir(output_dir):
        return
    prefixes = [name for name, _statuses in ALERTS_REVIEW_BUCKETS] + ['other']
    for filename in os.listdir(output_dir):
        if not filename.startswith('alerts_') or not filename.endswith('.csv'):
            continue
        if any(
            filename == f'alerts_{prefix}.csv'
            or re.match(rf'^alerts_{re.escape(prefix)}_\d{{3}}\.csv$', filename)
            for prefix in prefixes
        ):
            try:
                os.remove(os.path.join(output_dir, filename))
            except OSError:
                pass


def _alerts_split_max_rows():
    raw = str(os.environ.get('JUA_ALERTS_SPLIT_MAX_ROWS') or '').strip()
    if raw:
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return ALERTS_SPLIT_MAX_ROWS


def _write_alerts_review_bucket(output_dir, bucket_name, rows, max_rows):
    if not rows:
        return
    os.makedirs(output_dir, exist_ok=True)
    max_rows = max(1, int(max_rows or ALERTS_SPLIT_MAX_ROWS))
    if len(rows) <= max_rows:
        _write_alert_rows_csv(os.path.join(output_dir, f'alerts_{bucket_name}.csv'), rows)
        return
    for index, start in enumerate(range(0, len(rows), max_rows), 1):
        _write_alert_rows_csv(
            os.path.join(output_dir, f'alerts_{bucket_name}_{index:03d}.csv'),
            rows[start:start + max_rows],
        )


def _write_alert_rows_csv(path, rows):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=ALERTS_CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def _alert_rows_for_result(result):
    identity = '|'.join([
        result.coord or '', result.api_name or '',
        getattr(result, 'api_signature', '') or '', getattr(result, 'symbol_kind', '') or '',
    ])
    api_id = 'API-' + hashlib.sha1(identity.encode('utf-8')).hexdigest()[:12]
    details = list(getattr(result, 'path_details', []) or [])
    if not details:
        call_paths = list(getattr(result, 'call_paths', []) or [])
        evidence_paths = list(getattr(result, 'evidence_paths', []) or [])
        count = max(len(call_paths), len(evidence_paths), 1)
        for index in range(count):
            evidence = list(evidence_paths[index] or []) if index < len(evidence_paths) else []
            first = evidence[0] if evidence else {}
            consumer_class, consumer_method = _split_alert_consumer(first.get('caller_symbol', ''))
            details.append({
                'path_status': result.analysis_status,
                'stop_reason': result.reason_code,
                'business_entry': _result_business_entry(result),
                'business_reachable': True if result.analysis_status == 'reachable' else None,
                'consumer_coord': first.get('owner_coord') or (
                    (result.dependency_chain_coords or [''])[0] if result.dependency_chain_coords else ''
                ),
                'consumer_class': first.get('consumer_class') or consumer_class,
                'consumer_method': first.get('consumer_method') or consumer_method,
                'consumer_signature': first.get('consumer_signature') or '',
                'path_text': call_paths[index] if index < len(call_paths) else '',
                'confidence': result.confidence_score,
                'depth': result.business_reach_depth,
                'evidence': evidence,
            })

    details = _deduplicate_equivalent_path_details(_suppress_suffix_covered_path_details(details))

    rows = []
    detail_file = f"by_api/{build_by_api_safe_filename(result)}.txt"
    for detail in details:
        evidence = list(detail.get('evidence') or [])
        path_status = str(detail.get('path_status') or result.analysis_status)
        stop_reason = str(detail.get('stop_reason') or result.reason_code)
        explanation = explain_reason_code(stop_reason, result)
        semantic_evidence = [
            {
                key: item.get(key) or ''
                for key in ('caller_symbol', 'callee_key', 'evidence_type', 'owner_coord')
            }
            for item in evidence
        ]
        path_identity = json.dumps({
            'api_id': api_id, 'status': path_status, 'stop_reason': stop_reason,
            'path_text': detail.get('path_text') or '', 'evidence': semantic_evidence,
        }, ensure_ascii=False, sort_keys=True)
        path_id = 'PATH-' + hashlib.sha1(path_identity.encode('utf-8')).hexdigest()[:12]
        conclusion_level, action_type = _path_conclusion(path_status)
        reachable = detail.get('business_reachable')
        capability_coverage = dict(getattr(result, 'capability_coverage', {}) or {})
        rows.append({
            'api_id': api_id,
            'path_id': path_id,
            'target_coord': result.coord,
            'changed_symbol': result.api_name,
            'api_signature': getattr(result, 'api_signature', '') or '',
            'symbol_kind': getattr(result, 'symbol_kind', '') or '',
            'change_type': result.change_type,
            'severity': result.severity,
            'api_status': result.analysis_status,
            'path_status': path_status,
            'conclusion_level': conclusion_level,
            'action_type': action_type,
            'business_reachable': 'true' if reachable is True else ('false' if reachable is False else 'unknown'),
            'business_entry': detail.get('business_entry') or '',
            'consumer_coord': detail.get('consumer_coord') or '',
            'consumer_class': detail.get('consumer_class') or '',
            'consumer_method': detail.get('consumer_method') or '',
            'consumer_signature': detail.get('consumer_signature') or '',
            'path_text': detail.get('path_text') or '',
            'stop_reason': stop_reason,
            'reason': explanation['reason'],
            'action': explanation['action'] or '',
            'confidence': f"{float(detail.get('confidence') or 0.0):.2f}",
            'depth': int(detail.get('depth') or 0),
            'path_occurrence_count': int(detail.get('_path_occurrence_count') or 1),
            'coverage_status': capability_coverage.get('status') or '',
            'coverage_details': json.dumps(
                {
                    'analyzers': capability_coverage.get('analyzers') or {},
                    'matrix': capability_coverage.get('matrix') or {},
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            'evidence_types': '|'.join(sorted({str(item.get('evidence_type') or '') for item in evidence if item.get('evidence_type')})),
            'evidence_files': '|'.join(sorted({str(item.get('file') or '') for item in evidence if item.get('file')})),
            'detail_file': detail_file,
        })
    return rows


def _deduplicate_equivalent_path_details(details):
    deduped = []
    seen = {}
    for detail in details or []:
        key = _alert_path_detail_identity(detail)
        if key in seen:
            existing = seen[key]
            existing['_path_occurrence_count'] = int(existing.get('_path_occurrence_count') or 1) + 1
            existing_evidence = list(existing.get('evidence') or [])
            existing_evidence.extend(list(detail.get('evidence') or []))
            existing['evidence'] = existing_evidence
            continue
        copied = dict(detail)
        copied['_path_occurrence_count'] = int(copied.get('_path_occurrence_count') or 1)
        seen[key] = copied
        deduped.append(copied)
    return deduped


def _alert_path_detail_identity(detail):
    semantic_evidence = [
        {
            key: item.get(key) or ''
            for key in ('caller_symbol', 'callee_key', 'evidence_type', 'owner_coord')
        }
        for item in list((detail or {}).get('evidence') or [])
    ]
    return json.dumps({
        'path_status': (detail or {}).get('path_status') or '',
        'stop_reason': (detail or {}).get('stop_reason') or '',
        'business_reachable': (detail or {}).get('business_reachable'),
        'business_entry': (detail or {}).get('business_entry') or '',
        'consumer_coord': (detail or {}).get('consumer_coord') or '',
        'consumer_class': (detail or {}).get('consumer_class') or '',
        'consumer_method': (detail or {}).get('consumer_method') or '',
        'consumer_signature': (detail or {}).get('consumer_signature') or '',
        'path_text': (detail or {}).get('path_text') or '',
        'evidence': semantic_evidence,
    }, ensure_ascii=False, sort_keys=True)


def _suppress_suffix_covered_path_details(details):
    indexed = []
    for index, detail in enumerate(details or []):
        nodes = _alert_path_nodes(detail)
        indexed.append((index, detail, nodes, _alert_path_status_rank(detail.get('path_status'))))
    suppressed = set()
    for index, _detail, nodes, status_rank in indexed:
        if len(nodes) < 2:
            continue
        for other_index, _other_detail, other_nodes, other_rank in indexed:
            if index == other_index:
                continue
            if len(other_nodes) <= len(nodes):
                continue
            if other_rank > status_rank:
                continue
            if other_nodes[-len(nodes):] == nodes:
                suppressed.add(index)
                break
    return [detail for index, detail, _nodes, _rank in indexed if index not in suppressed]


def _alert_path_status_rank(path_status):
    return {
        'reachable': 0,
        'uncertain': 1,
        'not_analyzed': 2,
        'not_found_in_static_analysis': 3,
        'not_reachable': 3,
    }.get(str(path_status or ''), 9)


def _alert_path_nodes(detail):
    path_text = str((detail or {}).get('path_text') or '').strip()
    if path_text:
        separator = ' -> ' if ' -> ' in path_text else (' → ' if ' → ' in path_text else '')
        if separator:
            return [part.strip() for part in path_text.split(separator) if part.strip()]
    evidence = list((detail or {}).get('evidence') or [])
    nodes = []
    for item in evidence:
        caller = str((item or {}).get('caller_symbol') or '').strip()
        callee = str((item or {}).get('callee_key') or '').strip()
        if caller and (not nodes or nodes[-1] != caller):
            nodes.append(caller)
        if callee:
            nodes.append(callee)
    return nodes


def _split_alert_consumer(symbol):
    value = str(symbol or '').strip()
    if not value:
        return '', ''
    # Runtime bytecode evidence prefixes the Java symbol with group:artifact:.
    if value.count(':') >= 2:
        value = value.split(':', 2)[-1]
    head = value.split('(', 1)[0]
    if '.' not in head:
        return head, ''
    return tuple(head.rsplit('.', 1))


def _result_business_entry(result):
    for node in getattr(result, 'critical_nodes_hit', []) or []:
        if node.get('type') == 'system_code_touched' and node.get('method'):
            return node['method']
    return ''


def _path_conclusion(path_status):
    return {
        'reachable': ('confirmed', 'fix'),
        'uncertain': ('candidate', 'review'),
        'not_analyzed': ('incomplete', 'rerun_analysis'),
        'not_found_in_static_analysis': ('no_static_path', 'review'),
        'not_reachable': ('no_static_path', 'review'),
    }.get(path_status, ('incomplete', 'review'))


def severity_rank(sev):
    """严重程度排序"""
    if sev == 'P0':
        return 0
    elif sev == 'P1':
        return 1
    elif sev == 'P2':
        return 2
    else:
        return 9


# ════════════════════════════════════════════��═════════════════════
# 测试
# ══════════════════════════════════════════════════════════════════

def test_output_formatter():
    """测试输出格式化器"""
    # 模拟TraceResult
    mock_result = type('TraceResult', (), {
        'api_name': 'com.example.Foo.changedMethod',
        'api_simple': 'changedMethod',
        'change_type': 'REMOVED',
        'coord': 'com.example:dependency-lib',
        'severity': 'P0',
        'confirmed': True,
        'source': 'jar_diff',
        'analysis_scope': 'api',
        'analysis_status': 'reachable',
        'is_reachable': True,
        'reachable_note': '触达系统代码',
        'business_reach_depth': 3,
        'dependency_chain_coords': [],
        'call_paths': ['Controller.handleRequest → Service.process → Foo.changedMethod'],
        'evidence_paths': [
            [
                {
                    'caller': 'Controller.handleRequest',
                    'callee': 'Service.process',
                    'confidence': 'high',
                    'evidence_type': 'instance_call',
                    'file': 'Controller.java',
                    'line': 30
                },
                {
                    'caller': 'Service.process',
                    'callee': 'Foo.changedMethod',
                    'confidence': 'high',
                    'evidence_type': 'instance_call',
                    'file': 'Service.java',
                    'line': 20
                }
            ]
        ],
        'reason_code': 'SYSTEM_CODE_REACHED',
        'verification_commands': [],
        'hops': [],
        'confidence_score': 0.90,
        'critical_nodes_hit': [
            {
                'type': 'system_code_touched',
                'method': 'Controller.handleRequest',
                'file': 'Controller.java',
                'line': 30
            }
        ]
    })()

    # 格式化输出
    formatted = format_call_chain_readable(mock_result)
    print(formatted)

    return 0


if __name__ == '__main__':
    sys.exit(test_output_formatter())
