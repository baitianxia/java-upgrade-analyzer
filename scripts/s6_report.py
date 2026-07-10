#!/usr/bin/env python3
"""
s6_report.py — Step 6：汇总报告

读取所有前序步骤的产出，生成结构化报告。
只描述问题，不提供修复方案。

用法：
  python s6_report.py \
    --report-dir .upgrade-report \
    --output-findings .upgrade-report/.runtime/findings/s6_findings.json \
    --output-report   .upgrade-report/deliverables/report.md
"""

import argparse, csv, json, os, re, sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent))
from compat import open_text, write_text
from pipeline_constants import (
    DELIVERABLES_DIRNAME,
    EVIDENCE_API_CHANGES_DIRNAME,
    EVIDENCE_CALL_CHAIN_DIRNAME,
    EVIDENCE_CONTEXT_DIRNAME,
    EVIDENCE_DEPENDENCIES_DIRNAME,
    EVIDENCE_DIRNAME,
    EVIDENCE_STATIC_SCAN_DIRNAME,
    PER_DEPENDENCY_DIRNAME,
    PER_DEPENDENCY_SUMMARY_FILE,
    RUNTIME_COVERAGE_DIRNAME,
    RUNTIME_DIRNAME,
)

S6_INLINE_LIMIT = 20
S6_NOT_FOUND_INLINE_LIMIT = S6_INLINE_LIMIT
S6_DETAIL_MD_FULL_LIMIT = 200
S6_DETAIL_MD_SAMPLE_LIMIT = 50
S6_DETAIL_MD_DEP_SUMMARY_LIMIT = 50
S6_CHANGED_API_SPLIT_ROWS = 500


def _evidence_dir(report_dir, name):
    return Path(report_dir) / EVIDENCE_DIRNAME / name


def _deliverables_dir(report_dir):
    return Path(report_dir) / DELIVERABLES_DIRNAME


def _runtime_dir(report_dir, name):
    return Path(report_dir) / RUNTIME_DIRNAME / name


def _dep_changes_path(report_dir):
    return _evidence_dir(report_dir, EVIDENCE_DEPENDENCIES_DIRNAME) / "dep_changes.csv"


def _context_path(report_dir):
    return _evidence_dir(report_dir, EVIDENCE_CONTEXT_DIRNAME) / "context.json"


def _static_scan_dir(report_dir):
    return _evidence_dir(report_dir, EVIDENCE_STATIC_SCAN_DIRNAME)


def _api_changes_dir(report_dir):
    return _evidence_dir(report_dir, EVIDENCE_API_CHANGES_DIRNAME)


def _call_chain_dir(report_dir):
    return _evidence_dir(report_dir, EVIDENCE_CALL_CHAIN_DIRNAME)


def _coverage_path(report_dir):
    return _runtime_dir(report_dir, RUNTIME_COVERAGE_DIRNAME) / "coverage.json"


def _step5_summary_coverage_fallback(call_summary):
    """Build a conservative coverage view when formal coverage.json is absent.

    The orchestrated pipeline writes .runtime/coverage/coverage.json. Some
    direct Step5/Step6 uses only have evidence/call_chain/summary.json. In that
    case the report should not show an unhelpful "unknown" if Step5 already
    emitted graph/coverage signals in meta.graph_stats.
    """
    graph_stats = ((call_summary or {}).get('meta') or {}).get('graph_stats') or {}
    if not graph_stats:
        return {}

    components = []
    critical = []
    total_apis = int((call_summary or {}).get('total_apis') or 0)
    all_symbols_preserved = bool(
        total_apis
        and int((call_summary or {}).get('not_impacted') or 0) == total_apis
    )

    def add_component(component_id, status, reason_codes=None, evidence=None, critical_if_incomplete=True):
        status = str(status or 'unknown')
        item = {
            'id': component_id,
            'status': status,
            'reason_codes': list(reason_codes or []),
            'evidence': [item for item in (evidence or []) if item],
        }
        components.append(item)
        if critical_if_incomplete and status not in {'complete', 'not_applicable'}:
            critical.append(component_id)

    truncated = bool(graph_stats.get('truncated'))
    truncation_reasons = list(graph_stats.get('truncation_reasons') or [])
    business_reason_codes = list(truncation_reasons)
    edge_cap_hits = graph_stats.get('edge_cap_hits') or 0
    if edge_cap_hits:
        business_reason_codes.append('edge_cap_hits')
    parser_fallback_reasons = graph_stats.get('parser_fallback_reasons') or {}
    if parser_fallback_reasons:
        business_reason_codes.append('parser_fallback')
    add_component(
        'business_reachability',
        'not_applicable' if all_symbols_preserved else (
            'partial' if (truncated or parser_fallback_reasons or edge_cap_hits) else 'complete'
        ),
        business_reason_codes,
        truncation_reasons,
    )

    source_alignment = graph_stats.get('source_artifact_alignment') or {}
    if source_alignment:
        add_component(
            'source_artifact_alignment',
            'not_applicable' if all_symbols_preserved else (source_alignment.get('status') or 'unknown'),
            source_alignment.get('reason_codes') or [],
            [source_alignment.get('artifact_path') or source_alignment.get('git_root') or ''],
        )

    artifact_bytecode = graph_stats.get('artifact_bytecode') or {}
    if artifact_bytecode:
        add_component(
            'artifact_bytecode_dependencies',
            artifact_bytecode.get('status') or 'unknown',
            artifact_bytecode.get('reason_codes') or [],
        )

    business_bytecode = graph_stats.get('business_bytecode') or {}
    if business_bytecode:
        add_component(
            'business_bytecode_graph',
            'not_applicable' if all_symbols_preserved else (business_bytecode.get('status') or 'unknown'),
            business_bytecode.get('failures') or [],
            critical_if_incomplete=False,
        )

    indirect_usage = graph_stats.get('indirect_usage') or {}
    if indirect_usage:
        add_component(
            'indirect_usage_matrix',
            'not_applicable' if all_symbols_preserved else (indirect_usage.get('status') or 'unknown'),
            indirect_usage.get('reason_codes') or [],
        )

    if critical:
        overall_status = 'partial'
    elif any(item.get('status') == 'unknown' for item in components):
        overall_status = 'unknown'
    else:
        overall_status = 'complete'

    return {
        'schema': 'java-upgrade-analyzer.coverage.v1',
        'source': 'step5_summary_fallback',
        'overall_status': overall_status,
        'critical_incomplete': critical,
        'components': components,
    }


S6_DETAIL_BUCKETS = {
    "not_impacted": {
        "title": "已确认不受影响清单",
        "conclusion": "已确认不受影响",
        "csv": "s6_not_impacted_apis.csv",
        "md": "s6_not_impacted_apis.md",
        "summary_key": "",
        "note": "最终制品证据证明这些变更 API 仍由其他运行时 JAR 以完全相同的 class 字节码提供。",
    },
    "uncertain": {
        "title": "需人工复核清单",
        "conclusion": "需人工复核",
        "csv": "s6_uncertain_apis.csv",
        "md": "s6_uncertain_apis.md",
        "summary_key": "uncertain_reason_summary",
        "note": "静态分析发现候选路径但存在歧义，需要人工核实。",
    },
    "probable_impact": {
        "title": "可能影响完整清单",
        "conclusion": "可能影响",
        "csv": "s6_probable_impact_apis.csv",
        "md": "s6_probable_impact_apis.md",
        "summary_key": "not_analyzed_reason_summary",
        "note": "已找到强相关证据，但当前静态证据不足以确认运行时表现。",
    },
    "needs_input": {
        "title": "缺少依赖源码/构建产物清单",
        "conclusion": "缺少依赖源码/构建产物",
        "csv": "s6_needs_input_apis.csv",
        "md": "s6_needs_input_apis.md",
        "summary_key": "not_analyzed_reason_summary",
        "note": "缺少依赖源码、目标模块或构建产物，当前无法完整回溯调用链。",
    },
    "not_analyzed": {
        "title": "本次未完成分析清单",
        "conclusion": "本次未完成分析",
        "csv": "s6_not_analyzed_apis.csv",
        "md": "s6_not_analyzed_apis.md",
        "summary_key": "not_analyzed_reason_summary",
        "note": "工具已知未覆盖该场景，不能按未影响解释。",
    },
    "not_found": {
        "title": "未发现调用路径清单",
        "conclusion": "静态分析未找到调用路径（不等于确定不影响）",
        "csv": "s6_not_found_apis.csv",
        "md": "s6_not_found_apis.md",
        "summary_key": "not_found_reason_summary",
        "note": "未发现调用路径不等于确定不影响；仅表示当前源码图未找到引用路径。",
    },
}


def load_json(path):
    if not os.path.exists(path):
        return {}
    try:
        with open_text(path) as f:
            return json.load(f)
    except Exception:
        return {}


def load_csv(path):
    if not os.path.exists(path):
        return []
    rows = []
    try:
        with open_text(path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row:
                    rows.append({k: (v or '').strip() for k, v in row.items()})
    except Exception:
        pass
    return rows


def count_lines(path):
    if not os.path.exists(path):
        return -1
    try:
        with open_text(path) as f:
            lines = [l for l in f if l.strip() and not l.startswith('#')]
        if path.endswith('.csv'):
            return max(len(lines) - 1, 0)  # 排除 CSV 表头
        return len(lines)
    except Exception:
        return -1


def relpath_for_report(path, report_dir):
    try:
        return Path(path).resolve().relative_to(Path(report_dir).resolve()).as_posix()
    except Exception:
        return Path(path).name


def _csv_cell(value):
    if isinstance(value, (list, tuple)):
        return " | ".join(str(item) for item in value)
    return str(value or "")


def summarize_item_reason_codes(items):
    counts = defaultdict(int)
    for item in items or []:
        counts[item.get("reason_code") or "UNKNOWN"] += 1
    return dict(sorted(counts.items(), key=lambda x: (-x[1], x[0])))


def summarize_item_reasons(items):
    """Summarize human explanations without exposing internal reason codes."""
    counts = defaultdict(int)
    for item in items or []:
        reason = str(
            item.get("user_reason")
            or item.get("reason")
            or "未提供足够证据说明原因"
        ).strip()
        counts[reason] += 1
    return dict(sorted(counts.items(), key=lambda x: (-x[1], x[0])))


def summarize_item_coords(items):
    counts = defaultdict(int)
    for item in items or []:
        counts[item.get("coord") or "UNKNOWN"] += 1
    return dict(sorted(counts.items(), key=lambda x: (-x[1], x[0])))


def _md_cell(value, limit=240):
    text = str(value or "").replace("|", "\\|").replace("\n", " ")
    if len(text) > limit:
        return text[:limit] + "…"
    return text


def _api_short_name(item):
    api = str(item.get('api') or item.get('api_name') or '').strip()
    if not api:
        return ''
    if '(' in api:
        api = api.split('(', 1)[0]
    return api.rsplit('.', 1)[-1] if '.' in api else api


def _human_signature(signature):
    text = str(signature or '').strip()
    if not text:
        return ''
    text = text.strip('`')
    if text.startswith('(') and text.endswith(')'):
        text = text[1:-1]
    if not text:
        return '无参数'
    parts = []
    for part in text.split(','):
        cleaned = part.strip()
        if not cleaned:
            continue
        cleaned = cleaned.replace('java.lang.', '')
        cleaned = cleaned.replace('java.util.', '')
        cleaned = cleaned.replace('$', '.')
        parts.append(cleaned)
    return ', '.join(parts) if parts else '无参数'


def _human_symbol_kind(kind):
    text = str(kind or '').strip().lower()
    labels = {
        'class': '类',
        'interface': '接口',
        'method': '方法',
        'constructor': '构造方法',
        'field': '字段',
        'enum': '枚举',
        'annotation': '注解',
    }
    return labels.get(text, text or 'API')


def _human_change_type(change_type, symbol_kind=''):
    text = str(change_type or '').strip().upper()
    kind = _human_symbol_kind(symbol_kind)
    labels = {
        'REMOVED': f'删除{kind}',
        'METHOD_REMOVED': '删除方法',
        'CLASS_REMOVED': '删除类',
        'FIELD_REMOVED': '删除字段',
        'CONSTRUCTOR_REMOVED': '删除构造方法',
        'ADDED': f'新增{kind}',
        'METHOD_ADDED': '新增方法',
        'CLASS_ADDED': '新增类',
        'FIELD_ADDED': '新增字段',
        'MODIFIED': f'修改{kind}',
        'CHANGED': f'修改{kind}',
        'METHOD_CHANGED': '修改方法',
        'FIELD_CHANGED': '修改字段',
        'BEHAVIOR_CHANGED': '行为变化',
        'CONSTANT_VALUE_CHANGED': '常量值变化',
        'SIGNATURE_CHANGED': '方法签名变化',
        'RETURN_TYPE_CHANGED': '返回类型变化',
        'ACCESS_MODIFIER_CHANGED': '访问权限变化',
        'DEPRECATED': f'废弃{kind}',
    }
    if text in labels:
        return labels[text]
    if text.endswith('_REMOVED'):
        return f'删除{kind}'
    if text.endswith('_ADDED'):
        return f'新增{kind}'
    if text.endswith('_CHANGED') or text.endswith('_MODIFIED'):
        return f'修改{kind}'
    return text.replace('_', ' ').strip().capitalize() if text else f'{kind}变化'


def _change_summary(item, severity=''):
    change = _human_change_type(item.get('change_type'), item.get('symbol_kind'))
    api_short = _api_short_name(item)
    signature = _human_signature(item.get('api_signature'))
    sev = str(severity or item.get('severity') or '').strip()
    pieces = [change]
    if api_short:
        pieces.append(api_short)
    if signature:
        pieces.append(f"参数：{signature}")
    if sev:
        pieces.append(f"严重级别：{sev}")
    return "，".join(pieces)


def _detail_row(idx, item, conclusion=''):
    reason = item.get("user_reason") or item.get("reason") or item.get("recommended_action") or ""
    focus = _detail_review_focus(item, conclusion)
    return (
        f"| {idx} | `{_md_cell(item.get('coord'))}` | `{_md_cell(item.get('api'))}` | "
        f"{_md_cell(_change_summary(item), 220)} | "
        f"{_md_cell(conclusion or item.get('user_conclusion') or _bucket_csv_conclusion('', item))} | "
        f"{_md_cell(reason)} | {_md_cell(focus)} |"
    )


def _detail_review_focus(item, conclusion=''):
    conclusion_text = str(conclusion or item.get("user_conclusion") or "").strip()
    reason = str(item.get("user_reason") or item.get("reason") or item.get("reason_code") or "").strip()
    if conclusion_text == "已确认影响":
        return "核对业务入口、消费方和变更 API 是否属于本次升级范围。"
    if conclusion_text == "可能影响":
        return "结合业务测试或运行时配置确认该行为变化是否会触发。"
    if conclusion_text in {"需要补充输入", "缺少依赖源码/构建产物"}:
        return "先补齐原因中提到的源码、构建产物或映射信息。"
    if conclusion_text == "已确认不受影响":
        return "核对保留该 API 的当前制品依赖是否确实随应用发布。"
    if "未找到" in conclusion_text:
        return "核对本轮源码、依赖和静态分析范围是否完整。"
    if reason:
        return "围绕原因字段核对对应证据。"
    return "打开 CSV 查看完整字段并按依赖坐标筛选。"


def build_bucket_detail_markdown(config, items, csv_name):
    reason_summary = summarize_item_reasons(items)
    coord_summary = summarize_item_coords(items)
    lines = [
        f"# {config.get('title') or 'S6 明细'}",
        "",
        f"- 总数：{len(items)}",
        f"- 说明：{config.get('note') or ''}",
        f"- 完整可筛选清单：`{csv_name}`",
        "",
        "## 先看什么",
        "",
        "- 先看下面的 API 明细表，重点读“原因”和“复核重点”。",
        "- 如果 Markdown 只展示样例，用完整 CSV 按依赖坐标或变更 API 筛选。",
        "- 需要调用链证据时，回到 `evidence/call_chain/alerts.csv` 按 API 或依赖坐标筛选。",
        "",
    ]

    if len(items) <= S6_DETAIL_MD_FULL_LIMIT:
        lines += [
            "## API 明细（完整）",
            "",
            "| # | 依赖坐标 | 变更 API | 变化 | 结论 | 原因 | 复核重点 |",
            "|---:|---|---|---|---|---|---|",
        ]
        for idx, item in enumerate(items, 1):
            lines.append(_detail_row(idx, item, config.get('conclusion') or ''))
        lines.append("")
    else:
        lines += [
            f"## 明细样例（前 {S6_DETAIL_MD_SAMPLE_LIMIT} 条）",
            "",
            f"> 本桶共有 {len(items)} 条，Markdown 只展示样例，避免明细文件自身难以阅读或预览失败；完整全集请看 `{csv_name}`。",
            "",
            "| # | 依赖坐标 | 变更 API | 变化 | 结论 | 原因 | 复核重点 |",
            "|---:|---|---|---|---|---|---|",
        ]
        for idx, item in enumerate(items[:S6_DETAIL_MD_SAMPLE_LIMIT], 1):
            lines.append(_detail_row(idx, item, config.get('conclusion') or ''))
        lines += [
            "",
            f"> 其余 {len(items) - S6_DETAIL_MD_SAMPLE_LIMIT} 条未在 Markdown 展开，请在 CSV 中筛选查看。",
            "",
        ]
    if reason_summary or coord_summary:
        lines += [
            "## 附录：聚合统计",
            "",
            "下面的统计只用于筛选明细，不作为单独结论。",
            "",
        ]
    if reason_summary:
        lines += [
            "### 原因分类",
            "",
            "| 原因 | 数量 |",
            "|---|---:|",
        ]
        for reason, count in reason_summary.items():
            lines.append(f"| {_md_cell(reason)} | {count} |")
        lines.append("")
    if coord_summary:
        lines += [
            f"### 依赖坐标分布（Top {min(S6_DETAIL_MD_DEP_SUMMARY_LIMIT, len(coord_summary))}）",
            "",
            "| 依赖坐标 | 数量 |",
            "|---|---:|",
        ]
        for coord, count in list(coord_summary.items())[:S6_DETAIL_MD_DEP_SUMMARY_LIMIT]:
            lines.append(f"| `{_md_cell(coord)}` | {count} |")
        if len(coord_summary) > S6_DETAIL_MD_DEP_SUMMARY_LIMIT:
            lines.append(
                f"| 其他 {len(coord_summary) - S6_DETAIL_MD_DEP_SUMMARY_LIMIT} 个依赖 | "
                f"{sum(list(coord_summary.values())[S6_DETAIL_MD_DEP_SUMMARY_LIMIT:])} |"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def write_bucket_detail_artifacts(report_dir, findings, bucket_name):
    """Write full bucket details outside the main Markdown report."""
    config = S6_DETAIL_BUCKETS.get(bucket_name) or {}
    items = list((findings or {}).get(bucket_name) or [])
    if bucket_name == "not_analyzed":
        items = [
            item for item in items
            if item.get("user_conclusion") not in {"可能影响", "需要补充输入"}
        ]
    artifacts = {}
    report_path = _deliverables_dir(report_dir)
    csv_path = report_path / config.get("csv", f"s6_{bucket_name}_apis.csv")
    md_path = report_path / config.get("md", f"s6_{bucket_name}_apis.md")
    if not items:
        # A rerun can legitimately move every item out of a bucket.  Keeping the
        # previous files would expose stale conclusions to users and contradict
        # the new report counts, so empty buckets must actively remove them.
        for stale_path in (csv_path, md_path):
            try:
                stale_path.unlink()
            except FileNotFoundError:
                pass
        return artifacts
    report_path.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "conclusion",
        "change_summary",
        "review_reason",
        "chain_summary",
        "chain_entry",
        "chain_target",
        "chain_hop_count",
        "chain_detail",
        "coord",
        "api",
        "api_signature",
        "symbol_kind",
        "change_type",
        "severity",
        "reason_code",
        "reason",
        "user_reason",
        "recommended_action",
        "verification",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in items:
            row = {key: _csv_cell(item.get(key)) for key in fieldnames}
            chain_view = _csv_chain_view(item)
            row["conclusion"] = _csv_cell(_bucket_csv_conclusion(bucket_name, item))
            row["change_summary"] = _change_summary(item)
            row["review_reason"] = _csv_cell(item.get("user_reason") or item.get("reason") or item.get("reason_code") or "")
            row["chain_summary"] = _csv_cell(chain_view["summary"])
            row["chain_entry"] = _csv_cell(chain_view["entry"])
            row["chain_target"] = _csv_cell(chain_view["target"])
            row["chain_hop_count"] = _csv_cell(chain_view["hop_count"])
            row["chain_detail"] = _csv_cell(chain_view["detail"])
            writer.writerow(row)

    write_text(
        str(md_path),
        build_bucket_detail_markdown(config, items, relpath_for_report(csv_path, report_dir)),
    )
    artifacts[f"{bucket_name}_csv"] = relpath_for_report(csv_path, report_dir)
    artifacts[f"{bucket_name}_md"] = relpath_for_report(md_path, report_dir)
    return artifacts


def _bucket_csv_conclusion(bucket_name, item):
    if bucket_name == "not_impacted":
        return "已确认不受影响"
    if bucket_name == "not_found":
        return "未发现静态调用路径"
    if bucket_name == "not_analyzed":
        return "未完成分析"
    user_conclusion = str((item or {}).get("user_conclusion") or "").strip()
    if user_conclusion:
        return user_conclusion
    return {
        "probable_impact": "可能影响",
        "uncertain": "需人工复核",
        "not_impacted": "已确认不受影响",
        "needs_input": "缺少依赖源码/构建产物",
        "not_analyzed": "未完成分析",
        "not_found": "未发现静态调用路径",
    }.get(bucket_name, "需人工复核")


def _csv_chain_view(item):
    item = item or {}
    nodes = []
    for path in item.get("call_paths") or []:
        nodes = _split_csv_chain_nodes(path)
        if nodes:
            break
    if not nodes:
        for evidence_path in item.get("evidence_paths") or []:
            nodes = _nodes_from_csv_evidence(evidence_path)
            if nodes:
                break
    api = str(item.get("api") or item.get("api_name") or "").strip()
    if not nodes and api:
        return {
            "summary": f"未形成完整链路；目标 API：{api}",
            "entry": "",
            "target": api,
            "hop_count": "",
            "detail": api,
        }
    if not nodes:
        return {"summary": "未形成完整链路", "entry": "", "target": "", "hop_count": "", "detail": ""}
    entry = nodes[0]
    target = _strip_changed_api_marker(nodes[-1])
    hop_count = max(0, len(nodes) - 1)
    return {
        "summary": f"入口：{entry}；终点：{target}；{hop_count} 跳" if len(nodes) >= 2 else f"未形成完整链路；目标 API：{target}",
        "entry": entry if len(nodes) >= 2 else "",
        "target": target,
        "hop_count": str(hop_count) if len(nodes) >= 2 else "",
        "detail": " -> ".join(f"{idx}. {node}" for idx, node in enumerate(nodes, 1)),
    }


def _strip_changed_api_marker(value):
    value = str(value or "").strip()
    marker = "变更API:"
    if value.startswith(marker):
        return value[len(marker):].strip()
    return value


def _split_csv_chain_nodes(path_text):
    text = str(path_text or "").strip()
    if not text:
        return []
    normalized = text.replace("→", "->")
    parts = [part.strip() for part in normalized.split("->") if part.strip()]
    return parts if len(parts) >= 2 else ([text] if text else [])


def _nodes_from_csv_evidence(evidence_path):
    nodes = []
    for edge in evidence_path or []:
        caller = str(edge.get("caller_symbol") or "").strip()
        callee = str(edge.get("callee_key") or "").strip()
        if caller and (not nodes or nodes[-1] != caller):
            nodes.append(caller)
        if callee and (not nodes or nodes[-1] != callee):
            nodes.append(callee)
    return nodes


def write_not_found_detail_artifacts(report_dir, findings):
    return write_bucket_detail_artifacts(report_dir, findings, "not_found")


def write_s6_detail_artifacts(report_dir, findings):
    artifacts = {}
    for bucket_name in S6_DETAIL_BUCKETS:
        artifacts.update(write_bucket_detail_artifacts(report_dir, findings, bucket_name))
    artifacts.update(write_changed_api_split_artifacts(report_dir))
    return artifacts


def available_s6_detail_artifacts(findings):
    """Return only bucket detail files produced by the current Step6 run."""
    artifacts = (findings or {}).get("artifacts") or {}
    rows = []
    for bucket_name, config in S6_DETAIL_BUCKETS.items():
        csv_key = f"{bucket_name}_csv"
        md_key = f"{bucket_name}_md"
        if not artifacts.get(csv_key) or not artifacts.get(md_key):
            continue
        rows.append({
            "bucket": bucket_name,
            "path": f"deliverables/{config['csv'][:-4]}.csv/md",
            "title": config.get("title") or bucket_name,
        })
    return rows


def write_changed_api_split_artifacts(report_dir):
    artifacts = {}
    source_path = _api_changes_dir(report_dir) / "all_changed_apis.csv"
    if not source_path.is_file():
        return artifacts

    split_dir = source_path.parent
    for stale_path in split_dir.glob("all_changed_apis_part_*.csv"):
        try:
            stale_path.unlink()
        except OSError:
            pass

    try:
        with source_path.open(encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = list(reader.fieldnames or [])
            rows = list(reader)
    except OSError:
        return artifacts

    if not fieldnames or not rows:
        return artifacts

    part_count = 0
    for start in range(0, len(rows), S6_CHANGED_API_SPLIT_ROWS):
        part_count += 1
        part_path = split_dir / f"all_changed_apis_part_{part_count:03d}.csv"
        with part_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows[start:start + S6_CHANGED_API_SPLIT_ROWS])

    artifacts["changed_apis_split_pattern"] = "evidence/api_changes/all_changed_apis_part_*.csv"
    artifacts["changed_apis_split_count"] = part_count
    return artifacts


def load_per_dependency_summaries(report_dir):
    per_dependency_root = _api_changes_dir(report_dir) / PER_DEPENDENCY_DIRNAME
    results = []
    if not per_dependency_root.is_dir():
        return results
    for child in sorted(per_dependency_root.iterdir()):
        if not child.is_dir():
            continue
        payload = load_json(str(child / PER_DEPENDENCY_SUMMARY_FILE))
        if payload:
            results.append(payload)
    return results


def build_api_identity_key(payload):
    payload = payload or {}
    return (
        str(payload.get('coord', '') or '').strip(),
        str(payload.get('api_name') or payload.get('api') or '').strip(),
        str(payload.get('api_signature', '') or '').strip(),
        str(payload.get('symbol_kind', '') or '').strip(),
        str(payload.get('change_type', '') or '').strip(),
    )


def _short_path(value, parts=4):
    text = str(value or "").strip()
    if not text:
        return ""
    items = Path(text).parts[-parts:]
    return "/".join(items) if items else text


def _module_from_evidence_file(value):
    text = str(value or "").strip()
    if not text:
        return ""
    parts = list(Path(text).parts)
    for marker in (("src", "main", "java"), ("src", "test", "java")):
        marker_len = len(marker)
        for idx in range(0, max(len(parts) - marker_len + 1, 0)):
            if tuple(parts[idx:idx + marker_len]) == marker:
                before = [part for part in parts[:idx] if part not in {"/", ""}]
                if before:
                    if len(before) >= 2 and before[-2].startswith("jua-real-project"):
                        return before[-1]
                    return "/".join(before[-2:]) if len(before) >= 2 else before[-1]
    return _short_path(text, parts=2)


def _impact_bucket(row):
    status = str(row.get("path_status") or row.get("api_status") or "").strip()
    conclusion = str(row.get("conclusion_level") or "").strip()
    business_reachable = str(row.get("business_reachable") or "").strip().lower()
    if status == "reachable" or conclusion == "confirmed" or business_reachable == "true":
        return "confirmed"
    if status == "not_impacted" or conclusion == "confirmed_no_impact":
        return "not_impacted"
    if status in {"uncertain", "not_analyzed"} or conclusion in {"candidate", "incomplete"}:
        return "review"
    if status == "not_found_in_static_analysis":
        return "not_found"
    return status or "unknown"


def _bucket_rank(bucket):
    return {"confirmed": 0, "review": 1, "not_impacted": 2, "not_found": 3, "unknown": 4}.get(bucket or "unknown", 9)


def _impact_sort_key(item):
    status_counts = item.get("status_counts") or {}
    return (
        _bucket_rank(item.get("bucket")),
        -int(status_counts.get("reachable") or 0),
        -int(item.get("path_count") or 0),
        item.get("coord", ""),
        item.get("api", ""),
    )


def build_impact_overview(alert_rows):
    """Convert Step5 alerts.csv into a human-first "what is affected" view."""
    api_map = {}
    entry_map = {}
    for row in alert_rows or []:
        api = str(row.get("changed_symbol") or "").strip()
        coord = str(row.get("target_coord") or "").strip()
        if not api:
            continue
        bucket = _impact_bucket(row)
        key = (
            coord,
            api,
            str(row.get("api_signature") or "").strip(),
            str(row.get("symbol_kind") or "").strip(),
            str(row.get("change_type") or "").strip(),
        )
        item = api_map.setdefault(key, {
            "coord": coord,
            "api": api,
            "api_signature": key[2],
            "symbol_kind": key[3],
            "change_type": key[4],
            "bucket": bucket,
            "status_counts": defaultdict(int),
            "path_count": 0,
            "entries": set(),
            "paths": [],
            "paths_by_status": defaultdict(list),
            "path_counts_by_status": defaultdict(int),
            "files": set(),
            "modules": set(),
            "actions": set(),
            "reasons": set(),
            "api_ids": set(),
        })
        if _bucket_rank(bucket) < _bucket_rank(item["bucket"]):
            item["bucket"] = bucket
        status = str(row.get("path_status") or row.get("api_status") or "unknown").strip() or "unknown"
        item["status_counts"][status] += 1
        try:
            occurrence_count = max(int(str(row.get("path_occurrence_count") or "1")), 1)
        except ValueError:
            occurrence_count = 1
        item["path_count"] += occurrence_count
        item["path_counts_by_status"][status] += occurrence_count
        api_id = str(row.get("api_id") or "").strip()
        if api_id:
            item["api_ids"].add(api_id)

        entry = str(row.get("business_entry") or "").strip()
        if not entry:
            consumer_class = str(row.get("consumer_class") or "").strip()
            consumer_method = str(row.get("consumer_method") or "").strip()
            entry = ".".join(part for part in (consumer_class, consumer_method) if part)
        if entry:
            item["entries"].add(entry)

        path_text = str(row.get("path_text") or "").strip()
        if path_text and path_text not in item["paths"]:
            item["paths"].append(path_text)
        if path_text and path_text not in item["paths_by_status"][status]:
            item["paths_by_status"][status].append(path_text)
        for raw_file in str(row.get("evidence_files") or "").split("|"):
            raw_file = raw_file.strip()
            if raw_file:
                item["files"].add(raw_file)
                module = _module_from_evidence_file(raw_file)
                if module:
                    item["modules"].add(module)
        action = str(row.get("action") or "").strip()
        if action:
            item["actions"].add(action)
        reason = str(row.get("reason") or row.get("stop_reason") or "").strip()
        if reason:
            item["reasons"].add(reason)

        if bucket == "confirmed" and entry:
            entry_item = entry_map.setdefault(entry, {
                "entry": entry,
                "apis": set(),
                "paths": [],
                "files": set(),
                "modules": set(),
                "path_count": 0,
            })
            entry_item["apis"].add(api)
            entry_item["path_count"] += occurrence_count
            if path_text and path_text not in entry_item["paths"]:
                entry_item["paths"].append(path_text)
            for raw_file in str(row.get("evidence_files") or "").split("|"):
                raw_file = raw_file.strip()
                if raw_file:
                    entry_item["files"].add(raw_file)
                    module = _module_from_evidence_file(raw_file)
                    if module:
                        entry_item["modules"].add(module)

    api_items = []
    for item in api_map.values():
        status_counts = dict(sorted(item["status_counts"].items(), key=lambda x: (-x[1], x[0])))
        api_items.append({
            "api_id": next(iter(item["api_ids"])) if len(item["api_ids"]) == 1 else "",
            "coord": item["coord"],
            "api": item["api"],
            "api_signature": item["api_signature"],
            "symbol_kind": item["symbol_kind"],
            "change_type": item["change_type"],
            "bucket": item["bucket"],
            "status_counts": status_counts,
            "path_count": item["path_count"],
            "entry_count": len(item["entries"]),
            "module_count": len(item["modules"]),
            "sample_modules": sorted(item["modules"])[:5],
            "sample_entries": sorted(item["entries"])[:3],
            "sample_paths": item["paths"][:2],
            "paths": item["paths"][:10],
            "paths_by_status": {
                status: paths[:10]
                for status, paths in item["paths_by_status"].items()
            },
            "path_counts_by_status": dict(item["path_counts_by_status"]),
            "sample_files": [_short_path(path) for path in sorted(item["files"])[:3]],
            "sample_actions": sorted(item["actions"])[:2],
            "sample_reasons": sorted(item["reasons"])[:2],
        })

    entry_items = []
    for item in entry_map.values():
        entry_items.append({
            "entry": item["entry"],
            "api_count": len(item["apis"]),
            "path_count": item["path_count"],
            "sample_modules": sorted(item["modules"])[:3],
            "sample_apis": sorted(item["apis"])[:3],
            "sample_paths": item["paths"][:2],
            "sample_files": [_short_path(path) for path in sorted(item["files"])[:2]],
        })

    api_items = sorted(api_items, key=_impact_sort_key)
    entry_items = sorted(entry_items, key=lambda x: (-x["api_count"], -x["path_count"], x["entry"]))
    return {
        "apis": api_items,
        "confirmed_apis": [item for item in api_items if item.get("bucket") == "confirmed"],
        "review_apis": [item for item in api_items if item.get("bucket") == "review"],
        "not_impacted_apis": [item for item in api_items if item.get("bucket") == "not_impacted"],
        "not_found_apis": [item for item in api_items if item.get("bucket") == "not_found"],
        "business_entries": entry_items,
    }


def collect_findings(d):
    findings = {
        'meta': {
            'read_order': [
                'deliverables/report.md（主报告）',
                's6_*_apis.csv/md（按结论拆分的完整 API 明细）',
                'evidence/call_chain/alerts.csv（完整逐链路台账）',
                'evidence/api_changes/all_changed_apis.csv（反向调用链输入变更集）',
                'evidence/static_scan/s3_*.csv/.txt（背景信号，用于补充排查方向）',
            ],
            'sampling_guide': [
                '从 P0/P1 各抽 3 条：沿 call_paths 打开源码核对调用关系',
                '对 uncertain 至少抽 3 条：先看 s6_uncertain_apis.csv/md，再到 alerts.csv 核对链路状态和证据文件',
                '从 all_changed_apis.csv 抽 3 条：核对 change_type / source 与原始证据是否一致',
                '从 s3_jdk_removed_api.csv / s3_jdk_javax_refs.csv 各抽 2 条：核对 文件:行号 是否为真实命中',
            ],
        },
        'generated_at':        datetime.now().isoformat(),
        'context':             {},
        'scan_stats':          {},
        'dep_compat_summary':  {},
        'background_signals':  {},
        'impacted_dependencies': [],
        'p0':                  [],
        'p1':                  [],
        'p2':                  [],
        'uncertain':           [],
        'probable_impact':     [],
        'not_impacted':        [],
        'needs_input':         [],
        'not_analyzed':        [],
        'not_found':           [],
        'uncertain_reason_summary': {},
        'not_analyzed_reason_summary': {},
        'not_found_reason_summary': {},
        'user_conclusion_summary': {},
        'module_impacts':      {},
        'dep_changes_summary': {},
        'per_dependency_results': [],
        'impact_overview': {
            'apis': [],
            'confirmed_apis': [],
            'review_apis': [],
            'not_found_apis': [],
            'business_entries': [],
        },
        'coverage': {},
    }

    findings['coverage'] = load_json(_coverage_path(d))

    # Step 2 上下文
    ctx = load_json(_context_path(d))
    findings['context'] = {
        'jdk':        f"{ctx.get('jdk_base','?')} → {ctx.get('jdk_current','?')}",
        'springboot': f"{ctx.get('springboot_base','?')} → {ctx.get('springboot_current','?')}",
        'build_tool': ctx.get('build_tool', '?'),
        'jdk_upgraded': ctx.get('jdk_upgraded', False),
        'sb_major':     ctx.get('springboot_major_upgrade', False),
        'tech_flags':   [k for k, v in ctx.get('tech_flags', {}).items() if v],
    }

    # Step 1 依赖变更统计
    dep_rows = load_csv(_dep_changes_path(d))
    dep_change_lookup = {}
    dep_counts = defaultdict(int)
    for row in dep_rows:
        dep_counts[row.get('change_type', '未知')] += 1
        coord = row.get('coord', '')
        if coord:
            dep_change_lookup[coord] = row
    findings['dep_changes_summary'] = dict(dep_counts)

    # Step 3 扫描统计
    static_dir = _static_scan_dir(d)
    for name, path in [
        ('jdk_removed_api',   static_dir / "s3_jdk_removed_api.csv"),
        ('jdk_javax_refs',    static_dir / "s3_jdk_javax_refs.csv"),
        ('jdk_internal_api',  static_dir / "s3_jdk_internal_api.csv"),
        ('jdk_reflection',    static_dir / "s3_jdk_reflection.csv"),
        ('jdk_serialization', static_dir / "s3_jdk_serialization.txt"),
        ('sb_config',         static_dir / "s3_springboot_config.csv"),
        ('sb_autoconfig',     static_dir / "s3_springboot_autoconfig.txt"),
    ]:
        findings['scan_stats'][name] = count_lines(path)

    dep_compat_rows = load_csv(static_dir / "s3_dependency_compat.csv")
    findings['scan_stats']['dep_compat'] = len(dep_compat_rows)
    if dep_compat_rows:
        by_type = defaultdict(int)
        compile_hits = 0
        by_coord = defaultdict(int)
        for row in dep_compat_rows:
            by_type[row.get('风险类型', '未知')] += 1
            by_coord[row.get('坐标', '未知依赖')] += 1
            if row.get('scope') == 'compile':
                compile_hits += 1
        findings['dep_compat_summary'] = {
            'total': len(dep_compat_rows),
            'compile_scope': compile_hits,
            'by_type': dict(sorted(by_type.items())),
            'top_coords': sorted(by_coord.items(), key=lambda x: (-x[1], x[0]))[:10],
            'top_rows': dep_compat_rows[:10],
        }

    # Step 4 jar 变更
    changed_apis = load_csv(_api_changes_dir(d) / "all_changed_apis.csv")
    findings['scan_stats']['changed_apis_total'] = len(changed_apis)
    findings['scan_stats']['changed_apis_p0'] = sum(
        1 for r in changed_apis if r.get('severity') == 'P0')
    findings['impact_overview'] = build_impact_overview(
        load_csv(_call_chain_dir(d) / "alerts.csv")
    )

    # Step 5 调用链
    call_summary = load_json(_call_chain_dir(d) / "summary.json")
    impacted_coords = set()
    if call_summary:
        if not findings.get('coverage'):
            findings['coverage'] = _step5_summary_coverage_fallback(call_summary)
        findings['user_conclusion_summary'] = dict(call_summary.get('user_conclusion_summary') or {})
        not_found_count = call_summary.get(
            'not_found_in_static_analysis',
            call_summary.get('not_reachable', 0),
        )
        findings['scan_stats']['call_chain_status'] = call_summary.get('status', 'done')
        findings['scan_stats']['call_chain_skip_reason'] = call_summary.get('skip_reason', '')
        findings['scan_stats']['call_chain_reachable']   = call_summary.get('reachable', 0)
        findings['scan_stats']['call_chain_not_impacted'] = call_summary.get('not_impacted', 0)
        findings['scan_stats']['call_chain_not_found_in_static_analysis'] = not_found_count
        findings['scan_stats']['call_chain_unreachable'] = not_found_count  # 向后兼容旧字段名
        findings['scan_stats']['call_chain_uncertain']   = call_summary.get('uncertain', 0)
        findings['scan_stats']['call_chain_not_analyzed'] = call_summary.get('not_analyzed', 0)

        for api_info in call_summary.get('not_impacted_apis', []):
            findings['not_impacted'].append({
                'coord': api_info.get('coord', ''),
                'api': api_info.get('api', ''),
                'api_signature': api_info.get('api_signature', ''),
                'symbol_kind': api_info.get('symbol_kind', ''),
                'change_type': api_info.get('change_type', ''),
                'severity': api_info.get('severity', ''),
                'call_paths': api_info.get('call_paths', []),
                'reason_code': api_info.get('reason_code', ''),
                'reason': api_info.get('reason', ''),
                'user_conclusion': api_info.get('user_conclusion', ''),
                'user_reason': api_info.get('user_reason', ''),
                'recommended_action': api_info.get('recommended_action', ''),
                'key_evidence': api_info.get('key_evidence', ''),
                'dependency_chain_coords': api_info.get('dependency_chain_coords', []),
                'evidence_paths': [],
            })

        for api_info in call_summary.get('reachable_apis', []):
            sev   = api_info.get('severity', 'P2')
            entry = {
                'coord':          api_info.get('coord', ''),
                'api':           api_info.get('api', ''),
                'api_signature': api_info.get('api_signature', ''),
                'symbol_kind':   api_info.get('symbol_kind', ''),
                'change_type':   api_info.get('change_type', ''),
                'call_paths':    api_info.get('call_paths', []),
                'reason_code':   api_info.get('reason_code', ''),
                'user_conclusion': api_info.get('user_conclusion', ''),
                'user_reason':   api_info.get('user_reason', ''),
                'recommended_action': api_info.get('recommended_action', ''),
                'key_evidence':  api_info.get('key_evidence', ''),
                'direct_callers': api_info.get('direct_callers', 0),
                'business_reach_depth': api_info.get('business_reach_depth'),
                'dependency_chain_coords': api_info.get('dependency_chain_coords', []),
                'evidence_paths': [],
            }
            by_api_path = str(_call_chain_dir(d) / 'by_api')
            if os.path.isdir(by_api_path):
                pass
            if entry['coord']:
                impacted_coords.add(entry['coord'])
            if sev == 'P0':    findings['p0'].append(entry)
            elif sev == 'P1':  findings['p1'].append(entry)
            else:              findings['p2'].append(entry)

        uncertain_reason_counts = defaultdict(int)
        for item in call_summary.get('uncertain_apis', []):
            coord = item.get('coord', '')
            if coord:
                impacted_coords.add(coord)
            reason_code = item.get('reason_code', '')
            uncertain_reason_counts[reason_code or 'UNKNOWN'] += 1
            findings['uncertain'].append({
                'coord':         coord,
                'api':          item.get('api', ''),
                'api_signature': item.get('api_signature', ''),
                'symbol_kind':  item.get('symbol_kind', ''),
                'change_type':  item.get('change_type', ''),
                'severity':     item.get('severity', ''),
                'user_conclusion': item.get('user_conclusion', ''),
                'user_reason':  item.get('user_reason', ''),
                'recommended_action': item.get('recommended_action', ''),
                'key_evidence': item.get('key_evidence', ''),
                'business_reach_depth': item.get('business_reach_depth'),
                'dependency_chain_coords': item.get('dependency_chain_coords', []),
                'reason':       item.get('reason', ''),
                'reason_code':  reason_code,
                'verification': item.get('verification', []),
                'evidence_paths': [],
            })
        findings['uncertain_reason_summary'] = dict(sorted(uncertain_reason_counts.items(), key=lambda x: (-x[1], x[0])))

        not_analyzed_reason_counts = defaultdict(int)
        for item in call_summary.get('not_analyzed_apis', []):
            coord = item.get('coord', '')
            if coord:
                impacted_coords.add(coord)
            reason_code = item.get('reason_code', '')
            not_analyzed_reason_counts[reason_code or 'UNKNOWN'] += 1
            entry = {
                'coord':         coord,
                'api':          item.get('api', ''),
                'api_signature': item.get('api_signature', ''),
                'symbol_kind':  item.get('symbol_kind', ''),
                'change_type':  item.get('change_type', ''),
                'severity':     item.get('severity', ''),
                'user_conclusion': item.get('user_conclusion', ''),
                'user_reason':  item.get('user_reason', ''),
                'recommended_action': item.get('recommended_action', ''),
                'key_evidence': item.get('key_evidence', ''),
                'business_reach_depth': item.get('business_reach_depth'),
                'dependency_chain_coords': item.get('dependency_chain_coords', []),
                'reason':       item.get('reason', ''),
                'reason_code':  reason_code,
                'verification': item.get('verification', []),
                'impact_mode':  item.get('impact_mode', ''),
                'evidence_paths': [],
            }
            findings['not_analyzed'].append(entry)
            if entry.get('user_conclusion') == '可能影响':
                findings['probable_impact'].append(entry)
            elif entry.get('user_conclusion') == '需要补充输入':
                findings['needs_input'].append(entry)
        findings['not_analyzed_reason_summary'] = dict(sorted(not_analyzed_reason_counts.items(), key=lambda x: (-x[1], x[0])))

        not_found_reason_counts = defaultdict(int)
        for item in call_summary.get('not_found_apis', []):
            coord = item.get('coord', '')
            if coord:
                impacted_coords.add(coord)
            reason_code = item.get('reason_code', '')
            not_found_reason_counts[reason_code or 'UNKNOWN'] += 1
            findings['not_found'].append({
                'coord':         coord,
                'api':          item.get('api', ''),
                'api_signature': item.get('api_signature', ''),
                'symbol_kind':  item.get('symbol_kind', ''),
                'change_type':  item.get('change_type', ''),
                'severity':     item.get('severity', ''),
                'user_conclusion': item.get('user_conclusion', ''),
                'user_reason':  item.get('user_reason', ''),
                'recommended_action': item.get('recommended_action', ''),
                'key_evidence': item.get('key_evidence', ''),
                'business_reach_depth': item.get('business_reach_depth'),
                'dependency_chain_coords': item.get('dependency_chain_coords', []),
                'reason':       item.get('reason', ''),
                'reason_code':  reason_code,
                'verification': item.get('verification', []),
                'evidence_paths': [],
            })
        findings['not_found_reason_summary'] = dict(sorted(not_found_reason_counts.items(), key=lambda x: (-x[1], x[0])))

    by_api_dir = str(_call_chain_dir(d) / 'by_api')
    by_api_lookup = {}
    if os.path.isdir(by_api_dir):
        for fname in os.listdir(by_api_dir):
            if not fname.endswith('.json'):
                continue
            payload = load_json(os.path.join(by_api_dir, fname))
            identity_key = build_api_identity_key(payload)
            if identity_key[0] and identity_key[1]:
                by_api_lookup[identity_key] = payload

    for bucket_name in ('p0', 'p1', 'p2', 'uncertain', 'not_impacted', 'not_analyzed', 'not_found'):
        for item in findings[bucket_name]:
            payload = by_api_lookup.get(build_api_identity_key(item), {})
            if payload:
                if not item.get('reason_code'):
                    item['reason_code'] = payload.get('reason_code', '')
                item['evidence_paths'] = payload.get('evidence_paths', [])
                if bucket_name not in ('uncertain', 'not_analyzed', 'not_found') and payload.get('reachable_note'):
                    item['reason'] = payload.get('reachable_note', '')

    if dep_compat_rows:
        impacted_rows = [r for r in dep_compat_rows if r.get('坐标', '') in impacted_coords]
        background_rows = [r for r in dep_compat_rows if r.get('坐标', '') not in impacted_coords]
        findings['dep_compat_summary']['impacted_total'] = len(impacted_rows)
        findings['background_signals']['dep_compat_total'] = len(background_rows)
        if impacted_rows:
            by_type = defaultdict(int)
            by_coord = defaultdict(int)
            for row in impacted_rows:
                by_type[row.get('风险类型', '未知')] += 1
                by_coord[row.get('坐标', '未知依赖')] += 1
            findings['dep_compat_summary']['impacted_by_type'] = dict(sorted(by_type.items()))
            findings['dep_compat_summary']['impacted_coords'] = sorted(
                by_coord.items(), key=lambda x: (-x[1], x[0])
            )[:10]
        if background_rows:
            bg_by_coord = defaultdict(int)
            for row in background_rows:
                bg_by_coord[row.get('坐标', '未知依赖')] += 1
            findings['background_signals']['dep_compat_top_coords'] = sorted(
                bg_by_coord.items(), key=lambda x: (-x[1], x[0])
            )[:10]

    # 按模块汇总
    module_dir = str(_call_chain_dir(d) / "by_module")
    if os.path.isdir(module_dir):
        for fname in sorted(os.listdir(module_dir)):
            if not fname.endswith('_impacts.json'):
                continue
            data = load_json(os.path.join(module_dir, fname))
            if data.get('impacts'):
                mod = data.get('module', fname.replace('_impacts.json', ''))
                findings['module_impacts'][mod] = {
                    'p0':           data.get('p0_count', 0),
                    'p1':           data.get('p1_count', 0),
                    'p2':           data.get('p2_count', 0),
                    'uncertain':    data.get('uncertain_count', 0),
                    'probable_impact': data.get('probable_impact_count', 0),
                    'needs_input':  data.get('needs_input_count', 0),
                    'not_analyzed': data.get('not_analyzed_count', 0),
                    'not_found':    data.get('not_found_in_static_analysis_count', data.get('not_found_count', 0)),
                    'impact_count': len(data.get('impacts', [])),
                }

    per_dependency_summaries = load_per_dependency_summaries(d)
    per_dependency_lookup = {}
    per_dependency_results = []
    for item in per_dependency_summaries:
        coord = str(item.get('coord', '') or '').strip()
        if not coord:
            continue
        step5 = dict(item.get('step5') or {})
        dep_row = dep_change_lookup.get(coord) or {}
        result = {
            'coord': coord,
            'change_type': str(item.get('change_type') or dep_row.get('change_type') or '').strip(),
            'old_version': str(item.get('old_version') or dep_row.get('old_version') or '').strip(),
            'new_version': str(item.get('new_version') or dep_row.get('new_version') or '').strip(),
            'reaches_system_source': bool(step5.get('reaches_system_source')),
            'final_status': str(step5.get('final_status') or step5.get('selected_status') or '').strip(),
            'blocked_at': str(step5.get('blocked_at') or '').strip(),
            'blocked_reason': str(step5.get('blocked_reason') or '').strip(),
            'evidence_level': str(step5.get('evidence_level') or '').strip(),
            'selected_api': str(step5.get('selected_api') or '').strip(),
            'step4': dict(item.get('step4') or {}),
            'step5': step5,
        }
        per_dependency_lookup[coord] = result
        per_dependency_results.append(result)

    impacted_dep_map = defaultdict(lambda: {
        'coord': '',
        'p0': 0,
        'p1': 0,
        'p2': 0,
        'uncertain': 0,
        'probable_impact': 0,
        'needs_input': 0,
        'not_analyzed': 0,
        'not_found': 0,
        'apis': set(),
        'change_type': '',
        'reaches_system_source': False,
        'final_status': '',
        'blocked_at': '',
        'blocked_reason': '',
        'evidence_level': '',
        'selected_api': '',
    })
    for sev_key, bucket in [('p0', findings['p0']), ('p1', findings['p1']), ('p2', findings['p2'])]:
        for item in bucket:
            coord = item.get('coord', '')
            if not coord:
                continue
            impacted_dep_map[coord]['coord'] = coord
            impacted_dep_map[coord][sev_key] += 1
            if item.get('api'):
                impacted_dep_map[coord]['apis'].add(item['api'])
    for item in findings['uncertain']:
        coord = item.get('coord', '')
        if not coord:
            continue
        impacted_dep_map[coord]['coord'] = coord
        impacted_dep_map[coord]['uncertain'] += 1
        if item.get('api'):
            impacted_dep_map[coord]['apis'].add(item['api'])
    for item in findings['not_analyzed']:
        coord = item.get('coord', '')
        if not coord:
            continue
        impacted_dep_map[coord]['coord'] = coord
        conclusion = item.get('user_conclusion', '')
        if conclusion == '可能影响':
            impacted_dep_map[coord]['probable_impact'] += 1
        elif conclusion == '需要补充输入':
            impacted_dep_map[coord]['needs_input'] += 1
        else:
            impacted_dep_map[coord]['not_analyzed'] += 1
        if item.get('api'):
            impacted_dep_map[coord]['apis'].add(item['api'])
    for item in findings['not_found']:
        coord = item.get('coord', '')
        if not coord:
            continue
        impacted_dep_map[coord]['coord'] = coord
        impacted_dep_map[coord]['not_found'] += 1
        if item.get('api'):
            impacted_dep_map[coord]['apis'].add(item['api'])

    impacted_dependencies = []
    for data in impacted_dep_map.values():
        per_dep = per_dependency_lookup.get(data['coord']) or {}
        dep_row = dep_change_lookup.get(data['coord']) or {}
        impacted_dependencies.append(
            {
                **data,
                'api_count': len(data['apis']),
                'apis': sorted(data['apis'])[:10],
                'change_type': per_dep.get('change_type') or dep_row.get('change_type', ''),
                'reaches_system_source': bool(per_dep.get('reaches_system_source')),
                'final_status': per_dep.get('final_status', ''),
                'blocked_at': per_dep.get('blocked_at', ''),
                'blocked_reason': per_dep.get('blocked_reason', ''),
                'evidence_level': per_dep.get('evidence_level', ''),
                'selected_api': per_dep.get('selected_api', ''),
            }
        )
    findings['impacted_dependencies'] = sorted(
        impacted_dependencies,
        key=lambda x: (
            -(x['p0'] * 100 + x['p1'] * 10 + x['p2']),
            -x['uncertain'],
            -x.get('probable_impact', 0),
            -x.get('needs_input', 0),
            -x.get('not_analyzed', 0),
            -x.get('not_found', 0),
            x['coord'],
        )
    )
    findings['per_dependency_results'] = sorted(
        per_dependency_results,
        key=lambda x: (
            0 if x.get('reaches_system_source') else 1,
            x.get('blocked_at', ''),
            x.get('coord', ''),
        ),
    )

    return findings


def _join_inline(values, limit=3, empty="-"):
    cleaned = [str(value or "").strip() for value in values or [] if str(value or "").strip()]
    if not cleaned:
        return empty
    text = "<br>".join(_md_cell(value, 180) for value in cleaned[:limit])
    if len(cleaned) > limit:
        text += f"<br>…另 {len(cleaned) - limit} 项"
    return text


def render_report_toc():
    return [
        "## 报告目录",
        "",
        "本报告主表按变更 API 展示分析结果。",
        "",
        "1. [核心结论](#一核心结论)",
        "2. [结论限制](#二结论限制)",
        "3. [分析结果总表](#三分析结果总表)",
        "4. [附录](#四附录)",
        "",
        "> 关键证据在主表中展示；完整逐链路台账以 `evidence/call_chain/alerts.csv` 为准。",
        "",
    ]


def _status_label_from_item(item):
    conclusion = str(item.get('user_conclusion') or '').strip()
    if conclusion:
        return conclusion
    bucket = str(item.get('bucket') or '').strip()
    if bucket == 'confirmed':
        return '已确认影响'
    if bucket == 'review':
        return '需人工复核'
    if bucket == 'not_impacted':
        return '已确认不受影响'
    if bucket == 'not_found':
        return '未发现调用路径'
    return '待确认'


DISPLAY_LABELS = {
    '当前无法确认': '需人工复核',
    '需要人工复核': '需人工复核',
    '需要补充输入': '缺少依赖源码/构建产物',
    '未覆盖/未分析': '本次未完成分析',
    '静态未找到': '未发现调用路径',
}


def _display_label(text):
    value = str(text or '').strip()
    if not value:
        return value
    parts = [part.strip() for part in value.split('；')]
    mapped = []
    for part in parts:
        if not part:
            continue
        label = DISPLAY_LABELS.get(part, part)
        if label not in mapped:
            mapped.append(label)
    return '；'.join(mapped)


def _coverage_status_label(status):
    labels = {
        'complete': '完整',
        'partial': '部分完整',
        'insufficient': '不足',
        'not_applicable': '不适用',
        'unknown': '未知',
    }
    return labels.get(str(status or 'unknown'), str(status or 'unknown'))


def _call_chain_status_label(status):
    labels = {
        'done': '已完成',
        'completed': '已完成',
        'complete': '已完成',
        'partial': '部分完成',
        'skipped': '未执行',
        'not_run': '未执行',
        'failed': '执行失败',
        'unknown': '未知',
    }
    return labels.get(str(status or 'unknown').strip() or 'unknown', '未知')


def _coverage_item_label(component_id):
    component_id = str(component_id or '').strip()
    labels = {
        'project_scope': '分析范围',
        'dependency_diff': '依赖变更识别',
        'build_provenance': '构建产物来源',
        'binary_api_diff': '二进制 API 对比',
        'artifact_bytecode_dependencies': '制品内依赖字节码',
        'source_artifact_alignment': '源码与制品一致性',
        'indirect_usage_matrix': '动态调用可能漏报',
        'business_reachability': '业务调用链回溯',
        'business_bytecode_graph': '业务字节码调用图',
        'static_scan': '静态扫描',
    }
    if component_id.startswith('framework_adapter:'):
        return '框架适配器'
    return labels.get(component_id, component_id.replace('_', ' ') or '未知检查项')


def _coverage_impact_text(component_id, reason_codes):
    component_id = str(component_id or '').strip()
    reasons = set(reason_codes or [])
    reason_texts = {
        'dependency_pairing_ambiguous': '依赖升级前后坐标匹配存在歧义。',
        'dependency_coordinates_unresolved': '部分依赖坐标未解析。',
        'artifact_hash_missing': '构建产物缺少哈希，无法确认输入制品是否稳定。',
        'base_or_current_build_not_succeeded': '升级前或升级后构建产物不完整。',
        'step4_coverage_missing': '缺少 API 对比覆盖记录。',
        'dependency_source_diff_not_available': '缺少依赖源码 diff，行为变化可能不完整。',
        'compiled_business_classes_not_available': '缺少业务编译产物，字节码调用补充分析不完整。',
        'step5_not_analyzed_targets': '部分变更 API 没有完成调用链分析。',
        'step5_target_count_mismatch': 'Step5 目标 API 数和结果数不一致。',
        'source_alignment_invalid': '源码与实际制品不一致，调用链需要复核。',
        's5_artifact_bytecode_catalog_missing': '缺少制品内依赖字节码清单。',
        'indirect_usage_coverage_missing': '反射、配置或间接调用可能漏报。',
        'reflection_source_partial': '反射调用可能漏报。',
    }
    known = [reason_texts[item] for item in sorted(reasons) if item in reason_texts]
    if known:
        return ' '.join(known)
    fallback = {
        'project_scope': '分析范围不完整，报告可能漏掉部分模块。',
        'dependency_diff': '依赖变更识别不完整，报告可能漏掉部分依赖变化。',
        'build_provenance': '构建产物来源不完整，结果可复现性不足。',
        'binary_api_diff': 'API 对比不完整，报告可能漏掉部分破坏性 API 变化。',
        'artifact_bytecode_dependencies': '制品内依赖分析不完整，运行时依赖链路可能不完整。',
        'source_artifact_alignment': '源码与实际制品不一致，调用链需要复核。',
        'indirect_usage_matrix': '动态调用可能漏报。',
        'business_reachability': '业务调用链回溯不完整，部分 API 影响无法确认。',
        'business_bytecode_graph': '业务字节码调用图不完整，补充调用证据可能缺失。',
        'static_scan': '静态扫描不完整，背景风险线索可能缺失。',
    }
    return fallback.get(component_id, '该检查项不完整，相关结论需要复核。')


def _coverage_component_lookup(coverage):
    return {
        str(item.get('id') or ''): item
        for item in (coverage.get('components') or [])
        if item.get('id')
    }


def _coverage_gap_rows(coverage):
    component_lookup = _coverage_component_lookup(coverage)
    rows = []
    for component_id in coverage.get('critical_incomplete') or []:
        component = component_lookup.get(str(component_id)) or {
            'id': component_id,
            'status': coverage.get('overall_status') or 'unknown',
            'reason_codes': [],
            'evidence': [],
        }
        rows.append({
            'label': _coverage_item_label(component.get('id')),
            'status': _coverage_status_label(component.get('status')),
            'impact': _coverage_impact_text(component.get('id'), component.get('reason_codes') or []),
            'evidence': component.get('evidence') or [],
        })
    return rows


def render_core_conclusion(findings):
    stat = findings.get('scan_stats') or {}
    coverage = findings.get('coverage') or {}
    p0 = findings.get('p0') or []
    p1 = findings.get('p1') or []
    p2 = findings.get('p2') or []
    uncertain = findings.get('uncertain') or []
    probable = findings.get('probable_impact') or []
    needs_input = findings.get('needs_input') or []
    not_analyzed = [
        item for item in findings.get('not_analyzed') or []
        if item.get('user_conclusion') not in {'可能影响', '需要补充输入'}
    ]
    not_found = findings.get('not_found') or []
    not_impacted = findings.get('not_impacted') or []
    confirmed_count = len(p0) + len(p1) + len(p2)
    if confirmed_count:
        verdict = f"发现 {confirmed_count} 个已确认/高风险影响项。"
    elif probable or uncertain or needs_input or not_analyzed:
        verdict = "本次报告未确认任何已影响当前系统的变更 API。仍有条目需要复核或补齐依赖源码/构建产物。"
    elif not_impacted and not (probable or uncertain or needs_input or not_analyzed or not_found):
        verdict = f"Step4 识别的 {len(not_impacted)} 个变更 API 均已确认仍由当前制品以相同字节码提供。"
    elif not_found:
        verdict = "未发现业务调用路径。"
    else:
        verdict = "当前报告范围内未发现影响项。"
    lines = [
        "## 一、核心结论",
        "",
        f"**一句话结论：{verdict}**",
        "",
        "| 项目 | 结果 |",
        "|---|---|",
        f"| 调用链分析状态 | {_call_chain_status_label(stat.get('call_chain_status'))} |",
        f"| 已确认/高风险影响项 | {confirmed_count} |",
        f"| 已确认不受影响 | {len(not_impacted)} |",
        f"| 可能影响 | {len(probable)} |",
        f"| 需人工复核 | {len(uncertain)} |",
        f"| 缺少依赖源码/构建产物 | {len(needs_input)} |",
        f"| 本次未完成分析 | {len(not_analyzed)} |",
        f"| 未发现调用路径 | {len(not_found)} |",
        f"| 分析完整度 | {'API 范围内完整' if not_impacted and len(not_impacted) == int(stat.get('call_chain_total') or len(not_impacted)) else _coverage_status_label(coverage.get('overall_status'))} |",
        "",
    ]
    return lines


def _identity_without_severity(item):
    return (
        str(item.get('coord', '') or '').strip(),
        str(item.get('api', '') or item.get('api_name', '') or '').strip(),
        str(item.get('api_signature', '') or '').strip(),
        str(item.get('symbol_kind', '') or '').strip(),
        str(item.get('change_type', '') or '').strip(),
    )


def _change_cell(item, severity=''):
    return _md_cell(_change_summary(item, severity), 220)


def _conclusion_for_report(item, fallback):
    conclusion = str(item.get('user_conclusion') or '').strip()
    if fallback == '已确认/高风险影响' and conclusion == '已确认影响':
        return conclusion
    if conclusion and fallback and fallback != conclusion:
        return _display_label(f"{fallback}；{conclusion}")
    if conclusion:
        return _display_label(conclusion)
    return _display_label(fallback)


def _paths_for_report(item, overview_lookup, desired_statuses=None):
    paths = []
    identity = _identity_without_severity(item)
    overview_found = identity in overview_lookup
    overview = overview_lookup.get(identity) or {}
    overview_paths = []
    paths_by_status = overview.get('paths_by_status') or {}
    for status in desired_statuses or []:
        overview_paths.extend(paths_by_status.get(status) or [])
    if not overview_paths and not desired_statuses:
        overview_paths = overview.get('paths') or overview.get('sample_paths') or []
    for path in overview_paths:
        text = str(path or '').strip()
        if text and text not in paths:
            paths.append(text)
    # alerts.csv keeps paths partitioned by path_status. Summary call_paths may
    # mix reachable and uncertain evidence, so it is only a fallback when the
    # exact-identity overview has no path for the requested status.
    if not paths and not overview_found:
        for path in item.get('call_paths') or []:
            text = str(path or '').strip()
            if text and text not in paths:
                paths.append(text)
    if not paths:
        for evidence_path in item.get('evidence_paths') or []:
            edge_texts = []
            for edge in evidence_path or []:
                caller = str(edge.get('caller_symbol') or '').strip()
                callee = str(edge.get('callee_key') or '').strip()
                if caller and callee:
                    edge_texts.append(f"{caller} → {callee}")
            if edge_texts:
                candidate = " → ".join(edge_texts)
                if candidate not in paths:
                    paths.append(candidate)
    return paths[:5]


def _path_count_for_report(item, overview_lookup, sampled_paths, desired_statuses=None):
    overview = overview_lookup.get(_identity_without_severity(item)) or {}
    if desired_statuses:
        counts = overview.get('path_counts_by_status') or {}
        raw_count = sum(int(counts.get(status) or 0) for status in desired_statuses)
    else:
        raw_count = overview.get('path_count')
    try:
        count = int(raw_count)
    except (TypeError, ValueError):
        count = 0
    return max(count, len(sampled_paths or []))


def _evidence_anchor(api_id):
    normalized = re.sub(
        r"[^a-z0-9_-]+",
        "-",
        str(api_id or "").strip().lower(),
    ).strip("-")
    return f"api-{normalized}" if normalized else ""


def _linked_evidence_text(row, text, link_label):
    anchor = _evidence_anchor(row.get('api_id'))
    if not anchor:
        return text
    return f"[{text}。{link_label}](#{anchor})"


def _evidence_summary_text(row):
    paths = row.get('paths') or []
    if paths:
        preserved = str(row.get('conclusion') or '') == '已确认不受影响'
        if row.get('confirmed_path_count'):
            text = f"已确认链路 {int(row.get('confirmed_path_count') or 0)} 条"
            uncertain_count = int(row.get('uncertain_path_count') or 0)
            not_analyzed_count = int(row.get('not_analyzed_path_count') or 0)
            if uncertain_count:
                text += f"；另有 {uncertain_count} 条依赖引用尚未回溯到业务入口"
            if not_analyzed_count:
                text += f"；另有 {not_analyzed_count} 条证据未完成分析"
            return _linked_evidence_text(row, text, '查看具体链路')
        evidence_label = '符号保留证据' if preserved else '调用链证据'
        path_count = int(row.get('path_count') or len(paths))
        if preserved:
            text = f"发现 {path_count} 条{evidence_label}"
            return _linked_evidence_text(row, text, '查看具体证据')
        if 'not_analyzed' in set(row.get('evidence_statuses') or []):
            text = f"发现 {path_count} 条分析证据，但本项未完成有效分析"
            return _linked_evidence_text(row, text, '查看证据详情')
        text = f"发现 {path_count} 条依赖引用，尚未回溯到业务入口"
        return _linked_evidence_text(row, text, '查看引用详情')
    reason = _human_reason(row.get('reason'))
    return reason or "-"


def _render_path_sample_cards(rows):
    cards = []
    for idx, row in enumerate(rows, 1):
        paths = row.get('paths') or []
        uncertain_paths = row.get('uncertain_paths') or []
        not_analyzed_paths = row.get('not_analyzed_paths') or []
        if not paths and not uncertain_paths and not not_analyzed_paths:
            continue
        path_count = int(row.get('path_count') or len(paths))
        confirmed_count = int(row.get('confirmed_path_count') or 0)
        uncertain_count = int(row.get('uncertain_path_count') or 0)
        not_analyzed_count = int(row.get('not_analyzed_path_count') or 0)
        preserved = str(row.get('conclusion') or '') == '已确认不受影响'
        api_id = str(row.get('api_id') or '').strip()
        anchor = _evidence_anchor(api_id)
        if anchor:
            cards += [f'<a id="{anchor}"></a>', ""]
        cards += [
            f"#### {idx}. `{_md_cell(row.get('api'), 220)}` 的证据",
            "",
            f"- **依赖坐标**：`{_md_cell(row.get('coord'), 180)}`",
            f"- **变化**：{row.get('change') or '-'}",
            f"- **结论**：{_md_cell(row.get('conclusion'), 160)}",
        ]
        if api_id:
            cards.append(f"- **API 编号**：`{_md_cell(api_id, 160)}`")
        if confirmed_count:
            count_text = f"- **证据数量**：已确认链路 {confirmed_count} 条"
            if uncertain_count:
                count_text += f"；另有 {uncertain_count} 条依赖引用尚未回溯到业务入口"
            if not_analyzed_count:
                count_text += f"；另有 {not_analyzed_count} 条证据未完成分析"
            cards.append(count_text)
            cards += [
                "",
                f"**已确认链路（当前展示 {len(paths)} 条，共 {confirmed_count} 条）**：",
                "",
            ]
            for path in paths:
                cards.append(f"- `{_md_cell(path, 320)}`")
            if uncertain_count:
                cards += [
                    "",
                    f"**尚未回溯到业务入口的依赖引用（当前展示 {len(uncertain_paths)} 条，共 {uncertain_count} 条）**：",
                    "",
                ]
                for path in uncertain_paths:
                    cards.append(f"- `{_md_cell(path, 320)}`")
            if not_analyzed_count:
                cards += [
                    "",
                    f"**未完成有效分析的证据（当前展示 {len(not_analyzed_paths)} 条，共 {not_analyzed_count} 条）**：",
                    "",
                ]
                for path in not_analyzed_paths:
                    cards.append(f"- `{_md_cell(path, 320)}`")
        else:
            statuses = set(row.get('evidence_statuses') or [])
            if preserved:
                evidence_label = '符号保留证据'
            elif 'not_analyzed' in statuses:
                evidence_label = '未完成有效分析的证据'
            else:
                evidence_label = '依赖引用'
            cards += [
                f"- **证据数量**：{path_count} 条",
                "",
                f"**{evidence_label}（当前展示 {len(paths)} 条，共 {path_count} 条）**：",
                "",
            ]
            for path in paths:
                cards.append(f"- `{_md_cell(path, 320)}`")
        if api_id:
            cards += [
                "",
                (
                    "完整证据：打开 `evidence/call_chain/alerts.csv`，"
                    f"筛选 `api_id = {_md_cell(api_id, 160)}`。"
                ),
            ]
            status_filters = []
            if confirmed_count:
                status_filters.append("`path_status = reachable` 是已确认链路")
            if uncertain_count or (
                not confirmed_count
                and not preserved
                and 'uncertain' in set(row.get('evidence_statuses') or [])
            ):
                status_filters.append(
                    "`path_status = uncertain` 是尚未回溯到业务入口的依赖引用"
                )
            if not_analyzed_count or (
                not confirmed_count
                and 'not_analyzed' in set(row.get('evidence_statuses') or [])
            ):
                status_filters.append(
                    "`path_status = not_analyzed` 是本次未完成有效分析的证据"
                )
            if status_filters:
                cards.append("；".join(status_filters) + "。")
        cards.append("")
    if not cards:
        return []
    has_symbol_evidence = any(row.get('conclusion') == '已确认不受影响' and row.get('paths') for row in rows)
    has_call_chain = any(row.get('conclusion') != '已确认不受影响' and row.get('paths') for row in rows)
    if has_call_chain and has_symbol_evidence:
        title = '调用链与符号保留证据'
        intro = '下面展示主表中的调用链和符号保留证据。'
    elif has_symbol_evidence:
        title = '符号保留证据'
        intro = '下面展示变更 API 仍由当前制品以相同字节码提供的证据。'
    else:
        title = '调用链证据'
        intro = '下面按 API 展示主表中的调用链证据。'
    return [
        f"### 3.1 {title}",
        "",
        f"{intro}完整证据台账以 `evidence/call_chain/alerts.csv` 为准。",
        "",
    ] + cards


def _human_reason(value):
    text = str(value or '').strip()
    if not text:
        return ''
    labels = {
        'NO_STATIC_PATH': '当前源码中未找到调用路径。',
        'NOT_FOUND_IN_STATIC_ANALYSIS': '当前源码中未找到调用路径。',
        'NO_CLASS_REFERENCE': '当前源码中未找到目标类引用。',
        'DEPENDENCY_SOURCE_MAPPING_MISSING': '缺少依赖源码，跨依赖调用链未完整回溯。',
        'MISSING_DEPENDENCY_SOURCE_MAPPING': '缺少依赖源码，跨依赖调用链未完整回溯。',
        'RESOURCE_OR_REFLECTION': '涉及资源配置或反射调用，静态分析无法确认实际调用目标。',
        'UNCERTAIN_DYNAMIC_PROXY_CALL': '存在动态代理调用，静态分析无法确认实际实现。',
        'BYTECODE_HIT_BUSINESS_ENTRY_NOT_CONFIRMED': '字节码发现候选入口，但还没有证明当前系统代码会调用到该 API。',
        'BEHAVIOR_CHANGED_RUNTIME_VERIFICATION': '行为变化需要运行时验证。',
        'BEHAVIOR_CHANGED_PRECISE_TARGET_NOT_CONFIRMED': '行为变化目标未精确确认。',
        'OVERLOAD_AMBIGUOUS_TARGET': '重载方法目标存在歧义。',
        'OVERLOAD_AMBIGUOUS_INTERMEDIATE': '中间调用存在重载歧义。',
        'LOW_CONFIDENCE_EDGE': '调用边置信度较低，需要复核。',
        'CALL_GRAPH_LIMITATION_SYMBOL_KIND': '当前符号类型的调用图识别不完整。',
        'ANALYSIS_INCOMPLETE': '分析未完整完成。',
        'RUNTIME_DEPENDENCY_USES_REMOVED_API': '运行时依赖可能使用已移除 API。',
        'PACKAGED_DEPENDENCY_BYTECODE_USAGE': '制品内依赖字节码命中该 API。',
        'BUSINESS_ARTIFACT_BYTECODE_USAGE': '业务制品字节码命中该 API。',
    }
    return labels.get(text, text.replace('_', ' ').strip().capitalize() if text.isupper() else text)


def build_api_result_rows(findings):
    overview_lookup = {
        _identity_without_severity(item): item
        for item in ((findings.get('impact_overview') or {}).get('apis') or [])
    }
    source_buckets = [
        ('已确认/高风险影响', 'P0', findings.get('p0') or []),
        ('已确认/高风险影响', 'P1', findings.get('p1') or []),
        ('已确认/高风险影响', 'P2', findings.get('p2') or []),
        ('可能影响', '', findings.get('probable_impact') or []),
        ('需人工复核', '', findings.get('uncertain') or []),
        ('已确认不受影响', '', findings.get('not_impacted') or []),
        ('缺少依赖源码/构建产物', '', findings.get('needs_input') or []),
        (
            '本次未完成分析',
            '',
            [
                item for item in (findings.get('not_analyzed') or [])
                if item.get('user_conclusion') not in {'可能影响', '需要补充输入'}
            ],
        ),
        ('未发现调用路径', '', findings.get('not_found') or []),
    ]
    rows = []
    seen = set()
    for fallback_conclusion, severity, items in source_buckets:
        desired_statuses = {
            '已确认/高风险影响': ('reachable',),
            '可能影响': ('not_analyzed',),
            '需人工复核': ('uncertain',),
            '已确认不受影响': ('not_impacted',),
            '缺少依赖源码/构建产物': ('not_analyzed',),
            '本次未完成分析': ('not_analyzed',),
            '未发现调用路径': ('not_found_in_static_analysis', 'not_reachable'),
        }.get(fallback_conclusion, ())
        for item in items:
            key = (_identity_without_severity(item), fallback_conclusion, severity)
            if key in seen:
                continue
            seen.add(key)
            sampled_paths = _paths_for_report(item, overview_lookup, desired_statuses)
            overview = overview_lookup.get(_identity_without_severity(item)) or {}
            counts_by_status = overview.get('path_counts_by_status') or {}
            confirmed_path_count = int(counts_by_status.get('reachable') or 0)
            additional_review_path_count = sum(
                int(counts_by_status.get(status) or 0)
                for status in ('uncertain', 'not_analyzed')
            ) if fallback_conclusion == '已确认/高风险影响' else 0
            uncertain_path_count = int(counts_by_status.get('uncertain') or 0)
            not_analyzed_path_count = int(counts_by_status.get('not_analyzed') or 0)
            paths_by_status = overview.get('paths_by_status') or {}
            uncertain_paths = list(paths_by_status.get('uncertain') or [])[:5]
            not_analyzed_paths = list(paths_by_status.get('not_analyzed') or [])[:5]
            rows.append({
                'api_id': str(overview.get('api_id') or '').strip(),
                'coord': item.get('coord', ''),
                'api': item.get('api', '') or item.get('api_name', ''),
                'change': _change_cell(item, severity),
                'conclusion': _conclusion_for_report(item, fallback_conclusion),
                'paths': sampled_paths,
                'uncertain_paths': uncertain_paths,
                'not_analyzed_paths': not_analyzed_paths,
                'evidence_statuses': list(desired_statuses),
                'path_count': _path_count_for_report(
                    item, overview_lookup, sampled_paths, desired_statuses
                ),
                'confirmed_path_count': confirmed_path_count if fallback_conclusion == '已确认/高风险影响' else 0,
                'additional_review_path_count': additional_review_path_count,
                'uncertain_path_count': uncertain_path_count,
                'not_analyzed_path_count': not_analyzed_path_count,
                'reason': item.get('user_reason') or item.get('reason') or item.get('reason_code') or '',
            })
    return rows


def render_api_result_table(findings):
    rows = build_api_result_rows(findings)
    lines = [
        "## 三、分析结果总表",
        "",
    ]
    if not rows:
        lines += ["✅ 当前没有可展示的变更 API 分析结果。", ""]
        return lines
    displayed = []
    skipped_by_conclusion = {}
    shown_by_conclusion = {}
    for row in rows:
        conclusion = str(row.get('conclusion') or '未分类')
        shown = shown_by_conclusion.get(conclusion, 0)
        if shown >= S6_INLINE_LIMIT:
            skipped_by_conclusion[conclusion] = skipped_by_conclusion.get(conclusion, 0) + 1
            continue
        shown_by_conclusion[conclusion] = shown + 1
        displayed.append(row)

    omitted_count = len(rows) - len(displayed)
    lines += [
        f"> 本表共有 {len(rows)} 条 API 分析结果，当前展示 {len(displayed)} 条，省略 {omitted_count} 条；"
        "完整逐链路台账见 `evidence/call_chain/alerts.csv`。",
    ]
    detail_rows = available_s6_detail_artifacts(findings)
    if detail_rows:
        detail_paths = "、".join(f"`{row['path']}`" for row in detail_rows)
        lines.append(f"> 本轮已生成的分类明细：{detail_paths}。")
    lines += [
        "> 排序：已确认/高风险、可能影响、需人工复核、已确认不受影响、缺少依赖源码/构建产物、本次未完成分析、未发现调用路径。",
        "",
        "| 依赖坐标 | 变更 API | 变化 | 结论 | 证据摘要 / 未确认原因 |",
        "|---|---|---|---|---|",
    ]

    for row in displayed:
        lines.append(
            f"| `{_md_cell(row.get('coord'), 180)}` | `{_md_cell(row.get('api'), 220)}` | "
            f"{row.get('change') or '-'} | {_md_cell(row.get('conclusion'), 160)} | "
            f"{_md_cell(_evidence_summary_text(row), 500)} |"
        )
    if skipped_by_conclusion:
        skipped = "；".join(f"{name} 省略 {count} 条" for name, count in skipped_by_conclusion.items())
        lines += [
            "",
            f"> 主报告按结论类型各展示前 {S6_INLINE_LIMIT} 条，{skipped}。",
        ]
    lines.append("")
    lines += _render_path_sample_cards(displayed)
    return lines


def render_limitations_section(findings):
    coverage = findings.get('coverage') or {}
    gap_rows = _coverage_gap_rows(coverage)
    not_impacted = findings.get('not_impacted') or []
    if not_impacted:
        gap_rows.append({
            'label': '已确认不受影响的范围',
            'status': 'scope_boundary',
            'impact': (
                '该结论只表示 Step4 识别的 API 仍由当前制品以相同类字节码提供；'
                '不包含被删除 JAR 中的 SPI 配置、资源文件、清单等非 API 内容。'
            ),
            'evidence': ['evidence/call_chain/alerts.csv'],
        })
    lines = [
        "## 二、结论限制", "",
    ]
    if gap_rows:
        lines += [
            "| 限制项 | 对结论的影响 | 证据文件 |",
            "|---|---|---|",
        ]
        for row in gap_rows:
            evidence = _join_inline(row.get('evidence'), limit=3) or "-"
            lines.append(
                f"| {_md_cell(row.get('label'), 120)} | {_md_cell(row.get('impact'), 260)} | {evidence} |"
            )
        lines.append("")
    else:
        lines += ["- 未发现影响结论的关键限制。", ""]
    return lines


def render_report_appendix(findings):
    lines = [
        "## 四、附录", "",
    ]
    lines += [
        "### 运行产物阅读分层", "",
        "#### 给用户看的产物", "",
        "| 文件 | 承载的信息 |",
        "|---|---|",
        "| `deliverables/report.md` | 最终报告；优先阅读这一份 |",
    ]
    for row in available_s6_detail_artifacts(findings):
        lines.append(f"| `{row['path']}` | {row['title']} |")
    lines += [
        "",
        "#### 用户深入排查时看的产物", "",
        "| 文件 | 承载的信息 |",
        "|---|---|",
        "| `evidence/dependencies/dep_changes.csv` | 依赖包变更列表 |",
        "| `evidence/api_changes/changed_dependencies.md` | 依赖包维度的 Step4 变化摘要；用于选择 Step5 分析范围 |",
        "| `evidence/api_changes/changed_dependencies.csv` | 依赖包维度的结构化清单；供筛选和自动化使用 |",
        "| `evidence/api_changes/all_changed_apis.csv` | 依赖 API 变化全集 |",
        f"| `evidence/api_changes/all_changed_apis_part_*.csv` | 依赖 API 变化拆分文件（每 {S6_CHANGED_API_SPLIT_ROWS} 条一份） |",
        "| `evidence/call_chain/alerts.csv` | 完整逐链路台账 |",
        "| `evidence/call_chain/alerts_<status>.csv` / `alerts_<status>_NNN.csv` | 按链路状态拆分的台账 |",
        "| `evidence/call_chain/by_api/*.json` | 单 API 原始链路证据；排查时按需读取 |",
        "| `evidence/static_scan/s3_*.csv/.txt` | JDK、Spring Boot、反射等静态扫描命中 |",
        "",
        "#### 程序使用的产物", "",
        "| 文件 | 承载的信息 |",
        "|---|---|",
        "| `.runtime/state/main_state.json` | 流程状态；用于恢复、重跑和 checkpoint 判断 |",
        "| `.runtime/state/interaction.json` | 当前等待用户确认的问题和选项 |",
        "| `.runtime/coverage/coverage.json` / `.runtime/coverage/s*_coverage.json` | 各步骤覆盖情况；用于判断结论限制 |",
        "| `.runtime/findings/s6_findings.json` | Step6 结构化结果；供程序读取，不作为人工优先阅读文件 |",
        "| `.runtime/indexes/s5_query_index.json` | 调用链查询索引；供只读查询命令使用 |",
        "",
    ]
    return lines


def build_report_sections_for_test_only():
    return [
        "核心结论",
        "结论限制",
        "分析结果总表",
        "附录",
        "本报告只呈现分析结果、证据和结论限制，不替使用者决定修改、验证或发布动作。",
        *render_report_appendix({}),
    ]


def generate_report(findings):
    ctx  = findings['context']

    L = [
        "# Java 升级兼容性分析报告", "",
        f"> 生成时间：{findings['generated_at']}  ",
        f"> JDK：{ctx.get('jdk','')} | Spring Boot：{ctx.get('springboot','')}  ",
        "> **本报告只描述问题，不提供修复方案**",
        "", "---", "",
    ]

    L += render_report_toc()
    L += ["---", ""]
    L += render_core_conclusion(findings)
    L += ["---", ""]
    L += render_limitations_section(findings)
    L += ["---", ""]
    L += render_api_result_table(findings)
    L += ["---", ""]
    L += render_report_appendix(findings)

    return '\n'.join(L)


def _fmt_issue(item):
    lines = [f"#### `{item.get('api','')}`", "",
             f"- **依赖坐标**：`{item.get('coord','?')}`",
             f"- **变化**：{_change_summary(item)}",
             f"- **业务直接命中**：{item.get('direct_callers',0)} 处"]
    if item.get('user_conclusion'):
        lines.append(f"- **结论**：{item.get('user_conclusion')}")
    if item.get('user_reason') or item.get('reason'):
        lines.append(f"- **说明**：{item.get('user_reason') or item.get('reason')}")
    if item.get('key_evidence'):
        lines.append(f"- **关键证据**：`{item.get('key_evidence')}`")
    if item.get('business_reach_depth'):
        lines.append(f"- **到达业务源码跳数**：第 {item.get('business_reach_depth')} 跳")
    if item.get('dependency_chain_coords'):
        lines.append(f"- **跨依赖链路**：`{' -> '.join(item.get('dependency_chain_coords', []))}`")
    for path in item.get('call_paths', [])[:3]:
        lines.append(f"- **调用路径**：`{path}`")
    evidence_paths = item.get('evidence_paths', []) or []
    if evidence_paths:
        first_path = evidence_paths[0]
        if first_path:
            lines.append("- **证据边**：")
            for edge in first_path[:5]:
                lines.append(
                    f"  - `{edge.get('caller_symbol','?')}` -> `{edge.get('callee_key','?')}` "
                    f"({edge.get('evidence_type','')}, {edge.get('confidence','')}) "
                    f"`{Path(edge.get('file','?')).name}:{edge.get('line','?')}`"
                )
    lines.append("")
    return lines


def main():
    ap = argparse.ArgumentParser(description='Step 6：汇总报告')
    ap.add_argument('--report-dir',      required=True)
    ap.add_argument('--output-findings', required=True)
    ap.add_argument('--output-report',   required=True)
    args = ap.parse_args()

    print("\nStep 6：生成报告...", file=sys.stderr)
    findings = collect_findings(args.report_dir)
    findings.setdefault('artifacts', {})
    findings['artifacts'].update(write_s6_detail_artifacts(args.report_dir, findings))

    Path(args.output_findings).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output_findings, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    write_text(args.output_report, generate_report(findings))

    p0, p1, p2, unk, na, nf = (len(findings[k]) for k in ('p0', 'p1', 'p2', 'uncertain', 'not_analyzed', 'not_found'))
    print(f"  P0={p0} P1={p1} P2={p2} ❓={unk} ⊘={na} ✗={nf}", file=sys.stderr)
    print(f"  findings → {args.output_findings}", file=sys.stderr)
    print(f"  report   → {args.output_report}",   file=sys.stderr)
    for key in sorted(findings.get('artifacts', {})):
        if key.endswith('_csv'):
            print(f"  {key} → {Path(args.report_dir) / findings['artifacts'][key]}", file=sys.stderr)


if __name__ == '__main__':
    main()
