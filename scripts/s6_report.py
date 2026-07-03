#!/usr/bin/env python3
"""
s6_report.py — Step 6：汇总报告

读取所有前序步骤的产出，生成结构化报告。
只描述问题，不提供修复方案。

用法：
  python s6_report.py \
    --report-dir .upgrade-report \
    --output-findings .upgrade-report/s6_findings.json \
    --output-report   .upgrade-report/s6_report.md
"""

import argparse, csv, json, os, sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent))
from compat import open_text, write_text
from pipeline_constants import PER_DEPENDENCY_DIRNAME, PER_DEPENDENCY_SUMMARY_FILE


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


def load_per_dependency_summaries(report_dir):
    per_dependency_root = Path(report_dir) / PER_DEPENDENCY_DIRNAME
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


def collect_findings(d):
    findings = {
        'meta': {
            'read_order': [
                's6_report.md（主报告，先看 P0/P1/❓）',
                's5_call_chain/summary.json（reachable / uncertain 证据）',
                's5_call_chain/by_api/*.json（真实 evidence_paths 与 reason_code）',
                's4_jar_compare/all_changed_apis.csv（反向调用链输入变更集）',
                's3_*.csv/.txt（背景信号，用于补充排查方向）',
            ],
            'sampling_guide': [
                '从 P0/P1 各抽 3 条：沿 call_paths 打开源码核对调用关系',
                '对 uncertain 至少抽 3 条：先看 reason_code，再看 verification 与 by_api/*.json 的 evidence_paths',
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
        'coverage': {},
    }

    findings['coverage'] = load_json(f"{d}/coverage.json")

    # Step 2 上下文
    ctx = load_json(f"{d}/s2_context.json")
    findings['context'] = {
        'jdk':        f"{ctx.get('jdk_base','?')} → {ctx.get('jdk_current','?')}",
        'springboot': f"{ctx.get('springboot_base','?')} → {ctx.get('springboot_current','?')}",
        'build_tool': ctx.get('build_tool', '?'),
        'jdk_upgraded': ctx.get('jdk_upgraded', False),
        'sb_major':     ctx.get('springboot_major_upgrade', False),
        'tech_flags':   [k for k, v in ctx.get('tech_flags', {}).items() if v],
    }

    # Step 1 依赖变更统计
    dep_rows = load_csv(f"{d}/s1_dep_changes.csv")
    dep_change_lookup = {}
    dep_counts = defaultdict(int)
    for row in dep_rows:
        dep_counts[row.get('change_type', '未知')] += 1
        coord = row.get('coord', '')
        if coord:
            dep_change_lookup[coord] = row
    findings['dep_changes_summary'] = dict(dep_counts)

    # Step 3 扫描统计
    for name, path in [
        ('jdk_removed_api',   f"{d}/s3_jdk_removed_api.csv"),
        ('jdk_javax_refs',    f"{d}/s3_jdk_javax_refs.csv"),
        ('jdk_internal_api',  f"{d}/s3_jdk_internal_api.csv"),
        ('jdk_reflection',    f"{d}/s3_jdk_reflection.csv"),
        ('jdk_serialization', f"{d}/s3_jdk_serialization.txt"),
        ('sb_config',         f"{d}/s3_springboot_config.csv"),
        ('sb_autoconfig',     f"{d}/s3_springboot_autoconfig.txt"),
    ]:
        findings['scan_stats'][name] = count_lines(path)

    dep_compat_rows = load_csv(f"{d}/s3_dependency_compat.csv")
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
    changed_apis = load_csv(f"{d}/s4_jar_compare/all_changed_apis.csv")
    findings['scan_stats']['changed_apis_total'] = len(changed_apis)
    findings['scan_stats']['changed_apis_p0'] = sum(
        1 for r in changed_apis if r.get('severity') == 'P0')

    # Step 5 调用链
    call_summary = load_json(f"{d}/s5_call_chain/summary.json")
    impacted_coords = set()
    if call_summary:
        findings['user_conclusion_summary'] = dict(call_summary.get('user_conclusion_summary') or {})
        not_found_count = call_summary.get(
            'not_found_in_static_analysis',
            call_summary.get('not_reachable', 0),
        )
        findings['scan_stats']['call_chain_status'] = call_summary.get('status', 'done')
        findings['scan_stats']['call_chain_skip_reason'] = call_summary.get('skip_reason', '')
        findings['scan_stats']['call_chain_reachable']   = call_summary.get('reachable', 0)
        findings['scan_stats']['call_chain_not_found_in_static_analysis'] = not_found_count
        findings['scan_stats']['call_chain_unreachable'] = not_found_count  # 向后兼容旧字段名
        findings['scan_stats']['call_chain_uncertain']   = call_summary.get('uncertain', 0)
        findings['scan_stats']['call_chain_not_analyzed'] = call_summary.get('not_analyzed', 0)

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
            by_api_path = os.path.join(d, 's5_call_chain', 'by_api')
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

    by_api_dir = os.path.join(d, 's5_call_chain', 'by_api')
    by_api_lookup = {}
    if os.path.isdir(by_api_dir):
        for fname in os.listdir(by_api_dir):
            if not fname.endswith('.json'):
                continue
            payload = load_json(os.path.join(by_api_dir, fname))
            identity_key = build_api_identity_key(payload)
            if identity_key[0] and identity_key[1]:
                by_api_lookup[identity_key] = payload

    for bucket_name in ('p0', 'p1', 'p2', 'uncertain', 'not_analyzed', 'not_found'):
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
    module_dir = f"{d}/s5_call_chain/by_module"
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


def generate_report(findings):
    ctx  = findings['context']
    stat = findings['scan_stats']
    p0 = findings['p0']
    p1 = findings['p1']
    p2 = findings['p2']
    unk = findings['uncertain']
    probable_impact = findings.get('probable_impact', [])
    needs_input = findings.get('needs_input', [])
    na = [
        item for item in findings['not_analyzed']
        if item.get('user_conclusion') not in {'可能影响', '需要补充输入'}
    ]
    nf = findings['not_found']
    conclusion_summary = findings.get('user_conclusion_summary', {})

    def summarize_reason_codes(items):
        counts = defaultdict(int)
        for item in items:
            counts[item.get('reason_code') or 'UNKNOWN'] += 1
        return dict(sorted(counts.items(), key=lambda x: (-x[1], x[0])))

    L = [
        "# Java 升级兼容性分析报告", "",
        f"> 生成时间：{findings['generated_at']}  ",
        f"> JDK：{ctx.get('jdk','')} | Spring Boot：{ctx.get('springboot','')}  ",
        "> **本报告只描述问题，不提供修复方案**",
        "", "---", "",
        "## 分析完整度", "",
        f"- 整体状态：{(findings.get('coverage') or {}).get('overall_status', 'unknown')}",
        f"- 关键未完成维度：{', '.join((findings.get('coverage') or {}).get('critical_incomplete') or []) or '无'}",
        "- `complete` 才表示计划范围内无已知覆盖缺口；`partial/insufficient` 均不能解释为没有风险。",
        "",
        "## 阅读与抽查", "",
        "**建议先看：**", "",
        f"- `{Path('s6_report.md')}`（主报告）",
        f"- `{Path('s5_call_chain/summary.json')}`（调用链结论、reason_code 与 call_paths）",
        f"- `{Path('s5_call_chain/by_api/*.json')}`（逐条 evidence_paths）",
        f"- `{Path('s4_jar_compare/all_changed_apis.csv')}`（进入反向调用链的变更集）",
        "", 
        "**建议固定抽查 10 条：**", "",
        "- 从 P0/P1 各抽 3 条：沿 call_paths 打开源码核对调用关系是否真实存在",
        "- 从 uncertain 抽 3 条：先看 reason_code，再核对 verification 与 evidence_paths 是否自洽",
        "- 从 all_changed_apis.csv 抽 3 条：核对 change_type / source 与原始证据是否一致",
        "- 从 s3_jdk_removed_api.csv / s3_jdk_javax_refs.csv 各抽 2 条：核对 文件:行号 是否为真实命中",
        "",
        "## 产物索引（每个文件是什么）", "",
        "说明：本目录 `.upgrade-report/` 默认全量产出证据文件。更完整的“产物字典”见本工具 README。", "",
        "- `s1_dep_changes.csv`：依赖变更范围（后续分析范围依据）",
        "- `s1_dep_alerts.csv`：需人工确认的依赖变更子集（降级/❓）",
        "- `s1_dep_summary.txt`：Step1 摘要（输入是否拿对、统计与 Top 风险）",
        "- `s2_context.json`：升级场景上下文（决定 Step3 扫描项与 Step4/5 策略）",
        "- `s2_dep_graph.json`：升级依赖关系图（叶→根顺序，用于辅助安排分析顺序）",
        "- `s3_*.csv/.txt`：静态扫描背景信号（线索，不直接等于影响系统）",
        "- `s4_jar_compare/`：依赖变化事实与证据池：", 
        "  - `all_changed_apis.csv`：聚合后的 API 变化清单（事实集合）",
        "  - `all_changed_apis_alerts.csv`：高风险子集（优先抽查）",
        "  - `summary.txt`：Step4 总控面板（缺 jar/JApiCmp/gitdiff 情况）",
        "  - `changed_classes.json`：类级变更索引（辅助定位变更类集合）",
        "  - `*_binary.txt`：JApiCmp 原始输出证据",
        "  - `*_gitdiff_api_changes.txt`：依赖源码 git diff 证据",
        "  - `*_behavior.txt`：changelog 行为变更任务（需人工确认）",
        "- `s5_call_chain/`：影响证明：",
        "  - `summary.json`：reachable/uncertain 结论、reason_code 与 call_paths（核心）",
        "  - `alerts.csv`：可运营的处理清单（按模块/严重级别排序）",
        "  - `summary.txt`：Step5 摘要（Top 模块/Top 触达/Top 不确定）",
        "  - `by_api/*.json`：单条风险的完整调用链证据（含 evidence_paths）",
        "  - `by_module/*_impacts.json`：按模块聚合影响摘要",
        "- `s6_findings.json`：结构化最终结果（机器可消费）",
        "- `s6_report.md`：最终人类报告（你正在读）",
        "- `main_state.json`：唯一主状态文件（业务参数、步骤输入输出、待交互状态）",
        "- `interaction.json`：待交互展示文件（只展示问题、选项与恢复提示）",
        "", "---", "",
        "## 一、风险总览", "",
        "| 级别 | 数量 | 含义 |",
        "|---|---|---|",
        f"| P0 静态编译不兼容候选 | {len(p0)} | 依赖变化与静态引用形成强冲突候选；若 current 构建成功则需核对构建溯源，不得写成已确认编译失败 |",
        f"| P1 运行时崩溃 | {len(p1)} | 编译通过但运行时抛异常 |",
        f"| P2 行为异常 | {len(p2)} | 功能可能不正确，需测试验证 |",
        f"| ❓ 待人工验证 | {len(unk)} | 静态分析发现候选路径，但存在歧义，需人工核实 |",
        f"| ≈ 可能影响 | {len(probable_impact)} | 已找到强相关证据，但仍需测试或运行时验证 |",
        f"| … 需要补充输入 | {len(needs_input)} | 关键输入缺失，当前结论不完整 |",
        f"| ⊘ 未覆盖/未分析 | {len(na)} | 工具已知未覆盖该场景，不能按“未影响”解释 |",
        f"| ✗ 静态未找到 | {len(nf)} | 当前源码图未找到路径，不等于确定未影响 |",
        "",
    ]

    total_apis = stat.get('changed_apis_total', 0)
    call_status = stat.get('call_chain_status', 'done')
    impacted_total = (
        len(p0) + len(p1) + len(p2) + len(unk)
        + len(probable_impact) + len(needs_input) + len(na) + len(nf)
    )
    if call_status == 'skipped':
        L += [
            "**调用链分析状态：**",
            f"- 状态：skipped（{stat.get('call_chain_skip_reason', '') or 'no_reason'}）",
            f"- Step4 变更 API 总数：{total_apis}",
            "- 请先检查 all_changed_apis.csv、Step4 summary.txt 与原始证据文件是否为空或提取失败。",
            "",
        ]
    elif total_apis > 0:
        L += [
            "**调用链分析：**",
            f"- 变更 API 总数：{total_apis}",
            f"- 已确认影响：{conclusion_summary.get('已确认影响', stat.get('call_chain_reachable', 0))}",
            f"- 可能影响：{conclusion_summary.get('可能影响', 0)}",
            f"- 当前无法确认：{conclusion_summary.get('当前无法确认', 0)}",
            f"- 需要补充输入：{conclusion_summary.get('需要补充输入', 0)}",
            f"- 静态未找到：{stat.get('call_chain_not_found_in_static_analysis', 0)}",
            "",
        ]
    if impacted_total == 0 and call_status != 'skipped':
        coverage_status = (findings.get('coverage') or {}).get('overall_status', 'unknown')
        L += [
            "**结论：**",
            f"- 当前未识别到已证明影响本系统的依赖/API 变更；分析完整度为 `{coverage_status}`。",
            "- 仅当关键覆盖维度 complete 时，才可表述为“在明确范围内未发现已确认影响”；否则只能表述为当前证据未发现。",
            "- 下文的扫描命中和依赖兼容信号仅作为背景线索，不作为当前系统的重点风险。",
            "",
        ]
    if impacted_total == 0 and call_status == 'skipped' and total_apis > 0:
        L += [
            "**结论：**",
            "- 调用链分析被跳过，无法基于静态分析证明“是否影响本系统”。",
            "- 请优先检查 Step4 产物是否完整，并重新执行 Step5。",
            "",
        ]

    L += [
        "## 二、当前系统受影响摘要", "",
        "| 项目 | 数量 | 说明 |",
        "|---|---|---|",
        f"| 已确认影响 | {conclusion_summary.get('已确认影响', stat.get('call_chain_reachable', 0))} | 已找到从系统代码到变更 API 的调用链 |",
        f"| 可能影响 | {conclusion_summary.get('可能影响', 0)} | 已找到强相关证据，但仍需测试或运行时验证 |",
        f"| 当前无法确认 | {conclusion_summary.get('当前无法确认', 0)} | 当前证据不足，需人工复核或补证据 |",
        f"| 需要补充输入 | {conclusion_summary.get('需要补充输入', 0)} | 关键输入缺失，当前结论不完整 |",
        "",
    ]

    impacted_deps = findings.get('impacted_dependencies', [])
    if impacted_deps:
        L += [
            "## 三、当前系统受影响的依赖", "",
            "| 依赖坐标 | 变更类型 | 回溯到系统源码 | 最终状态 | 止步层 | P0 | P1 | P2 | ❓ | ≈ | … | ⊘ | ✗ | 受影响 API 数 |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for dep in impacted_deps:
            L.append(
                f"| {dep['coord']} | {dep.get('change_type', '')} | "
                f"{'是' if dep.get('reaches_system_source') else '否'} | {dep.get('final_status', '')} | "
                f"{dep.get('blocked_at', '')} | {dep['p0']} | {dep['p1']} | {dep['p2']} | {dep['uncertain']} | "
                f"{dep.get('probable_impact', 0)} | {dep.get('needs_input', 0)} | {dep.get('not_analyzed', 0)} | "
                f"{dep.get('not_found', 0)} | {dep['api_count']} |"
            )
        L.append("")

    per_dependency_results = findings.get('per_dependency_results', [])
    if per_dependency_results:
        L += [
            "### 单依赖包最终结论", "",
            "| 依赖坐标 | 变更类型 | 回溯到系统源码 | 最终状态 | 止步层 | 阻塞原因 | 证据等级 | 代表 API |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for item in per_dependency_results:
            L.append(
                f"| {item.get('coord', '')} | {item.get('change_type', '')} | "
                f"{'是' if item.get('reaches_system_source') else '否'} | {item.get('final_status', '')} | "
                f"{item.get('blocked_at', '')} | {item.get('blocked_reason', '')} | "
                f"{item.get('evidence_level', '')} | {item.get('selected_api', '')} |"
            )
        L.append("")

    L += [
        "## 四、扫描统计", "",
        "| 扫描项 | 命中数 |", "|---|---|",
    ]
    for key, label in [
        ('jdk_removed_api',  'JDK 已移除 API'),
        ('jdk_javax_refs',   'javax.* 引用'),
        ('jdk_internal_api', 'JDK 内部 API'),
        ('jdk_reflection',   '反射操作'),
        ('sb_config',        'Spring Boot 配置键'),
        ('dep_compat',       '依赖包兼容信号'),
    ]:
        v = stat.get(key, -1)
        L.append(f"| {label} | {v if v >= 0 else '未扫描'} |")
    L.append("")

    dep_compat = findings.get('dep_compat_summary', {})
    if dep_compat and dep_compat.get('impacted_total', 0) > 0:
        L += [
            "## 五、与当前系统相关的依赖包兼容信号", "",
            f"- 已命中且影响到系统调用链的依赖信号：{dep_compat.get('impacted_total', 0)}",
        ]
        for risk_type, cnt in dep_compat.get('impacted_by_type', {}).items():
            L.append(f"- {risk_type}: {cnt}")
        L.append("")
        top_coords = dep_compat.get('impacted_coords', [])
        if top_coords:
            L += ["**命中最多的依赖（Top 10）**", "", "| 依赖坐标 | 命中数 |", "|---|---|"]
            for coord, cnt in top_coords:
                L.append(f"| {coord} | {cnt} |")
            L.append("")

    dep_sum = findings.get('dep_changes_summary', {})
    if dep_sum:
        L += ["## 六、依赖变更概览", "", "| 变更类型 | 数量 |", "|---|---|"]
        for ct, cnt in sorted(dep_sum.items()):
            L.append(f"| {ct} | {cnt} |")
        L.append("")

    L += ["---", ""]

    def section(title, items, emoji):
        if items:
            L.extend([f"## {title}（{len(items)} 个）", ""])
            for item in items:
                L.extend(_fmt_issue(item))
        else:
            L.extend([f"## {title}", "", f"✅ 无{emoji}问题", ""])
        L.extend(["---", ""])

    section("七、P0 编译失败", p0, "P0")
    section("八、P1 运行时崩溃", p1, "P1")
    section("九、P2 行为异常", p2, "P2")

    L += [f"## 十、待人工验证（{len(unk)} 项）", ""]
    if unk:
        reason_summary = findings.get('uncertain_reason_summary', {})
        if reason_summary:
            L += ["**原因分类**", ""]
            for reason_code, cnt in reason_summary.items():
                L.append(f"- `{reason_code}`：{cnt}")
            L.append("")
        for item in unk:
            L.append(f"### `{item.get('api','')}`")
            if item.get('reason_code'):
                L.append(f"- **原因码**：`{item.get('reason_code')}`")
            L.append(f"- **原因**：{item.get('reason','')}")
            for cmd in item.get('verification', []):
                L.append(f"- **验证**：`{cmd}`")
            evidence_paths = item.get('evidence_paths', []) or []
            if evidence_paths:
                first_path = evidence_paths[0]
                if first_path:
                    L.append("- **已知证据路径（摘要）**：")
                    for edge in first_path[:5]:
                        L.append(
                            f"  - `{edge.get('caller_symbol','?')}` -> `{edge.get('callee_key','?')}` "
                            f"({edge.get('evidence_type','')}, {edge.get('confidence','')}) "
                            f"`{Path(edge.get('file','?')).name}:{edge.get('line','?')}`"
                        )
            L.append("")
    else:
        L += ["✅ 无待验证项", ""]
    L += ["---", ""]

    L += [f"## 十一、可能影响（{len(probable_impact)} 项）", ""]
    if probable_impact:
        for item in probable_impact:
            L.extend(_fmt_issue(item))
    else:
        L += ["✅ 无可能影响项", ""]
    L += ["---", ""]

    L += [f"## 十二、需要补充输入（{len(needs_input)} 项）", ""]
    if needs_input:
        for item in needs_input:
            L.append(f"### `{item.get('api','')}`")
            if item.get('reason_code'):
                L.append(f"- **原因码**：`{item.get('reason_code')}`")
            if item.get('user_reason') or item.get('reason'):
                L.append(f"- **说明**：{item.get('user_reason') or item.get('reason')}")
            if item.get('recommended_action'):
                L.append(f"- **推荐动作**：{item.get('recommended_action')}")
            for cmd in item.get('verification', []):
                L.append(f"- **建议动作**：`{cmd}`")
            L.append("")
    else:
        L += ["✅ 无待补输入项", ""]
    L += ["---", ""]

    L += [f"## 十三、未覆盖/未分析（{len(na)} 项）", ""]
    if na:
        reason_summary = summarize_reason_codes(na)
        if reason_summary:
            L += ["**原因分类**", ""]
            for reason_code, cnt in reason_summary.items():
                L.append(f"- `{reason_code}`：{cnt}")
            L.append("")
        for item in na:
            L.append(f"### `{item.get('api','')}`")
            if item.get('reason_code'):
                L.append(f"- **原因码**：`{item.get('reason_code')}`")
            if item.get('impact_mode'):
                L.append(f"- **影响类型**：`{item.get('impact_mode')}`")
            L.append(f"- **说明**：{item.get('reason','')}")
            for cmd in item.get('verification', []):
                L.append(f"- **建议动作**：`{cmd}`")
            L.append("")
    else:
        L += ["✅ 无未覆盖项", ""]
    L += ["---", ""]

    L += [f"## 十四、静态未找到路径（{len(nf)} 项）", ""]
    if nf:
        reason_summary = findings.get('not_found_reason_summary', {})
        if reason_summary:
            L += ["**原因分类**", ""]
            for reason_code, cnt in reason_summary.items():
                L.append(f"- `{reason_code}`：{cnt}")
            L.append("")
        for item in nf:
            L.append(f"### `{item.get('api','')}`")
            if item.get('reason_code'):
                L.append(f"- **原因码**：`{item.get('reason_code')}`")
            L.append(f"- **说明**：{item.get('reason','')}")
            for cmd in item.get('verification', []):
                L.append(f"- **建议动作**：`{cmd}`")
            L.append("")
    else:
        L += ["✅ 无静态未找到项", ""]
    L += ["---", ""]

    mod_impacts = findings.get('module_impacts', {})
    L += ["## 十五、受影响的系统模块", ""]
    if mod_impacts:
        L += ["| 模块 | P0 | P1 | P2 | ❓ | ≈ | … | ⊘ | ✗ | 影响点数 |",
              "|---|---|---|---|---|---|---|---|---|---|"]
        for mod, data in sorted(mod_impacts.items(),
                                 key=lambda x: -(x[1]['p0']*100+x[1]['p1']*10+x[1]['p2'])):
            L.append(f"| {mod} | {data['p0']} | {data['p1']} | {data['p2']} "
                     f"| {data['uncertain']} | {data.get('probable_impact', 0)} | {data.get('needs_input', 0)} "
                     f"| {data.get('not_analyzed', 0)} | {data.get('not_found', 0)} | {data['impact_count']} |")
        L.append("")
    else:
        L += ["✅ 当前未识别到受影响模块", ""]

    background = findings.get('background_signals', {})
    if background:
        L += ["## 附录A、背景信号（未证明影响当前系统）", ""]
        dep_compat_total = background.get('dep_compat_total', 0)
        if dep_compat_total:
            L += [
                f"- 依赖包兼容信号命中 {dep_compat_total} 项，但当前未证明影响系统调用链。",
                "- 这些结果适合作为排查线索，不作为主报告重点风险。",
                "",
            ]
            top_coords = background.get('dep_compat_top_coords', [])
            if top_coords:
                L += ["| 依赖坐标 | 背景命中数 |", "|---|---|"]
                for coord, cnt in top_coords:
                    L.append(f"| {coord} | {cnt} |")
                L.append("")

    return '\n'.join(L)


def _fmt_issue(item):
    lines = [f"### `{item.get('api','')}`", "",
             f"- **依赖坐标**：`{item.get('coord','?')}`",
             f"- **变更类型**：{item.get('change_type','')}",
             f"- **业务直接命中**：{item.get('direct_callers',0)} 处"]
    if item.get('symbol_kind'):
        lines.append(f"- **符号类型**：`{item.get('symbol_kind')}`")
    if item.get('api_signature'):
        lines.append(f"- **方法签名**：`{item.get('api_signature')}`")
    if item.get('reason_code'):
        lines.append(f"- **原因码**：`{item.get('reason_code')}`")
    if item.get('user_conclusion'):
        lines.append(f"- **结论**：{item.get('user_conclusion')}")
    if item.get('user_reason') or item.get('reason'):
        lines.append(f"- **说明**：{item.get('user_reason') or item.get('reason')}")
    if item.get('recommended_action'):
        lines.append(f"- **推荐动作**：{item.get('recommended_action')}")
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

    Path(args.output_findings).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output_findings, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    write_text(args.output_report, generate_report(findings))

    p0, p1, p2, unk, na, nf = (len(findings[k]) for k in ('p0', 'p1', 'p2', 'uncertain', 'not_analyzed', 'not_found'))
    print(f"  P0={p0} P1={p1} P2={p2} ❓={unk} ⊘={na} ✗={nf}", file=sys.stderr)
    print(f"  findings → {args.output_findings}", file=sys.stderr)
    print(f"  report   → {args.output_report}",   file=sys.stderr)


if __name__ == '__main__':
    main()
