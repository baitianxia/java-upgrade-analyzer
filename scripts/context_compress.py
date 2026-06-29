#!/usr/bin/env python3
"""
context_compress.py — 主动上下文压缩

在长分析任务中，模型上下文会随对话增长而耗尽。
本脚本将当前分析状态压缩为最小必要信息，
让模型在新对话中能够恢复并继续，而不需要重读所有历史。

使用时机：
  - 每个 Step 完成后，调用一次生成检查点
  - 上下文接近上限时（模型感知到），立即调用并开启新对话
  - 子任务（依赖分析）完成时，调用后交给父任务

用法：
  # 保存状态摘要
  python3 context_compress.py save \\
    --report-dir .upgrade-report \\
    --completed-step 4 \\
    --output .upgrade-report/context_summary.json

  # 恢复时读取（新对话开头）
  python3 context_compress.py load \\
    --input .upgrade-report/context_summary.json
"""

import argparse, csv, json, os, sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from compat import open_text
from pipeline_constants import STEP_SEQUENCE, STEP_TO_MAJOR


def normalize_step_id(completed_step=None, completed_step_id=None):
    if completed_step_id:
        if completed_step_id not in STEP_SEQUENCE:
            raise ValueError(f'未知步骤标识：{completed_step_id}')
        return completed_step_id

    mapping = {
        1: 'step1',
        2: 'step2',
        3: 'step3',
        4: 'step4',
        5: 'step5',
        6: 'step6',
    }
    if completed_step not in mapping:
        raise ValueError(f'未知步骤编号：{completed_step}')
    return mapping[completed_step]


def completed_step_ids(step_id):
    idx = STEP_SEQUENCE.index(step_id)
    return STEP_SEQUENCE[:idx + 1]


def next_step_id(step_id):
    idx = STEP_SEQUENCE.index(step_id)
    if idx + 1 >= len(STEP_SEQUENCE):
        return None
    return STEP_SEQUENCE[idx + 1]


# ── 各步骤的摘要提取逻辑 ─────────────────────────────────────────

def summarize_step1(report_dir):
    """Step 1：只保留依赖数量和关键变更，丢弃所有中间细节"""
    csv_path = f"{report_dir}/s1_dep_changes.csv"
    if not os.path.exists(csv_path):
        return {'status': 'missing'}

    total, major_upgraded, minor_upgraded, downgraded, added, removed = 0, 0, 0, 0, 0, 0
    high_risk = []

    with open_text(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1
            ct = row.get('change_type', '')
            coord = row.get('coord', '')
            scope = row.get('scope', 'compile')
            if '大版本' in ct and scope == 'compile':
                major_upgraded += 1
                high_risk.append(f"{coord}: {row.get('old_version')}→{row.get('new_version')}")
            elif '小版本' in ct:
                minor_upgraded += 1
            elif '降级' in ct:
                downgraded += 1
                high_risk.append(f"⚠️降级 {coord}: {row.get('old_version')}→{row.get('new_version')}")
            elif ct == '新增':
                added += 1
            elif ct == '移除':
                removed += 1

    return {
        'status': 'done',
        'total_deps': total,
        'major_upgrades': major_upgraded,
        'minor_upgrades': minor_upgraded,
        'downgrades': downgraded,
        'added': added,
        'removed': removed,
        'high_risk_items': high_risk[:20],  # 只保留前 20 条
    }


def summarize_step2(report_dir):
    """Step 2：只保留关键上下文字段"""
    ctx_path = f"{report_dir}/s2_context.json"
    if not os.path.exists(ctx_path):
        return {'status': 'missing'}

    with open_text(ctx_path) as f:
        ctx = json.load(f)

    # 只保留后续步骤需要的字段，丢弃详细列表
    return {
        'status': 'done',
        'build_tool':              ctx.get('build_tool'),
        'jdk_base':                ctx.get('jdk_base'),
        'jdk_current':             ctx.get('jdk_current'),
        'jdk_upgraded':            ctx.get('jdk_upgraded'),
        'springboot_base':         ctx.get('springboot_base'),
        'springboot_current':      ctx.get('springboot_current'),
        'springboot_major_upgrade':ctx.get('springboot_major_upgrade'),
        'spring_cloud':            ctx.get('spring_cloud'),
        'changed_dependency_count': len(ctx.get('changed_dependencies', [])),
        'changed_dependency_names': [l['artifact_id'] for l in ctx.get('changed_dependencies', [])],
        'tech_flags_active':       [k for k, v in ctx.get('tech_flags', {}).items() if v],
        'total_deps':              ctx.get('total_deps'),
        'changed_deps':            ctx.get('changed_deps'),
    }


def summarize_step3(report_dir):
    """Step 3：只保留命中数量，丢弃每行详情"""
    def count_csv(path):
        if not os.path.exists(path):
            return -1
        with open_text(path) as f:
            return max(sum(1 for l in f if l.strip() and not l.startswith('#')) - 1, 0)

    def count_txt(path):
        if not os.path.exists(path):
            return -1
        with open_text(path) as f:
            return sum(1 for l in f if l.strip())

    return {
        'status': 'done',
        'jdk_removed_api_count':   count_csv(f"{report_dir}/s3_jdk_removed_api.csv"),
        'jdk_javax_refs_count':    count_csv(f"{report_dir}/s3_jdk_javax_refs.csv"),
        'jdk_internal_api_count':  count_csv(f"{report_dir}/s3_jdk_internal_api.csv"),
        'jdk_reflection_count':    count_csv(f"{report_dir}/s3_jdk_reflection.csv"),
        'jdk_serialization_count': count_txt(f"{report_dir}/s3_jdk_serialization.txt"),
        'sb_config_count':         count_csv(f"{report_dir}/s3_springboot_config.csv"),
        'sb_autoconfig_count':     count_txt(f"{report_dir}/s3_springboot_autoconfig.txt"),
        'dep_compat_count':        count_csv(f"{report_dir}/s3_dependency_compat.csv"),
        'risk_candidate_count':    count_csv(f"{report_dir}/s3_risk_candidates.csv"),
        'note': '详细内容在文件中，需要时读取对应 csv/txt'
    }


def summarize_step4(report_dir):
    """Step 4：只保留变更 API 的数量和关键清单"""
    csv_path = f"{report_dir}/s4_jar_compare/all_changed_apis.csv"
    if not os.path.exists(csv_path):
        return {'status': 'missing'}

    p0, p1, p2 = [], [], []
    unconfirmed = []
    jar_dir = f"{report_dir}/s4_jar_compare"
    jar_missing = []

    with open_text(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            sev = row.get('severity', 'P2')
            confirmed = row.get('confirmed', 'false')
            api = row.get('api_name', '')[:60]
            coord = row.get('coord', '')

            entry = f"{coord}: {api} ({row.get('change_type','')})"
            if sev == 'P0':
                p0.append(entry)
            elif sev == 'P1':
                p1.append(entry)
            else:
                p2.append(entry)
            if confirmed != 'true':
                unconfirmed.append(api)

    # 检查 jar 未找到情况
    if os.path.isdir(jar_dir):
        for f in os.listdir(jar_dir):
            if f.endswith('_binary.txt'):
                try:
                    content = Path(f"{jar_dir}/{f}").read_text(
                        encoding='utf-8', errors='replace')[:300]
                    if '未找到' in content or 'jar 未找到' in content:
                        jar_missing.append(f)
                except Exception:
                    pass

    # 从 main_state.json 读取派生出的依赖仓库映射（用于 Step5 自动发现）
    dependency_repo_mappings = []
    main_state_path = os.path.join(report_dir, 'main_state.json')
    if os.path.exists(main_state_path):
        try:
            with open(main_state_path, 'r', encoding='utf-8') as f:
                main_state = json.load(f)
            found = False
            for step_id in ('step5', 'step4', 'step3', 'step2', 'step1'):
                step_data = dict(main_state.get(step_id) or {})
                for key in ('input', 'output'):
                    payload = step_data.get(key)
                    if isinstance(payload, dict) and payload.get('dependency_repo_mappings'):
                        dependency_repo_mappings = payload.get('dependency_repo_mappings', [])
                        found = True
                        break
                if found:
                    break
        except Exception:
            pass

    return {
        'status': 'done',
        'total_changed_apis': len(p0) + len(p1) + len(p2),
        'p0_count': len(p0),
        'p1_count': len(p1),
        'p2_count': len(p2),
        'unconfirmed_count': len(unconfirmed),
        'jar_missing_count': len(jar_missing),
        # 保存派生出的依赖仓库映射（用于 Step5 自动发现依赖源码映射）
        'dependency_repo_mappings': dependency_repo_mappings,
        # 只保留 P0 清单（最重要），P1/P2 只保留计数
        'p0_apis': p0[:30],
        'jar_missing': jar_missing[:10],
        'note': f'完整清单在 {csv_path}'
    }


def _count_step5_affected_modules(report_dir):
    module_dir = Path(report_dir) / 's5_call_chain' / 'by_module'
    if not module_dir.exists():
        return 0
    affected = 0
    for path in module_dir.glob('*_impacts.json'):
        try:
            with open_text(path) as f:
                payload = json.load(f)
            if payload.get('impacts'):
                affected += 1
        except Exception:
            continue
    return affected


def _build_step5_severity_breakdown(summary):
    counts = {'P0': 0, 'P1': 0, 'P2': 0}
    for bucket in ('reachable_apis', 'uncertain_apis', 'not_analyzed_apis', 'not_found_apis'):
        for item in summary.get(bucket, []) or []:
            severity = str((item or {}).get('severity') or '').strip()
            if severity in counts:
                counts[severity] += 1
    return counts


def summarize_step5(report_dir):
    """Step 5：只保留影响摘要，丢弃每条调用链详情"""
    summary_path = f"{report_dir}/s5_call_chain/summary.json"
    if not os.path.exists(summary_path):
        return {'status': 'missing'}

    with open_text(summary_path) as f:
        summary = json.load(f)

    # 只保留顶层摘要数字和 Top 10 影响
    return {
        'status':             summary.get('status', 'done'),
        'skip_reason':        summary.get('skip_reason', ''),
        'total_apis':         summary.get('total_apis', 0),
        'reachable':          summary.get('reachable', 0),
        'not_found_in_static_analysis': summary.get('not_found_in_static_analysis', summary.get('not_reachable', 0)),
        'uncertain':          summary.get('uncertain', 0),
        'not_analyzed':       summary.get('not_analyzed', 0),
        'modules_affected':   _count_step5_affected_modules(report_dir),
        'severity_breakdown': _build_step5_severity_breakdown(summary),
        'quality_gate':       summary.get('quality_gate', {}),
        'user_conclusion_summary': summary.get('user_conclusion_summary', {}),
        'deprecated_aliases': summary.get('deprecated_aliases', {}),
        # 只保留 Top 10 可达风险
        'top_reachable': summary.get('reachable_apis', [])[:10],
        # 保留所有 uncertain（需人工验证，不能丢）
        'all_uncertain': summary.get('uncertain_apis', []),
        'note': f'完整调用链在 {report_dir}/s5_call_chain/by_api/ 和 by_module/'
    }


# ── 主检查点结构 ──────────────────────────────────────────────────

def build_checkpoint(report_dir, completed_step=None, completed_step_id=None,
                     blocked=False, blocking_reason=None):
    """构建最小化检查点，只包含恢复任务所需的最少信息"""
    step_id = normalize_step_id(completed_step, completed_step_id)
    completed = STEP_TO_MAJOR[step_id]
    finished_steps = completed_step_ids(step_id)
    next_id = next_step_id(step_id)

    checkpoint = {
        'meta': {
            'what': '执行检查点（断点续跑状态 + 各步骤最小摘要）',
            'why': '让使用者/协作者快速判断卡点与下一步该补齐什么，并支持续跑',
            'how_to_read': [
                'blocked=true 或 status=awaiting_* 时优先看 blocking_reason、pending_interaction 与 resume_instructions.files_to_read',
                'completed_step/current_step/next_step_id 说明流程推进到哪一步',
                'steps 下是每个已完成步骤的最小摘要（避免阅读大文件）',
            ],
        },
        'version':           '2.0',
        'saved_at':          datetime.now().isoformat(),
        'completed_step':    completed,
        'completed_step_id': step_id,
        'completed_steps':   finished_steps,
        'current_step':      next_id or 'done',
        'next_step':         completed + 1 if next_id else None,
        'next_step_id':      next_id,
        'status':            'completed',
        'blocked':           blocked,
        'blocking_reason':   blocking_reason,
        'pending_interaction': None,
        'report_dir':        str(Path(report_dir).resolve()),

        # 恢复时需要知道的关键参数
        'resume_instructions': _build_resume_instructions(next_id),

        # 各步骤摘要（只保留必要信息）
        'steps': {}
    }

    extractors = {
        'step1': summarize_step1,
        'step2': summarize_step2,
        'step3': summarize_step3,
        'step4': summarize_step4,
        'step5': summarize_step5,
    }

    for current_id in finished_steps:
        extractor = extractors.get(current_id)
        if not extractor:
            continue
        try:
            checkpoint['steps'][current_id] = extractor(report_dir)
        except Exception as e:
            checkpoint['steps'][current_id] = {
                'status': 'error', 'error': str(e)
            }

    return checkpoint


def _build_resume_instructions(next_step):
    """生成恢复指令——新对话开头的 AI 需要知道做什么"""
    next_label = next_step or 'done'
    instructions = {
        'context': (
            f"这是 Java 升级兼容性分析任务的续接。"
            f"已根据状态摘要恢复执行状态，当前应从 {next_label} 继续。"
            f"所有中间结果已保存在 report_dir 下，请优先读取 main_state.json 了解当前状态。"
        ),
        'next_action': _get_next_action(next_step),
        'files_to_read': _get_files_to_read(next_step),
        'do_not': [
            '不要重新执行已完成的步骤',
            '不要读取大型原始构建输出，只读摘要',
            '不要在对话中展开完整的调用链列表，只展示关键摘要',
        ]
    }
    return instructions


def _get_next_action(next_step):
    actions = {
        'step1': '先切到 base/current 执行真实构建，再生成 Step1 依赖差异。',
        'step2': '运行 s2_context_from_deps.py 推断项目上下文，并同步产出依赖关系图。',
        'step3': '根据 s2_context.json 的标志位运行对应的 Step 3 扫描脚本。',
        'step4': '运行 s4_jar_compare.py 做 jar 包变更对比。',
        'step5': '对 s4_jar_compare/all_changed_apis.csv 逐条执行反向调用链追踪（默认 max_depth=5，高/中/低置信度边分别消耗 1/2/5 单位代价，详见 SKILL.md）。',
        'step6': '运行 s6_report.py 生成最终报告。',
        None: '分析已完成，查看 s6_report.md。'
    }
    return actions.get(next_step, f'继续 {next_step}')


def _get_files_to_read(next_step):
    """新对话开始时应该读取的最小文件集"""
    files = {
        'step1': ['项目根目录', '基准分支', '当前分支'],
        'step2': ['main_state.json', 's1_dep_changes.csv（前 20 行即可）'],
        'step3': ['main_state.json', 's2_context.json'],
        'step4': ['main_state.json', 's2_context.json', 's1_dep_changes.csv'],
        'step5': ['main_state.json', 's4_jar_compare/all_changed_apis.csv', 's2_context.json'],
        'step6': ['main_state.json', 's5_call_chain/summary.json', 's4_jar_compare/all_changed_apis.csv'],
        None: ['s6_report.md'],
    }
    return files.get(next_step, ['main_state.json'])


# ── 上下文感知压缩（运行时主动调用）────────────────────────────

def estimate_context_usage(report_dir):
    """
    估算当前分析状态在上下文中占用的 token 量。
    返回 (estimated_tokens, recommendation)
    """
    sizes = {}
    for fname in os.listdir(report_dir):
        fpath = os.path.join(report_dir, fname)
        if os.path.isfile(fpath):
            sizes[fname] = os.path.getsize(fpath)

    total_bytes = sum(sizes.values())
    # 粗估：1 token ≈ 4 bytes（中英混合文本）
    estimated_tokens = total_bytes // 4

    if estimated_tokens > 50000:
        rec = 'HIGH: 立即保存检查点，在新对话中继续'
    elif estimated_tokens > 20000:
        rec = 'MEDIUM: 建议在当前步骤完成后保存检查点'
    else:
        rec = 'LOW: 上下文用量正常'

    return estimated_tokens, rec, sizes


# ── 显示恢复信息 ─────────────────────────────────────────────────

def display_checkpoint(checkpoint_path):
    """在新对话开头读取并显示检查点，让 AI 快速了解现状"""
    with open_text(checkpoint_path) as f:
        ckpt = json.load(f)

    print("=" * 60)
    print(f"任务恢复：Java 升级兼容性分析")
    print(f"保存时间：{ckpt.get('saved_at', '未知')}")
    print(f"已完成：{ckpt.get('completed_step_id', ckpt.get('completed_step', '?'))}")
    print(f"当前待执行：{ckpt.get('current_step', ckpt.get('next_step_id', '?'))}")
    print(f"报告目录：{ckpt.get('report_dir', '.')}")
    print(f"当前状态：{ckpt.get('status', 'unknown')}")
    if ckpt.get('blocked'):
        print(f"阻塞状态：是")
        print(f"阻塞原因：{ckpt.get('blocking_reason', '未知')}")
    else:
        print("阻塞状态：否")
    pending = ckpt.get('pending_interaction') or {}
    if pending:
        print(f"待交互标题：{pending.get('title', '')}")
        print(f"待交互问题：{pending.get('question', '')}")
    print()

    inst = ckpt.get('resume_instructions', {})
    print(f"下一步行动：{inst.get('next_action', '')}")
    print()
    print(f"需要读取的文件：")
    for f in inst.get('files_to_read', []):
        print(f"  - {f}")
    print()

    # 显示关键发现摘要
    steps = ckpt.get('steps', {})
    print("已完成步骤摘要：")

    def fmt_num(value):
        return value if isinstance(value, int) and value >= 0 else '未扫描'

    def fmt_ver(value):
        return value if value not in (None, '', 'unknown') else '?'

    if 'step1' in steps:
        s = steps['step1']
        print(f"  Step 1 依赖变更：{s.get('total_deps',0)} 个依赖，"
              f"大版本升级 {s.get('major_upgrades',0)} 个，"
              f"小版本升级 {s.get('minor_upgrades',0)} 个，"
              f"降级 {s.get('downgrades',0)} 个")
        if s.get('high_risk_items'):
            print(f"    高风险（前 5）：{s['high_risk_items'][:5]}")

    if 'step2' in steps:
        s = steps['step2']
        print(f"  Step 2 上下文：JDK {fmt_ver(s.get('jdk_base'))}→{fmt_ver(s.get('jdk_current'))}，"
              f"Spring Boot {fmt_ver(s.get('springboot_base'))}→{fmt_ver(s.get('springboot_current'))}，"
              f"升级依赖 {s.get('changed_dependency_count',0)} 个")

    if 'step3' in steps:
        s = steps['step3']
        removed = fmt_num(s.get('jdk_removed_api_count', -1))
        javax   = fmt_num(s.get('jdk_javax_refs_count', -1))
        depc    = fmt_num(s.get('dep_compat_count', -1))
        print(f"  Step 3 扫描：已移除 API {removed} 处，javax 引用 {javax} 处，依赖兼容信号 {depc} 处")

    if 'step4' in steps:
        s = steps['step4']
        print(f"  Step 4 jar 对比：P0={s.get('p0_count',0)} P1={s.get('p1_count',0)} P2={s.get('p2_count',0)}")
        if s.get('jar_missing_count', 0) > 0:
            print(f"    ⚠️  {s['jar_missing_count']} 个依赖 jar 未找到，对比不完整")

    if 'step5' in steps:
        s = steps['step5']
        if s.get('status') == 'skipped':
            print(f"  Step 5 调用链：已跳过（{s.get('skip_reason', 'unknown')}）")
        else:
            print(f"  Step 5 调用链：可达风险 {s.get('reachable',0)} 个，"
                  f"待验证 {s.get('uncertain',0)} 个，"
                  f"未覆盖 {s.get('not_analyzed',0)} 个，"
                  f"影响模块 {s.get('modules_affected',0)} 个")

    print()
    print("注意：")
    for note in inst.get('do_not', []):
        print(f"  ✗ {note}")
    print("=" * 60)


# ── 主入口 ───────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description='上下文压缩与任务状态摘要管理')
    sub = ap.add_subparsers(dest='cmd')

    # save 子命令
    save_p = sub.add_parser('save', help='保存当前进度状态摘要')
    save_p.add_argument('--report-dir',     required=True)
    save_p.add_argument('--completed-step', type=int, choices=[1, 2, 3, 4, 5, 6])
    save_p.add_argument('--completed-step-id', choices=STEP_SEQUENCE)
    save_p.add_argument('--output',         required=True,
                        help='状态摘要输出路径（建议 .upgrade-report/context_summary.json）')

    # load 子命令
    load_p = sub.add_parser('load', help='在新对话开头恢复任务状态')
    load_p.add_argument('--input', required=True)

    # status 子命令
    status_p = sub.add_parser('status', help='显示当前上下文用量估算')
    status_p.add_argument('--report-dir', required=True)

    args = ap.parse_args()

    if args.cmd == 'save':
        if args.completed_step is None and not args.completed_step_id:
            ap.error('save 模式必须至少提供 --completed-step 或 --completed-step-id')
        ckpt = build_checkpoint(
            args.report_dir,
            completed_step=args.completed_step,
            completed_step_id=args.completed_step_id,
        )
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(ckpt, f, ensure_ascii=False, indent=2)
        size_kb = os.path.getsize(args.output) // 1024
        print(f"✅ 状态摘要已保存：{args.output}（{size_kb} KB）", file=sys.stderr)
        completed_label = ckpt.get('completed_step_id', args.completed_step)
        next_label = ckpt.get('current_step', 'done')
        print(f"   已完成 {completed_label}，下一步是 {next_label}",
              file=sys.stderr)
        print(f"   在新对话中运行：python3 context_compress.py load --input {args.output}",
              file=sys.stderr)

    elif args.cmd == 'load':
        display_checkpoint(args.input)

    elif args.cmd == 'status':
        tokens, rec, sizes = estimate_context_usage(args.report_dir)
        print(f"当前报告目录大小估算：约 {tokens:,} tokens")
        print(f"建议：{rec}")
        if sizes:
            print("\n最大的文件：")
            for fname, size in sorted(sizes.items(), key=lambda x: -x[1])[:5]:
                print(f"  {fname}: {size // 1024} KB")
    else:
        ap.print_help()


if __name__ == '__main__':
    main()
