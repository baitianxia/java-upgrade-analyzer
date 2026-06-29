#!/usr/bin/env python3
"""gate.py — 步骤门控器（完整版在 java-upgrade-analyzer/scripts/gate.py）"""
import argparse, csv, json, os, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pipeline_constants import GATE_SEQUENCE
GATES = list(GATE_SEQUENCE)

def python_cmds():
    return ['python3', 'python', 'py -3']

def fail(msg, instructions=None):
    print(f"\n{'='*60}\n❌ 门控未通过：{msg}", file=sys.stderr)
    if instructions:
        print("\n需要执行：", file=sys.stderr)
        for i in instructions: print(f"  {i}", file=sys.stderr)
    print('='*60, file=sys.stderr)
    sys.exit(1)

def ok(msg): print(f"✅ {msg}", file=sys.stderr)


def read_csv_dicts(path, required_headers):
    try:
        with open(path, encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            missing = [h for h in required_headers if h not in headers]
            if missing:
                fail(f"{os.path.basename(path)} 缺少表头字段：{missing}")
            return [{k: (v or "").strip() for k, v in row.items()} for row in reader if row]
    except csv.Error as exc:
        fail(f"{os.path.basename(path)} 不是合法 CSV：{exc}")


def has_dep_versions(row):
    old_ver = (row.get("old_version") or "").strip()
    new_ver = (row.get("new_version") or "").strip()
    return old_ver not in ("", "-") or new_ver not in ("", "-")

def gate_step1_scope(d):
    csv_path = f"{d}/s1_dep_changes.csv"
    current_csv_path = f"{d}/s1_deps_current_resolved.csv"
    if not os.path.exists(csv_path):
        fail("s1_dep_changes.csv 不存在，请先执行 Step 1",
             [f"{pc} scripts/run_step.py --step step1 --project-dir . --report-dir .upgrade-report --base-branch <base_branch> --current-branch <current_branch>"
              for pc in python_cmds()])
    dep_rows = read_csv_dicts(
        csv_path,
        ["coord", "old_version", "new_version", "change_type", "risk", "scope"],
    )
    valid_dep_rows = [row for row in dep_rows if (row.get("coord") or "").strip() and has_dep_versions(row)]
    if not valid_dep_rows:
        fail("s1_dep_changes.csv 没有有效依赖数据行，请检查 Step1 的真实构建结果是否完整")
    if not os.path.exists(current_csv_path):
        fail("s1_deps_current_resolved.csv 不存在，请重新执行 Step 1",
             [f"{pc} scripts/run_step.py --step step1 --project-dir . --report-dir .upgrade-report --base-branch <base_branch> --current-branch <current_branch>"
              for pc in python_cmds()])
    current_rows = read_csv_dicts(
        current_csv_path,
        ["coord", "version", "scope", "remark"],
    )
    valid_current_rows = [
        row for row in current_rows
        if (row.get("coord") or "").strip() and (row.get("version") or "").strip() not in ("", "-")
    ]
    if not valid_current_rows:
        fail("s1_deps_current_resolved.csv 没有有效当前依赖数据行，请重新执行 Step 1")
    ok(f"step1_scope 门控通过：变更清单={len(valid_dep_rows)} 当前依赖={len(valid_current_rows)}")

def gate_context(d):
    ctx_path = f"{d}/s2_context.json"
    if not os.path.exists(ctx_path): fail("s2_context.json 不存在")
    with open(ctx_path, encoding="utf-8", errors="replace") as f:
        ctx = json.load(f)
    missing = [f for f in ['build_tool', 'base_branch', 'current_branch'] if not ctx.get(f)]
    if missing: fail(f"s2_context.json 缺少字段：{missing}", ["请手动编辑 s2_context.json 补充缺失字段"])
    needs = []
    if not ctx.get('jdk_base') or ctx.get('jdk_base') == 'unknown': needs.append("jdk_base")
    if not ctx.get('jdk_current') or ctx.get('jdk_current') == 'unknown': needs.append("jdk_current")
    if needs:
        print(
            f"\n⚠️  以下字段无法自动推断，需在 Step2 checkpoint 中人工确认或补充：{needs}",
            file=sys.stderr,
        )
        print(
            '  - 请复核 .upgrade-report/s2_context.json 中的 jdk_base/jdk_current，必要时手动补为 "8"、"17"、"21"',
            file=sys.stderr,
        )
    ok(f"context 门控通过：JDK {ctx.get('jdk_base')}→{ctx.get('jdk_current')}")

def gate_scan(d):
    ctx_path = f"{d}/s2_context.json"
    ctx = {}
    if os.path.exists(ctx_path):
        with open(ctx_path, encoding="utf-8", errors="replace") as f:
            ctx = json.load(f)
    issues = []
    if ctx.get('jdk_upgraded'):
        for f in [
            's3_jdk_removed_api.csv',
            's3_jdk_javax_refs.csv',
            's3_jdk_internal_api.csv',
            's3_jdk_reflection.csv',
            's3_jdk_serialization.txt',
            's3_jdk_runtime_flags.csv',
        ]:
            if not os.path.exists(f"{d}/{f}"):
                issues.append(f)
    if ctx.get('springboot_major_upgrade') and not os.path.exists(f"{d}/s3_jdk_javax_refs.csv"):
        issues.append('s3_jdk_javax_refs.csv')
    if ctx.get('springboot_major_upgrade'):
        for f in ['s3_springboot_config.csv', 's3_springboot_autoconfig.txt']:
            if not os.path.exists(f"{d}/{f}"):
                issues.append(f)
    if os.path.exists(f"{d}/s1_deps_current_resolved.csv") or os.path.exists(f"{d}/s1_dep_changes.csv"):
        dep_compat = f"{d}/s3_dependency_compat.csv"
        if not os.path.exists(dep_compat):
            issues.append('s3_dependency_compat.csv')
        dep_classfile = f"{d}/s3_dependency_classfile.csv"
        if not os.path.exists(dep_classfile):
            issues.append('s3_dependency_classfile.csv')
        risk_candidates = f"{d}/s3_risk_candidates.csv"
        if not os.path.exists(risk_candidates):
            issues.append('s3_risk_candidates.csv')
    if issues:
        fail(f"以下扫描文件缺失：{issues}",
             [f"{pc} scripts/s3_scan.py --all --source-dir . --output-dir .upgrade-report --dep-current .upgrade-report/s1_deps_current_resolved.csv"
              for pc in python_cmds()])
    ok("scan 门控通过")

def gate_jar_compare(d):
    csv_path = f"{d}/s4_jar_compare/all_changed_apis.csv"
    ref_txt_path = f"{d}/s4_jar_compare/git_ref_matches.txt"
    ref_json_path = f"{d}/s4_jar_compare/git_ref_matches.json"
    pending_ref_path = f"{d}/s4_jar_compare/git_ref_pending.json"
    timeouts_path = f"{d}/s4_jar_compare/timeouts.json"
    if not os.path.exists(csv_path):
        fail("all_changed_apis.csv 不存在，请先执行 Step 4（jar 对比）")
    for path in (ref_txt_path, ref_json_path):
        if not os.path.exists(path):
            fail(f"{os.path.basename(path)} 不存在，请重新执行 Step 4，确认源码 diff ref 匹配结果已生成")
    if os.path.exists(pending_ref_path):
        with open(pending_ref_path, encoding="utf-8", errors="replace") as f:
            pending_payload = json.load(f)
        pending_items = list(pending_payload.get("items") or [])
        if pending_items:
            fail(
                f"以下依赖的 git refs 仍待人工确认：{len(pending_items)} 个",
                [
                    "查看 s4_jar_compare/git_ref_pending.json 与 git_ref_matches.*，确认 old_ref/new_ref 后重跑 Step4",
                    "通过 --response-json 传入 dependency_git_ref_overrides，再继续流程",
                ],
            )
    if os.path.exists(timeouts_path):
        with open(timeouts_path, encoding="utf-8", errors="replace") as f:
            timeout_payload = json.load(f)
        timeout_items = list(timeout_payload.get("items") or [])
        if timeout_items:
            fail(
                f"Step4 存在超时导致的证据缺失：{len(timeout_items)} 项",
                [
                    "查看 s4_jar_compare/timeouts.json，确认是 git diff、JApiCmp 还是 dependency:get 超时",
                    "通过 --response-json 调整 step4_git_diff_timeout / step4_japicmp_timeout / step4_fetch_timeout 后重跑 Step4",
                ],
            )
    with open(csv_path, encoding="utf-8", errors="replace") as f:
        rows = sum(1 for l in f if l.strip() and not l.startswith('#')) - 1
    print(f"  all_changed_apis.csv：{rows} 个变更 API", file=sys.stderr)

    if rows == 0:
        print("\n⚠️  Step 4 未识别到变更 API。Step5 将基于空输入生成跳过说明，而不是直接得出“无风险”结论。", file=sys.stderr)

    jar_missing = []
    jar_dir = f"{d}/s4_jar_compare"
    if os.path.isdir(jar_dir):
        for f in os.listdir(jar_dir):
            if f.endswith('_binary.txt'):
                try:
                    content = open(f"{jar_dir}/{f}", encoding="utf-8", errors="replace").read(200)
                    if '未找到' in content or 'jar 未找到' in content:
                        jar_missing.append(f)
                except Exception:
                    pass
    if jar_missing:
        fail(
            f"以下依赖 jar 未找到，Step4 证据池不完整：{jar_missing[:5]}",
            ["补齐缺失 jar 或修复 Maven 仓库配置后，重新执行 Step 4"]
        )
    ok(f"jar_compare 门控通过：{rows} 个变更 API")

def gate_call_chain(d, strict_risk_gate=False):
    summary_path = f"{d}/s5_call_chain/summary.json"
    if not os.path.exists(summary_path):
        fail("s5_call_chain/summary.json 不存在，请先执行 Step 5")
    with open(summary_path, encoding="utf-8", errors="replace") as f:
        summary = json.load(f)
    if summary.get('status') == 'skipped':
        if strict_risk_gate:
            fail("调用链分析被跳过，严格模式下禁止继续", ["补齐 Step4/Step5 所需输入后重新执行分析"])
        print(f"\n⚠️  调用链分析被跳过：{summary.get('skip_reason', 'unknown')}", file=sys.stderr)
        for note in summary.get('notes', [])[:3]:
            print(f"  - {note}", file=sys.stderr)
        ok("call_chain 门控通过：调用链分析未执行（不会得出“无风险”结论）")
        return
    uncertain = summary.get('uncertain', 0)
    not_analyzed = summary.get('not_analyzed', 0)
    not_found = summary.get('not_found_in_static_analysis', summary.get('not_reachable', 0))
    user_conclusion_summary = dict(summary.get('user_conclusion_summary') or {})
    quality_gate = dict(summary.get('quality_gate') or {})
    needs_input = int(quality_gate.get('needs_input', user_conclusion_summary.get('需要补充输入', 0)) or 0)
    inconclusive = int(quality_gate.get('inconclusive', user_conclusion_summary.get('当前无法确认', 0)) or 0)
    probable_impact = int(quality_gate.get('probable_impact', user_conclusion_summary.get('可能影响', 0)) or 0)
    confirmed_impact = int(quality_gate.get('confirmed_impact', user_conclusion_summary.get('已确认影响', 0)) or 0)
    high_risk_inconclusive = int(quality_gate.get('high_risk_inconclusive', 0) or 0)
    if uncertain > 0:
        print(f"\n⚠️  {uncertain} 个风险点无法静态确认：", file=sys.stderr)
        for item in summary.get('uncertain_apis', [])[:5]:
            print(f"  - {item.get('api','')[:60]}: {item.get('reason','')[:60]}", file=sys.stderr)
    if not_analyzed > 0:
        print(f"\n⚠️  {not_analyzed} 个风险点属于未覆盖/未分析：", file=sys.stderr)
        for item in summary.get('not_analyzed_apis', [])[:5]:
            print(f"  - {item.get('api','')[:60]}: {item.get('reason','')[:60]}", file=sys.stderr)
    if not_found > 0:
        print(f"\n⚠️  {not_found} 个风险点属于静态未找到路径：", file=sys.stderr)
        for item in summary.get('not_found_apis', [])[:5]:
            print(f"  - {item.get('api','')[:60]}: {item.get('reason','')[:60]}", file=sys.stderr)
    if needs_input > 0:
        print(
            f"\n⚠️  Step5 仍有 {needs_input} 个风险点需要补充输入，"
            "应优先在 checkpoint 中补充 dependency_source_dirs 或选择重跑当前步骤。",
            file=sys.stderr,
        )
    if strict_risk_gate and (uncertain > 0 or not_analyzed > 0 or not_found > 0):
        fail(
            f"严格模式下调用链仍存在盲区：uncertain={uncertain}, not_analyzed={not_analyzed}, not_found={not_found}",
            ["补齐 dependency_source_dirs、排查静态未找到项，或关闭严格模式后重试"]
        )
    if strict_risk_gate and high_risk_inconclusive > 0:
        fail(
            f"严格模式下仍有 {high_risk_inconclusive} 个高风险项无法确认",
            ["优先人工复核 P0/P1 的当前无法确认项，必要时补输入后重跑 Step5"],
        )
    ok(
        f"call_chain 门控通过：已确认影响={confirmed_impact} 可能影响={probable_impact} "
        f"当前无法确认={inconclusive} 静态未找到={not_found}"
    )

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--step', required=True, choices=GATES)
    ap.add_argument('--report-dir', default='.upgrade-report')
    ap.add_argument('--strict-risk-gate', action='store_true')
    args = ap.parse_args()
    gates = {'step1_scope': gate_step1_scope, 'context': gate_context, 'scan': gate_scan,
             'jar_compare': gate_jar_compare, 'call_chain': lambda d: gate_call_chain(d, strict_risk_gate=args.strict_risk_gate)}
    gates[args.step](args.report_dir)
    print(f"\n门控 [{args.step}] 通过，可以进入下一步。", file=sys.stderr)

if __name__ == '__main__': main()
