#!/usr/bin/env python3
"""gate.py — 步骤门控器（完整版在 java-upgrade-analyzer/scripts/gate.py）"""
import argparse, csv, json, os, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pipeline_constants import (
    EVIDENCE_API_CHANGES_DIRNAME,
    EVIDENCE_CALL_CHAIN_DIRNAME,
    EVIDENCE_CONTEXT_DIRNAME,
    EVIDENCE_DEPENDENCIES_DIRNAME,
    EVIDENCE_DIRNAME,
    EVIDENCE_STATIC_SCAN_DIRNAME,
    GATE_SEQUENCE,
    RUNTIME_COVERAGE_DIRNAME,
    RUNTIME_DIRNAME,
    STEP1_DEPENDENCY_JARS_MANIFEST_FILE,
)
from analysis_contract import sha256_file
from artifact_safety import require_safe_archive
from csv_io import open_csv_read
GATES = list(GATE_SEQUENCE)

def python_cmds():
    return (
        ['python', 'py -3']
        if sys.platform == 'win32'
        else ['python3', 'python']
    )

def fail(msg, instructions=None):
    print(f"\n{'='*60}\n❌ 门控未通过：{msg}", file=sys.stderr)
    if instructions:
        print("\n需要执行：", file=sys.stderr)
        for i in instructions: print(f"  {i}", file=sys.stderr)
    print('='*60, file=sys.stderr)
    sys.exit(1)

def ok(msg): print(f"✅ {msg}", file=sys.stderr)


def evidence_dependencies_dir(report_dir):
    return Path(report_dir) / EVIDENCE_DIRNAME / EVIDENCE_DEPENDENCIES_DIRNAME


def evidence_context_dir(report_dir):
    return Path(report_dir) / EVIDENCE_DIRNAME / EVIDENCE_CONTEXT_DIRNAME


def evidence_static_scan_dir(report_dir):
    return Path(report_dir) / EVIDENCE_DIRNAME / EVIDENCE_STATIC_SCAN_DIRNAME


def evidence_api_changes_dir(report_dir):
    return Path(report_dir) / EVIDENCE_DIRNAME / EVIDENCE_API_CHANGES_DIRNAME


def evidence_call_chain_dir(report_dir):
    return Path(report_dir) / EVIDENCE_DIRNAME / EVIDENCE_CALL_CHAIN_DIRNAME


def runtime_coverage_dir(report_dir):
    return Path(report_dir) / RUNTIME_DIRNAME / RUNTIME_COVERAGE_DIRNAME


def dep_changes_path(report_dir):
    return evidence_dependencies_dir(report_dir) / "dep_changes.csv"


def current_resolved_path(report_dir):
    return evidence_dependencies_dir(report_dir) / "deps_current_resolved.csv"


def provenance_path(report_dir):
    return evidence_dependencies_dir(report_dir) / "build_provenance.json"


def dependency_jars_manifest_path(report_dir):
    return evidence_dependencies_dir(report_dir) / STEP1_DEPENDENCY_JARS_MANIFEST_FILE


def context_path(report_dir):
    return evidence_context_dir(report_dir) / "context.json"


def coverage_path(report_dir):
    return runtime_coverage_dir(report_dir) / "coverage.json"


def read_csv_dicts(path, required_headers):
    try:
        with open_csv_read(path) as f:
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


def require_safe_step1_retained_archive(path, label):
    try:
        require_safe_archive(
            path,
            inspect_nested_archives=False,
            allow_duplicate_maven_metadata=True,
        )
    except (OSError, ValueError) as exc:
        fail(
            f"Step1 留存制品安全校验失败：{label}（{exc}）",
            ["修复 Step1 最终制品条目后重新执行 Step1；禁止继续 Step4/Step5"],
        )


def gate_step1_scope(d):
    csv_path = dep_changes_path(d)
    current_csv_path = current_resolved_path(d)
    provenance_file = provenance_path(d)
    if not csv_path.exists():
        fail("evidence/dependencies/dep_changes.csv 不存在，请先执行 Step 1",
             [f"{pc} scripts/run_step.py --step step1 --project-dir . --report-dir .upgrade-report --base-branch <base_branch> --current-branch <current_branch>"
              for pc in python_cmds()])
    dep_rows = read_csv_dicts(
        csv_path,
        [
            "coord", "old_version", "new_version", "change_type", "risk", "scope",
            "resolution_status", "base_lib_entry", "current_lib_entry",
        ],
    )
    valid_dep_rows = [row for row in dep_rows if (row.get("coord") or "").strip() and has_dep_versions(row)]
    if not valid_dep_rows:
        fail("evidence/dependencies/dep_changes.csv 没有有效依赖数据行，请检查 Step1 的真实构建结果是否完整")
    if not current_csv_path.exists():
        fail("evidence/dependencies/deps_current_resolved.csv 不存在，请重新执行 Step 1",
             [f"{pc} scripts/run_step.py --step step1 --project-dir . --report-dir .upgrade-report --base-branch <base_branch> --current-branch <current_branch>"
              for pc in python_cmds()])
    current_rows = read_csv_dicts(
        current_csv_path,
        [
            "coord", "version", "scope", "remark", "lib_entry",
            "resolution_status",
        ],
    )
    valid_current_rows = [
        row for row in current_rows
        if (row.get("coord") or "").strip() and (row.get("version") or "").strip() not in ("", "-")
    ]
    if not valid_current_rows:
        fail("evidence/dependencies/deps_current_resolved.csv 没有有效当前依赖数据行，请重新执行 Step 1")
    if not provenance_file.exists():
        fail("evidence/dependencies/build_provenance.json 不存在，无法证明 base/current 均来自成功构建或有效产物")
    with open(provenance_file, encoding="utf-8", errors="replace") as f:
        provenance = json.load(f)
    sides = list(provenance.get("sides") or [])
    if not provenance.get("both_builds_succeeded") or {item.get("side") for item in sides} != {"base", "current"}:
        fail("仅允许分析 base/current 均成功构建的升级结果")
    if any(not item.get("artifact_sha256") for item in sides):
        fail("evidence/dependencies/build_provenance.json 缺少 base/current 产物哈希，无法校验源码与制品对齐")
    manifest_file = dependency_jars_manifest_path(d)
    if not manifest_file.is_file():
        fail("Step1 依赖制品清单不存在，请重新执行 Step1")
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"Step1 依赖制品清单无法读取：{type(exc).__name__}")
    manifest_items = list(manifest.get("items") or [])
    gav_hashes = {}
    for item in manifest_items:
        coord = str(item.get("coord") or "").strip()
        coord_parts = coord.split(":", 2)
        classifier = str(item.get("classifier") or "").strip()
        if not classifier and len(coord_parts) == 3:
            classifier = coord_parts[2].strip()
        gav_coord = (
            ":".join(coord_parts[:2])
            if len(coord_parts) >= 2
            else coord
        )
        key = (
            str(item.get("side") or "").strip(),
            gav_coord,
            str(item.get("version") or "").strip(),
            classifier,
        )
        gav_hashes.setdefault(key, set()).add(
            str(item.get("nested_jar_sha256") or "").lower()
        )
    for (side, coord, version, classifier), hashes in gav_hashes.items():
        if len(hashes) > 1:
            classifier_suffix = f":{classifier}" if classifier else ""
            fail(
                f"Step1 同一 GAV 对应多个不同字节的最终制品条目："
                f"{side} {coord}:{version}{classifier_suffix}"
            )
    item_by_side_entry = {
        (
            str(item.get("side") or "").strip(),
            str(item.get("lib_entry") or "").replace("\\", "/").strip(),
        ): item
        for item in manifest_items
        if isinstance(item, dict)
    }
    for row in dep_rows:
        if str(row.get("resolution_status") or "").strip() != "resolved":
            continue
        if str(row.get("change_type") or "").strip() == "未变":
            continue
        for side, version_field, entry_field in (
            ("base", "old_version", "base_lib_entry"),
            ("current", "new_version", "current_lib_entry"),
        ):
            if str(row.get(version_field) or "").strip() in ("", "-"):
                continue
            lib_entry = str(row.get(entry_field) or "").replace("\\", "/").strip()
            if not lib_entry:
                fail(f"Step1 变化依赖缺少 {entry_field}：{row.get('coord')}")
            item = item_by_side_entry.get((side, lib_entry))
            if not item:
                fail(f"Step1 未留存变化依赖 JAR：{row.get('coord')}（{side}）")
            retained_path = Path(str(item.get("retained_path") or ""))
            expected_sha = str(item.get("nested_jar_sha256") or "").strip()
            if not retained_path.is_file() or not expected_sha:
                fail(f"Step1 变化依赖 JAR 不可用：{row.get('coord')}（{side}）")
            if sha256_file(retained_path) != expected_sha:
                fail(f"Step1 变化依赖 JAR SHA-256 不一致：{row.get('coord')}（{side}）")
            require_safe_step1_retained_archive(
                retained_path,
                f"{row.get('coord')}（{side}）",
            )
    for row in current_rows:
        if str(row.get("resolution_status") or "").strip() != "resolved":
            continue
        if str(row.get("scope") or "").strip() in {"test", "provided", "optional"}:
            continue
        coord = str(row.get("coord") or "").strip()
        version = str(row.get("version") or "").strip()
        if not coord or version in ("", "-"):
            continue
        lib_entry = str(row.get("lib_entry") or "").replace("\\", "/").strip()
        if not lib_entry:
            fail(f"Step1 当前运行依赖缺少 lib_entry：{coord}")
        item = item_by_side_entry.get(("current", lib_entry))
        if not item or "step5_runtime" not in set(item.get("purposes") or ()):
            fail(f"Step1 未留存当前运行依赖 JAR：{coord}")
        retained_path = Path(str(item.get("retained_path") or ""))
        expected_sha = str(item.get("nested_jar_sha256") or "").strip()
        if not retained_path.is_file() or not expected_sha:
            fail(f"Step1 当前运行依赖 JAR 不可用：{coord}")
        if sha256_file(retained_path) != expected_sha:
            fail(f"Step1 当前运行依赖 JAR SHA-256 不一致：{coord}")
        require_safe_step1_retained_archive(retained_path, coord)
    for item in manifest.get("business_artifacts") or ():
        if not isinstance(item, dict) or str(item.get("side") or "") != "current":
            continue
        retained_path = Path(str(item.get("retained_path") or ""))
        expected_sha = str(item.get("sha256") or "").strip()
        if not retained_path.is_file() or not expected_sha:
            fail("Step1 当前业务类制品不可用")
        if sha256_file(retained_path) != expected_sha:
            fail("Step1 当前业务类制品 SHA-256 不一致")
        require_safe_step1_retained_archive(retained_path, "current 业务内容")
    ok(f"step1_scope 门控通过：变更清单={len(valid_dep_rows)} 当前依赖={len(valid_current_rows)}")

def gate_context(d):
    ctx_path = context_path(d)
    if not ctx_path.exists(): fail("evidence/context/context.json 不存在")
    with open(ctx_path, encoding="utf-8", errors="replace") as f:
        ctx = json.load(f)
    missing = [f for f in ['build_tool', 'base_branch', 'current_branch'] if not ctx.get(f)]
    if missing: fail(f"evidence/context/context.json 缺少字段：{missing}", ["请在 Step2 checkpoint 中补充缺失字段后重跑"])
    needs = []
    if not ctx.get('jdk_base') or ctx.get('jdk_base') == 'unknown': needs.append("jdk_base")
    if not ctx.get('jdk_current') or ctx.get('jdk_current') == 'unknown': needs.append("jdk_current")
    if needs:
        print(
            f"\n⚠️  以下字段无法自动推断，需在 Step2 checkpoint 中人工确认或补充：{needs}",
            file=sys.stderr,
        )
        print(
            '  - 请复核 .upgrade-report/evidence/context/context.json 中的 jdk_base/jdk_current，必要时手动补为 "8"、"17"、"21"',
            file=sys.stderr,
        )
    ok(f"context 门控通过：JDK {ctx.get('jdk_base')}→{ctx.get('jdk_current')}")

def gate_scan(d):
    ctx_path = context_path(d)
    ctx = {}
    scan_dir = evidence_static_scan_dir(d)
    if ctx_path.exists():
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
            if not (scan_dir / f).exists():
                issues.append(f)
    if ctx.get('springboot_major_upgrade') and not (scan_dir / "s3_jdk_javax_refs.csv").exists():
        issues.append('s3_jdk_javax_refs.csv')
    if ctx.get('springboot_major_upgrade'):
        for f in ['s3_springboot_config.csv', 's3_springboot_autoconfig.txt']:
            if not (scan_dir / f).exists():
                issues.append(f)
    if current_resolved_path(d).exists() or dep_changes_path(d).exists():
        dep_compat = scan_dir / "s3_dependency_compat.csv"
        if not dep_compat.exists():
            issues.append('s3_dependency_compat.csv')
        dep_classfile = scan_dir / "s3_dependency_classfile.csv"
        if not dep_classfile.exists():
            issues.append('s3_dependency_classfile.csv')
    if issues:
        fail(f"以下扫描文件缺失：{issues}",
             [f"{pc} scripts/run_step.py --step step3 --project-dir . --report-dir .upgrade-report"
              for pc in python_cmds()])
    ok("scan 门控通过")

def gate_jar_compare(d, strict_risk_gate=False):
    jar_dir = evidence_api_changes_dir(d)
    csv_path = jar_dir / "all_changed_apis.csv"
    ref_txt_path = jar_dir / "git_ref_matches.txt"
    ref_json_path = jar_dir / "git_ref_matches.json"
    pending_ref_path = jar_dir / "git_ref_pending.json"
    timeouts_path = jar_dir / "timeouts.json"
    if not csv_path.exists():
        fail("evidence/api_changes/all_changed_apis.csv 不存在，请先执行 Step 4（jar 对比）")
    for path in (ref_txt_path, ref_json_path):
        if not path.exists():
            fail(f"{os.path.basename(path)} 不存在，请重新执行 Step 4，确认源码 diff ref 匹配结果已生成")
    if pending_ref_path.exists():
        with open(pending_ref_path, encoding="utf-8", errors="replace") as f:
            pending_payload = json.load(f)
        pending_items = list(pending_payload.get("items") or [])
        if pending_items:
            fail(
                f"以下依赖的 git refs 仍待人工确认：{len(pending_items)} 个",
                [
                    "查看 evidence/api_changes/git_ref_pending.json 与 git_ref_matches.*，确认 old_ref/new_ref 后重跑 Step4",
                    "通过 --response-json 传入 dependency_git_ref_overrides，再继续流程",
                ],
            )
    if timeouts_path.exists():
        with open(timeouts_path, encoding="utf-8", errors="replace") as f:
            timeout_payload = json.load(f)
        timeout_items = list(timeout_payload.get("items") or [])
        if timeout_items:
            if strict_risk_gate:
                fail(
                    f"严格模式下 Step4 不允许存在超时证据缺失：{len(timeout_items)} 项",
                    ["查看 evidence/api_changes/timeouts.json，修复后重跑 Step4"],
                )
            print(
                f"\n⚠️ Step4 存在 {len(timeout_items)} 个超时项；标准模式继续生成受限结论，"
                "不会把证据缺口解释为无影响。",
                file=sys.stderr,
            )
    with open(csv_path, encoding="utf-8", errors="replace") as f:
        rows = sum(1 for l in f if l.strip() and not l.startswith('#')) - 1
    print(f"  all_changed_apis.csv：{rows} 个变更 API", file=sys.stderr)

    if rows == 0:
        print("\n⚠️  Step 4 未识别到变更 API。Step5 将基于空输入生成跳过说明，而不是直接得出“无风险”结论。", file=sys.stderr)

    jar_missing = []
    if jar_dir.is_dir():
        for f in os.listdir(jar_dir):
            if f.endswith('_binary.txt'):
                try:
                    content = open(jar_dir / f, encoding="utf-8", errors="replace").read(200)
                    if '最终制品' in content and ('证据缺失' in content or '未找到' in content):
                        jar_missing.append(f)
                except (OSError, UnicodeError) as exc:
                    jar_missing.append(f"{f}:unreadable:{type(exc).__name__}")
    if jar_missing:
        fail(
            f"以下依赖缺少最终制品 JAR 证据，Step4 证据池不完整：{jar_missing[:5]}",
            ["修复 Step1 最终制品或制品内依赖条目证据后，重新执行 Step4"]
        )
    ok(f"jar_compare 门控通过：{rows} 个变更 API")

def gate_call_chain(d, strict_risk_gate=False):
    summary_path = evidence_call_chain_dir(d) / "summary.json"
    if not summary_path.exists():
        fail("evidence/call_chain/summary.json 不存在，请先执行 Step 5")
    with open(summary_path, encoding="utf-8", errors="replace") as f:
        summary = json.load(f)
    coverage_file = coverage_path(d)
    coverage = {}
    if coverage_file.is_file():
        try:
            coverage = json.loads(coverage_file.read_text(encoding='utf-8'))
        except json.JSONDecodeError:
            fail('.runtime/coverage/coverage.json 无效，无法判断分析完整性')
    critical_incomplete = list(coverage.get('critical_incomplete') or [])
    components = {item.get('id'): item for item in coverage.get('components') or []}
    if critical_incomplete and coverage.get('enforcement') == 'required':
        # Standard mode may continue to produce a diagnostic report, but the
        # report must not turn this into a safe/zero-impact conclusion. Strict
        # mode below remains a hard gate.
        print(
            f"\n⚠️ 关键覆盖维度未完整，标准模式仅允许生成受限结论：{critical_incomplete}",
            file=sys.stderr,
        )
        summary['safe_conclusion_allowed'] = False
    if strict_risk_gate and critical_incomplete:
        fail(
            f"严格模式要求关键覆盖维度全部 complete：{critical_incomplete}",
            ['根据 .runtime/coverage/coverage.json 补齐 partial/insufficient 维度后重跑'],
        )
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
    needs_input = int(quality_gate.get('needs_input', user_conclusion_summary.get('input_required', 0)) or 0)
    inconclusive = int(quality_gate.get('inconclusive', user_conclusion_summary.get('inconclusive', 0)) or 0)
    probable_impact = int(quality_gate.get('probable_impact', user_conclusion_summary.get('probable_impact', 0)) or 0)
    confirmed_impact = int(quality_gate.get('confirmed_impact', user_conclusion_summary.get('confirmed_impact', 0)) or 0)
    confirmed_no_impact = int(summary.get('not_impacted', user_conclusion_summary.get('confirmed_no_impact', 0)) or 0)
    high_risk_inconclusive = int(quality_gate.get('high_risk_inconclusive', 0) or 0)
    if uncertain > 0:
        print(f"\n⚠️  {uncertain} 个风险点需要人工复核：", file=sys.stderr)
        for item in summary.get('uncertain_apis', [])[:5]:
            print(f"  - {item.get('api','')[:60]}: {item.get('reason','')[:60]}", file=sys.stderr)
    if not_analyzed > 0:
        print(f"\n⚠️  {not_analyzed} 个风险点本次未完成分析：", file=sys.stderr)
        for item in summary.get('not_analyzed_apis', [])[:5]:
            print(f"  - {item.get('api','')[:60]}: {item.get('reason','')[:60]}", file=sys.stderr)
    if not_found > 0:
        print(f"\n⚠️  {not_found} 个风险点未发现调用路径：", file=sys.stderr)
        for item in summary.get('not_found_apis', [])[:5]:
            print(f"  - {item.get('api','')[:60]}: {item.get('reason','')[:60]}", file=sys.stderr)
    if needs_input > 0:
        print(
            f"\n⚠️  Step5 仍有 {needs_input} 个风险点缺少依赖源码证据；"
            "系统已使用最终制品字节码继续并限制相关结论。"
            "如需提高覆盖率，可在报告生成后补充源码并重跑 Step5。",
            file=sys.stderr,
        )
    if strict_risk_gate and (uncertain > 0 or not_analyzed > 0 or not_found > 0):
        fail(
            f"严格模式下调用链仍存在未完成项：需人工复核={uncertain}, 本次未完成分析={not_analyzed}, 未发现调用路径={not_found}",
            ["补齐依赖源码目录、排查未发现调用路径的项，或关闭严格模式后重试"]
        )
    if strict_risk_gate and high_risk_inconclusive > 0:
        fail(
            f"严格模式下仍有 {high_risk_inconclusive} 个高风险项需要人工复核",
            ["优先人工复核 P0/P1 项，必要时补输入后重跑 Step5"],
        )
    ok(
        f"call_chain 门控通过：已确认影响={confirmed_impact} 可能影响={probable_impact} "
        f"已确认不受影响={confirmed_no_impact} 需人工复核={inconclusive} 未发现调用路径={not_found}"
    )

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--step', required=True, choices=GATES)
    ap.add_argument('--report-dir', default='.upgrade-report')
    ap.add_argument('--strict-risk-gate', action='store_true')
    args = ap.parse_args()
    gates = {'step1_scope': gate_step1_scope, 'context': gate_context, 'scan': gate_scan,
             'jar_compare': lambda d: gate_jar_compare(d, strict_risk_gate=args.strict_risk_gate),
             'call_chain': lambda d: gate_call_chain(d, strict_risk_gate=args.strict_risk_gate)}
    gates[args.step](args.report_dir)
    print(f"\n门控 [{args.step}] 通过，可以进入下一步。", file=sys.stderr)

if __name__ == '__main__': main()
