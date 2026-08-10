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
from binary_report import load_validated_generation
from binary_first_contract import BinaryFirstContractError
from csv_io import open_csv_read
from s4_contract import ALL_CHANGED_APIS_FIELDS
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
        if not item or "binary_runtime" not in set(item.get("purposes") or ()):
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

def gate_binary_generation(d, strict_risk_gate=False):
    jar_dir = evidence_api_changes_dir(d)
    api_path = jar_dir / "all_changed_apis.csv"
    dependency_path = jar_dir / "changed_dependencies.csv"
    summary_path = jar_dir / "summary.json"
    required_user_files = (
        api_path,
        dependency_path,
        jar_dir / "changed_dependencies.md",
        summary_path,
        jar_dir / "summary.md",
        jar_dir / "review.md",
        jar_dir / "business_bytecode_changed_api_refs.csv",
        jar_dir / "business_bytecode_priority_evidence.json",
    )
    try:
        loaded = load_validated_generation(d)
    except BinaryFirstContractError as exc:
        fail(f"binary generation 完整性门禁失败：{exc.reason_code}: {exc}")
    missing = [str(path.relative_to(Path(d))) for path in required_user_files if not path.is_file()]
    if missing:
        fail(f"Step4 面向用户的复核文件缺失：{missing}")
    try:
        published = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"Step4 summary.json 无效：{exc}")
    if (
        published.get("schema") != "java-upgrade-analyzer.binary-step4-summary.v1"
        or published.get("authority") != "binary_first"
        or published.get("result_generation_identity")
        != loaded["manifest"].get("result_generation_identity")
    ):
        fail("Step4 发布结果与 active binary generation 不一致")
    api_rows = read_csv_dicts(api_path, ALL_CHANGED_APIS_FIELDS)
    dependency_rows = read_csv_dicts(
        dependency_path, ("coord", "changed_api_count", "detail")
    )
    if any(not row.get("coord") or row.get("coord") == "UNBOUND_RUNTIME_ARTIFACT" for row in api_rows):
        fail("Step4 发布的变化 API 缺少可复核的依赖包身份")
    api_coords = {row["coord"] for row in api_rows}
    dependency_coords = {row["coord"] for row in dependency_rows}
    if api_coords != dependency_coords:
        fail("Step4 API 明细与依赖包汇总的坐标集合不一致")
    if len(api_rows) != int(published.get("published_api_change_count") or 0):
        fail("Step4 all_changed_apis.csv 行数与 generation 发布摘要不一致")
    authoritative = int(published.get("authoritative_change_fact_count") or 0)
    diagnostic = int(published.get("diagnostic_candidate_fact_count") or 0)
    excluded = int(published.get("excluded_decision_count") or 0)
    if strict_risk_gate and loaded["summary"].get("decision_coverage_status") != "complete":
        fail("严格门禁要求 binary decision coverage=complete")
    ok(
        "binary_generation 门控通过："
        f"正式变化={authoritative} 诊断候选={diagnostic} 排除={excluded}，独立 Oracle 已通过"
    )

def gate_binary_report(d, strict_risk_gate=False):
    summary_path = evidence_call_chain_dir(d) / "summary.json"
    if not summary_path.exists():
        fail("evidence/call_chain/summary.json 不存在，请先执行 Step 5")
    try:
        loaded = load_validated_generation(d)
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except BinaryFirstContractError as exc:
        fail(f"binary generation 完整性门禁失败：{exc.reason_code}: {exc}")
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"Step5 summary.json 无效：{exc}")
    if (
        summary.get("schema") != "java-upgrade-analyzer.binary-step5-summary.v1"
        or summary.get("authority") != "binary_first"
        or summary.get("result_generation_identity")
        != loaded["manifest"].get("result_generation_identity")
    ):
        fail("Step5 发布结果与 active binary generation 不一致")
    user_files = (
        evidence_call_chain_dir(d) / "summary.md",
        evidence_call_chain_dir(d) / "alerts.csv",
        evidence_call_chain_dir(d) / "by_api",
    )
    missing = [str(path.relative_to(Path(d))) for path in user_files if not path.exists()]
    if missing:
        fail(f"Step5 面向用户的复核文件缺失：{missing}")
    alert_rows = read_csv_dicts(
        evidence_call_chain_dir(d) / "alerts.csv",
        (
            "api_identity", "target_coord", "changed_symbol",
            "api_signature", "path_status", "path_text",
        ),
    )
    published_api_identities = {
        row["api_identity"] for row in alert_rows if row.get("api_identity")
    }
    if len(published_api_identities) != int(summary.get("total_apis") or 0):
        fail("Step5 alerts.csv 的唯一 API 数与 summary.json 不一致")
    if any(not row.get("target_coord") for row in alert_rows):
        fail("Step5 触达结果丢失依赖包维度")
    query_index_path = Path(d) / RUNTIME_DIRNAME / "indexes" / "s5_query_index.json"
    try:
        query_index = json.loads(query_index_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"Step5 调用链查询索引无效：{exc}")
    if (
        query_index.get("schema") != "java-upgrade-analyzer.s5-query-index.v1"
        or query_index.get("result_generation_identity")
        != loaded["manifest"].get("result_generation_identity")
    ):
        fail("Step5 调用链查询索引与 active binary generation 不一致")
    uncertain = int(summary.get("uncertain") or 0)
    not_analyzed = int(summary.get("not_analyzed") or 0)
    if strict_risk_gate and loaded["summary"].get("trace_coverage_status") != "complete":
        fail("严格门禁要求 binary trace coverage=complete")
    if strict_risk_gate and (uncertain or not_analyzed):
        fail(
            f"严格门禁不允许未完成结果：uncertain={uncertain}, not_analyzed={not_analyzed}"
        )
    ok(
        "binary_report 门控通过："
        f"reachable={summary.get('reachable', 0)} "
        f"uncertain={uncertain} "
        f"not_found={summary.get('not_found_in_static_analysis', 0)} "
        f"not_analyzed={not_analyzed}"
    )

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--step', required=True, choices=GATES)
    ap.add_argument('--report-dir', default='.upgrade-report')
    ap.add_argument('--strict-risk-gate', action='store_true')
    args = ap.parse_args()
    gates = {'step1_scope': gate_step1_scope, 'context': gate_context, 'scan': gate_scan,
             'binary_generation': lambda d: gate_binary_generation(d, strict_risk_gate=args.strict_risk_gate),
             'binary_report': lambda d: gate_binary_report(d, strict_risk_gate=args.strict_risk_gate)}
    gates[args.step](args.report_dir)
    print(f"\n门控 [{args.step}] 通过，可以进入下一步。", file=sys.stderr)

if __name__ == '__main__': main()
