#!/usr/bin/env python3
"""gate.py — 步骤门控器（完整版在 java-upgrade-analyzer/scripts/gate.py）"""
import argparse, csv, json, os, sys
from collections import Counter, defaultdict
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
from binary_report import (
    _validate_step6_candidate_under_parent_workflow_lock,
    _step5_publication_input_identity,
    write_binary_report_publication_failure_result,
    load_validated_generation,
    materialize_report_publication_gate_candidate,
    materialize_report_publication_committed_snapshot,
    validate_step6_publication_candidate,
)
from binary_first_contract import BinaryFirstContractError
from csv_io import open_csv_read
from path_runtime import short_temporary_directory
from s4_contract import (
    ALL_CHANGED_APIS_FIELDS, DEFAULT_SEVERITY, make_per_dependency_dirname,
)
from signature_utils import jvm_method_parameter_signature
GATES = list(GATE_SEQUENCE)
_GATE_RESULT_JSON_PATH = ""

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


def fail_binary_report_contract(message, error):
    if _GATE_RESULT_JSON_PATH:
        write_binary_report_publication_failure_result(
            _GATE_RESULT_JSON_PATH,
            error,
            phase="step6",
        )
    fail(message)

def ok(msg): print(f"✅ {msg}", file=sys.stderr)


def _formal_step5_target(item):
    """Independently project one validated-generation API for gate checks."""

    artifacts = list(item.get("dependency_artifacts") or ())
    lineages = sorted({
        str(artifact.get("logical_dependency_lineage") or "").strip()
        for artifact in artifacts
        if str(artifact.get("logical_dependency_lineage") or "").strip()
    })
    base_coords = [
        str(artifact.get("coord") or "").strip()
        for artifact in artifacts
        if artifact.get("side") == "base" and artifact.get("coord")
    ]
    current_coords = [
        str(artifact.get("coord") or "").strip()
        for artifact in artifacts
        if artifact.get("side") == "current" and artifact.get("coord")
    ]
    fallback_origin = next((
        str(artifact.get("runtime_code_source_origin_identity") or "").strip()
        for artifact in artifacts
        if artifact.get("runtime_code_source_origin_identity")
    ), "")
    declared_coords = sorted({
        str(coord or "").strip()
        for key in ("base_dependency_coords", "current_dependency_coords")
        for coord in item.get(key) or ()
        if str(coord or "").strip()
    })
    versioned_candidate = next(iter(current_coords or base_coords), "")
    parts = versioned_candidate.split(":")
    normalized_candidate = (
        ":".join(parts[:-1]) if len(parts) >= 3 else versioned_candidate
    )
    coord = next(iter(lineages), "") or normalized_candidate
    if not coord and declared_coords:
        declared_parts = declared_coords[0].split(":")
        coord = (
            ":".join(declared_parts[:-1])
            if len(declared_parts) >= 3 else declared_coords[0]
        )
    coord = coord or fallback_origin
    if not coord:
        coord = "未绑定制品（需查看裁决证据）"
    owner = str(item.get("display_owner") or "").replace("/", ".")
    member = str(item.get("display_member") or "")
    api = owner if not member or member == "<class>" else f"{owner}.{member}"
    descriptor = str(item.get("display_descriptor") or "")
    signature = (
        jvm_method_parameter_signature(descriptor)
        if descriptor.startswith("(") else ""
    )
    path_records = [
        path for path in item.get("paths") or ()
        if isinstance(path, dict) and str(path.get("path_text") or "").strip()
    ]
    paths = [str(path.get("path_text") or "").strip() for path in path_records]
    return {
        "reported_api_identity": str(
            item.get("reported_api_identity") or ""
        ).strip(),
        "coord": coord,
        "api": api,
        "api_signature": signature,
        "symbol_kind": str(item.get("display_member_kind") or ""),
        "analysis_status": str(item.get("reachability_status") or ""),
        "call_paths": paths,
        "path_details": [{
            "path_status": str(item.get("reachability_status") or ""),
            "path_text": str(path.get("path_text") or "").strip(),
            "path_certainty": str(path.get("path_certainty") or ""),
            "entry_kinds": list(path.get("entry_kinds") or ()),
            "entry_kind_labels": list(path.get("entry_kind_labels") or ()),
            "entrypoint_dependency_coords": list(
                path.get("entrypoint_dependency_coords") or ()
            ),
            "entrypoint_activation_reasons": list(
                path.get("entrypoint_activation_reasons") or ()
            ),
            "mechanism_kinds": list(path.get("mechanism_kinds") or ()),
            "mechanism_labels": list(path.get("mechanism_labels") or ()),
        } for path in path_records],
        "path_set_complete": bool(item.get("path_set_complete")),
        "exact_path_exists": bool(item.get("exact_path_exists")),
        "possible_path_exists": bool(item.get("possible_path_exists")),
        "impact_conclusion": str(item.get("impact_conclusion") or ""),
        "static_linkage_status": str(item.get("static_linkage_status") or ""),
        "runtime_verification_status": str(
            item.get("runtime_verification_status") or ""
        ),
        "contributing_change_fact_ids": [
            str(identity or "").strip()
            for identity in item.get("contributing_change_fact_ids") or ()
            if str(identity or "").strip()
        ],
    }


def _formal_step5_resource(item):
    coord = _formal_step5_target(item)["coord"]
    artifacts = list(item.get("dependency_artifacts") or ())
    base_coords = [
        str(artifact.get("coord") or "").strip()
        for artifact in artifacts
        if artifact.get("side") == "base" and artifact.get("coord")
    ]
    current_coords = [
        str(artifact.get("coord") or "").strip()
        for artifact in artifacts
        if artifact.get("side") == "current" and artifact.get("coord")
    ]

    def version(coords):
        if not coords:
            return "-"
        parts = coords[0].split(":")
        return parts[-1] if len(parts) >= 3 else coords[0]
    callers = []
    for caller in item.get("activation_callers") or ():
        if not isinstance(caller, dict) or caller.get("path_certainty") not in {
            "exact", "possible",
        }:
            continue
        owner = str(caller.get("caller_class_name") or "").replace("/", ".")
        member = str(caller.get("caller_member_name") or "")
        descriptor = str(caller.get("caller_descriptor") or "")
        signature = (
            jvm_method_parameter_signature(descriptor)
            if descriptor.startswith("(") else "()"
        )
        callers.append({
            **dict(caller),
            "display_caller": f"{owner}.{member}{signature}",
        })
    return {
        **dict(item),
        "coord": coord,
        "old_version": version(base_coords),
        "new_version": version(current_coords),
        "activation_callers": callers,
        "business_entries": sorted({
            caller["display_caller"] for caller in callers
            if caller.get("display_caller")
        }),
    }


def _step4_change_type(decision):
    scope = decision.get("fact_scope") or {}
    evidence = decision.get("evidence") or {}
    fact_kind = str(decision.get("fact_kind") or "")
    change_kind = str(
        scope.get("member_change_kind") or "implementation_changed"
    )
    base_contract = evidence.get("base_contract")
    current_contract = evidence.get("current_contract")
    if fact_kind == "member_resolution":
        return "MEMBER_RESOLUTION_CHANGED"
    if fact_kind == "provider_topology":
        base_status = str(
            (evidence.get("base_provider") or {}).get(
                "class_provider_status"
            ) or "missing"
        )
        current_status = str(
            (evidence.get("current_provider") or {}).get(
                "class_provider_status"
            ) or "missing"
        )
        if base_status == "resolved" and current_status == "missing":
            return "CLASS_REMOVED"
        if base_status == "missing" and current_status == "resolved":
            return "CLASS_ADDED"
        return "BEHAVIOR_CHANGED"
    if change_kind == "added" and fact_kind == "class":
        return "CLASS_ADDED"
    if change_kind == "added" and fact_kind == "field":
        return "DATA_FIELD_ADDED"
    if change_kind == "removed" and fact_kind == "field":
        return "DATA_FIELD_REMOVED"
    if (
        change_kind == "contract_changed"
        and isinstance(base_contract, dict)
        and isinstance(current_contract, dict)
    ):
        def visibility(access):
            value = int(access or 0)
            if value & 0x0001:
                return 3
            if value & 0x0004:
                return 2
            if value & 0x0002:
                return 0
            return 1

        if visibility(current_contract.get("access")) < visibility(
            base_contract.get("access")
        ):
            return "ACCESS_REDUCED"
        if fact_kind == "field" and base_contract.get(
            "descriptor"
        ) != current_contract.get("descriptor"):
            return "DATA_FIELD_TYPE_CHANGED"
        if fact_kind == "field" and base_contract.get(
            "constant"
        ) != current_contract.get("constant"):
            return "CONSTANT_VALUE_CHANGED"
        if base_contract.get("descriptor") != current_contract.get(
            "descriptor"
        ):
            return "SIGNATURE_CHANGED"
        return "CONTRACT_CHANGED"
    return {
        "removed": "REMOVED",
        "descriptor_changed": "SIGNATURE_CHANGED",
        "access_changed": "ACCESS_REDUCED",
        "constant_value_changed": "CONSTANT_VALUE_CHANGED",
        "added": "METHOD_ADDED",
        "implementation_changed": "BEHAVIOR_CHANGED",
        "contract_changed": "BEHAVIOR_CHANGED",
    }.get(change_kind, "BEHAVIOR_CHANGED")


def _step4_decision_projection(decision):
    scope = decision.get("fact_scope") or {}
    evidence = decision.get("evidence") or {}
    artifacts = list(decision.get("dependency_artifacts") or ())
    lineages = [
        str(item.get("logical_dependency_lineage") or "").strip()
        for item in artifacts if item.get("logical_dependency_lineage")
    ]
    base_coords = [
        str(item.get("coord") or "").strip()
        for item in artifacts
        if item.get("side") == "base" and item.get("coord")
    ]
    current_coords = [
        str(item.get("coord") or "").strip()
        for item in artifacts
        if item.get("side") == "current" and item.get("coord")
    ]
    coord = next((value for value in lineages if value), "")
    if not coord:
        candidate = next(iter(current_coords or base_coords), "")
        parts = candidate.split(":")
        coord = ":".join(parts[:-1]) if len(parts) >= 3 else candidate
    coord = coord or next((
        str(item.get("runtime_code_source_origin_identity") or "").strip()
        for item in artifacts if item.get("runtime_code_source_origin_identity")
    ), "") or "UNBOUND_RUNTIME_ARTIFACT"

    def version(coords):
        if not coords:
            return "-"
        parts = coords[0].split(":")
        return parts[-1] if len(parts) >= 3 else coords[0]

    owner = str(scope.get("class_name") or "").replace("/", ".")
    member = str(scope.get("member_name") or "")
    descriptor = str(scope.get("descriptor") or "")
    api_name = owner if not member or member == "<class>" else f"{owner}.{member}"
    member_kind = str(
        scope.get("member_kind") or decision.get("fact_kind") or "class"
    )
    if member == "<init>":
        member_kind = "constructor"
    if member_kind not in {"method", "field", "class", "constructor"}:
        member_kind = "class"
    signature = (
        jvm_method_parameter_signature(descriptor)
        if member_kind in {"method", "constructor"}
        and descriptor.startswith("(") else ""
    )
    change_type = _step4_change_type(decision)
    change_kind = str(
        scope.get("member_change_kind") or "implementation_changed"
    )
    change_label = {
        "added": "新增",
        "removed": "删除",
        "descriptor_changed": "签名变化",
        "access_changed": "访问权限变化",
        "constant_value_changed": "常量值变化",
        "implementation_changed": "实现变化",
        "contract_changed": "二进制契约变化",
        "class_provider": "类提供者变化",
        "class_definition": "类定义结果变化",
    }.get(change_kind, change_kind)
    if str(decision.get("fact_kind") or "") == "member_resolution":
        base_resolution = evidence.get("base_resolution") or {}
        current_resolution = evidence.get("current_resolution") or {}
        old_value = str(
            base_resolution.get("resolved_owner")
            or base_resolution.get("member_resolution_status")
            or ""
        )
        new_value = str(
            current_resolution.get("resolved_owner")
            or current_resolution.get("member_resolution_status")
            or ""
        )
    else:
        old_value = json.dumps(
            evidence.get("base_contract")
            or evidence.get("base_member_fingerprint")
            or "",
            ensure_ascii=False,
            sort_keys=True,
        )
        new_value = json.dumps(
            evidence.get("current_contract")
            or evidence.get("current_member_fingerprint")
            or "",
            ensure_ascii=False,
            sort_keys=True,
        )
    incompatible = change_type in {
        "REMOVED", "SIGNATURE_CHANGED", "ACCESS_REDUCED",
    }
    reason_code = str(decision.get("reason_code") or "")
    return {
        "conclusion": "二进制运行时有效变化",
        "change_summary": f"{change_label}：{api_name}{descriptor}",
        "review_reason": (
            f"依赖 {coord} 的运行时有效制品发生变化；"
            f"裁决原因 {reason_code or '-'}"
        ),
        "coord": coord,
        "old_version": version(base_coords),
        "new_version": version(current_coords),
        "change_type": change_type,
        "api_name": api_name,
        "api_simple": member or owner.rsplit(".", 1)[-1],
        "symbol_kind": member_kind,
        "api_signature": signature,
        "change_fact_identity": str(
            decision.get("change_fact_identity") or ""
        ),
        "decision_identity": str(decision.get("decision_identity") or ""),
        "confirmed": "true",
        "severity": DEFAULT_SEVERITY.get(change_type, "P1"),
        "source": "classfile_contract",
        "binary_compatible": "false" if incompatible else "true",
        "source_compatible": "false" if incompatible else "unknown",
        "compatibility_flags": reason_code,
        "reason_code": reason_code,
        "data_contract_evidence": "",
        "old_value": old_value,
        "new_value": new_value,
        "field_descriptor": descriptor if member_kind == "field" else "",
        "old_field_has_constant_value": "",
        "constant_field_evidence_json": "",
    }


def _step4_source_truth(loaded):
    """Reconstruct the public source-assistance views from generation facts."""

    coverage = dict(loaded.get("coverage") or {})
    inputs = dict(coverage.get("source_inputs") or {})
    overlay = dict(coverage.get("source_overlay") or {})
    attestation = dict(loaded.get("source_attestation") or {})
    business = dict(inputs.get("business") or {})
    dependencies = dict(inputs.get("dependencies") or {})
    business_available = business.get("status") == "available"
    dependency_available = dependencies.get("status") == "available"
    business_label = (
        "构建输入已具备并直接使用"
        if business_available and business.get("origin") == "checkout_build"
        else ("已提供并直接使用" if business_available else "未提供")
    )
    dependency_label = "已提供并直接使用" if dependency_available else "未提供"
    source_inputs = {
        "purpose_version": str(inputs.get("purpose_version") or "missing"),
        "business": business,
        "dependencies": dependencies,
        "label": f"业务源码：{business_label}；依赖源码：{dependency_label}",
        "effect": (
            "可用源码用于补充文件/行号、声明与语义解释；正式变化、运行时解析和精确可执行边"
            "仍由最终二进制制品决定。未提供的源码类别会单独保留解释覆盖缺口。"
        ),
        "coverage_status": str(
            overlay.get("coverage_status") or "not_provided"
        ),
        "mapped_count": int(overlay.get("mapped_count") or 0),
        "ambiguous_count": int(overlay.get("ambiguous_count") or 0),
        "conflict_count": int(overlay.get("conflict_count") or 0),
        "language_file_counts": dict(
            attestation.get("language_file_counts") or {}
        ),
        "coverage_gaps": list(attestation.get("coverage_gaps") or ()),
    }
    declarations = {
        str(item.get("overlay_identity") or ""): dict(item)
        for item in (
            (loaded.get("source_explanations") or {}).get("declarations")
            or ()
        )
        if isinstance(item, dict)
    }
    method_rows = []
    for item in overlay.get("rows") or ():
        if (
            not isinstance(item, dict)
            or str(item.get("mapping_status") or "") != "mapped"
        ):
            continue
        location = dict(item.get("source_location") or {})
        member = dict(item.get("binary_member") or {})
        descriptor = str(member.get("descriptor") or "")
        signature = (
            jvm_method_parameter_signature(descriptor)
            if descriptor.startswith("(") else descriptor
        )
        class_name = str(member.get("class_name") or "").replace("/", ".")
        member_name = str(member.get("member_name") or "")
        declaration = declarations.get(
            str(item.get("overlay_identity") or ""), {}
        )
        line = int(location.get("line") or 0)
        end_line = int(location.get("end_line") or 0)
        line_text = (
            str(line) if not end_line or end_line == line
            else f"{line}-{end_line}"
        )
        method_rows.append({
            "源码归属": str(location.get("owner_coord") or "未标识"),
            "归属类型": str(location.get("owner_type") or "unknown"),
            "二进制制品": str(member.get("artifact_coord") or "未标识"),
            "二进制方法": f"{class_name}.{member_name}{signature}",
            "源码位置": (
                f"{location.get('logical_path') or '未知'}:{line_text}"
                if line_text
                else str(location.get("logical_path") or "未知")
            ),
            "模块": str(location.get("module") or ""),
            "语言": str(location.get("language") or ""),
            "源码声明": str(declaration.get("declared_signature") or ""),
            "注解": "、".join(
                map(str, declaration.get("annotations") or ())
            ),
            "修饰符": " ".join(
                map(str, declaration.get("modifiers") or ())
            ),
        })
    method_rows.sort(key=lambda item: (
        item["源码归属"], item["二进制制品"],
        item["二进制方法"], item["源码位置"],
    ))
    candidate_rows = []
    for item in (
        (loaded.get("source_explanations") or {}).get(
            "candidate_relationships"
        ) or ()
    ):
        if not isinstance(item, dict):
            continue
        descriptor = str(item.get("caller_binary_descriptor") or "")
        signature = (
            jvm_method_parameter_signature(descriptor)
            if descriptor.startswith("(") else descriptor
        )
        caller_class = str(
            item.get("caller_binary_class_name") or ""
        ).replace("/", ".")
        candidate_rows.append({
            "源码归属": str(item.get("source_owner_coord") or "未标识"),
            "二进制制品": str(
                item.get("binary_artifact_coord") or "未标识"
            ),
            "调用方": (
                f"{caller_class}."
                f"{item.get('caller_binary_member_name') or ''}{signature}"
            ),
            "源码位置": (
                f"{item.get('caller_logical_path') or '未知'}:"
                f"{item.get('source_line') or 0}"
            ),
            "候选目标": str(item.get("callee_key") or ""),
            "证据类型": str(item.get("evidence_type") or ""),
            "置信度": str(item.get("confidence") or ""),
            "权威边界": "源码候选关系，不是可执行调用边",
        })
    gap_rows = [{
        "原因": (
            "该语言暂不提供源码位置/内联证明映射"
            if gap.get("reason_code") == "BINARY_SOURCE_LANGUAGE_NOT_MAPPED"
            else "源码解析不完整"
        ),
        "语言": str(gap.get("language") or ""),
        "源码归属": str(gap.get("owner_coord") or ""),
        "模块": str(gap.get("module") or ""),
        "源码文件": str(gap.get("logical_path") or ""),
        "解析器": str(gap.get("actual_parser") or ""),
        "错误节点": str(gap.get("error_nodes") or ""),
    } for gap in source_inputs["coverage_gaps"] if isinstance(gap, dict)]
    return source_inputs, method_rows, candidate_rows, gap_rows


def _step4_expected_source_review(source_inputs, method_rows, candidate_rows):
    language_summary = "、".join(
        f"{language} {count} 个"
        for language, count in sorted(
            source_inputs["language_file_counts"].items()
        )
    ) or "未提供源码文件"
    lines = [
        "# 源码辅助证据", "",
        f"- 源码状态：{source_inputs['label']}",
        f"- 覆盖状态：`{source_inputs['coverage_status']}`",
        f"- 已映射方法：{source_inputs['mapped_count']}",
        f"- 源码文件：{language_summary}",
        f"- 未映射/解析缺口：{len(source_inputs['coverage_gaps'])} 个；"
        "[查看逐文件缺口](coverage_gaps.csv)",
        "- 完整源码快照与 SHA：[source_snapshot.json](source_snapshot.json)",
        "", source_inputs["effect"], "",
    ]
    if method_rows:
        lines.extend((
            "| 源码归属 | 二进制制品 | 二进制方法 | 源码位置 | 源码声明 | 注解 |",
            "|---|---|---|---|---|---|",
        ))
        lines.extend(
            f"| `{row['源码归属']}` | `{row['二进制制品']}` | "
            f"`{row['二进制方法']}` | `{row['源码位置']}` | "
            f"{row['源码声明'] or '-'} | {row['注解'] or '-'} |"
            for row in method_rows
        )
    elif source_inputs["coverage_status"] == "not_provided":
        lines.append(
            "本次没有可用源码输入，因此没有源码映射行；这不影响二进制正式结论。"
        )
    else:
        lines.append(
            "已使用源码，但没有方法完成精确 descriptor 映射；请结合覆盖状态和冲突计数复核。"
        )
    lines.extend(("", "## 源码候选关系", ""))
    if candidate_rows:
        lines.extend((
            "以下关系用于人工解释和候选复核，不能替代字节码可执行边。",
            "",
            "| 源码归属 | 调用方 | 候选目标 | 源码位置 | 置信度 |",
            "|---|---|---|---|---|",
        ))
        lines.extend(
            f"| `{row['源码归属']}` | `{row['调用方']}` | "
            f"`{row['候选目标']}` | `{row['源码位置']}` | "
            f"`{row['置信度']}` |"
            for row in candidate_rows
        )
    else:
        lines.append("本次没有生成源码候选调用关系。")
    return "\n".join(lines) + "\n"


def _load_current_step4_api_rows(report_dir, expected_receipt_identity):
    report = Path(report_dir).resolve()
    with short_temporary_directory(
        prefix="jua-step5-gate-step4-snapshot-"
    ) as temporary:
        snapshot = materialize_report_publication_committed_snapshot(
            (
                evidence_api_changes_dir(report),
                report / EVIDENCE_DIRNAME / "source_analysis",
            ),
            Path(temporary).resolve(),
        )
        if snapshot.get("committed_receipt_identity") != expected_receipt_identity:
            fail("Step5 gate 读取的 Step4 快照不是当前绑定的 release")
        destinations = tuple(
            Path(item)
            for item in snapshot.get("snapshot_destinations") or ()
        )
        if len(destinations) != 2:
            fail("Step5 gate 的 Step4 committed snapshot 不完整")
        rows = read_csv_dicts(
            destinations[0] / "all_changed_apis.csv",
            ALL_CHANGED_APIS_FIELDS,
        )
        return rows, {
            **dict(snapshot),
            "snapshot_destinations": (),
        }


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
    if missing: fail(f"evidence/context/context.json 缺少字段：{missing}", ["Step0 确认记录或 Step2 上下文生成不完整，请从 Step0 修正输入后重跑"])
    needs = []
    if not ctx.get('jdk_base') or ctx.get('jdk_base') == 'unknown': needs.append("jdk_base")
    if not ctx.get('jdk_current') or ctx.get('jdk_current') == 'unknown': needs.append("jdk_current")
    if needs:
        print(
            f"\n⚠️  以下字段无法从 Step0 确认记录与制品证据推断：{needs}",
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
    invalid = []
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
    dependency_jars = evidence_dependencies_dir(d) / 'dependency_jars.json'
    if dependency_jars.exists():
        contract_files = (
            's3_database_contract_changes.csv',
            's3_database_contract_summary.json',
            's3_database_contract_changes.md',
        )
        for filename in contract_files:
            if not (scan_dir / filename).exists():
                issues.append(filename)
        if not any(filename in issues for filename in contract_files):
            summary_path = scan_dir / 's3_database_contract_summary.json'
            csv_path = scan_dir / 's3_database_contract_changes.csv'
            try:
                with summary_path.open(encoding='utf-8') as source:
                    contract_summary = json.load(source)
                if contract_summary.get('schema') != (
                    'java-upgrade-analyzer.database-contract-changes.v1'
                ):
                    invalid.append('s3_database_contract_summary.json:schema')
                if contract_summary.get('coverage_status') not in {
                    'complete', 'partial', 'insufficient'
                }:
                    invalid.append('s3_database_contract_summary.json:coverage_status')
                expected_count = int(contract_summary.get('change_count'))
                with open_csv_read(csv_path) as source:
                    reader = csv.DictReader(source)
                    required_columns = {
                        '依赖包', '变化类型', '契约类型', '可信度', '表', '列',
                        '契约位置', '语句或字段', '人工复核建议',
                    }
                    if not required_columns.issubset(set(reader.fieldnames or ())):
                        invalid.append('s3_database_contract_changes.csv:header')
                    actual_count = sum(1 for row in reader if row)
                if actual_count != expected_count:
                    invalid.append('s3_database_contract_changes.csv:row_count')
                review_text = (
                    scan_dir / 's3_database_contract_changes.md'
                ).read_text(encoding='utf-8')
                if '# 数据库契约变化明细' not in review_text:
                    invalid.append('s3_database_contract_changes.md:contract')
            except (
                OSError, UnicodeError, json.JSONDecodeError, AttributeError,
                TypeError, ValueError, csv.Error,
            ) as error:
                invalid.append(
                    f's3_database_contract_outputs:{type(error).__name__}'
                )
    if issues or invalid:
        detail = []
        if issues:
            detail.append(f"缺失={issues}")
        if invalid:
            detail.append(f"无效={invalid}")
        fail(f"扫描产物未通过门禁：{'；'.join(detail)}",
             [f"{pc} scripts/run_step.py --step step3 --project-dir . --report-dir .upgrade-report"
              for pc in python_cmds()])
    ok("scan 门控通过")

def gate_binary_generation(
    d,
    strict_risk_gate=False,
    *,
    candidate_api_dir=None,
    candidate_source_dir=None,
    candidate_activation_identity="",
):
    jar_dir = (
        Path(candidate_api_dir)
        if candidate_api_dir is not None
        else evidence_api_changes_dir(d)
    )
    api_path = jar_dir / "all_changed_apis.csv"
    dependency_path = jar_dir / "changed_dependencies.csv"
    summary_path = jar_dir / "summary.json"
    source_dir = (
        Path(candidate_source_dir)
        if candidate_source_dir is not None
        else Path(d) / EVIDENCE_DIRNAME / 'source_analysis'
    )
    required_user_files = (
        api_path,
        dependency_path,
        jar_dir / "changed_dependencies.md",
        summary_path,
        jar_dir / "summary.md",
        jar_dir / "review.md",
        jar_dir / "business_bytecode_changed_api_refs.csv",
        jar_dir / "business_bytecode_priority_evidence.json",
        source_dir / "review.md",
        source_dir / "method_mappings.csv",
        source_dir / "candidate_relationships.csv",
        source_dir / "coverage_gaps.csv",
        source_dir / "source_snapshot.json",
    )
    try:
        loaded = load_validated_generation(
            d,
            candidate_activation_identity=candidate_activation_identity,
        )
    except BinaryFirstContractError as exc:
        fail(f"binary generation 完整性门禁失败：{exc.reason_code}: {exc}")
    missing = [str(path) for path in required_user_files if not path.is_file()]
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
        or published.get("analysis_context_identity")
        != loaded["manifest"].get("analysis_context_identity")
    ):
        fail("Step4 发布结果与 active binary generation 不一致")
    decisions_payload = loaded.get("decisions") or {}
    projections_payload = loaded.get("projections") or {}
    authoritative_decisions = decisions_payload.get(
        "authoritative_change_facts"
    )
    diagnostic_decisions = decisions_payload.get("diagnostic_candidate_facts")
    excluded_decisions = decisions_payload.get("excluded_decisions")
    assessments = projections_payload.get(
        "authoritative_projection_assessments"
    )
    unprojectable = projections_payload.get("confirmed_unprojectable_facts")
    for label, rows in (
        ("authoritative_change_facts", authoritative_decisions),
        ("diagnostic_candidate_facts", diagnostic_decisions),
        ("excluded_decisions", excluded_decisions),
        ("authoritative_projection_assessments", assessments),
        ("confirmed_unprojectable_facts", unprojectable),
    ):
        if not isinstance(rows, list) or any(
            not isinstance(item, dict) for item in rows
        ):
            fail(f"validated generation 的 {label} 真值集合无效")
    decision_identities = [
        str(item.get("decision_identity") or "").strip()
        for item in authoritative_decisions
    ]
    fact_identities = [
        str(item.get("change_fact_identity") or "").strip()
        for item in authoritative_decisions
    ]
    if (
        any(not value for value in decision_identities + fact_identities)
        or len(set(decision_identities)) != len(decision_identities)
        or len(set(fact_identities)) != len(fact_identities)
    ):
        fail("validated generation 的正式变化事实/裁决身份为空或重复")
    assessment_decision_identities = [
        str(item.get("decision_identity") or "").strip()
        for item in assessments
    ]
    if (
        any(not value for value in assessment_decision_identities)
        or len(set(assessment_decision_identities)) != len(
            assessment_decision_identities
        )
        or set(assessment_decision_identities) != set(decision_identities)
    ):
        fail("validated generation 的投影裁决集合不守恒")
    assessment_by_decision = {
        str(item["decision_identity"]): item for item in assessments
    }
    targetable_decisions = [
        item for item in authoritative_decisions
        if assessment_by_decision[item["decision_identity"]].get(
            "analysis_projection_status"
        ) == "targetable"
    ]
    expected_unprojectable = {
        str(item.get("decision_identity") or "").strip()
        for item in authoritative_decisions
        if assessment_by_decision[item["decision_identity"]].get(
            "analysis_projection_status"
        ) == "unsupported"
    }
    actual_unprojectable = {
        str(item.get("decision_identity") or "").strip()
        for item in unprojectable
    }
    if (
        any(
            item.get("analysis_projection_status")
            not in {"targetable", "unsupported"}
            for item in assessments
        )
        or actual_unprojectable != expected_unprojectable
    ):
        fail("validated generation 的可投影/不可投影分区不一致")
    api_rows = read_csv_dicts(api_path, ALL_CHANGED_APIS_FIELDS)
    dependency_rows = read_csv_dicts(
        dependency_path, ("coord", "changed_api_count", "detail")
    )
    if len(dependency_rows) != len({row.get("coord") for row in dependency_rows}):
        fail("Step4 依赖包汇总包含重复坐标")
    if any(not row.get("coord") or row.get("coord") == "UNBOUND_RUNTIME_ARTIFACT" for row in api_rows):
        fail("Step4 发布的变化 API 缺少可复核的依赖包身份")
    api_coords = {row["coord"] for row in api_rows}
    dependency_coords = {row["coord"] for row in dependency_rows}
    if api_coords != dependency_coords:
        fail("Step4 API 明细与依赖包汇总的坐标集合不一致")
    if len(api_rows) != int(published.get("published_api_change_count") or 0):
        fail("Step4 all_changed_apis.csv 行数与 generation 发布摘要不一致")
    if len(dependency_rows) != int(published.get("dependency_count") or 0):
        fail("Step4 changed_dependencies.csv 行数与 generation 发布摘要不一致")
    api_count_by_coord = {}
    for row in api_rows:
        api_count_by_coord[row["coord"]] = api_count_by_coord.get(row["coord"], 0) + 1
    for row in dependency_rows:
        try:
            declared_count = int(row.get("changed_api_count") or "")
        except ValueError:
            fail("Step4 依赖包汇总的 changed_api_count 不是整数")
        if declared_count != api_count_by_coord.get(row["coord"], 0):
            fail("Step4 依赖包汇总与 API 明细计数不一致")
    expected_api_by_fact = {
        item["change_fact_identity"]: item
        for item in map(_step4_decision_projection, targetable_decisions)
    }
    actual_api_fact_identities = [
        str(row.get("change_fact_identity") or "").strip()
        for row in api_rows
    ]
    if (
        any(not value for value in actual_api_fact_identities)
        or len(set(actual_api_fact_identities)) != len(
            actual_api_fact_identities
        )
        or set(actual_api_fact_identities) != set(expected_api_by_fact)
    ):
        fail("Step4 all_changed_apis.csv 与正式可投影变化事实集合不一致")
    expected_fields = tuple(
        field for field in ALL_CHANGED_APIS_FIELDS
        if field != "evidence_path"
    )
    for row in api_rows:
        expected = expected_api_by_fact[row["change_fact_identity"]]
        mismatched = [
            field for field in expected_fields
            if row.get(field, "") != str(expected.get(field, ""))
        ]
        if mismatched:
            fail(
                "Step4 API 明细篡改或投影错误："
                f"fact={row['change_fact_identity']} fields={mismatched}"
            )
        if not str(row.get("evidence_path") or "").replace("\\", "/").endswith(
            "/binary_decisions.json"
        ):
            fail("Step4 API 明细未绑定 binary_decisions.json 证据")
    expected_summary = {
        "authoritative_change_fact_count": len(authoritative_decisions),
        "targetable_change_fact_count": len(targetable_decisions),
        "confirmed_unprojectable_fact_count": len(unprojectable),
        "diagnostic_candidate_fact_count": len(diagnostic_decisions),
        "excluded_decision_count": len(excluded_decisions),
        "dependency_count": len({
            item["coord"] for item in expected_api_by_fact.values()
        }),
        "published_api_change_count": len(expected_api_by_fact),
        "decision_coverage_status": loaded.get("summary", {}).get(
            "decision_coverage_status"
        ),
        "trace_coverage_status": loaded.get("summary", {}).get(
            "trace_coverage_status"
        ),
        "coverage": loaded.get("coverage"),
    }
    for key, expected in expected_summary.items():
        if published.get(key) != expected:
            fail(
                "Step4 summary.json 未由 validated generation 真值重算："
                f"{key}"
            )
    per_dependency = jar_dir / "s4_per_dependency"
    if per_dependency.is_symlink() or not per_dependency.is_dir():
        fail("Step4 s4_per_dependency 目录缺失或类型无效")
    expected_details = {
        f"s4_per_dependency/{make_per_dependency_dirname(row['coord'])}/summary.md"
        for row in dependency_rows
    }
    declared_details = {row.get("detail") for row in dependency_rows}
    actual_details = {
        path.relative_to(jar_dir).as_posix()
        for path in per_dependency.glob("*/summary.md")
        if path.is_file() and not path.is_symlink()
    }
    if declared_details != expected_details or actual_details != expected_details:
        fail("Step4 逐依赖明细与 changed_dependencies.csv 不一致")
    try:
        source_snapshot = json.loads(
            (source_dir / "source_snapshot.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"Step4 source_snapshot.json 无效：{exc}")
    if source_snapshot != loaded.get("source_attestation"):
        fail("Step4 源码快照与 validated binary generation 不一致")
    method_rows = read_csv_dicts(
        source_dir / "method_mappings.csv",
        ("源码归属", "归属类型", "二进制制品", "二进制方法", "源码位置", "模块", "语言",
         "源码声明", "注解", "修饰符"),
    )
    candidate_rows = read_csv_dicts(
        source_dir / "candidate_relationships.csv",
        ("源码归属", "二进制制品", "调用方", "源码位置", "候选目标", "证据类型", "置信度", "权威边界"),
    )
    gap_rows = read_csv_dicts(
        source_dir / "coverage_gaps.csv",
        ("原因", "语言", "源码归属", "模块", "源码文件", "解析器", "错误节点"),
    )
    try:
        (
            expected_source_summary,
            expected_method_rows,
            expected_candidate_rows,
            expected_gap_rows,
        ) = _step4_source_truth(loaded)
    except (AttributeError, TypeError, ValueError) as exc:
        fail(f"validated generation 的源码辅助真值无效：{type(exc).__name__}")
    source_summary = dict(published.get("source_inputs") or {})
    if source_summary != expected_source_summary:
        fail("Step4 summary.json 的源码输入摘要不是 generation 真值投影")
    if method_rows != expected_method_rows:
        fail("Step4 源码方法映射与 generation overlay 真值不一致")
    if candidate_rows != expected_candidate_rows:
        fail("Step4 源码候选关系与 generation 解释证据不一致")
    if gap_rows != expected_gap_rows:
        fail("Step4 源码覆盖缺口与 generation attestation 不一致")
    try:
        actual_source_review = (source_dir / "review.md").read_text(
            encoding="utf-8"
        )
    except (OSError, UnicodeError) as exc:
        fail(f"Step4 源码人工复核文件无法读取：{type(exc).__name__}")
    if actual_source_review != _step4_expected_source_review(
        expected_source_summary,
        expected_method_rows,
        expected_candidate_rows,
    ):
        fail("Step4 源码人工复核文件不是结构化真值的确定性渲染")
    authoritative = int(published.get("authoritative_change_fact_count") or 0)
    diagnostic = int(published.get("diagnostic_candidate_fact_count") or 0)
    excluded = int(published.get("excluded_decision_count") or 0)
    if strict_risk_gate and loaded["summary"].get("decision_coverage_status") != "complete":
        fail("严格门禁要求 binary decision coverage=complete")
    ok(
        "binary_generation 门控通过："
        f"正式变化={authoritative} 诊断候选={diagnostic} 排除={excluded}，独立 Oracle 已通过"
    )

def gate_binary_report(
    d,
    strict_risk_gate=False,
    *,
    candidate_call_chain_dir=None,
    candidate_binary_analysis_dir=None,
    candidate_index_dir=None,
    candidate_publication_binding=None,
):
    call_chain_dir = (
        Path(candidate_call_chain_dir)
        if candidate_call_chain_dir is not None
        else evidence_call_chain_dir(d)
    )
    binary_analysis_dir = (
        Path(candidate_binary_analysis_dir)
        if candidate_binary_analysis_dir is not None
        else Path(d) / EVIDENCE_DIRNAME / "binary_analysis"
    )
    index_dir = (
        Path(candidate_index_dir)
        if candidate_index_dir is not None
        else Path(d) / RUNTIME_DIRNAME / "indexes"
    )
    summary_path = call_chain_dir / "summary.json"
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
    if candidate_publication_binding is not None and (
        summary.get("step4_publication_receipt_identity")
        != candidate_publication_binding.get(
            "upstream_publication_receipt_identity"
        )
        or summary.get("step5_publication_input_identity")
        != candidate_publication_binding.get("publication_input_identity")
    ):
        fail("Step5 发布摘要未绑定当前候选事务的上游/范围身份")
    user_files = (
        call_chain_dir / "summary.md",
        call_chain_dir / "alerts.csv",
        call_chain_dir / "selection.json",
        call_chain_dir / "coverage.json",
        call_chain_dir / "by_api",
        binary_analysis_dir / "system-reachability.md",
    )
    missing = [str(path) for path in user_files if not path.exists()]
    if missing:
        fail(f"Step5 面向用户的复核文件缺失：{missing}")
    alert_rows = read_csv_dicts(
        call_chain_dir / "alerts.csv",
        (
            "api_identity", "target_coord", "changed_symbol",
            "api_signature", "symbol_kind", "change_type",
            "reported_api_identity", "change_fact_identity",
            "decision_identity",
            "path_status", "path_text",
        ),
    )
    published_api_identities = {
        row["api_identity"] for row in alert_rows if row.get("api_identity")
    }
    if len(published_api_identities) != int(summary.get("total_apis") or 0):
        fail("Step5 alerts.csv 的唯一 API 数与 summary.json 不一致")
    if any(not row.get("target_coord") for row in alert_rows):
        fail("Step5 触达结果丢失依赖包维度")
    by_identity_statuses = {}
    for row in alert_rows:
        identity = str(row.get("api_identity") or "")
        if identity:
            by_identity_statuses.setdefault(identity, set()).add(
                str(row.get("path_status") or "")
            )
    if any(len(statuses) != 1 for statuses in by_identity_statuses.values()):
        fail("Step5 alerts.csv 同一 API 出现互相冲突的分析状态")
    summary_buckets = (
        ("reachable_apis", "reachable"),
        ("uncertain_apis", "uncertain"),
        ("not_found_apis", "not_found_in_static_analysis"),
        ("not_analyzed_apis", "not_analyzed"),
    )
    summary_items = []
    for key, expected_status in summary_buckets:
        bucket = summary.get(key)
        if not isinstance(bucket, list) or any(
            not isinstance(item, dict) for item in bucket
        ):
            fail(f"Step5 summary.json 的 {key} 不是完整对象列表")
        if any(
            str(item.get("analysis_status") or "") != expected_status
            for item in bucket
        ):
            fail(f"Step5 summary.json 的 {key} 含错误分析状态")
        summary_items.extend(bucket)
    if len(summary_items) != int(summary.get("total_apis") or 0):
        fail("Step5 summary.json 的逐 API 明细数与 total_apis 不一致")
    if (
        summary.get("not_impacted") != 0
        or summary.get("not_impacted_apis") != []
    ):
        fail("Step5 不允许注入 generation 未定义的确认不受影响结果桶")
    summary_identity_values = [
        str(item.get("api_identity") or "").strip()
        for item in summary_items
    ]
    if (
        any(not identity for identity in summary_identity_values)
        or len(set(summary_identity_values)) != len(summary_identity_values)
    ):
        fail("Step5 summary.json 含空白或重复 API 身份")
    summary_by_identity = {
        str(item["api_identity"]): item for item in summary_items
    }
    summary_identities = set(summary_by_identity)
    if summary_identities != published_api_identities:
        fail("Step5 summary.json 与 alerts.csv 的 API 身份集合不一致")
    reported_identities = [
        str(item.get("reported_api_identity") or "").strip()
        for item in summary_items
    ]
    if any(not identity for identity in reported_identities):
        fail("Step5 summary.json 的 API 缺少 binary generation 报告身份")
    expected_status_counts = {
        "reachable": int(summary.get("reachable") or 0),
        "uncertain": int(summary.get("uncertain") or 0),
        "not_found_in_static_analysis": int(
            summary.get("not_found_in_static_analysis") or 0
        ),
        "not_analyzed": int(summary.get("not_analyzed") or 0),
    }
    actual_status_counts = {
        status: sum(status in statuses for statuses in by_identity_statuses.values())
        for status in expected_status_counts
    }
    if actual_status_counts != expected_status_counts:
        fail("Step5 状态汇总与 alerts.csv 的唯一 API 状态计数不一致")
    by_api_dir = call_chain_dir / "by_api"
    by_api_files = sorted(by_api_dir.glob("*.json"))
    if len(by_api_files) != len(published_api_identities):
        fail("Step5 by_api 明细文件数与唯一 API 数不一致")
    try:
        by_api_payloads = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in by_api_files
        ]
        by_api_identities = {
            str(payload.get("api_identity") or "")
            for payload in by_api_payloads
            if isinstance(payload, dict)
        }
        selection = json.loads(
            (call_chain_dir / "selection.json").read_text(encoding="utf-8")
        )
        coverage = json.loads(
            (call_chain_dir / "coverage.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"Step5 事务内结构化文件无效：{exc}")
    if by_api_identities != published_api_identities:
        fail("Step5 by_api 明细与 alerts.csv 的 API 身份集合不一致")
    if (
        any(not isinstance(payload, dict) for payload in by_api_payloads)
        or {
            str(payload.get("api_identity") or ""): payload
            for payload in by_api_payloads
        }
        != summary_by_identity
    ):
        fail("Step5 by_api 明细内容与 summary.json 的逐 API 事实不一致")
    included_reported_identities = selection.get(
        "included_reported_api_identities"
    )
    expected_reported_identities = sorted(set(reported_identities))
    if (
        selection.get("schema")
        != "java-upgrade-analyzer.binary-step5-selection.v1"
        or selection.get("result_generation_identity")
        != loaded["manifest"].get("result_generation_identity")
        or selection.get("step4_publication_receipt_identity")
        != summary.get("step4_publication_receipt_identity")
        or selection.get("step5_publication_input_identity")
        != summary.get("step5_publication_input_identity")
        or summary.get("analysis_scope") != selection
        or included_reported_identities != expected_reported_identities
    ):
        fail("Step5 selection.json 与发布摘要的范围/上游身份不一致")

    formal_rows = (loaded.get("formal") or {}).get("by_api")
    if not isinstance(formal_rows, list) or any(
        not isinstance(item, dict) for item in formal_rows
    ):
        fail("validated generation 缺少可核验的 formal.by_api 真值集合")
    formal_targets = [_formal_step5_target(item) for item in formal_rows]
    formal_identity_values = [
        target["reported_api_identity"] for target in formal_targets
    ]
    if (
        any(not identity for identity in formal_identity_values)
        or len(set(formal_identity_values)) != len(formal_identity_values)
    ):
        fail("validated generation 的 formal.by_api 身份为空或重复")
    formal_by_reported_identity = {
        target["reported_api_identity"]: target for target in formal_targets
    }
    step4_rows, step4_snapshot = _load_current_step4_api_rows(
        d, str(summary.get("step4_publication_receipt_identity") or "")
    )
    step4_fact_values = [
        str(row.get("change_fact_identity") or "").strip()
        for row in step4_rows
    ]
    if (
        any(not identity for identity in step4_fact_values)
        or len(set(step4_fact_values)) != len(step4_fact_values)
    ):
        fail("Step4 committed snapshot 的变化事实身份为空或重复")
    step4_by_fact = {
        str(row["change_fact_identity"]): row for row in step4_rows
    }
    all_expected_pairs = []
    for reported_identity, target in formal_by_reported_identity.items():
        fact_ids = target["contributing_change_fact_ids"]
        if (
            not fact_ids
            or len(set(fact_ids)) != len(fact_ids)
            or any(fact_id not in step4_by_fact for fact_id in fact_ids)
        ):
            fail("validated generation 的 API 未完整绑定 Step4 正式变化事实")
        all_expected_pairs.extend(
            (reported_identity, fact_id) for fact_id in fact_ids
        )
    if len(set(all_expected_pairs)) != len(all_expected_pairs):
        fail("validated generation 的 reported API/变化事实映射重复")

    formal_resource_rows = (loaded.get("formal") or {}).get(
        "resource_activation_results"
    ) or []
    if not isinstance(formal_resource_rows, list) or any(
        not isinstance(item, dict) for item in formal_resource_rows
    ):
        fail("validated generation 的资源激活真值集合无效")
    expected_resources = [
        _formal_step5_resource(item) for item in formal_resource_rows
    ]
    available_coords = sorted({
        *(
            str(step4_by_fact[fact_id].get("coord") or "").strip()
            for _reported, fact_id in all_expected_pairs
        ),
        *(
            str(item.get("coord") or "").strip()
            for item in expected_resources
        ),
    } - {""})
    selected_coords = selection.get("selected_coords")
    selected_names = selection.get("selected_names")
    included_coords = selection.get("included_dependency_coords")
    excluded_coords = selection.get("excluded_dependency_coords")
    for label, values in (
        ("selected_coords", selected_coords),
        ("selected_names", selected_names),
        ("included_dependency_coords", included_coords),
        ("excluded_dependency_coords", excluded_coords),
    ):
        if (
            not isinstance(values, list)
            or any(not isinstance(value, str) or not value.strip() for value in values)
            or values != sorted(set(values))
        ):
            fail(f"Step5 selection.json 的 {label} 不是规范集合")
    expected_included_coords = (
        sorted(
            coord for coord in available_coords
            if coord in set(selected_coords)
            or coord.split(":")[-1] in set(selected_names)
        )
        if selected_coords or selected_names else available_coords
    )
    expected_mode = (
        "partial" if selected_coords or selected_names else "full"
    )
    unmatched_selected_coords = sorted(
        set(selected_coords) - set(available_coords)
    )
    unmatched_selected_names = sorted(
        name for name in selected_names
        if not any(coord.split(":")[-1] == name for coord in available_coords)
    )
    if (
        selection.get("mode") != expected_mode
        or unmatched_selected_coords
        or unmatched_selected_names
        or selection.get("validation_status") != "passed"
        or included_coords != expected_included_coords
        or excluded_coords
        != sorted(set(available_coords) - set(expected_included_coords))
        or selection.get("available_dependency_count") != len(available_coords)
        or selection.get("included_dependency_count")
        != len(expected_included_coords)
    ):
        fail("Step5 selection.json 的依赖范围不是 generation 真值的精确分区")
    included_pairs = [
        pair for pair in all_expected_pairs
        if str(step4_by_fact[pair[1]].get("coord") or "")
        in set(expected_included_coords)
    ]
    expected_generation_reported_identities = sorted({
        reported for reported, _fact in included_pairs
    })
    if (
        included_reported_identities != expected_generation_reported_identities
        or selection.get("total_api_count") != len(all_expected_pairs)
        or selection.get("included_api_count") != len(included_pairs)
        or selection.get("analyzed_api_count") != len(included_pairs)
        or selection.get("excluded_api_count")
        != len(all_expected_pairs) - len(included_pairs)
        or int(summary.get("total_apis") or 0) != len(included_pairs)
    ):
        fail("Step5 选择范围未精确投影 generation 的变化事实集合")
    live_input_identity = _step5_publication_input_identity(
        loaded=loaded,
        step4_receipt=step4_snapshot,
        selected_coords=set(selected_coords),
        selected_names=set(selected_names),
    )
    if (
        selection.get("step5_publication_input_identity")
        != live_input_identity
        or (
            candidate_publication_binding is not None
            and candidate_publication_binding.get("publication_input_identity")
            != live_input_identity
        )
    ):
        fail("Step5 publication input identity 未绑定真实选择范围")

    candidate_pairs = [
        (
            str(item.get("reported_api_identity") or ""),
            str(item.get("change_fact_identity") or ""),
        )
        for item in summary_items
    ]
    if Counter(candidate_pairs) != Counter(included_pairs):
        fail("Step5 summary.json 漏报、增报或重复了 generation 变化事实")
    for item in summary_items:
        reported_identity = str(item.get("reported_api_identity") or "")
        fact_identity = str(item.get("change_fact_identity") or "")
        expected = formal_by_reported_identity.get(reported_identity)
        change = step4_by_fact.get(fact_identity)
        expected_symbol_kind = str(
            (change or {}).get("symbol_kind")
            or (expected or {}).get("symbol_kind")
            or ""
        )
        expected_api_identity = "|".join((
            str((change or {}).get("coord") or ""),
            str((expected or {}).get("api") or ""),
            str((expected or {}).get("api_signature") or ""),
            expected_symbol_kind,
            str((change or {}).get("change_type") or ""),
            fact_identity,
        ))
        expected_core = {
                "coord": str(change.get("coord") or ""),
                "api": str(expected.get("api") or ""),
                "api_signature": str(expected.get("api_signature") or ""),
                "symbol_kind": expected_symbol_kind,
                "analysis_status": str(expected.get("analysis_status") or ""),
                "change_type": str(change.get("change_type") or ""),
                "old_version": str(change.get("old_version") or ""),
                "new_version": str(change.get("new_version") or ""),
                "decision_identity": str(change.get("decision_identity") or ""),
                "api_identity": expected_api_identity,
                "impact_conclusion": str(
                    expected.get("impact_conclusion") or ""
                ),
                "static_linkage_status": str(
                    expected.get("static_linkage_status") or ""
                ),
                "runtime_verification_status": str(
                    expected.get("runtime_verification_status") or ""
                ),
            } if expected is not None and change is not None else {}
        core_mismatches = [
            key for key, expected_value in expected_core.items()
            if str(item.get(key) or "") != expected_value
        ]
        actual_paths = [
            str(path or "").strip()
            for path in item.get("call_paths") or ()
            if str(path or "").strip()
        ]
        boolean_mismatches = [
            key for key in (
                "path_set_complete", "exact_path_exists",
                "possible_path_exists",
            )
            if expected is not None
            and bool(item.get(key)) != bool(expected[key])
        ]
        if (
            expected is None
            or change is None
            or core_mismatches
            or actual_paths != expected["call_paths"]
            or item.get("path_details") != expected["path_details"]
            or boolean_mismatches
        ):
            mismatch_labels = list(core_mismatches)
            if expected is not None and actual_paths != expected["call_paths"]:
                mismatch_labels.append("call_paths")
            if (
                expected is not None
                and item.get("path_details") != expected["path_details"]
            ):
                mismatch_labels.append("path_details")
            mismatch_labels.extend(boolean_mismatches)
            fail(
                "Step5 summary.json 未精确投影 generation/Step4 API 真值："
                f"reported={reported_identity} fact={fact_identity} "
                f"fields={mismatch_labels or ['missing_truth']}"
            )

    published_resources = summary.get("resource_activation_results")
    if not isinstance(published_resources, list) or published_resources != [
        item for item in expected_resources
        if item.get("coord") in set(expected_included_coords)
    ]:
        fail("Step5 资源激活结果未精确投影 generation 真值和选择范围")

    alerts_by_identity = defaultdict(list)
    for row in alert_rows:
        alerts_by_identity[str(row.get("api_identity") or "")].append(row)
    for identity, item in summary_by_identity.items():
        rows = alerts_by_identity.get(identity) or []
        expected_paths = [
            str(path or "").strip()
            for path in item.get("call_paths") or ()
            if str(path or "").strip()
        ] or [""]
        expected_core = {
            "target_coord": str(item.get("coord") or ""),
            "changed_symbol": str(item.get("api") or ""),
            "api_signature": str(item.get("api_signature") or ""),
            "symbol_kind": str(item.get("symbol_kind") or ""),
            "change_type": str(item.get("change_type") or ""),
            "reported_api_identity": str(
                item.get("reported_api_identity") or ""
            ),
            "change_fact_identity": str(
                item.get("change_fact_identity") or ""
            ),
            "decision_identity": str(
                item.get("decision_identity") or ""
            ),
            "path_status": str(item.get("analysis_status") or ""),
        }
        if (
            len(rows) != len(expected_paths)
            or Counter(row.get("path_text") or "" for row in rows)
            != Counter(expected_paths)
            or any(
                any((row.get(key) or "") != value for key, value in expected_core.items())
                for row in rows
            )
        ):
            fail("Step5 alerts.csv 与 summary/by_api 的 API 归属、状态或路径不一致")

    summary_md = (call_chain_dir / "summary.md").read_text(encoding="utf-8")
    binary_md = (
        binary_analysis_dir / "system-reachability.md"
    ).read_text(encoding="utf-8")
    count_lines = (
        f"- 变化 API：{summary['total_apis']}",
        f"- 已发现静态可执行路径：{summary['reachable']}",
        f"- 结论不确定：{summary['uncertain']}",
        f"- 未完成分析：{summary['not_analyzed']}",
    )
    if any(line not in summary_md or line not in binary_md for line in count_lines):
        fail("Step5 人工摘要与结构化计数不一致")
    if coverage.get("schema") != "java-upgrade-analyzer.coverage.v1":
        fail("Step5 coverage.json 不是受支持的覆盖率契约")
    for component in coverage.get("components") or ():
        if not isinstance(component, dict):
            fail("Step5 coverage.json components 含非对象记录")
        for raw in component.get("evidence") or ():
            text = str(raw or "").split("#", 1)[0].replace("\\", "/").strip()
            relative = Path(text)
            if (
                not text
                or relative.is_absolute()
                or ".." in relative.parts
                or len(relative.parts) < 2
                or "/".join(relative.parts[:2]) not in {
                    "evidence/dependencies",
                    "evidence/context",
                    "evidence/static_scan",
                    "evidence/api_changes",
                    "evidence/call_chain",
                    ".runtime/coverage",
                    ".runtime/state",
                }
            ):
                fail(
                    "Step5 coverage.json 含越界或不受支持的 evidence 路径："
                    f"{raw}"
                )
    query_index_path = index_dir / "s5_query_index.json"
    try:
        query_index = json.loads(query_index_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"Step5 调用链查询索引无效：{exc}")
    if (
        query_index.get("schema") != "java-upgrade-analyzer.s5-query-index.v1"
        or query_index.get("result_generation_identity")
        != loaded["manifest"].get("result_generation_identity")
        or query_index.get("step4_publication_receipt_identity")
        != summary.get("step4_publication_receipt_identity")
        or query_index.get("step5_publication_input_identity")
        != summary.get("step5_publication_input_identity")
    ):
        fail("Step5 调用链查询索引与 active binary generation 不一致")
    summary_targets = [
        (
            str(item.get("coord") or ""),
            str(item.get("api") or ""),
            str(item.get("api_signature") or ""),
            str(item.get("symbol_kind") or ""),
            str(item.get("api_identity") or ""),
            str(item.get("reported_api_identity") or ""),
            str(item.get("change_fact_identity") or ""),
            str(item.get("decision_identity") or ""),
            str(item.get("change_type") or ""),
        )
        for item in summary_items
    ]
    raw_indexed_targets = query_index.get("target_apis")
    if not isinstance(raw_indexed_targets, list) or any(
        not isinstance(item, dict) for item in raw_indexed_targets
    ):
        fail("Step5 查询索引 target_apis 不是完整对象列表")
    indexed_targets = [
        (
            str(item.get("coord") or ""),
            str(item.get("api_name") or ""),
            str(item.get("api_signature") or ""),
            str(item.get("symbol_kind") or ""),
            str(item.get("api_identity") or ""),
            str(item.get("reported_api_identity") or ""),
            str(item.get("change_fact_identity") or ""),
            str(item.get("decision_identity") or ""),
            str(item.get("change_type") or ""),
        )
        for item in raw_indexed_targets
    ]
    if Counter(indexed_targets) != Counter(summary_targets):
        fail("Step5 查询索引目标与 summary.json 的 API 目标集合不一致")
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


def gate_binary_final_report(
    d,
    *,
    candidate_deliverables_dir=None,
    candidate_findings_dir=None,
    candidate_publication_binding=None,
):
    report = Path(d).resolve()
    if candidate_deliverables_dir is None:
        with short_temporary_directory(
            prefix="jua-step6-committed-gate-"
        ) as temporary:
            try:
                snapshot = materialize_report_publication_committed_snapshot(
                    (
                        report / "deliverables",
                        report / RUNTIME_DIRNAME / "findings",
                    ),
                    Path(temporary).resolve(),
                )
                candidates = tuple(
                    Path(item)
                    for item in snapshot.get("snapshot_destinations") or ()
                )
                if len(candidates) != 2:
                    fail("Step6 committed publication snapshot 不完整")
                validate_step6_publication_candidate(
                    report,
                    candidate_deliverables_dir=candidates[0],
                    candidate_findings_dir=candidates[1],
                    candidate_publication_binding=snapshot.get("binding") or {},
                )
            except BinaryFirstContractError as exc:
                fail_binary_report_contract(
                    "Step6 正式报告门控失败："
                    f"{exc.reason_code}: {exc}",
                    exc,
                )
    else:
        try:
            _validate_step6_candidate_under_parent_workflow_lock(
                report,
                candidate_deliverables_dir=candidate_deliverables_dir,
                candidate_findings_dir=candidate_findings_dir,
                candidate_publication_binding=(
                    candidate_publication_binding or {}
                ),
            )
        except BinaryFirstContractError as exc:
            fail_binary_report_contract(
                "Step6 candidate 正式报告门控失败："
                f"{exc.reason_code}: {exc}",
                exc,
            )
    ok("binary_final_report 门控通过：候选交付物与当前 Step5 release 一致")

def main():
    global _GATE_RESULT_JSON_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument('--step', required=True, choices=GATES)
    ap.add_argument('--report-dir', default='.upgrade-report')
    ap.add_argument('--strict-risk-gate', action='store_true')
    ap.add_argument('--publication-transaction-id', default='')
    ap.add_argument('--publication-binding-json', default='')
    ap.add_argument('--publication-content-identity', default='')
    ap.add_argument('--candidate-activation-identity', default='')
    ap.add_argument('--result-json', default='')
    args = ap.parse_args()
    _GATE_RESULT_JSON_PATH = str(args.result_json or "").strip()
    publication_fields = (
        args.publication_transaction_id,
        args.publication_binding_json,
        args.publication_content_identity,
    )
    if any(publication_fields) or args.candidate_activation_identity:
        if args.step not in {
            'binary_generation', 'binary_report', 'binary_final_report'
        }:
            ap.error('candidate publication tokens are unsupported for this gate')
        if not all(publication_fields):
            ap.error('candidate gate requires every publication token field')
        try:
            binding = json.loads(args.publication_binding_json)
        except (TypeError, json.JSONDecodeError) as exc:
            ap.error(f'--publication-binding-json is invalid: {exc}')
        if not isinstance(binding, dict):
            ap.error('candidate publication binding must be an object')
        if args.step == 'binary_generation':
            declared_activation = str(
                binding.get('activation_identity') or ''
            )
            if declared_activation != str(
                args.candidate_activation_identity or ''
            ):
                ap.error('candidate activation identity is not transaction-bound')
        elif args.candidate_activation_identity:
            ap.error('downstream candidate gates do not accept a pending activation')
        report = Path(args.report_dir).resolve()
        if args.step == 'binary_generation':
            destinations = (
                evidence_api_changes_dir(report),
                report / EVIDENCE_DIRNAME / 'source_analysis',
            )
        elif args.step == 'binary_report':
            destinations = (
                evidence_call_chain_dir(report),
                report / EVIDENCE_DIRNAME / 'binary_analysis',
                report / RUNTIME_DIRNAME / 'indexes',
            )
        else:
            destinations = (
                report / 'deliverables',
                report / RUNTIME_DIRNAME / 'findings',
            )
        with short_temporary_directory(
            prefix=f'jua-{args.step}-gate-candidate-'
        ) as temporary:
            snapshot = materialize_report_publication_gate_candidate(
                destinations,
                Path(temporary).resolve(),
                expected_transaction_id=args.publication_transaction_id,
                expected_binding=binding,
                expected_published_content_identity=(
                    args.publication_content_identity
                ),
            )
            candidate_destinations = list(
                snapshot.get('candidate_destinations') or ()
            )
            if len(candidate_destinations) != len(destinations):
                fail(f'{args.step} candidate publication snapshot is incomplete')
            if args.step == 'binary_generation':
                gate_binary_generation(
                    report,
                    strict_risk_gate=args.strict_risk_gate,
                    candidate_api_dir=candidate_destinations[0],
                    candidate_source_dir=candidate_destinations[1],
                    candidate_activation_identity=(
                        args.candidate_activation_identity
                    ),
                )
            elif args.step == 'binary_report':
                try:
                    loaded = load_validated_generation(report)
                except BinaryFirstContractError as exc:
                    fail(
                        'Step5 active generation 无法验证：'
                        f'{exc.reason_code}: {exc}'
                    )
                if any(
                    binding.get(field) != expected
                    for field, expected in (
                        (
                            'result_generation_identity',
                            loaded['manifest'].get(
                                'result_generation_identity'
                            ),
                        ),
                        (
                            'validation_run_identity',
                            loaded['active'].get('validation_run_identity'),
                        ),
                        (
                            'validation_result_sha256',
                            loaded['active'].get('validation_result_sha256'),
                        ),
                    )
                ) or (
                    loaded['active'].get('activation_identity')
                    and binding.get('activation_identity')
                    != loaded['active'].get('activation_identity')
                ):
                    fail('Step5 publication binding 与 active generation 不一致')
                gate_binary_report(
                    report,
                    strict_risk_gate=args.strict_risk_gate,
                    candidate_call_chain_dir=candidate_destinations[0],
                    candidate_binary_analysis_dir=candidate_destinations[1],
                    candidate_index_dir=candidate_destinations[2],
                    candidate_publication_binding=binding,
                )
            else:
                gate_binary_final_report(
                    report,
                    candidate_deliverables_dir=candidate_destinations[0],
                    candidate_findings_dir=candidate_destinations[1],
                    candidate_publication_binding=binding,
                )
        print(f"\n门控 [{args.step}] 通过，可以进入下一步。", file=sys.stderr)
        return
    gates = {'step1_scope': gate_step1_scope, 'context': gate_context, 'scan': gate_scan,
             'binary_generation': lambda d: gate_binary_generation(d, strict_risk_gate=args.strict_risk_gate),
             'binary_report': lambda d: gate_binary_report(d, strict_risk_gate=args.strict_risk_gate),
             'binary_final_report': gate_binary_final_report}
    gates[args.step](args.report_dir)
    print(f"\n门控 [{args.step}] 通过，可以进入下一步。", file=sys.stderr)

if __name__ == '__main__': main()
