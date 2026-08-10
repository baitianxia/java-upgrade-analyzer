#!/usr/bin/env python3
"""Publish native Step4/5/6 reports from one validated binary generation.

Published files are terminal views for users and gates.  They never become
inputs to the binary graph and preserve the four independent result axes.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import csv
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Mapping

from binary_first_contract import BinaryFirstContractError
from analysis_contract import write_coverage_report
from csv_io import open_csv_write
from path_runtime import make_short_temp_dir
from s4_contract import ALL_CHANGED_APIS_FIELDS, DEFAULT_SEVERITY, make_per_dependency_dirname
import s6_report
from signature_utils import jvm_method_parameter_signature
BINARY_OUTPUT_RELATIVE_PATH = Path(".runtime/binary_authority")


class BinaryReportError(BinaryFirstContractError):
    pass


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BinaryReportError(
            "BINARY_REPORT_JSON_INVALID", f"{path}: {error}"
        ) from error
    if not isinstance(value, dict):
        raise BinaryReportError(
            "BINARY_REPORT_JSON_INVALID", f"{path}: root must be an object"
        )
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _generation_within_root(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise BinaryReportError(
            "BINARY_ACTIVE_GENERATION_PATH_ESCAPE", str(candidate)
        ) from error
    return candidate


def load_validated_generation(report_dir: str | Path) -> dict[str, Any]:
    report = Path(report_dir).resolve()
    root = report / BINARY_OUTPUT_RELATIVE_PATH
    active = _load_json(root / "active_binary_generation.json")
    generation_identity = str(active.get("result_generation_identity") or "")
    generation = _generation_within_root(root, str(active.get("generation_directory") or ""))
    if generation.name != generation_identity or not generation.is_dir():
        raise BinaryReportError(
            "BINARY_ACTIVE_GENERATION_INVALID", str(generation)
        )
    manifest = _load_json(generation / "result_generation.json")
    if (
        manifest.get("result_generation_identity") != generation_identity
        or manifest.get("authority") != "binary_first"
    ):
        raise BinaryReportError(
            "BINARY_GENERATION_MANIFEST_MISMATCH", generation_identity
        )
    for name, expected in (manifest.get("sidecar_content_identities") or {}).items():
        if Path(str(name)).name != str(name):
            raise BinaryReportError(
                "BINARY_GENERATION_SIDECAR_NAME_INVALID", str(name)
            )
        path = generation / str(name)
        if not path.is_file() or _sha256(path) != expected:
            raise BinaryReportError(
                "BINARY_GENERATION_SIDECAR_INTEGRITY_FAILED", str(path)
            )
    validation_identity = str(active.get("validation_run_identity") or "")
    validation_path = generation / "validation" / f"{validation_identity}.json"
    validation = _load_json(validation_path)
    if (
        not validation_identity
        or validation.get("validation_run_identity") != validation_identity
        or validation.get("result_generation_identity") != generation_identity
        or validation.get("status") != "passed"
        or int(validation.get("issue_count") or 0) != 0
    ):
        raise BinaryReportError(
            "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID", str(validation_path)
        )
    source_explanations_path = generation / "binary_source_explanations.json"
    source_attestation_path = generation / "binary_source_attestation.json"
    return {
        "report_dir": report,
        "active": active,
        "manifest": manifest,
        "validation": validation,
        "generation": generation,
        "summary": _load_json(generation / "binary_summary.json"),
        "decisions": _load_json(generation / "binary_decisions.json"),
        "projections": _load_json(generation / "binary_projections.json"),
        "formal": _load_json(generation / "binary_formal_results.json"),
        "candidate": _load_json(generation / "binary_candidate_results.json"),
        "coverage": _load_json(generation / "binary_coverage.json"),
        "source_explanations": (
            _load_json(source_explanations_path)
            if source_explanations_path.is_file()
            else {
                "authority": "not_provided",
                "declarations": [],
                "candidate_relationships": [],
            }
        ),
        "source_attestation": (
            _load_json(source_attestation_path)
            if source_attestation_path.is_file()
            else {"coverage_gaps": [], "language_file_counts": {}}
        ),
    }


def _stage_directory(destination: Path, writer) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = make_short_temp_dir(
        prefix=f".{destination.name}.binary-stage",
        preferred_root=destination.parent,
        strict_preferred=True,
    )
    backup = destination.with_name(f".{destination.name}.binary-backup-{os.getpid()}")
    try:
        writer(stage)
        if backup.exists():
            shutil.rmtree(backup)
        if destination.exists():
            os.replace(destination, backup)
        try:
            os.replace(stage, destination)
        except Exception:
            if backup.exists() and not destination.exists():
                os.replace(backup, destination)
            raise
        if backup.exists():
            shutil.rmtree(backup)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def _api_display(scope: Mapping[str, Any]) -> tuple[str, str, str]:
    owner = str(scope.get("class_name") or "").replace("/", ".")
    member = str(scope.get("member_name") or "")
    descriptor = str(scope.get("descriptor") or "")
    api_name = owner if not member or member == "<class>" else f"{owner}.{member}"
    return api_name, member or owner.rsplit(".", 1)[-1], descriptor


_CHANGE_LABELS = {
    "added": "新增",
    "removed": "删除",
    "descriptor_changed": "签名变化",
    "access_changed": "访问权限变化",
    "constant_value_changed": "常量值变化",
    "implementation_changed": "实现变化",
    "contract_changed": "二进制契约变化",
    "class_provider": "类提供者变化",
    "class_definition": "类定义结果变化",
}


def _dependency_view(record: Mapping[str, Any]) -> dict[str, str]:
    artifacts = list(record.get("dependency_artifacts") or ())
    lineages = sorted({
        str(item.get("logical_dependency_lineage") or "")
        for item in artifacts if item.get("logical_dependency_lineage")
    })
    base = sorted({
        str(item.get("coord") or item.get("runtime_code_source_origin_identity") or "")
        for item in artifacts if item.get("side") == "base"
    } - {""})
    current = sorted({
        str(item.get("coord") or item.get("runtime_code_source_origin_identity") or "")
        for item in artifacts if item.get("side") == "current"
    } - {""})
    fallback = sorted({
        str(item.get("coord") or item.get("runtime_code_source_origin_identity") or "")
        for item in artifacts
    } - {""})
    normalized_coord, _base_version, _current_version = _artifact_coord_parts(record)
    normalized_fallback = (
        [normalized_coord]
        if normalized_coord and normalized_coord != "UNBOUND_RUNTIME_ARTIFACT"
        else fallback
    )
    dependency = (
        "、".join(lineages or normalized_fallback)
        or "未绑定制品（需查看裁决证据）"
    )
    return {
        "dependency": dependency,
        "dependency_lineage": "|".join(lineages),
        "base_dependency": "|".join(base) or "-",
        "current_dependency": "|".join(current) or "-",
    }


def _change_object(record: Mapping[str, Any]) -> str:
    scope = record.get("fact_scope") or {}
    api_name, _simple, descriptor = _api_display(scope)
    if api_name:
        return f"{api_name}{descriptor}"
    return str(
        scope.get("resource_name")
        or scope.get("entry_name")
        or scope.get("mechanism")
        or record.get("fact_kind")
        or "未知对象"
    )


def _source_usage_view(loaded: Mapping[str, Any]) -> dict[str, Any]:
    coverage = dict(loaded.get("coverage") or {})
    usage = dict(coverage.get("source_usage") or {})
    overlay = dict(coverage.get("source_overlay") or {})
    attestation = dict(loaded.get("source_attestation") or {})
    decision = str(usage.get("decision") or "").strip()
    decision_source = str(usage.get("decision_source") or "missing")
    if decision == "use_source":
        label = (
            "用户已提供源码，系统直接使用"
            if decision_source == "user_provided_source"
            else "用户选择使用源码"
        )
        effect = (
            "源码用于补充文件/行号、声明与语义解释；"
            "正式变化、运行时解析和精确可执行边仍由最终二进制制品决定。"
        )
    elif decision == "skip_source":
        label = "用户选择不提供源码"
        effect = (
            "本次只执行二进制分析；正式结果仍有效，但源码位置、声明/注解、可读上下文和候选关系覆盖缺失。"
        )
    else:
        label = "源码选择记录缺失"
        effect = "当前 generation 没有可验证的用户源码选择记录。"
    return {
        "decision": decision or "missing",
        "decision_source": decision_source,
        "purpose_version": str(usage.get("purpose_version") or "missing"),
        "label": label,
        "effect": effect,
        "coverage_status": str(overlay.get("coverage_status") or "not_provided"),
        "mapped_count": int(overlay.get("mapped_count") or 0),
        "ambiguous_count": int(overlay.get("ambiguous_count") or 0),
        "conflict_count": int(overlay.get("conflict_count") or 0),
        "language_file_counts": dict(
            attestation.get("language_file_counts") or {}
        ),
        "coverage_gaps": list(attestation.get("coverage_gaps") or ()),
    }


def _source_review_rows(loaded: Mapping[str, Any]) -> list[dict[str, str]]:
    overlay = dict((loaded.get("coverage") or {}).get("source_overlay") or {})
    declarations = {
        str(item.get("overlay_identity") or ""): dict(item)
        for item in (loaded.get("source_explanations") or {}).get("declarations") or []
    }
    rows = []
    for item in overlay.get("rows") or []:
        if str(item.get("mapping_status") or "") != "mapped":
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
        declaration = declarations.get(str(item.get("overlay_identity") or ""), {})
        line = int(location.get("line") or 0)
        end_line = int(location.get("end_line") or 0)
        line_text = str(line) if not end_line or end_line == line else f"{line}-{end_line}"
        rows.append({
            "源码归属": str(location.get("owner_coord") or "未标识"),
            "归属类型": str(location.get("owner_type") or "unknown"),
            "二进制制品": str(member.get("artifact_coord") or "未标识"),
            "二进制方法": f"{class_name}.{member_name}{signature}",
            "源码位置": (
                f"{location.get('logical_path') or '未知'}:{line_text}"
                if line_text else str(location.get("logical_path") or "未知")
            ),
            "模块": str(location.get("module") or ""),
            "语言": str(location.get("language") or ""),
            "源码声明": str(declaration.get("declared_signature") or ""),
            "注解": "、".join(map(str, declaration.get("annotations") or [])),
            "修饰符": " ".join(map(str, declaration.get("modifiers") or [])),
        })
    return sorted(rows, key=lambda item: (
        item["源码归属"], item["二进制制品"], item["二进制方法"], item["源码位置"]
    ))


def _source_candidate_review_rows(loaded: Mapping[str, Any]) -> list[dict[str, str]]:
    rows = []
    for item in (
        (loaded.get("source_explanations") or {}).get("candidate_relationships") or []
    ):
        descriptor = str(item.get("caller_binary_descriptor") or "")
        signature = (
            jvm_method_parameter_signature(descriptor)
            if descriptor.startswith("(") else descriptor
        )
        caller_class = str(item.get("caller_binary_class_name") or "").replace("/", ".")
        caller_member = str(item.get("caller_binary_member_name") or "")
        rows.append({
            "源码归属": str(item.get("source_owner_coord") or "未标识"),
            "二进制制品": str(item.get("binary_artifact_coord") or "未标识"),
            "调用方": f"{caller_class}.{caller_member}{signature}",
            "源码位置": f"{item.get('caller_logical_path') or '未知'}:{item.get('source_line') or 0}",
            "候选目标": str(item.get("callee_key") or ""),
            "证据类型": str(item.get("evidence_type") or ""),
            "置信度": str(item.get("confidence") or ""),
            "权威边界": "源码候选关系，不是可执行调用边",
        })
    return rows


def _change_label(record: Mapping[str, Any]) -> str:
    scope = record.get("fact_scope") or {}
    value = str(
        scope.get("member_change_kind")
        or scope.get("mechanism")
        or record.get("fact_kind")
        or "changed"
    )
    return _CHANGE_LABELS.get(value, value)


def _review_row(
    record: Mapping[str, Any],
    assessment: Mapping[str, Any] | None,
    *,
    conclusion: str,
) -> dict[str, str]:
    dependency = _dependency_view(record)
    evidence = record.get("evidence") or {}
    coverage_gaps = list(record.get("coverage_gaps") or ())
    return {
        "依赖包": dependency["dependency"],
        "升级前制品": dependency["base_dependency"],
        "升级后制品": dependency["current_dependency"],
        "变化对象": _change_object(record),
        "变化类型": _change_label(record),
        "裁决结论": conclusion,
        "裁决原因": str(record.get("reason_code") or ""),
        "投影状态": str((assessment or {}).get("analysis_projection_status") or "未投影"),
        "覆盖状态": (
            str((assessment or {}).get("projection_coverage_status") or "")
            or ("不完整" if coverage_gaps else "完整")
        ),
        "需人工复核": "是" if conclusion != "正式变化" or coverage_gaps else "否",
        "升级前证据": json.dumps(
            evidence.get("base_contract") or evidence.get("base_member_fingerprint") or {},
            ensure_ascii=False, sort_keys=True,
        ),
        "升级后证据": json.dumps(
            evidence.get("current_contract") or evidence.get("current_member_fingerprint") or {},
            ensure_ascii=False, sort_keys=True,
        ),
        "证据缺口": "|".join(str(item) for item in coverage_gaps) or "-",
        "decision_identity": str(record.get("decision_identity") or ""),
    }


_PRODUCT_CHANGE_TYPES = {
    "removed": "REMOVED",
    "descriptor_changed": "SIGNATURE_CHANGED",
    "access_changed": "ACCESS_REDUCED",
    "constant_value_changed": "CONSTANT_VALUE_CHANGED",
    "added": "METHOD_ADDED",
    "implementation_changed": "BEHAVIOR_CHANGED",
    "contract_changed": "BEHAVIOR_CHANGED",
}


def _visibility_rank(access: Any) -> int:
    value = int(access or 0)
    if value & 0x0001:  # public
        return 3
    if value & 0x0004:  # protected
        return 2
    if value & 0x0002:  # private
        return 0
    return 1


def _product_change_type(decision: Mapping[str, Any]) -> str:
    scope = decision.get("fact_scope") or {}
    evidence = decision.get("evidence") or {}
    fact_kind = str(decision.get("fact_kind") or "")
    change_kind = str(scope.get("member_change_kind") or "implementation_changed")
    base_contract = evidence.get("base_contract")
    current_contract = evidence.get("current_contract")

    if fact_kind == "member_resolution":
        return "MEMBER_RESOLUTION_CHANGED"

    if fact_kind == "provider_topology":
        base_status = str((evidence.get("base_provider") or {}).get("class_provider_status") or "missing")
        current_status = str((evidence.get("current_provider") or {}).get("class_provider_status") or "missing")
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
    if change_kind == "contract_changed" and isinstance(base_contract, Mapping) and isinstance(current_contract, Mapping):
        if _visibility_rank(current_contract.get("access")) < _visibility_rank(base_contract.get("access")):
            return "ACCESS_REDUCED"
        if (
            fact_kind == "field"
            and base_contract.get("descriptor") != current_contract.get("descriptor")
        ):
            return "DATA_FIELD_TYPE_CHANGED"
        if (
            fact_kind == "field"
            and base_contract.get("constant") != current_contract.get("constant")
        ):
            return "CONSTANT_VALUE_CHANGED"
        if base_contract.get("descriptor") != current_contract.get("descriptor"):
            return "SIGNATURE_CHANGED"
        return "CONTRACT_CHANGED"
    return _PRODUCT_CHANGE_TYPES.get(change_kind, "BEHAVIOR_CHANGED")


def _artifact_coord_parts(record: Mapping[str, Any]) -> tuple[str, str, str]:
    artifacts = list(record.get("dependency_artifacts") or ())
    lineages = [
        str(item.get("logical_dependency_lineage") or "").strip()
        for item in artifacts if item.get("logical_dependency_lineage")
    ]
    base_coords = [
        str(item.get("coord") or "").strip()
        for item in artifacts if item.get("side") == "base" and item.get("coord")
    ]
    current_coords = [
        str(item.get("coord") or "").strip()
        for item in artifacts if item.get("side") == "current" and item.get("coord")
    ]
    fallback = next((
        str(item.get("runtime_code_source_origin_identity") or "").strip()
        for item in artifacts if item.get("runtime_code_source_origin_identity")
    ), "")
    coord = next((item for item in lineages if item), "")
    if not coord:
        candidate = next(iter(current_coords or base_coords), "")
        parts = candidate.split(":")
        coord = ":".join(parts[:-1]) if len(parts) >= 3 else candidate
    coord = coord or fallback or "UNBOUND_RUNTIME_ARTIFACT"

    def version(values: list[str]) -> str:
        if not values:
            return "-"
        parts = values[0].split(":")
        return parts[-1] if len(parts) >= 3 else values[0]

    return coord, version(base_coords), version(current_coords)


def _resource_activation_item(result: Mapping[str, Any]) -> dict[str, Any]:
    coord, old_version, new_version = _artifact_coord_parts(result)
    callers = []
    for caller in result.get("activation_callers") or ():
        if caller.get("path_certainty") not in {"exact", "possible"}:
            continue
        owner = str(caller.get("caller_class_name") or "").replace("/", ".")
        name = str(caller.get("caller_member_name") or "")
        descriptor = str(caller.get("caller_descriptor") or "")
        signature = (
            jvm_method_parameter_signature(descriptor)
            if descriptor.startswith("(") else "()"
        )
        callers.append({
            **dict(caller),
            "display_caller": f"{owner}.{name}{signature}",
        })
    return {
        **dict(result),
        "coord": coord,
        "old_version": old_version,
        "new_version": new_version,
        "activation_callers": callers,
        "business_entries": sorted({
            item["display_caller"] for item in callers
            if item.get("display_caller")
        }),
    }


def _product_change_row(
    decision: Mapping[str, Any],
    assessment: Mapping[str, Any],
    *,
    evidence_path: str,
) -> dict[str, Any]:
    scope = decision.get("fact_scope") or {}
    evidence = decision.get("evidence") or {}
    api_name, simple, descriptor = _api_display(scope)
    member_kind = str(scope.get("member_kind") or decision.get("fact_kind") or "class")
    if str(scope.get("member_name") or "") == "<init>":
        member_kind = "constructor"
    if member_kind not in {"method", "field", "class", "constructor"}:
        member_kind = "class"
    change_kind = str(scope.get("member_change_kind") or "implementation_changed")
    change_type = _product_change_type(decision)
    coord, old_version, new_version = _artifact_coord_parts(decision)
    incompatible = change_type in {"REMOVED", "SIGNATURE_CHANGED", "ACCESS_REDUCED"}
    change_label = _CHANGE_LABELS.get(change_kind, change_kind)
    api_signature = (
        jvm_method_parameter_signature(descriptor)
        if member_kind in {"method", "constructor"} and descriptor.startswith("(")
        else ""
    )
    if str(decision.get("fact_kind") or "") == "member_resolution":
        base_resolution = evidence.get("base_resolution") or {}
        current_resolution = evidence.get("current_resolution") or {}
        old_value = str(base_resolution.get("resolved_owner") or base_resolution.get("member_resolution_status") or "")
        new_value = str(current_resolution.get("resolved_owner") or current_resolution.get("member_resolution_status") or "")
    else:
        old_value = json.dumps(
            evidence.get("base_contract") or evidence.get("base_member_fingerprint") or "",
            ensure_ascii=False, sort_keys=True,
        )
        new_value = json.dumps(
            evidence.get("current_contract") or evidence.get("current_member_fingerprint") or "",
            ensure_ascii=False, sort_keys=True,
        )
    return {
        "conclusion": "二进制运行时有效变化",
        "change_summary": f"{change_label}：{api_name}{descriptor}",
        "review_reason": (
            f"依赖 {coord} 的运行时有效制品发生变化；"
            f"裁决原因 {decision.get('reason_code') or '-'}"
        ),
        "coord": coord,
        "old_version": old_version,
        "new_version": new_version,
        "change_type": change_type,
        "api_name": api_name,
        "api_simple": simple,
        "symbol_kind": member_kind,
        "api_signature": api_signature,
        "confirmed": "true",
        "severity": DEFAULT_SEVERITY.get(change_type, "P1"),
        "source": "classfile_contract",
        "binary_compatible": "false" if incompatible else "true",
        "source_compatible": "false" if incompatible else "unknown",
        "compatibility_flags": str(decision.get("reason_code") or ""),
        "reason_code": str(decision.get("reason_code") or ""),
        "data_contract_evidence": "",
        "evidence_path": evidence_path,
        "old_value": old_value,
        "new_value": new_value,
        "field_descriptor": descriptor if member_kind == "field" else "",
        "old_field_has_constant_value": "",
        "constant_field_evidence_json": "",
        "_decision_identity": str(decision.get("decision_identity") or ""),
        "_change_fact_identity": str(decision.get("change_fact_identity") or ""),
        "_projection_status": str(assessment.get("analysis_projection_status") or ""),
        "_projection_coverage_status": str(assessment.get("projection_coverage_status") or ""),
    }


def _trace_metrics_by_change(loaded: Mapping[str, Any]) -> dict[str, dict[str, int]]:
    metrics: dict[str, dict[str, int]] = {}
    for result in loaded["formal"].get("results") or ():
        identity = str(result.get("change_fact_identity") or "")
        item = metrics.setdefault(identity, {
            "exact_api": 0, "possible_api": 0,
            "exact_paths": 0, "possible_paths": 0,
        })
        exact_paths = sum(
            path.get("path_certainty") == "exact" for path in result.get("paths") or ()
        )
        possible_paths = sum(
            path.get("path_certainty") == "possible" for path in result.get("paths") or ()
        )
        item["exact_api"] = max(item["exact_api"], int(bool(result.get("exact_path_exists"))))
        item["possible_api"] = max(item["possible_api"], int(bool(result.get("possible_path_exists"))))
        item["exact_paths"] += exact_paths
        item["possible_paths"] += possible_paths
    return metrics


def publish_step4(report_dir: str | Path, output_dir: str | Path) -> dict[str, Any]:
    loaded = load_validated_generation(report_dir)
    source_usage = _source_usage_view(loaded)
    source_review_rows = _source_review_rows(loaded)
    source_candidate_rows = _source_candidate_review_rows(loaded)
    decisions = list(loaded["decisions"].get("authoritative_change_facts") or ())
    assessments = {
        str(item.get("decision_identity") or ""): item
        for item in loaded["projections"].get("authoritative_projection_assessments") or ()
    }
    generation = loaded["generation"]
    evidence_path = str(
        (generation / "binary_decisions.json").relative_to(loaded["report_dir"])
    )
    rows = []
    review_rows = []
    for decision in decisions:
        assessment = assessments.get(str(decision.get("decision_identity") or ""), {})
        if assessment.get("analysis_projection_status") == "targetable":
            rows.append(_product_change_row(
                decision, assessment, evidence_path=evidence_path
            ))
        review_rows.append(_review_row(
            decision, assessment, conclusion="正式变化"
        ))
    for decision in loaded["decisions"].get("diagnostic_candidate_facts") or ():
        review_rows.append(_review_row(
            decision, None, conclusion="诊断候选（证据不完整）"
        ))

    trace_metrics = _trace_metrics_by_change(loaded)
    dependencies: dict[str, dict[str, Any]] = {}
    for row in rows:
        dependency = dependencies.setdefault(row["coord"], {
            "rows": [], "change_types": set(), "symbol_kinds": set(),
            "exact_api_ids": set(), "possible_api_ids": set(),
            "exact_paths": 0, "possible_paths": 0,
        })
        dependency["rows"].append(row)
        dependency["change_types"].add(row["change_type"])
        dependency["symbol_kinds"].add(row["symbol_kind"])
        metric = trace_metrics.get(row["_change_fact_identity"], {})
        if metric.get("exact_api"):
            dependency["exact_api_ids"].add(row["_change_fact_identity"])
        if metric.get("possible_api"):
            dependency["possible_api_ids"].add(row["_change_fact_identity"])
        dependency["exact_paths"] += int(metric.get("exact_paths") or 0)
        dependency["possible_paths"] += int(metric.get("possible_paths") or 0)

    output = Path(output_dir).resolve()
    def write(stage: Path) -> None:
        with open_csv_write(stage / "all_changed_apis.csv") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=ALL_CHANGED_APIS_FIELDS, extrasaction="ignore"
            )
            writer.writeheader()
            writer.writerows(rows)

        dependency_fields = (
            "selection_key", "coord", "dependency_name", "changed_api_count",
            "high_risk_api_count", "business_exact_referenced_api_count",
            "business_candidate_referenced_api_count",
            "business_exact_reference_occurrence_count",
            "business_candidate_reference_occurrence_count",
            "business_reference_occurrence_count", "business_bytecode_scan_status",
            "dependency_source_status", "impact_priority_rank", "recommended",
            "change_types", "symbol_kinds", "review_focus", "detail",
        )
        dependency_rows = []
        ordered_dependencies = sorted(
            dependencies.items(),
            key=lambda item: (
                -len(item[1]["exact_api_ids"]),
                -len(item[1]["possible_api_ids"]),
                -len(item[1]["rows"]),
                item[0],
            ),
        )
        for rank, (coord, item) in enumerate(ordered_dependencies, start=1):
            detail = (
                f"s4_per_dependency/{make_per_dependency_dirname(coord)}/summary.md"
            )
            exact_count = len(item["exact_api_ids"])
            possible_count = len(item["possible_api_ids"] - item["exact_api_ids"])
            dependency_rows.append({
                "selection_key": coord,
                "coord": coord,
                "dependency_name": coord.split(":")[-1],
                "changed_api_count": len(item["rows"]),
                "high_risk_api_count": sum(
                    row["severity"] in {"P0", "P1"} for row in item["rows"]
                ),
                "business_exact_referenced_api_count": exact_count,
                "business_candidate_referenced_api_count": possible_count,
                "business_exact_reference_occurrence_count": item["exact_paths"],
                "business_candidate_reference_occurrence_count": item["possible_paths"],
                "business_reference_occurrence_count": (
                    item["exact_paths"] + item["possible_paths"]
                ),
                "business_bytecode_scan_status": (
                    "complete" if loaded["summary"].get("trace_coverage_status") == "complete"
                    else "incomplete"
                ),
                "dependency_source_status": "not_applicable",
                "impact_priority_rank": rank,
                "recommended": "true" if rank <= 10 else "false",
                "change_types": ", ".join(sorted(item["change_types"])),
                "symbol_kinds": ", ".join(sorted(item["symbol_kinds"])),
                "review_focus": (
                    f"发现 {exact_count} 个精确触达、{possible_count} 个可能触达的变化 API"
                ),
                "detail": detail,
            })
        with open_csv_write(stage / "changed_dependencies.csv") as handle:
            writer = csv.DictWriter(handle, fieldnames=dependency_fields)
            writer.writeheader()
            writer.writerows(dependency_rows)

        dependency_lines = [
            "# 发生 API 变化的依赖包", "",
            "本文件列出全部由当前运行时有效二进制制品引起、可进入系统触达分析的依赖包。", "",
            "完整人工裁决：[review.md](review.md)；"
            "需要筛选或批量处理时使用 [all_changed_apis.csv](all_changed_apis.csv)。", "",
            "| 排名 | Top 10 | 依赖包 | 精确触达 API | 可能触达 API | 变化 API 数 | 为什么先看 | 明细 |",
            "|---:|:---:|---|---:|---:|---:|---|---|",
        ]
        if dependency_rows:
            dependency_lines.extend(
                f"| {row['impact_priority_rank']} | "
                f"{'是' if row['recommended'] == 'true' else '否'} | `{row['coord']}` | "
                f"{row['business_exact_referenced_api_count']} | "
                f"{row['business_candidate_referenced_api_count']} | "
                f"{row['changed_api_count']} | {row['review_focus']} | "
                f"[查看]({row['detail']}) |"
                for row in dependency_rows
            )
        else:
            dependency_lines.append("| - | - | - | 0 | 0 | 0 | - | - |")
        _atomic_text(stage / "changed_dependencies.md", "\n".join(dependency_lines) + "\n")

        per_dependency = stage / "s4_per_dependency"
        per_dependency.mkdir()
        for dependency_row in dependency_rows:
            coord = dependency_row["coord"]
            detail_dir = per_dependency / make_per_dependency_dirname(coord)
            detail_dir.mkdir()
            detail_lines = [
                f"# {coord} 变化明细", "",
                f"- 变化 API：{dependency_row['changed_api_count']}",
                f"- 精确触达：{dependency_row['business_exact_referenced_api_count']}",
                f"- 可能触达：{dependency_row['business_candidate_referenced_api_count']}", "",
                "完整裁决上下文：[review.md](../../review.md)；"
                "可筛选明细：[all_changed_apis.csv](../../all_changed_apis.csv)。", "",
                "| 变化对象 | 类型 | 严重级别 | 结论 | 证据 |",
                "|---|---|---|---|---|",
            ]
            for row in dependencies[coord]["rows"]:
                detail_lines.append(
                    f"| `{row['api_name']}{row['api_signature']}` | {row['change_type']} | "
                    f"{row['severity']} | {row['conclusion']} | "
                    "[查看完整裁决](../../review.md) |"
                )
            _atomic_text(detail_dir / "summary.md", "\n".join(detail_lines) + "\n")

        reference_fields = (
            "coord", "api_name", "api_signature", "symbol_kind", "change_type",
            "match_quality", "caller_class", "caller_method", "caller_signature",
            "instruction_offset", "callee_key", "evidence_type", "artifact_entry",
        )
        reference_rows = []
        for row in rows:
            metric = trace_metrics.get(row["_change_fact_identity"], {})
            if metric.get("exact_api") or metric.get("possible_api"):
                reference_rows.append({
                    "coord": row["coord"], "api_name": row["api_name"],
                    "api_signature": row["api_signature"], "symbol_kind": row["symbol_kind"],
                    "change_type": row["change_type"],
                    "match_quality": "exact" if metric.get("exact_api") else "possible",
                    "caller_class": "详见 Step5 调用链",
                    "caller_method": "", "caller_signature": "", "instruction_offset": "",
                    "callee_key": f"{row['api_name']}{row['api_signature']}",
                    "evidence_type": "binary_effective_graph_path",
                    "artifact_entry": evidence_path,
                })
        with open_csv_write(stage / "business_bytecode_changed_api_refs.csv") as handle:
            writer = csv.DictWriter(handle, fieldnames=reference_fields)
            writer.writeheader()
            writer.writerows(reference_rows)
        _atomic_json(stage / "business_bytecode_priority_evidence.json", {
            "schema": "java-upgrade-analyzer.step4-business-priority-evidence.v1",
            "authority": "binary_first",
            "scan_status": (
                "complete" if loaded["summary"].get("trace_coverage_status") == "complete"
                else "incomplete"
            ),
            "reason_codes": list(loaded["coverage"].get("trace_coverage_gaps") or ()),
            "evidence_file": "business_bytecode_changed_api_refs.csv",
            "matched_dependency_count": sum(
                bool(row["business_reference_occurrence_count"]) for row in dependency_rows
            ),
            "exact_referenced_api_count": sum(
                row["business_exact_referenced_api_count"] for row in dependency_rows
            ),
            "candidate_referenced_api_count": sum(
                row["business_candidate_referenced_api_count"] for row in dependency_rows
            ),
        })

        source_fields = (
            "源码归属", "归属类型", "二进制制品", "二进制方法", "源码位置", "模块", "语言",
            "源码声明", "注解", "修饰符",
        )
        with open_csv_write(stage / "source_overlay.csv") as handle:
            writer = csv.DictWriter(handle, fieldnames=source_fields)
            writer.writeheader()
            writer.writerows(source_review_rows)
        source_gap_fields = (
            "原因", "语言", "源码归属", "模块", "源码文件", "解析器", "错误节点",
        )
        source_gap_rows = [{
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
        } for gap in source_usage["coverage_gaps"]]
        with open_csv_write(stage / "source_coverage_gaps.csv") as handle:
            writer = csv.DictWriter(handle, fieldnames=source_gap_fields)
            writer.writeheader()
            writer.writerows(source_gap_rows)
        _atomic_json(
            stage / "source_snapshot.json", loaded["source_attestation"]
        )
        language_summary = "、".join(
            f"{language} {count} 个"
            for language, count in sorted(
                source_usage["language_file_counts"].items()
            )
        ) or "未提供源码文件"
        source_lines = [
            "# 源码辅助证据", "",
            f"- 源码状态：{source_usage['label']}",
            f"- 覆盖状态：`{source_usage['coverage_status']}`",
            f"- 已映射方法：{source_usage['mapped_count']}",
            f"- 源码文件：{language_summary}",
            f"- 未映射/解析缺口：{len(source_gap_rows)} 个；"
            "[查看逐文件缺口](coverage_gaps.csv)",
            "- 完整源码快照与 SHA：[source_snapshot.json](source_snapshot.json)", "",
            source_usage["effect"], "",
        ]
        if source_review_rows:
            source_lines.extend((
                "| 源码归属 | 二进制制品 | 二进制方法 | 源码位置 | 源码声明 | 注解 |",
                "|---|---|---|---|---|---|",
            ))
            source_lines.extend(
                f"| `{row['源码归属']}` | `{row['二进制制品']}` | "
                f"`{row['二进制方法']}` | `{row['源码位置']}` | "
                f"{row['源码声明'] or '-'} | {row['注解'] or '-'} |"
                for row in source_review_rows
            )
        elif source_usage["decision"] == "skip_source":
            source_lines.append("本次由用户明确选择不提供源码，因此没有源码映射行；这不影响二进制正式结论。")
        else:
            source_lines.append("已使用源码，但没有方法完成精确 descriptor 映射；请结合覆盖状态和冲突计数复核。")
        candidate_fields = (
            "源码归属", "二进制制品", "调用方", "源码位置", "候选目标",
            "证据类型", "置信度", "权威边界",
        )
        with open_csv_write(stage / "source_candidate_relationships.csv") as handle:
            writer = csv.DictWriter(handle, fieldnames=candidate_fields)
            writer.writeheader()
            writer.writerows(source_candidate_rows)
        source_lines.extend(("", "## 源码候选关系", ""))
        if source_candidate_rows:
            source_lines.extend((
                "以下关系用于人工解释和候选复核，不能替代字节码可执行边。", "",
                "| 源码归属 | 调用方 | 候选目标 | 源码位置 | 置信度 |",
                "|---|---|---|---|---|",
            ))
            source_lines.extend(
                f"| `{row['源码归属']}` | `{row['调用方']}` | `{row['候选目标']}` | "
                f"`{row['源码位置']}` | `{row['置信度']}` |"
                for row in source_candidate_rows
            )
        else:
            source_lines.append("本次没有生成源码候选调用关系。")
        _atomic_text(stage / "source_overlay.md", "\n".join(source_lines) + "\n")

        summary = {
            "schema": "java-upgrade-analyzer.binary-step4-summary.v1",
            "authority": "binary_first",
            "result_generation_identity": loaded["manifest"]["result_generation_identity"],
            "analysis_context_identity": loaded["manifest"]["analysis_context_identity"],
            "authoritative_change_fact_count": len(decisions),
            "targetable_change_fact_count": sum(
                item.get("analysis_projection_status") == "targetable"
                for item in assessments.values()
            ),
            "confirmed_unprojectable_fact_count": len(
                loaded["projections"].get("confirmed_unprojectable_facts") or ()
            ),
            "diagnostic_candidate_fact_count": len(
                loaded["decisions"].get("diagnostic_candidate_facts") or ()
            ),
            "excluded_decision_count": len(loaded["decisions"].get("excluded_decisions") or ()),
            "dependency_count": len(dependency_rows),
            "published_api_change_count": len(rows),
            "source_usage": source_usage,
            "decision_coverage_status": loaded["summary"].get(
                "decision_coverage_status"
            ),
            "trace_coverage_status": loaded["summary"].get(
                "trace_coverage_status"
            ),
            "coverage": loaded["coverage"],
        }
        _atomic_json(stage / "summary.json", summary)
        summary_lines = [
            "# Binary-first 运行时变化事实", "",
            "人工复核请先看 `changed_dependencies.md`，再进入依赖明细；"
            "需要筛选或批量处理时使用 `all_changed_apis.csv`。", "",
            f"- 权威变化事实：{summary['authoritative_change_fact_count']}",
            f"- 可投影变化事实：{summary['targetable_change_fact_count']}",
            f"- 确认但不可投影：{summary['confirmed_unprojectable_fact_count']}",
            f"- 诊断候选事实：{summary['diagnostic_candidate_fact_count']}",
            f"- 排除裁决：{summary['excluded_decision_count']}",
            f"- 涉及依赖：{summary['dependency_count']}",
            f"- 源码选择：{source_usage['label']}",
            f"- 源码映射：{source_usage['mapped_count']} 个，覆盖状态 `{source_usage['coverage_status']}`",
            "",
        ]
        summary_lines.extend((
            source_usage["effect"], "",
            "源码辅助证据：`../source_analysis/review.md`；"
            "结构化映射：`../source_analysis/method_mappings.csv`；"
            "候选关系：`../source_analysis/candidate_relationships.csv`；"
            "逐文件缺口：`../source_analysis/coverage_gaps.csv`。", "",
        ))
        _atomic_text(stage / "summary.md", "\n".join(summary_lines))

        review_lines = [
            "# 运行时变化人工复核", "",
            "本报告按引起变化的依赖包分组。`正式变化` 来自完整二进制裁决；"
            "`诊断候选` 表示证据仍有缺口，不能解释为无影响。", "",
            f"- 源码选择：{source_usage['label']}",
            f"- 源码覆盖：`{source_usage['coverage_status']}`；已映射 {source_usage['mapped_count']} 个方法",
            f"- 作用边界：{source_usage['effect']}", "",
        ]
        review_dependencies = sorted({row["依赖包"] for row in review_rows})
        for dependency in review_dependencies:
            review_lines.extend((f"## {dependency}", ""))
            for row in (item for item in review_rows if item["依赖包"] == dependency):
                review_lines.extend((
                    f"### {row['变化对象']}", "",
                    f"- 制品：`{row['升级前制品']}` → `{row['升级后制品']}`",
                    f"- 变化：{row['变化类型']}",
                    f"- 结论：{row['裁决结论']}",
                    f"- 原因：`{row['裁决原因']}`",
                    f"- 投影/覆盖：{row['投影状态']} / {row['覆盖状态']}",
                    f"- 需要人工复核：{row['需人工复核']}",
                    f"- 证据缺口：{row['证据缺口']}",
                    f"- 裁决身份：`{row['decision_identity']}`", "",
                ))
        _atomic_text(stage / "review.md", "\n".join(review_lines))
    _stage_directory(output, write)
    source_output = loaded["report_dir"] / "evidence" / "source_analysis"

    def publish_source(stage: Path) -> None:
        shutil.copyfile(output / "source_overlay.md", stage / "review.md")
        shutil.copyfile(output / "source_overlay.csv", stage / "method_mappings.csv")
        shutil.copyfile(
            output / "source_candidate_relationships.csv",
            stage / "candidate_relationships.csv",
        )
        shutil.copyfile(
            output / "source_coverage_gaps.csv",
            stage / "coverage_gaps.csv",
        )
        shutil.copyfile(
            output / "source_snapshot.json",
            stage / "source_snapshot.json",
        )

    _stage_directory(source_output, publish_source)
    for obsolete_source_file in (
        "source_overlay.md", "source_overlay.csv",
        "source_candidate_relationships.csv",
        "source_coverage_gaps.csv", "source_snapshot.json",
    ):
        (output / obsolete_source_file).unlink()
    return {"phase": "step4", "change_fact_count": len(rows), "output_dir": str(output)}


def _result_item(api: Mapping[str, Any]) -> dict[str, Any]:
    owner = str(api.get("display_owner") or "").replace("/", ".")
    member = str(api.get("display_member") or "")
    name = owner if not member or member == "<class>" else f"{owner}.{member}"
    dependency = _dependency_view(api)
    paths = list(api.get("paths") or ())
    primary_path = next(
        (item for item in paths if item.get("path_certainty") == "exact"),
        paths[0] if paths else {},
    )
    descriptor = str(api.get("display_descriptor") or "")
    api_signature = (
        jvm_method_parameter_signature(descriptor)
        if descriptor.startswith("(") else ""
    )
    return {
        "coord": dependency["dependency"],
        "target_coord": dependency["dependency"],
        "base_dependency": dependency["base_dependency"],
        "current_dependency": dependency["current_dependency"],
        "api": name,
        "changed_symbol": name,
        "api_signature": api_signature,
        "symbol_kind": str(api.get("display_member_kind") or ""),
        "reported_api_identity": api.get("reported_api_identity"),
        "reachability_status": api.get("reachability_status"),
        "path_status": api.get("reachability_status"),
        "impact_conclusion": api.get("impact_conclusion"),
        "static_linkage_status": api.get("static_linkage_status"),
        "runtime_verification_status": api.get("runtime_verification_status"),
        "path_set_complete": bool(api.get("path_set_complete")),
        "exact_path_exists": bool(api.get("exact_path_exists")),
        "possible_path_exists": bool(api.get("possible_path_exists")),
        "path_text": str(primary_path.get("path_text") or ""),
        "path_certainty": str(primary_path.get("path_certainty") or ""),
        "paths": paths,
        "reason": "二进制运行时有效变化的系统触达结果",
        "contributing_change_fact_ids": list(api.get("contributing_change_fact_ids") or ()),
    }


LEGACY_ALERT_FIELDS = (
    "conclusion", "change_summary", "review_reason", "chain_summary",
    "review_focus", "chain_entry", "chain_target", "chain_hop_count",
    "chain_detail", "api_identity", "path_id", "target_coord",
    "changed_symbol", "api_signature", "symbol_kind", "compile_impact",
    "runtime_link_impact", "change_type", "severity", "path_status",
    "uncertainty_kind", "business_reachable", "entry_kind", "reach_kind",
    "business_entry", "consumer_coord", "consumer_class", "consumer_method",
    "consumer_signature", "path_text", "path_occurrence_count",
    "evidence_files", "detail_file",
)


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _change_row_key(row: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(row.get("coord") or "").strip(),
        str(row.get("api_name") or row.get("api") or "").strip(),
        str(row.get("api_signature") or "").strip(),
        str(row.get("symbol_kind") or "").strip(),
    )


def _change_rows_by_result(
    report_dir: str | Path,
) -> tuple[list[dict[str, str]], dict[tuple[str, str, str, str], dict[str, str]]]:
    rows = _read_csv_rows(
        Path(report_dir).resolve() / "evidence" / "api_changes" / "all_changed_apis.csv"
    )
    lookup: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for row in rows:
        lookup.setdefault(_change_row_key(row), row)
    return rows, lookup


def _legacy_result_item(
    item: Mapping[str, Any],
    change_row: Mapping[str, Any] | None,
) -> dict[str, Any]:
    change = dict(change_row or {})
    paths = [
        str(path.get("path_text") or "").strip()
        for path in item.get("paths") or []
        if str(path.get("path_text") or "").strip()
    ]
    if not paths and str(item.get("path_text") or "").strip():
        paths = [str(item.get("path_text") or "").strip()]
    state = str(item.get("reachability_status") or "not_analyzed")
    if state == "reachable":
        user_conclusion = "已确认影响"
        reason_code = "RUNTIME_VERIFICATION_REQUIRED"
        user_reason = (
            "已确认当前系统存在到该变化 API 的精确静态可执行调用关系；"
            "这里确认的是调用关系受到 API 变化影响，不表示运行时故障已经发生，"
            "仍需定向测试验证。"
        )
    elif state == "uncertain":
        user_conclusion = "结论未确定（存在候选证据）" if paths else "结论未确定（静态分析能力边界）"
        reason_code = "BINARY_REACHABILITY_UNCERTAIN"
        user_reason = "存在候选证据或静态分析边界，当前不能确认实际影响。"
    elif state == "not_found_in_static_analysis":
        user_conclusion = "未发现调用路径"
        reason_code = "NOT_FOUND_IN_STATIC_ANALYSIS"
        user_reason = "当前完整静态范围内未发现调用路径；该结论不能解释为安全。"
    else:
        user_conclusion = "本次未完成分析"
        reason_code = "BINARY_TRACE_NOT_ANALYZED"
        user_reason = "二进制触达分析未形成可采用结果，不能解释为未受影响。"
    api = str(item.get("api") or "")
    api_signature = str(item.get("api_signature") or "")
    old_version = str(change.get("old_version") or "")
    new_version = str(change.get("new_version") or "")
    business_entry = paths[0].split(" → ", 1)[0] if paths else ""
    primary_path = next(
        (
            candidate for candidate in item.get("paths") or []
            if candidate.get("path_text") == (paths[0] if paths else "")
        ),
        {},
    )
    return {
        **dict(item),
        "api_identity": "|".join((
            str(item.get("coord") or ""), api, api_signature,
            str(item.get("symbol_kind") or ""), str(change.get("change_type") or ""),
        )),
        "old_version": old_version,
        "new_version": new_version,
        "api_name": api,
        "api_simple": api.rsplit(".", 1)[-1],
        "change_type": str(change.get("change_type") or ""),
        "symbol_kind": str(change.get("symbol_kind") or item.get("symbol_kind") or ""),
        "severity": str(change.get("severity") or "P1"),
        "confirmed": str(change.get("confirmed") or "true"),
        "source": str(change.get("source") or "binary_first"),
        "analysis_status": state,
        "uncertainty_kind": (
            "candidate_evidence" if state == "uncertain" and paths
            else "analysis_limitation" if state == "uncertain" else ""
        ),
        "reason_code": reason_code,
        "reason": user_reason,
        "reachable_note": user_reason,
        "direct_callers": len(paths),
        "business_reach_depth": max(len(paths[0].split(" → ")) - 1, 0) if paths else 0,
        "dependency_chain_coords": [],
        "call_paths": paths,
        "path_details": [
            {
                "path_status": state,
                "path_text": path,
                "path_certainty": str(
                    next((candidate.get("path_certainty") for candidate in item.get("paths") or [] if candidate.get("path_text") == path), "")
                ),
                "entry_kinds": list(
                    next((candidate.get("entry_kinds") or [] for candidate in item.get("paths") or [] if candidate.get("path_text") == path), [])
                ),
                "entry_kind_labels": list(
                    next((candidate.get("entry_kind_labels") or [] for candidate in item.get("paths") or [] if candidate.get("path_text") == path), [])
                ),
                "entrypoint_dependency_coords": list(
                    next((candidate.get("entrypoint_dependency_coords") or [] for candidate in item.get("paths") or [] if candidate.get("path_text") == path), [])
                ),
                "entrypoint_activation_reasons": list(
                    next((candidate.get("entrypoint_activation_reasons") or [] for candidate in item.get("paths") or [] if candidate.get("path_text") == path), [])
                ),
                "mechanism_kinds": list(
                    next((candidate.get("mechanism_kinds") or [] for candidate in item.get("paths") or [] if candidate.get("path_text") == path), [])
                ),
                "mechanism_labels": list(
                    next((candidate.get("mechanism_labels") or [] for candidate in item.get("paths") or [] if candidate.get("path_text") == path), [])
                ),
            }
            for path in paths
        ],
        "evidence_paths": [],
        "verification": ["执行相关单元测试、集成测试或运行时回归验证。"] if state == "reachable" else [],
        "priority_score": 0,
        "priority_factors": {},
        "user_conclusion": user_conclusion,
        "decision_bucket": "probable_impact" if state == "reachable" else state,
        "user_reason": user_reason,
        "recommended_action": (
            "根据已定位调用关系执行定向回归验证。" if state == "reachable"
            else "复核证据边界并补充缺失输入或测试。"
        ),
        "key_evidence": paths[0] if paths else "",
        "business_entry": business_entry,
        "entry_kind": " / ".join(primary_path.get("entry_kind_labels") or ()),
        "entrypoint_dependency": " / ".join(
            primary_path.get("entrypoint_dependency_coords") or ()
        ),
        "change_summary": str(change.get("change_summary") or ""),
        "old_value": str(change.get("old_value") or ""),
        "new_value": str(change.get("new_value") or ""),
        "review_reason": str(change.get("review_reason") or user_reason),
    }


def _legacy_alert_rows(items: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows = []
    for item in items:
        paths = list(item.get("call_paths") or []) or [""]
        for index, path in enumerate(paths, start=1):
            path_detail = next(
                (
                    candidate for candidate in item.get("path_details") or ()
                    if str(candidate.get("path_text") or "") == str(path)
                ),
                {},
            )
            entry_kind = " / ".join(
                str(value) for value in path_detail.get("entry_kind_labels") or ()
                if str(value)
            )
            entrypoint_dependency = " / ".join(
                str(value)
                for value in path_detail.get("entrypoint_dependency_coords") or ()
                if str(value)
            )
            mechanism_labels = " / ".join(
                str(value)
                for value in path_detail.get("mechanism_labels") or ()
                if str(value)
            )
            nodes = [part.strip() for part in str(path).split(" → ") if part.strip()]
            entry = nodes[0] if nodes else str(item.get("business_entry") or "")
            target = nodes[-1] if nodes else f"{item.get('api') or ''}{item.get('api_signature') or ''}"
            identity = str(item.get("api_identity") or "")
            digest = hashlib.sha1(f"{identity}|{path}|{index}".encode("utf-8")).hexdigest()[:12]
            status = str(item.get("analysis_status") or "not_analyzed")
            entry_prefix, separator, entry_signature = entry.partition("(")
            entry_signature = f"({entry_signature}" if separator else ""
            consumer_class, dot, consumer_method = entry_prefix.rpartition(".")
            if not dot:
                consumer_class, consumer_method = entry_prefix, ""
            rows.append({
                "conclusion": str(item.get("user_conclusion") or ""),
                "change_summary": str(item.get("change_summary") or ""),
                "review_reason": str(item.get("review_reason") or item.get("user_reason") or ""),
                "chain_summary": (
                    f"入口类型：{entry_kind or '业务字节码入口'}；入口：{entry}；"
                    f"路径机制：{mechanism_labels or '字节码直接调用'}；"
                    f"终点：{target}；{max(len(nodes) - 1, 0)} 次调用（{len(nodes)} 个节点）"
                    if path else f"未形成完整链路；目标 API：{target}"
                ),
                "review_focus": str(item.get("recommended_action") or ""),
                "chain_entry": entry,
                "chain_target": target,
                "chain_hop_count": str(max(len(nodes) - 1, 0)),
                "chain_detail": " -> ".join(f"{position}. {node}" for position, node in enumerate(nodes, start=1)),
                "api_identity": identity,
                "path_id": f"PATH-{digest}",
                "target_coord": str(item.get("coord") or ""),
                "changed_symbol": str(item.get("api") or ""),
                "api_signature": str(item.get("api_signature") or ""),
                "symbol_kind": str(item.get("symbol_kind") or ""),
                "compile_impact": str(item.get("static_linkage_status") or ""),
                "runtime_link_impact": str(item.get("impact_conclusion") or ""),
                "change_type": str(item.get("change_type") or ""),
                "severity": str(item.get("severity") or "P1"),
                "path_status": status,
                "uncertainty_kind": str(item.get("uncertainty_kind") or ""),
                "business_reachable": "true" if status == "reachable" else "unknown",
                "entry_kind": entry_kind or ("业务字节码入口" if entry else ""),
                "reach_kind": mechanism_labels or ("字节码直接调用" if path else ""),
                "business_entry": entry,
                "consumer_coord": entrypoint_dependency or ("业务制品" if entry else ""),
                "consumer_class": consumer_class,
                "consumer_method": consumer_method,
                "consumer_signature": entry_signature,
                "path_text": str(path),
                "path_occurrence_count": "1",
                "evidence_files": ".runtime/binary_authority/active_binary_generation.json",
                "detail_file": "",
            })
    return rows


def _safe_detail_filename(item: Mapping[str, Any]) -> str:
    identity = str(item.get("api_identity") or item.get("reported_api_identity") or "api")
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", identity).strip("_")[:96] or "api"
    return f"{slug}_{hashlib.sha1(identity.encode('utf-8')).hexdigest()[:12]}.json"


def _legacy_coverage(loaded: Mapping[str, Any]) -> dict[str, Any]:
    def reason_codes(values: Any) -> list[str]:
        result = []
        for value in values or ():
            if isinstance(value, Mapping):
                code = str(value.get("reason_code") or value.get("code") or "").strip()
            else:
                code = str(value or "").strip()
            if code and code not in result:
                result.append(code)
        return result

    summary = dict(loaded.get("summary") or {})
    binary = dict(loaded.get("coverage") or {})
    decision_status = str(summary.get("decision_coverage_status") or "unknown")
    trace_status = str(summary.get("trace_coverage_status") or "unknown")
    components = [
        {
            "id": "binary_api_diff",
            "status": "complete" if decision_status == "complete" else "partial",
            "reason_codes": reason_codes(
                summary.get("decision_coverage_gaps")
                or binary.get("decision_coverage_gaps")
            ),
            "evidence": [".runtime/binary_authority/active_binary_generation.json"],
        },
        {
            "id": "business_reachability",
            "status": "complete" if trace_status == "complete" else "partial",
            "reason_codes": reason_codes(
                summary.get("trace_coverage_gaps")
                or binary.get("trace_coverage_gaps")
            ),
            "evidence": ["evidence/call_chain/alerts.csv"],
        },
    ]
    critical = [item["id"] for item in components if item["status"] != "complete"]
    return {
        "schema": "java-upgrade-analyzer.coverage.v1",
        "overall_status": "complete" if not critical else "partial",
        "critical_incomplete": critical,
        "components": components,
        "binary": binary,
    }


def publish_step5(
    report_dir: str | Path,
    output_dir: str | Path,
    *,
    selected_coords: tuple[str, ...] = (),
    selected_names: tuple[str, ...] = (),
) -> dict[str, Any]:
    loaded = load_validated_generation(report_dir)
    source_usage = _source_usage_view(loaded)
    by_api = list(loaded["formal"].get("by_api") or ())
    raw_items = [_result_item(item) for item in by_api]
    all_resource_items = [
        _resource_activation_item(item)
        for item in loaded["formal"].get("resource_activation_results") or ()
    ]
    _change_rows, change_lookup = _change_rows_by_result(report_dir)
    projection_assessments = {
        str(item.get("decision_identity") or ""): item
        for item in loaded["projections"].get("authoritative_projection_assessments") or ()
    }
    changes_by_fact_identity = {}
    for decision in loaded["decisions"].get("authoritative_change_facts") or ():
        fact_identity = str(decision.get("change_fact_identity") or "")
        assessment = projection_assessments.get(
            str(decision.get("decision_identity") or ""), {}
        )
        if fact_identity and assessment.get("analysis_projection_status") == "targetable":
            changes_by_fact_identity[fact_identity] = _product_change_row(
                decision,
                assessment,
                evidence_path=".runtime/binary_authority/active_binary_generation.json",
            )

    def change_for(item: Mapping[str, Any]) -> dict[str, str]:
        for fact_identity in item.get("contributing_change_fact_ids") or ():
            exact_fact = changes_by_fact_identity.get(str(fact_identity or ""))
            if exact_fact is not None:
                return exact_fact
        exact = change_lookup.get(_change_row_key(item))
        if exact is not None:
            return exact
        coord = str(item.get("coord") or "")
        api = str(item.get("api") or "")
        kind = str(item.get("symbol_kind") or "")
        same_kind = next(
            (
                row for key, row in change_lookup.items()
                if key[0] == coord and key[1] == api and key[3] == kind
            ),
            {},
        )
        if same_kind:
            return same_kind
        return next(
            (row for key, row in change_lookup.items() if key[0] == coord and key[1] == api),
            {},
        )

    all_items = [
        _legacy_result_item(item, change_for(item)) for item in raw_items
    ]
    items = list(all_items)
    selected_coord_set = {str(item).strip() for item in selected_coords if str(item).strip()}
    selected_name_set = {str(item).strip() for item in selected_names if str(item).strip()}
    if selected_coord_set or selected_name_set:
        items = [
            item for item in items
            if item["coord"] in selected_coord_set
            or item["coord"].split(":")[-1] in selected_name_set
        ]
    by_state = {
        state: [item for item in items if item["analysis_status"] == state]
        for state in ("reachable", "uncertain", "not_found_in_static_analysis", "not_analyzed")
    }
    binary_summary = loaded["summary"]
    dependency_rows = _read_csv_rows(
        Path(report_dir).resolve() / "evidence" / "dependencies" / "dep_changes.csv"
    )
    all_dependency_coords = sorted({
        str(row.get("coord") or row.get("comparison_key") or "").strip()
        for row in dependency_rows
        if str(row.get("coord") or row.get("comparison_key") or "").strip()
    } | {item["coord"] for item in all_items})
    if selected_coord_set or selected_name_set:
        included_dependency_coords = sorted({
            coord for coord in all_dependency_coords
            if coord in selected_coord_set or coord.split(":")[-1] in selected_name_set
        })
    else:
        included_dependency_coords = list(all_dependency_coords)
    resource_items = [
        item for item in all_resource_items
        if item["coord"] in included_dependency_coords
    ]
    excluded_dependency_coords = sorted(
        set(all_dependency_coords) - set(included_dependency_coords)
    )
    scope = {
        "mode": "partial" if selected_coord_set or selected_name_set else "full",
        "validation_status": "passed",
        "selected_coords": sorted(selected_coord_set),
        "selected_names": sorted(selected_name_set),
        "included_dependency_coords": included_dependency_coords,
        "excluded_dependency_coords": excluded_dependency_coords,
        "available_dependency_count": len(all_dependency_coords),
        "included_dependency_count": len(included_dependency_coords),
        "total_api_count": len(all_items),
        "analyzed_api_count": len(items),
        "included_api_count": len(items),
        "included_reported_api_identities": sorted(
            str(item.get("reported_api_identity") or "") for item in items
        ),
        "excluded_api_count": len(all_items) - len(items),
    }
    summary = {
        "schema": "java-upgrade-analyzer.binary-step5-summary.v1",
        "status": "done",
        "skip_reason": "",
        "origin_step": "step5",
        "authority": "binary_first",
        "result_generation_identity": loaded["manifest"]["result_generation_identity"],
        "analysis_context_identity": loaded["manifest"]["analysis_context_identity"],
        "total_apis": len(items),
        "reachable": len(by_state["reachable"]),
        "not_impacted": 0,
        "uncertain": len(by_state["uncertain"]),
        "not_found_in_static_analysis": len(by_state["not_found_in_static_analysis"]),
        "not_analyzed": len(by_state["not_analyzed"]),
        "analysis_scope": scope,
        "reachable_apis": by_state["reachable"],
        "not_impacted_apis": [],
        "uncertain_apis": by_state["uncertain"],
        "not_found_apis": by_state["not_found_in_static_analysis"],
        "not_analyzed_apis": by_state["not_analyzed"],
        "resource_activation_results": resource_items,
        "meta": {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "total_apis": len(items),
            "reachable": len(by_state["reachable"]),
            "not_impacted": 0,
            "uncertain": len(by_state["uncertain"]),
            "not_analyzed": len(by_state["not_analyzed"]),
            "not_found_in_static_analysis": len(by_state["not_found_in_static_analysis"]),
            "tool": "binary_pipeline.py + binary_report.py",
            "graph_stats": {
                "truncated": binary_summary.get("trace_coverage_status") != "complete",
                "truncation_reasons": list(binary_summary.get("trace_coverage_gaps") or ()),
            },
        },
        "formal_dimensions": {
            "reachability_status": ["reachable", "uncertain", "not_found_in_static_analysis", "not_analyzed"],
            "impact_conclusion": ["probable_impact", "inconclusive"],
            "runtime_verification_status": ["required_not_executed", "undetermined"],
                "static_linkage_status": [
                    "compatible_or_not_applicable", "incompatible_if_executed", "undetermined"
                ],
        },
        "quality_gate": {
            "probable_impact": sum(
                item["impact_conclusion"] == "probable_impact" for item in items
            ),
            "inconclusive": len(by_state["uncertain"]) + len(by_state["not_analyzed"]),
        },
        "user_conclusion_summary": {
            "probable_impact": sum(
                item["impact_conclusion"] == "probable_impact" for item in items
            ),
            "inconclusive": len(by_state["uncertain"]) + len(by_state["not_analyzed"]),
        },
        "diagnostic_guidance": [],
        "candidate_diagnostics": {
            "fact_count": int(binary_summary.get("diagnostic_candidate_fact_count") or 0),
            "trace_result_count": int(binary_summary.get("candidate_trace_result_count") or 0),
            "included_in_formal_totals": False,
        },
        "coverage": loaded["coverage"],
        "source_usage": source_usage,
    }
    output = Path(output_dir).resolve()
    def write(stage: Path) -> None:
        _atomic_json(stage / "summary.json", summary)
        alert_rows = _legacy_alert_rows(items)
        with open_csv_write(stage / "alerts.csv") as handle:
            writer = csv.DictWriter(handle, fieldnames=LEGACY_ALERT_FIELDS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(alert_rows)
        for status in (
            "reachable", "uncertain", "not_found_in_static_analysis", "not_analyzed"
        ):
            status_rows = [row for row in alert_rows if row["path_status"] == status]
            if not status_rows:
                continue
            with open_csv_write(stage / f"alerts_{status}.csv") as handle:
                writer = csv.DictWriter(handle, fieldnames=LEGACY_ALERT_FIELDS, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(status_rows)
        by_api_dir = stage / "by_api"
        by_api_dir.mkdir()
        for item in items:
            _atomic_json(by_api_dir / _safe_detail_filename(item), item)
        dependency_counts = {
            coord: {
                "total": 0,
                "reachable": 0,
                "uncertain": 0,
                "not_found_in_static_analysis": 0,
                "not_analyzed": 0,
            }
            for coord in included_dependency_coords
        }
        for item in items:
            counts = dependency_counts.setdefault(item["coord"], {
                "total": 0,
                "reachable": 0,
                "uncertain": 0,
                "not_found_in_static_analysis": 0,
                "not_analyzed": 0,
            })
            counts["total"] += 1
            counts[str(item["analysis_status"])] += 1
        for item in resource_items:
            counts = dependency_counts.setdefault(item["coord"], {
                "total": 0,
                "reachable": 0,
                "uncertain": 0,
                "not_found_in_static_analysis": 0,
                "not_analyzed": 0,
            })
            counts.setdefault("resource_activation_reachable", 0)
            counts["resource_activation_reachable"] += int(
                item.get("activation_status") == "reachable"
            )
        lines = [
            "# 系统触达证据", "",
            "本报告按引起变化的依赖包汇总。完整筛选表见 `alerts.csv`，逐 API 证据见 `by_api/`。", "",
            f"- 变化 API：{summary['total_apis']}",
            f"- 已发现静态可执行路径：{summary['reachable']}",
            f"- 结论不确定：{summary['uncertain']}",
            f"- 静态范围内未发现路径：{summary['not_found_in_static_analysis']}",
            f"- 未完成分析：{summary['not_analyzed']}", "",
            f"- 源码选择：{source_usage['label']}",
            f"- 源码映射：{source_usage['mapped_count']} 个，覆盖状态 `{source_usage['coverage_status']}`", "",
            source_usage["effect"], "",
            "`not_found_in_static_analysis` 不是已确认无影响；静态可执行路径也不等于已完成运行时验证。", "",
            "## 运行时资源激活", "",
        ]
        if resource_items:
            lines.extend((
                "| 依赖包 | 资源 | 激活状态 | 当前系统入口 |",
                "|---|---|---|---|",
            ))
            for item in resource_items:
                entries = "<br>".join(
                    f"`{entry}`" for entry in item.get("business_entries") or ()
                ) or "-"
                status_label = {
                    "reachable": "已确认当前系统激活",
                    "uncertain": "存在候选激活关系",
                    "not_found_in_static_analysis": "未发现静态激活关系",
                    "not_analyzed": "未完成激活分析",
                }.get(str(item.get("activation_status") or ""), "未知")
                lines.append(
                    f"| `{item['coord']}` | `{item['resource_name']}` | "
                    f"{status_label} | {entries} |"
                )
        else:
            lines.append("本轮没有可展示的运行时资源变化激活结果。")
        lines.extend([
            "",
            "## 按依赖汇总", "",
            "| 依赖包 | API 数 | 已发现路径 | 资源激活 | 不确定 | 未发现路径 | 未分析 |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ])
        for coord, counts in sorted(dependency_counts.items()):
            lines.append(
                f"| `{coord}` | {counts['total']} | {counts['reachable']} | "
                f"{counts.get('resource_activation_reachable', 0)} | "
                f"{counts['uncertain']} | {counts['not_found_in_static_analysis']} | "
                f"{counts['not_analyzed']} |"
            )
        _atomic_text(stage / "summary.md", "\n".join(lines) + "\n")
    _stage_directory(output, write)
    scope_path = Path(report_dir).resolve() / ".runtime" / "cache" / "step5_selection.json"
    _atomic_json(scope_path, scope)
    _atomic_json(
        Path(report_dir).resolve() / ".runtime" / "coverage" / "s4_coverage.json",
        _legacy_coverage(loaded),
    )
    binary_review = Path(report_dir).resolve() / "evidence" / "binary_analysis"
    binary_review.mkdir(parents=True, exist_ok=True)
    _atomic_text(
        binary_review / "system-reachability.md",
        "\n".join((
            "# 二进制系统触达执行摘要", "",
            "该文件记录新引擎执行信息；面向人工复核的正式结果仍从 `deliverables/report.md` 开始阅读。", "",
            f"- 变化 API：{summary['total_apis']}",
            f"- 已发现静态可执行路径：{summary['reachable']}",
            f"- 结论不确定：{summary['uncertain']}",
            f"- 未发现静态路径：{summary['not_found_in_static_analysis']}",
            f"- 未完成分析：{summary['not_analyzed']}",
            f"- 源码选择：{source_usage['label']}", "",
            source_usage["effect"], "",
        )),
    )
    query_index = {
        "schema": "java-upgrade-analyzer.s5-query-index.v1",
        "authority": "binary_first",
        "result_generation_identity": loaded["manifest"]["result_generation_identity"],
        "methods": {},
        "lookup_keys_by_symbol": {},
        "reverse_edges": {},
        "target_apis": [
            {
                "coord": item["coord"],
                "api_name": item["api"],
                "api_signature": item["api_signature"],
                "symbol_kind": item["symbol_kind"],
            }
            for item in items
        ],
        "stats": {
            "methods_indexed": 0,
            "reverse_edge_keys": 0,
            "target_apis_indexed": len(items),
            "query_path_source": "evidence/call_chain/alerts.csv",
        },
    }
    _atomic_json(
        Path(report_dir).resolve() / ".runtime" / "indexes" / "s5_query_index.json",
        query_index,
    )
    write_coverage_report(Path(report_dir).resolve())
    return {"phase": "step5", "api_count": len(items), "output_dir": str(output)}


def publish_step6(
    report_dir: str | Path,
    output_findings: str | Path,
    output_report: str | Path,
) -> dict[str, Any]:
    """Render binary-first facts through the established human report contract."""
    report_root = Path(report_dir).resolve()
    loaded = load_validated_generation(report_root)
    step5_summary_path = report_root / "evidence" / "call_chain" / "summary.json"
    step5_summary = _load_json(step5_summary_path)
    if step5_summary.get("result_generation_identity") != loaded["manifest"].get(
        "result_generation_identity"
    ):
        raise BinaryReportError(
            "BINARY_STEP5_GENERATION_MISMATCH", str(step5_summary_path)
        )

    findings = s6_report.collect_findings(report_root)
    findings["schema"] = "java-upgrade-analyzer.binary-findings.v2"
    findings["authority"] = "binary_first"
    findings["result_generation_identity"] = (
        loaded["manifest"]["result_generation_identity"]
    )
    findings["analysis_context_identity"] = (
        loaded["manifest"]["analysis_context_identity"]
    )
    findings["source_usage"] = _source_usage_view(loaded)
    findings["resource_impacts"] = [
        _resource_activation_item(item)
        for item in loaded["formal"].get("resource_activation_results") or ()
    ]
    findings["binary_dimensions"] = {
        "reachability_status": {
            state: sum(
                item.get("reachability_status") == state
                for item in (loaded["formal"].get("by_api") or ())
            )
            for state in (
                "reachable", "uncertain",
                "not_found_in_static_analysis", "not_analyzed",
            )
        },
        "impact_conclusion": {
            "probable_impact": sum(
                item.get("impact_conclusion") == "probable_impact"
                for item in (loaded["formal"].get("by_api") or ())
            ),
            "inconclusive": sum(
                item.get("impact_conclusion") != "probable_impact"
                for item in (loaded["formal"].get("by_api") or ())
            ),
        },
        "runtime_verification_status": "not_executed",
    }
    findings.setdefault("artifacts", {})
    findings["artifacts"].update({
        "binary_generation": str(loaded["generation"]),
        "binary_formal_results": str(
            loaded["generation"] / "binary_formal_results.json"
        ),
        "binary_candidate_results": str(
            loaded["generation"] / "binary_candidate_results.json"
        ),
        "binary_change_review_md": "evidence/api_changes/review.md",
        "source_analysis_review_md": "evidence/source_analysis/review.md",
    })

    report_path = Path(output_report).resolve()
    findings_path = Path(output_findings).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    s6_report.cleanup_legacy_s6_detail_artifacts(report_root)
    findings["artifacts"].update(
        s6_report.write_changed_api_split_artifacts(report_root)
    )
    findings["artifacts"]["analysis_scope_md"] = (
        s6_report.write_analysis_scope_artifact(report_root, findings)
    )
    diagnostic_detail = s6_report.write_diagnostic_detail_artifact(
        report_root, findings
    )
    if diagnostic_detail:
        findings["artifacts"]["diagnostic_detail_md"] = diagnostic_detail
    primary_artifacts, _api_model, _dependency_model = (
        s6_report.write_primary_report_artifacts(report_root, findings)
    )
    findings["artifacts"].update(primary_artifacts)
    _atomic_json(findings_path, findings)
    _atomic_text(report_path, s6_report.generate_report(findings))
    return {
        "phase": "step6",
        "api_count": int(findings.get("call_chain_target_count") or 0),
        "report": str(report_path),
    }

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Publish validated binary generation reports")
    parser.add_argument("--phase", choices=("step4", "step5", "step6"), required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--output-findings", default="")
    parser.add_argument("--output-report", default="")
    parser.add_argument("--selected-coord", action="append", default=[])
    parser.add_argument("--selected-name", action="append", default=[])
    args = parser.parse_args(argv)
    if args.phase == "step4":
        if not args.output_dir:
            parser.error("--output-dir is required for step4")
        result = publish_step4(args.report_dir, args.output_dir)
    elif args.phase == "step5":
        if not args.output_dir:
            parser.error("--output-dir is required for step5")
        result = publish_step5(
            args.report_dir,
            args.output_dir,
            selected_coords=tuple(args.selected_coord),
            selected_names=tuple(args.selected_name),
        )
    else:
        if not args.output_findings or not args.output_report:
            parser.error("--output-findings and --output-report are required for step6")
        result = publish_step6(args.report_dir, args.output_findings, args.output_report)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
