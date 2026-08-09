#!/usr/bin/env python3
"""Materialize Step4/5/6 compatibility views from one validated binary generation.

The files written here are projections for existing consumers.  They never
become inputs to the binary graph and deliberately preserve the v2 four-axis
state instead of translating it to legacy confirmed-impact/no-impact states.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Mapping

from binary_first_contract import BinaryFirstContractError
from csv_io import open_csv_write
from path_runtime import make_short_temp_dir
from s4_contract import ALL_CHANGED_APIS_FIELDS


ENGINE_DESCRIPTOR_RELATIVE_PATH = Path(".runtime/state/engine_generation.json")
BINARY_OUTPUT_RELATIVE_PATH = Path(".runtime/binary_authority")


class BinaryCompatibilityOutputError(BinaryFirstContractError):
    pass


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BinaryCompatibilityOutputError(
            "BINARY_COMPAT_JSON_INVALID", f"{path}: {error}"
        ) from error
    if not isinstance(value, dict):
        raise BinaryCompatibilityOutputError(
            "BINARY_COMPAT_JSON_INVALID", f"{path}: root must be an object"
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


def write_engine_descriptor(report_dir: str | Path, payload: Mapping[str, Any]) -> Path:
    report = Path(report_dir).resolve()
    value = {
        "schema": "java-upgrade-analyzer.engine-generation.v1",
        **dict(payload),
    }
    path = report / ENGINE_DESCRIPTOR_RELATIVE_PATH
    _atomic_json(path, value)
    return path


def _generation_within_root(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise BinaryCompatibilityOutputError(
            "BINARY_ACTIVE_GENERATION_PATH_ESCAPE", str(candidate)
        ) from error
    return candidate


def load_validated_generation(report_dir: str | Path) -> dict[str, Any]:
    report = Path(report_dir).resolve()
    engine_descriptor_path = report / ENGINE_DESCRIPTOR_RELATIVE_PATH
    engine = _load_json(engine_descriptor_path)
    if engine.get("authoritative_engine") != "binary":
        raise BinaryCompatibilityOutputError(
            "BINARY_ENGINE_DESCRIPTOR_NOT_AUTHORITATIVE",
            str(engine.get("authoritative_engine") or "missing"),
        )
    root = report / BINARY_OUTPUT_RELATIVE_PATH
    active = _load_json(root / "active_binary_generation.json")
    generation_identity = str(active.get("result_generation_identity") or "")
    if generation_identity != str(engine.get("result_generation_identity") or ""):
        raise BinaryCompatibilityOutputError(
            "BINARY_ENGINE_ACTIVE_GENERATION_MISMATCH", generation_identity
        )
    generation = _generation_within_root(root, str(active.get("generation_directory") or ""))
    if generation.name != generation_identity or not generation.is_dir():
        raise BinaryCompatibilityOutputError(
            "BINARY_ACTIVE_GENERATION_INVALID", str(generation)
        )
    manifest = _load_json(generation / "result_generation.json")
    if (
        manifest.get("result_generation_identity") != generation_identity
        or manifest.get("analysis_context_identity") != engine.get("analysis_context_identity")
        or manifest.get("engine_mode") not in {
            "binary_strict", "binary_with_legacy_fallback"
        }
    ):
        raise BinaryCompatibilityOutputError(
            "BINARY_GENERATION_MANIFEST_MISMATCH", generation_identity
        )
    for name, expected in (manifest.get("sidecar_content_identities") or {}).items():
        if Path(str(name)).name != str(name):
            raise BinaryCompatibilityOutputError(
                "BINARY_GENERATION_SIDECAR_NAME_INVALID", str(name)
            )
        path = generation / str(name)
        if not path.is_file() or _sha256(path) != expected:
            raise BinaryCompatibilityOutputError(
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
        raise BinaryCompatibilityOutputError(
            "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID", str(validation_path)
        )
    return {
        "report_dir": report,
        "engine": engine,
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


def _legacy_change_type(decision: Mapping[str, Any]) -> str:
    change = str((decision.get("fact_scope") or {}).get("member_change_kind") or "")
    return {
        "removed": "REMOVED",
        "added": "BEHAVIOR_CHANGED",
        "descriptor_changed": "SIGNATURE_CHANGED",
        "access_changed": "ACCESS_REDUCED",
        "constant_value_changed": "CONSTANT_VALUE_CHANGED",
    }.get(change, "BEHAVIOR_CHANGED")


def materialize_step4(report_dir: str | Path, output_dir: str | Path) -> dict[str, Any]:
    loaded = load_validated_generation(report_dir)
    decisions = list(loaded["decisions"].get("authoritative_change_facts") or ())
    targetable_decision_ids = {
        str(item.get("decision_identity") or "")
        for item in loaded["projections"].get("authoritative_projection_assessments") or ()
        if item.get("analysis_projection_status") == "targetable"
    }
    generation = loaded["generation"]
    rows = []
    for decision in decisions:
        # This compatibility CSV is an API inventory.  Runtime-effective
        # resource/topology facts without a formal API projection remain in
        # binary_decisions.json and the summary; inventing a placeholder API
        # here would corrupt both selection and downstream counts.
        if str(decision.get("decision_identity") or "") not in targetable_decision_ids:
            continue
        scope = decision.get("fact_scope") or {}
        api_name, simple, descriptor = _api_display(scope)
        member_kind = str(scope.get("member_kind") or "")
        symbol_kind = member_kind if member_kind in {
            "method", "field", "constructor", "class"
        } else "class"
        rows.append({
            "conclusion": "二进制运行时有效变化",
            "change_summary": str(scope.get("member_change_kind") or decision.get("fact_kind") or "changed"),
            "review_reason": str(decision.get("reason_code") or "RUNTIME_EFFECTIVE_CHANGE_CONFIRMED"),
            "coord": str(scope.get("coord") or "binary-runtime-scope"),
            "old_version": "binary-base",
            "new_version": "binary-current",
            "change_type": _legacy_change_type(decision),
            "api_name": api_name,
            "api_simple": simple,
            "symbol_kind": symbol_kind,
            "api_signature": descriptor,
            "confirmed": "true",
            "severity": "P1",
            "source": "jar_bytecode",
            "binary_compatible": "unknown",
            "source_compatible": "unknown",
            "compatibility_flags": str(decision.get("reason_code") or ""),
            "reason_code": str(decision.get("reason_code") or ""),
            "data_contract_evidence": "",
            "evidence_path": str(generation / "binary_decisions.json"),
            "old_value": "",
            "new_value": "",
            "field_descriptor": descriptor if scope.get("member_kind") == "field" else "",
            "old_field_has_constant_value": "",
            "constant_field_evidence_json": "",
        })

    output = Path(output_dir).resolve()
    def write(stage: Path) -> None:
        with open_csv_write(stage / "all_changed_apis.csv") as handle:
            writer = csv.DictWriter(handle, fieldnames=ALL_CHANGED_APIS_FIELDS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        dependencies: dict[str, int] = {}
        for row in rows:
            dependencies[row["coord"]] = dependencies.get(row["coord"], 0) + 1
        with open_csv_write(stage / "changed_dependencies.csv") as handle:
            writer = csv.DictWriter(handle, fieldnames=("coord", "api_count", "engine_mode", "generation_identity"))
            writer.writeheader()
            for coord, count in sorted(dependencies.items()):
                writer.writerow({
                    "coord": coord, "api_count": count,
                    "engine_mode": loaded["manifest"]["engine_mode"],
                    "generation_identity": loaded["manifest"]["result_generation_identity"],
                })
        (stage / "changed_dependencies.md").write_text(
            "# Binary-first 变化依赖\n\n" + "\n".join(
                f"- `{coord}`：{count} 个运行时有效变化" for coord, count in sorted(dependencies.items())
            ) + "\n",
            encoding="utf-8",
        )
        shutil.copy2(generation / "binary_decisions.json", stage / "binary_decisions.json")
        shutil.copy2(generation / "binary_projections.json", stage / "binary_projections.json")
        shutil.copy2(generation / "binary_pairings.json", stage / "binary_pairings.json")
        _atomic_json(stage / "binary_step4_summary.json", {
            "schema": "java-upgrade-analyzer.binary-step4-compat.v1",
            "result_generation_identity": loaded["manifest"]["result_generation_identity"],
            "analysis_context_identity": loaded["manifest"]["analysis_context_identity"],
            "authoritative_change_fact_count": len(decisions),
            "targetable_api_change_count": len(rows),
            "confirmed_unprojectable_fact_count": len(
                loaded["projections"].get("confirmed_unprojectable_facts") or ()
            ),
            "diagnostic_candidate_fact_count": len(
                loaded["decisions"].get("diagnostic_candidate_facts") or ()
            ),
            "excluded_decision_count": len(loaded["decisions"].get("excluded_decisions") or ()),
            "source_role": "optional_overlay_only",
        })
    _stage_directory(output, write)
    return {"phase": "step4", "row_count": len(rows), "output_dir": str(output)}


def _result_item(api: Mapping[str, Any]) -> dict[str, Any]:
    owner = str(api.get("display_owner") or "").replace("/", ".")
    member = str(api.get("display_member") or "")
    name = owner if not member or member == "<class>" else f"{owner}.{member}"
    return {
        "api": name,
        "reported_api_identity": api.get("reported_api_identity"),
        "reachability_status": api.get("reachability_status"),
        "impact_conclusion": api.get("impact_conclusion"),
        "static_linkage_status": api.get("static_linkage_status"),
        "runtime_verification_status": api.get("runtime_verification_status"),
        "path_set_complete": bool(api.get("path_set_complete")),
        "exact_path_exists": bool(api.get("exact_path_exists")),
        "possible_path_exists": bool(api.get("possible_path_exists")),
        "reason": "binary runtime-effective projection",
    }


def materialize_step5(report_dir: str | Path, output_dir: str | Path) -> dict[str, Any]:
    loaded = load_validated_generation(report_dir)
    by_api = list(loaded["formal"].get("by_api") or ())
    items = [_result_item(item) for item in by_api]
    by_state = {
        state: [item for item in items if item["reachability_status"] == state]
        for state in ("reachable", "uncertain", "not_found_in_static_analysis", "not_analyzed")
    }
    binary_summary = loaded["summary"]
    summary = {
        "schema": "java-upgrade-analyzer.binary-step5-summary.v1",
        "status": "complete" if binary_summary.get("trace_coverage_status") == "complete" else "completed_with_limits",
        "engine_mode": loaded["manifest"]["engine_mode"],
        "result_generation_identity": loaded["manifest"]["result_generation_identity"],
        "analysis_context_identity": loaded["manifest"]["analysis_context_identity"],
        "total_apis": len(items),
        "reachable": len(by_state["reachable"]),
        "uncertain": len(by_state["uncertain"]),
        "not_found_in_static_analysis": len(by_state["not_found_in_static_analysis"]),
        "not_analyzed": len(by_state["not_analyzed"]),
        "not_impacted": 0,
        "reachable_apis": by_state["reachable"],
        "uncertain_apis": by_state["uncertain"],
        "not_found_apis": by_state["not_found_in_static_analysis"],
        "not_analyzed_apis": by_state["not_analyzed"],
        "not_impacted_apis": [],
        "formal_dimensions": {
            "reachability_status": ["reachable", "uncertain", "not_found_in_static_analysis", "not_analyzed"],
            "impact_conclusion": ["probable_impact", "inconclusive"],
            "runtime_verification_status": ["required_not_executed", "undetermined"],
                "static_linkage_status": [
                    "compatible_or_not_applicable", "incompatible_if_executed", "undetermined"
                ],
        },
        "quality_gate": {
            "probable_impact": int(binary_summary.get("probable_impact_total") or 0),
            "inconclusive": len(by_state["uncertain"]) + len(by_state["not_analyzed"]),
            "confirmed_impact": 0,
            "confirmed_no_impact": 0,
        },
        "user_conclusion_summary": {
            "probable_impact": int(binary_summary.get("probable_impact_total") or 0),
            "inconclusive": len(by_state["uncertain"]) + len(by_state["not_analyzed"]),
            "confirmed_impact": 0,
            "confirmed_no_impact": 0,
        },
        "candidate_diagnostics": {
            "fact_count": int(binary_summary.get("diagnostic_candidate_fact_count") or 0),
            "trace_result_count": int(binary_summary.get("candidate_trace_result_count") or 0),
            "included_in_formal_totals": False,
        },
        "coverage": loaded["coverage"],
    }
    output = Path(output_dir).resolve()
    def write(stage: Path) -> None:
        _atomic_json(stage / "summary.json", summary)
        shutil.copy2(loaded["generation"] / "binary_formal_results.json", stage / "binary_formal_results.json")
        shutil.copy2(loaded["generation"] / "binary_candidate_results.json", stage / "binary_candidate_results.json")
        with open_csv_write(stage / "alerts.csv") as handle:
            fields = (
                "api", "reachability_status", "impact_conclusion", "static_linkage_status",
                "runtime_verification_status", "path_set_complete",
                "exact_path_exists", "possible_path_exists", "reported_api_identity",
            )
            writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(items)
        by_api_dir = stage / "by_api"
        by_api_dir.mkdir()
        for index, item in enumerate(items):
            _atomic_json(by_api_dir / f"{index:06d}.json", item)
    _stage_directory(output, write)
    return {"phase": "step5", "api_count": len(items), "output_dir": str(output)}


def materialize_step6(
    report_dir: str | Path,
    output_findings: str | Path,
    output_report: str | Path,
) -> dict[str, Any]:
    loaded = load_validated_generation(report_dir)
    by_api = list(loaded["formal"].get("by_api") or ())
    rows = [_result_item(item) for item in by_api]
    state = lambda value: [item for item in rows if item["reachability_status"] == value]
    coverage_complete = (
        loaded["summary"].get("decision_coverage_status") == "complete"
        and loaded["summary"].get("trace_coverage_status") == "complete"
    )
    findings = {
        "schema": "java-upgrade-analyzer.binary-findings.v1",
        "engine_mode": loaded["manifest"]["engine_mode"],
        "result_generation_identity": loaded["manifest"]["result_generation_identity"],
        "analysis_context_identity": loaded["manifest"]["analysis_context_identity"],
        "p0": [], "p1": [], "p2": [],
        "probable_impact": [item for item in rows if item["impact_conclusion"] == "probable_impact"],
        "uncertain": state("uncertain"),
        "not_analyzed": state("not_analyzed"),
        "not_found": state("not_found_in_static_analysis"),
        "needs_input": [],
        "diagnostics": list(loaded["candidate"].get("results") or ()),
        "coverage": {
            "overall_status": "complete" if coverage_complete else "partial",
            "binary": loaded["coverage"],
        },
        "analysis_scope": {
            "mode": "full",
            "validation_status": "passed",
            "total_api_count": len(rows),
            "analyzed_api_count": len(rows),
        },
        "formal_state_contract": {
            "confirmed_impact_emitted": False,
            "confirmed_no_impact_emitted": False,
            "runtime_verification_executed_by_system": False,
        },
        "artifacts": {
            "binary_generation": str(loaded["generation"]),
            "binary_formal_results": str(loaded["generation"] / "binary_formal_results.json"),
            "binary_candidate_results": str(loaded["generation"] / "binary_candidate_results.json"),
        },
    }
    findings_path = Path(output_findings).resolve()
    report_path = Path(output_report).resolve()
    _atomic_json(findings_path, findings)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Java 升级二进制优先分析报告", "",
        f"- Generation：`{loaded['manifest']['result_generation_identity']}`",
        f"- Analysis context：`{loaded['manifest']['analysis_context_identity']}`",
        f"- 独立验证：`{loaded['validation']['status']}`",
        f"- 裁决覆盖：`{loaded['summary'].get('decision_coverage_status')}`",
        f"- 触达覆盖：`{loaded['summary'].get('trace_coverage_status')}`", "",
        "## 正式四维结果", "",
        f"- reachable：{len(state('reachable'))}",
        f"- uncertain：{len(state('uncertain'))}",
        f"- not_found_in_static_analysis：{len(state('not_found_in_static_analysis'))}",
        f"- not_analyzed：{len(state('not_analyzed'))}",
        f"- probable_impact：{len(findings['probable_impact'])}",
        "- runtime verification：系统未执行，正式结果仅为 required_not_executed/undetermined", "",
        "`not_found_in_static_analysis` 只表示在当前完整静态范围内未发现路径，不表示已确认无影响。", "",
        "## 诊断候选", "",
        f"候选事实与正式变化互斥；本代候选触达结果 {len(findings['diagnostics'])} 项。", "",
        "## 明细", "",
    ]
    for item in rows:
        lines.append(
            f"- `{item['api']}`：{item['reachability_status']} / "
            f"{item['static_linkage_status']} / {item['impact_conclusion']} / "
            f"{item['runtime_verification_status']}"
        )
    _atomic_text(report_path, "\n".join(lines) + "\n")
    return {"phase": "step6", "api_count": len(rows), "report": str(report_path)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Materialize validated binary generation outputs")
    parser.add_argument("--phase", choices=("step4", "step5", "step6"), required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--output-findings", default="")
    parser.add_argument("--output-report", default="")
    args = parser.parse_args(argv)
    if args.phase == "step4":
        if not args.output_dir:
            parser.error("--output-dir is required for step4")
        result = materialize_step4(args.report_dir, args.output_dir)
    elif args.phase == "step5":
        if not args.output_dir:
            parser.error("--output-dir is required for step5")
        result = materialize_step5(args.report_dir, args.output_dir)
    else:
        if not args.output_findings or not args.output_report:
            parser.error("--output-findings and --output-report are required for step6")
        result = materialize_step6(args.report_dir, args.output_findings, args.output_report)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
