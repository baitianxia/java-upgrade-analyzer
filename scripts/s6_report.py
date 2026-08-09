#!/usr/bin/env python3
"""
s6_report.py — Step 6：汇总报告

读取所有前序步骤的产出，生成结构化事实报告和证据边界。

用法：
  python s6_report.py \
    --report-dir .upgrade-report \
    --output-findings .upgrade-report/.runtime/findings/s6_findings.json \
    --output-report   .upgrade-report/deliverables/report.md
"""

import argparse, csv, hashlib, json, os, re, sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent))
from compat import open_text, write_text
from csv_io import open_csv_read, open_csv_write
from diagnostic_contract import canonical_reason_code
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
    RUNTIME_CACHE_DIRNAME,
    RUNTIME_COVERAGE_DIRNAME,
    RUNTIME_DIRNAME,
    UNCERTAINTY_KIND_ANALYSIS_LIMITATION,
    UNCERTAINTY_KIND_CANDIDATE_EVIDENCE,
)
from reason_guidance import (
    REASON_GUIDANCE_SCHEMA,
    build_catalog_guidance,
    build_diagnostic_guidance_from_summary,
    guidance_for_reason_code,
)
from signature_utils import (
    normalize_signature_for_identity,
    signatures_match_identity,
)

S6_INLINE_LIMIT = 20
S6_MAIN_RESULT_LIMIT = 12
S6_MAIN_DEPENDENCY_LIMIT = 20
S6_MAIN_INCOMPLETE_LIMIT = 10
S6_MAIN_PATH_DETAIL_LIMIT = 3
S6_MAIN_DIAGNOSTIC_LIMIT = 5
S6_CONCENTRATION_LIMIT = 5
S6_NOT_FOUND_INLINE_LIMIT = S6_INLINE_LIMIT
S6_DETAIL_MD_FULL_LIMIT = 200
S6_DETAIL_MD_SAMPLE_LIMIT = 50
S6_DETAIL_MD_DEP_SUMMARY_LIMIT = 50
S6_CHANGED_API_SPLIT_ROWS = 500

UNCERTAIN_CANDIDATE_CONCLUSION = "结论未确定（存在候选证据）"
UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION = "结论未确定（静态分析能力边界）"


def _uncertainty_kind(item):
    """Read the Step5 evidence subtype, with a safe legacy-artifact fallback."""
    item = item or {}
    kind = str(item.get("uncertainty_kind") or "").strip()
    if kind in {
        UNCERTAINTY_KIND_CANDIDATE_EVIDENCE,
        UNCERTAINTY_KIND_ANALYSIS_LIMITATION,
    }:
        return kind
    if any(str(path or "").strip() for path in (item.get("call_paths") or [])):
        return UNCERTAINTY_KIND_CANDIDATE_EVIDENCE
    if _has_uncertain_evidence_items(item.get("evidence_paths") or []):
        return UNCERTAINTY_KIND_CANDIDATE_EVIDENCE
    for detail in item.get("path_details") or []:
        if not isinstance(detail, dict):
            continue
        if (
            str(detail.get("path_text") or "").strip()
            or _has_uncertain_evidence_items([detail.get("evidence") or []])
        ):
            return UNCERTAINTY_KIND_CANDIDATE_EVIDENCE
    return UNCERTAINTY_KIND_ANALYSIS_LIMITATION


def _has_uncertain_evidence_items(evidence_paths):
    for path in evidence_paths or []:
        if isinstance(path, dict):
            if any(value not in ('', None, [], {}) for value in path.values()):
                return True
            continue
        for evidence in path or []:
            if isinstance(evidence, dict):
                if any(value not in ('', None, [], {}) for value in evidence.values()):
                    return True
            elif str(evidence or '').strip():
                return True
    return False


def _uncertain_conclusion(item):
    if _uncertainty_kind(item) == UNCERTAINTY_KIND_ANALYSIS_LIMITATION:
        return UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION
    return UNCERTAIN_CANDIDATE_CONCLUSION


def _uncertainty_counts(items):
    counts = defaultdict(int)
    for item in items or []:
        counts[_uncertainty_kind(item)] += 1
    return counts


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


def _step5_selection_path(report_dir):
    return _runtime_dir(report_dir, RUNTIME_CACHE_DIRNAME) / "step5_selection.json"


def _step5_summary_coverage_fallback(call_summary):
    """Build a conservative coverage view when formal coverage.json is absent.

    The orchestrated pipeline writes .runtime/coverage/coverage.json. Some
    direct Step5/Step6 uses only have evidence/call_chain/summary.json. In that
    case the report should not show an unhelpful "unknown" if Step5 already
    emitted graph/coverage signals in meta.graph_stats.
    """
    def mapping(value):
        return value if isinstance(value, dict) else {}

    def values(value):
        return list(value) if isinstance(value, (list, tuple, set)) else []

    def integer(value):
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    meta = mapping((call_summary or {}).get('meta'))
    graph_stats = mapping(meta.get('graph_stats'))
    if not graph_stats:
        return {}

    components = []
    critical = []
    total_apis = integer((call_summary or {}).get('total_apis'))
    all_symbols_preserved = bool(
        total_apis
        and integer((call_summary or {}).get('not_impacted')) == total_apis
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
    truncation_reasons = values(graph_stats.get('truncation_reasons'))
    business_reason_codes = list(truncation_reasons)
    edge_cap_hits = graph_stats.get('edge_cap_hits') or 0
    if edge_cap_hits:
        business_reason_codes.append('edge_cap_hits')
    parser_fallback_reasons = mapping(
        graph_stats.get('parser_fallback_reasons')
    )
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

    source_alignment = mapping(graph_stats.get('source_artifact_alignment'))
    if source_alignment:
        add_component(
            'source_artifact_alignment',
            'not_applicable' if all_symbols_preserved else (source_alignment.get('status') or 'unknown'),
            source_alignment.get('reason_codes') or [],
            [source_alignment.get('artifact_path') or source_alignment.get('git_root') or ''],
        )

    artifact_bytecode = mapping(graph_stats.get('artifact_bytecode'))
    if artifact_bytecode:
        add_component(
            'artifact_bytecode_dependencies',
            artifact_bytecode.get('status') or 'unknown',
            artifact_bytecode.get('reason_codes') or [],
        )

    business_bytecode = mapping(graph_stats.get('business_bytecode'))
    if business_bytecode:
        add_component(
            'business_bytecode_graph',
            'not_applicable' if all_symbols_preserved else (business_bytecode.get('status') or 'unknown'),
            business_bytecode.get('failures') or [],
            critical_if_incomplete=False,
        )

    indirect_usage = mapping(graph_stats.get('indirect_usage'))
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
    "confirmed": {
        "title": "已确认影响分布与明细索引",
        "conclusion": "已确认影响",
        "csv": "s6_confirmed_impact_apis.csv",
        "md": "s6_confirmed_impact_apis.md",
        "summary_key": "",
        "note": "每一项均有当前系统入口或最终制品到变更 API 的已确认触达证据。",
    },
    "not_impacted": {
        "title": "已确认不受影响清单",
        "conclusion": "已确认不受影响",
        "csv": "s6_not_impacted_apis.csv",
        "md": "s6_not_impacted_apis.md",
        "summary_key": "",
        "note": "最终制品证据证明这些变更 API 仍由其他运行时 JAR 以完全相同的 class 字节码提供。",
    },
    "uncertain": {
        "title": "结论未确定清单",
        "conclusion": "",
        "csv": "s6_uncertain_apis.csv",
        "md": "s6_uncertain_apis.md",
        "summary_key": "uncertain_reason_summary",
        "show_priority": True,
        "note": (
            "包含已有候选证据但链路未确认的项目，以及因静态分析能力边界"
            "无法取得候选调用证据的项目；两类证据状态在明细中分别标注。"
        ),
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
        "title": "输入不足且结论未确定清单",
        "conclusion": "输入不足，结论未确定",
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


class ArtifactContentError(ValueError):
    """An input exists and parses, but does not satisfy its evidence contract."""


class JSONRootTypeError(ArtifactContentError):
    """A JSON evidence file has a non-object root."""


def _record_diagnostic(diagnostics, *, artifact, stage, path, error):
    if diagnostics is None:
        return
    diagnostics.append({
        "artifact": str(artifact or Path(path).name),
        "stage": stage,
        "path": str(path),
        "error_type": type(error).__name__,
        "message": str(error),
    })


def load_json(path, *, diagnostics=None, artifact="", required=False):
    if not os.path.exists(path):
        if required:
            _record_diagnostic(
                diagnostics,
                artifact=artifact,
                stage="json_missing",
                path=path,
                error=FileNotFoundError(str(path)),
            )
        return {}
    try:
        with open_text(path) as f:
            payload = json.load(f)
        if not isinstance(payload, dict):
            _record_diagnostic(
                diagnostics,
                artifact=artifact,
                stage="json_contract",
                path=path,
                error=JSONRootTypeError(
                    f"expected object root, got {type(payload).__name__}"
                ),
            )
            return {}
        return payload
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _record_diagnostic(
            diagnostics, artifact=artifact, stage="json_load", path=path, error=exc
        )
        return {}


def _normalize_csv_dict_row(row):
    normalized = {}
    for key, value in (row or {}).items():
        if key is None or not isinstance(key, str):
            raise ArtifactContentError(
                "CSV row contains more values than the header"
            )
        if value is not None and not isinstance(value, str):
            raise ArtifactContentError(
                "CSV row contains a non-text value"
            )
        normalized[key] = (value or "").strip()
    return normalized


def load_csv(path, *, diagnostics=None, artifact="", required=False):
    if not os.path.exists(path):
        if required:
            _record_diagnostic(
                diagnostics,
                artifact=artifact,
                stage="csv_missing",
                path=path,
                error=FileNotFoundError(str(path)),
            )
        return []
    rows = []
    try:
        with open_csv_read(path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row:
                    rows.append(_normalize_csv_dict_row(row))
    except (
        OSError,
        UnicodeError,
        csv.Error,
        ArtifactContentError,
    ) as exc:
        rows.clear()
        _record_diagnostic(
            diagnostics, artifact=artifact, stage="csv_load", path=path, error=exc
        )
    return rows


def iter_csv_rows(path, *, diagnostics=None, artifact="", required=False):
    """Yield normalized CSV rows without retaining the full file in memory."""
    if not os.path.exists(path):
        if required:
            _record_diagnostic(
                diagnostics,
                artifact=artifact,
                stage="csv_missing",
                path=path,
                error=FileNotFoundError(str(path)),
            )
        return
    try:
        with open_csv_read(path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row:
                    yield _normalize_csv_dict_row(row)
    except (
        OSError,
        UnicodeError,
        csv.Error,
        ArtifactContentError,
    ) as exc:
        _record_diagnostic(
            diagnostics, artifact=artifact, stage="csv_stream", path=path, error=exc
        )


def _record_content_diagnostic(
    diagnostics, *, artifact, stage, path, message
):
    if any(
        str(item.get("artifact") or "") == str(artifact)
        and str(item.get("stage") or "") == str(stage)
        for item in (diagnostics or [])
    ):
        return
    _record_diagnostic(
        diagnostics,
        artifact=artifact,
        stage=stage,
        path=path,
        error=ArtifactContentError(message),
    )


def _artifact_has_diagnostic(diagnostics, artifact):
    return any(
        str(item.get("artifact") or "") == str(artifact)
        for item in (diagnostics or [])
    )


def _strict_non_negative_int(value):
    return value if type(value) is int and value >= 0 else None


def _valid_origin_step(value, fallback=""):
    normalized = str(value or "").strip().lower()
    if re.fullmatch(r"step[1-6]", normalized):
        return normalized
    normalized_fallback = str(fallback or "").strip().lower()
    if re.fullmatch(r"step[1-6]", normalized_fallback):
        return normalized_fallback
    return ""


def _invalidate_analysis_scope(scope, reason):
    scope["mode"] = ""
    scope["validation_status"] = "invalid"
    scope["invalid_reason"] = str(reason or "").strip()
    for field in (
        "available_dependency_count",
        "included_dependency_count",
        "total_api_count",
        "analyzed_api_count",
    ):
        scope[field] = 0


def _changed_api_diagnostic_invalidates_scope(diagnostics):
    return any(
        str(item.get("artifact") or "") == "changed_apis"
        and str(item.get("stage") or "") in {
            "csv_missing",
            "csv_load",
            "csv_contract",
            "csv_consistency",
            "identity_consistency",
        }
        for item in diagnostics or []
    )


def _artifact_has_fatal_csv_diagnostic(diagnostics, artifact):
    return any(
        str(item.get("artifact") or "") == str(artifact)
        and str(item.get("stage") or "") in {
            "csv_missing",
            "csv_load",
            "csv_stream",
            "csv_contract",
        }
        for item in diagnostics or []
    )


def _validate_csv_contract(
    path,
    *,
    diagnostics,
    artifact,
    required_column_groups,
    require_data=False,
):
    if not Path(path).is_file():
        return
    try:
        with open_csv_read(path) as source:
            reader = csv.reader(source)
            header = [str(value or "").strip() for value in (next(reader, []) or [])]
            first_data_row = next(
                (row for row in reader if any(str(value or "").strip() for value in row)),
                None,
            )
    except (OSError, UnicodeError, csv.Error):
        return
    if not header:
        _record_content_diagnostic(
            diagnostics,
            artifact=artifact,
            stage="csv_contract",
            path=path,
            message="CSV header is missing",
        )
        return
    header_set = set(header)
    missing_groups = [
        sorted(group)
        for group in required_column_groups
        if not header_set.intersection(group)
    ]
    if missing_groups:
        _record_content_diagnostic(
            diagnostics,
            artifact=artifact,
            stage="csv_contract",
            path=path,
            message=f"required columns missing: {missing_groups}",
        )
        return
    if require_data and first_data_row is None:
        _record_content_diagnostic(
            diagnostics,
            artifact=artifact,
            stage="csv_contract",
            path=path,
            message="CSV has no data rows for a non-empty analysis target set",
        )


_ALERT_PATH_STATUSES = {
    "reachable",
    "uncertain",
    "not_impacted",
    "not_found_in_static_analysis",
    "not_reachable",
    "not_analyzed",
}


def _alert_target_matches_changed_symbol(target, row):
    target = re.sub(
        r"^(?:变更\s*API|changed\s*api)\s*[:：]\s*",
        "",
        str(target or "").strip(),
        flags=re.IGNORECASE,
    )
    changed_symbol = str(row.get("changed_symbol") or "").strip()
    if not target or not changed_symbol:
        return False

    def split_member(value):
        text = str(value or "").strip()
        signature_start = text.find("(")
        if signature_start < 0 or not text.endswith(")"):
            return text, ""
        return text[:signature_start].strip(), text[signature_start:].strip()

    target_base, target_signature = split_member(target)
    changed_base, embedded_signature = split_member(changed_symbol)
    if target_base != changed_base:
        return False
    expected_signature = str(
        row.get("api_signature") or embedded_signature or ""
    ).strip()
    # Older evidence may omit a signature from the rendered chain node. When
    # both sides do record one, however, a different overload is not evidence
    # for the changed API.
    if target_signature and expected_signature:
        return signatures_match_identity(
            target_signature,
            expected_signature,
        )
    return True


def _alert_path_entry_matches_business_entry(path_entry, row):
    path_entry = re.sub(
        r"^(?:业务入口|调用起点|业务制品|business\s*(?:entry|artifact)|chain\s*entry)\s*[:：]\s*",
        "",
        str(path_entry or "").strip(),
        flags=re.IGNORECASE,
    )
    business_entry = str(row.get("business_entry") or "").strip()
    if not path_entry or not business_entry:
        return False

    def split_member(value):
        text = str(value or "").strip()
        signature_start = text.find("(")
        if signature_start < 0 or not text.endswith(")"):
            return text, ""
        return text[:signature_start].strip(), text[signature_start:].strip()

    path_base, path_signature = split_member(path_entry)
    business_base, business_signature = split_member(business_entry)
    if path_base != business_base:
        return False
    if path_signature and business_signature:
        return signatures_match_identity(
            path_signature,
            business_signature,
        )
    return True


def _alert_row_has_reachable_path_evidence(row):
    path_text = str(row.get("path_text") or "").strip()
    path_nodes = _split_csv_chain_nodes(path_text)
    if (
        len(path_nodes) >= 2
        and _alert_path_entry_matches_business_entry(path_nodes[0], row)
        and _alert_target_matches_changed_symbol(path_nodes[-1], row)
    ):
        return True
    # A declared runtime entrypoint may itself be the changed API.  This is a
    # valid zero-hop executable path, not missing evidence; both identities
    # still have to match exactly.
    if (
        len(path_nodes) == 1
        and _alert_path_entry_matches_business_entry(path_nodes[0], row)
        and _alert_target_matches_changed_symbol(path_nodes[0], row)
    ):
        return True
    chain_entry = str(row.get("chain_entry") or "").strip()
    chain_target = str(row.get("chain_target") or "").strip()
    try:
        chain_hops = int(str(row.get("chain_hop_count") or "0"))
    except ValueError:
        chain_hops = 0
    if (
        chain_entry
        and chain_target
        and chain_hops >= 0
        and _alert_path_entry_matches_business_entry(chain_entry, row)
        and _alert_target_matches_changed_symbol(chain_target, row)
    ):
        return True
    return False


def _alert_row_has_preserved_bytecode_evidence(row):
    evidence_files = [
        value.strip()
        for value in str(row.get("evidence_files") or "").split("|")
        if value.strip()
    ]
    if not evidence_files:
        return False
    path_text = str(row.get("path_text") or "").strip()
    path_nodes = _split_csv_chain_nodes(path_text)
    target_matches = bool(
        len(path_nodes) >= 2
        and _alert_target_matches_changed_symbol(path_nodes[-1], row)
    )
    evidence_text = " ".join(
        str(row.get(field) or "")
        for field in (
            "path_text",
            "chain_detail",
            "review_reason",
        )
    )
    return bool(
        target_matches
        and re.search(
            r"(?:class|类).{0,12}字节码.{0,12}(?:完全一致|相同)|"
            r"字节码.{0,12}(?:完全一致|相同)",
            evidence_text,
            flags=re.IGNORECASE,
        )
    )


def _validated_alert_rows(path, *, diagnostics, required=False):
    for row in iter_csv_rows(
        path,
        diagnostics=diagnostics,
        artifact="call_chain_alerts",
        required=required,
    ):
        status = str(
            row.get("path_status") or row.get("api_status") or ""
        ).strip()
        issue = ""
        if status not in _ALERT_PATH_STATUSES:
            issue = "alerts contains an unrecognized path status"
        expected_levels = {
            "reachable": "confirmed",
            "uncertain": "candidate",
            "not_impacted": "confirmed_no_impact",
            "not_found_in_static_analysis": "no_static_path",
            "not_reachable": "no_static_path",
            "not_analyzed": "incomplete",
        }
        conclusion_level = str(
            row.get("conclusion_level") or ""
        ).strip()
        business_reachable = str(
            row.get("business_reachable") or ""
        ).strip().lower()
        if (
            not issue
            and conclusion_level
            and conclusion_level != expected_levels.get(status)
        ):
            issue = (
                "alerts path status conflicts with conclusion level"
            )
        elif (
            not issue
            and business_reachable == "true"
            and status != "reachable"
        ):
            issue = (
                "alerts path status conflicts with business reachability"
            )
        elif (
            not issue
            and status == "reachable"
            and business_reachable == "false"
        ):
            issue = (
                "alerts path status conflicts with business reachability"
            )
        elif (
            not issue
            and status == "reachable"
            and not _alert_row_has_reachable_path_evidence(row)
        ):
            issue = "reachable alert has no matching physical call path"
        elif (
            not issue
            and status == "not_impacted"
            and not _alert_row_has_preserved_bytecode_evidence(row)
        ):
            issue = (
                "not-impacted alert has no matching preserved-bytecode evidence"
            )
        if issue:
            _record_content_diagnostic(
                diagnostics,
                artifact="call_chain_alerts",
                stage="row_contract",
                path=path,
                message=issue,
            )
            continue
        yield row


def _validate_call_summary_contract(path, summary, diagnostics):
    if not Path(path).is_file() or any(
        str(item.get("artifact") or "") == "call_chain_summary"
        and str(item.get("stage") or "") in {
            "json_load", "json_contract", "json_missing"
        }
        for item in diagnostics or []
    ):
        return
    issues = []
    contract_fields = {
        "status", "total_apis", "reachable", "reachable_apis",
        "not_impacted_apis", "uncertain_apis", "not_analyzed_apis",
        "not_found_apis",
    }
    if not summary or not contract_fields.intersection(summary):
        issues.append("summary has no status, target count, or result buckets")

    status = summary.get("status")
    no_changed_api_skip = False
    if not isinstance(status, str) or not status.strip():
        issues.append("status is missing or not text")
    elif status not in {"done", "skipped"}:
        issues.append(f"status {status!r} is not a completed Step5 result")
    elif (
        status == "skipped"
        and str(summary.get("skip_reason") or "") != "no_changed_apis"
    ):
        issues.append("skipped status does not record no_changed_apis")
    elif status == "skipped":
        no_changed_api_skip = True

    bucket_names = (
        "reachable_apis",
        "not_impacted_apis",
        "uncertain_apis",
        "not_analyzed_apis",
        "not_found_apis",
    )
    for bucket_name in bucket_names:
        value = summary.get(bucket_name, [])
        if not isinstance(value, list):
            issues.append(f"{bucket_name} is not a list")
            summary[bucket_name] = []
            continue
        valid_items = []
        for item in value:
            if not isinstance(item, dict):
                issues.append(f"{bucket_name} contains non-object entries")
                continue
            normalized_item = dict(item)
            for field in (
                "coord",
                "api",
                "api_name",
                "api_signature",
                "symbol_kind",
                "change_type",
                "severity",
                "old_version",
                "new_version",
                "reason_code",
                "reason",
                "user_conclusion",
                "user_reason",
                "key_evidence",
                "business_entry",
                "impact_mode",
            ):
                field_value = normalized_item.get(field)
                if field_value is not None and not isinstance(
                    field_value, str
                ):
                    issues.append(f"{bucket_name}.{field} is not text")
                    normalized_item[field] = ""
            for field in (
                "call_paths",
                "dependency_chain_coords",
                "verification",
            ):
                field_value = normalized_item.get(field, [])
                if not isinstance(field_value, list):
                    issues.append(f"{bucket_name}.{field} is not a list")
                    field_value = []
                normalized_values = [
                    entry for entry in field_value
                    if isinstance(entry, str)
                ]
                if len(normalized_values) != len(field_value):
                    issues.append(
                        f"{bucket_name}.{field} contains non-text entries"
                    )
                normalized_item[field] = normalized_values
            valid_items.append(normalized_item)
        if len(valid_items) != len(value):
            issues.append(f"{bucket_name} contains invalid entries")
            summary[bucket_name] = valid_items
        else:
            summary[bucket_name] = valid_items

    for object_field in ("user_conclusion_summary", "graph_stats"):
        value = summary.get(object_field, {})
        if value is not None and not isinstance(value, dict):
            issues.append(f"{object_field} is not an object")
            summary[object_field] = {}
    user_conclusion_summary = summary.get("user_conclusion_summary") or {}
    if isinstance(user_conclusion_summary, dict):
        allowed_conclusion_keys = {
            "confirmed_impact",
            "confirmed_no_impact",
            "probable_impact",
            "inconclusive",
            "input_required",
        }
        invalid_conclusion_keys = sorted(
            str(key)
            for key in user_conclusion_summary
            if str(key) not in allowed_conclusion_keys
        )
        if invalid_conclusion_keys:
            _record_content_diagnostic(
                diagnostics,
                artifact="call_chain_summary",
                stage="json_contract",
                path=path,
                message=(
                    "user_conclusion_summary contains non-contract keys: "
                    + ", ".join(invalid_conclusion_keys)
                ),
            )
            summary["user_conclusion_summary"] = {
                key: user_conclusion_summary[key]
                for key in allowed_conclusion_keys
                if key in user_conclusion_summary
            }
    meta = summary.get("meta", {})
    if meta is not None and not isinstance(meta, dict):
        issues.append("meta is not an object")
        meta = {}
        summary["meta"] = meta
    if isinstance(meta, dict):
        graph_stats = meta.get("graph_stats", {})
        if graph_stats is not None and not isinstance(graph_stats, dict):
            issues.append("meta.graph_stats is not an object")
            graph_stats = {}
            meta["graph_stats"] = graph_stats
        if isinstance(graph_stats, dict):
            for field in (
                "parser_fallback_reasons",
                "source_artifact_alignment",
                "artifact_bytecode",
                "business_bytecode",
                "indirect_usage",
            ):
                value = graph_stats.get(field)
                if value is not None and not isinstance(value, dict):
                    issues.append(f"meta.graph_stats.{field} is not an object")
                    graph_stats[field] = {}
            truncation_reasons = graph_stats.get("truncation_reasons")
            if (
                truncation_reasons is not None
                and not isinstance(truncation_reasons, list)
            ):
                issues.append(
                    "meta.graph_stats.truncation_reasons is not a list"
                )
                graph_stats["truncation_reasons"] = []
    guidance = summary.get("diagnostic_guidance")
    if guidance is not None and not isinstance(guidance, list):
        issues.append("diagnostic_guidance is not a list")
        summary["diagnostic_guidance"] = []
    elif isinstance(guidance, list):
        normalized_guidance = []
        for item in guidance:
            if not isinstance(item, dict):
                issues.append(
                    "diagnostic_guidance contains a non-object entry"
                )
                continue
            normalized = dict(item)
            for field in (
                "reason_code",
                "origin_step",
                "title",
                "trigger_condition",
                "semantic_impact",
                "observed_scope",
            ):
                value = normalized.get(field)
                if value is not None and not isinstance(value, str):
                    issues.append(
                        f"diagnostic_guidance.{field} is not text"
                    )
                    normalized[field] = ""
            origin_step = str(
                normalized.get("origin_step") or "unknown"
            ).strip().lower()
            if not re.fullmatch(r"step[1-6]|unknown", origin_step):
                issues.append(
                    "diagnostic_guidance.origin_step is invalid"
                )
                origin_step = "unknown"
            normalized["origin_step"] = origin_step
            reason_code = str(
                normalized.get("reason_code") or "UNKNOWN"
            ).strip()
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", reason_code):
                issues.append(
                    "diagnostic_guidance.reason_code is invalid"
                )
                reason_code = "UNKNOWN"
            normalized["reason_code"] = reason_code
            observed_scope = str(
                normalized.get("observed_scope") or "unknown"
            ).strip().lower()
            if observed_scope not in {
                "global", "path", "api", "step", "mixed", "unknown"
            }:
                issues.append(
                    "diagnostic_guidance.observed_scope is invalid"
                )
                observed_scope = "unknown"
            normalized["observed_scope"] = observed_scope
            for field in (
                "affected_classes",
                "affected_artifacts",
                "affected_artifact_entries",
                "collectors",
                "failure_detail_summaries",
                "source_components",
                "sample_apis",
                "repair_actions",
                "verification_steps",
            ):
                value = normalized.get(field, [])
                if not isinstance(value, list):
                    issues.append(
                        f"diagnostic_guidance.{field} is not a list"
                    )
                    value = []
                text_values = [
                    entry.strip()
                    for entry in value
                    if isinstance(entry, str) and entry.strip()
                ]
                if len(text_values) != len(value):
                    issues.append(
                        f"diagnostic_guidance.{field} contains non-text entries"
                    )
                normalized[field] = text_values
            candidates = normalized.get("candidate_evidence", [])
            if not isinstance(candidates, list):
                issues.append(
                    "diagnostic_guidance.candidate_evidence is not a list"
                )
                candidates = []
            normalized_candidates = []
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue
                normalized_candidate = dict(candidate)
                for field in (
                    "coord",
                    "artifact",
                    "artifact_entry",
                    "bytecode_sha256",
                ):
                    value = normalized_candidate.get(field)
                    if value is not None and not isinstance(value, str):
                        issues.append(
                            "diagnostic_guidance.candidate_evidence."
                            f"{field} is not text"
                        )
                        normalized_candidate[field] = ""
                normalized_candidates.append(normalized_candidate)
            normalized["candidate_evidence"] = normalized_candidates
            if len(normalized_candidates) != len(candidates):
                issues.append(
                    "diagnostic_guidance.candidate_evidence contains "
                    "non-object entries"
                )
            count_fallbacks = (
                ("affected_api_count", 0),
                ("primary_reason_api_count", "affected_api_count"),
                ("potentially_affected_api_count", "affected_api_count"),
                ("observed_failure_count", 0),
                ("failure_record_count", "observed_failure_count"),
                ("failure_occurrence_count", 0),
                ("raw_blocking_failure_count", 0),
                ("relevant_blocking_failure_count", 0),
            )
            for field, fallback in count_fallbacks:
                default_value = (
                    normalized.get(fallback, 0)
                    if isinstance(fallback, str)
                    else fallback
                )
                value = _strict_non_negative_int(
                    normalized.get(field, default_value)
                )
                if value is None:
                    issues.append(
                        f"diagnostic_guidance.{field} is not a "
                        "non-negative integer"
                    )
                    value = 0
                normalized[field] = value
            blocking = normalized.get("blocking", False)
            if not isinstance(blocking, bool):
                issues.append(
                    "diagnostic_guidance.blocking is not boolean"
                )
                blocking = False
            normalized["blocking"] = blocking
            normalized_guidance.append(normalized)
        summary["diagnostic_guidance"] = normalized_guidance

    total = None
    if "total_apis" in summary:
        total = _strict_non_negative_int(summary.get("total_apis"))
        if total is None:
            issues.append("total_apis is not a non-negative integer")

    count_pairs = (
        ("reachable", "reachable_apis"),
        ("not_impacted", "not_impacted_apis"),
        ("uncertain", "uncertain_apis"),
        ("not_analyzed", "not_analyzed_apis"),
        ("not_found_in_static_analysis", "not_found_apis"),
    )
    for count_field, bucket_name in count_pairs:
        if count_field not in summary:
            continue
        recorded_count = _strict_non_negative_int(
            summary.get(count_field)
        )
        if recorded_count is None:
            issues.append(
                f"{count_field} is not a non-negative integer"
            )
            continue
        if recorded_count != len(summary.get(bucket_name) or []):
            issues.append(
                f"{count_field} does not match {bucket_name}"
            )

    accounted = sum(len(summary.get(name) or []) for name in bucket_names)
    if total is not None and total != accounted:
        issues.append("total_apis does not match result bucket entries")
    identity_rows = _summary_result_identity_rows(summary)
    complete_identities = [
        identity for identity, _bucket in identity_rows
        if _identity_is_complete(identity)
    ]
    if len(complete_identities) != accounted:
        issues.append("one or more result entries have an incomplete API identity")
    if len(set(complete_identities)) != len(complete_identities):
        issues.append("result buckets contain duplicate API identities")
    if total is not None and total != len(set(complete_identities)):
        issues.append("total_apis does not match unique API identities")
    invalid_no_changed_api_skip = bool(
        no_changed_api_skip
        and (
            (total is not None and total != 0)
            or accounted
            or any(
                _strict_non_negative_int(
                    summary.get(count_field)
                ) not in {0}
                for count_field, _bucket_name in count_pairs
                if count_field in summary
            )
        )
    )
    if invalid_no_changed_api_skip:
        issues.append(
            "no_changed_apis skip contains non-zero counts or result entries"
        )
        for bucket_name in bucket_names:
            summary[bucket_name] = []
        for count_field, _bucket_name in count_pairs:
            summary[count_field] = 0
        summary["total_apis"] = 0

    if issues:
        identity_buckets = defaultdict(set)
        for bucket_name in bucket_names:
            for item in summary.get(bucket_name) or []:
                identity = build_api_identity_key(item)
                if _identity_is_complete(identity):
                    identity_buckets[identity].add(bucket_name)
        conflicting_identities = {
            identity
            for identity, buckets in identity_buckets.items()
            if len(buckets) > 1
        }
        seen_identities = set()
        for bucket_name in bucket_names:
            sanitized_items = []
            for item in summary.get(bucket_name) or []:
                identity = build_api_identity_key(item)
                if (
                    not _identity_is_complete(identity)
                    or identity in conflicting_identities
                    or identity in seen_identities
                ):
                    continue
                seen_identities.add(identity)
                sanitized = dict(item)
                for field in (
                    "reason",
                    "user_reason",
                    "key_evidence",
                    "call_paths",
                    "recommended_action",
                    "verification",
                ):
                    sanitized.pop(field, None)
                sanitized_items.append(sanitized)
            summary[bucket_name] = sanitized_items
        _record_content_diagnostic(
            diagnostics,
            artifact="call_chain_summary",
            stage="json_contract",
            path=path,
            message="; ".join(dict.fromkeys(issues)),
        )


def _call_summary_target_count(summary):
    if "total_apis" in (summary or {}):
        try:
            return max(int(summary.get("total_apis") or 0), 0)
        except (TypeError, ValueError):
            return 0
    identities = set()
    for bucket in (
        "reachable_apis",
        "not_impacted_apis",
        "uncertain_apis",
        "not_analyzed_apis",
        "not_found_apis",
    ):
        for item in (summary or {}).get(bucket) or []:
            if isinstance(item, dict):
                identities.add(build_api_identity_key(item))
    return len(identities)


def _validate_coverage_contract(path, coverage, diagnostics):
    if not Path(path).is_file() or _artifact_has_diagnostic(
        diagnostics, "coverage"
    ):
        return
    issues = []
    overall_status = coverage.get("overall_status")
    if not isinstance(overall_status, str) or not overall_status.strip():
        issues.append("overall_status is missing or not text")
        coverage["overall_status"] = "unknown"
    elif overall_status not in {
        "complete", "partial", "insufficient", "not_applicable", "unknown"
    }:
        issues.append("overall_status is not a recognized coverage status")
        coverage["overall_status"] = "unknown"

    critical = coverage.get("critical_incomplete", [])
    if not isinstance(critical, list):
        issues.append("critical_incomplete is not a list")
        critical = []
    normalized_critical = []
    for value in critical:
        if not isinstance(value, str):
            issues.append("critical_incomplete contains a non-text entry")
            continue
        normalized = value.strip()
        if normalized:
            normalized_critical.append(normalized)
    coverage["critical_incomplete"] = normalized_critical

    components = coverage.get("components", [])
    if not isinstance(components, list):
        issues.append("components is not a list")
        components = []
    normalized_components = []
    for component in components:
        if not isinstance(component, dict):
            issues.append("components contains a non-object entry")
            continue
        normalized = dict(component)
        component_id = normalized.get("id")
        if not isinstance(component_id, str) or not component_id.strip():
            issues.append("coverage component id is missing")
            continue
        normalized["id"] = component_id.strip()
        component_status = normalized.get("status")
        if (
            not isinstance(component_status, str)
            or component_status not in {
                "complete",
                "partial",
                "insufficient",
                "not_applicable",
                "unknown",
            }
        ):
            issues.append("coverage component status is invalid")
            normalized["status"] = "unknown"
        for field in ("reason_codes", "evidence"):
            value = normalized.get(field, [])
            if not isinstance(value, list):
                issues.append(f"coverage component {field} is not a list")
                value = []
            normalized_values = []
            for item in value:
                if not isinstance(item, str):
                    issues.append(
                        f"coverage component {field} contains a non-text entry"
                    )
                    continue
                item = item.strip()
                if item:
                    normalized_values.append(item)
            normalized[field] = normalized_values
        normalized_components.append(normalized)
    coverage["components"] = normalized_components

    incomplete_component_ids = {
        str(component.get("id") or "")
        for component in normalized_components
        if component.get("status") not in {"complete", "not_applicable"}
    }
    if (
        coverage.get("overall_status") in {"complete", "not_applicable"}
        and (normalized_critical or incomplete_component_ids)
    ):
        issues.append(
            "overall_status conflicts with incomplete coverage components"
        )
        coverage["overall_status"] = "partial"
    component_status_by_id = {
        str(component.get("id") or ""): str(component.get("status") or "")
        for component in normalized_components
    }
    for component_id in normalized_critical:
        if component_status_by_id.get(component_id) in {
            "complete", "not_applicable"
        }:
            issues.append(
                "critical_incomplete conflicts with component status"
            )
            coverage["overall_status"] = "partial"

    if issues:
        _record_content_diagnostic(
            diagnostics,
            artifact="coverage",
            stage="json_contract",
            path=path,
            message="; ".join(dict.fromkeys(issues)),
        )


def _validate_analysis_scope_contract(path, scope, diagnostics):
    if not Path(path).is_file() or _artifact_has_diagnostic(
        diagnostics, "step5_selection"
    ):
        return
    issues = []
    mode = scope.get("mode")
    if not isinstance(mode, str) or mode not in {"full", "partial"}:
        issues.append("mode is not full or partial")
        scope["mode"] = ""

    for field in (
        "available_dependency_count",
        "included_dependency_count",
        "total_api_count",
        "analyzed_api_count",
    ):
        value = scope.get(field, 0)
        normalized = _strict_non_negative_int(value)
        if normalized is None:
            issues.append(f"{field} is not a non-negative integer")
            normalized = 0
        scope[field] = normalized

    for field in (
        "included_dependency_coords",
        "excluded_dependency_coords",
        "selected_names",
    ):
        value = scope.get(field, [])
        if not isinstance(value, list):
            issues.append(f"{field} is not a list")
            value = []
        normalized_values = []
        for item in value:
            if not isinstance(item, str):
                issues.append(f"{field} contains a non-text entry")
                continue
            item = item.strip()
            if item:
                normalized_values.append(item)
        scope[field] = normalized_values

    available = int(scope.get("available_dependency_count") or 0)
    included = int(scope.get("included_dependency_count") or 0)
    if included > available:
        issues.append(
            "included_dependency_count exceeds available_dependency_count"
        )
    if scope.get("mode") == "full" and included != available:
        issues.append(
            "full scope dependency counts are not equal"
        )
    included_coords = {
        str(item).strip()
        for item in scope.get("included_dependency_coords") or []
        if str(item).strip()
    }
    excluded_coords = {
        str(item).strip()
        for item in scope.get("excluded_dependency_coords") or []
        if str(item).strip()
    }
    if included_coords.intersection(excluded_coords):
        issues.append("included and excluded dependency coordinates overlap")
    if "included_dependency_coords" in scope and included_coords:
        if len(included_coords) != included:
            issues.append(
                "included dependency coordinate count does not match"
            )
    if "excluded_dependency_coords" in scope and excluded_coords:
        if len(excluded_coords) != max(available - included, 0):
            issues.append(
                "excluded dependency coordinate count does not match"
            )
    if scope.get("mode") == "full" and excluded_coords:
        issues.append("full scope contains excluded dependencies")
    if (
        scope.get("mode") == "partial"
        and len(included_coords) != included
    ):
        issues.append(
            "partial scope does not record every included dependency coordinate"
        )
    if (
        scope.get("mode") == "partial"
        and len(excluded_coords) != max(available - included, 0)
    ):
        issues.append(
            "partial scope does not record every excluded dependency coordinate"
        )

    if issues:
        _invalidate_analysis_scope(
            scope, "分析范围快照结构无效"
        )
        _record_content_diagnostic(
            diagnostics,
            artifact="step5_selection",
            stage="json_contract",
            path=path,
            message="; ".join(dict.fromkeys(issues)),
        )


def _validate_context_contract(path, context, diagnostics):
    if not Path(path).is_file() or _artifact_has_diagnostic(
        diagnostics, "context"
    ):
        return
    issues = []
    for field in (
        "jdk_base",
        "jdk_current",
        "springboot_base",
        "springboot_current",
        "build_tool",
    ):
        value = context.get(field)
        if value is not None and not isinstance(value, str):
            issues.append(f"{field} is not text")
            context[field] = ""
    for field in ("jdk_upgraded", "springboot_major_upgrade"):
        value = context.get(field)
        if value is not None and not isinstance(value, bool):
            issues.append(f"{field} is not boolean")
            context[field] = False
    tech_flags = context.get("tech_flags", {})
    if not isinstance(tech_flags, dict):
        issues.append("tech_flags is not an object")
        tech_flags = {}
    normalized_flags = {}
    for key, value in tech_flags.items():
        if not isinstance(key, str) or not isinstance(value, bool):
            issues.append("tech_flags contains a non-boolean flag")
            continue
        normalized_flags[key] = value
    context["tech_flags"] = normalized_flags
    if issues:
        _record_content_diagnostic(
            diagnostics,
            artifact="context",
            stage="json_contract",
            path=path,
            message="; ".join(dict.fromkeys(issues)),
        )


def count_lines(path):
    if not os.path.exists(path):
        return -1
    try:
        with open_text(path) as f:
            line_count = sum(1 for line in f if line.strip() and not line.startswith('#'))
        if path.endswith('.csv'):
            return max(line_count - 1, 0)  # 排除 CSV 表头
        return line_count
    except (OSError, UnicodeError):
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
        counts[
            canonical_reason_code(item.get("reason_code") or "UNKNOWN")
        ] += 1
    return dict(sorted(counts.items(), key=lambda x: (-x[1], x[0])))


def summarize_item_reasons(items, conclusion=''):
    """Summarize human explanations without exposing internal reason codes."""
    counts = defaultdict(int)
    for item in items or []:
        reason = (
            _objective_item_reason(item, conclusion)
            or "未提供足够证据说明原因"
        )
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
        'DATA_FIELD_ADDED': 'DTO 字段新增',
        'DATA_FIELD_REMOVED': 'DTO 字段删除',
        'DATA_FIELD_TYPE_CHANGED': 'DTO 字段类型变化',
        'SIGNATURE_CHANGED': '方法签名变化',
        'RETURN_TYPE_CHANGED': '返回类型变化',
        'ACCESS_MODIFIER_CHANGED': '访问权限变化',
        'ACCESS_REDUCED': '访问权限收紧',
        'SOURCE_INCOMPATIBLE': '源码不兼容',
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
    signature = _human_signature(item.get('api_signature'))
    sev = str(severity or item.get('severity') or '').strip()
    pieces = [change]
    if signature:
        pieces.append(f"参数：{signature}")
    if str(item.get('change_type') or '').upper() == 'DATA_FIELD_ADDED' and item.get('new_value'):
        pieces.append(f"字段类型：{item.get('new_value')}")
    elif str(item.get('change_type') or '').upper() == 'DATA_FIELD_REMOVED' and item.get('old_value'):
        pieces.append(f"原字段类型：{item.get('old_value')}")
    elif str(item.get('change_type') or '').upper() == 'DATA_FIELD_TYPE_CHANGED':
        old_value = str(item.get('old_value') or '').strip() or '未知'
        new_value = str(item.get('new_value') or '').strip() or '未知'
        pieces.append(f"字段类型：{old_value} → {new_value}")
    if sev:
        pieces.append(f"严重级别：{sev}")
    return "，".join(pieces)


def _exclusive_not_analyzed(findings):
    """Return the residual not-analyzed bucket without its named sub-buckets."""
    return [
        item for item in (findings.get('not_analyzed') or [])
        if item.get('user_conclusion') not in {'可能影响', '需要补充输入'}
    ]


def _version_transition(item):
    old_version = str(item.get('old_version') or '').strip()
    new_version = str(item.get('new_version') or '').strip()
    if not old_version and not new_version:
        return ''
    old_display = '未引入' if old_version == '-' else (old_version or '未记录')
    new_display = '已移除' if new_version == '-' else (new_version or '未记录')
    return f"{old_display} → {new_display}"


def _human_chain_node(value):
    text = str(value or '').strip()
    if not text:
        return ''
    # Bytecode paths may prefix dependency nodes with ``group:artifact:``.
    # The coordinate is useful in structured evidence but makes the primary
    # report almost impossible to scan, so keep just the callable here.
    parts = text.split(':', 2)
    if len(parts) == 3 and '.' in parts[0] and parts[1]:
        text = parts[2]
    return text.replace('java.lang.', '').replace(' -> ', ' → ')


def _human_chain(value):
    raw = str(value or '').strip()
    if not raw:
        return ''
    nodes = re.split(r'\s*(?:->|→)\s*', raw)
    cleaned = [_human_chain_node(node) for node in nodes]
    return ' → '.join(node for node in cleaned if node)


def _call_path_shape(value):
    """Return node names plus any signatures recorded for a call path."""
    raw = str(value or '').strip()
    if not raw:
        return (), ()
    bases = []
    signatures = []
    for raw_node in re.split(r'\s*(?:->|→)\s*', raw):
        node = raw_node.strip()
        if not node:
            continue
        match = re.match(r'^(.*?)(\([^()]*\))\s*$', node)
        if match:
            bases.append(re.sub(r'\s+', ' ', match.group(1).strip()))
            signatures.append(match.group(2))
        else:
            bases.append(re.sub(r'\s+', ' ', node))
            signatures.append(None)
    return tuple(bases), tuple(signatures)


def _call_path_signatures_compatible(left, right):
    return all(
        not left_sig or not right_sig or left_sig == right_sig
        for left_sig, right_sig in zip(left, right)
    )


def _signature_variant_sort_key(signatures):
    return tuple(
        (0, "") if signature is None else (1, str(signature))
        for signature in signatures
    )


def _minimum_compatible_variant_groups(variants):
    """Return a stable lower-bound-preserving grouping of partial signatures."""
    variants = sorted(set(variants), key=_signature_variant_sort_key)
    if not variants:
        return 0
    conflicts = {
        index: {
            other_index
            for other_index, other in enumerate(variants)
            if other_index != index
            and not _call_path_signatures_compatible(
                variants[index],
                other,
            )
        }
        for index in range(len(variants))
    }
    def selected_vertex(colors):
        uncolored = [
            index for index in range(len(variants))
            if index not in colors
        ]
        return min(
            uncolored,
            key=lambda index: (
                -len({
                    colors[other]
                    for other in conflicts[index]
                    if other in colors
                }),
                -len(conflicts[index]),
                -sum(bool(value) for value in variants[index]),
                _signature_variant_sort_key(variants[index]),
            ),
        )

    # First establish a deterministic upper bound with DSATUR. A color is one
    # logical path compatible with every partial signature assigned to it.
    colors = {}
    while len(colors) < len(variants):
        current = selected_vertex(colors)
        unavailable = {
            colors[other]
            for other in conflicts[current]
            if other in colors
        }
        color = 0
        while color in unavailable:
            color += 1
        colors[current] = color
    best = max(colors.values()) + 1

    # A deterministic maximal clique supplies a safe lower bound and resolves
    # the common complete/conflict-free cases without backtracking.
    clique = []
    for index in sorted(
        range(len(variants)),
        key=lambda value: (
            -len(conflicts[value]),
            _signature_variant_sort_key(variants[value]),
        ),
    ):
        if all(index in conflicts[member] for member in clique):
            clique.append(index)
    lower_bound = max(len(clique), 1)
    if best == lower_bound:
        return best

    # Exact coloring keeps ambiguous partial signatures from inflating the
    # reported chain count. Very large overload sets use the deterministic
    # upper bound above to avoid exponential report generation.
    if len(variants) > 32:
        return best

    assigned = {}

    def search(used_color_count):
        nonlocal best
        if best == lower_bound:
            return
        if len(assigned) == len(variants):
            best = min(best, used_color_count)
            return
        if used_color_count >= best:
            return
        current = selected_vertex(assigned)
        unavailable = {
            assigned[other]
            for other in conflicts[current]
            if other in assigned
        }
        for color in range(used_color_count):
            if color in unavailable:
                continue
            assigned[current] = color
            search(used_color_count)
            assigned.pop(current, None)
        if used_color_count + 1 < best:
            assigned[current] = used_color_count
            search(used_color_count + 1)
            assigned.pop(current, None)

    search(0)
    return best


def _distinct_call_path_count(paths):
    grouped = defaultdict(list)
    for path in paths or []:
        bases, signatures = _call_path_shape(path)
        if bases:
            grouped[bases].append(signatures)

    count = 0
    for variants in grouped.values():
        count += max(_minimum_compatible_variant_groups(variants), 1)
    return count


def _scope_text(findings):
    scope = findings.get('analysis_scope') or {}
    if scope.get("validation_status") == "invalid":
        return "分析范围无法核验，不能按全量分析解释"
    mode = str(scope.get('mode') or '').strip()
    included_dependencies = int(scope.get('included_dependency_count') or 0)
    available_dependencies = int(scope.get('available_dependency_count') or 0)
    analyzed_apis = int(scope.get('analyzed_api_count') or 0)
    total_apis = int(scope.get('total_api_count') or 0)
    counts = []
    if available_dependencies:
        counts.append(f"变化依赖 {included_dependencies}/{available_dependencies}")
    if total_apis:
        counts.append(f"变化 API {analyzed_apis}/{total_apis}")
    suffix = f"（{'，'.join(counts)}）" if counts else ''
    if mode == 'full':
        return f"全量分析{suffix}"
    if mode == 'partial':
        return f"部分分析{suffix}"
    return "范围快照缺失，不能按全量分析解释"


def _known_context_parts(findings):
    context = findings.get('context') or {}
    parts = []
    for label, key in (('JDK', 'jdk'), ('Spring Boot', 'springboot')):
        value = str(context.get(key) or '').strip()
        if not value or value in {'? → ?', '?'}:
            continue
        if value.startswith('? → '):
            parts.append(f"{label} 目标版本 {value[4:]}（基线版本未记录）")
        else:
            parts.append(f"{label} {value}")
    build_tool = str(context.get('build_tool') or '').strip()
    if build_tool and build_tool != '?':
        parts.append(f"构建工具 {build_tool}")
    return parts


def _uncertain_item_sort_key(item):
    return (
        -int(item.get("priority_score") or 0),
        _severity_rank(item.get("severity")),
        -len(item.get("call_paths") or item.get("paths") or []),
        str(item.get("api") or item.get("api_name") or ""),
        str(item.get("api_signature") or ""),
    )


def _order_uncertain_items_by_dependency(items):
    """Keep dependency coordinates contiguous while ordering review risk."""
    grouped = defaultdict(list)
    for item in items or []:
        coord = str((item or {}).get("coord") or "").strip()
        grouped[coord].append(item)

    dependency_groups = []
    for coord, group_items in grouped.items():
        ordered_items = sorted(group_items, key=_uncertain_item_sort_key)
        scores = [int((item or {}).get("priority_score") or 0) for item in ordered_items]
        dependency_groups.append({
            "coord": coord,
            "items": ordered_items,
            "dependency_uncertain_api_count": len(ordered_items),
            "dependency_top_priority_score": max(scores, default=0),
            "dependency_total_priority_score": sum(scores),
        })

    dependency_groups.sort(key=lambda group: (
        -int(group["dependency_top_priority_score"]),
        -int(group["dependency_total_priority_score"]),
        -int(group["dependency_uncertain_api_count"]),
        not bool(group["coord"]),
        str(group["coord"]),
    ))

    ordered = []
    for rank, group in enumerate(dependency_groups, 1):
        for item in group["items"]:
            enriched = dict(item or {})
            enriched.update({
                "dependency_priority_rank": rank,
                "dependency_top_priority_score": group[
                    "dependency_top_priority_score"
                ],
                "dependency_total_priority_score": group[
                    "dependency_total_priority_score"
                ],
                "dependency_uncertain_api_count": group[
                    "dependency_uncertain_api_count"
                ],
            })
            ordered.append(enriched)
    return ordered


def _detail_row(idx, item, conclusion='', *, show_priority=False):
    display_conclusion = str(conclusion or '').strip()
    if not display_conclusion and str((item or {}).get('uncertainty_kind') or '').strip():
        display_conclusion = _uncertain_conclusion(item)
    if not display_conclusion:
        display_conclusion = (
            item.get("user_conclusion")
            or _bucket_csv_conclusion('', item)
        )
    reason = (
        _objective_item_reason(
            item,
            display_conclusion,
        )
        or "未记录更多客观原因。"
    )
    boundary = _detail_review_focus(item, display_conclusion)
    priority_cell = (
        f"| {int(item.get('priority_score') or 0)} "
        if show_priority
        else ""
    )
    return (
        f"| {idx} | `{_md_cell(item.get('coord'))}` | `{_md_cell(item.get('api'))}` | "
        f"{priority_cell}"
        f"{_md_cell(_change_summary(item), 220)} | "
        f"{_md_cell(display_conclusion)} | "
        f"{_md_cell(reason)} | {_md_cell(boundary)} |"
    )


def _detail_review_focus(item, conclusion=''):
    conclusion_text = str(conclusion or item.get("user_conclusion") or "").strip()
    reason = str(item.get("user_reason") or item.get("reason") or item.get("reason_code") or "").strip()
    if conclusion_text == "已确认影响":
        return "当前证据已形成从系统入口到变更 API 的完整链路。"
    if conclusion_text == "可能影响":
        return "现有证据不能确认该行为变化在运行时是否会触发。"
    if conclusion_text in {
        "结论未确定（存在候选证据）",
        "结论未确定（候选证据）",
    }:
        return "现有记录包含候选证据，但未形成完整的系统触达事实。"
    if conclusion_text == UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION:
        return (
            "当前未发现候选调用证据；受静态分析能力边界限制，"
            "需通过源码检索、动态验证或业务回归确认。"
        )
    if conclusion_text in {
        "需要补充输入", "缺少依赖源码/构建产物", "输入不足，结论未确定"
    }:
        return "本轮缺少源码、构建产物或映射信息，未形成确定结论。"
    if conclusion_text == "本次未完成分析":
        return "该项没有形成完整分析结果，不能按未影响解释。"
    if conclusion_text == "已确认不受影响":
        return "结论只覆盖当前制品中的 API 字节码保留事实。"
    if "未找到" in conclusion_text:
        return "当前静态分析范围内未找到路径；不等同于已确认不受影响。"
    return "当前记录没有更多可展示的结论边界。"


def build_bucket_detail_markdown(config, items, csv_name, *, alerts_available=False):
    if config.get("show_priority"):
        items = _order_uncertain_items_by_dependency(items)
    reason_summary = summarize_item_reasons(
        items, config.get("conclusion") or ""
    )
    coord_summary = summarize_item_coords(items)
    severity_summary = defaultdict(int)
    change_summary = defaultdict(int)
    for item in items or []:
        severity_summary[str(item.get("severity") or "未分级").upper()] += 1
        change_summary[
            _human_change_type(
                item.get("change_type"),
                item.get("symbol_kind"),
            )
        ] += 1
    severity_summary = dict(sorted(
        severity_summary.items(),
        key=lambda item: (_severity_rank(item[0]), item[0]),
    ))
    change_summary = dict(sorted(
        change_summary.items(),
        key=lambda item: (-item[1], item[0]),
    ))
    lines = [
        f"# {config.get('title') or 'S6 明细'}",
        "",
        f"- 总数：{len(items)}",
        f"- 说明：{config.get('note') or ''}",
        f"- 完整可筛选清单：`{csv_name}`",
        "",
        "## 内容说明",
        "",
        "- 下表记录变更事实、当前结论、形成结论的原因和适用边界。",
        "- Markdown 仅在数据量较大时展示样例；完整记录保存在同名 CSV。",
    ]
    if config.get("show_priority"):
        lines.append(
            "- 两级排序：先按依赖组最高分、组内总分排列依赖坐标，"
            "再在每个依赖内部按 API 复核优先分数降序排列。"
        )
        lines.append(
            "- API 复核优先分数 = 严重级别权重 × 调用方权重 × 运行时必加载权重。"
        )
    if alerts_available:
        lines.append("- 完整逐链路事实保存在 `evidence/call_chain/alerts.csv`。")
    lines.append("")

    if len(items) > 1:
        lines += [
            "## 事实分布",
            "",
        ]
    if len(items) > 1 and coord_summary and config.get("show_priority"):
        dependency_rows = []
        seen_dependency_ranks = set()
        for item in items:
            dependency_rank = int(item.get("dependency_priority_rank") or 0)
            if dependency_rank in seen_dependency_ranks:
                continue
            seen_dependency_ranks.add(dependency_rank)
            dependency_rows.append(item)
        lines += [
            "### 依赖复核顺序",
            "",
            "| 依赖排名 | 依赖坐标 | 组内最高分 | 组内总分 | uncertain API 数 |",
            "|---:|---|---:|---:|---:|",
        ]
        for item in dependency_rows[:S6_DETAIL_MD_DEP_SUMMARY_LIMIT]:
            lines.append(
                f"| {int(item.get('dependency_priority_rank') or 0)} | "
                f"`{_md_cell(item.get('coord'))}` | "
                f"{int(item.get('dependency_top_priority_score') or 0)} | "
                f"{int(item.get('dependency_total_priority_score') or 0)} | "
                f"{int(item.get('dependency_uncertain_api_count') or 0)} |"
            )
        if len(dependency_rows) > S6_DETAIL_MD_DEP_SUMMARY_LIMIT:
            lines.append(
                f"| 其他 {len(dependency_rows) - S6_DETAIL_MD_DEP_SUMMARY_LIMIT} 个依赖 | "
                "— | — | — | — |"
            )
        lines.append("")
    elif len(items) > 1 and coord_summary:
        lines += [
            f"### 依赖坐标分布（前 {min(S6_DETAIL_MD_DEP_SUMMARY_LIMIT, len(coord_summary))} 个）",
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
    if len(items) > 1 and severity_summary:
        lines += [
            "### 严重级别分布",
            "",
            "| 严重级别 | 数量 |",
            "|---|---:|",
        ]
        for severity, count in severity_summary.items():
            lines.append(f"| {_md_cell(severity, 40)} | {count} |")
        lines.append("")
    if len(items) > 1 and change_summary:
        lines += [
            "### 变化类型分布",
            "",
            "| 变化类型 | 数量 |",
            "|---|---:|",
        ]
        for change_type, count in change_summary.items():
            lines.append(f"| {_md_cell(change_type, 120)} | {count} |")
        lines.append("")
    if len(items) > 1 and reason_summary:
        lines += [
            "### 原因分类",
            "",
            "| 原因 | 数量 |",
            "|---|---:|",
        ]
        for reason, count in reason_summary.items():
            lines.append(f"| {_md_cell(reason)} | {count} |")
        lines.append("")

    if len(items) <= S6_DETAIL_MD_FULL_LIMIT:
        priority_header = " 复核优先分数 |" if config.get("show_priority") else ""
        priority_separator = "---:|" if config.get("show_priority") else ""
        lines += [
            "## API 明细（完整）",
            "",
            f"| # | 依赖坐标 | 变更 API |{priority_header} 变化 | 结论 | 原因 | 结论边界 |",
            f"|---:|---|---|{priority_separator}---|---|---|---|",
        ]
        for idx, item in enumerate(items, 1):
            lines.append(_detail_row(
                idx,
                item,
                config.get('conclusion') or '',
                show_priority=bool(config.get("show_priority")),
            ))
        lines.append("")
    else:
        priority_header = " 复核优先分数 |" if config.get("show_priority") else ""
        priority_separator = "---:|" if config.get("show_priority") else ""
        lines += [
            f"## 明细样例（排序前 {S6_DETAIL_MD_SAMPLE_LIMIT} 条）",
            "",
            (
                f"本文件展示 {S6_DETAIL_MD_SAMPLE_LIMIT}/{len(items)} 条；"
                f"同名 CSV 保存全部 {len(items)} 条。"
            ),
            "",
            f"| # | 依赖坐标 | 变更 API |{priority_header} 变化 | 结论 | 原因 | 结论边界 |",
            f"|---:|---|---|{priority_separator}---|---|---|---|",
        ]
        for idx, item in enumerate(items[:S6_DETAIL_MD_SAMPLE_LIMIT], 1):
            lines.append(_detail_row(
                idx,
                item,
                config.get('conclusion') or '',
                show_priority=bool(config.get("show_priority")),
            ))
        lines += [
            "",
            f"未在本 Markdown 展开的记录：{len(items) - S6_DETAIL_MD_SAMPLE_LIMIT} 条。",
            "",
        ]
    return "\n".join(lines) + "\n"


def _write_confirmed_detail_artifacts(report_dir, findings, config):
    """Write every confirmed result in a human-readable, non-prescriptive form."""
    rows = [
        row for row in build_api_result_rows(findings)
        if row.get("conclusion") == "已确认影响"
    ]
    artifacts = {}
    report_path = _deliverables_dir(report_dir)
    csv_path = report_path / config["csv"]
    md_path = report_path / config["md"]
    if len(rows) <= min(8, S6_MAIN_RESULT_LIMIT):
        for stale_path in (csv_path, md_path):
            try:
                stale_path.unlink()
            except FileNotFoundError:
                pass
        return artifacts

    report_path.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "severity",
        "business_entries",
        "modules",
        "coord",
        "old_version",
        "new_version",
        "api",
        "api_signature",
        "change",
        "confirmed_fact",
        "evidence_summary",
        "path_count",
        "occurrence_count",
    ]
    with open_csv_write(csv_path) as output:
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "severity": _csv_cell(row.get("severity") or "未分级"),
                "business_entries": _csv_cell(" | ".join(row.get("business_entries") or [])),
                "modules": _csv_cell(" | ".join(row.get("modules") or [])),
                "coord": _csv_cell(row.get("coord")),
                "old_version": _csv_cell(row.get("old_version")),
                "new_version": _csv_cell(row.get("new_version")),
                "api": _csv_cell(row.get("api")),
                "api_signature": _csv_cell(row.get("api_signature")),
                "change": _csv_cell(row.get("change_without_severity")),
                "confirmed_fact": _csv_cell(
                    _human_reason(row.get("reason")) or "调用链已触达当前系统。"
                ),
                "evidence_summary": _csv_cell(_row_evidence_text(row)),
                "path_count": int(row.get("path_count") or 0),
                "occurrence_count": int(row.get("occurrence_count") or 0),
            })

    lines = [
        f"# {config['title']}",
        "",
        f"- 总数：{len(rows)}",
        f"- 说明：{config['note']}",
        f"- 结构化清单：`{relpath_for_report(csv_path, report_dir)}`",
        "",
    ]
    lines.extend(
        render_impact_distribution(
            findings,
            heading_level=2,
            force=True,
        )
    )
    if len(rows) <= S6_DETAIL_MD_FULL_LIMIT:
        displayed_rows = rows
        lines += [
            "## 已确认影响明细（完整）",
            "",
        ]
    else:
        displayed_rows = rows[:S6_DETAIL_MD_SAMPLE_LIMIT]
        lines += [
            f"## 已确认影响明细（排序前 {len(displayed_rows)} 项）",
            "",
            (
                f"本文件展示 {len(displayed_rows)}/{len(rows)} 项；"
                f"同名 CSV 保存全部 {len(rows)} 项。"
            ),
            "",
        ]
    lines += [
        "| # | 严重级别 | 业务入口 / 模块 | 依赖变化 | API 变化 | 已确认事实 | 证据 |",
        "|---:|---|---|---|---|---|---|",
    ]
    for index, row in enumerate(displayed_rows, 1):
        fact = _human_reason(row.get("reason")) or "调用链已触达当前系统。"
        lines.append(
            f"| {index} | {_md_cell(row.get('severity') or '未分级', 40)} | "
            f"{_business_scope_cell(row)} | {_dependency_change_cell(row)} | "
            f"`{_md_cell(_item_api_label(row), 220)}`<br>"
            f"{_md_cell(row.get('change_without_severity'), 180)} | "
            f"{_md_cell(fact, 320)} | {_md_cell(_row_evidence_text(row), 180)} |"
        )
    lines.append("")
    if len(displayed_rows) < len(rows):
        lines.extend([
            f"未在本 Markdown 展开的记录：{len(rows) - len(displayed_rows)} 项。",
            "",
        ])
    alerts_path = str(((findings.get("artifacts") or {}).get("alerts_csv") or "")).strip()
    if alerts_path:
        lines.extend([
            f"逐链路物理记录：{_report_link(alerts_path, '逐链路证据台账')}。",
            "",
        ])
    write_text(str(md_path), "\n".join(lines))
    artifacts["confirmed_csv"] = relpath_for_report(csv_path, report_dir)
    artifacts["confirmed_md"] = relpath_for_report(md_path, report_dir)
    return artifacts


def write_bucket_detail_artifacts(report_dir, findings, bucket_name):
    """Write full bucket details outside the main Markdown report."""
    config = S6_DETAIL_BUCKETS.get(bucket_name) or {}
    if bucket_name == "confirmed":
        return _write_confirmed_detail_artifacts(report_dir, findings, config)
    items = list((findings or {}).get(bucket_name) or [])
    if bucket_name == "not_analyzed":
        items = [
            item for item in items
            if item.get("user_conclusion") not in {"可能影响", "需要补充输入"}
        ]
    if bucket_name == "uncertain":
        items = _order_uncertain_items_by_dependency(items)
    else:
        items = sorted(
            items,
            key=lambda item: (
                _severity_rank(item.get("severity")),
                -len(item.get("call_paths") or []),
                str(item.get("coord") or ""),
                str(item.get("api") or item.get("api_name") or ""),
                str(item.get("api_signature") or ""),
            ),
        )
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
    ]
    if bucket_name == "uncertain":
        fieldnames.extend([
            "dependency_priority_rank",
            "dependency_top_priority_score",
            "dependency_total_priority_score",
            "dependency_uncertain_api_count",
        ])
    fieldnames.extend([
        "priority_score",
        "uncertainty_kind",
        "reason_code",
        "reason",
        "user_reason",
    ])
    with open_csv_write(csv_path) as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in items:
            row = {key: _csv_cell(item.get(key)) for key in fieldnames}
            chain_view = _csv_chain_view(item)
            row["conclusion"] = _csv_cell(_bucket_csv_conclusion(bucket_name, item))
            row["change_summary"] = _change_summary(item)
            conclusion = _bucket_csv_conclusion(bucket_name, item)
            objective_reason = _objective_item_reason(item, conclusion)
            row["review_reason"] = _csv_cell(objective_reason)
            row["reason"] = ""
            row["user_reason"] = ""
            row["chain_summary"] = _csv_cell(chain_view["summary"])
            row["chain_entry"] = _csv_cell(chain_view["entry"])
            row["chain_target"] = _csv_cell(chain_view["target"])
            row["chain_hop_count"] = _csv_cell(chain_view["hop_count"])
            row["chain_detail"] = _csv_cell(chain_view["detail"])
            writer.writerow(row)

    write_text(
        str(md_path),
        build_bucket_detail_markdown(
            config,
            items,
            relpath_for_report(csv_path, report_dir),
            alerts_available=bool(
                ((findings.get("artifacts") or {}).get("alerts_csv") or "")
            ),
        ),
    )
    artifacts[f"{bucket_name}_csv"] = relpath_for_report(csv_path, report_dir)
    artifacts[f"{bucket_name}_md"] = relpath_for_report(md_path, report_dir)
    return artifacts


def _bucket_csv_conclusion(bucket_name, item):
    if bucket_name == "uncertain":
        return _uncertain_conclusion(item)
    structural_conclusions = {
        "confirmed": "已确认影响",
        "probable_impact": "可能影响",
        "not_impacted": "已确认不受影响",
        "needs_input": "输入不足，结论未确定",
        "not_analyzed": "未完成分析",
        "not_found": "未发现静态调用路径",
    }
    if bucket_name in structural_conclusions:
        return structural_conclusions[bucket_name]
    user_conclusion = str((item or {}).get("user_conclusion") or "").strip()
    if user_conclusion:
        return user_conclusion
    return "结论未确定"


def _csv_chain_view(item):
    item = item or {}
    nodes = []
    for path in item.get("call_paths") or []:
        nodes = _split_csv_chain_nodes(path)
        if nodes:
            break
    if not nodes:
        for evidence_path in _normalize_evidence_paths(
            item.get("evidence_paths")
        )[0]:
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
        "summary": (
            f"入口：{entry}；终点：{target}；{hop_count} 次调用（{len(nodes)} 个节点）"
            if len(nodes) >= 2 else f"未形成完整链路；目标 API：{target}"
        ),
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
    if not isinstance(evidence_path, list):
        return nodes
    for edge in evidence_path:
        if not isinstance(edge, dict):
            continue
        caller = str(edge.get("caller_symbol") or "").strip()
        callee = str(edge.get("callee_key") or "").strip()
        if caller and (not nodes or nodes[-1] != caller):
            nodes.append(caller)
        if callee and (not nodes or nodes[-1] != callee):
            nodes.append(callee)
    return nodes


def _normalize_evidence_paths(value):
    if value is None:
        return [], True
    if not isinstance(value, list):
        return [], False
    normalized_paths = []
    valid = True
    for evidence_path in value:
        if not isinstance(evidence_path, list):
            valid = False
            continue
        normalized_edges = []
        for edge in evidence_path:
            if not isinstance(edge, dict):
                valid = False
                continue
            normalized_edges.append(dict(edge))
        if normalized_edges:
            normalized_paths.append(normalized_edges)
        elif evidence_path:
            valid = False
    return normalized_paths, valid


def write_not_found_detail_artifacts(report_dir, findings):
    return write_bucket_detail_artifacts(report_dir, findings, "not_found")


def write_s6_detail_artifacts(report_dir, findings):
    artifacts = {}
    for bucket_name in S6_DETAIL_BUCKETS:
        artifacts.update(write_bucket_detail_artifacts(report_dir, findings, bucket_name))
    artifacts.update(write_changed_api_split_artifacts(report_dir))
    return artifacts


def write_analysis_scope_artifact(report_dir, findings):
    """Materialize the exact Step5 scope as a stable, human-readable boundary.

    The runtime snapshot remains the machine source of truth. This page exposes
    the same facts without inferring a full analysis when the snapshot is absent.
    """
    scope = dict((findings or {}).get("analysis_scope") or {})
    mode = str(scope.get("mode") or "").strip()
    included = sorted({str(item).strip() for item in scope.get("included_dependency_coords") or [] if str(item).strip()})
    excluded = sorted({str(item).strip() for item in scope.get("excluded_dependency_coords") or [] if str(item).strip()})
    selected_names = sorted({str(item).strip() for item in scope.get("selected_names") or [] if str(item).strip()})
    available_count = int(scope.get("available_dependency_count") or 0)
    included_count = int(scope.get("included_dependency_count") or len(included))
    total_api_count = int(scope.get("total_api_count") or 0)
    analyzed_api_count = int(scope.get("analyzed_api_count") or 0)

    if mode == "full":
        mode_label = "全量分析"
        boundary = (
            "本轮覆盖依赖 API 变化分析识别出的全部变化依赖及其变化 API；"
            "这里的“全量”不等于覆盖所有未变化依赖，也不包含 JAR 中未被 API 比对识别的资源、SPI 配置或清单变化。"
        )
    elif mode == "partial":
        mode_label = "部分分析"
        boundary = (
            "本轮只分析用户选中的变化依赖。未选依赖不在本报告结论范围内，"
            "该范围不支持整个系统不受影响的结论。"
        )
    else:
        if scope.get("validation_status") == "invalid":
            mode_label = "范围无法核验"
            boundary = (
                "分析范围快照与变化 API 证据未通过一致性校验；"
                "最终报告不支持全量分析或全局无影响结论。"
            )
        else:
            mode_label = "范围未记录"
            boundary = (
                "缺少可核验的分析范围快照，无法证明本轮覆盖了全部变化依赖；"
                "最终报告不支持全量分析或全局无影响结论。"
            )

    lines = [
        "# 本轮分析范围",
        "",
        "> 这份文件回答“最终结论具体覆盖了哪些变化依赖和 API”。",
        "",
        "## 范围结论",
        "",
        f"- **模式**：{mode_label}",
        (
            f"- **变化依赖**：总数 {available_count}；"
            f"纳入本轮分析 {included_count}；"
            f"未纳入 {max(available_count - included_count, 0)}"
        ),
        (
            f"- **变化 API**：总数 {total_api_count}；"
            f"纳入本轮分析 {analyzed_api_count}；"
            f"未纳入 {max(total_api_count - analyzed_api_count, 0)}"
        ),
        f"- **结论边界**：{boundary}",
        "",
    ]
    if included:
        lines.extend(["## 已纳入的依赖", ""])
        lines.extend(f"- `{coord}`" for coord in included)
        lines.append("")
    if excluded:
        lines.extend([
            "## 未纳入的依赖",
            "",
            "| 依赖 | 未纳入原因 |",
            "|---|---|",
        ])
        lines.extend(
            f"| `{coord}` | 用户指定的分析范围未包含该依赖 |"
            for coord in excluded
        )
        lines.append("")
    if selected_names:
        lines.extend([
            "## 用户输入中使用的名称",
            "",
            *[f"- `{name}`" for name in selected_names],
            "",
        ])
    source_usage = dict((findings or {}).get("source_usage") or {})
    if source_usage:
        lines.extend([
            "## 源码辅助分析",
            "",
            f"- **用户选择**：{source_usage.get('label') or '源码选择记录缺失'}",
            f"- **作用和边界**：{source_usage.get('effect') or '未记录'}",
            f"- **映射数量**：{int(source_usage.get('mapped_count') or 0)}",
            f"- **覆盖状态**：`{source_usage.get('coverage_status') or 'not_provided'}`",
        ])
        source_review = (
            Path(report_dir) / "evidence" / "source_analysis" / "review.md"
        )
        if source_review.is_file():
            lines.append(
                "- **人工复核入口**："
                "[源码辅助证据](../evidence/source_analysis/review.md)"
            )
        lines.append("")
    evidence_links = [
        (
            "变化依赖摘要",
            "changed_dependencies.md",
            "evidence/api_changes/changed_dependencies.md",
        ),
        ("变化 API 全集", "all_changed_apis.csv", "evidence/api_changes/all_changed_apis.csv"),
        ("逐 API 系统触达台账", "alerts.csv", "evidence/call_chain/alerts.csv"),
    ]
    lines.extend(["## 可核验证据", ""])
    for label, file_name, relative_path in evidence_links:
        if (Path(report_dir) / relative_path).is_file():
            lines.append(f"- {label}：[{file_name}](../{relative_path})")
        else:
            lines.append(f"- {label}：本轮未生成，不作为结论依据。")
    lines.append("")

    output_path = _deliverables_dir(report_dir) / "analysis-scope.md"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_text(str(output_path), "\n".join(lines))
    return relpath_for_report(output_path, report_dir)


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
            "csv_path": str(artifacts.get(csv_key) or ""),
            "md_path": str(artifacts.get(md_key) or ""),
            "title": config.get("title") or bucket_name,
        })
    return rows


def _write_changed_api_part(path, fieldnames, rows):
    with open_csv_write(path) as output:
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


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
        source = open_csv_read(source_path)
    except OSError:
        return artifacts

    part_count = 0
    row_count = 0
    try:
        with source:
            reader = csv.DictReader(source)
            fieldnames = list(reader.fieldnames or [])
            if not fieldnames:
                return artifacts
            part_rows = []
            for row in reader:
                part_rows.append(row)
                row_count += 1
                if len(part_rows) == S6_CHANGED_API_SPLIT_ROWS:
                    part_count += 1
                    part_path = split_dir / f"all_changed_apis_part_{part_count:03d}.csv"
                    _write_changed_api_part(part_path, fieldnames, part_rows)
                    part_rows = []
            if part_rows:
                part_count += 1
                part_path = split_dir / f"all_changed_apis_part_{part_count:03d}.csv"
                _write_changed_api_part(part_path, fieldnames, part_rows)
    except (OSError, csv.Error):
        return artifacts

    if not row_count:
        return artifacts

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


def _canonical_identity_coord(value):
    """Remove report-only version decorations from a dependency coordinate."""
    text = str(value or '').strip()
    return re.sub(
        r"\s*[（(][^（）()]*?(?:→|->)[^（）()]*?[）)]\s*$",
        "",
        text,
    ).strip()


def _canonical_identity_signature(value):
    raw = str(value or "").strip()
    normalized = normalize_signature_for_identity(raw)
    if normalized:
        return normalized
    return "".join(raw.replace("$", ".").split())


def _canonical_identity_api(value, signature):
    """Keep the signature in its own identity field when a display label repeats it."""
    api = str(value or '').strip()
    normalized_signature = _canonical_identity_signature(signature)
    signature_start = api.find("(")
    if (
        normalized_signature
        and signature_start >= 0
        and api.endswith(")")
        and signatures_match_identity(
            api[signature_start:],
            normalized_signature,
        )
    ):
        api = api[:signature_start].rstrip()
    return api


def _canonical_report_identity(payload):
    payload = payload or {}
    signature = _canonical_identity_signature(
        payload.get('api_signature', '')
    )
    return (
        _canonical_identity_coord(payload.get('coord', '')),
        _canonical_identity_api(
            payload.get('api_name') or payload.get('api') or '',
            signature,
        ),
        signature,
        str(payload.get('symbol_kind', '') or '').strip(),
        str(payload.get('change_type', '') or '').strip(),
    )


def build_api_identity_key(payload):
    return _canonical_report_identity(payload)


def _identity_is_complete(identity):
    return bool(identity and identity[0] and identity[1])


def _summary_result_identity_rows(summary):
    bucket_labels = {
        "reachable_apis": "confirmed",
        "not_impacted_apis": "not_impacted",
        "uncertain_apis": "review",
        "not_analyzed_apis": "review",
        "not_found_apis": "not_found",
    }
    rows = []
    for bucket_name, bucket_label in bucket_labels.items():
        for item in (summary or {}).get(bucket_name) or []:
            if isinstance(item, dict):
                rows.append((build_api_identity_key(item), bucket_label))
    return rows


def _downgrade_unverified_certain_results(call_summary, verified_identities):
    moved = []
    for bucket_name in ("reachable_apis", "not_impacted_apis"):
        retained = []
        for item in (call_summary or {}).get(bucket_name) or []:
            identity = build_api_identity_key(item)
            if identity in verified_identities:
                retained.append(item)
                continue
            downgraded = dict(item)
            downgraded.update({
                "user_conclusion": "需要补充输入",
                "reason_code": "S6_EVIDENCE_IDENTITY_MISMATCH",
                "origin_step": "step6",
                "reason": (
                    "变化 API 清单、系统触达汇总和逐链路台账未能共同确认该项。"
                ),
                "user_reason": (
                    "变化 API 清单、系统触达汇总和逐链路台账未能共同确认该项。"
                ),
                "call_paths": [],
                "key_evidence": "",
            })
            moved.append(downgraded)
        call_summary[bucket_name] = retained
    if moved:
        existing = list(call_summary.get("not_analyzed_apis") or [])
        existing_identities = {
            build_api_identity_key(item)
            for item in existing
            if isinstance(item, dict)
        }
        existing.extend(
            item for item in moved
            if build_api_identity_key(item) not in existing_identities
        )
        call_summary["not_analyzed_apis"] = existing
        call_summary["reachable"] = len(
            call_summary.get("reachable_apis") or []
        )
        call_summary["not_impacted"] = len(
            call_summary.get("not_impacted_apis") or []
        )
        call_summary["not_analyzed"] = len(existing)
        diagnostic_guidance = list(
            call_summary.get("diagnostic_guidance") or []
        )
        if not any(
            isinstance(item, dict)
            and item.get("reason_code") == "S6_EVIDENCE_IDENTITY_MISMATCH"
            for item in diagnostic_guidance
        ):
            diagnostic_guidance.append({
                "reason_code": "S6_EVIDENCE_IDENTITY_MISMATCH",
                "origin_step": "step6",
                "observed_scope": "api",
                "affected_api_count": len(moved),
                "observed_failure_count": len(moved),
                "blocking": True,
                "sample_apis": [
                    " | ".join(
                        value for value in (
                            str(item.get("coord") or ""),
                            str(item.get("api") or ""),
                            str(item.get("api_signature") or ""),
                        )
                        if value
                    )
                    for item in moved[:5]
                ],
            })
        call_summary["diagnostic_guidance"] = diagnostic_guidance


def _validate_scope_consistency(
    *,
    scope,
    target_api_count,
    changed_apis,
    diagnostics,
    selection_path,
):
    if _artifact_has_diagnostic(diagnostics, "step5_selection"):
        return
    mode = str((scope or {}).get("mode") or "")
    analyzed = int((scope or {}).get("analyzed_api_count") or 0)
    total = int((scope or {}).get("total_api_count") or 0)
    changed_identities = {
        build_api_identity_key(item)
        for item in changed_apis or []
        if _identity_is_complete(build_api_identity_key(item))
    }
    issues = []
    if mode == "full":
        if not (
            analyzed == total == int(target_api_count)
        ):
            issues.append(
                "full scope API counts do not match the Step5 target count"
            )
    elif mode == "partial":
        if analyzed != int(target_api_count) or total < analyzed:
            issues.append(
                "partial scope API counts do not match the Step5 target count"
            )
    if (
        not _artifact_has_diagnostic(diagnostics, "changed_apis")
        and total != len(changed_identities)
    ):
        issues.append(
            "scope total_api_count does not match unique changed API identities"
        )
    if not issues:
        return
    _invalidate_analysis_scope(
        scope, "分析范围数量与变化 API 证据不一致"
    )
    _record_content_diagnostic(
        diagnostics,
        artifact="step5_selection",
        stage="identity_consistency",
        path=selection_path,
        message="; ".join(dict.fromkeys(issues)),
    )


def _validate_cross_artifact_identities(
    *,
    call_summary,
    changed_apis,
    impact_overview,
    scope_mode,
    diagnostics,
    changed_apis_path,
    alerts_path,
):
    summary_rows = _summary_result_identity_rows(call_summary)
    summary_identities = {
        identity for identity, _bucket in summary_rows
        if _identity_is_complete(identity)
    }
    summary_bucket_map = {
        identity: bucket
        for identity, bucket in summary_rows
        if _identity_is_complete(identity)
    }
    changed_rows_by_identity = defaultdict(list)
    for item in changed_apis or []:
        identity = build_api_identity_key(item)
        if _identity_is_complete(identity):
            changed_rows_by_identity[identity].append(item)
    changed_identities = set(changed_rows_by_identity)
    overview_items = list((impact_overview or {}).get('apis') or [])
    overview_by_identity = {
        build_api_identity_key(item): item
        for item in overview_items
        if _identity_is_complete(build_api_identity_key(item))
    }
    alert_identities = {
        build_api_identity_key(item)
        for item in overview_items
        if _identity_is_complete(build_api_identity_key(item))
    }
    alert_bucket_map = {
        build_api_identity_key(item): str(item.get('bucket') or '')
        for item in overview_items
        if _identity_is_complete(build_api_identity_key(item))
    }

    if summary_identities - changed_identities or (
        scope_mode == 'full' and changed_identities != summary_identities
    ):
        if not _artifact_has_diagnostic(diagnostics, 'changed_apis'):
            _record_content_diagnostic(
                diagnostics,
                artifact='changed_apis',
                stage='identity_consistency',
                path=changed_apis_path,
                message=(
                    "changed API identities do not match the Step5 result set"
                ),
            )

    alert_identity_mismatch = alert_identities != summary_identities
    alert_bucket_mismatch = any(
        alert_bucket_map.get(identity) != bucket
        for identity, bucket in summary_bucket_map.items()
        if identity in alert_bucket_map
    )
    if (
        (alert_identity_mismatch or alert_bucket_mismatch)
        and (summary_identities or alert_identities)
        and not _artifact_has_diagnostic(diagnostics, 'call_chain_alerts')
    ):
        _record_content_diagnostic(
            diagnostics,
            artifact='call_chain_alerts',
            stage='identity_consistency',
            path=alerts_path,
            message=(
                "alerts identities or conclusion buckets do not match "
                "the Step5 summary"
            ),
        )

    # Step4's changed API inventory is the source of truth for the change
    # severity and compared versions. Step5 repeats these fields only to make
    # its own artifacts self-contained. Normalize those repeated fields before
    # assigning report buckets so a stale summary cannot turn P2 into P0 or
    # display a version transition that was never compared.
    field_value_names = {
        "severity": "severity_values",
        "old_version": "old_version_values",
        "new_version": "new_version_values",
    }
    conflicted_changed_identities = set()
    summary_field_mismatches = []
    alert_field_mismatches = []
    changed_field_conflicts = []
    summary_items_by_identity = defaultdict(list)
    for bucket_name in (
        "reachable_apis",
        "not_impacted_apis",
        "uncertain_apis",
        "not_analyzed_apis",
        "not_found_apis",
    ):
        for item in (call_summary or {}).get(bucket_name) or []:
            if not isinstance(item, dict):
                continue
            identity = build_api_identity_key(item)
            if _identity_is_complete(identity):
                summary_items_by_identity[identity].append(item)

    for identity, source_rows in changed_rows_by_identity.items():
        overview_item = overview_by_identity.get(identity)
        for field, overview_field in field_value_names.items():
            source_values = {
                str(row.get(field) or "").strip()
                for row in source_rows
                if str(row.get(field) or "").strip()
            }
            if len(source_values) > 1:
                conflicted_changed_identities.add(identity)
                changed_field_conflicts.append(
                    f"{field} has conflicting values for one API identity"
                )
                continue
            if not source_values:
                continue
            source_value = next(iter(source_values))
            for summary_item in summary_items_by_identity.get(identity) or []:
                repeated_value = str(summary_item.get(field) or "").strip()
                if repeated_value and repeated_value != source_value:
                    summary_field_mismatches.append(
                        f"{field} does not match changed API inventory"
                    )
                summary_item[field] = source_value
            if overview_item is None:
                continue
            repeated_values = {
                str(value or "").strip()
                for value in overview_item.get(overview_field) or []
                if str(value or "").strip()
            }
            if repeated_values and repeated_values != {source_value}:
                alert_field_mismatches.append(
                    f"{field} does not match changed API inventory"
                )
            overview_item[overview_field] = [source_value]

    if (
        changed_field_conflicts
        and not _artifact_has_diagnostic(diagnostics, "changed_apis")
    ):
        _record_content_diagnostic(
            diagnostics,
            artifact="changed_apis",
            stage="field_consistency",
            path=changed_apis_path,
            message="; ".join(dict.fromkeys(changed_field_conflicts)),
        )
    if (
        summary_field_mismatches
        and not _artifact_has_diagnostic(diagnostics, "call_chain_summary")
    ):
        _record_content_diagnostic(
            diagnostics,
            artifact="call_chain_summary",
            stage="field_consistency",
            path=Path(alerts_path).parent / "summary.json",
            message="; ".join(dict.fromkeys(summary_field_mismatches)),
        )
    if (
        alert_field_mismatches
        and not _artifact_has_diagnostic(diagnostics, "call_chain_alerts")
    ):
        _record_content_diagnostic(
            diagnostics,
            artifact="call_chain_alerts",
            stage="field_consistency",
            path=alerts_path,
            message="; ".join(dict.fromkeys(alert_field_mismatches)),
        )
    independently_verified = {
        identity
        for identity, bucket in summary_bucket_map.items()
        if (
            identity in changed_identities
            and alert_bucket_map.get(identity) == bucket
            and identity not in conflicted_changed_identities
        )
    }
    _downgrade_unverified_certain_results(
        call_summary,
        independently_verified,
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
    if status == "reachable":
        return "confirmed"
    if status == "not_impacted":
        return "not_impacted"
    if status in {"uncertain", "not_analyzed"}:
        return "review"
    if status in {"not_found_in_static_analysis", "not_reachable"}:
        return "not_found"
    return "unknown"


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
        item.get("api_signature", ""),
        item.get("symbol_kind", ""),
        item.get("change_type", ""),
    )


def build_impact_overview(alert_rows):
    """Convert Step5 alerts.csv into a human-first "what is affected" view."""
    api_map = {}
    entry_map = {}
    seen_rows = set()
    occurrence_values = {}
    entry_occurrence_values = {}
    valid_record_count = 0
    all_business_entries = set()
    for row in alert_rows or []:
        row_fingerprint = tuple(
            sorted(
                (str(key), str(value or '').strip())
                for key, value in (row or {}).items()
            )
        )
        if row_fingerprint in seen_rows:
            continue
        seen_rows.add(row_fingerprint)
        api = str(row.get("changed_symbol") or "").strip()
        coord = str(row.get("target_coord") or "").strip()
        if not api:
            continue
        valid_record_count += 1
        bucket = _impact_bucket(row)
        key = (
            coord,
            api,
            _canonical_identity_signature(row.get("api_signature")),
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
            "occurrence_count": 0,
            "entries": set(),
            "entries_by_status": defaultdict(set),
            "paths": [],
            "paths_by_status": defaultdict(list),
            "occurrence_counts_by_status": defaultdict(int),
            "files": set(),
            "modules": set(),
            "actions": set(),
            "reasons": set(),
            "api_ids": set(),
            "severities": set(),
            "old_versions": set(),
            "new_versions": set(),
        })
        if _bucket_rank(bucket) < _bucket_rank(item["bucket"]):
            item["bucket"] = bucket
        status = str(row.get("path_status") or row.get("api_status") or "unknown").strip() or "unknown"
        try:
            occurrence_count = max(int(str(row.get("path_occurrence_count") or "1")), 1)
        except ValueError:
            occurrence_count = 1
        api_id = str(row.get("api_id") or "").strip()
        if api_id:
            item["api_ids"].add(api_id)
        for field, target in (
            ("severity", item["severities"]),
            ("old_version", item["old_versions"]),
            ("new_version", item["new_versions"]),
        ):
            value = str(row.get(field) or "").strip()
            if value:
                target.add(value)

        entry = str(row.get("business_entry") or row.get("chain_entry") or "").strip()
        if not entry:
            consumer_class = str(row.get("consumer_class") or "").strip()
            consumer_method = str(row.get("consumer_method") or "").strip()
            entry = ".".join(part for part in (consumer_class, consumer_method) if part)
        if entry:
            item["entries"].add(entry)
            item["entries_by_status"][status].add(entry)
            all_business_entries.add(entry)

        path_text = str(row.get("path_text") or "").strip()
        evidence_files = tuple(
            sorted(
                raw_file.strip()
                for raw_file in str(row.get("evidence_files") or "").split("|")
                if raw_file.strip()
            )
        )
        # A single physical chain can be emitted more than once with different
        # explanatory text. Reasons and review labels are metadata, not extra
        # evidence hits. Count the greatest recorded occurrence value once for
        # the same API/status/path/entry/evidence identity.
        occurrence_key = (
            key,
            status,
            path_text,
            "" if path_text else entry,
            evidence_files,
        )
        previous_occurrence_count = occurrence_values.get(occurrence_key, 0)
        occurrence_delta = max(
            occurrence_count - previous_occurrence_count,
            0,
        )
        if occurrence_key not in occurrence_values:
            item["status_counts"][status] += 1
        occurrence_values[occurrence_key] = max(
            previous_occurrence_count,
            occurrence_count,
        )
        item["occurrence_count"] += occurrence_delta
        item["occurrence_counts_by_status"][status] += occurrence_delta
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
        action = str(row.get("action") or row.get("review_focus") or "").strip()
        if action:
            item["actions"].add(action)
        reason = str(
            row.get("reason") or row.get("review_reason") or row.get("stop_reason") or ""
        ).strip()
        if reason:
            item["reasons"].add(reason)

        if bucket == "confirmed" and entry:
            entry_item = entry_map.setdefault(entry, {
                "entry": entry,
                "api_identities": set(),
                "api_labels": set(),
                "dependencies": set(),
                "paths": [],
                "files": set(),
                "modules": set(),
                "occurrence_count": 0,
            })
            entry_item["api_identities"].add(key)
            entry_item["api_labels"].add(api)
            if coord:
                entry_item["dependencies"].add(coord)
            entry_occurrence_key = (
                entry,
                key,
                status,
                path_text,
                evidence_files,
            )
            previous_entry_occurrence = entry_occurrence_values.get(
                entry_occurrence_key,
                0,
            )
            entry_item["occurrence_count"] += max(
                occurrence_count - previous_entry_occurrence,
                0,
            )
            entry_occurrence_values[entry_occurrence_key] = max(
                previous_entry_occurrence,
                occurrence_count,
            )
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
            "path_count": _distinct_call_path_count(item["paths"]),
            "occurrence_count": item["occurrence_count"],
            "entry_count": len(item["entries"]),
            "module_count": len(item["modules"]),
            "sample_modules": sorted(item["modules"])[:5],
            "sample_entries": sorted(item["entries"])[:3],
            "all_entries_by_status": {
                status: sorted(entries)
                for status, entries in sorted(
                    item["entries_by_status"].items()
                )
            },
            "entry_counts_by_status": {
                status: len(entries)
                for status, entries in sorted(
                    item["entries_by_status"].items()
                )
            },
            "entries_by_status": {
                status: sorted(entries)[:5]
                for status, entries in sorted(
                    item["entries_by_status"].items()
                )
            },
            "sample_paths": sorted(item["paths"])[:2],
            "paths": sorted(item["paths"])[:10],
            "paths_by_status": {
                status: sorted(paths)[:10]
                for status, paths in sorted(
                    item["paths_by_status"].items()
                )
            },
            "path_counts_by_status": {
                status: _distinct_call_path_count(paths)
                for status, paths in sorted(
                    item["paths_by_status"].items()
                )
            },
            "logical_path_counts_by_status": {
                status: _distinct_call_path_count(paths)
                for status, paths in sorted(
                    item["paths_by_status"].items()
                )
            },
            "occurrence_counts_by_status": dict(sorted(
                item["occurrence_counts_by_status"].items()
            )),
            "sample_files": [_short_path(path) for path in sorted(item["files"])[:3]],
            "sample_actions": sorted(item["actions"])[:2],
            "sample_reasons": sorted(item["reasons"])[:2],
            "severity_values": sorted(item["severities"]),
            "old_version_values": sorted(item["old_versions"]),
            "new_version_values": sorted(item["new_versions"]),
        })

    entry_items = []
    for item in entry_map.values():
        entry_items.append({
            "entry": item["entry"],
            "api_count": len(item["api_identities"]),
            "dependency_count": len(item["dependencies"]),
            "path_count": _distinct_call_path_count(item["paths"]),
            "occurrence_count": item["occurrence_count"],
            "sample_modules": sorted(item["modules"])[:3],
            "sample_apis": sorted(item["api_labels"])[:3],
            "sample_dependencies": sorted(item["dependencies"])[:3],
            "sample_paths": sorted(item["paths"])[:2],
            "sample_files": [_short_path(path) for path in sorted(item["files"])[:2]],
        })

    api_items = sorted(api_items, key=_impact_sort_key)
    entry_items = sorted(entry_items, key=lambda x: (-x["api_count"], -x["path_count"], x["entry"]))
    return {
        "record_count": valid_record_count,
        "logical_path_count": sum(
            int(item.get("path_count") or 0) for item in api_items
        ),
        "occurrence_count": sum(
            int(item.get("occurrence_count") or 0) for item in api_items
        ),
        "dependency_count": len({
            item.get("coord")
            for item in api_items
            if item.get("coord")
        }),
        "business_entry_count": len(all_business_entries),
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
                'deliverables/all-affected-dependencies.md（完整依赖分析明细）',
                'deliverables/all-affected-dependencies.csv（完整依赖分析表格）',
                'deliverables/all-impact-details.md（完整 API 分析与调用关系明细）',
                'deliverables/all-impact-details.csv（完整 API 与调用关系表格）',
                'evidence/call_chain/alerts.csv（原始分析记录）',
                'evidence/api_changes/all_changed_apis.csv（变化 API 原始清单）',
            ],
            'sampling_guide': [],
        },
        'generated_at':        datetime.now().isoformat(timespec='seconds'),
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
        'uncertain_dependency_summary': [],
        'uncertainty_kind_summary': {},
        'not_analyzed_reason_summary': {},
        'not_found_reason_summary': {},
        'diagnostic_guidance_schema': REASON_GUIDANCE_SCHEMA,
        'diagnostic_guidance': [],
        'user_conclusion_summary': {},
        'module_impacts':      {},
        'dep_changes_summary': {},
        'dependency_changes':  [],
        'changed_api_inventory': [],
        'call_chain_target_count': 0,
        'per_dependency_results': [],
        'impact_overview': {
            'apis': [],
            'confirmed_apis': [],
            'review_apis': [],
            'not_found_apis': [],
            'business_entries': [],
        },
        'coverage': {},
        'analysis_scope': {},
        'diagnostics': [],
        'artifacts': {},
    }
    diagnostics = findings['diagnostics']

    for key, path in (
        ('dependency_changes_csv', _dep_changes_path(d)),
        ('alerts_csv', _call_chain_dir(d) / 'alerts.csv'),
        (
            'bytecode_unresolved_csv',
            _call_chain_dir(d) / 'bytecode_unresolved.csv',
        ),
        ('changed_apis_csv', _api_changes_dir(d) / 'all_changed_apis.csv'),
        (
            'build_provenance_json',
            _evidence_dir(d, EVIDENCE_DEPENDENCIES_DIRNAME)
            / 'build_provenance.json',
        ),
    ):
        if path.is_file():
            findings['artifacts'][key] = relpath_for_report(path, d)

    coverage_path = _coverage_path(d)
    findings['coverage'] = load_json(
        coverage_path,
        diagnostics=diagnostics,
        artifact='coverage',
        required=True,
    )
    _validate_coverage_contract(
        coverage_path, findings['coverage'], diagnostics
    )
    selection_path = _step5_selection_path(d)
    findings['analysis_scope'] = load_json(
        selection_path,
        diagnostics=diagnostics,
        artifact='step5_selection',
        required=True,
    )
    _validate_analysis_scope_contract(
        selection_path, findings['analysis_scope'], diagnostics
    )

    # Step 2 上下文
    context_path = _context_path(d)
    ctx = load_json(
        context_path, diagnostics=diagnostics, artifact='context'
    )
    _validate_context_contract(context_path, ctx, diagnostics)
    findings['context'] = {
        'jdk':        f"{ctx.get('jdk_base','?')} → {ctx.get('jdk_current','?')}",
        'springboot': f"{ctx.get('springboot_base','?')} → {ctx.get('springboot_current','?')}",
        'build_tool': ctx.get('build_tool', '?'),
        'jdk_upgraded': ctx.get('jdk_upgraded', False),
        'sb_major':     ctx.get('springboot_major_upgrade', False),
        'tech_flags':   [k for k, v in ctx.get('tech_flags', {}).items() if v],
    }

    # Step 1 依赖变更统计
    dep_rows = load_csv(
        _dep_changes_path(d), diagnostics=diagnostics, artifact='dependency_changes'
    )
    dep_change_lookup = {}
    dep_counts = defaultdict(int)
    for row in dep_rows:
        dep_counts[row.get('change_type', '未知')] += 1
        coord = row.get('coord', '')
        if coord:
            dep_change_lookup[coord] = row
    findings['dep_changes_summary'] = dict(dep_counts)
    findings['dependency_changes'] = [dict(row) for row in dep_rows]

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

    dep_compat_rows = load_csv(
        static_dir / "s3_dependency_compat.csv",
        diagnostics=diagnostics,
        artifact='step3_dependency_compat',
    )
    findings['scan_stats']['dep_compat'] = len(dep_compat_rows)
    if dep_compat_rows:
        by_type = defaultdict(int)
        compile_hits = 0
        by_coord = defaultdict(int)
        for row in dep_compat_rows:
            by_type[row.get('风险类型', '未知')] += 1
            by_coord[row.get('坐标', '未知依赖')] += 1
            if (row.get('依赖范围') or row.get('scope')) == 'compile':
                compile_hits += 1
        findings['dep_compat_summary'] = {
            'total': len(dep_compat_rows),
            'compile_scope': compile_hits,
            'by_type': dict(sorted(by_type.items())),
            'top_coords': sorted(by_coord.items(), key=lambda x: (-x[1], x[0]))[:10],
            'top_rows': dep_compat_rows[:10],
        }

    # Step 5 汇总先决定逐链路台账是否应当存在。零变化 API 的正式
    # skipped 结果不生成 alerts.csv，这不是证据缺口。
    call_summary_path = _call_chain_dir(d) / "summary.json"
    call_summary = load_json(
        call_summary_path,
        diagnostics=diagnostics,
        artifact='call_chain_summary',
        required=True,
    )
    _validate_call_summary_contract(
        call_summary_path, call_summary, diagnostics
    )
    target_api_count = _call_summary_target_count(call_summary)
    findings['call_chain_target_count'] = target_api_count

    # Step 4 jar 变更
    changed_apis_path = _api_changes_dir(d) / "all_changed_apis.csv"
    changed_apis = load_csv(
        changed_apis_path,
        diagnostics=diagnostics,
        artifact='changed_apis',
        required=True,
    )
    _validate_csv_contract(
        changed_apis_path,
        diagnostics=diagnostics,
        artifact='changed_apis',
        required_column_groups=(
            {'coord'},
            {'api_name', 'api', 'changed_symbol'},
        ),
        require_data=target_api_count > 0,
    )
    if _changed_api_diagnostic_invalidates_scope(diagnostics):
        _invalidate_analysis_scope(
            findings["analysis_scope"],
            "变化 API 全集未通过证据合同校验",
        )
    _validate_scope_consistency(
        scope=findings['analysis_scope'],
        target_api_count=target_api_count,
        changed_apis=changed_apis,
        diagnostics=diagnostics,
        selection_path=selection_path,
    )
    scope_mode = str(
        (findings.get('analysis_scope') or {}).get('mode') or ''
    ).strip()
    changed_count_mismatch = (
        target_api_count > 0
        and (
            len(changed_apis) < target_api_count
            or (scope_mode == 'full' and len(changed_apis) != target_api_count)
        )
    )
    if (
        changed_count_mismatch
        and not _artifact_has_diagnostic(diagnostics, 'changed_apis')
    ):
        _record_content_diagnostic(
            diagnostics,
            artifact='changed_apis',
            stage='csv_consistency',
            path=changed_apis_path,
            message=(
                "changed API row count does not match the Step5 target count"
            ),
        )
    if _changed_api_diagnostic_invalidates_scope(diagnostics):
        _invalidate_analysis_scope(
            findings["analysis_scope"],
            "变化 API 范围未通过证据合同校验",
        )
    findings['scan_stats']['changed_apis_total'] = len(changed_apis)
    findings['changed_api_inventory'] = [dict(row) for row in changed_apis]
    findings['scan_stats']['changed_apis_p0'] = sum(
        1 for r in changed_apis if r.get('severity') == 'P0')

    alerts_path = _call_chain_dir(d) / "alerts.csv"
    findings['scan_stats']['alerts_raw_record_count'] = sum(
        1 for _row in iter_csv_rows(alerts_path)
    )
    _validate_csv_contract(
        alerts_path,
        diagnostics=diagnostics,
        artifact='call_chain_alerts',
        required_column_groups=(
            {'target_coord', 'coord'},
            {'changed_symbol', 'api', 'api_name'},
            {'path_status', 'api_status'},
        ),
        require_data=target_api_count > 0,
    )
    findings['impact_overview'] = build_impact_overview(
        _validated_alert_rows(
            alerts_path,
            diagnostics=diagnostics,
            required=target_api_count > 0,
        )
    )
    if _artifact_has_fatal_csv_diagnostic(
        diagnostics, "call_chain_alerts"
    ):
        findings["impact_overview"] = build_impact_overview([])
    alert_api_count = len(
        (findings.get('impact_overview') or {}).get('apis') or []
    )
    if (
        target_api_count > 0
        and alert_api_count != target_api_count
        and not _artifact_has_diagnostic(diagnostics, 'call_chain_alerts')
    ):
        _record_content_diagnostic(
            diagnostics,
            artifact='call_chain_alerts',
            stage='csv_consistency',
            path=alerts_path,
            message=(
                "alerts API count does not match the Step5 target count"
            ),
        )
    _validate_cross_artifact_identities(
        call_summary=call_summary,
        changed_apis=changed_apis,
        impact_overview=findings['impact_overview'],
        scope_mode=scope_mode,
        diagnostics=diagnostics,
        changed_apis_path=changed_apis_path,
        alerts_path=alerts_path,
    )
    if _changed_api_diagnostic_invalidates_scope(diagnostics):
        _invalidate_analysis_scope(
            findings["analysis_scope"],
            "变化 API 身份与系统触达结果不一致",
        )

    # Step 5 调用链
    impacted_coords = set()
    if call_summary:
        diagnostic_guidance = call_summary.get('diagnostic_guidance')
        if not isinstance(diagnostic_guidance, list):
            diagnostic_guidance = build_diagnostic_guidance_from_summary(
                call_summary
            )
        summary_origin_step = _valid_origin_step(
            call_summary.get("origin_step"),
            "step5",
        )
        findings['diagnostic_guidance_schema'] = REASON_GUIDANCE_SCHEMA
        normalized_guidance = []
        for item in diagnostic_guidance:
            if not isinstance(item, dict):
                continue
            raw_item = dict(item)
            raw_origin_step = _valid_origin_step(
                raw_item.get("origin_step"),
                summary_origin_step,
            )
            definition = guidance_for_reason_code(
                item.get('reason_code') or 'UNKNOWN',
                origin_step=raw_origin_step,
            )
            normalized_origin_step = _valid_origin_step(
                definition.get("origin_step"),
                raw_origin_step,
            )
            normalized_item = {
                **definition,
                'reason_code': definition['reason_code'],
                'reason_code_aliases': definition['reason_code_aliases'],
                'diagnostic_schema': definition['diagnostic_schema'],
                'diagnostic_contract': definition['diagnostic_contract'],
                'origin_step': normalized_origin_step or "unknown",
                'observed_scope': raw_item.get('observed_scope') or 'unknown',
                'affected_api_count': raw_item.get('affected_api_count') or 0,
                'affected_api_count_semantics': (
                    raw_item.get('affected_api_count_semantics') or 'legacy_unknown'
                ),
                'primary_reason_api_count': (
                    raw_item.get('primary_reason_api_count')
                    if raw_item.get('primary_reason_api_count') is not None
                    else raw_item.get('affected_api_count') or 0
                ),
                'potentially_affected_api_count': (
                    raw_item.get('potentially_affected_api_count')
                    if raw_item.get('potentially_affected_api_count') is not None
                    else raw_item.get('affected_api_count') or 0
                ),
                'observed_failure_count': (
                    raw_item.get('observed_failure_count') or 0
                ),
                'failure_record_count': (
                    raw_item.get('failure_record_count')
                    if raw_item.get('failure_record_count') is not None
                    else raw_item.get('observed_failure_count') or 0
                ),
                'failure_occurrence_count': (
                    raw_item.get('failure_occurrence_count')
                    if raw_item.get('failure_occurrence_count') is not None
                    else 0
                ),
                'raw_blocking_failure_count': (
                    raw_item.get('raw_blocking_failure_count') or 0
                ),
                'relevant_blocking_failure_count': (
                    raw_item.get('relevant_blocking_failure_count') or 0
                ),
                'blocking_semantics': (
                    raw_item.get('blocking_semantics') or 'legacy_unknown'
                ),
                'blocking': bool(raw_item.get('blocking')),
                'affected_classes': list(
                    raw_item.get('affected_classes') or []
                ),
                'affected_artifacts': list(
                    raw_item.get('affected_artifacts') or []
                ),
                'affected_artifact_entries': list(
                    raw_item.get('affected_artifact_entries') or []
                ),
                'evidence_file': str(
                    raw_item.get('evidence_file')
                    or next(iter(raw_item.get('evidence_files') or []), '')
                ),
                'evidence_files': list(
                    raw_item.get('evidence_files')
                    or ([raw_item.get('evidence_file')]
                        if raw_item.get('evidence_file') else [])
                ),
                'collectors': list(raw_item.get('collectors') or []),
                'candidate_evidence': list(
                    raw_item.get('candidate_evidence') or []
                ),
                'source_components': list(
                    raw_item.get('source_components') or []
                ),
                'sample_apis': list(raw_item.get('sample_apis') or []),
                # Raw diagnostic prose may contain operator instructions.
                # Human artifacts use catalog facts and physical evidence only.
                'failure_detail_summaries': [],
                'repair_actions': [],
                'verification_steps': [],
                'decision_text': '',
                'recommended_decision': '',
                'ignore_when': '',
            }
            normalized_guidance.append(normalized_item)
        findings['diagnostic_guidance'] = normalized_guidance
        if not findings.get('coverage'):
            findings['coverage'] = _step5_summary_coverage_fallback(call_summary)
        findings['user_conclusion_summary'] = dict(
            call_summary.get('user_conclusion_summary') or {}
        )
        findings['uncertain_dependency_summary'] = list(
            call_summary.get('uncertain_dependency_summary') or []
        )
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
                'old_version': api_info.get('old_version', ''),
                'new_version': api_info.get('new_version', ''),
                'api': api_info.get('api', ''),
                'api_signature': api_info.get('api_signature', ''),
                'symbol_kind': api_info.get('symbol_kind', ''),
                'change_type': api_info.get('change_type', ''),
                'severity': api_info.get('severity', ''),
                'call_paths': api_info.get('call_paths', []),
                'reason_code': canonical_reason_code(
                    api_info.get('reason_code') or 'UNKNOWN'
                ),
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
                'old_version':    api_info.get('old_version', ''),
                'new_version':    api_info.get('new_version', ''),
                'api':           api_info.get('api', ''),
                'api_signature': api_info.get('api_signature', ''),
                'symbol_kind':   api_info.get('symbol_kind', ''),
                'change_type':   api_info.get('change_type', ''),
                'call_paths':    api_info.get('call_paths', []),
                'reason_code': canonical_reason_code(
                    api_info.get('reason_code') or 'UNKNOWN'
                ),
                'reason':        api_info.get('reason', ''),
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
            # The established human report uses "已确认影响" to mean that a
            # changed API has a confirmed current-system call relationship.  It
            # does not claim that a runtime failure was observed.  Preserve the
            # explicit human conclusion before consulting the binary engine's
            # separate runtime-impact dimension.
            if api_info.get('user_conclusion') == '已确认影响':
                if sev == 'P0':
                    findings['p0'].append(entry)
                elif sev == 'P1':
                    findings['p1'].append(entry)
                else:
                    findings['p2'].append(entry)
            elif (
                api_info.get('user_conclusion') == '可能影响'
                or (
                    not api_info.get('user_conclusion')
                    and api_info.get('decision_bucket') == 'probable_impact'
                )
            ):
                entry['severity'] = sev
                entry['user_conclusion'] = '可能影响'
                findings['probable_impact'].append(entry)
            elif sev == 'P0':
                findings['p0'].append(entry)
            elif sev == 'P1':
                findings['p1'].append(entry)
            else:
                findings['p2'].append(entry)

        uncertain_reason_counts = defaultdict(int)
        uncertainty_kind_counts = defaultdict(int)
        for item in call_summary.get('uncertain_apis', []):
            coord = item.get('coord', '')
            if coord:
                impacted_coords.add(coord)
            reason_code = canonical_reason_code(
                item.get('reason_code') or 'UNKNOWN'
            )
            uncertainty_kind = _uncertainty_kind(item)
            uncertain_reason_counts[reason_code or 'UNKNOWN'] += 1
            uncertainty_kind_counts[uncertainty_kind] += 1
            findings['uncertain'].append({
                'coord':         coord,
                'old_version':   item.get('old_version', ''),
                'new_version':   item.get('new_version', ''),
                'api':          item.get('api', ''),
                'api_signature': item.get('api_signature', ''),
                'symbol_kind':  item.get('symbol_kind', ''),
                'change_type':  item.get('change_type', ''),
                'severity':     item.get('severity', ''),
                'user_conclusion': _uncertain_conclusion(item),
                'uncertainty_kind': uncertainty_kind,
                'user_reason':  item.get('user_reason', ''),
                'recommended_action': item.get('recommended_action', ''),
                'key_evidence': item.get('key_evidence', ''),
                'business_reach_depth': item.get('business_reach_depth'),
                'dependency_chain_coords': item.get('dependency_chain_coords', []),
                'call_paths': item.get('call_paths', []),
                'path_details': item.get('path_details', []),
                'compile_impact': item.get('compile_impact', ''),
                'runtime_link_impact': item.get('runtime_link_impact', ''),
                'priority_score': int(item.get('priority_score') or 0),
                'priority_factors': dict(item.get('priority_factors') or {}),
                'reason':       item.get('reason', ''),
                'reason_code':  reason_code,
                'origin_step':  item.get('origin_step', ''),
                'verification': item.get('verification', []),
                'evidence_paths': [],
            })
        findings['uncertain_reason_summary'] = dict(sorted(uncertain_reason_counts.items(), key=lambda x: (-x[1], x[0])))
        findings['uncertainty_kind_summary'] = dict(sorted(
            uncertainty_kind_counts.items(), key=lambda x: x[0]
        ))

        not_analyzed_reason_counts = defaultdict(int)
        for item in call_summary.get('not_analyzed_apis', []):
            coord = item.get('coord', '')
            if coord:
                impacted_coords.add(coord)
            reason_code = canonical_reason_code(
                item.get('reason_code') or 'UNKNOWN'
            )
            not_analyzed_reason_counts[reason_code or 'UNKNOWN'] += 1
            entry = {
                'coord':         coord,
                'old_version':   item.get('old_version', ''),
                'new_version':   item.get('new_version', ''),
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
                'origin_step':  item.get('origin_step', ''),
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
            reason_code = canonical_reason_code(
                item.get('reason_code') or 'UNKNOWN'
            )
            not_found_reason_counts[reason_code or 'UNKNOWN'] += 1
            findings['not_found'].append({
                'coord':         coord,
                'old_version':   item.get('old_version', ''),
                'new_version':   item.get('new_version', ''),
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
            by_api_path = os.path.join(by_api_dir, fname)
            payload = load_json(
                by_api_path,
                diagnostics=diagnostics,
                artifact=f'call_chain_by_api:{fname}',
            )
            evidence_paths, evidence_paths_valid = _normalize_evidence_paths(
                payload.get('evidence_paths', [])
            )
            payload['evidence_paths'] = evidence_paths
            if (
                not evidence_paths_valid
                and not _artifact_has_diagnostic(
                    diagnostics, f'call_chain_by_api:{fname}'
                )
            ):
                _record_content_diagnostic(
                    diagnostics,
                    artifact=f'call_chain_by_api:{fname}',
                    stage='json_contract',
                    path=by_api_path,
                    message='evidence_paths is not a list of edge lists',
                )
            identity_key = build_api_identity_key(payload)
            if identity_key[0] and identity_key[1]:
                by_api_lookup[identity_key] = payload

    for bucket_name in ('p0', 'p1', 'p2', 'uncertain', 'not_impacted', 'not_analyzed', 'not_found'):
        for item in findings[bucket_name]:
            payload = by_api_lookup.get(build_api_identity_key(item), {})
            if payload:
                if not item.get('reason_code'):
                    item['reason_code'] = payload.get('reason_code', '')
                item['evidence_paths'] = _normalize_evidence_paths(
                    payload.get('evidence_paths', [])
                )[0]
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
            data = load_json(
                os.path.join(module_dir, fname),
                diagnostics=diagnostics,
                artifact=f'call_chain_by_module:{fname}',
            )
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
        sample_results = list(step5.get('sample_results') or [])
        sample_result = sample_results[0] if sample_results else {}
        dep_row = dep_change_lookup.get(coord) or {}
        result = {
            'coord': coord,
            'change_type': str(
                item.get('change_type')
                or dep_row.get('change_type')
                or sample_result.get('change_type')
                or ''
            ).strip(),
            'old_version': str(
                item.get('old_version')
                or dep_row.get('old_version')
                or sample_result.get('old_version')
                or ''
            ).strip(),
            'new_version': str(
                item.get('new_version')
                or dep_row.get('new_version')
                or sample_result.get('new_version')
                or ''
            ).strip(),
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
        'old_version': '',
        'new_version': '',
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
            impacted_dep_map[coord]['old_version'] = (
                impacted_dep_map[coord]['old_version']
                or str(item.get('old_version') or '')
            )
            impacted_dep_map[coord]['new_version'] = (
                impacted_dep_map[coord]['new_version']
                or str(item.get('new_version') or '')
            )
            if item.get('api'):
                impacted_dep_map[coord]['apis'].add(item['api'])
    for item in findings['uncertain']:
        coord = item.get('coord', '')
        if not coord:
            continue
        impacted_dep_map[coord]['coord'] = coord
        impacted_dep_map[coord]['uncertain'] += 1
        impacted_dep_map[coord]['old_version'] = (
            impacted_dep_map[coord]['old_version']
            or str(item.get('old_version') or '')
        )
        impacted_dep_map[coord]['new_version'] = (
            impacted_dep_map[coord]['new_version']
            or str(item.get('new_version') or '')
        )
        if item.get('api'):
            impacted_dep_map[coord]['apis'].add(item['api'])
    for item in findings['not_analyzed']:
        coord = item.get('coord', '')
        if not coord:
            continue
        impacted_dep_map[coord]['coord'] = coord
        impacted_dep_map[coord]['old_version'] = (
            impacted_dep_map[coord]['old_version']
            or str(item.get('old_version') or '')
        )
        impacted_dep_map[coord]['new_version'] = (
            impacted_dep_map[coord]['new_version']
            or str(item.get('new_version') or '')
        )
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
        impacted_dep_map[coord]['old_version'] = (
            impacted_dep_map[coord]['old_version']
            or str(item.get('old_version') or '')
        )
        impacted_dep_map[coord]['new_version'] = (
            impacted_dep_map[coord]['new_version']
            or str(item.get('new_version') or '')
        )
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
                'old_version': (
                    per_dep.get('old_version')
                    or dep_row.get('old_version', '')
                    or data.get('old_version', '')
                ),
                'new_version': (
                    per_dep.get('new_version')
                    or dep_row.get('new_version', '')
                    or data.get('new_version', '')
                ),
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

    component_by_reason = defaultdict(list)
    for component in (findings.get('coverage') or {}).get('components') or []:
        component_id = str(component.get('id') or '').strip()
        for reason_code in component.get('reason_codes') or []:
            code = str(reason_code or '').strip()
            if code and component_id not in component_by_reason[code]:
                component_by_reason[code].append(component_id)
    existing_guidance = {
        str(item.get('reason_code') or ''): item
        for item in findings.get('diagnostic_guidance') or []
        if isinstance(item, dict)
    }
    for reason_code, component_ids in component_by_reason.items():
        for item in build_catalog_guidance(
            [reason_code],
            observed_scope='step',
            source_components=component_ids,
        ):
            existing_guidance.setdefault(item['reason_code'], item)
    findings['diagnostic_guidance'] = sorted(
        existing_guidance.values(),
        key=lambda item: (
            str(item.get('origin_step') or 'unknown'),
            not bool(item.get('blocking')),
            str(item.get('reason_code') or ''),
        ),
    )
    fatal_csv_stages = {
        "csv_missing",
        "csv_load",
        "csv_stream",
        "csv_contract",
    }
    fatal_alerts = any(
        str(item.get("artifact") or "") == "call_chain_alerts"
        and str(item.get("stage") or "") in fatal_csv_stages
        for item in diagnostics
    )
    fatal_changed_apis = any(
        str(item.get("artifact") or "") == "changed_apis"
        and str(item.get("stage") or "") in fatal_csv_stages
        for item in diagnostics
    )
    if fatal_alerts or (
        target_api_count > 0
        and not (findings.get("impact_overview") or {}).get("apis")
    ):
        findings['artifacts'].pop('alerts_csv', None)
    if fatal_changed_apis or (target_api_count > 0 and not changed_apis):
        findings['artifacts'].pop('changed_apis_csv', None)
    findings['available_evidence_paths'] = _collect_available_evidence_paths(
        d, findings
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


def _report_link(path, label=None):
    """Build a link relative to deliverables/report.md."""
    normalized = str(path or '').strip().replace('\\', '/')
    if not normalized:
        return '-'
    if Path(normalized).is_absolute():
        href = normalized
    else:
        href = normalized[len('deliverables/'):] if normalized.startswith('deliverables/') else f'../{normalized}'
    return f"[{label or normalized}]({href})"


def _collect_available_evidence_paths(report_dir, findings):
    candidates = set()
    for value in ((findings.get('artifacts') or {}).values()):
        normalized = str(value or '').strip().replace('\\', '/')
        if normalized:
            candidates.add(normalized)
    for component in ((findings.get('coverage') or {}).get('components') or []):
        for value in component.get('evidence') or []:
            normalized = str(value or '').strip().replace('\\', '/')
            if normalized:
                candidates.add(normalized)

    available = []
    for value in sorted(candidates):
        candidate_path = Path(value)
        if not candidate_path.is_absolute():
            candidate_path = Path(report_dir) / value
        if candidate_path.is_file():
            available.append(value)
    return available


def _evidence_is_available(findings, value):
    normalized = str(value or '').strip().replace('\\', '/')
    if not normalized:
        return False
    # Hand-built findings used by callers predate availability tracking. Their
    # links remain unchanged; collected findings only expose verified files.
    if 'available_evidence_paths' not in findings:
        return True
    available = {
        str(item or '').strip().replace('\\', '/')
        for item in (findings.get('available_evidence_paths') or [])
    }
    available.update(
        str(item or '').strip().replace('\\', '/')
        for item in ((findings.get('artifacts') or {}).values())
        if str(item or '').strip()
    )
    return normalized in available


def _join_report_links(values, limit=3, empty='-'):
    cleaned = [str(value or '').strip() for value in values or [] if str(value or '').strip()]
    if not cleaned:
        return empty
    text = '<br>'.join(_report_link(value) for value in cleaned[:limit])
    if len(cleaned) > limit:
        text += f'<br>…另 {len(cleaned) - limit} 项'
    return text


DISPLAY_LABELS = {
    '当前无法确认': '结论未确定',
    '需要人工复核': '结论未确定（存在候选证据）',
    '需人工复核': '结论未确定（存在候选证据）',
    '需要补充输入': '输入不足，结论未确定',
    '缺少依赖源码/构建产物': '输入不足，结论未确定',
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
        'partial': '存在缺口',
        'insufficient': '不足',
        'not_applicable': '不适用',
        'unknown': '未记录',
    }
    return labels.get(str(status or 'unknown'), '未记录')


def _effective_coverage_status(findings):
    status = str(
        ((findings.get('coverage') or {}).get('overall_status')) or 'unknown'
    )
    if findings.get('diagnostics') and status in {'complete', 'not_applicable'}:
        return 'partial'
    return status


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
        'behavior_diff': '依赖行为变化识别',
        'artifact_bytecode_dependencies': '制品内依赖字节码',
        'source_artifact_alignment': '源码与制品一致性',
        'indirect_usage_matrix': '动态调用可能漏报',
        'business_reachability': '业务调用链回溯',
        'business_bytecode_graph': '业务字节码调用图',
        'static_scan': '静态扫描',
    }
    if component_id.startswith('framework_adapter:'):
        return '框架适配器'
    return labels.get(component_id, '其他覆盖组件')


def _coverage_impact_text(component_id, reason_codes):
    component_id = str(component_id or '').strip()
    reasons = {
        canonical_reason_code(reason_code)
        for reason_code in (reason_codes or ())
    }
    raw_reason_texts = {
        'dependency_pairing_ambiguous': '依赖升级前后坐标匹配存在歧义。',
        'dependency_coordinates_unresolved': '部分依赖坐标未解析。',
        'artifact_hash_missing': '构建产物缺少哈希，无法确认输入制品是否稳定。',
        'base_or_current_build_not_succeeded': '升级前或升级后构建产物不完整。',
        'step4_coverage_missing': '缺少 API 对比覆盖记录。',
        'dependency_source_diff_not_available': '缺少依赖源码 diff，行为变化可能不完整。',
        'dependency_source_or_git_ref_coverage_incomplete': '依赖行为变化识别未覆盖全部升级依赖。',
        'DEPENDENCY_SOURCE_REF_UNAVAILABLE': '依赖源码版本无法可靠固定。',
        'DEPENDENCY_SOURCE_DIFF_UNAVAILABLE': '依赖源码差异分析未能完成。',
        'FINAL_JAR_BEHAVIOR_DIFF_UNAVAILABLE': '最终 JAR 方法字节码兜底未能完成。',
        'JAPICMP_EXECUTION_FAILED': '部分依赖的 JApiCmp 执行失败，没有形成 API 变化数据。',
        'JAPICMP_TIMEOUT': 'JApiCmp 二进制 API 对比超时。',
        'compiled_business_classes_not_available': '缺少业务编译产物，字节码调用补充分析不完整。',
        'step5_not_analyzed_targets': '部分变更 API 没有完成调用链分析。',
        'step5_target_count_mismatch': 'Step5 目标 API 数和结果数不一致。',
        'source_revision_unavailable': (
            '未能取得源码或构建记录的修订版本，源码与制品一致性未验证。'
        ),
        'build_provenance_missing': (
            '缺少构建来源记录，源码与制品一致性未验证。'
        ),
        'direct_artifact_source_revision_unverified': (
            '当前制品没有可比对的源码修订记录，源码与制品一致性未验证。'
        ),
        'source_revision_differs_from_build_revision': (
            '源码修订版本与构建制品记录的修订版本不一致。'
        ),
        'source_worktree_has_unbuilt_changes': (
            '源码工作区包含未进入当前构建制品的变化。'
        ),
        'artifact_sha256_mismatch': '当前制品哈希与构建来源记录不一致。',
        'target_module_mismatch': '当前制品不属于构建来源记录中的目标模块。',
        'source_alignment_invalid': (
            '源码与制品一致性记录无法读取，一致性状态未验证。'
        ),
        's5_artifact_bytecode_catalog_missing': '缺少制品内依赖字节码清单。',
        'indirect_usage_coverage_missing': '反射、配置或间接调用可能漏报。',
        'reflection_source_partial': '反射调用可能漏报。',
    }
    reason_texts = {
        canonical_reason_code(reason_code): text
        for reason_code, text in raw_reason_texts.items()
    }
    known = [reason_texts[item] for item in sorted(reasons) if item in reason_texts]
    if known:
        return ' '.join(known)
    fallback = {
        'project_scope': '分析范围不完整，报告可能漏掉部分模块。',
        'dependency_diff': '依赖变更识别不完整，报告可能漏掉部分依赖变化。',
        'build_provenance': '构建产物来源不完整，结果可复现性不足。',
        'binary_api_diff': 'API 对比不完整，报告可能漏掉部分破坏性 API 变化。',
        'behavior_diff': '依赖行为变化识别不完整，可能漏掉签名不变的方法实现变化。',
        'artifact_bytecode_dependencies': '制品内依赖分析不完整，运行时依赖链路可能不完整。',
        'source_artifact_alignment': (
            '源码与实际制品的一致性未得到验证，源码级调用位置未完全确认。'
        ),
        'indirect_usage_matrix': '动态调用可能漏报。',
        'business_reachability': '业务调用链回溯不完整，部分 API 影响无法确认。',
        'business_bytecode_graph': '业务字节码调用图不完整，补充调用证据可能缺失。',
        'static_scan': '静态扫描不完整，背景风险线索可能缺失。',
    }
    return fallback.get(component_id, '该检查项不完整，相关结论的适用范围受到限制。')


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
    overall_status = str(coverage.get('overall_status') or 'unknown')
    if not rows and overall_status not in {'complete', 'not_applicable'}:
        rows.append({
            'label': (
                '证据覆盖状态未记录'
                if overall_status == 'unknown'
                else '证据覆盖存在未展开缺口'
            ),
            'status': _coverage_status_label(overall_status),
            'impact': (
                '当前记录不支持“证据覆盖完整”结论；'
                '未确认项和未发现路径项的解释范围受到限制。'
            ),
            'evidence': [],
        })
    return rows


def _overview_for_item(findings, item):
    identity = _canonical_report_identity(item)
    for overview in ((findings.get('impact_overview') or {}).get('apis') or []):
        if _canonical_report_identity(overview) == identity:
            return overview
    return {}


def _dependency_for_item(findings, item):
    coord = _canonical_identity_coord(item.get('coord'))
    for dependency in findings.get('impacted_dependencies') or []:
        if _canonical_identity_coord(dependency.get('coord')) == coord:
            return dependency
    for dependency in findings.get('per_dependency_results') or []:
        if _canonical_identity_coord(dependency.get('coord')) == coord:
            return dependency
    return {}


def _item_api_label(item):
    api = str(item.get('api') or item.get('api_name') or '').strip()
    signature = str(item.get('api_signature') or '').strip()
    if signature and '(' not in api:
        return f"{api}{signature}"
    return api


def _item_business_entries(findings, item, limit=3, statuses=None):
    entries = []
    direct_entry = str(item.get('business_entry') or '').strip()
    if direct_entry:
        entries.append(direct_entry)
    overview = _overview_for_item(findings, item)
    overview_entries = []
    if statuses:
        for status in statuses:
            overview_entries.extend(
                (overview.get('entries_by_status') or {}).get(status) or []
            )
    else:
        overview_entries = list(overview.get('sample_entries') or [])
    for entry in overview_entries:
        entry = str(entry or '').strip()
        if entry and entry not in entries:
            entries.append(entry)
    if not entries:
        overview_paths = []
        if statuses:
            for status in statuses:
                overview_paths.extend(
                    (overview.get('paths_by_status') or {}).get(status) or []
                )
        else:
            overview_paths = list(
                overview.get('paths') or overview.get('sample_paths') or []
            )
        for path in [
            *overview_paths,
            *list(item.get('call_paths') or []),
        ]:
            first_node = re.split(r'\s*(?:->|→)\s*', str(path or '').strip(), maxsplit=1)[0]
            first_node = _human_chain_node(first_node)
            if first_node and first_node not in entries:
                entries.append(first_node)
    deduplicated = []
    for entry in entries:
        base = entry.split('(', 1)[0]
        if '(' not in entry and any(
            existing.split('(', 1)[0] == base and '(' in existing
            for existing in entries
        ):
            continue
        if entry not in deduplicated:
            deduplicated.append(entry)
    if limit is None:
        return deduplicated
    return deduplicated[:limit]


def _item_modules(findings, item, limit=3):
    modules = []
    overview = _overview_for_item(findings, item)
    for module in overview.get('sample_modules') or []:
        module = str(module or '').strip()
        if module and module not in modules:
            modules.append(module)
    return modules[:limit]


def _item_effect_text(findings, item, fallback='', conclusion=''):
    return _objective_item_reason(item, conclusion) or fallback


def _confirmed_items(findings):
    return [
        *list(findings.get('p0') or []),
        *list(findings.get('p1') or []),
        *list(findings.get('p2') or []),
    ]


def _unresolved_count(findings):
    return (
        len(findings.get('probable_impact') or [])
        + len(findings.get('uncertain') or [])
        + len(findings.get('needs_input') or [])
        + len(_exclusive_not_analyzed(findings))
    )


def render_core_conclusion(findings):
    coverage = findings.get('coverage') or {}
    confirmed = [
        row for row in build_api_result_rows(findings)
        if row.get("conclusion") == "已确认影响"
    ]
    p0 = list(findings.get('p0') or [])
    p1 = list(findings.get('p1') or [])
    unresolved_count = _unresolved_count(findings)
    not_found = findings.get('not_found') or []
    not_impacted = findings.get('not_impacted') or []
    uncertainty_counts = _uncertainty_counts(findings.get('uncertain') or [])
    coverage_incomplete = _effective_coverage_status(findings) not in {
        'complete', 'not_applicable'
    }
    analysis_scope = findings.get('analysis_scope') or {}
    scope_mode = str(analysis_scope.get('mode') or '').strip()
    if confirmed:
        verdict = f"已确认当前系统受到升级影响，共 {len(confirmed)} 个变更 API。"
    elif unresolved_count:
        verdict = (
            "本轮没有形成已确认影响结论，"
            f"另有 {unresolved_count} 个变更 API 的结论尚未确定。"
        )
    elif coverage_incomplete:
        verdict = "本轮没有形成已确认影响结论，但当前证据不足以支持“系统不受影响”结论。"
    elif not_impacted and not not_found:
        verdict = (
            f"本轮 {len(not_impacted)} 个变更 API 均有当前制品中的相同类字节码保留证据；"
            "该结论只覆盖这些 API 符号。"
        )
    elif not_found:
        verdict = "静态分析未发现业务调用路径；该结果不等同于已确认不受影响。"
    else:
        verdict = "本轮没有可展示的变更 API 分析结果。"

    lines = [
        "## 一、事实摘要",
        "",
        f"**结论：{verdict}**",
        "",
        f"- **分析范围**：{_scope_text(findings)}。",
    ]

    counts = []
    for label, count in (
        ('已确认影响', len(confirmed)),
        ('高风险（P0/P1）', len(p0) + len(p1)),
        ('可能影响', len(findings.get('probable_impact') or [])),
        (
            '结论未确定（候选证据）',
            uncertainty_counts.get(UNCERTAINTY_KIND_CANDIDATE_EVIDENCE, 0),
        ),
        (
            '结论未确定（静态分析能力边界）',
            uncertainty_counts.get(UNCERTAINTY_KIND_ANALYSIS_LIMITATION, 0),
        ),
        ('缺少输入', len(findings.get('needs_input') or [])),
        ('本次未完成分析', len(_exclusive_not_analyzed(findings))),
        ('未发现调用路径', len(not_found)),
        ('已确认不受影响', len(not_impacted)),
    ):
        if count:
            counts.append(f"{label} {count}")
    if counts:
        lines.append(f"- **结果分布**：{'；'.join(counts)}。")

    distribution_lines = render_impact_distribution(findings)
    if distribution_lines:
        lines.extend(["", *distribution_lines])

    if confirmed:
        top = confirmed[0]
        dependency = _dependency_for_item(findings, top)
        version = _version_transition(top) or _version_transition(dependency)
        coord = str(top.get('coord') or dependency.get('coord') or '未知依赖')
        dependency_text = f"`{coord}`"
        if version:
            dependency_text += f"（{version}）"
        api_text = _item_api_label(top) or '未知 API'
        entries = _item_business_entries(
            findings, top, limit=1, statuses=('reachable',)
        )
        fact = f"{dependency_text} 的 `{api_text}` 已确认触达当前系统"
        if entries:
            fact += f"，业务入口为 `{entries[0]}`"
        effect = _item_effect_text(
            findings, top, conclusion='已确认影响'
        )
        if effect:
            fact += f"。{effect.rstrip('。')}。"
        else:
            fact += "。"
        lines.extend(["", f"**代表性已确认事实**：{fact}"])

    if scope_mode == 'partial':
        lines.extend([
            "",
            "> 本报告只覆盖已选择的变化依赖；未选择的变化依赖不在上述数量和结论中。",
        ])
    elif scope_mode not in {'full'}:
        scope_invalid = (
            analysis_scope.get("validation_status") == "invalid"
        )
        lines.extend([
            "",
            (
                "> 分析范围无法核验，无法证明上述结果覆盖全部变化依赖。"
                if scope_invalid
                else "> 分析范围快照缺失，无法证明上述结果覆盖全部变化依赖。"
            ),
        ])
    if coverage_incomplete and confirmed:
        lines.extend([
            "",
            (
                "> 证据覆盖存在缺口。该缺口不推翻已经由当前最终制品或完整调用链证明的"
                "“已确认影响”，但会限制未命中项和不受影响项的解释范围。"
            ),
        ])
    lines.append("")

    scope_artifact = ((findings.get('artifacts') or {}).get('analysis_scope_md') or '').strip()
    if scope_artifact:
        lines.extend([
            "分析范围明细：[本轮分析范围](analysis-scope.md)。",
            "",
        ])
    return lines


def _identity_without_severity(item):
    return _canonical_report_identity(item)


def _change_cell(item, severity='', *, include_item_severity=True):
    source = item
    if not include_item_severity:
        source = {**dict(item or {}), "severity": ""}
    return _md_cell(_change_summary(source, severity), 220)


def _conclusion_for_report(item, fallback):
    # The structural Step5 bucket is the report conclusion. Free-text legacy
    # labels may be broader, older, or contradictory and are never merged into
    # the displayed status.
    if fallback == UNCERTAIN_CANDIDATE_CONCLUSION:
        return _uncertain_conclusion(item)
    if fallback:
        return _display_label(fallback)
    conclusion = str(item.get('user_conclusion') or '').strip()
    if conclusion:
        return _display_label(conclusion)
    return _display_label(fallback)


def _uncertainty_kind_for_report(item, overview):
    explicit = str((item or {}).get('uncertainty_kind') or '').strip()
    if explicit in {
        UNCERTAINTY_KIND_CANDIDATE_EVIDENCE,
        UNCERTAINTY_KIND_ANALYSIS_LIMITATION,
    }:
        return explicit
    overview = overview or {}
    uncertain_paths = list(
        ((overview.get('paths_by_status') or {}).get('uncertain') or [])
    )
    uncertain_count = max(
        int((overview.get('logical_path_counts_by_status') or {}).get('uncertain') or 0),
        int((overview.get('path_counts_by_status') or {}).get('uncertain') or 0),
    )
    if uncertain_paths or uncertain_count:
        return UNCERTAINTY_KIND_CANDIDATE_EVIDENCE
    return _uncertainty_kind(item)


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
        for evidence_path in _normalize_evidence_paths(
            item.get('evidence_paths')
        )[0]:
            nodes = _nodes_from_csv_evidence(evidence_path)
            if len(nodes) >= 2:
                candidate = " → ".join(nodes)
                if candidate not in paths:
                    paths.append(candidate)
    return paths[:5]


def _path_count_for_report(item, overview_lookup, sampled_paths, desired_statuses=None):
    overview = overview_lookup.get(_identity_without_severity(item)) or {}
    if desired_statuses:
        logical_counts = (
            overview.get("logical_path_counts_by_status") or {}
        )
        paths_by_status = overview.get('paths_by_status') or {}
        available_paths = [
            path
            for status in desired_statuses
            for path in (paths_by_status.get(status) or [])
        ]
        if any(
            status in logical_counts for status in desired_statuses
        ):
            raw_count = sum(
                int(logical_counts.get(status) or 0)
                for status in desired_statuses
            )
        elif available_paths:
            raw_count = _distinct_call_path_count(available_paths)
        else:
            counts = overview.get('path_counts_by_status') or {}
            raw_count = sum(
                int(counts.get(status) or 0) for status in desired_statuses
            )
    else:
        paths = overview.get('paths') or overview.get('sample_paths') or []
        raw_count = (
            _distinct_call_path_count(paths)
            if paths
            else overview.get('path_count')
        )
    try:
        count = int(raw_count)
    except (TypeError, ValueError):
        count = 0
    return max(count, _distinct_call_path_count(sampled_paths))


def _occurrence_count_for_report(
    item, overview_lookup, path_count, desired_statuses=None
):
    overview = overview_lookup.get(_identity_without_severity(item)) or {}
    if desired_statuses:
        counts = (
            overview.get('occurrence_counts_by_status')
            or overview.get('path_counts_by_status')
            or {}
        )
        raw_count = sum(
            int(counts.get(status) or 0) for status in desired_statuses
        )
    else:
        raw_count = (
            overview.get('occurrence_count')
            or overview.get('path_count')
        )
    try:
        count = int(raw_count)
    except (TypeError, ValueError):
        count = 0
    return max(count, int(path_count or 0))


def _render_path_sample_cards(rows, findings=None):
    evidence_rows = [
        row for row in rows
        if (row.get('paths') or [])
        and str(row.get('conclusion') or '') in {'已确认影响', '已确认不受影响'}
    ][:S6_MAIN_PATH_DETAIL_LIMIT]
    if not evidence_rows:
        return []

    lines = [
        "### 代表性证据链",
        "",
    ]
    alerts_path = str(
        ((((findings or {}).get('artifacts') or {}).get('alerts_csv')) or '')
    ).strip()
    if alerts_path:
        lines.extend([
            (
                "这里只展示少量代表性证据；完整物理记录位于"
                f"{_report_link(alerts_path, '逐链路证据台账')}。"
            ),
            "",
        ])
    else:
        lines.extend(["以下链路来自本轮汇总记录中保留的证据。", ""])
    for idx, row in enumerate(evidence_rows, 1):
        paths = list(row.get('paths') or [])
        path_count = int(row.get('path_count') or len(paths))
        occurrence_count = int(row.get('occurrence_count') or path_count)
        entries = list(row.get('business_entries') or [])
        lines.extend([
            f"#### {idx}. `{_md_cell(_item_api_label(row), 220)}`",
            "",
            f"- **结论**：{_md_cell(row.get('conclusion'), 120)}",
            f"- **依赖**：`{_md_cell(row.get('coord'), 180)}`"
            + (f"（{_version_transition(row)}）" if _version_transition(row) else ""),
        ])
        if entries:
            lines.append(f"- **业务入口**：{_join_inline([f'`{entry}`' for entry in entries], limit=3)}")
        evidence_count = f"{path_count} 条调用链"
        if occurrence_count > path_count:
            evidence_count += f"；共 {occurrence_count} 次命中"
        lines.append(f"- **证据数量**：{evidence_count}")
        lines.extend(["", "**代表性链路**：", ""])
        for path in paths[:1]:
            lines.append(f"- `{_md_cell(_human_chain(path), 360)}`")
        lines.append("")
    return lines


def _human_reason(value):
    text = str(value or '').strip()
    if not text:
        return ''
    labels = {
        'NO_STATIC_PATH': '当前源码中未找到调用路径。',
        'NOT_FOUND_IN_STATIC_ANALYSIS': '当前源码中未找到调用路径。',
        'NO_CLASS_REFERENCE': '当前源码中未找到目标类引用。',
        'DEPENDENCY_SOURCE_MAPPING_MISSING': '缺少依赖源码，跨依赖调用链未完整回溯。',
        'RUNTIME_DEPENDENCY_JARS_UNAVAILABLE': (
            '缺少当前最终制品的运行时依赖 JAR，无法完成从依赖调用到'
            '当前系统调用起点的回溯。'
        ),
        'MISSING_API_SIGNATURE': (
            '变化 API 记录缺少参数签名，无法精确区分重载方法。'
        ),
        'MISSING_API_NAME': (
            '变化 API 记录缺少完整 API 名称，无法建立精确调用目标。'
        ),
        'MISSING_SYMBOL_KIND': (
            '变化 API 记录缺少符号类型，无法判断其是方法、字段、类还是构造方法。'
        ),
        'ARTIFACT_BYTECODE_COVERAGE_INCOMPLETE': (
            '当前最终制品中的业务 class 或运行时依赖 JAR 未被完整扫描。'
        ),
        'SOURCE_ARTIFACT_ALIGNMENT_UNVERIFIED': (
            '当前源码与本轮分析使用的构建制品是否一致未得到确认。'
        ),
        'MISSING_DEPENDENCY_SOURCE_MAPPING': '缺少依赖源码，跨依赖调用链未完整回溯。',
        'RESOURCE_OR_REFLECTION': '涉及资源配置或反射调用，静态分析无法确认实际调用目标。',
        'UNCERTAIN_DYNAMIC_PROXY_CALL': '存在动态代理调用，静态分析无法确认实际实现。',
        'BYTECODE_HIT_BUSINESS_ENTRY_NOT_CONFIRMED': '字节码发现候选入口，但还没有证明当前系统代码会调用到该 API。',
        'BEHAVIOR_CHANGED_RUNTIME_VERIFICATION': '静态证据不能确认该行为变化的运行时结果。',
        'BEHAVIOR_CHANGED_PRECISE_TARGET_NOT_CONFIRMED': '行为变化目标未精确确认。',
        'OVERLOAD_AMBIGUOUS_TARGET': '重载方法目标存在歧义。',
        'OVERLOAD_AMBIGUOUS_INTERMEDIATE': '中间调用存在重载歧义。',
        'LOW_CONFIDENCE_EDGE': '调用边置信度较低，尚未形成确定结论。',
        'CALL_GRAPH_LIMITATION_SYMBOL_KIND': '当前符号类型的调用图识别不完整。',
        'INLINED_CONSTANT_USAGE_UNDETECTABLE': (
            '编译期常量可能已内联到调用方，静态字节码中不会保留字段访问指令。'
        ),
        'ANALYSIS_INCOMPLETE': '分析未完整完成。',
        'SYSTEM_CODE_REACHED': '调用链已从当前系统入口触达变更 API。',
        'RUNTIME_VERIFICATION_REQUIRED': (
            '已确认当前系统存在到该变化 API 的精确静态可执行调用关系；'
            '这里确认的是调用关系受到 API 变化影响，不表示运行时故障已经发生，'
            '仍需定向测试验证。'
        ),
        'RUNTIME_DEPENDENCY_USES_REMOVED_API': (
            '当前最终制品中的运行时依赖仍引用已移除 API；'
            '加载或执行该路径时存在链接错误风险。'
        ),
        'PACKAGED_DEPENDENCY_BYTECODE_USAGE': '制品内依赖字节码命中该 API。',
        'BUSINESS_ARTIFACT_BYTECODE_USAGE': '业务制品字节码命中该 API。',
        'S6_EVIDENCE_IDENTITY_MISMATCH': (
            '变化 API 清单、系统触达汇总和逐链路台账未能共同确认该项。'
        ),
    }
    if text in labels:
        return labels[text]
    if re.fullmatch(r'[A-Z][A-Z0-9_]*', text):
        return '当前记录没有可展示的标准化原因说明。'
    if re.fullmatch(r'[A-Za-z][A-Za-z0-9 .:/_-]*', text):
        return '当前记录未提供可直接用于主报告的中文原因说明。'
    if (
        any(token in text for token in (
            '建议',
            '下一步',
            '待办',
            '完成标准',
            '修复动作',
        ))
        or re.search(
            r'(?:需|需要|请|应该|应当|必须).{0,16}'
            r'(?:验证|测试|复核|检查|修改|执行|补充|处理)',
            text,
        )
    ):
        return ''
    return text


def _reason_conflicts_with_conclusion(value, conclusion):
    text = re.sub(r"\s+", "", str(value or ""))
    status = str(conclusion or "").strip()
    if not text or not status:
        return False
    no_impact_claim = bool(
        re.search(
            r"(?:完全|确认|确定)?不受影响|(?:没有|不存在|无)影响|完全兼容",
            text,
        )
    )
    confirmed_impact_claim = bool(
        re.search(
            r"已确认(?:存在)?影响|确认.{0,12}(?:受到|存在).{0,6}影响|"
            r"已证明.{0,12}(?:触达|影响)|系统.{0,8}受到.{0,4}影响",
            text,
        )
    )
    if status == "已确认影响":
        return no_impact_claim
    if status == "已确认不受影响":
        return confirmed_impact_claim or bool(
            re.search(
                r"(?:链接|加载|调用).{0,8}(?:错误|失败)风险|"
                r"调用链.{0,8}触达变更API",
                text,
            )
        )
    if status in {
        "可能影响",
        UNCERTAIN_CANDIDATE_CONCLUSION,
        UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION,
        "输入不足，结论未确定",
        "本次未完成分析",
        "未发现调用路径",
    }:
        return no_impact_claim or confirmed_impact_claim
    return False


def _objective_reason_text(value, conclusion=''):
    text = _human_reason(value)
    if not text or _reason_conflicts_with_conclusion(text, conclusion):
        return ''
    return text


def _objective_item_reason(item, conclusion=''):
    item = item or {}
    # Human-readable reports accept only controlled reason codes. Arbitrary
    # free text remains in machine evidence and cannot inject instructions or
    # contradict the structural result bucket.
    return _objective_reason_text(item.get("reason_code"), conclusion)


def _report_reason_code_sort_key(value):
    priority = {
        "RUNTIME_DEPENDENCY_USES_REMOVED_API": 0,
        "SYSTEM_CODE_REACHED": 1,
        "BUSINESS_ARTIFACT_BYTECODE_USAGE": 2,
        "PACKAGED_DEPENDENCY_BYTECODE_USAGE": 3,
    }
    normalized = str(value or "").strip()
    return (priority.get(normalized, 10), normalized)


def _set_report_row_reasons(row, reason_codes, conclusion):
    ordered_codes = sorted(
        {
            str(value or "").strip()
            for value in reason_codes or []
            if str(value or "").strip()
        },
        key=_report_reason_code_sort_key,
    )
    reason_texts = []
    for reason_code in ordered_codes:
        reason = _objective_reason_text(reason_code, conclusion)
        normalized = reason.rstrip("。")
        if normalized and normalized not in reason_texts:
            reason_texts.append(normalized)
    row["reason_codes"] = ordered_codes
    row["reason_code"] = ordered_codes[0] if ordered_codes else ""
    row["reason"] = "。".join(reason_texts) + ("。" if reason_texts else "")


def _severity_rank(value):
    return {
        "P0": 0,
        "P1": 1,
        "P2": 2,
    }.get(str(value or "").strip().upper(), 3)


def _normalized_report_severity(value):
    return str(value or "").strip().upper() or "未分级"


def _api_result_rank(row):
    conclusion = str((row or {}).get("conclusion") or "").strip()
    if conclusion == "已确认影响":
        return 0
    if conclusion == "已确认不受影响":
        return 2
    if _api_result_is_incomplete(row or {}):
        return 3
    return 1


def _api_call_relationship_count(row):
    row = row or {}
    review_total = max(
        int(row.get("additional_review_path_count") or 0),
        (
            int(row.get("uncertain_path_count") or 0)
            + int(row.get("not_analyzed_path_count") or 0)
        ),
    )
    explicit_total = (
        int(row.get("confirmed_path_count") or 0)
        + review_total
    )
    return max(
        explicit_total,
        int(row.get("path_count") or 0),
    )


def _report_result_sort_key(row):
    return (
        str(row.get("coord") or ""),
        _api_result_rank(row),
        -_api_call_relationship_count(row),
        str(row.get("api") or ""),
        str(row.get("api_signature") or ""),
        str(row.get("change_type") or ""),
    )


def build_api_result_rows(findings):
    overview_lookup = {
        _identity_without_severity(item): item
        for item in ((findings.get('impact_overview') or {}).get('apis') or [])
    }
    source_buckets = [
        ('已确认影响', 'P0', findings.get('p0') or []),
        ('已确认影响', 'P1', findings.get('p1') or []),
        ('已确认影响', 'P2', findings.get('p2') or []),
        ('可能影响', '', findings.get('probable_impact') or []),
        ('结论未确定（存在候选证据）', '', findings.get('uncertain') or []),
        ('已确认不受影响', '', findings.get('not_impacted') or []),
        ('输入不足，结论未确定', '', findings.get('needs_input') or []),
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
    row_by_key = {}
    version_values_by_key = {}
    for fallback_conclusion, severity, items in source_buckets:
        desired_statuses = {
            '已确认影响': ('reachable',),
            # A binary-first result may prove an executable path while keeping
            # runtime impact at probable.  Preserve that exact relationship in
            # the human report instead of treating it as an incomplete run.
            '可能影响': ('reachable', 'uncertain', 'not_analyzed'),
            '结论未确定（存在候选证据）': ('uncertain',),
            '已确认不受影响': ('not_impacted',),
            '输入不足，结论未确定': ('not_analyzed',),
            '本次未完成分析': ('not_analyzed',),
            '未发现调用路径': ('not_found_in_static_analysis', 'not_reachable'),
        }.get(fallback_conclusion, ())
        for item in items:
            identity = _identity_without_severity(item)
            report_item = item
            if fallback_conclusion == UNCERTAIN_CANDIDATE_CONCLUSION:
                report_item = {
                    **dict(item or {}),
                    'uncertainty_kind': _uncertainty_kind_for_report(
                        item, overview_lookup.get(identity) or {}
                    ),
                }
            item_conclusion = _conclusion_for_report(
                report_item, fallback_conclusion
            )
            key = (identity, item_conclusion)
            dependency = _dependency_for_item(findings, item)
            old_version = str(
                item.get("old_version")
                or dependency.get("old_version")
                or ""
            ).strip()
            new_version = str(
                item.get("new_version")
                or dependency.get("new_version")
                or ""
            ).strip()
            if key in row_by_key:
                existing = row_by_key[key]
                version_values = version_values_by_key[key]
                if old_version:
                    version_values["old"].add(old_version)
                if new_version:
                    version_values["new"].add(new_version)
                existing["old_version"] = (
                    next(iter(version_values["old"]))
                    if len(version_values["old"]) == 1
                    else ""
                )
                existing["new_version"] = (
                    next(iter(version_values["new"]))
                    if len(version_values["new"]) == 1
                    else ""
                )
                duplicate_entries = _item_business_entries(
                    findings,
                    item,
                    limit=None,
                    statuses=desired_statuses,
                )
                existing["business_entries"] = sorted({
                    *existing.get("business_entries", []),
                    *duplicate_entries,
                })
                existing["business_entry_count"] = len(
                    existing["business_entries"]
                )
                _set_report_row_reasons(
                    existing,
                    [
                        *existing.get("reason_codes", []),
                        item.get("reason_code"),
                    ],
                    existing.get('conclusion') or fallback_conclusion,
                )
                continue
            sampled_paths = _paths_for_report(item, overview_lookup, desired_statuses)
            overview = overview_lookup.get(identity) or {}
            counts_by_status = overview.get('path_counts_by_status') or {}
            logical_counts_by_status = (
                overview.get("logical_path_counts_by_status") or {}
            )
            paths_by_status = overview.get('paths_by_status') or {}
            all_entries_by_status = (
                overview.get('all_entries_by_status') or {}
            )

            def status_path_count(status):
                if status in logical_counts_by_status:
                    return int(
                        logical_counts_by_status.get(status) or 0
                    )
                status_paths = list(paths_by_status.get(status) or [])
                if status_paths:
                    return _distinct_call_path_count(status_paths)
                return int(counts_by_status.get(status) or 0)

            confirmed_path_count = status_path_count('reachable')
            occurrences_by_status = (
                overview.get('occurrence_counts_by_status')
                or counts_by_status
            )
            confirmed_occurrence_count = int(
                occurrences_by_status.get('reachable') or 0
            )
            additional_review_path_count = sum(
                status_path_count(status)
                for status in ('uncertain', 'not_analyzed')
            ) if fallback_conclusion == '已确认影响' else 0
            uncertain_path_count = status_path_count('uncertain')
            not_analyzed_path_count = status_path_count('not_analyzed')
            uncertain_paths = list(paths_by_status.get('uncertain') or [])[:5]
            not_analyzed_paths = list(paths_by_status.get('not_analyzed') or [])[:5]
            fallback_business_entries = _item_business_entries(
                findings,
                item,
                limit=None,
                statuses=desired_statuses,
            )
            all_business_entries = {
                str(entry or "").strip()
                for status in desired_statuses
                for entry in (all_entries_by_status.get(status) or [])
                if str(entry or "").strip()
            }
            all_business_entries.update(fallback_business_entries)
            business_entries = sorted(all_business_entries)
            modules = _item_modules(findings, item)
            path_count = _path_count_for_report(
                item, overview_lookup, sampled_paths, desired_statuses
            )
            occurrence_count = _occurrence_count_for_report(
                item,
                overview_lookup,
                path_count,
                desired_statuses,
            )
            row = {
                'api_id': str(overview.get('api_id') or '').strip(),
                'coord': identity[0],
                'old_version': old_version,
                'new_version': new_version,
                'api': identity[1],
                'api_signature': identity[2],
                'symbol_kind': identity[3],
                'change_type': identity[4],
                'severity': _normalized_report_severity(
                    severity or item.get('severity')
                ),
                'change': _change_cell(item, severity),
                'change_without_severity': _change_cell(
                    item,
                    include_item_severity=False,
                ),
                'conclusion': item_conclusion,
                'uncertainty_kind': (
                    _uncertainty_kind(report_item)
                    if fallback_conclusion == UNCERTAIN_CANDIDATE_CONCLUSION
                    else ''
                ),
                'priority_score': int(item.get('priority_score') or 0),
                'priority_factors': dict(item.get('priority_factors') or {}),
                'business_entries': business_entries,
                'business_entry_count': len(all_business_entries),
                'modules': modules,
                'paths': sampled_paths,
                'uncertain_paths': uncertain_paths,
                'not_analyzed_paths': not_analyzed_paths,
                'evidence_statuses': list(desired_statuses),
                'path_count': path_count,
                'occurrence_count': occurrence_count,
                # Executable-path certainty and impact certainty are separate.
                # A probable impact may still have an exact binary call path.
                'confirmed_path_count': confirmed_path_count,
                'confirmed_occurrence_count': confirmed_occurrence_count,
                'additional_review_path_count': additional_review_path_count,
                'uncertain_path_count': uncertain_path_count,
                'not_analyzed_path_count': not_analyzed_path_count,
            }
            _set_report_row_reasons(
                row,
                [item.get("reason_code")],
                row.get('conclusion') or fallback_conclusion,
            )
            rows.append(row)
            row_by_key[key] = row
            version_values_by_key[key] = {
                "old": {old_version} if old_version else set(),
                "new": {new_version} if new_version else set(),
            }
    return sorted(rows, key=_report_result_sort_key)


def _percentage(numerator, denominator):
    if not denominator:
        return "0.0%"
    return f"{(100.0 * numerator / denominator):.1f}%"


def _confirmed_impact_distribution(findings, rows=None):
    rows = [
        row for row in (rows or build_api_result_rows(findings))
        if row.get("conclusion") == "已确认影响"
    ]
    overview_lookup = {
        _identity_without_severity(item): item
        for item in ((findings.get("impact_overview") or {}).get("apis") or [])
    }
    dependencies = {}
    entries = {}
    change_types = defaultdict(int)
    severity_counts = defaultdict(int)
    entry_api_relations = 0

    for row in rows:
        coord = str(row.get("coord") or "").strip() or "未知依赖"
        severity = _normalized_report_severity(row.get("severity"))
        severity_counts[severity] += 1
        change_label = _human_change_type(
            row.get("change_type"), row.get("symbol_kind")
        )
        change_types[change_label] += 1

        overview = overview_lookup.get(_identity_without_severity(row)) or {}
        reachable_entries = {
            str(value or "").strip()
            for value in (
                (overview.get("all_entries_by_status") or {}).get("reachable")
                or row.get("business_entries")
                or []
            )
            if str(value or "").strip()
        }
        dependency = dependencies.setdefault(coord, {
            "coord": coord,
            "api_count": 0,
            "p0": 0,
            "p1": 0,
            "p2": 0,
            "unclassified": 0,
            "entries": set(),
            "path_count": 0,
            "occurrence_count": 0,
        })
        dependency["api_count"] += 1
        severity_key = severity.lower()
        if severity_key in {"p0", "p1", "p2"}:
            dependency[severity_key] += 1
        else:
            dependency["unclassified"] += 1
        dependency["entries"].update(reachable_entries)
        dependency["path_count"] += int(
            row.get("confirmed_path_count") or row.get("path_count") or 0
        )
        dependency["occurrence_count"] += int(
            row.get("confirmed_occurrence_count")
            or row.get("occurrence_count")
            or 0
        )

        api_identity = _identity_without_severity(row)
        for entry in reachable_entries:
            entry_item = entries.setdefault(entry, {
                "entry": entry,
                "api_identities": set(),
                "dependencies": set(),
                "p0": 0,
                "p1": 0,
                "p2": 0,
                "unclassified": 0,
            })
            if api_identity in entry_item["api_identities"]:
                continue
            entry_item["api_identities"].add(api_identity)
            entry_item["dependencies"].add(coord)
            if severity_key in {"p0", "p1", "p2"}:
                entry_item[severity_key] += 1
            else:
                entry_item["unclassified"] += 1
            entry_api_relations += 1

    dependency_rows = []
    for item in dependencies.values():
        dependency_rows.append({
            **item,
            "business_entry_count": len(item["entries"]),
        })
    dependency_rows.sort(key=lambda item: (
        -int(item.get("p0") or 0),
        -int(item.get("p1") or 0),
        -int(item.get("api_count") or 0),
        -int(item.get("path_count") or 0),
        str(item.get("coord") or ""),
    ))

    entry_rows = []
    for item in entries.values():
        entry_rows.append({
            **item,
            "api_count": len(item["api_identities"]),
            "dependency_count": len(item["dependencies"]),
        })
    entry_rows.sort(key=lambda item: (
        -int(item.get("p0") or 0),
        -int(item.get("p1") or 0),
        -int(item.get("api_count") or 0),
        -int(item.get("dependency_count") or 0),
        str(item.get("entry") or ""),
    ))

    return {
        "confirmed_count": len(rows),
        "dependency_rows": dependency_rows,
        "entry_rows": entry_rows,
        "entry_api_relation_count": entry_api_relations,
        "severity_counts": dict(severity_counts),
        "change_types": dict(sorted(
            change_types.items(),
            key=lambda item: (-item[1], item[0]),
        )),
        "logical_path_count": sum(
            int(row.get("confirmed_path_count") or row.get("path_count") or 0)
            for row in rows
        ),
        "occurrence_count": sum(
            int(
                row.get("confirmed_occurrence_count")
                or row.get("occurrence_count")
                or 0
            )
            for row in rows
        ),
    }


def render_impact_distribution(findings, *, heading_level=3, force=False):
    overview = findings.get("impact_overview") or {}
    distribution = _confirmed_impact_distribution(findings)
    confirmed_count = int(distribution.get("confirmed_count") or 0)
    dependency_rows = list(distribution.get("dependency_rows") or [])
    entry_rows = list(distribution.get("entry_rows") or [])
    record_count = int(overview.get("record_count") or 0)
    all_api_count = len(overview.get("apis") or [])
    should_render = (
        force
        or confirmed_count > min(8, S6_MAIN_RESULT_LIMIT)
        or record_count > S6_MAIN_RESULT_LIMIT
        or len(dependency_rows) > 1
        or len(entry_rows) > 3
    )
    if not confirmed_count or not should_render:
        return []

    normalized_heading_level = max(2, min(5, int(heading_level or 3)))
    heading = "#" * normalized_heading_level
    subheading = "#" * (normalized_heading_level + 1)
    lines = [
        f"{heading} 已确认影响分布",
        "",
    ]
    if record_count:
        lines.append(
            f"- **证据归并**：逐链路台账包含 {record_count} 条有效记录，"
            f"归并为 {all_api_count} 个变更 API。"
        )
    lines.append(
        f"- **已确认范围**：{confirmed_count} 个变更 API，"
        f"分布于 {len(dependency_rows)} 个依赖和 {len(entry_rows)} 个业务入口；"
        f"形成 {int(distribution.get('logical_path_count') or 0)} 条不同调用链，"
        f"证据命中 {int(distribution.get('occurrence_count') or 0)} 次。"
    )

    top_dependencies = dependency_rows[:3]
    if len(dependency_rows) > 1 and top_dependencies:
        top_api_count = sum(
            int(item.get("api_count") or 0) for item in top_dependencies
        )
        lines.append(
            f"- **依赖集中度**：表中前 {len(top_dependencies)} 个依赖包含 "
            f"{top_api_count}/{confirmed_count} 个已确认影响 API"
            f"（{_percentage(top_api_count, confirmed_count)}）。"
        )

    change_types = list((distribution.get("change_types") or {}).items())
    if change_types:
        displayed_changes = "；".join(
            f"{label} {count}"
            for label, count in change_types[:S6_CONCENTRATION_LIMIT]
        )
        remaining_change_count = sum(
            count for _label, count in change_types[S6_CONCENTRATION_LIMIT:]
        )
        if remaining_change_count:
            displayed_changes += f"；其他变化 {remaining_change_count}"
        lines.append(f"- **变化类型分布**：{displayed_changes}。")
    lines.append("")

    lines += [
        f"{subheading} 依赖分布（前 {min(S6_CONCENTRATION_LIMIT, len(dependency_rows))} 个）",
        "",
        "| 依赖 | P0 | P1 | P2 | 已确认 API | 业务入口 | 不同调用链 | 证据命中 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in dependency_rows[:S6_CONCENTRATION_LIMIT]:
        lines.append(
            f"| `{_md_cell(item.get('coord'), 180)}` | "
            f"{int(item.get('p0') or 0)} | {int(item.get('p1') or 0)} | "
            f"{int(item.get('p2') or 0)} | {int(item.get('api_count') or 0)} | "
            f"{int(item.get('business_entry_count') or 0)} | "
            f"{int(item.get('path_count') or 0)} | "
            f"{int(item.get('occurrence_count') or 0)} |"
        )
    if len(dependency_rows) > S6_CONCENTRATION_LIMIT:
        remaining = dependency_rows[S6_CONCENTRATION_LIMIT:]
        lines.append(
            f"| 其他 {len(remaining)} 个依赖 | "
            f"{sum(int(item.get('p0') or 0) for item in remaining)} | "
            f"{sum(int(item.get('p1') or 0) for item in remaining)} | "
            f"{sum(int(item.get('p2') or 0) for item in remaining)} | "
            f"{sum(int(item.get('api_count') or 0) for item in remaining)} | "
            "- | "
            f"{sum(int(item.get('path_count') or 0) for item in remaining)} | "
            f"{sum(int(item.get('occurrence_count') or 0) for item in remaining)} |"
        )
    lines.append("")

    if entry_rows:
        lines += [
            f"{subheading} 业务入口分布（前 {min(S6_CONCENTRATION_LIMIT, len(entry_rows))} 个）",
            "",
            "| 业务入口 | P0 | P1 | P2 | 关联变更 API | 涉及依赖 |",
            "|---|---:|---:|---:|---:|---:|",
        ]
        for item in entry_rows[:S6_CONCENTRATION_LIMIT]:
            lines.append(
                f"| `{_md_cell(item.get('entry'), 260)}` | "
                f"{int(item.get('p0') or 0)} | {int(item.get('p1') or 0)} | "
                f"{int(item.get('p2') or 0)} | "
                f"{int(item.get('api_count') or 0)} | "
                f"{int(item.get('dependency_count') or 0)} |"
            )
        if len(entry_rows) > S6_CONCENTRATION_LIMIT:
            relation_total = int(
                distribution.get("entry_api_relation_count") or 0
            )
            displayed_relations = sum(
                int(item.get("api_count") or 0)
                for item in entry_rows[:S6_CONCENTRATION_LIMIT]
            )
            lines.append(
                f"| 其他 {len(entry_rows) - S6_CONCENTRATION_LIMIT} 个业务入口 | "
                "- | - | - | "
                f"{relation_total - displayed_relations} | - |"
            )
        lines.append("")
    return lines


def render_other_result_distribution(rows, *, heading_level=3):
    rows = list(rows or [])
    if len(rows) <= S6_MAIN_RESULT_LIMIT:
        return []

    conclusion_counts = defaultdict(int)
    severity_counts = defaultdict(int)
    change_type_counts = defaultdict(int)
    dependency_counts = defaultdict(int)
    for row in rows:
        conclusion_counts[
            str(row.get("conclusion") or "未记录结论状态")
        ] += 1
        severity_counts[
            _normalized_report_severity(row.get("severity"))
        ] += 1
        change_type_counts[
            _human_change_type(
                row.get("change_type"), row.get("symbol_kind")
            )
        ] += 1
        dependency_counts[
            str(row.get("coord") or "").strip() or "未知依赖"
        ] += 1

    conclusions = sorted(
        conclusion_counts.items(),
        key=lambda item: (-item[1], item[0]),
    )
    severities = sorted(
        severity_counts.items(),
        key=lambda item: (
            _severity_rank(item[0]),
            -item[1],
            item[0],
        ),
    )
    change_types = sorted(
        change_type_counts.items(),
        key=lambda item: (-item[1], item[0]),
    )
    dependencies = sorted(
        dependency_counts.items(),
        key=lambda item: (-item[1], item[0]),
    )

    normalized_heading_level = max(2, min(5, int(heading_level or 3)))
    heading = "#" * normalized_heading_level
    subheading = "#" * (normalized_heading_level + 1)

    def count_text(items):
        return "；".join(
            f"{_md_cell(label, 160)} {count}"
            for label, count in items
        )

    displayed_change_types = change_types[:S6_CONCENTRATION_LIMIT]
    remaining_change_count = sum(
        count for _label, count in change_types[S6_CONCENTRATION_LIMIT:]
    )
    change_type_text = count_text(displayed_change_types)
    if remaining_change_count:
        change_type_text += f"；其他变化 {remaining_change_count}"

    top_dependencies = dependencies[:S6_CONCENTRATION_LIMIT]
    top_dependency_count = sum(count for _coord, count in top_dependencies)
    lines = [
        f"{heading} 非“已确认影响”结果分布",
        "",
        f"- **结论状态分布**：{count_text(conclusions)}。",
        f"- **严重级别分布**：{count_text(severities)}。",
        f"- **变化类型分布**：{change_type_text}。",
        (
            f"- **依赖分布范围**：前 {len(top_dependencies)} 个依赖包含 "
            f"{top_dependency_count}/{len(rows)} 个结果"
            f"（{_percentage(top_dependency_count, len(rows))}）。"
        ),
        "",
        f"{subheading} 依赖分布（前 {len(top_dependencies)} 个）",
        "",
        "| 依赖 | 结果数量 |",
        "|---|---:|",
    ]
    for coord, count in top_dependencies:
        lines.append(f"| `{_md_cell(coord, 180)}` | {count} |")
    if len(dependencies) > S6_CONCENTRATION_LIMIT:
        remaining = dependencies[S6_CONCENTRATION_LIMIT:]
        lines.append(
            f"| 其他 {len(remaining)} 个依赖 | "
            f"{sum(count for _coord, count in remaining)} |"
        )
    lines.append("")
    return lines


def _business_scope_cell(row):
    entries = list(row.get('business_entries') or [])
    modules = list(row.get('modules') or [])
    if entries:
        return _join_inline([f"`{entry}`" for entry in entries], limit=2)
    if modules:
        return "模块：" + _join_inline(modules, limit=2)
    return "未定位到业务入口"


def _dependency_change_cell(row):
    coord = str(row.get('coord') or '未知依赖')
    version = _version_transition(row)
    return f"`{_md_cell(coord, 160)}`" + (f"<br>{version}" if version else "")


def _row_evidence_text(row):
    confirmed_count = int(row.get('confirmed_path_count') or 0)
    confirmed_occurrences = int(
        row.get('confirmed_occurrence_count') or confirmed_count
    )
    path_count = int(row.get('path_count') or 0)
    if confirmed_count:
        text = f"已确认调用链 {confirmed_count} 条"
        if confirmed_occurrences > confirmed_count:
            text += f"；证据命中 {confirmed_occurrences} 次"
        return text
    if row.get('conclusion') == '已确认影响' and path_count:
        text = f"已确认调用链 {path_count} 条"
        occurrence_count = int(row.get('occurrence_count') or path_count)
        if occurrence_count > path_count:
            text += f"；证据命中 {occurrence_count} 次"
        return text
    if row.get('conclusion') == '已确认不受影响' and path_count:
        return f"相同类字节码保留证据 {path_count} 条"
    if path_count:
        return f"候选或未完成证据 {path_count} 条"
    return _human_reason(row.get('reason')) or '未记录可展示的证据摘要'


def _result_boundary_text(row):
    conclusion = str(row.get('conclusion') or '')
    reason = _human_reason(row.get('reason'))
    boundaries = {
        '可能影响': '已有相关证据，但当前证据不能确认运行时是否会触发该影响。',
        UNCERTAIN_CANDIDATE_CONCLUSION: '存在候选调用关系，但尚未形成完整的系统触达证据。',
        UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION: (
            '当前未发现候选调用证据；受静态分析能力边界限制，不能据此判定未使用。'
        ),
        '输入不足，结论未确定': '本轮输入不足，未形成影响或不受影响结论。',
        '本次未完成分析': '该项未完成有效分析，不能按未影响解释。',
        '未发现调用路径': '当前静态分析范围内未找到路径；该结果不等同于已确认不受影响。',
        '已确认不受影响': (
            '当前制品存在相同类字节码保留证据；结论只覆盖 API 符号，'
            '不覆盖资源、SPI 或清单内容。'
        ),
    }
    boundary = boundaries.get(conclusion, '')
    if reason and reason.rstrip('。') not in boundary:
        return f"{reason.rstrip('。')}。{boundary}" if boundary else reason
    return boundary or reason or '当前记录未提供更多结论边界。'


def render_api_result_table(findings):
    rows = build_api_result_rows(findings)
    confirmed_rows = [row for row in rows if row.get('conclusion') == '已确认影响']
    other_rows = [row for row in rows if row.get('conclusion') != '已确认影响']
    detail_artifacts = available_s6_detail_artifacts(findings)
    confirmed_detail = next(
        (row for row in detail_artifacts if row.get('bucket') == 'confirmed'),
        None,
    )

    confirmed_limit = min(8, S6_MAIN_RESULT_LIMIT)
    displayed_confirmed = (
        confirmed_rows[:confirmed_limit]
        if confirmed_detail
        else confirmed_rows
    )
    remaining = max(S6_MAIN_RESULT_LIMIT - len(displayed_confirmed), 0)
    displayed_other = other_rows[:remaining]

    lines = ["## 二、已确认影响", ""]
    if not confirmed_rows:
        lines += ["本轮没有形成“已确认影响”结论的变更 API。", ""]
    else:
        omitted = len(confirmed_rows) - len(displayed_confirmed)
        summary_text = (
            f"本轮共有 {len(confirmed_rows)} 个已确认影响项；"
            f"下表展示 {len(displayed_confirmed)} 个"
        )
        if omitted:
            summary_text += (
                f"，其余 {omitted} 个的分布与排序样例位于"
                f"{_report_link(confirmed_detail['md_path'], confirmed_detail['title'])}；"
                f"全部 {len(confirmed_rows)} 个记录保存在"
                f"{_report_link(confirmed_detail['csv_path'], '已确认影响结构化清单')}。"
            )
        else:
            summary_text += "。"
        lines += [
            summary_text,
            "",
            "| 严重级别 | 业务入口 / 模块 | 依赖变化 | API 变化 | 已确认事实 | 证据 |",
            "|---|---|---|---|---|---|",
        ]
        for row in displayed_confirmed:
            fact = _human_reason(row.get('reason')) or '调用链已触达当前系统。'
            lines.append(
                f"| {_md_cell(row.get('severity') or '未分级', 40)} | "
                f"{_business_scope_cell(row)} | {_dependency_change_cell(row)} | "
                f"`{_md_cell(_item_api_label(row), 220)}`<br>"
                f"{_md_cell(row.get('change_without_severity'), 180)} | "
                f"{_md_cell(fact, 320)} | {_md_cell(_row_evidence_text(row), 180)} |"
            )
        lines.append("")
        lines += _render_path_sample_cards(displayed_confirmed, findings)

    lines += ["## 三、未确认事实和其他结果", ""]
    if not other_rows:
        lines += ["本轮没有未确认项或其他结论项。", ""]
        return lines

    lines += render_other_result_distribution(other_rows)

    omitted_other = len(other_rows) - len(displayed_other)
    lines += [
        (
            f"本轮共有 {len(other_rows)} 个非“已确认影响”结果；"
            f"下表展示 {len(displayed_other)} 个"
            + (f"，其余 {omitted_other} 个位于分类明细中。" if omitted_other else "。")
        ),
        "",
        "| 结论状态 | 涉及范围 | 依赖变化 | API 变化 | 已有事实与结论边界 |",
        "|---|---|---|---|---|",
    ]
    for row in displayed_other:
        lines.append(
            f"| {_md_cell(row.get('conclusion'), 120)} | {_business_scope_cell(row)} | "
            f"{_dependency_change_cell(row)} | "
            f"`{_md_cell(_item_api_label(row), 220)}`<br>{_md_cell(row.get('change'), 180)} | "
            f"{_md_cell(_result_boundary_text(row), 420)} |"
        )
    lines.append("")

    detail_rows = [
        row for row in detail_artifacts
        if row.get('bucket') != 'confirmed'
    ]
    if detail_rows:
        detail_links = "、".join(
            _report_link(row['md_path'], row['title']) for row in detail_rows
        )
        lines.extend([f"分类完整清单：{detail_links}。", ""])
    return lines


def _input_diagnostic_artifact_label(item):
    artifact = str((item or {}).get('artifact') or '').strip()
    exact_labels = {
        'coverage': '证据覆盖记录',
        'step5_selection': '分析范围快照',
        'context': '升级上下文',
        'dependency_changes': '依赖变化记录',
        'step3_dependency_compat': '依赖兼容扫描记录',
        'changed_apis': '变化 API 全集',
        'call_chain_alerts': '逐链路证据台账',
        'call_chain_summary': '系统触达汇总',
    }
    if artifact in exact_labels:
        return exact_labels[artifact]
    if artifact.startswith('call_chain_by_api:'):
        return '单个 API 的调用链证据'
    if artifact.startswith('call_chain_by_module:'):
        return '模块影响汇总'
    return '分析输入证据'


def _input_diagnostic_error_text(item):
    if str((item or {}).get("stage") or "") in {
        "row_contract",
        "identity_consistency",
        "field_consistency",
        "csv_consistency",
    }:
        return "部分记录的结构或关联关系校验未通过"
    error_type = str((item or {}).get('error_type') or '').strip()
    labels = {
        'JSONDecodeError': 'JSON 内容无法解析',
        'UnicodeDecodeError': '文本编码无法解析',
        'UnicodeError': '文本编码无法解析',
        'Error': 'CSV 内容无法解析',
        'FileNotFoundError': '文件未生成',
        'ArtifactContentError': '文件结构无法用于本轮分析',
        'JSONRootTypeError': 'JSON 根结构不是对象',
        'OSError': '文件读取失败',
        'PermissionError': '文件无法读取',
    }
    return labels.get(error_type, '文件内容无法读取')


def _input_diagnostic_fact_label(item):
    if str((item or {}).get("stage") or "") in {
        "row_contract",
        "identity_consistency",
        "field_consistency",
        "csv_consistency",
    }:
        return f"{_input_diagnostic_artifact_label(item)}部分记录无效"
    error_type = str((item or {}).get('error_type') or '')
    if error_type == 'FileNotFoundError':
        state = '未生成'
    elif error_type in {'ArtifactContentError', 'JSONRootTypeError'}:
        state = '结构无效'
    else:
        state = '无法读取'
    return f"{_input_diagnostic_artifact_label(item)}{state}"


def _input_diagnostic_impact(item, findings=None):
    artifact = str((item or {}).get('artifact') or '').strip()
    stage = str((item or {}).get("stage") or "")
    partial_record_failure = stage in {
        "row_contract",
        "identity_consistency",
        "field_consistency",
        "csv_consistency",
    }
    if artifact == 'call_chain_summary':
        if str((item or {}).get('error_type') or '') in {
            'ArtifactContentError',
            'JSONRootTypeError',
        }:
            return (
                '该文件中的结构或数量存在异常；'
                '能够由变化 API 清单和逐链路台账独立对应的结果仍保留，'
                '其余汇总结论未被采用。'
            )
        return (
            '系统触达汇总未被采用；'
            '依赖该文件形成的影响分类和数量不可用。'
        )
    if artifact == 'call_chain_alerts':
        if partial_record_failure:
            return (
                '未通过校验的逐链路记录未被采用；'
                '其余结构有效的记录仍作为对应 API 的分析记录。'
            )
        return (
            '逐链路记录未被采用；业务入口、调用链数量和证据命中次数可能缺失。'
        )
    if artifact == 'changed_apis':
        if partial_record_failure:
            return (
                '未通过校验的变化 API 记录未被采用；'
                '其余结构有效的记录仍保留，但完整范围无法确认。'
            )
        return '变化 API 全集未被采用；API 变化数量和覆盖范围可能缺失。'
    if artifact == 'coverage':
        coverage = (findings or {}).get("coverage") or {}
        coverage_status = str(
            coverage.get("overall_status") or ""
        ).strip()
        if coverage_status == "partial":
            return (
                "正式证据覆盖文件未生成；现有系统触达汇总显示"
                "关键证据覆盖不完整。"
            )
        if coverage_status in {"complete", "not_applicable"}:
            return (
                "正式证据覆盖文件未生成；现有系统触达汇总记录了"
                f"{'证据覆盖完整' if coverage_status == 'complete' else '证据覆盖不适用'}，"
                "但缺少独立的正式覆盖记录。"
            )
        return '证据覆盖状态无法确认；报告不支持“证据覆盖完整”结论。'
    if artifact == 'step5_selection':
        return '本轮分析范围无法确认；报告不支持全量分析结论。'
    if artifact == 'context':
        return '升级版本和构建环境信息可能缺失。'
    if artifact == 'dependency_changes':
        return '依赖版本变化信息可能缺失。'
    if artifact.startswith('call_chain_by_api:'):
        return '对应 API 的物理调用边可能缺失。'
    if artifact.startswith('call_chain_by_module:'):
        return '对应模块的影响汇总可能缺失。'
    return '依赖该文件形成的统计或结论可能缺失。'


def _input_diagnostic_gap_rows(findings):
    diagnostics = list(findings.get('diagnostics') or [])
    rows = []
    for item in diagnostics[:S6_MAIN_DIAGNOSTIC_LIMIT]:
        file_name = Path(str(item.get('path') or '')).name or '文件名未记录'
        error_text = _input_diagnostic_error_text(item)
        rows.append({
            'label': _input_diagnostic_fact_label(item),
            'impact': _input_diagnostic_impact(item, findings),
            'evidence': [],
            'evidence_text': f"`{_md_cell(file_name, 120)}`：{error_text}",
        })
    if len(diagnostics) > S6_MAIN_DIAGNOSTIC_LIMIT:
        rows.append({
            'label': (
                f"另有 {len(diagnostics) - S6_MAIN_DIAGNOSTIC_LIMIT} 个"
                "输入证据文件缺失或无法读取"
            ),
            'impact': '这些文件对应的统计或结论可能缺失。',
            'evidence': [],
            'evidence_text': '完整记录保存在分析诊断明细中',
        })
    return rows


def render_input_diagnostics(findings):
    diagnostics = list(findings.get('diagnostics') or [])
    if not diagnostics:
        return []
    lines = [
        "## 输入证据读取事实",
        "",
        "| 输入证据 | 文件 | 读取结果 | 对结论的限制 |",
        "|---|---|---|---|",
    ]
    for item in diagnostics:
        file_name = Path(str(item.get('path') or '')).name or '文件名未记录'
        lines.append(
            f"| {_md_cell(_input_diagnostic_artifact_label(item), 100)} | "
            f"`{_md_cell(file_name, 160)}` | "
            f"{_input_diagnostic_error_text(item)} | "
            f"{_md_cell(_input_diagnostic_impact(item, findings), 300)} |"
        )
    lines.append("")
    return lines


def _diagnostic_scope_label(scope):
    return {
        'global': '全局',
        'path': '相关调用路径',
        'api': '单个 API',
        'step': '对应步骤/覆盖组件',
        'mixed': '混合作用域',
        'unknown': '旧结果未记录',
    }.get(str(scope or ''), '未记录')


def _diagnostic_origin_label(origin):
    value = str(origin or "").strip().lower()
    if not value or value == "unknown":
        return "未记录"
    match = re.fullmatch(r"step[_ -]?(\d+)", value)
    if match:
        return f"Step {match.group(1)}"
    return "未记录"


def _diagnostic_reason_code(value):
    code = str(value or "UNKNOWN").strip()
    if re.fullmatch(r"[A-Z][A-Z0-9_]*", code):
        return code
    return "UNKNOWN"


def _diagnostic_definition(item):
    code = _diagnostic_reason_code(
        (item or {}).get("reason_code")
    )
    return guidance_for_reason_code(
        code,
        origin_step=(item or {}).get("origin_step") or "",
    )


_OBJECTIVE_DIAGNOSTIC_TRIGGER_CONDITIONS = {
    "BYTECODE_CALLER_UNRESOLVED": (
        "业务字节码扫描发现调用方，但现有源码方法索引无法将该调用方"
        "唯一对应到源码方法。"
    ),
    "INCOMPLETE_EVIDENCE_COVERAGE": (
        "至少一个必需证据组件处于不完整、失败或未记录状态。"
    ),
}


def _self_contained_diagnostic_detail(value):
    text = str(value or '').strip()
    if not text:
        return ''
    text = re.sub(
        r'\s*[；;,，。]?\s*(?:详见|参见|see)\s+[`"\']?occurrences[`"\']?.*$',
        '',
        text,
        flags=re.IGNORECASE,
    ).strip()
    return text


def _diagnostic_evidence_text(item):
    pieces = []
    classes = list(item.get('affected_classes') or [])
    artifacts = list(item.get('affected_artifacts') or [])
    entries = list(item.get('affected_artifact_entries') or [])
    collectors = list(item.get('collectors') or [])
    candidates = list(item.get('candidate_evidence') or [])
    source_components = list(item.get('source_components') or [])
    evidence_files = list(
        item.get('evidence_files')
        or ([item.get('evidence_file')] if item.get('evidence_file') else [])
    )
    if classes:
        pieces.append('类：' + '、'.join(classes[:5]))
    if artifacts:
        pieces.append('制品：' + '、'.join(_short_path(value) for value in artifacts[:3]))
    if entries:
        pieces.append('物理条目：' + '、'.join(entries[:3]))
    if collectors:
        pieces.append('采集器：' + '、'.join(collectors[:3]))
    if candidates:
        candidate_text = []
        for candidate in candidates[:3]:
            coord = str(candidate.get('coord') or '').strip()
            entry = str(candidate.get('artifact_entry') or '').strip()
            digest = str(candidate.get('bytecode_sha256') or '').strip()
            label = coord or _short_path(candidate.get('artifact') or '')
            if entry:
                label = f"{label}@{entry}" if label else entry
            if digest:
                label += f" (class sha256={digest[:12]}…)"
            if label:
                candidate_text.append(label)
        if candidate_text:
            pieces.append('候选：' + '、'.join(candidate_text))
    if source_components:
        pieces.append(
            '覆盖组件：'
            + '、'.join(_coverage_item_label(value) for value in source_components[:5])
        )
    if evidence_files:
        pieces.append(
            '指令级明细：'
            + '、'.join(
                _report_link(value, Path(str(value)).name)
                for value in evidence_files[:3]
            )
        )
    return '；'.join(pieces) or '当前只记录了 API 级原因，未附加制品或类证据。'


def render_diagnostic_guidance(findings):
    guidance = list(findings.get('diagnostic_guidance') or [])
    if not guidance:
        return []
    lines = [
        "## 分析诊断事实",
        "",
        "| 来源阶段 | 诊断编码 | 事实 | 本轮作用域 | 相关 API | 是否限制结论 |",
        "|---|---|---|---|---:|---|",
    ]
    for item in guidance:
        code = _diagnostic_reason_code(item.get('reason_code'))
        related_api_count = _diagnostic_potential_api_count(item)
        lines.append(
            f"| {_md_cell(_diagnostic_origin_label(item.get('origin_step')), 40)} | "
            f"`{_md_cell(code, 100)}` | "
            f"{_md_cell(_diagnostic_plain_title(item), 120)} | "
            f"{_diagnostic_scope_label(item.get('observed_scope'))} | "
            f"{related_api_count} | "
            f"{'是' if item.get('blocking') else '否'} |"
        )
    lines.append("")

    for item in guidance:
        code = _diagnostic_reason_code(item.get('reason_code'))
        definition = _diagnostic_definition(item)
        trigger_condition = str(
            _OBJECTIVE_DIAGNOSTIC_TRIGGER_CONDITIONS.get(code)
            or definition.get('trigger_condition')
            or ''
        ).strip()
        if (
            not trigger_condition
            or "具体触发证据见本条" in trigger_condition
        ):
            trigger_condition = "未记录更具体的触发条件。"
        lines += [
            f"#### `{code}` — {_diagnostic_plain_title(item)}",
            "",
            f"- **记录条件**：{trigger_condition}",
            f"- **本轮观察范围**：{_diagnostic_observed_scope_text(item)}",
            f"- **对结论的限制**：{_diagnostic_objective_impact(item)}",
            f"- **物理证据**：{_diagnostic_evidence_text(item)}",
        ]
        sample_apis = list(item.get('sample_apis') or [])
        if sample_apis:
            lines += [
                "",
                "**相关 API 样例**：",
                "",
            ]
            for api_identity in sample_apis:
                lines.append(f"- `{_md_cell(api_identity, 300)}`")
        lines.append("")
    return lines


def render_diagnostic_detail_artifact(findings):
    lines = [
        "# 分析诊断明细",
        "",
        "本文件保存诊断编码、来源阶段、观察范围和证据。主报告只呈现这些诊断对结论的客观限制。",
        "",
    ]
    input_detail = render_input_diagnostics(findings)
    guidance_detail = render_diagnostic_guidance(findings)
    if input_detail:
        lines.extend(input_detail)
    if guidance_detail:
        lines.extend(guidance_detail)
    if not input_detail and not guidance_detail:
        lines.extend(["本轮没有分析诊断记录。", ""])
    return "\n".join(lines).rstrip() + "\n"


def write_diagnostic_detail_artifact(report_dir, findings):
    relative_path = "deliverables/analysis-diagnostics.md"
    path = Path(report_dir) / relative_path
    if not (
        (findings.get('diagnostic_guidance') or [])
        or (findings.get('diagnostics') or [])
    ):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return ""
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text(path, render_diagnostic_detail_artifact(findings))
    return relative_path


def _diagnostic_plain_title(item):
    code = _diagnostic_reason_code(item.get('reason_code'))
    definition = _diagnostic_definition(item)
    title = str(definition.get('title') or '').strip()
    if title and title not in {'分析诊断需要处理', '分析诊断'}:
        return title
    labels = {
        'BYTECODE_CALLER_UNRESOLVED': '业务字节码中有调用方未能映射到源码方法',
        'DEPENDENCY_SOURCE_REF_UNAVAILABLE': '依赖源码版本未能固定',
        'JAPICMP_EXECUTION_FAILED': '部分依赖的二进制 API 对比未完成',
        'JAPICMP_TIMEOUT': '部分依赖的二进制 API 对比超时',
        'SPRING_RUNTIME_CLASS_AMBIGUOUS': 'Spring 运行时类存在多个无法区分的候选',
        'MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED': 'MyBatis 运行时制品解析失败',
        'S6_EVIDENCE_IDENTITY_MISMATCH': '跨产物 API 身份未能一致确认',
    }
    if code in labels:
        return labels[code]
    return '分析过程记录了证据缺口'


def _objective_diagnostic_text(value, fallback=''):
    text = str(value or '').strip()
    if not text:
        return fallback
    replacements = {
        '当前结论需要复核': '当前结论的适用范围受到限制',
        '需要人工复核': '尚未形成确定结论',
        '需人工复核': '结论尚未确定',
        '建议决策': '结论状态',
        '只应阻断': '影响范围仅限于',
        '不应被降级': '不受该诊断影响',
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    return text


def _diagnostic_potential_api_count(item):
    if item.get('potentially_affected_api_count') is not None:
        return (
            _strict_non_negative_int(item.get('potentially_affected_api_count'))
            or 0
        )
    return _strict_non_negative_int(item.get('affected_api_count')) or 0


def _diagnostic_observed_scope_text(item):
    affected_count = _diagnostic_potential_api_count(item)
    primary_count = (
        _strict_non_negative_int(item.get('primary_reason_api_count')) or 0
    )
    record_count = (
        _strict_non_negative_int(item.get('failure_record_count'))
        if item.get('failure_record_count') is not None
        else _strict_non_negative_int(item.get('observed_failure_count'))
    ) or 0
    occurrence_count = (
        _strict_non_negative_int(item.get('failure_occurrence_count')) or 0
    )
    if affected_count:
        text = f"传播范围关联 {affected_count} 个 API"
        if primary_count:
            text += f"，其中 {primary_count} 个以该原因为主原因"
        text += f"；记录作用域为{_diagnostic_scope_label(item.get('observed_scope'))}"
        if record_count:
            text += f"；failure 记录 {record_count} 条"
            if occurrence_count and occurrence_count != record_count:
                text += f"，包含 {occurrence_count} 个物理位置"
        return text + "。"
    text = (
        "未关联到本轮目标 API；"
        f"记录作用域为{_diagnostic_scope_label(item.get('observed_scope'))}"
    )
    if record_count:
        text += f"；failure 记录 {record_count} 条"
        if occurrence_count and occurrence_count != record_count:
            text += f"，包含 {occurrence_count} 个物理位置"
    return text + "。"


def _diagnostic_objective_impact(item):
    code = _diagnostic_reason_code(item.get("reason_code"))
    affected_count = _diagnostic_potential_api_count(item)
    if affected_count:
        definition = _diagnostic_definition(item)
        return _objective_diagnostic_text(
            definition.get('semantic_impact'),
            '该诊断限制相关 API 结论的解释范围。',
        )
    if (
        str(item.get('observed_scope') or '').strip() == 'api'
        and (_strict_non_negative_int(item.get('raw_blocking_failure_count')) or 0)
        and not (
            _strict_non_negative_int(item.get('relevant_blocking_failure_count'))
            or 0
        )
    ):
        return (
            "该 API 级 failure 未与本轮目标 API 建立关联，不限制本轮 API 结论；"
            "原始记录仅作为覆盖遥测保留。"
        )
    if bool(item.get('blocking')):
        scope = str(item.get('observed_scope') or '').strip()
        if code == "BYTECODE_CALLER_UNRESOLVED":
            return (
                "分析过程记录了未映射到源码方法的字节码调用方；"
                "对应源码入口和源码位置可能缺失。"
            )
        fallback = (
            '该诊断记录为全局作用域；'
            '未完成、未确认和未命中结果的解释范围受到限制。'
            if scope == 'global'
            else '该诊断限制对应分析步骤及其下游结论的解释范围。'
        )
        return fallback
    return (
        "不改变已由完整调用链或当前最终制品证明的影响结论；"
        "未完成、未确认和未命中结果的解释范围受到限制。"
    )


def render_diagnostic_summary(findings):
    guidance = list(findings.get('diagnostic_guidance') or [])
    if not guidance:
        return []
    lines = [
        "### 分析诊断摘要",
        "",
        "| 诊断事实 | 本轮观察范围 | 对结论的限制 |",
        "|---|---|---|",
    ]
    for item in guidance[:S6_MAIN_DIAGNOSTIC_LIMIT]:
        lines.append(
            f"| {_md_cell(_diagnostic_plain_title(item), 160)} | "
            f"{_md_cell(_diagnostic_observed_scope_text(item), 260)} | "
            f"{_md_cell(_diagnostic_objective_impact(item), 300)} |"
        )
    if len(guidance) > S6_MAIN_DIAGNOSTIC_LIMIT:
        lines.append(
            f"| 其他 {len(guidance) - S6_MAIN_DIAGNOSTIC_LIMIT} 条诊断 | "
            "未在主报告展开。 | 具体作用范围保留在诊断明细中。 |"
        )
    lines.append("")
    diagnostic_path = ((findings.get('artifacts') or {}).get('diagnostic_detail_md') or '').strip()
    if diagnostic_path:
        lines.extend([
            "诊断编码、来源阶段和物理证据：[分析诊断明细](analysis-diagnostics.md)。",
            "",
        ])
    return lines


def render_limitations_section(findings):
    coverage = findings.get('coverage') or {}
    gap_rows = [
        *_input_diagnostic_gap_rows(findings),
        *_coverage_gap_rows(coverage),
    ]
    analysis_scope = findings.get('analysis_scope') or {}
    scope_mode = str(analysis_scope.get('mode') or '')
    if scope_mode == 'partial':
        excluded = list(analysis_scope.get('excluded_dependency_coords') or [])
        excluded_preview = '、'.join(excluded[:5])
        if len(excluded) > 5:
            excluded_preview += f" 等 {len(excluded)} 个依赖"
        gap_rows.insert(0, {
            'label': '本轮只覆盖部分变化依赖',
            'impact': (
                '本报告结论只适用于所选依赖；未选择的变化依赖未执行系统触达分析，'
                '当前范围不支持全局无影响结论。'
                + (f" 未分析：{excluded_preview}。" if excluded_preview else '')
            ),
            'evidence': ['deliverables/analysis-scope.md'],
        })
    elif scope_mode != 'full':
        scope_invalid = (
            analysis_scope.get("validation_status") == "invalid"
        )
        gap_rows.insert(0, {
            'label': (
                '分析范围无法核验'
                if scope_invalid
                else '分析范围快照缺失'
            ),
            'impact': (
                '分析范围与变化 API 证据未通过一致性校验；'
                '报告不支持全量分析或全局无影响结论。'
                if scope_invalid
                else
                '无法证明本轮覆盖了全部变化依赖；'
                '报告不支持全量分析或全局无影响结论。'
            ),
            'evidence': [],
        })
    not_impacted = findings.get('not_impacted') or []
    if not_impacted:
        gap_rows.append({
            'label': '已确认不受影响的范围',
            'impact': (
                '该结论只表示依赖 API 变化分析识别的 API 仍由当前制品以相同类字节码提供；'
                '不包含被删除 JAR 中的 SPI 配置、资源文件、清单等非 API 内容。'
            ),
            'evidence': ['evidence/call_chain/alerts.csv'],
        })
    lines = [
        "## 四、分析范围和证据边界",
        "",
        f"- **本轮范围**：{_scope_text(findings)}。",
        f"- **证据覆盖**：{_coverage_status_label(_effective_coverage_status(findings))}。",
        "",
    ]
    if gap_rows:
        if _confirmed_items(findings):
            lines += [
                (
                    "下列边界不推翻已经由当前最终制品或完整调用链证明的“已确认影响”；"
                    "它们限制的是未确认项、未命中项或源码定位的解释范围。"
                ),
                "",
            ]
        lines += [
            "| 边界事实 | 对结论的限制 | 证据 |",
            "|---|---|---|",
        ]
        for row in gap_rows:
            evidence_links = []
            for value in row.get('evidence') or []:
                normalized = str(value or '').strip()
                if (
                    not normalized
                    or normalized.startswith('.runtime/')
                    or not _evidence_is_available(findings, normalized)
                ):
                    continue
                label = Path(normalized).name if Path(normalized).is_absolute() else normalized
                evidence_links.append(_report_link(normalized, label))
            evidence = (
                str(row.get('evidence_text') or '').strip()
                or "<br>".join(evidence_links[:3])
                or "-"
            )
            lines.append(
                f"| {_md_cell(row.get('label'), 120)} | {_md_cell(row.get('impact'), 260)} | {evidence} |"
            )
        lines.append("")
    else:
        lines += ["未记录会改变结论适用范围的关键证据缺口。", ""]
    lines += render_diagnostic_summary(findings)
    return lines


def render_report_appendix(findings):
    rows = []
    artifacts = findings.get('artifacts') or {}
    scope_path = str(artifacts.get('analysis_scope_md') or '').strip()
    if scope_path:
        rows.append(
            "| [本轮分析范围](analysis-scope.md) | 已纳入和未纳入的变化依赖及 API 数量 |"
        )
    alerts_path = str(artifacts.get('alerts_csv') or '').strip()
    if alerts_path:
        rows.append(
            f"| {_report_link(alerts_path, '`evidence/call_chain/alerts.csv`')} | "
            "完整逐链路证据台账 |"
        )
    changed_apis_path = str(artifacts.get('changed_apis_csv') or '').strip()
    if changed_apis_path:
        rows.append(
            f"| {_report_link(changed_apis_path, '`evidence/api_changes/all_changed_apis.csv`')} | "
            "本轮 API 变化全集 |"
        )
    diagnostic_path = str(artifacts.get('diagnostic_detail_md') or '').strip()
    if diagnostic_path:
        rows.append(
            "| [分析诊断明细](analysis-diagnostics.md) | 诊断编码、来源阶段、观察范围和物理证据 |"
        )
    for detail in available_s6_detail_artifacts(findings):
        rows.append(
            f"| {_report_link(detail['csv_path'], detail['title'] + '（完整 CSV）')} | "
            "该结论分类的完整结构化记录 |"
        )
    lines = ["## 五、证据索引", ""]
    if not rows:
        return [
            *lines,
            "本轮没有记录可用的证据文件或分类明细文件。",
            "",
        ]
    return [
        *lines,
        "| 证据 | 记录内容 |",
        "|---|---|",
        *rows,
        "",
    ]


_INCOMPLETE_API_CONCLUSIONS = {
    "输入不足，结论未确定",
    "本次未完成分析",
}


def _api_result_is_incomplete(row):
    return str((row or {}).get("conclusion") or "").strip() in (
        _INCOMPLETE_API_CONCLUSIONS
    )


def _api_human_category(row):
    if _api_result_is_incomplete(row):
        return "未完成分析"
    conclusion = str((row or {}).get("conclusion") or "").strip()
    if conclusion == "已确认影响":
        return "确认有影响"
    if conclusion == "已确认不受影响":
        return "确认不受影响"
    if conclusion == "未发现调用路径":
        return "未发现调用路径"
    # Unknown completed labels remain unconfirmed and must never fall through
    # to a positive or safe conclusion.
    return "结论未确定"


def _api_human_category_counts(api_model):
    counts = defaultdict(int)
    for row in (api_model or {}).get("rows") or []:
        counts[_api_human_category(row)] += int(
            row.get("aggregate_count") or 1
        )
    return counts


def _api_result_priority(row):
    """Prefer a completed structural result when duplicate evidence exists."""
    ranks = {
        "已确认影响": 0,
        "已确认不受影响": 1,
        "可能影响": 2,
        UNCERTAIN_CANDIDATE_CONCLUSION: 3,
        UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION: 3,
        "未发现调用路径": 4,
        "输入不足，结论未确定": 5,
        "本次未完成分析": 6,
    }
    return (
        ranks.get(str((row or {}).get("conclusion") or ""), 9),
        _report_result_sort_key(row or {}),
    )


def _analysis_conclusion_label(row):
    conclusion = str((row or {}).get("conclusion") or "").strip()
    labels = {
        "已确认影响": "确认有影响",
        "已确认不受影响": "确认不受影响",
        "可能影响": "未确认影响（存在候选关系）",
        UNCERTAIN_CANDIDATE_CONCLUSION: "未确认影响（存在候选关系）",
        UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION: "未确认影响（静态分析能力边界）",
        "未发现调用路径": "未确认影响",
        "输入不足，结论未确定": "未完成分析",
        "本次未完成分析": "未完成分析",
    }
    return labels.get(conclusion, conclusion or "未完成分析")


def _scope_excluded_coords(findings):
    return {
        _canonical_identity_coord(value)
        for value in (
            (findings.get("analysis_scope") or {}).get(
                "excluded_dependency_coords"
            )
            or []
        )
        if _canonical_identity_coord(value)
    }


def _report_scope_is_verified(findings):
    scope = (findings or {}).get("analysis_scope") or {}
    return (
        str(scope.get("mode") or "").strip() in {"full", "partial"}
        and scope.get("validation_status") != "invalid"
    )


def _report_scope_included_coords(findings):
    """Return the exact dependency population for a valid partial report.

    A partial Step5 run is a deliberate report boundary. The Step1/Step4
    inventories remain complete evidence, but only the explicitly included
    dependencies belong to the Step6 result population.
    """
    scope = (findings or {}).get("analysis_scope") or {}
    if (
        str(scope.get("mode") or "").strip() != "partial"
        or scope.get("validation_status") == "invalid"
    ):
        return None
    included = {
        _canonical_identity_coord(value)
        for value in scope.get("included_dependency_coords") or []
        if _canonical_identity_coord(value)
    }
    declared_count = int(scope.get("included_dependency_count") or 0)
    if len(included) != declared_count:
        return None
    return included


def _incomplete_api_reason(row, findings):
    explicit = str((row or {}).get("incomplete_reason") or "").strip()
    if explicit:
        return explicit
    coord = _canonical_identity_coord((row or {}).get("coord"))
    if coord and coord in _scope_excluded_coords(findings):
        return (
            "本轮调用关系分析范围未包含该依赖，因此该 API "
            "没有产生调用关系分析结果。"
        )
    reason = _objective_reason_text(
        (row or {}).get("reason_code"),
        (row or {}).get("conclusion"),
    )
    if reason:
        return reason
    reason = _human_reason((row or {}).get("reason"))
    if reason:
        return reason
    return "当前记录没有保存该 API 未完成调用关系分析的具体原因。"


def _inventory_api_row(item):
    identity = build_api_identity_key(item)
    normalized = {
        "coord": identity[0],
        "api": identity[1],
        "api_signature": identity[2],
        "symbol_kind": identity[3],
        "change_type": identity[4],
        "severity": _normalized_report_severity(item.get("severity")),
        "old_version": str(item.get("old_version") or "").strip(),
        "new_version": str(item.get("new_version") or "").strip(),
        "paths": [],
        "business_entries": [],
        "business_entry_count": 0,
        "path_count": 0,
        "occurrence_count": 0,
        "confirmed_path_count": 0,
        "confirmed_occurrence_count": 0,
        "evidence_statuses": [],
        "aggregate_count": 1,
    }
    normalized["change_without_severity"] = _change_cell(
        normalized,
        include_item_severity=False,
    )
    normalized["change"] = normalized["change_without_severity"]
    return normalized


def build_human_api_analysis(findings):
    """Build the exact changed/completed/incomplete API population for reports."""
    report_scope_coords = _report_scope_included_coords(findings)
    result_groups = defaultdict(list)
    for row in build_api_result_rows(findings):
        identity = build_api_identity_key(row)
        if (
            _identity_is_complete(identity)
            and (
                report_scope_coords is None
                or identity[0] in report_scope_coords
            )
        ):
            result_groups[identity].append(dict(row))

    selected_results = {
        identity: sorted(rows, key=_api_result_priority)[0]
        for identity, rows in result_groups.items()
    }
    raw_inventory = list(findings.get("changed_api_inventory") or [])
    if report_scope_coords is not None:
        raw_inventory = [
            item
            for item in raw_inventory
            if _canonical_identity_coord(item.get("coord"))
            in report_scope_coords
        ]
    inventory = {}
    inventory_variant_counts = defaultdict(lambda: defaultdict(int))
    complete_inventory_row_count = 0
    for item in raw_inventory:
        identity = build_api_identity_key(item)
        if _identity_is_complete(identity):
            complete_inventory_row_count += 1
            normalized_inventory_row = _inventory_api_row(item)
            inventory.setdefault(identity, normalized_inventory_row)
            variant = (
                str(normalized_inventory_row.get("old_version") or ""),
                str(normalized_inventory_row.get("new_version") or ""),
                str(normalized_inventory_row.get("severity") or ""),
                str(
                    normalized_inventory_row.get(
                        "change_without_severity"
                    )
                    or ""
                ),
            )
            inventory_variant_counts[identity][variant] += 1
    conflicting_inventory_identities = {
        identity: sum(variants.values())
        for identity, variants in inventory_variant_counts.items()
        if len(variants) > 1
    }
    duplicate_inventory_count = max(
        complete_inventory_row_count - len(inventory),
        0,
    )
    incomplete_inventory_identity_count = max(
        len(raw_inventory) - complete_inventory_row_count,
        0,
    )

    excluded_coords = _scope_excluded_coords(findings)
    rows = []
    for identity, inventory_row in inventory.items():
        result = selected_results.pop(identity, None)
        if result is None:
            result = dict(inventory_row)
            result["conclusion"] = "本次未完成分析"
            if identity[0] in excluded_coords:
                result["incomplete_reason"] = (
                    "本轮调用关系分析范围未包含该依赖，因此该 API "
                    "没有产生调用关系分析结果。"
                )
            else:
                result["incomplete_reason"] = (
                    "变化 API 清单中记录了该 API，但调用关系分析结果中"
                    "没有对应记录。"
                )
        else:
            for field in (
                "old_version",
                "new_version",
                "symbol_kind",
                "change_type",
                "api_signature",
            ):
                if not result.get(field):
                    result[field] = inventory_row.get(field, "")
            if not result.get("change_without_severity"):
                result["change_without_severity"] = inventory_row[
                    "change_without_severity"
                ]
        conflict_record_count = int(
            conflicting_inventory_identities.get(identity) or 0
        )
        if conflict_record_count:
            result["old_version"] = ""
            result["new_version"] = ""
            result["conclusion"] = "本次未完成分析"
            result["incomplete_reason"] = (
                "变化 API 清单中同一 API 身份存在 "
                f"{conflict_record_count} 条互相冲突的版本或变化内容记录，"
                "无法确认该 API 的唯一变化内容。"
            )
            result["input_record_conflict"] = True
        result.setdefault("aggregate_count", 1)
        rows.append(result)

    # When the inventory is available it is the authoritative changed-API
    # population. A result with a different identity is a consistency error,
    # not an additional changed API. If the inventory is unavailable, retain
    # structurally valid results so the report does not discard known facts.
    if not inventory:
        for result in selected_results.values():
            result = dict(result)
            result.setdefault("aggregate_count", 1)
            rows.append(result)

    known_count = sum(int(row.get("aggregate_count") or 1) for row in rows)
    scope = findings.get("analysis_scope") or {}
    if report_scope_coords is not None:
        source_counts = [
            (
                "本轮分析范围",
                int(scope.get("analyzed_api_count") or 0),
            ),
            (
                "调用关系目标",
                int(findings.get("call_chain_target_count") or 0),
            ),
        ]
    else:
        source_counts = [
            (
                "分析范围",
                int(scope.get("total_api_count") or 0),
            ),
            (
                "调用关系目标",
                int(findings.get("call_chain_target_count") or 0),
            ),
            (
                "变化 API 清单行数",
                int(
                    (findings.get("scan_stats") or {}).get(
                        "changed_apis_total"
                    )
                    or 0
                ),
            ),
        ]
    positive_source_counts = [
        (label, count) for label, count in source_counts if count > 0
    ]
    declared_values = {
        count for _label, count in positive_source_counts
    }
    population_unconfirmed = False
    count_note = ""
    missing_identity_count = 0

    if raw_inventory:
        inventory_population_count = (
            len(inventory) + incomplete_inventory_identity_count
        )
        missing_identity_count = incomplete_inventory_identity_count
        note_parts = [
            (
                f"变化 API 原始清单记录 {len(raw_inventory)} 行，"
                f"可识别 {len(inventory)} 个唯一 API 身份"
            )
        ]
        if duplicate_inventory_count:
            note_parts.append(
                f"其中 {duplicate_inventory_count} 行与其他记录使用相同 API 身份"
            )
        if conflicting_inventory_identities:
            note_parts.append(
                f"其中 {len(conflicting_inventory_identities)} 个 API 身份"
                "存在互相冲突的记录"
            )
        if incomplete_inventory_identity_count:
            note_parts.append(
                f"其中 {incomplete_inventory_identity_count} 行没有完整 API 身份"
            )
        mismatched_sources = [
            (label, count)
            for label, count in positive_source_counts
            if count != inventory_population_count
            and not (
                label == "变化 API 清单行数"
                and count == len(raw_inventory)
            )
        ]
        if mismatched_sources:
            note_parts.append(
                "其他产物记录的数量为"
                + "、".join(
                    f"{label} {count}"
                    for label, count in mismatched_sources
                )
            )
        if (
            duplicate_inventory_count
            or incomplete_inventory_identity_count
            or mismatched_sources
        ):
            note_parts.append(
                "变化 API 总数按可识别唯一身份与身份缺失记录合计为 "
                f"{inventory_population_count}"
            )
            count_note = "；".join(note_parts) + "。"
    elif len(declared_values) > 1:
        population_unconfirmed = True
        count_note = (
            "变化 API 总数无法确认："
            + "、".join(
                f"{label}记录 {count} 个"
                for label, count in positive_source_counts
            )
            + f"；当前只能逐项识别 {known_count} 个唯一 API。"
        )
    else:
        declared_total = max(
            [known_count, *declared_values]
        )
        missing_identity_count = max(declared_total - known_count, 0)

    if missing_identity_count:
        if raw_inventory and incomplete_inventory_identity_count:
            incomplete_reason = (
                f"变化 API 原始清单中有 {missing_identity_count} 条记录"
                "没有完整的依赖坐标和 API 身份，因此无法逐项完成"
                "调用关系分析。"
            )
            declared_total = known_count + missing_identity_count
        else:
            incomplete_reason = (
                f"变化 API 总数为 {declared_total}，但现有变化 API 清单和"
                f"调用关系结果只能逐项识别 {known_count} 个 API；"
                f"其余 {missing_identity_count} 个 API 的身份没有记录。"
            )
        rows.append({
            "coord": "",
            "api": "API 身份未记录",
            "api_signature": "",
            "symbol_kind": "",
            "change_type": "",
            "severity": "未分级",
            "old_version": "",
            "new_version": "",
            "change_without_severity": "变化内容未记录",
            "change": "变化内容未记录",
            "paths": [],
            "business_entries": [],
            "business_entry_count": 0,
            "path_count": 0,
            "occurrence_count": 0,
            "confirmed_path_count": 0,
            "confirmed_occurrence_count": 0,
            "evidence_statuses": [],
            "conclusion": "本次未完成分析",
            "aggregate_count": missing_identity_count,
            "incomplete_reason": incomplete_reason,
        })

    rows.sort(
        key=lambda row: (
            1 if _api_result_is_incomplete(row) else 0,
            *_report_result_sort_key(row),
        )
    )
    completed = [row for row in rows if not _api_result_is_incomplete(row)]
    incomplete = [row for row in rows if _api_result_is_incomplete(row)]
    completed = [
        row
        for _coord, dependency_rows in _completed_api_rows_by_dependency({
            "completed": completed,
        })
        for row in dependency_rows
    ]
    # Keep the model order identical to the Markdown and CSV detail artifacts:
    # dependency coordinates first, APIs within each dependency second.
    rows = [*completed, *incomplete]
    total_count = sum(int(row.get("aggregate_count") or 1) for row in rows)
    completed_count = sum(
        int(row.get("aggregate_count") or 1) for row in completed
    )
    incomplete_count = sum(
        int(row.get("aggregate_count") or 1) for row in incomplete
    )
    confirmed_count = sum(
        int(row.get("aggregate_count") or 1)
        for row in completed
        if row.get("conclusion") == "已确认影响"
    )
    confirmed_no_impact_count = sum(
        int(row.get("aggregate_count") or 1)
        for row in completed
        if row.get("conclusion") == "已确认不受影响"
    )
    return {
        "rows": rows,
        "completed": completed,
        "incomplete": incomplete,
        "total_count": total_count,
        "completed_count": completed_count,
        "incomplete_count": incomplete_count,
        "confirmed_count": confirmed_count,
        "confirmed_no_impact_count": confirmed_no_impact_count,
        "unconfirmed_count": max(
            completed_count
            - confirmed_count
            - confirmed_no_impact_count,
            0,
        ),
        "confirmed_relationship_count": sum(
            int(row.get("confirmed_path_count") or row.get("path_count") or 0)
            for row in completed
        ),
        "population_unconfirmed": population_unconfirmed,
        "count_note": count_note,
        "identified_count": known_count,
        "scope_verified": _report_scope_is_verified(findings),
    }


def _dependency_change_type(item):
    change_type = str((item or {}).get("change_type") or "").strip()
    if change_type:
        labels = {
            "major": "大版本升级",
            "minor": "小版本升级",
            "patch": "补丁版本升级",
            "new": "新增",
            "added": "新增",
            "removed": "移除",
        }
        return labels.get(change_type.lower(), change_type)
    old_version = str((item or {}).get("old_version") or "").strip()
    new_version = str((item or {}).get("new_version") or "").strip()
    if old_version == "-":
        return "新增"
    if new_version == "-":
        return "移除"
    return "版本变化"


def _dependency_anchor(coord):
    coord = str(coord or "").strip()
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", coord).strip("-").lower()
    digest = hashlib.sha1(coord.encode("utf-8")).hexdigest()[:8]
    return f"dependency-{slug[:48] or 'unknown'}-{digest}"


def _dependency_api_change_text(api_rows):
    counts = defaultdict(int)
    total = 0
    for row in api_rows:
        count = int(row.get("aggregate_count") or 1)
        total += count
        counts[
            _human_change_type(
                row.get("change_type"),
                row.get("symbol_kind"),
            )
        ] += count
    if not total:
        return "未记录变化 API"
    if len(counts) == 1:
        label, count = next(iter(counts.items()))
        return f"均为{label}" if count == total else f"{label} {count}"
    return "；".join(
        f"{label} {count}"
        for label, count in sorted(
            counts.items(), key=lambda item: (-item[1], item[0])
        )[:3]
    )


def _dependency_incomplete_reason(api_rows, findings, excluded=False):
    if excluded:
        return (
            "本轮调用关系分析范围未包含该依赖，因此该依赖的变化 API "
            "没有产生调用关系分析结果。"
        )
    reasons = []
    for row in api_rows:
        if not _api_result_is_incomplete(row):
            continue
        reason = _incomplete_api_reason(row, findings).rstrip("。")
        if reason and reason not in reasons:
            reasons.append(reason)
    if not reasons:
        return "当前记录没有保存该依赖未完成调用关系分析的具体原因。"
    incomplete_count = sum(
        int(row.get("aggregate_count") or 1)
        for row in api_rows
        if _api_result_is_incomplete(row)
    )
    prefix = (
        f"该依赖有 {incomplete_count} 个变化 API 未完成调用关系分析："
        if incomplete_count
        else ""
    )
    if len(reasons) == 1:
        return prefix + reasons[0] + "。"
    return prefix + "；".join(reasons[:3]) + ("。" if reasons else "")


def _dependency_basis(api_rows):
    total = sum(int(row.get("aggregate_count") or 1) for row in api_rows)
    confirmed = [
        row for row in api_rows
        if not _api_result_is_incomplete(row)
        and row.get("conclusion") == "已确认影响"
    ]
    confirmed_api_count = sum(
        int(row.get("aggregate_count") or 1) for row in confirmed
    )
    confirmed_paths = sum(
        int(row.get("confirmed_path_count") or row.get("path_count") or 0)
        for row in confirmed
    )
    if confirmed_api_count:
        if not confirmed_paths:
            return (
                f"{confirmed_api_count}/{total} 个变化 API 已形成确认有影响结论；"
                "对应调用关系数量未记录。"
            )
        return (
            f"{confirmed_api_count}/{total} 个变化 API 有当前系统调用关系，"
            f"共 {confirmed_paths} 条。"
        )
    not_found = sum(
        int(row.get("aggregate_count") or 1)
        for row in api_rows
        if row.get("conclusion") == "未发现调用路径"
    )
    not_impacted = sum(
        int(row.get("aggregate_count") or 1)
        for row in api_rows
        if row.get("conclusion") == "已确认不受影响"
    )
    if total and not_found == total:
        return (
            f"本轮分析对 {not_found}/{total} 个变化 API "
            "均未发现当前系统调用关系。"
        )
    if total and not_impacted == total:
        return (
            f"{not_impacted}/{total} 个变化 API 均有当前制品中的"
            "相同类字节码保留记录。"
        )
    probable_with_exact_path = [
        row for row in api_rows
        if row.get("conclusion") == "可能影响"
        and int(row.get("confirmed_path_count") or 0) > 0
    ]
    if probable_with_exact_path:
        path_count = sum(
            int(row.get("confirmed_path_count") or 0)
            for row in probable_with_exact_path
        )
        return (
            f"{len(probable_with_exact_path)}/{total} 个变化 API 已确认存在"
            f"静态可执行调用关系，共 {path_count} 条；运行时影响仍需验证。"
        )
    if not total:
        return "该依赖没有进入调用关系分析的变化 API。"
    parts = []
    for conclusion, label in (
        ("已确认不受影响", "确认不受影响"),
        ("可能影响", "存在候选关系"),
        (UNCERTAIN_CANDIDATE_CONCLUSION, "存在候选关系"),
        (UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION, "静态分析能力边界"),
        ("未发现调用路径", "未发现调用关系"),
    ):
        count = sum(
            int(row.get("aggregate_count") or 1)
            for row in api_rows
            if row.get("conclusion") == conclusion
        )
        if count:
            parts.append(f"{label} {count}")
    return "；".join(parts) + ("。" if parts else "")


def _dependency_result_rank(row):
    conclusion = str(
        (row or {}).get("analysis_conclusion") or ""
    ).strip()
    if (
        conclusion == "确认有影响"
        or int((row or {}).get("confirmed_api_count") or 0) > 0
    ):
        return 0
    if conclusion == "确认不受 API 调用影响":
        return 2
    if not (row or {}).get("analysis_complete"):
        return 3
    return 1


def _dependency_display_sort_key(row):
    return (
        _dependency_result_rank(row),
        -int((row or {}).get("top_uncertain_priority_score") or 0),
        -int((row or {}).get("total_uncertain_priority_score") or 0),
        -int((row or {}).get("call_relationship_count") or 0),
        str((row or {}).get("coord") or ""),
    )


def build_human_dependency_analysis(findings, api_model=None):
    api_model = api_model or build_human_api_analysis(findings)
    report_scope_coords = _report_scope_included_coords(findings)
    api_by_coord = defaultdict(list)
    unassigned_api_rows = []
    for row in api_model["rows"]:
        coord = _canonical_identity_coord(row.get("coord"))
        if coord:
            api_by_coord[coord].append(row)
        else:
            unassigned_api_rows.append(row)

    raw_dependency_inventory = list(
        findings.get("dependency_changes") or []
    )
    if report_scope_coords is not None:
        raw_dependency_inventory = [
            item
            for item in raw_dependency_inventory
            if _canonical_identity_coord(item.get("coord"))
            in report_scope_coords
        ]
    dependencies = {}
    dependency_variant_counts = defaultdict(lambda: defaultdict(int))
    complete_dependency_row_count = 0
    for item in raw_dependency_inventory:
        coord = _canonical_identity_coord(item.get("coord"))
        if coord:
            complete_dependency_row_count += 1
            dependencies.setdefault(coord, dict(item))
            variant = (
                str(item.get("old_version") or "").strip(),
                str(item.get("new_version") or "").strip(),
                str(item.get("change_type") or "").strip(),
            )
            dependency_variant_counts[coord][variant] += 1
    conflicting_dependency_identities = {
        coord: sum(variants.values())
        for coord, variants in dependency_variant_counts.items()
        if len(variants) > 1
    }
    duplicate_dependency_count = max(
        complete_dependency_row_count - len(dependencies),
        0,
    )
    dependency_inventory_identity_count = len(dependencies)
    incomplete_dependency_identity_count = max(
        len(raw_dependency_inventory) - complete_dependency_row_count,
        0,
    )
    for item in findings.get("per_dependency_results") or []:
        coord = _canonical_identity_coord(item.get("coord"))
        if not coord:
            continue
        if (
            report_scope_coords is not None
            and coord not in report_scope_coords
        ):
            continue
        if raw_dependency_inventory and coord not in dependencies:
            continue
        target = dependencies.setdefault(coord, {"coord": coord})
        for field in ("old_version", "new_version", "change_type"):
            if not target.get(field) and item.get(field):
                target[field] = item.get(field)
    for coord, rows in api_by_coord.items():
        if raw_dependency_inventory and coord not in dependencies:
            continue
        target = dependencies.setdefault(coord, {"coord": coord})
        for field in ("old_version", "new_version"):
            values = {
                str(row.get(field) or "").strip()
                for row in rows
                if str(row.get(field) or "").strip()
            }
            if not target.get(field) and len(values) == 1:
                target[field] = next(iter(values))

    # When exactly one changed dependency is known, changed APIs without a
    # recorded dependency identity can still be assigned to that sole
    # dependency. With multiple dependencies the ownership is unknowable, so
    # every dependency remains incomplete instead of being falsely marked as
    # fully analyzed.
    if len(dependencies) == 1 and unassigned_api_rows:
        only_coord = next(iter(dependencies))
        api_by_coord[only_coord].extend(unassigned_api_rows)
        unassigned_api_rows = []
    unassigned_api_count = sum(
        int(row.get("aggregate_count") or 1)
        for row in unassigned_api_rows
    )

    excluded_coords = (
        set()
        if report_scope_coords is not None
        else _scope_excluded_coords(findings)
    )
    result_rows = []
    for coord, dependency in dependencies.items():
        api_rows = api_by_coord.get(coord, [])
        api_total = sum(int(row.get("aggregate_count") or 1) for row in api_rows)
        api_completed = sum(
            int(row.get("aggregate_count") or 1)
            for row in api_rows
            if not _api_result_is_incomplete(row)
        )
        api_incomplete = max(api_total - api_completed, 0)
        excluded = coord in excluded_coords
        api_population_unconfirmed = bool(
            api_model.get("population_unconfirmed")
        )
        dependency_record_conflict = (
            coord in conflicting_dependency_identities
        )
        incomplete = (
            excluded
            or api_incomplete > 0
            or unassigned_api_count > 0
            or api_population_unconfirmed
            or dependency_record_conflict
        )
        confirmed_api_count = sum(
            int(row.get("aggregate_count") or 1)
            for row in api_rows
            if not _api_result_is_incomplete(row)
            and row.get("conclusion") == "已确认影响"
        )
        confirmed_relationships = sum(
            int(row.get("confirmed_path_count") or row.get("path_count") or 0)
            for row in api_rows
            if not _api_result_is_incomplete(row)
            and row.get("conclusion") == "已确认影响"
        )
        call_relationships = sum(
            _api_call_relationship_count(row)
            for row in api_rows
            if not _api_result_is_incomplete(row)
        )
        call_relationship_api_count = sum(
            int(row.get("confirmed_path_count") or 0) > 0
            for row in api_rows
            if not _api_result_is_incomplete(row)
        )
        uncertain_priority_scores = [
            int(row.get("priority_score") or 0)
            for row in api_rows
            if str(row.get("conclusion") or "") in {
                "可能影响",
                UNCERTAIN_CANDIDATE_CONCLUSION,
                UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION,
            }
        ]
        if incomplete:
            conclusion = (
                "部分结果确认有影响；分析未完成"
                if confirmed_api_count
                else "未完成分析"
            )
        elif confirmed_api_count:
            conclusion = "确认有影响"
        elif api_rows and all(
            row.get("conclusion") == "已确认不受影响"
            for row in api_rows
        ):
            conclusion = "确认不受 API 调用影响"
        else:
            conclusion = "未确认影响"
        incomplete_reason = (
            _dependency_incomplete_reason(
                api_rows,
                findings,
                excluded=excluded,
            )
            if excluded or api_incomplete > 0
            else ""
        )
        if unassigned_api_count:
            unassigned_reason = (
                f"{unassigned_api_count} 个变化 API 的依赖归属没有记录，"
                "因此无法确认该依赖是否已完成全部变化 API 分析。"
            )
            incomplete_reason = (
                f"{incomplete_reason.rstrip('。')}；{unassigned_reason}"
                if incomplete_reason
                else unassigned_reason
            )
        if api_population_unconfirmed:
            population_reason = (
                "变化 API 总数记录不一致，因此无法确认该依赖是否已完成"
                "全部变化 API 分析。"
            )
            incomplete_reason = (
                f"{incomplete_reason.rstrip('。')}；{population_reason}"
                if incomplete_reason
                else population_reason
            )
        if dependency_record_conflict:
            conflict_reason = (
                "依赖变化清单中同一依赖身份存在 "
                f"{conflicting_dependency_identities[coord]} 条互相冲突的"
                "版本或变更类型记录，无法确认唯一的依赖变化内容。"
            )
            incomplete_reason = (
                f"{incomplete_reason.rstrip('。')}；{conflict_reason}"
                if incomplete_reason
                else conflict_reason
            )
        api_change_text = _dependency_api_change_text(api_rows)
        if unassigned_api_count:
            api_change_text += (
                f"；另有 {unassigned_api_count} 个变化 API "
                "的依赖归属未记录"
            )
        result_rows.append({
            **dependency,
            "coord": coord,
            "old_version": (
                "" if dependency_record_conflict
                else dependency.get("old_version", "")
            ),
            "new_version": (
                "" if dependency_record_conflict
                else dependency.get("new_version", "")
            ),
            "change_type": (
                "变化记录冲突"
                if dependency_record_conflict
                else dependency.get("change_type", "")
            ),
            "api_rows": api_rows,
            "api_total": api_total,
            "api_completed": api_completed,
            "api_incomplete": api_incomplete,
            "analysis_complete": not incomplete,
            "confirmed_api_count": confirmed_api_count,
            "confirmed_relationship_count": confirmed_relationships,
            "call_relationship_count": call_relationships,
            "call_relationship_api_count": call_relationship_api_count,
            "top_uncertain_priority_score": max(
                uncertain_priority_scores, default=0
            ),
            "total_uncertain_priority_score": sum(
                uncertain_priority_scores
            ),
            "unassigned_api_count": unassigned_api_count,
            "analysis_conclusion": conclusion,
            "conclusion_basis": _dependency_basis(api_rows),
            "incomplete_reason": incomplete_reason,
            "api_change_text": api_change_text,
            "aggregate_count": 1,
            "input_record_conflict": dependency_record_conflict,
        })

    known_count = len(result_rows)
    if report_scope_coords is not None:
        dependency_source_counts = [
            (
                "本轮分析范围",
                int(
                    (findings.get("analysis_scope") or {}).get(
                        "included_dependency_count"
                    )
                    or 0
                ),
            ),
        ]
    else:
        dependency_source_counts = [
            (
                "分析范围",
                int(
                    (findings.get("analysis_scope") or {}).get(
                        "available_dependency_count"
                    )
                    or 0
                ),
            ),
            (
                "依赖变化汇总",
                sum(
                    int(value or 0)
                    for value in (
                        findings.get("dep_changes_summary") or {}
                    ).values()
                ),
            ),
        ]
    positive_dependency_source_counts = [
        (label, count)
        for label, count in dependency_source_counts
        if count > 0
    ]
    dependency_declared_values = {
        count for _label, count in positive_dependency_source_counts
    }
    population_unconfirmed = False
    count_note = ""
    missing_count = 0

    if raw_dependency_inventory:
        dependency_inventory_population_count = (
            dependency_inventory_identity_count
            + incomplete_dependency_identity_count
        )
        missing_count = incomplete_dependency_identity_count
        note_parts = [
            (
                f"依赖变化原始清单记录 {len(raw_dependency_inventory)} 行，"
                f"可识别 {dependency_inventory_identity_count} 个唯一依赖身份"
            )
        ]
        if duplicate_dependency_count:
            note_parts.append(
                f"其中 {duplicate_dependency_count} 行与其他记录使用相同依赖身份"
            )
        if conflicting_dependency_identities:
            note_parts.append(
                f"其中 {len(conflicting_dependency_identities)} 个依赖身份"
                "存在互相冲突的记录"
            )
        if incomplete_dependency_identity_count:
            note_parts.append(
                f"其中 {incomplete_dependency_identity_count} 行没有完整依赖身份"
            )
        mismatched_dependency_sources = [
            (label, count)
            for label, count in positive_dependency_source_counts
            if count != dependency_inventory_population_count
        ]
        if mismatched_dependency_sources:
            note_parts.append(
                "其他产物记录的数量为"
                + "、".join(
                    f"{label} {count}"
                    for label, count in mismatched_dependency_sources
                )
            )
        if (
            duplicate_dependency_count
            or incomplete_dependency_identity_count
            or mismatched_dependency_sources
        ):
            note_parts.append(
                "变化依赖总数按可识别唯一身份与身份缺失记录合计为 "
                f"{dependency_inventory_population_count}"
            )
            count_note = "；".join(note_parts) + "。"
    elif len(dependency_declared_values) > 1:
        population_unconfirmed = True
        count_note = (
            "变化依赖总数无法确认："
            + "、".join(
                f"{label}记录 {count} 个"
                for label, count in positive_dependency_source_counts
            )
            + f"；当前只能逐项识别 {known_count} 个唯一依赖。"
        )
    else:
        declared_total = max(
            [known_count, *dependency_declared_values]
        )
        missing_count = max(declared_total - known_count, 0)

    if missing_count:
        if raw_dependency_inventory and incomplete_dependency_identity_count:
            incomplete_reason = (
                f"依赖变化原始清单中有 {missing_count} 条记录没有完整的"
                "依赖坐标，因此无法逐项完成依赖分析。"
            )
            declared_total = known_count + missing_count
        else:
            incomplete_reason = (
                f"变化依赖总数为 {declared_total}，但现有依赖变化记录只能"
                f"逐项识别 {known_count} 个依赖；其余 {missing_count} 个依赖"
                "的身份没有记录。"
            )
        result_rows.append({
            "coord": "依赖身份未记录",
            "old_version": "",
            "new_version": "",
            "change_type": "变化内容未记录",
            "api_rows": [],
            "api_total": 0,
            "api_completed": 0,
            "api_incomplete": 0,
            "analysis_complete": False,
            "confirmed_api_count": 0,
            "confirmed_relationship_count": 0,
            "call_relationship_count": 0,
            "unassigned_api_count": 0,
            "analysis_conclusion": "未完成分析",
            "conclusion_basis": "",
            "incomplete_reason": incomplete_reason,
            "api_change_text": "变化内容未记录",
            "aggregate_count": missing_count,
        })

    completed = [row for row in result_rows if row["analysis_complete"]]
    incomplete = [row for row in result_rows if not row["analysis_complete"]]
    completed.sort(key=_dependency_display_sort_key)
    incomplete.sort(
        key=lambda row: (
            -int(row.get("call_relationship_count") or 0),
            str(row.get("coord") or ""),
        )
    )
    completed_count = sum(
        int(row.get("aggregate_count") or 1) for row in completed
    )
    incomplete_count = sum(
        int(row.get("aggregate_count") or 1) for row in incomplete
    )
    confirmed_completed_count = sum(
        int(row.get("aggregate_count") or 1)
        for row in completed
        if row.get("analysis_conclusion") == "确认有影响"
    )
    confirmed_no_impact_completed_count = sum(
        int(row.get("aggregate_count") or 1)
        for row in completed
        if row.get("analysis_conclusion") == "确认不受 API 调用影响"
    )
    confirmed_any_count = sum(
        int(row.get("aggregate_count") or 1)
        for row in result_rows
        if int(row.get("confirmed_api_count") or 0) > 0
    )
    confirmed_incomplete_count = sum(
        int(row.get("aggregate_count") or 1)
        for row in incomplete
        if int(row.get("confirmed_api_count") or 0) > 0
    )
    return {
        "rows": [*incomplete, *completed],
        "completed": completed,
        "incomplete": incomplete,
        "total_count": completed_count + incomplete_count,
        "completed_count": completed_count,
        "incomplete_count": incomplete_count,
        "confirmed_completed_count": confirmed_completed_count,
        "confirmed_no_impact_completed_count": (
            confirmed_no_impact_completed_count
        ),
        "unconfirmed_completed_count": max(
            completed_count
            - confirmed_completed_count
            - confirmed_no_impact_completed_count,
            0,
        ),
        "confirmed_any_count": confirmed_any_count,
        "confirmed_incomplete_count": confirmed_incomplete_count,
        "population_unconfirmed": population_unconfirmed,
        "count_note": count_note,
        "identified_count": known_count,
        "scope_verified": _report_scope_is_verified(findings),
    }


def _dependency_identity_cell(row):
    coord = _md_cell(row.get("coord"), 180)
    aggregate_count = int(row.get("aggregate_count") or 1)
    if aggregate_count > 1:
        coord += f"（{aggregate_count} 个）"
    return f"`{coord}`"


def _dependency_version_change_cell(row):
    version = _version_transition(row)
    change_type = _dependency_change_type(row)
    value = _md_cell(version or "版本变化未记录", 120)
    if change_type:
        value += f"<br>{_md_cell(change_type, 100)}"
    return value


def _dependency_result_explanation(row):
    if row.get("analysis_complete"):
        return str(row.get("conclusion_basis") or "").strip()
    return str(row.get("incomplete_reason") or "").strip()


def _dependency_detail_table(rows, include_link=False):
    headers = (
        "| 依赖 | 版本变化 | API 分析（已完成/总数） | "
        "当前系统调用关系 | 分析结果 | 结果说明 |"
    )
    divider = "|---|---|---:|---|---|---|"
    lines = [headers, divider]
    for row in rows:
        api_total = int(row.get("api_total") or 0)
        api_completed = int(row.get("api_completed") or 0)
        api_incomplete = int(row.get("api_incomplete") or 0)
        unassigned_api_count = int(
            row.get("unassigned_api_count") or 0
        )
        api_analysis = (
            f"{api_completed}/{api_total}<br>"
            f"{_md_cell(row.get('api_change_text'), 140)}"
        )
        if include_link:
            links = []
            if api_completed:
                link_label = (
                    f"该依赖的 {api_total} 个 API 及调用关系"
                    if row.get("analysis_complete") and api_total
                    else "已完成 API 及调用关系"
                )
                links.append(
                    f"[{link_label}]"
                    f"(all-impact-details.md#{_dependency_anchor(row.get('coord'))})"
                )
            if api_incomplete or unassigned_api_count:
                links.append(
                    "[未完成 API 及原因]"
                    "(all-impact-details.md#unanalyzed-apis)"
                )
            if links:
                api_analysis += "<br>" + "<br>".join(links)
        line = (
            f"| {_dependency_identity_cell(row)} | "
            f"{_dependency_version_change_cell(row)} | "
            f"{api_analysis} | "
            f"{_dependency_current_calls_cell(row)} | "
            f"{_md_cell(row.get('analysis_conclusion'), 120)} | "
            f"{_md_cell(_dependency_result_explanation(row), 360)} |"
        )
        lines.append(line)
    return lines


def _dependency_current_calls_cell(row):
    api_count = int(
        row.get("call_relationship_api_count")
        or row.get("confirmed_api_count")
        or 0
    )
    relationships = int(
        row.get("call_relationship_count")
        or row.get("confirmed_relationship_count")
        or 0
    )
    if api_count and not relationships:
        return f"{api_count} 个变化 API<br>调用关系数量未记录"
    if not relationships:
        return "0 条已确认调用关系"
    return (
        f"{api_count} 个变化 API<br>{relationships} 条调用关系"
    )


def _dependency_completed_table(rows, include_link=False):
    return _dependency_detail_table(rows, include_link=include_link)


def _dependency_incomplete_table(rows, include_link=False):
    return _dependency_detail_table(rows, include_link=include_link)


def _population_total_cell(model):
    if model.get("population_unconfirmed"):
        return (
            "无法确认<br>"
            f"已识别 {int(model.get('total_count') or 0)}"
        )
    return str(int(model.get("total_count") or 0))


def _population_incomplete_cell(model):
    if model.get("population_unconfirmed"):
        return (
            "无法确认<br>"
            f"已识别 {int(model.get('incomplete_count') or 0)}"
        )
    return str(int(model.get("incomplete_count") or 0))


def _count_label(noun, suffix):
    separator = (
        " "
        if re.search(r"[A-Za-z0-9]$", str(noun or ""))
        else ""
    )
    return f"{noun}{separator}{suffix}"


def _population_full_range(model, noun):
    total = int(model.get("total_count") or 0)
    if not model.get("scope_verified"):
        return (
            f"分析范围无法核验；现有记录中可识别 {noun} {total} 个"
        )
    if model.get("population_unconfirmed"):
        return (
            f"本轮分析范围内：{_count_label(noun, '总数')}无法确认；"
            f"逐项识别 {total} 个"
        )
    return f"本轮分析范围内：{noun} {total}/{total}"


def _main_report_range(model, noun, displayed_count):
    total = int(model.get("total_count") or 0)
    if not model.get("scope_verified"):
        return (
            f"分析范围无法核验、现有记录中可识别 {noun} {total} 个、"
            f"正文展示 {displayed_count} 个"
        )
    if model.get("population_unconfirmed"):
        return (
            f"本轮分析范围内：{_count_label(noun, '总数')}无法确认、"
            f"逐项识别 {total} 个、"
            f"正文展示 {displayed_count} 个"
        )
    return (
        f"本轮分析范围内：{_count_label(noun, '汇总')}覆盖 {total}/{total}、"
        f"逐项展示 {displayed_count}/{total}"
    )


def render_report_scope_notice(findings):
    scope = (findings or {}).get("analysis_scope") or {}
    source_usage = (findings or {}).get("source_usage") or {}
    source_notice = []
    if source_usage:
        source_notice = [
            (
                f"> **源码辅助分析**：{source_usage.get('label') or '源码选择记录缺失'}。"
                f"{source_usage.get('effect') or ''}"
            ),
            "",
        ]
    scope_mode = str(scope.get("mode") or "").strip()
    scope_verified = _report_scope_is_verified(findings)
    if scope_mode == "full" and scope_verified:
        return source_notice
    if scope_mode != "partial" or not scope_verified:
        reason = (
            "分析范围记录未通过一致性校验"
            if scope.get("validation_status") == "invalid"
            else "分析范围记录缺失"
        )
        return [
            *source_notice,
            (
                f"> **分析范围无法核验**：{reason}。"
                "以下统计只汇总现有记录中可识别的对象，"
                "不能解释为本轮分析的完整范围。"
            ),
            "",
        ]
    included_dependencies = int(
        scope.get("included_dependency_count") or 0
    )
    available_dependencies = int(
        scope.get("available_dependency_count") or 0
    )
    analyzed_apis = int(scope.get("analyzed_api_count") or 0)
    total_apis = int(scope.get("total_api_count") or 0)
    excluded_dependencies = max(
        available_dependencies - included_dependencies,
        0,
    )
    excluded_apis = max(total_apis - analyzed_apis, 0)
    scope_path = str(
        ((findings.get("artifacts") or {}).get("analysis_scope_md") or "")
    ).strip()
    scope_link = (
        _report_link(scope_path, "分析范围记录")
        if scope_path
        else "分析范围记录"
    )
    return [
        *source_notice,
        (
            "> **本轮分析范围**：用户指定纳入 "
            f"{included_dependencies}/{available_dependencies} 个变化依赖、"
            f"{analyzed_apis}/{total_apis} 个变化 API。"
        ),
        (
            "> 以下统计和两份完整分析明细只包含已纳入对象。"
        ),
        (
            f"> 未纳入的 {excluded_dependencies} 个依赖和 {excluded_apis} 个 "
            "API 不计入“未完成分析”。"
            f"未纳入对象及原因记录在{scope_link}中。"
        ),
        "",
    ]


def render_dependency_conclusions(findings, dependency_model=None):
    dependency_model = dependency_model or build_human_dependency_analysis(
        findings
    )
    confirmed_any = dependency_model["confirmed_any_count"]
    if confirmed_any:
        headline = (
            f"{confirmed_any} 个变化依赖已确认存在当前系统调用关系；"
            "这些调用目标在新版本中发生了变化。"
        )
    else:
        headline = "本轮没有变化依赖形成“确认对当前系统有影响”的结论。"
    lines = [
        "## 一、依赖层面结论",
        "",
        f"**{headline}**",
        "",
        (
            "| 变化依赖总数 | 已完成分析 | 未完成分析 | 确认有影响 | "
            "确认不受影响 | 尚未确认影响 |"
        ),
        "|---:|---:|---:|---:|---:|---:|",
        (
            f"| {_population_total_cell(dependency_model)} | "
            f"{dependency_model['completed_count']} | "
            f"{_population_incomplete_cell(dependency_model)} | "
            f"{dependency_model['confirmed_any_count']} | "
            f"{dependency_model['confirmed_no_impact_completed_count']} | "
            f"{dependency_model['unconfirmed_completed_count']} |"
        ),
        "",
    ]
    if dependency_model.get("count_note"):
        lines.extend([
            dependency_model["count_note"],
            "",
        ])
    incomplete = dependency_model["incomplete"]
    if incomplete:
        displayed = incomplete[:S6_MAIN_INCOMPLETE_LIMIT]
        displayed_count = sum(
            int(row.get("aggregate_count") or 1) for row in displayed
        )
        lines.extend([
            (
                "### 未完成分析的依赖"
                f"（展示 {displayed_count}/{dependency_model['incomplete_count']}）"
            ),
            "",
            (
                f"正文展示 {displayed_count}/"
                f"{dependency_model['incomplete_count']} 个未完成分析的依赖；"
                + (
                    f"未展开 {dependency_model['incomplete_count'] - displayed_count} 个。"
                    if displayed_count < dependency_model["incomplete_count"]
                    else ""
                )
                + "全部未完成原因见"
                "[完整依赖分析明细](all-affected-dependencies.md)。"
            ),
            "",
            *_dependency_incomplete_table(displayed),
            "",
        ])
    completed = dependency_model["completed"]
    if completed:
        displayed = completed[:S6_MAIN_DEPENDENCY_LIMIT]
        displayed_count = sum(
            int(row.get("aggregate_count") or 1) for row in displayed
        )
        lines.extend([
            (
                "### 已完成分析的依赖"
                f"（展示 {displayed_count}/{dependency_model['completed_count']}）"
            ),
            "",
            (
                (
                    f"正文展示 {displayed_count}/"
                    f"{dependency_model['completed_count']} 个已完成分析的依赖；"
                    f"未展开 {dependency_model['completed_count'] - displayed_count} 个。"
                    if displayed_count < dependency_model["completed_count"]
                    else ""
                )
                + "完整结果见"
                "[完整依赖分析明细](all-affected-dependencies.md)。"
            ),
            "",
            *_dependency_completed_table(displayed),
            "",
        ])
    return lines


def _main_completed_api_rows(rows):
    actionable = [
        row
        for row in rows or []
        if _api_human_category(row) in {"确认有影响", "结论未确定"}
    ]
    return [
        row
        for _coord, dependency_rows in _completed_api_rows_by_dependency({
            "completed": actionable,
        })
        for row in dependency_rows
    ]


def _main_relationship_cell(row):
    paths = list(row.get("paths") or [])
    conclusion = str(row.get("conclusion") or "")
    if conclusion == "已确认影响" and paths:
        preferred_path = max(
            paths,
            key=lambda path: (
                sum(bool(value) for value in _call_path_shape(path)[1]),
                len(str(path or "")),
                str(path or ""),
            ),
        )
        relation = f"`{_md_cell(_human_chain(preferred_path), 420)}`"
        path_count = int(
            row.get("confirmed_path_count") or row.get("path_count") or 0
        )
        if path_count > 1:
            relation += f"<br>共 {path_count} 条调用关系"
        return relation
    if conclusion == "已确认影响":
        return "已确认存在当前系统调用关系；完整关系未记录"
    if conclusion in {
        "可能影响",
        "结论未确定（存在候选证据）",
    } and paths:
        if int(row.get("confirmed_path_count") or 0) > 0:
            return f"已确认调用关系：`{_md_cell(_human_chain(paths[0]), 380)}`"
        return f"候选关系：`{_md_cell(_human_chain(paths[0]), 380)}`"
    if conclusion == "已确认不受影响":
        return "无已确认受影响调用关系"
    return "本轮分析未发现当前系统调用关系"


def _api_result_explanation(row, findings=None):
    if _api_result_is_incomplete(row):
        return _incomplete_api_reason(row, findings or {})
    conclusion = str(row.get("conclusion") or "").strip()
    if conclusion == "已确认影响":
        runtime_boundary = (
            "这里确认的是调用关系受到 API 变化影响，不表示运行时故障已经发生，"
            "仍需定向测试验证。"
        )
        reason = _human_reason(row.get("reason"))
        if reason:
            if "不表示运行时故障已经发生" in reason:
                return reason
            return f"{reason.rstrip('。')}。{runtime_boundary}"
        path_count = int(
            row.get("confirmed_path_count") or row.get("path_count") or 0
        )
        if path_count:
            return (
                f"{path_count} 条已确认调用关系到达该 API。"
                f"{runtime_boundary}"
            )
        return (
            "已有证据确认当前系统调用关系到达该 API。"
            f"{runtime_boundary}"
        )
    if conclusion == "已确认不受影响":
        return "当前制品中的相同类字节码保留该 API。"
    if conclusion == "未发现调用路径":
        return (
            "当前静态分析范围内未找到调用关系；"
            "该结果不等于确认不受影响。"
        )
    if conclusion == "可能影响":
        path_count = int(row.get("confirmed_path_count") or 0)
        if path_count:
            return (
                f"{path_count} 条静态可执行调用关系已确认；"
                "是否在真实运行时触发兼容性问题仍需定向验证。"
            )
        return (
            "已有相关证据，但现有证据不能确认当前系统是否会触发该影响。"
        )
    if conclusion == UNCERTAIN_CANDIDATE_CONCLUSION:
        priority = int(row.get("priority_score") or 0)
        prefix = f"复核优先分数 {priority}。" if priority else ""
        return prefix + "存在候选调用关系，但尚未形成完整的系统触达证据。"
    if conclusion == UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION:
        priority = int(row.get("priority_score") or 0)
        prefix = f"复核优先分数 {priority}。" if priority else ""
        return (
            prefix
            + "当前未发现候选调用证据；受静态分析能力边界限制，"
            "不能据此判定该 API 未被使用。"
        )
    boundary = _result_boundary_text(row)
    if boundary and boundary != "当前记录未提供更多结论边界。":
        return boundary
    return "当前记录没有保存更多结果说明。"


def _api_detail_table(
    rows,
    findings=None,
    *,
    full=False,
    alert_details=None,
):
    lines = [
        (
            "| 依赖 | API | 新版本中的变化 | 当前系统调用关系 | "
            "分析结果 | 结果说明 |"
        ),
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        count = int(row.get("aggregate_count") or 1)
        api = _item_api_label(row) or str(row.get("api") or "API 身份未记录")
        if count > 1:
            api = f"{api}（{count} 个）"
        incomplete = _api_result_is_incomplete(row)
        if incomplete:
            relationship = "调用关系分析未完成"
        elif full:
            relationship = _full_relationship_cell(
                row,
                alert_details or {},
            )
        else:
            relationship = _main_relationship_cell(row)
        if full:
            coord = _full_md_cell(
                row.get("coord") or "依赖身份未记录"
            )
            api_cell = _full_md_cell(api)
            change = _full_md_cell(row.get("change_without_severity"))
            result = _full_md_cell(_analysis_conclusion_label(row))
            explanation = _full_md_cell(
                _api_result_explanation(row, findings)
            )
        else:
            coord = _md_cell(
                row.get("coord") or "依赖身份未记录",
                180,
            )
            api_cell = _md_cell(api, 220)
            change = _md_cell(
                row.get("change_without_severity"),
                180,
            )
            result = _md_cell(_analysis_conclusion_label(row), 140)
            explanation = _md_cell(
                _api_result_explanation(row, findings),
                360,
            )
        lines.append(
            f"| `{coord}` | `{api_cell}` | {change} | "
            f"{relationship} | {result} | {explanation} |"
        )
    return lines


def _api_incomplete_table(rows, findings=None):
    return _api_detail_table(rows, findings)


def _api_completed_table(rows, findings=None):
    return _api_detail_table(rows, findings)


def render_api_and_calls(findings, api_model=None):
    api_model = api_model or build_human_api_analysis(findings)
    lines = [
        "## 二、API 及调用关系",
        "",
        (
            "| 变化 API 总数 | 已完成分析 | 未完成分析 | 确认有影响 | "
            "确认不受影响 | 尚未确认影响 |"
        ),
        "|---:|---:|---:|---:|---:|---:|",
        (
            f"| {_population_total_cell(api_model)} | "
            f"{api_model['completed_count']} | "
            f"{_population_incomplete_cell(api_model)} | "
            f"{api_model['confirmed_count']} | "
            f"{api_model['confirmed_no_impact_count']} | "
            f"{api_model['unconfirmed_count']} |"
        ),
        "",
    ]
    if api_model.get("count_note"):
        lines.extend([
            api_model["count_note"],
            "",
        ])
    if api_model["incomplete"]:
        displayed = api_model["incomplete"][:S6_MAIN_INCOMPLETE_LIMIT]
        displayed_count = sum(
            int(row.get("aggregate_count") or 1) for row in displayed
        )
        lines.extend([
            (
                "### 未完成分析的 API"
                f"（展示 {displayed_count}/{api_model['incomplete_count']}）"
            ),
            "",
            (
                f"正文展示 {displayed_count}/{api_model['incomplete_count']} "
                "个未完成分析的 API；"
                + (
                    f"未展开 {api_model['incomplete_count'] - displayed_count} 个。"
                    if displayed_count < api_model["incomplete_count"]
                    else ""
                )
                + "全部未完成原因见"
                "[完整 API 分析与调用关系明细]"
                "(all-impact-details.md#unanalyzed-apis)。"
            ),
            "",
        ])
        lines.extend([
            *_api_incomplete_table(displayed, findings),
            "",
        ])
    completed = api_model["completed"]
    if completed:
        actionable = _main_completed_api_rows(completed)
        actionable_count = sum(
            int(row.get("aggregate_count") or 1) for row in actionable
        )
        lines.extend([
            (
                "### 已确认触达与结论未确定的 API"
                f"（完整展示 {actionable_count}/{actionable_count}）"
            ),
            "",
            (
                "本节按依赖坐标分组，完整展示全部已确认调用关系和结论未确定的 API。"
                "依赖之间按已确认影响、复核优先分数和调用关系强度排序；"
                "每个依赖内部再按结论与复核优先分数排序。"
            ),
            "",
        ])
        if not actionable:
            lines.extend([
                "本轮没有已确认调用关系或结论未确定的 API。",
                "",
            ])
        for index, (coord, dependency_rows) in enumerate(
            _completed_api_rows_by_dependency({"completed": actionable}),
            start=1,
        ):
            confirmed_impact_count = sum(
                int(row.get("aggregate_count") or 1)
                for row in dependency_rows
                if _api_human_category(row) == "确认有影响"
            )
            unconfirmed_count = sum(
                int(row.get("aggregate_count") or 1)
                for row in dependency_rows
                if _api_human_category(row) == "结论未确定"
            )
            lines.extend([
                f"#### {index}. `{_full_md_cell(coord or '依赖身份未记录')}`",
                "",
                (
                    f"本依赖完整展示 {confirmed_impact_count} 个确认有影响、"
                    f"{unconfirmed_count} 个结论未确定的 API。"
                ),
                "",
                *_api_completed_table(dependency_rows, findings),
                "",
            ])

        category_counts = _api_human_category_counts(api_model)
        not_impacted_count = int(category_counts.get("确认不受影响") or 0)
        not_found_count = int(
            category_counts.get("未发现调用路径") or 0
        )
        lines.extend([
            "### 其他已完成状态统计",
            "",
            "| 状态 | 数量 | 正文展示方式 |",
            "|---|---:|---|",
            (
                f"| 确认不受影响 | {not_impacted_count} | "
                "仅统计；完整逐项记录见明细文件。 |"
            ),
            (
                f"| 静态分析未发现调用路径 | {not_found_count} | "
                "仅统计，不展开 API；未发现路径不等于确认不受影响。 |"
            ),
            "",
            (
                f"全部 {api_model['completed_count']} 个已完成结果及 "
                f"{api_model['confirmed_relationship_count']} 条已确认调用关系见"
                "[完整 API 分析与调用关系明细](all-impact-details.md)。"
            ),
            "",
        ])
    return lines


def _full_md_cell(value):
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def _load_full_alert_details(report_dir):
    details = defaultdict(lambda: {
        "paths_by_status": defaultdict(dict),
        "reasons_by_status": defaultdict(list),
    })
    path = _call_chain_dir(report_dir) / "alerts.csv"
    for row in _validated_alert_rows(
        path,
        diagnostics=[],
        required=False,
    ):
        identity = build_api_identity_key({
            "coord": row.get("target_coord") or row.get("coord"),
            "api": (
                row.get("changed_symbol")
                or row.get("api")
                or row.get("api_name")
            ),
            "api_signature": row.get("api_signature"),
            "symbol_kind": row.get("symbol_kind"),
            "change_type": row.get("change_type"),
        })
        if not _identity_is_complete(identity):
            continue
        status = str(
            row.get("path_status") or row.get("api_status") or ""
        ).strip()
        path_text = str(row.get("path_text") or "").strip()
        if not path_text:
            entry = str(
                row.get("business_entry") or row.get("chain_entry") or ""
            ).strip()
            target = str(
                row.get("chain_target") or row.get("changed_symbol") or ""
            ).strip()
            if entry and target:
                path_text = f"{entry} → {target}"
        if path_text:
            path_text = _human_chain(path_text)
            try:
                occurrences = max(
                    int(row.get("path_occurrence_count") or 1),
                    1,
                )
            except (TypeError, ValueError):
                occurrences = 1
            previous = details[identity]["paths_by_status"][status].get(
                path_text,
                0,
            )
            details[identity]["paths_by_status"][status][path_text] = max(
                previous,
                occurrences,
            )
        reason = str(row.get("review_reason") or "").strip()
        if (
            reason
            and reason
            not in details[identity]["reasons_by_status"][status]
        ):
            details[identity]["reasons_by_status"][status].append(reason)
    return details


def _full_relationship_cell(row, alert_details):
    identity = build_api_identity_key(row)
    detail = alert_details.get(identity) or {}
    paths_by_status = detail.get("paths_by_status") or {}
    conclusion = str(row.get("conclusion") or "")
    if conclusion == "已确认影响":
        statuses = ("reachable",)
        prefix = ""
    elif conclusion in {
        "可能影响",
        "结论未确定（存在候选证据）",
    }:
        statuses = ("reachable", "uncertain", "not_analyzed")
        prefix = (
            "已确认调用关系："
            if (paths_by_status.get("reachable") or {})
            else "候选关系："
        )
    else:
        statuses = ()
        prefix = ""
    raw_paths = {}
    for status in statuses:
        for path, occurrences in sorted(
            (paths_by_status.get(status) or {}).items()
        ):
            raw_paths[path] = max(
                int(raw_paths.get(path) or 0),
                int(occurrences or 0),
            )
    paths = _logical_full_path_labels(raw_paths)
    if not paths:
        for path in row.get("paths") or []:
            text = _full_md_cell(_human_chain(path))
            if text and f"`{text}`" not in paths:
                paths.append(f"`{text}`")
    if paths:
        return prefix + "<br>".join(paths)
    if conclusion == "已确认影响":
        return "已确认存在当前系统调用关系；完整关系未记录"
    if conclusion == "已确认不受影响":
        return "无已确认受影响调用关系"
    return "本轮分析未发现当前系统调用关系"


def _logical_full_path_labels(path_occurrences):
    """Collapse partial-signature duplicates while preserving overload conflicts."""
    grouped = defaultdict(list)
    for path, occurrences in (path_occurrences or {}).items():
        bases, signatures = _call_path_shape(path)
        if bases:
            grouped[bases].append({
                "path": path,
                "signatures": signatures,
                "occurrences": int(occurrences or 0),
            })
    labels = []
    for bases in sorted(grouped):
        clusters = []
        candidates = sorted(
            grouped[bases],
            key=lambda item: (
                -sum(bool(value) for value in item["signatures"]),
                -len(str(item["path"] or "")),
                str(item["path"] or ""),
            ),
        )
        for candidate in candidates:
            compatible = next(
                (
                    cluster
                    for cluster in clusters
                    if all(
                        _call_path_signatures_compatible(
                            candidate["signatures"],
                            member["signatures"],
                        )
                        for member in cluster
                    )
                ),
                None,
            )
            if compatible is None:
                clusters.append([candidate])
            else:
                compatible.append(candidate)
        for cluster in clusters:
            representative = min(
                cluster,
                key=lambda item: (
                    -sum(bool(value) for value in item["signatures"]),
                    -len(str(item["path"] or "")),
                    str(item["path"] or ""),
                ),
            )
            occurrences = sum(
                int(item.get("occurrences") or 0) for item in cluster
            )
            text = _full_md_cell(representative["path"])
            if occurrences > 1:
                text += f"（记录 {occurrences} 次）"
            labels.append(f"`{text}`")
    return labels


_FULL_DEPENDENCY_CSV_FIELDS = [
    "依赖",
    "版本变化",
    "API 分析（已完成/总数）",
    "当前系统调用关系",
    "分析结果",
    "结果说明",
]

_FULL_API_CSV_FIELDS = [
    "依赖",
    "API",
    "新版本中的变化",
    "当前系统调用关系",
    "分析结果",
    "结果说明",
]


def _csv_text(value):
    return (
        str(value or "")
        .replace("<br>", "\n")
        .replace("\\|", "|")
        .replace("`", "")
        .strip()
    )


def _write_human_csv(path, fieldnames, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open_csv_write(path) as output:
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _dependency_csv_row(row):
    api_analysis = (
        f"{int(row.get('api_completed') or 0)}/"
        f"{int(row.get('api_total') or 0)}"
    )
    api_change_text = str(row.get("api_change_text") or "").strip()
    if api_change_text:
        api_analysis += f"\n{api_change_text}"
    return {
        "依赖": str(row.get("coord") or "依赖身份未记录"),
        "版本变化": _csv_text(_dependency_version_change_cell(row)),
        "API 分析（已完成/总数）": api_analysis,
        "当前系统调用关系": _csv_text(
            _dependency_current_calls_cell(row)
        ),
        "分析结果": str(row.get("analysis_conclusion") or ""),
        "结果说明": _dependency_result_explanation(row),
    }


def _api_csv_row(row, findings, alert_details):
    count = int(row.get("aggregate_count") or 1)
    api = _item_api_label(row) or str(
        row.get("api") or "API 身份未记录"
    )
    if count > 1:
        api = f"{api}（{count} 个）"
    relationship = (
        "调用关系分析未完成"
        if _api_result_is_incomplete(row)
        else _full_relationship_cell(row, alert_details)
    )
    return {
        "依赖": str(row.get("coord") or "依赖身份未记录"),
        "API": api,
        "新版本中的变化": _csv_text(
            row.get("change_without_severity")
        ),
        "当前系统调用关系": _csv_text(relationship),
        "分析结果": _analysis_conclusion_label(row),
        "结果说明": _api_result_explanation(row, findings),
    }


def _completed_api_rows_by_dependency(api_model):
    grouped = defaultdict(list)
    for row in api_model.get("completed") or []:
        grouped[_canonical_identity_coord(row.get("coord"))].append(row)

    def row_sort_key(row):
        category = _api_human_category(row)
        if category == "确认有影响":
            return (
                0,
                _severity_rank(row.get("severity")),
                -_api_call_relationship_count(row),
                0,
                str(row.get("api") or ""),
                str(row.get("api_signature") or ""),
                str(row.get("change_type") or ""),
            )
        if category == "结论未确定":
            return (
                1,
                -int(row.get("priority_score") or 0),
                _severity_rank(row.get("severity")),
                -_api_call_relationship_count(row),
                str(row.get("api") or ""),
                str(row.get("api_signature") or ""),
                str(row.get("change_type") or ""),
            )
        return (
            2,
            _api_result_rank(row),
            _severity_rank(row.get("severity")),
            -_api_call_relationship_count(row),
            str(row.get("api") or ""),
            str(row.get("api_signature") or ""),
            str(row.get("change_type") or ""),
        )

    dependency_groups = []
    for coord, rows in grouped.items():
        ordered_rows = sorted(rows, key=row_sort_key)
        result_ranks = [_api_result_rank(row) for row in ordered_rows]
        best_result_rank = min(result_ranks, default=99)
        best_severity_rank = min(
            (
                _severity_rank(row.get("severity"))
                for row in ordered_rows
                if _api_result_rank(row) == best_result_rank
            ),
            default=99,
        )
        unconfirmed_scores = [
            int(row.get("priority_score") or 0)
            for row in ordered_rows
            if _api_human_category(row) == "结论未确定"
        ]
        dependency_groups.append({
            "coord": coord,
            "rows": ordered_rows,
            "best_result_rank": best_result_rank,
            "best_severity_rank": best_severity_rank,
            "top_priority_score": max(unconfirmed_scores, default=0),
            "total_priority_score": sum(unconfirmed_scores),
            "unconfirmed_count": len(unconfirmed_scores),
            "confirmed_impact_count": sum(
                _api_human_category(row) == "确认有影响"
                for row in ordered_rows
            ),
            "relationship_count": sum(
                _api_call_relationship_count(row) for row in ordered_rows
            ),
        })

    def dependency_group_sort_key(group):
        result_rank = int(group["best_result_rank"])
        stable_tail = (
            not bool(group["coord"]),
            str(group["coord"]),
        )
        if int(group["confirmed_impact_count"]):
            return (
                0,
                int(group["best_severity_rank"]),
                -int(group["relationship_count"]),
                -int(group["confirmed_impact_count"]),
                -int(group["top_priority_score"]),
                *stable_tail,
            )
        if int(group["unconfirmed_count"]):
            return (
                1,
                -int(group["top_priority_score"]),
                -int(group["total_priority_score"]),
                -int(group["unconfirmed_count"]),
                int(group["best_severity_rank"]),
                -int(group["relationship_count"]),
                *stable_tail,
            )
        return (
            2,
            result_rank,
            int(group["best_severity_rank"]),
            -int(group["relationship_count"]),
            -len(group["rows"]),
            -int(group["top_priority_score"]),
            -int(group["total_priority_score"]),
            *stable_tail,
        )

    dependency_groups.sort(key=dependency_group_sort_key)
    return [
        (group["coord"], group["rows"])
        for group in dependency_groups
    ]


def write_full_dependency_analysis_artifact(
    report_dir,
    findings,
    dependency_model=None,
):
    dependency_model = dependency_model or build_human_dependency_analysis(
        findings
    )
    output = _deliverables_dir(report_dir) / "all-affected-dependencies.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    if _report_scope_is_verified(findings):
        range_note = (
            "> 本文件完整展示本轮分析范围内的依赖结果；"
            "未纳入本轮分析的依赖不属于“未完成分析”，"
            "统一记录在[分析范围记录](analysis-scope.md)中。"
        )
    else:
        range_note = (
            "> 本文件汇总现有记录中可识别的依赖结果；"
            "当前分析范围无法核验，不能把本文件解释为"
            "本轮分析的完整依赖结果。"
        )
    lines = [
        "# 完整依赖分析明细",
        "",
        range_note,
        "",
        (
            "| 变化依赖总数 | 已完成分析 | 未完成分析 | 确认有影响 | "
            "确认不受影响 | 尚未确认影响 |"
        ),
        "|---:|---:|---:|---:|---:|---:|",
        (
            f"| {_population_total_cell(dependency_model)} | "
            f"{dependency_model['completed_count']} | "
            f"{_population_incomplete_cell(dependency_model)} | "
            f"{dependency_model['confirmed_any_count']} | "
            f"{dependency_model['confirmed_no_impact_completed_count']} | "
            f"{dependency_model['unconfirmed_completed_count']} |"
        ),
        "",
    ]
    if dependency_model.get("count_note"):
        lines.extend([
            dependency_model["count_note"],
            "",
        ])
    if dependency_model["incomplete"]:
        lines.extend([
            (
                f"## 未完成分析的依赖"
                f"（{dependency_model['incomplete_count']}）"
            ),
            "",
            *_dependency_incomplete_table(
                dependency_model["incomplete"],
                include_link=True,
            ),
            "",
        ])
    if dependency_model["completed"]:
        lines.extend([
            (
                f"## 已完成分析的依赖"
                f"（{dependency_model['completed_count']}）"
            ),
            "",
            (
                "依赖先按影响结论、严重级别、未确认影响最高优先分和"
                "总优先分排序，再比较调用关系数量；“API 分析”中的"
                "链接指向该依赖的完整 API 结果。"
            ),
            "",
            *_dependency_completed_table(
                dependency_model["completed"],
                include_link=True,
            ),
            "",
        ])
    write_text(str(output), "\n".join(lines))
    return relpath_for_report(output, report_dir)


def write_full_dependency_analysis_csv(
    report_dir,
    dependency_model,
):
    output = _deliverables_dir(
        report_dir
    ) / "all-affected-dependencies.csv"
    ordered_rows = [
        *list(dependency_model.get("incomplete") or []),
        *list(dependency_model.get("completed") or []),
    ]
    _write_human_csv(
        output,
        _FULL_DEPENDENCY_CSV_FIELDS,
        (_dependency_csv_row(row) for row in ordered_rows),
    )
    return relpath_for_report(output, report_dir)


def write_full_api_analysis_artifact(
    report_dir,
    findings,
    api_model=None,
    dependency_model=None,
):
    api_model = api_model or build_human_api_analysis(findings)
    dependency_model = dependency_model or build_human_dependency_analysis(
        findings,
        api_model,
    )
    alert_details = _load_full_alert_details(report_dir)
    output = _deliverables_dir(report_dir) / "all-impact-details.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    if _report_scope_is_verified(findings):
        range_note = (
            "> 本文件完整展示本轮分析范围内的 API 结果和调用关系；"
            "未纳入本轮分析的 API 不属于“未完成分析”，"
            "其所属依赖统一记录在[分析范围记录](analysis-scope.md)中。"
        )
    else:
        range_note = (
            "> 本文件汇总现有记录中可识别的 API 结果和调用关系；"
            "当前分析范围无法核验，不能把本文件解释为"
            "本轮分析的完整 API 结果。"
        )
    lines = [
        "# 完整 API 分析与调用关系明细",
        "",
        range_note,
        "",
        (
            "| 变化 API 总数 | 已完成分析 | 未完成分析 | 确认有影响 | "
            "确认不受影响 | 尚未确认影响 |"
        ),
        "|---:|---:|---:|---:|---:|---:|",
        (
            f"| {_population_total_cell(api_model)} | "
            f"{api_model['completed_count']} | "
            f"{_population_incomplete_cell(api_model)} | "
            f"{api_model['confirmed_count']} | "
            f"{api_model['confirmed_no_impact_count']} | "
            f"{api_model['unconfirmed_count']} |"
        ),
        "",
    ]
    if api_model.get("count_note"):
        lines.extend([
            api_model["count_note"],
            "",
        ])
    if api_model["incomplete"]:
        lines.extend([
            '<a id="unanalyzed-apis"></a>',
            "",
            f"## 未完成分析的 API（{api_model['incomplete_count']}）",
            "",
            *_api_detail_table(
                api_model["incomplete"],
                findings,
                full=True,
                alert_details=alert_details,
            ),
            "",
        ])

    completed_by_coord = _completed_api_rows_by_dependency(api_model)
    if api_model["completed"]:
        lines.extend([
            (
                f"以下 {api_model['completed_count']} 个已完成分析的 API "
                "按依赖影响程度展示；依赖之间先比较最强结论、严重级别"
                "和未确认影响优先分数，每个依赖内再按结论类型及 API "
                "复核优先分数排列。"
            ),
            "",
        ])
    dependency_lookup = {
        _canonical_identity_coord(row.get("coord")): row
        for row in dependency_model["rows"]
    }
    for coord, rows in completed_by_coord:
        dependency = dependency_lookup.get(coord) or {"coord": coord}
        lines.extend([
            f'<a id="{_dependency_anchor(coord)}"></a>',
            "",
            (
                f"## `{_full_md_cell(coord or '依赖身份未记录')}`"
                + (
                    f"：{_full_md_cell(_version_transition(dependency))}"
                    if _version_transition(dependency)
                    else ""
                )
            ),
            "",
            (
                f"本依赖有 {sum(int(row.get('aggregate_count') or 1) for row in rows)} "
                "个已完成分析的变化 API。"
            ),
            "",
            *_api_detail_table(
                rows,
                findings,
                full=True,
                alert_details=alert_details,
            ),
            "",
        ])
    write_text(str(output), "\n".join(lines))
    return relpath_for_report(output, report_dir)


def write_full_api_analysis_csv(
    report_dir,
    findings,
    api_model,
):
    output = _deliverables_dir(report_dir) / "all-impact-details.csv"
    alert_details = _load_full_alert_details(report_dir)
    completed_rows = [
        row
        for _coord, rows in _completed_api_rows_by_dependency(api_model)
        for row in rows
    ]
    ordered_rows = [
        *list(api_model.get("incomplete") or []),
        *completed_rows,
    ]
    _write_human_csv(
        output,
        _FULL_API_CSV_FIELDS,
        (
            _api_csv_row(row, findings, alert_details)
            for row in ordered_rows
        ),
    )
    return relpath_for_report(output, report_dir)


def cleanup_legacy_s6_detail_artifacts(report_dir):
    """Remove obsolete split files so users see one complete API detail file."""
    deliverables = _deliverables_dir(report_dir)
    for config in S6_DETAIL_BUCKETS.values():
        for key in ("csv", "md"):
            filename = str(config.get(key) or "").strip()
            if not filename:
                continue
            try:
                (deliverables / filename).unlink()
            except FileNotFoundError:
                pass


def write_primary_report_artifacts(report_dir, findings):
    api_model = build_human_api_analysis(findings)
    dependency_model = build_human_dependency_analysis(findings, api_model)
    artifacts = {
        "full_dependency_analysis_md": (
            write_full_dependency_analysis_artifact(
                report_dir,
                findings,
                dependency_model,
            )
        ),
        "full_dependency_analysis_csv": (
            write_full_dependency_analysis_csv(
                report_dir,
                dependency_model,
            )
        ),
        "full_api_analysis_md": write_full_api_analysis_artifact(
            report_dir,
            findings,
            api_model,
            dependency_model,
        ),
        "full_api_analysis_csv": write_full_api_analysis_csv(
            report_dir,
            findings,
            api_model,
        ),
    }
    return artifacts, api_model, dependency_model


def render_user_visible_files(
    findings,
    api_model=None,
    dependency_model=None,
):
    api_model = api_model or build_human_api_analysis(findings)
    dependency_model = dependency_model or build_human_dependency_analysis(
        findings,
        api_model,
    )
    scope = findings.get("analysis_scope") or {}
    scope_verified = _report_scope_is_verified(findings)
    partial_scope = (
        str(scope.get("mode") or "").strip() == "partial"
        and scope_verified
    )
    raw_dependency_record_count = len(
        findings.get("dependency_changes") or []
    )
    raw_api_record_count = len(
        findings.get("changed_api_inventory") or []
    )
    displayed_dependencies = sum(
        int(row.get("aggregate_count") or 1)
        for row in dependency_model["incomplete"][
            :S6_MAIN_INCOMPLETE_LIMIT
        ]
    ) + sum(
        int(row.get("aggregate_count") or 1)
        for row in dependency_model["completed"][
            :S6_MAIN_DEPENDENCY_LIMIT
        ]
    )
    displayed_api_rows = sum(
        int(row.get("aggregate_count") or 1)
        for row in api_model["incomplete"][:S6_MAIN_INCOMPLETE_LIMIT]
    ) + sum(
        int(row.get("aggregate_count") or 1)
        for row in _main_completed_api_rows(api_model["completed"])
    )
    rows = [
        (
            "当前报告（`report.md`）",
            "依赖和 API 的分析结论、未完成原因、部分调用关系及文件说明",
            (
                f"{_main_report_range(dependency_model, '依赖', displayed_dependencies)}；"
                f"{_main_report_range(api_model, 'API', displayed_api_rows)}"
            ),
            "当前文件全部正文",
        ),
        (
            "[完整依赖分析明细](all-affected-dependencies.md)"
            "（`all-affected-dependencies.md`）<br>"
            "[完整依赖分析 CSV](all-affected-dependencies.csv)"
            "（`all-affected-dependencies.csv`）",
            (
                (
                    "本轮分析范围内全部变化依赖"
                    if scope_verified
                    else "现有记录中可识别的变化依赖"
                )
                + "的分析状态、确认有影响数量、未完成原因，"
                "以及对应 API 明细链接；CSV 使用相同数据和排序"
            ),
            _population_full_range(dependency_model, "变化依赖"),
            "“一、依赖层面结论”",
        ),
        (
            "[完整 API 分析与调用关系明细](all-impact-details.md)"
            "（`all-impact-details.md`）<br>"
            "[完整 API 与调用关系 CSV](all-impact-details.csv)"
            "（`all-impact-details.csv`）",
            (
                (
                    "本轮分析范围内全部变化 API"
                    if scope_verified
                    else "现有记录中可识别的变化 API"
                )
                + "的分析状态；"
                "确认有影响项展示完整调用关系，未完成项记录具体原因；"
                "CSV 使用相同数据和排序"
            ),
            (
                f"{_population_full_range(api_model, '变化 API')}；"
                "已确认调用关系全量 "
                f"{api_model['confirmed_relationship_count']}/"
                f"{api_model['confirmed_relationship_count']}"
            ),
            "“二、API 及调用关系”",
        ),
    ]
    artifacts = findings.get("artifacts") or {}
    alerts_path = str(artifacts.get("alerts_csv") or "").strip()
    if alerts_path:
        valid_record_count = int(
            (findings.get("impact_overview") or {}).get("record_count") or 0
        )
        raw_record_count = int(
            (findings.get("scan_stats") or {}).get(
                "alerts_raw_record_count"
            )
            or valid_record_count
        )
        if raw_record_count > valid_record_count:
            alerts_range = (
                f"原始分析记录 {raw_record_count} 条；"
                f"采用 {valid_record_count} 条；"
                f"未采用 {raw_record_count - valid_record_count} 条"
            )
        else:
            alerts_range = f"原始分析记录全量 {raw_record_count} 条"
        rows.append((
            _report_link(alerts_path, "原始分析记录")
            + "（`alerts.csv`）",
            (
                "一条原始分析记录一行；保留分析状态、调用起点、"
                "完整调用关系和证据文件"
            ),
            alerts_range,
            "“二、API 及调用关系”",
        ))
    dep_changes_path = str(
        artifacts.get("dependency_changes_csv") or ""
    ).strip()
    if dep_changes_path:
        rows.append((
            _report_link(dep_changes_path, "依赖变化原始清单"),
            (
                "选择分析范围前识别出的依赖版本变化和依赖变更类型"
            ),
            (
                f"选择前原始记录全量 {raw_dependency_record_count} 条"
                + (
                    "；包含未纳入本轮分析的对象"
                    if partial_scope
                    else ""
                )
            ),
            "“一、依赖层面结论”",
        ))
    changed_path = str(artifacts.get("changed_apis_csv") or "").strip()
    if changed_path:
        rows.append((
            _report_link(changed_path, "变化 API 原始清单"),
            (
                "选择分析范围前通过新旧依赖对比识别出的变化 API "
                "及变化类型"
            ),
            (
                f"选择前原始记录全量 {raw_api_record_count} 条"
                + (
                    "；包含未纳入本轮分析的对象"
                    if partial_scope
                    else ""
                )
            ),
            "“二、API 及调用关系”",
        ))
    binary_review_path = str(
        artifacts.get("binary_change_review_md") or ""
    ).strip()
    if binary_review_path:
        rows.append((
            _report_link(binary_review_path, "完整二进制变化裁决"),
            (
                "按依赖包列出正式变化、不可投影的运行时机制变化、"
                "诊断候选及其证据缺口，供人工复核"
            ),
            "已识别二进制裁决全量，包含未进入 API 调用链表的资源与运行时机制变化",
            "依赖与 API 结论的原始裁决依据",
        ))
    source_review_path = str(
        artifacts.get("source_analysis_review_md") or ""
    ).strip()
    if source_review_path:
        rows.append((
            _report_link(source_review_path, "源码辅助分析复核"),
            (
                "记录用户的源码选择、源码到二进制方法的映射、"
                "源码补充信息及其非权威边界"
            ),
            "用户授权范围内的源码辅助证据全量",
            "主报告顶部的源码使用说明",
        ))
    build_provenance_path = str(
        artifacts.get("build_provenance_json") or ""
    ).strip()
    if build_provenance_path:
        rows.append((
            _report_link(
                build_provenance_path,
                "构建来源与制品身份",
            ),
            "项目构建工具、模块、实际分析制品及其来源",
            "本轮构建和制品来源记录",
            "依赖与 API 结论所使用的制品身份",
        ))
    scope_path = str(artifacts.get("analysis_scope_md") or "").strip()
    if scope_path:
        rows.append((
            _report_link(scope_path, "分析范围记录"),
            (
                "选择前总数、本轮纳入数量、未纳入数量、"
                "未纳入依赖及具体原因"
            ),
            (
                f"变化依赖 {int(scope.get('included_dependency_count') or 0)}/"
                f"{int(scope.get('available_dependency_count') or 0)}；"
                f"变化 API {int(scope.get('analyzed_api_count') or 0)}/"
                f"{int(scope.get('total_api_count') or 0)}"
            ),
            "主报告顶部的分析范围说明",
        ))
    diagnostic_path = str(
        artifacts.get("diagnostic_detail_md") or ""
    ).strip()
    if diagnostic_path:
        input_diagnostic_count = len(findings.get("diagnostics") or [])
        analysis_diagnostic_count = len(
            findings.get("diagnostic_guidance") or []
        )
        rows.append((
            _report_link(diagnostic_path, "分析异常记录"),
            (
                "分析输入读取或结构异常，以及分析过程中记录的"
                "结论限制和影响范围"
            ),
            (
                f"输入异常 {input_diagnostic_count} 项；"
                f"分析诊断 {analysis_diagnostic_count} 项"
            ),
            "未完成分析原因与结论限制",
        ))
    lines = [
        "## 三、用户可见文件说明",
        "",
        "| 文件 | 包含内容 | 数据范围 | 对应主报告 |",
        "|---|---|---|---|",
    ]
    lines.extend(
        f"| {file_cell} | {_md_cell(contents, 300)} | "
        f"{_md_cell(data_range, 240)} | {_md_cell(section, 160)} |"
        for file_cell, contents, data_range, section in rows
    )
    lines.append("")
    return lines


def build_report_sections_for_test_only():
    return [
        "依赖层面结论",
        "API 及调用关系",
        "用户可见文件说明",
    ]


def generate_report(findings):
    api_model = build_human_api_analysis(findings)
    dependency_model = build_human_dependency_analysis(findings, api_model)
    L = [
        "# Java 依赖升级影响报告",
        "",
        f"> 生成时间：{findings.get('generated_at') or '未记录'}",
        "",
    ]
    L += render_report_scope_notice(findings)
    L += render_dependency_conclusions(findings, dependency_model)
    L += render_api_and_calls(findings, api_model)
    L += render_user_visible_files(
        findings,
        api_model,
        dependency_model,
    )

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
    evidence_paths = _normalize_evidence_paths(
        item.get('evidence_paths')
    )[0]
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

    print("\n正在生成最终分析报告…", file=sys.stderr)
    findings = collect_findings(args.report_dir)
    findings.setdefault('artifacts', {})
    cleanup_legacy_s6_detail_artifacts(args.report_dir)
    findings['artifacts'].update(
        write_changed_api_split_artifacts(args.report_dir)
    )
    findings['artifacts']['analysis_scope_md'] = write_analysis_scope_artifact(
        args.report_dir, findings
    )
    diagnostic_detail = write_diagnostic_detail_artifact(
        args.report_dir, findings
    )
    if diagnostic_detail:
        findings['artifacts']['diagnostic_detail_md'] = diagnostic_detail
    primary_artifacts, _api_model, _dependency_model = (
        write_primary_report_artifacts(args.report_dir, findings)
    )
    findings['artifacts'].update(primary_artifacts)

    Path(args.output_findings).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output_findings, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    write_text(args.output_report, generate_report(findings))

    p0, p1, p2, unk, nf = (
        len(findings[k])
        for k in ('p0', 'p1', 'p2', 'uncertain', 'not_found')
    )
    probable = len(findings.get('probable_impact') or [])
    uncertainty_counts = _uncertainty_counts(findings.get('uncertain') or [])
    uncertain_candidates = uncertainty_counts.get(
        UNCERTAINTY_KIND_CANDIDATE_EVIDENCE, 0
    )
    uncertain_limitations = uncertainty_counts.get(
        UNCERTAINTY_KIND_ANALYSIS_LIMITATION, 0
    )
    needs_input = len(findings.get('needs_input') or [])
    not_analyzed = len(_exclusive_not_analyzed(findings))
    print("最终分析报告已生成。", file=sys.stderr)
    print(
        f"结果：已确认影响 {p0 + p1 + p2}（其中高风险 {p0 + p1}），"
        f"可能影响 {probable}，结论未确定 {unk}"
        f"（候选证据 {uncertain_candidates}、静态分析能力边界 {uncertain_limitations}），"
        f"输入不足且结论未确定 {needs_input}，"
        f"本次未完成分析 {not_analyzed}，未发现静态路径 {nf}。",
        file=sys.stderr,
    )
    print(f"最终报告：{args.output_report}", file=sys.stderr)
    print(
        (
            "完整依赖分析明细："
            f"{_deliverables_dir(args.report_dir) / 'all-affected-dependencies.md'}；"
            f"{_deliverables_dir(args.report_dir) / 'all-affected-dependencies.csv'}"
        ),
        file=sys.stderr,
    )
    print(
        (
            "完整 API 分析与调用关系明细："
            f"{_deliverables_dir(args.report_dir) / 'all-impact-details.md'}；"
            f"{_deliverables_dir(args.report_dir) / 'all-impact-details.csv'}"
        ),
        file=sys.stderr,
    )


if __name__ == '__main__':
    main()
