#!/usr/bin/env python3
"""
s5_call_chain_engine_integrated.py

集成所有改进模块的Step 5引擎。

核心改进：
  ✓ 自动发现依赖源码映射（解决重复配置问题）
  ✓ Java AST 主链路 + Kotlin/异常场景正则降级
  ✓ 置信度加权深度（不再固定3跳）
  ✓ 系统代码触达识别（Service/Facade/Manager/Handler 等业务层）
  ✓ 增强型输出格式（可读调用链 + 明确action）

使用方式：
  python s5_call_chain_engine_integrated.py \
    --all-changed-apis .upgrade-report/evidence/api_changes/all_changed_apis.csv \
    --source-dirs src/main/java \
    --report-dir .upgrade-report \
    --output-dir .upgrade-report/evidence/call_chain

注：无需手动配置 `--dependency-source-mappings`，系统自动从 Step 4 配置推断
"""

import argparse
import csv
import gc
import hashlib
import io
import json
import os
import re
import sys
import time
import traceback
import zipfile
from collections import defaultdict, deque
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

# 引入新模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auto_discover_bridge_sources import auto_discover_bridge_sources
from enhanced_source_analyzer import (
    CallEdge,
    MethodDef,
    analyze_file,
    ensure_tree_sitter_available,
    extract_call_edges_enhanced,
    is_test_source_path,
    tree_sitter_status,
)
from confidence_weighted_tracer import (
    build_api_identity_key,
    critical_parser_fallback_reasons,
    build_api_target_keys,
    trace_all_apis_with_confidence_weighting,
)
from enhanced_output_formatter import generate_enhanced_summary, register_step5_summary_artifacts
import compat as compat_module
from compat import run_cmd
from csv_io import open_csv_read, open_csv_write
from progress_logging import PhaseTimer, emit_progress
from business_bytecode_graph import collect_business_bytecode_batch
from indirect_usage_analyzer import (
    apply_indirect_usage_batch_compatibility,
    api_key as indirect_api_key,
    collect_indirect_usage_batch,
)
from framework_adapters import run_framework_adapters, serialize_framework_batches
from step5_evidence_ingestion import ingest_collector_batches
from step5_evidence_model import CoverageRecord, EvidenceFailure, thaw_evidence_value
from step5_graph import SourceGraph
from tool_execution import ExternalToolError, execute_external_tool
from step5_memory_observer import (
    ProcessTreeObserver,
    Step5ResourceBudgetExceeded,
    evaluate_process_tree_budget,
    record_step5_memory,
    set_active_process_tree_observer,
)
from step5_artifact_fact_store import Step5ArtifactFactStore
from signature_utils import normalize_signature_for_identity, signatures_match_identity
from analysis_contract import build_project_scope, discover_project_modules, sha256_file
from artifact_safety import require_safe_archive
from pipeline_constants import (
    EVIDENCE_API_CHANGES_DIRNAME,
    EVIDENCE_CALL_CHAIN_DIRNAME,
    EVIDENCE_CONTEXT_DIRNAME,
    EVIDENCE_DEPENDENCIES_DIRNAME,
    EVIDENCE_DIRNAME,
    RUNTIME_CACHE_DIRNAME,
    RUNTIME_DIRNAME,
    RUNTIME_INDEXES_DIRNAME,
    RUNTIME_OBSERVABILITY_DIRNAME,
    RUNTIME_STATE_DIRNAME,
    STEP5_ARTIFACT_BYTECODE_CATALOG_FILE,
    STEP5_ARTIFACT_BYTECODE_DIRNAME,
    STEP5_ARTIFACT_BYTECODE_INDEX_FILE,
    STEP5_QUERY_INDEX_FILE,
    STEP1_DEPENDENCY_JARS_MANIFEST_FILE,
)
from s5_query_call_chain import write_query_index
from dependency_source_alignment import align_dependency_source_mappings
from artifact_alignment import build_artifact_alignment

STEP_INTERACTION_PREFIX = "JUA_STEP_INTERACTION_JSON:"
MAIN_STATE_FILE_NAME = "main_state.json"
EVIDENCE_FAILURE_OCCURRENCE_FIELDS = (
    'caller_symbol', 'caller_qualified_key', 'artifact', 'artifact_entry',
    'class_name', 'line', 'instruction_offset', 'detail',
)


def _serialize_ingestion_failure(collector, failure):
    return {
        'collector': collector,
        'reason_code': failure.reason_code,
        'blocking': failure.blocking,
        'api_identity': failure.api_identity,
        'artifact': failure.artifact,
        'class_name': failure.class_name,
        'detail': failure.detail,
        'occurrences': [
            tuple(getattr(occurrence, field_name)
                  for field_name in EVIDENCE_FAILURE_OCCURRENCE_FIELDS)
            for occurrence in failure.occurrences
        ],
    }


def _evidence_dir(report_dir, name):
    return Path(report_dir) / EVIDENCE_DIRNAME / name


def _runtime_dir(report_dir, name):
    return Path(report_dir) / RUNTIME_DIRNAME / name


def _state_path(report_dir):
    return _runtime_dir(report_dir, RUNTIME_STATE_DIRNAME) / MAIN_STATE_FILE_NAME


def _dep_changes_path(report_dir):
    return _evidence_dir(report_dir, EVIDENCE_DEPENDENCIES_DIRNAME) / "dep_changes.csv"


def _current_resolved_path(report_dir):
    return _evidence_dir(report_dir, EVIDENCE_DEPENDENCIES_DIRNAME) / "deps_current_resolved.csv"


def _step1_dependency_jars_manifest_path(report_dir):
    return (
        _evidence_dir(report_dir, EVIDENCE_DEPENDENCIES_DIRNAME)
        / STEP1_DEPENDENCY_JARS_MANIFEST_FILE
    )


def _build_provenance_path(report_dir):
    return _evidence_dir(report_dir, EVIDENCE_DEPENDENCIES_DIRNAME) / "build_provenance.json"


def _context_path(report_dir):
    return _evidence_dir(report_dir, EVIDENCE_CONTEXT_DIRNAME) / "context.json"


def load_context_source_dirs(context_path):
    path = Path(context_path)
    if not path.exists():
        return []
    try:
        context = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"STEP5_CONTEXT_PARSE_FAILED:{path}:{type(exc).__name__}:{exc}"
        ) from exc
    source_dirs = context.get("source_dirs") or []
    if not isinstance(source_dirs, list) or any(
        not isinstance(item, str) for item in source_dirs
    ):
        raise RuntimeError(
            f"STEP5_CONTEXT_PARSE_FAILED:{path}:source_dirs must be a string list"
        )
    return source_dirs


def _source_mapping_summary_path(report_dir):
    return _evidence_dir(report_dir, EVIDENCE_CONTEXT_DIRNAME) / "source_mapping_summary.json"


def _all_changed_apis_path(report_dir):
    return _evidence_dir(report_dir, EVIDENCE_API_CHANGES_DIRNAME) / "all_changed_apis.csv"


def _call_chain_dir(report_dir):
    return _evidence_dir(report_dir, EVIDENCE_CALL_CHAIN_DIRNAME)


def _runtime_cache_dir(report_dir):
    return _runtime_dir(report_dir, RUNTIME_CACHE_DIRNAME)


def _runtime_observability_dir(report_dir):
    return _runtime_dir(report_dir, RUNTIME_OBSERVABILITY_DIRNAME)


def _default_query_index_path(report_dir):
    return _runtime_dir(report_dir, RUNTIME_INDEXES_DIRNAME) / STEP5_QUERY_INDEX_FILE


def _env_flag_enabled(name):
    return str(os.environ.get(name, '') or '').strip().lower() in {'1', 'true', 'yes', 'on'}


def _step5_debug_enabled():
    return _env_flag_enabled('JUA_STEP5_DEBUG')


def _step5_debug(topic, message, **fields):
    if not _step5_debug_enabled():
        return
    payload = {
        'topic': str(topic or '').strip(),
        'message': str(message or '').strip(),
    }
    for key, value in (fields or {}).items():
        if value is None:
            continue
        payload[key] = value
    print(
        f"[step5-debug] {json.dumps(thaw_evidence_value(payload), ensure_ascii=False, sort_keys=True)}",
        file=sys.stderr,
    )


STEP5_TIMING_FIELDS = [
    'section',
    'metric',
    'value',
    'status',
    'started_at',
    'ended_at',
    'elapsed_sec',
    'item',
    'message',
]


class Step5TimingRecorder:
    """Keep the Step5 timing CSV useful before the final metrics exist."""

    def __init__(self, report_dir):
        self.report_dir = report_dir
        self.path = _runtime_observability_dir(report_dir) / 'step5_timing.csv'
        self._activity_rows = []
        self._metrics = {}
        self.write_metrics({})

    @property
    def activity_rows(self):
        return [dict(row) for row in self._activity_rows]

    def start_phase(self, phase, *, item='', message=''):
        token = {
            'row_index': len(self._activity_rows),
            'started_perf': time.perf_counter(),
        }
        self._activity_rows.append({
            'section': 'activity',
            'metric': str(phase or ''),
            'value': '',
            'status': 'running',
            'started_at': datetime.now().astimezone().isoformat(timespec='milliseconds'),
            'ended_at': '',
            'elapsed_sec': '',
            'item': str(item or ''),
            'message': str(message or f'正在执行 {phase}'),
        })
        self.write_metrics(self._metrics)
        return token

    def finish_phase(self, token, *, status='completed', message=''):
        elapsed = time.perf_counter() - float(token.get('started_perf') or 0.0)
        index = int(token.get('row_index'))
        row = dict(self._activity_rows[index])
        row.update({
            'status': str(status or ''),
            'ended_at': datetime.now().astimezone().isoformat(timespec='milliseconds'),
            'elapsed_sec': f'{max(0.0, elapsed):.3f}',
            'message': str(message or row.get('message') or ''),
        })
        self._activity_rows[index] = row
        self.write_metrics(self._metrics)
        return elapsed

    def write_metrics(self, graph_stats):
        self._metrics = dict(graph_stats or {})
        return _write_step5_timing_csv(
            self.report_dir,
            self._metrics,
            activity_rows=self._activity_rows,
        )


def _write_step5_timing_csv(report_dir, graph_stats, *, activity_rows=None):
    """Persist live Step5 activities plus final performance metrics."""
    perf = ((graph_stats or {}).get('step5_perf') or {})
    rows = [dict(row) for row in (activity_rows or [])]
    preferred_keys = {
        'main': [
            'business_graph_elapsed_sec',
            'dependency_graph_elapsed_sec',
            'business_bytecode_elapsed_sec',
            'business_bytecode_classes_scanned',
            'business_bytecode_edges_found',
            'business_bytecode_classfile_fast_path_classes',
            'business_bytecode_javap_fallback_classes',
            'source_artifact_alignment_elapsed_sec',
            'framework_adapters_elapsed_sec',
            'framework_adapter_merge_elapsed_sec',
            'indirect_usage_elapsed_sec',
            'query_index_elapsed_sec',
            'indirect_usage_target_count',
            'indirect_usage_owner_count',
            'indirect_usage_source_methods_scanned',
            'indirect_usage_source_methods_with_indirect_markers',
            'indirect_usage_owner_presence_scans',
            'indirect_usage_potential_legacy_method_target_pairs',
        ],
        'bytecode_scan': [
            'elapsed_sec',
            'javap_elapsed_sec',
            'visited_classes',
            'javap_tasks',
            'javap_classes',
            'hit_apis',
            'scan_failures',
        ],
        'bytecode_expand': [
            'elapsed_sec',
            'member_index_elapsed_sec',
            'calls',
            'candidate_cache_hits',
            'member_index_builds',
            'member_index_uses',
            'candidate_classes',
            'javap_classes',
            'edges_added',
        ],
        'trace': [
            'elapsed_sec',
            'api_elapsed_sec',
            'apis_traced',
            'total_apis',
            'frontier_pops',
            'frontier_pushes',
            'incoming_edges_scanned',
            'incoming_edges_cache_hits',
            'incoming_edges_cache_misses',
            'incoming_edges_cache_size',
            'multi_target_group_count',
            'multi_target_target_count',
            'multi_target_shared_key_count',
            'multi_target_propagated_states',
            'reverse_transition_cache_builds',
            'reverse_transition_cache_hits',
            'reverse_transition_cache_size',
            'reverse_transition_edges_materialized',
            'reverse_transition_edges_reused',
            'critical_node_cache_hits',
            'critical_node_cache_misses',
            'critical_node_cache_size',
            'critical_node_fast_none',
            'adaptive_exact_high_frontier_steps',
            'adaptive_exact_high_cost_limit',
            'depth_truncated_candidate_count',
            'direct_class_usage_elapsed_sec',
            'direct_class_usage_scanned_methods',
            'direct_class_usage_cache_hits',
            'direct_class_usage_cache_misses',
            'direct_class_usage_cache_size',
            'direct_field_usage_elapsed_sec',
            'direct_field_usage_scanned_methods',
            'direct_field_usage_cache_hits',
            'direct_field_usage_cache_misses',
            'direct_field_usage_cache_size',
            'direct_source_fact_index_builds',
            'direct_source_fact_index_hits',
            'direct_source_fact_index_elapsed_sec',
            'direct_source_fact_index_scanned_methods',
            'direct_source_fact_index_body_reads',
            'direct_source_fact_index_body_cache_evictions',
            'direct_source_fact_index_class_keys',
            'direct_source_fact_index_field_keys',
            'declared_signature_index_builds',
            'declared_signature_index_elapsed_sec',
            'declared_signature_index_size',
        ],
        'report': [
            'elapsed_sec',
            'summary_text_elapsed_sec',
            'by_api_elapsed_sec',
            'alerts_elapsed_sec',
            'summary_json_elapsed_sec',
            'by_module_elapsed_sec',
            'by_api_count',
        ],
        'artifact_facts': [
            'inventory_elapsed_sec',
            'inventory_builds',
            'inventory_hits',
            'class_bytes_reads',
            'class_bytes_read',
            'resource_bytes_reads',
            'resource_bytes_read',
            'fact_build_elapsed_sec',
            'fact_hits',
            'fact_misses',
            'fact_failures',
            'javap_requests',
            'javap_starts',
            'javap_shared_hits',
            'javap_failures',
        ],
        'memory': [],
    }
    for section, keys in preferred_keys.items():
        bucket = perf.get(section) or {}
        if not isinstance(bucket, dict):
            continue
        for key in keys:
            if key in bucket:
                rows.append({
                    'section': section,
                    'metric': key,
                    'value': bucket.get(key),
                })
        for key in sorted(bucket):
            if key in keys or isinstance(bucket.get(key), (dict, list)):
                continue
            rows.append({
                'section': section,
                'metric': key,
                'value': bucket.get(key),
            })
    if not rows:
        observability_dir = _runtime_observability_dir(report_dir)
        observability_dir.mkdir(parents=True, exist_ok=True)
        path = observability_dir / 'step5_timing.csv'
        with open_csv_write(path) as f:
            csv.DictWriter(f, fieldnames=STEP5_TIMING_FIELDS).writeheader()
        return str(path)
    observability_dir = _runtime_observability_dir(report_dir)
    observability_dir.mkdir(parents=True, exist_ok=True)
    path = observability_dir / 'step5_timing.csv'
    with open_csv_write(path) as f:
        writer = csv.DictWriter(f, fieldnames=STEP5_TIMING_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return str(path)


def _observe_step5_memory(graph_stats, phase, *, graph=None, extra=None):
    sample = record_step5_memory(
        graph_stats,
        phase,
        graph=graph,
        extra=extra,
    )
    try:
        soft_limit_mb = float(os.environ.get('JUA_STEP5_PROCESS_TREE_SOFT_RSS_MB') or 0.0)
        hard_limit_mb = float(os.environ.get('JUA_STEP5_PROCESS_TREE_HARD_RSS_MB') or 0.0)
    except ValueError as exc:
        raise ValueError(
            'JUA_STEP5_PROCESS_TREE_SOFT_RSS_MB and '
            'JUA_STEP5_PROCESS_TREE_HARD_RSS_MB must be numeric'
        ) from exc
    budget = evaluate_process_tree_budget(
        sample,
        soft_limit_mb=soft_limit_mb,
        hard_limit_mb=hard_limit_mb,
    )
    budget_metrics = graph_stats.setdefault('step5_perf', {}).setdefault(
        'resource_budget', {}
    )
    budget_metrics.update({
        'status': budget['status'],
        'reason_code': budget['reason_code'],
        'observed_peak_rss_mb': budget['peak_rss_mb'],
        'limit_mb': budget['limit_mb'],
        'checked_phase': phase,
    })
    emit_progress(
        "step5",
        "memory",
        (
            f"{phase}: current_rss={sample['current_rss_mb']:.1f}MB, "
            f"peak_rss={sample['peak_rss_mb']:.1f}MB, "
            f"methods={sample['method_count']}, "
            f"reverse_edges={sample['reverse_edge_count']}"
        ),
    )
    if budget['status'] == 'warning':
        os.environ['JUA_STEP5_BYTECODE_JAVAP_WORKERS'] = '1'
        body_cache_evictions = 0
        for method_def in getattr(graph, 'methods_by_id', {}).values() if graph is not None else ():
            if getattr(method_def, '_body_text_cached', ''):
                method_def._body_text_cached = ''
                body_cache_evictions += 1
        budget_metrics.update({
            'adaptive_javap_workers': 1,
            'body_cache_evictions': int(
                budget_metrics.get('body_cache_evictions') or 0
            ) + body_cache_evictions,
        })
        emit_progress(
            'step5',
            'resource-budget',
            (
                f"{budget['reason_code']}: peak={budget['peak_rss_mb']:.1f}MB, "
                f"soft_limit={budget['limit_mb']:.1f}MB"
            ),
        )
    if budget['status'] == 'blocked':
        raise Step5ResourceBudgetExceeded(
            f"{budget['reason_code']}: peak={budget['peak_rss_mb']:.1f}MB, "
            f"hard_limit={budget['limit_mb']:.1f}MB, phase={phase}"
        )
    return sample


# ══════════════════════════════════════════════════════════════════
# Step 5集成版：完整流程
# ══════════════════════════════════════════════════════════════════

def load_orchestrated_step5_input(report_dir):
    """正式流程下仅从 main_state 读取 Step5 已确认输入，调试 CLI 不参与正式求值。"""
    if os.environ.get("JUA_ORCHESTRATED") != "1":
        return {}
    state_path = _state_path(report_dir)
    if not state_path.exists():
        return {}
    try:
        with state_path.open("r", encoding="utf-8") as f:
            main_state = json.load(f)
    except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
        return {}
    return dict((((main_state or {}).get("step5") or {}).get("input")) or {})


def write_missing_dependency_mapping_details(
    output_dir,
    missing_mapping_items,
    missing_mapping_coords,
    has_provided_dependency_inputs,
    bridge_discovery=None,
):
    details_path = os.path.join(output_dir, "missing_dependency_source_mappings.json")
    details = {
        "status": "degraded",
        "reason_code": "step5_dependency_source_mapping_missing",
        "resolution": "continue_with_final_artifact_bytecode_and_restricted_conclusion",
        "generated_at": datetime.now().isoformat(),
        "missing_mapping_count": len(missing_mapping_items or []),
        "missing_mapping_coords": list(missing_mapping_coords or []),
        "has_provided_dependency_inputs": bool(has_provided_dependency_inputs),
        "missing_items": list(missing_mapping_items or []),
        "provided_dependency_source_dirs": list((bridge_discovery or {}).get("provided_dependency_source_dirs") or []),
        "source_dirs_detected_without_coord": list((bridge_discovery or {}).get("source_dirs_detected_without_coord") or []),
        "unresolved_dependency_source_dirs": list((bridge_discovery or {}).get("unresolved_dependency_source_dirs") or []),
        "discovery_log": list((bridge_discovery or {}).get("discovery_log") or []),
    }
    with open(details_path, "w", encoding="utf-8") as f:
        json.dump(details, f, ensure_ascii=False, indent=2)
    return details_path


def _iter_existing_source_dirs(source_dirs):
    for item in source_dirs or []:
        text = str(item or "").strip()
        if not text:
            continue
        path = Path(text).expanduser()
        if path.exists() and path.is_dir():
            yield path


def _dependency_mapping_source_dirs(dependency_source_mappings):
    dirs = []
    for item in dependency_source_mappings or []:
        if isinstance(item, dict):
            candidates = item.get("source_dirs") or item.get("paths") or []
            if isinstance(candidates, str):
                candidates = [candidates]
            dirs.extend(str(candidate or "").strip() for candidate in candidates)
            if item.get("path"):
                dirs.append(str(item.get("path") or "").strip())
            continue
        text = str(item or "").strip()
        if not text:
            continue
        if "=" in text:
            dirs.append(text.split("=", 1)[1].strip())
        else:
            dirs.append(text)
    return [item for item in dirs if item]


def has_java_source_file(source_dirs, max_dirs=200):
    checked = 0
    for source_dir in _iter_existing_source_dirs(source_dirs):
        checked += 1
        if checked > max_dirs:
            return True
        try:
            for _path in source_dir.rglob("*.java"):
                return True
        except OSError:
            continue
    return False


def write_tree_sitter_preflight_details(output_dir, status, source_dirs):
    details_path = os.path.join(output_dir, "tree_sitter_preflight.json")
    details = {
        "status": "blocked_by_system",
        "reason_code": "step5_tree_sitter_missing_need_resolution",
        "generated_at": datetime.now().isoformat(),
        "tree_sitter": dict(status or {}),
        "source_dirs_checked": [str(item) for item in (source_dirs or [])],
        "impact": [
            "Step5 无法使用 tree-sitter Java AST 主链路。",
            "tree-sitter 是 Java 源码调用链分析的必需工具；未安装时不会生成后续分析结论。",
        ],
        "manual_install": [
            (status or {}).get("install_command") or "python scripts/bootstrap_runtime.py",
        ],
    }
    with open(details_path, "w", encoding="utf-8") as f:
        json.dump(details, f, ensure_ascii=False, indent=2)
    return details_path


def step5_integrated_main(args):
    previous_debug = os.environ.get('JUA_STEP5_DEBUG')
    previous_break = os.environ.get('JUA_STEP5_DEBUG_BREAK')
    previous_javap_workers = os.environ.get('JUA_STEP5_BYTECODE_JAVAP_WORKERS')
    if getattr(args, 'debug_analysis', False):
        os.environ['JUA_STEP5_DEBUG'] = '1'
    if getattr(args, 'debug_break', False):
        os.environ['JUA_STEP5_DEBUG_BREAK'] = '1'
    process_observer = ProcessTreeObserver(
        temporary_paths=(Path(infer_step5_report_dir(args)) / '.runtime',),
    ).start()
    previous_memory_observer = set_active_process_tree_observer(process_observer)
    previous_command_observer = compat_module.set_process_observer(process_observer)
    try:
        return _step5_integrated_main_impl(args)
    finally:
        compat_module.set_process_observer(previous_command_observer)
        process_observer.stop()
        set_active_process_tree_observer(previous_memory_observer)
        if previous_debug is None:
            os.environ.pop('JUA_STEP5_DEBUG', None)
        else:
            os.environ['JUA_STEP5_DEBUG'] = previous_debug
        if previous_break is None:
            os.environ.pop('JUA_STEP5_DEBUG_BREAK', None)
        else:
            os.environ['JUA_STEP5_DEBUG_BREAK'] = previous_break
        if previous_javap_workers is None:
            os.environ.pop('JUA_STEP5_BYTECODE_JAVAP_WORKERS', None)
        else:
            os.environ['JUA_STEP5_BYTECODE_JAVAP_WORKERS'] = previous_javap_workers


def infer_step5_report_dir(args):
    explicit = str(getattr(args, 'report_dir', '') or '').strip()
    if explicit:
        return explicit

    all_changed_apis = str(getattr(args, 'all_changed_apis', '') or '').strip()
    if all_changed_apis:
        api_path = Path(all_changed_apis).expanduser()
        if api_path.name == 'all_changed_apis.csv' and api_path.parent.name == EVIDENCE_API_CHANGES_DIRNAME:
            return str(api_path.parent.parent.parent)

    output_dir = str(getattr(args, 'output_dir', '') or '').strip()
    if output_dir:
        output_path = Path(output_dir).expanduser()
        if output_path.name == EVIDENCE_CALL_CHAIN_DIRNAME:
            return str(output_path.parent.parent)

    return '.upgrade-report'


def _report_step5_debug_event(hypothesis_id, location, msg, data=None, run_id='pre-fix'):
    if not _step5_debug_enabled():
        return
    # #region debug-point A:bridge-check
    _step5_debug(
        f"debug_event:{hypothesis_id}",
        msg,
        location=location,
        run_id=run_id,
        **(data or {}),
    )
    # #endregion


def _requires_current_final_artifact_edges(bytecode_stats):
    return str((bytecode_stats or {}).get('evidence_source') or '') == 'current_final_artifact'


class _ReverseEdgeOverlay(Mapping):
    """Read-only reverse-edge view that allocates only for overlaid keys."""

    def __init__(self, base, overlay):
        self._base = base or {}
        self._overlay = overlay or {}

    def __getitem__(self, key):
        base_present = key in self._base
        overlay_present = key in self._overlay
        if not base_present and not overlay_present:
            raise KeyError(key)
        if not overlay_present:
            return self._base[key]
        if not base_present:
            return self._overlay[key]
        return tuple(self._base[key]) + tuple(self._overlay[key])

    def __iter__(self):
        yield from self._base
        for key in self._overlay:
            if key not in self._base:
                yield key

    def __len__(self):
        return len(self._base) + sum(key not in self._base for key in self._overlay)


def _graph_snapshot_with_bytecode_batch(graph, batch):
    """Provide indirect coverage a read-only view of pending bytecode reflection evidence."""
    snapshot = SimpleNamespace(**vars(graph))
    overlay = defaultdict(list)
    for edge in batch.edges:
        if not edge.edge_kind.startswith('bytecode_reflection_'):
            continue
        overlay[edge.callee_symbol].append(
            SimpleNamespace(evidence_type=edge.edge_kind)
        )
    snapshot.reverse_edges = _ReverseEdgeOverlay(
        getattr(graph, 'reverse_edges', {}) or {},
        {key: tuple(edges) for key, edges in overlay.items()},
    )
    return snapshot


def _build_business_bytecode_coverage(batch, ingestion_result, api_identities):
    bytecode_stats = dict(batch.metrics)
    business_failures = [
        failure
        for collector, failure in ingestion_result.failures_by_collector
        if collector == 'business_bytecode'
    ]
    blocking_failures = [failure for failure in business_failures if failure.blocking]
    scan_applicable = bool(
        bytecode_stats.get('classes_scanned')
        and bytecode_stats.get('evidence_source') == 'current_final_artifact'
    )
    applicable = bool(blocking_failures) or scan_applicable
    def failures_for_api(api_identity):
        parts = str(api_identity or '').split('|')
        api_name = parts[1].strip() if len(parts) > 1 else str(api_identity or '').strip()
        signature = parts[2].strip() if len(parts) > 2 else ''
        normalized_api_name = api_name.replace('$', '.')
        normalized_signature = normalize_signature_for_identity(signature.replace('$', '.'))
        relevant = []
        for failure in blocking_failures:
            failure_identity = str(failure.api_identity or '').strip()
            normalized_failure = failure_identity.replace('$', '.')
            if (
                not failure_identity
                or failure_identity == str(api_identity)
                or normalized_failure == normalized_api_name
            ):
                relevant.append(failure)
                continue
            if not normalized_failure.startswith(f'{normalized_api_name}('):
                continue
            failure_signature = normalized_failure[len(normalized_api_name):]
            if signatures_match_identity(failure_signature, normalized_signature):
                relevant.append(failure)
        return relevant

    coverage = []
    for api_identity in api_identities:
        relevant_failures = failures_for_api(api_identity)
        if relevant_failures:
            api_status = 'partial' if bytecode_stats.get('classes_scanned') else 'insufficient'
        else:
            api_status = 'complete' if scan_applicable else 'not_applicable'
        coverage.append(CoverageRecord(
            collector='business_bytecode',
            api_identity=api_identity,
            status=api_status,
            reason_codes=tuple(sorted({failure.reason_code for failure in relevant_failures})),
            applicable=applicable,
        ))
    coverage = tuple(coverage)
    statuses = {item.status for item in coverage}
    status = (
        'insufficient' if 'insufficient' in statuses
        else 'partial' if 'partial' in statuses
        else 'complete' if 'complete' in statuses
        else 'not_applicable'
    )
    reason_codes = sorted({
        reason_code for item in coverage for reason_code in item.reason_codes
    })
    return coverage, status, reason_codes


def _step5_integrated_main_impl(args):
    """
    Step 5集成版主流程

    改进点：
      1. 自动发现依赖源码映射（无需手动配置）
      2. 使用当前主分析器构建图（Java AST 优先）
      3. 置信度加权追踪
      4. 增强型输出格式
      5. 【修复】真正使用Step2解析出的业务源码目录（优先args.source_dirs，再用context恢复）
    """
    print("\nStep 5 开始（集成版）", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    step_timer = PhaseTimer("step5", "total")
    emit_progress("step5", "plan", "开始调用链影响分析")

    # Phase 0: 参数准备
    report_dir = infer_step5_report_dir(args)
    output_dir = args.output_dir or str(_call_chain_dir(report_dir))
    os.makedirs(output_dir, exist_ok=True)
    legacy_timing_path = Path(output_dir) / 'step5_timing.csv'
    if legacy_timing_path.exists():
        legacy_timing_path.unlink()
    timing = Step5TimingRecorder(report_dir)
    total_timing_token = timing.start_phase(
        'step5.total',
        message='正在执行 Step5 调用链影响分析',
    )
    input_timing_token = timing.start_phase(
        'input.resolve',
        item=str(report_dir),
        message='正在解析 Step5 输入、源码目录和运行参数',
    )
    orchestrated_input = load_orchestrated_step5_input(report_dir)

    # Phase 1: 先确定 all_changed_apis_path（避免未定义变量错误）
    all_changed_apis_path = args.all_changed_apis
    if not all_changed_apis_path:
        all_changed_apis_path = str(_all_changed_apis_path(report_dir))

    # Phase 2: 正式流程优先使用 main_state 中已确认的 Step5 输入；调试模式才使用 CLI
    context_path = str(_context_path(report_dir))
    context_source_dirs = []

    context_source_dirs = load_context_source_dirs(context_path)

    # 业务源码目录来源优先级：
    # 1. 正式流程：main_state.step5.input.source_dirs
    # 2. 调试模式：命令行 args.source_dirs
    # 3. 当前报告 evidence/context/context.json
    business_source_dirs = (
        orchestrated_input.get("source_dirs")
        if orchestrated_input.get("source_dirs")
        else (args.source_dirs if args.source_dirs else context_source_dirs)
    )

    if not business_source_dirs:
        timing.finish_phase(
            input_timing_token,
            status='failed',
            message='Step5 输入解析失败：缺少业务源码目录',
        )
        timing.finish_phase(
            total_timing_token,
            status='failed',
            message='Step5 因缺少业务源码目录停止',
        )
        print("❌ 至少需要提供一个业务源码目录", file=sys.stderr)
        print("  请通过以下方式指定：", file=sys.stderr)
        print("  1. 命令行 --source-dirs", file=sys.stderr)
        print("  2. 主状态中已确认并由调度层展开到 args.source_dirs 的业务源码目录", file=sys.stderr)
        print("  3. evidence/context/context.json 中的 source_dirs", file=sys.stderr)
        return 1

    if orchestrated_input.get("source_dirs"):
        print(f"  【正式流程】从 main_state 读取源码目录：{business_source_dirs}", file=sys.stderr)
    elif args.source_dirs:
        print(f"  使用命令行指定源码目录：{args.source_dirs}", file=sys.stderr)
    elif context_source_dirs:
        print(f"  从 evidence/context/context.json 读取源码目录：{context_source_dirs}", file=sys.stderr)
    timing.finish_phase(
        input_timing_token,
        message=f'输入解析完成，业务源码目录 {len(business_source_dirs)} 个',
    )
    _step5_debug(
        'step5_inputs',
        'resolved step5 input sources',
        report_dir=os.path.abspath(report_dir),
        output_dir=os.path.abspath(output_dir),
        all_changed_apis_path=os.path.abspath(all_changed_apis_path),
        business_source_dirs=list(business_source_dirs or []),
        input_source='main_state' if orchestrated_input.get("source_dirs") else ('cli' if args.source_dirs else 'context'),
        orchestrated=bool(orchestrated_input),
    )

    # Phase 2.5: 自动发现依赖源码映射
    dependency_source_mappings = (
        orchestrated_input.get("dependency_source_mappings")
        if "dependency_source_mappings" in orchestrated_input
        else (args.dependency_source_mappings or [])
    )
    raw_dependency_source_mappings = list(dependency_source_mappings or [])
    allow_degraded = (
        bool(orchestrated_input.get("allow_degraded"))
        if "allow_degraded" in orchestrated_input
        else bool(args.allow_degraded)
    )
    bridge_discovery = None

    if not dependency_source_mappings:
        print("\n自动发现依赖源码映射...", file=sys.stderr)
        discovery_timer = time.perf_counter()
        discovery_timing_token = timing.start_phase(
            'input.dependency_source_discovery',
            item=str(report_dir),
            message='正在自动发现依赖源码与依赖坐标的映射',
        )
        emit_progress("step5", "discovery", "开始自动发现依赖源码映射")
        bridge_discovery = auto_discover_bridge_sources(report_dir)

        if bridge_discovery['dependency_source_mappings']:
            dependency_source_mappings = bridge_discovery['dependency_source_mappings']
            raw_dependency_source_mappings = list(dependency_source_mappings or [])
            print(f"  发现：{len(bridge_discovery['matched_coords'])} 个可用依赖源码映射", file=sys.stderr)
        else:
            provided_dependency_dirs = bridge_discovery.get('provided_dependency_source_dirs') or []
            detected_unmapped_dirs = bridge_discovery.get('source_dirs_detected_without_coord') or []
            if provided_dependency_dirs or detected_unmapped_dirs:
                print("  ⚠️ 已提供依赖源码目录/仓库，但当前未能自动解析到可用依赖源码映射", file=sys.stderr)
                for line in (bridge_discovery.get('discovery_log') or [])[:3]:
                    print(f"    - {line}", file=sys.stderr)
            else:
                print("  ⚠️ 未找到可用的依赖源码映射", file=sys.stderr)
        emit_progress(
            "step5",
            "discovery",
            f"依赖源码映射发现完成，可用映射 {len(dependency_source_mappings)} 个",
            elapsed=time.perf_counter() - discovery_timer,
        )
        timing.finish_phase(
            discovery_timing_token,
            message=f'依赖源码映射发现完成，可用映射 {len(dependency_source_mappings)} 个',
        )
    _step5_debug(
        'dependency_mapping_resolution',
        'resolved dependency source mappings for step5',
        mapping_count=len(dependency_source_mappings or []),
        mappings=list(dependency_source_mappings or []),
        allow_degraded=allow_degraded,
        discovery_summary={
            'matched_coords': list((bridge_discovery or {}).get('matched_coords') or []),
            'provided_dependency_source_dirs': list((bridge_discovery or {}).get('provided_dependency_source_dirs') or []),
            'source_dirs_detected_without_coord': list((bridge_discovery or {}).get('source_dirs_detected_without_coord') or []),
            'unresolved_dependency_source_dirs': list((bridge_discovery or {}).get('unresolved_dependency_source_dirs') or []),
        },
    )

    # Phase 2.6: Java AST parser preflight.
    # tree-sitter 不是“可有可无”的小优化：它直接影响 Step5 源码图的准确性。
    # 因此正式流程中，若存在 Java 源码但依赖预检失败，必须停止；不允许 regex 降级。
    tree_sitter_source_dirs = list(business_source_dirs or []) + _dependency_mapping_source_dirs(dependency_source_mappings)
    parser_timing_token = timing.start_phase(
        'preflight.java_parser',
        item=f'{len(tree_sitter_source_dirs)} source roots',
        message='正在检查 Java 源码与 tree-sitter 解析器',
    )
    if has_java_source_file(tree_sitter_source_dirs):
        if not ensure_tree_sitter_available():
            status = tree_sitter_status()
            timing.finish_phase(
                parser_timing_token,
                status='failed',
                message='Java 解析器预检失败：tree-sitter 不可用',
            )
            timing.finish_phase(
                total_timing_token,
                status='failed',
                message='Step5 因 Java 解析器不可用停止',
            )
            print("\n❌ tree-sitter 不可用，无法执行 Java 源码调用链分析。", file=sys.stderr)
            if status.get("auto_install_error"):
                print(f"依赖预检失败原因：{status.get('auto_install_error')}", file=sys.stderr)
            print(f"请安装：{status.get('install_command')}", file=sys.stderr)
            details_path = write_tree_sitter_preflight_details(
                output_dir,
                status,
                tree_sitter_source_dirs,
            )
            print(f"诊断文件：{details_path}", file=sys.stderr)
            print(
                "已记录为系统环境阻塞；不会把内部解析器故障转成用户确认，"
                "也不会用低准确率解析路径继续。",
                file=sys.stderr,
            )
            return 1
    else:
        _step5_debug(
            'tree_sitter_preflight',
            'skip tree-sitter preflight because no Java source files were detected',
            checked_source_dirs=list(tree_sitter_source_dirs or []),
        )
    timing.finish_phase(
        parser_timing_token,
        message='Java 源码解析器预检完成',
    )

    # Phase 3: 先只用业务源码构建基础图，判断哪些API真的必须跨依赖边界
    business_roots = build_source_roots(business_source_dirs, [])
    if not business_roots:
        timing.finish_phase(
            total_timing_token,
            status='failed',
            message='Step5 因业务源码根为空停止',
        )
        print("❌ 至少需要提供一个业务源码目录", file=sys.stderr)
        return 1

    # Phase 4: 检查API文件是否存在
    if not os.path.exists(all_changed_apis_path):
        timing.finish_phase(
            total_timing_token,
            status='failed',
            message=f'Step5 变更 API 文件不存在：{all_changed_apis_path}',
        )
        print(f"❌ 变更API文件不存在：{all_changed_apis_path}", file=sys.stderr)
        return 1

    api_input_timing_token = timing.start_phase(
        'input.changed_apis',
        item=str(all_changed_apis_path),
        message='正在读取并规范化变更 API 清单',
    )
    all_apis = load_changed_apis(all_changed_apis_path, args.jdk_scan_dir)

    if not all_apis:
        timing.finish_phase(
            api_input_timing_token,
            status='skipped',
            message='变更 API 清单为空',
        )
        timing.finish_phase(
            total_timing_token,
            status='skipped',
            message='Step5 因变更 API 清单为空跳过',
        )
        print("⚠️ Step 5跳过：all_changed_apis.csv为空", file=sys.stderr)
        write_skip_summary(output_dir, all_changed_apis_path)
        return 0
    timing.finish_phase(
        api_input_timing_token,
        message=f'变更 API 加载完成，共 {len(all_apis)} 个',
    )

    print(f"\n加载变更API：{len(all_apis)} 个", file=sys.stderr)
    emit_progress("step5", "input", f"已加载 {len(all_apis)} 个变更 API")
    _step5_debug(
        'step5_api_scope',
        'loaded api scope for tracing',
        total_apis=len(all_apis),
        sample_apis=[
            {
                'api_name': item.get('api_name', ''),
                'api_signature': item.get('api_signature', ''),
                'coord': item.get('coord', ''),
            }
            for item in all_apis[:5]
        ],
    )

    _report_step5_debug_event(
        'CATALOG',
        's5_call_chain_engine_integrated.py:runtime-catalog',
        'starting runtime dependency catalog build',
        data={
            'report_dir': report_dir,
            'all_api_count': len(all_apis),
        },
    )
    catalog_timing_token = timing.start_phase(
        'input.runtime_artifact_catalog',
        item=str(report_dir),
        message='正在读取 Step1 留存制品并构建当前运行时依赖目录',
    )
    runtime_dependency_catalog = build_runtime_dependency_catalog(
        report_dir,
        business_source_dirs=business_source_dirs,
    )
    catalog_blockers = runtime_dependency_catalog_blockers(
        runtime_dependency_catalog
    )
    if catalog_blockers:
        timing.finish_phase(
            catalog_timing_token,
            status='failed',
            message=f'运行时依赖目录构建失败，阻塞项 {len(catalog_blockers)} 个',
        )
        timing.finish_phase(
            total_timing_token,
            status='failed',
            message='Step5 因运行时制品证据不完整停止',
        )
        details_path = write_runtime_catalog_preflight_failure(
            output_dir,
            runtime_dependency_catalog,
            catalog_blockers,
        )
        print(
            "\n❌ Step5 前置检查失败：Step1 留存的核心制品证据不完整或不可安全读取。",
            file=sys.stderr,
        )
        for item in catalog_blockers[:5]:
            target = (
                item.get('coord')
                or item.get('artifact_entry')
                or '<runtime-catalog>'
            )
            print(
                f"  - {target}: {item.get('reason') or 'invalid'}",
                file=sys.stderr,
            )
        print(f"诊断文件：{details_path}", file=sys.stderr)
        print(
            "必须从 Step1 修复制品证据后重跑；本次不会构建调用图、"
            "生成“未完成分析”结论或进入 Step6。",
            file=sys.stderr,
        )
        return 2
    artifact_fact_store = Step5ArtifactFactStore.from_catalog(
        runtime_dependency_catalog
    )
    allowed_business_classes = runtime_business_class_index(runtime_dependency_catalog)
    dependency_source_mappings, skipped_dependency_source_mappings = (
        filter_dependency_source_mappings_for_runtime(
            dependency_source_mappings,
            runtime_dependency_catalog,
        )
    )
    if skipped_dependency_source_mappings:
        print(
            f"  ⚠️ 已忽略 {len(skipped_dependency_source_mappings)} 个不属于当前运行时依赖的源码映射",
            file=sys.stderr,
        )
    dependency_source_alignment = align_dependency_source_mappings(
        report_dir,
        dependency_source_mappings,
        runtime_dependency_catalog,
    )
    dependency_source_mappings = list(dependency_source_alignment.get('mappings') or [])
    allowed_dependency_classes_by_coord = {
        str(coord): set(classes or set())
        for coord, classes in (
            dependency_source_alignment.get('allowed_classes_by_coord') or {}
        ).items()
    }
    rejected_source_records = [
        item for item in (dependency_source_alignment.get('records') or [])
        if item.get('status') != 'aligned'
    ]
    if rejected_source_records:
        bridge_discovery = dict(bridge_discovery or {})
        unresolved = list(bridge_discovery.get('unresolved_dependency_source_dirs') or [])
        for item in rejected_source_records:
            unresolved.append({
                'root_path': item.get('original_mapping_path') or '',
                'coord': item.get('coord') or '',
                'reason': item.get('reason') or '依赖源码版本无法与当前运行时 JAR 对齐',
                'reason_code': item.get('reason_code') or 'dependency_source_alignment_failed',
            })
        bridge_discovery['unresolved_dependency_source_dirs'] = unresolved
        print(
            f"  ⚠️ 已拒绝 {len(rejected_source_records)} 个未与当前运行时 JAR 版本对齐的依赖源码映射",
            file=sys.stderr,
        )
    if dependency_source_mappings:
        print(
            f"  已将 {len(dependency_source_mappings)} 个依赖源码根固定到 Step4 确认的当前版本 commit",
            file=sys.stderr,
        )
    timing.finish_phase(
        catalog_timing_token,
        message=(
            '运行时依赖目录与源码映射对齐完成，'
            f'依赖 {len((runtime_dependency_catalog or {}).get("by_coord") or {})} 个'
        ),
    )
    _report_step5_debug_event(
        'CATALOG',
        's5_call_chain_engine_integrated.py:runtime-catalog',
        'finished runtime dependency catalog build',
        data={
            'report_dir': report_dir,
            'runtime_coord_count': len((runtime_dependency_catalog or {}).get('by_coord') or {}),
            'sample_runtime_coords': sorted(list(((runtime_dependency_catalog or {}).get('by_coord') or {}).keys()))[:8],
            'dependency_source_mapping_count_after_runtime_filter': len(dependency_source_mappings or []),
            'skipped_dependency_source_mappings': skipped_dependency_source_mappings[:20],
            'dependency_source_alignment_evidence': dependency_source_alignment.get('evidence_path') or '',
            'dependency_source_alignment_rejected': len(rejected_source_records),
        },
    )

    print("\n构建业务源码基础图（跨依赖判定预分析）...", file=sys.stderr)
    business_graph_timer = time.perf_counter()
    business_graph_timing_token = timing.start_phase(
        'graph.business_source',
        item=f'{len(business_roots)} source roots',
        message='正在解析业务源码并构建基础调用图',
    )
    emit_progress("step5", "graph", "开始构建业务源码基础图")
    business_jar_metadata = build_jar_metadata_for_source_roots(
        business_roots,
        report_dir,
        runtime_dependency_catalog=runtime_dependency_catalog,
    )
    business_graph_result = build_enhanced_source_graph(
        business_roots,
        max_methods=getattr(args, 'max_methods', None),
        jar_metadata=business_jar_metadata,
        retain_analysis_cache=bool(dependency_source_mappings),
        allowed_business_classes=allowed_business_classes,
    )
    business_graph_elapsed = time.perf_counter() - business_graph_timer
    business_graph_memory = _observe_step5_memory(
        business_graph_result['stats'],
        'business_graph_ready',
        graph=business_graph_result['graph'],
    )
    timing.finish_phase(
        business_graph_timing_token,
        message=(
            '业务源码基础图构建完成，'
            f'方法 {len(business_graph_result["graph"].methods_by_id)} 个'
        ),
    )
    emit_progress(
        "step5",
        "graph",
        "业务源码基础图构建完成",
        elapsed=business_graph_elapsed,
    )

    bridge_check_timer = time.perf_counter()
    bridge_timing_token = timing.start_phase(
        'graph.bridge_requirements',
        item=f'{len(all_apis)} APIs',
        message='正在判断每个变更 API 是否需要跨依赖继续追踪',
    )
    emit_progress("step5", "bridge-check", "开始判断哪些 API 需要跨依赖继续分析")
    api_bridge_requirements = check_apis_that_need_bridge(
        all_apis,
        report_dir,
        business_source_dirs,
        business_graph_result['graph'],
        dependency_source_mappings,
        business_graph_result['stats'],
        runtime_dependency_catalog=runtime_dependency_catalog,
    )
    emit_progress(
        "step5",
        "bridge-check",
        "跨依赖分析判定完成",
        elapsed=time.perf_counter() - bridge_check_timer,
    )
    timing.finish_phase(
        bridge_timing_token,
        message='变更 API 跨依赖追踪需求判定完成',
    )
    needs_count = sum(1 for v in api_bridge_requirements.values() if v.get('needs_bridge'))
    missing_mapping_items = [
        item for item in api_bridge_requirements.values()
        if (
            item.get('needs_bridge')
            and not item.get('has_dependency_source_mapping')
            and not item.get('has_packaged_bytecode_fallback')
        )
    ]
    missing_mapping_count = len(missing_mapping_items)
    missing_mapping_coords = sorted(
        {
            str(item.get('coord') or '').strip()
            for item in missing_mapping_items
            if str(item.get('coord') or '').strip()
        }
    )
    if needs_count:
        print(f"  需要跨依赖继续分析的 API：{needs_count} 个", file=sys.stderr)
    else:
        print("  当前变更 API 均可直接在业务源码图中分析，无需额外依赖源码映射", file=sys.stderr)
    if missing_mapping_count:
        print(
            f"  缺少依赖源码映射的 API：{missing_mapping_count} 个"
            f"（涉及依赖 {len(missing_mapping_coords)} 个）",
            file=sys.stderr,
        )
    _step5_debug(
        'bridge_check_summary',
        'evaluated which apis need cross-dependency tracing',
        total_apis=len(all_apis),
        needs_bridge_count=needs_count,
        missing_mapping_count=missing_mapping_count,
        missing_mapping_coords=missing_mapping_coords,
        sample_bridge_requirements=[
            {
                'api': key,
                'needs_bridge': bool(info.get('needs_bridge')),
                'has_dependency_source_mapping': bool(info.get('has_dependency_source_mapping', True)),
                'has_packaged_bytecode_fallback': bool(info.get('has_packaged_bytecode_fallback')),
                'reason': info.get('reason', ''),
            }
            for key, info in list((api_bridge_requirements or {}).items())[:5]
        ],
    )

    has_provided_dependency_inputs = bool(
        dependency_source_mappings
        or raw_dependency_source_mappings
        or (bridge_discovery or {}).get('provided_dependency_source_dirs')
        or (bridge_discovery or {}).get('source_dirs_detected_without_coord')
    )

    if missing_mapping_count and not allow_degraded:
        _step5_debug(
            'bridge_check_auto_degraded',
            'step5 automatically continues with restricted evidence because dependency source mappings are missing',
            missing_mapping_count=missing_mapping_count,
            missing_mapping_coords=missing_mapping_coords,
            has_provided_dependency_inputs=has_provided_dependency_inputs,
        )
        print(
            "\n⚠️ 依赖源码映射不完整；系统将自动使用最终制品字节码继续，"
            "无法补齐的 API 会进入“本次未完成分析”，不会要求用户批准降级。",
            file=sys.stderr,
        )
        if missing_mapping_coords:
            print(
                f"  缺失映射的依赖坐标：{', '.join(missing_mapping_coords[:10])}",
                file=sys.stderr,
            )
        details_path = write_missing_dependency_mapping_details(
            output_dir,
            missing_mapping_items,
            missing_mapping_coords,
            has_provided_dependency_inputs,
            bridge_discovery=bridge_discovery,
        )
        allow_degraded = True

    if missing_mapping_count and allow_degraded:
        _step5_debug(
            'bridge_check_degraded',
            'step5 continues in degraded mode for missing dependency mappings',
            missing_mapping_count=missing_mapping_count,
            missing_mapping_coords=missing_mapping_coords,
        )
        if has_provided_dependency_inputs:
            print("  ⚠️ 允许降级执行：已提供依赖源码目录/仓库，但目标依赖的源码映射仍不完整；相关 API 会进入“本次未完成分析”清单", file=sys.stderr)
        else:
            print("  ⚠️ 允许降级执行：需要依赖源码映射的 API 会进入“本次未完成分析”清单", file=sys.stderr)

    # Phase 5: 构建增强型源码图
    full_graph_timing_token = timing.start_phase(
        'graph.full_source',
        item=f'{len(dependency_source_mappings)} dependency mappings',
        message=(
            '正在构建业务与依赖源码完整调用图'
            if dependency_source_mappings
            else '正在准备复用业务源码调用图'
        ),
    )
    source_roots = build_source_roots(business_source_dirs, dependency_source_mappings)
    jar_metadata = build_jar_metadata_for_source_roots(
        source_roots,
        report_dir,
        runtime_dependency_catalog=runtime_dependency_catalog,
    )
    _step5_debug(
        'graph_roots',
        'prepared source roots and jar metadata',
        source_root_count=len(source_roots or []),
        source_roots=source_roots,
        jar_metadata_class_count=len((jar_metadata or {}).get('by_class') or {}),
        jar_metadata_jar_count=len((jar_metadata or {}).get('jar_paths') or {}),
    )
    if dependency_source_mappings:
        print("\n构建完整源码调用图（业务 + 依赖源码映射）...", file=sys.stderr)
        full_graph_timer = time.perf_counter()
        emit_progress(
            "step5",
            "graph",
            f"开始构建依赖源码图，映射数 {len(dependency_source_mappings)}",
        )
        dependency_only_roots = [
            root for root in source_roots
            if str(root.get('owner_type') or '').strip() == 'dependency'
        ]
        reused_analysis = business_graph_result.get('analysis_cache') or []
        # 依赖源码增量构图前释放业务预分析阶段的大对象，避免双图长时间并存。
        business_graph_result['graph'] = None
        business_graph_result['type_metadata'] = None
        business_graph_result['stats'] = None
        gc.collect()
        graph_result = build_enhanced_source_graph(
            dependency_only_roots,
            max_methods=getattr(args, 'max_methods', None),
            jar_metadata=jar_metadata,
            reused_analysis=reused_analysis,
            retain_analysis_cache=False,
            allowed_dependency_classes_by_coord=allowed_dependency_classes_by_coord,
            allowed_business_classes=allowed_business_classes,
        )
        full_graph_elapsed = time.perf_counter() - full_graph_timer
        business_graph_result = None
        reused_analysis = None
        emit_progress(
            "step5",
            "graph",
            f"依赖源码图构建完成，依赖源码根 {len(dependency_only_roots)} 个",
            elapsed=full_graph_elapsed,
        )
    else:
        full_graph_elapsed = 0.0
        print("\n复用业务源码图进行调用链分析...", file=sys.stderr)
        emit_progress("step5", "graph", "未提供依赖源码映射，复用业务源码图")
        graph_result = business_graph_result
    timing.finish_phase(
        full_graph_timing_token,
        status='completed' if dependency_source_mappings else 'reused',
        message=(
            f'完整源码图准备完成，源码根 {len(source_roots)} 个'
            if dependency_source_mappings
            else '无依赖源码映射，已复用业务源码基础图'
        ),
    )

    graph = graph_result['graph']
    graph.runtime_dependency_catalog = runtime_dependency_catalog
    graph.step5_artifact_fact_store = artifact_fact_store
    type_metadata = graph_result['type_metadata']
    graph_stats = graph_result['stats']
    graph_stats.setdefault('step5_perf', {})
    graph_stats['step5_perf'].setdefault('main', {})
    graph_stats['step5_perf'].setdefault('memory', {}).update({
        f'business_graph_ready_{key}': value
        for key, value in business_graph_memory.items()
    })
    graph_stats['step5_perf']['main'].update({
        'business_graph_elapsed_sec': round(business_graph_elapsed, 3),
        'dependency_graph_elapsed_sec': round(full_graph_elapsed, 3),
        'source_root_count': len(source_roots or []),
        'business_source_root_count': len(business_roots or []),
        'dependency_source_mapping_count': len(dependency_source_mappings or []),
        'dependency_source_alignment_rejected': len(rejected_source_records),
        'dependency_source_alignment_evidence': dependency_source_alignment.get('evidence_path') or '',
    })
    _observe_step5_memory(
        graph_stats,
        'source_graph_ready',
        graph=graph,
    )
    bytecode_timer = time.perf_counter()
    bytecode_timing_token = timing.start_phase(
        'graph.business_bytecode',
        item=f'{len(business_roots)} business roots',
        message='正在扫描当前业务制品字节码并补充真实调用边',
    )
    bytecode_batch = collect_business_bytecode_batch(
        business_roots,
        runtime_dependency_catalog,
        str(_runtime_cache_dir(report_dir) / STEP5_ARTIFACT_BYTECODE_INDEX_FILE),
        fact_store=artifact_fact_store,
    )
    bytecode_stats = dict(bytecode_batch.metrics)
    graph.require_current_final_artifact_business_edges = (
        _requires_current_final_artifact_edges(bytecode_stats)
    )
    graph_stats['step5_perf']['main']['business_bytecode_elapsed_sec'] = round(time.perf_counter() - bytecode_timer, 3)
    graph_stats['step5_perf']['main']['business_bytecode_classes_scanned'] = int(
        bytecode_stats.get('classes_scanned') or 0
    )
    graph_stats['step5_perf']['main']['business_bytecode_edges_found'] = int(
        bytecode_stats.get('edges_found') or 0
    )
    graph_stats['step5_perf']['main']['business_bytecode_classfile_fast_path_classes'] = int(
        bytecode_stats.get('classfile_fast_path_classes') or 0
    )
    graph_stats['step5_perf']['main']['business_bytecode_javap_fallback_classes'] = int(
        bytecode_stats.get('javap_fallback_classes') or 0
    )
    timing.finish_phase(
        bytecode_timing_token,
        message=(
            '业务字节码扫描完成，'
            f'类 {int(bytecode_stats.get("classes_scanned") or 0)} 个，'
            f'调用边 {int(bytecode_stats.get("edges_found") or 0)} 条'
        ),
    )
    _observe_step5_memory(
        graph_stats,
        'business_bytecode_collected',
        graph=graph,
        extra={'batch_edge_count': len(bytecode_batch.edges)},
    )
    graph_stats['artifact_bytecode'] = {
        'status': runtime_dependency_catalog.get('status', 'insufficient'),
        'reason_codes': list(runtime_dependency_catalog.get('reason_codes') or []),
        **(runtime_dependency_catalog.get('metrics') or {}),
    }
    source_alignment_timer = time.perf_counter()
    alignment_timing_token = timing.start_phase(
        'evidence.source_artifact_alignment',
        item=f'{len(business_source_dirs)} business roots',
        message='正在核对业务源码与当前最终制品的一致性',
    )
    source_alignment = assess_source_artifact_alignment(report_dir, business_source_dirs)
    graph.source_artifact_alignment = source_alignment
    graph_stats['source_artifact_alignment'] = source_alignment
    graph_stats['step5_perf']['main']['source_artifact_alignment_elapsed_sec'] = round(
        time.perf_counter() - source_alignment_timer, 3
    )
    timing.finish_phase(
        alignment_timing_token,
        message='业务源码与最终制品一致性核对完成',
    )
    framework_output = str(_call_chain_dir(report_dir) / 'framework_adapters.json')
    framework_timer = time.perf_counter()
    framework_timing_token = timing.start_phase(
        'evidence.framework_adapters',
        item=f'{len(source_roots)} source roots',
        message='正在分析 Spring、MyBatis 等框架隐式调用关系',
    )
    framework_batches = run_framework_adapters(
        source_roots,
        artifact_catalog=runtime_dependency_catalog,
        fact_store=artifact_fact_store,
    )
    serialize_framework_batches(framework_batches, framework_output)
    graph_stats['step5_perf']['main']['framework_adapters_elapsed_sec'] = round(
        time.perf_counter() - framework_timer, 3
    )
    timing.finish_phase(
        framework_timing_token,
        message=f'框架适配分析完成，证据批次 {len(framework_batches)} 个',
    )
    graph_stats['framework_adapters'] = {
        batch.collector: {
            'status': next(
                (coverage.status for coverage in batch.coverage
                 if coverage.collector == batch.collector),
                'partial',
            ),
            **{
                key: thaw_evidence_value(value) for key, value in batch.metrics
                if not str(key).startswith('_legacy_')
            },
            'error_count': len(batch.failures),
        }
        for batch in framework_batches
    }
    indirect_timer = time.perf_counter()
    indirect_timing_token = timing.start_phase(
        'evidence.indirect_usage',
        item=f'{len(all_apis)} APIs',
        message='正在分析反射、配置和间接引用等非直接调用',
    )
    indirect_batch = collect_indirect_usage_batch(
        _graph_snapshot_with_bytecode_batch(graph, bytecode_batch),
        all_apis,
        source_roots,
    )
    _observe_step5_memory(
        graph_stats,
        'indirect_usage_collected',
        graph=graph,
        extra={'batch_edge_count': len(indirect_batch.edges)},
    )
    timing.finish_phase(
        indirect_timing_token,
        message=f'间接引用分析完成，候选边 {len(indirect_batch.edges)} 条',
    )
    framework_merge_timer = time.perf_counter()
    merge_timing_token = timing.start_phase(
        'evidence.merge',
        message='正在把字节码、框架和间接引用证据合并到调用图',
    )
    ingestion_result = ingest_collector_batches(
        graph, (bytecode_batch, *framework_batches, indirect_batch)
    )
    graph_stats['step5_perf']['main']['framework_adapter_merge_elapsed_sec'] = round(
        time.perf_counter() - framework_merge_timer, 3
    )
    timing.finish_phase(
        merge_timing_token,
        message=(
            '调用证据合并完成，'
            f'新增边 {ingestion_result.merged_edges} 条，'
            f'拒绝边 {ingestion_result.rejected_edges} 条'
        ),
    )
    graph_stats['framework_adapter_merge'] = {
        key: getattr(ingestion_result, key)
        for key in (
            'matched_callback_edges',
            'unmatched_callback_edges',
            'framework_entry_methods',
            'runtime_framework_entry_methods',
            'runtime_framework_entry_classes',
            'framework_activation_linked_methods',
            'framework_proxy_dispatch_edges',
            'framework_mybatis_proxy_dispatch_edges',
            'framework_transaction_proxy_edges',
            'framework_activation_edges',
            'ambiguous_framework_proxy_dispatches',
        )
    }
    # Keep the typed failure ledger for tracing, but defer its output-shaped
    # duplicate until the collector batches have been released.  On shaded
    # artifacts this ledger can contain more than 100k physical occurrences;
    # eagerly holding both representations raises peak RSS without adding any
    # analysis fact.
    ingestion_failure_records = tuple(ingestion_result.failures_by_collector)
    graph_stats['evidence_ingestion'] = {
        'merged_edges': ingestion_result.merged_edges,
        'duplicate_edges': ingestion_result.duplicate_edges,
        'rejected_edges': ingestion_result.rejected_edges,
        'failure_count': len(ingestion_result.failures),
        'failure_occurrence_fields': list(EVIDENCE_FAILURE_OCCURRENCE_FIELDS),
        # Preserve insertion order in the final JSON while avoiding eager
        # materialization.  This placeholder is replaced before reporting.
        'failures': None,
        'reason_codes': sorted({
            failure.reason_code
            for _collector, failure in ingestion_failure_records
        }),
    }
    bytecode_merge = {
        'merged_edges': dict(ingestion_result.merged_by_collector).get('business_bytecode', 0),
        'skipped_unresolved_callers': dict(ingestion_result.rejected_by_collector).get(
            'business_bytecode', 0
        ),
    }
    business_coverage, business_coverage_status, business_reason_codes = (
        _build_business_bytecode_coverage(
            bytecode_batch,
            ingestion_result,
            tuple(indirect_api_key(api_row) for api_row in all_apis),
        )
    )
    graph.step5_collector_coverage = tuple(
        getattr(graph, 'step5_collector_coverage', ()) or ()
    ) + business_coverage
    graph_stats['business_bytecode'] = {
        **bytecode_stats,
        **bytecode_merge,
        'status': business_coverage_status,
        'failures': business_reason_codes,
        'reason_codes': business_reason_codes,
        'coverage_by_api': {
            item.api_identity: {
                'status': item.status,
                'reason_codes': list(item.reason_codes),
                'applicable': item.applicable,
            }
            for item in business_coverage
        },
    }
    graph_stats['indirect_usage'] = apply_indirect_usage_batch_compatibility(
        graph, indirect_batch
    )
    indirect_elapsed = time.perf_counter() - indirect_timer
    indirect_stats = graph_stats.get('indirect_usage') or {}
    graph_stats['step5_perf']['main'].update({
        'indirect_usage_elapsed_sec': round(indirect_elapsed, 3),
        'indirect_usage_target_count': int(indirect_stats.get('target_count') or 0),
        'indirect_usage_owner_count': int(indirect_stats.get('owner_count') or 0),
        'indirect_usage_source_methods_scanned': int(indirect_stats.get('source_methods_scanned') or 0),
        'indirect_usage_source_methods_with_indirect_markers': int(
            indirect_stats.get('source_methods_with_indirect_markers') or 0
        ),
        'indirect_usage_owner_presence_scans': int(indirect_stats.get('owner_presence_scans') or 0),
        'indirect_usage_potential_legacy_method_target_pairs': int(
            indirect_stats.get('potential_legacy_method_target_pairs') or 0
        ),
    })
    _observe_step5_memory(
        graph_stats,
        'evidence_merged',
        graph=graph,
        extra={
            'merged_edge_count': ingestion_result.merged_edges,
            'rejected_edge_count': ingestion_result.rejected_edges,
        },
    )
    # All collector evidence, coverage and metrics have been transferred to the
    # graph/stats. Releasing these local containers shortens their overlap with
    # tracing caches without removing any graph edge or evidence record.
    del bytecode_batch
    del framework_batches
    del indirect_batch
    del ingestion_result
    emit_progress(
        "step5",
        "perf",
        (
            "图增强耗时："
            f"source_alignment={graph_stats['step5_perf']['main']['source_artifact_alignment_elapsed_sec']}s，"
            f"framework={graph_stats['step5_perf']['main']['framework_adapters_elapsed_sec']}s，"
            f"framework_merge={graph_stats['step5_perf']['main']['framework_adapter_merge_elapsed_sec']}s，"
            f"indirect_usage={graph_stats['step5_perf']['main']['indirect_usage_elapsed_sec']}s，"
            f"potential_method_target_pairs={graph_stats['step5_perf']['main']['indirect_usage_potential_legacy_method_target_pairs']}，"
            f"owner_presence_scans={graph_stats['step5_perf']['main']['indirect_usage_owner_presence_scans']}"
        ),
    )
    graph.report_dir = str(report_dir)
    graph.persistent_artifact_cache_dir = str(
        Path(report_dir) / '.runtime' / 'artifact_fact_cache'
    )

    print(f"  方法数：{len(graph.methods_by_id)}", file=sys.stderr)
    print(f"  反向边数：{len(graph.reverse_edges)}", file=sys.stderr)
    parser_usage = graph_stats.get('parser_usage', {})
    print(
        f"  解析器使用：tree_sitter={parser_usage.get('tree_sitter', 0)}, "
        f"regex={parser_usage.get('regex', 0)}",
        file=sys.stderr,
    )
    if graph_stats.get('parser_fallback_reasons'):
        print(
            f"  解析器降级：{graph_stats.get('parser_fallback_reasons')}",
            file=sys.stderr,
        )

    if graph_stats.get('truncated'):
        print(f"  ⚠️ 图构建截断：{','.join(graph_stats.get('truncation_reasons', []))}", file=sys.stderr)
    _step5_debug(
        'graph_summary',
        'graph build completed',
        methods_indexed=len(graph.methods_by_id),
        reverse_edge_keys=len(graph.reverse_edges),
        graph_stats=graph_stats,
        type_metadata_count=len(type_metadata or {}),
    )
    # Phase 5: 置信度加权反向追踪（核心改进）
    print("\n反向追踪调用链（置信度加权）...", file=sys.stderr)
    emit_progress("step5", "trace", f"开始反向追踪，共 {len(all_apis)} 个 API")

    # Key clarification: max_depth semantics
    # SKILL.md defines:
    #   - High confidence edge: depth_cost=1 (全精确 High 路径可按图规模自适应加深)
    #   - Medium confidence edge: depth_cost=2 (max_depth=5 allows 2-3 hops)
    #   - Low confidence edge: depth_cost=5 (stops immediately)
    # max_depth controls "max cumulative cost", not "max hop count"
    # User passing 5 means "paths with cost<=5", actual hops depend on each hop's confidence
    max_depth = orchestrated_input.get("max_depth") if "max_depth" in orchestrated_input else (
        args.max_depth if hasattr(args, 'max_depth') else 5
    )
    if max_depth in (None, ""):
        max_depth = 5
    # 关键修复：直接使用max_depth，让语义清晰
    # 用户传3就是最多3条边，不再转换
    trace_timing_token = timing.start_phase(
        'trace.changed_apis',
        item=f'{len(all_apis)} APIs',
        message=f'正在反向追踪 {len(all_apis)} 个变更 API 的业务调用链',
    )
    all_results = trace_all_apis_with_confidence_weighting(
        all_apis,
        graph,
        type_metadata,
        max_total_cost=max_depth,
        api_bridge_requirements=api_bridge_requirements,
        allow_degraded=allow_degraded,
        graph_stats=graph_stats,
    )
    _observe_step5_memory(
        graph_stats,
        'trace_complete',
        graph=graph,
        extra={'result_count': len(all_results)},
    )
    timing.finish_phase(
        trace_timing_token,
        message=f'变更 API 调用链追踪完成，结果 {len(all_results)} 条',
    )
    # Runtime bytecode closure can add methods and reverse edges while tracing.
    # Refresh the persisted query index so it describes the same graph as the report.
    query_index_refresh_timer = time.perf_counter()
    query_index_timing_token = timing.start_phase(
        'write.query_index',
        item=str(getattr(args, 'query_index', '') or _default_query_index_path(report_dir)),
        message='正在写入可查询的调用图索引',
    )
    query_index_path = write_query_index(
        graph,
        str(Path(getattr(args, 'query_index', '') or _default_query_index_path(report_dir))),
        graph_stats={
            'methods_indexed': len(graph.methods_by_id),
            'reverse_edge_keys': len(graph.reverse_edges),
        },
    )
    graph_stats['step5_perf']['main']['query_index_elapsed_sec'] = round(
        time.perf_counter() - query_index_refresh_timer,
        3,
    )
    timing.finish_phase(
        query_index_timing_token,
        message=f'调用图查询索引写入完成：{query_index_path}',
    )
    print(f"  调用链查询索引 → {query_index_path}", file=sys.stderr)
    _step5_debug(
        'trace_batch_summary',
        'completed tracing all apis',
        total_results=len(all_results),
        status_counts={
            'reachable': sum(1 for r in all_results if r.analysis_status == 'reachable'),
            'not_impacted': sum(1 for r in all_results if r.analysis_status == 'not_impacted'),
            'uncertain': sum(1 for r in all_results if r.analysis_status == 'uncertain'),
            'not_analyzed': sum(1 for r in all_results if r.analysis_status == 'not_analyzed'),
            'not_found_in_static_analysis': sum(
                1 for r in all_results if r.analysis_status in ('not_found_in_static_analysis', 'not_reachable')
            ),
        },
        sample_results=[
            {
                'api_name': r.api_name,
                'analysis_status': r.analysis_status,
                'reason_code': r.reason_code,
                'match_provenance': r.match_provenance,
            }
            for r in all_results[:5]
        ],
    )

    graph_stats['evidence_ingestion']['failures'] = [
        _serialize_ingestion_failure(collector, failure)
        for collector, failure in ingestion_failure_records
    ]
    # Tracing and the persisted query index have consumed the typed ledger.
    # TraceResult envelopes and graph_stats now own every externally visible
    # fact, so retaining the internal dataclasses would only duplicate memory
    # during JSON generation.
    graph.step5_evidence_failures = ()
    graph.step5_evidence_failures_by_collector = ()
    del ingestion_failure_records

    # Phase 6: 增强型输出（核心改进）
    print("\n生成分析报告...", file=sys.stderr)
    graph_stats['step5_perf']['artifact_facts'] = artifact_fact_store.metrics()
    # The query index, analyzer-edge ledger and TraceResult envelopes now own
    # every externally visible fact.  The mutable graph and runtime scan
    # indexes are analysis workspaces, not report inputs; retaining them while
    # formatting 185k API entries made the two largest object graphs overlap.
    graph_method_count = len(graph.methods_by_id)
    graph_reverse_edge_count = int(getattr(graph, 'reverse_edge_count', 0) or 0)
    graph = None
    graph_result = None
    business_graph_result = None
    runtime_dependency_catalog = None
    type_metadata = None
    api_bridge_requirements = None
    all_apis = None
    business_coverage = None
    artifact_fact_store = None
    jar_metadata = None
    gc.collect()
    _observe_step5_memory(
        graph_stats,
        'report_input_released',
        graph=None,
        extra={
            'result_count': len(all_results),
            'released_graph_methods': graph_method_count,
            'released_graph_reverse_edges': graph_reverse_edge_count,
        },
    )
    summary_timer = time.perf_counter()
    report_timing_token = timing.start_phase(
        'write.reports',
        item=str(output_dir),
        message='正在生成汇总报告、告警和逐 API 证据视图',
    )
    emit_progress("step5", "report", "开始生成汇总报告与证据视图")
    generate_enhanced_summary(all_results, output_dir, graph_stats=graph_stats)
    _observe_step5_memory(
        graph_stats,
        'report_ready',
        graph=None,
        extra={'result_count': len(all_results)},
    )
    emit_progress(
        "step5",
        "report",
        "汇总报告生成完成",
        elapsed=time.perf_counter() - summary_timer,
    )
    timing.finish_phase(
        report_timing_token,
        message='Step5 汇总报告与证据视图生成完成',
    )
    timing_csv = timing.write_metrics(graph_stats)
    if timing_csv:
        print(f"  耗时明细 → {timing_csv}", file=sys.stderr)
    register_step5_summary_artifacts(output_dir, report_dir=report_dir)

    # 统计
    reachable_count = sum(1 for r in all_results if r.analysis_status == 'reachable')
    not_impacted_count = sum(1 for r in all_results if r.analysis_status == 'not_impacted')
    uncertain_count = sum(1 for r in all_results if r.analysis_status == 'uncertain')
    not_analyzed_count = sum(1 for r in all_results if r.analysis_status == 'not_analyzed')
    not_found_count = sum(
        1 for r in all_results
        if r.analysis_status in ('not_found_in_static_analysis', 'not_reachable')
    )

    print("\n分析结果：", file=sys.stderr)
    print(f"  ✓ 已确认影响: {reachable_count}", file=sys.stderr)
    print(f"  ○ 已确认不受影响: {not_impacted_count}", file=sys.stderr)
    print(f"  ❓ 需人工复核: {uncertain_count}", file=sys.stderr)
    print(f"  ⊘ 本次未完成分析: {not_analyzed_count}", file=sys.stderr)
    print(f"  ✗ 未发现调用路径: {not_found_count}", file=sys.stderr)

    print("\nStep 5 完成", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    emit_progress(
        "step5",
        "done",
        (
            "Step5 完成，"
            f"reachable={reachable_count}，not_impacted={not_impacted_count}，uncertain={uncertain_count}，"
            f"not_analyzed={not_analyzed_count}，not_found={not_found_count}"
        ),
        elapsed=step_timer.elapsed(),
    )
    _step5_debug(
        'step5_done',
        'step5 completed',
        reachable=reachable_count,
        uncertain=uncertain_count,
        not_analyzed=not_analyzed_count,
        not_found=not_found_count,
        elapsed_seconds=step_timer.elapsed(),
    )
    timing.finish_phase(
        total_timing_token,
        message='Step5 调用链影响分析完成',
    )
    timing.write_metrics(graph_stats)

    return 0


# ══════════════════════════════════════════════════════════════════
# 辅助函数
# ══════════════════════════════════════════════════════════════════

def build_source_roots(source_dirs, dependency_source_mappings):
    """
    构建源码根配置（兼容原有格式）
    """
    roots = []

    # 业务源码
    for path in source_dirs:
        if os.path.isdir(path):
            roots.append({
                'root': os.path.abspath(path),
                'owner_type': 'business',
                'owner_coord': 'BUSINESS',
                'module': infer_module_name(path)
            })

    # 依赖源码映射
    for mapping in dependency_source_mappings or []:
        if '=' not in mapping:
            continue

        coord, path = mapping.split('=', 1)
        coord = coord.strip()
        path = path.strip()

        if os.path.isdir(path):
            roots.append({
                'root': os.path.abspath(path),
                'owner_type': 'dependency',
                'owner_coord': coord,
                'module': infer_module_name(path)
            })

    return roots


def _coord_ga(coord):
    parts = str(coord or '').strip().split(':')
    if len(parts) < 2:
        return ''
    return ':'.join(parts[:2])


def filter_dependency_source_mappings_for_runtime(dependency_source_mappings, runtime_dependency_catalog):
    """
    Keep dependency source mappings scoped to jars that are actually present in the
    current runtime dependency catalog.

    Dependency source is auxiliary evidence for jars used by the analyzed system;
    it must not expand the graph through arbitrary source repositories provided by
    the user. If the runtime catalog is unavailable, keep the old behavior rather
    than silently dropping possible evidence.
    """
    mappings = list(dependency_source_mappings or [])
    by_coord = (runtime_dependency_catalog or {}).get('by_coord') or {}
    runtime_coords = {
        str(coord or '').strip()
        for coord in by_coord.keys()
        if str(coord or '').strip() and str(coord or '').strip() != '__business__'
    }
    if not mappings or not runtime_coords:
        return mappings, []

    runtime_ga = {_coord_ga(coord) for coord in runtime_coords if _coord_ga(coord)}
    kept = []
    skipped = []
    seen_kept = set()
    for mapping in mappings:
        raw = str(mapping or '').strip()
        if '=' not in raw:
            skipped.append({
                'mapping': raw,
                'coord': '',
                'reason': 'invalid_mapping_format',
            })
            continue
        coord, path = raw.split('=', 1)
        coord = coord.strip()
        coord_key = _coord_ga(coord)
        if coord in runtime_coords or (coord_key and coord_key in runtime_ga):
            if raw not in seen_kept:
                kept.append(raw)
                seen_kept.add(raw)
            continue
        skipped.append({
            'mapping': raw,
            'coord': coord,
            'reason': 'dependency_source_not_in_current_runtime_catalog',
        })
    return kept, skipped


def infer_module_name(path):
    """推断模块名"""
    normalized = path.replace('\\', '/').rstrip('/')
    for marker in ('/src/main/', '/src/test/'):
        if marker in normalized:
            module_root = normalized.split(marker, 1)[0]
            return os.path.basename(module_root) or 'root'
    return os.path.basename(normalized) or 'root'


def _split_coord(coord):
    parts = str(coord or '').strip().split(':')
    if len(parts) < 2:
        return '', ''
    return parts[0].strip(), parts[1].strip()


def _recover_reactor_module_coords(
    business_source_dirs, packaged_coords, *, active_profiles=None,
):
    source_paths = [
        Path(value).resolve() for value in (business_source_dirs or [])
        if str(value or '').strip()
    ]
    artifact_coords = {
        str(value or '').strip()
        for value in (packaged_coords or ())
        if str(value or '').strip()
    }
    if not source_paths or not artifact_coords:
        return set()

    candidate_roots = set()
    for source_path in source_paths:
        start = source_path if source_path.is_dir() else source_path.parent
        candidate_roots.update(
            parent for parent in (start, *start.parents)
            if any((parent / name).is_file() for name in (
                'pom.xml', 'build.gradle', 'build.gradle.kts',
                'settings.gradle', 'settings.gradle.kts',
            ))
        )

    recovered_scopes = []
    for candidate in sorted(candidate_roots, key=lambda path: len(path.parts), reverse=True):
        discovery = discover_project_modules(
            candidate, active_profiles=active_profiles
        )
        reactor_coords = {
            str(item.get('coord') or '').strip()
            for item in discovery.get('modules') or []
            if str(item.get('coord') or '').strip()
        }
        for target_coord in sorted(artifact_coords & reactor_coords):
            scope = build_project_scope(
                candidate, target_coord, active_profiles=active_profiles
            )
            included = {
                str(item).strip()
                for item in scope.get('included_module_coords') or []
                if str(item).strip()
            }
            if included:
                recovered_scopes.append(included)
    return max(recovered_scopes, key=len, default=set())


def build_runtime_dependency_catalog(report_dir, business_source_dirs=None):
    current_resolved_path = str(_current_resolved_path(report_dir))
    catalog = {
        'by_coord': {},
        'entries': [],
        'jar_paths': {},
        'status': 'insufficient',
        'reason_codes': [],
        'metrics': {},
        'target_jdk': '',
    }
    application_module_coords = set()
    active_maven_profiles = set()
    state_path = _state_path(report_dir)
    if state_path.is_file():
        try:
            state_payload = json.loads(state_path.read_text(encoding='utf-8'))
            for step in ('step5', 'step4', 'step3', 'step2', 'step1'):
                section = state_payload.get(step) or {}
                state_view = section.get('input') or {}
                scope = state_view.get('project_scope') or {}
                if not scope:
                    continue
                application_module_coords = {
                    str(item).strip()
                    for item in scope.get('included_module_coords') or []
                    if str(item).strip()
                }
                active_maven_profiles = {
                    str(item).strip()
                    for item in (
                        state_view.get('active_maven_profiles')
                        or scope.get('active_maven_profiles')
                        or []
                    )
                    if str(item).strip()
                }
                break
        except (OSError, json.JSONDecodeError, AttributeError):
            catalog['reason_codes'].append('project_scope_unreadable')
    context_path = str(_context_path(report_dir))
    if os.path.exists(context_path):
        try:
            context = json.loads(Path(context_path).read_text(encoding='utf-8'))
            target_jdk = str(context.get('jdk_current') or '').strip()
            if target_jdk.lower() != 'unknown':
                catalog['target_jdk'] = target_jdk
        except (OSError, json.JSONDecodeError):
            catalog['reason_codes'].append('s2_context_unreadable')
    if not os.path.exists(current_resolved_path):
        return catalog

    with open_csv_read(current_resolved_path) as f:
        rows = list(csv.DictReader(f))

    manifest_path = _step1_dependency_jars_manifest_path(report_dir)
    manifest = {}
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        except (OSError, UnicodeError, json.JSONDecodeError):
            catalog['reason_codes'].append('step1_dependency_jars_manifest_unreadable')
    else:
        catalog['reason_codes'].append('step1_dependency_jars_manifest_missing')

    runtime_manifest_items = [
        item for item in (manifest.get('items') or ())
        if isinstance(item, dict)
        and str(item.get('side') or '').strip() == 'current'
        and 'step5_runtime' in set(item.get('purposes') or ())
    ]
    packaged_coords = {
        str(item.get('coord') or '').strip()
        for item in runtime_manifest_items
        if str(item.get('coord') or '').strip()
    }
    if not application_module_coords:
        application_module_coords.update(
            _recover_reactor_module_coords(
                business_source_dirs,
                packaged_coords,
                active_profiles=active_maven_profiles,
            )
        )

    exact_count = 0
    extraction_failures = []
    conflicted_coords = set()
    business_class_count = 0
    final_artifact_sha256 = ''
    row_by_entry = {
        str(row.get('lib_entry') or '').replace('\\', '/').strip(): row
        for row in rows
        if str(row.get('lib_entry') or '').strip()
    }
    for manifest_item in sorted(
        runtime_manifest_items,
        key=lambda item: str(item.get('lib_entry') or ''),
    ):
        lib_entry = str(manifest_item.get('lib_entry') or '').replace('\\', '/').strip()
        row = row_by_entry.get(lib_entry) or {}
        coord = str(row.get('coord') or manifest_item.get('coord') or '').strip()
        version = str(row.get('version') or manifest_item.get('version') or '').strip()
        scope = str(row.get('scope') or manifest_item.get('scope') or '').strip()
        jar_path = Path(str(manifest_item.get('retained_path') or ''))
        expected_sha = str(manifest_item.get('nested_jar_sha256') or '').lower()
        outer_sha = str(manifest_item.get('outer_artifact_sha256') or '').lower()
        if outer_sha:
            if final_artifact_sha256 and final_artifact_sha256 != outer_sha:
                extraction_failures.append({
                    'coord': coord, 'lib_entry': lib_entry,
                    'reason': 'step1_outer_artifact_identity_conflict',
                })
                continue
            final_artifact_sha256 = outer_sha
        if not coord or not version:
            extraction_failures.append({
                'coord': coord, 'lib_entry': lib_entry,
                'reason': 'step1_runtime_identity_missing',
            })
            continue
        if coord in conflicted_coords:
            continue
        if not jar_path.is_file() or not re.fullmatch(r'[0-9a-f]{64}', expected_sha):
            extraction_failures.append({
                'coord': coord, 'lib_entry': lib_entry,
                'reason': 'step1_retained_dependency_jar_missing',
            })
            continue
        try:
            if sha256_file(jar_path) != expected_sha:
                raise ValueError('sha256_mismatch')
            require_safe_archive(
                jar_path,
                inspect_nested_archives=False,
                allow_duplicate_maven_metadata=True,
            )
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            extraction_failures.append({
                'coord': coord, 'lib_entry': lib_entry,
                'reason': f'step1_retained_dependency_jar_invalid:{exc}',
            })
            continue
        application_owned = coord in application_module_coords
        item = {
            'coord': coord,
            'version': version,
            'scope': scope,
            'jar_path': str(jar_path),
            'artifact_entry': lib_entry,
            'artifact_entries': [lib_entry],
            'sha256': expected_sha,
            'evidence_source': 'current_final_artifact',
            'evidence_origin': 'step1_retained_dependency_jar',
            'application_owned': application_owned,
        }
        if application_owned:
            item['ownership_evidence'] = {
                'authority': 'reactor_coordinate_and_final_artifact_entry',
                'reactor_coord': coord,
                'artifact_entry': lib_entry,
                'final_artifact_sha256': final_artifact_sha256,
            }
        previous = catalog['by_coord'].get(coord)
        if previous:
            if str(previous.get('sha256') or '') == expected_sha:
                previous['artifact_entries'] = sorted(set(
                    previous.get('artifact_entries') or ()
                ) | {lib_entry})
                continue
            extraction_failures.append({
                'coord': coord, 'lib_entry': lib_entry,
                'reason': 'runtime_coordinate_identity_conflict',
            })
            catalog['by_coord'].pop(coord, None)
            catalog['jar_paths'].pop(coord, None)
            catalog['entries'] = [
                value for value in catalog['entries']
                if str(value.get('coord') or '') != coord
            ]
            conflicted_coords.add(coord)
            continue
        catalog['by_coord'][coord] = item
        catalog['entries'].append(item)
        catalog['jar_paths'][coord] = str(jar_path)
        exact_count += 1

    for business_item in manifest.get('business_artifacts') or ():
        if (
            not isinstance(business_item, dict)
            or str(business_item.get('side') or '').strip() != 'current'
        ):
            continue
        business_jar = Path(str(business_item.get('retained_path') or ''))
        business_sha = str(business_item.get('sha256') or '').lower()
        outer_sha = str(business_item.get('outer_artifact_sha256') or '').lower()
        try:
            if not business_jar.is_file() or not re.fullmatch(
                r'[0-9a-f]{64}', business_sha
            ):
                raise ValueError('business_artifact_missing')
            if sha256_file(business_jar) != business_sha:
                raise ValueError('business_artifact_sha256_mismatch')
            require_safe_archive(
                business_jar,
                inspect_nested_archives=False,
                allow_duplicate_maven_metadata=True,
            )
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            extraction_failures.append({
                'coord': '__business__', 'lib_entry': '<business-classes>',
                'reason': f'step1_business_artifact_invalid:{exc}',
            })
            break
        if outer_sha:
            if final_artifact_sha256 and final_artifact_sha256 != outer_sha:
                extraction_failures.append({
                    'coord': '__business__', 'lib_entry': '<business-classes>',
                    'reason': 'step1_outer_artifact_identity_conflict',
                })
                break
            final_artifact_sha256 = outer_sha
        business_class_count = int(business_item.get('class_count') or 0)
        catalog['by_coord']['__business__'] = {
            'coord': '__business__',
            'version': '',
            'scope': 'business',
            'jar_path': str(business_jar),
            'artifact_entry': '<business-classes>',
            'sha256': business_sha,
            'evidence_source': 'current_final_artifact',
            'evidence_origin': 'step1_retained_business_content',
            'application_owned': True,
        }
        catalog['entries'].append(catalog['by_coord']['__business__'])
        catalog['jar_paths']['__business__'] = str(business_jar)
        break

    if final_artifact_sha256:
        catalog['final_artifact_sha256'] = final_artifact_sha256
    catalog['artifact_safety'] = {
        'safe': not extraction_failures,
        'source': 'step1_retained_artifacts',
        'inspected_archives': exact_count + int('__business__' in catalog['by_coord']),
        'nested_archives_inspected': 0,
    }

    expected_coords = {
        str(row.get('coord') or '').strip() for row in rows
        if str(row.get('coord') or '').strip()
        and str(row.get('resolution_status') or 'resolved').strip() == 'resolved'
        and str(row.get('scope') or '').strip() not in {'test', 'provided', 'optional'}
    }
    missing_coords = sorted(expected_coords - set(catalog['by_coord']))
    if missing_coords:
        catalog['reason_codes'].append('runtime_dependency_jars_missing')
    if extraction_failures:
        catalog['reason_codes'].append('step1_retained_artifact_invalid')
    catalog['status'] = (
        'complete' if manifest and not extraction_failures and not missing_coords
        else ('partial' if catalog['by_coord'] else 'insufficient')
    )
    catalog['metrics'] = {
        'expected_runtime_dependencies': len(expected_coords),
        'exact_artifact_dependencies': sum(
            1 for item in catalog['entries']
            if str(item.get('coord') or '') != '__business__'
        ),
        'missing_dependencies': len(missing_coords),
        'business_classes': business_class_count,
        'extraction_failures': len(extraction_failures),
        'application_owned_nested_dependencies': sum(
            1 for item in catalog['entries']
            if item.get('application_owned')
            and str(item.get('coord') or '') != '__business__'
        ),
    }
    catalog['extraction_failures'] = extraction_failures
    serializable = {key: value for key, value in catalog.items() if not key.startswith('_')}
    catalog_path = _runtime_cache_dir(report_dir) / STEP5_ARTIFACT_BYTECODE_CATALOG_FILE
    catalog_path.parent.mkdir(parents=True, exist_ok=True)
    catalog_path.write_text(
        json.dumps(serializable, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
    )
    return catalog


def runtime_dependency_catalog_blockers(runtime_dependency_catalog):
    """Return core artifact failures that must stop Step5 before graph analysis."""
    catalog = runtime_dependency_catalog or {}
    status = str(catalog.get('status') or 'insufficient').strip()
    if status == 'complete':
        return []
    blockers = []
    reason_codes = [
        str(value or '').strip()
        for value in catalog.get('reason_codes') or ()
        if str(value or '').strip()
    ]
    for item in catalog.get('extraction_failures') or ():
        if not isinstance(item, dict):
            continue
        blockers.append({
            'coord': str(item.get('coord') or '').strip(),
            'artifact_entry': str(item.get('lib_entry') or '').strip(),
            'reason': str(item.get('reason') or 'retained_artifact_invalid').strip(),
        })
    if not blockers:
        blockers.append({
            'coord': '',
            'artifact_entry': '',
            'reason': ','.join(reason_codes) or f'runtime_catalog_{status}',
        })
    return blockers


def write_runtime_catalog_preflight_failure(
    output_dir, runtime_dependency_catalog, blockers,
):
    path = Path(output_dir) / 'artifact_preflight_failure.json'
    path.write_text(
        json.dumps(
            {
                'schema': 'java-upgrade-analyzer.step5-artifact-preflight.v1',
                'status': 'blocked_by_system',
                'reason_code': 'STEP1_RETAINED_ARTIFACT_EVIDENCE_INVALID',
                'catalog_status': str(
                    (runtime_dependency_catalog or {}).get('status')
                    or 'insufficient'
                ),
                'catalog_reason_codes': list(
                    (runtime_dependency_catalog or {}).get('reason_codes') or ()
                ),
                'blockers': list(blockers or ()),
                'next_action': 'restart_from_step1',
            },
            ensure_ascii=False,
            indent=2,
        ) + '\n',
        encoding='utf-8',
    )
    return path


def runtime_business_class_index(runtime_dependency_catalog):
    """Return only classes packaged at the executable application's entry boundary."""
    business_item = ((runtime_dependency_catalog or {}).get('by_coord') or {}).get('__business__') or {}
    jar_path = str(business_item.get('jar_path') or '').strip()
    if not jar_path or not os.path.isfile(jar_path):
        return None
    classes = set()
    try:
        with zipfile.ZipFile(jar_path) as jar:
            classes.update(
                entry[:-6].replace('/', '.')
                for entry in jar.namelist()
                if entry.endswith('.class')
                and not entry.startswith('META-INF/')
                and not entry.endswith('module-info.class')
            )
    except (OSError, zipfile.BadZipFile):
        return None
    return classes


def assess_source_artifact_alignment(report_dir, business_source_dirs):
    provenance_path = _build_provenance_path(report_dir)
    current = {}
    if provenance_path.is_file():
        try:
            provenance = json.loads(provenance_path.read_text(encoding='utf-8'))
            current = next(
                (item for item in provenance.get('sides') or [] if item.get('side') == 'current'),
                {},
            )
        except (OSError, json.JSONDecodeError):
            current = {}
    source_root = str((business_source_dirs or [''])[0] or '')
    git_root = revision = ''
    dirty = None
    if source_root and os.path.isdir(source_root):
        stdout, _stderr, rc = run_cmd(['git', '-C', source_root, 'rev-parse', '--show-toplevel'])
        if rc == 0:
            git_root = stdout.strip()
            stdout, _stderr, rc = run_cmd(['git', '-C', git_root, 'rev-parse', 'HEAD'])
            revision = stdout.strip() if rc == 0 else ''
            stdout, _stderr, rc = run_cmd(['git', '-C', git_root, 'status', '--porcelain'])
            dirty = bool(stdout.strip()) if rc == 0 else None
    expected_revision = str(current.get('revision') or '').strip()
    source_mode = str(current.get('source_mode') or '').strip()
    reasons = []
    if not current:
        status = 'unverified'
        reasons.append('build_provenance_missing')
    elif not expected_revision or not revision:
        status = 'unverified'
        reasons.append('source_revision_unavailable')
    else:
        alignment = build_artifact_alignment(
            git_root,
            current.get('original_artifact_path') or current.get('artifact_path') or '',
            target_module=current.get('target_module') or '',
            build_command=(str(current.get('build_command') or ''),),
            build_profile=current.get('build_profile') or '',
            expected_revision=expected_revision,
            expected_sha256=current.get('artifact_sha256') or '',
            internally_built=source_mode == 'checkout_build',
        )
        reason_map = {
            'source_revision_mismatch': 'source_revision_differs_from_build_revision',
            'source_worktree_dirty': 'source_worktree_has_unbuilt_changes',
            'external_artifact_manifest_missing': 'direct_artifact_source_revision_unverified',
        }
        reasons = [reason_map.get(item, item) for item in alignment.reasons]
        conflict_reasons = {
            'source_revision_differs_from_build_revision',
            'source_worktree_has_unbuilt_changes',
            'artifact_sha256_mismatch',
            'target_module_mismatch',
        }
        if alignment.status == 'aligned':
            status = 'aligned'
        elif any(item in conflict_reasons for item in reasons):
            status = 'conflict'
        else:
            status = 'unverified'
    payload = {
        'schema': 'java-upgrade-analyzer.source-artifact-alignment.v1',
        'status': status,
        'reason_codes': reasons,
        'source_mode': source_mode,
        'expected_revision': expected_revision,
        'actual_revision': revision,
        'git_root': git_root,
        'worktree_dirty': dirty,
        'target_module': current.get('target_module', ''),
        'artifact_path': current.get('artifact_path', ''),
        'artifact_sha256': current.get('artifact_sha256', ''),
        'alignment_record': alignment.to_dict() if current and expected_revision and revision else {},
    }
    alignment_path = _call_chain_dir(report_dir) / 'source_artifact_alignment.json'
    alignment_path.parent.mkdir(parents=True, exist_ok=True)
    alignment_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
    )
    return payload


def _normalize_descriptor_type(descriptor, preserve_array=False):
    if not descriptor:
        return ''
    array_dims = 0
    while descriptor.startswith('['):
        array_dims += 1
        descriptor = descriptor[1:]
    primitive_map = {
        'V': 'void',
        'Z': 'boolean',
        'B': 'byte',
        'C': 'char',
        'S': 'short',
        'I': 'int',
        'J': 'long',
        'F': 'float',
        'D': 'double',
    }
    if descriptor in primitive_map:
        base = primitive_map[descriptor]
    elif descriptor.startswith('L') and descriptor.endswith(';'):
        base = descriptor[1:-1].replace('/', '.')
    else:
        base = descriptor.replace('/', '.')
    if array_dims:
        suffix = '[]' * array_dims
        if preserve_array:
            return f'{base}{suffix}'
    return base


def _parse_method_descriptor(descriptor):
    descriptor = str(descriptor or '').strip()
    if not descriptor.startswith('('):
        return [], ''
    idx = 1
    params = []
    while idx < len(descriptor) and descriptor[idx] != ')':
        start = idx
        while idx < len(descriptor) and descriptor[idx] == '[':
            idx += 1
        if idx >= len(descriptor):
            break
        if descriptor[idx] == 'L':
            end = descriptor.find(';', idx)
            if end < 0:
                break
            idx = end + 1
        else:
            idx += 1
        params.append(_normalize_descriptor_type(descriptor[start:idx], preserve_array=True))
    return_type = ''
    if idx < len(descriptor) and descriptor[idx] == ')':
        return_type = _normalize_descriptor_type(descriptor[idx + 1:], preserve_array=True)
    return params, return_type


def _build_signature_from_params(param_types):
    params = [str(item or '').strip() for item in (param_types or [])]
    if not params:
        return '()'
    normalized = []
    for item in params:
        text = item.replace('...', '[]')
        if '<' in text:
            text = text.split('<', 1)[0].strip()
        if '.' in text:
            text = text.rsplit('.', 1)[-1]
        normalized.append(text)
    return '(' + ', '.join(normalized) + ')'


def _run_javap_for_class(jar_path, class_fqcn):
    return execute_external_tool(
        ['javap', '-classpath', jar_path, '-s', '-p', class_fqcn],
        stage='step5.jar-metadata.javap',
        reason_prefix='STEP5_JAR_METADATA_JAVAP',
        timeout_seconds=30,
        blocking=True,
        require_stdout=True,
        runner=run_cmd,
    ).require_success().stdout


def _parse_javap_signature_block(text, class_fqcn):
    metadata = {
        'class_fqcn': class_fqcn,
        'kind': 'class',
        'extends': [],
        'implements': [],
        'methods': defaultdict(dict),
    }
    current_method_name = ''
    current_param_types = []
    header_match = re.search(
        r'(?:public|protected|private)?\s*(?:abstract\s+|final\s+)?(class|interface)\s+'
        r'[\w.$]+\s*(?:extends\s+([^{\n]+?))?\s*(?:implements\s+([^{\n]+))?\s*\{',
        text,
    )
    if header_match:
        metadata['kind'] = 'interface' if header_match.group(1) == 'interface' else 'class'
        extends_part = (header_match.group(2) or '').strip()
        implements_part = (header_match.group(3) or '').strip()
        if extends_part:
            metadata['extends'] = [
                item.strip().replace('$', '.')
                for item in extends_part.split(',')
                if item.strip() and item.strip() != 'java.lang.Object'
            ]
        if implements_part:
            metadata['implements'] = [
                item.strip().replace('$', '.')
                for item in implements_part.split(',')
                if item.strip()
            ]
    for raw_line in (text or '').splitlines():
        line = raw_line.strip()
        if not line:
            continue
        descriptor_match = re.match(r'descriptor:\s*(\S+)', line)
        if descriptor_match and current_method_name:
            descriptor = descriptor_match.group(1).strip()
            current_param_types, return_type = _parse_method_descriptor(descriptor)
            signature = _build_signature_from_params(current_param_types)
            metadata['methods'][current_method_name][signature] = return_type
            continue
        if line.startswith('descriptor:'):
            continue
        if not line.endswith(';'):
            current_method_name = ''
            current_param_types = []
            continue
        if '(' not in line or ')' not in line:
            current_method_name = ''
            current_param_types = []
            continue
        decl = line[:-1]
        method_match = re.search(r'([A-Za-z_$][\w$]*)\s*\(', decl)
        if not method_match:
            current_method_name = ''
            current_param_types = []
            continue
        current_method_name = method_match.group(1)
        current_param_types = []
    metadata['methods'] = {
        method_name: dict(signatures)
        for method_name, signatures in metadata['methods'].items()
    }
    return metadata


def _normalize_class_reference(type_name):
    text = str(type_name or '').strip()
    if not text:
        return ''
    text = text.replace('...', '[]')
    text = text.replace('$', '.')
    text = re.sub(r'@\w+(?:\([^)]*\))?\s*', '', text)
    text = text.replace('?', '').replace('extends ', '').replace('super ', '').strip()
    if '<' in text:
        text = text.split('<', 1)[0].strip()
    while text.endswith('[]'):
        text = text[:-2].strip()
    if text in {'void', 'boolean', 'byte', 'char', 'short', 'int', 'long', 'float', 'double'}:
        return ''
    if '.' not in text or any(ch in text for ch in ' ,()'):
        return ''
    return text


def _ensure_coord_class_index(metadata, coord, jar_path):
    class_index_by_coord = metadata.setdefault('_class_index_by_coord', {})
    cached = class_index_by_coord.get(coord)
    if cached is not None:
        return cached
    class_index = {}
    with zipfile.ZipFile(jar_path) as zf:
        for entry in zf.namelist():
            if not entry.endswith('.class') or entry.startswith('META-INF/'):
                continue
            binary_name = entry[:-6].replace('/', '.')
            normalized_name = binary_name.replace('$', '.')
            class_index.setdefault(normalized_name, binary_name)
    class_index_by_coord[coord] = class_index
    return class_index


def _locate_jar_class(metadata, class_fqcn):
    class_locations = metadata.setdefault('_class_locations', {})
    if class_fqcn in class_locations:
        return class_locations[class_fqcn]
    for coord, jar_path in (metadata.get('jar_paths') or {}).items():
        class_index = _ensure_coord_class_index(metadata, coord, jar_path)
        binary_name = class_index.get(class_fqcn)
        if binary_name:
            located = (coord, jar_path, binary_name)
            class_locations[class_fqcn] = located
            return located
    class_locations[class_fqcn] = None
    return None


def hydrate_jar_metadata_for_classes(metadata, target_classes, source_known_classes=None):
    metadata = metadata or {}
    by_class = metadata.setdefault('by_class', {})
    by_coord = metadata.setdefault('by_coord', {})
    pending = deque()
    queued = set()
    source_known_classes = set(source_known_classes or [])

    for class_name in target_classes or []:
        normalized = _normalize_class_reference(class_name)
        if not normalized or normalized in source_known_classes or normalized in by_class:
            continue
        if normalized in queued:
            continue
        pending.append(normalized)
        queued.add(normalized)

    while pending:
        class_fqcn = pending.popleft()
        located = _locate_jar_class(metadata, class_fqcn)
        if not located:
            continue
        coord, jar_path, binary_name = located
        try:
            javap_text = _run_javap_for_class(jar_path, binary_name)
        except ExternalToolError as exc:
            failure = exc.failure.to_mapping()
            failure.update({
                'coord': coord,
                'jar_path': jar_path,
                'class_fqcn': class_fqcn,
                'class_binary_name': binary_name,
            })
            metadata.setdefault('failures', []).append(failure)
            metadata['complete'] = False
            continue
        class_meta = _parse_javap_signature_block(javap_text, class_fqcn)
        by_class[class_fqcn] = class_meta
        coord_meta = by_coord.setdefault(
            coord,
            {
                'coord': coord,
                'version': '',
                'jar_path': jar_path,
                'classes': {},
            },
        )
        coord_meta['classes'][class_fqcn] = class_meta
        for parent in (class_meta.get('extends') or []) + (class_meta.get('implements') or []):
            normalized_parent = _normalize_class_reference(parent)
            if (
                normalized_parent
                and normalized_parent not in source_known_classes
                and normalized_parent not in by_class
                and normalized_parent not in queued
            ):
                pending.append(normalized_parent)
                queued.add(normalized_parent)


def _index_jar_classes_for_source_resolution(metadata):
    by_simple = defaultdict(set)
    all_classes = set()
    for jar_path in (metadata.get('jar_paths') or {}).values():
        if not jar_path or not os.path.isfile(jar_path):
            continue
        try:
            with zipfile.ZipFile(jar_path) as jar:
                for name in jar.namelist():
                    if not name.endswith('.class') or name.startswith('META-INF/'):
                        continue
                    if name.endswith('module-info.class') or name.endswith('package-info.class'):
                        continue
                    class_name = name[:-6].replace('/', '.')
                    for prefix in ('BOOT-INF.classes.', 'WEB-INF.classes.'):
                        if class_name.startswith(prefix):
                            class_name = class_name[len(prefix):]
                            break
                    if class_name.startswith(('BOOT-INF.', 'WEB-INF.', 'lib.')):
                        continue
                    all_classes.add(class_name)
                    simple = class_name.rsplit('.', 1)[-1].split('$', 1)[0]
                    if simple:
                        by_simple[simple].add(class_name)
        except (OSError, zipfile.BadZipFile):
            continue
    metadata['all_class_fqcns'] = sorted(all_classes)
    metadata['classes_by_simple'] = {
        simple: sorted(values)
        for simple, values in sorted(by_simple.items())
    }
    return metadata


def build_jar_metadata_for_source_roots(source_roots, report_dir, runtime_dependency_catalog=None):
    metadata = {
        'complete': True,
        'failures': [],
        'by_coord': {},
        'by_class': {},
        'jar_paths': {},
        'all_class_fqcns': [],
        'classes_by_simple': {},
    }
    for coord, item in ((runtime_dependency_catalog or {}).get('by_coord') or {}).items():
        coord = str(coord or '').strip()
        if not coord or coord == '__business__':
            continue
        jar_path = str((item or {}).get('jar_path') or '').strip()
        if not jar_path or not os.path.isfile(jar_path):
            continue
        metadata['jar_paths'][coord] = jar_path
        metadata['by_coord'].setdefault(coord, {
            'coord': coord,
            'version': str((item or {}).get('version') or ''),
            'jar_path': jar_path,
            'classes': {},
        })
    return _index_jar_classes_for_source_resolution(metadata)


def _collect_external_class_candidates(class_info, all_methods, resolve_type_name, known_classes):
    candidates = set()
    known_classes = set(known_classes or [])
    for info in (class_info or {}).values():
        if info.get('owner_type') != 'business':
            continue
        owner_info = {
            'imports': info.get('imports', {}),
            'package_name': info.get('package_name', ''),
        }
        for raw_name in (info.get('extends_raw') or []) + (info.get('implements_raw') or []):
            normalized = _normalize_class_reference(resolve_type_name(raw_name, owner_info))
            if normalized and normalized not in known_classes:
                candidates.add(normalized)
    for method_def in all_methods or []:
        if getattr(method_def, 'owner_type', '') != 'business':
            continue
        for raw_name in (
            [getattr(method_def, 'return_type', '')]
            + list((getattr(method_def, 'param_types', {}) or {}).values())
            + list((getattr(method_def, 'field_types', {}) or {}).values())
            + list((getattr(method_def, 'local_var_types', {}) or {}).values())
        ):
            normalized = _normalize_class_reference(raw_name)
            if normalized and normalized not in known_classes:
                candidates.add(normalized)
    return candidates


def load_changed_apis(csv_path, jdk_scan_dir=""):
    """加载变更API列表"""
    rows = []

    with open_csv_read(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(dict(row))

    _step5_debug(
        'input_changed_apis',
        'loaded changed api rows',
        csv_path=os.path.abspath(csv_path),
        jdk_scan_dir=os.path.abspath(jdk_scan_dir) if jdk_scan_dir else '',
        total_rows=len(rows),
        excluded_count=0,
        sample_api_names=[item.get('api_name', '') for item in rows[:5]],
    )

    return rows


def _has_direct_business_usage(api_row, business_graph):
    """检查业务源码是否直接调用了变更API，不需要额外依赖源码映射即可证明影响。"""
    graph_type_metadata = getattr(business_graph, 'type_metadata', {}) or {}
    target_keys = build_api_target_keys(
        api_row,
        graph=business_graph,
        type_metadata=graph_type_metadata,
    )
    for key in target_keys:
        if not business_graph.reverse_edges.get(key):
            continue
        if key.startswith('class:'):
            continue
        for edge in business_graph.reverse_edges.get(key, []):
            method_def = business_graph.methods_by_id.get(edge.caller_symbol_id)
            if method_def and method_def.owner_type == 'business' and not method_def.is_test:
                return True
    return False


def _empty_graph_stats():
    return {
        'truncated': False,
        'truncation_reasons': [],
        'methods_indexed': 0,
        'reverse_edges_indexed': 0,
        'edge_cap_hits': 0,
        'edge_cap_keys': [],
        'parser_usage': {
            'tree_sitter': 0,
            'regex': 0,
        },
        'parser_fallback_reasons': {},
        'parser_fallback_files': [],
    }


def _record_parser_info(stats, file_path, parser_info):
    parser_info = parser_info or {}
    actual_parser = parser_info.get('actual_parser', 'regex')
    stats['parser_usage'][actual_parser] = stats['parser_usage'].get(actual_parser, 0) + 1
    fallback_reason = parser_info.get('fallback_reason')
    if fallback_reason:
        stats['parser_fallback_reasons'][fallback_reason] = (
            stats['parser_fallback_reasons'].get(fallback_reason, 0) + 1
        )
        if len(stats['parser_fallback_files']) < 20:
            stats['parser_fallback_files'].append({
                'file': file_path,
                'reason': fallback_reason,
            })


def _extract_declared_types(file_content):
    package_match = re.search(r'^\s*package\s+([A-Za-z_][\w.]*)\s*;?', file_content, re.MULTILINE)
    package_name = package_match.group(1) if package_match else ''
    imports = {}
    for import_match in re.finditer(r'^\s*import\s+([A-Za-z_][\w.]*)\s*;?', file_content, re.MULTILINE):
        fqcn = import_match.group(1)
        imports[fqcn.rsplit('.', 1)[-1]] = fqcn

    declared_types = {}
    lines = file_content.splitlines()
    for idx, line in enumerate(lines):
        decl_match = re.search(
            r'^\s*(?:public|protected|private|abstract|final|sealed|open|data|internal|static|\s)*'
            r'(class|interface|enum)\s+([A-Z][A-Za-z0-9_]*)\b([^{]*)\{?',
            line
        )
        if not decl_match:
            continue
        kind = decl_match.group(1)
        class_name = decl_match.group(2)
        tail = decl_match.group(3) or ''
        annotations = []
        for back_idx in range(idx - 1, max(idx - 10, -1), -1):
            prev = lines[back_idx].strip()
            if not prev:
                break
            if prev.startswith('@'):
                ann_match = re.match(r'@(\w+)', prev)
                if ann_match:
                    annotations.insert(0, ann_match.group(1))
                continue
            break
        extends_raw = []
        implements_raw = []
        if kind == 'interface':
            extends_match = re.search(r'\bextends\s+([^{]+)$', tail)
            if extends_match:
                extends_raw = [item.strip() for item in extends_match.group(1).split(',') if item.strip()]
        else:
            extends_match = re.search(r'\bextends\s+([^{]+?)(?:\bimplements\b|$)', tail)
            if extends_match:
                extends_raw = [extends_match.group(1).strip()] if extends_match.group(1).strip() else []
            implements_match = re.search(r'\bimplements\s+([^{]+)$', tail)
            if implements_match:
                implements_raw = [item.strip() for item in implements_match.group(1).split(',') if item.strip()]
        declared_types[class_name] = {
            'kind': kind,
            'annotations': annotations,
            'extends_raw': extends_raw,
            'implements_raw': implements_raw,
        }
    return package_name, imports, declared_types


def _analyze_source_file_entry(file_path, root):
    # Java sources should consistently prefer AST parsing for both business and
    # dependency roots. analyze_file() will still fall back to regex when the
    # runtime lacks tree-sitter support or the file cannot be parsed.
    prefer_tree_sitter = True
    methods, parser_info = analyze_file(
        file_path,
        root,
        prefer_tree_sitter=prefer_tree_sitter,
        return_diagnostics=True,
    )
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            file_content = f.read()
    except OSError:
        file_content = ''
    package_name, imports, declared_types = _extract_declared_types(file_content)
    return {
        'file_path': os.path.abspath(file_path),
        'root': dict(root),
        'methods': methods,
        'parser_info': parser_info,
        'package_name': package_name,
        'imports': imports,
        'declared_types': declared_types,
    }


def _source_class_in_allowed_jar(class_fqcn, allowed_classes):
    class_fqcn = str(class_fqcn or '').strip()
    if not class_fqcn:
        return False
    if class_fqcn in allowed_classes:
        return True
    # Source parsers commonly represent nested classes as Outer.Inner while
    # classfiles use Outer$Inner. Try only package-preserving nested variants.
    parts = class_fqcn.split('.')
    for class_start in range(1, len(parts)):
        candidate = '.'.join(parts[:class_start]) + '.' + '$'.join(parts[class_start:])
        if candidate in allowed_classes:
            return True
    return any(value.startswith(f"{class_fqcn}$") for value in allowed_classes)


def _filter_dependency_source_entry(entry, allowed_dependency_classes_by_coord):
    root = (entry or {}).get('root') or {}
    if str(root.get('owner_type') or '').strip() != 'dependency':
        return entry
    coord = str(root.get('owner_coord') or '').strip()
    allowed = set((allowed_dependency_classes_by_coord or {}).get(coord) or set())
    if not allowed:
        return None
    kept_methods = [
        method for method in (entry.get('methods') or [])
        if _source_class_in_allowed_jar(getattr(method, 'class_fqcn', ''), allowed)
    ]
    package_name = str(entry.get('package_name') or '').strip()
    kept_declared_types = {}
    for class_name, metadata in (entry.get('declared_types') or {}).items():
        class_fqcn = f"{package_name}.{class_name}" if package_name else str(class_name)
        if _source_class_in_allowed_jar(class_fqcn, allowed):
            kept_declared_types[class_name] = metadata
    if not kept_methods and not kept_declared_types:
        return None
    filtered = dict(entry)
    filtered['methods'] = kept_methods
    filtered['declared_types'] = kept_declared_types
    return filtered


def _filter_source_entry(
    entry,
    allowed_business_classes=None,
    allowed_dependency_classes_by_coord=None,
):
    root = (entry or {}).get('root') or {}
    owner_type = str(root.get('owner_type') or '').strip()
    if owner_type == 'business' and allowed_business_classes is not None:
        allowed = set(allowed_business_classes)
        kept_methods = [
            method for method in (entry.get('methods') or [])
            if _source_class_in_allowed_jar(getattr(method, 'class_fqcn', ''), allowed)
        ]
        package_name = str(entry.get('package_name') or '').strip()
        kept_declared_types = {
            class_name: metadata
            for class_name, metadata in (entry.get('declared_types') or {}).items()
            if _source_class_in_allowed_jar(
                f"{package_name}.{class_name}" if package_name else str(class_name),
                allowed,
            )
        }
        if not kept_methods and not kept_declared_types:
            return None
        filtered = dict(entry)
        filtered['methods'] = kept_methods
        filtered['declared_types'] = kept_declared_types
        return filtered
    if owner_type == 'dependency' and allowed_dependency_classes_by_coord is not None:
        return _filter_dependency_source_entry(entry, allowed_dependency_classes_by_coord)
    return entry


def _collect_source_file_entries(
    source_roots,
    reused_analysis=None,
    allowed_dependency_classes_by_coord=None,
    allowed_business_classes=None,
):
    skip_dirs = {
        '.git', 'target', 'build', '.gradle', 'out', 'bin',
        'node_modules', '.idea', '.upgrade-report'
    }
    entries = []
    seen_files = set()
    stats = _empty_graph_stats()

    for entry in sorted(
        reused_analysis or [],
        key=lambda item: os.path.abspath(str((item or {}).get('file_path') or '')),
    ):
        file_path = os.path.abspath(str(entry.get('file_path') or ''))
        if not file_path or file_path in seen_files:
            continue
        included = False
        if entry.get('file_path') != file_path:
            copied = dict(entry)
            copied['file_path'] = file_path
            copied['root'] = dict(entry.get('root') or {})
            filtered = _filter_source_entry(
                copied,
                allowed_business_classes=allowed_business_classes,
                allowed_dependency_classes_by_coord=allowed_dependency_classes_by_coord,
            ) if (allowed_business_classes is not None or allowed_dependency_classes_by_coord is not None) else copied
            if filtered is not None:
                entries.append(filtered)
                included = True
        else:
            filtered = _filter_source_entry(
                entry,
                allowed_business_classes=allowed_business_classes,
                allowed_dependency_classes_by_coord=allowed_dependency_classes_by_coord,
            ) if (allowed_business_classes is not None or allowed_dependency_classes_by_coord is not None) else entry
            if filtered is not None:
                entries.append(filtered)
                included = True
        seen_files.add(file_path)
        if included:
            _record_parser_info(stats, file_path, entry.get('parser_info') or {})

    for root in sorted(
        source_roots or [],
        key=lambda item: (
            str((item or {}).get('root') or ''),
            str((item or {}).get('owner_type') or ''),
            str((item or {}).get('owner_coord') or ''),
            str((item or {}).get('module') or ''),
        ),
    ):
        root_path = str((root or {}).get('root') or '').strip()
        if not root_path or not os.path.isdir(root_path):
            continue
        for current_root, dirs, files in os.walk(root_path):
            dirs[:] = sorted(
                d for d in dirs
                if d not in skip_dirs
            )
            for filename in sorted(files):
                if not filename.endswith(('.java', '.kt', '.kts')):
                    continue
                file_path = os.path.abspath(os.path.join(current_root, filename))
                if file_path in seen_files:
                    continue
                entry = _analyze_source_file_entry(file_path, root)
                parser_info = entry.get('parser_info') or {}
                if allowed_business_classes is not None or allowed_dependency_classes_by_coord is not None:
                    entry = _filter_source_entry(
                        entry,
                        allowed_business_classes=allowed_business_classes,
                        allowed_dependency_classes_by_coord=allowed_dependency_classes_by_coord,
                    )
                if entry is not None:
                    entries.append(entry)
                seen_files.add(file_path)
                if entry is not None:
                    _record_parser_info(stats, file_path, parser_info)
    _step5_debug(
        'graph_source_collection',
        'collected source file entries for graph build',
        source_root_count=len(source_roots or []),
        reused_analysis_count=len(reused_analysis or []),
        collected_files=len(entries),
        parser_usage=stats.get('parser_usage', {}),
        parser_fallback_reasons=stats.get('parser_fallback_reasons', {}),
    )
    entries.sort(key=lambda item: os.path.abspath(str((item or {}).get('file_path') or '')))
    return entries, stats


def build_enhanced_source_graph(
    source_roots,
    max_methods=None,
    jar_metadata=None,
    reused_analysis=None,
    retain_analysis_cache=True,
    allowed_dependency_classes_by_coord=None,
    allowed_business_classes=None,
):
    """
    构建增强型源码图

    改进：
      - 使用增强分析器（AST/增强正则）
      - Lambda/方法引用识别
      - 泛型类型完整解析
      - 填充type_metadata（关键修复）
    """
    from collections import defaultdict

    methods_by_id = {}
    methods_by_qualified = defaultdict(list)
    methods_by_simple = defaultdict(list)
    reverse_edges = defaultdict(list)
    lookup_keys_by_symbol = {}
    type_metadata = {}  # 关键修复：必须填充
    all_methods = []

    # 类型信息收集器
    class_info = {}  # class_fqcn -> ClassInfo
    interface_implementations = defaultdict(list)  # interface -> 实现类列表

    file_entries, stats = _collect_source_file_entries(
        source_roots,
        reused_analysis=reused_analysis,
        allowed_dependency_classes_by_coord=allowed_dependency_classes_by_coord,
        allowed_business_classes=allowed_business_classes,
    )
    _step5_debug(
        'graph_build_start',
        'starting enhanced source graph build',
        source_root_count=len(source_roots or []),
        reused_analysis_count=len(reused_analysis or []),
        retain_analysis_cache=bool(retain_analysis_cache),
        max_methods=max_methods,
    )

    def build_method_declared_signature(method_def):
        values = list((getattr(method_def, 'param_declared_types', {}) or {}).values())
        if not values:
            values = list((getattr(method_def, 'param_types', {}) or {}).values())
        normalized = []
        for value in values:
            text = str(value or '').strip()
            if not text:
                return ''
            text = text.replace('...', '[]')
            if '<' in text:
                text = text.split('<', 1)[0].strip()
            if '.' in text:
                text = text.rsplit('.', 1)[-1]
            normalized.append(text)
        return '(' + ', '.join(normalized) + ')' if normalized or values == [] else ''

    def enrich_method_declared_identity(method_def):
        signature = build_method_declared_signature(method_def)
        qualified_key = str(getattr(method_def, 'qualified_key', '') or '').strip()
        declared_key = f"{qualified_key}{signature}" if qualified_key and signature else qualified_key
        try:
            method_def.declared_signature = signature
            method_def.declared_qualified_key = declared_key
        except (AttributeError, TypeError):
            stats['method_identity_annotation_failures'] = (
                stats.get('method_identity_annotation_failures', 0) + 1
            )
        return signature, declared_key

    def method_lookup_keys(method_def):
        signature, declared_key = enrich_method_declared_identity(method_def)
        keys = []
        for value in (
            declared_key,
            getattr(method_def, 'qualified_key', ''),
            f"{getattr(method_def, 'simple_key', '')}{signature}" if signature else '',
            getattr(method_def, 'simple_key', ''),
            f"class:{getattr(method_def, 'class_fqcn', '')}" if getattr(method_def, 'class_fqcn', '') else '',
        ):
            value = str(value or '').strip()
            if value and value not in keys:
                keys.append(value)
        return keys

    unique_signatures_by_qualified_key = defaultdict(set)
    unique_signatures_by_simple_key = defaultdict(set)

    def is_probably_fully_qualified_method_key(edge_key):
        value = str(edge_key or '').strip()
        if not value or value.startswith(('method:', 'class:', 'field:', 'invokedynamic:')):
            return False
        prefix = value.split('(', 1)[0]
        if '.' not in prefix:
            return False
        owner = prefix.rsplit('.', 1)[0]
        return '.' in owner

    def is_method_like_edge(edge):
        evidence_type = str(getattr(edge, 'evidence_type', '') or '')
        callee_key = str(getattr(edge, 'callee_key', '') or '')
        if evidence_type in {
            'ast_method_invocation',
            'instance_call',
            'lambda_call',
            'method_reference',
            'constructor_invocation',
            'bytecode_method_invocation',
            'bytecode_constructor_invocation',
            'runtime_dependency_method_invocation',
            'runtime_dependency_constructor_invocation',
        }:
            return True
        return bool(callee_key and not callee_key.startswith(('class:', 'field:', 'invokedynamic:')) and '(' in callee_key)

    def has_method_signature(edge_key):
        value = str(edge_key or '').strip()
        return '(' in value and value.endswith(')')

    def annotate_edge_resolution(edge):
        callee_key = str(getattr(edge, 'callee_key', '') or '').strip()
        fqcn_complete = is_probably_fully_qualified_method_key(callee_key) or callee_key.startswith('class:')
        signature_complete = (not is_method_like_edge(edge)) or has_method_signature(callee_key)
        try:
            edge.callee_fqcn_complete = bool(fqcn_complete)
            edge.callee_signature_complete = bool(signature_complete)
            if not fqcn_complete and is_method_like_edge(edge):
                edge.callee_resolution_note = '缺少调用目标所属类全限定名'
            elif not signature_complete:
                edge.callee_resolution_note = '缺少调用目标方法参数签名'
            else:
                edge.callee_resolution_note = '调用目标已解析到全限定名和签名'
        except (AttributeError, TypeError):
            stats['edge_resolution_annotation_failures'] = (
                stats.get('edge_resolution_annotation_failures', 0) + 1
            )

    def build_reverse_edge_keys(edge):
        annotate_edge_resolution(edge)
        callee_key = (getattr(edge, 'callee_key', '') or '').strip()
        is_dependency_edge = getattr(edge, 'owner_type', '') == 'dependency'
        if is_dependency_edge and not is_probably_fully_qualified_method_key(callee_key):
            stats['dependency_edges_skipped_without_fqcn'] = stats.get('dependency_edges_skipped_without_fqcn', 0) + 1
            return []
        if is_dependency_edge and is_method_like_edge(edge) and not has_method_signature(callee_key):
            stats['dependency_method_edges_skipped_without_signature'] = (
                stats.get('dependency_method_edges_skipped_without_signature', 0) + 1
            )
            return []
        keys = []
        edge_key_candidates = [edge.callee_key] if is_dependency_edge else [edge.callee_key, edge.callee_simple_key]
        for edge_key in edge_key_candidates:
            edge_key = (edge_key or '').strip()
            if not edge_key:
                continue
            keys.append(edge_key)
            if '(' in edge_key and edge_key.endswith(')'):
                keys.append(edge_key.split('(', 1)[0])
        # Method references like `this::toDto` do not carry explicit arg expressions.
        # If the referenced target has a single declared signature in source, index that
        # exact signature as well so Step5 can avoid unnecessary name-only fallback.
        if getattr(edge, 'evidence_type', '') == 'method_reference':
            for base_key, signature_map in [
                ((edge.callee_key or '').strip(), unique_signatures_by_qualified_key),
                ((edge.callee_simple_key or '').strip(), unique_signatures_by_simple_key),
            ]:
                if is_dependency_edge and base_key == (edge.callee_simple_key or '').strip():
                    continue
                if not base_key or '(' in base_key:
                    continue
                signatures = sorted(signature_map.get(base_key, set()))
                if len(signatures) == 1:
                    keys.append(f"{base_key}{signatures[0]}")
        return list(dict.fromkeys(keys))

    def method_sort_key(method_def):
        return (
            str(getattr(method_def, 'file', '') or ''),
            int(getattr(method_def, 'line', 0) or 0),
            str(getattr(method_def, 'qualified_key', '') or ''),
            str(getattr(method_def, 'symbol_id', '') or ''),
        )

    def edge_sort_key(edge):
        confidence_rank = {'high': 0, 'medium': 1, 'low': 2}.get(getattr(edge, 'confidence', ''), 9)
        owner_rank = 0 if getattr(edge, 'owner_type', '') == 'business' else 1
        return (
            confidence_rank,
            owner_rank,
            str(getattr(edge, 'caller_qualified_key', '') or ''),
            str(getattr(edge, 'callee_key', '') or ''),
            str(getattr(edge, 'file', '') or ''),
            int(getattr(edge, 'line', 0) or 0),
            str(getattr(edge, 'owner_coord', '') or ''),
            str(getattr(edge, 'module', '') or ''),
        )

    for entry in file_entries:
        methods = sorted(list(entry.get('methods') or []), key=method_sort_key)
        package_name = entry.get('package_name') or ''
        imports = dict(entry.get('imports') or {})
        declared_types = dict(entry.get('declared_types') or {})
        root_info = dict(entry.get('root') or {})

        for declared_name, declared in declared_types.items():
            class_fqcn = f"{package_name}.{declared_name}" if package_name else declared_name
            if class_fqcn not in class_info:
                class_info[class_fqcn] = {
                    'kind': 'interface' if declared.get('kind') == 'interface' else 'class',
                    'extends_raw': list(declared.get('extends_raw', []) or []),
                    'implements_raw': list(declared.get('implements_raw', []) or []),
                    'extends': [],
                    'implements': [],
                    'implementations': [],
                    'owner_type': root_info.get('owner_type', 'business'),
                    'package_name': package_name,
                    'imports': dict(imports),
                    'annotations': set(declared.get('annotations', []) or []),
                }
            else:
                class_info[class_fqcn]['annotations'].update(declared.get('annotations', []) or [])
                for parent in declared.get('extends_raw', []):
                    if parent and parent not in class_info[class_fqcn]['extends_raw']:
                        class_info[class_fqcn]['extends_raw'].append(parent)
                for interface in declared.get('implements_raw', []):
                    if interface and interface not in class_info[class_fqcn]['implements_raw']:
                        class_info[class_fqcn]['implements_raw'].append(interface)

        # 第一遍：收集类型信息
        for method_def in methods:
            class_fqcn = method_def.class_fqcn
            declared = declared_types.get(method_def.class_name, {})
            is_interface = method_def.is_interface or declared.get('kind') == 'interface'

            if class_fqcn not in class_info:
                class_info[class_fqcn] = {
                    'kind': 'interface' if is_interface else 'class',
                    'extends_raw': [],
                    'implements_raw': [],
                    'extends': [],
                    'implements': [],
                    'implementations': [],
                    'owner_type': method_def.owner_type,
                    'package_name': package_name,
                    'imports': dict(imports),
                    'annotations': set(declared.get('annotations', []) or method_def.class_annotations or []),
                }
            else:
                if is_interface:
                    class_info[class_fqcn]['kind'] = 'interface'
                class_info[class_fqcn]['annotations'].update(
                    declared.get('annotations', []) or method_def.class_annotations or []
                )
            for parent in declared.get('extends_raw', []):
                if parent and parent not in class_info[class_fqcn]['extends_raw']:
                    class_info[class_fqcn]['extends_raw'].append(parent)
            for interface in declared.get('implements_raw', []):
                if interface and interface not in class_info[class_fqcn]['implements_raw']:
                    class_info[class_fqcn]['implements_raw'].append(interface)

        for method_def in methods:
            if max_methods is not None and len(methods_by_id) >= max_methods:
                stats['truncated'] = True
                if 'max_methods' not in stats['truncation_reasons']:
                    stats['truncation_reasons'].append('max_methods')
                break
            methods_by_id[method_def.symbol_id] = method_def

            # 额外索引（兼容confidence_weighted_tracer）
            methods_by_qualified[method_def.qualified_key].append(method_def.symbol_id)
            methods_by_simple[method_def.simple_key].append(method_def.symbol_id)
            lookup_keys_by_symbol[method_def.symbol_id] = method_lookup_keys(method_def)
            all_methods.append(method_def)

            # 关键修复：更新class_info的kind（interface vs class）
            class_meta = class_info.get(method_def.class_fqcn, {})
            if method_def.is_interface:
                class_meta['kind'] = 'interface'
            if method_def.class_annotations:
                class_meta.setdefault('annotations', set()).update(method_def.class_annotations)

        if max_methods is not None and len(methods_by_id) >= max_methods:
            break

    stats['methods_indexed'] = len(methods_by_id)
    if max_methods is not None and len(methods_by_id) >= max_methods:
        stats['truncated'] = True
        if 'max_methods' not in stats['truncation_reasons']:
            stats['truncation_reasons'].append('max_methods')

    known_classes = set(class_info.keys())
    jar_metadata = jar_metadata or {}
    classes_by_simple = defaultdict(list)
    for class_fqcn in known_classes:
        classes_by_simple[class_fqcn.rsplit('.', 1)[-1]].append(class_fqcn)
    classpath_classes = set(jar_metadata.get('all_class_fqcns') or [])
    classpath_classes_by_simple = {
        simple: list(values or [])
        for simple, values in (jar_metadata.get('classes_by_simple') or {}).items()
    }

    def resolve_type_name(raw_name, owner_info):
        name = (raw_name or '').strip()
        if not name:
            return ''
        name = re.sub(r'<[^>]+>', '', name).strip()
        name = name.replace('?', '').replace('extends ', '').replace('super ', '').strip()
        if not name:
            return ''
        if '.' in name:
            if name in known_classes:
                return name
            return name
        imports = owner_info.get('imports', {})
        if name in imports:
            return imports[name]
        package_name = owner_info.get('package_name', '')
        package_candidate = f"{package_name}.{name}" if package_name else name
        if package_candidate in known_classes:
            return package_candidate
        matches = classes_by_simple.get(name, [])
        if len(matches) == 1:
            return matches[0]
        classpath_matches = classpath_classes_by_simple.get(name, [])
        if len(classpath_matches) == 1:
            return classpath_matches[0]
        if name == 'Object':
            return 'java.lang.Object'
        return package_candidate

    def infer_initializer_arg_signature(arg_text, context_text=''):
        text = (arg_text or '').strip()
        if not text:
            return '()'
        args = [item.strip() for item in text.split(',')]
        inferred = []
        for arg in args:
            while arg.endswith(')') and arg.count(')') > arg.count('('):
                arg = arg[:-1].strip()
            if not arg:
                continue
            if '.class' in arg or arg.endswith('getClass()') or arg == 'getClass()':
                inferred.append('Class')
            elif (arg.startswith('"') and arg.endswith('"')) or (arg.startswith("'") and arg.endswith("'")):
                inferred.append('String')
            elif re.fullmatch(r'[-+]?\d+[lL]?', arg):
                inferred.append('long' if arg.lower().endswith('l') else 'int')
            elif arg in {'true', 'false'}:
                inferred.append('boolean')
            elif re.search(rf'\bString\s+{re.escape(arg)}\b', context_text or ''):
                inferred.append('String')
            else:
                inferred.append('')
        if not inferred or any(not item for item in inferred):
            return ''
        return '(' + ', '.join(inferred) + ')'

    def collect_initializer_edges():
        synthetic_methods = []
        synthetic_edges = []
        synthetic_method_keys = set()
        invocation_pattern = re.compile(
            r'\b((?:[a-z_]\w*\.)*[A-Z]\w*)\s*\.\s*([a-zA-Z_]\w*)\s*\(([^;\n]*)\)'
        )
        field_access_pattern = re.compile(
            r'\b((?:[a-z_]\w*\.)*[A-Z]\w*)\s*\.\s*([A-Za-z_]\w*)\b'
        )

        def build_synthetic_method(
            class_fqcn,
            file_path,
            line_no,
            column,
            line,
            package_name,
            imports,
            static_imports,
            owner_type,
            owner_coord,
            source_root,
            module,
        ):
            synthetic_id = f"{class_fqcn}#<class-init>@{file_path}:{line_no}:{column}"
            if synthetic_id in synthetic_method_keys:
                return None
            synthetic_method_keys.add(synthetic_id)
            return MethodDef(
                symbol_id=synthetic_id,
                qualified_key=f"{class_fqcn}.<class-init>",
                simple_key='method:<class-init>',
                class_fqcn=class_fqcn,
                class_name=class_fqcn.rsplit('.', 1)[-1],
                method_name='<class-init>',
                return_type='void',
                file=file_path,
                line=line_no,
                end_line=line_no,
                package_name=package_name,
                owner_type=owner_type,
                owner_coord=owner_coord,
                module=module,
                source_root=source_root,
                language=(
                    'kotlin' if file_path.endswith(('.kt', '.kts')) else 'java'
                ),
                is_test=is_test_source_path(file_path),
                imports=imports,
                static_imports=static_imports,
                body_text=line,
                is_static=True,
            )

        for entry in file_entries:
            file_path = str(entry.get('file_path') or '')
            if not file_path:
                continue
            methods = list(entry.get('methods') or [])
            method_ranges = [
                (
                    int(getattr(method_def, 'line', 0) or 0),
                    int(getattr(method_def, 'end_line', 0) or getattr(method_def, 'line', 0) or 0),
                )
                for method_def in methods
            ]
            package_name = entry.get('package_name') or ''
            imports = dict(entry.get('imports') or {})
            declared_types = dict(entry.get('declared_types') or {})
            if not declared_types:
                continue
            declared_name = next(iter(declared_types.keys()))
            class_fqcn = f"{package_name}.{declared_name}" if package_name else declared_name
            root_info = dict(entry.get('root') or {})
            owner_type = root_info.get('owner_type', 'business')
            owner_coord = root_info.get('coord') or ('BUSINESS' if owner_type == 'business' else '')
            source_root = root_info.get('root') or ''
            module = root_info.get('module') or Path(file_path).parent.name
            try:
                lines = Path(file_path).read_text(encoding='utf-8', errors='replace').splitlines()
            except OSError:
                continue
            static_imports = {}
            for raw_line in lines[:200]:
                static_match = re.match(r'^\s*import\s+static\s+([A-Za-z_][\w.]*)\s*;', raw_line)
                if not static_match:
                    continue
                fq_member = static_match.group(1)
                static_imports[fq_member.rsplit('.', 1)[-1]] = fq_member

            for line_no, line in enumerate(lines, 1):
                if any(start <= line_no <= end for start, end in method_ranges if start and end):
                    continue
                if '.' not in line and not any(re.search(rf'\b{re.escape(simple)}\b', line) for simple in static_imports):
                    continue
                stripped = line.strip()
                if not stripped or stripped.startswith(('*', '//', '/*')):
                    continue
                if field_access_pattern.search(line) or any(
                    re.search(rf'\b{re.escape(simple)}\b', line) for simple in static_imports
                ):
                    method_def = build_synthetic_method(
                        class_fqcn,
                        file_path,
                        line_no,
                        0,
                        line,
                        package_name,
                        imports,
                        static_imports,
                        owner_type,
                        owner_coord,
                        source_root,
                        module,
                    )
                    if method_def is not None:
                        synthetic_methods.append(method_def)
                if '(' not in line:
                    continue
                for match in invocation_pattern.finditer(line):
                    receiver = match.group(1)
                    method_name = match.group(2)
                    args_text = match.group(3)
                    if not receiver or not method_name:
                        continue
                    if '.' in receiver:
                        receiver_fqcn = receiver
                    else:
                        receiver_fqcn = imports.get(receiver) or (
                            f"{package_name}.{receiver}" if package_name else receiver
                        )
                    if not receiver_fqcn or receiver_fqcn.startswith(package_name + '.new '):
                        continue
                    context_text = '\n'.join(lines[max(0, line_no - 6):line_no])
                    signature = infer_initializer_arg_signature(args_text, context_text=context_text)
                    base_callee = f"{receiver_fqcn}.{method_name}"
                    callee_key = f"{base_callee}{signature}" if signature else base_callee
                    simple_key = f"method:{method_name}{signature}" if signature else f"method:{method_name}"
                    qualified_key = f"{class_fqcn}.<class-init>"
                    method_def = build_synthetic_method(
                        class_fqcn,
                        file_path,
                        line_no,
                        match.start(),
                        line,
                        package_name,
                        imports,
                        static_imports,
                        owner_type,
                        owner_coord,
                        source_root,
                        module,
                    )
                    if method_def is not None:
                        synthetic_methods.append(method_def)
                    synthetic_edges.append(CallEdge(
                        caller_symbol_id=method_def.symbol_id if method_def is not None else f"{class_fqcn}#<class-init>@{file_path}:{line_no}:{match.start()}",
                        caller_qualified_key=qualified_key,
                        callee_key=callee_key,
                        callee_simple_key=simple_key,
                        evidence_type='initializer_invocation',
                        confidence='high',
                        file=file_path,
                        line=line_no,
                        content=stripped,
                        owner_type=owner_type,
                        owner_coord=owner_coord,
                        module=module,
                        is_test=is_test_source_path(file_path),
                    ))
        return synthetic_methods, synthetic_edges

    jar_class_candidates = _collect_external_class_candidates(
        class_info,
        all_methods,
        resolve_type_name,
        known_classes,
    )
    if jar_class_candidates and (jar_metadata.get('jar_paths') or {}):
        hydrate_jar_metadata_for_classes(
            jar_metadata,
            jar_class_candidates,
            source_known_classes=known_classes,
        )
    jar_classes = set((jar_metadata.get('by_class') or {}).keys())
    for class_fqcn in jar_classes:
        if class_fqcn not in known_classes:
            known_classes.add(class_fqcn)
            classes_by_simple[class_fqcn.rsplit('.', 1)[-1]].append(class_fqcn)
    known_class_fqcns_for_resolution = set(known_classes) | classpath_classes | jar_classes
    known_classes_by_simple_for_resolution = defaultdict(list)
    for class_fqcn in sorted(known_class_fqcns_for_resolution):
        simple = class_fqcn.rsplit('.', 1)[-1].split('$', 1)[0]
        if simple and class_fqcn not in known_classes_by_simple_for_resolution[simple]:
            known_classes_by_simple_for_resolution[simple].append(class_fqcn)
    # This lookup is read-only during edge extraction.  Keep one shared mapping
    # instead of allocating an O(class-count) dict for every source method.
    # Tuple values also prevent accidental mutation through a MethodDef.
    shared_known_classes_by_simple_for_resolution = {
        simple: tuple(class_fqcns)
        for simple, class_fqcns in known_classes_by_simple_for_resolution.items()
    }

    for class_fqcn, info in class_info.items():
        info['extends'] = []
        info['implements'] = []
        for raw_parent in info.get('extends_raw', []):
            resolved = resolve_type_name(raw_parent, info)
            if resolved and resolved not in info['extends']:
                info['extends'].append(resolved)
        for raw_interface in info.get('implements_raw', []):
            resolved = resolve_type_name(raw_interface, info)
            if resolved and resolved not in info['implements']:
                info['implements'].append(resolved)

    for class_fqcn, jar_class_meta in (jar_metadata.get('by_class') or {}).items():
        jar_extends = [
            parent for parent in (jar_class_meta.get('extends') or [])
            if parent and parent not in {'java.lang.Object'}
        ]
        jar_implements = [item for item in (jar_class_meta.get('implements') or []) if item]
        existing = class_info.setdefault(
            class_fqcn,
            {
                'kind': 'interface' if jar_class_meta.get('kind') == 'interface' else 'class',
                'extends_raw': [],
                'implements_raw': [],
                'extends': [],
                'implements': [],
                'implementations': [],
                'owner_type': 'dependency',
                'package_name': class_fqcn.rsplit('.', 1)[0] if '.' in class_fqcn else '',
                'imports': {},
                'annotations': set(),
            },
        )
        for parent in jar_extends:
            if parent not in existing['extends']:
                existing['extends'].append(parent)
        for interface in jar_implements:
            if interface not in existing['implements']:
                existing['implements'].append(interface)

    # 关键修复：填充 interface_implementations（接口->实现类映射）
    # 这样 is_framework_boundary() 可以区分"有实现类"和"无实现类"
    for class_fqcn, info in class_info.items():
        # 如果是类（非接口），找出它实现的接口
        if info.get('kind') != 'interface':
            for interface in info.get('implements', []):
                interface_implementations[interface].append(class_fqcn)
        # 如果是类，检查它是否扩展了父类（父类的实现类也间接实现子接口）
        for parent in info.get('extends', []):
            parent_info = class_info.get(parent, {})
            if parent_info.get('kind') != 'interface':
                for interface in parent_info.get('implements', []):
                    if class_fqcn not in interface_implementations[interface]:
                        interface_implementations[interface].append(class_fqcn)

    # 关键修复：填充type_metadata
    # 为每个类构建完整的继承关系，包含 implementations 列表
    for class_fqcn, info in class_info.items():
        # 获取该类的所有父接口（含间接父接口）
        all_interfaces = set(info.get('implements', []))
        for parent in info.get('extends', []):
            parent_info = class_info.get(parent, {})
            all_interfaces.update(parent_info.get('implements', []))
        # 接口的实现类 = 所有实现了该接口的类（含间接实现）
        impls_for_interface = set(interface_implementations.get(class_fqcn, []))
        if info.get('kind') == 'interface':
            # 收集所有直接/间接实现类
            for other_fqcn, other_info in class_info.items():
                if other_info.get('kind') == 'class':
                    if class_fqcn in other_info.get('implements', []):
                        impls_for_interface.add(other_fqcn)
                    # 检查间接实现（通过父类）
                    for parent in other_info.get('extends', []):
                        parent_info = class_info.get(parent, {})
                        if class_fqcn in parent_info.get('implements', []):
                            impls_for_interface.add(other_fqcn)
        type_metadata[class_fqcn] = {
            'kind': info.get('kind', 'class'),
            'extends': info.get('extends', []),
            'implements': info.get('implements', []),
            'implementations': sorted(impls_for_interface),
            'subclasses': [],
            'annotations': sorted(info.get('annotations', set())),
        }

    for class_fqcn, meta in list(type_metadata.items()):
        for parent in meta.get('extends', []) or []:
            if parent in type_metadata and class_fqcn not in type_metadata[parent]['subclasses']:
                type_metadata[parent]['subclasses'].append(class_fqcn)

    def collect_interface_implementations(interface_fqcn, visited=None):
        if visited is None:
            visited = set()
        if interface_fqcn in visited:
            return set()
        visited.add(interface_fqcn)

        interface_meta = type_metadata.get(interface_fqcn, {}) or {}
        collected = set(interface_meta.get('implementations', []) or [])
        for child in interface_meta.get('subclasses', []) or []:
            child_meta = type_metadata.get(child, {}) or {}
            if child_meta.get('kind') != 'interface':
                continue
            collected.update(child_meta.get('implementations', []) or [])
            collected.update(collect_interface_implementations(child, visited))
        return collected

    for class_fqcn, meta in list(type_metadata.items()):
        if meta.get('kind') == 'interface':
            meta['implementations'] = sorted(collect_interface_implementations(class_fqcn))

    initializer_methods, initializer_edges = collect_initializer_edges()
    for method_def in initializer_methods:
        if max_methods is not None and len(methods_by_id) >= max_methods:
            stats['truncated'] = True
            if 'max_methods' not in stats['truncation_reasons']:
                stats['truncation_reasons'].append('max_methods')
            break
        methods_by_id[method_def.symbol_id] = method_def
        methods_by_qualified[method_def.qualified_key].append(method_def.symbol_id)
        methods_by_simple[method_def.simple_key].append(method_def.symbol_id)
        lookup_keys_by_symbol[method_def.symbol_id] = method_lookup_keys(method_def)
        all_methods.append(method_def)
    stats['initializer_methods_indexed'] = len(initializer_methods)
    stats['initializer_edges_discovered'] = len(initializer_edges)

    global_method_return_types = defaultdict(dict)
    global_method_return_types_by_signature = defaultdict(lambda: defaultdict(dict))
    for method_def in all_methods:
        if method_def.return_type:
            signature = _build_signature_from_params(method_def.param_declared_types.values())
            global_method_return_types[method_def.class_fqcn][method_def.method_name] = method_def.return_type
            global_method_return_types_by_signature[method_def.class_fqcn][method_def.method_name][signature] = (
                method_def.return_type
            )
    for class_fqcn, jar_class_meta in (jar_metadata.get('by_class') or {}).items():
        method_map = jar_class_meta.get('methods') or {}
        for method_name, signatures in method_map.items():
            existing = global_method_return_types.get(class_fqcn, {}).get(method_name)
            if not existing and signatures:
                if len(signatures) == 1:
                    global_method_return_types[class_fqcn][method_name] = next(iter(signatures.values()))
            for signature, return_type in signatures.items():
                global_method_return_types_by_signature[class_fqcn][method_name][signature] = return_type
    global_method_return_types = {
        class_fqcn: dict(return_types)
        for class_fqcn, return_types in global_method_return_types.items()
    }
    global_method_return_types_by_signature = {
        class_fqcn: {
            method_name: dict(signatures)
            for method_name, signatures in method_map.items()
        }
        for class_fqcn, method_map in global_method_return_types_by_signature.items()
    }
    local_method_return_types_by_class = defaultdict(lambda: defaultdict(dict))
    for candidate in all_methods:
        if not candidate.return_type:
            continue
        signature = _build_signature_from_params(candidate.param_declared_types.values())
        local_method_return_types_by_class[candidate.class_fqcn][candidate.method_name][signature] = (
            candidate.return_type
        )
    local_method_return_types_by_class = {
        class_fqcn: {
            method_name: dict(signatures)
            for method_name, signatures in method_map.items()
        }
        for class_fqcn, method_map in local_method_return_types_by_class.items()
    }
    global_field_types = defaultdict(dict)
    for candidate in all_methods:
        class_fqcn = getattr(candidate, 'class_fqcn', '')
        if not class_fqcn:
            continue
        for field_name, field_type in (getattr(candidate, 'field_types', {}) or {}).items():
            if field_name and field_type and field_name not in global_field_types[class_fqcn]:
                global_field_types[class_fqcn][field_name] = field_type
    field_decl_pattern = re.compile(
        r'^\s*(?:public|protected|private|static|final|volatile|transient|\s)*'
        r'(?P<type>[A-Za-z_][\w.$]*(?:\s*<[^;=(){}]+>)?(?:\[\]|\.\.\.)?)\s+'
        r'(?P<name>[A-Za-z_]\w*)\s*(?:=|;)'
    )
    for entry in file_entries:
        file_path = str(entry.get('file_path') or '')
        declared_types = dict(entry.get('declared_types') or {})
        if not file_path or not declared_types:
            continue
        package_name = entry.get('package_name') or ''
        imports = dict(entry.get('imports') or {})
        owner_info = {
            'imports': imports,
            'package_name': package_name,
        }
        try:
            lines = Path(file_path).read_text(encoding='utf-8', errors='replace').splitlines()
        except OSError:
            continue
        class_name = next(iter(declared_types.keys()))
        class_fqcn = f"{package_name}.{class_name}" if package_name else class_name
        for raw_line in lines:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith(('*', '//', '/*', 'import ', 'package ')):
                continue
            match = field_decl_pattern.match(raw_line)
            if not match:
                continue
            raw_type = match.group('type').strip()
            field_name = match.group('name').strip()
            if field_name and raw_type and field_name not in global_field_types[class_fqcn]:
                global_field_types[class_fqcn][field_name] = resolve_type_name(raw_type, owner_info)
    global_field_types = {
        class_fqcn: dict(fields)
        for class_fqcn, fields in global_field_types.items()
    }
    all_methods = sorted(all_methods, key=method_sort_key)

    for method_def in all_methods:
        declared_signature = build_method_declared_signature(method_def)
        if declared_signature:
            unique_signatures_by_qualified_key[method_def.qualified_key].add(declared_signature)
            unique_signatures_by_simple_key[method_def.simple_key].add(declared_signature)
        method_def.local_method_return_types = local_method_return_types_by_class.get(
            method_def.class_fqcn,
            {},
        )
        method_def.known_method_return_types = global_method_return_types
        method_def.known_method_return_types_by_signature = global_method_return_types_by_signature
        method_def.known_type_metadata = type_metadata
        method_def.known_field_types = global_field_types
        method_def.known_class_fqcns = known_class_fqcns_for_resolution
        method_def.known_classes_by_simple = shared_known_classes_by_simple_for_resolution

    for method_def in all_methods:
        if getattr(method_def, 'method_name', '') == '<class-init>':
            continue
        edges = extract_call_edges_enhanced(method_def, include_low_confidence=False)
        # Annotation members with a changed default are semantically consumed
        # even when a source use omits that member (`@TargetAnno`).  Index the
        # annotation-owner usage separately; the tracer only consults this key
        # for a concrete changed member of the same annotation type.
        annotation_names = list(dict.fromkeys(
            list(getattr(method_def, 'class_annotations', []) or [])
            + list(getattr(method_def, 'annotations', []) or [])
        ))
        for annotation_name in annotation_names:
            annotation_fqcn = resolve_type_name(annotation_name, {
                'imports': getattr(method_def, 'imports', {}) or {},
                'package_name': getattr(method_def, 'package_name', '') or '',
            })
            if not annotation_fqcn:
                continue
            edges.append(CallEdge(
                caller_symbol_id=method_def.symbol_id,
                caller_qualified_key=method_def.qualified_key,
                callee_key=f"annotation:{annotation_fqcn}",
                callee_simple_key=f"annotation:{annotation_name}",
                evidence_type='annotation_default_usage',
                confidence='medium',
                file=method_def.file,
                line=method_def.line,
                content=f"@{annotation_name}",
                owner_type=method_def.owner_type,
                owner_coord=method_def.owner_coord,
                module=method_def.module,
                is_test=method_def.is_test,
            ))
        for edge in edges:
            edge_keys = build_reverse_edge_keys(edge)

            for edge_key in edge_keys:
                MAX_EDGES_PER_KEY = 10000
                existing = reverse_edges[edge_key]
                if len(existing) < MAX_EDGES_PER_KEY:
                    existing.append(edge)
                    stats['reverse_edges_indexed'] += 1
                else:
                    stats['edge_cap_hits'] += 1
                    if len(stats['edge_cap_keys']) < 20 and edge_key not in stats['edge_cap_keys']:
                        stats['edge_cap_keys'].append(edge_key)
                    # 使用确定性替换策略，避免同一输入多次运行结果不一致。
                    def edge_rank(item):
                        confidence_rank = {'high': 0, 'medium': 1, 'low': 2}.get(getattr(item, 'confidence', ''), 9)
                        owner_rank = 0 if getattr(item, 'owner_type', '') == 'business' else 1
                        file_rank = getattr(item, 'file', '') or ''
                        line_rank = int(getattr(item, 'line', 0) or 0)
                        return (confidence_rank, owner_rank, file_rank, line_rank)

                    worst_idx = max(range(len(existing)), key=lambda idx: edge_rank(existing[idx]))
                    if edge_rank(edge) < edge_rank(existing[worst_idx]):
                        existing[worst_idx] = edge

    for edge in initializer_edges:
        edge_keys = build_reverse_edge_keys(edge)
        for edge_key in edge_keys:
            existing = reverse_edges[edge_key]
            if len(existing) < 10000:
                existing.append(edge)
                stats['reverse_edges_indexed'] += 1
                stats['initializer_edges_indexed'] = stats.get('initializer_edges_indexed', 0) + 1
            else:
                stats['edge_cap_hits'] += 1
                if len(stats['edge_cap_keys']) < 20 and edge_key not in stats['edge_cap_keys']:
                    stats['edge_cap_keys'].append(edge_key)

    for edge_key, edges in reverse_edges.items():
        edges.sort(key=edge_sort_key)

    graph = SourceGraph(
        methods_by_id=methods_by_id,
        methods_by_qualified=dict(methods_by_qualified),
        methods_by_simple=dict(methods_by_simple),
        reverse_edges=dict(reverse_edges),
        reverse_edge_count=int(stats.get('reverse_edges_indexed') or 0),
        lookup_keys_by_symbol=lookup_keys_by_symbol,
        type_metadata=type_metadata  # 现在有数据了
    )
    jar_metadata_failures = list((jar_metadata or {}).get('failures') or [])
    if jar_metadata_failures:
        stats['parser_fallback_reasons']['jar_metadata_tool_failure'] = len(
            jar_metadata_failures
        )
        for failure in jar_metadata_failures[:20]:
            stats['parser_fallback_files'].append({
                'file': str(failure.get('jar_path') or ''),
                'reason': str(failure.get('reason_code') or 'JAR_METADATA_TOOL_FAILURE'),
            })
        graph.step5_evidence_failures = tuple(
            EvidenceFailure(
                stage=str(failure.get('stage') or 'step5.jar-metadata.javap'),
                reason_code=str(
                    failure.get('reason_code') or 'STEP5_JAR_METADATA_JAVAP_FAILED'
                ),
                blocking=bool(failure.get('blocking', True)),
                artifact=str(failure.get('jar_path') or ''),
                class_name=str(failure.get('class_fqcn') or ''),
                detail='; '.join(
                    f'{key}={value}'
                    for key, value in sorted(failure.items())
                    if value not in (None, '', [], ())
                ),
            )
            for failure in jar_metadata_failures
        )
    _step5_debug(
        'graph_build_complete',
        'finished enhanced source graph build',
        methods_indexed=len(methods_by_id),
        reverse_edge_keys=len(reverse_edges),
        lookup_key_symbols=len(lookup_keys_by_symbol),
        type_metadata_count=len(type_metadata),
        stats=stats,
    )

    return {
        'graph': graph,
        'type_metadata': type_metadata,
        'stats': stats,
        'analysis_cache': file_entries if retain_analysis_cache else [],
    }


def write_skip_summary(output_dir, input_path):
    """写入跳过摘要"""
    summary = {
        'status': 'skipped',
        'skip_reason': 'no_changed_apis',
        'generated_at': datetime.now().isoformat(),
        'input_file': input_path,
        'total_apis': 0,
        'notes': [
            '调用链分析未执行，因 all_changed_apis.csv 为空',
            '这不等于"无风险"，请检查 Step4 的输出'
        ]
    }

    summary_path = os.path.join(output_dir, 'summary.json')
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)


def _normalize_multi_value_option(raw_values):
    """兼容 argparse 的单次多值和重复传参两种写法。"""
    normalized = []
    for item in raw_values or []:
        if isinstance(item, (list, tuple)):
            candidates = item
        else:
            candidates = [item]
        for candidate in candidates:
            text = str(candidate or '').strip()
            if text:
                normalized.append(text)
    return normalized


# ══════════════════════════════════════════════════════════════════
# 主入口
# ══════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description='Step 5集成版：调用链影响分析（增强型）'
    )

    ap.add_argument(
        '--all-changed-apis',
        default='',
        help='变更API文件路径（默认从report-dir读取）'
    )

    ap.add_argument(
        '--jdk-scan-dir',
        default='',
        help='JDK扫描目录（用于过滤JDK removed API）'
    )

    ap.add_argument(
        '--source-dirs',
        nargs='+',
        default=['src/main/java'],
        help='业务源码目录列表'
    )

    ap.add_argument(
        '--dependency-source-mappings',
        action='append',
        nargs='+',
        default=[],
        help='依赖源码映射（可选，系统自动发现）'
    )

    ap.add_argument(
        '--report-dir',
        default='',
        help='报告目录'
    )

    ap.add_argument(
        '--output-dir',
        default='',
        help='输出目录（默认report-dir/evidence/call_chain）'
    )

    ap.add_argument(
        '--query-index',
        default='',
        help='调用链查询索引输出路径（默认report-dir/.runtime/indexes/s5_query_index.json）'
    )

    ap.add_argument(
        '--max-depth',
        type=int,
        default=5,
        help='最大追踪深度（默认5，与文档high confidence=最多5跳一致）'
    )

    ap.add_argument(
        '--allow-degraded',
        action='store_true',
        help='允许在缺少关键输入时继续执行'
    )

    ap.add_argument(
        '--max-methods',
        type=int,
        default=None,
        help='限制索引的方法数，用于回归测试和超大仓库保护'
    )
    ap.add_argument(
        '--debug-analysis',
        action='store_true',
        help='调试模式：输出Step5结构化调试日志（仅调试使用）'
    )
    ap.add_argument(
        '--debug-break',
        action='store_true',
        help='调试模式：遇到关键分析阻断时触发 breakpoint()（仅调试使用）'
    )

    args = ap.parse_args()
    args.dependency_source_mappings = _normalize_multi_value_option(args.dependency_source_mappings)

    try:
        return step5_integrated_main(args)
    except KeyboardInterrupt:
        print("\nStep 5 已被用户中断", file=sys.stderr)
        return 130
    except Exception as exc:
        print("\n❌ Step 5 执行失败：发生未捕获异常", file=sys.stderr)
        print(f"  异常类型：{type(exc).__name__}", file=sys.stderr)
        print(f"  异常信息：{exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1


def check_if_needs_bridge_sources(all_apis_path, report_dir, source_dirs=None, business_graph=None):
    """
    Check if dependency source mappings are needed (enhanced version)

    Extended rules:
      1. Business code直接命中变更 API 时，无需额外依赖源码映射
      2. 未命中直接调用且需要跨依赖边界时，要求依赖源码映射

    Improvements:
      - No longer solely dependent on coarse dependency classification
      - Only requires dependency source mappings if call chain actually needs to cross dependency boundary
      - If business code directly calls changed API, no extra mapping needed (can trace directly)
    """
    import csv

    # Read context
    context_path = str(_context_path(report_dir))
    context_source_dirs = []
    if os.path.exists(context_path):
        with open(context_path, 'r', encoding='utf-8') as f:
            context = json.load(f)
            context_source_dirs = context.get('source_dirs') or []

    # Collect all changed API coords and their api_names
    changed_apis = []
    try:
        with open_csv_read(all_apis_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                coord = row.get('coord', '')
                api_name = row.get('api_name', '')
                if coord and api_name:
                    changed_apis.append(dict(row))
    except (OSError, UnicodeError, csv.Error) as e:
        print(f"Error checking APIs: {e}", file=sys.stderr)
        return False

    if not changed_apis:
        return False

    requirements = check_apis_that_need_bridge(
        changed_apis,
        report_dir,
        source_dirs if source_dirs else context_source_dirs,
        business_graph
    )
    return any(info.get('needs_bridge') for info in requirements.values())


def _valid_dependency_source_mapping_coords(dependency_source_mappings):
    coords = set()
    for item in dependency_source_mappings or []:
        if not isinstance(item, str) or '=' not in item:
            continue
        coord, path = item.split('=', 1)
        coord = coord.strip()
        path = path.strip()
        if coord and path and os.path.isdir(path):
            coords.add(coord)
    return coords


def business_graph_precheck_incomplete(graph_stats):
    graph_stats = graph_stats or {}
    return bool(
        graph_stats.get('truncated')
        or critical_parser_fallback_reasons(graph_stats)
        or int(graph_stats.get('edge_cap_hits') or 0) > 0
    )


def check_apis_that_need_bridge(
    all_apis_input,
    report_dir,
    source_dirs=None,
    business_graph=None,
    dependency_source_mappings=None,
    business_graph_stats=None,
    runtime_dependency_catalog=None,
):
    """
    Check which specific APIs need dependency source mappings (api-level decision)

    Returns dict: {coord: {'needs_bridge': bool, 'reason': str}}
    """
    # Read context
    context_path = str(_context_path(report_dir))
    if os.path.exists(context_path):
        with open(context_path, 'r', encoding='utf-8') as f:
            context = json.load(f)
            # 如果没有传入 source_dirs，从上下文读取
            if source_dirs is None:
                source_dirs = context.get('source_dirs') or []

    available_mapping_coords = _valid_dependency_source_mapping_coords(dependency_source_mappings)
    available_runtime_coords = set((runtime_dependency_catalog or {}).get('by_coord', {}).keys())
    precheck_incomplete = business_graph_precheck_incomplete(business_graph_stats)

    result = {}
    if isinstance(all_apis_input, str):
        import csv
        try:
            with open_csv_read(all_apis_input) as f:
                all_apis = list(csv.DictReader(f))
        except (OSError, UnicodeError, csv.Error) as e:
            print(f"Error checking APIs: {e}", file=sys.stderr)
            return result
    else:
        all_apis = list(all_apis_input or [])

    for row in all_apis:
        coord = row.get('coord', '')
        api_name = row.get('api_name', '')
        key = build_api_identity_key(row)
        # Step5 always evaluates the final-artifact bytecode contract. An empty or
        # incomplete catalog is itself evidence of insufficient coverage, not a
        # reason to silently fall back to source-only negative conclusions.
        has_packaged_bytecode_fallback = (
            str(
                (runtime_dependency_catalog or {}).get('status') or ''
            ).strip()
            == 'complete'
        )

        if not coord or not api_name:
            continue

        if api_name.startswith('org.apache.commons.lang'):
            _report_step5_debug_event(
                'A',
                's5_call_chain_engine_integrated.py:bridge-check',
                'bridge-check evaluated commons-lang api',
                data={
                    'coord': coord,
                    'api_name': api_name,
                    'identity_key': key,
                    'available_runtime_coord_count': len(available_runtime_coords),
                    'sample_runtime_coords': sorted(list(available_runtime_coords))[:8],
                    'has_dependency_source_mapping': coord in available_mapping_coords,
                    'has_packaged_bytecode_fallback': has_packaged_bytecode_fallback,
                },
            )

        # 【关键修复】只有业务图找到直接的 caller 才算 direct usage
        # 原因：import 只能证明类型可见，不能证明方法被调用
        # 例如：import com.example.Foo; 只能说明 Foo 类可见
        # 但如果变更的是 Foo.bar() 方法，还需要业务代码真的调用了 bar()
        # 只有当业务源码图能找到 Foo.bar() 的调用边时，才说明变更方法真的被使用
        if business_graph and _has_direct_business_usage(row, business_graph):
            result[key] = {
                'needs_bridge': False,
                'reason': 'direct_business_usage',
                'coord': coord,
                'has_dependency_source_mapping': True,
                'has_packaged_bytecode_fallback': has_packaged_bytecode_fallback,
            }
            continue

        if precheck_incomplete:
            result[key] = {
                'needs_bridge': False,
                'reason': 'business_graph_precheck_incomplete',
                'coord': coord,
                'has_dependency_source_mapping': coord in available_mapping_coords,
                'has_packaged_bytecode_fallback': has_packaged_bytecode_fallback,
                'precheck_incomplete': True,
            }
            continue

        # 【移除】exact_class_imported 逻辑
        # import 了变更类不等于方法被调用，以下场景都可能导致误判：
        #   1. 业务只使用类的静态常量，不调用变更的方法
        #   2. 业务通过反射/接口间接调用，静态分析找不到
        #   3. 业务通过动态代理调用，静态分析找不到
        # 只要业务图没找到直接的调用边，就应该要求跨依赖补充映射

        # 默认：业务图没找到直接调用，需要依赖源码映射才能确认是否影响系统
        result[key] = {
            'needs_bridge': True,
            'reason': 'no_direct_call_found',
            'coord': coord,
            'has_dependency_source_mapping': coord in available_mapping_coords,
            'has_packaged_bytecode_fallback': has_packaged_bytecode_fallback,
        }

    return result


if __name__ == '__main__':
    sys.exit(main())
