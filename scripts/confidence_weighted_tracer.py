#!/usr/bin/env python3
"""
confidence_weighted_tracer.py

置信度加权反向追踪引擎

目标：证明变更 API 是否触达系统代码（不要求最外层入口）。

核心改进：
  ✓ 置信度加权深度（High:最多5跳, Medium:最多3跳, Low:立即停止）
  ✓ 系统代码触达识别（Service/Facade/Manager/Handler 等业务层）
  ✓ 框架边界识别
  ✓ 精确四态分类（reachable/uncertain/not_analyzed/not_found_in_static_analysis）

替换原有trace_one_api()的固定深度策略
"""

import csv
import json
import hashlib
import io
import os
import re
import struct
import sys
import tempfile
import time
import zipfile
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, deque
from dataclasses import dataclass, field, replace
from pathlib import Path
from threading import Event, Lock

from compat import run_cmd
from csv_io import open_csv_read, open_csv_write
from edge_truth import EDGE_IDENTITY_FIELDS, canonical_edge_identity
from progress_logging import emit_progress, should_log_progress, suggest_log_interval
from signature_utils import (
    canonical_api_identity,
    normalize_signature_for_identity,
    normalize_signature_for_lookup,
    signatures_match_identity,
    split_signature_params,
)
from enhanced_source_analyzer import CallEdge, MethodDef, _strip_strings_and_comments
from business_bytecode_graph import parse_classfile_calls
from artifact_safety import inspect_archive
from constant_impact import classify_constant_impact
from indirect_usage_analyzer import (
    api_key as indirect_api_key,
    parse_javap_indirect_references,
)
from step5_evidence_model import (
    ActivationEvidence,
    AnalysisOutcome,
    CoverageRecord,
    EvidenceAuthority,
    EvidenceConcern,
    EvidenceEnvelope,
    EvidenceFailure,
    ModuleScope,
    PhysicalCallEdge,
    PreservationEvidence,
    ReachabilityPath,
    TraceSeed,
    classify_module_scope,
    decide_envelope,
    thaw_evidence_value,
)


NON_BLOCKING_PARSER_FALLBACK_REASONS = {
    'prefer_tree_sitter_disabled',
    'unsupported_language_kotlin',
}

CALL_GRAPH_LIMITED_SYMBOL_KINDS = {
    'class',
    'field',
}

ANALYZER_EDGE_PROCEDURE_VERSION = 'java-upgrade-analyzer.analyzer-edge-ledger.v1'
ARTIFACT_PARSE_CACHE_PROCEDURE_VERSION = 'java-upgrade-analyzer.runtime-javap.v1'
RUNTIME_MEMBER_INDEX_CACHE_SCHEMA = 'java-upgrade-analyzer.runtime-member-index.v3'
ANALYZER_EDGE_PROCEDURE = (
    'Step5 executable bytecode matching at analyzer edge creation points'
)
_IMMUTABLE_ARTIFACT_PARSE_CACHE = {}
_IMMUTABLE_ARTIFACT_PARSE_CACHE_LOCK = Lock()
_IMMUTABLE_ARTIFACT_PARSE_INFLIGHT = {}
_IMMUTABLE_ARTIFACT_PARSE_CACHE_GENERATION = 0
_STEP5_PERF_STATS_INIT_LOCK = Lock()
ANALYZER_EDGE_FIELDS = (
    'artifact_sha256',
    'artifact_entry',
    'caller_owner',
    'caller_member',
    'caller_descriptor',
    'callee_owner',
    'callee_member',
    'callee_descriptor',
    'opcode_family',
    'instruction_offset',
    'api_identity',
    'edge_role',
    'evidence_path',
    'authority',
    'authority_version',
    'procedure',
    'procedure_version',
)


def _valid_sha256(value):
    value = str(value or '').strip()
    return len(value) == 64 and all(char in '0123456789abcdef' for char in value)


def clear_immutable_artifact_parse_cache():
    """Reset immutable parsed-bytecode entries for isolated process tests."""
    global _IMMUTABLE_ARTIFACT_PARSE_CACHE_GENERATION
    with _IMMUTABLE_ARTIFACT_PARSE_CACHE_LOCK:
        _IMMUTABLE_ARTIFACT_PARSE_CACHE_GENERATION += 1
        stale_events = list(_IMMUTABLE_ARTIFACT_PARSE_INFLIGHT.values())
        _IMMUTABLE_ARTIFACT_PARSE_CACHE.clear()
        _IMMUTABLE_ARTIFACT_PARSE_INFLIGHT.clear()
    for event in stale_events:
        event.set()


def _artifact_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _immutable_artifact_parse_cache_key(
    artifact_sha256, target_jdk, class_binary_name, multi_release_version,
    class_entry='',
):
    normalized_entry = str(class_entry or '').strip().lstrip('/')
    if not normalized_entry and class_binary_name:
        logical_entry = str(class_binary_name).replace('.', '/') + '.class'
        normalized_entry = (
            f'META-INF/versions/{multi_release_version}/{logical_entry}'
            if str(multi_release_version or '').isdigit()
            else logical_entry
        )
    return (
        str(artifact_sha256 or '').strip(),
        ARTIFACT_PARSE_CACHE_PROCEDURE_VERSION,
        str(target_jdk or '').strip(),
        str(class_binary_name or '').strip(),
        str(multi_release_version or '').strip(),
        normalized_entry,
    )


def _verified_final_artifact_provenance(graph):
    cached = getattr(graph, '_verified_final_artifact_provenance', None)
    if cached is not None:
        return cached
    result = {
        'complete': False,
        'artifact_sha256': '',
        'entries': set(),
        'entry_sha256': {},
        'nested_entries': {},
        'nested_entry_sha256': {},
        'failures': [],
    }
    report_dir = str(getattr(graph, 'report_dir', '') or '').strip()
    provenance_path = Path(report_dir) / 'evidence' / 'dependencies' / 'build_provenance.json'
    try:
        payload = json.loads(provenance_path.read_text(encoding='utf-8'))
        current = next(
            (item for item in payload.get('sides') or [] if item.get('side') == 'current'),
            {},
        )
        artifact_path = Path(str(current.get('artifact_path') or '').strip())
        expected_sha256 = str(current.get('artifact_sha256') or '').strip()
        safety = inspect_archive(artifact_path)
        if not safety.safe:
            raise ValueError(
                'artifact safety violation:'
                + ','.join(safety.details or safety.reason_codes)
            )
        snapshot = artifact_path.read_bytes()
        actual_sha256 = hashlib.sha256(snapshot).hexdigest()
        if not _valid_sha256(expected_sha256) or actual_sha256 != expected_sha256:
            raise ValueError('current final artifact SHA-256 is missing or mismatched')
        with zipfile.ZipFile(io.BytesIO(snapshot)) as outer:
            entries = {item.filename for item in outer.infolist() if not item.is_dir()}
            entry_sha256 = {}
            nested_entries = {}
            nested_entry_sha256 = {}
            nested_failures = []
            for entry in sorted(entries):
                entry_bytes = outer.read(entry)
                entry_sha256[entry] = hashlib.sha256(entry_bytes).hexdigest()
                if not entry.endswith('.jar'):
                    continue
                try:
                    with zipfile.ZipFile(io.BytesIO(entry_bytes)) as nested:
                        nested_entries[entry] = {
                            item.filename for item in nested.infolist() if not item.is_dir()
                        }
                        nested_entry_sha256[entry] = {
                            item.filename: hashlib.sha256(nested.read(item)).hexdigest()
                            for item in nested.infolist()
                            if not item.is_dir()
                        }
                except (OSError, zipfile.BadZipFile) as exc:
                    nested_failures.append(
                        f'{entry}:{type(exc).__name__}:{exc}'
                    )
                    continue
        result = {
            'complete': not nested_failures,
            'artifact_sha256': expected_sha256,
            'entries': entries,
            'entry_sha256': entry_sha256,
            'nested_entries': nested_entries,
            'nested_entry_sha256': nested_entry_sha256,
            'failures': nested_failures,
        }
    except (OSError, ValueError, KeyError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        result['failures'] = [f'{type(exc).__name__}:{exc}']
    for failure in result.get('failures') or []:
        _record_analyzer_ledger_failure(
            graph,
            'FINAL_ARTIFACT_PROVENANCE_UNREADABLE',
            artifact=str(provenance_path),
            error=failure,
        )
    setattr(graph, '_verified_final_artifact_provenance', result)
    return result


def _normalized_artifact_container_entry(edge):
    container_entry = str(
        (edge or {}).get('artifact_container_entry') or ''
    ).replace('\\', '/').strip('/')
    if container_entry.startswith('<') and container_entry.endswith('>'):
        return ''
    return container_entry


def _analyzer_edge_artifact_entry(graph, edge, provenance):
    class_entry = str((edge or {}).get('class_entry') or '').replace('\\', '/').strip('/')
    container_entry = _normalized_artifact_container_entry(edge)
    if not container_entry and str((edge or {}).get('coord') or '') != '__business__':
        return ''
    if container_entry and class_entry:
        nested = (provenance.get('nested_entries') or {}).get(container_entry)
        if nested is not None and class_entry in nested:
            return f'{container_entry}!/{class_entry}'
    if class_entry:
        candidates = [
            class_entry,
            f'BOOT-INF/classes/{class_entry}',
            f'WEB-INF/classes/{class_entry}',
        ]
        for candidate in candidates:
            if candidate in (provenance.get('entries') or set()):
                return candidate
    return ''


def _normalized_instruction_offset(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if value >= 0 else None
    text = str(value).strip() if value is not None else ''
    return text if text.isdigit() else None


def _evidence_bytes_match_final_artifact(edge, provenance, artifact_entry):
    jar_path = str((edge or {}).get('jar_path') or '').strip()
    class_entry = str((edge or {}).get('class_entry') or '').replace('\\', '/').strip('/')
    if not jar_path or not class_entry or not os.path.isfile(jar_path):
        return False
    container_entry = _normalized_artifact_container_entry(edge)
    try:
        if container_entry:
            expected_jar_sha = (provenance.get('entry_sha256') or {}).get(container_entry)
            if not expected_jar_sha:
                return False
            scanned_jar = Path(jar_path).read_bytes()
            if hashlib.sha256(scanned_jar).hexdigest() != expected_jar_sha:
                return False
            expected_class_sha = (
                (provenance.get('nested_entry_sha256') or {}).get(container_entry) or {}
            ).get(class_entry)
            if not expected_class_sha:
                return False
            with zipfile.ZipFile(io.BytesIO(scanned_jar)) as archive:
                return hashlib.sha256(archive.read(class_entry)).hexdigest() == expected_class_sha

        expected_class_sha = (provenance.get('entry_sha256') or {}).get(artifact_entry)
        if not expected_class_sha:
            return False
        with zipfile.ZipFile(jar_path) as archive:
            scanned_class = archive.read(class_entry)
        return hashlib.sha256(scanned_class).hexdigest() == expected_class_sha
    except (OSError, KeyError, zipfile.BadZipFile):
        return False


def _normalize_analyzer_edge(graph, api_row, edge):
    provenance = _verified_final_artifact_provenance(graph)
    artifact_entry = _analyzer_edge_artifact_entry(graph, edge, provenance)
    instruction_offset = _normalized_instruction_offset(
        (edge or {}).get('instruction_offset')
    )
    evidence_bound = bool(
        provenance.get('complete')
        and artifact_entry
        and _evidence_bytes_match_final_artifact(edge, provenance, artifact_entry)
    )
    row = {
        'artifact_sha256': provenance.get('artifact_sha256') or '',
        'artifact_entry': artifact_entry,
        'caller_owner': str(
            (edge or {}).get('caller_owner') or (edge or {}).get('class_fqcn') or ''
        ).strip(),
        'caller_member': str((edge or {}).get('consumer_method') or '').strip(),
        'caller_descriptor': str((edge or {}).get('consumer_descriptor') or '').strip(),
        'callee_owner': str((edge or {}).get('callee_owner') or '').strip(),
        'callee_member': str((edge or {}).get('callee_member') or '').strip(),
        'callee_descriptor': str((edge or {}).get('callee_descriptor') or '').strip(),
        'opcode_family': str((edge or {}).get('opcode_family') or '').strip(),
        'instruction_offset': instruction_offset or '',
        'api_identity': build_api_identity_key(api_row or {}),
        'edge_role': str((edge or {}).get('edge_role') or 'external_consumer').strip(),
        'evidence_path': str((edge or {}).get('jar_path') or '').strip()
        + (f'!/{str((edge or {}).get("class_entry") or "").strip("/")}' if (edge or {}).get('class_entry') else ''),
        'authority': 'java-upgrade-analyzer',
        'authority_version': ANALYZER_EDGE_PROCEDURE_VERSION,
        'procedure': ANALYZER_EDGE_PROCEDURE,
        'procedure_version': ANALYZER_EDGE_PROCEDURE_VERSION,
    }
    complete = bool(
        provenance.get('complete')
        and artifact_entry
        and instruction_offset is not None
        and evidence_bound
        and all(str(row.get(field) or '').strip() for field in EDGE_IDENTITY_FIELDS)
    )
    if provenance.get('complete') and artifact_entry and not evidence_bound:
        _record_analyzer_ledger_failure(
            graph,
            'EDGE_EVIDENCE_BYTES_MISMATCH',
            artifact_entry=artifact_entry,
            evidence_path=row.get('evidence_path', ''),
        )
    return row, complete


def record_analyzer_edge(graph, api_row, edge):
    if graph is None:
        return None
    graph._analyzer_edge_discovery_count = int(
        getattr(graph, '_analyzer_edge_discovery_count', 0) or 0
    ) + 1
    row, complete = _normalize_analyzer_edge(graph, api_row, edge)
    if not complete:
        graph._analyzer_edge_incomplete_count = int(
            getattr(graph, '_analyzer_edge_incomplete_count', 0) or 0
        ) + 1
        return None
    analyzer_edges = getattr(graph, 'analyzer_edges', None)
    if analyzer_edges is None:
        analyzer_edges = {}
        graph.analyzer_edges = analyzer_edges
    identity = physical_analyzer_edge_identity(row)
    current = analyzer_edges.get(identity)
    if current is None or canonical_analyzer_edge_sort_key(row) < canonical_analyzer_edge_sort_key(current):
        analyzer_edges[identity] = row
    return row


def canonical_analyzer_edge_sort_key(row):
    return tuple(str((row or {}).get(field) or '') for field in (
        *EDGE_IDENTITY_FIELDS,
        'artifact_entry',
        'api_identity',
        'edge_role',
        'instruction_offset',
    ))


def physical_analyzer_edge_identity(row):
    return '|'.join((
        str((row or {}).get('api_identity') or ''),
        canonical_edge_identity(row),
        str((row or {}).get('artifact_entry') or ''),
        str((row or {}).get('caller_owner') or ''),
        str((row or {}).get('caller_member') or ''),
        str((row or {}).get('caller_descriptor') or ''),
        str((row or {}).get('instruction_offset') or ''),
    ))


def _record_analyzer_ledger_failure(graph, reason, **fields):
    if graph is None:
        return
    reason_code = str(reason or 'UNKNOWN_ANALYZER_FAILURE').strip().upper()
    failures = getattr(graph, '_analyzer_edge_failures', None)
    if failures is None:
        failures = set()
        graph._analyzer_edge_failures = failures
    failures.add((
        reason_code,
        tuple(sorted((str(key), str(value or '')) for key, value in fields.items())),
    ))
    typed_failure = EvidenceFailure(
        stage='analyzer-edge-collection',
        reason_code=reason_code,
        blocking=True,
        api_identity=str(fields.get('api_identity') or ''),
        artifact=str(
            fields.get('artifact')
            or fields.get('jar_path')
            or fields.get('file')
            or ''
        ),
        class_name=str(
            fields.get('class_name')
            or fields.get('class_binary_name')
            or fields.get('class_entry')
            or ''
        ),
        detail='; '.join(
            f'{key}={value}'
            for key, value in sorted(fields.items())
            if value not in (None, '')
        ),
    )
    typed_failures = tuple(getattr(graph, 'step5_evidence_failures', ()) or ())
    if typed_failure not in typed_failures:
        graph.step5_evidence_failures = typed_failures + (typed_failure,)


def _record_analyzer_scan_failures(graph, failures):
    for failure in failures or []:
        if isinstance(failure, dict):
            reason = failure.get('reason') or 'bytecode_scan_failure'
            _record_analyzer_ledger_failure(
                graph,
                reason,
                **{key: value for key, value in failure.items() if key != 'reason'},
            )
        else:
            _record_analyzer_ledger_failure(graph, str(failure or 'bytecode_scan_failure'))


def write_analyzer_edge_ledger(graph, graph_stats=None):
    graph_stats = graph_stats if graph_stats is not None else {}
    provenance = _verified_final_artifact_provenance(graph)
    rows = sorted(
        list((getattr(graph, 'analyzer_edges', {}) or {}).values()),
        key=canonical_analyzer_edge_sort_key,
    )
    discovery_count = int(getattr(graph, '_analyzer_edge_discovery_count', 0) or 0)
    incomplete_count = int(getattr(graph, '_analyzer_edge_incomplete_count', 0) or 0)
    failures = set(getattr(graph, '_analyzer_edge_failures', set()) or set())
    if not provenance.get('complete'):
        failures.add(('final_artifact_provenance_invalid', ()))
    if incomplete_count:
        failures.add(('incomplete_edge_metadata', (('count', str(incomplete_count)),)))
    graph_stats['analyzer_edge_count'] = len(rows)
    graph_stats['duplicate_edge_count'] = max(0, discovery_count - incomplete_count - len(rows))
    graph_stats['edge_ledger_failure_count'] = len(failures)
    graph_stats['edge_ledger_complete'] = bool(
        provenance.get('complete') and not incomplete_count and not failures
    )
    report_dir = str(getattr(graph, 'report_dir', '') or '').strip()
    if not report_dir:
        return ''
    output_path = Path(report_dir) / 'evidence' / 'call_chain' / 'analyzer_edges.csv'
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open_csv_write(output_path) as handle:
        writer = csv.DictWriter(handle, fieldnames=ANALYZER_EDGE_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return str(output_path)


def _env_flag_enabled(name):
    return str(os.environ.get(name, '') or '').strip().lower() in {'1', 'true', 'yes', 'on'}


def _step5_debug_enabled():
    return _env_flag_enabled('JUA_STEP5_DEBUG')


def _step5_debug_break_enabled():
    return _env_flag_enabled('JUA_STEP5_DEBUG_BREAK')


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
    print(f"[step5-debug] {json.dumps(payload, ensure_ascii=False, sort_keys=True)}", file=sys.stderr)


def _step5_debug_break(topic, **fields):
    if not _step5_debug_break_enabled():
        return
    _step5_debug(topic, 'breakpoint triggered', **fields)
    breakpoint()


def _step5_bytecode_javap_workers():
    value = str(os.environ.get('JUA_STEP5_BYTECODE_JAVAP_WORKERS') or '').strip()
    if value:
        try:
            return max(1, min(16, int(value)))
        except ValueError:
            return 4
    return 4


def _step5_runtime_member_index_min_jars():
    value = str(os.environ.get('JUA_STEP5_RUNTIME_MEMBER_INDEX_MIN_JARS') or '').strip()
    if value:
        try:
            return max(1, int(value))
        except ValueError:
            return 50
    return 50


def _step5_runtime_member_index_max_bytes():
    value = str(os.environ.get('JUA_STEP5_RUNTIME_MEMBER_INDEX_MAX_BYTES') or '').strip()
    if value:
        try:
            return max(1, int(value))
        except ValueError:
            return 32 * 1024 * 1024
    return 32 * 1024 * 1024


def _runtime_member_index_catalog_bytes(graph, catalog_entries):
    cached = getattr(graph, '_runtime_member_index_catalog_bytes', None)
    if cached is not None:
        return int(cached)
    total = 0
    for item in catalog_entries or []:
        jar_path = str(item.get('jar_path') or '').strip()
        if not jar_path:
            continue
        try:
            total += int(os.path.getsize(jar_path))
        except OSError:
            continue
    setattr(graph, '_runtime_member_index_catalog_bytes', total)
    return total


def _should_prefer_runtime_member_candidate_index(graph, catalog_entries):
    if bool(getattr(graph, '_prefer_runtime_dependency_member_candidate_index', False)):
        return True, 'explicit'
    entry_count = len(catalog_entries or [])
    threshold = _step5_runtime_member_index_min_jars()
    if entry_count >= threshold:
        catalog_bytes = _runtime_member_index_catalog_bytes(graph, catalog_entries)
        max_bytes = _step5_runtime_member_index_max_bytes()
        if catalog_bytes > max_bytes:
            return True, f'large_artifact_catalog:{catalog_bytes}>{max_bytes}'
        return True, f'large_runtime_catalog:{entry_count}>={threshold}'
    return False, ''


def _step5_perf_state(graph):
    if graph is None:
        return None, None
    with _STEP5_PERF_STATS_INIT_LOCK:
        lock = getattr(graph, '_step5_perf_lock', None)
        if lock is None:
            lock = Lock()
            setattr(graph, '_step5_perf_lock', lock)
        stats = getattr(graph, '_step5_perf_stats', None)
        if stats is None:
            stats = {
                'bytecode_scan': defaultdict(float),
                'bytecode_expand': defaultdict(float),
                'trace': defaultdict(float),
            }
            setattr(graph, '_step5_perf_stats', stats)
    return stats, lock


def _step5_perf_stats(graph):
    stats, _lock = _step5_perf_state(graph)
    return stats


def _perf_add(graph, section, key, value=1):
    stats, lock = _step5_perf_state(graph)
    if stats is None:
        return
    with lock:
        stats.setdefault(section, defaultdict(float))[key] += value


def _perf_max(graph, section, key, value):
    stats, lock = _step5_perf_state(graph)
    if stats is None:
        return
    with lock:
        bucket = stats.setdefault(section, defaultdict(float))
        bucket[key] = max(bucket.get(key, 0), value)


def _perf_record_top(graph, section, key, item, elapsed_key='elapsed_sec', limit=20):
    stats, lock = _step5_perf_state(graph)
    if stats is None or not isinstance(item, dict):
        return
    with lock:
        bucket = stats.setdefault(section, defaultdict(float))
        values = bucket.get(key)
        if not isinstance(values, list):
            values = []
            bucket[key] = values
        values.append(dict(item))
        values.sort(key=lambda row: (
            -float(row.get(elapsed_key) or 0),
            json.dumps(row, sort_keys=True, default=str, ensure_ascii=True),
        ))
        del values[limit:]


def _perf_append(graph, section, key, item):
    stats, lock = _step5_perf_state(graph)
    if stats is None or not isinstance(item, dict):
        return
    with lock:
        bucket = stats.setdefault(section, defaultdict(float))
        values = bucket.get(key)
        if not isinstance(values, list):
            values = []
            bucket[key] = values
        values.append(dict(item))


def _peak_rss_mb():
    try:
        import resource

        raw = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss or 0.0)
    except (ImportError, OSError, ValueError):
        return 0.0
    divisor = 1024.0 * 1024.0 if sys.platform == 'darwin' else 1024.0
    return raw / divisor


def _record_actual_artifact_class_parse(
    graph, artifact_sha256, target_jdk, class_binary_name, multi_release_version,
    class_entry='', parser_kind='',
):
    stats, lock = _step5_perf_state(graph)
    if stats is None:
        return
    physical_class_key = (
        str(artifact_sha256 or '').strip(),
        ARTIFACT_PARSE_CACHE_PROCEDURE_VERSION,
        str(target_jdk or '').strip(),
        str(class_binary_name or '').strip(),
        str(multi_release_version or '').strip(),
    )
    with lock:
        bucket = stats.setdefault('bytecode_scan', defaultdict(float))
        bucket['class_entries_parsed'] += 1
        if not _valid_sha256(artifact_sha256):
            return
        parsed_classes = getattr(graph, '_step5_parsed_artifact_classes', None)
        if parsed_classes is None:
            parsed_classes = set()
            setattr(graph, '_step5_parsed_artifact_classes', parsed_classes)
        if physical_class_key in parsed_classes:
            bucket['duplicate_class_scans'] += 1
            samples = bucket.setdefault('duplicate_class_scan_samples', [])
            if len(samples) < 20:
                samples.append({
                    'artifact_sha256': physical_class_key[0],
                    'target_jdk': physical_class_key[2],
                    'class_binary_name': physical_class_key[3],
                    'multi_release_version': physical_class_key[4],
                    'class_entry': str(class_entry or ''),
                    'parser_kind': str(parser_kind or ''),
                })
        parsed_classes.add(physical_class_key)


def _round_perf_value(value):
    if isinstance(value, float):
        return round(value, 3)
    if isinstance(value, list):
        return [_round_perf_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _round_perf_value(item) for key, item in value.items()}
    return value


def _finalize_step5_perf_stats(graph):
    stats, lock = _step5_perf_state(graph)
    if not stats:
        return {}
    with lock:
        snapshot = {
            section: {
                key: ([dict(item) if isinstance(item, dict) else item for item in value]
                      if isinstance(value, list) else value)
                for key, value in dict(values or {}).items()
            }
            for section, values in stats.items()
        }
    finalized = {}
    for section, values in snapshot.items():
        bucket = {}
        for key, value in dict(values or {}).items():
            if section == 'bytecode_scan' and key == 'class_parse_elapsed_sec':
                bucket[key] = round(float(value or 0.0), 6)
            else:
                bucket[key] = _round_perf_value(value)
        finalized[section] = bucket
    return finalized


def _merge_step5_perf_stats(target, updates):
    if not isinstance(target, dict) or not isinstance(updates, dict):
        return
    for section, values in updates.items():
        if isinstance(values, dict) and isinstance(target.get(section), dict):
            target[section].update(values)
        else:
            target[section] = values


def _emit_step5_perf_summary(graph):
    perf = _finalize_step5_perf_stats(graph)
    if not perf:
        return
    scan = perf.get('bytecode_scan') or {}
    expand = perf.get('bytecode_expand') or {}
    trace = perf.get('trace') or {}
    emit_progress(
        "step5",
        "perf",
        (
            "性能统计："
            f"scan_elapsed={scan.get('elapsed_sec', 0)}s，"
            f"scan_visited_classes={int(scan.get('visited_classes', 0))}，"
            f"scan_javap_tasks={int(scan.get('javap_tasks', 0))}，"
            f"expand_elapsed={expand.get('elapsed_sec', 0)}s，"
            f"expand_calls={int(expand.get('calls', 0))}，"
            f"expand_cache_hits={int(expand.get('candidate_cache_hits', 0))}，"
            f"member_index_builds={int(expand.get('member_index_builds', 0))}，"
            f"trace_elapsed={trace.get('elapsed_sec', 0)}s"
        ),
    )
    slow_apis = (trace.get('slow_api_traces') or [])[:5]
    slow_jars = (scan.get('slow_jar_scans') or [])[:5]
    slow_lookups = (expand.get('slow_runtime_lookups') or [])[:5]
    if slow_apis or slow_jars or slow_lookups:
        def _fmt(items, label_key):
            parts = []
            for item in items:
                label = str(item.get(label_key) or item.get('api_name') or item.get('lookup') or item.get('coord') or '<unknown>')
                parts.append(f"{label[:80]}={item.get('elapsed_sec', 0)}s")
            return "; ".join(parts)

        emit_progress(
            "step5",
            "perf",
            (
                "慢项Top："
                f"apis=[{_fmt(slow_apis, 'api_name')}]，"
                f"jars=[{_fmt(slow_jars, 'coord')}]，"
                f"lookups=[{_fmt(slow_lookups, 'lookup')}]"
            ),
        )


def _debug_trace_result(topic, result, **fields):
    _step5_debug(
        topic,
        'trace api produced result',
        api_name=getattr(result, 'api_name', ''),
        api_signature=getattr(result, 'api_signature', ''),
        analysis_status=getattr(result, 'analysis_status', ''),
        reason_code=getattr(result, 'reason_code', ''),
        match_provenance=getattr(result, 'match_provenance', ''),
        call_path_count=len(getattr(result, 'call_paths', []) or []),
        **fields,
    )


@dataclass
class TraceResult:
    """追踪结果"""
    api_name: str
    api_simple: str
    api_signature: str
    symbol_kind: str
    change_type: str
    coord: str
    severity: str
    confirmed: bool
    source: str
    analysis_scope: str
    analysis_status: str  # reachable / uncertain / not_analyzed
    direct_callers: int
    is_reachable: bool
    reachable_note: str
    business_reach_depth: int
    dependency_chain_coords: list
    call_paths: list
    evidence_paths: list
    reason_code: str
    verification_commands: list
    hops: list
    confidence_score: float
    critical_nodes_hit: list
    match_provenance: str = ''
    match_tier: int = -1
    # Step4's compared versions are carried into user-facing evidence instead
    # of forcing reviewers to look up the coordinate in a separate file.
    old_version: str = ''
    new_version: str = ''
    # 全部终止链路的人工复核视图；call_paths/evidence_paths 保留兼容语义。
    path_details: list = field(default_factory=list)
    capability_coverage: dict = field(default_factory=dict)
    compile_impact: str = ''
    runtime_link_impact: str = ''
    constant_impact_evidence: dict = field(default_factory=dict)


@dataclass
class TraceDraft:
    """Mutable rendering/evidence workspace with no provisional conclusion."""
    api_name: str
    api_simple: str
    api_signature: str
    symbol_kind: str
    change_type: str
    coord: str
    severity: str
    confirmed: bool
    source: str
    analysis_scope: str
    dependency_chain_coords: list = field(default_factory=list)
    call_paths: list = field(default_factory=list)
    evidence_paths: list = field(default_factory=list)
    verification_commands: list = field(default_factory=list)
    hops: list = field(default_factory=list)
    confidence_score: float = 1.0
    critical_nodes_hit: list = field(default_factory=list)
    match_provenance: str = ''
    match_tier: int = -1
    old_version: str = ''
    new_version: str = ''
    path_details: list = field(default_factory=list)
    capability_coverage: dict = field(default_factory=dict)
    compile_impact: str = ''
    runtime_link_impact: str = ''
    constant_impact_evidence: dict = field(default_factory=dict)
    envelope_paths: tuple = field(default_factory=tuple)
    envelope_failures: tuple = field(default_factory=tuple)
    envelope_concerns: tuple = field(default_factory=tuple)
    envelope_preservation: object = None
    envelope_coverage: tuple = field(default_factory=tuple)


def render_trace_result(seed: TraceSeed, outcome: AnalysisOutcome) -> TraceResult:
    """Materialize the legacy result contract at the terminal policy boundary."""
    decision = outcome.decision
    return TraceResult(
        api_name=seed.api_name,
        api_simple=seed.api_simple,
        api_signature=seed.api_signature,
        symbol_kind=seed.symbol_kind,
        change_type=seed.change_type,
        coord=seed.coord,
        severity=seed.severity,
        confirmed=seed.confirmed,
        source=seed.source,
        analysis_scope=seed.analysis_scope,
        analysis_status=decision.analysis_status,
        direct_callers=decision.direct_callers,
        is_reachable=decision.is_reachable,
        reachable_note=decision.reachable_note,
        business_reach_depth=decision.business_reach_depth,
        dependency_chain_coords=thaw_evidence_value(outcome.dependency_chain_coords),
        call_paths=thaw_evidence_value(outcome.call_paths),
        evidence_paths=thaw_evidence_value(outcome.evidence_paths),
        reason_code=decision.reason_code,
        verification_commands=thaw_evidence_value(outcome.verification_commands),
        hops=thaw_evidence_value(outcome.hops),
        confidence_score=outcome.confidence_score,
        critical_nodes_hit=thaw_evidence_value(outcome.critical_nodes_hit),
        match_provenance=outcome.match_provenance,
        match_tier=outcome.match_tier,
        old_version=seed.old_version,
        new_version=seed.new_version,
        path_details=thaw_evidence_value(outcome.path_details),
        capability_coverage=thaw_evidence_value(dict(outcome.capability_coverage)),
        compile_impact=outcome.compile_impact,
        runtime_link_impact=outcome.runtime_link_impact,
        constant_impact_evidence=thaw_evidence_value(
            dict(outcome.constant_impact_evidence)
        ),
    )


def _trace_target_identity(result):
    return canonical_api_identity({
        'coord': getattr(result, 'coord', ''),
        'api_name': getattr(result, 'api_name', ''),
        'api_signature': getattr(result, 'api_signature', ''),
        'symbol_kind': getattr(result, 'symbol_kind', ''),
        'change_type': getattr(result, 'change_type', ''),
    })


def _target_reverse_path_context(api_row, graph):
    """Return collectors and caller symbols that can participate in this target's paths."""
    reverse_edges = getattr(graph, 'reverse_edges', {}) or {}
    api_name = str((api_row or {}).get('api_name') or '').strip()
    if not api_name or not reverse_edges:
        return set(), set()
    normalized_api_name = api_name.replace('$', '.')
    api_signature = normalize_signature_for_identity(
        str((api_row or {}).get('api_signature') or '').replace('$', '.')
    )
    key_index = getattr(graph, '_step5_reverse_keys_by_unsigned', None)
    if not key_index or key_index[0] != len(reverse_edges):
        grouped = defaultdict(list)
        for key in reverse_edges:
            text = str(key)
            grouped[text.split('(', 1)[0].replace('$', '.')].append(text)
        keys_by_unsigned = dict(grouped)
        setattr(
            graph, '_step5_reverse_keys_by_unsigned',
            (len(reverse_edges), keys_by_unsigned),
        )
    else:
        keys_by_unsigned = key_index[1]

    def matching_keys(symbol, required_signature=''):
        symbol = str(symbol or '')
        unsigned = symbol.split('(', 1)[0].replace('$', '.')
        signature = required_signature or normalize_signature_for_identity(
            (('(' + symbol.split('(', 1)[1]) if '(' in symbol else '').replace('$', '.')
        )
        candidates = tuple(keys_by_unsigned.get(unsigned, ()))
        if not signature:
            return candidates
        return tuple(
            key for key in candidates
            if signatures_match_identity(
                (('(' + key.split('(', 1)[1]) if '(' in key else '').replace('$', '.'),
                signature,
            )
        )

    pending = deque(matching_keys(normalized_api_name, api_signature))
    visited = set()
    collectors = set()
    symbols = set()
    while pending:
        current = pending.popleft()
        if current in visited:
            continue
        visited.add(current)
        for edge in reverse_edges.get(current, ()) or ():
            collector = str(getattr(edge, 'collector', '') or '').strip()
            if collector:
                collectors.add(collector)
            caller_id = str(getattr(edge, 'caller_symbol_id', '') or '').strip()
            caller_key = str(getattr(edge, 'caller_qualified_key', '') or '').strip()
            for caller in (caller_id, caller_key):
                if not caller:
                    continue
                symbols.add(caller)
                symbols.add(caller.split('(', 1)[0])
                for key in matching_keys(caller):
                    if key not in visited:
                        pending.append(key)
    return collectors, symbols


def _path_subject_matches(subject, symbols):
    subject = str(subject or '').strip().split('(', 1)[0]
    return bool(subject) and any(
        subject == symbol or subject.startswith(f'{symbol}.') or symbol.startswith(f'{subject}.')
        for symbol in symbols
    )


def _new_trace_draft(api_row, graph=None):
    draft = TraceDraft(
        api_name=str(api_row.get('api_name') or '').strip(),
        api_simple=api_row.get('api_simple', ''),
        api_signature=api_row.get('api_signature', ''),
        symbol_kind=get_symbol_kind(api_row),
        change_type=api_row.get('change_type', ''),
        coord=api_row.get('coord', ''),
        severity=api_row.get('severity', ''),
        confirmed=api_row.get('confirmed') == 'true',
        source=api_row.get('source', ''),
        analysis_scope=api_row.get('analysis_scope', 'api'),
        old_version=str(api_row.get('old_version') or '').strip(),
        new_version=str(api_row.get('new_version') or '').strip(),
        capability_coverage=_capability_coverage_for_api(api_row, graph),
    )
    source_identity = indirect_api_key(api_row)
    target_identity = _trace_target_identity(draft)
    path_collectors, path_symbols = _target_reverse_path_context(api_row, graph)
    path_scoped_collectors = {
        record.collector
        for record in tuple(getattr(graph, 'step5_collector_coverage', ()) or ())
        if getattr(record, 'scope', 'api') == 'path'
    }
    relevant_path_concerns = tuple(
        concern
        for concern in tuple(getattr(graph, 'step5_evidence_concerns', ()) or ())
        if (
            concern.api_identity in {source_identity, target_identity}
            or (
                not concern.api_identity
                and concern.stage in path_scoped_collectors
                and _path_subject_matches(concern.class_name, path_symbols)
            )
        )
    )
    coverage_by_collector = defaultdict(list)
    for record in tuple(getattr(graph, 'step5_collector_coverage', ()) or ()):
        if record.api_identity not in {
            source_identity, target_identity, record.collector,
        }:
            continue
        if (
            getattr(record, 'scope', 'api') == 'path'
            and record.collector not in path_collectors
            and not any(concern.stage == record.collector for concern in relevant_path_concerns)
        ):
            continue
        coverage_by_collector[record.collector].append(record)
    coverage_status_rank = {
        'not_applicable': 0,
        'complete': 1,
        'partial': 2,
        'insufficient': 3,
    }
    merged_coverage = []
    for collector in sorted(coverage_by_collector):
        records = coverage_by_collector[collector]
        applicable = [record for record in records if record.applicable]
        candidates = applicable or records
        selected = max(
            candidates,
            key=lambda record: coverage_status_rank.get(record.status, 4),
        )
        reason_codes = tuple(sorted({
            reason_code
            for record in records
            for reason_code in record.reason_codes
        }))
        merged_coverage.append(replace(
            selected,
            api_identity=target_identity,
            reason_codes=reason_codes,
            applicable=bool(applicable),
        ))
    relevant_identities = {'', source_identity, target_identity}
    draft.envelope_coverage = tuple(merged_coverage)
    draft.envelope_failures = tuple(
        failure
        for failure in tuple(getattr(graph, 'step5_evidence_failures', ()) or ())
        if failure.api_identity in relevant_identities
    )
    draft.envelope_concerns = tuple(
        replace(concern, api_identity=target_identity)
        for concern in tuple(getattr(graph, 'step5_evidence_concerns', ()) or ())
        if (
            concern.api_identity in {source_identity, target_identity}
            or concern in relevant_path_concerns
        )
    )
    return draft


def _merge_evidence_items(existing, additions):
    merged = list(existing or ())
    for item in tuple(additions or ()):
        if item not in merged:
            merged.append(item)
    return tuple(merged)


def _finalize_trace_draft(draft):
    target_identity = _trace_target_identity(draft)
    envelope = EvidenceEnvelope(
        target_identity=target_identity,
        paths=tuple(draft.envelope_paths),
        failures=tuple(draft.envelope_failures),
        concerns=tuple(draft.envelope_concerns),
        preservation=draft.envelope_preservation,
        coverage=tuple(draft.envelope_coverage),
    )
    decision = decide_envelope(envelope)
    seed = TraceSeed(
        api_name=draft.api_name,
        api_simple=draft.api_simple,
        api_signature=draft.api_signature,
        symbol_kind=draft.symbol_kind,
        change_type=draft.change_type,
        coord=draft.coord,
        severity=draft.severity,
        confirmed=draft.confirmed,
        source=draft.source,
        analysis_scope=draft.analysis_scope,
        old_version=draft.old_version,
        new_version=draft.new_version,
    )
    outcome = AnalysisOutcome(
        decision=decision,
        dependency_chain_coords=tuple(draft.dependency_chain_coords),
        call_paths=tuple(draft.call_paths),
        evidence_paths=tuple(draft.evidence_paths),
        path_details=tuple(draft.path_details),
        verification_commands=tuple(draft.verification_commands),
        hops=tuple(draft.hops),
        confidence_score=draft.confidence_score,
        critical_nodes_hit=tuple(draft.critical_nodes_hit),
        match_provenance=draft.match_provenance,
        match_tier=draft.match_tier,
        capability_coverage=tuple(sorted(draft.capability_coverage.items())),
        compile_impact=draft.compile_impact,
        runtime_link_impact=draft.runtime_link_impact,
        constant_impact_evidence=tuple(sorted(draft.constant_impact_evidence.items())),
    )
    return render_trace_result(seed, outcome)


def _apply_evidence_decision(
    result,
    paths=(),
    failures=(),
    *,
    concerns=(),
    preservation=None,
    complete_scan=False,
    coverage=(),
):
    target_identity = _trace_target_identity(result)
    coverage_items = tuple(coverage)
    if complete_scan and not coverage_items:
        coverage_items = (CoverageRecord(
            collector="legacy_complete_scan",
            api_identity=target_identity,
            status="complete",
        ),)
    if isinstance(result, TraceDraft):
        result.envelope_paths = _merge_evidence_items(result.envelope_paths, paths)
        result.envelope_failures = _merge_evidence_items(
            result.envelope_failures, failures
        )
        result.envelope_concerns = _merge_evidence_items(
            result.envelope_concerns, concerns
        )
        if preservation is not None:
            result.envelope_preservation = preservation
        result.envelope_coverage = _merge_evidence_items(
            result.envelope_coverage, coverage_items
        )
        return result
    raise TypeError("evidence builders require TraceDraft before terminal rendering")


def _apply_blocking_failure(result, stage, reason_code, note, paths=()):
    return _apply_evidence_decision(result, paths=paths, failures=(EvidenceFailure(
        stage=stage,
        reason_code=reason_code,
        blocking=True,
        api_identity=changed_api_display_target(result),
        detail=note,
    ),))


def _apply_uncertainty(result, stage, reason_code, note, paths=()):
    return _apply_evidence_decision(result, paths=paths, concerns=(EvidenceConcern(
        stage=stage,
        reason_code=reason_code,
        detail=note,
        api_identity=changed_api_display_target(result),
    ),))


def _iter_business_methods(graph):
    for method_def in (getattr(graph, 'methods_by_id', {}) or {}).values():
        if getattr(method_def, 'owner_type', '') == 'business' and not getattr(method_def, 'is_test', False):
            yield method_def


def _build_direct_usage_result(result, method_def, reason_code, note, evidence_type, display_target):
    caller_name = getattr(method_def, 'qualified_key', '') or getattr(method_def, 'symbol_id', '')
    result.call_paths = [f"{caller_name} -> {display_target}"]
    result.evidence_paths = [[
        {
            'caller_symbol': caller_name,
            'callee_key': display_target,
            'evidence_type': evidence_type,
            'confidence': 'high',
            'file': getattr(method_def, 'file', ''),
            'line': getattr(method_def, 'line', 0),
        }
    ]]
    return _apply_evidence_decision(result, paths=(ReachabilityPath(
        path_text=result.call_paths[0],
        entry_scope=ModuleScope.BUSINESS_CLASSES,
        complete=True,
        reason_code=reason_code,
        note=note,
        depth=1,
    ),))


def _build_direct_usage_results(result, matches, reason_code, note, display_target):
    unique_matches = []
    seen = set()
    for method_def, evidence_type in matches or []:
        caller_name = getattr(method_def, 'qualified_key', '') or getattr(method_def, 'symbol_id', '')
        identity = (
            caller_name,
            evidence_type,
            getattr(method_def, 'file', ''),
            getattr(method_def, 'line', 0),
        )
        if not caller_name or identity in seen:
            continue
        seen.add(identity)
        unique_matches.append((method_def, evidence_type, caller_name))

    if not unique_matches:
        return result

    result.call_paths = []
    result.evidence_paths = []
    result.path_details = []

    for method_def, evidence_type, caller_name in unique_matches:
        path_text = f"{caller_name} -> {display_target}"
        evidence = [{
            'caller_symbol': caller_name,
            'callee_key': display_target,
            'evidence_type': evidence_type,
            'confidence': 'high',
            'file': getattr(method_def, 'file', ''),
            'line': getattr(method_def, 'line', 0),
        }]
        result.call_paths.append(path_text)
        result.evidence_paths.append(evidence)
        consumer_class = getattr(method_def, 'class_fqcn', '') or caller_name.rsplit('.', 1)[0]
        consumer_method = getattr(method_def, 'method_name', '') or caller_name.rsplit('.', 1)[-1]
        result.path_details.append({
            'path_status': 'reachable',
            'stop_reason': reason_code,
            'business_entry': caller_name,
            'business_reachable': True,
            'consumer_coord': 'BUSINESS',
            'consumer_class': consumer_class,
            'consumer_method': consumer_method,
            'consumer_signature': '',
            'path_text': path_text,
            'confidence': 1.0,
            'depth': 1,
            'evidence': evidence,
            'terminal_symbol': caller_name,
        })
    return _apply_evidence_decision(result, paths=tuple(
        ReachabilityPath(
            path_text=path_text,
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=True,
            reason_code=reason_code,
            note=note,
            depth=1,
        )
        for path_text in result.call_paths
    ))


def _find_direct_business_class_usage(api_row, graph, trace_cache=None):
    target_class = str(api_row.get('matched_class') or api_row.get('api_name') or '').strip()
    if not target_class:
        return None
    trace_cache = ensure_trace_cache(trace_cache)
    cache = trace_cache['direct_business_class_usage']
    if target_class in cache:
        _perf_add(graph, 'trace', 'direct_class_usage_cache_hits', 1)
        return cache[target_class]
    _perf_add(graph, 'trace', 'direct_class_usage_cache_misses', 1)
    started_at = time.perf_counter()
    scanned_methods = 0
    simple_name = target_class.rsplit('.', 1)[-1]
    simple_name_patterns = [
        re.compile(r'\bnew\s+' + re.escape(simple_name) + r'\b'),
        re.compile(r'\b' + re.escape(simple_name) + r'\s*\.class\b'),
        re.compile(r'\binstanceof\s+' + re.escape(simple_name) + r'\b'),
        re.compile(r'\(\s*' + re.escape(simple_name) + r'\s*\)'),
    ]
    fqcn_pattern = re.compile(re.escape(target_class))
    for method_def in _iter_business_methods(graph):
        scanned_methods += 1
        declared_types = (
            [getattr(method_def, 'return_type', '')]
            + list((getattr(method_def, 'param_types', {}) or {}).values())
            + list((getattr(method_def, 'field_types', {}) or {}).values())
            + list((getattr(method_def, 'local_var_types', {}) or {}).values())
        )
        if target_class in declared_types:
            cache[target_class] = (method_def, 'declared_type')
            _perf_add(graph, 'trace', 'direct_class_usage_scanned_methods', scanned_methods)
            _perf_add(graph, 'trace', 'direct_class_usage_elapsed_sec', time.perf_counter() - started_at)
            _perf_max(graph, 'trace', 'direct_class_usage_cache_size', len(cache))
            return cache[target_class]
        imports = getattr(method_def, 'imports', {}) or {}
        wildcard_imports = getattr(method_def, 'wildcard_imports', {}) or []
        body_text = getattr(method_def, 'get_body_text', lambda: '')() or ''
        code_text = _strip_strings_and_comments(body_text)
        import_matches_target = imports.get(simple_name) == target_class
        wildcard_matches_target = any(f"{pkg}.{simple_name}" == target_class for pkg in wildcard_imports)
        if (import_matches_target or wildcard_matches_target) and any(
            pattern.search(code_text) for pattern in simple_name_patterns
        ):
            cache[target_class] = (method_def, 'imported_type')
            _perf_add(graph, 'trace', 'direct_class_usage_scanned_methods', scanned_methods)
            _perf_add(graph, 'trace', 'direct_class_usage_elapsed_sec', time.perf_counter() - started_at)
            _perf_max(graph, 'trace', 'direct_class_usage_cache_size', len(cache))
            return cache[target_class]
        if fqcn_pattern.search(code_text):
            cache[target_class] = (method_def, 'body_reference')
            _perf_add(graph, 'trace', 'direct_class_usage_scanned_methods', scanned_methods)
            _perf_add(graph, 'trace', 'direct_class_usage_elapsed_sec', time.perf_counter() - started_at)
            _perf_max(graph, 'trace', 'direct_class_usage_cache_size', len(cache))
            return cache[target_class]
    cache[target_class] = None
    _perf_add(graph, 'trace', 'direct_class_usage_scanned_methods', scanned_methods)
    _perf_add(graph, 'trace', 'direct_class_usage_elapsed_sec', time.perf_counter() - started_at)
    _perf_max(graph, 'trace', 'direct_class_usage_cache_size', len(cache))
    return None


def _find_direct_business_field_usages(api_row, graph, trace_cache=None):
    api_name = str(api_row.get('api_name') or '').strip()
    field_name = str(api_row.get('api_simple') or '').strip() or (api_name.rsplit('.', 1)[-1] if '.' in api_name else '')
    owner_class = api_name.rsplit('.', 1)[0] if '.' in api_name else ''
    owner_simple = owner_class.rsplit('.', 1)[-1] if owner_class else ''
    if not field_name:
        return []
    cache_key = api_name or f"{owner_class}.{field_name}"
    trace_cache = ensure_trace_cache(trace_cache)
    cache = trace_cache['direct_business_field_usages']
    if cache_key in cache:
        _perf_add(graph, 'trace', 'direct_field_usage_cache_hits', 1)
        return list(cache[cache_key] or [])
    _perf_add(graph, 'trace', 'direct_field_usage_cache_misses', 1)
    started_at = time.perf_counter()
    scanned_methods = 0
    simple_access_pattern = (
        re.compile(r'\b' + re.escape(owner_simple) + r'\s*\.\s*' + re.escape(field_name) + r'\b')
        if owner_simple else None
    )
    fqcn_access_pattern = (
        re.compile(re.escape(owner_class) + r'\s*\.\s*' + re.escape(field_name) + r'\b')
        if owner_class else None
    )
    matches = []
    for method_def in _iter_business_methods(graph):
        scanned_methods += 1
        static_imports = getattr(method_def, 'static_imports', {}) or {}
        if static_imports.get(field_name) == api_name:
            matches.append((method_def, 'static_import'))
            continue
        body_text = getattr(method_def, 'get_body_text', lambda: '')() or ''
        if fqcn_access_pattern and fqcn_access_pattern.search(body_text):
            matches.append((method_def, 'field_access'))
            continue
        if simple_access_pattern and simple_access_pattern.search(body_text):
            imports = getattr(method_def, 'imports', {}) or {}
            wildcard_imports = getattr(method_def, 'wildcard_imports', {}) or []
            package_name = getattr(method_def, 'package_name', '') or ''
            if imports.get(owner_simple) == owner_class or any(
                f"{pkg}.{owner_simple}" == owner_class for pkg in wildcard_imports
            ) or (package_name and f"{package_name}.{owner_simple}" == owner_class):
                matches.append((method_def, 'field_access'))
    cache[cache_key] = tuple(matches)
    _perf_add(graph, 'trace', 'direct_field_usage_scanned_methods', scanned_methods)
    _perf_add(graph, 'trace', 'direct_field_usage_elapsed_sec', time.perf_counter() - started_at)
    _perf_max(graph, 'trace', 'direct_field_usage_cache_size', len(cache))
    return matches


def _find_direct_business_field_usage(api_row, graph, trace_cache=None):
    usages = _find_direct_business_field_usages(api_row, graph, trace_cache=trace_cache)
    return usages[0] if usages else None


def _try_build_direct_usage_result(api_row, result, graph, trace_cache=None):
    if graph is None:
        return None

    trace_cache = ensure_trace_cache(trace_cache)
    matched = None
    symbol_kind = str(result.symbol_kind or '').strip()
    analysis_scope = str(result.analysis_scope or '').strip()

    if analysis_scope == 'class_usage' or symbol_kind == 'class':
        matched = _find_direct_business_class_usage(api_row, graph, trace_cache=trace_cache)
        if matched:
            method_def, evidence_type = matched
            note = '已在系统源码中找到目标类型的直接使用证据'
            return _build_direct_usage_result(
                result,
                method_def,
                'DIRECT_CLASS_USAGE',
                note,
                evidence_type,
                str(api_row.get('matched_class') or api_row.get('api_name') or '').strip(),
            )

    if symbol_kind == 'field':
        matches = _find_direct_business_field_usages(api_row, graph, trace_cache=trace_cache)
        if matches:
            reason_code = (
                'DIRECT_STATIC_IMPORT_USAGE'
                if all(evidence_type == 'static_import' for _method_def, evidence_type in matches)
                else 'DIRECT_FIELD_USAGE'
            )
            note = (
                '已在系统源码中找到目标字段的 static import 直接引用'
                if reason_code == 'DIRECT_STATIC_IMPORT_USAGE'
                else '已在系统源码中找到目标字段的直接访问证据'
            )
            return _build_direct_usage_results(
                result,
                matches,
                reason_code,
                note,
                str(api_row.get('api_name') or '').strip(),
            )

    return None


def _has_exact_business_bytecode_target(api_row, graph):
    api_name = str((api_row or {}).get('api_name') or '').strip()
    target_signature = normalize_signature_for_lookup(
        str((api_row or {}).get('api_signature') or '').strip()
    )
    if not api_name or target_signature is None:
        return False
    reverse_edges = getattr(graph, 'reverse_edges', {}) or {}
    for key, edges in reverse_edges.items():
        key = str(key or '')
        if not key.startswith(api_name):
            continue
        signature = extract_signature_suffix_from_key(key)
        if normalize_signature_for_lookup(signature) != target_signature:
            continue
        if any(
            str(getattr(edge, 'evidence_type', '')).startswith('bytecode_')
            and str(getattr(edge, 'evidence_source', '')) == 'current_final_artifact'
            and bool(str(getattr(edge, 'artifact_sha256', '')).strip())
            and str(getattr(edge, 'owner_type', '')) == 'business'
            and not bool(getattr(edge, 'is_test', False))
            for edge in (edges or [])
        ):
            return True
    return False


def _get_runtime_dependency_catalog(graph):
    return getattr(graph, 'runtime_dependency_catalog', {}) or {}


def _changed_api_owner_fqcn(api_row):
    api_name = str((api_row or {}).get('api_name') or '').strip()
    kind = get_symbol_kind(api_row or {})
    if not api_name:
        return ''
    if kind == 'class':
        return api_name.replace('$', '.')
    if kind == 'constructor':
        simple = str((api_row or {}).get('api_simple') or '').strip()
        suffix = f'.{simple}' if simple else ''
        if suffix and api_name.endswith(suffix):
            return api_name[:-len(suffix)].replace('$', '.')
    return api_name.rsplit('.', 1)[0].replace('$', '.') if '.' in api_name else ''


def _step4_artifact_cache_filename(lib_entry):
    raw = str(lib_entry or '').replace('\\', '/').strip('/')
    safe = re.sub(r'[^A-Za-z0-9._/-]+', '_', raw).replace('/', '__')
    return safe or 'unknown.jar'


def _normalized_class_fqcn(entry_name):
    entry = str(entry_name or '').replace('\\', '/')
    if not entry.endswith('.class') or entry.endswith(('module-info.class', 'package-info.class')):
        return ''
    return entry[:-6].replace('/', '.').replace('$', '.')


def _build_identical_current_class_provider_index(all_apis, graph):
    """Find removed classes that remain byte-for-byte present in current JARs.

    A dependency coordinate can disappear while an aggregate/shaded runtime JAR
    still supplies the same class. Treating every reference as a removal impact
    in that case is incorrect: the symbol never left the runtime class path.
    Only byte-for-byte identical class providers are accepted here; a same-name
    but different class remains subject to ordinary impact tracing.
    """
    if not graph:
        return {}
    cached = getattr(graph, 'identical_current_class_providers', None)
    if cached is not None:
        return cached
    report_dir = str(getattr(graph, 'report_dir', '') or '').strip()
    targets = defaultdict(set)
    for api_row in all_apis or []:
        if str(api_row.get('new_version') or '').strip() != '-':
            continue
        if str(api_row.get('change_type') or '').strip().upper() not in {'REMOVED', 'METHOD_REMOVED', 'CLASS_REMOVED'}:
            continue
        coord = str(api_row.get('coord') or '').strip()
        owner = _changed_api_owner_fqcn(api_row)
        if coord and owner:
            targets[coord].add(owner)
    if not report_dir or not targets:
        setattr(graph, 'identical_current_class_providers', {})
        return {}

    dep_changes_path = os.path.join(report_dir, 'evidence', 'dependencies', 'dep_changes.csv')
    old_jars = {}
    try:
        import csv
        with open_csv_read(dep_changes_path) as handle:
            for row in csv.DictReader(handle):
                coord = str(row.get('coord') or '').strip()
                entry = str(row.get('base_lib_entry') or '').strip()
                if coord not in targets or not entry:
                    continue
                candidate = os.path.join(
                    report_dir,
                    'evidence',
                    'api_changes',
                    'step4_artifact_jars',
                    'base',
                    _step4_artifact_cache_filename(entry),
                )
                if os.path.isfile(candidate):
                    old_jars[coord] = candidate
    except (OSError, ValueError) as exc:
        _record_analyzer_ledger_failure(
            graph,
            'PRESERVATION_MANIFEST_UNREADABLE',
            artifact=dep_changes_path,
            error_type=type(exc).__name__,
            error=str(exc),
        )
        old_jars = {}

    old_hashes = {}
    for coord, jar_path in old_jars.items():
        owners = targets.get(coord) or set()
        try:
            with zipfile.ZipFile(jar_path) as zf:
                for entry in zf.namelist():
                    owner = _normalized_class_fqcn(entry)
                    if owner not in owners:
                        continue
                    data = zf.read(entry)
                    old_hashes[(coord, owner)] = {
                        'sha256': hashlib.sha256(data).hexdigest(),
                        'old_jar': jar_path,
                        'old_class_entry': entry,
                    }
        except Exception as exc:
            _record_analyzer_ledger_failure(
                graph,
                'PRESERVATION_BASE_ARTIFACT_UNREADABLE',
                artifact=jar_path,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            continue

    providers = defaultdict(list)
    wanted_owners = {owner for _coord, owner in old_hashes}
    catalog = _get_runtime_dependency_catalog(graph)
    for item in list(catalog.get('entries') or []):
        provider_coord = str(item.get('coord') or '').strip()
        jar_path = str(item.get('jar_path') or '').strip()
        if not provider_coord or provider_coord == '__business__' or not os.path.isfile(jar_path):
            continue
        try:
            with zipfile.ZipFile(jar_path) as zf:
                for entry in zf.namelist():
                    owner = _normalized_class_fqcn(entry)
                    if owner not in wanted_owners:
                        continue
                    digest = hashlib.sha256(zf.read(entry)).hexdigest()
                    for target_coord in targets:
                        old = old_hashes.get((target_coord, owner))
                        if not old or old['sha256'] != digest or provider_coord == target_coord:
                            continue
                        providers[(target_coord, owner)].append({
                            'provider_coord': provider_coord,
                            'provider_jar': jar_path,
                            'provider_class_entry': entry,
                            'class_sha256': digest,
                            **old,
                        })
        except Exception as exc:
            _record_analyzer_ledger_failure(
                graph,
                'PRESERVATION_PROVIDER_ARTIFACT_UNREADABLE',
                artifact=jar_path,
                provider_coord=provider_coord,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            continue
    result = {key: value for key, value in providers.items() if value}
    setattr(graph, 'identical_current_class_providers', result)
    _perf_add(graph, 'trace', 'identical_provider_classes', len(result))
    return result


def _build_runtime_symbol_preserved_result(result, api_row, graph):
    owner = _changed_api_owner_fqcn(api_row)
    providers = list((getattr(graph, 'identical_current_class_providers', {}) or {}).get(
        (str(api_row.get('coord') or '').strip(), owner),
        [],
    ))
    if not providers:
        return None
    provider = providers[0]
    provider_coord = provider.get('provider_coord') or ''
    target = changed_api_display_target(result)
    provider_node = f'{provider_coord}:{owner}（与删除前 class 字节码完全一致）'
    path_text = f'{provider_node} -> {target}'
    evidence = [{
        'caller_symbol': provider_node,
        'callee_key': target,
        'evidence_type': 'identical_current_class_provider',
        'confidence': 'high',
        'file': provider.get('provider_jar') or '',
        'line': 0,
        'owner_coord': provider_coord,
        'class_sha256': provider.get('class_sha256') or '',
        'old_jar': provider.get('old_jar') or '',
        'old_class_entry': provider.get('old_class_entry') or '',
        'provider_class_entry': provider.get('provider_class_entry') or '',
    }]
    preservation_note = (
        f'当前最终制品中的 {provider_coord} 仍提供 {owner}，且 class 字节码与删除前完全一致；'
        '该变更 API 没有从运行时类路径消失。'
    )
    result.dependency_chain_coords = [provider_coord] if provider_coord else []
    result.call_paths = [path_text]
    result.evidence_paths = [evidence]
    result.path_details = [{
        'path_status': 'not_impacted',
        'stop_reason': 'RUNTIME_SYMBOL_PRESERVED_IDENTICALLY',
        'business_entry': '',
        'business_reachable': False,
        'consumer_coord': provider_coord,
        'consumer_class': owner,
        'consumer_method': '',
        'consumer_signature': '',
        'path_text': path_text,
        'confidence': 1.0,
        'depth': 0,
        'evidence': evidence,
    }]
    result.verification_commands = []
    return _apply_evidence_decision(
        result,
        preservation=PreservationEvidence(
            reason_code='RUNTIME_SYMBOL_PRESERVED_IDENTICALLY',
            detail=preservation_note,
            api_identity=target,
            artifact=str(provider.get('provider_jar') or ''),
        ),
    )


def _apply_source_artifact_miss(result, graph, reachable_note):
    alignment = getattr(graph, 'source_artifact_alignment', {}) or {}
    alignment_status = str(alignment.get('status') or '').strip()
    if alignment_status in {'', 'aligned', 'conflict'}:
        reason_code = 'SOURCE_BYTECODE_EDGE_CONFLICT'
        note = reachable_note
    else:
        reason_code = 'SOURCE_ARTIFACT_ALIGNMENT_UNVERIFIED'
        note = (
            '源码中发现了目标调用，但无法确认这份源码就是本次打包产物对应的源码；'
            '因此不能用打包产物未命中来否定这条源码调用线索'
        )
    _downgrade_reachable_path_details(result, 'uncertain', reason_code)
    result.envelope_paths = tuple(
        path for path in result.envelope_paths if not path.complete
    )
    candidate_paths = tuple(
        ReachabilityPath(
            path_text=str(detail.get('path_text') or ''),
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=False,
            stop_reason=reason_code,
            depth=int(detail.get('depth') or 1),
        )
        for detail in (result.path_details or [])
        if detail.get('business_entry') or detail.get('business_reachable') is not False
    )
    if not candidate_paths and result.call_paths:
        candidate_paths = tuple(
            ReachabilityPath(
                path_text=str(path_text),
                entry_scope=ModuleScope.BUSINESS_CLASSES,
                complete=False,
                stop_reason=reason_code,
                depth=1,
            )
            for path_text in result.call_paths
        )
    return _apply_evidence_decision(
        result,
        paths=candidate_paths,
        concerns=(EvidenceConcern(
            stage='source-artifact-reconciliation',
            reason_code=reason_code,
            detail=note,
            api_identity=_trace_target_identity(result),
        ),),
    )


def _attach_source_only_paths(
    result, graph, matched_key_groups, *, stop_reason='SOURCE_ONLY_ARTIFACT_CONFLICT'
):
    if not bool(getattr(graph, 'require_current_final_artifact_business_edges', False)):
        return False

    reverse_edges = getattr(graph, 'reverse_edges', {}) or {}
    source_edges = []
    seen = set()
    for group in matched_key_groups or []:
        for key in group.get('matched_keys', []) or []:
            for edge in reverse_edges.get(key, []) or []:
                if _edge_allowed_for_trace(edge, graph) or bool(getattr(edge, 'is_test', False)):
                    continue
                identity = (
                    str(getattr(edge, 'caller_symbol_id', '') or ''),
                    str(getattr(edge, 'callee_key', '') or key),
                    str(getattr(edge, 'file', '') or ''),
                    int(getattr(edge, 'line', 0) or 0),
                )
                if identity in seen:
                    continue
                seen.add(identity)
                source_edges.append((key, edge))

    if not source_edges:
        return False

    result.call_paths = []
    result.evidence_paths = []
    result.path_details = []
    for key, edge in source_edges:
        caller = str(
            getattr(edge, 'caller_qualified_key', '')
            or getattr(edge, 'caller_symbol_id', '')
            or '?'
        )
        callee = str(getattr(edge, 'callee_key', '') or key)
        path_text = f'{caller} -> {callee}'
        evidence = [{
            'caller_symbol': caller,
            'callee_key': callee,
            'evidence_type': str(getattr(edge, 'evidence_type', '') or 'source_reference'),
            'evidence_source': str(getattr(edge, 'evidence_source', '') or 'source_worktree'),
            'confidence': str(getattr(edge, 'confidence', '') or 'medium'),
            'file': str(getattr(edge, 'file', '') or ''),
            'line': int(getattr(edge, 'line', 0) or 0),
        }]
        result.call_paths.append(path_text)
        result.evidence_paths.append(evidence)
        result.path_details.append({
            'path_status': 'uncertain' if stop_reason != 'SOURCE_ONLY_ARTIFACT_CONFLICT' else 'reachable',
            'stop_reason': stop_reason,
            'business_entry': caller,
            'business_reachable': None if stop_reason != 'SOURCE_ONLY_ARTIFACT_CONFLICT' else True,
            'path_text': path_text,
            'confidence': result.confidence_score,
            'depth': 1,
            'evidence': evidence,
        })
    return True


def _build_source_only_artifact_conflict_result(result, graph, matched_key_groups):
    if not _attach_source_only_paths(result, graph, matched_key_groups):
        return None

    return _apply_source_artifact_miss(result, graph, (
        '源码中发现了目标调用，但当前最终制品的字节码扫描没有发现对应引用；'
        '源码线索仅用于报告源码与制品冲突，不能作为运行时可达证据'
    ))


def _downgrade_reachable_path_details(result, path_status, stop_reason):
    for detail in getattr(result, 'path_details', []) or []:
        if detail.get('path_status') != 'reachable':
            continue
        detail['path_status'] = path_status
        detail['stop_reason'] = stop_reason
        detail['business_reachable'] = None


def _is_inlined_constant_change(api_row):
    if get_symbol_kind(api_row) != 'field':
        return False
    evidence, complete, has_constant_value = _constant_field_evidence(api_row)
    evidence_proves_inlining = bool(
        evidence and complete and has_constant_value
        and str(api_row.get('change_type') or '').strip().upper()
        in {'CONSTANT_VALUE_CHANGED', 'REMOVED', 'FIELD_REMOVED'}
    )
    return bool(
        evidence_proves_inlining
        or str(api_row.get('change_type') or '').strip() == 'CONSTANT_VALUE_CHANGED'
        or 'CONSTANT' in str(api_row.get('compatibility_flags') or '').upper()
        or str(api_row.get('reason_code') or '').strip().lower()
        == 'constant_value_changed'
    )


def _has_constant_field_evidence(api_row):
    if get_symbol_kind(api_row) != 'field':
        return False
    evidence, _complete, _has_constant = _constant_field_evidence(api_row)
    return bool(evidence)


def _evidence_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    return str(value or '').strip().lower() in {'1', 'true', 'yes', 'on'}


def _constant_field_evidence(api_row):
    row = api_row or {}
    raw = row.get('constant_field_evidence_json')
    if isinstance(raw, Mapping):
        payload = dict(raw)
    elif str(raw or '').strip():
        try:
            decoded = json.loads(str(raw))
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = {
                'status': 'incomplete',
                'failures': ['constant_field_evidence_json_invalid'],
            }
        else:
            payload = dict(decoded) if isinstance(decoded, Mapping) else {
                'status': 'incomplete',
                'failures': ['constant_field_evidence_json_not_object'],
            }
    else:
        payload = {}
    if payload:
        complete = str(payload.get('status') or '') == 'complete'
        return payload, complete, (
            _evidence_bool(payload.get('has_constant_value')) if complete else False
        )
    if 'old_field_has_constant_value' in row:
        value = _evidence_bool(row.get('old_field_has_constant_value'))
        return {
            'status': 'legacy',
            'has_constant_value': value,
        }, True, value
    return {}, False, False


def _apply_constant_impact(
    result, api_row, graph, *, runtime_field_edge_present, source_reference_present=None
):
    if not _has_constant_field_evidence(api_row):
        return result
    if source_reference_present is None:
        source_reference_present = any(
            str(edge.get('evidence_type') or '') in {
                'field_access', 'static_import_field', 'source_reference'
            }
            for path in (result.evidence_paths or [])
            for edge in (path or [])
        )
    source_artifact_aligned = (
        str((getattr(graph, 'source_artifact_alignment', {}) or {}).get('status') or '')
        == 'aligned'
    )
    old_field_evidence, old_evidence_present, old_field_has_constant_value = (
        _constant_field_evidence(api_row)
    )
    impact = classify_constant_impact(
        change_type=(api_row or {}).get('change_type') or result.change_type,
        old_field_has_constant_value=old_field_has_constant_value,
        source_reference_present=bool(source_reference_present),
        runtime_field_edge_present=bool(runtime_field_edge_present),
        source_artifact_aligned=source_artifact_aligned,
    ).to_dict()
    if not runtime_field_edge_present and not old_evidence_present:
        impact['runtime_link_impact'] = 'unverified'
    result.compile_impact = impact.pop('compile_impact')
    result.runtime_link_impact = impact.pop('runtime_link_impact')
    if old_field_evidence:
        impact['old_field'] = old_field_evidence
    result.constant_impact_evidence = impact
    return result


def _build_inlined_constant_result(result, api_row=None, graph=None):
    note = (
        '编译期常量值已变化，但调用方 class 可能只保留内联旧值而没有字段访问指令；'
        '字节码未发现 getstatic/getfield 不能解释为未使用'
    )
    result.verification_commands = [
        '搜索业务及依赖源码中的常量字段引用，并执行覆盖该常量语义的回归测试',
        '必要时比较调用方 class 常量池与 old/new 常量值，但不要仅凭字面量命中确认调用关系',
    ]
    _apply_constant_impact(
        result, dict(api_row or {}), graph, runtime_field_edge_present=False
    )
    reason_code = 'INLINED_CONSTANT_USAGE_UNDETECTABLE'
    _downgrade_reachable_path_details(result, 'uncertain', reason_code)
    result.envelope_paths = tuple(
        path for path in result.envelope_paths if not path.complete
    )
    candidate_paths = tuple(
        ReachabilityPath(
            path_text=str(detail.get('path_text') or ''),
            entry_scope=ModuleScope.BUSINESS_CLASSES,
            complete=False,
            stop_reason=reason_code,
            depth=int(detail.get('depth') or 1),
        )
        for detail in (result.path_details or [])
        if detail.get('business_entry') or detail.get('business_reachable') is not False
    )
    return _apply_evidence_decision(result, paths=candidate_paths, concerns=(EvidenceConcern(
        stage='constant-bytecode-analysis',
        reason_code=reason_code,
        detail=note,
        api_identity=_trace_target_identity(result),
    ),))


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


def _method_descriptor_to_lookup_signature(descriptor):
    params, _return_type = _parse_method_descriptor(descriptor)
    signature = _build_signature_from_params(params)
    normalized = normalize_signature_for_lookup(signature)
    return normalized or signature


def _field_descriptor_to_lookup_signature(descriptor):
    normalized = _normalize_descriptor_type(str(descriptor or '').strip(), preserve_array=True)
    return normalized or ''


def _extract_target_owner_and_member(api_row):
    symbol_kind = get_symbol_kind(api_row)
    api_name = str(api_row.get('api_name') or '').strip()
    matched_class = str(api_row.get('matched_class') or '').strip()
    api_simple = str(api_row.get('api_simple') or '').strip()
    if symbol_kind == 'class' or str(api_row.get('analysis_scope') or '').strip() == 'class_usage':
        return matched_class or api_name, '', symbol_kind
    if not api_name or '.' not in api_name:
        return '', '', symbol_kind
    owner, member = api_name.rsplit('.', 1)
    if symbol_kind == 'constructor':
        return owner, '<init>', symbol_kind
    return owner, api_simple or member, symbol_kind


def _jvm_internal_owner_name(owner):
    """Convert a source-style FQCN to its JVM internal nested-class name."""
    parts = [part for part in str(owner or '').strip().split('.') if part]
    if not parts:
        return ''
    class_start = next(
        (idx for idx, part in enumerate(parts) if part[:1].isupper()),
        len(parts) - 1,
    )
    package = '/'.join(parts[:class_start])
    classes = '$'.join(parts[class_start:])
    return f"{package}/{classes}" if package else classes


def _class_bytes_might_reference_target(data, owner_internal_name, member_name=''):
    if not data or not owner_internal_name:
        return False
    owner_bytes = owner_internal_name.encode('utf-8')
    dotted_owner_bytes = owner_internal_name.replace('/', '.').encode('utf-8')
    if owner_bytes not in data and dotted_owner_bytes not in data:
        return False
    if member_name and member_name != '<init>' and member_name.encode('utf-8') not in data:
        return False
    return True


def _parse_classfile_constant_pool_summary(data):
    """Return a small constant-pool summary without invoking javap.

    This is intentionally conservative: parse failures return None so callers can
    fall back to the old javap path rather than miss evidence. For valid class
    files, it lets Step5 distinguish real symbolic references from plain string
    constants that merely mention a target owner name.
    """
    try:
        if not data or len(data) < 10 or data[:4] != b'\xca\xfe\xba\xbe':
            return None
        cp_count = struct.unpack_from('>H', data, 8)[0]
        utf8 = {}
        class_name_indexes = []
        ref_entries = []
        name_and_type_indexes = {}
        has_dynamic_reference = False
        idx = 10
        cp_index = 1
        while cp_index < cp_count:
            if idx >= len(data):
                return None
            tag = data[idx]
            idx += 1
            if tag == 1:  # Utf8
                if idx + 2 > len(data):
                    return None
                length = struct.unpack_from('>H', data, idx)[0]
                idx += 2
                if idx + length > len(data):
                    return None
                utf8[cp_index] = data[idx:idx + length].decode('utf-8', errors='replace')
                idx += length
            elif tag == 7:  # Class
                if idx + 2 > len(data):
                    return None
                class_name_indexes.append(struct.unpack_from('>H', data, idx)[0])
                idx += 2
            elif tag in (9, 10, 11):  # Fieldref / Methodref / InterfaceMethodref
                if idx + 4 > len(data):
                    return None
                ref_entries.append({
                    'tag': tag,
                    'class_index': struct.unpack_from('>H', data, idx)[0],
                    'name_and_type_index': struct.unpack_from('>H', data, idx + 2)[0],
                })
                idx += 4
            elif tag == 12:  # NameAndType
                if idx + 4 > len(data):
                    return None
                name_and_type_indexes[cp_index] = {
                    'name_index': struct.unpack_from('>H', data, idx)[0],
                    'descriptor_index': struct.unpack_from('>H', data, idx + 2)[0],
                }
                idx += 4
            elif tag in (3, 4):  # Integer / Float
                idx += 4
            elif tag in (5, 6):  # Long / Double, takes two entries
                idx += 8
                cp_index += 1
            elif tag == 8:  # String
                idx += 2
            elif tag == 15:  # MethodHandle
                idx += 3
            elif tag == 16:  # MethodType
                idx += 2
            elif tag in (17, 18):  # Dynamic / InvokeDynamic
                has_dynamic_reference = True
                idx += 4
            elif tag in (19, 20):  # Module / Package
                idx += 2
            else:
                return None
            if idx > len(data):
                return None
            cp_index += 1
        class_internal = {utf8.get(name_index, '') for name_index in class_name_indexes}
        ref_class_internal = {
            utf8.get(name_index, '')
            for name_index in class_name_indexes
            if name_index
        }
        # Ref class indexes point to CONSTANT_Class entries; class_name_indexes
        # above does not preserve the original cp index, so build a second pass
        # mapping while keeping the parser simple.
        class_by_cp_index = {}
        idx = 10
        cp_index = 1
        while cp_index < cp_count:
            tag = data[idx]
            idx += 1
            if tag == 1:
                length = struct.unpack_from('>H', data, idx)[0]
                idx += 2 + length
            elif tag == 7:
                class_by_cp_index[cp_index] = utf8.get(struct.unpack_from('>H', data, idx)[0], '')
                idx += 2
            elif tag in (9, 10, 11):
                idx += 4
            elif tag == 12:
                idx += 4
            elif tag in (3, 4):
                idx += 4
            elif tag in (5, 6):
                idx += 8
                cp_index += 1
            elif tag == 8:
                idx += 2
            elif tag == 15:
                idx += 3
            elif tag == 16:
                idx += 2
            elif tag in (17, 18):
                has_dynamic_reference = True
                idx += 4
            elif tag in (19, 20):
                idx += 2
            else:
                return None
            cp_index += 1
        ref_class_internal = {
            class_by_cp_index.get(class_index, '')
            for class_index in [item.get('class_index') for item in ref_entries]
        }
        ref_member_names = {
            utf8.get((name_and_type_indexes.get(name_and_type_index, {}) or {}).get('name_index', ''), '')
            for name_and_type_index in [item.get('name_and_type_index') for item in ref_entries]
        }
        ref_members = []
        for item in ref_entries:
            nt = name_and_type_indexes.get(item.get('name_and_type_index'), {}) or {}
            owner = class_by_cp_index.get(item.get('class_index'), '')
            name = utf8.get(nt.get('name_index'), '')
            descriptor = utf8.get(nt.get('descriptor_index'), '')
            if owner and name:
                ref_members.append({
                    'tag': item.get('tag'),
                    'owner': owner,
                    'name': name,
                    'descriptor': descriptor,
                })
        ref_member_descriptors = {item.get('descriptor') or '' for item in ref_members if item.get('descriptor')}
        utf8_values = set(utf8.values())
        return {
            'class_internal_names': {item for item in class_internal if item},
            'ref_internal_names': {item for item in ref_class_internal if item},
            'ref_member_names': {item for item in ref_member_names if item},
            'ref_member_descriptors': ref_member_descriptors,
            'ref_members': ref_members,
            'has_dynamic_reference': has_dynamic_reference,
            'utf8_values': utf8_values,
        }
    except Exception:
        return None


def _run_javap_bytecode_dump(jar_path, class_binary_name, multi_release_version=None):
    command = ['javap', '-classpath', jar_path, '-verbose', '-c', '-s', '-p']
    if multi_release_version not in (None, '', 'base'):
        command.extend(['--multi-release', str(multi_release_version)])
    command.append(class_binary_name)
    stdout, _stderr, rc = run_cmd(
        command,
        timeout=30,
    )
    return stdout if rc == 0 else ''


_CLASSFILE_OPCODE_NAMES = {
    0xb2: 'getstatic', 0xb3: 'putstatic', 0xb4: 'getfield', 0xb5: 'putfield',
    0xb6: 'invokevirtual', 0xb7: 'invokespecial', 0xb8: 'invokestatic',
    0xb9: 'invokeinterface', 0xbb: 'new', 0xbd: 'anewarray',
    0xc0: 'checkcast', 0xc1: 'instanceof', 0xc5: 'multianewarray',
}


def _references_from_executable_classfile_edges(edges, class_binary_name=''):
    references = {
        'method_refs': [],
        'field_refs': [],
        'class_refs': set(),
        'class_instruction_refs': [],
    }
    for edge in edges or []:
        evidence_type = str(edge.get('evidence_type') or '')
        if evidence_type == 'bytecode_class_reference':
            continue
        content = str(edge.get('content') or '')
        opcode_match = re.search(r'opcode 0x([0-9a-fA-F]{2})', content)
        opcode_family = _CLASSFILE_OPCODE_NAMES.get(
            int(opcode_match.group(1), 16) if opcode_match else -1, ''
        )
        instruction_offset = edge.get('line')
        if not opcode_family or instruction_offset is None:
            continue
        callee_key = str(edge.get('callee_key') or '')
        caller_method = str(edge.get('caller_name') or '<unknown>')
        class_simple = str(class_binary_name or '').rsplit('.', 1)[-1]
        if caller_method in {class_simple, str(class_binary_name or '')}:
            caller_method = '<init>'
        caller_descriptor = str(edge.get('caller_descriptor') or '')
        caller_signature = (
            _method_descriptor_to_lookup_signature(caller_descriptor)
            if caller_descriptor else str(edge.get('caller_signature') or '')
        )
        if evidence_type in {
            'bytecode_method_invocation', 'bytecode_constructor_invocation',
            'bytecode_invokedynamic_method_reference',
        }:
            owner_and_member, _, signature_tail = callee_key.partition('(')
            owner, _, member = owner_and_member.rpartition('.')
            callee_descriptor = str(edge.get('callee_descriptor') or '')
            signature = (
                _method_descriptor_to_lookup_signature(callee_descriptor)
                if callee_descriptor.startswith('(')
                else normalize_signature_for_lookup(
                    f'({signature_tail}' if signature_tail else ''
                )
            )
            jvm_member = '<init>' if evidence_type == 'bytecode_constructor_invocation' else member
            references['method_refs'].append({
                'owner': owner,
                'jvm_owner': str(edge.get('callee_jvm_owner') or owner),
                'name': jvm_member,
                'descriptor': callee_descriptor,
                'signature': signature,
                'consumer_method': caller_method,
                'consumer_signature': caller_signature,
                'consumer_descriptor': caller_descriptor,
                'opcode_family': opcode_family,
                'instruction_offset': instruction_offset,
                'reference_kind': 'classfile_methodref',
            })
            if evidence_type == 'bytecode_invokedynamic_method_reference':
                references['method_refs'][-1]['reference_kind'] = 'invokedynamic_method_handle'
            references['class_refs'].add(owner)
        elif evidence_type == 'bytecode_field_access':
            owner, _, member = callee_key.rpartition('.')
            references['field_refs'].append({
                'owner': owner,
                'jvm_owner': str(edge.get('callee_jvm_owner') or owner),
                'name': member,
                'descriptor': str(edge.get('callee_descriptor') or ''),
                'signature': '',
                'consumer_method': caller_method,
                'consumer_signature': caller_signature,
                'consumer_descriptor': caller_descriptor,
                'opcode_family': opcode_family,
                'instruction_offset': instruction_offset,
                'reference_kind': 'classfile_fieldref',
            })
            references['class_refs'].add(owner)
        elif evidence_type == 'bytecode_type_reference':
            owner = callee_key
        else:
            continue
        references['class_instruction_refs'].append({
            'owner': owner,
            'consumer_method': caller_method,
            'consumer_signature': caller_signature,
            'consumer_descriptor': caller_descriptor,
            'reference_kind': 'classfile_type_reference',
            'opcode_family': opcode_family,
            'instruction_offset': instruction_offset,
        })
        references['class_refs'].add(owner)
    references['class_refs'] = sorted(references['class_refs'])
    return references


def _parse_javap_bytecode_references(text, class_binary_name=''):
    references = {
        'method_refs': [],
        'field_refs': [],
        'class_refs': set(),
        'class_instruction_refs': [],
    }
    # javap omits the owner for references to members declared by the class
    # currently being disassembled, for example:
    #   invokevirtual #31 // Method buildBannerText:()Ljava/lang/String;
    # Requiring ``owner.member`` here silently removes every such intra-class
    # edge and breaks otherwise valid dependency A -> B -> changed-API chains.
    method_pattern = re.compile(
        r'//\s+(?:Interface)?Method\s+(?:([A-Za-z0-9_/$]+)\.)?'
        r'(?:"([^"]+)"|([A-Za-z0-9_$<>]+)):(\S+)'
    )
    field_pattern = re.compile(
        r'//\s+Field\s+(?:([A-Za-z0-9_/$]+)\.)?([A-Za-z0-9_$]+):(\S+)'
    )
    class_pattern = re.compile(r'//\s+class\s+([A-Za-z0-9_/$]+)')
    descriptor_pattern = re.compile(r'L([A-Za-z0-9_/$]+);')
    method_header_pattern = re.compile(
        r'^\s*(?:[\w.$<>\[\],?]+\s+)*([\w$<>.]+)\([^;]*\)'
        r'(?:\s+throws\s+[^;]+)?;\s*$'
    )
    bootstrap_start_pattern = re.compile(r'^\s*(\d+):\s+#\d+\s+REF_\w+')
    method_handle_pattern = re.compile(
        r'(?:#\d+\s+)?REF_\w+\s+([A-Za-z0-9_/$]+)\.(?:"([^"]+)"|([A-Za-z0-9_$<>]+)):(\S+)'
    )
    bootstrap_targets = {}
    current_bootstrap = None
    in_bootstrap_section = False
    for raw_line in (text or '').splitlines():
        line = raw_line.strip()
        if line == 'BootstrapMethods:':
            in_bootstrap_section = True
            current_bootstrap = None
            continue
        if not in_bootstrap_section:
            continue
        start = bootstrap_start_pattern.match(raw_line)
        if start:
            current_bootstrap = int(start.group(1))
            bootstrap_targets.setdefault(current_bootstrap, [])
        handle = method_handle_pattern.search(line)
        if handle and current_bootstrap is not None:
            jvm_owner = handle.group(1).replace('/', '.')
            owner = jvm_owner.replace('$', '.')
            if owner in {
                'java.lang.invoke.LambdaMetafactory',
                'java.lang.invoke.StringConcatFactory',
            }:
                continue
            bootstrap_targets[current_bootstrap].append({
                'owner': owner,
                'jvm_owner': jvm_owner,
                'name': handle.group(2) or handle.group(3) or '',
                'descriptor': handle.group(4),
            })
    current_member = ''
    current_signature = ''
    current_descriptor = ''
    class_simple = str(class_binary_name or '').rsplit('.', 1)[-1]

    def record_class_instruction(
        owner, reference_kind, opcode_family, instruction_offset,
        consumer_method=None, consumer_signature=None, consumer_descriptor=None,
    ):
        if not owner or not opcode_family or instruction_offset is None:
            return
        references['class_instruction_refs'].append({
            'owner': owner,
            'consumer_method': current_member if consumer_method is None else consumer_method,
            'consumer_signature': current_signature if consumer_signature is None else consumer_signature,
            'consumer_descriptor': current_descriptor if consumer_descriptor is None else consumer_descriptor,
            'reference_kind': reference_kind,
            'opcode_family': opcode_family,
            'instruction_offset': instruction_offset,
        })

    for raw_line in (text or '').splitlines():
        line = raw_line.strip()
        if not line:
            continue
        header = method_header_pattern.match(raw_line)
        if header:
            current_member = header.group(1).rsplit('.', 1)[-1]
            if current_member == class_simple:
                current_member = '<init>'
            current_signature = ''
            current_descriptor = ''
            continue
        if re.match(r'^\s*static\s+\{\};\s*$', raw_line):
            current_member = '<clinit>'
            current_signature = ''
            current_descriptor = ''
            continue
        if line.startswith('descriptor:') and current_member:
            current_descriptor = line.split(':', 1)[1].strip()
            current_signature = _method_descriptor_to_lookup_signature(current_descriptor)
            for match in descriptor_pattern.findall(line):
                references['class_refs'].add(match.replace('/', '.').replace('$', '.'))
            continue
        # Constant-pool declarations also contain "// Method/Field" comments,
        # but they do not identify the consuming method. Only instruction lines
        # are valid member-level usage evidence.
        instruction_line = bool(re.match(r'^\d+:', line))
        instruction = re.match(r'^(\d+):\s+([a-z][a-z0-9_]*)\b', line)
        instruction_offset = int(instruction.group(1)) if instruction else None
        opcode_family = instruction.group(2) if instruction else ''
        dynamic_match = re.search(r'\binvokedynamic\b.*//\s+InvokeDynamic\s+#(\d+):', line)
        if dynamic_match and instruction_line:
            for target in bootstrap_targets.get(int(dynamic_match.group(1)), []):
                descriptor = target.get('descriptor') or ''
                references['method_refs'].append({
                    'owner': target.get('owner') or '',
                    'jvm_owner': target.get('jvm_owner') or target.get('owner') or '',
                    'name': target.get('name') or '',
                    'descriptor': descriptor,
                    'signature': _method_descriptor_to_lookup_signature(descriptor),
                    'consumer_method': current_member,
                    'consumer_signature': current_signature,
                    'consumer_descriptor': current_descriptor,
                    'opcode_family': opcode_family,
                    'instruction_offset': instruction_offset,
                    'reference_kind': 'invokedynamic_method_handle',
                })
                references['class_refs'].add(target.get('owner') or '')
                record_class_instruction(
                    target.get('owner') or '', 'invokedynamic_method_handle',
                    opcode_family, instruction_offset,
                )
        method_match = method_pattern.search(line)
        if method_match and instruction_line:
            jvm_owner = (
                method_match.group(1).replace('/', '.')
                if method_match.group(1)
                else str(class_binary_name or '').replace('/', '.')
            )
            owner = jvm_owner.replace('$', '.')
            method_name = method_match.group(2) or method_match.group(3) or ''
            descriptor = method_match.group(4).strip()
            references['method_refs'].append({
                'owner': owner,
                'jvm_owner': jvm_owner,
                'name': method_name,
                'descriptor': descriptor,
                'signature': _method_descriptor_to_lookup_signature(descriptor),
                'consumer_method': current_member,
                'consumer_signature': current_signature,
                'consumer_descriptor': current_descriptor,
                'opcode_family': opcode_family,
                'instruction_offset': instruction_offset,
            })
            references['class_refs'].add(owner)
            record_class_instruction(owner, 'method_reference', opcode_family, instruction_offset)
            continue
        field_match = field_pattern.search(line)
        if field_match and instruction_line:
            jvm_owner = (
                field_match.group(1).replace('/', '.')
                if field_match.group(1)
                else str(class_binary_name or '').replace('/', '.')
            )
            owner = jvm_owner.replace('$', '.')
            descriptor = field_match.group(3).strip()
            references['field_refs'].append({
                'owner': owner,
                'jvm_owner': jvm_owner,
                'name': field_match.group(2),
                'descriptor': descriptor,
                'signature': _field_descriptor_to_lookup_signature(descriptor),
                'consumer_method': current_member,
                'consumer_signature': current_signature,
                'consumer_descriptor': current_descriptor,
                'opcode_family': opcode_family,
                'instruction_offset': instruction_offset,
            })
            references['class_refs'].add(owner)
            record_class_instruction(owner, 'field_reference', opcode_family, instruction_offset)
            continue
        class_match = class_pattern.search(line)
        if class_match:
            owner = class_match.group(1).replace('/', '.').replace('$', '.')
            references['class_refs'].add(owner)
            if instruction_line:
                record_class_instruction(owner, 'type_reference', opcode_family, instruction_offset)
        if line.startswith('descriptor:'):
            descriptor = line.split(':', 1)[1].strip()
            for match in descriptor_pattern.findall(descriptor):
                references['class_refs'].add(match.replace('/', '.').replace('$', '.'))
    for item in parse_javap_indirect_references(text, class_binary_name):
        kind = item.get('kind')
        owner = item.get('owner') or ''
        references['class_refs'].add(owner)
        if kind == 'class':
            record_class_instruction(
                owner, item.get('reference_kind') or '',
                item.get('opcode_family') or '', item.get('instruction_offset'),
                consumer_method=item.get('consumer_method') or '',
                consumer_signature=item.get('consumer_signature') or '',
                consumer_descriptor=item.get('consumer_descriptor') or '',
            )
            continue
        if kind == 'field':
            references['field_refs'].append({
                'owner': owner, 'name': item.get('name') or '', 'descriptor': '',
                'signature': '', 'consumer_method': item.get('consumer_method') or '',
                'consumer_signature': item.get('consumer_signature') or '',
                'reference_kind': item.get('reference_kind'),
                'opcode_family': item.get('opcode_family') or '',
                'instruction_offset': item.get('instruction_offset'),
            })
            continue
        references['method_refs'].append({
            'owner': owner,
            'name': '<init>' if kind == 'constructor' else (item.get('name') or ''),
            'descriptor': '', 'signature': item.get('signature') or '',
            'signature_resolved': bool(item.get('signature_resolved')),
            'consumer_method': item.get('consumer_method') or '',
            'consumer_signature': item.get('consumer_signature') or '',
            'reference_kind': item.get('reference_kind'),
            'opcode_family': item.get('opcode_family') or '',
            'instruction_offset': item.get('instruction_offset'),
        })
    references['class_refs'] = sorted(references['class_refs'])
    return references


def _load_immutable_artifact_parse(
    artifact_sha256, target_jdk, class_binary_name, multi_release_version,
    graph, parse, class_entry='',
):
    """Parse one physical class once per artifact, procedure, JDK, and generation."""
    if not _valid_sha256(artifact_sha256):
        return parse()
    immutable_key = _immutable_artifact_parse_cache_key(
        artifact_sha256, target_jdk, class_binary_name, multi_release_version,
        class_entry=class_entry,
    )

    def deserialize(serialized):
        return json.loads(serialized)

    while True:
        with _IMMUTABLE_ARTIFACT_PARSE_CACHE_LOCK:
            generation = _IMMUTABLE_ARTIFACT_PARSE_CACHE_GENERATION
            cached_serialized = _IMMUTABLE_ARTIFACT_PARSE_CACHE.get(immutable_key)
            if isinstance(cached_serialized, str):
                cached = deserialize(cached_serialized)
                cache_hit = True
                parse_event = None
                owns_parse = False
            else:
                if immutable_key in _IMMUTABLE_ARTIFACT_PARSE_CACHE:
                    _IMMUTABLE_ARTIFACT_PARSE_CACHE.pop(immutable_key, None)
                cache_hit = False
                inflight_key = (generation, immutable_key)
                parse_event = _IMMUTABLE_ARTIFACT_PARSE_INFLIGHT.get(inflight_key)
                owns_parse = parse_event is None
                if owns_parse:
                    parse_event = Event()
                    _IMMUTABLE_ARTIFACT_PARSE_INFLIGHT[inflight_key] = parse_event
        if cache_hit:
            _perf_add(graph, 'bytecode_scan', 'artifact_cache_hits', 1)
            return cached
        if not owns_parse:
            parse_event.wait()
            continue
        _perf_add(graph, 'bytecode_scan', 'artifact_cache_misses', 1)
        parse_started_at = time.perf_counter()
        try:
            parsed = parse()
        except Exception:
            with _IMMUTABLE_ARTIFACT_PARSE_CACHE_LOCK:
                inflight_key = (generation, immutable_key)
                if _IMMUTABLE_ARTIFACT_PARSE_INFLIGHT.get(inflight_key) is parse_event:
                    _IMMUTABLE_ARTIFACT_PARSE_INFLIGHT.pop(inflight_key, None)
                    parse_event.set()
            raise
        finally:
            _perf_add(
                graph, 'bytecode_scan', 'class_parse_elapsed_sec',
                time.perf_counter() - parse_started_at,
            )
        serialized = json.dumps(
            parsed,
            default=lambda value: sorted(value) if isinstance(value, set) else TypeError,
            sort_keys=True,
            separators=(',', ':'),
        )
        with _IMMUTABLE_ARTIFACT_PARSE_CACHE_LOCK:
            inflight_key = (generation, immutable_key)
            if (
                _IMMUTABLE_ARTIFACT_PARSE_CACHE_GENERATION == generation
                and _IMMUTABLE_ARTIFACT_PARSE_INFLIGHT.get(inflight_key) is parse_event
            ):
                _IMMUTABLE_ARTIFACT_PARSE_CACHE[immutable_key] = serialized
                _IMMUTABLE_ARTIFACT_PARSE_INFLIGHT.pop(inflight_key, None)
                parse_event.set()
        return parsed


def _load_runtime_dependency_class_references(
    catalog, coord, jar_path, class_binary_name, multi_release_version=None,
    artifact_sha256='', target_jdk=None, graph=None, class_entry='',
):
    immutable_key = _immutable_artifact_parse_cache_key(
        artifact_sha256, target_jdk, class_binary_name, multi_release_version,
        class_entry=class_entry,
    )
    cache_key = (coord, jar_path, *immutable_key)
    with _IMMUTABLE_ARTIFACT_PARSE_CACHE_LOCK:
        generation = _IMMUTABLE_ARTIFACT_PARSE_CACHE_GENERATION
        cache = catalog.setdefault('_bytecode_reference_cache', {})
        cache_generations = catalog.setdefault('_bytecode_reference_cache_generations', {})
        if cache_generations.get(cache_key) == generation and cache_key in cache:
            _perf_add(graph, 'bytecode_scan', 'artifact_cache_hits', 1)
            return cache[cache_key]
        cache.pop(cache_key, None)
        cache_generations.pop(cache_key, None)

    def parse():
        text = _run_javap_bytecode_dump(
            jar_path, class_binary_name, multi_release_version=multi_release_version
        )
        _perf_add(graph, 'bytecode_scan', 'javap_fallbacks', 1)
        if not text:
            return None
        parsed = _parse_javap_bytecode_references(text, class_binary_name)
        _record_actual_artifact_class_parse(
            graph, artifact_sha256, target_jdk, class_binary_name, multi_release_version,
            class_entry=class_entry, parser_kind='javap',
        )
        return parsed

    parsed = _load_immutable_artifact_parse(
        artifact_sha256, target_jdk, class_binary_name, multi_release_version,
        graph, parse, class_entry=class_entry,
    )
    with _IMMUTABLE_ARTIFACT_PARSE_CACHE_LOCK:
        if _IMMUTABLE_ARTIFACT_PARSE_CACHE_GENERATION == generation:
            cache = catalog.setdefault('_bytecode_reference_cache', {})
            cache_generations = catalog.setdefault('_bytecode_reference_cache_generations', {})
            cache[cache_key] = parsed
            cache_generations[cache_key] = generation
    return parsed


def _load_direct_classfile_references(
    data, artifact_sha256, target_jdk, class_binary_name,
    multi_release_version=None, class_entry='', graph=None,
):
    """Cache the complete non-reflective/non-dynamic classfile fast path.

    The namespace prevents a shallow direct result from colliding with the
    authoritative javap cache introduced by the immutable artifact cache.
    """
    base_key = _immutable_artifact_parse_cache_key(
        artifact_sha256, target_jdk, class_binary_name, multi_release_version,
        class_entry=class_entry,
    )
    cache_key = ('classfile-executable-v3', *base_key)
    generation = _IMMUTABLE_ARTIFACT_PARSE_CACHE_GENERATION
    if _valid_sha256(artifact_sha256):
        with _IMMUTABLE_ARTIFACT_PARSE_CACHE_LOCK:
            cached = _IMMUTABLE_ARTIFACT_PARSE_CACHE.get(cache_key)
        if isinstance(cached, str):
            _perf_add(graph, 'bytecode_scan', 'artifact_cache_hits', 1)
            return json.loads(cached)

    parse_started_at = time.perf_counter()
    direct_edges = None
    summary = None
    try:
        direct_edges = parse_classfile_calls(data, class_binary_name)
        if direct_edges is not None:
            summary = _parse_classfile_constant_pool_summary(data)
    finally:
        _perf_add(
            graph, 'bytecode_scan', 'class_parse_elapsed_sec',
            time.perf_counter() - parse_started_at,
        )
    if direct_edges is None:
        return None
    if summary is None or summary.get('has_dynamic_reference'):
        return None
    references = _references_from_executable_classfile_edges(
        direct_edges, class_binary_name=class_binary_name
    )
    _perf_add(graph, 'bytecode_scan', 'artifact_cache_misses', 1)
    _record_actual_artifact_class_parse(
        graph, artifact_sha256, target_jdk, class_binary_name, multi_release_version,
        class_entry=class_entry, parser_kind='classfile',
    )
    if _valid_sha256(artifact_sha256):
        serialized = json.dumps(references, sort_keys=True, separators=(',', ':'))
        with _IMMUTABLE_ARTIFACT_PARSE_CACHE_LOCK:
            if _IMMUTABLE_ARTIFACT_PARSE_CACHE_GENERATION == generation:
                _IMMUTABLE_ARTIFACT_PARSE_CACHE[cache_key] = serialized
    return references


def _load_runtime_dependency_class_references_for_task(task):
    # A valid direct classfile parse is authoritative for ordinary bytecode and
    # avoids spawning a JVM per class.  Reflection and unresolved invokedynamic
    # classes deliberately do not populate this field and retain the javap path.
    if task.get('preparsed_references') is not None:
        return task, task.get('preparsed_references')
    jar_path = str(task.get('jar_path') or '')
    class_entry = str(task.get('class_entry') or '')
    if jar_path and class_entry:
        with zipfile.ZipFile(jar_path) as archive:
            class_bytes = archive.read(class_entry)
        references = _load_direct_classfile_references(
            class_bytes,
            task.get('artifact_sha256') or '',
            task.get('target_jdk'),
            task.get('class_binary_name') or '',
            multi_release_version=task.get('multi_release_version'),
            class_entry=class_entry,
            graph=task.get('graph'),
        )
        if references is not None:
            return task, references
    references = _load_runtime_dependency_class_references(
        task['catalog'],
        task['coord'],
        task['jar_path'],
        task['class_binary_name'],
        multi_release_version=task.get('multi_release_version'),
        artifact_sha256=task.get('artifact_sha256') or '',
        target_jdk=task.get('target_jdk'),
        graph=task.get('graph'),
        class_entry=task.get('class_entry') or '',
    )
    return task, references


def _runtime_reference_signature_matches(
    target_signature, reference, target_owner='', allow_ambiguous_unqualified=False
):
    target_signature = str(target_signature or '').strip()
    reference_signature = str((reference or {}).get('signature') or '').strip()
    if not target_signature:
        return True
    if reference_signature == target_signature:
        return True
    target_params = split_signature_params(target_signature)
    descriptor_params, _return_type = _parse_method_descriptor(
        str((reference or {}).get('descriptor') or '')
    )
    if target_params is None or len(target_params) != len(descriptor_params):
        return False

    target_internal_owner = _jvm_internal_owner_name(target_owner)
    target_package = (
        target_internal_owner.rsplit('/', 1)[0].replace('/', '.')
        if '/' in target_internal_owner else ''
    )

    def type_matches(target_type, descriptor_type):
        target_type = str(target_type or '').strip().replace('...', '[]').replace('/', '.')
        descriptor_type = str(descriptor_type or '').strip().replace('/', '.').replace('$', '.')
        while '<' in target_type:
            target_type = target_type.split('<', 1)[0].strip()
        target_arrays = 0
        descriptor_arrays = 0
        while target_type.endswith('[]'):
            target_arrays += 1
            target_type = target_type[:-2].strip()
        while descriptor_type.endswith('[]'):
            descriptor_arrays += 1
            descriptor_type = descriptor_type[:-2].strip()
        if target_arrays != descriptor_arrays:
            return False
        target_type = target_type.replace('$', '.')
        if target_type == descriptor_type:
            return True
        if '.' not in target_type:
            if target_type in _JAVA_LANG_SIMPLE_TYPES:
                return descriptor_type == f'java.lang.{target_type}'
            if target_package and descriptor_type == f'{target_package}.{target_type}':
                return True
            return bool(
                allow_ambiguous_unqualified
                and descriptor_type.rsplit('.', 1)[-1] == target_type
            )
        if target_package and target_type[:1].isupper():
            return descriptor_type == f'{target_package}.{target_type}'
        return False

    return all(
        type_matches(target_type, descriptor_type)
        for target_type, descriptor_type in zip(target_params, descriptor_params)
    )


def _match_runtime_dependency_references(api_row, references):
    references = references or {}
    owner, member_name, symbol_kind = _extract_target_owner_and_member(api_row)
    if not owner:
        return []
    target_signature = str(api_row.get('api_signature') or '').strip()
    target_lookup_signature = normalize_signature_for_lookup(target_signature) or target_signature

    if symbol_kind == 'class' or str(api_row.get('analysis_scope') or '').strip() == 'class_usage':
        matches = []
        for item in references.get('class_instruction_refs') or []:
            if str(item.get('owner') or '').replace('$', '.') != str(owner).replace('$', '.'):
                continue
            if not item.get('opcode_family') or item.get('instruction_offset') is None:
                continue
            matches.append({
                'evidence_type': (
                    'bytecode_reflection_class_lookup'
                    if item.get('reference_kind') == 'reflection_class'
                    else 'bytecode_class_reference'
                ),
                'target_display': owner,
                'consumer_method': item.get('consumer_method') or '<unknown>',
                'consumer_signature': item.get('consumer_signature') or '',
                'consumer_descriptor': item.get('consumer_descriptor') or '',
                'callee_owner': owner,
                'callee_member': '',
                'callee_descriptor': '',
                'opcode_family': item.get('opcode_family') or '',
                'instruction_offset': item.get('instruction_offset'),
            })
        return _dedupe_runtime_matches(matches)

    if symbol_kind in {'method', 'constructor'}:
        matches = []
        for item in references.get('method_refs') or []:
            if (
                str(item.get('owner') or '').replace('$', '.') != str(owner or '').replace('$', '.')
                or item.get('name') != member_name
            ):
                continue
            if (
                str(item.get('reference_kind') or '').startswith('reflection_')
                and (not item.get('opcode_family') or item.get('instruction_offset') is None)
            ):
                continue
            if target_lookup_signature:
                if item.get('reference_kind', '').startswith('reflection_') and not item.get('signature_resolved'):
                    continue
                signature_ambiguous = False
                if not _runtime_reference_signature_matches(target_signature, item, owner):
                    signature_ambiguous = _runtime_reference_signature_matches(
                        target_signature, item, owner,
                        allow_ambiguous_unqualified=True,
                    )
                    if not signature_ambiguous:
                        continue
            else:
                signature_ambiguous = False
            matches.append({
                'evidence_type': (
                    'bytecode_invokedynamic_method_reference'
                    if item.get('reference_kind') == 'invokedynamic_method_handle'
                    else 'bytecode_constant_pool_method_reference'
                    if item.get('reference_kind') == 'classfile_methodref'
                    else 'bytecode_reflection_method_invocation'
                    if item.get('reference_kind') in {'reflection_method', 'reflection_constructor'}
                    else ('bytecode_method_invocation' if symbol_kind == 'method' else 'bytecode_constructor_invocation')
                ),
                'target_display': f"{owner}.{member_name}{item.get('signature') or ''}",
                'consumer_method': item.get('consumer_method') or '<unknown>',
                'consumer_signature': item.get('consumer_signature') or '',
                'consumer_descriptor': item.get('consumer_descriptor') or '',
                'callee_owner': item.get('jvm_owner') or item.get('owner') or '',
                'callee_member': item.get('name') or '',
                'callee_descriptor': item.get('descriptor') or '',
                'opcode_family': item.get('opcode_family') or '',
                'instruction_offset': item.get('instruction_offset'),
                'signature_ambiguous': signature_ambiguous,
            })
        return _dedupe_runtime_matches(matches)

    if symbol_kind == 'field':
        matches = []
        for item in references.get('field_refs') or []:
            if (
                str(item.get('owner') or '').replace('$', '.') != str(owner or '').replace('$', '.')
                or item.get('name') != member_name
            ):
                continue
            if (
                str(item.get('reference_kind') or '').startswith('reflection_')
                and (not item.get('opcode_family') or item.get('instruction_offset') is None)
            ):
                continue
            matches.append({
                'evidence_type': (
                    'bytecode_reflection_field_access'
                    if item.get('reference_kind') == 'reflection_field'
                    else 'bytecode_constant_pool_field_reference'
                    if item.get('reference_kind') == 'classfile_fieldref'
                    else 'bytecode_field_access'
                ),
                'target_display': f"{owner}.{member_name}",
                'consumer_method': item.get('consumer_method') or '<unknown>',
                'consumer_signature': item.get('consumer_signature') or '',
                'consumer_descriptor': item.get('consumer_descriptor') or '',
                'callee_owner': item.get('jvm_owner') or item.get('owner') or '',
                'callee_member': item.get('name') or '',
                'callee_descriptor': item.get('descriptor') or '',
                'opcode_family': item.get('opcode_family') or '',
                'instruction_offset': item.get('instruction_offset'),
            })
        return _dedupe_runtime_matches(matches)

    return []


def _dedupe_runtime_matches(matches):
    unique = []
    seen = set()
    for item in matches or []:
        identity = (
            item.get('evidence_type'), item.get('target_display'),
            item.get('consumer_method'), item.get('consumer_signature'),
            item.get('consumer_descriptor'), item.get('callee_descriptor'),
            item.get('opcode_family'), item.get('instruction_offset'),
            bool(item.get('signature_ambiguous')),
        )
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(item)
    return unique


def _api_row_for_graph_callee(callee_key, api_rows):
    parsed = _parse_runtime_method_lookup_key(callee_key)
    if parsed:
        callee_owner, callee_member, callee_signature = parsed
        normalized_callee_signature = (
            normalize_signature_for_lookup(callee_signature) or callee_signature
        )
        for api_row in api_rows or []:
            owner, member, symbol_kind = _extract_target_owner_and_member(api_row)
            if symbol_kind not in {'method', 'constructor'}:
                continue
            if str(owner or '').replace('$', '.') != str(callee_owner or '').replace('$', '.'):
                continue
            graph_member = '<init>' if symbol_kind == 'constructor' else callee_member
            if member != graph_member:
                continue
            api_signature = normalize_signature_for_lookup(
                str((api_row or {}).get('api_signature') or '')
            ) or str((api_row or {}).get('api_signature') or '')
            if not api_signature or api_signature == normalized_callee_signature:
                return api_row
    return None


def _graph_edge_target_row(edge, api_rows):
    callee_key = str(getattr(edge, 'callee_key', '') or '').strip()
    matched_api = _api_row_for_graph_callee(callee_key, api_rows)
    if matched_api is not None:
        return matched_api
    evidence_type = str(getattr(edge, 'evidence_type', '') or '')
    if 'field' in evidence_type:
        field_owner, separator, field_member = callee_key.rpartition('.')
        for api_row in api_rows or []:
            owner, member, symbol_kind = _extract_target_owner_and_member(api_row)
            if (
                separator
                and symbol_kind == 'field'
                and str(owner or '').replace('$', '.') == field_owner.replace('$', '.')
                and member == field_member
            ):
                return api_row
    parsed = _parse_runtime_method_lookup_key(callee_key)
    if not parsed:
        return None
    owner, member, signature = parsed
    symbol_kind = 'field' if 'field' in evidence_type else 'method'
    return {
        'coord': str(getattr(edge, 'owner_coord', '') or ''),
        'api_name': f'{owner}.{member}',
        'api_simple': member,
        'api_signature': signature,
        'symbol_kind': symbol_kind,
        'change_type': 'GRAPH_EXECUTABLE_EDGE',
    }


def _runtime_reference_edge_matches_api(api_row, edge):
    owner, member, symbol_kind = _extract_target_owner_and_member(api_row)
    if (
        str((edge or {}).get('callee_owner') or '') != owner
        or str((edge or {}).get('callee_member') or '') != member
    ):
        return False
    if symbol_kind == 'field':
        return True
    descriptor = str((edge or {}).get('callee_descriptor') or '')
    if not descriptor.startswith('('):
        return False
    return normalize_signature_for_lookup(
        _method_descriptor_to_lookup_signature(descriptor)
    ) == normalize_signature_for_lookup(str((api_row or {}).get('api_signature') or ''))


def _retain_exhaustive_runtime_reference_edges(api_rows, edges):
    incoming = defaultdict(list)
    for edge in edges or []:
        incoming[(
            str(edge.get('callee_owner') or ''),
            str(edge.get('callee_member') or ''),
            str(edge.get('callee_descriptor') or ''),
        )].append(edge)
    retained = []
    for api_row in api_rows or []:
        pending = deque(
            edge for edge in (edges or [])
            if _runtime_reference_edge_matches_api(api_row, edge)
        )
        visited = set()
        while pending:
            edge = pending.popleft()
            physical_identity = tuple(str(edge.get(field) or '') for field in (
                'caller_owner', 'consumer_method', 'consumer_descriptor',
                'callee_owner', 'callee_member', 'callee_descriptor',
                'opcode_family', 'jar_path', 'class_entry', 'instruction_offset',
            ))
            if physical_identity in visited:
                continue
            visited.add(physical_identity)
            retained.append({'api_row': api_row, 'edge': edge})
            if str(edge.get('coord') or '') == '__business__':
                continue
            pending.extend(incoming.get((
                str(edge.get('caller_owner') or ''),
                str(edge.get('consumer_method') or ''),
                str(edge.get('consumer_descriptor') or ''),
            ), []))
    return retained


def _collect_exhaustive_runtime_reference_edges(graph):
    catalog = _get_runtime_dependency_catalog(graph)
    catalog_entries = list(catalog.get('entries') or [])
    target_jdk = catalog.get('target_jdk')
    edges = []
    started_at = time.perf_counter()
    emit_progress(
        'step5', 'edge-ledger',
        '开始生成最终制品完整运行时边台账',
        total=len(catalog_entries),
    )
    for item_index, item in enumerate(catalog_entries, 1):
        coord = str(item.get('coord') or '').strip()
        jar_path = str(item.get('jar_path') or '').strip()
        container_entry = '' if coord == '__business__' else str(
            item.get('artifact_entry') or ''
        ).strip()
        if not coord or not jar_path or not os.path.isfile(jar_path):
            _record_analyzer_ledger_failure(
                graph, 'EXHAUSTIVE_RUNTIME_ARTIFACT_MISSING',
                coord=coord, jar_path=jar_path,
            )
            continue
        try:
            artifact_sha256 = _artifact_sha256(jar_path)
            with zipfile.ZipFile(jar_path) as archive:
                try:
                    manifest = archive.read('META-INF/MANIFEST.MF').decode(
                        'utf-8', errors='replace'
                    )
                except KeyError:
                    manifest = ''
                multi_release_enabled = bool(re.search(
                    r'(?im)^Multi-Release\s*:\s*true\s*$', manifest
                ))
                variants, _is_multi_release, _parsed_target = _runtime_class_variants(
                    archive.namelist(), target_jdk,
                    multi_release_enabled=multi_release_enabled,
                )
                for class_entry, logical_name, selected_version in variants:
                    if logical_name.endswith(('module-info.class', 'package-info.class')):
                        continue
                    class_binary_name = logical_name[:-6].replace('/', '.')
                    data = archive.read(class_entry)
                    references = _load_direct_classfile_references(
                        data, artifact_sha256, target_jdk, class_binary_name,
                        multi_release_version=selected_version,
                        class_entry=class_entry, graph=graph,
                    )
                    if references is None:
                        references = _load_runtime_dependency_class_references(
                            catalog, coord, jar_path, class_binary_name,
                            multi_release_version=selected_version,
                            artifact_sha256=artifact_sha256, target_jdk=target_jdk,
                            graph=graph, class_entry=class_entry,
                        )
                    if references is None:
                        _record_analyzer_ledger_failure(
                            graph, 'EXHAUSTIVE_RUNTIME_CLASS_PARSE_FAILED',
                            coord=coord, class_entry=class_entry,
                        )
                        continue
                    member_refs = list(references.get('method_refs') or [])
                    member_refs.extend(references.get('field_refs') or [])
                    for reference in member_refs:
                        callee_owner = str(
                            reference.get('jvm_owner') or reference.get('owner') or ''
                        ).strip()
                        edge = {
                            'coord': coord,
                            'artifact_container_entry': container_entry,
                            'jar_path': jar_path,
                            'class_entry': class_entry,
                            'caller_owner': class_binary_name,
                            'class_fqcn': class_binary_name,
                            'consumer_method': str(reference.get('consumer_method') or ''),
                            'consumer_descriptor': str(reference.get('consumer_descriptor') or ''),
                            'callee_owner': callee_owner,
                            'callee_member': str(reference.get('name') or ''),
                            'callee_descriptor': str(reference.get('descriptor') or ''),
                            'opcode_family': str(reference.get('opcode_family') or ''),
                            'instruction_offset': reference.get('instruction_offset'),
                        }
                        if (
                            edge['consumer_method']
                            and edge['consumer_descriptor']
                            and edge['callee_owner']
                            and edge['callee_member']
                            and edge['callee_descriptor']
                            and edge['opcode_family']
                            and _normalized_instruction_offset(edge['instruction_offset']) is not None
                        ):
                            edges.append(edge)
        except (OSError, KeyError, ValueError, zipfile.BadZipFile) as exc:
            _record_analyzer_ledger_failure(
                graph, 'EXHAUSTIVE_RUNTIME_ARCHIVE_FAILED',
                coord=coord, jar_path=jar_path,
                error_type=type(exc).__name__, error=str(exc),
            )
        emit_progress(
            'step5', 'edge-ledger',
            '完整运行时边台账扫描进度',
            current=item_index, total=len(catalog_entries),
            elapsed=time.perf_counter() - started_at,
            item=coord or jar_path,
        )
    _perf_add(
        graph, 'edge_ledger', 'exhaustive_collect_elapsed_sec',
        time.perf_counter() - started_at,
    )
    _perf_add(graph, 'edge_ledger', 'exhaustive_runtime_edges', len(edges))
    return edges


def collect_graph_analyzer_edges(graph, api_rows):
    """Complete the ledger from verified edges already found during target tracing."""
    if graph is None:
        return 0
    provenance = _verified_final_artifact_provenance(graph)
    if not provenance.get('complete'):
        _record_analyzer_ledger_failure(graph, 'final_artifact_provenance_invalid')
        return 0
    collected = _collect_target_runtime_reference_closure(graph, api_rows)
    candidate_edges = []
    seen_edges = set()
    for edges in (getattr(graph, 'reverse_edges', {}) or {}).values():
        for edge in edges or []:
            edge_object_id = id(edge)
            if edge_object_id in seen_edges:
                continue
            seen_edges.add(edge_object_id)
            if str(getattr(edge, 'evidence_source', '') or '') != 'current_final_artifact':
                continue
            if str(getattr(edge, 'owner_type', '') or '') != 'business':
                continue
            if bool(getattr(edge, 'is_test', False)):
                continue
            evidence_type = str(getattr(edge, 'evidence_type', '') or '')
            if evidence_type in {
                'bytecode_method_invocation',
                'bytecode_constructor_invocation',
                'bytecode_field_access',
            }:
                candidate_edges.append(edge)
    if not candidate_edges:
        return collected

    catalog = _get_runtime_dependency_catalog(graph)
    business_item = (catalog.get('by_coord') or {}).get('__business__') or next(
        (
            item for item in (catalog.get('entries') or [])
            if str(item.get('coord') or '') == '__business__'
        ),
        {},
    )
    business_jar = str(business_item.get('jar_path') or '').strip()
    if not business_jar or not os.path.isfile(business_jar):
        _record_analyzer_ledger_failure(
            graph, 'BUSINESS_BYTECODE_JAR_MISSING', jar_path=business_jar
        )
        return 0
    business_jar_sha256 = str(business_item.get('sha256') or '').strip()
    try:
        actual_business_jar_sha256 = hashlib.sha256(Path(business_jar).read_bytes()).hexdigest()
    except OSError:
        actual_business_jar_sha256 = ''
    if (
        not _valid_sha256(business_jar_sha256)
        or actual_business_jar_sha256 != business_jar_sha256
    ):
        _record_analyzer_ledger_failure(
            graph,
            'BUSINESS_BYTECODE_JAR_SHA_MISMATCH',
            jar_path=business_jar,
        )
        return 0

    methods_by_id = getattr(graph, 'methods_by_id', {}) or {}
    for edge in candidate_edges:
        if str(getattr(edge, 'artifact_sha256', '') or '') != business_jar_sha256:
            _record_analyzer_ledger_failure(
                graph,
                'BUSINESS_EDGE_ARTIFACT_SHA_MISMATCH',
                callee_key=getattr(edge, 'callee_key', ''),
            )
            continue
        _jar_path, separator, class_entry = str(getattr(edge, 'file', '') or '').partition('!/')
        if not separator or not class_entry.endswith('.class'):
            _record_analyzer_ledger_failure(
                graph,
                'BUSINESS_EDGE_CLASS_ENTRY_MISSING',
                evidence_path=getattr(edge, 'file', ''),
            )
            continue
        versioned_entry = re.match(r'^META-INF/versions/(\d+)/(.*\.class)$', class_entry)
        selected_version = int(versioned_entry.group(1)) if versioned_entry else 'base'
        logical_class_entry = versioned_entry.group(2) if versioned_entry else class_entry
        class_binary_name = logical_class_entry[:-6].replace('/', '.')
        target_row = _graph_edge_target_row(edge, api_rows)
        if target_row is None:
            _record_analyzer_ledger_failure(
                graph,
                'BUSINESS_EDGE_TARGET_UNRESOLVED',
                callee_key=getattr(edge, 'callee_key', ''),
            )
            continue
        caller = methods_by_id.get(getattr(edge, 'caller_symbol_id', ''))
        caller_member = str(getattr(caller, 'method_name', '') or '').strip()
        references = None
        try:
            with zipfile.ZipFile(business_jar) as archive:
                class_bytes = archive.read(class_entry)
            references = _load_direct_classfile_references(
                class_bytes,
                business_jar_sha256,
                catalog.get('target_jdk'),
                class_binary_name,
                multi_release_version=selected_version,
                class_entry=class_entry,
                graph=graph,
            )
        except (OSError, KeyError, ValueError, zipfile.BadZipFile):
            references = None
        if references is None:
            references = _load_runtime_dependency_class_references(
                catalog,
                '__business__',
                business_jar,
                class_binary_name,
                artifact_sha256=business_jar_sha256,
                target_jdk=catalog.get('target_jdk'),
                multi_release_version=selected_version,
                graph=graph,
                class_entry=class_entry,
            )
        if references is None:
            _record_analyzer_ledger_failure(
                graph,
                'BUSINESS_EDGE_JAVAP_FAILED',
                class_entry=class_entry,
            )
            continue
        matches = _match_runtime_dependency_references(target_row, references)
        if caller_member:
            matches = [
                match for match in matches
                if str(match.get('consumer_method') or '') == caller_member
            ]
        if not matches:
            _record_analyzer_ledger_failure(
                graph,
                'BUSINESS_EDGE_INSTRUCTION_UNRESOLVED',
                class_entry=class_entry,
                callee_key=getattr(edge, 'callee_key', ''),
            )
            continue
        for matched in matches:
            hit = {
                'coord': '__business__',
                'artifact_container_entry': '',
                'edge_role': 'external_consumer',
                'jar_path': business_jar,
                'class_entry': class_entry,
                'caller_owner': class_binary_name,
                'class_fqcn': class_binary_name.replace('$', '.'),
                'consumer_method': matched.get('consumer_method') or '<unknown>',
                'consumer_descriptor': matched.get('consumer_descriptor') or '',
                'callee_owner': matched.get('callee_owner') or '',
                'callee_member': matched.get('callee_member') or '',
                'callee_descriptor': matched.get('callee_descriptor') or '',
                'opcode_family': matched.get('opcode_family') or '',
                'instruction_offset': matched.get('instruction_offset'),
            }
            if record_analyzer_edge(graph, target_row, hit) is not None:
                collected += 1
    return collected


def _match_runtime_dependency_reference(api_row, references):
    """Compatibility wrapper for callers that only need the first match."""
    matches = _match_runtime_dependency_references(api_row, references)
    return matches[0] if matches else None


def _runtime_class_variants(entries, target_jdk=None, multi_release_enabled=True):
    """Return effective class entries from a normal or Multi-Release JAR."""
    base = {}
    versioned = {}
    for entry in entries or []:
        if not str(entry).endswith('.class'):
            continue
        match = re.match(r'^META-INF/versions/(\d+)/(.*\.class)$', str(entry))
        if match:
            if multi_release_enabled:
                versioned.setdefault(match.group(2), []).append((int(match.group(1)), str(entry)))
        elif not str(entry).startswith('META-INF/'):
            base[str(entry)] = str(entry)

    try:
        raw_target = str(target_jdk or '').strip()
        target = int(raw_target.split('.', 1)[1]) if raw_target.startswith('1.') else int(raw_target.split('.', 1)[0])
    except ValueError:
        target = None

    variants = []
    logical_names = sorted(set(base) | set(versioned))
    for logical_name in logical_names:
        if target is None:
            if logical_name in base:
                variants.append((base[logical_name], logical_name, 'base'))
            for version, entry in sorted(versioned.get(logical_name, [])):
                variants.append((entry, logical_name, version))
            continue
        selected_entry = base.get(logical_name)
        selected_version = 'base'
        for version, entry in sorted(versioned.get(logical_name, [])):
            if version <= target:
                selected_entry = entry
                selected_version = version
        if selected_entry:
            variants.append((selected_entry, logical_name, selected_version))
    return variants, bool(versioned), target


def _scan_packaged_runtime_dependencies_for_api(api_row, graph):
    catalog = _get_runtime_dependency_catalog(graph)
    catalog_status = str(catalog.get('status') or '').strip()
    if catalog_status and catalog_status != 'complete':
        _record_analyzer_ledger_failure(
            graph,
            'ARTIFACT_BYTECODE_COVERAGE_INCOMPLETE',
            catalog_status=catalog_status,
        )
    identity_key = build_api_identity_key(api_row)
    cached_results = catalog.get('_packaged_api_scan_results') or {}
    active_trace_serial = int(
        getattr(graph, '_active_packaged_scan_trace_serial', 0) or 0
    )
    if (
        active_trace_serial
        and catalog.get('_packaged_api_scan_validated_trace_serial') == active_trace_serial
        and identity_key in cached_results
    ):
        return cached_results[identity_key]
    _build_packaged_runtime_dependency_scan_cache([api_row], graph)
    cached_results = catalog.get('_packaged_api_scan_results') or {}
    if identity_key in cached_results:
        return cached_results[identity_key]

    by_coord = catalog.get('by_coord') or {}
    catalog_entries = list(catalog.get('entries') or [
        ({'coord': coord, **item} if not item.get('coord') else item)
        for coord, item in by_coord.items()
    ])
    if not catalog_entries:
        _record_analyzer_ledger_failure(graph, 'RUNTIME_DEPENDENCY_JARS_UNAVAILABLE')
        return {'status': 'unavailable', 'reason': 'RUNTIME_DEPENDENCY_JARS_UNAVAILABLE'}

    owner, member_name, _symbol_kind = _extract_target_owner_and_member(api_row)
    owner_internal_name = _jvm_internal_owner_name(owner)
    if not owner_internal_name:
        _record_analyzer_ledger_failure(graph, 'BYTECODE_TARGET_UNRESOLVED')
        return {'status': 'unavailable', 'reason': 'BYTECODE_TARGET_UNRESOLVED'}

    hits = []
    scan_failures = []
    scanned_classes = 0
    visited_classes = 0
    multi_release_seen = False
    multi_release_target_resolved = False
    target_jdk = catalog.get('target_jdk')
    for item in catalog_entries:
        coord = str(item.get('coord') or '').strip()
        same_coord = coord == str(api_row.get('coord') or '').strip()
        if same_coord and item.get('application_owned') is False:
            _perf_add(graph, 'bytecode_scan', 'external_provider_jars_skipped', 1)
            continue
        jar_path = str(item.get('jar_path') or '').strip()
        if not jar_path or not os.path.exists(jar_path):
            scan_failures.append({
                'reason': 'RUNTIME_DEPENDENCY_JAR_MISSING',
                'coord': coord,
                'jar_path': jar_path,
            })
            continue
        try:
            artifact_sha256 = _artifact_sha256(jar_path)
            with zipfile.ZipFile(jar_path) as zf:
                try:
                    manifest = zf.read('META-INF/MANIFEST.MF').decode('utf-8', errors='replace')
                except KeyError:
                    manifest = ''
                multi_release_enabled = bool(re.search(
                    r'(?im)^Multi-Release\s*:\s*true\s*$', manifest
                ))
                variants, is_multi_release, parsed_target = _runtime_class_variants(
                    zf.namelist(), target_jdk, multi_release_enabled=multi_release_enabled
                )
                multi_release_seen = multi_release_seen or is_multi_release
                if is_multi_release and parsed_target is not None:
                    multi_release_target_resolved = True
                for entry, logical_name, selected_version in variants:
                    if logical_name.endswith('module-info.class') or logical_name.endswith('package-info.class'):
                        continue
                    visited_classes += 1
                    data = zf.read(entry)
                    if not _class_bytes_might_reference_target(data, owner_internal_name, member_name):
                        continue
                    class_binary_name = logical_name[:-6].replace('/', '.')
                    references = _load_runtime_dependency_class_references(
                        catalog, coord, jar_path, class_binary_name,
                        multi_release_version=selected_version,
                        artifact_sha256=artifact_sha256, target_jdk=target_jdk, graph=graph,
                        class_entry=entry,
                    )
                    if references is None:
                        scan_failures.append({
                            'reason': 'BYTECODE_JAVAP_FAILED', 'coord': coord,
                            'jar_path': jar_path, 'class_binary_name': class_binary_name,
                            'multi_release_version': selected_version,
                        })
                        continue
                    scanned_classes += 1
                    matches = _match_runtime_dependency_references(api_row, references)
                    if not matches:
                        continue
                    for matched in matches:
                        hit = {
                            'coord': coord,
                            'target_coord': str(api_row.get('coord') or '').strip(),
                            'application_owned': bool(item.get('application_owned')),
                            'ownership_evidence': item.get('ownership_evidence'),
                            'edge_role': 'internal_bridge' if same_coord else 'external_consumer',
                            'direct_consumer': not same_coord,
                            'jar_path': jar_path,
                            'artifact_container_entry': item.get('artifact_entry') or '',
                            'caller_owner': class_binary_name,
                            'class_fqcn': class_binary_name.replace('$', '.'),
                            'consumer_method': matched.get('consumer_method') or '<unknown>',
                            'consumer_signature': matched.get('consumer_signature') or '',
                            'consumer_descriptor': matched.get('consumer_descriptor') or '',
                            'callee_owner': matched.get('callee_owner') or '',
                            'callee_member': matched.get('callee_member') or '',
                            'callee_descriptor': matched.get('callee_descriptor') or '',
                            'opcode_family': matched.get('opcode_family') or '',
                            'instruction_offset': matched.get('instruction_offset'),
                            'evidence_type': matched.get('evidence_type') or 'bytecode_reference',
                            'signature_ambiguous': bool(matched.get('signature_ambiguous')),
                            'target_display': matched.get('target_display') or owner,
                            'class_entry': entry,
                            'multi_release_version': selected_version,
                        }
                        hits.append(hit)
                        record_analyzer_edge(graph, api_row, hit)
        except Exception as exc:
            scan_failures.append({
                'reason': 'BYTECODE_SCAN_FAILED', 'coord': coord,
                'jar_path': jar_path, 'error': str(exc),
            })
            continue
    _record_analyzer_scan_failures(graph, scan_failures)
    if hits:
        unique_hits = _deduplicate_physical_packaged_hits(hits)
        return {
            'status': 'hit', 'hits': unique_hits, 'scan_failures': scan_failures,
            'scanned_classes': scanned_classes, 'visited_classes': visited_classes,
        }
    if multi_release_seen and not multi_release_target_resolved:
        _record_analyzer_ledger_failure(graph, 'MULTI_RELEASE_TARGET_JDK_UNKNOWN')
        return {
            'status': 'unavailable', 'reason': 'MULTI_RELEASE_TARGET_JDK_UNKNOWN',
            'scan_failures': scan_failures, 'scanned_classes': scanned_classes,
            'visited_classes': visited_classes,
        }
    if catalog_status and catalog_status != 'complete':
        return {
            'status': 'unavailable',
            'reason': 'ARTIFACT_BYTECODE_COVERAGE_INCOMPLETE',
            'catalog_status': catalog.get('status'),
            'catalog_reason_codes': list(catalog.get('reason_codes') or []),
            'scan_failures': scan_failures,
            'scanned_classes': scanned_classes,
            'visited_classes': visited_classes,
        }
    if scan_failures:
        first = scan_failures[0]
        return {'status': 'unavailable', **first, 'scan_failures': scan_failures}
    return {
        'status': 'miss', 'scan_failures': scan_failures,
        'scanned_classes': scanned_classes, 'visited_classes': visited_classes,
    }


def _mark_packaged_scan_input_changed(
    existing, api_rows, failures, scanned_classes, visited_classes,
):
    existing.clear()
    for row in api_rows or ():
        existing[build_api_identity_key(row)] = {
            'status': 'unavailable',
            'reason': 'BYTECODE_SCAN_INPUT_CHANGED',
            'scan_failures': list(failures or ()),
            'scanned_classes': scanned_classes,
            'visited_classes': visited_classes,
            'scan_mode': 'batch',
        }
    return existing


def _commit_packaged_analyzer_edges_transaction(graph, api_hit_pairs):
    analyzer_edges = getattr(graph, 'analyzer_edges', None)
    before = dict(analyzer_edges or {})
    discovery_before = int(
        getattr(graph, '_analyzer_edge_discovery_count', 0) or 0
    )
    incomplete_before = int(
        getattr(graph, '_analyzer_edge_incomplete_count', 0) or 0
    )
    failures_before = set(
        getattr(graph, '_analyzer_edge_failures', set()) or set()
    )
    typed_failures_before = tuple(
        getattr(graph, 'step5_evidence_failures', ()) or ()
    )
    committed = []
    try:
        for api_row, hit in api_hit_pairs or ():
            row = record_analyzer_edge(graph, api_row, hit)
            if row is not None:
                committed.append(row)
    except BaseException:
        current = getattr(graph, 'analyzer_edges', None)
        if current is not None:
            current.clear()
            current.update(before)
        graph._analyzer_edge_discovery_count = discovery_before
        graph._analyzer_edge_incomplete_count = incomplete_before
        graph._analyzer_edge_failures = failures_before
        graph.step5_evidence_failures = typed_failures_before
        raise
    return committed


def _build_packaged_runtime_dependency_scan_cache(api_rows, graph):
    """Batch scan final-artifact runtime dependency bytecode once for all Step5 APIs.

    The previous per-API path repeatedly opened every runtime JAR and repeatedly
    ran javap for the same class. Removed JAR analysis can expand to thousands of
    changed APIs, so the naive complexity becomes APIs × runtime-jars × classes.
    This cache scans each candidate runtime class at most once and then fans the
    parsed bytecode references back out to all matching APIs.
    """
    catalog = _get_runtime_dependency_catalog(graph)
    if not catalog:
        _record_analyzer_ledger_failure(graph, 'RUNTIME_DEPENDENCY_JARS_UNAVAILABLE')
        return {}
    initial_catalog_status = str(catalog.get('status') or '').strip()
    if initial_catalog_status and initial_catalog_status != 'complete':
        _record_analyzer_ledger_failure(
            graph,
            'ARTIFACT_BYTECODE_COVERAGE_INCOMPLETE',
            catalog_status=initial_catalog_status,
        )
    scan_started_at = time.perf_counter()
    _perf_add(graph, 'bytecode_scan', 'calls', 1)
    for metric in (
        'artifact_bytes', 'artifact_count', 'class_entries_scoped',
        'internal_bridge_class_scans', 'direct_consumer_class_scans',
        'external_provider_jars_skipped',
        'artifact_cache_hits', 'artifact_cache_misses', 'javap_fallbacks',
        'class_entries_parsed', 'class_parse_elapsed_sec', 'duplicate_class_scans',
    ):
        _perf_add(graph, 'bytecode_scan', metric, 0)
    by_coord = catalog.get('by_coord') or {}
    catalog_entries = list(catalog.get('entries') or [
        ({'coord': coord, **item} if not item.get('coord') else item)
        for coord, item in by_coord.items()
    ])
    target_jdk = catalog.get('target_jdk')
    current_stat_snapshot = _runtime_artifact_stat_snapshot(
        catalog_entries, target_jdk
    )
    existing = catalog.setdefault('_packaged_api_scan_results', {})
    if (
        existing
        and catalog.get('_packaged_api_scan_stat_snapshot') != current_stat_snapshot
    ):
        existing.clear()
    api_rows = [dict(row or {}) for row in (api_rows or []) if (row or {}).get('api_name')]
    missing_rows = [
        row for row in api_rows
        if build_api_identity_key(row) not in existing
    ]
    _perf_add(graph, 'bytecode_scan', 'api_rows', len(api_rows))
    _perf_add(graph, 'bytecode_scan', 'missing_api_rows', len(missing_rows))
    _perf_add(graph, 'bytecode_scan', 'cache_hit_api_rows', max(0, len(api_rows) - len(missing_rows)))
    if not missing_rows:
        snapshot_after_cache_check = _runtime_artifact_stat_snapshot(
            catalog_entries, target_jdk
        )
        if snapshot_after_cache_check != current_stat_snapshot:
            existing.clear()
            missing_rows = list(api_rows)
            current_stat_snapshot = snapshot_after_cache_check
        else:
            _perf_add(graph, 'bytecode_scan', 'elapsed_sec', time.perf_counter() - scan_started_at)
            return existing

    target_rows_by_owner = defaultdict(list)
    owner_internal_names = {}
    for row in missing_rows:
        key = build_api_identity_key(row)
        owner, _member_name, _symbol_kind = _extract_target_owner_and_member(row)
        if not owner:
            _record_analyzer_ledger_failure(
                graph,
                'BYTECODE_TARGET_UNRESOLVED',
                api_identity=key,
            )
            existing[key] = {
                'status': 'unavailable',
                'reason': 'BYTECODE_TARGET_UNRESOLVED',
                'scan_failures': [],
                'scanned_classes': 0,
                'visited_classes': 0,
            }
            continue
        canonical_owner = owner.replace('$', '.')
        target_rows_by_owner[canonical_owner].append(row)
        owner_internal_names[canonical_owner] = _jvm_internal_owner_name(owner)

    if not target_rows_by_owner:
        _perf_add(graph, 'bytecode_scan', 'elapsed_sec', time.perf_counter() - scan_started_at)
        return existing

    scan_failures = []
    candidate_failures_by_key = defaultdict(list)
    hits_by_key = defaultdict(list)
    javap_tasks = []
    scanned_classes = 0
    actual_javap_classes = 0
    direct_classfile_classes = 0
    visited_classes = 0
    multi_release_seen = False
    multi_release_target_resolved = False
    counted_artifacts = set()
    scanned_artifact_sha256 = {}
    fast_member_index = None
    fast_member_index_identity = None
    started_at = time.perf_counter()
    progress_interval = suggest_log_interval(len(catalog_entries), target_updates=8, minimum=1)

    if not catalog_entries:
        _record_analyzer_ledger_failure(graph, 'RUNTIME_DEPENDENCY_JARS_UNAVAILABLE')
        for row in missing_rows:
            key = build_api_identity_key(row)
            existing.setdefault(key, {
                'status': 'unavailable',
                'reason': 'RUNTIME_DEPENDENCY_JARS_UNAVAILABLE',
                'scan_failures': [],
                'scanned_classes': 0,
                'visited_classes': 0,
            })
        _perf_add(graph, 'bytecode_scan', 'elapsed_sec', time.perf_counter() - scan_started_at)
        return existing

    _perf_add(graph, 'bytecode_scan', 'catalog_entries', len(catalog_entries))
    _perf_max(graph, 'bytecode_scan', 'max_catalog_entries', len(catalog_entries))
    emit_progress(
        "step5",
        "bytecode-scan",
        f"开始批量扫描运行时依赖字节码，依赖数={len(catalog_entries)}，API数={len(missing_rows)}",
    )

    scan_catalog_entries = catalog_entries
    fact_store = getattr(graph, 'step5_artifact_fact_store', None)
    if fact_store is not None and len(missing_rows) >= 32 and len(catalog_entries) >= 8:
        member_index = _build_runtime_dependency_member_candidate_index(
            graph, catalog_entries, target_jdk,
        )
        indexed_tasks = _batch_candidates_from_runtime_member_index(
            member_index, target_rows_by_owner,
        )
        verified_inventories = {}
        for item in catalog_entries:
            coord = str(item.get('coord') or '').strip()
            inventory = fact_store.inventory(coord) if coord else None
            if not (
                inventory is not None
                and not inventory.failure
                and inventory.identity.path == str(item.get('jar_path') or '').strip()
                and inventory.identity.sha256 == str(item.get('sha256') or '').lower()
            ):
                verified_inventories = {}
                indexed_tasks = None
                break
            verified_inventories[coord] = inventory
        if indexed_tasks is not None:
            member_index['_stat_snapshot'] = current_stat_snapshot
            setattr(graph, '_runtime_dependency_member_candidate_index', member_index)
            fast_member_index = member_index
            fast_member_index_identity = (
                _runtime_member_index_cache_identity_from_verified_catalog(
                    catalog_entries, target_jdk,
                )
            )
            scan_catalog_entries = []
            for item in catalog_entries:
                coord = str(item.get('coord') or '').strip()
                ownership_explicitly_external = item.get('application_owned') is False
                eligible = any(
                    not ownership_explicitly_external
                    or str(row.get('coord') or '').strip() != coord
                    for rows in target_rows_by_owner.values() for row in rows
                )
                if not eligible:
                    _perf_add(graph, 'bytecode_scan', 'external_provider_jars_skipped', 1)
                    continue
                inventory = verified_inventories[coord]
                jar_path = str(item.get('jar_path') or '').strip()
                artifact_sha256 = inventory.identity.sha256
                scanned_artifact_sha256[str(Path(jar_path).resolve())] = artifact_sha256
                if artifact_sha256 in counted_artifacts:
                    _perf_add(graph, 'bytecode_scan', 'duplicate_jar_scans', 1)
                else:
                    counted_artifacts.add(artifact_sha256)
                    _perf_add(graph, 'bytecode_scan', 'artifact_bytes', os.path.getsize(jar_path))
                    _perf_add(graph, 'bytecode_scan', 'artifact_count', 1)
                scoped_classes = sum(
                    1 for location in inventory.classes
                    if not location.logical_name.endswith(
                        ('module-info.class', 'package-info.class')
                    )
                )
                visited_classes += scoped_classes
                _perf_add(graph, 'bytecode_scan', 'class_entries_scoped', scoped_classes)
                multi_release_seen = multi_release_seen or inventory.multi_release
                if inventory.multi_release and inventory.target_jdk_resolved:
                    multi_release_target_resolved = True
            for task in indexed_tasks:
                javap_tasks.append({
                    **task,
                    'catalog': catalog,
                    'graph': graph,
                    'caller_owner': task.get('class_binary_name') or '',
                    'preparsed_references': None,
                })
            _perf_add(graph, 'bytecode_scan', 'member_index_fast_path', 1)
            _perf_add(
                graph, 'bytecode_scan',
                'member_index_candidate_classes', len(javap_tasks),
            )

    owner_packages = defaultdict(list)
    for owner, internal in owner_internal_names.items():
        internal_package = internal.rsplit('/', 1)[0] if '/' in internal else ''
        dotted_package = owner.rsplit('.', 1)[0] if '.' in owner else ''
        owner_packages[(internal_package, dotted_package)].append(
            (owner, internal.encode('utf-8'), owner.encode('utf-8'))
        )
    package_bytes = [
        (
            internal_package.encode('utf-8') if internal_package else b'',
            dotted_package.encode('utf-8') if dotted_package else b'',
            grouped_owners,
        )
        for (internal_package, dotted_package), grouped_owners in owner_packages.items()
    ]

    for idx, item in enumerate(scan_catalog_entries, 1):
        coord = str(item.get('coord') or '').strip()
        application_owned = bool(item.get('application_owned'))
        ownership_explicitly_external = item.get('application_owned') is False
        eligible_owners = {
            owner
            for owner, rows in target_rows_by_owner.items()
            if not ownership_explicitly_external or any(
                str(row.get('coord') or '').strip() != coord for row in rows
            )
        }
        if not eligible_owners:
            _perf_add(graph, 'bytecode_scan', 'external_provider_jars_skipped', 1)
            continue
        jar_path = str(item.get('jar_path') or '').strip()
        jar_started_at = time.perf_counter()
        jar_visited_classes = 0
        jar_candidate_classes = 0
        jar_constant_pool_hits = 0
        jar_failed = False
        if should_log_progress(idx, len(catalog_entries), progress_interval):
            emit_progress(
                "step5",
                "bytecode-scan",
                f"正在扫描运行时依赖字节码 {coord or '<unknown>'}",
                current=idx,
                total=len(catalog_entries),
                elapsed=time.perf_counter() - started_at,
                item=coord or jar_path,
            )
        if not jar_path or not os.path.exists(jar_path):
            _perf_add(graph, 'bytecode_scan', 'missing_jars', 1)
            jar_failed = True
            scan_failures.append({
                'reason': 'RUNTIME_DEPENDENCY_JAR_MISSING',
                'coord': coord,
                'jar_path': jar_path,
            })
            _perf_record_top(graph, 'bytecode_scan', 'slow_jar_scans', {
                'coord': coord,
                'jar_path': jar_path,
                'elapsed_sec': time.perf_counter() - jar_started_at,
                'visited_classes': jar_visited_classes,
                'candidate_classes': jar_candidate_classes,
                'constant_pool_hits': jar_constant_pool_hits,
                'failed': jar_failed,
            })
            continue
        try:
            artifact_sha256 = _artifact_sha256(jar_path)
            scanned_artifact_sha256[str(Path(jar_path).resolve())] = artifact_sha256
            if artifact_sha256 in counted_artifacts:
                _perf_add(graph, 'bytecode_scan', 'duplicate_jar_scans', 1)
            else:
                counted_artifacts.add(artifact_sha256)
                _perf_add(graph, 'bytecode_scan', 'artifact_bytes', os.path.getsize(jar_path))
                _perf_add(graph, 'bytecode_scan', 'artifact_count', 1)
            with zipfile.ZipFile(jar_path) as zf:
                try:
                    manifest = zf.read('META-INF/MANIFEST.MF').decode('utf-8', errors='replace')
                except KeyError:
                    manifest = ''
                multi_release_enabled = bool(re.search(
                    r'(?im)^Multi-Release\s*:\s*true\s*$', manifest
                ))
                variants, is_multi_release, parsed_target = _runtime_class_variants(
                    zf.namelist(), target_jdk, multi_release_enabled=multi_release_enabled
                )
                multi_release_seen = multi_release_seen or is_multi_release
                if is_multi_release and parsed_target is not None:
                    multi_release_target_resolved = True
                for entry, logical_name, selected_version in variants:
                    if logical_name.endswith('module-info.class') or logical_name.endswith('package-info.class'):
                        continue
                    visited_classes += 1
                    jar_visited_classes += 1
                    _perf_add(graph, 'bytecode_scan', 'class_entries_scoped', 1)
                    data = zf.read(entry)
                    owner_candidates = []
                    for internal_package_bytes, dotted_package_bytes, grouped_owners in package_bytes:
                        if (
                            internal_package_bytes
                            and internal_package_bytes not in data
                            and dotted_package_bytes
                            and dotted_package_bytes not in data
                        ):
                            continue
                        owner_candidates.extend(grouped_owners)
                    candidate_owners = [
                        owner for owner, internal_bytes, dotted_bytes in owner_candidates
                        if owner in eligible_owners
                        and (internal_bytes in data or dotted_bytes in data)
                    ]
                    if not candidate_owners:
                        continue
                    class_binary_name = logical_name[:-6].replace('/', '.')
                    preparsed_references = _load_direct_classfile_references(
                        data, artifact_sha256, target_jdk, class_binary_name,
                        multi_release_version=selected_version, class_entry=entry, graph=graph,
                    )
                    if preparsed_references is not None:
                        jar_constant_pool_hits += 1
                        _perf_add(graph, 'bytecode_scan', 'classfile_fast_path_hits', 1)
                    javap_tasks.append({
                        'catalog': catalog,
                        'coord': coord,
                        'jar_path': jar_path,
                        'artifact_container_entry': item.get('artifact_entry') or '',
                        'caller_owner': class_binary_name,
                        'class_binary_name': class_binary_name,
                        'class_fqcn': class_binary_name.replace('$', '.'),
                        'class_entry': entry,
                        'multi_release_version': selected_version,
                        'artifact_sha256': artifact_sha256,
                        'target_jdk': target_jdk,
                        'graph': graph,
                        'candidate_owners': sorted(set(candidate_owners)),
                        'preparsed_references': preparsed_references,
                        'application_owned': bool(item.get('application_owned')),
                        'ownership_evidence': item.get('ownership_evidence'),
                    })
                    jar_candidate_classes += 1
        except Exception as exc:
            _perf_add(graph, 'bytecode_scan', 'jar_scan_failures', 1)
            jar_failed = True
            scan_failures.append({
                'reason': 'BYTECODE_SCAN_FAILED',
                'coord': coord,
                'jar_path': jar_path,
                'error': str(exc),
            })
        finally:
            _perf_record_top(graph, 'bytecode_scan', 'slow_jar_scans', {
                'coord': coord,
                'jar_path': jar_path,
                'elapsed_sec': time.perf_counter() - jar_started_at,
                'visited_classes': jar_visited_classes,
                'candidate_classes': jar_candidate_classes,
                'constant_pool_hits': jar_constant_pool_hits,
                'failed': jar_failed,
            })

    if javap_tasks:
        workers = min(_step5_bytecode_javap_workers(), len(javap_tasks))
        javap_started_at = time.perf_counter()
        emit_progress(
            "step5",
            "bytecode-scan",
            f"解析候选运行时依赖字节码，候选class={len(javap_tasks)}，并行度={workers}",
            elapsed=time.perf_counter() - started_at,
        )

        def handle_javap_result(task, references):
            nonlocal scanned_classes, actual_javap_classes, direct_classfile_classes
            coord = task.get('coord') or ''
            jar_path = task.get('jar_path') or ''
            class_binary_name = task.get('class_binary_name') or ''
            task_started_at = float(task.get('_javap_started_at') or time.perf_counter())
            task_elapsed = time.perf_counter() - task_started_at
            selected_version = task.get('multi_release_version')
            candidate_owners = task.get('candidate_owners') or []
            if references is None:
                _perf_add(graph, 'bytecode_scan', 'javap_failures', 1)
                _perf_record_top(graph, 'bytecode_scan', 'slow_javap_tasks', {
                    'coord': coord,
                    'jar_path': jar_path,
                    'class_binary_name': class_binary_name,
                    'multi_release_version': selected_version,
                    'elapsed_sec': task_elapsed,
                    'failed': True,
                })
                failure = {
                    'reason': 'BYTECODE_JAVAP_FAILED',
                    'coord': coord,
                    'jar_path': jar_path,
                    'class_binary_name': class_binary_name,
                    'multi_release_version': selected_version,
                }
                failure.update(task.get('parse_failure') or {})
                for owner in set(candidate_owners):
                    for api_row in target_rows_by_owner.get(owner, []):
                        candidate_failures_by_key[build_api_identity_key(api_row)].append(failure)
                return
            scanned_classes += 1
            if task.get('preparsed_references') is not None:
                direct_classfile_classes += 1
            else:
                actual_javap_classes += 1
            _perf_record_top(graph, 'bytecode_scan', 'slow_javap_tasks', {
                'coord': coord,
                'jar_path': jar_path,
                'class_binary_name': class_binary_name,
                'multi_release_version': selected_version,
                'elapsed_sec': task_elapsed,
                'failed': False,
            })
            referenced_owners = {
                str(value or '').replace('$', '.')
                for value in (references.get('class_refs') or [])
                if value
            }
            referenced_owners.update(
                str(item.get('owner') or '').replace('$', '.')
                for item in references.get('method_refs') or []
                if item.get('owner')
            )
            referenced_owners.update(
                str(item.get('owner') or '').replace('$', '.')
                for item in references.get('field_refs') or []
                if item.get('owner')
            )
            matched_api_keys = set()
            for owner in set(candidate_owners) & {item for item in referenced_owners if item}:
                for api_row in target_rows_by_owner.get(owner, []):
                    same_coord = coord == str(api_row.get('coord') or '').strip()
                    matches = _match_runtime_dependency_references(api_row, references)
                    if not matches:
                        continue
                    key = build_api_identity_key(api_row)
                    if key not in matched_api_keys:
                        matched_api_keys.add(key)
                        metric = (
                            'internal_bridge_class_scans'
                            if coord == str(api_row.get('coord') or '').strip()
                            else 'direct_consumer_class_scans'
                        )
                        _perf_add(graph, 'bytecode_scan', metric, 1)
                    for matched in matches:
                        hit = {
                            'coord': coord,
                            'target_coord': str(api_row.get('coord') or '').strip(),
                            'application_owned': bool(task.get('application_owned')),
                            'ownership_evidence': task.get('ownership_evidence'),
                            'edge_role': 'internal_bridge' if same_coord else 'external_consumer',
                            'direct_consumer': not same_coord,
                            'jar_path': jar_path,
                            'artifact_container_entry': task.get('artifact_container_entry') or '',
                            'caller_owner': task.get('caller_owner') or class_binary_name,
                            'class_fqcn': task.get('class_fqcn') or class_binary_name.replace('$', '.'),
                            'consumer_method': matched.get('consumer_method') or '<unknown>',
                            'consumer_signature': matched.get('consumer_signature') or '',
                            'consumer_descriptor': matched.get('consumer_descriptor') or '',
                            'callee_owner': matched.get('callee_owner') or '',
                            'callee_member': matched.get('callee_member') or '',
                            'callee_descriptor': matched.get('callee_descriptor') or '',
                            'opcode_family': matched.get('opcode_family') or '',
                            'instruction_offset': matched.get('instruction_offset'),
                            'evidence_type': matched.get('evidence_type') or 'bytecode_reference',
                            'signature_ambiguous': bool(matched.get('signature_ambiguous')),
                            'target_display': matched.get('target_display') or owner,
                            'class_entry': task.get('class_entry') or '',
                            'multi_release_version': selected_version,
                        }
                        hits_by_key[key].append(hit)

        if workers <= 1:
            progress_interval = suggest_log_interval(len(javap_tasks), target_updates=12, minimum=1)
            for done_count, task in enumerate(javap_tasks, 1):
                task['_javap_started_at'] = time.perf_counter()
                _task, references = _load_runtime_dependency_class_references_for_task(task)
                handle_javap_result(_task, references)
                if should_log_progress(done_count, len(javap_tasks), progress_interval):
                    emit_progress(
                        "step5",
                        "bytecode-scan",
                        "运行时依赖候选 class 解析进度",
                        current=done_count,
                        total=len(javap_tasks),
                        elapsed=time.perf_counter() - javap_started_at,
                        item=(task.get('class_binary_name') or '')[:100],
                    )
        else:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_map = {
                    executor.submit(
                        _load_runtime_dependency_class_references_for_task,
                        {**task, '_javap_started_at': time.perf_counter()},
                    ): task
                    for task in javap_tasks
                }
                progress_interval = suggest_log_interval(len(future_map), target_updates=12, minimum=1)
                for done_count, future in enumerate(as_completed(future_map), 1):
                    task = future_map[future]
                    try:
                        _task, references = future.result()
                    except Exception as exc:
                        _task, references = task, None
                        _task['parse_failure'] = {
                            'reason': 'BYTECODE_WORKER_FAILED',
                            'error_type': type(exc).__name__,
                            'error': str(exc),
                        }
                    handle_javap_result(_task, references)
                    if should_log_progress(done_count, len(future_map), progress_interval):
                        emit_progress(
                            "step5",
                            "bytecode-scan",
                            "运行时依赖候选 class 解析进度",
                            current=done_count,
                            total=len(future_map),
                            elapsed=time.perf_counter() - javap_started_at,
                            item=(task.get('class_binary_name') or '')[:100],
                        )
        _perf_add(graph, 'bytecode_scan', 'javap_elapsed_sec', time.perf_counter() - javap_started_at)

    snapshot_before_final_hash = _runtime_artifact_stat_snapshot(
        catalog_entries, target_jdk
    )
    changed_artifacts = []
    for jar_path, expected_sha256 in sorted(scanned_artifact_sha256.items()):
        try:
            actual_sha256 = _artifact_sha256(jar_path)
        except OSError as exc:
            actual_sha256 = ''
            error = f'{type(exc).__name__}:{exc}'
        else:
            error = ''
        if actual_sha256 != expected_sha256:
            changed_artifacts.append({
                'reason': 'BYTECODE_SCAN_INPUT_CHANGED',
                'jar_path': jar_path,
                'expected_sha256': expected_sha256,
                'actual_sha256': actual_sha256,
                'error': error,
            })
    snapshot_after_final_hash = _runtime_artifact_stat_snapshot(
        catalog_entries, target_jdk
    )
    if snapshot_after_final_hash != snapshot_before_final_hash:
        changed_artifacts.append({
            'reason': 'BYTECODE_SCAN_INPUT_CHANGED',
            'jar_path': '',
            'expected_sha256': '',
            'actual_sha256': '',
            'error': 'runtime dependency stat identity changed during final verification',
        })
    if changed_artifacts:
        scan_failures.extend(changed_artifacts)
        _record_analyzer_scan_failures(graph, changed_artifacts)
        _mark_packaged_scan_input_changed(
            existing, api_rows, changed_artifacts,
            scanned_classes, visited_classes,
        )
        catalog['_packaged_api_scan_stat_snapshot'] = None
        _perf_add(graph, 'bytecode_scan', 'scan_failures', len(scan_failures))
        _perf_add(graph, 'bytecode_scan', 'elapsed_sec', time.perf_counter() - scan_started_at)
        return existing

    committed_analyzer_edges = _commit_packaged_analyzer_edges_transaction(
        graph,
        [
            (row, hit)
            for row in missing_rows
            for hit in (hits_by_key.get(build_api_identity_key(row)) or ())
        ],
    )

    snapshot_after_commit = _runtime_artifact_stat_snapshot(
        catalog_entries, target_jdk
    )
    if snapshot_after_commit != snapshot_after_final_hash:
        analyzer_edges = getattr(graph, 'analyzer_edges', {}) or {}
        for row in committed_analyzer_edges:
            identity = physical_analyzer_edge_identity(row)
            if analyzer_edges.get(identity) is row:
                analyzer_edges.pop(identity, None)
        failure = {
            'reason': 'BYTECODE_SCAN_INPUT_CHANGED',
            'jar_path': '',
            'error': 'runtime dependency stat identity changed during edge commit',
        }
        _record_analyzer_scan_failures(graph, [failure])
        _mark_packaged_scan_input_changed(
            existing, api_rows, [failure], scanned_classes, visited_classes,
        )
        catalog['_packaged_api_scan_stat_snapshot'] = None
        _perf_add(graph, 'bytecode_scan', 'scan_failures', 1)
        _perf_add(graph, 'bytecode_scan', 'elapsed_sec', time.perf_counter() - scan_started_at)
        return existing

    member_cache_path = _runtime_member_index_cache_path(graph)
    if (
        fast_member_index is not None
        and fast_member_index_identity is not None
        and member_cache_path is not None
    ):
        try:
            _write_runtime_member_index_cache(
                member_cache_path, fast_member_index_identity, fast_member_index,
            )
            fast_member_index['_identity'] = fast_member_index_identity
            _perf_add(graph, 'bytecode_expand', 'member_index_cache_writes', 1)
        except (OSError, TypeError, ValueError):
            _perf_add(graph, 'bytecode_expand', 'member_index_cache_write_failures', 1)

    catalog['_packaged_api_scan_stat_snapshot'] = snapshot_after_commit
    _record_analyzer_scan_failures(graph, scan_failures)
    for failures in candidate_failures_by_key.values():
        _record_analyzer_scan_failures(graph, failures)
    catalog_status = str(catalog.get('status') or '').strip()
    for row in missing_rows:
        key = build_api_identity_key(row)
        if key in existing and existing[key].get('status') == 'unavailable':
            continue
        hits = hits_by_key.get(key) or []
        api_scan_failures = scan_failures + list(candidate_failures_by_key.get(key) or [])
        if hits:
            unique_hits = _deduplicate_physical_packaged_hits(hits)
            existing[key] = {
                'status': 'hit',
                'hits': unique_hits,
                'scan_failures': api_scan_failures,
                'scanned_classes': scanned_classes,
                'visited_classes': visited_classes,
                'scan_mode': 'batch',
            }
            continue
        if multi_release_seen and not multi_release_target_resolved:
            _record_analyzer_ledger_failure(
                graph,
                'MULTI_RELEASE_TARGET_JDK_UNKNOWN',
                api_identity=key,
            )
            existing[key] = {
                'status': 'unavailable',
                'reason': 'MULTI_RELEASE_TARGET_JDK_UNKNOWN',
                'scan_failures': api_scan_failures,
                'scanned_classes': scanned_classes,
                'visited_classes': visited_classes,
                'scan_mode': 'batch',
            }
            continue
        if catalog_status and catalog_status != 'complete':
            existing[key] = {
                'status': 'unavailable',
                'reason': 'ARTIFACT_BYTECODE_COVERAGE_INCOMPLETE',
                'catalog_status': catalog.get('status'),
                'catalog_reason_codes': list(catalog.get('reason_codes') or []),
                'scan_failures': api_scan_failures,
                'scanned_classes': scanned_classes,
                'visited_classes': visited_classes,
                'scan_mode': 'batch',
            }
            continue
        if api_scan_failures:
            first = dict(api_scan_failures[0])
            existing[key] = {
                'status': 'unavailable',
                **first,
                'scan_failures': api_scan_failures,
                'scanned_classes': scanned_classes,
                'visited_classes': visited_classes,
                'scan_mode': 'batch',
            }
            continue
        existing[key] = {
            'status': 'miss',
            'scan_failures': api_scan_failures,
            'scanned_classes': scanned_classes,
            'visited_classes': visited_classes,
            'scan_mode': 'batch',
        }

    emit_progress(
        "step5",
        "bytecode-scan",
        (
            "运行时依赖字节码批量扫描完成，"
            f"visited_classes={visited_classes}，classfile_fast_path={direct_classfile_classes}，"
            f"javap_classes={actual_javap_classes}，"
            f"hit_apis={sum(1 for key in hits_by_key if hits_by_key.get(key))}"
        ),
        current=len(catalog_entries),
        total=len(catalog_entries),
        elapsed=time.perf_counter() - started_at,
    )
    _perf_add(graph, 'bytecode_scan', 'elapsed_sec', time.perf_counter() - scan_started_at)
    _perf_add(graph, 'bytecode_scan', 'visited_classes', visited_classes)
    _perf_add(graph, 'bytecode_scan', 'candidate_parse_tasks', len(javap_tasks))
    _perf_add(graph, 'bytecode_scan', 'javap_tasks', actual_javap_classes)
    _perf_add(graph, 'bytecode_scan', 'classfile_fast_path_classes', direct_classfile_classes)
    _perf_add(graph, 'bytecode_scan', 'javap_classes', actual_javap_classes)
    _perf_add(graph, 'bytecode_scan', 'hit_apis', sum(1 for key in hits_by_key if hits_by_key.get(key)))
    _perf_add(graph, 'bytecode_scan', 'scan_failures', len(scan_failures))
    return existing


_JAVA_LANG_SIMPLE_TYPES = {
    'Boolean', 'Byte', 'Character', 'CharSequence', 'Class', 'Double', 'Enum',
    'Float', 'Integer', 'Long', 'Number', 'Object', 'Short', 'String', 'Void',
}


def _expand_java_lang_signature(signature):
    text = str(signature or '').strip()
    if not (text.startswith('(') and text.endswith(')')):
        return ''
    body = text[1:-1].strip()
    if not body:
        return text
    parts = [part.strip() for part in body.split(',')]
    expanded = []
    changed = False
    for part in parts:
        array_suffix = ''
        base = part
        while base.endswith('[]'):
            array_suffix += '[]'
            base = base[:-2].strip()
        if base in _JAVA_LANG_SIMPLE_TYPES:
            expanded.append(f"java.lang.{base}{array_suffix}")
            changed = True
        else:
            expanded.append(part)
    return '(' + ', '.join(expanded) + ')' if changed else ''


def _packaged_hit_consumer_lookup_keys(hit):
    class_fqcn = str(hit.get('class_fqcn') or '').strip()
    consumer_method = str(hit.get('consumer_method') or '').strip()
    consumer_signature = str(hit.get('consumer_signature') or '').strip()
    if not class_fqcn or not consumer_method or consumer_method == '<class>':
        return []
    method_display = consumer_method
    if consumer_method == '<init>':
        method_display = class_fqcn.rsplit('.', 1)[-1]
    keys = []
    signatures = [consumer_signature] if consumer_signature else []
    expanded_signature = _expand_java_lang_signature(consumer_signature)
    if expanded_signature:
        signatures.append(expanded_signature)
    for signature in signatures:
        keys.append(f"{class_fqcn}.{consumer_method}{signature}")
        if method_display != consumer_method:
            keys.append(f"{class_fqcn}.{method_display}{signature}")
    if not consumer_signature:
        keys.append(f"{class_fqcn}.{consumer_method}")
        if method_display != consumer_method:
            keys.append(f"{class_fqcn}.{method_display}")
    return list(dict.fromkeys(keys))


def _parse_runtime_method_lookup_key(key):
    value = str(key or '').strip()
    if not value or value.startswith(('class:', 'method:', 'field:', 'invokedynamic:')):
        return None
    signature = ''
    owner_member = value
    if '(' in value:
        owner_member, tail = value.split('(', 1)
        signature = '(' + tail
    if '.' not in owner_member:
        return None
    owner, member = owner_member.rsplit('.', 1)
    if not owner or not member:
        return None
    return owner, member, signature


def _runtime_method_def_for_packaged_caller(coord, jar_path, class_fqcn, method_name, signature):
    normalized_class = str(class_fqcn or '').replace('$', '.')
    method_name = str(method_name or '').strip() or '<unknown>'
    signature = str(signature or '').strip()
    # Runtime reverse expansion must retain the JVM constructor member name.
    # Replacing it with the class name creates a key no classfile can call.
    display_method = method_name
    qualified_key = f'{normalized_class}.{display_method}{signature}'
    return MethodDef(
        symbol_id=f'runtime:{coord}:{qualified_key}',
        qualified_key=qualified_key,
        simple_key=f'{display_method}{signature}',
        class_fqcn=normalized_class,
        class_name=normalized_class.rsplit('.', 1)[-1],
        method_name=display_method,
        return_type='',
        file=str(jar_path or ''),
        line=0,
        end_line=0,
        package_name=normalized_class.rsplit('.', 1)[0] if '.' in normalized_class else '',
        owner_type='business' if str(coord or '') == '__business__' else 'dependency',
        owner_coord=str(coord or ''),
        module='',
        source_root='',
        language='bytecode',
        is_test=False,
    )


def _add_runtime_dependency_caller_edge(
    graph, lookup_key, coord, jar_path, class_fqcn, matched, analyzer_hit=None
):
    methods_by_id = getattr(graph, 'methods_by_id', {}) or {}
    reverse_edges = getattr(graph, 'reverse_edges', {}) or {}
    reverse_edge_count = getattr(graph, 'reverse_edge_count', None)
    if reverse_edge_count is None:
        reverse_edge_count = sum(len(edges) for edges in reverse_edges.values())
    consumer_method = matched.get('consumer_method') or '<unknown>'
    consumer_signature = matched.get('consumer_signature') or ''
    caller = _runtime_method_def_for_packaged_caller(
        coord, jar_path, class_fqcn, consumer_method, consumer_signature
    )
    methods_by_id.setdefault(caller.symbol_id, caller)
    parsed_lookup = _parse_runtime_method_lookup_key(lookup_key)
    lookup_member = parsed_lookup[1] if parsed_lookup else ''
    lookup_signature = parsed_lookup[2] if parsed_lookup else ''
    lookup_simple_signature = normalize_signature_for_lookup(lookup_signature) or lookup_signature
    edge = CallEdge(
        caller_symbol_id=caller.symbol_id,
        caller_qualified_key=caller.qualified_key,
        callee_key=lookup_key,
        callee_simple_key=f'method:{lookup_member}{lookup_simple_signature}',
        evidence_type=matched.get('evidence_type') or 'runtime_dependency_bytecode_invocation',
        confidence='high',
        file=str(jar_path or ''),
        line=0,
        content='runtime dependency bytecode caller',
        owner_type='business' if str(coord or '') == '__business__' else 'dependency',
        owner_coord=str(coord or ''),
        module='',
        is_test=False,
        callee_param_types=[],
    )
    edge.callee_fqcn_complete = bool(
        lookup_key
        and '.' in str(lookup_key).split('(', 1)[0]
        and not str(lookup_key).startswith(('method:', 'field:', 'class:'))
    )
    edge.callee_signature_complete = bool(lookup_signature)
    if edge.callee_fqcn_complete and edge.callee_signature_complete:
        edge.callee_resolution_note = '调用目标已解析到全限定名和签名'
    elif not edge.callee_fqcn_complete:
        edge.callee_resolution_note = '缺少调用目标所属类全限定名'
    else:
        edge.callee_resolution_note = '缺少调用目标方法参数签名'
    if analyzer_hit:
        edge.runtime_analyzer_hit = dict(analyzer_hit)
        edge.application_owned = bool(analyzer_hit.get('application_owned'))
        edge.ownership_evidence = analyzer_hit.get('ownership_evidence')
    if str(coord or '') == '__business__':
        edge.evidence_source = 'current_final_artifact'
    for key in (lookup_key, edge.callee_simple_key):
        bucket = reverse_edges.setdefault(key, [])
        identity = (
            edge.caller_symbol_id, edge.callee_key, edge.evidence_type,
            _normalized_instruction_offset((analyzer_hit or {}).get('instruction_offset')),
            str((analyzer_hit or {}).get('consumer_descriptor') or ''),
            str((analyzer_hit or {}).get('callee_descriptor') or ''),
        )
        if any((
            old.caller_symbol_id, old.callee_key, old.evidence_type,
            _normalized_instruction_offset(
                (getattr(old, 'runtime_analyzer_hit', {}) or {}).get('instruction_offset')
            ),
            str((getattr(old, 'runtime_analyzer_hit', {}) or {}).get('consumer_descriptor') or ''),
            str((getattr(old, 'runtime_analyzer_hit', {}) or {}).get('callee_descriptor') or ''),
        ) == identity for old in bucket):
            continue
        bucket.append(edge)
        reverse_edge_count += 1
    graph.methods_by_id = methods_by_id
    graph.reverse_edges = reverse_edges
    graph.reverse_edge_count = reverse_edge_count
    return edge


def _runtime_member_index_cache_identity(catalog_entries, target_jdk):
    artifacts = []
    for item in catalog_entries or ():
        jar_path = str(item.get('jar_path') or '').strip()
        resolved = str(Path(jar_path).resolve()) if jar_path else ''
        artifact_sha256 = ''
        if jar_path and os.path.isfile(jar_path):
            artifact_sha256 = _artifact_sha256(jar_path)
        artifacts.append({
            'coord': str(item.get('coord') or '').strip(),
            'jar_path': resolved,
            'artifact_entry': str(item.get('artifact_entry') or ''),
            'artifact_sha256': artifact_sha256,
            'application_owned': item.get('application_owned'),
            'ownership_evidence': item.get('ownership_evidence'),
        })
    return {
        'schema': RUNTIME_MEMBER_INDEX_CACHE_SCHEMA,
        'target_jdk': str(target_jdk or ''),
        'artifacts': sorted(
            artifacts,
            key=lambda row: (
                row['coord'], row['jar_path'], row['artifact_entry'],
                row['artifact_sha256'],
            ),
        ),
    }


def _runtime_member_index_cache_identity_from_verified_catalog(
    catalog_entries, target_jdk,
):
    """Build the same identity after every catalog SHA was verified by the fact store."""
    artifacts = [{
        'coord': str(item.get('coord') or '').strip(),
        'jar_path': str(Path(str(item.get('jar_path') or '')).resolve()),
        'artifact_entry': str(item.get('artifact_entry') or ''),
        'artifact_sha256': str(item.get('sha256') or '').lower(),
        'application_owned': item.get('application_owned'),
        'ownership_evidence': item.get('ownership_evidence'),
    } for item in catalog_entries or ()]
    return {
        'schema': RUNTIME_MEMBER_INDEX_CACHE_SCHEMA,
        'target_jdk': str(target_jdk or ''),
        'artifacts': sorted(
            artifacts,
            key=lambda row: (
                row['coord'], row['jar_path'], row['artifact_entry'],
                row['artifact_sha256'],
            ),
        ),
    }


def _runtime_artifact_stat_snapshot(catalog_entries, target_jdk):
    artifacts = []
    for item in catalog_entries or ():
        jar_path = str(item.get('jar_path') or '').strip()
        resolved = str(Path(jar_path).resolve()) if jar_path else ''
        stat_identity = None
        if jar_path:
            try:
                stat = os.stat(jar_path)
                stat_identity = (
                    int(stat.st_dev), int(stat.st_ino), int(stat.st_size),
                    int(stat.st_mtime_ns), int(stat.st_ctime_ns),
                )
            except OSError:
                stat_identity = None
        artifacts.append((
            str(item.get('coord') or '').strip(), resolved,
            str(item.get('artifact_entry') or ''), stat_identity,
            item.get('application_owned'), item.get('ownership_evidence'),
        ))
    return (str(target_jdk or ''), tuple(sorted(artifacts, key=repr)))


def _runtime_member_index_cache_path(graph):
    report_dir = str(getattr(graph, 'report_dir', '') or '').strip()
    if not report_dir:
        return None
    return (
        Path(report_dir) / '.runtime' / 'cache'
        / 's5_runtime_member_candidate_index.json'
    )


def _runtime_member_index_serializable(index):
    return {
        'tasks': list(index.get('tasks') or []),
        'unparsed_tasks': list(index.get('unparsed_tasks') or []),
        'direct_by_owner_member': [
            {
                'owner': owner,
                'member': member,
                'task_ids': sorted(
                    (task_ids,) if isinstance(task_ids, int) else task_ids
                ),
            }
            for (owner, member), task_ids in sorted(
                (index.get('direct_by_owner_member') or {}).items()
            )
        ],
        'direct_by_owner': {
            key: sorted((value,) if isinstance(value, int) else value)
            for key, value in sorted((index.get('direct_by_owner') or {}).items())
        },
        'owner_string_ids': {
            key: sorted((value,) if isinstance(value, int) else value)
            for key, value in sorted((index.get('owner_string_ids') or {}).items())
        },
        'member_string_ids': {
            key: sorted((value,) if isinstance(value, int) else value)
            for key, value in sorted((index.get('member_string_ids') or {}).items())
        },
        'reflection_ids': sorted(index.get('reflection_ids') or ()),
        'visited_classes': int(index.get('visited_classes') or 0),
        'parse_failures': int(index.get('parse_failures') or 0),
        'complete': bool(index.get('complete', True)),
        'failures': list(index.get('failures') or []),
    }


def _runtime_member_index_from_serializable(payload, graph):
    direct = {}
    for row in payload.pop('direct_by_owner_member', None) or ():
        task_ids = tuple(sorted({int(value) for value in (row.get('task_ids') or ())}))
        direct[(str(row.get('owner') or ''), str(row.get('member') or ''))] = (
            task_ids[0] if len(task_ids) == 1 else task_ids
        )
    owner_string_ids = payload.pop('owner_string_ids', None) or {}
    for key, values in owner_string_ids.items():
        values = tuple(sorted(set(values or ())))
        owner_string_ids[key] = values[0] if len(values) == 1 else values
    member_string_ids = payload.pop('member_string_ids', None) or {}
    for key, values in member_string_ids.items():
        values = tuple(sorted(set(values or ())))
        member_string_ids[key] = values[0] if len(values) == 1 else values
    direct_by_owner = payload.pop('direct_by_owner', None) or {}
    for key, values in direct_by_owner.items():
        values = tuple(sorted(set(values or ())))
        direct_by_owner[key] = values[0] if len(values) == 1 else values
    tasks = payload.pop('tasks', None) or []
    unparsed_tasks = payload.pop('unparsed_tasks', None) or []
    shared_strings = {}
    shared_keys = (
        'coord', 'jar_path', 'artifact_container_entry', 'artifact_sha256',
        'target_jdk', 'ownership_evidence', 'multi_release_version',
    )
    for task in (*tasks, *unparsed_tasks):
        for key in shared_keys:
            value = task.get(key)
            if isinstance(value, str):
                task[key] = shared_strings.setdefault(value, value)
        if task.get('class_binary_name') == task.get('class_fqcn'):
            task['class_fqcn'] = task.get('class_binary_name')
    return {
        'graph': graph,
        'catalog': _get_runtime_dependency_catalog(graph),
        'tasks': tasks,
        'unparsed_tasks': unparsed_tasks,
        'direct_by_owner_member': direct,
        'direct_by_owner': direct_by_owner,
        'owner_string_ids': owner_string_ids,
        'member_string_ids': member_string_ids,
        'reflection_ids': set(payload.pop('reflection_ids', None) or ()),
        'visited_classes': int(payload.get('visited_classes') or 0),
        'parse_failures': int(payload.get('parse_failures') or 0),
        'complete': bool(payload.get('complete', True)),
        'failures': payload.pop('failures', None) or [],
    }


def _runtime_member_index_canonical_bytes(payload):
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
    ).encode('utf-8')


def _runtime_member_index_integrity_sha256(payload):
    digest = hashlib.sha256()
    encoder = json.JSONEncoder(
        ensure_ascii=False, sort_keys=True, separators=(',', ':'),
    )
    for chunk in encoder.iterencode(payload):
        digest.update(chunk.encode('utf-8'))
    return digest.hexdigest()


def _write_runtime_member_index_cache(path, identity, index):
    body = {
        'identity': identity,
        'index': _runtime_member_index_serializable(index),
    }
    wrapper = {
        **body,
        'integrity_sha256': hashlib.sha256(
            _runtime_member_index_canonical_bytes(body)
        ).hexdigest(),
    }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', encoding='utf-8', dir=path.parent,
            prefix=path.name + '.', suffix='.tmp', delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump(wrapper, handle, ensure_ascii=False, sort_keys=True)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception as exc:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError as cleanup_exc:
                exc.add_note(
                    f'runtime member index temporary cache cleanup failed: {cleanup_exc}'
                )
        raise


def _load_runtime_member_index_cache(path, identity, graph):
    with Path(path).open('r', encoding='utf-8') as handle:
        wrapper = json.load(handle)
    body = {
        'identity': wrapper.get('identity'),
        'index': wrapper.get('index'),
    }
    if body['identity'] != identity or not isinstance(body['index'], dict):
        raise ValueError('runtime member index cache identity mismatch')
    expected = _runtime_member_index_integrity_sha256(body)
    if wrapper.get('integrity_sha256') != expected:
        raise ValueError('runtime member index cache integrity mismatch')
    index = _runtime_member_index_from_serializable(body['index'], graph)
    if not index.get('complete'):
        raise ValueError('incomplete runtime member index cannot be reused')
    return index


def _add_runtime_member_task_id(buckets, key, task_id):
    current = buckets.get(key)
    if current is None:
        buckets[key] = task_id
    elif isinstance(current, int):
        if current != task_id:
            buckets[key] = {current, task_id}
    else:
        current.add(task_id)


def _build_runtime_dependency_member_candidate_index(graph, catalog_entries, target_jdk):
    index_started_at = time.perf_counter()
    _perf_add(graph, 'bytecode_expand', 'member_index_builds', 1)
    tasks = []
    unparsed_tasks = []
    direct_by_owner_member = {}
    direct_by_owner = {}
    owner_string_ids = {}
    member_string_ids = {}
    reflection_ids = set()
    visited_classes = 0
    parse_failures = 0
    failures = []
    started_at = time.perf_counter()
    progress_interval = suggest_log_interval(len(catalog_entries), target_updates=6, minimum=1)
    for idx, item in enumerate(catalog_entries or [], 1):
        coord = str(item.get('coord') or '').strip()
        if should_log_progress(idx, len(catalog_entries), progress_interval):
            emit_progress(
                "step5",
                "bytecode-expand",
                "构建运行时依赖 member 候选索引",
                current=idx,
                total=len(catalog_entries),
                elapsed=time.perf_counter() - started_at,
                item=coord or str(item.get('jar_path') or '')[:120],
            )
        if not coord:
            parse_failures += 1
            failure = {
                'reason': 'BYTECODE_MEMBER_INDEX_COORD_MISSING',
                'coord': '',
                'jar_path': str(item.get('jar_path') or '').strip(),
                'error_type': 'ValueError',
                'error': 'runtime member index catalog entry has no coordinate',
            }
            failures.append(failure)
            _record_analyzer_ledger_failure(graph, **failure)
            continue
        jar_path = str(item.get('jar_path') or '').strip()
        if not jar_path or not os.path.exists(jar_path):
            parse_failures += 1
            failure = {
                'reason': 'BYTECODE_MEMBER_INDEX_ARTIFACT_MISSING',
                'coord': coord,
                'jar_path': jar_path,
                'error_type': 'FileNotFoundError',
                'error': 'runtime member index artifact is missing',
            }
            failures.append(failure)
            _record_analyzer_ledger_failure(graph, **failure)
            continue
        try:
            fact_store = getattr(graph, 'step5_artifact_fact_store', None)
            shared_inventory = fact_store.inventory(coord) if fact_store is not None else None
            expected_sha256 = str(item.get('sha256') or '').lower()
            use_shared = bool(
                shared_inventory is not None
                and not shared_inventory.failure
                and shared_inventory.identity.path == jar_path
                and shared_inventory.identity.sha256 == expected_sha256
            )
            artifact_sha256 = (
                shared_inventory.identity.sha256 if use_shared
                else _artifact_sha256(jar_path)
            )

            def consume_class(entry, logical_name, selected_version, data):
                    nonlocal visited_classes, parse_failures
                    if logical_name.endswith(('module-info.class', 'package-info.class')):
                        return
                    visited_classes += 1
                    class_binary_name = logical_name[:-6].replace('/', '.')
                    task = {
                        'coord': coord,
                        'jar_path': jar_path,
                        'artifact_container_entry': item.get('artifact_entry') or '',
                        'class_entry': entry,
                        'class_binary_name': class_binary_name,
                        'class_fqcn': class_binary_name.replace('$', '.'),
                        'multi_release_version': selected_version,
                        'artifact_sha256': artifact_sha256,
                        'target_jdk': target_jdk,
                        'application_owned': item.get('application_owned'),
                        'ownership_evidence': item.get('ownership_evidence'),
                    }
                    summary = _parse_classfile_constant_pool_summary(data)
                    if summary is None:
                        parse_failures += 1
                        unparsed_tasks.append(task)
                        return
                    task_id = len(tasks)
                    tasks.append(task)
                    for referenced_owner in summary.get('class_internal_names') or ():
                        normalized_owner = (
                            str(referenced_owner or '')
                            .replace('/', '.').replace('$', '.')
                        )
                        if normalized_owner:
                            _add_runtime_member_task_id(
                                direct_by_owner, normalized_owner, task_id,
                            )
                    member_refs = list(summary.get('ref_members') or [])
                    for ref in member_refs:
                        owner = str(ref.get('owner') or '').replace('/', '.').replace('$', '.')
                        member = str(ref.get('name') or '')
                        if owner and member:
                            _add_runtime_member_task_id(
                                direct_by_owner_member, (owner, member), task_id
                            )
                    utf8_values = {
                        str(value or '') for value in (summary.get('utf8_values') or set())
                        if value
                    }
                    reflective = summary.get('has_dynamic_reference') or any(
                        marker in utf8_values
                        for marker in (
                            'java/lang/Class', 'java/lang/reflect/Method',
                            'java/lang/reflect/Constructor', 'java/lang/invoke/MethodHandles',
                        )
                    )
                    if reflective:
                        reflection_ids.add(task_id)
                        for value in utf8_values:
                            if re.fullmatch(r'[A-Za-z_$][\w$]*(?:[/.][A-Za-z_$][\w$]*)+', value):
                                _add_runtime_member_task_id(owner_string_ids, value, task_id)
                                dotted_owner = value.replace('/', '.').replace('$', '.')
                                _add_runtime_member_task_id(
                                    owner_string_ids, dotted_owner, task_id
                                )
                                _add_runtime_member_task_id(
                                    owner_string_ids, dotted_owner.replace('.', '/'), task_id
                                )
                            if re.fullmatch(r'[A-Za-z_$][\w$]*', value):
                                _add_runtime_member_task_id(member_string_ids, value, task_id)

            if use_shared:
                for location, data in fact_store.iter_class_bytes(coord):
                    consume_class(
                        location.physical_entry, location.logical_name,
                        location.multi_release_version, data,
                    )
            else:
                with zipfile.ZipFile(jar_path) as zf:
                    try:
                        manifest = zf.read('META-INF/MANIFEST.MF').decode(
                            'utf-8', errors='replace',
                        )
                    except KeyError:
                        manifest = ''
                    multi_release_enabled = bool(re.search(
                        r'(?im)^Multi-Release\s*:\s*true\s*$', manifest
                    ))
                    variants, _is_multi_release, _parsed_target = _runtime_class_variants(
                        zf.namelist(), target_jdk,
                        multi_release_enabled=multi_release_enabled,
                    )
                    for entry, logical_name, selected_version in variants:
                        consume_class(
                            entry, logical_name, selected_version, zf.read(entry),
                        )
        except Exception as exc:
            parse_failures += 1
            failure = {
                'reason': 'BYTECODE_MEMBER_INDEX_ARCHIVE_FAILED',
                'coord': coord,
                'jar_path': jar_path,
                'error_type': type(exc).__name__,
                'error': str(exc),
            }
            failures.append(failure)
            _record_analyzer_ledger_failure(graph, **failure)
            continue
    _perf_add(graph, 'bytecode_expand', 'member_index_elapsed_sec', time.perf_counter() - index_started_at)
    _perf_add(graph, 'bytecode_expand', 'member_index_visited_classes', visited_classes)
    _perf_add(graph, 'bytecode_expand', 'member_index_tasks', len(tasks))
    _perf_add(graph, 'bytecode_expand', 'member_index_unparsed_tasks', len(unparsed_tasks))
    _perf_add(graph, 'bytecode_expand', 'member_index_parse_failures', parse_failures)
    for buckets in (
        direct_by_owner_member, direct_by_owner,
        owner_string_ids, member_string_ids,
    ):
        for key, task_ids in buckets.items():
            if not isinstance(task_ids, int):
                buckets[key] = tuple(sorted(task_ids))
    return {
        'graph': graph,
        'catalog': _get_runtime_dependency_catalog(graph),
        'tasks': tasks,
        'unparsed_tasks': unparsed_tasks,
        'direct_by_owner_member': direct_by_owner_member,
        'direct_by_owner': direct_by_owner,
        'owner_string_ids': owner_string_ids,
        'member_string_ids': member_string_ids,
        'reflection_ids': reflection_ids,
        'visited_classes': visited_classes,
        'parse_failures': parse_failures,
        'complete': not failures,
        'failures': failures,
    }


def _get_runtime_dependency_member_candidate_index(graph, catalog_entries, target_jdk):
    if not graph:
        return None
    cached = getattr(graph, '_runtime_dependency_member_candidate_index', None)
    if cached is not None:
        current_stat_snapshot = _runtime_artifact_stat_snapshot(
            catalog_entries, target_jdk
        )
        if cached.get('_stat_snapshot') == current_stat_snapshot:
            return cached
        snapshot_before_identity = current_stat_snapshot
        try:
            current_identity = _runtime_member_index_cache_identity(
                catalog_entries, target_jdk
            )
        except OSError:
            current_identity = None
        snapshot_after_identity = _runtime_artifact_stat_snapshot(
            catalog_entries, target_jdk
        )
        if (
            current_identity is not None
            and cached.get('_identity') == current_identity
            and snapshot_after_identity == snapshot_before_identity
        ):
            cached['_stat_snapshot'] = snapshot_after_identity
            return cached
        setattr(graph, '_runtime_dependency_member_candidate_index', None)
    cache_path = _runtime_member_index_cache_path(graph)
    identity = None
    if cache_path is not None:
        cache_started_at = time.perf_counter()
        try:
            snapshot_before_load = _runtime_artifact_stat_snapshot(
                catalog_entries, target_jdk
            )
            identity = _runtime_member_index_cache_identity(catalog_entries, target_jdk)
            index = _load_runtime_member_index_cache(cache_path, identity, graph)
            identity_after_load = _runtime_member_index_cache_identity(
                catalog_entries, target_jdk
            )
            snapshot_after_load = _runtime_artifact_stat_snapshot(
                catalog_entries, target_jdk
            )
            if (
                identity_after_load == identity
                and snapshot_after_load == snapshot_before_load
            ):
                index['_identity'] = identity_after_load
                index['_stat_snapshot'] = snapshot_after_load
                _perf_add(graph, 'bytecode_expand', 'member_index_persistent_cache_hits', 1)
                _perf_add(
                    graph, 'bytecode_expand', 'member_index_cache_load_elapsed_sec',
                    time.perf_counter() - cache_started_at,
                )
                setattr(graph, '_runtime_dependency_member_candidate_index', index)
                return index
            identity = identity_after_load
            _perf_add(
                graph, 'bytecode_expand',
                'member_index_cache_input_changed_misses', 1,
            )
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            _perf_add(graph, 'bytecode_expand', 'member_index_persistent_cache_misses', 1)
    if identity is None:
        try:
            identity = _runtime_member_index_cache_identity(
                catalog_entries, target_jdk
            )
        except OSError:
            identity = None
    index = _build_runtime_dependency_member_candidate_index(graph, catalog_entries, target_jdk)
    snapshot_before_final_identity = _runtime_artifact_stat_snapshot(
        catalog_entries, target_jdk
    )
    try:
        identity_after_build = _runtime_member_index_cache_identity(
            catalog_entries, target_jdk
        )
    except OSError as exc:
        identity_after_build = None
        identity_error = f'{type(exc).__name__}:{exc}'
    else:
        identity_error = ''
    snapshot_after_final_identity = _runtime_artifact_stat_snapshot(
        catalog_entries, target_jdk
    )
    if (
        identity is None
        or identity_after_build != identity
        or snapshot_after_final_identity != snapshot_before_final_identity
    ):
        failure = {
            'reason': 'BYTECODE_MEMBER_INDEX_INPUT_CHANGED',
            'error_type': 'ArtifactIdentityChanged',
            'error': identity_error or 'runtime dependency identity changed during index build',
        }
        index['complete'] = False
        index.setdefault('failures', []).append(failure)
        _record_analyzer_ledger_failure(graph, **failure)
    else:
        index['_identity'] = identity_after_build
        index['_stat_snapshot'] = snapshot_after_final_identity
    setattr(graph, '_runtime_dependency_member_candidate_index', index)
    if cache_path is not None and index.get('complete'):
        snapshot_before_cache_write = _runtime_artifact_stat_snapshot(
            catalog_entries, target_jdk
        )
        try:
            if identity is None:
                identity = _runtime_member_index_cache_identity(
                    catalog_entries, target_jdk
                )
            _write_runtime_member_index_cache(cache_path, identity, index)
        except (OSError, TypeError, ValueError):
            _perf_add(graph, 'bytecode_expand', 'member_index_cache_write_failures', 1)
        snapshot_after_cache_write = _runtime_artifact_stat_snapshot(
            catalog_entries, target_jdk
        )
        if snapshot_after_cache_write != snapshot_before_cache_write:
            failure = {
                'reason': 'BYTECODE_MEMBER_INDEX_INPUT_CHANGED',
                'error_type': 'ArtifactIdentityChanged',
                'error': 'runtime dependency identity changed during cache write',
            }
            index['complete'] = False
            index.setdefault('failures', []).append(failure)
            index.pop('_identity', None)
            index.pop('_stat_snapshot', None)
            _record_analyzer_ledger_failure(graph, **failure)
            try:
                Path(cache_path).unlink(missing_ok=True)
            except OSError as exc:
                _perf_add(
                    graph, 'bytecode_expand',
                    'member_index_cache_cleanup_failures', 1,
                )
                index.setdefault('failures', []).append({
                    'reason': 'BYTECODE_MEMBER_INDEX_CACHE_CLEANUP_FAILED',
                    'error_type': type(exc).__name__,
                    'error': str(exc),
                })
    emit_progress(
        "step5",
        "bytecode-expand",
        (
            "运行时依赖 member 候选索引完成，"
            f"classes={index.get('visited_classes', 0)}，"
            f"tasks={len(index.get('tasks') or [])}，"
            f"unparsed={len(index.get('unparsed_tasks') or [])}"
        ),
    )
    return index


def _candidate_tasks_from_runtime_member_index(index, owner, member):
    if not index:
        return None
    if not bool(index.get('complete', True)):
        return None
    direct_ids = (index.get('direct_by_owner_member') or {}).get((owner, member), set())
    task_ids = {direct_ids} if isinstance(direct_ids, int) else set(direct_ids)
    owner_value = (index.get('owner_string_ids') or {}).get(owner, set())
    owner_ids = {owner_value} if isinstance(owner_value, int) else set(owner_value)
    internal_owner_value = (index.get('owner_string_ids') or {}).get(
        _jvm_internal_owner_name(owner), set()
    )
    owner_ids.update(
        {internal_owner_value}
        if isinstance(internal_owner_value, int) else internal_owner_value
    )
    member_value = (index.get('member_string_ids') or {}).get(member, set())
    member_ids = {member_value} if isinstance(member_value, int) else set(member_value)
    reflection_ids = set(index.get('reflection_ids') or set())
    task_ids.update(owner_ids & member_ids & reflection_ids)
    tasks = list(index.get('tasks') or [])
    candidates = [tasks[item] for item in sorted(task_ids) if 0 <= item < len(tasks)]
    unparsed_checked = 0
    unparsed_selected = 0
    owner_internal = _jvm_internal_owner_name(owner)
    for task in index.get('unparsed_tasks') or []:
        unparsed_checked += 1
        jar_path = str(task.get('jar_path') or '')
        class_entry = str(task.get('class_entry') or '')
        if not jar_path or not class_entry or not os.path.exists(jar_path):
            continue
        try:
            with zipfile.ZipFile(jar_path) as zf:
                data = zf.read(class_entry)
        except Exception as exc:
            failure = {
                'reason': 'BYTECODE_MEMBER_INDEX_LATE_ARCHIVE_FAILED',
                'coord': str(task.get('coord') or ''),
                'jar_path': jar_path,
                'class_entry': class_entry,
                'error_type': type(exc).__name__,
                'error': str(exc),
            }
            index.setdefault('failures', []).append(failure)
            index['complete'] = False
            graph = task.get('graph') or index.get('graph')
            if graph is not None:
                _record_analyzer_ledger_failure(graph, **failure)
            return None
        if _class_bytes_might_reference_target(data, owner_internal, member):
            unparsed_selected += 1
            candidates.append(task)
    unique_candidates = []
    seen_candidates = set()
    for task in candidates:
        identity = (str(task.get('jar_path') or ''), str(task.get('class_entry') or ''))
        if identity in seen_candidates:
            continue
        seen_candidates.add(identity)
        unique_candidates.append(task)
    index['last_unparsed_checked'] = unparsed_checked
    index['last_unparsed_selected'] = unparsed_selected
    return unique_candidates


def _batch_candidates_from_runtime_member_index(index, target_rows_by_owner):
    """Select exact parse candidates without rescanning every class per API."""
    if not index or not index.get('complete') or index.get('unparsed_tasks'):
        return None

    def task_ids(value):
        if value is None:
            return set()
        if isinstance(value, int):
            return {value}
        return set(value)

    tasks = list(index.get('tasks') or ())
    candidate_owners_by_task = defaultdict(set)
    direct_by_owner_member = index.get('direct_by_owner_member') or {}
    direct_by_owner = index.get('direct_by_owner') or {}
    owner_string_ids = index.get('owner_string_ids') or {}
    member_string_ids = index.get('member_string_ids') or {}
    reflection_ids = set(index.get('reflection_ids') or ())
    for owner, rows in (target_rows_by_owner or {}).items():
        owner_ids = task_ids(direct_by_owner.get(owner))
        reflected_owner_ids = task_ids(owner_string_ids.get(owner))
        reflected_owner_ids.update(
            task_ids(owner_string_ids.get(_jvm_internal_owner_name(owner)))
        )
        for row in rows or ():
            _resolved_owner, member, symbol_kind = _extract_target_owner_and_member(row)
            selected_ids = set(
                owner_ids
                if symbol_kind in {'class', 'interface', 'annotation', 'enum'}
                else ()
            )
            if member:
                selected_ids.update(
                    task_ids(direct_by_owner_member.get((owner, member)))
                )
                selected_ids.update(
                    reflected_owner_ids
                    & task_ids(member_string_ids.get(member))
                    & reflection_ids
                )
            else:
                selected_ids.update(reflected_owner_ids & reflection_ids)
            for task_id in selected_ids:
                if not 0 <= task_id < len(tasks):
                    continue
                task = tasks[task_id]
                if (
                    task.get('application_owned') is False
                    and str(task.get('coord') or '').strip()
                    == str(row.get('coord') or '').strip()
                ):
                    continue
                candidate_owners_by_task[task_id].add(owner)
    return [
        {
            **tasks[task_id],
            'candidate_owners': sorted(candidate_owners),
        }
        for task_id, candidate_owners in sorted(candidate_owners_by_task.items())
    ]


def _ensure_runtime_dependency_callers_for_key(
    graph, lookup_key, *, excluded_provider_coord=''
):
    expand_started_at = time.perf_counter()
    _perf_add(graph, 'bytecode_expand', 'calls', 1)
    if not graph:
        return {'expanded': False, 'edges_added': 0, 'javap_classes': 0, 'visited_classes': 0}
    parsed = _parse_runtime_method_lookup_key(lookup_key)
    if not parsed:
        return {'expanded': False, 'edges_added': 0, 'javap_classes': 0, 'visited_classes': 0}
    expanded = getattr(graph, '_runtime_dependency_caller_expanded', None)
    if expanded is None:
        expanded = set()
        setattr(graph, '_runtime_dependency_caller_expanded', expanded)
    normalized_excluded_coord = str(excluded_provider_coord or '').strip()
    expansion_key = (
        (lookup_key, normalized_excluded_coord)
        if normalized_excluded_coord else lookup_key
    )
    if expansion_key in expanded:
        _perf_add(graph, 'bytecode_expand', 'already_expanded_hits', 1)
        _perf_add(graph, 'bytecode_expand', 'elapsed_sec', time.perf_counter() - expand_started_at)
        owner, member, signature = parsed
        _perf_record_top(graph, 'bytecode_expand', 'slow_runtime_lookups', {
            'lookup': lookup_key,
            'owner': owner,
            'member': member,
            'signature': signature,
            'elapsed_sec': time.perf_counter() - expand_started_at,
            'candidate_source': 'already_expanded',
            'candidate_cache_hit': True,
            'candidate_classes': 0,
            'javap_classes': 0,
            'edges_added': 0,
            'visited_classes': 0,
        })
        return {'expanded': False, 'edges_added': 0, 'javap_classes': 0, 'visited_classes': 0}
    expanded.add(expansion_key)

    owner, member, signature = parsed
    normalized_signature = normalize_signature_for_lookup(signature) or signature
    api_row = {
        'api_name': f'{owner}.{member}',
        'api_simple': member,
        'api_signature': normalized_signature,
        'symbol_kind': 'method',
    }
    catalog = _get_runtime_dependency_catalog(graph)
    by_coord = catalog.get('by_coord') or {}
    catalog_entries = list(catalog.get('entries') or [
        ({'coord': coord, **item} if not item.get('coord') else item)
        for coord, item in by_coord.items()
    ])
    owner_internal = _jvm_internal_owner_name(owner)
    visited_classes = 0
    javap_classes = 0
    edges_added = 0
    expansion_failures = []
    target_jdk = catalog.get('target_jdk')
    candidate_cache = getattr(graph, '_runtime_dependency_caller_candidate_cache', None)
    if candidate_cache is None:
        candidate_cache = {}
        setattr(graph, '_runtime_dependency_caller_candidate_cache', candidate_cache)
    candidate_source = 'unknown'
    candidate_cache_hit = False
    member_index_unparsed_checked = 0
    member_index_unparsed_selected = 0
    # Candidate discovery depends only on owner/member, not on the specific
    # spelling of the signature.  Cache it so String/java.lang.String variants
    # and repeated paths do not rescan every runtime JAR.
    candidate_cache_key = (
        (owner, member, normalized_excluded_coord)
        if normalized_excluded_coord else (owner, member)
    )
    cached_candidates = candidate_cache.get(candidate_cache_key)
    if cached_candidates is not None:
        _perf_add(graph, 'bytecode_expand', 'candidate_cache_hits', 1)
        candidate_cache_hit = True
        candidate_source = 'cache'
        javap_tasks = list(cached_candidates.get('javap_tasks') or [])
        visited_classes = int(cached_candidates.get('visited_classes') or 0)
    else:
        _perf_add(graph, 'bytecode_expand', 'candidate_cache_misses', 1)
        prior_light_scans = int(getattr(graph, '_runtime_dependency_caller_candidate_light_scans', 0) or 0)
        prefer_member_index, prefer_member_index_reason = _should_prefer_runtime_member_candidate_index(
            graph,
            catalog_entries,
        )
        large_artifact_catalog = prefer_member_index_reason.startswith('large_artifact_catalog:')
        use_member_index = bool(prefer_member_index_reason) or prior_light_scans >= 3
        indexed_tasks = None
        member_index = None
        if large_artifact_catalog:
            _perf_add(graph, 'bytecode_expand', 'member_index_large_artifact_catalog', 1)
        if use_member_index:
            _perf_add(graph, 'bytecode_expand', 'member_index_uses', 1)
            if prefer_member_index_reason:
                _perf_add(graph, 'bytecode_expand', 'member_index_preferred', 1)
                if prefer_member_index_reason.startswith(('large_runtime_catalog:', 'large_artifact_catalog:')):
                    _perf_add(graph, 'bytecode_expand', 'member_index_auto_large_catalog', 1)
                    if not bool(getattr(graph, '_runtime_member_index_large_catalog_logged', False)):
                        setattr(graph, '_runtime_member_index_large_catalog_logged', True)
                        emit_progress(
                            "step5",
                            "bytecode-expand",
                            f"运行时依赖规模较大，直接启用轻量 member 候选索引：{prefer_member_index_reason}",
                        )
            member_index = _get_runtime_dependency_member_candidate_index(graph, catalog_entries, target_jdk)
            indexed_tasks = _candidate_tasks_from_runtime_member_index(member_index, owner, member)
        if indexed_tasks is not None:
            indexed_tasks = [
                task for task in indexed_tasks
                if not (
                    str(task.get('coord') or '').strip()
                    == str(excluded_provider_coord or '').strip()
                    and task.get('application_owned') is False
                )
            ]
            candidate_source = 'member_index'
            _perf_add(graph, 'bytecode_expand', 'member_index_candidate_queries', 1)
            member_index_unparsed_checked = int((member_index or {}).get('last_unparsed_checked') or 0)
            member_index_unparsed_selected = int((member_index or {}).get('last_unparsed_selected') or 0)
            _perf_add(graph, 'bytecode_expand', 'member_index_unparsed_checked', member_index_unparsed_checked)
            _perf_add(graph, 'bytecode_expand', 'member_index_unparsed_selected', member_index_unparsed_selected)
            javap_tasks = list(indexed_tasks)
            visited_classes = int((member_index or {}).get('visited_classes') or 0)
        else:
            candidate_source = 'light_scan'
            _perf_add(graph, 'bytecode_expand', 'light_scans', 1)
            setattr(graph, '_runtime_dependency_caller_candidate_light_scans', prior_light_scans + 1)
            javap_tasks = []
            scan_started_at = time.perf_counter()
            progress_interval = suggest_log_interval(len(catalog_entries), target_updates=6, minimum=1)
            for idx, item in enumerate(catalog_entries, 1):
                coord = str(item.get('coord') or '').strip()
                if (
                    coord == str(excluded_provider_coord or '').strip()
                    and item.get('application_owned') is False
                ):
                    _perf_add(
                        graph, 'bytecode_expand',
                        'external_provider_jars_skipped', 1,
                    )
                    continue
                if should_log_progress(idx, len(catalog_entries), progress_interval):
                    emit_progress(
                        "step5",
                        "bytecode-expand",
                        f"查找运行时依赖调用者候选 owner={owner[:100]} member={member}",
                        current=idx,
                        total=len(catalog_entries),
                        elapsed=time.perf_counter() - scan_started_at,
                        item=coord or str(item.get('jar_path') or '')[:120],
                    )
                if not coord:
                    continue
                jar_path = str(item.get('jar_path') or '').strip()
                if not jar_path or not os.path.exists(jar_path):
                    continue
                try:
                    artifact_sha256 = _artifact_sha256(jar_path)
                    with zipfile.ZipFile(jar_path) as zf:
                        try:
                            manifest = zf.read('META-INF/MANIFEST.MF').decode('utf-8', errors='replace')
                        except KeyError:
                            manifest = ''
                        multi_release_enabled = bool(re.search(
                            r'(?im)^Multi-Release\s*:\s*true\s*$', manifest
                        ))
                        variants, _is_multi_release, _parsed_target = _runtime_class_variants(
                            zf.namelist(), target_jdk, multi_release_enabled=multi_release_enabled
                        )
                        for entry, logical_name, selected_version in variants:
                            if logical_name.endswith(('module-info.class', 'package-info.class')):
                                continue
                            visited_classes += 1
                            data = zf.read(entry)
                            if not _class_bytes_might_reference_target(data, owner_internal, member):
                                continue
                            class_binary_name = logical_name[:-6].replace('/', '.')
                            preparsed_references = _load_direct_classfile_references(
                                data, artifact_sha256, target_jdk, class_binary_name,
                                multi_release_version=selected_version,
                                class_entry=entry, graph=graph,
                            )
                            javap_tasks.append({
                                'catalog': catalog,
                                'coord': coord,
                                'jar_path': jar_path,
                                'artifact_container_entry': item.get('artifact_entry') or '',
                                'class_entry': entry,
                                'class_binary_name': class_binary_name,
                                'class_fqcn': class_binary_name.replace('$', '.'),
                                'multi_release_version': selected_version,
                                'artifact_sha256': artifact_sha256,
                                'target_jdk': target_jdk,
                                'graph': graph,
                                'application_owned': item.get('application_owned'),
                                'ownership_evidence': item.get('ownership_evidence'),
                                'preparsed_references': preparsed_references,
                            })
                except Exception as exc:
                    _perf_add(graph, 'bytecode_expand', 'light_scan_failures', 1)
                    expansion_failures.append({
                        'reason': 'BYTECODE_EXPAND_ARCHIVE_FAILED',
                        'coord': coord,
                        'jar_path': jar_path,
                        'error_type': type(exc).__name__,
                        'error': str(exc),
                    })
                    continue
            _perf_add(graph, 'bytecode_expand', 'light_scan_elapsed_sec', time.perf_counter() - scan_started_at)
        javap_tasks = [
            {**task, 'catalog': catalog, 'graph': graph}
            for task in javap_tasks
        ]
        candidate_cache[candidate_cache_key] = {
            'javap_tasks': list(javap_tasks),
            'visited_classes': visited_classes,
        }

    def handle_javap_result(task, references):
        nonlocal javap_classes, edges_added
        if references is None:
            expansion_failures.append({
                'reason': 'BYTECODE_EXPAND_PARSE_FAILED',
                'coord': task.get('coord') or '',
                'jar_path': task.get('jar_path') or '',
                'class_binary_name': task.get('class_binary_name') or '',
                **(task.get('parse_failure') or {}),
            })
            return
        javap_classes += 1
        matches = _match_runtime_dependency_references(api_row, references)
        for matched in matches:
            analyzer_hit = {
                'coord': task.get('coord') or '',
                'jar_path': task.get('jar_path') or '',
                'artifact_container_entry': (
                    '' if str(task.get('coord') or '') == '__business__'
                    else task.get('artifact_container_entry') or ''
                ),
                'class_entry': task.get('class_entry') or '',
                'caller_owner': task.get('class_binary_name') or '',
                'class_fqcn': task.get('class_fqcn') or '',
                'consumer_method': matched.get('consumer_method') or '<unknown>',
                'consumer_signature': matched.get('consumer_signature') or '',
                'consumer_descriptor': matched.get('consumer_descriptor') or '',
                'callee_owner': matched.get('callee_owner') or '',
                'callee_member': matched.get('callee_member') or '',
                'callee_descriptor': matched.get('callee_descriptor') or '',
                'opcode_family': matched.get('opcode_family') or '',
                'instruction_offset': matched.get('instruction_offset'),
            }
            _add_runtime_dependency_caller_edge(
                graph, lookup_key,
                task.get('coord') or '',
                task.get('jar_path') or '',
                task.get('class_fqcn') or (task.get('class_binary_name') or '').replace('$', '.'),
                matched,
                analyzer_hit=analyzer_hit,
            )
            edges_added += 1

    if javap_tasks:
        workers = min(_step5_bytecode_javap_workers(), len(javap_tasks))
        javap_started_at = time.perf_counter()
        # Small lookups are frequent during reverse traversal. Emitting one or
        # more lines for every 1-8 class lookup can create tens of thousands of
        # log lines while hiding the actual hotspots. Large lookups remain
        # visible here; all lookups are still retained in aggregate timing and
        # slow-item statistics.
        log_lookup_progress = len(javap_tasks) >= 50
        if log_lookup_progress:
            emit_progress(
                "step5",
                "bytecode-expand",
                f"扩展运行时依赖调用者字节码，lookup={lookup_key[:120]}，候选class={len(javap_tasks)}，并行度={workers}",
            )
        if workers <= 1:
            for task in javap_tasks:
                _task, references = _load_runtime_dependency_class_references_for_task(task)
                handle_javap_result(_task, references)
        else:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_map = {
                    executor.submit(_load_runtime_dependency_class_references_for_task, task): task
                    for task in javap_tasks
                }
                progress_interval = suggest_log_interval(len(future_map), target_updates=8, minimum=1)
                for done_count, future in enumerate(as_completed(future_map), 1):
                    task = future_map[future]
                    try:
                        _task, references = future.result()
                    except Exception as exc:
                        _task, references = task, None
                        _task['parse_failure'] = {
                            'error_type': type(exc).__name__,
                            'error': str(exc),
                        }
                    handle_javap_result(_task, references)
                    if log_lookup_progress and should_log_progress(done_count, len(future_map), progress_interval):
                        emit_progress(
                            "step5",
                            "bytecode-expand",
                            f"运行时依赖调用者字节码扩展进度 lookup={lookup_key[:100]}",
                            current=done_count,
                            total=len(future_map),
                            elapsed=time.perf_counter() - javap_started_at,
                        )
        _perf_add(graph, 'bytecode_expand', 'javap_elapsed_sec', time.perf_counter() - javap_started_at)
    _perf_add(graph, 'bytecode_expand', 'elapsed_sec', time.perf_counter() - expand_started_at)
    _perf_add(graph, 'bytecode_expand', 'candidate_classes', len(javap_tasks))
    if expansion_failures:
        expanded.discard(expansion_key)
        failures = getattr(graph, '_runtime_dependency_expand_failures', None)
        if failures is None:
            failures = []
            setattr(graph, '_runtime_dependency_expand_failures', failures)
        failures.extend(expansion_failures)
        _record_analyzer_ledger_failure(
            graph, 'BYTECODE_EXPANSION_INCOMPLETE', lookup_key=lookup_key,
            failure_count=len(expansion_failures),
        )
    _perf_add(graph, 'bytecode_expand', 'javap_classes', javap_classes)
    _perf_add(graph, 'bytecode_expand', 'edges_added', edges_added)
    _perf_add(graph, 'bytecode_expand', 'visited_classes', visited_classes)
    _perf_record_top(graph, 'bytecode_expand', 'slow_runtime_lookups', {
        'lookup': lookup_key,
        'owner': owner,
        'member': member,
        'signature': signature,
        'elapsed_sec': time.perf_counter() - expand_started_at,
        'candidate_source': candidate_source,
        'candidate_cache_hit': candidate_cache_hit,
        'candidate_classes': len(javap_tasks),
        'javap_classes': javap_classes,
        'edges_added': edges_added,
        'visited_classes': visited_classes,
        'member_index_unparsed_checked': member_index_unparsed_checked,
        'member_index_unparsed_selected': member_index_unparsed_selected,
    })
    return {
        'expanded': True,
        'edges_added': edges_added,
        'javap_classes': javap_classes,
        'visited_classes': visited_classes,
    }


def _collect_target_runtime_reference_closure(graph, api_rows):
    """Record the complete runtime caller closure for each original target API."""
    collected = 0
    catalog = _get_runtime_dependency_catalog(graph)
    scan_results = catalog.get('_packaged_api_scan_results') or {}
    for api_row in api_rows or []:
        api_name = str(api_row.get('api_name') or '').strip()
        api_signature = normalize_signature_for_lookup(
            str(api_row.get('api_signature') or '')
        )
        if not api_name:
            continue
        queue = deque()
        symbol_kind = str(api_row.get('symbol_kind') or 'method')
        if symbol_kind in {'method', 'constructor'} and api_signature:
            queue.extend(_method_lookup_key_variants(f'{api_name}{api_signature}'))
        scan = scan_results.get(build_api_identity_key(api_row)) or {}
        for hit in scan.get('hits') or []:
            queue.extend(_packaged_hit_consumer_lookup_keys(hit))
        visited = set()
        while queue:
            lookup_key = queue.popleft()
            if lookup_key in visited:
                continue
            visited.add(lookup_key)
            _ensure_runtime_dependency_callers_for_key(
                graph,
                lookup_key,
                excluded_provider_coord=str(api_row.get('coord') or '').strip(),
            )
            reverse_edges = getattr(graph, 'reverse_edges', {}) or {}
            methods_by_id = getattr(graph, 'methods_by_id', {}) or {}
            for edge in list(reverse_edges.get(lookup_key, []) or []):
                hit = getattr(edge, 'runtime_analyzer_hit', None)
                if not hit:
                    if (
                        str(getattr(edge, 'evidence_source', '') or '') == 'current_final_artifact'
                        and str(getattr(edge, 'owner_type', '') or '') == 'business'
                        and not bool(getattr(edge, 'is_test', False))
                    ):
                        collected += _record_business_closure_edge(
                            graph, api_row, lookup_key, edge
                        )
                    continue
                ledger_hit = dict(hit)
                ledger_hit['edge_role'] = (
                    'internal_bridge'
                    if (
                        str(ledger_hit.get('coord') or '') == str(api_row.get('coord') or '')
                        and bool(ledger_hit.get('application_owned'))
                    )
                    else 'external_consumer'
                )
                if record_analyzer_edge(graph, api_row, ledger_hit) is not None:
                    collected += 1
                caller = methods_by_id.get(getattr(edge, 'caller_symbol_id', ''))
                caller_key = str(getattr(caller, 'qualified_key', '') or '').strip()
                for variant in _method_lookup_key_variants(caller_key):
                    if variant not in visited:
                        queue.append(variant)
    return collected


def _record_business_closure_edge(graph, root_api_row, lookup_key, edge):
    parsed = _parse_runtime_method_lookup_key(lookup_key)
    if not parsed:
        return 0
    owner, member, signature = parsed
    target_row = {
        'api_name': f'{owner}.{member}',
        'api_simple': member,
        'api_signature': normalize_signature_for_lookup(signature) or signature,
        'symbol_kind': 'method',
    }
    catalog = _get_runtime_dependency_catalog(graph)
    business_item = (catalog.get('by_coord') or {}).get('__business__') or next(
        (
            item for item in (catalog.get('entries') or [])
            if str(item.get('coord') or '') == '__business__'
        ),
        {},
    )
    business_jar = str(business_item.get('jar_path') or '').strip()
    business_sha256 = str(business_item.get('sha256') or '').strip()
    _jar_path, separator, class_entry = str(getattr(edge, 'file', '') or '').partition('!/')
    if (
        not separator
        or not class_entry.endswith('.class')
        or not business_jar
        or not os.path.isfile(business_jar)
        or not _valid_sha256(business_sha256)
    ):
        _record_analyzer_ledger_failure(
            graph, 'BUSINESS_CLOSURE_EVIDENCE_INVALID', lookup_key=lookup_key
        )
        return 0
    versioned_entry = re.match(r'^META-INF/versions/(\d+)/(.*\.class)$', class_entry)
    selected_version = int(versioned_entry.group(1)) if versioned_entry else 'base'
    logical_class_entry = versioned_entry.group(2) if versioned_entry else class_entry
    class_binary_name = logical_class_entry[:-6].replace('/', '.')
    references = None
    try:
        with zipfile.ZipFile(business_jar) as archive:
            class_bytes = archive.read(class_entry)
        references = _load_direct_classfile_references(
            class_bytes,
            business_sha256,
            catalog.get('target_jdk'),
            class_binary_name,
            multi_release_version=selected_version,
            class_entry=class_entry,
            graph=graph,
        )
    except (OSError, KeyError, ValueError, zipfile.BadZipFile):
        references = None
    if references is None:
        references = _load_runtime_dependency_class_references(
            catalog,
            '__business__',
            business_jar,
            class_binary_name,
            artifact_sha256=business_sha256,
            target_jdk=catalog.get('target_jdk'),
            multi_release_version=selected_version,
            graph=graph,
            class_entry=class_entry,
        )
    if references is None:
        _record_analyzer_ledger_failure(
            graph, 'BUSINESS_CLOSURE_CLASS_PARSE_FAILED', class_entry=class_entry
        )
        return 0
    caller = (getattr(graph, 'methods_by_id', {}) or {}).get(
        getattr(edge, 'caller_symbol_id', '')
    )
    caller_member = str(getattr(caller, 'method_name', '') or '').strip()
    matches = _match_runtime_dependency_references(target_row, references)
    if caller_member:
        matches = [
            match for match in matches
            if str(match.get('consumer_method') or '') == caller_member
        ]
    collected = 0
    for matched in matches:
        hit = {
            'coord': '__business__',
            'artifact_container_entry': '',
            'edge_role': 'external_consumer',
            'jar_path': business_jar,
            'class_entry': class_entry,
            'caller_owner': class_binary_name,
            'class_fqcn': class_binary_name.replace('$', '.'),
            'consumer_method': matched.get('consumer_method') or '<unknown>',
            'consumer_descriptor': matched.get('consumer_descriptor') or '',
            'callee_owner': matched.get('callee_owner') or '',
            'callee_member': matched.get('callee_member') or '',
            'callee_descriptor': matched.get('callee_descriptor') or '',
            'opcode_family': matched.get('opcode_family') or '',
            'instruction_offset': matched.get('instruction_offset'),
        }
        if record_analyzer_edge(graph, root_api_row, hit) is not None:
            collected += 1
    return collected


def _method_lookup_key_variants(key):
    value = str(key or '').strip()
    if not value or '(' not in value:
        return [value] if value else []
    prefix, tail = value.split('(', 1)
    signature = '(' + tail
    variants = [value]
    normalized = normalize_signature_for_lookup(signature)
    if normalized and normalized != signature:
        variants.append(prefix + normalized)
    expanded = _expand_java_lang_signature(signature)
    if expanded and expanded != signature:
        variants.append(prefix + expanded)
    return list(dict.fromkeys(item for item in variants if item))


def _find_business_callers_for_packaged_hit(hit, graph, max_depth=None):
    if not graph:
        return []
    if max_depth is None:
        max_depth = int(getattr(graph, '_trace_max_total_cost', 5) or 5)
    reverse_edges = getattr(graph, 'reverse_edges', {}) or {}
    methods_by_id = getattr(graph, 'methods_by_id', {}) or {}
    if not reverse_edges:
        return []
    has_business_methods = any(
        getattr(method_def, 'owner_type', '') == 'business' and not getattr(method_def, 'is_test', False)
        for method_def in methods_by_id.values()
    )
    has_runtime_framework_entries = bool(
        getattr(graph, 'framework_runtime_entry_methods', {}) or {}
    )
    if not has_business_methods and not has_runtime_framework_entries:
        return []
    lookup_keys = tuple(_packaged_hit_consumer_lookup_keys(hit))
    if not lookup_keys:
        return []
    path_cache = getattr(graph, '_packaged_hit_business_path_cache', None)
    if path_cache is None:
        path_cache = {}
        setattr(graph, '_packaged_hit_business_path_cache', path_cache)
    cache_key = (lookup_keys, int(max_depth or 0))
    if cache_key in path_cache:
        return list(path_cache.get(cache_key) or [])
    queue = deque()
    queued = set()
    for key in lookup_keys:
        if key not in queued:
            queue.append((key, []))
            queued.add(key)
    visited = set()
    paths = []
    while queue:
        current_key, path = queue.popleft()
        queued.discard(current_key)
        if current_key in visited or len(path) >= max_depth:
            continue
        visited.add(current_key)
        _ensure_runtime_dependency_callers_for_key(
            graph,
            current_key,
            excluded_provider_coord=str(hit.get('target_coord') or '').strip(),
        )
        incoming_edges = (
            edge for edge in (reverse_edges.get(current_key, []) or [])
            if _edge_allowed_for_trace(edge, graph)
        )
        for edge in sorted(incoming_edges, key=stable_edge_sort_key):
            method_def = methods_by_id.get(getattr(edge, 'caller_symbol_id', ''))
            if method_def is None:
                continue
            next_path = path + [edge]
            if getattr(method_def, 'owner_type', '') == 'business' and not getattr(method_def, 'is_test', False):
                paths.append((method_def, next_path, []))
                continue
            runtime_entries = _runtime_framework_entries_for_method(method_def, graph)
            if runtime_entries:
                paths.append((method_def, next_path, runtime_entries))
                continue
            caller_key = getattr(method_def, 'qualified_key', '') or getattr(edge, 'caller_qualified_key', '')
            if caller_key:
                for variant in _method_lookup_key_variants(caller_key):
                    if variant not in visited and variant not in queued:
                        queue.append((variant, next_path))
                        queued.add(variant)
    path_cache[cache_key] = list(paths)
    return paths


def _runtime_framework_entries_for_method(method_def, graph):
    unsigned = str(getattr(method_def, 'qualified_key', '') or '').split('(', 1)[0]
    if not unsigned:
        return []
    return list((getattr(graph, 'framework_runtime_entry_methods', {}) or {}).get(unsigned) or [])


def _packaged_hit_runtime_framework_entry(hit, graph):
    if not graph:
        return None, []
    class_fqcn = str(hit.get('class_fqcn') or '').strip()
    consumer_method = str(hit.get('consumer_method') or '').strip()
    if not class_fqcn or not consumer_method or consumer_method == '<class>':
        return None, []
    method = _runtime_method_def_for_packaged_caller(
        str(hit.get('coord') or ''),
        str(hit.get('jar_path') or ''),
        class_fqcn,
        consumer_method,
        str(hit.get('consumer_signature') or ''),
    )
    entries = _runtime_framework_entries_for_method(method, graph)
    return (method, entries) if entries else (None, [])


def _packaged_hit_is_external_consumer(hit):
    role = str((hit or {}).get('edge_role') or '').strip()
    if role == 'internal_bridge':
        return False
    if role == 'external_consumer':
        return True
    if 'direct_consumer' in (hit or {}):
        return bool(hit.get('direct_consumer'))
    return True


def _packaged_hit_sort_key(hit):
    instruction_offset = _normalized_instruction_offset(
        (hit or {}).get('instruction_offset')
    )
    return (
        str((hit or {}).get('coord') or ''),
        str((hit or {}).get('artifact_container_entry') or ''),
        str((hit or {}).get('jar_path') or ''),
        str((hit or {}).get('class_entry') or ''),
        str((hit or {}).get('class_fqcn') or ''),
        str((hit or {}).get('consumer_method') or ''),
        str((hit or {}).get('consumer_signature') or ''),
        str((hit or {}).get('consumer_descriptor') or ''),
        str((hit or {}).get('callee_owner') or ''),
        str((hit or {}).get('callee_member') or ''),
        str((hit or {}).get('callee_descriptor') or ''),
        str((hit or {}).get('opcode_family') or ''),
        str((hit or {}).get('target_display') or ''),
        -1 if instruction_offset is None else int(instruction_offset),
        str((hit or {}).get('edge_role') or ''),
        str((hit or {}).get('evidence_type') or ''),
        str((hit or {}).get('multi_release_version') or ''),
        bool((hit or {}).get('signature_ambiguous')),
    )


def _deduplicate_physical_packaged_hits(hits):
    unique = []
    seen = set()
    for hit in sorted(hits or (), key=_packaged_hit_sort_key):
        identity = _packaged_hit_sort_key(hit)
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(hit)
    return unique


def _select_canonical_packaged_hits(hits):
    unique = []
    seen = set()
    for hit in _deduplicate_physical_packaged_hits(hits):
        identity = tuple(hit.get(field) for field in (
            'coord', 'class_fqcn', 'consumer_method', 'consumer_signature',
            'evidence_type', 'target_display', 'multi_release_version',
        ))
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(hit)
    return unique


def _build_packaged_dependency_hit_result(result, hits, graph=None):
    physical_hits = _deduplicate_physical_packaged_hits(hits)
    hits = _select_canonical_packaged_hits(physical_hits)
    ambiguous_hits = [
        item for item in physical_hits if item.get('signature_ambiguous')
    ]
    business_hits = [
        item for item in physical_hits
        if item.get('coord') == '__business__' and not item.get('signature_ambiguous')
    ]
    display_business_hits = [
        item for item in hits
        if item.get('coord') == '__business__' and not item.get('signature_ambiguous')
    ]
    if graph is not None and len([
        item for item in physical_hits if item not in business_hits
    ]) >= 8:
        setattr(graph, '_prefer_runtime_dependency_member_candidate_index', True)
    bridged_hits = []
    for item in physical_hits:
        if item.get('signature_ambiguous'):
            continue
        runtime_entry, framework_entries = _packaged_hit_runtime_framework_entry(item, graph)
        if runtime_entry is not None:
            bridged_hits.append({
                'hit': item,
                'business_entry': runtime_entry,
                'bridge_edges': [],
                'framework_entries': framework_entries,
            })
            continue
        if item in business_hits:
            continue
        for business_entry, bridge_edges, framework_entries in _find_business_callers_for_packaged_hit(item, graph):
            bridged_hits.append({
                'hit': item,
                'business_entry': business_entry,
                'bridge_edges': bridge_edges,
                'framework_entries': framework_entries,
            })
    dependency_chain = []
    for item in physical_hits:
        coord = str(item.get('coord') or '').strip()
        if coord and coord not in dependency_chain:
            dependency_chain.append(coord)
    for bridged in bridged_hits:
        for edge in bridged.get('bridge_edges') or []:
            coord = str(getattr(edge, 'owner_coord', '') or '').strip()
            if (
                coord
                and coord not in {'__business__', 'BUSINESS', '业务制品'}
                and coord not in dependency_chain
            ):
                dependency_chain.append(coord)
    result.dependency_chain_coords = dependency_chain
    ordered_hits = display_business_hits + [
        item for item in hits if item not in display_business_hits
    ]
    result.call_paths = []
    result.evidence_paths = []
    result.path_details = []
    for hit in ordered_hits:
        consumer_member = str(hit.get('consumer_method') or '<unknown>')
        consumer_signature = str(hit.get('consumer_signature') or '')
        consumer_symbol = f"{hit.get('class_fqcn')}.{consumer_member}{consumer_signature}"
        consumer_display = f"{hit.get('coord')}:{consumer_symbol}"
        path_text = f"{consumer_display} -> {hit.get('target_display')}"
        result.call_paths.append(f"{consumer_display} -> {hit.get('target_display')}")
        evidence = [{
            'caller_symbol': consumer_display,
            'callee_key': hit.get('target_display'),
            'evidence_type': hit.get('evidence_type'),
            'edge_role': hit.get('edge_role') or 'external_consumer',
            'direct_consumer': _packaged_hit_is_external_consumer(hit),
            'confidence': 'high',
            'file': hit.get('jar_path', ''),
            'line': 0,
            'owner_coord': hit.get('coord', ''),
            'consumer_class': hit.get('class_fqcn', ''),
            'consumer_method': consumer_member,
            'consumer_signature': consumer_signature,
            'instruction_offset': hit.get('instruction_offset'),
        }]
        result.evidence_paths.append(evidence)
        result.path_details.append({
            'path_status': 'reachable' if hit in business_hits else 'uncertain',
            'stop_reason': '' if hit in business_hits else 'BUSINESS_ENTRY_NOT_CONFIRMED',
            'business_entry': consumer_symbol if hit in business_hits else '',
            'business_reachable': hit in business_hits,
            'consumer_coord': hit.get('coord', ''),
            'consumer_class': hit.get('class_fqcn', ''),
            'consumer_method': consumer_member,
            'consumer_signature': consumer_signature,
            'edge_role': hit.get('edge_role') or 'external_consumer',
            'direct_consumer': _packaged_hit_is_external_consumer(hit),
            'path_text': path_text,
            'confidence': 1.0,
            'depth': 1,
            'evidence': evidence,
        })
    for bridged in bridged_hits:
        hit = bridged['hit']
        bridge_edges = bridged.get('bridge_edges') or []
        framework_entries = bridged.get('framework_entries') or []
        business_entry = bridged.get('business_entry')
        consumer_member = str(hit.get('consumer_method') or '<unknown>')
        consumer_signature = str(hit.get('consumer_signature') or '')
        consumer_symbol = f"{hit.get('class_fqcn')}.{consumer_member}{consumer_signature}"
        consumer_display = f"{hit.get('coord')}:{consumer_symbol}"
        target_display = hit.get('target_display')
        activation = ((framework_entries[0].get('provenance') or {}).get('business_activation') or []) if framework_entries else []
        activation_entry = str((activation[0] or {}).get('business_entry') or '').strip() if activation else ''
        path_nodes = ([activation_entry, 'Spring Boot框架注册'] if activation_entry else []) + [
            _format_bridge_edge_caller(edge)
            for edge in reversed(bridge_edges)
        ]
        path_nodes.append(consumer_display)
        path_nodes.append(target_display)
        path_text = " -> ".join(str(item) for item in path_nodes if item)
        result.call_paths.append(path_text)
        evidence = []
        for framework_entry in framework_entries:
            provenance = framework_entry.get('provenance') or {}
            evidence.append({
                'caller_symbol': framework_entry.get('source') or 'framework:spring',
                'callee_key': getattr(business_entry, 'qualified_key', ''),
                'evidence_type': framework_entry.get('edge_kind') or 'spring_runtime_registered_callback',
                'confidence': framework_entry.get('confidence') or 'high',
                'file': provenance.get('jar') or '',
                'line': provenance.get('line') or 0,
                'owner_coord': provenance.get('coord') or '',
                'resource': provenance.get('resource') or '',
                'business_activation': provenance.get('business_activation') or [],
                'semantic': True,
                'activation_verified': bool(
                    framework_entry.get('activation_verified')
                ),
            })
        for edge in reversed(bridge_edges):
            evidence.append({
                'caller_symbol': getattr(edge, 'caller_qualified_key', '') or getattr(edge, 'caller_symbol_id', '?'),
                'callee_key': getattr(edge, 'callee_key', ''),
                'evidence_type': getattr(edge, 'evidence_type', ''),
                'confidence': getattr(edge, 'confidence', 'high'),
                'file': getattr(edge, 'file', ''),
                'line': getattr(edge, 'line', 0),
                'owner_coord': getattr(edge, 'owner_coord', ''),
                'instruction_offset': getattr(edge, 'instruction_offset', None),
                'semantic': bool(
                    getattr(edge, 'semantic', False)
                    or getattr(edge, 'framework_registration', False)
                ),
                'activation_verified': _semantic_edge_activation_verified(edge),
            })
        evidence.append({
            'caller_symbol': consumer_display,
            'callee_key': target_display,
            'evidence_type': hit.get('evidence_type'),
            'edge_role': hit.get('edge_role') or 'external_consumer',
            'direct_consumer': _packaged_hit_is_external_consumer(hit),
            'confidence': 'high',
            'file': hit.get('jar_path', ''),
            'line': 0,
            'owner_coord': hit.get('coord', ''),
            'consumer_class': hit.get('class_fqcn', ''),
            'consumer_method': consumer_member,
            'consumer_signature': consumer_signature,
            'instruction_offset': hit.get('instruction_offset'),
        })
        result.evidence_paths.append(evidence)
        result.path_details.append({
            'path_status': 'reachable',
            'stop_reason': 'RUNTIME_FRAMEWORK_ENTRY_REACHED' if framework_entries else '',
            'business_entry': getattr(business_entry, 'qualified_key', '') or path_nodes[0],
            'business_reachable': True,
            'consumer_coord': hit.get('coord', ''),
            'consumer_class': hit.get('class_fqcn', ''),
            'consumer_method': consumer_member,
            'consumer_signature': consumer_signature,
            'edge_role': hit.get('edge_role') or 'external_consumer',
            'direct_consumer': _packaged_hit_is_external_consumer(hit),
            'path_text': path_text,
            'confidence': 1.0,
            'depth': len(evidence),
            'evidence': evidence,
        })
    has_business_path = bool(business_hits or bridged_hits)
    if ambiguous_hits and not has_business_path:
        for detail in result.path_details:
            detail['path_status'] = 'uncertain'
            detail['business_reachable'] = None
            detail['stop_reason'] = 'UNQUALIFIED_SIGNATURE_TYPE_AMBIGUOUS'

    hit_by_consumer = {
        (
            str(hit.get('coord') or ''),
            str(hit.get('class_fqcn') or ''),
            str(hit.get('consumer_method') or '<unknown>'),
            str(hit.get('consumer_signature') or ''),
        ): hit
        for hit in hits
    }
    typed_paths = []
    for detail in result.path_details:
        hit = hit_by_consumer.get((
            str(detail.get('consumer_coord') or ''),
            str(detail.get('consumer_class') or ''),
            str(detail.get('consumer_method') or '<unknown>'),
            str(detail.get('consumer_signature') or ''),
        ), {})
        if detail.get('business_reachable') is True:
            entry_scope = ModuleScope.BUSINESS_CLASSES
        else:
            entry_scope = classify_module_scope(hit)
        stop_reason = str(detail.get('stop_reason') or '')
        typed_evidence = tuple(
            PhysicalCallEdge(
                caller_symbol=str(edge.get('caller_symbol') or ''),
                callee_key=str(edge.get('callee_key') or ''),
                evidence_type=str(edge.get('evidence_type') or ''),
                owner_scope=classify_module_scope({
                    'coord': edge.get('owner_coord'),
                    'application_owned': hit.get('application_owned'),
                    'ownership_evidence': hit.get('ownership_evidence'),
                }),
                owner_coord=str(edge.get('owner_coord') or ''),
                artifact=str(edge.get('file') or ''),
                confidence=str(edge.get('confidence') or 'high'),
                instruction_offset=(
                    int(_normalized_instruction_offset(edge.get('instruction_offset')))
                    if _normalized_instruction_offset(edge.get('instruction_offset')) is not None
                    else -1
                ),
                semantic=bool(edge.get('semantic')),
                activation_verified=bool(
                    edge.get('activation_verified') and _typed_activation_evidence(edge)
                ),
                activation_evidence=(
                    _typed_activation_evidence(edge)
                    if edge.get('activation_verified') else ()
                ),
            )
            for edge in detail.get('evidence') or []
        )
        dependency_removed_impact = (
            str(result.new_version or '').strip() == '-'
            and _packaged_hit_is_external_consumer(hit)
        )
        typed_paths.append(ReachabilityPath(
            path_text=str(detail.get('path_text') or ''),
            entry_scope=entry_scope,
            complete=(
                detail.get('path_status') == 'reachable'
                and detail.get('business_reachable') is True
            ),
            ambiguous=stop_reason == 'UNQUALIFIED_SIGNATURE_TYPE_AMBIGUOUS',
            truncated=stop_reason in {'MAX_DEPTH_REACHED', 'PATH_TRUNCATED'},
            stop_reason=stop_reason,
            reason_code=(
                'RUNTIME_DEPENDENCY_USES_REMOVED_API'
                if dependency_removed_impact
                else ''
            ),
            note=(
                '已确认当前最终制品中的其他运行时依赖字节码仍引用被删除依赖的目标符号；'
                '加载或执行该路径时存在 NoClassDefFoundError/NoSuchMethodError 风险'
                if dependency_removed_impact
                else ''
            ),
            depth=int(detail.get('depth') or 1),
            evidence=typed_evidence,
        ))
    _apply_evidence_decision(result, paths=tuple(typed_paths))
    result.verification_commands = [
        '如需继续证明是否回到系统源码，请补充 dependency_source_dirs 或检查业务对这些依赖的入口调用',
        '优先审查命中的无源码依赖及其对外暴露入口'
    ]
    return result


def _merge_runtime_framework_paths(result, hits, graph):
    """Keep complete runtime-registration paths alongside source-graph paths.

    The ordinary reverse tracer can recognize a packaged callback as a critical
    node.  Its generic result, however, starts at that callback and loses the
    business-startup and Spring registration evidence.  Rebuild the artifact
    result on a separate TraceResult and merge only confirmed framework paths so
    that the human-facing chain retains the actual runtime entry.
    """
    if not hits:
        return result
    packaged_seed = replace(
        result,
        call_paths=[],
        evidence_paths=[],
        path_details=[],
        dependency_chain_coords=list(result.dependency_chain_coords or []),
        verification_commands=list(result.verification_commands or []),
        hops=list(result.hops or []),
        critical_nodes_hit=list(result.critical_nodes_hit or []),
    )
    packaged = _build_packaged_dependency_hit_result(packaged_seed, hits, graph)
    confirmed_details = [
        item for item in list(packaged.path_details or [])
        if item.get('path_status') == 'reachable'
        and item.get('stop_reason') == 'RUNTIME_FRAMEWORK_ENTRY_REACHED'
        and any(
            edge.get('semantic') and edge.get('activation_verified')
            for edge in (item.get('evidence') or [])
        )
    ]
    if not confirmed_details:
        return result
    runtime_entry_keys = set((getattr(graph, 'framework_runtime_entry_methods', {}) or {}).keys())
    result.path_details = [
        item for item in list(result.path_details or [])
        if not (
            item.get('stop_reason') == 'SYSTEM_CODE_REACHED'
            and str(item.get('business_entry') or '').split('(', 1)[0] in runtime_entry_keys
        )
    ]
    retained_pairs = []
    for path_text, evidence in zip(result.call_paths or [], result.evidence_paths or []):
        if '变更API:' in str(path_text) and any(key in str(path_text) for key in runtime_entry_keys):
            continue
        retained_pairs.append((path_text, evidence))
    result.call_paths = [item[0] for item in retained_pairs]
    result.evidence_paths = [item[1] for item in retained_pairs]
    existing_paths = {
        str(item.get('path_text') or '')
        for item in list(result.path_details or [])
    }
    for detail in confirmed_details:
        path_text = str(detail.get('path_text') or '')
        if path_text and path_text not in existing_paths:
            result.path_details.append(detail)
            existing_paths.add(path_text)
    for path_text, evidence in zip(packaged.call_paths or [], packaged.evidence_paths or []):
        if path_text not in (result.call_paths or []):
            result.call_paths.append(path_text)
            result.evidence_paths.append(evidence)
    for coord in packaged.dependency_chain_coords or []:
        if coord not in result.dependency_chain_coords:
            result.dependency_chain_coords.append(coord)
    activation_edge = next(
        edge
        for edge in (confirmed_details[0].get('evidence') or [])
        if edge.get('semantic') and edge.get('activation_verified')
    )
    return _apply_evidence_decision(result, paths=(ReachabilityPath(
        path_text=str(confirmed_details[0].get('path_text') or ''),
        entry_scope=ModuleScope.BUSINESS_CLASSES,
        complete=True,
        stop_reason='RUNTIME_FRAMEWORK_ENTRY_REACHED',
        reason_code='RUNTIME_FRAMEWORK_ENTRY_REACHED',
        note='已通过最终制品中的框架注册确认目标符号会进入运行时调用路径',
        depth=int(confirmed_details[0].get('depth') or 1),
        evidence=(PhysicalCallEdge(
            caller_symbol=str(activation_edge.get('caller_symbol') or ''),
            callee_key=str(activation_edge.get('callee_key') or ''),
            evidence_type=str(activation_edge.get('evidence_type') or ''),
            owner_scope=ModuleScope.BUSINESS_CLASSES,
            owner_coord=str(activation_edge.get('owner_coord') or ''),
            artifact=str(activation_edge.get('file') or ''),
            confidence=str(activation_edge.get('confidence') or 'high'),
            semantic=True,
            activation_verified=bool(_typed_activation_evidence(activation_edge)),
            activation_evidence=_typed_activation_evidence(activation_edge),
        ),),
    ),))


def _format_bridge_edge_caller(edge):
    """Format an intermediate bridge caller for human-readable packaged dependency paths."""
    caller = str(getattr(edge, 'caller_qualified_key', '') or getattr(edge, 'caller_symbol_id', '?'))
    coord = str(getattr(edge, 'owner_coord', '') or '').strip()
    if coord and coord not in {'BUSINESS', '__business__'} and not caller.startswith(f"{coord}:"):
        return f"{coord}:{caller}"
    return caller


def _build_packaged_dependency_not_found_result(result):
    _apply_evidence_decision(result, complete_scan=True)
    result.verification_commands = [
        '检查是否存在反射、字符串、配置文件或 SPI 间接引用',
        '必要时结合运行验证确认该依赖变更是否会在实际路径触发'
    ]
    return result


def _build_packaged_dependency_incomplete_result(result, scan_result):
    reason_code = str((scan_result or {}).get('reason') or 'ANALYSIS_INCOMPLETE').strip() or 'ANALYSIS_INCOMPLETE'
    _apply_evidence_decision(result, failures=(EvidenceFailure(
        stage='packaged-bytecode-scan',
        reason_code=reason_code,
        blocking=True,
        detail='最终制品字节码分析未完整覆盖，当前无法把未命中解释为安全',
    ),))
    result.verification_commands = [
        '检查当前环境是否可执行 javap，并确认 Step1 留存制品及其中的嵌套依赖 JAR 完整可读',
        '必要时补充 dependency_source_dirs 或重新准备依赖产物后重跑 Step 5',
    ]
    return result


def _build_indirect_usage_result(result, api_row, graph):
    key = indirect_api_key(api_row)
    exact_findings = list((getattr(graph, 'indirect_usage_findings', {}) or {}).get(key) or [])
    unresolved = list((getattr(graph, 'indirect_usage_unresolved', {}) or {}).get(key) or [])
    findings = exact_findings + unresolved
    if not findings:
        return None
    reason_code = str(findings[0].get('reason_code') or 'INDIRECT_TARGET_REFERENCE')
    note = (
        '已发现与变更 API 相关的间接引用证据，但当前证据不能唯一证明该路径触达并执行目标 API'
    )
    result.call_paths = []
    result.evidence_paths = []
    result.path_details = []
    typed_paths = []
    for finding in findings:
        caller = str(finding.get('caller_symbol') or 'indirect-reference')
        owner_coord = str(finding.get('owner_coord') or '')
        owner_scope = classify_module_scope({
            'coord': (
                '__business__'
                if owner_coord in {'BUSINESS', '__business__', '业务制品'}
                else owner_coord
            ),
        })
        path_text = f"{caller} -> {result.api_name}{result.api_signature or ''}"
        evidence = [{
            'caller_symbol': caller,
            'callee_key': f"{result.api_name}{result.api_signature or ''}",
            'evidence_type': finding.get('evidence_type') or 'indirect_reference',
            'confidence': 'medium',
            'file': finding.get('file') or '',
            'line': int(finding.get('line') or 0),
            'owner_coord': finding.get('owner_coord') or '',
        }]
        result.call_paths.append(path_text)
        result.evidence_paths.append(evidence)
        result.path_details.append({
            'path_status': 'uncertain',
            'stop_reason': finding.get('reason_code') or reason_code,
            'business_reachable': None,
            'consumer_coord': finding.get('owner_coord') or '',
            'consumer_class': '', 'consumer_method': caller,
            'consumer_signature': '', 'path_text': path_text,
            'confidence': 0.6, 'depth': 1, 'evidence': evidence,
        })
        typed_paths.append(ReachabilityPath(
            path_text=path_text,
            entry_scope=owner_scope,
            complete=owner_scope == ModuleScope.BUSINESS_CLASSES,
            stop_reason=str(finding.get('reason_code') or reason_code),
            reason_code=str(finding.get('reason_code') or reason_code),
            note=note,
            depth=1,
            evidence=(PhysicalCallEdge(
                caller_symbol=caller,
                callee_key=f"{result.api_name}{result.api_signature or ''}",
                evidence_type=str(
                    finding.get('evidence_type') or 'indirect_reference'
                ),
                owner_scope=owner_scope,
                owner_coord=owner_coord,
                artifact=str(finding.get('file') or ''),
                confidence='medium',
                semantic=True,
                activation_verified=False,
            ),),
        ))
    result.verification_commands = [
        '核对间接引用中的动态类名、成员名和参数类型',
        '结合实际配置或运行测试确认目标 API 是否会被调用',
    ]
    return _apply_evidence_decision(result, paths=tuple(typed_paths), concerns=(EvidenceConcern(
        stage='indirect-usage-analysis',
        reason_code=reason_code,
        detail=note,
        api_identity=key,
    ),))


def _capability_coverage_for_api(api_row, graph):
    coverage = dict(getattr(graph, 'indirect_analysis_coverage', {}) or {})
    per_api = dict(coverage.get('by_api') or {})
    identity = indirect_api_key(api_row)
    item = dict(per_api.get(identity) or {})
    collector_records = [
        record
        for record in (getattr(graph, 'step5_collector_coverage', ()) or ())
        if record.api_identity == identity and record.applicable
    ]
    if not item and not collector_records:
        return coverage
    statuses = [item.get('status') or 'not_applicable'] if item else []
    statuses.extend(record.status for record in collector_records)
    if 'insufficient' in statuses:
        status = 'insufficient'
    elif 'partial' in statuses:
        status = 'partial'
    elif 'complete' in statuses:
        status = 'complete'
    else:
        status = 'not_applicable'
    reason_codes = list(item.get('reason_codes') or [])
    for record in collector_records:
        for reason_code in record.reason_codes:
            if reason_code not in reason_codes:
                reason_codes.append(reason_code)
    symbol_kind = get_symbol_kind(api_row)
    analyzers = dict(item.get('matrix') or {})
    for record in collector_records:
        analyzers[record.collector] = record.status
    return {
        'status': status,
        'reason_codes': reason_codes,
        'analyzers': analyzers,
        'matrix': {symbol_kind: analyzers},
    }


def _build_indirect_coverage_incomplete_result(result):
    coverage = dict(result.capability_coverage or {})
    reasons = list(coverage.get('reason_codes') or [])
    business_incomplete = any(
        reason.startswith(('BYTECODE_', 'CURRENT_FINAL_ARTIFACT_', 'EVIDENCE_'))
        for reason in reasons
    )
    note = (
        ('目标 API 存在适用但未完整覆盖的证据采集，不能把静态未命中解释为未发现引用。'
         if business_incomplete else
         '目标 API 存在适用但未完整覆盖的间接调用机制，不能把静态未命中解释为未发现引用。')
        + (f"未完整能力：{', '.join(reasons)}" if reasons else '')
    )
    result.verification_commands = [
        '查看 alerts.csv 的 coverage_details，定位 partial/insufficient 的间接分析能力',
        '补充对应源码、制品或框架证据后重新运行 Step 5',
    ]
    return _apply_evidence_decision(result, failures=(EvidenceFailure(
        stage='evidence-coverage' if business_incomplete else 'indirect-usage-analysis',
        reason_code=(
            'INCOMPLETE_EVIDENCE_COVERAGE'
            if business_incomplete else 'INDIRECT_ANALYSIS_INCOMPLETE'
        ),
        blocking=True,
        detail=note,
    ),))


def critical_parser_fallback_reasons(graph_stats):
    graph_stats = graph_stats or {}
    parser_fallback_reasons = graph_stats.get('parser_fallback_reasons') or {}
    return {
        key: value
        for key, value in parser_fallback_reasons.items()
        if key not in NON_BLOCKING_PARSER_FALLBACK_REASONS
    }


def _api_owner_and_member(api_row):
    api_name = str((api_row or {}).get('api_name') or (api_row or {}).get('api') or '').strip()
    if not api_name or '.' not in api_name:
        return '', ''
    owner, member = api_name.rsplit('.', 1)
    return owner.strip(), member.strip()


def _fallback_file_may_reference_api(file_path, api_row):
    owner, member = _api_owner_and_member(api_row)
    if not owner:
        return True
    owner_path = owner.replace('.', '/')
    normalized_path = str(file_path or '').replace('\\', '/')
    if owner_path and owner_path in normalized_path:
        return True
    try:
        with open(str(file_path), 'r', encoding='utf-8', errors='ignore') as handle:
            text = handle.read()
    except OSError:
        return True
    owner_simple = owner.rsplit('.', 1)[-1]
    owner_package = owner.rsplit('.', 1)[0] if '.' in owner else ''
    if owner in text:
        return True
    if member and f"{owner_simple}.{member}" in text:
        return True
    if owner_package and re.search(rf"\bimport\s+{re.escape(owner_package)}\.\*\s*;", text):
        if owner_simple in text or (member and member in text):
            return True
    return False


def parser_fallback_reasons_relevant_to_api(graph_stats, api_row):
    critical_reasons = critical_parser_fallback_reasons(graph_stats)
    if not critical_reasons:
        return {}
    if not api_row:
        return critical_reasons
    fallback_files = [
        dict(item or {})
        for item in ((graph_stats or {}).get('parser_fallback_files') or [])
        if str((item or {}).get('reason') or '') in critical_reasons
    ]
    total_critical_files = sum(int(value or 0) for value in critical_reasons.values())
    if not fallback_files:
        return critical_reasons
    # parser_fallback_files is capped in graph stats. If it does not cover all critical
    # fallbacks, keep the conservative global incomplete signal for unknown files.
    if len(fallback_files) < total_critical_files:
        return critical_reasons
    relevant = defaultdict(int)
    for item in fallback_files:
        reason = str(item.get('reason') or '').strip()
        file_path = str(item.get('file') or '').strip()
        if reason and _fallback_file_may_reference_api(file_path, api_row):
            relevant[reason] += 1
    return dict(relevant)


# ══════════════════════════════════════════════════════════════════
# 关键节点识别
# ══════════════════════════════════════════════════════════════════

# 业务入口标记
BUSINESS_ENTRY_HINTS = [
    'Controller', 'Service', 'Handler', 'Endpoint', 'Facade',
    'Job', 'Task', 'Scheduler', 'Listener', 'Consumer',
    'Presenter', 'Action', 'Application', 'Main', 'App'
]

# 框架边界注解
# 注意：不要把 @Service / @Controller / @RestController / @Component 放在这里！
# 这些注解标注的类是业务层入口，会先命中 is_business_entry_point 而不会进入这里。
# 如果把它们放在这里，框架追踪会提前停止，导致真正的业务入口被错判。
# 只放真正表示"框架注入点"的注解（非业务类上的注解）。
FRAMEWORK_BOUNDARY_ANNOTATIONS = [
    'Autowired', 'Bean', 'Entity', 'Table',
    'Configuration', 'Import', 'Inject', 'Named',
    'Value', 'PropertySource', 'ConfigurationProperties',
    'Scheduled', 'EventListener'
]

FRAMEWORK_INTERFACE_ANNOTATIONS = [
    'Mapper', 'Repository', 'FeignClient', 'RestClient'
]

# 工具类标记（跳过追踪）
UTILITY_CLASS_HINTS = [
    'Utils', 'Helper', 'Constants', 'Config', 'Logger',
    'Log', 'Exception', 'Error', 'Result', 'Response'
]


def collect_all_annotations(method_def, class_meta):
    annotations = set(method_def.annotations or [])
    annotations.update(method_def.class_annotations or [])
    annotations.update(class_meta.get('annotations', []) or [])
    return annotations


def is_business_framework_interface(method_def, class_meta, all_annotations):
    if method_def.owner_type != 'business':
        return False
    if not (method_def.is_interface or class_meta.get('kind') == 'interface'):
        return False
    if any(ann in all_annotations for ann in FRAMEWORK_INTERFACE_ANNOTATIONS):
        return True
    # 没有显式注解时，仍然识别常见的框架接口命名模式，避免“类型注入但无注解”漏判。
    if class_meta.get('kind') == 'interface':
        interface_name = method_def.class_name or ''
        if interface_name.endswith(('Mapper', 'Repository', 'Client')):
            return True
    return False


def is_framework_callback_entry(method_def, class_meta, all_annotations):
    if method_def.owner_type != 'business':
        return False
    if 'public' not in (method_def.modifiers or []):
        return False

    callback_method_annotations = {
        'ModelAttribute', 'InitBinder', 'ExceptionHandler',
    }
    if any(ann in all_annotations for ann in callback_method_annotations):
        return True

    callback_interfaces = {
        'Formatter': {'parse', 'print'},
        'Parser': {'parse'},
        'Printer': {'print'},
        'Converter': {'convert'},
        'GenericConverter': {'convert'},
        'Validator': {'validate', 'supports'},
        'HandlerMethodArgumentResolver': {'supportsParameter', 'resolveArgument'},
        'HandlerInterceptor': {'preHandle', 'postHandle', 'afterCompletion'},
        'ApplicationRunner': {'run'},
        'CommandLineRunner': {'run'},
    }
    implements = class_meta.get('implements', []) or []
    interface_names = {item.rsplit('.', 1)[-1] for item in implements if item}
    method_name = (getattr(method_def, 'method_name', '') or '').strip()
    for interface_name, callback_methods in callback_interfaces.items():
        if interface_name in interface_names and method_name in callback_methods:
            return True

    stereotype_annotations = {'Component', 'ControllerAdvice', 'RestControllerAdvice'}
    if any(ann in all_annotations for ann in stereotype_annotations):
        class_name = method_def.class_name or ''
        callback_hints = ('Formatter', 'Converter', 'Validator', 'Resolver', 'Interceptor')
        if any(hint in class_name for hint in callback_hints):
            return True

    return False


def edge_to_evidence(edge, graph=None):
    method_def = graph.methods_by_id.get(edge.caller_symbol_id) if graph else None
    caller_key = getattr(edge, 'caller_qualified_key', None)
    if method_def:
        caller_key = method_def.qualified_key
    if not caller_key:
        caller_key = getattr(edge, 'caller_symbol_id', '?')
    evidence = {
        'caller_symbol': caller_key,
        'callee_key': getattr(edge, 'callee_key', '?'),
        'confidence': getattr(edge, 'confidence', '?'),
        'evidence_type': getattr(edge, 'evidence_type', '?'),
        'file': getattr(edge, 'file', ''),
        'line': getattr(edge, 'line', 0),
        'owner_coord': getattr(edge, 'owner_coord', ''),
        'module': getattr(edge, 'module', ''),
    }
    instruction_offset = _normalized_instruction_offset(
        getattr(edge, 'instruction_offset', None)
    )
    if instruction_offset is not None:
        evidence['instruction_offset'] = int(instruction_offset)
    if getattr(edge, 'framework_registration', False):
        evidence.update({
            'framework_registration': True,
            'framework_source': getattr(edge, 'framework_source', ''),
            'framework_target': getattr(edge, 'framework_target', ''),
            'runtime_activation': getattr(edge, 'runtime_activation', ''),
            'human_edge': 'Spring Boot 根据当前制品中的框架注册触发回调',
        })
    semantic = bool(
        getattr(edge, 'semantic', False)
        or getattr(edge, 'framework_registration', False)
    )
    if semantic:
        evidence['semantic'] = True
        evidence['activation_verified'] = _semantic_edge_activation_verified(edge)
    return evidence


def is_system_code_touched(method_def, _type_metadata):
    """
    识别系统代码触达信号

    目标：只要触达系统自有源码中的非测试方法，即为 reachable。
    不要求到达 HTTP/消息/调度等最外层入口，也不再额外排除配置类/工具类。

    最小排除：
      1. 非业务源码（owner_type != business）
      2. 测试代码
    """
    if method_def.owner_type != 'business':
        return False

    if getattr(method_def, 'is_test', False):
        return False

    return True


def is_framework_boundary(method_def, type_metadata):
    """
    识别框架边界

    规则：
      1. 框架注入注解（@Autowired, @Bean等，但排除 @Mapper/@Repository/@FeignClient）
      2. 接口无实现（动态代理），但排除业务代码中的框架接口（已在 is_system_code_touched 处理）

    注意：
      MyBatis Mapper/JPA Repository/Feign Client 等接口虽然没有具体实现，
      但它们是业务代码直接依赖的 API 边界，应在 is_system_code_touched 中识别，
      而不是在这里标记为框架边界而停止追踪。
    """
    class_meta = type_metadata.get(method_def.class_fqcn, {})
    all_annotations = collect_all_annotations(method_def, class_meta)

    if is_business_framework_interface(method_def, class_meta, all_annotations):
        return False

    # 规则 1: 框架注入注解（支持类级和方法级）
    if any(ann in all_annotations for ann in FRAMEWORK_BOUNDARY_ANNOTATIONS):
        return True

    # 规则 2: 接口无实现（动态代理）- 通用情况。
    # Java 接口也可以声明 static/default/private 具体方法；这些方法的
    # 实现就在接口中，不依赖动态代理或实现类。把它们当成边界会让
    # FieldUtils/MethodUtils 这类真实调用链过早停止。
    if class_meta.get('kind') == 'interface':
        modifiers = set(getattr(method_def, 'modifiers', None) or [])
        if getattr(method_def, 'is_static', False) or modifiers.intersection({'static', 'default', 'private'}):
            return False
        # 检查是否有实现类
        implementations = class_meta.get('implementations', [])
        if not implementations:
            # 如果是依赖包中的接口（非业务代码），才视为框架边界
            if method_def.owner_type != 'business':
                return True  # 依赖包的动态代理接口

    return False


def is_utility_class(method_def):
    """识别工具类（跳过追踪）"""
    class_name = method_def.class_name

    if any(hint in class_name for hint in UTILITY_CLASS_HINTS):
        return True

    return False


# ══════════════════════════════════════════════════════════════════
# 置信度加权深度策略
# ══════════════════════════════════════════════════════════════════

def calculate_depth_cost(confidence):
    """
    计算深度代价（置信度加权）

    High confidence: cost = 1（可追踪5跳）
    Medium confidence: cost = 2（可追踪3跳）
    Low confidence: cost = 5（立即停止）
    """
    if confidence == 'high':
        return 1
    elif confidence == 'medium':
        return 2
    else:  # low
        return 5


def update_path_frontier(frontier, *, cost, confidence):
    """Maintain the non-dominated (cost, confidence) states for one symbol.

    Cost and confidence are independent dimensions: a shorter path may be less
    trustworthy, while a longer path may consist entirely of exact bytecode or
    AST edges.  Collapsing both into a cost-first tuple can discard the latter
    before candidate selection gets a chance to prefer its stronger evidence.
    """
    states = list(frontier or [])
    if any(old_cost <= cost and old_confidence >= confidence for old_cost, old_confidence in states):
        return True, states
    states = [
        (old_cost, old_confidence)
        for old_cost, old_confidence in states
        if not (cost <= old_cost and confidence >= old_confidence)
    ]
    states.append((cost, confidence))
    states.sort(key=lambda item: (item[0], -item[1]))
    return False, states


def should_stop_tracing(current_cost, max_cost, confidence_score, critical_node_hit, last_edge_confidence=''):
    """
    判断是否应该停止追踪

    停止条件：
      1. 代价超过限制（max_cost=5）
      2. 置信度衰减至阈值以下（< 0.3）
      3. 触达系统代码（已证明变更 API 被系统代码使用）
      4. 遇到框架边界（无法继续静态分析）
    """
    # 代价限制
    if current_cost >= max_cost:
        if last_edge_confidence == 'low':
            return True, 'LOW_CONFIDENCE_EDGE'
        return True, 'DEPTH_LIMIT_REACHED'

    # 置信度衰减
    if confidence_score < 0.3:
        return True, 'CONFIDENCE_DECAYED'

    # 系统代码触达（成功回溯）
    if critical_node_hit and critical_node_hit.get('type') == 'system_code_touched':
        return True, 'SYSTEM_CODE_REACHED'

    # 框架边界（无法继续）
    if critical_node_hit and critical_node_hit.get('type') == 'framework_boundary':
        return True, 'FRAMEWORK_BOUNDARY'

    return False, None


def calculate_confidence_decay(current_score, edge_confidence):
    """
    计算置信度衰减

    规则：
      - High confidence边：衰减5%（×0.95）
      - Medium confidence边：衰减20%（×0.8）
      - Low confidence边：衰减50%（×0.5）
    """
    if edge_confidence == 'high':
        return current_score * 0.95
    elif edge_confidence == 'medium':
        return current_score * 0.8
    else:  # low
        return current_score * 0.5


# ══════════════════════════════════════════════════════════════════
# 核心追踪逻辑
# ══════════════════════════════════════════════════════════════════

def _collect_trace_api_with_confidence_weighting(
    api_row,
    graph,
    type_metadata,
    max_total_cost=5,
    needs_bridge=False,
    has_dependency_source_mapping=True,
    has_packaged_bytecode_fallback=False,
    allow_degraded=False,
    graph_stats=None,
    trace_cache=None,
):
    """
    置信度加权反向追踪

    核心改进：
      1. 置信度加权深度（不再固定3跳）
      2. 关键节点识别（业务入口/框架边界）
      3. 精确四态分类：reachable / uncertain / not_analyzed / not_found_in_static_analysis

    Args:
        api_row: 变更API信息
        graph: 源码调用图
        type_metadata: 类型元数据（继承关系）
        max_total_cost: 最大总代价（默认5）
        needs_bridge: 该 API 是否需要依赖源码映射才能完整追踪
        has_dependency_source_mapping: 当前 API 所属依赖是否具备可用源码映射
        has_packaged_bytecode_fallback: 当前 API 是否具备最终制品字节码分析契约（名称保留用于兼容）
        allow_degraded: 如果为 True，缺依赖源码映射时标记为 not_analyzed 而非静态未找到

    Returns:
        TraceResult
    """
    api_name = api_row.get('api_name', '').strip()
    result = _new_trace_draft(api_row, graph)
    _step5_debug(
        'trace_api_start',
        'starting trace for api',
        api_name=api_name,
        api_signature=result.api_signature,
        symbol_kind=result.symbol_kind,
        change_type=result.change_type,
        coord=result.coord,
        max_total_cost=max_total_cost,
        needs_bridge=needs_bridge,
        has_dependency_source_mapping=has_dependency_source_mapping,
        has_packaged_bytecode_fallback=has_packaged_bytecode_fallback,
        allow_degraded=allow_degraded,
    )

    if not get_symbol_kind(api_row):
        _apply_blocking_failure(
            result, 'input-validation', 'MISSING_SYMBOL_KIND',
            'Step 5 需要 symbol_kind 才能判断当前变更是方法、字段、类还是构造器',
        )
        result.verification_commands = [
            '回到 Step 4 重新生成包含 symbol_kind 的变更 API 清单',
            '确认 all_changed_apis.csv 每一行都明确标注 symbol_kind',
        ]
        _debug_trace_result('trace_api_result', result)
        return result

    if method_api_requires_signature(api_row) and not (api_row.get('api_name') or '').strip():
        note = (
            '方法级调用链分析要求目标 API 具备全限定名；'
            '当前输入只有简单名/签名时，Step5 不会使用 method:* 回退键生成结论，'
            '以避免跨类同名方法误匹配'
        )
        _apply_blocking_failure(result, 'input-validation', 'MISSING_API_NAME', note)
        result.verification_commands = [
            '回到 Step 4 重新生成包含 api_name 全限定名的变更 API 清单',
            '确认 all_changed_apis.csv 中方法/构造器行的 api_name 不是空值',
        ]
        _debug_trace_result('trace_api_result', result)
        return result

    if method_api_requires_signature(api_row) and not has_precise_api_signature(api_row):
        _apply_blocking_failure(
            result, 'input-validation', 'MISSING_API_SIGNATURE',
            '方法级调用链分析要求精确参数签名；当前输入缺少 api_signature，无法区分重载方法',
        )
        result.verification_commands = [
            '回到 Step 4 重新生成包含 api_signature 的变更 API 清单',
            '确认变更方法的参数类型已被精确提取',
        ]
        _debug_trace_result('trace_api_result', result)
        return result

    preserved_result = _build_runtime_symbol_preserved_result(result, api_row, graph)
    if preserved_result is not None:
        _debug_trace_result('trace_api_result', preserved_result)
        return preserved_result

    # 行为变更：即使找到调用链也需运行时验证
    if result.change_type == 'BEHAVIOR_CHANGED':
        # 先尝试追踪看是否存在调用链
        # 如果找到 reachable 路径，说明存在真实影响（但仍需运行时验证）
        # 如果未找到，说明"目前代码未使用"或"需要补充依赖源码映射"
        pass  # 继续追踪，保留后续的路径分析能力

    dependency_removed = str(api_row.get('new_version') or '').strip() == '-'
    artifact_scan_incomplete = None
    artifact_dependency_hits = []
    artifact_scan_miss = False
    if has_packaged_bytecode_fallback:
        scan_result = _scan_packaged_runtime_dependencies_for_api(api_row, graph)
        scan_status = str((scan_result or {}).get('status') or '').strip()
        if scan_status == 'hit':
            scan_hits = scan_result.get('hits') or []
            if any(
                item.get('coord') == '__business__'
                for item in scan_hits
            ):
                packaged_dependency_result = _build_packaged_dependency_hit_result(result, scan_hits, graph)
                _apply_constant_impact(
                    packaged_dependency_result,
                    api_row,
                    graph,
                    runtime_field_edge_present=True,
                )
                _debug_trace_result('trace_api_result', packaged_dependency_result)
                return packaged_dependency_result
            artifact_dependency_hits = scan_hits
        if scan_status == 'miss':
            artifact_scan_miss = True
        if scan_status == 'unavailable':
            artifact_scan_incomplete = scan_result

    direct_usage_result = _try_build_direct_usage_result(api_row, result, graph, trace_cache=trace_cache)
    if direct_usage_result is not None:
        if artifact_scan_miss and not _has_verified_final_artifact_framework_target(
            api_row, graph
        ):
            if _is_inlined_constant_change(api_row):
                _build_inlined_constant_result(direct_usage_result, api_row, graph)
            else:
                _apply_source_artifact_miss(direct_usage_result, graph, (
                    '源码中发现了目标调用，但当前打包产物的字节码扫描没有发现对应引用；'
                    '可能是源码、构建参数或目标模块与本次打包产物不一致，当前不能确认影响'
                ))
        if artifact_dependency_hits:
            for hit in artifact_dependency_hits:
                consumer_display = f"{hit.get('coord')}:{hit.get('class_fqcn')}"
                direct_usage_result.call_paths.append(
                    f"{consumer_display} -> {hit.get('target_display')}"
                )
                direct_usage_result.evidence_paths.append([{
                    'caller_symbol': consumer_display,
                    'callee_key': hit.get('target_display'),
                    'evidence_type': hit.get('evidence_type'),
                    'edge_role': hit.get('edge_role') or 'external_consumer',
                    'direct_consumer': _packaged_hit_is_external_consumer(hit),
                    'confidence': 'high',
                    'file': hit.get('jar_path', ''),
                    'line': 0,
                }])
                coord = str(hit.get('coord') or '').strip()
                if coord and coord not in direct_usage_result.dependency_chain_coords:
                    direct_usage_result.dependency_chain_coords.append(coord)
            _apply_constant_impact(
                direct_usage_result,
                api_row,
                graph,
                runtime_field_edge_present=True,
            )
        _debug_trace_result('trace_api_result', direct_usage_result)
        return direct_usage_result

    # 类级目标没有正式的方法级反向追踪主路径；若最终制品已稳定命中字节码引用，
    # 仍应沿用打包依赖命中结论，而不是被后续 CLASS_USAGE_ONLY 覆盖。
    if artifact_dependency_hits and (result.analysis_scope == 'class_usage' or result.symbol_kind == 'class'):
        packaged_dependency_result = _build_packaged_dependency_hit_result(result, artifact_dependency_hits, graph)
        _debug_trace_result('trace_api_result', packaged_dependency_result)
        return packaged_dependency_result

    if result.analysis_scope == 'class_usage' or result.symbol_kind == 'class':
        indirect_result = _build_indirect_usage_result(result, api_row, graph)
        if indirect_result is not None:
            _debug_trace_result('trace_api_result', indirect_result)
            return indirect_result

    if (
        artifact_scan_incomplete
        and needs_bridge
        and not has_dependency_source_mapping
        and not _has_exact_business_bytecode_target(api_row, graph)
    ):
        built = _build_packaged_dependency_incomplete_result(result, artifact_scan_incomplete)
        _debug_trace_result('trace_api_result', built)
        return built

    # 类级fallback：不追踪
    if result.analysis_scope == 'class_usage':
        _apply_blocking_failure(
            result, 'input-validation', 'CLASS_USAGE_ONLY',
            '类级候选只能证明类型使用，无法确认具体API影响',
        )
        result.verification_commands = [
            f"审查 {api_row.get('matched_class')} 的具体使用场景"
        ]
        _debug_trace_result('trace_api_result', result)
        return result

    # 构建目标键
    target_key_groups = build_api_target_key_groups(api_row, graph=graph, type_metadata=type_metadata)
    target_keys = flatten_key_groups(target_key_groups)
    if not target_keys:
        _apply_blocking_failure(
            result, 'target-key-construction', 'NO_TARGET_KEYS', '无法从输入提取可追踪目标',
        )
        _debug_trace_result('trace_api_result', result)
        return result
    _step5_debug(
        'target_key_groups',
        'built target key groups for api',
        api_name=api_name,
        api_signature=result.api_signature,
        target_key_groups=target_key_groups,
        flattened_target_keys=target_keys,
    )

    # BFS反向追踪（置信度加权）
    queue = deque()
    # A symbol can have multiple Pareto-optimal states.  Keeping only the
    # cheapest state would let a short low-confidence guess suppress a longer
    # exact path before final candidate ranking.
    visited = {}  # (symbol_id, provenance_family) -> [(cost, confidence), ...]

    trace_cache = ensure_trace_cache(trace_cache)
    reverse_edges = getattr(graph, 'reverse_edges', {}) or {}
    methods_by_id = getattr(graph, 'methods_by_id', {}) or {}

    target_match_groups = select_matching_key_groups(target_key_groups, reverse_edges)
    _step5_debug(
        'target_match_groups',
        'selected target match groups from reverse edges',
        api_name=api_name,
        api_signature=result.api_signature,
        target_match_groups=target_match_groups,
    )
    target_match_groups, target_overload_block = filter_target_match_groups_for_overload_safety(
        api_row,
        target_match_groups,
        graph,
        type_metadata=type_metadata,
        trace_cache=trace_cache,
    )
    _step5_debug(
        'target_match_groups_filtered',
        'applied overload safety filtering to target match groups',
        api_name=api_name,
        api_signature=result.api_signature,
        target_match_groups=target_match_groups,
        target_overload_block=target_overload_block,
    )
    if target_overload_block:
        _step5_debug(
            'overload_target_block',
            'target api blocked because only unsigned matches survived',
            api_name=api_name,
            api_signature=result.api_signature,
            target_match_groups=target_match_groups,
            overload_info=target_overload_block,
        )
        _step5_debug_break(
            'overload_target_block',
            api_name=api_name,
            api_signature=result.api_signature,
            target_match_groups=target_match_groups,
            overload_info=target_overload_block,
        )
        # An exact current-artifact bytecode descriptor is stronger than an
        # ambiguous source-graph fallback. Preserve the concrete dependency
        # consumer and signature for review; only the path back to business code
        # remains uncertain.
        if artifact_dependency_hits:
            packaged_dependency_result = _build_packaged_dependency_hit_result(
                result,
                artifact_dependency_hits,
                graph,
            )
            _debug_trace_result(
                'trace_api_result',
                packaged_dependency_result,
                overload_info=target_overload_block,
            )
            return packaged_dependency_result
        if artifact_scan_miss:
            # The source graph may retain an unsigned alias beside fully typed
            # calls to sibling overloads.  If the complete current artifact scan
            # found no exact descriptor hit, there is no remaining static path
            # to disambiguate: report a static miss instead of claiming the
            # requested overload could not be analyzed.  This does not mean the
            # runtime is proven safe; the returned result keeps the standard
            # reflection/configuration caveat.
            built = _build_packaged_dependency_not_found_result(result)
            _debug_trace_result(
                'trace_api_result',
                built,
                overload_info=target_overload_block,
            )
            return built
        blocked = build_overload_ambiguous_result(result, target_overload_block)
        _debug_trace_result('trace_api_result', blocked, overload_info=target_overload_block)
        return blocked

    for matched_group in target_match_groups:
        for key in matched_group['matched_keys']:
            queue.append({
                'key': key,
                'path': [],
                'cost': 0,
                'confidence': apply_provenance_confidence_modifier(1.0, matched_group['provenance']),
                'depth': 0,
                'provenance': matched_group['provenance'],
                'provenance_family': matched_group['provenance_family'],
                'match_tier': matched_group['tier_index'],
            })
    _step5_debug(
        'trace_frontier_seed',
        'seeded bfs frontier from target matches',
        api_name=api_name,
        seed_count=len(queue),
        seed_groups=target_match_groups,
    )
    reachable_candidates = []
    uncertain_candidates = []
    not_analyzed_candidates = []

    while queue:
        frontier = queue.popleft()
        _perf_add(graph, 'trace', 'frontier_pops', 1)
        current_key = frontier['key']
        current_path = frontier['path']
        current_cost = frontier['cost']
        current_confidence = frontier['confidence']
        current_depth = frontier['depth']
        _step5_debug(
            'trace_frontier_pop',
            'processing frontier item',
            api_name=api_name,
            current_key=current_key,
            current_cost=current_cost,
            current_confidence=current_confidence,
            current_depth=current_depth,
            provenance=frontier.get('provenance', ''),
        )

        # 查询反向索引
        incoming_edges = get_cached_sorted_incoming_edges(
            reverse_edges,
            current_key,
            trace_cache=trace_cache,
            graph=graph,
        )
        _perf_add(graph, 'trace', 'incoming_edges_scanned', len(incoming_edges))

        if not incoming_edges:
            # 链路终点
            if current_depth > 0:
                not_analyzed_candidates.append({
                    'path': current_path,
                    'reason': 'NO_CALLERS',
                    'cost': current_cost,
                    'confidence': current_confidence
                })
                _step5_debug(
                    'trace_no_callers',
                    'frontier key has no incoming callers',
                    api_name=api_name,
                    current_key=current_key,
                    current_depth=current_depth,
                )
            continue

        # 处理每条边
        for edge in incoming_edges:
            # 过滤test方法
            method_def = methods_by_id.get(edge.caller_symbol_id)
            if not method_def or method_def.is_test:
                continue

            # 关键修复：加权去重策略
            # 只保留 cost 更低的路径（cost 越低越好）
            # 计算新代价和置信度
            edge_cost = calculate_depth_cost(edge.confidence)
            new_cost = current_cost + edge_cost
            new_confidence = calculate_confidence_decay(current_confidence, edge.confidence)
            new_depth = current_depth + 1

            visited_key = (method_def.symbol_id, frontier.get('provenance_family', 'exact'))
            dominated, updated_frontier = update_path_frontier(
                visited.get(visited_key),
                cost=new_cost,
                confidence=new_confidence,
            )
            if dominated:
                _step5_debug(
                    'trace_pruned',
                    'skipped path because an equal or Pareto-better path already exists',
                    api_name=api_name,
                    current_key=current_key,
                    caller=method_def.qualified_key,
                    existing_frontier=visited.get(visited_key),
                    candidate_score=(new_cost, new_confidence),
                )
                continue  # 已有更优路径，跳过
            visited[visited_key] = updated_frontier

            # 必须记录“到达该节点后的总代价”，否则后续更优路径会被错误剪枝。
            # 这里同时保留 provenance_family，避免 exact / polymorphic / fallback 互相误剪枝。

            # 检查关键节点
            critical_node = get_cached_critical_node(
                method_def,
                graph,
                type_metadata,
                trace_cache=trace_cache,
            )

            # 判断是否停止
            should_stop, stop_reason = should_stop_tracing(
                new_cost,
                max_total_cost,
                new_confidence,
                critical_node,
                edge.confidence,
            )

            # 构建新路径
            new_path = current_path + [edge]

            # 分类处理
            if critical_node and critical_node['type'] == 'system_code_touched':
                # 成功触达系统代码
                reachable_candidates.append({
                    'path': new_path,
                    'entry_point': critical_node,
                    'cost': new_cost,
                    'confidence': new_confidence,
                    'depth': new_depth,
                    'provenance': frontier.get('provenance', ''),
                    'match_tier': frontier.get('match_tier', -1),
                })
                _step5_debug(
                    'trace_reachable_candidate',
                    'candidate path reached system code',
                    api_name=api_name,
                    caller=method_def.qualified_key,
                    current_key=current_key,
                    new_cost=new_cost,
                    new_depth=new_depth,
                )
                # 触达系统代码已经足以证明 reachable，但报告复核时还需要尽量看到
                # A -> B -> C -> D 这类完整上游链路。过去这里直接停止，导致
                # alerts.csv 通常只展示第一个业务调用点 C -> D。现在在不改变
                # reachable 判定的前提下，若仍在 cost/confidence 边界内，继续
                # 沿高/中置信业务边向上游扩展，直到 max_total_cost 或图边界。
                if new_cost < max_total_cost and new_confidence >= 0.3 and edge.confidence in ('high', 'medium'):
                    matched_lookup_groups, method_overload_block = get_cached_method_lookup_resolution(
                        method_def,
                        type_metadata,
                        graph,
                        trace_cache=trace_cache,
                    )
                    # 上游补全只走精确签名。这里的目标是让报告展示更完整的
                    # A -> B -> C -> D 证据链，而不是扩大召回。若沿用
                    # fallback_simple / polymorphic，真实大项目里容易因为 init/close
                    # 等同名方法串出大量不可靠长链路，违背准确性优先原则。
                    matched_lookup_groups = [
                        group for group in matched_lookup_groups
                        if group.get('provenance') == 'exact_signature'
                    ]
                    if method_overload_block:
                        _step5_debug(
                            'trace_reachable_overload_boundary',
                            'reachable path recorded but upstream expansion stopped at overloaded business method',
                            current_key=current_key,
                            method=method_def.qualified_key,
                            overload_info=method_overload_block,
                            path_length=len(new_path),
                        )
                    else:
                        for matched_group in matched_lookup_groups:
                            merged_provenance = merge_match_provenance(
                                frontier.get('provenance', ''),
                                matched_group['provenance'],
                            )
                            for next_key in matched_group['matched_keys']:
                                queue.append({
                                    'key': next_key,
                                    'path': new_path,
                                    'cost': new_cost,
                                    'confidence': apply_provenance_confidence_modifier(
                                        new_confidence,
                                        matched_group['provenance'],
                                    ),
                                    'depth': new_depth,
                                    'provenance': merged_provenance,
                                    'provenance_family': merged_provenance_family(
                                        frontier.get('provenance_family', 'exact'),
                                        matched_group['provenance_family'],
                                    ),
                                    'match_tier': max(frontier.get('match_tier', -1), matched_group['tier_index']),
                                })
                                _perf_add(graph, 'trace', 'frontier_pushes', 1)
                        _step5_debug(
                            'trace_expand_after_system_reached',
                            'continued tracing upstream after recording reachable system-code candidate',
                            api_name=api_name,
                            caller=method_def.qualified_key,
                            current_key=current_key,
                            matched_lookup_groups=matched_lookup_groups,
                            queue_size=len(queue),
                        )
                continue

            if critical_node and critical_node['type'] == 'framework_boundary':
                # 框架边界，无法继续
                not_analyzed_candidates.append({
                    'path': new_path,
                    'boundary': critical_node,
                    'reason': 'FRAMEWORK_BOUNDARY',
                    'cost': new_cost,
                    'confidence': new_confidence,
                    'provenance': frontier.get('provenance', ''),
                    'match_tier': frontier.get('match_tier', -1),
                })
                _step5_debug(
                    'trace_framework_boundary',
                    'candidate path stopped at framework boundary',
                    api_name=api_name,
                    caller=method_def.qualified_key,
                    current_key=current_key,
                    new_cost=new_cost,
                )
                continue

            if should_stop:
                # 达到停止条件
                if stop_reason in {'DEPTH_LIMIT_REACHED', 'LOW_CONFIDENCE_EDGE'}:
                    uncertain_candidates.append({
                        'path': new_path,
                        'reason': stop_reason,
                        'cost': new_cost,
                        'confidence': new_confidence,
                        'depth': new_depth,
                        'provenance': frontier.get('provenance', ''),
                        'match_tier': frontier.get('match_tier', -1),
                    })
                elif stop_reason == 'CONFIDENCE_DECAYED':
                    uncertain_candidates.append({
                        'path': new_path,
                        'reason': 'CONFIDENCE_DECAYED',
                        'cost': new_cost,
                        'confidence': new_confidence,
                        'depth': new_depth,
                        'provenance': frontier.get('provenance', ''),
                        'match_tier': frontier.get('match_tier', -1),
                    })
                _step5_debug(
                    'trace_stop_condition',
                    'candidate path stopped by tracing policy',
                    api_name=api_name,
                    caller=method_def.qualified_key,
                    current_key=current_key,
                    stop_reason=stop_reason,
                    new_cost=new_cost,
                    new_depth=new_depth,
                    new_confidence=new_confidence,
                )
                continue

            # 继续追踪
            matched_lookup_groups, method_overload_block = get_cached_method_lookup_resolution(
                method_def,
                type_metadata,
                graph,
                trace_cache=trace_cache,
            )
            if method_overload_block:
                _step5_debug(
                    'trace_overload_intermediate',
                    'trace stopped at intermediate overloaded method',
                    current_key=current_key,
                    method=method_def.qualified_key,
                    overload_info=method_overload_block,
                    path_length=len(new_path),
                )
                _step5_debug_break(
                    'trace_overload_intermediate',
                    current_key=current_key,
                    method=method_def.qualified_key,
                    overload_info=method_overload_block,
                    path_length=len(new_path),
                )
                not_analyzed_candidates.append({
                    'path': new_path,
                    'reason': 'OVERLOAD_AMBIGUOUS_INTERMEDIATE',
                    'boundary': {
                        'method': critical_node_method_label(method_def),
                        'reason': build_intermediate_overload_reason(method_def, method_overload_block),
                    },
                    'provenance': frontier.get('provenance', ''),
                    'match_tier': frontier.get('match_tier', -1),
                    'verification_commands': [
                        '补全该中间方法调用点的参数类型推断，确保能命中精确签名',
                        '若确有多个 overload，请人工复核当前调用链是否串到了 sibling overload',
                    ],
                })
                continue
            if method_def.owner_type == 'business':
                # 业务代码：低置信度边不再建图时丢弃，而是在 tracer 中保守停止并归入 uncertain。
                if edge.confidence in ('high', 'medium'):
                    for matched_group in matched_lookup_groups:
                        merged_provenance = merge_match_provenance(
                            frontier.get('provenance', ''),
                            matched_group['provenance'],
                        )
                        for next_key in matched_group['matched_keys']:
                            queue.append({
                                'key': next_key,
                                'path': new_path,
                                'cost': new_cost,
                                'confidence': apply_provenance_confidence_modifier(
                                    new_confidence,
                                    matched_group['provenance'],
                                ),
                                'depth': new_depth,
                                'provenance': merged_provenance,
                                'provenance_family': merged_provenance_family(
                                    frontier.get('provenance_family', 'exact'),
                                    matched_group['provenance_family'],
                                ),
                                'match_tier': max(frontier.get('match_tier', -1), matched_group['tier_index']),
                            })
                            _perf_add(graph, 'trace', 'frontier_pushes', 1)
                    _step5_debug(
                        'trace_expand',
                        'expanded frontier through business caller',
                        api_name=api_name,
                        caller=method_def.qualified_key,
                        current_key=current_key,
                        matched_lookup_groups=matched_lookup_groups,
                        queue_size=len(queue),
                    )
                else:
                    uncertain_candidates.append({
                        'path': new_path,
                        'reason': 'CONFIDENCE_DECAYED',
                        'cost': new_cost,
                        'confidence': new_confidence,
                        'depth': new_depth,
                        'provenance': frontier.get('provenance', ''),
                        'match_tier': frontier.get('match_tier', -1),
                    })
                    _step5_debug(
                        'trace_decay_stop',
                        'business edge downgraded to uncertain because confidence is too low',
                        api_name=api_name,
                        caller=method_def.qualified_key,
                        current_key=current_key,
                        edge_confidence=edge.confidence,
                    )
            else:
                # 依赖包代码：继续追踪
                for matched_group in matched_lookup_groups:
                    merged_provenance = merge_match_provenance(
                        frontier.get('provenance', ''),
                        matched_group['provenance'],
                    )
                    for next_key in matched_group['matched_keys']:
                        queue.append({
                            'key': next_key,
                            'path': new_path,
                            'cost': new_cost,
                            'confidence': apply_provenance_confidence_modifier(
                                new_confidence,
                                matched_group['provenance'],
                            ),
                            'depth': new_depth,
                            'provenance': merged_provenance,
                            'provenance_family': merged_provenance_family(
                                frontier.get('provenance_family', 'exact'),
                                matched_group['provenance_family'],
                            ),
                            'match_tier': max(frontier.get('match_tier', -1), matched_group['tier_index']),
                        })
                        _perf_add(graph, 'trace', 'frontier_pushes', 1)
                _step5_debug(
                    'trace_expand',
                    'expanded frontier through dependency caller',
                    api_name=api_name,
                    caller=method_def.qualified_key,
                    current_key=current_key,
                    matched_lookup_groups=matched_lookup_groups,
                    queue_size=len(queue),
                )

    # 保存全部终止链路供人工复核；API 级状态仍由下面的最优证据规则求值。
    result.path_details = build_all_candidate_path_details(
        reachable_candidates,
        uncertain_candidates,
        not_analyzed_candidates,
        graph,
        final_target=changed_api_display_target(result),
    )

    # 选择最优结果
    if reachable_candidates:
        best = select_best_candidate(reachable_candidates)
        if artifact_scan_miss and not has_verified_final_artifact_framework_path(best):
            built = build_reachable_result(result, best, graph)
            _apply_source_artifact_miss(built, graph, (
                '源码中发现了可达调用链，但当前打包产物的字节码扫描没有发现对应引用；'
                '可能是源码、构建参数或目标模块与本次打包产物不一致，当前不能确认影响'
            ))
            _debug_trace_result('trace_api_result', built)
            return built
        # 行为变更：即使找到调用链也需运行时验证
        if result.change_type == 'BEHAVIOR_CHANGED':
            safe_best, unsafe_best = select_behavior_changed_candidate(api_row, reachable_candidates)
            if unsafe_best is not None:
                built = build_behavior_changed_fallback_simple_result(result, unsafe_best, graph)
                _debug_trace_result('trace_api_result', built, candidate_counts={
                    'reachable': len(reachable_candidates),
                    'uncertain': len(uncertain_candidates),
                    'not_analyzed': len(not_analyzed_candidates),
                })
                return built
            built = build_behavior_changed_result(result, safe_best or best, graph)
            _debug_trace_result('trace_api_result', built, candidate_counts={
                'reachable': len(reachable_candidates),
                'uncertain': len(uncertain_candidates),
                'not_analyzed': len(not_analyzed_candidates),
            })
            return built
        safe_best, unsafe_best, unsafe_reason = select_confirmable_reachable_candidate(result, reachable_candidates)
        if unsafe_best is not None:
            if unsafe_reason == 'INTERNAL_ONLY_DIRECT_CONSUMER':
                built = build_internal_only_direct_consumer_result(result, unsafe_best, graph)
            else:
                built = build_fallback_simple_unconfirmed_result(result, unsafe_best, graph)
            _debug_trace_result('trace_api_result', built, candidate_counts={
                'reachable': len(reachable_candidates),
                'uncertain': len(uncertain_candidates),
                'not_analyzed': len(not_analyzed_candidates),
            })
            return built
        built = build_reachable_result(result, safe_best or best, graph)
        _apply_constant_impact(
            built,
            api_row,
            graph,
            runtime_field_edge_present=True,
        )
        if artifact_dependency_hits:
            built = _merge_runtime_framework_paths(
                built,
                artifact_dependency_hits,
                graph,
            )
            _apply_constant_impact(
                built,
                api_row,
                graph,
                runtime_field_edge_present=True,
            )
        _debug_trace_result('trace_api_result', built, candidate_counts={
            'reachable': len(reachable_candidates),
            'uncertain': len(uncertain_candidates),
            'not_analyzed': len(not_analyzed_candidates),
        })
        return built

    # 运行时依赖字节码命中是强证据，但不应抢在源码反向追踪之前提前终止方法级分析。
    # 对有依赖源码映射的多模块系统，应先允许 tracer 继续证明是否最终回到 BUSINESS。
    # 只有在源码图没有产出更强结论时，才回退为打包依赖字节码命中结论。
    if artifact_dependency_hits:
        packaged_dependency_result = _build_packaged_dependency_hit_result(result, artifact_dependency_hits, graph)
        _apply_constant_impact(
            packaged_dependency_result,
            api_row,
            graph,
            runtime_field_edge_present=True,
        )
        _debug_trace_result('trace_api_result', packaged_dependency_result, candidate_counts={
            'reachable': len(reachable_candidates),
            'uncertain': len(uncertain_candidates),
            'not_analyzed': len(not_analyzed_candidates),
        })
        return packaged_dependency_result

    if uncertain_candidates:
        if needs_bridge and (not has_dependency_source_mapping) and allow_degraded:
            built = build_missing_dependency_source_mapping_result(result)
            _debug_trace_result('trace_api_result', built, candidate_counts={
                'reachable': len(reachable_candidates),
                'uncertain': len(uncertain_candidates),
                'not_analyzed': len(not_analyzed_candidates),
            })
            return built
        best = select_best_candidate(uncertain_candidates)
        built = build_uncertain_result(result, best)
        _debug_trace_result('trace_api_result', built, candidate_counts={
            'reachable': len(reachable_candidates),
            'uncertain': len(uncertain_candidates),
            'not_analyzed': len(not_analyzed_candidates),
        })
        return built

    if not_analyzed_candidates:
        best = select_best_candidate(not_analyzed_candidates)
        built = build_not_analyzed_result(result, best)
        _debug_trace_result('trace_api_result', built, candidate_counts={
            'reachable': len(reachable_candidates),
            'uncertain': len(uncertain_candidates),
            'not_analyzed': len(not_analyzed_candidates),
        })
        return built

    # 未找到任何路径
    # 【修复】改进四态分类语义：将 not_reachable 改为更准确的 not_found_in_static_analysis
    # 原因：静态分析未找到路径不等于"确定未影响"，可能是：
    # 1. 反射调用/动态代理/配置文件引用
    # 2. 测试代码或非扫描目录中的引用
    # 3. 运行时动态加载的代码
    indirect_result = _build_indirect_usage_result(result, api_row, graph)
    if indirect_result is not None:
        _debug_trace_result('trace_api_result', indirect_result)
        return indirect_result

    if (result.capability_coverage or {}).get('status') in {'partial', 'insufficient'}:
        built = _build_indirect_coverage_incomplete_result(result)
        _debug_trace_result('trace_api_result', built)
        return built

    if artifact_scan_miss:
        if _is_inlined_constant_change(api_row):
            _attach_source_only_paths(
                result,
                graph,
                target_match_groups,
                stop_reason='INLINED_CONSTANT_USAGE_UNDETECTABLE',
            )
            built = _build_inlined_constant_result(result, api_row, graph)
            _debug_trace_result('trace_api_result', built)
            return built
        source_conflict = _build_source_only_artifact_conflict_result(
            result,
            graph,
            target_match_groups,
        )
        if source_conflict is not None:
            _debug_trace_result('trace_api_result', source_conflict)
            return source_conflict
        built = _build_packaged_dependency_not_found_result(result)
        _debug_trace_result('trace_api_result', built)
        return built

    if needs_bridge and (not has_dependency_source_mapping) and allow_degraded:
        built = build_missing_dependency_source_mapping_result(result)
        _debug_trace_result('trace_api_result', built)
        return built

    if needs_bridge and (not has_dependency_source_mapping) and not allow_degraded:
        # 需要依赖源码映射但不允许降级 → 不应该走到这里（应该在前面就报错）
        # 如果走到了这里，说明图搜索空间不足，而非映射问题
        _apply_blocking_failure(
            result, 'source-graph-analysis', 'ANALYSIS_INCOMPLETE',
            '分析不完整，可能需要补充依赖源码映射或调整分析参数',
        )
        result.verification_commands = [
            '检查是否需要补充依赖源码映射',
            '或调整 max_depth 参数重新分析'
        ]
        _debug_trace_result('trace_api_result', result)
        return result

    graph_completeness = assess_graph_completeness(graph_stats, api_row=api_row)
    if graph_completeness['incomplete']:
        built = build_analysis_incomplete_result(result, graph_completeness)
        _debug_trace_result('trace_api_result', built, graph_completeness=graph_completeness)
        return built

    if artifact_scan_incomplete:
        built = _build_packaged_dependency_incomplete_result(result, artifact_scan_incomplete)
        _debug_trace_result('trace_api_result', built)
        return built

    if result.symbol_kind in CALL_GRAPH_LIMITED_SYMBOL_KINDS:
        built = build_call_graph_limited_symbol_result(result)
        _debug_trace_result('trace_api_result', built)
        return built

    # 只有当不需要依赖源码映射，且搜索空间完整时，才输出 not_found_in_static_analysis
    # 注意：这不代表"确定未影响"，只表示"静态分析未找到"
    _apply_evidence_decision(result, complete_scan=True)
    result.verification_commands = [
        '搜索项目中是否包含该API名称的字符串引用',
        '检查是否有反射调用: Class.forName/Method.invoke',
        '检查配置文件: XML/YAML/Properties',
        '运行全量测试验证是否有运行时影响'
    ]
    _debug_trace_result('trace_api_result', result, candidate_counts={
        'reachable': len(reachable_candidates),
        'uncertain': len(uncertain_candidates),
        'not_analyzed': len(not_analyzed_candidates),
    })
    return result


def trace_api_with_confidence_weighting(
    api_row,
    graph,
    type_metadata,
    max_total_cost=5,
    needs_bridge=False,
    has_dependency_source_mapping=True,
    has_packaged_bytecode_fallback=False,
    allow_degraded=False,
    graph_stats=None,
    trace_cache=None,
):
    draft = _collect_trace_api_with_confidence_weighting(
        api_row,
        graph,
        type_metadata,
        max_total_cost=max_total_cost,
        needs_bridge=needs_bridge,
        has_dependency_source_mapping=has_dependency_source_mapping,
        has_packaged_bytecode_fallback=has_packaged_bytecode_fallback,
        allow_degraded=allow_degraded,
        graph_stats=graph_stats,
        trace_cache=trace_cache,
    )
    if not isinstance(draft, TraceDraft):
        raise TypeError(
            "Step5 evidence collector must return TraceDraft before terminal rendering"
        )
    return _finalize_trace_draft(draft)


def append_unique(keys, value):
    value = (value or '').strip()
    if not value or value in keys:
        return
    keys.append(value)


def extend_unique(keys, values):
    for value in values or []:
        append_unique(keys, value)


PROVENANCE_RANK = {
    'exact_signature': 0,
    'compatible_signature': 0,
    'exact_name': 1,
    'polymorphic': 2,
    'fallback_simple': 3,
    '': 99,
}

PROVENANCE_FAMILY_RANK = {
    'exact': 0,
    'polymorphic': 1,
    'fallback_simple': 2,
    '': 99,
}

PROVENANCE_FAMILY = {
    'exact_signature': 'exact',
    'exact_name': 'exact',
    'polymorphic': 'polymorphic',
    'fallback_simple': 'fallback_simple',
}


def provenance_rank(provenance):
    return PROVENANCE_RANK.get((provenance or '').strip(), 99)


def provenance_family_rank(family):
    return PROVENANCE_FAMILY_RANK.get((family or '').strip(), 99)


def merge_match_provenance(current, new_value):
    current = (current or '').strip()
    new_value = (new_value or '').strip()
    if not current:
        return new_value
    if not new_value:
        return current
    return current if provenance_rank(current) >= provenance_rank(new_value) else new_value


def merged_provenance_family(current_family, new_family):
    current_family = (current_family or '').strip()
    new_family = (new_family or '').strip()
    if not current_family:
        return new_family
    if not new_family:
        return current_family
    return (
        current_family
        if provenance_family_rank(current_family) >= provenance_family_rank(new_family)
        else new_family
    )


def apply_provenance_confidence_modifier(confidence, provenance):
    modifiers = {
        'exact_signature': 1.0,
        'compatible_signature': 1.0,
        'exact_name': 0.98,
        'polymorphic': 0.94,
        'fallback_simple': 0.85,
    }
    return confidence * modifiers.get((provenance or '').strip(), 1.0)


def append_key_group(groups, provenance, keys):
    key_list = []
    extend_unique(key_list, keys)
    if not key_list:
        return
    groups.append({
        'tier_index': len(groups),
        'provenance': provenance,
        'provenance_family': PROVENANCE_FAMILY.get(provenance, ''),
        'keys': key_list,
    })


def select_matching_key_groups(key_groups, reverse_edges):
    matched_groups = []
    for group in key_groups or []:
        matched_keys = []
        for key in group.get('keys', []):
            if reverse_edges.get(key):
                append_unique(matched_keys, key)
        if matched_keys:
            matched_groups.append({
                'tier_index': group.get('tier_index', -1),
                'provenance': group.get('provenance', ''),
                'provenance_family': group.get('provenance_family', ''),
                'matched_keys': matched_keys,
            })
    return matched_groups


def ensure_trace_cache(trace_cache=None):
    trace_cache = trace_cache if trace_cache is not None else {}
    trace_cache.setdefault('overload_signatures', {})
    trace_cache.setdefault('method_lookup_resolution', {})
    trace_cache.setdefault('sorted_incoming_edges_by_key', {})
    trace_cache.setdefault('critical_node_by_symbol_id', {})
    trace_cache.setdefault('direct_business_class_usage', {})
    trace_cache.setdefault('direct_business_field_usages', {})
    trace_cache.setdefault('declared_method_signature_index', None)
    trace_cache.setdefault('declared_method_signature_index_owner', None)
    trace_cache.setdefault('overload_signature_index', None)
    trace_cache.setdefault('overload_signature_index_owner', None)
    return trace_cache


def _valid_projected_sha256(value):
    return bool(re.fullmatch(r'[0-9a-fA-F]{64}', str(value or '')))


def _inspectable_runtime_analyzer_hit(edge):
    hit = getattr(edge, 'runtime_analyzer_hit', None)
    return hit if isinstance(hit, Mapping) and bool(hit) else None


def _verified_composite_framework_projection(edge):
    caller_file = str(getattr(edge, 'caller_evidence_file', '') or '').strip()
    caller_entry = str(getattr(edge, 'caller_artifact_entry', '') or '').strip()
    if '!/' in caller_file and caller_file.split('!/', 1)[1] != caller_entry:
        return False
    return bool(
        getattr(edge, 'framework_registration', False) is True
        and getattr(edge, 'framework_final_artifact_verified', False) is True
        and getattr(edge, 'semantic', False) is True
        and str(getattr(edge, 'evidence_source', '') or '') == 'framework_semantic'
        and str(getattr(edge, 'evidence_authority', '') or '') == 'framework_semantic'
        and str(getattr(edge, 'framework_evidence_source', '') or '')
        == 'framework_semantic'
        and str(getattr(edge, 'framework_evidence_authority', '') or '')
        == 'framework_semantic'
        and _valid_projected_sha256(
            getattr(edge, 'framework_evidence_artifact_sha256', '')
        )
        and str(getattr(edge, 'framework_evidence_artifact_entry', '') or '').strip()
        and str(getattr(edge, 'artifact_sha256', '') or '')
        == str(getattr(edge, 'framework_evidence_artifact_sha256', '') or '')
        and str(getattr(edge, 'artifact_entry', '') or '')
        == str(getattr(edge, 'framework_evidence_artifact_entry', '') or '')
        and str(getattr(edge, 'collector', '') or '').strip()
        and str(getattr(edge, 'framework_source', '') or '').strip()
        and str(getattr(edge, 'framework_target', '') or '').strip()
        == str(getattr(edge, 'callee_key', '') or '').strip()
        and str(getattr(edge, 'caller_evidence_source', '') or '')
        == 'current_final_artifact'
        and str(getattr(edge, 'caller_evidence_authority', '') or '')
        == 'current_final_artifact'
        and _valid_projected_sha256(
            getattr(edge, 'caller_artifact_sha256', '')
        )
        and caller_file
        and caller_entry
        and str(getattr(edge, 'owner_type', '') or '') == 'business'
        and not bool(getattr(edge, 'is_test', False))
    )


def _edge_allowed_for_trace(edge, graph):
    if not bool(getattr(graph, 'require_current_final_artifact_business_edges', False)):
        return True
    if getattr(edge, 'framework_registration', False) or getattr(edge, 'semantic', False):
        return _verified_composite_framework_projection(edge)
    return bool(
        str(getattr(edge, 'evidence_source', '') or '') == 'current_final_artifact'
        or _inspectable_runtime_analyzer_hit(edge)
    )


def _semantic_edge_activation_verified(edge):
    semantic = bool(
        getattr(edge, 'semantic', False)
        or getattr(edge, 'framework_registration', False)
    )
    if not semantic:
        return False
    return bool(
        getattr(edge, 'framework_activation_verified', False)
        or _verified_composite_framework_projection(edge)
    )


def _typed_activation_evidence(edge):
    """Project activation proof only when its authority can be independently located."""
    keys = (
        'evidence_type', 'edge_kind', 'file', 'caller_evidence_file',
        'caller_symbol', 'caller_symbol_id', 'framework_evidence_artifact_sha256',
        'caller_artifact_sha256', 'artifact_sha256', 'evidence_source',
    )
    value = edge if isinstance(edge, Mapping) else {
        key: getattr(edge, key, None) for key in keys
    }
    evidence_type = str(
        value.get('evidence_type') or value.get('edge_kind') or 'semantic_activation'
    ).strip()
    source = str(
        value.get('file') or value.get('caller_evidence_file')
        or value.get('caller_symbol') or value.get('caller_symbol_id') or ''
    ).strip()
    digest = str(
        value.get('framework_evidence_artifact_sha256')
        or value.get('caller_artifact_sha256')
        or value.get('artifact_sha256') or ''
    ).strip().lower()
    if source and _valid_projected_sha256(digest):
        return (ActivationEvidence(
            authority=EvidenceAuthority.CURRENT_FINAL_ARTIFACT,
            proof_kind=evidence_type,
            source=source,
            artifact_sha256=digest,
        ),)
    evidence_source = str(value.get('evidence_source') or '').strip()
    if source and (
        evidence_source == 'source_indirect_inference'
        or any(token in evidence_type for token in ('reflection', 'method_handle', 'resource_lookup'))
    ):
        return (ActivationEvidence(
            authority=EvidenceAuthority.SOURCE_INDIRECT_INFERENCE,
            proof_kind=evidence_type,
            source=source,
        ),)
    return ()


def get_cached_sorted_incoming_edges(reverse_edges, current_key, trace_cache=None, graph=None):
    trace_cache = ensure_trace_cache(trace_cache)
    cache = trace_cache['sorted_incoming_edges_by_key']
    if current_key in cache:
        _perf_add(graph, 'trace', 'incoming_edges_cache_hits', 1)
        return cache[current_key]
    _perf_add(graph, 'trace', 'incoming_edges_cache_misses', 1)
    incoming_edges = list(reverse_edges.get(current_key, []) or [])
    incoming_edges = [edge for edge in incoming_edges if _edge_allowed_for_trace(edge, graph)]
    incoming_edges = tuple(sorted(incoming_edges, key=stable_edge_sort_key))
    cache[current_key] = incoming_edges
    _perf_max(graph, 'trace', 'incoming_edges_cache_size', len(cache))
    return incoming_edges


def critical_node_method_label(method_def):
    """Return an IDE-locatable entry method including its overload signature."""
    qualified_key = str(getattr(method_def, 'qualified_key', '') or '').strip()
    signature = str(getattr(method_def, 'declared_signature', '') or '').strip()
    if not signature:
        declared_types = getattr(method_def, 'param_declared_types', {}) or {}
        signature = _build_signature_from_params(declared_types.values())
    if signature and qualified_key and not qualified_key.endswith(signature):
        return f"{qualified_key}{signature}"
    return qualified_key


def critical_node_entry_kind(method_def, framework_edge_kind=''):
    annotations = list(getattr(method_def, 'annotations', []) or [])
    annotations.extend(list(getattr(method_def, 'class_annotations', []) or []))
    names = {
        str(annotation or '').strip().lstrip('@').split('(', 1)[0].rsplit('.', 1)[-1]
        for annotation in annotations
        if str(annotation or '').strip()
    }
    if names & {'RequestMapping', 'GetMapping', 'PostMapping', 'PutMapping', 'DeleteMapping', 'PatchMapping'}:
        return 'spring_web_endpoint'
    if 'Scheduled' in names:
        return 'spring_scheduled_entry'
    if 'EventListener' in names:
        return 'spring_event_listener'
    if names & {'KafkaListener', 'RabbitListener', 'JmsListener', 'RocketMQMessageListener'}:
        return 'spring_message_listener'
    if names & {
        'PrePersist', 'PostPersist', 'PreUpdate', 'PostUpdate',
        'PreRemove', 'PostRemove', 'PostLoad',
    }:
        return 'jpa_lifecycle_callback'
    edge_kind = str(framework_edge_kind or '').strip()
    if edge_kind == 'spring_event_listener':
        return 'spring_event_listener'
    if edge_kind:
        return edge_kind
    return 'business_method' if getattr(method_def, 'owner_type', '') == 'business' else 'runtime_dependency_entry'


def get_cached_critical_node(method_def, graph, type_metadata, trace_cache=None):
    trace_cache = ensure_trace_cache(trace_cache)
    cache = trace_cache['critical_node_by_symbol_id']
    symbol_id = getattr(method_def, 'symbol_id', '')
    if symbol_id in cache:
        _perf_add(graph, 'trace', 'critical_node_cache_hits', 1)
        return cache[symbol_id]
    _perf_add(graph, 'trace', 'critical_node_cache_misses', 1)
    critical_node = None
    framework_entries = (
        getattr(graph, 'framework_entry_symbols', {}) or {}
    ).get(symbol_id) or []
    runtime_framework_entries = (
        getattr(graph, 'framework_runtime_entry_methods', {}) or {}
    ).get(str(getattr(method_def, 'qualified_key', '') or '').split('(', 1)[0]) or []
    activation_linked = symbol_id in (
        getattr(graph, 'framework_activation_linked_symbols', set()) or set()
    )
    if runtime_framework_entries and not activation_linked:
        first_framework_entry = runtime_framework_entries[0]
        entry_kind = str(first_framework_entry.get('edge_kind') or '').strip()
        entry_provenance = first_framework_entry.get('provenance') or {}
        activation_verified = (
            str(first_framework_entry.get('runtime_activation') or '').strip()
            == 'active'
            and (
                entry_kind in {
                    'spring_scheduled_entry',
                    'spring_xml_scheduled_task',
                    'spring_runtime_active_entry',
                }
                or bool(entry_provenance.get('business_activation'))
            )
        )
        entry_scope = (
            'business'
            if getattr(method_def, 'owner_type', '') == 'business'
            else 'runtime_dependency_entry'
        )
        critical_node = {
            'type': 'system_code_touched',
            'entry_scope': entry_scope,
            'method': critical_node_method_label(method_def),
            'file': method_def.file,
            'line': method_def.line,
            'framework_edge_kind': first_framework_entry.get('edge_kind'),
            'entry_kind': critical_node_entry_kind(method_def, first_framework_entry.get('edge_kind')),
            'framework_adapter': first_framework_entry.get('adapter'),
            'framework_runtime_registration': True,
            'activation_verified': activation_verified,
        }
    elif framework_entries and not activation_linked:
        confirmed_framework_entries = []
        for item in framework_entries:
            if item.get('ambiguity'):
                continue
            runtime_activation = str(item.get('runtime_activation') or '').strip()
            if runtime_activation in {'conditional', 'unproven'}:
                continue
            edge_kind = str(item.get('edge_kind') or '').strip()
            # Dependency callbacks require positive activation evidence. A source
            # declaration such as ApplicationListener or an auto-configuration
            # registration is only a candidate until the current artifact proves
            # activation. Scheduled/PostConstruct/XML task entries are explicit
            # runtime triggers and remain confirmable.
            if getattr(method_def, 'owner_type', '') != 'business' and not (
                runtime_activation == 'active'
                or edge_kind == 'spring_runtime_active_entry'
            ):
                continue
            if item.get('conditions') and runtime_activation != 'active' and edge_kind != 'spring_runtime_active_entry':
                continue
            confirmed_framework_entries.append(item)
        first_framework_entry = confirmed_framework_entries[0] if confirmed_framework_entries else None
        if first_framework_entry is None:
            if is_system_code_touched(method_def, type_metadata):
                critical_node = {
                    'type': 'system_code_touched',
                    'entry_scope': 'business',
                    'method': critical_node_method_label(method_def),
                    'file': method_def.file,
                    'line': method_def.line,
                    'entry_kind': critical_node_entry_kind(method_def),
                }
            else:
                critical_node = {
                    'type': 'framework_boundary',
                    'method': critical_node_method_label(method_def),
                    'reason': '框架入口存在运行条件，当前制品证据尚未证明该入口会被激活',
                }
        else:
            entry_scope = (
                'business'
                if getattr(method_def, 'owner_type', '') == 'business'
                else 'runtime_dependency_entry'
            )
            critical_node = {
                'type': 'system_code_touched',
                'entry_scope': entry_scope,
                'method': critical_node_method_label(method_def),
                'file': method_def.file,
                'line': method_def.line,
                'framework_edge_kind': first_framework_entry.get('edge_kind'),
                'entry_kind': critical_node_entry_kind(method_def, first_framework_entry.get('edge_kind')),
                'framework_adapter': first_framework_entry.get('adapter'),
            }
    elif is_system_code_touched(method_def, type_metadata):
        critical_node = {
            'type': 'system_code_touched',
            'entry_scope': 'business',
            'method': critical_node_method_label(method_def),
            'file': method_def.file,
            'line': method_def.line,
            'entry_kind': critical_node_entry_kind(method_def),
        }
    elif (
        getattr(method_def, 'owner_type', '') != 'business'
        and not getattr(method_def, 'annotations', None)
        and not getattr(method_def, 'class_annotations', None)
        and not (type_metadata or {}).get(getattr(method_def, 'class_fqcn', '') or '')
    ):
        # Most runtime dependency methods have no source/type metadata in the analysis graph.
        # In that case the framework-boundary rules below cannot produce a positive result:
        # they only inspect annotations and class metadata. Returning None here preserves
        # semantics while avoiding hundreds of thousands of empty metadata checks.
        critical_node = None
        _perf_add(graph, 'trace', 'critical_node_fast_none', 1)
    elif is_framework_boundary(method_def, type_metadata):
        critical_node = {
            'type': 'framework_boundary',
            'method': critical_node_method_label(method_def),
            'reason': '动态代理或框架注入'
        }
    cache[symbol_id] = critical_node
    _perf_max(graph, 'trace', 'critical_node_cache_size', len(cache))
    return critical_node


def get_cached_overload_signatures(api_name, reverse_edges, trace_cache=None):
    api_name = (api_name or '').strip()
    if not api_name:
        return set()
    trace_cache = ensure_trace_cache(trace_cache)
    overload_cache = trace_cache['overload_signatures']
    reverse_edges_owner = id(reverse_edges)
    if (
        trace_cache.get('overload_signature_index') is None
        or trace_cache.get('overload_signature_index_owner') != reverse_edges_owner
    ):
        trace_cache['overload_signature_index'] = build_overload_signature_index(reverse_edges)
        trace_cache['overload_signature_index_owner'] = reverse_edges_owner
    if api_name not in overload_cache:
        overload_cache[api_name] = set(
            (trace_cache.get('overload_signature_index') or {}).get(api_name, set())
        )
    return overload_cache[api_name]


def flatten_key_groups(key_groups):
    keys = []
    for group in key_groups or []:
        extend_unique(keys, group.get('keys', []))
    return keys


def stable_edge_sort_key(edge):
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


def stable_candidate_tiebreak_key(candidate):
    path = candidate.get('path') or []
    path_fingerprint = tuple(
        (
            str(getattr(edge, 'caller_qualified_key', '') or ''),
            str(getattr(edge, 'callee_key', '') or ''),
            str(getattr(edge, 'file', '') or ''),
            int(getattr(edge, 'line', 0) or 0),
        )
        for edge in path
    )
    boundary_reason = str(((candidate.get('boundary') or {}).get('reason')) or '')
    return (
        str(candidate.get('reason', '') or ''),
        str(candidate.get('final_target', '') or ''),
        str(candidate.get('provenance', '') or ''),
        str(candidate.get('provenance_family', '') or ''),
        path_fingerprint,
        boundary_reason,
    )


def select_best_candidate(candidates):
    return max(
        candidates,
        key=lambda candidate: (
            candidate.get('confidence', 0.0),
            -provenance_rank(candidate.get('provenance', '')),
            -candidate.get('cost', 0),
            -candidate.get('depth', 0),
            stable_candidate_tiebreak_key(candidate),
        ),
    )


def changed_api_display_target(result):
    api_name = str(getattr(result, 'api_name', '') or '').strip()
    api_signature = str(getattr(result, 'api_signature', '') or '').strip()
    symbol_kind = str(getattr(result, 'symbol_kind', '') or '').strip()
    if api_name and symbol_kind in {'method', 'constructor'} and api_signature:
        return f"{api_name}{api_signature}"
    return api_name


def build_all_candidate_path_details(reachable, uncertain, not_analyzed, graph, final_target=''):
    details = []
    groups = (
        ('reachable', 'SYSTEM_CODE_REACHED', reachable or []),
        ('uncertain', '', uncertain or []),
        ('not_analyzed', '', not_analyzed or []),
    )
    seen = set()
    for path_status, default_reason, candidates in groups:
        for candidate in candidates:
            path_edges = list(candidate.get('path') or [])
            evidence = [edge_to_evidence(edge, graph=graph) for edge in path_edges]
            entry = dict(candidate.get('entry_point') or candidate.get('boundary') or {})
            entry_scope = str(entry.get('entry_scope') or '')
            stop_reason = str(candidate.get('reason') or default_reason)
            display_target = final_target or entry.get('method') or stop_reason or '未找到业务入口'
            path_text = format_call_chain(path_edges, display_target) if path_edges else display_target
            identity = (
                path_status,
                stop_reason,
                tuple(
                    (item.get('caller_symbol'), item.get('callee_key'), item.get('evidence_type'))
                    for item in evidence
                ),
            )
            if identity in seen:
                continue
            seen.add(identity)
            first = evidence[0] if evidence else {}
            last = evidence[-1] if evidence else {}
            consumer_symbol = str(first.get('caller_symbol') or '')
            consumer_class, consumer_method = split_consumer_symbol(consumer_symbol)
            business_reachable = path_status == 'reachable' and entry_scope != 'runtime_dependency_entry'
            business_entry = str(entry.get('method') or '') if business_reachable else ''
            effective_stop_reason = stop_reason
            if path_status == 'reachable' and entry_scope == 'runtime_dependency_entry':
                effective_stop_reason = 'RUNTIME_DEPENDENCY_ENTRY_REACHED'
            details.append({
                'path_status': path_status,
                'stop_reason': effective_stop_reason,
                'business_entry': business_entry,
                'business_reachable': business_reachable,
                'entry_kind': str(entry.get('entry_kind') or ''),
                'consumer_coord': str(first.get('owner_coord') or ''),
                'consumer_class': consumer_class,
                'consumer_method': consumer_method,
                'consumer_signature': '',
                'path_text': path_text,
                'confidence': float(candidate.get('confidence') or 0.0),
                'depth': int(candidate.get('depth') or len(path_edges)),
                'evidence': evidence,
                'terminal_symbol': last.get('caller_symbol') or business_entry,
            })
    return sorted(details, key=lambda item: (
        {'reachable': 0, 'uncertain': 1, 'not_analyzed': 2}.get(item.get('path_status'), 9),
        item.get('path_text') or '',
    ))


def split_consumer_symbol(symbol):
    value = str(symbol or '').strip()
    if not value:
        return '', ''
    head = value.split('(', 1)[0]
    if '.' not in head:
        return head, ''
    owner, member = head.rsplit('.', 1)
    return owner, member


def has_external_direct_consumer(target_coord, candidate):
    path_edges = candidate.get('path') or []
    if not path_edges:
        return False
    direct_edge = path_edges[0]
    owner_type = getattr(direct_edge, 'owner_type', '')
    owner_coord = getattr(direct_edge, 'owner_coord', '')
    if owner_type == 'business' or owner_coord == 'BUSINESS':
        return True
    target_coord = (target_coord or '').strip()
    owner_coord = (owner_coord or '').strip()
    return bool(owner_coord) and bool(target_coord) and owner_coord != target_coord


def has_verified_final_artifact_business_path(candidate):
    path_edges = list(candidate.get('path') or [])
    if not path_edges:
        return False
    has_business_edge = False
    for edge in path_edges:
        runtime_hit = _inspectable_runtime_analyzer_hit(edge)
        framework_edge = bool(
            getattr(edge, 'framework_registration', False)
            or getattr(edge, 'semantic', False)
        )
        framework_verified = (
            _verified_composite_framework_projection(edge)
            if framework_edge else False
        )
        final_artifact_edge = (
            str(getattr(edge, 'evidence_source', '') or '') == 'current_final_artifact'
        )
        if not runtime_hit and not final_artifact_edge and not framework_verified:
            return False
        if (
            str(getattr(edge, 'owner_type', '') or '') == 'business'
            and (
                final_artifact_edge
                or framework_verified
                or str((runtime_hit or {}).get('coord') or '') == '__business__'
            )
        ):
            has_business_edge = True
    return has_business_edge


def has_verified_final_artifact_framework_path(candidate):
    path_edges = list(candidate.get('path') or [])
    if not path_edges:
        return False
    has_business_edge = False
    has_framework_edge = False
    for edge in path_edges:
        runtime_hit = _inspectable_runtime_analyzer_hit(edge)
        framework_edge = bool(
            getattr(edge, 'framework_registration', False)
            or getattr(edge, 'semantic', False)
        )
        framework_verified = (
            _verified_composite_framework_projection(edge)
            if framework_edge else False
        )
        final_artifact_edge = (
            str(getattr(edge, 'evidence_source', '') or '') == 'current_final_artifact'
        )
        if not runtime_hit and not final_artifact_edge and not framework_verified:
            return False
        if framework_edge:
            if not framework_verified:
                return False
            has_framework_edge = True
        if (
            str(getattr(edge, 'owner_type', '') or '') == 'business'
            and (
                final_artifact_edge
                or framework_verified
                or str((runtime_hit or {}).get('coord') or '') == '__business__'
            )
        ):
            has_business_edge = True
    return has_business_edge and has_framework_edge


def _has_verified_final_artifact_framework_target(api_row, graph):
    api_name = str((api_row or {}).get('api_name') or '').strip()
    target_signature = normalize_signature_for_lookup(
        str((api_row or {}).get('api_signature') or '').strip()
    )
    if not api_name or target_signature is None:
        return False
    for key, edges in (getattr(graph, 'reverse_edges', {}) or {}).items():
        key = str(key or '')
        if not key.startswith(api_name):
            continue
        signature = extract_signature_suffix_from_key(key)
        if normalize_signature_for_lookup(signature) != target_signature:
            continue
        if any(
            _verified_composite_framework_projection(edge)
            for edge in (edges or [])
        ):
            return True
    return False


def select_confirmable_reachable_candidate(result, candidates):
    safe_candidates = []
    fallback_only_candidates = []
    internal_only_candidates = []
    internal_only_precise_candidates = []

    for candidate in candidates or []:
        provenance = (candidate.get('provenance') or '').strip()
        if provenance == 'fallback_simple':
            fallback_only_candidates.append(candidate)
            continue
        if has_verified_final_artifact_business_path(candidate):
            safe_candidates.append(candidate)
            continue
        if not has_external_direct_consumer(result.coord, candidate):
            if provenance in {'exact_signature', 'compatible_signature', 'polymorphic'}:
                internal_only_precise_candidates.append(candidate)
                continue
            internal_only_candidates.append(candidate)
            continue
        safe_candidates.append(candidate)

    if safe_candidates:
        return select_best_candidate(safe_candidates), None, ''
    if internal_only_precise_candidates:
        return select_best_candidate(internal_only_precise_candidates), None, ''
    if internal_only_candidates:
        return None, select_best_candidate(internal_only_candidates), 'INTERNAL_ONLY_DIRECT_CONSUMER'
    if fallback_only_candidates:
        return None, select_best_candidate(fallback_only_candidates), 'FALLBACK_SIMPLE_PATH_UNCONFIRMED'
    return None, None, ''


def extract_signature_suffix_from_key(key):
    key = (key or '').strip()
    if '(' in key and key.endswith(')'):
        return key[key.index('('):]
    return ''


PRIMITIVE_TYPES = {
    'byte', 'short', 'int', 'long', 'float', 'double', 'boolean', 'char',
}

JAVA_BUILTIN_SUPERTYPES = {
    'java.lang.String': {
        'java.lang.CharSequence',
        'java.lang.Comparable',
        'java.io.Serializable',
        'java.lang.Object',
    },
    'java.lang.StringBuilder': {
        'java.lang.CharSequence',
        'java.lang.Appendable',
        'java.io.Serializable',
        'java.lang.Object',
    },
    'java.lang.StringBuffer': {
        'java.lang.CharSequence',
        'java.lang.Appendable',
        'java.io.Serializable',
        'java.lang.Object',
    },
    'java.util.Map': {
        'java.lang.Object',
    },
    'java.util.concurrent.ConcurrentMap': {
        'java.util.Map',
        'java.lang.Object',
    },
    'java.util.SortedMap': {
        'java.util.Map',
        'java.lang.Object',
    },
    'java.util.NavigableMap': {
        'java.util.SortedMap',
        'java.util.Map',
        'java.lang.Object',
    },
    'java.util.concurrent.ConcurrentNavigableMap': {
        'java.util.concurrent.ConcurrentMap',
        'java.util.NavigableMap',
        'java.util.SortedMap',
        'java.util.Map',
        'java.lang.Object',
    },
    'java.util.concurrent.ConcurrentHashMap': {
        'java.util.concurrent.ConcurrentMap',
        'java.util.Map',
        'java.lang.Object',
    },
    'java.util.HashMap': {
        'java.util.Map',
        'java.lang.Object',
    },
    'java.util.LinkedHashMap': {
        'java.util.HashMap',
        'java.util.Map',
        'java.lang.Object',
    },
    'java.util.TreeMap': {
        'java.util.Map',
        'java.lang.Object',
    },
    'java.util.Collection': {
        'java.lang.Object',
    },
    'java.util.List': {
        'java.util.Collection',
        'java.lang.Iterable',
        'java.lang.Object',
    },
    'java.util.Set': {
        'java.util.Collection',
        'java.lang.Iterable',
        'java.lang.Object',
    },
    'java.util.ArrayList': {
        'java.util.List',
        'java.util.Collection',
        'java.lang.Iterable',
        'java.lang.Object',
    },
    'java.util.HashSet': {
        'java.util.Set',
        'java.util.Collection',
        'java.lang.Iterable',
        'java.lang.Object',
    },
}

JAVA_BUILTIN_SIMPLE_TO_FQCN = {
    fqcn.rsplit('.', 1)[-1]: fqcn
    for fqcn in JAVA_BUILTIN_SUPERTYPES
}
JAVA_BUILTIN_SIMPLE_TO_FQCN.update({
    'Object': 'java.lang.Object',
    'CharSequence': 'java.lang.CharSequence',
    'Comparable': 'java.lang.Comparable',
    'Appendable': 'java.lang.Appendable',
    'Serializable': 'java.io.Serializable',
    'Iterable': 'java.lang.Iterable',
})


def strip_generic_content(type_name):
    type_name = (type_name or '').strip()
    if not type_name:
        return ''

    chars = []
    generic_depth = 0
    for ch in type_name:
        if ch == '<':
            generic_depth += 1
            continue
        if ch == '>':
            if generic_depth <= 0:
                return ''
            generic_depth -= 1
            continue
        if generic_depth == 0:
            chars.append(ch)

    if generic_depth != 0:
        return ''

    return ''.join(chars).strip()


def normalize_type_reference(type_name, keep_fqcn=True):
    type_name = (type_name or '').strip()
    if not type_name:
        return ''
    type_name = type_name.replace('...', '[]')
    type_name = strip_generic_content(type_name)
    if not type_name or type_name == '?':
        return ''
    if not keep_fqcn and '.' in type_name:
        type_name = type_name.rsplit('.', 1)[-1]
    return type_name


def split_array_suffix(type_name):
    type_name = (type_name or '').strip()
    dimensions = 0
    while type_name.endswith('[]'):
        dimensions += 1
        type_name = type_name[:-2].strip()
    return type_name, dimensions


def canonical_builtin_type_name(type_name):
    type_name = (type_name or '').strip()
    if not type_name:
        return ''
    if type_name in JAVA_BUILTIN_SIMPLE_TO_FQCN:
        return JAVA_BUILTIN_SIMPLE_TO_FQCN[type_name]
    return type_name


def builtin_supertypes_for(type_name):
    canonical = canonical_builtin_type_name(type_name)
    if not canonical:
        return set()
    simple = canonical.rsplit('.', 1)[-1]
    supertypes = {canonical, simple}
    for parent in JAVA_BUILTIN_SUPERTYPES.get(canonical, set()):
        supertypes.add(parent)
        supertypes.add(parent.rsplit('.', 1)[-1])
    return supertypes


def is_probable_type_reference(type_name):
    normalized = normalize_type_reference(type_name, keep_fqcn=True)
    if not normalized:
        return False
    base_name, _ = split_array_suffix(normalized)
    if base_name in PRIMITIVE_TYPES:
        return True
    simple_name = base_name.rsplit('.', 1)[-1]
    return bool(simple_name and (simple_name[0].isupper() or simple_name == '?'))


def is_valid_signature_suffix(signature):
    params = split_signature_params(signature)
    if params is None:
        return False
    return all(is_probable_type_reference(param) for param in params)


def collect_overload_signatures(api_name, reverse_edges):
    return set(build_overload_signature_index(reverse_edges).get((api_name or '').strip(), set()))


def build_overload_signature_index(reverse_edges):
    index = {}
    for key in (reverse_edges or {}).keys():
        if not isinstance(key, str):
            continue
        if '(' not in key or not key.endswith(')'):
            continue
        base_key = key.split('(', 1)[0].strip()
        if not base_key:
            continue
        signature = extract_signature_suffix_from_key(key)
        if signature and is_valid_signature_suffix(signature):
            index.setdefault(base_key, set()).add(signature)
    return index


def resolve_type_candidates(type_name, type_metadata):
    normalized = normalize_type_reference(type_name, keep_fqcn=True)
    if not normalized:
        return set()

    base_name, dimensions = split_array_suffix(normalized)
    suffix = '[]' * dimensions
    if base_name in PRIMITIVE_TYPES:
        return {base_name + suffix}

    resolved = set()
    if base_name in (type_metadata or {}):
        resolved.add(base_name + suffix)

    simple_name = base_name.rsplit('.', 1)[-1]
    for known_type in (type_metadata or {}).keys():
        if known_type.rsplit('.', 1)[-1] == simple_name:
            resolved.add(known_type + suffix)

    if resolved:
        return resolved
    return {base_name + suffix}


def collect_all_supertypes(type_name, type_metadata, visited=None):
    type_name = (type_name or '').strip()
    if not type_name:
        return set()
    if visited is None:
        visited = set()
    if type_name in visited:
        return set()

    visited.add(type_name)
    supertypes = {type_name}
    class_meta = (type_metadata or {}).get(type_name, {})
    for parent in (class_meta.get('extends') or []) + (class_meta.get('implements') or []):
        if not parent:
            continue
        supertypes.update(collect_all_supertypes(parent, type_metadata, visited))
    return supertypes


def is_candidate_param_compatible_with_target(candidate_type, target_type, type_metadata):
    candidate_normalized = normalize_type_reference(candidate_type, keep_fqcn=True)
    target_normalized = normalize_type_reference(target_type, keep_fqcn=True)
    if not candidate_normalized or not target_normalized:
        return False

    candidate_base, candidate_dims = split_array_suffix(candidate_normalized)
    target_base, target_dims = split_array_suffix(target_normalized)
    if candidate_dims != target_dims:
        return False

    if candidate_base == target_base:
        return True

    candidate_simple = candidate_base.rsplit('.', 1)[-1]
    target_simple = target_base.rsplit('.', 1)[-1]
    if candidate_simple == target_simple:
        return True

    if target_simple == 'Object':
        return True

    if candidate_base in PRIMITIVE_TYPES or target_base in PRIMITIVE_TYPES:
        return False

    builtin_candidate_supertypes = builtin_supertypes_for(candidate_base)
    if target_base in builtin_candidate_supertypes or target_simple in builtin_candidate_supertypes:
        return True

    target_candidates = resolve_type_candidates(target_base, type_metadata)
    candidate_candidates = resolve_type_candidates(candidate_base, type_metadata)
    for candidate_name in candidate_candidates:
        candidate_root, _ = split_array_suffix(candidate_name)
        supertypes = collect_all_supertypes(candidate_root, type_metadata)
        super_simple_names = {item.rsplit('.', 1)[-1] for item in supertypes}
        for target_name in target_candidates:
            target_root, _ = split_array_suffix(target_name)
            if target_root in supertypes or target_root.rsplit('.', 1)[-1] in super_simple_names:
                return True
    return False


def is_varargs_type_reference(type_name):
    return str(type_name or '').strip().endswith('...')


def varargs_element_type(type_name):
    normalized = str(type_name or '').strip()
    if normalized.endswith('...'):
        return normalized[:-3].strip()
    if normalized.endswith('[]'):
        return normalized[:-2].strip()
    return normalized


def is_candidate_signature_compatible_with_target(candidate_params, target_params, type_metadata):
    if candidate_params is None or target_params is None:
        return False
    if target_params and is_varargs_type_reference(target_params[-1]):
        fixed_target_params = target_params[:-1]
        if len(candidate_params) < len(fixed_target_params):
            return False
        fixed_candidate_params = candidate_params[:len(fixed_target_params)]
        if not all(
            is_candidate_param_compatible_with_target(candidate_type, target_type, type_metadata)
            for candidate_type, target_type in zip(fixed_candidate_params, fixed_target_params)
        ):
            return False

        remaining_candidate_params = candidate_params[len(fixed_target_params):]
        if not remaining_candidate_params:
            return True

        target_vararg = target_params[-1]
        target_array = target_vararg.replace('...', '[]')
        target_element = varargs_element_type(target_vararg)
        if len(remaining_candidate_params) == 1 and is_candidate_param_compatible_with_target(
            remaining_candidate_params[0],
            target_array,
            type_metadata,
        ):
            return True

        return all(
            is_candidate_param_compatible_with_target(candidate_type, target_element, type_metadata)
            for candidate_type in remaining_candidate_params
        )

    if len(candidate_params) == len(target_params):
        return all(
            is_candidate_param_compatible_with_target(candidate_type, target_type, type_metadata)
            for candidate_type, target_type in zip(candidate_params, target_params)
        )
    return False


def select_compatible_overload_signatures(target_signature, overload_signatures, type_metadata):
    target_params = split_signature_params(target_signature)
    if target_params is None:
        return []

    compatible = []
    for signature in overload_signatures or []:
        candidate_params = split_signature_params(signature)
        if candidate_params is None:
            continue
        if is_candidate_signature_compatible_with_target(candidate_params, target_params, type_metadata):
            compatible.append(signature)
    return compatible


def exclude_signatures_owned_by_sibling_overloads(
    api_name,
    target_signature,
    compatible_signatures,
    graph,
    type_metadata=None,
):
    """Do not assign a call-site signature to the wrong overload.

    Source edges may describe argument types rather than the selected JVM method
    descriptor.  That is useful for resolving a lone varargs/general overload, but
    it becomes unsafe when the same declaration family contains a more specific
    sibling with exactly that signature.  Java overload resolution selects the
    sibling in that case (for example Logger.info(String, Object) must not prove
    Logger.info(String, Object...)).
    """
    overload_index = getattr(graph, 'changed_api_overload_signatures', {}) or {}
    declared_targets = set(overload_index.get((api_name or '').strip()) or set())
    if not declared_targets:
        return list(compatible_signatures or [])

    target_normalized = normalize_signature_for_lookup(target_signature) or target_signature
    sibling_signatures = {
        signature
        for signature in declared_targets
        if (normalize_signature_for_lookup(signature) or signature) != target_normalized
    }
    target_params = split_signature_params(target_signature)
    target_is_varargs = bool(target_params and is_varargs_type_reference(target_params[-1]))
    retained = []
    for signature in compatible_signatures or []:
        candidate_normalized = normalize_signature_for_lookup(signature) or signature
        if any(
            candidate_normalized == (normalize_signature_for_lookup(sibling) or sibling)
            for sibling in sibling_signatures
        ):
            continue
        # Java considers applicable fixed-arity overloads before a varargs
        # declaration. A source call inferred as (String, String), for example,
        # selects info(String, Object) rather than info(String, Object...).
        if target_is_varargs:
            candidate_params = split_signature_params(signature)
            fixed_sibling_applies = False
            for sibling in sibling_signatures:
                sibling_params = split_signature_params(sibling)
                if sibling_params is None or any(is_varargs_type_reference(item) for item in sibling_params):
                    continue
                if is_candidate_signature_compatible_with_target(
                    candidate_params,
                    sibling_params,
                    type_metadata or {},
                ):
                    fixed_sibling_applies = True
                    break
            if fixed_sibling_applies:
                continue
        retained.append(signature)
    return retained


def build_declared_method_signature_index(graph):
    index = defaultdict(set)
    methods_by_id = getattr(graph, 'methods_by_id', {}) or {}
    for method_def in methods_by_id.values():
        qualified_key = getattr(method_def, 'qualified_key', '')
        if not qualified_key:
            continue
        for signature in build_method_signature_suffixes(method_def):
            if signature:
                index[qualified_key].add(signature)
    return index


def collect_declared_method_signatures(api_name, graph, trace_cache=None):
    api_name = (api_name or '').strip()
    if not api_name:
        return set()
    trace_cache = ensure_trace_cache(trace_cache)
    methods_by_id = getattr(graph, 'methods_by_id', {}) or {}
    owner = id(methods_by_id)
    if (
        trace_cache.get('declared_method_signature_index') is None
        or trace_cache.get('declared_method_signature_index_owner') != owner
    ):
        started_at = time.perf_counter()
        trace_cache['declared_method_signature_index'] = build_declared_method_signature_index(graph)
        trace_cache['declared_method_signature_index_owner'] = owner
        _perf_add(graph, 'trace', 'declared_signature_index_builds', 1)
        _perf_add(graph, 'trace', 'declared_signature_index_elapsed_sec', time.perf_counter() - started_at)
        _perf_max(
            graph,
            'trace',
            'declared_signature_index_size',
            len(trace_cache.get('declared_method_signature_index') or {}),
        )
    index = trace_cache.get('declared_method_signature_index') or {}
    return set(index.get(api_name) or set())


def filter_target_match_groups_for_overload_safety(api_row, matched_groups, graph, type_metadata=None, trace_cache=None):
    if not method_api_requires_signature(api_row) or not has_precise_api_signature(api_row):
        return matched_groups, None

    api_name = (api_row.get('api_name') or '').strip()
    if not api_name:
        return matched_groups, None

    symbol_kind = get_symbol_kind(api_row)
    direct_overload_block = None
    target_signature = api_row.get('api_signature', '')
    target_params = split_signature_params(target_signature)
    target_is_varargs = bool(target_params and is_varargs_type_reference(target_params[-1]))
    declared_signatures = collect_declared_method_signatures(api_name, graph, trace_cache=trace_cache)
    has_exact_signature_match = any(
        group.get('provenance') == 'exact_signature'
        for group in (matched_groups or [])
    )
    allow_multiple_observed_compatible = False
    declared_compatible_signatures = []
    if declared_signatures:
        declared_compatible_signatures = select_compatible_overload_signatures(
            target_signature,
            declared_signatures,
            type_metadata or {},
        )
        declared_compatible_signatures = exclude_signatures_owned_by_sibling_overloads(
            api_name,
            target_signature,
            declared_compatible_signatures,
            graph,
            type_metadata=type_metadata,
        )
        if len(declared_compatible_signatures) == 1:
            allow_multiple_observed_compatible = True

    overload_signatures = get_cached_overload_signatures(
        api_name,
        getattr(graph, 'reverse_edges', {}) or {},
        trace_cache=trace_cache,
    )
    if (
        symbol_kind == 'constructor'
        and len(declared_signatures) > 1
        and not has_exact_signature_match
        and not overload_signatures
    ):
        return [], {
            'api_name': api_name,
            'api_signature': api_row.get('api_signature', ''),
            'overload_signatures': sorted(declared_signatures),
        }

    if overload_signatures:
        safe_groups = [
            {
                'tier_index': group.get('tier_index', -1),
                'provenance': group.get('provenance', ''),
                'provenance_family': group.get('provenance_family', ''),
                'matched_keys': list(group.get('matched_keys', []) or []),
            }
            for group in (matched_groups or [])
            if group.get('provenance') == 'exact_signature'
        ]
        if safe_groups:
            if len(declared_signatures) == 1 and len(declared_compatible_signatures) == 1:
                for group in matched_groups or []:
                    if group.get('provenance') != 'exact_name':
                        continue
                    for matched_key in group.get('matched_keys', []) or []:
                        if matched_key == api_name and (getattr(graph, 'reverse_edges', {}) or {}).get(matched_key):
                            for safe_group in safe_groups:
                                append_unique(safe_group['matched_keys'], matched_key)
            compatible_signatures = select_compatible_overload_signatures(
                target_signature,
                overload_signatures,
                type_metadata or {},
            )
            compatible_signatures = exclude_signatures_owned_by_sibling_overloads(
                api_name,
                target_signature,
                compatible_signatures,
                graph,
                type_metadata=type_metadata,
            )
            for compatible_signature in compatible_signatures:
                compatible_key = f"{api_name}{compatible_signature}"
                if (getattr(graph, 'reverse_edges', {}) or {}).get(compatible_key):
                    for group in safe_groups:
                        append_unique(group['matched_keys'], compatible_key)
            return safe_groups, None

        compatible_signatures = select_compatible_overload_signatures(
            target_signature,
            overload_signatures,
            type_metadata or {},
        )
        compatible_signatures = exclude_signatures_owned_by_sibling_overloads(
            api_name,
            target_signature,
            compatible_signatures,
            graph,
            type_metadata=type_metadata,
        )
        if target_is_varargs and compatible_signatures:
            compatible_keys = [
                f"{api_name}{compatible_signature}"
                for compatible_signature in compatible_signatures
                if (getattr(graph, 'reverse_edges', {}) or {}).get(f"{api_name}{compatible_signature}")
            ]
            if compatible_keys:
                return [
                    {
                        'tier_index': 0,
                        'provenance': 'compatible_signature',
                        'provenance_family': 'exact_signature',
                        'matched_keys': compatible_keys,
                    }
                ], None
        if len(compatible_signatures) == 1:
            compatible_key = f"{api_name}{compatible_signatures[0]}"
            if (getattr(graph, 'reverse_edges', {}) or {}).get(compatible_key):
                return [
                    {
                        'tier_index': 0,
                        'provenance': 'compatible_signature',
                        'provenance_family': 'exact_signature',
                        'matched_keys': [compatible_key],
                    }
                ], None

        # Even if the graph only observed one overload signature, exact_name remains unsafe
        # when that signature is not the requested target. This commonly happens for
        # constructors where reverse_edges contains `Type.Type` plus a sibling overload like
        # `Type.Type(String)`, but the removed target is `Type.Type(String, HttpStatus)`.
        direct_overload_block = {
            'api_name': api_name,
            'api_signature': api_row.get('api_signature', ''),
            'overload_signatures': sorted(overload_signatures),
        }

    resolved_groups, descendant_overload_block = resolve_target_matched_groups_for_overload_safety(
        matched_groups,
        target_signature,
        graph,
        type_metadata=type_metadata,
        trace_cache=trace_cache,
        allow_multiple_compatible=allow_multiple_observed_compatible,
    )
    if resolved_groups:
        return resolved_groups, None
    if descendant_overload_block:
        return [], descendant_overload_block
    if direct_overload_block:
        return [], direct_overload_block
    return matched_groups, None


def build_overload_ambiguous_result(result, overload_info):
    overload_signatures = overload_info.get('overload_signatures') or []
    overload_text = ', '.join(overload_signatures[:5])
    note = (
        '目标 API 存在重载，当前仅命中了无签名回退键，'
        f'无法安全确认是否是目标签名 {overload_info.get("api_signature")}'
        + (f'；已知重载：{overload_text}' if overload_text else '')
    )
    _apply_blocking_failure(
        result, 'overload-resolution', 'OVERLOAD_AMBIGUOUS_TARGET', note,
    )
    result.verification_commands = [
        '优先补全/保留精确 api_signature，并确认调用点参数类型推断成功',
        '若仍无法命中精确签名，请人工复核重载方法的真实调用点',
    ]
    return result


def resolve_target_matched_groups_for_overload_safety(
    matched_groups,
    target_signature,
    graph,
    type_metadata=None,
    trace_cache=None,
    allow_multiple_compatible=False,
):
    reverse_edges = getattr(graph, 'reverse_edges', {}) or {}
    safe_groups = []
    ambiguous_keys = []

    for group in matched_groups or []:
        resolved_keys = []
        for key in group.get('matched_keys', []) or []:
            signature = extract_signature_suffix_from_key(key)
            if signature:
                append_unique(resolved_keys, key)
                continue

            overload_signatures = get_cached_overload_signatures(
                key,
                reverse_edges,
                trace_cache=trace_cache,
            )
            if not overload_signatures:
                append_unique(resolved_keys, key)
                continue

            compatible_signatures = select_compatible_overload_signatures(
                target_signature,
                overload_signatures,
                type_metadata or {},
            )
            if allow_multiple_compatible and compatible_signatures:
                for compatible_signature in compatible_signatures:
                    compatible_key = f"{key}{compatible_signature}"
                    if reverse_edges.get(compatible_key):
                        append_unique(resolved_keys, compatible_key)
                if resolved_keys:
                    continue
            if len(compatible_signatures) == 1:
                compatible_key = f"{key}{compatible_signatures[0]}"
                if reverse_edges.get(compatible_key):
                    append_unique(resolved_keys, compatible_key)
                    continue

            ambiguous_keys.append(
                {
                    'api_name': key,
                    'overload_signatures': sorted(overload_signatures),
                }
            )

        if resolved_keys:
            safe_groups.append(
                {
                    'tier_index': group.get('tier_index', -1),
                    'provenance': group.get('provenance', ''),
                    'provenance_family': group.get('provenance_family', ''),
                    'matched_keys': resolved_keys,
                }
            )

    if safe_groups:
        return safe_groups, None
    if ambiguous_keys:
        return [], {
            'api_name': ambiguous_keys[0].get('api_name', ''),
            'api_signature': target_signature,
            'overload_signatures': ambiguous_keys[0].get('overload_signatures', []),
        }
    return [], None


def signature_suffix_set_from_method(method_def):
    return {
        sig for sig in build_method_signature_suffixes(method_def)
        if (sig or '').strip()
    }


def filter_matched_keys_by_signatures(matched_keys, allowed_signatures):
    filtered = []
    for key in matched_keys or []:
        signature = extract_signature_suffix_from_key(key)
        if signature and signature in allowed_signatures:
            append_unique(filtered, key)
    return filtered


def filter_method_lookup_groups_for_overload_safety(method_def, matched_groups, graph, trace_cache=None):
    allowed_signatures = signature_suffix_set_from_method(method_def)
    if not allowed_signatures:
        return matched_groups, None

    reverse_edges = getattr(graph, 'reverse_edges', {}) or {}
    overload_signatures = get_cached_overload_signatures(
        method_def.qualified_key,
        reverse_edges,
        trace_cache=trace_cache,
    )
    simple_overload_signatures = get_cached_overload_signatures(
        method_def.simple_key,
        reverse_edges,
        trace_cache=trace_cache,
    )
    combined_overload_signatures = sorted(
        set(overload_signatures or []).union(simple_overload_signatures or [])
    )
    if len(combined_overload_signatures) <= 1:
        return matched_groups, None

    safe_groups = []
    for group in matched_groups or []:
        filtered_keys = filter_matched_keys_by_signatures(
            group.get('matched_keys', []),
            allowed_signatures,
        )
        if filtered_keys:
            safe_groups.append({
                'tier_index': group.get('tier_index', -1),
                'provenance': group.get('provenance', ''),
                'provenance_family': group.get('provenance_family', ''),
                'matched_keys': filtered_keys,
            })

    if safe_groups:
        return safe_groups, None

    overload_block = {
        'method': critical_node_method_label(method_def),
        'expected_signatures': sorted(allowed_signatures),
        'overload_signatures': combined_overload_signatures,
    }
    _step5_debug(
        'overload_intermediate_block',
        'intermediate method blocked because only unsigned matches survived',
        method=method_def.qualified_key,
        expected_signatures=sorted(allowed_signatures),
        overload_signatures=combined_overload_signatures,
        matched_groups=matched_groups,
    )
    _step5_debug_break(
        'overload_intermediate_block',
        method=method_def.qualified_key,
        expected_signatures=sorted(allowed_signatures),
        overload_signatures=combined_overload_signatures,
        matched_groups=matched_groups,
    )
    return [], overload_block


def build_intermediate_overload_reason(method_def, overload_info):
    expected_text = ', '.join(overload_info.get('expected_signatures') or [])
    overload_text = ', '.join(overload_info.get('overload_signatures') or [])
    return (
        f"中间方法 {method_def.qualified_key} 存在重载，当前只命中了无签名回退键；"
        f"期望签名：{expected_text or 'unknown'}；"
        f"已知重载：{overload_text or 'unknown'}"
    )


def get_cached_method_lookup_resolution(method_def, type_metadata, graph, trace_cache=None):
    trace_cache = ensure_trace_cache(trace_cache)
    cache_key = (
        getattr(method_def, 'symbol_id', ''),
        getattr(method_def, 'qualified_key', ''),
        tuple(build_method_signature_suffixes(method_def)),
    )
    lookup_cache = trace_cache['method_lookup_resolution']
    cached = lookup_cache.get(cache_key)
    if cached is not None:
        return cached

    lookup_key_groups = build_method_lookup_key_groups(method_def, type_metadata, graph=graph)
    matched_lookup_groups = select_matching_key_groups(lookup_key_groups, getattr(graph, 'reverse_edges', {}) or {})
    # Accuracy guard: never expand the main Step5 trace through method-name-only
    # fallback keys.  A path such as A -> method:send -> B.send is exactly the
    # class of false positive that can stitch unrelated implementations or
    # unpackaged source modules into a business impact chain.  If the caller
    # cannot be resolved by FQCN/signature/polymorphic evidence, the static
    # trace must stop instead of inventing a chain from a simple method name.
    matched_lookup_groups = [
        group for group in matched_lookup_groups
        if group.get('provenance') != 'fallback_simple'
    ]
    if not matched_lookup_groups:
        _step5_debug(
            'method_lookup_resolution',
            'no precise lookup groups matched reverse edges',
            method=method_def.qualified_key,
            lookup_key_groups=lookup_key_groups,
        )
    resolved = filter_method_lookup_groups_for_overload_safety(
        method_def,
        matched_lookup_groups,
        graph,
        trace_cache=trace_cache,
    )
    lookup_cache[cache_key] = resolved
    return resolved


def assess_graph_completeness(graph_stats, api_row=None):
    graph_stats = graph_stats or {}
    reasons = []
    verification = []
    reason_codes = []

    if graph_stats.get('truncated'):
        truncation_reasons = graph_stats.get('truncation_reasons') or []
        reason_text = '图构建被截断'
        if truncation_reasons:
            reason_text = f"{reason_text}（{', '.join(truncation_reasons)}）"
        reasons.append(reason_text)
        verification.append('提高 max_methods 或缩小分析范围后重跑 Step 5')

    parser_fallback_reasons = parser_fallback_reasons_relevant_to_api(graph_stats, api_row)
    if parser_fallback_reasons:
        parser_items = ', '.join(
            f"{key}={value}" for key, value in sorted(parser_fallback_reasons.items())
        )
        reasons.append(f"部分源码使用降级解析器（{parser_items}）")
        verification.append('优先修复 tree-sitter/语法兼容问题，减少 regex 降级文件')

    edge_cap_hits = int(graph_stats.get('edge_cap_hits') or 0)
    if edge_cap_hits > 0:
        reasons.append(f"反向边索引命中过载保护（edge_cap_hits={edge_cap_hits}）")
        verification.append('检查热点调用点，必要时提升边上限或拆分分析范围')

    business_bytecode = graph_stats.get('business_bytecode') or {}
    if business_bytecode.get('status') in {'partial', 'insufficient'}:
        business_reason_codes = list(
            business_bytecode.get('reason_codes')
            or business_bytecode.get('failures')
            or ['BUSINESS_BYTECODE_INCOMPLETE']
        )
        for reason_code in business_reason_codes:
            if reason_code not in reason_codes:
                reason_codes.append(reason_code)
        reasons.append(
            '业务字节码证据不完整（'
            + ', '.join(business_reason_codes)
            + '）'
        )
        verification.append('修复业务制品字节码采集或调用方解析失败后重跑 Step 5')

    return {
        'incomplete': bool(reasons),
        'reasons': reasons,
        'reason_codes': reason_codes,
        'verification_commands': verification,
    }


def build_analysis_incomplete_result(result, graph_completeness):
    reasons = graph_completeness.get('reasons') or []
    if reasons:
        note = f"分析不完整：{'；'.join(reasons)}"
    else:
        note = '分析不完整，当前无法把静态未找到解释为未影响'
    _apply_blocking_failure(
        result, 'source-graph-analysis', 'ANALYSIS_INCOMPLETE', note,
    )
    result.verification_commands = (
        graph_completeness.get('verification_commands') or []
    ) + [
        '重新运行 Step 5 后，再判断是否属于 not_found_in_static_analysis'
    ]
    return result


def build_call_graph_limited_symbol_result(result):
    symbol_kind = (result.symbol_kind or 'unknown').strip() or 'unknown'
    note = (
        '当前 Step5 主要基于方法反向调用图；'
        f'对 {symbol_kind} 符号的静态证明能力有限，'
        '当前结果不能解释为静态未找到调用路径'
    )
    _apply_blocking_failure(
        result, 'call-graph-analysis', 'CALL_GRAPH_LIMITATION_SYMBOL_KIND', note,
    )
    result.verification_commands = [
        '结合类型引用、字段访问、构造调用等非方法证据继续复核',
        '检查配置文件、注解元数据、反射调用或 SPI/回调注册',
        '必要时补充更适合该符号类型的专项静态分析或人工抽查',
    ]
    return result


def behavior_changed_requires_precise_match(api_row):
    return (
        (api_row.get('change_type') or '').strip() == 'BEHAVIOR_CHANGED'
        and method_api_requires_signature(api_row)
        and bool((api_row.get('api_name') or '').strip())
        and has_precise_api_signature(api_row)
    )


def select_behavior_changed_candidate(api_row, candidates):
    if not behavior_changed_requires_precise_match(api_row):
        return select_best_candidate(candidates), None

    strict_candidates = [
        candidate for candidate in (candidates or [])
        if candidate.get('provenance') != 'fallback_simple'
    ]
    if strict_candidates:
        return select_best_candidate(strict_candidates), None

    return None, select_best_candidate(candidates)


def build_api_target_key_tiers(api_row):
    tiers = []
    api_name = api_row.get('api_name', '').strip()
    matched_class = api_row.get('matched_class', '').strip()
    api_simple = api_row.get('api_simple', '').strip()
    api_signature = api_row.get('api_signature', '').strip()
    symbol_kind = get_symbol_kind(api_row)
    requires_signature = symbol_kind in {'method', 'constructor'}

    if api_name:
        if symbol_kind == 'class':
            append_key_tier(tiers, [f"class:{api_name}"])
        elif requires_signature:
            if api_signature:
                append_key_tier(tiers, [f"{api_name}{api_signature}"])
                normalized_signature = normalize_signature_for_lookup(api_signature)
                if normalized_signature and normalized_signature != api_signature:
                    append_key_tier(tiers, [f"{api_name}{normalized_signature}"])
            # 方法级追踪在起点上优先保留 FQCN，避免 method:{name} 过早跨类串链。
            append_key_tier(tiers, [api_name])
        else:
            append_key_tier(tiers, [api_name])
            if '.' in api_name:
                class_part = api_name.rsplit('.', 1)[0]
                append_key_tier(tiers, [f"class:{class_part}"])

    if matched_class:
        append_key_tier(tiers, [f"class:{matched_class}"])

    if api_simple:
        if requires_signature:
            # 只有缺少 FQCN 时，才允许退化到 simple key。
            if not api_name:
                if api_signature:
                    append_key_tier(tiers, [f"method:{api_simple}{api_signature}"])
                    normalized_signature = normalize_signature_for_lookup(api_signature)
                    if normalized_signature and normalized_signature != api_signature:
                        append_key_tier(tiers, [f"method:{api_simple}{normalized_signature}"])
                append_key_tier(tiers, [f"method:{api_simple}"])
        else:
            append_key_tier(tiers, [f"method:{api_simple}"])

    return tiers


def _extract_api_target_method_info(api_row):
    api_name = (api_row.get('api_name') or '').strip()
    if not api_name or '.' not in api_name:
        return '', '', []

    class_fqcn, method_name = api_name.rsplit('.', 1)
    api_signature = (api_row.get('api_signature') or '').strip()
    signature_suffixes = []
    if api_signature:
        append_unique(signature_suffixes, api_signature)
        normalized_signature = normalize_signature_for_lookup(api_signature)
        if normalized_signature and normalized_signature != api_signature:
            append_unique(signature_suffixes, normalized_signature)
    return class_fqcn, method_name, signature_suffixes


def _class_declares_matching_method(class_fqcn, method_name, signature_suffixes, graph):
    if graph is None:
        return False
    methods_by_id = getattr(graph, 'methods_by_id', {}) or {}
    for method_def in methods_by_id.values():
        if getattr(method_def, 'class_fqcn', '') != class_fqcn:
            continue
        if getattr(method_def, 'method_name', '') != method_name:
            continue
        if not signature_suffixes:
            return True
        declared_suffixes = build_method_signature_suffixes(method_def)
        if not declared_suffixes:
            return True
        if any(sig in declared_suffixes for sig in signature_suffixes):
            return True
    return False


def _append_method_lookup_values(keys_with_sig, keys_without_sig, class_fqcn, method_name, signature_suffixes):
    append_unique(keys_without_sig, f"{class_fqcn}.{method_name}")
    for sig in signature_suffixes or []:
        append_unique(keys_with_sig, f"{class_fqcn}.{method_name}{sig}")


def _collect_inherited_subclass_tiers(class_fqcn, method_name, signature_suffixes, type_metadata, graph, visited=None):
    if visited is None:
        visited = set()
    if class_fqcn in visited:
        return []
    visited.add(class_fqcn)

    class_meta = type_metadata.get(class_fqcn, {}) or {}
    tiers = []
    subclass_sig_keys = []
    subclass_name_keys = []

    for subclass in class_meta.get('subclasses', []) or []:
        if _class_declares_matching_method(subclass, method_name, signature_suffixes, graph):
            # 子类自行覆盖后，调用会落到子类实现而不是当前目标方法，停止沿这条分支下钻。
            continue
        _append_method_lookup_values(subclass_sig_keys, subclass_name_keys, subclass, method_name, signature_suffixes)
        extend_tiers(
            tiers,
            _collect_inherited_subclass_tiers(
                subclass,
                method_name,
                signature_suffixes,
                type_metadata,
                graph,
                visited=visited,
            ),
        )

    prepend = []
    append_key_tier(prepend, subclass_sig_keys)
    append_key_tier(prepend, subclass_name_keys)
    prepend.extend(tiers)
    return prepend


def _collect_unambiguous_interface_dispatch_tiers(class_fqcn, method_name, signature_suffixes, type_metadata):
    tiers = []
    sig_keys = []
    name_keys = []

    interface_candidates = []
    seen = set()

    def visit_interfaces(target_class):
        if target_class in seen:
            return
        seen.add(target_class)
        target_meta = type_metadata.get(target_class, {}) or {}
        for interface in target_meta.get('implements', []) or []:
            interface_candidates.append(interface)
            visit_interfaces(interface)
        for parent in target_meta.get('extends', []) or []:
            visit_interfaces(parent)

    visit_interfaces(class_fqcn)
    for interface in interface_candidates:
        interface_meta = type_metadata.get(interface, {}) or {}
        implementations = sorted(set(interface_meta.get('implementations', []) or []))
        if implementations != [class_fqcn]:
            continue
        _append_method_lookup_values(sig_keys, name_keys, interface, method_name, signature_suffixes)

    append_key_tier(tiers, sig_keys)
    append_key_tier(tiers, name_keys)
    return tiers


def _build_api_polymorphic_target_tiers(api_row, graph=None, type_metadata=None):
    if graph is None or not type_metadata:
        return []

    symbol_kind = get_symbol_kind(api_row)
    if symbol_kind not in {'method', 'constructor'}:
        return []

    class_fqcn, method_name, signature_suffixes = _extract_api_target_method_info(api_row)
    if not class_fqcn or not method_name:
        return []

    class_meta = type_metadata.get(class_fqcn, {}) or {}
    if not class_meta:
        return []

    tiers = []
    kind = class_meta.get('kind', 'class')
    if kind == 'interface':
        extend_tiers(
            tiers,
            collect_inheritance_chain_tiers(
                class_fqcn,
                method_name,
                signature_suffixes,
                type_metadata,
                visited=set(),
                max_depth=20,
            ),
        )
        extend_tiers(
            tiers,
            _collect_inherited_subclass_tiers(
                class_fqcn,
                method_name,
                signature_suffixes,
                type_metadata,
                graph,
                visited=set(),
            ),
        )
        return tiers

    extend_tiers(
        tiers,
        _collect_inherited_subclass_tiers(
            class_fqcn,
            method_name,
            signature_suffixes,
            type_metadata,
            graph,
            visited=set(),
        ),
    )
    extend_tiers(
        tiers,
        _collect_unambiguous_interface_dispatch_tiers(
            class_fqcn,
            method_name,
            signature_suffixes,
            type_metadata,
        ),
    )
    return tiers


def build_api_target_key_groups(api_row, graph=None, type_metadata=None):
    groups = []
    api_name = api_row.get('api_name', '').strip()
    matched_class = api_row.get('matched_class', '').strip()
    api_simple = api_row.get('api_simple', '').strip()
    api_signature = api_row.get('api_signature', '').strip()
    symbol_kind = get_symbol_kind(api_row)
    requires_signature = symbol_kind in {'method', 'constructor'}

    if api_name:
        if symbol_kind == 'class':
            append_key_group(groups, 'exact_name', [f"class:{api_name}"])
        elif requires_signature:
            exact_keys = []
            if api_signature:
                exact_keys.append(f"{api_name}{api_signature}")
                normalized_signature = normalize_signature_for_lookup(api_signature)
                if normalized_signature and normalized_signature != api_signature:
                    exact_keys.append(f"{api_name}{normalized_signature}")
            append_key_group(groups, 'exact_signature', exact_keys)
            append_key_group(groups, 'exact_name', [api_name])
            # A changed annotation member default affects every source use of
            # that annotation which omits the member.  Annotation usage is
            # indexed by owner rather than guessed member name, and stays in a
            # separate group so it cannot weaken exact method matching.
            if '.' in api_name:
                annotation_owner = api_name.rsplit('.', 1)[0]
                append_key_group(groups, 'annotation_default_usage', [f"annotation:{annotation_owner}"])
        else:
            append_key_group(groups, 'exact_name', [api_name])
            if '.' in api_name:
                class_part = api_name.rsplit('.', 1)[0]
                append_key_group(groups, 'exact_name', [f"class:{class_part}"])

    if matched_class:
        append_key_group(groups, 'exact_name', [f"class:{matched_class}"])

    if api_simple and not api_name:
        if requires_signature and api_signature:
            fallback_keys = [f"method:{api_simple}{api_signature}"]
            normalized_signature = normalize_signature_for_lookup(api_signature)
            if normalized_signature and normalized_signature != api_signature:
                fallback_keys.append(f"method:{api_simple}{normalized_signature}")
            append_key_group(groups, 'fallback_simple', fallback_keys)
        append_key_group(groups, 'fallback_simple', [f"method:{api_simple}"])

    for tier in _build_api_polymorphic_target_tiers(api_row, graph=graph, type_metadata=type_metadata):
        append_key_group(groups, 'polymorphic', tier)

    return groups


def build_api_target_keys(api_row, graph=None, type_metadata=None):
    """
    Build API target keys (improved version)

    Improvement:
      - Try to use param types if available in api_row
      - This helps reduce false positives for overloaded methods

    Note: Current s4_contract does not provide param types,
    so this is a forward-looking improvement that will become
    useful when the contract is extended.
    """
    tiers = list(build_api_target_key_tiers(api_row))
    extend_tiers(tiers, _build_api_polymorphic_target_tiers(api_row, graph=graph, type_metadata=type_metadata))
    return flatten_key_tiers(tiers)


def build_api_identity_key(api_row):
    """为 Step4 -> Step5 串联构建稳定的 API 级唯一键。"""
    normalized = dict(api_row or {})
    normalized['symbol_kind'] = get_symbol_kind(normalized)
    return canonical_api_identity(normalized)


def has_precise_api_signature(api_row):
    api_signature = (api_row.get('api_signature') or '').strip()
    return bool(api_signature and api_signature.startswith('(') and api_signature.endswith(')'))


def get_symbol_kind(api_row):
    symbol_kind = (api_row.get('symbol_kind') or '').strip().lower()
    if symbol_kind in {'method', 'field', 'class', 'constructor'}:
        return symbol_kind
    if (api_row.get('analysis_scope', 'api') or 'api') == 'class_usage':
        return 'class'
    api_signature = (api_row.get('api_signature') or '').strip()
    api_name = (api_row.get('api_name') or '').strip()
    api_simple = (api_row.get('api_simple') or '').strip()
    if has_precise_api_signature(api_row):
        if api_simple and api_simple[:1].isupper() and api_name.endswith(f".{api_simple}"):
            return 'constructor'
        return 'method'
    if api_name and not api_signature:
        tail = api_name.rsplit('.', 1)[-1]
        if tail and tail[:1].isupper() and not api_simple:
            return 'class'
    return ''


def method_api_requires_signature(api_row):
    return get_symbol_kind(api_row) in {'method', 'constructor'}



def get_lookup_keys(method_def, type_metadata, graph=None):
    """
    获取方法查找键（包括完整继承链）

    改进：
      1. 递归处理多层继承
      2. 完整处理接口继承链
      3. 处理接口的父接口
      4. 仅使用元数据中已证明的继承关系，不把所有同名方法隐式并入 Object
    """
    return flatten_key_tiers(get_lookup_key_tiers(method_def, type_metadata, graph=graph))


def get_lookup_key_tiers(method_def, type_metadata, graph=None):
    tiers = []
    signature_suffixes = build_method_signature_suffixes(method_def)
    append_key_tier(tiers, build_method_signature_lookup_keys(method_def, signature_suffixes))
    append_key_tier(tiers, [method_def.qualified_key])

    inheritance_tiers = collect_inheritance_chain_tiers(
        method_def.class_fqcn,
        method_def.method_name,
        signature_suffixes,
        type_metadata,
        visited=set(),
        max_depth=20,
    )
    tiers.extend(inheritance_tiers)
    extend_tiers(
        tiers,
        _collect_inherited_subclass_tiers(
            method_def.class_fqcn,
            method_def.method_name,
            signature_suffixes,
            type_metadata,
            graph,
            visited=set(),
        ),
    )
    append_key_tier(tiers, [f"class:{method_def.class_fqcn}"])
    append_key_tier(tiers, build_simple_signature_lookup_keys(method_def, signature_suffixes))
    append_key_tier(tiers, [method_def.simple_key])
    return tiers


def ensure_method_identity_fields(method_def):
    qualified_key = str(getattr(method_def, 'qualified_key', '') or '').strip()
    if qualified_key and not getattr(method_def, 'class_fqcn', None) and '.' in qualified_key:
        setattr(method_def, 'class_fqcn', qualified_key.rsplit('.', 1)[0])
    if qualified_key and not getattr(method_def, 'method_name', None):
        setattr(method_def, 'method_name', qualified_key.rsplit('.', 1)[-1])
    if not getattr(method_def, 'simple_key', None) and getattr(method_def, 'method_name', None):
        setattr(method_def, 'simple_key', f"method:{getattr(method_def, 'method_name')}")
    return method_def


def build_method_lookup_key_groups(method_def, type_metadata, graph=None):
    method_def = ensure_method_identity_fields(method_def)
    groups = []
    signature_suffixes = build_method_signature_suffixes(method_def)
    append_key_group(groups, 'exact_signature', build_method_signature_lookup_keys(method_def, signature_suffixes))
    append_key_group(groups, 'exact_name', [method_def.qualified_key])
    for tier in collect_inheritance_chain_tiers(
        method_def.class_fqcn,
        method_def.method_name,
        signature_suffixes,
        type_metadata,
        visited=set(),
        max_depth=20,
    ):
        append_key_group(groups, 'polymorphic', tier)
    for tier in _collect_inherited_subclass_tiers(
        method_def.class_fqcn,
        method_def.method_name,
        signature_suffixes,
        type_metadata,
        graph,
        visited=set(),
    ):
        append_key_group(groups, 'polymorphic', tier)
    append_key_group(groups, 'fallback_simple', build_simple_signature_lookup_keys(method_def, signature_suffixes))
    append_key_group(groups, 'fallback_simple', [method_def.simple_key])
    return groups


def build_method_signature_suffixes(method_def):
    suffixes = []
    param_types = list((getattr(method_def, 'param_types', {}) or {}).values())
    param_declared_types = list((getattr(method_def, 'param_declared_types', {}) or {}).values())

    def append_signature(type_names):
        sig = build_signature_suffix(type_names)
        append_unique(suffixes, sig)

    append_signature(param_declared_types)
    append_signature(param_types)
    return suffixes


def build_signature_suffix(type_names):
    normalized = []
    for type_name in type_names:
        type_name = normalize_type_name(type_name)
        if not type_name:
            return ''
        normalized.append(type_name)
    if not normalized and list(type_names or []):
        return ''
    return '(' + ', '.join(normalized) + ')'


def normalize_type_name(type_name):
    type_name = (type_name or '').strip()
    if not type_name:
        return ''
    type_name = type_name.replace('...', '[]')
    if '<' in type_name:
        type_name = type_name.split('<', 1)[0].strip()
    if '.' in type_name:
        type_name = type_name.rsplit('.', 1)[-1]
    return type_name


def build_method_signature_lookup_keys(method_def, signature_suffixes=None):
    keys = []
    for sig in signature_suffixes or []:
        append_unique(keys, f"{method_def.qualified_key}{sig}")
    return keys


def build_simple_signature_lookup_keys(method_def, signature_suffixes=None):
    keys = []
    for sig in signature_suffixes or []:
        append_unique(keys, f"{method_def.simple_key}{sig}")
    return keys


def collect_inheritance_chain(class_fqcn, method_name, signature_suffixes, type_metadata, visited=None, max_depth=20):
    return flatten_key_tiers(
        collect_inheritance_chain_tiers(
            class_fqcn,
            method_name,
            signature_suffixes,
            type_metadata,
            visited=visited,
            max_depth=max_depth,
        )
    )


def collect_inheritance_chain_tiers(class_fqcn, method_name, signature_suffixes, type_metadata, visited=None, max_depth=20):
    """
    递归收集完整的继承链

    Args:
        class_fqcn: 类的完全限定名
        method_name: 方法名（用于生成完整键）
        type_metadata: 类型元数据
        visited: 已访问的类（防止循环继承）
        max_depth: 最大递归深度

    Returns:
        List[List[str]]: 分层方法查找键列表
    """
    if visited is None:
        visited = set()

    if max_depth <= 0 or class_fqcn in visited:
        return []

    visited.add(class_fqcn)
    method_sig_keys = []
    method_no_sig_keys = []
    class_keys = []

    class_meta = type_metadata.get(class_fqcn, {})

    def append_method_keys(target_class):
        append_unique(method_no_sig_keys, f"{target_class}.{method_name}")
        for sig in signature_suffixes or []:
            append_unique(method_sig_keys, f"{target_class}.{method_name}{sig}")
        append_unique(class_keys, f"class:{target_class}")

    # 处理父类（extends）
    for parent in class_meta.get('extends', []):
        append_method_keys(parent)

    # 处理接口（implements）
    for interface in class_meta.get('implements', []):
        append_method_keys(interface)

        # 递归处理接口的父接口
        interface_meta = type_metadata.get(interface, {})
        for parent_interface in interface_meta.get('extends', []):  # 接口的extends
            append_method_keys(parent_interface)

    # 接口 -> 实现类 的双向补充，有助于多态/代理场景继续展开。
    for implementation in class_meta.get('implementations', []):
        append_method_keys(implementation)

    tiers = []
    append_key_tier(tiers, method_sig_keys)
    append_key_tier(tiers, method_no_sig_keys)
    append_key_tier(tiers, class_keys)

    for parent in class_meta.get('extends', []):
        extend_tiers(
            tiers,
            collect_inheritance_chain_tiers(parent, method_name, signature_suffixes, type_metadata, visited, max_depth - 1),
        )

    for interface in class_meta.get('implements', []):
        extend_tiers(
            tiers,
            collect_inheritance_chain_tiers(interface, method_name, signature_suffixes, type_metadata, visited, max_depth - 1),
        )
        interface_meta = type_metadata.get(interface, {})
        for parent_interface in interface_meta.get('extends', []):
            extend_tiers(
                tiers,
                collect_inheritance_chain_tiers(
                    parent_interface, method_name, signature_suffixes, type_metadata, visited, max_depth - 1
                ),
            )

    for implementation in class_meta.get('implementations', []):
        extend_tiers(
            tiers,
            collect_inheritance_chain_tiers(implementation, method_name, signature_suffixes, type_metadata, visited, max_depth - 1),
        )

    return tiers


def append_key_tier(tiers, values):
    tier = []
    extend_unique(tier, values)
    if tier:
        tiers.append(tier)


def extend_tiers(target_tiers, new_tiers):
    for tier in new_tiers or []:
        append_key_tier(target_tiers, tier)


def flatten_key_tiers(key_tiers):
    keys = []
    for tier in key_tiers or []:
        extend_unique(keys, tier)
    return keys


def select_matching_keys_from_tiers(key_tiers, reverse_edges):
    for tier in key_tiers or []:
        matched = []
        for key in tier:
            if reverse_edges.get(key):
                append_unique(matched, key)
        if matched:
            return matched
    return []


def _candidate_reachability_path(result, candidate, complete, reason_code, note):
    path_edges = list(candidate.get('path') or [])
    path_text = (
        (result.call_paths or [""])[0]
        or format_call_chain(path_edges, changed_api_display_target(result))
    )
    has_business_entry = bool(candidate.get('entry_point')) or any(
        getattr(edge, 'owner_coord', '') == 'BUSINESS' for edge in path_edges
    )
    typed_evidence = []
    for edge in path_edges:
        owner_coord = str(getattr(edge, 'owner_coord', '') or '')
        instruction_offset = _normalized_instruction_offset(
            getattr(edge, 'instruction_offset', None)
        )
        typed_evidence.append(PhysicalCallEdge(
            caller_symbol=str(
                getattr(edge, 'caller_qualified_key', '')
                or getattr(edge, 'caller_symbol_id', '')
            ),
            callee_key=str(getattr(edge, 'callee_key', '') or ''),
            evidence_type=str(getattr(edge, 'evidence_type', '') or ''),
            owner_scope=classify_module_scope({
                'coord': (
                    '__business__'
                    if owner_coord in {'BUSINESS', '业务制品'}
                    else owner_coord
                ),
                'application_owned': bool(
                    getattr(edge, 'application_owned', False)
                ),
                'ownership_evidence': getattr(edge, 'ownership_evidence', None),
            }),
            owner_coord=owner_coord,
            artifact=str(getattr(edge, 'file', '') or ''),
            confidence=str(getattr(edge, 'confidence', 'high') or 'high'),
            instruction_offset=(
                int(instruction_offset) if instruction_offset is not None else -1
            ),
            semantic=bool(
                getattr(edge, 'semantic', False)
                or getattr(edge, 'framework_registration', False)
            ),
            activation_verified=bool(
                _semantic_edge_activation_verified(edge)
                and _typed_activation_evidence(edge)
            ),
            activation_evidence=(
                _typed_activation_evidence(edge)
                if _semantic_edge_activation_verified(edge) else ()
            ),
        ))
    entry_point = candidate.get('entry_point') or {}
    if (
        entry_point.get('entry_scope') == 'runtime_dependency_entry'
        and entry_point.get('framework_runtime_registration')
    ):
        adapter = str(entry_point.get('framework_adapter') or 'framework-runtime')
        typed_evidence.insert(0, PhysicalCallEdge(
            caller_symbol=f'framework:{adapter}',
            callee_key=str(entry_point.get('method') or ''),
            evidence_type='framework_runtime_active_entry',
            owner_scope=ModuleScope.EXTERNAL_DEPENDENCY,
            artifact=str(entry_point.get('file') or ''),
            confidence='high',
            semantic=True,
            activation_verified=bool(
                entry_point.get('activation_verified')
                and _typed_activation_evidence(entry_point)
            ),
            activation_evidence=(
                _typed_activation_evidence(entry_point)
                if entry_point.get('activation_verified') else ()
            ),
        ))
    return ReachabilityPath(
        path_text=path_text,
        entry_scope=(
            ModuleScope.BUSINESS_CLASSES
            if has_business_entry
            else ModuleScope.EXTERNAL_DEPENDENCY
        ),
        complete=complete,
        truncated=reason_code in {'DEPTH_LIMIT_REACHED', 'MAX_DEPTH_REACHED', 'PATH_TRUNCATED'},
        stop_reason=reason_code,
        reason_code=reason_code,
        note=note,
        depth=int(candidate.get('depth') or len(path_edges) or 1),
        evidence=tuple(typed_evidence),
    )


def build_reachable_result(result, candidate, graph):
    """构建reachable结果"""
    result.confidence_score = candidate['confidence']
    entry_point = candidate['entry_point']
    if entry_point.get('entry_scope') == 'runtime_dependency_entry':
        reason_code = 'RUNTIME_DEPENDENCY_ENTRY_REACHED'
        note = (
            f"已触达当前制品中会由框架或运行时机制触发的依赖入口"
            f"（置信度{candidate['confidence']:.2f}）"
        )
    else:
        reason_code = 'SYSTEM_CODE_REACHED'
        note = f"触达系统代码（置信度{candidate['confidence']:.2f}）"

    # 构建调用链
    path_edges = candidate['path']
    result.call_paths = [
        format_call_chain(path_edges, changed_api_display_target(result))
    ]
    # 追踪跨越的依赖边界（dependency_chain_coords）
    # 检查路径中是否经过dependency-owned源码
    crossed_coords = set()
    for edge in path_edges:
        if edge.owner_coord and edge.owner_coord != 'BUSINESS':
            crossed_coords.add(edge.owner_coord)
    if crossed_coords:
        result.dependency_chain_coords = sorted(crossed_coords)

    result.evidence_paths = [[edge_to_evidence(edge, graph=graph) for edge in path_edges]]

    result.critical_nodes_hit = [entry_point]
    result.match_provenance = candidate.get('provenance', '')
    result.match_tier = candidate.get('match_tier', -1)

    return _apply_evidence_decision(result, paths=(
        _candidate_reachability_path(result, candidate, True, reason_code, note),
    ))


def build_behavior_changed_result(result, candidate, graph):
    """
    构建行为变更结果（需运行时验证）

    行为变更与签名变更不同：即使找到调用链，也不能直接判定为"已触达系统"，
    因为签名没变不代表运行时行为没变。需要通过运行时测试验证。
    """
    # 注意：change_type == 'BEHAVIOR_CHANGED' 的语义是"需要运行时验证"
    # 即使找到了调用链，analysis_status 应该是 not_analyzed
    result.confidence_score = candidate['confidence']
    reason_code = 'BEHAVIOR_CHANGED_RUNTIME_VERIFICATION'
    note = '找到调用链，但签名未变的情况下行为可能变化，需运行时验证'

    # 构建调用链（用于人工审查）
    path_edges = candidate['path']
    entry_point = candidate['entry_point']

    result.call_paths = [
        format_call_chain(path_edges, changed_api_display_target(result))
    ]
    # 追踪跨越的依赖边界
    crossed_coords = set()
    for edge in path_edges:
        if getattr(edge, 'owner_coord', None) and edge.owner_coord != 'BUSINESS':
            crossed_coords.add(edge.owner_coord)
    if crossed_coords:
        result.dependency_chain_coords = sorted(crossed_coords)

    result.evidence_paths = [[edge_to_evidence(edge, graph=graph) for edge in path_edges]]

    result.critical_nodes_hit = [entry_point]
    result.match_provenance = candidate.get('provenance', '')
    result.match_tier = candidate.get('match_tier', -1)

    result.verification_commands = [
        '行为变更需运行时测试验证',
        '建议执行相关单元测试或集成测试',
        f'调用链已定位，需确认运行时行为是否受影响'
    ]
    _downgrade_reachable_path_details(result, 'not_analyzed', reason_code)
    path = _candidate_reachability_path(result, candidate, False, reason_code, note)
    return _apply_blocking_failure(result, 'behavior-change-analysis', reason_code, note, (path,))


def build_behavior_changed_fallback_simple_result(result, candidate, graph):
    result.confidence_score = candidate['confidence']
    reason_code = 'BEHAVIOR_CHANGED_PRECISE_TARGET_NOT_CONFIRMED'
    note = (
        '找到调用链，但当前命中依赖 fallback_simple 回退；'
        '对于已有完整签名的行为变更，这不足以安全确认目标 API'
    )

    path_edges = candidate['path']
    entry_point = candidate['entry_point']

    result.call_paths = [
        format_call_chain(path_edges, changed_api_display_target(result))
    ]
    crossed_coords = set()
    for edge in path_edges:
        if getattr(edge, 'owner_coord', None) and edge.owner_coord != 'BUSINESS':
            crossed_coords.add(edge.owner_coord)
    if crossed_coords:
        result.dependency_chain_coords = sorted(crossed_coords)

    result.evidence_paths = [[edge_to_evidence(edge, graph=graph) for edge in path_edges]]
    result.critical_nodes_hit = [entry_point]
    result.match_provenance = candidate.get('provenance', '')
    result.match_tier = candidate.get('match_tier', -1)
    result.verification_commands = [
        '补全中间调用点的类型/签名推断，避免命中 fallback_simple 回退键',
        '人工复核该调用链是否真的落在目标 API，而不是同名 sibling 方法',
        '确认后再执行相关单元测试或集成测试验证行为变化',
    ]
    _downgrade_reachable_path_details(result, 'not_analyzed', reason_code)
    path = _candidate_reachability_path(result, candidate, False, reason_code, note)
    return _apply_blocking_failure(result, 'signature-resolution', reason_code, note, (path,))


def build_fallback_simple_unconfirmed_result(result, candidate, graph):
    _ = graph
    result.confidence_score = candidate['confidence']
    reason_code = 'FALLBACK_SIMPLE_PATH_UNCONFIRMED'
    note = (
        '找到候选调用链，但其中依赖 fallback_simple 回退；'
        '当前证据不足以安全确认命中的就是目标 API'
    )

    path_edges = candidate['path']
    entry_point = candidate['entry_point']

    result.call_paths = [
        format_call_chain(path_edges, changed_api_display_target(result))
    ]
    crossed_coords = set()
    for edge in path_edges:
        coord = getattr(edge, 'owner_coord', '')
        if coord and coord != 'BUSINESS':
            crossed_coords.add(coord)
    result.dependency_chain_coords = sorted(crossed_coords)

    result.evidence_paths = [[edge_to_evidence(edge) for edge in path_edges]]
    result.match_provenance = candidate.get('provenance', '')
    result.match_tier = candidate.get('match_tier', -1)
    result.verification_commands = [
        '补全中间调用点的类型/签名推断，避免命中 fallback_simple 回退键',
        '人工复核该候选链路是否真的落在目标 API，而不是同名 sibling 方法',
        '若目标属于 SPI/回调接口，请继续确认业务代码是否实现、注册或显式引用了该类型',
    ]
    _downgrade_reachable_path_details(result, 'not_analyzed', reason_code)
    path = _candidate_reachability_path(result, candidate, False, reason_code, note)
    return _apply_blocking_failure(result, 'signature-resolution', reason_code, note, (path,))


def build_internal_only_direct_consumer_result(result, candidate, graph):
    _ = graph
    result.confidence_score = candidate['confidence']
    reason_code = 'INTERNAL_ONLY_DIRECT_CONSUMER'
    note = (
        '找到候选调用链，但变更 API 的直接调用者仍位于同一依赖内部；'
        '当前证据不足以证明外部消费者真实依赖了这个变更 API'
    )

    path_edges = candidate['path']
    entry_point = candidate['entry_point']

    result.call_paths = [
        format_call_chain(path_edges, changed_api_display_target(result))
    ]
    crossed_coords = set()
    for edge in path_edges:
        coord = getattr(edge, 'owner_coord', '')
        if coord and coord != 'BUSINESS':
            crossed_coords.add(coord)
    result.dependency_chain_coords = sorted(crossed_coords)

    result.evidence_paths = [[edge_to_evidence(edge) for edge in path_edges]]
    result.match_provenance = candidate.get('provenance', '')
    result.match_tier = candidate.get('match_tier', -1)
    result.verification_commands = [
        '优先确认业务代码或其他依赖是否直接调用了该变更 API，而不是只经过目标依赖的内部实现',
        '若当前路径只证明同坐标依赖内部自调用，请不要直接判定为已确认影响',
        '若目标属于 SPI/回调接口，还需继续确认业务代码是否实现、注册或显式引用了该类型',
    ]
    _downgrade_reachable_path_details(result, 'not_analyzed', reason_code)
    path = _candidate_reachability_path(result, candidate, False, reason_code, note)
    return _apply_blocking_failure(result, 'consumer-ownership', reason_code, note, (path,))


def build_uncertain_result(result, candidate):
    """构建uncertain结果"""
    result.confidence_score = candidate['confidence']
    reason_code = candidate['reason']
    note = f"链路置信度{candidate['confidence']:.2f}，需人工确认"

    path_edges = candidate['path']

    result.call_paths = [
        format_call_chain(path_edges, changed_api_display_target(result) or "未找到业务入口")
    ]
    result.verification_commands = [
        "审查链路中的低置信度边",
        f"确认 {getattr(path_edges[-1], 'file', '?')}:{getattr(path_edges[-1], 'line', '?')} 的调用上下文"
    ]

    # 追踪跨越的依赖边界（dependency_chain_coords）
    crossed_coords = set()
    for edge in path_edges:
        if getattr(edge, 'owner_coord', None) and edge.owner_coord != 'BUSINESS':
            crossed_coords.add(edge.owner_coord)
    if crossed_coords:
        result.dependency_chain_coords = sorted(crossed_coords)

    # 构建证据路径（兼容 s6_report.py）
    result.evidence_paths = [[edge_to_evidence(edge) for edge in path_edges]]
    result.match_provenance = candidate.get('provenance', '')
    result.match_tier = candidate.get('match_tier', -1)

    path = _candidate_reachability_path(result, candidate, False, reason_code, note)
    return _apply_uncertainty(result, 'confidence-analysis', reason_code, note, (path,))


def build_not_analyzed_result(result, candidate):
    """构建not_analyzed结果"""
    reason_code = candidate.get('reason', 'UNKNOWN')
    note = candidate.get('boundary', {}).get('reason', '无法静态分析')

    # 关键修复：填充 call_paths / evidence_paths（s6_report.py 依赖这些字段）
    path_edges = candidate.get('path', [])

    # 从路径提取方法名构造可读调用链
    if path_edges:
        parts = []
        for edge in reversed(path_edges):
            caller_key = getattr(edge, 'caller_qualified_key', '') or getattr(edge, 'caller_symbol_id', '?')
            method_name = caller_key.rsplit('.', 1)[-1] if '.' in caller_key else caller_key
            parts.append(f"{method_name}()")
        parts.append('变更API')
        result.call_paths = [" -> ".join(parts)]
        result.evidence_paths = [[edge_to_evidence(e) for e in path_edges]]
    else:
        result.call_paths = []
        result.evidence_paths = []

    result.match_provenance = candidate.get('provenance', '')
    result.match_tier = candidate.get('match_tier', -1)

    if 'boundary' in candidate:
        boundary = candidate['boundary']
        result.verification_commands = [
            f"框架边界：{boundary['method']}",
            "审查框架配置（Spring/MyBatis等）"
        ]
    elif candidate.get('verification_commands'):
        result.verification_commands = candidate.get('verification_commands') or []

    path = _candidate_reachability_path(result, candidate, False, reason_code, note)
    return _apply_blocking_failure(result, 'call-graph-boundary', reason_code, note, (path,))


def build_missing_dependency_source_mapping_result(result):
    """构建缺少依赖源码映射导致的 not_analyzed 结果"""
    _apply_blocking_failure(
        result, 'dependency-source-discovery', 'DEPENDENCY_SOURCE_MAPPING_MISSING',
        '需要可用的依赖源码映射才能完成分析，当前分析能力受限',
    )
    result.verification_commands = [
        '补充 dependency_source_dirs 指向依赖源码工程或仓库根目录',
        '确认系统能够从依赖源码中解析出目标模块坐标与源码目录',
        '然后重新运行 Step 5'
    ]
    return result


def format_call_chain(path_edges, final_target):
    """把反向追踪边还原为“业务调用方 → ... → 变更符号”的完整正向链路。"""
    if not path_edges:
        return final_target

    parts = []
    for edge in reversed(path_edges):
        parts.append(str(
            getattr(edge, 'caller_qualified_key', '')
            or getattr(edge, 'caller_symbol_id', '?')
        ))
        if getattr(edge, 'framework_registration', False):
            parts.append('Spring Boot框架注册')
    # path_edges[0] 是变更符号的直接消费边。源码/字节码里看到的 callee
    # 可能是子类、适配器或继承分派目标；对外展示时仍必须以 Step4 的
    # 变更 API 作为链路终点，否则用户会看到“分析 A，终点却是 B”。
    direct_callee = str(getattr(path_edges[0], 'callee_key', '') or '').strip()
    final_target = str(final_target or '').strip()
    if direct_callee and direct_callee != final_target:
        parts.append(direct_callee)
    if final_target:
        parts.append(f"变更API: {final_target}")

    return " → ".join(parts)


# ══════════════════════════════════════════════════════════════════
# 批量追踪入口
# ══════════════════════════════════════════════════════════════════

def trace_all_apis_with_confidence_weighting(all_apis, graph, type_metadata, max_total_cost=5,
                                            api_bridge_requirements=None, allow_degraded=False,
                                            graph_stats=None):
    """
    批量追踪所有变更API

    Args:
        all_apis: List[Dict] 变更API列表
        graph: 源码调用图
        type_metadata: 类型元数据
        max_total_cost: 最大总代价（控制追踪深度）
        api_bridge_requirements: dict of {api_key: {'needs_bridge': bool, 'reason': str}}
        allow_degraded: 如果为 True，当 API 需要依赖源码映射但未提供时，标记为 not_analyzed

    Returns:
        List[TraceResult]
    """
    if api_bridge_requirements is None:
        api_bridge_requirements = {}

    trace_started_at = time.perf_counter()
    _perf_add(graph, 'trace', 'calls', 1)
    results = []
    trace_cache = ensure_trace_cache()
    total = len(all_apis or [])
    progress_interval = suggest_log_interval(total, target_updates=12, minimum=1)
    started_at = time.perf_counter()
    status_counts = {
        'reachable': 0,
        'not_impacted': 0,
        'uncertain': 0,
        'not_analyzed': 0,
        'not_found_in_static_analysis': 0,
        'not_reachable': 0,
    }
    _step5_debug(
        'trace_batch_start',
        'starting batch trace for all apis',
        total_apis=total,
        max_total_cost=max_total_cost,
        allow_degraded=allow_degraded,
        graph_stats=graph_stats or {},
    )
    if graph is not None and all_apis:
        graph._active_packaged_scan_trace_serial = int(
            getattr(graph, '_active_packaged_scan_trace_serial', 0) or 0
        ) + 1
        catalog = _get_runtime_dependency_catalog(graph)
        catalog['_packaged_api_scan_validated_trace_serial'] = 0
        try:
            graph._trace_max_total_cost = int(max_total_cost or 5)
            changed_api_overload_signatures = defaultdict(set)
            for row in all_apis:
                if not method_api_requires_signature(row):
                    continue
                api_name = str(row.get('api_name') or '').strip()
                api_signature = str(row.get('api_signature') or '').strip()
                if api_name and api_signature:
                    changed_api_overload_signatures[api_name].add(api_signature)
            graph.changed_api_overload_signatures = {
                api_name: frozenset(signatures)
                for api_name, signatures in changed_api_overload_signatures.items()
            }
            identical_providers = _build_identical_current_class_provider_index(
                all_apis, graph
            )
            scan_apis = [
                row for row in all_apis
                if (
                    str(row.get('coord') or '').strip(),
                    _changed_api_owner_fqcn(row),
                ) not in identical_providers
            ]
            _build_packaged_runtime_dependency_scan_cache(scan_apis, graph)
        except BaseException:
            graph._active_packaged_scan_trace_serial = 0
            catalog['_packaged_api_scan_validated_trace_serial'] = 0
            raise
        catalog['_packaged_api_scan_validated_trace_serial'] = (
            graph._active_packaged_scan_trace_serial
        )

    for idx, api_row in enumerate(all_apis, 1):
        api_started_at = time.perf_counter()
        api_name = str(api_row.get('api_name', '') or '').strip()
        if not api_name:
            # A malformed Step4 row must never disappear from the denominator:
            # users need to see why an API could not be traced, rather than a
            # deceptively smaller ``total_apis`` in summary.json.
            draft = _new_trace_draft(api_row, graph)
            draft.confidence_score = 0.0
            _apply_blocking_failure(
                draft,
                'input-validation',
                'MISSING_API_NAME',
                '变更 API 清单缺少 api_name，无法建立精确目标符号。',
            )
            result = _finalize_trace_draft(draft)
            results.append(result)
            status_counts['not_analyzed'] += 1
            continue

        # 检查该 API 是否需要依赖源码映射
        bridge_info = api_bridge_requirements.get(build_api_identity_key(api_row), {})
        needs_bridge = bridge_info.get('needs_bridge', False)
        has_dependency_source_mapping = bridge_info.get('has_dependency_source_mapping', True)
        has_packaged_bytecode_fallback = bridge_info.get('has_packaged_bytecode_fallback', False)

        if should_log_progress(idx, total, progress_interval):
            emit_progress(
                "step5",
                "trace",
                f"正在追踪 {api_name[:80]}",
                current=idx,
                total=total,
                elapsed=time.perf_counter() - started_at,
                item=api_name[:80],
            )
        _step5_debug(
            'trace_batch_item',
            'dispatching api trace',
            index=idx,
            total=total,
            api_name=api_name,
            api_signature=api_row.get('api_signature', ''),
            bridge_info=bridge_info,
        )

        try:
            result = trace_api_with_confidence_weighting(
                api_row,
                graph,
                type_metadata,
                max_total_cost=max_total_cost,
                needs_bridge=needs_bridge,
                has_dependency_source_mapping=has_dependency_source_mapping,
                has_packaged_bytecode_fallback=has_packaged_bytecode_fallback,
                allow_degraded=allow_degraded,
                graph_stats=graph_stats,
                trace_cache=trace_cache,
            )
        except BaseException:
            if graph is not None:
                graph._active_packaged_scan_trace_serial = 0
                catalog = _get_runtime_dependency_catalog(graph)
                catalog['_packaged_api_scan_validated_trace_serial'] = 0
            raise

        results.append(result)
        api_elapsed_sec = time.perf_counter() - api_started_at
        _perf_add(graph, 'trace', 'api_elapsed_sec', api_elapsed_sec)
        _perf_add(graph, 'trace', 'apis_traced', 1)
        status = result.analysis_status or 'unknown'
        api_timing = {
            'api_name': api_name,
            'api_signature': api_row.get('api_signature', ''),
            'symbol_kind': api_row.get('symbol_kind', ''),
            'change_type': api_row.get('change_type', ''),
            'severity': api_row.get('severity', ''),
            'elapsed_sec': api_elapsed_sec,
            'analysis_status': status,
            'direct_callers': getattr(result, 'direct_callers', 0),
            'business_reach_depth': getattr(result, 'business_reach_depth', None),
            'confidence_score': getattr(result, 'confidence_score', None),
            'reason_code': getattr(result, 'reason_code', ''),
        }
        _perf_append(graph, 'trace', 'api_trace_timings', api_timing)
        _perf_record_top(graph, 'trace', 'slow_api_traces', api_timing)
        status_counts[status] = status_counts.get(status, 0) + 1
        if should_log_progress(idx, total, progress_interval):
            emit_progress(
                "step5",
                "trace",
                (
                    "追踪进度更新，"
                    f"reachable={status_counts.get('reachable', 0)}，"
                    f"not_impacted={status_counts.get('not_impacted', 0)}，"
                    f"uncertain={status_counts.get('uncertain', 0)}，"
                    f"not_analyzed={status_counts.get('not_analyzed', 0)}，"
                    f"not_found={status_counts.get('not_found_in_static_analysis', 0) + status_counts.get('not_reachable', 0)}"
                ),
                current=idx,
                total=total,
                elapsed=time.perf_counter() - started_at,
            )

    if graph is not None:
        graph._active_packaged_scan_trace_serial = 0
        catalog = _get_runtime_dependency_catalog(graph)
        catalog['_packaged_api_scan_validated_trace_serial'] = 0

    emit_progress(
        "step5",
        "trace",
        (
            "反向追踪完成，"
            f"reachable={status_counts.get('reachable', 0)}，"
            f"not_impacted={status_counts.get('not_impacted', 0)}，"
            f"uncertain={status_counts.get('uncertain', 0)}，"
            f"not_analyzed={status_counts.get('not_analyzed', 0)}，"
            f"not_found={status_counts.get('not_found_in_static_analysis', 0) + status_counts.get('not_reachable', 0)}"
        ),
        current=len(results),
        total=total,
        elapsed=time.perf_counter() - started_at,
    )
    _step5_debug(
        'trace_batch_done',
        'finished batch trace for all apis',
        total_results=len(results),
        status_counts=status_counts,
        elapsed_seconds=time.perf_counter() - started_at,
    )
    _perf_add(graph, 'trace', 'elapsed_sec', time.perf_counter() - trace_started_at)
    _perf_add(graph, 'trace', 'total_apis', total)
    _perf_max(graph, 'main', 'peak_rss_mb', _peak_rss_mb())
    collect_graph_analyzer_edges(graph, all_apis)
    ledger_stats = graph_stats if graph_stats is not None else {}
    write_analyzer_edge_ledger(graph, graph_stats=ledger_stats)
    if graph_stats is not None:
        _merge_step5_perf_stats(
            graph_stats.setdefault('step5_perf', {}),
            _finalize_step5_perf_stats(graph),
        )
    _emit_step5_perf_summary(graph)
    return results


# ══════════════════════════════════════════════════════════════════
# 测试入口
# ══════════════════════════════════════════════════════════════════

def test_confidence_weighted_tracer():
    """测试置信度加权追踪"""
    # 模拟数据
    # 模拟图结构（简化）
    # 实际测试需要完整graph

    print("测试置信度加权追踪逻辑")
    print("  API: com.example.Foo.changedMethod")
    print("  策略：置信度加权深度")

    return 0


if __name__ == '__main__':
    sys.exit(test_confidence_weighted_tracer())
