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

import json
import os
import re
import struct
import sys
import time
import zipfile
from collections import defaultdict, deque
from dataclasses import dataclass, field

from compat import run_cmd
from progress_logging import emit_progress, should_log_progress, suggest_log_interval
from signature_utils import normalize_signature_for_lookup, split_signature_params
from enhanced_source_analyzer import CallEdge, MethodDef
from indirect_usage_analyzer import (
    api_key as indirect_api_key,
    parse_javap_indirect_references,
)


NON_BLOCKING_PARSER_FALLBACK_REASONS = {
    'prefer_tree_sitter_disabled',
    'unsupported_language_kotlin',
}

CALL_GRAPH_LIMITED_SYMBOL_KINDS = {
    'class',
    'field',
}


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
    # 全部终止链路的人工复核视图；call_paths/evidence_paths 保留兼容语义。
    path_details: list = field(default_factory=list)
    capability_coverage: dict = field(default_factory=dict)


def _iter_business_methods(graph):
    for method_def in (getattr(graph, 'methods_by_id', {}) or {}).values():
        if getattr(method_def, 'owner_type', '') == 'business' and not getattr(method_def, 'is_test', False):
            yield method_def


def _build_direct_usage_result(result, method_def, reason_code, note, evidence_type, display_target):
    result.analysis_status = 'reachable'
    result.is_reachable = True
    result.reason_code = reason_code
    result.reachable_note = note
    result.direct_callers = 1
    result.business_reach_depth = 1
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
    return result


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

    result.analysis_status = 'reachable'
    result.is_reachable = True
    result.reason_code = reason_code
    result.reachable_note = note
    result.direct_callers = len(unique_matches)
    result.business_reach_depth = 1
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
    return result


def _find_direct_business_class_usage(api_row, graph):
    target_class = str(api_row.get('matched_class') or api_row.get('api_name') or '').strip()
    if not target_class:
        return None
    simple_name = target_class.rsplit('.', 1)[-1]
    simple_name_patterns = [
        re.compile(r'\bnew\s+' + re.escape(simple_name) + r'\b'),
        re.compile(r'\b' + re.escape(simple_name) + r'\s*\.class\b'),
        re.compile(r'\binstanceof\s+' + re.escape(simple_name) + r'\b'),
        re.compile(r'\(\s*' + re.escape(simple_name) + r'\s*\)'),
    ]
    fqcn_pattern = re.compile(re.escape(target_class))
    for method_def in _iter_business_methods(graph):
        declared_types = (
            [getattr(method_def, 'return_type', '')]
            + list((getattr(method_def, 'param_types', {}) or {}).values())
            + list((getattr(method_def, 'field_types', {}) or {}).values())
            + list((getattr(method_def, 'local_var_types', {}) or {}).values())
        )
        if target_class in declared_types:
            return method_def, 'declared_type'
        imports = getattr(method_def, 'imports', {}) or {}
        wildcard_imports = getattr(method_def, 'wildcard_imports', {}) or []
        body_text = getattr(method_def, 'get_body_text', lambda: '')() or ''
        import_matches_target = imports.get(simple_name) == target_class
        wildcard_matches_target = any(f"{pkg}.{simple_name}" == target_class for pkg in wildcard_imports)
        if (import_matches_target or wildcard_matches_target) and any(
            pattern.search(body_text) for pattern in simple_name_patterns
        ):
            return method_def, 'imported_type'
        if fqcn_pattern.search(body_text):
            return method_def, 'body_reference'
    return None


def _find_direct_business_field_usages(api_row, graph):
    api_name = str(api_row.get('api_name') or '').strip()
    field_name = str(api_row.get('api_simple') or '').strip() or (api_name.rsplit('.', 1)[-1] if '.' in api_name else '')
    owner_class = api_name.rsplit('.', 1)[0] if '.' in api_name else ''
    owner_simple = owner_class.rsplit('.', 1)[-1] if owner_class else ''
    if not field_name:
        return []
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
            if imports.get(owner_simple) == owner_class or any(
                f"{pkg}.{owner_simple}" == owner_class for pkg in wildcard_imports
            ):
                matches.append((method_def, 'field_access'))
    return matches


def _find_direct_business_field_usage(api_row, graph):
    usages = _find_direct_business_field_usages(api_row, graph)
    return usages[0] if usages else None


def _try_build_direct_usage_result(api_row, result, graph):
    if graph is None:
        return None

    matched = None
    symbol_kind = str(result.symbol_kind or '').strip()
    analysis_scope = str(result.analysis_scope or '').strip()

    if analysis_scope == 'class_usage' or symbol_kind == 'class':
        matched = _find_direct_business_class_usage(api_row, graph)
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
        matches = _find_direct_business_field_usages(api_row, graph)
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


def _get_runtime_dependency_catalog(graph):
    return getattr(graph, 'runtime_dependency_catalog', {}) or {}


def _apply_source_artifact_miss(result, graph, reachable_note):
    alignment = getattr(graph, 'source_artifact_alignment', {}) or {}
    alignment_status = str(alignment.get('status') or '').strip()
    result.analysis_status = 'uncertain'
    result.is_reachable = None
    if alignment_status in {'', 'aligned', 'conflict'}:
        result.reason_code = 'SOURCE_BYTECODE_EDGE_CONFLICT'
        result.reachable_note = reachable_note
    else:
        result.reason_code = 'SOURCE_ARTIFACT_ALIGNMENT_UNVERIFIED'
        result.reachable_note = (
            '源码图存在目标调用，但源码与最终制品未证明来自同一 revision/profile；'
            '字节码未命中不能用于反证源码候选'
        )
    _downgrade_reachable_path_details(result, 'uncertain', result.reason_code)
    return result


def _downgrade_reachable_path_details(result, path_status, stop_reason):
    for detail in getattr(result, 'path_details', []) or []:
        if detail.get('path_status') != 'reachable':
            continue
        detail['path_status'] = path_status
        detail['stop_reason'] = stop_reason
        detail['business_reachable'] = None


def _is_inlined_constant_change(api_row):
    return (
        get_symbol_kind(api_row) == 'field'
        and (
            str(api_row.get('change_type') or '').strip() == 'CONSTANT_VALUE_CHANGED'
            or 'CONSTANT' in str(api_row.get('compatibility_flags') or '').upper()
            or (
                str(api_row.get('old_value') or '')
                and str(api_row.get('new_value') or '')
                and str(api_row.get('old_value')) != str(api_row.get('new_value'))
            )
        )
    )


def _build_inlined_constant_result(result):
    result.analysis_status = 'uncertain'
    result.is_reachable = None
    result.reason_code = 'INLINED_CONSTANT_USAGE_UNDETECTABLE'
    result.reachable_note = (
        '编译期常量值已变化，但调用方 class 可能只保留内联旧值而没有字段访问指令；'
        '字节码未发现 getstatic/getfield 不能解释为未使用'
    )
    result.verification_commands = [
        '搜索业务及依赖源码中的常量字段引用，并执行覆盖该常量语义的回归测试',
        '必要时比较调用方 class 常量池与 old/new 常量值，但不要仅凭字面量命中确认调用关系',
    ]
    return result


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
        ref_class_indexes = []
        name_and_type_name_indexes = {}
        ref_name_and_type_indexes = []
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
                ref_class_indexes.append(struct.unpack_from('>H', data, idx)[0])
                ref_name_and_type_indexes.append(struct.unpack_from('>H', data, idx + 2)[0])
                idx += 4
            elif tag == 12:  # NameAndType
                if idx + 4 > len(data):
                    return None
                name_and_type_name_indexes[cp_index] = struct.unpack_from('>H', data, idx)[0]
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
                idx += 4
            elif tag in (19, 20):
                idx += 2
            else:
                return None
            cp_index += 1
        ref_class_internal = {
            class_by_cp_index.get(class_index, '')
            for class_index in ref_class_indexes
        }
        ref_member_names = {
            utf8.get(name_and_type_name_indexes.get(name_and_type_index, ''), '')
            for name_and_type_index in ref_name_and_type_indexes
        }
        utf8_values = set(utf8.values())
        return {
            'class_internal_names': {item for item in class_internal if item},
            'ref_internal_names': {item for item in ref_class_internal if item},
            'ref_member_names': {item for item in ref_member_names if item},
            'utf8_values': utf8_values,
        }
    except Exception:
        return None


def _runtime_prefilter_owner_candidates(owner_candidates, data, target_rows_by_owner):
    if not owner_candidates:
        return []
    summary = _parse_classfile_constant_pool_summary(data)
    if summary is None:
        return [owner for owner, _internal_bytes, _dotted_bytes in owner_candidates]
    class_names = summary.get('class_internal_names') or set()
    ref_names = summary.get('ref_internal_names') or set()
    utf8_values = summary.get('utf8_values') or set()
    ref_member_names = summary.get('ref_member_names') or set()
    filtered = []
    for owner, _internal_bytes, _dotted_bytes in owner_candidates:
        internal = owner.replace('.', '/')
        if internal in class_names or internal in ref_names:
            filtered.append(owner)
            continue
        owner_as_string = internal in utf8_values or owner in utf8_values
        if not owner_as_string:
            continue
        for api_row in target_rows_by_owner.get(owner, []):
            _api_owner, member_name, symbol_kind = _extract_target_owner_and_member(api_row)
            if symbol_kind == 'class' or str(api_row.get('analysis_scope') or '').strip() == 'class_usage':
                filtered.append(owner)
                break
            if symbol_kind == 'constructor':
                constructor_reflection_names = {
                    'getConstructor',
                    'getDeclaredConstructor',
                    'newInstance',
                }
                if constructor_reflection_names & (utf8_values | ref_member_names):
                    filtered.append(owner)
                    break
            if symbol_kind == 'field':
                field_reflection_names = {
                    'getField',
                    'getDeclaredField',
                    'findGetter',
                    'findSetter',
                    'findStaticGetter',
                    'findStaticSetter',
                }
                if (
                    member_name
                    and (member_name in utf8_values or member_name in ref_member_names)
                    and field_reflection_names & (utf8_values | ref_member_names)
                ):
                    filtered.append(owner)
                    break
            if symbol_kind == 'method':
                method_reflection_names = {
                    'getMethod',
                    'getDeclaredMethod',
                    'findStatic',
                    'findVirtual',
                    'findSpecial',
                    'unreflect',
                    'unreflectSpecial',
                }
                if (
                    member_name
                    and (member_name in utf8_values or member_name in ref_member_names)
                    and method_reflection_names & (utf8_values | ref_member_names)
                ):
                    filtered.append(owner)
                    break
    return list(dict.fromkeys(filtered))


def _run_javap_bytecode_dump(jar_path, class_binary_name, multi_release_version=None):
    command = ['javap', '-classpath', jar_path, '-verbose', '-c', '-s', '-p']
    if multi_release_version is not None:
        command.extend(['--multi-release', str(multi_release_version)])
    command.append(class_binary_name)
    stdout, _stderr, rc = run_cmd(
        command,
        timeout=30,
    )
    return stdout if rc == 0 else ''


def _parse_javap_bytecode_references(text, class_binary_name=''):
    references = {
        'method_refs': [],
        'field_refs': [],
        'class_refs': set(),
    }
    method_pattern = re.compile(
        r'//\s+(?:Interface)?Method\s+([A-Za-z0-9_/$]+)\.(?:"([^"]+)"|([A-Za-z0-9_$<>]+)):(\S+)'
    )
    field_pattern = re.compile(
        r'//\s+Field\s+([A-Za-z0-9_/$]+)\.([A-Za-z0-9_$]+):(\S+)'
    )
    class_pattern = re.compile(r'//\s+class\s+([A-Za-z0-9_/$]+)')
    descriptor_pattern = re.compile(r'L([A-Za-z0-9_/$]+);')
    method_header_pattern = re.compile(
        r'^\s*(?:[\w.$<>\[\],?]+\s+)+([\w$<>.]+)\([^;]*\)'
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
            owner = handle.group(1).replace('/', '.').replace('$', '.')
            if owner in {
                'java.lang.invoke.LambdaMetafactory',
                'java.lang.invoke.StringConcatFactory',
            }:
                continue
            bootstrap_targets[current_bootstrap].append({
                'owner': owner,
                'name': handle.group(2) or handle.group(3) or '',
                'descriptor': handle.group(4),
            })
    current_member = ''
    current_signature = ''
    class_simple = str(class_binary_name or '').rsplit('.', 1)[-1]
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
            continue
        if re.match(r'^\s*static\s+\{\};\s*$', raw_line):
            current_member = '<clinit>'
            current_signature = ''
            continue
        if line.startswith('descriptor:') and current_member:
            current_signature = _method_descriptor_to_lookup_signature(line.split(':', 1)[1].strip())
            for match in descriptor_pattern.findall(line):
                references['class_refs'].add(match.replace('/', '.').replace('$', '.'))
            continue
        # Constant-pool declarations also contain "// Method/Field" comments,
        # but they do not identify the consuming method. Only instruction lines
        # are valid member-level usage evidence.
        instruction_line = bool(re.match(r'^\d+:', line))
        dynamic_match = re.search(r'\binvokedynamic\b.*//\s+InvokeDynamic\s+#(\d+):', line)
        if dynamic_match and instruction_line:
            for target in bootstrap_targets.get(int(dynamic_match.group(1)), []):
                descriptor = target.get('descriptor') or ''
                references['method_refs'].append({
                    'owner': target.get('owner') or '',
                    'name': target.get('name') or '',
                    'descriptor': descriptor,
                    'signature': _method_descriptor_to_lookup_signature(descriptor),
                    'consumer_method': current_member,
                    'consumer_signature': current_signature,
                    'reference_kind': 'invokedynamic_method_handle',
                })
                references['class_refs'].add(target.get('owner') or '')
        method_match = method_pattern.search(line)
        if method_match and instruction_line:
            owner = method_match.group(1).replace('/', '.').replace('$', '.')
            method_name = method_match.group(2) or method_match.group(3) or ''
            descriptor = method_match.group(4).strip()
            references['method_refs'].append({
                'owner': owner,
                'name': method_name,
                'descriptor': descriptor,
                'signature': _method_descriptor_to_lookup_signature(descriptor),
                'consumer_method': current_member,
                'consumer_signature': current_signature,
            })
            references['class_refs'].add(owner)
            continue
        field_match = field_pattern.search(line)
        if field_match and instruction_line:
            owner = field_match.group(1).replace('/', '.').replace('$', '.')
            descriptor = field_match.group(3).strip()
            references['field_refs'].append({
                'owner': owner,
                'name': field_match.group(2),
                'descriptor': descriptor,
                'signature': _field_descriptor_to_lookup_signature(descriptor),
                'consumer_method': current_member,
                'consumer_signature': current_signature,
            })
            references['class_refs'].add(owner)
            continue
        class_match = class_pattern.search(line)
        if class_match:
            references['class_refs'].add(class_match.group(1).replace('/', '.').replace('$', '.'))
        if line.startswith('descriptor:'):
            descriptor = line.split(':', 1)[1].strip()
            for match in descriptor_pattern.findall(descriptor):
                references['class_refs'].add(match.replace('/', '.').replace('$', '.'))
    for item in parse_javap_indirect_references(text, class_binary_name):
        kind = item.get('kind')
        owner = item.get('owner') or ''
        references['class_refs'].add(owner)
        if kind == 'class':
            continue
        if kind == 'field':
            references['field_refs'].append({
                'owner': owner, 'name': item.get('name') or '', 'descriptor': '',
                'signature': '', 'consumer_method': item.get('consumer_method') or '',
                'consumer_signature': item.get('consumer_signature') or '',
                'reference_kind': item.get('reference_kind'),
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
        })
    references['class_refs'] = sorted(references['class_refs'])
    return references


def _load_runtime_dependency_class_references(
    catalog, coord, jar_path, class_binary_name, multi_release_version=None
):
    cache = catalog.setdefault('_bytecode_reference_cache', {})
    cache_key = (coord, jar_path, class_binary_name, multi_release_version)
    if cache_key in cache:
        return cache[cache_key]
    text = _run_javap_bytecode_dump(
        jar_path, class_binary_name, multi_release_version=multi_release_version
    )
    if not text:
        cache[cache_key] = None
        return None
    parsed = _parse_javap_bytecode_references(text, class_binary_name)
    cache[cache_key] = parsed
    return parsed


def _match_runtime_dependency_references(api_row, references):
    references = references or {}
    owner, member_name, symbol_kind = _extract_target_owner_and_member(api_row)
    if not owner:
        return []
    target_signature = str(api_row.get('api_signature') or '').strip()
    target_lookup_signature = normalize_signature_for_lookup(target_signature) or target_signature

    if symbol_kind == 'class' or str(api_row.get('analysis_scope') or '').strip() == 'class_usage':
        if owner in set(references.get('class_refs') or []):
            return [{
                'evidence_type': 'bytecode_class_reference',
                'target_display': owner,
                'consumer_method': '<class>',
                'consumer_signature': '',
            }]
        return []

    if symbol_kind in {'method', 'constructor'}:
        matches = []
        for item in references.get('method_refs') or []:
            if item.get('owner') != owner or item.get('name') != member_name:
                continue
            if target_lookup_signature:
                if item.get('reference_kind', '').startswith('reflection_') and not item.get('signature_resolved'):
                    continue
                if item.get('signature') and item.get('signature') != target_lookup_signature:
                    continue
            matches.append({
                'evidence_type': (
                    'bytecode_invokedynamic_method_reference'
                    if item.get('reference_kind') == 'invokedynamic_method_handle'
                    else 'bytecode_reflection_method_invocation'
                    if item.get('reference_kind') in {'reflection_method', 'reflection_constructor'}
                    else ('bytecode_method_invocation' if symbol_kind == 'method' else 'bytecode_constructor_invocation')
                ),
                'target_display': f"{owner}.{member_name}{item.get('signature') or ''}",
                'consumer_method': item.get('consumer_method') or '<unknown>',
                'consumer_signature': item.get('consumer_signature') or '',
            })
        return _dedupe_runtime_matches(matches)

    if symbol_kind == 'field':
        matches = []
        for item in references.get('field_refs') or []:
            if item.get('owner') != owner or item.get('name') != member_name:
                continue
            matches.append({
                'evidence_type': (
                    'bytecode_reflection_field_access'
                    if item.get('reference_kind') == 'reflection_field'
                    else 'bytecode_field_access'
                ),
                'target_display': f"{owner}.{member_name}",
                'consumer_method': item.get('consumer_method') or '<unknown>',
                'consumer_signature': item.get('consumer_signature') or '',
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
        )
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(item)
    return unique


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
    cached_results = catalog.get('_packaged_api_scan_results') or {}
    identity_key = build_api_identity_key(api_row)
    if identity_key in cached_results:
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
        return {'status': 'unavailable', 'reason': 'RUNTIME_DEPENDENCY_JARS_UNAVAILABLE'}

    owner, member_name, _symbol_kind = _extract_target_owner_and_member(api_row)
    owner_internal_name = str(owner or '').replace('.', '/')
    if not owner_internal_name:
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
        if coord == str(api_row.get('coord') or '').strip():
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
                    if not _runtime_prefilter_owner_candidates(
                        [(owner, owner_internal_name.encode('utf-8'), owner.encode('utf-8'))],
                        data,
                        {owner: [api_row]},
                    ):
                        continue
                    class_binary_name = logical_name[:-6].replace('/', '.')
                    references = _load_runtime_dependency_class_references(
                        catalog, coord, jar_path, class_binary_name,
                        multi_release_version=selected_version,
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
                        hits.append({
                            'coord': coord,
                            'jar_path': jar_path,
                            'class_fqcn': class_binary_name.replace('$', '.'),
                            'consumer_method': matched.get('consumer_method') or '<unknown>',
                            'consumer_signature': matched.get('consumer_signature') or '',
                            'evidence_type': matched.get('evidence_type') or 'bytecode_reference',
                            'target_display': matched.get('target_display') or owner,
                            'class_entry': entry,
                            'multi_release_version': selected_version,
                        })
        except Exception as exc:
            scan_failures.append({
                'reason': 'BYTECODE_SCAN_FAILED', 'coord': coord,
                'jar_path': jar_path, 'error': str(exc),
            })
            continue
    if hits:
        unique_hits = []
        seen_hits = set()
        for hit in hits:
            identity = tuple(hit.get(key) for key in (
                'coord', 'class_fqcn', 'consumer_method', 'consumer_signature',
                'evidence_type', 'target_display', 'multi_release_version',
            ))
            if identity not in seen_hits:
                seen_hits.add(identity)
                unique_hits.append(hit)
        return {
            'status': 'hit', 'hits': unique_hits, 'scan_failures': scan_failures,
            'scanned_classes': scanned_classes, 'visited_classes': visited_classes,
        }
    if multi_release_seen and not multi_release_target_resolved:
        return {
            'status': 'unavailable', 'reason': 'MULTI_RELEASE_TARGET_JDK_UNKNOWN',
            'scan_failures': scan_failures, 'scanned_classes': scanned_classes,
            'visited_classes': visited_classes,
        }
    catalog_status = str(catalog.get('status') or '').strip()
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
        return {}
    existing = catalog.setdefault('_packaged_api_scan_results', {})
    api_rows = [dict(row or {}) for row in (api_rows or []) if (row or {}).get('api_name')]
    missing_rows = [
        row for row in api_rows
        if build_api_identity_key(row) not in existing
    ]
    if not missing_rows:
        return existing

    target_rows_by_owner = defaultdict(list)
    owner_internal_names = {}
    for row in missing_rows:
        key = build_api_identity_key(row)
        owner, _member_name, _symbol_kind = _extract_target_owner_and_member(row)
        if not owner:
            existing[key] = {
                'status': 'unavailable',
                'reason': 'BYTECODE_TARGET_UNRESOLVED',
                'scan_failures': [],
                'scanned_classes': 0,
                'visited_classes': 0,
            }
            continue
        target_rows_by_owner[owner].append(row)
        owner_internal_names[owner] = owner.replace('.', '/')

    if not target_rows_by_owner:
        return existing

    by_coord = catalog.get('by_coord') or {}
    catalog_entries = list(catalog.get('entries') or [
        ({'coord': coord, **item} if not item.get('coord') else item)
        for coord, item in by_coord.items()
    ])

    scan_failures = []
    candidate_failures_by_key = defaultdict(list)
    hits_by_key = defaultdict(list)
    scanned_classes = 0
    visited_classes = 0
    multi_release_seen = False
    multi_release_target_resolved = False
    target_jdk = catalog.get('target_jdk')
    started_at = time.perf_counter()
    progress_interval = suggest_log_interval(len(catalog_entries), target_updates=8, minimum=1)

    if not catalog_entries:
        for row in missing_rows:
            key = build_api_identity_key(row)
            existing.setdefault(key, {
                'status': 'unavailable',
                'reason': 'RUNTIME_DEPENDENCY_JARS_UNAVAILABLE',
                'scan_failures': [],
                'scanned_classes': 0,
                'visited_classes': 0,
            })
        return existing

    emit_progress(
        "step5",
        "bytecode-scan",
        f"开始批量扫描运行时依赖字节码，依赖数={len(catalog_entries)}，API数={len(missing_rows)}",
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

    for idx, item in enumerate(catalog_entries, 1):
        coord = str(item.get('coord') or '').strip()
        jar_path = str(item.get('jar_path') or '').strip()
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
            scan_failures.append({
                'reason': 'RUNTIME_DEPENDENCY_JAR_MISSING',
                'coord': coord,
                'jar_path': jar_path,
            })
            continue
        try:
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
                        if internal_bytes in data or dotted_bytes in data
                    ]
                    if candidate_owners:
                        candidate_owner_set = set(candidate_owners)
                        candidate_owners = _runtime_prefilter_owner_candidates(
                            [
                                (owner, internal_bytes, dotted_bytes)
                                for owner, internal_bytes, dotted_bytes in owner_candidates
                                if owner in candidate_owner_set
                            ],
                            data,
                            target_rows_by_owner,
                        )
                    if not candidate_owners:
                        continue
                    class_binary_name = logical_name[:-6].replace('/', '.')
                    references = _load_runtime_dependency_class_references(
                        catalog, coord, jar_path, class_binary_name,
                        multi_release_version=selected_version,
                    )
                    if references is None:
                        failure = {
                            'reason': 'BYTECODE_JAVAP_FAILED',
                            'coord': coord,
                            'jar_path': jar_path,
                            'class_binary_name': class_binary_name,
                            'multi_release_version': selected_version,
                        }
                        for owner in set(candidate_owners):
                            for api_row in target_rows_by_owner.get(owner, []):
                                candidate_failures_by_key[build_api_identity_key(api_row)].append(failure)
                        continue
                    scanned_classes += 1
                    referenced_owners = set(references.get('class_refs') or [])
                    referenced_owners.update(
                        item.get('owner') for item in references.get('method_refs') or []
                    )
                    referenced_owners.update(
                        item.get('owner') for item in references.get('field_refs') or []
                    )
                    for owner in set(candidate_owners) & {item for item in referenced_owners if item}:
                        for api_row in target_rows_by_owner.get(owner, []):
                            if coord == str(api_row.get('coord') or '').strip():
                                continue
                            matches = _match_runtime_dependency_references(api_row, references)
                            if not matches:
                                continue
                            key = build_api_identity_key(api_row)
                            for matched in matches:
                                hits_by_key[key].append({
                                    'coord': coord,
                                    'jar_path': jar_path,
                                    'class_fqcn': class_binary_name.replace('$', '.'),
                                    'consumer_method': matched.get('consumer_method') or '<unknown>',
                                    'consumer_signature': matched.get('consumer_signature') or '',
                                    'evidence_type': matched.get('evidence_type') or 'bytecode_reference',
                                    'target_display': matched.get('target_display') or owner,
                                    'class_entry': entry,
                                    'multi_release_version': selected_version,
                                })
        except Exception as exc:
            scan_failures.append({
                'reason': 'BYTECODE_SCAN_FAILED',
                'coord': coord,
                'jar_path': jar_path,
                'error': str(exc),
            })

    catalog_status = str(catalog.get('status') or '').strip()
    for row in missing_rows:
        key = build_api_identity_key(row)
        if key in existing and existing[key].get('status') == 'unavailable':
            continue
        hits = hits_by_key.get(key) or []
        api_scan_failures = scan_failures + list(candidate_failures_by_key.get(key) or [])
        if hits:
            unique_hits = []
            seen_hits = set()
            for hit in hits:
                identity = tuple(hit.get(field) for field in (
                    'coord', 'class_fqcn', 'consumer_method', 'consumer_signature',
                    'evidence_type', 'target_display', 'multi_release_version',
                ))
                if identity in seen_hits:
                    continue
                seen_hits.add(identity)
                unique_hits.append(hit)
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
            f"visited_classes={visited_classes}，javap_classes={scanned_classes}，"
            f"hit_apis={sum(1 for key in hits_by_key if hits_by_key.get(key))}"
        ),
        current=len(catalog_entries),
        total=len(catalog_entries),
        elapsed=time.perf_counter() - started_at,
    )
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
    display_method = normalized_class.rsplit('.', 1)[-1] if method_name == '<init>' else method_name
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
        owner_type='dependency',
        owner_coord=str(coord or ''),
        module='',
        source_root='',
        language='bytecode',
        is_test=False,
    )


def _add_runtime_dependency_caller_edge(graph, lookup_key, coord, jar_path, class_fqcn, matched):
    methods_by_id = getattr(graph, 'methods_by_id', {}) or {}
    reverse_edges = getattr(graph, 'reverse_edges', {}) or {}
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
        owner_type='dependency',
        owner_coord=str(coord or ''),
        module='',
        is_test=False,
        callee_param_types=[],
    )
    for key in (lookup_key, edge.callee_simple_key):
        bucket = reverse_edges.setdefault(key, [])
        identity = (edge.caller_symbol_id, edge.callee_key, edge.evidence_type)
        if any((old.caller_symbol_id, old.callee_key, old.evidence_type) == identity for old in bucket):
            continue
        bucket.append(edge)
    graph.methods_by_id = methods_by_id
    graph.reverse_edges = reverse_edges
    return edge


def _ensure_runtime_dependency_callers_for_key(graph, lookup_key):
    if not graph:
        return {'expanded': False, 'edges_added': 0, 'javap_classes': 0, 'visited_classes': 0}
    parsed = _parse_runtime_method_lookup_key(lookup_key)
    if not parsed:
        return {'expanded': False, 'edges_added': 0, 'javap_classes': 0, 'visited_classes': 0}
    expanded = getattr(graph, '_runtime_dependency_caller_expanded', None)
    if expanded is None:
        expanded = set()
        setattr(graph, '_runtime_dependency_caller_expanded', expanded)
    if lookup_key in expanded:
        return {'expanded': False, 'edges_added': 0, 'javap_classes': 0, 'visited_classes': 0}
    expanded.add(lookup_key)

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
    owner_internal = owner.replace('.', '/')
    target_rows_by_owner = {owner: [api_row]}
    visited_classes = 0
    javap_classes = 0
    edges_added = 0
    target_jdk = catalog.get('target_jdk')
    for item in catalog_entries:
        coord = str(item.get('coord') or '').strip()
        if not coord or coord == '__business__':
            continue
        jar_path = str(item.get('jar_path') or '').strip()
        if not jar_path or not os.path.exists(jar_path):
            continue
        try:
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
                    if not _runtime_prefilter_owner_candidates(
                        [(owner, owner_internal.encode('utf-8'), owner.encode('utf-8'))],
                        data,
                        target_rows_by_owner,
                    ):
                        continue
                    class_binary_name = logical_name[:-6].replace('/', '.')
                    references = _load_runtime_dependency_class_references(
                        catalog, coord, jar_path, class_binary_name,
                        multi_release_version=selected_version,
                    )
                    javap_classes += 1
                    if references is None:
                        continue
                    matches = _match_runtime_dependency_references(api_row, references)
                    for matched in matches:
                        _add_runtime_dependency_caller_edge(
                            graph, lookup_key, coord, jar_path,
                            class_binary_name.replace('$', '.'),
                            matched,
                        )
                        edges_added += 1
        except Exception:
            continue
    return {
        'expanded': True,
        'edges_added': edges_added,
        'javap_classes': javap_classes,
        'visited_classes': visited_classes,
    }


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


def _find_business_callers_for_packaged_hit(hit, graph, max_depth=4):
    if not graph:
        return []
    reverse_edges = getattr(graph, 'reverse_edges', {}) or {}
    methods_by_id = getattr(graph, 'methods_by_id', {}) or {}
    if not reverse_edges:
        return []
    if not any(
        getattr(method_def, 'owner_type', '') == 'business' and not getattr(method_def, 'is_test', False)
        for method_def in methods_by_id.values()
    ):
        return []
    queue = []
    for key in _packaged_hit_consumer_lookup_keys(hit):
        queue.append((key, []))
    visited = set()
    paths = []
    while queue:
        current_key, path = queue.pop(0)
        if current_key in visited or len(path) >= max_depth:
            continue
        visited.add(current_key)
        _ensure_runtime_dependency_callers_for_key(graph, current_key)
        for edge in sorted(reverse_edges.get(current_key, []) or [], key=stable_edge_sort_key):
            method_def = methods_by_id.get(getattr(edge, 'caller_symbol_id', ''))
            if method_def is None:
                continue
            next_path = path + [edge]
            if getattr(method_def, 'owner_type', '') == 'business' and not getattr(method_def, 'is_test', False):
                paths.append((method_def, next_path))
                continue
            caller_key = getattr(method_def, 'qualified_key', '') or getattr(edge, 'caller_qualified_key', '')
            if caller_key:
                for variant in _method_lookup_key_variants(caller_key):
                    queue.append((variant, next_path))
    return paths


def _build_packaged_dependency_hit_result(result, hits, graph=None):
    business_hits = [item for item in hits if item.get('coord') == '__business__']
    bridged_hits = []
    for item in hits:
        if item.get('coord') == '__business__':
            continue
        for business_entry, bridge_edges in _find_business_callers_for_packaged_hit(item, graph):
            bridged_hits.append({
                'hit': item,
                'business_entry': business_entry,
                'bridge_edges': bridge_edges,
            })
    dependency_chain = []
    for item in hits:
        coord = str(item.get('coord') or '').strip()
        if coord and coord not in dependency_chain:
            dependency_chain.append(coord)
    for bridged in bridged_hits:
        for edge in bridged.get('bridge_edges') or []:
            coord = str(getattr(edge, 'owner_coord', '') or '').strip()
            if coord and coord != '__business__' and coord not in dependency_chain:
                dependency_chain.append(coord)
    has_business_path = bool(business_hits or bridged_hits)
    result.analysis_status = 'reachable' if has_business_path else 'uncertain'
    result.is_reachable = True if has_business_path else None
    result.reason_code = 'BUSINESS_ARTIFACT_BYTECODE_USAGE' if has_business_path else 'PACKAGED_DEPENDENCY_BYTECODE_USAGE'
    result.reachable_note = (
        '已在当前最终制品中确认业务 class 可到达目标符号引用'
        if has_business_path else
        '已在当前最终制品的运行时依赖字节码中确认对目标符号的稳定引用，'
        '但当前尚未证明这些依赖是否回到系统业务入口'
    )
    result.dependency_chain_coords = dependency_chain
    ordered_hits = business_hits + [item for item in hits if item not in business_hits]
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
            'confidence': 'high',
            'file': hit.get('jar_path', ''),
            'line': 0,
            'owner_coord': hit.get('coord', ''),
            'consumer_class': hit.get('class_fqcn', ''),
            'consumer_method': consumer_member,
            'consumer_signature': consumer_signature,
        }]
        result.evidence_paths.append(evidence)
        result.path_details.append({
            'path_status': 'reachable' if hit.get('coord') == '__business__' else 'uncertain',
            'stop_reason': '' if hit.get('coord') == '__business__' else 'BUSINESS_ENTRY_NOT_CONFIRMED',
            'business_entry': consumer_symbol if hit.get('coord') == '__business__' else '',
            'business_reachable': hit.get('coord') == '__business__',
            'consumer_coord': hit.get('coord', ''),
            'consumer_class': hit.get('class_fqcn', ''),
            'consumer_method': consumer_member,
            'consumer_signature': consumer_signature,
            'path_text': path_text,
            'confidence': 1.0,
            'depth': 1,
            'evidence': evidence,
        })
    for bridged in bridged_hits:
        hit = bridged['hit']
        bridge_edges = bridged.get('bridge_edges') or []
        business_entry = bridged.get('business_entry')
        consumer_member = str(hit.get('consumer_method') or '<unknown>')
        consumer_signature = str(hit.get('consumer_signature') or '')
        consumer_symbol = f"{hit.get('class_fqcn')}.{consumer_member}{consumer_signature}"
        consumer_display = f"{hit.get('coord')}:{consumer_symbol}"
        target_display = hit.get('target_display')
        path_nodes = [
            getattr(edge, 'caller_qualified_key', '') or getattr(edge, 'caller_symbol_id', '?')
            for edge in reversed(bridge_edges)
        ]
        path_nodes.append(consumer_display)
        path_nodes.append(target_display)
        path_text = " -> ".join(str(item) for item in path_nodes if item)
        result.call_paths.append(path_text)
        evidence = []
        for edge in reversed(bridge_edges):
            evidence.append({
                'caller_symbol': getattr(edge, 'caller_qualified_key', '') or getattr(edge, 'caller_symbol_id', '?'),
                'callee_key': getattr(edge, 'callee_key', ''),
                'evidence_type': getattr(edge, 'evidence_type', ''),
                'confidence': getattr(edge, 'confidence', 'high'),
                'file': getattr(edge, 'file', ''),
                'line': getattr(edge, 'line', 0),
                'owner_coord': getattr(edge, 'owner_coord', ''),
            })
        evidence.append({
            'caller_symbol': consumer_display,
            'callee_key': target_display,
            'evidence_type': hit.get('evidence_type'),
            'confidence': 'high',
            'file': hit.get('jar_path', ''),
            'line': 0,
            'owner_coord': hit.get('coord', ''),
            'consumer_class': hit.get('class_fqcn', ''),
            'consumer_method': consumer_member,
            'consumer_signature': consumer_signature,
        })
        result.evidence_paths.append(evidence)
        result.path_details.append({
            'path_status': 'reachable',
            'stop_reason': '',
            'business_entry': getattr(business_entry, 'qualified_key', '') or path_nodes[0],
            'business_reachable': True,
            'consumer_coord': hit.get('coord', ''),
            'consumer_class': hit.get('class_fqcn', ''),
            'consumer_method': consumer_member,
            'consumer_signature': consumer_signature,
            'path_text': path_text,
            'confidence': 1.0,
            'depth': len(evidence),
            'evidence': evidence,
        })
    reachable_details = [item for item in result.path_details if item.get('path_status') == 'reachable']
    if reachable_details:
        result.direct_callers = len(reachable_details)
        result.business_reach_depth = min(int(item.get('depth') or 1) for item in reachable_details)
    result.verification_commands = [
        '如需继续证明是否回到系统源码，请补充 dependency_source_dirs 或检查业务对这些依赖的入口调用',
        '优先审查命中的无源码依赖及其对外暴露入口'
    ]
    return result


def _build_packaged_dependency_not_found_result(result):
    result.analysis_status = 'not_found_in_static_analysis'
    result.is_reachable = False
    result.reason_code = 'NO_STATIC_PATH'
    result.reachable_note = (
        '已对当前最终制品的业务 class 和运行时依赖 jar 执行字节码扫描，未发现目标符号引用。'
        '这不代表运行时一定安全。'
    )
    result.verification_commands = [
        '检查是否存在反射、字符串、配置文件或 SPI 间接引用',
        '必要时结合运行验证确认该依赖变更是否会在实际路径触发'
    ]
    return result


def _build_packaged_dependency_incomplete_result(result, scan_result):
    result.analysis_status = 'not_analyzed'
    result.is_reachable = None
    result.reason_code = str((scan_result or {}).get('reason') or 'ANALYSIS_INCOMPLETE').strip() or 'ANALYSIS_INCOMPLETE'
    result.reachable_note = '最终制品字节码分析未完整覆盖，当前无法把未命中解释为安全'
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
    result.analysis_status = 'uncertain'
    result.is_reachable = None
    result.reason_code = str(findings[0].get('reason_code') or 'INDIRECT_TARGET_REFERENCE')
    result.reachable_note = (
        '已发现与变更 API 相关的间接引用证据，但当前证据不能唯一证明该路径触达并执行目标 API'
    )
    result.call_paths = []
    result.evidence_paths = []
    result.path_details = []
    for finding in findings:
        caller = str(finding.get('caller_symbol') or 'indirect-reference')
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
            'stop_reason': finding.get('reason_code') or result.reason_code,
            'business_reachable': None,
            'consumer_coord': finding.get('owner_coord') or '',
            'consumer_class': '', 'consumer_method': caller,
            'consumer_signature': '', 'path_text': path_text,
            'confidence': 0.6, 'depth': 1, 'evidence': evidence,
        })
    result.verification_commands = [
        '核对间接引用中的动态类名、成员名和参数类型',
        '结合实际配置或运行测试确认目标 API 是否会被调用',
    ]
    return result


def _capability_coverage_for_api(api_row, graph):
    coverage = dict(getattr(graph, 'indirect_analysis_coverage', {}) or {})
    per_api = dict(coverage.get('by_api') or {})
    item = dict(per_api.get(indirect_api_key(api_row)) or {})
    if not item:
        return coverage
    symbol_kind = get_symbol_kind(api_row)
    return {
        'status': item.get('status') or 'not_applicable',
        'reason_codes': list(item.get('reason_codes') or []),
        'analyzers': dict(item.get('matrix') or {}),
        'matrix': {symbol_kind: dict(item.get('matrix') or {})},
    }


def _build_indirect_coverage_incomplete_result(result):
    coverage = dict(result.capability_coverage or {})
    reasons = list(coverage.get('reason_codes') or [])
    result.analysis_status = 'not_analyzed'
    result.is_reachable = None
    result.reason_code = 'INDIRECT_ANALYSIS_INCOMPLETE'
    result.reachable_note = (
        '目标 API 存在适用但未完整覆盖的间接调用机制，不能把静态未命中解释为未发现引用。'
        + (f"未完整能力：{', '.join(reasons)}" if reasons else '')
    )
    result.verification_commands = [
        '查看 alerts.csv 的 coverage_details，定位 partial/insufficient 的间接分析能力',
        '补充对应源码、制品或框架证据后重新运行 Step 5',
    ]
    return result


def critical_parser_fallback_reasons(graph_stats):
    graph_stats = graph_stats or {}
    parser_fallback_reasons = graph_stats.get('parser_fallback_reasons') or {}
    return {
        key: value
        for key, value in parser_fallback_reasons.items()
        if key not in NON_BLOCKING_PARSER_FALLBACK_REASONS
    }


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
    return {
        'caller_symbol': caller_key,
        'callee_key': getattr(edge, 'callee_key', '?'),
        'confidence': getattr(edge, 'confidence', '?'),
        'evidence_type': getattr(edge, 'evidence_type', '?'),
        'file': getattr(edge, 'file', ''),
        'line': getattr(edge, 'line', 0),
        'owner_coord': getattr(edge, 'owner_coord', ''),
        'module': getattr(edge, 'module', ''),
    }


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

    # 规则 2: 接口无实现（动态代理）- 通用情况
    if class_meta.get('kind') == 'interface':
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
    result = TraceResult(
        api_name=api_name,
        api_simple=api_row.get('api_simple', ''),
        api_signature=api_row.get('api_signature', ''),
        symbol_kind=get_symbol_kind(api_row),
        change_type=api_row.get('change_type', ''),
        coord=api_row.get('coord', ''),
        severity=api_row.get('severity', ''),
        confirmed=api_row.get('confirmed') == 'true',
        source=api_row.get('source', ''),
        analysis_scope=api_row.get('analysis_scope', 'api'),
        analysis_status='not_analyzed',
        direct_callers=0,
        is_reachable=False,
        reachable_note='',
        business_reach_depth=0,
        dependency_chain_coords=[],
        call_paths=[],
        evidence_paths=[],
        reason_code='',
        verification_commands=[],
        hops=[],
        confidence_score=1.0,
        critical_nodes_hit=[],
        match_provenance='',
        match_tier=-1,
        capability_coverage=_capability_coverage_for_api(api_row, graph),
    )
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
            if any(item.get('coord') == '__business__' for item in scan_hits):
                packaged_dependency_result = _build_packaged_dependency_hit_result(result, scan_hits, graph)
                _debug_trace_result('trace_api_result', packaged_dependency_result)
                return packaged_dependency_result
            artifact_dependency_hits = scan_hits
        if scan_status == 'miss':
            artifact_scan_miss = True
        if scan_status == 'unavailable':
            artifact_scan_incomplete = scan_result

    direct_usage_result = _try_build_direct_usage_result(api_row, result, graph)
    if direct_usage_result is not None:
        if artifact_scan_miss:
            _apply_source_artifact_miss(direct_usage_result, graph, (
                '源码图存在目标调用，但与当前最终制品的完整字节码扫描结果冲突；'
                '可能是源码与制品 revision/profile 不一致，当前不能确认影响'
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
                    'confidence': 'high',
                    'file': hit.get('jar_path', ''),
                    'line': 0,
                }])
                coord = str(hit.get('coord') or '').strip()
                if coord and coord not in direct_usage_result.dependency_chain_coords:
                    direct_usage_result.dependency_chain_coords.append(coord)
        _debug_trace_result('trace_api_result', direct_usage_result)
        return direct_usage_result

    # 类级目标没有正式的方法级反向追踪主路径；若最终制品已稳定命中字节码引用，
    # 仍应沿用打包依赖命中结论，而不是被后续 CLASS_USAGE_ONLY 覆盖。
    if artifact_dependency_hits and (result.analysis_scope == 'class_usage' or result.symbol_kind == 'class'):
        packaged_dependency_result = _build_packaged_dependency_hit_result(result, artifact_dependency_hits, graph)
        _debug_trace_result('trace_api_result', packaged_dependency_result)
        return packaged_dependency_result

    if artifact_scan_incomplete and needs_bridge and not has_dependency_source_mapping:
        built = _build_packaged_dependency_incomplete_result(result, artifact_scan_incomplete)
        _debug_trace_result('trace_api_result', built)
        return built

    # 类级fallback：不追踪
    if result.analysis_scope == 'class_usage':
        result.analysis_status = 'not_analyzed'
        result.reason_code = 'CLASS_USAGE_ONLY'
        result.reachable_note = '类级候选只能证明类型使用，无法确认具体API影响'
        result.verification_commands = [
            f"审查 {api_row.get('matched_class')} 的具体使用场景"
        ]
        _debug_trace_result('trace_api_result', result)
        return result

    if not get_symbol_kind(api_row):
        result.analysis_status = 'not_analyzed'
        result.reason_code = 'MISSING_SYMBOL_KIND'
        result.reachable_note = 'Step 5 需要 symbol_kind 才能判断当前变更是方法、字段、类还是构造器'
        result.verification_commands = [
            '回到 Step 4 重新生成包含 symbol_kind 的变更 API 清单',
            '确认 all_changed_apis.csv 每一行都明确标注 symbol_kind',
        ]
        _debug_trace_result('trace_api_result', result)
        return result

    if method_api_requires_signature(api_row) and not has_precise_api_signature(api_row):
        result.analysis_status = 'not_analyzed'
        result.reason_code = 'MISSING_API_SIGNATURE'
        result.reachable_note = '方法级调用链分析要求精确参数签名；当前输入缺少 api_signature，无法区分重载方法'
        result.verification_commands = [
            '回到 Step 4 重新生成包含 api_signature 的变更 API 清单',
            '确认变更方法的参数类型已被精确提取',
        ]
        _debug_trace_result('trace_api_result', result)
        return result

    # 构建目标键
    target_key_groups = build_api_target_key_groups(api_row, graph=graph, type_metadata=type_metadata)
    target_keys = flatten_key_groups(target_key_groups)
    if not target_keys:
        result.analysis_status = 'not_analyzed'
        result.reason_code = 'NO_TARGET_KEYS'
        result.reachable_note = '无法从输入提取可追踪目标'
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
    visited = {}  # (symbol_id, provenance_family) -> best(cost, -confidence)

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
        incoming_edges = sorted(reverse_edges.get(current_key, []), key=stable_edge_sort_key)

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
            path_score = (new_cost, -new_confidence)
            existing_score = visited.get(visited_key)
            if existing_score is not None and path_score >= existing_score:
                _step5_debug(
                    'trace_pruned',
                    'skipped path because an equal or better path already exists',
                    api_name=api_name,
                    current_key=current_key,
                    caller=method_def.qualified_key,
                    existing_score=existing_score,
                    candidate_score=path_score,
                )
                continue  # 已有更优路径，跳过
            visited[visited_key] = path_score

            # 必须记录“到达该节点后的总代价”，否则后续更优路径会被错误剪枝。
            # 这里同时保留 provenance_family，避免 exact / polymorphic / fallback 互相误剪枝。

            # 检查关键节点
            critical_node = None
            framework_entries = (
                getattr(graph, 'framework_entry_symbols', {}) or {}
            ).get(method_def.symbol_id) or []
            if framework_entries:
                first_framework_entry = framework_entries[0]
                critical_node = {
                    'type': 'system_code_touched',
                    'method': method_def.qualified_key,
                    'file': method_def.file,
                    'line': method_def.line,
                    'framework_edge_kind': first_framework_entry.get('edge_kind'),
                    'framework_adapter': first_framework_entry.get('adapter'),
                }
            elif is_system_code_touched(method_def, type_metadata):
                critical_node = {
                    'type': 'system_code_touched',
                    'method': method_def.qualified_key,
                    'file': method_def.file,
                    'line': method_def.line
                }
            elif is_framework_boundary(method_def, type_metadata):
                critical_node = {
                    'type': 'framework_boundary',
                    'method': method_def.qualified_key,
                    'reason': '动态代理或框架注入'
                }

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
                        'method': method_def.qualified_key,
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
    )

    # 选择最优结果
    if reachable_candidates:
        best = select_best_candidate(reachable_candidates)
        if artifact_scan_miss:
            built = build_reachable_result(result, best, graph)
            _apply_source_artifact_miss(built, graph, (
                '源码图存在可达调用链，但当前最终制品的完整字节码扫描未发现对应引用；'
                '可能是源码与制品 revision/profile 不一致，当前不能确认影响'
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
        if dependency_removed:
            packaged_dependency_result.reason_code = 'RUNTIME_DEPENDENCY_USES_REMOVED_API'
            packaged_dependency_result.reachable_note = (
                '已确认当前最终制品中的其他运行时依赖字节码仍引用被删除依赖的目标符号；'
                '加载或执行该路径时存在 NoClassDefFoundError/NoSuchMethodError 风险'
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
            built = _build_inlined_constant_result(result)
            _debug_trace_result('trace_api_result', built)
            return built
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
        result.analysis_status = 'not_analyzed'
        result.reason_code = 'ANALYSIS_INCOMPLETE'
        result.reachable_note = '分析不完整，可能需要补充依赖源码映射或调整分析参数'
        result.verification_commands = [
            '检查是否需要补充依赖源码映射',
            '或调整 max_depth 参数重新分析'
        ]
        _debug_trace_result('trace_api_result', result)
        return result

    graph_completeness = assess_graph_completeness(graph_stats)
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
    result.analysis_status = 'not_found_in_static_analysis'
    result.reason_code = 'NO_STATIC_PATH'
    result.reachable_note = (
        '静态分析未找到调用路径。这不代表确定未影响系统。'
        '可能原因：反射调用、动态代理、配置文件引用、测试代码引用等。'
    )
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
    trace_cache.setdefault('overload_signature_index', None)
    trace_cache.setdefault('overload_signature_index_owner', None)
    return trace_cache


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


def build_all_candidate_path_details(reachable, uncertain, not_analyzed, graph):
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
            stop_reason = str(candidate.get('reason') or default_reason)
            final_target = entry.get('method') or stop_reason or '未找到业务入口'
            path_text = format_call_chain(path_edges, final_target) if path_edges else final_target
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
            business_entry = str(entry.get('method') or '') if path_status == 'reachable' else ''
            details.append({
                'path_status': path_status,
                'stop_reason': stop_reason,
                'business_entry': business_entry,
                'business_reachable': path_status == 'reachable',
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


def collect_declared_method_signatures(api_name, graph):
    signatures = set()
    methods_by_id = getattr(graph, 'methods_by_id', {}) or {}
    for method_def in methods_by_id.values():
        if getattr(method_def, 'qualified_key', '') != api_name:
            continue
        for signature in build_method_signature_suffixes(method_def):
            if signature:
                signatures.add(signature)
    return signatures


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
    declared_signatures = collect_declared_method_signatures(api_name, graph)
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
    result.analysis_status = 'not_analyzed'
    result.is_reachable = None
    result.reason_code = 'OVERLOAD_AMBIGUOUS_TARGET'
    overload_signatures = overload_info.get('overload_signatures') or []
    overload_text = ', '.join(overload_signatures[:5])
    result.reachable_note = (
        '目标 API 存在重载，当前仅命中了无签名回退键，'
        f'无法安全确认是否是目标签名 {overload_info.get("api_signature")}'
        + (f'；已知重载：{overload_text}' if overload_text else '')
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
        'method': method_def.qualified_key,
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
    if not matched_lookup_groups:
        _step5_debug(
            'method_lookup_resolution',
            'no lookup groups matched reverse edges',
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


def assess_graph_completeness(graph_stats):
    graph_stats = graph_stats or {}
    reasons = []
    verification = []

    if graph_stats.get('truncated'):
        truncation_reasons = graph_stats.get('truncation_reasons') or []
        reason_text = '图构建被截断'
        if truncation_reasons:
            reason_text = f"{reason_text}（{', '.join(truncation_reasons)}）"
        reasons.append(reason_text)
        verification.append('提高 max_methods 或缩小分析范围后重跑 Step 5')

    parser_fallback_reasons = critical_parser_fallback_reasons(graph_stats)
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

    return {
        'incomplete': bool(reasons),
        'reasons': reasons,
        'verification_commands': verification,
    }


def build_analysis_incomplete_result(result, graph_completeness):
    result.analysis_status = 'not_analyzed'
    result.is_reachable = None
    result.reason_code = 'ANALYSIS_INCOMPLETE'
    reasons = graph_completeness.get('reasons') or []
    if reasons:
        result.reachable_note = f"分析不完整：{'；'.join(reasons)}"
    else:
        result.reachable_note = '分析不完整，当前无法把静态未找到解释为未影响'
    result.verification_commands = (
        graph_completeness.get('verification_commands') or []
    ) + [
        '重新运行 Step 5 后，再判断是否属于 not_found_in_static_analysis'
    ]
    return result


def build_call_graph_limited_symbol_result(result):
    result.analysis_status = 'not_analyzed'
    result.is_reachable = None
    result.reason_code = 'CALL_GRAPH_LIMITATION_SYMBOL_KIND'
    symbol_kind = (result.symbol_kind or 'unknown').strip() or 'unknown'
    result.reachable_note = (
        '当前 Step5 主要基于方法反向调用图；'
        f'对 {symbol_kind} 符号的静态证明能力有限，'
        '当前结果不能解释为静态未找到调用路径'
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
    return (
        (api_row.get('coord') or '').strip(),
        (api_row.get('api_name') or '').strip(),
        (api_row.get('api_signature') or '').strip(),
        (get_symbol_kind(api_row) or '').strip(),
        (api_row.get('change_type') or '').strip(),
    )


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
      4. 添加Object类默认方法
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


def build_method_lookup_key_groups(method_def, type_metadata, graph=None):
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

    # 添加Object类（所有类的最终父类）
    if class_fqcn != 'java.lang.Object':
        append_method_keys('java.lang.Object')

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


def build_reachable_result(result, candidate, graph):
    """构建reachable结果"""
    result.analysis_status = 'reachable'
    result.is_reachable = True
    result.business_reach_depth = candidate['depth']
    result.confidence_score = candidate['confidence']
    result.reason_code = 'SYSTEM_CODE_REACHED'
    result.reachable_note = f"触达系统代码（置信度{candidate['confidence']:.2f}）"

    # 构建调用链
    path_edges = candidate['path']
    entry_point = candidate['entry_point']

    result.call_paths = [
        format_call_chain(path_edges, entry_point['method'])
    ]
    result.direct_callers = 1 if path_edges and getattr(path_edges[0], 'owner_coord', '') == 'BUSINESS' else 0

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

    return result


def build_behavior_changed_result(result, candidate, graph):
    """
    构建行为变更结果（需运行时验证）

    行为变更与签名变更不同：即使找到调用链，也不能直接判定为"已触达系统"，
    因为签名没变不代表运行时行为没变。需要通过运行时测试验证。
    """
    # 注意：change_type == 'BEHAVIOR_CHANGED' 的语义是"需要运行时验证"
    # 即使找到了调用链，analysis_status 应该是 not_analyzed
    result.analysis_status = 'not_analyzed'
    result.is_reachable = None
    result.business_reach_depth = candidate['depth']
    result.confidence_score = candidate['confidence']
    result.reason_code = 'BEHAVIOR_CHANGED_RUNTIME_VERIFICATION'
    result.reachable_note = '找到调用链，但签名未变的情况下行为可能变化，需运行时验证'

    # 构建调用链（用于人工审查）
    path_edges = candidate['path']
    entry_point = candidate['entry_point']

    result.call_paths = [
        format_call_chain(path_edges, entry_point['method'])
    ]
    result.direct_callers = 1 if path_edges and getattr(path_edges[0], 'owner_coord', '') == 'BUSINESS' else 0

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
    _downgrade_reachable_path_details(result, 'not_analyzed', result.reason_code)

    return result


def build_behavior_changed_fallback_simple_result(result, candidate, graph):
    result.analysis_status = 'not_analyzed'
    result.is_reachable = None
    result.business_reach_depth = candidate['depth']
    result.confidence_score = candidate['confidence']
    result.reason_code = 'BEHAVIOR_CHANGED_PRECISE_TARGET_NOT_CONFIRMED'
    result.reachable_note = (
        '找到调用链，但当前命中依赖 fallback_simple 回退；'
        '对于已有完整签名的行为变更，这不足以安全确认目标 API'
    )

    path_edges = candidate['path']
    entry_point = candidate['entry_point']

    result.call_paths = [
        format_call_chain(path_edges, entry_point['method'])
    ]
    result.direct_callers = 1 if path_edges and getattr(path_edges[0], 'owner_coord', '') == 'BUSINESS' else 0

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
    _downgrade_reachable_path_details(result, 'not_analyzed', result.reason_code)
    return result


def build_fallback_simple_unconfirmed_result(result, candidate, graph):
    _ = graph
    result.analysis_status = 'not_analyzed'
    result.is_reachable = None
    result.business_reach_depth = candidate['depth']
    result.confidence_score = candidate['confidence']
    result.reason_code = 'FALLBACK_SIMPLE_PATH_UNCONFIRMED'
    result.reachable_note = (
        '找到候选调用链，但其中依赖 fallback_simple 回退；'
        '当前证据不足以安全确认命中的就是目标 API'
    )

    path_edges = candidate['path']
    entry_point = candidate['entry_point']

    result.call_paths = [
        format_call_chain(path_edges, entry_point['method'])
    ]
    result.direct_callers = 1 if path_edges and getattr(path_edges[0], 'owner_coord', '') == 'BUSINESS' else 0

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
    _downgrade_reachable_path_details(result, 'not_analyzed', result.reason_code)
    return result


def build_internal_only_direct_consumer_result(result, candidate, graph):
    _ = graph
    result.analysis_status = 'not_analyzed'
    result.is_reachable = None
    result.business_reach_depth = candidate['depth']
    result.confidence_score = candidate['confidence']
    result.reason_code = 'INTERNAL_ONLY_DIRECT_CONSUMER'
    result.reachable_note = (
        '找到候选调用链，但变更 API 的直接调用者仍位于同一依赖内部；'
        '当前证据不足以证明外部消费者真实依赖了这个变更 API'
    )

    path_edges = candidate['path']
    entry_point = candidate['entry_point']

    result.call_paths = [
        format_call_chain(path_edges, entry_point['method'])
    ]
    result.direct_callers = 1 if path_edges and getattr(path_edges[0], 'owner_coord', '') == 'BUSINESS' else 0

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
    _downgrade_reachable_path_details(result, 'not_analyzed', result.reason_code)
    return result


def build_uncertain_result(result, candidate):
    """构建uncertain结果"""
    result.analysis_status = 'uncertain'
    result.is_reachable = None
    result.confidence_score = candidate['confidence']
    result.reason_code = candidate['reason']
    result.reachable_note = f"链路置信度{candidate['confidence']:.2f}，需人工确认"

    path_edges = candidate['path']

    result.call_paths = [
        format_call_chain(path_edges, "未找到业务入口")
    ]
    result.direct_callers = 1 if path_edges and getattr(path_edges[0], 'owner_coord', '') == 'BUSINESS' else 0

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

    return result


def build_not_analyzed_result(result, candidate):
    """构建not_analyzed结果"""
    result.analysis_status = 'not_analyzed'
    result.is_reachable = None
    result.reason_code = candidate.get('reason', 'UNKNOWN')
    result.reachable_note = candidate.get('boundary', {}).get('reason', '无法静态分析')

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
        result.direct_callers = 1 if getattr(path_edges[0], 'owner_coord', '') == 'BUSINESS' else 0

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

    return result


def build_missing_dependency_source_mapping_result(result):
    """构建缺少依赖源码映射导致的 not_analyzed 结果"""
    result.analysis_status = 'not_analyzed'
    result.is_reachable = None
    result.reason_code = 'DEPENDENCY_SOURCE_MAPPING_MISSING'
    result.reachable_note = '需要可用的依赖源码映射才能完成分析，当前分析能力受限'
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

    parts = [
        str(getattr(edge, 'caller_qualified_key', '') or getattr(edge, 'caller_symbol_id', '?'))
        for edge in reversed(path_edges)
    ]
    # path_edges[0] 是变更符号的直接消费边，其 callee 才是链路终点。
    changed_target = str(getattr(path_edges[0], 'callee_key', '') or final_target)
    parts.append(changed_target)

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

    results = []
    trace_cache = ensure_trace_cache()
    total = len(all_apis or [])
    progress_interval = suggest_log_interval(total, target_updates=12, minimum=1)
    started_at = time.perf_counter()
    status_counts = {
        'reachable': 0,
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
        _build_packaged_runtime_dependency_scan_cache(all_apis, graph)

    for idx, api_row in enumerate(all_apis, 1):
        api_name = api_row.get('api_name', '')
        if not api_name:
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

        results.append(result)
        status = result.analysis_status or 'unknown'
        status_counts[status] = status_counts.get(status, 0) + 1
        if should_log_progress(idx, total, progress_interval):
            emit_progress(
                "step5",
                "trace",
                (
                    "追踪进度更新，"
                    f"reachable={status_counts.get('reachable', 0)}，"
                    f"uncertain={status_counts.get('uncertain', 0)}，"
                    f"not_analyzed={status_counts.get('not_analyzed', 0)}，"
                    f"not_found={status_counts.get('not_found_in_static_analysis', 0) + status_counts.get('not_reachable', 0)}"
                ),
                current=idx,
                total=total,
                elapsed=time.perf_counter() - started_at,
            )

    emit_progress(
        "step5",
        "trace",
        (
            "反向追踪完成，"
            f"reachable={status_counts.get('reachable', 0)}，"
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
