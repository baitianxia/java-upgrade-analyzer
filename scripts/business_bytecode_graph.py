#!/usr/bin/env python3
"""Build and merge current business-class bytecode evidence into the source graph."""

from __future__ import annotations

import os
import json
import re
import zipfile
from pathlib import Path

from compat import run_cmd
from enhanced_source_analyzer import CallEdge
from indirect_usage_analyzer import parse_javap_indirect_references


METHOD_REF_RE = re.compile(
    r'//\s+(?:Interface)?Method\s+([A-Za-z0-9_/$]+)\.(?:"([^"]+)"|([A-Za-z0-9_$<>]+)):(\S+)'
)
FIELD_REF_RE = re.compile(r'//\s+Field\s+([A-Za-z0-9_/$]+)\.([A-Za-z0-9_$]+):(\S+)')
TYPE_INSN_RE = re.compile(
    r'\b(?:new|anewarray|checkcast|instanceof|multianewarray)\b.*//\s+class\s+([A-Za-z0-9_/$]+)'
)
CLASS_CP_RE = re.compile(r'^\s*#\d+\s+=\s+Class\s+.*//\s+([A-Za-z0-9_/$]+)\s*$')
INVOKEDYNAMIC_RE = re.compile(r'\binvokedynamic\b.*//\s+InvokeDynamic\s+([^:]+):([^\s]+)')
DESCRIPTOR_CLASS_RE = re.compile(r'L([A-Za-z0-9_/$]+);')
METHOD_HEADER_RE = re.compile(r'^\s*(?:[\w.$<>\[\],?]+\s+)+([\w$<>]+)\([^;]*\);\s*$')


def _descriptor_type(descriptor, index):
    arrays = 0
    while index < len(descriptor) and descriptor[index] == '[':
        arrays += 1
        index += 1
    primitives = {'B': 'byte', 'C': 'char', 'D': 'double', 'F': 'float', 'I': 'int',
                  'J': 'long', 'S': 'short', 'Z': 'boolean', 'V': 'void'}
    if index >= len(descriptor):
        return '', index
    marker = descriptor[index]
    if marker == 'L':
        end = descriptor.find(';', index)
        if end < 0:
            return '', len(descriptor)
        value = descriptor[index + 1:end].replace('/', '.').replace('$', '.')
        index = end + 1
    else:
        value = primitives.get(marker, marker)
        index += 1
    return value + '[]' * arrays, index


def method_descriptor_signature(descriptor):
    if not descriptor.startswith('('):
        return ''
    index = 1
    params = []
    while index < len(descriptor) and descriptor[index] != ')':
        value, next_index = _descriptor_type(descriptor, index)
        if next_index <= index:
            break
        if value:
            params.append(value)
        index = next_index
    return '(' + ','.join(params) + ')'


def parse_javap_calls(text, class_name):
    """Return caller/callee evidence with JVM descriptors normalized to source keys."""
    current_method = ''
    current_signature = ''
    edges = []
    lines = (text or '').splitlines()
    class_refs = set()
    for index, raw in enumerate(lines):
        cp_match = CLASS_CP_RE.match(raw)
        if cp_match:
            target = cp_match.group(1).replace('/', '.').replace('$', '.')
            if target != class_name:
                class_refs.add(target)
        header = METHOD_HEADER_RE.match(raw)
        if header:
            current_method = header.group(1)
            if current_method == class_name.rsplit('.', 1)[-1]:
                current_method = '<init>'
            current_signature = ''
            continue
        if raw.strip().startswith('descriptor:') and current_method:
            descriptor = raw.split(':', 1)[1].strip()
            current_signature = method_descriptor_signature(descriptor)
            class_refs.update(
                value.replace('/', '.').replace('$', '.')
                for value in DESCRIPTOR_CLASS_RE.findall(descriptor)
            )
            continue
        if not current_method:
            continue
        type_match = TYPE_INSN_RE.search(raw)
        if type_match:
            owner = type_match.group(1).replace('/', '.').replace('$', '.')
            edges.append({
                'caller_owner': class_name,
                'caller_name': class_name.rsplit('.', 1)[-1] if current_method == '<init>' else current_method,
                'caller_signature': current_signature,
                'callee_key': owner,
                'callee_simple_key': f'class:{owner.rsplit(".", 1)[-1]}',
                'evidence_type': 'bytecode_type_reference',
                'line': index + 1,
                'content': raw.strip(),
            })
            continue
        dynamic_match = INVOKEDYNAMIC_RE.search(raw)
        if dynamic_match:
            signature = method_descriptor_signature(dynamic_match.group(2))
            edges.append({
                'caller_owner': class_name,
                'caller_name': class_name.rsplit('.', 1)[-1] if current_method == '<init>' else current_method,
                'caller_signature': current_signature,
                'callee_key': f'invokedynamic:{dynamic_match.group(1)}{signature}',
                'callee_simple_key': f'invokedynamic:{dynamic_match.group(1)}',
                'evidence_type': 'bytecode_invokedynamic',
                'line': index + 1,
                'content': raw.strip(),
            })
            continue
        method_match = METHOD_REF_RE.search(raw)
        if method_match:
            owner = method_match.group(1).replace('/', '.').replace('$', '.')
            member = method_match.group(2) or method_match.group(3) or ''
            signature = method_descriptor_signature(method_match.group(4))
            display_member = owner.rsplit('.', 1)[-1] if member == '<init>' else member
            edges.append({
                'caller_owner': class_name,
                'caller_name': class_name.rsplit('.', 1)[-1] if current_method == '<init>' else current_method,
                'caller_signature': current_signature,
                'callee_key': f'{owner}.{display_member}{signature}',
                'callee_simple_key': f'method:{display_member}{signature}',
                'evidence_type': 'bytecode_constructor_invocation' if member == '<init>' else 'bytecode_method_invocation',
                'line': index + 1,
                'content': raw.strip(),
            })
            continue
        field_match = FIELD_REF_RE.search(raw)
        if field_match:
            owner = field_match.group(1).replace('/', '.').replace('$', '.')
            member = field_match.group(2)
            edges.append({
                'caller_owner': class_name,
                'caller_name': class_name.rsplit('.', 1)[-1] if current_method == '<init>' else current_method,
                'caller_signature': current_signature,
                'callee_key': f'{owner}.{member}',
                'callee_simple_key': f'field:{member}',
                'evidence_type': 'bytecode_field_access',
                'line': index + 1,
                'content': raw.strip(),
            })
    for item in parse_javap_indirect_references(text, class_name):
        owner = item.get('owner') or ''
        kind = item.get('kind') or ''
        member = item.get('name') or ''
        signature = item.get('signature') or ''
        if kind in {'method', 'constructor'} and not item.get('signature_resolved'):
            continue
        if kind == 'class':
            callee_key = f'class:{owner}'
            simple_key = f'class:{owner.rsplit(".", 1)[-1]}'
            evidence_type = 'bytecode_reflection_class_lookup'
        elif kind == 'field':
            callee_key = f'{owner}.{member}'
            simple_key = f'field:{member}'
            evidence_type = 'bytecode_reflection_field_access'
        else:
            display_member = owner.rsplit('.', 1)[-1] if kind == 'constructor' else member
            callee_key = f'{owner}.{display_member}{signature}'
            simple_key = f'method:{display_member}{signature}'
            evidence_type = 'bytecode_reflection_constructor_invocation' if kind == 'constructor' else 'bytecode_reflection_method_invocation'
        edges.append({
            'caller_owner': class_name,
            'caller_name': class_name.rsplit('.', 1)[-1] if item.get('consumer_method') == '<init>' else item.get('consumer_method'),
            'caller_signature': item.get('consumer_signature') or '',
            'callee_key': callee_key,
            'callee_simple_key': simple_key,
            'evidence_type': evidence_type,
            'line': item.get('line') or 0,
            'content': 'javap reflection data-flow',
        })

    # Verbose javap exposes generic signatures, annotations and bootstrap arguments
    # through constant-pool Class entries. Keep these as class-level evidence even
    # when no executable instruction references the type directly.
    existing = {item['callee_key'] for item in edges if item['evidence_type'] == 'bytecode_type_reference'}
    for owner in sorted(class_refs - existing):
        edges.append({
            'caller_owner': class_name,
            'caller_name': class_name.rsplit('.', 1)[-1],
            'caller_signature': '',
            'callee_key': owner,
            'callee_simple_key': f'class:{owner.rsplit(".", 1)[-1]}',
            'evidence_type': 'bytecode_class_reference',
            'line': 0,
            'content': 'javap -v constant-pool/signature/annotation reference',
        })
    return edges


def discover_class_roots(source_roots):
    roots = []
    for item in source_roots or []:
        root = Path(str((item or {}).get('root') or item)).resolve()
        normalized = root.as_posix()
        for marker, replacement in (
            ('/src/main/java', '/target/classes'),
            ('/src/main/kotlin', '/target/classes'),
            ('/src/main/groovy', '/target/classes'),
        ):
            if normalized.endswith(marker):
                candidate = Path(normalized[:-len(marker)] + replacement)
                if candidate.is_dir() and candidate not in roots:
                    roots.append(candidate)
    return roots


def collect_business_bytecode_edges(source_roots, max_classes=10000, artifact_catalog=None, cache_path=None):
    evidence = []
    failures = []
    scanned = 0
    business_item = ((artifact_catalog or {}).get('by_coord') or {}).get('__business__') or {}
    business_jar = str(business_item.get('jar_path') or '').strip()
    cache_key = str(business_item.get('sha256') or '').strip()
    if cache_path and cache_key:
        try:
            cached = json.loads(Path(cache_path).read_text(encoding='utf-8'))
            if cached.get('schema') == 'java-upgrade-analyzer.bytecode-index.v1' and cached.get('artifact_sha256') == cache_key:
                return list(cached.get('edges') or []), {**dict(cached.get('metrics') or {}), 'cache_hit': True}
        except (OSError, ValueError, TypeError):
            pass
    if business_jar and os.path.isfile(business_jar):
        try:
            with zipfile.ZipFile(business_jar) as zf:
                class_entries = sorted(
                    name for name in zf.namelist()
                    if name.endswith('.class')
                    and not name.startswith('META-INF/')
                    and not name.endswith(('module-info.class', 'package-info.class'))
                )
            for entry in class_entries:
                if scanned >= max_classes:
                    failures.append('class_scan_limit_reached')
                    break
                class_name = entry[:-6].replace('/', '.')
                stdout, stderr, rc = run_cmd(
                    ['javap', '-classpath', business_jar, '-c', '-s', '-p', '-v', class_name],
                    timeout=30,
                )
                scanned += 1
                if rc != 0:
                    failures.append(f'javap_failed:{class_name}:{(stderr or "")[:80]}')
                    continue
                for item in parse_javap_calls(stdout, class_name):
                    item['class_file'] = f'{business_jar}!/{entry}'
                    item['artifact_sha256'] = business_item.get('sha256', '')
                    evidence.append(item)
            metrics = {
                'classes_scanned': scanned,
                'edges_found': len(evidence),
                'method_edges': sum(item.get('evidence_type') == 'bytecode_method_invocation' for item in evidence),
                'field_edges': sum(item.get('evidence_type') == 'bytecode_field_access' for item in evidence),
                'type_edges': sum(item.get('evidence_type') in {'bytecode_type_reference', 'bytecode_class_reference'} for item in evidence),
                'invokedynamic_edges': sum(item.get('evidence_type') == 'bytecode_invokedynamic' for item in evidence),
                'failures': failures,
                'evidence_source': 'current_final_artifact',
            }
            if cache_path and cache_key:
                cache_file = Path(cache_path)
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(json.dumps({
                    'schema': 'java-upgrade-analyzer.bytecode-index.v1',
                    'artifact_sha256': cache_key,
                    'edges': evidence,
                    'metrics': metrics,
                }, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            return evidence, metrics
        except (OSError, zipfile.BadZipFile) as exc:
            failures.append(f'business_artifact_scan_failed:{exc}')

    for class_root in discover_class_roots(source_roots):
        class_files = sorted(class_root.rglob('*.class'))
        for class_file in class_files:
            if scanned >= max_classes:
                failures.append('class_scan_limit_reached')
                break
            relative = class_file.relative_to(class_root).as_posix()
            if '$' in relative.rsplit('/', 1)[-1]:
                continue
            class_name = relative[:-6].replace('/', '.')
            stdout, stderr, rc = run_cmd(
                ['javap', '-classpath', str(class_root), '-c', '-s', '-p', '-v', class_name],
                timeout=30,
            )
            scanned += 1
            if rc != 0:
                failures.append(f'javap_failed:{class_name}:{(stderr or "")[:80]}')
                continue
            for item in parse_javap_calls(stdout, class_name):
                item['class_file'] = str(class_file)
                evidence.append(item)
    return evidence, {
        'classes_scanned': scanned,
        'edges_found': len(evidence),
        'failures': failures,
        'evidence_source': 'build_directory_fallback' if scanned else 'unavailable',
    }


def _source_method_for_edge(graph, item):
    qualified = f"{item['caller_owner']}.{item['caller_name']}"
    methods_by_id = getattr(graph, 'methods_by_id', {}) or {}
    raw_candidates = list((getattr(graph, 'methods_by_qualified', {}) or {}).get(qualified) or [])
    candidates = []
    for raw_candidate in raw_candidates:
        if hasattr(raw_candidate, 'symbol_id'):
            candidates.append(raw_candidate)
            continue
        method_def = methods_by_id.get(raw_candidate)
        if method_def is not None:
            candidates.append(method_def)
    if len(candidates) == 1:
        return candidates[0]
    signature = item.get('caller_signature') or ''
    if signature:
        matches = []
        for candidate in candidates:
            lookup_keys = (getattr(graph, 'lookup_keys_by_symbol', {}) or {}).get(candidate.symbol_id) or []
            if any(str(key).endswith(signature) for key in lookup_keys):
                matches.append(candidate)
        if len(matches) == 1:
            return matches[0]
    return None


def merge_business_bytecode_edges(graph, evidence):
    reverse_edges = getattr(graph, 'reverse_edges', {})
    merged = 0
    skipped = 0
    for item in evidence or []:
        caller = _source_method_for_edge(graph, item)
        if caller is None:
            skipped += 1
            continue
        edge = CallEdge(
            caller_symbol_id=caller.symbol_id,
            caller_qualified_key=caller.qualified_key,
            callee_key=item['callee_key'],
            callee_simple_key=item['callee_simple_key'],
            evidence_type=item['evidence_type'],
            confidence='high',
            file=item.get('class_file', ''),
            line=item.get('line', 0),
            content=item.get('content', '')[:100],
            owner_type='business',
            owner_coord=getattr(caller, 'owner_coord', ''),
            module=getattr(caller, 'module', ''),
            is_test=False,
            callee_param_types=[],
        )
        for key in (edge.callee_key, edge.callee_simple_key):
            bucket = reverse_edges.setdefault(key, [])
            identity = (edge.caller_symbol_id, edge.callee_key, edge.evidence_type)
            if any((old.caller_symbol_id, old.callee_key, old.evidence_type) == identity for old in bucket):
                continue
            bucket.append(edge)
        merged += 1
    return {'merged_edges': merged, 'skipped_unresolved_callers': skipped}
