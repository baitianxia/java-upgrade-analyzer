#!/usr/bin/env python3
"""Independent evidence adapters for Java SPI, Spring, and MyBatis implicit edges."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Protocol


class FrameworkAdapter(Protocol):
    """Stable adapter contract; implementations never mutate the source graph."""

    adapter: str
    version: str

    def detect(self, source_roots): ...
    def analyze(self, source_roots): ...


def _source_paths(source_roots):
    for item in source_roots or []:
        value = (item or {}).get('root') if isinstance(item, dict) else item
        if value and Path(value).is_dir():
            yield Path(value).resolve()


def _resource_roots(source_roots):
    seen = set()
    for source in _source_paths(source_roots):
        normalized = source.as_posix()
        for marker in ('/src/main/java', '/src/main/kotlin', '/src/main/groovy'):
            if normalized.endswith(marker):
                resource = Path(normalized[:-len(marker)] + '/src/main/resources')
                if resource.is_dir() and resource not in seen:
                    seen.add(resource)
                    yield resource


def _status(applicable, errors):
    if not applicable:
        return 'not_applicable'
    return 'partial' if errors else 'complete'


def run_spi_adapter(source_roots):
    edges, nodes, findings, errors = [], [], [], []
    files = []
    source_classes = set()
    load_points = []
    for source in _source_paths(source_roots):
        for java_file in sorted(source.rglob('*.java')):
            try:
                source_text = java_file.read_text(encoding='utf-8', errors='replace')
            except OSError as exc:
                errors.append(f'{java_file}:{type(exc).__name__}')
                continue
            owner = _java_package_and_class(source_text, java_file.stem)
            if owner:
                source_classes.add(owner)
            imports = {value.rsplit('.', 1)[-1]: value for value in re.findall(r'\bimport\s+([\w.]+)\s*;', source_text)}
            for line_no, line in enumerate(source_text.splitlines(), 1):
                for match in re.finditer(r'\bServiceLoader\s*\.\s*load\s*\(\s*([\w.]+)\s*\.class', line):
                    raw = match.group(1)
                    interface = imports.get(raw, raw)
                    load_points.append((owner, interface, str(java_file), line_no))
                    edges.append({
                        'source': owner, 'target': interface,
                        'edge_kind': 'java_spi_load_point', 'confidence': 'high',
                        'conditions': [], 'ambiguity': False,
                        'provenance': {'file': str(java_file), 'line': line_no},
                    })
    for root in _resource_roots(source_roots):
        services = root / 'META-INF' / 'services'
        service_files = sorted(item for item in services.iterdir() if item.is_file()) if services.is_dir() else []
        for path in service_files:
            files.append(str(path))
            interface = path.name.strip()
            try:
                providers = []
                for raw in path.read_text(encoding='utf-8').splitlines():
                    provider = raw.split('#', 1)[0].strip()
                    if provider:
                        providers.append(provider)
                for provider in providers:
                    nodes.extend([
                        {'id': interface, 'kind': 'spi_interface'},
                        {'id': provider, 'kind': 'spi_provider'},
                    ])
                    edges.append({
                        'source': interface, 'target': provider,
                        'edge_kind': 'java_spi_registration', 'confidence': 'high',
                        'conditions': [], 'ambiguity': len(providers) > 1,
                        'provenance': {'file': str(path)},
                    })
                    if provider not in source_classes:
                        findings.append({
                            'reason_code': 'spi_provider_class_unverified',
                            'subject': provider, 'interface': interface, 'file': str(path),
                        })
                if len(providers) > 1:
                    findings.append({
                        'reason_code': 'spi_multiple_providers', 'subject': interface,
                        'candidates': providers,
                    })
            except (OSError, UnicodeError) as exc:
                errors.append(f'{path}:{type(exc).__name__}')
        imports_path = root / 'META-INF' / 'spring' / 'org.springframework.boot.autoconfigure.AutoConfiguration.imports'
        if imports_path.is_file():
            files.append(str(imports_path))
            try:
                for line_no, raw in enumerate(imports_path.read_text(encoding='utf-8').splitlines(), 1):
                    target = raw.split('#', 1)[0].strip()
                    if not target:
                        continue
                    nodes.append({'id': target, 'kind': 'spring_autoconfiguration'})
                    edges.append({
                        'source': 'framework:spring-autoconfiguration', 'target': target,
                        'edge_kind': 'spring_autoconfiguration_registration', 'confidence': 'high',
                        'conditions': [], 'ambiguity': False,
                        'provenance': {'file': str(imports_path), 'line': line_no},
                    })
            except (OSError, UnicodeError) as exc:
                errors.append(f'{imports_path}:{type(exc).__name__}')
        factories_path = root / 'META-INF' / 'spring.factories'
        if factories_path.is_file():
            files.append(str(factories_path))
            try:
                logical_lines = []
                pending = ''
                for raw in factories_path.read_text(encoding='utf-8').splitlines():
                    stripped = raw.strip()
                    if not stripped or stripped.startswith(('#', '!')):
                        continue
                    pending += stripped[:-1] if stripped.endswith('\\') else stripped
                    if not stripped.endswith('\\'):
                        logical_lines.append(pending)
                        pending = ''
                if pending:
                    logical_lines.append(pending)
                for line_no, line in enumerate(logical_lines, 1):
                    if '=' not in line:
                        continue
                    registration_type, values = line.split('=', 1)
                    for target in (item.strip() for item in values.split(',')):
                        if not target:
                            continue
                        nodes.append({'id': target, 'kind': 'spring_factories_registration'})
                        edges.append({
                            'source': registration_type.strip(), 'target': target,
                            'edge_kind': 'spring_factories_registration', 'confidence': 'high',
                            'conditions': [], 'ambiguity': False,
                            'provenance': {'file': str(factories_path), 'line': line_no},
                        })
            except (OSError, UnicodeError) as exc:
                errors.append(f'{factories_path}:{type(exc).__name__}')
    registered_interfaces = {
        edge['source'] for edge in edges if edge.get('edge_kind') == 'java_spi_registration'
    }
    for owner, interface, file_path, line_no in load_points:
        if interface not in registered_interfaces:
            findings.append({
                'reason_code': 'spi_load_point_without_local_provider',
                'subject': owner, 'interface': interface, 'file': file_path, 'line': line_no,
            })
    ambiguous = any(item.get('reason_code') in {
        'spi_multiple_providers', 'spi_provider_class_unverified', 'spi_load_point_without_local_provider'
    } for item in findings)
    return {
        'adapter': 'java_spi', 'version': '1',
        'status': 'partial' if files and (errors or ambiguous) else _status(bool(files), errors),
        'nodes': nodes, 'edges': edges, 'findings': findings, 'errors': errors,
        'metrics': {'resource_files': len(files), 'load_points': len(load_points), 'edges': len(edges)},
    }


def _java_package_and_class(text, fallback=''):
    package = re.search(r'\bpackage\s+([\w.]+)\s*;', text)
    clazz = re.search(r'\b(?:class|interface|record|enum)\s+(\w+)', text)
    simple = clazz.group(1) if clazz else fallback
    return f'{package.group(1)}.{simple}' if package and simple else simple


def run_spring_adapter(source_roots):
    edges, nodes, findings, errors = [], [], [], []
    scanned = 0
    applicable = False
    bean_candidates = []
    listener_pattern = re.compile(r'@EventListener(?:\([^)]*\))?[\s\S]{0,500}?\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{')
    bean_pattern = re.compile(r'@(Component|Service|Repository|Controller|Configuration|Bean)\b')
    condition_pattern = re.compile(r'@(ConditionalOn\w+)(?:\(([^)]*)\))?')
    callback_methods = {
        'ApplicationRunner': {'run'},
        'CommandLineRunner': {'run'},
        'Filter': {'doFilter'},
        'HandlerInterceptor': {'preHandle', 'postHandle', 'afterCompletion'},
        'Converter': {'convert'},
        'Formatter': {'parse', 'print'},
        'WebMvcConfigurer': set(),
    }
    for root in _source_paths(source_roots):
        for path in sorted(root.rglob('*.java')):
            scanned += 1
            try:
                text = path.read_text(encoding='utf-8', errors='replace')
            except OSError as exc:
                errors.append(f'{path}:{type(exc).__name__}')
                continue
            if not ('org.springframework' in text or '@EventListener' in text or bean_pattern.search(text)):
                continue
            applicable = True
            owner = _java_package_and_class(text, path.stem)
            imports = {
                item.rsplit('.', 1)[-1]: item
                for item in re.findall(r'\bimport\s+([\w.]+)\s*;', text)
            }
            conditions = [
                {'annotation': match.group(1), 'expression': (match.group(2) or '').strip()}
                for match in condition_pattern.finditer(text)
            ]
            class_match = re.search(
                r'\bclass\s+(\w+)(?:\s+extends\s+[\w.<>]+)?\s+implements\s+([^\{]+)',
                text,
            )
            if class_match and bean_pattern.search(text):
                implemented = []
                for raw_interface in class_match.group(2).split(','):
                    simple = re.sub(r'<.*>', '', raw_interface).strip()
                    interface = imports.get(simple, simple)
                    implemented.append((simple, interface))
                    bean_candidates.append({
                        'interface': interface,
                        'implementation': owner,
                        'primary': bool(re.search(r'@Primary\b', text)),
                        'qualifiers': re.findall(r'@Qualifier\s*\(\s*"([^"]+)"\s*\)', text),
                        'file': str(path),
                    })
                method_names = re.findall(
                    r'\b(?:public|protected)\s+(?:[\w.$<>\[\],?]+\s+)+([A-Za-z_]\w*)\s*\(',
                    text,
                )
                for simple, interface in implemented:
                    if simple not in callback_methods:
                        continue
                    allowed = callback_methods[simple]
                    for method_name in method_names:
                        if allowed and method_name not in allowed:
                            continue
                        target = f'{owner}.{method_name}'
                        nodes.append({'id': target, 'kind': 'spring_callback'})
                        edges.append({
                            'source': f'framework:spring-callback:{interface}', 'target': target,
                            'edge_kind': 'spring_framework_callback', 'confidence': 'high',
                            'conditions': conditions, 'ambiguity': False,
                            'provenance': {'file': str(path), 'interface': interface},
                        })
            for match in listener_pattern.finditer(text):
                target = f'{owner}.{match.group(1)}'
                nodes.append({'id': target, 'kind': 'spring_event_listener'})
                edges.append({
                    'source': 'framework:spring-event-dispatch', 'target': target,
                    'edge_kind': 'spring_event_listener', 'confidence': 'high',
                    'conditions': conditions, 'ambiguity': False,
                    'provenance': {'file': str(path), 'annotation': '@EventListener'},
                })
            if conditions:
                findings.append({
                    'reason_code': 'spring_conditions_require_runtime_evaluation',
                    'subject': owner, 'conditions': conditions,
                })
    by_interface = {}
    for item in bean_candidates:
        by_interface.setdefault(item['interface'], []).append(item)
    for interface, candidates in sorted(by_interface.items()):
        primary = [item for item in candidates if item['primary']]
        resolved = primary if len(primary) == 1 else candidates
        unique = len(resolved) == 1
        for item in (resolved if unique else []):
            edges.append({
                'source': interface, 'target': item['implementation'],
                'edge_kind': 'spring_bean_dispatch',
                'confidence': 'high' if unique else 'medium',
                'conditions': [], 'ambiguity': not unique,
                'provenance': {
                    'file': item['file'], 'primary': item['primary'],
                    'qualifiers': item['qualifiers'],
                },
            })
        if not unique:
            findings.append({
                'reason_code': 'AMBIGUOUS_FRAMEWORK_DISPATCH',
                'subject': interface,
                'candidates': [item['implementation'] for item in candidates],
                'candidate_count': len(candidates),
                'ambiguity_reason': 'multiple beans and no unique @Primary candidate',
            })
    unresolved = any(
        finding.get('reason_code') in {
            'spring_conditions_require_runtime_evaluation', 'AMBIGUOUS_FRAMEWORK_DISPATCH'
        }
        for finding in findings
    )
    return {
        'adapter': 'spring_basic', 'version': '1',
        'status': 'partial' if applicable and (errors or unresolved) else _status(applicable, errors),
        'nodes': nodes, 'edges': edges, 'findings': findings, 'errors': errors,
        'metrics': {'source_files_scanned': scanned, 'edges': len(edges)},
    }


def run_mybatis_adapter(source_roots):
    edges, nodes, findings, errors = [], [], [], []
    files = []
    annotation_files = 0
    statement_tags = {'select', 'insert', 'update', 'delete'}
    for root in _resource_roots(source_roots):
        for path in sorted(root.rglob('*.xml')):
            try:
                tree = ET.parse(str(path))
            except ET.ParseError:
                continue
            except OSError as exc:
                errors.append(f'{path}:{type(exc).__name__}')
                continue
            mapper = tree.getroot()
            root_tag = str(mapper.tag).rsplit('}', 1)[-1]
            if root_tag == 'configuration':
                files.append(str(path))
                for child in mapper.iter():
                    tag = str(child.tag).rsplit('}', 1)[-1]
                    target = str(child.attrib.get('handler') or child.attrib.get('interceptor') or '').strip()
                    if tag == 'typeHandler' and target:
                        edges.append({
                            'source': str(child.attrib.get('javaType') or 'framework:mybatis-type-system'),
                            'target': target, 'edge_kind': 'mybatis_type_handler_registration',
                            'confidence': 'high', 'conditions': [], 'ambiguity': False,
                            'provenance': {'file': str(path)},
                        })
                    elif tag == 'plugin' and target:
                        edges.append({
                            'source': 'framework:mybatis-plugin-chain', 'target': target,
                            'edge_kind': 'mybatis_plugin_registration', 'confidence': 'high',
                            'conditions': [], 'ambiguity': False,
                            'provenance': {'file': str(path)},
                        })
                continue
            if root_tag != 'mapper':
                continue
            namespace = str(mapper.attrib.get('namespace') or '').strip()
            if not namespace:
                errors.append(f'{path}:mapper_namespace_missing')
                continue
            files.append(str(path))
            for child in mapper:
                tag = str(child.tag).rsplit('}', 1)[-1]
                statement_id = str(child.attrib.get('id') or '').strip()
                if tag not in statement_tags or not statement_id:
                    continue
                target = f'{namespace}.{statement_id}'
                nodes.append({'id': target, 'kind': 'mybatis_mapper_statement'})
                edges.append({
                    'source': f'framework:mybatis-proxy:{namespace}', 'target': target,
                    'edge_kind': 'mybatis_mapper_binding', 'confidence': 'high',
                    'conditions': [], 'ambiguity': False,
                    'provenance': {'file': str(path), 'statement_id': statement_id},
                })
                for attr in ('parameterType', 'resultType', 'resultMap'):
                    value = str(child.attrib.get(attr) or '').strip()
                    if value:
                        findings.append({
                            'reason_code': 'mybatis_type_reference', 'subject': target,
                            'attribute': attr, 'value': value, 'file': str(path),
                        })
                        edges.append({
                            'source': target, 'target': value,
                            'edge_kind': 'mybatis_type_reference', 'confidence': 'high',
                            'conditions': [], 'ambiguity': False,
                            'provenance': {'file': str(path), 'attribute': attr},
                        })
                type_handler = str(child.attrib.get('typeHandler') or '').strip()
                if type_handler:
                    edges.append({
                        'source': target, 'target': type_handler,
                        'edge_kind': 'mybatis_type_handler_binding', 'confidence': 'high',
                        'conditions': [], 'ambiguity': False,
                        'provenance': {'file': str(path), 'statement_id': statement_id},
                    })
            for child in mapper.iter():
                tag = str(child.tag).rsplit('}', 1)[-1]
                if tag == 'typeHandler':
                    handler = str(child.attrib.get('handler') or '').strip()
                    java_type = str(child.attrib.get('javaType') or '').strip()
                    if handler:
                        edges.append({
                            'source': java_type or 'framework:mybatis-type-system', 'target': handler,
                            'edge_kind': 'mybatis_type_handler_registration', 'confidence': 'high',
                            'conditions': [], 'ambiguity': False,
                            'provenance': {'file': str(path)},
                        })
                elif tag == 'plugin':
                    interceptor = str(child.attrib.get('interceptor') or '').strip()
                    if interceptor:
                        edges.append({
                            'source': 'framework:mybatis-plugin-chain', 'target': interceptor,
                            'edge_kind': 'mybatis_plugin_registration', 'confidence': 'high',
                            'conditions': [], 'ambiguity': False,
                            'provenance': {'file': str(path)},
                        })
    annotation_pattern = re.compile(r'@(Select|Insert|Update|Delete|SelectProvider|InsertProvider|UpdateProvider|DeleteProvider)\b')
    for source in _source_paths(source_roots):
        for path in sorted(source.rglob('*.java')):
            try:
                text = path.read_text(encoding='utf-8', errors='replace')
            except OSError as exc:
                errors.append(f'{path}:{type(exc).__name__}')
                continue
            if not annotation_pattern.search(text):
                continue
            annotation_files += 1
            owner = _java_package_and_class(text, path.stem)
            for match in re.finditer(r'@(Select|Insert|Update|Delete|\w+Provider)\b[^\n]*\n?\s*(?:public\s+)?[\w.$<>\[\],?]+\s+(\w+)\s*\(', text):
                target = f'{owner}.{match.group(2)}'
                edges.append({
                    'source': f'framework:mybatis-proxy:{owner}', 'target': target,
                    'edge_kind': 'mybatis_annotation_binding', 'confidence': 'high',
                    'conditions': [], 'ambiguity': False,
                    'provenance': {'file': str(path), 'annotation': '@' + match.group(1)},
                })
                nodes.append({'id': target, 'kind': 'mybatis_mapper_method'})
    return {
        'adapter': 'mybatis', 'version': '1', 'status': _status(bool(files or annotation_files), errors),
        'nodes': nodes, 'edges': edges, 'findings': findings, 'errors': errors,
        'metrics': {'xml_files': len(files), 'annotation_files': annotation_files, 'edges': len(edges)},
    }


def run_framework_adapters(source_roots, output_path=''):
    adapters = [
        run_spi_adapter(source_roots),
        run_spring_adapter(source_roots),
        run_mybatis_adapter(source_roots),
    ]
    for adapter in adapters:
        normalized = []
        for edge in adapter.get('edges') or []:
            ambiguity = bool(edge.get('ambiguity'))
            normalized.append({
                **edge,
                'adapter': adapter.get('adapter'),
                'adapter_version': adapter.get('version'),
                'evidence': dict(edge.get('provenance') or {}),
                'activation_conditions': list(edge.get('conditions') or []),
                'candidate_count': int(edge.get('candidate_count') or (2 if ambiguity else 1)),
                'ambiguity_reason': edge.get('ambiguity_reason') or ('multiple candidates' if ambiguity else ''),
            })
        adapter['edges'] = normalized
        adapter.setdefault('metrics', {})['ambiguous_edges'] = sum(
            bool(edge.get('ambiguity')) for edge in normalized
        )
        adapter['metrics']['conditional_edges'] = sum(
            bool(edge.get('activation_conditions')) for edge in normalized
        )
        adapter['metrics']['nodes'] = len(adapter.get('nodes') or [])
    payload = {
        'schema': 'java-upgrade-analyzer.framework-adapters.v1',
        'adapters': adapters,
    }
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return payload


def attach_framework_edges_to_graph(graph, payload):
    """Attach deterministic framework callback entries to the normal source/bytecode graph."""
    methods = list((getattr(graph, 'methods_by_id', {}) or {}).values())
    entries = {}
    matched_edges = 0
    unmatched_edges = 0
    supported_kinds = {
        'spring_event_listener', 'spring_framework_callback', 'spring_bean_dispatch',
        'java_spi_load_point', 'java_spi_registration',
        'mybatis_mapper_binding', 'mybatis_annotation_binding',
        'mybatis_type_reference',
        'mybatis_type_handler_binding', 'mybatis_type_handler_registration',
        'mybatis_plugin_registration', 'spring_autoconfiguration_registration',
        'spring_factories_registration',
    }
    for adapter in (payload or {}).get('adapters') or []:
        for edge in adapter.get('edges') or []:
            if edge.get('edge_kind') not in supported_kinds:
                continue
            target = str(edge.get('target') or '').strip()
            candidates = []
            for method in methods:
                qualified = str(getattr(method, 'qualified_key', '') or '')
                if qualified == target or qualified.startswith(target + '('):
                    candidates.append(method)
            if not candidates:
                unmatched_edges += 1
                continue
            for method in candidates:
                entries.setdefault(method.symbol_id, []).append({
                    **edge,
                    'adapter': adapter.get('adapter'),
                    'adapter_version': adapter.get('version'),
                })
                matched_edges += 1
    graph.framework_entry_symbols = entries
    graph.framework_edges = [
        edge
        for adapter in (payload or {}).get('adapters') or []
        for edge in adapter.get('edges') or []
    ]
    return {
        'matched_callback_edges': matched_edges,
        'unmatched_callback_edges': unmatched_edges,
        'framework_entry_methods': len(entries),
    }
