#!/usr/bin/env python3
"""Independent evidence adapters for Java SPI, Spring, MyBatis and proxy edges."""

from __future__ import annotations

import json
import re
import safe_xml as ET
import subprocess
import tempfile
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Protocol

from enhanced_source_analyzer import analyze_file
from signature_utils import normalize_signature_for_lookup


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


def _is_production_source_file(path):
    normalized = '/' + Path(path).as_posix().strip('/') + '/'
    return not any(marker in normalized for marker in (
        '/src/test/',
        '/src/tests/',
        '/src/it/',
        '/src/integration-test/',
        '/src/integrationTest/',
        '/target/generated-test-sources/',
        '/build/generated/sources/test/',
    ))


def _production_java_files(source_roots):
    """Yield each production Java file once across overlapping source roots."""
    seen = set()
    for root in _source_paths(source_roots):
        for path in sorted(root.rglob('*.java')):
            resolved = path.resolve()
            if resolved in seen or not _is_production_source_file(resolved):
                continue
            seen.add(resolved)
            yield resolved


def _mask_java_comments(text):
    """Remove comments while preserving offsets, newlines, and string literals."""
    chars = list(str(text or ''))
    index = 0
    state = 'code'
    while index < len(chars):
        current = chars[index]
        following = chars[index + 1] if index + 1 < len(chars) else ''
        if state == 'code':
            if current == '"':
                state = 'string'
            elif current == "'":
                state = 'char'
            elif current == '/' and following == '/':
                chars[index] = chars[index + 1] = ' '
                index += 1
                state = 'line_comment'
            elif current == '/' and following == '*':
                chars[index] = chars[index + 1] = ' '
                index += 1
                state = 'block_comment'
        elif state in {'string', 'char'}:
            quote = '"' if state == 'string' else "'"
            if current == '\\':
                index += 1
            elif current == quote:
                state = 'code'
        elif state == 'line_comment':
            if current in '\r\n':
                state = 'code'
            else:
                chars[index] = ' '
        elif state == 'block_comment':
            if current == '*' and following == '/':
                chars[index] = chars[index + 1] = ' '
                index += 1
                state = 'code'
            elif current not in '\r\n':
                chars[index] = ' '
        index += 1
    return ''.join(chars)


def _mask_java_literals(text):
    """Mask string/character bodies after comments have been removed."""
    chars = list(str(text or ''))
    index = 0
    quote = ''
    while index < len(chars):
        current = chars[index]
        if not quote and current in {'"', "'"}:
            quote = current
        elif quote:
            if current == '\\':
                if index + 1 < len(chars) and chars[index + 1] not in '\r\n':
                    chars[index + 1] = ' '
                    index += 1
            elif current == quote:
                quote = ''
            elif current not in '\r\n':
                chars[index] = ' '
        index += 1
    return ''.join(chars)


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


def _xml_local_name(tag):
    return str(tag or '').rsplit('}', 1)[-1].split(':')[-1]


def _xml_attr(element, *names):
    attrs = element.attrib or {}
    for name in names:
        if name in attrs:
            return str(attrs.get(name) or '').strip()
    for key, value in attrs.items():
        if _xml_local_name(key) in names:
            return str(value or '').strip()
    return ''


def _split_bean_ref(value):
    text = str(value or '').strip()
    if not text:
        return '', ''
    if '.' in text and not text.startswith('&'):
        bean_id, method = text.rsplit('.', 1)
        if bean_id and method:
            return bean_id, method
    return text, ''


def run_spi_adapter(source_roots):
    edges, nodes, findings, errors = [], [], [], []
    files = []
    source_classes = set()
    load_points = []
    for java_file in _production_java_files(source_roots):
        try:
            source_text = _mask_java_comments(
                java_file.read_text(encoding='utf-8', errors='replace')
            )
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
        # Dubbo SPI registrations use the same interface-to-provider shape as
        # ServiceLoader but live under META-INF/dubbo[/internal|/external] and
        # optionally prefix the implementation with `name=`.  Treat them as
        # deterministic provider registrations so a provider method can be a
        # framework-reachable graph entry rather than an isolated class.
        for relative_dir in ('META-INF/dubbo', 'META-INF/dubbo/internal', 'META-INF/dubbo/external'):
            registry_dir = root / relative_dir
            registry_files = (
                sorted(item for item in registry_dir.iterdir() if item.is_file())
                if registry_dir.is_dir() else []
            )
            for path in registry_files:
                files.append(str(path))
                interface = path.name.strip()
                try:
                    providers = []
                    for raw in path.read_text(encoding='utf-8').splitlines():
                        value = raw.split('#', 1)[0].strip()
                        if not value:
                            continue
                        provider = value.split('=', 1)[-1].strip()
                        if provider:
                            providers.append(provider)
                    for provider in providers:
                        nodes.extend([
                            {'id': interface, 'kind': 'dubbo_spi_interface'},
                            {'id': provider, 'kind': 'dubbo_spi_provider'},
                        ])
                        edges.append({
                            'source': interface, 'target': provider,
                            'edge_kind': 'dubbo_spi_registration', 'confidence': 'high',
                            'conditions': [], 'ambiguity': len(providers) > 1,
                            'provenance': {'file': str(path)},
                        })
                        if provider not in source_classes:
                            findings.append({
                                'reason_code': 'dubbo_spi_provider_class_unverified',
                                'subject': provider, 'interface': interface, 'file': str(path),
                            })
                    if len(providers) > 1:
                        findings.append({
                            'reason_code': 'dubbo_spi_multiple_providers',
                            'subject': interface, 'candidates': providers,
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
    active_method_pattern = re.compile(
        r'@(?:[\w.]+\.)?(Scheduled|PostConstruct|KafkaListener|RabbitListener|JmsListener)(?:\([^)]*\))?'
        r'[\s\S]{0,500}?'
        r'\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{'
    )
    jpa_lifecycle_pattern = re.compile(
        r'@(?:[\w.]+\.)?(PrePersist|PostPersist|PreUpdate|PostUpdate|PreRemove|PostRemove|PostLoad)'
        r'(?:\([^)]*\))?'
        r'[\s\S]{0,500}?'
        r'\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{'
    )
    bean_pattern = re.compile(r'@(Component|Service|Repository|Controller|Configuration|Bean)\b')
    bean_method_pattern = re.compile(
        r'@Bean(?:\s*\([^)]*\))?\s*'
        r'(?P<post_annotations>(?:@[A-Za-z_$][\w.$]*(?:\s*\([^)]*\))?\s*)*)'
        r'(?:(?:public|protected|private|static|final|synchronized)\s+)*'
        r'(?P<return_type>[A-Za-z_$][\w.$]*(?:\s*<[^>{}]+>)?(?:\[\])?)\s+'
        r'(?P<method_name>[A-Za-z_$]\w*)\s*\([^)]*\)\s*\{(?P<body>[\s\S]*?)\}',
    )
    condition_pattern = re.compile(r'@(ConditionalOn\w+)(?:\(([^)]*)\))?')
    callback_methods = {
        'ApplicationRunner': {'run'},
        'CommandLineRunner': {'run'},
        'InitializingBean': {'afterPropertiesSet'},
        'Lifecycle': {'start', 'stop'},
        'SmartLifecycle': {'start', 'stop'},
        'ApplicationListener': {'onApplicationEvent'},
        'Job': {'execute'},
        'Filter': {'doFilter'},
        'HandlerInterceptor': {'preHandle', 'postHandle', 'afterCompletion'},
        'Converter': {'convert'},
        'Formatter': {'parse', 'print'},
        'WebMvcConfigurer': set(),
    }
    for path in _production_java_files(source_roots):
            scanned += 1
            try:
                text = _mask_java_comments(path.read_text(encoding='utf-8', errors='replace'))
            except OSError as exc:
                errors.append(f'{path}:{type(exc).__name__}')
                continue
            if not (
                'org.springframework' in text
                or 'org.quartz' in text
                or '@EventListener' in text
                or '@Scheduled' in text
                or '@PostConstruct' in text
                or 'jakarta.persistence' in text
                or 'javax.persistence' in text
                or re.search(r'@(PrePersist|PostPersist|PreUpdate|PostUpdate|PreRemove|PostRemove|PostLoad)\b', text)
                or bean_pattern.search(text)
            ):
                continue
            applicable = True
            owner = _java_package_and_class(text, path.stem)
            owner_simple = owner.rsplit('.', 1)[-1]
            package_name = owner.rsplit('.', 1)[0] if '.' in owner else ''
            imports = {
                item.rsplit('.', 1)[-1]: item
                for item in re.findall(r'\bimport\s+([\w.]+)\s*;', text)
            }
            conditions = [
                {'annotation': match.group(1), 'expression': (match.group(2) or '').strip()}
                for match in condition_pattern.finditer(text)
            ]
            ast_methods = []
            ast_authoritative = False
            try:
                ast_methods, parser_info = analyze_file(
                    str(path),
                    {"root": str(path.parent), "owner_type": "business", "owner_coord": "BUSINESS"},
                    prefer_tree_sitter=True,
                    return_diagnostics=True,
                )
                ast_authoritative = parser_info.get('actual_parser') == 'tree_sitter'
            except (OSError, RuntimeError, ValueError) as exc:
                errors.append(f'{path}:spring_ast:{type(exc).__name__}')
            class_match = re.search(
                rf'\bclass\s+{re.escape(owner_simple)}'
                r'(?:\s+extends\s+[\w.<>]+)?\s+implements\s+([^\{]+)',
                text,
            )
            if class_match and bean_pattern.search(text):
                implemented = []
                for raw_interface in class_match.group(1).split(','):
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
            bean_methods_found = 0
            for bean_match in bean_method_pattern.finditer(text):
                bean_methods_found += 1
                return_type = re.sub(r'<.*>', '', bean_match.group('return_type')).replace('[]', '').strip()
                return_simple = return_type.rsplit('.', 1)[-1]
                interface = imports.get(return_simple, return_type)
                if '.' not in interface and package_name:
                    interface = f'{package_name}.{interface}'
                implementation_match = re.search(r'\bnew\s+([A-Za-z_$][\w.$]*)\s*\(', bean_match.group('body'))
                if not implementation_match:
                    findings.append({
                        'reason_code': 'spring_bean_method_unresolved',
                        'subject': f"{owner}.{bean_match.group('method_name')}",
                        'return_type': interface,
                        'file': str(path),
                    })
                    continue
                implementation_type = implementation_match.group(1)
                implementation_simple = implementation_type.rsplit('.', 1)[-1]
                implementation = imports.get(implementation_simple, implementation_type)
                if '.' not in implementation and package_name:
                    implementation = f'{package_name}.{implementation}'
                annotation_prefix = text[max(0, bean_match.start() - 200):bean_match.start()]
                annotation_prefix = re.split(r'[;}\{]', annotation_prefix)[-1]
                method_annotations = annotation_prefix + bean_match.group('post_annotations')
                bean_candidates.append({
                    'interface': interface,
                    'implementation': implementation,
                    'primary': bool(re.search(r'@Primary\b', method_annotations)),
                    'qualifiers': re.findall(r'@Qualifier\s*\(\s*"([^"]+)"\s*\)', method_annotations),
                    'file': str(path),
                    'source_method': bean_match.group('method_name'),
                })
            if '@Bean' in text and not bean_methods_found:
                findings.append({
                    'reason_code': 'spring_bean_method_unresolved',
                    'subject': owner,
                    'file': str(path),
                })
            listener_targets = []
            active_targets = []
            jpa_lifecycle_targets = []
            if ast_authoritative:
                for method in ast_methods:
                    annotations = {str(item).rsplit('.', 1)[-1] for item in method.annotations or []}
                    method_owner = str(getattr(method, 'class_fqcn', '') or owner)
                    method_name = str(getattr(method, 'method_name', '') or '')
                    if method_name and 'EventListener' in annotations:
                        listener_targets.append((f'{method_owner}.{method_name}', '@EventListener'))
                    for annotation in ('Scheduled', 'PostConstruct', 'KafkaListener', 'RabbitListener', 'JmsListener'):
                        if method_name and annotation in annotations:
                            active_targets.append((f'{method_owner}.{method_name}', annotation))
                    for annotation in (
                        'PrePersist', 'PostPersist', 'PreUpdate', 'PostUpdate',
                        'PreRemove', 'PostRemove', 'PostLoad',
                    ):
                        if method_name and annotation in annotations:
                            jpa_lifecycle_targets.append((f'{method_owner}.{method_name}', annotation))
            else:
                listener_targets.extend(
                    (f'{owner}.{match.group(1)}', '@EventListener')
                    for match in listener_pattern.finditer(text)
                )
                active_targets.extend(
                    (f'{owner}.{match.group(2)}', match.group(1))
                    for match in active_method_pattern.finditer(text)
                )
                jpa_lifecycle_targets.extend(
                    (f'{owner}.{match.group(2)}', match.group(1))
                    for match in jpa_lifecycle_pattern.finditer(text)
                )
            for target, annotation in listener_targets:
                nodes.append({'id': target, 'kind': 'spring_event_listener'})
                edges.append({
                    'source': 'framework:spring-event-dispatch', 'target': target,
                    'edge_kind': 'spring_event_listener', 'confidence': 'high',
                    'conditions': conditions, 'ambiguity': False,
                    'provenance': {
                        'file': str(path), 'annotation': annotation,
                        'parser': 'tree_sitter' if ast_authoritative else 'masked_text_fallback',
                    },
                })
            for target, annotation in active_targets:
                nodes.append({'id': target, 'kind': 'spring_runtime_active_entry'})
                edges.append({
                    'source': f'framework:spring-active-entry:{annotation}',
                    'target': target,
                    'edge_kind': 'spring_runtime_active_entry',
                    'confidence': 'high',
                    'conditions': conditions,
                    'ambiguity': False,
                    'provenance': {
                        'file': str(path), 'annotation': f'@{annotation}',
                        'parser': 'tree_sitter' if ast_authoritative else 'masked_text_fallback',
                    },
                })
            for target, annotation in jpa_lifecycle_targets:
                nodes.append({'id': target, 'kind': 'jpa_lifecycle_callback'})
                edges.append({
                    'source': f'framework:jpa-lifecycle:{annotation}',
                    'target': target,
                    'edge_kind': 'jpa_lifecycle_callback',
                    'confidence': 'high',
                    # The annotation proves callback semantics, but static
                    # analysis alone cannot prove that this entity lifecycle is
                    # exercised in the current runtime profile.
                    'runtime_activation': 'conditional',
                    'conditions': [{'annotation': annotation, 'requires': 'entity_lifecycle'}],
                    'ambiguity': False,
                    'provenance': {
                        'file': str(path), 'annotation': f'@{annotation}',
                        'parser': 'tree_sitter' if ast_authoritative else 'masked_text_fallback',
                    },
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
    xml_files = 0
    for root in _resource_roots(source_roots):
        for path in sorted(root.rglob('*.xml')):
            try:
                tree = ET.parse(str(path))
            except ET.ParseError:
                continue
            except OSError as exc:
                errors.append(f'{path}:{type(exc).__name__}')
                continue
            root_element = tree.getroot()
            bean_classes = {}
            bean_factory_methods = {}
            xml_active_entries = []
            xml_property_edges = []
            for element in root_element.iter():
                tag = _xml_local_name(element.tag)
                if tag != 'bean':
                    continue
                bean_id = _xml_attr(element, 'id', 'name')
                bean_class = _xml_attr(element, 'class')
                if bean_id and bean_class:
                    bean_classes[bean_id] = bean_class
                init_method = _xml_attr(element, 'init-method')
                if bean_id and bean_class and init_method:
                    xml_active_entries.append({
                        'bean_id': bean_id,
                        'class': bean_class,
                        'method': init_method,
                        'kind': 'spring_xml_init_method',
                    })
                factory_class = _xml_attr(element, 'class')
                if bean_id and factory_class.endswith('MethodInvokingJobDetailFactoryBean'):
                    props = {
                        _xml_attr(child, 'name'): child
                        for child in list(element)
                        if _xml_local_name(child.tag) == 'property' and _xml_attr(child, 'name')
                    }
                    target_bean = ''
                    target_method = ''
                    target_object = props.get('targetObject')
                    if target_object is not None:
                        target_bean = _xml_attr(target_object, 'ref', 'bean')
                        if not target_bean:
                            for child in list(target_object):
                                if _xml_local_name(child.tag) == 'ref':
                                    target_bean = _xml_attr(child, 'bean', 'local')
                                    break
                    target_method_element = props.get('targetMethod')
                    if target_method_element is not None:
                        target_method = _xml_attr(target_method_element, 'value')
                        if not target_method:
                            for child in list(target_method_element):
                                if _xml_local_name(child.tag) == 'value':
                                    target_method = (child.text or '').strip()
                                    break
                    target_class = bean_classes.get(target_bean, '')
                    if target_class and target_method:
                        xml_active_entries.append({
                            'bean_id': target_bean,
                            'class': target_class,
                            'method': target_method,
                            'kind': 'spring_xml_quartz_method_invoking_job',
                        })
                    else:
                        findings.append({
                            'reason_code': 'spring_xml_quartz_job_unresolved',
                            'subject': bean_id,
                            'file': str(path),
                        })
            # Resolve ordinary `<property ref="...">` injection only after
            # collecting every bean class, so forward references are handled
            # as reliably as backward references.  This is a component
            # association, not an executable method call, therefore it is kept
            # as separate framework evidence.
            for element in root_element.iter():
                if _xml_local_name(element.tag) != 'bean':
                    continue
                source_id = _xml_attr(element, 'id', 'name')
                source_class = bean_classes.get(source_id, '')
                if not source_class:
                    continue
                for child in list(element):
                    if _xml_local_name(child.tag) != 'property':
                        continue
                    target_id = _xml_attr(child, 'ref', 'bean')
                    if not target_id:
                        for nested in list(child):
                            if _xml_local_name(nested.tag) == 'ref':
                                target_id = _xml_attr(nested, 'bean', 'local')
                                if target_id:
                                    break
                    target_class = bean_classes.get(target_id, '')
                    if target_class:
                        xml_property_edges.append({
                            'source': source_class,
                            'target': target_class,
                            'property': _xml_attr(child, 'name'),
                            'bean_id': source_id,
                            'target_bean_id': target_id,
                        })
                    elif target_id:
                        findings.append({
                            'reason_code': 'spring_xml_property_ref_unresolved',
                            'subject': source_id,
                            'property': _xml_attr(child, 'name'),
                            'target_bean_id': target_id,
                            'file': str(path),
                        })
            for element in root_element.iter():
                tag = _xml_local_name(element.tag)
                if tag != 'scheduled':
                    continue
                ref = _xml_attr(element, 'ref')
                method = _xml_attr(element, 'method')
                if not ref:
                    ref, method_from_ref = _split_bean_ref(_xml_attr(element, 'target'))
                    method = method or method_from_ref
                bean_class = bean_classes.get(ref, '')
                if bean_class and method:
                    xml_active_entries.append({
                        'bean_id': ref,
                        'class': bean_class,
                        'method': method,
                        'kind': 'spring_xml_scheduled_task',
                    })
                else:
                    findings.append({
                        'reason_code': 'spring_xml_scheduled_task_unresolved',
                        'subject': ref or _xml_attr(element, 'target'),
                        'method': method,
                        'file': str(path),
                    })
            if xml_active_entries or xml_property_edges:
                xml_files += 1
                applicable = True
            for item in xml_active_entries:
                target = f"{item['class']}.{item['method']}"
                nodes.append({'id': target, 'kind': 'spring_runtime_active_entry'})
                edges.append({
                    'source': f"framework:{item['kind']}",
                    'target': target,
                    'edge_kind': 'spring_runtime_active_entry',
                    'confidence': 'high',
                    'conditions': [],
                    'ambiguity': False,
                    'provenance': {
                        'file': str(path),
                        'xml_kind': item['kind'],
                        'bean_id': item.get('bean_id', ''),
                    },
                })
            for item in xml_property_edges:
                nodes.extend([
                    {'id': item['source'], 'kind': 'spring_xml_bean'},
                    {'id': item['target'], 'kind': 'spring_xml_bean'},
                ])
                edges.append({
                    'source': item['source'], 'target': item['target'],
                    'edge_kind': 'spring_xml_property_injection', 'confidence': 'high',
                    'conditions': [], 'ambiguity': False,
                    'provenance': {
                        'file': str(path),
                        'bean_id': item['bean_id'],
                        'target_bean_id': item['target_bean_id'],
                        'property': item['property'],
                    },
                })
    unresolved = any(
        finding.get('reason_code') in {
            'spring_conditions_require_runtime_evaluation', 'AMBIGUOUS_FRAMEWORK_DISPATCH',
            'spring_bean_method_unresolved', 'spring_xml_scheduled_task_unresolved',
            'spring_xml_quartz_job_unresolved', 'spring_xml_property_ref_unresolved',
        }
        for finding in findings
    )
    return {
        'adapter': 'spring_basic', 'version': '1',
        'status': 'partial' if applicable and (errors or unresolved) else _status(applicable, errors),
        'nodes': nodes, 'edges': edges, 'findings': findings, 'errors': errors,
        'metrics': {'source_files_scanned': scanned, 'xml_files_scanned': xml_files, 'edges': len(edges)},
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
    annotation_pattern = re.compile(
        r'@(?:[A-Za-z_][\w.]*\.)?'
        r'(Select|Insert|Update|Delete|SelectProvider|InsertProvider|UpdateProvider|DeleteProvider)\b'
    )
    mybatis_annotations = {
        'Select', 'Insert', 'Update', 'Delete',
        'SelectProvider', 'InsertProvider', 'UpdateProvider', 'DeleteProvider',
    }
    for path in _production_java_files(source_roots):
            try:
                text = _mask_java_comments(path.read_text(encoding='utf-8', errors='replace'))
            except OSError as exc:
                errors.append(f'{path}:{type(exc).__name__}')
                continue
            if not annotation_pattern.search(text):
                continue
            annotation_files += 1
            owner = _java_package_and_class(text, path.stem)
            bindings = []
            try:
                methods, parser_info = analyze_file(
                    str(path),
                    {"root": str(path.parent), "owner_type": "business", "owner_coord": "BUSINESS"},
                    prefer_tree_sitter=True,
                    return_diagnostics=True,
                )
            except (OSError, RuntimeError, ValueError) as exc:
                methods, parser_info = [], {'actual_parser': 'unavailable'}
                errors.append(f'{path}:mybatis_ast:{type(exc).__name__}')
            if parser_info.get('actual_parser') == 'tree_sitter':
                for method in methods:
                    annotations = {
                        str(item).rsplit('.', 1)[-1] for item in method.annotations or []
                    }
                    for annotation in sorted(annotations & mybatis_annotations):
                        bindings.append((
                            f"{getattr(method, 'class_fqcn', '') or owner}.{method.method_name}",
                            annotation,
                            'tree_sitter',
                        ))
            else:
                for match in re.finditer(
                    r'@(Select|Insert|Update|Delete|\w+Provider)\b[^\n]*\n?\s*'
                    r'(?:public\s+)?[\w.$<>\[\],?]+\s+(\w+)\s*\(', text
                ):
                    bindings.append((f'{owner}.{match.group(2)}', match.group(1), 'masked_text_fallback'))
            for target, annotation, parser in bindings:
                edges.append({
                    'source': f'framework:mybatis-proxy:{owner}', 'target': target,
                    'edge_kind': 'mybatis_annotation_binding', 'confidence': 'high',
                    'conditions': [], 'ambiguity': False,
                    'provenance': {
                        'file': str(path), 'annotation': '@' + annotation, 'parser': parser,
                    },
                })
                nodes.append({'id': target, 'kind': 'mybatis_mapper_method'})
    return {
        'adapter': 'mybatis', 'version': '1', 'status': _status(bool(files or annotation_files), errors),
        'nodes': nodes, 'edges': edges, 'findings': findings, 'errors': errors,
        'metrics': {'xml_files': len(files), 'annotation_files': annotation_files, 'edges': len(edges)},
    }


def run_dynamic_proxy_adapter(source_roots):
    edges, nodes, findings, errors = [], [], [], []
    scanned = 0
    registrations = 0
    callback_methods = {
        'InvocationHandler': ('framework:jdk-dynamic-proxy', {'invoke'}),
        'MethodInterceptor': ('framework:dynamic-proxy-advice', {'invoke', 'intercept'}),
    }
    source_files = []
    handlers = {}
    for path in _production_java_files(source_roots):
            scanned += 1
            try:
                text = _mask_java_comments(path.read_text(encoding='utf-8', errors='replace'))
            except OSError as exc:
                errors.append(f'{path}:{type(exc).__name__}')
                continue
            code_text = _mask_java_literals(text)
            source_files.append((path, code_text))
            if not any(marker in code_text for marker in (
                'InvocationHandler', 'MethodInterceptor', 'Proxy.newProxyInstance', 'Enhancer.create',
            )):
                continue
            owner = _java_package_and_class(code_text, path.stem)
            imports = {
                item.rsplit('.', 1)[-1]: item
                for item in re.findall(r'\bimport\s+([\w.]+)\s*;', code_text)
            }
            class_match = re.search(
                rf'\bclass\s+{re.escape(owner.rsplit(".", 1)[-1])}'
                r'(?:\s+extends\s+[\w.<>]+)?(?:\s+implements\s+([^\{]+))?',
                code_text,
            )
            implemented = []
            if class_match and class_match.group(1):
                for raw_interface in class_match.group(1).split(','):
                    simple = re.sub(r'<.*>', '', raw_interface).strip()
                    implemented.append(imports.get(simple, simple))
            method_names = set(re.findall(
                r'\b(?:public|protected)\s+(?:[\w.$<>\[\],?]+\s+)+([A-Za-z_]\w*)\s*\(',
                code_text,
            ))
            for raw_interface in implemented:
                simple = raw_interface.rsplit('.', 1)[-1]
                if simple not in callback_methods:
                    continue
                source, allowed = callback_methods[simple]
                callbacks = []
                for method_name in sorted(method_names):
                    if method_name not in allowed:
                        continue
                    callbacks.append(method_name)
                if callbacks:
                    handlers[owner] = {
                        'source': source,
                        'interface': raw_interface,
                        'methods': callbacks,
                        'file': str(path),
                    }

    registration_pattern = re.compile(
        r'Proxy\s*\.\s*newProxyInstance\s*\([\s\S]{0,800}?'
        r'new\s+Class(?:<[^>]+>)?\s*\[\s*\]\s*\{(?P<interfaces>[^}]*)\}'
        r'\s*,\s*(?P<handler>new\s+[A-Za-z_$][\w.$]*|[A-Za-z_$]\w*)',
        re.S,
    )
    for path, text in source_files:
        owner = _java_package_and_class(text, path.stem)
        imports = {
            item.rsplit('.', 1)[-1]: item
            for item in re.findall(r'\bimport\s+([\w.]+)\s*;', text)
        }
        matched_registrations = 0
        for match in registration_pattern.finditer(text):
            matched_registrations += 1
            registrations += 1
            interfaces = []
            for item in match.group('interfaces').split(','):
                class_match = re.search(r'([A-Za-z_$][\w.$]*)\s*\.\s*class\b', item.strip())
                if class_match:
                    value = class_match.group(1)
                    interfaces.append(imports.get(value.rsplit('.', 1)[-1], value))
            handler_expr = match.group('handler').strip()
            if handler_expr.startswith('new '):
                handler_type = handler_expr[4:].strip()
            else:
                declaration = re.search(
                    rf'\b([A-Za-z_$][\w.$<>]*)\s+{re.escape(handler_expr)}\b', text
                )
                handler_type = re.sub(r'<.*>', '', declaration.group(1)) if declaration else ''
            handler_type = imports.get(handler_type.rsplit('.', 1)[-1], handler_type)
            if handler_type and '.' not in handler_type:
                package_name = owner.rsplit('.', 1)[0] if '.' in owner else ''
                handler_type = f'{package_name}.{handler_type}' if package_name else handler_type
            handler = handlers.get(handler_type)
            findings.append({
                'reason_code': 'dynamic_proxy_registration',
                'subject': owner,
                'handler': handler_type,
                'interfaces': interfaces,
                'file': str(path),
            })
            if not handler:
                findings.append({
                    'reason_code': 'dynamic_proxy_handler_unresolved',
                    'subject': owner,
                    'handler': handler_type,
                    'file': str(path),
                })
                continue
            for method_name in handler['methods']:
                target = f'{handler_type}.{method_name}'
                nodes.append({'id': target, 'kind': 'dynamic_proxy_callback'})
                edges.append({
                    'source': handler['source'],
                    'target': target,
                    'edge_kind': 'dynamic_proxy_callback',
                    'confidence': 'high',
                    'conditions': [],
                    'ambiguity': False,
                    'provenance': {
                        'file': str(path),
                        'handler_file': handler['file'],
                        'interface': handler['interface'],
                    },
                })
        unmatched_registrations = max(0, text.count('Proxy.newProxyInstance') - matched_registrations)
        if unmatched_registrations:
            registrations += unmatched_registrations
            findings.append({
                'reason_code': 'dynamic_proxy_handler_unresolved',
                'subject': owner,
                'file': str(path),
                'count': unmatched_registrations,
            })
        if 'Enhancer.create' in text:
            registrations += text.count('Enhancer.create')
            findings.append({
                'reason_code': 'dynamic_proxy_handler_unresolved',
                'subject': owner,
                'file': str(path),
            })
    unresolved = any(
        item.get('reason_code') == 'dynamic_proxy_handler_unresolved'
        for item in findings
    )
    applicable = registrations > 0
    status = 'partial' if applicable and (errors or unresolved) else _status(applicable, errors)
    return {
        'adapter': 'dynamic_proxy_basic',
        'version': '1',
        'status': status,
        'nodes': nodes,
        'edges': edges,
        'findings': findings,
        'errors': errors,
        'metrics': {
            'source_files_scanned': scanned,
            'proxy_registrations': registrations,
            'edges': len(edges),
        },
    }


def run_declarative_http_client_adapter(source_roots):
    edges, nodes, findings, errors = [], [], [], []
    scanned = 0
    applicable = False
    client_annotations = ('FeignClient', 'HttpExchange')
    request_annotations = (
        'HttpExchange', 'GetExchange', 'PostExchange', 'PutExchange',
        'DeleteExchange', 'PatchExchange', 'RequestMapping', 'GetMapping',
        'PostMapping', 'PutMapping', 'DeleteMapping', 'PatchMapping', 'RequestLine',
    )
    request_pattern = re.compile(
        r'@(HttpExchange|GetExchange|PostExchange|PutExchange|DeleteExchange|PatchExchange|'
        r'RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestLine)'
        r'\s*(?:\(([^)]*)\))?'
    )
    interface_method_pattern = re.compile(
        r'(?P<annotations>(?:@[A-Za-z_$][\w.$]*(?:\s*\([^)]*\))?\s*)*)'
        r'(?:(?:public|default|static)\s+)?'
        r'(?P<return_type>[\w.$<>\[\],?]+)\s+'
        r'(?P<method_name>[A-Za-z_$]\w*)\s*\([^;{}]*\)\s*;',
        re.S,
    )

    def mapping_path(expression):
        text = str(expression or '').strip()
        if not text:
            return ''
        match = re.search(r'(?:\bvalue|\bpath)\s*=\s*["\']([^"\']+)["\']', text)
        if not match:
            match = re.search(r'["\']([^"\']+)["\']', text)
        return match.group(1).strip() if match else ''

    def combine_mapping_paths(class_path, method_path):
        if not class_path:
            return method_path
        if not method_path:
            return class_path
        return '/' + '/'.join((class_path.strip('/'), method_path.strip('/')))

    for path in _production_java_files(source_roots):
            scanned += 1
            try:
                text = _mask_java_comments(path.read_text(encoding='utf-8', errors='replace'))
            except OSError as exc:
                errors.append(f'{path}:{type(exc).__name__}')
                continue
            if not any(f'@{marker}' in text for marker in client_annotations):
                continue
            owner = _java_package_and_class(text, path.stem)
            if ' interface ' not in f' {text} ':
                continue
            class_annotations = text[:text.find('{')] if '{' in text else text
            if not any(f'@{marker}' in class_annotations for marker in client_annotations):
                continue
            applicable = True
            dynamic_endpoint = bool(re.search(r'[@$]\{[^}]+\}', class_annotations))
            client_kind = (
                'feign'
                if '@FeignClient' in class_annotations
                else 'http_exchange'
            )
            class_mapping_match = re.search(r'@RequestMapping\s*(?:\(([^)]*)\))?', class_annotations)
            class_mapping_expr = class_mapping_match.group(1) if class_mapping_match else ''
            class_mapping = mapping_path(class_mapping_expr)
            client_edges = 0
            for match in interface_method_pattern.finditer(text):
                annotations = match.group('annotations') or ''
                if not any(f'@{marker}' in annotations for marker in request_annotations):
                    continue
                method_name = match.group('method_name')
                target = f'{owner}.{method_name}'
                request_match = request_pattern.search(annotations) or request_pattern.search(class_annotations)
                request_annotation = request_match.group(1) if request_match else ('FeignClient' if client_kind == 'feign' else 'HttpExchange')
                request_expr = (request_match.group(2) or '').strip() if request_match else ''
                if request_expr and re.search(r'[@$]\{[^}]+\}', request_expr):
                    dynamic_endpoint = True
                request_mapping = combine_mapping_paths(class_mapping, mapping_path(request_expr))
                nodes.append({'id': target, 'kind': 'declarative_http_client_method'})
                edges.append({
                    'source': target,
                    'target': f'framework:declarative-http-client:{client_kind}:{owner}',
                    'edge_kind': 'declarative_http_client_outbound',
                    'confidence': 'high',
                    'conditions': [],
                    'ambiguity': False,
                    'provenance': {
                        'file': str(path),
                        'client_kind': client_kind,
                        'request_annotation': request_annotation,
                        'request_mapping': request_mapping,
                    },
                })
                client_edges += 1
            findings.append({
                'reason_code': 'declarative_http_client_registration',
                'subject': owner,
                'client_kind': client_kind,
                'file': str(path),
            })
            if dynamic_endpoint:
                findings.append({
                    'reason_code': 'declarative_http_client_runtime_endpoint',
                    'subject': owner,
                    'client_kind': client_kind,
                    'file': str(path),
                })
            if client_edges == 0:
                findings.append({
                    'reason_code': 'declarative_http_client_method_mapping_unresolved',
                    'subject': owner,
                    'client_kind': client_kind,
                    'file': str(path),
                })
    unresolved = any(
        item.get('reason_code') in {
            'declarative_http_client_runtime_endpoint',
            'declarative_http_client_method_mapping_unresolved',
        }
        for item in findings
    )
    return {
        'adapter': 'declarative_http_client_basic',
        'version': '1',
        'status': 'partial' if applicable and (errors or unresolved) else _status(applicable, errors),
        'nodes': nodes,
        'edges': edges,
        'findings': findings,
        'errors': errors,
        'metrics': {
            'source_files_scanned': scanned,
            'clients': len({item['subject'] for item in findings if item.get('reason_code') == 'declarative_http_client_registration'}),
            'edges': len(edges),
        },
    }


_SPRING_RUNTIME_CALLBACK_METHODS = {
    'org.springframework.context.ApplicationListener': 'onApplicationEvent',
    'org.springframework.boot.env.EnvironmentPostProcessor': 'postProcessEnvironment',
    'org.springframework.context.ApplicationContextInitializer': 'initialize',
}


def _spring_boot_business_activation(source_roots):
    evidence = []
    business_roots = []
    for item in source_roots or []:
        if isinstance(item, dict):
            if str(item.get('owner_type') or 'business').strip() != 'business':
                continue
            value = item.get('root')
        else:
            value = item
        if value and Path(value).is_dir():
            business_roots.append(Path(value).resolve())
    for root in business_roots:
        for path in sorted(root.rglob('*.java')):
            normalized_path = path.as_posix()
            if '/src/test/' in normalized_path or '/test/' in normalized_path:
                continue
            try:
                text = _mask_java_comments(path.read_text(encoding='utf-8', errors='replace'))
            except OSError:
                continue
            if not (
                re.search(r'\bSpringApplication\s*\.\s*run\s*\(', text)
                or re.search(r'@(?:[\w.]+\.)?(?:SpringBootApplication|EnableAutoConfiguration)\b', text)
            ):
                continue
            owner = _java_package_and_class(text, path.stem)
            spring_application_run = bool(re.search(r'\bSpringApplication\s*\.\s*run\s*\(', text))
            evidence.append({
                'file': str(path),
                'spring_application_run': spring_application_run,
                'spring_boot_annotation': bool(re.search(
                    r'@(?:[\w.]+\.)?(?:SpringBootApplication|EnableAutoConfiguration)\b', text
                )),
                'business_entry': f'{owner}.main' if owner and spring_application_run else owner,
            })
    return evidence


def _logical_properties(text):
    logical_lines = []
    pending = ''
    for raw in str(text or '').splitlines():
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
        key, values = line.split('=', 1)
        yield line_no, key.strip(), [item.strip() for item in values.split(',') if item.strip()]


_JAVAP_METHOD_HEADER = re.compile(
    r'^  (?P<header>.+?\([^;]*\))(?: throws [^;]+)?;$'
)
_JAVAP_INSTRUCTION = re.compile(r'^\s*(?P<offset>\d+):\s+(?P<opcode>[a-z][a-z0-9_]*)\b(?P<rest>.*)$')
_MESSAGE_LISTENER_ADAPTER_INIT = (
    'org/springframework/amqp/rabbit/listener/adapter/MessageListenerAdapter."<init>":'
    '(Ljava/lang/Object;Ljava/lang/String;)V'
)


def _descriptor_reference_slots(descriptor, is_static):
    slots = {}
    slot = 0 if is_static else 1
    index = 1
    while index < len(descriptor) and descriptor[index] != ')':
        start = index
        while descriptor[index] == '[':
            index += 1
        code = descriptor[index]
        reference = ''
        width = 1
        if code == 'L':
            end = descriptor.index(';', index)
            reference = descriptor[index + 1:end].replace('/', '.')
            index = end + 1
        else:
            if code in {'J', 'D'} and start == index:
                width = 2
            index += 1
        if reference and start == index - len(reference) - 2:
            slots[slot] = reference
        slot += width
    return slots


def _parse_javap_methods(text):
    owner_match = re.search(r'^(?:public\s+)?(?:class|interface|enum|record)\s+([\w.$]+)', text, re.MULTILINE)
    owner = owner_match.group(1) if owner_match else ''
    methods = []
    current = None
    for line in text.splitlines():
        header_match = _JAVAP_METHOD_HEADER.match(line)
        if header_match:
            header = header_match.group('header')
            prefix = header.split('(', 1)[0].strip()
            current = {
                'owner': owner,
                'member': prefix.rsplit(' ', 1)[-1].rsplit('.', 1)[-1],
                'header': header,
                'descriptor': '',
                'instructions': [],
            }
            methods.append(current)
            continue
        if current is None:
            continue
        descriptor_match = re.match(r'^\s+descriptor:\s+(\S+)\s*$', line)
        if descriptor_match:
            current['descriptor'] = descriptor_match.group(1)
            continue
        instruction_match = _JAVAP_INSTRUCTION.match(line)
        if instruction_match:
            current['instructions'].append({
                'offset': int(instruction_match.group('offset')),
                'opcode': instruction_match.group('opcode'),
                'rest': instruction_match.group('rest'),
            })
    return owner, methods


def _descriptor_parameter_types(descriptor):
    primitives = {
        'B': 'byte', 'C': 'char', 'D': 'double', 'F': 'float',
        'I': 'int', 'J': 'long', 'S': 'short', 'Z': 'boolean',
    }
    if not str(descriptor or '').startswith('('):
        return None
    parameters = []
    index = 1
    while index < len(descriptor) and descriptor[index] != ')':
        dimensions = 0
        while index < len(descriptor) and descriptor[index] == '[':
            dimensions += 1
            index += 1
        if index >= len(descriptor):
            return None
        marker = descriptor[index]
        if marker == 'L':
            end = descriptor.find(';', index)
            if end < 0:
                return None
            value = descriptor[index + 1:end].replace('/', '.').replace('$', '.')
            index = end + 1
        else:
            value = primitives.get(marker)
            index += 1
        if not value:
            return None
        parameters.append(value + '[]' * dimensions)
    return parameters if index < len(descriptor) and descriptor[index] == ')' else None


_SPRING_DATA_REPOSITORY_CONTRACTS = {
    'Repository', 'CrudRepository', 'ListCrudRepository',
    'PagingAndSortingRepository', 'ListPagingAndSortingRepository',
    'JpaRepository',
}
_SIMPLE_JPA_REPOSITORY = (
    'org.springframework.data.jpa.repository.support.SimpleJpaRepository'
)


def _split_java_type_list(value):
    values = []
    start = 0
    depth = 0
    for index, character in enumerate(str(value or '')):
        if character == '<':
            depth += 1
        elif character == '>':
            depth = max(0, depth - 1)
        elif character == ',' and depth == 0:
            values.append(value[start:index].strip())
            start = index + 1
    tail = value[start:].strip()
    if tail:
        values.append(tail)
    return values


def _spring_data_business_repositories(source_roots):
    repositories = []
    for path in _production_java_files(source_roots):
        try:
            text = _mask_java_comments(path.read_text(encoding='utf-8', errors='replace'))
        except OSError:
            continue
        imports = {
            value.rsplit('.', 1)[-1]: value
            for value in re.findall(r'\bimport\s+([\w.]+)\s*;', text)
        }
        interface = re.search(
            r'\binterface\s+([A-Za-z_$]\w*)\s+extends\s+([^\{]+)\{', text
        )
        if not interface:
            continue
        spring_contracts = []
        for raw_parent in _split_java_type_list(interface.group(2)):
            parent = re.sub(r'<[\s\S]*>', '', raw_parent).strip()
            simple = parent.rsplit('.', 1)[-1]
            resolved = imports.get(simple, parent)
            if (
                simple in _SPRING_DATA_REPOSITORY_CONTRACTS
                and str(resolved).startswith('org.springframework.data.')
            ):
                spring_contracts.append(resolved)
        if not spring_contracts:
            continue
        declared_method_counts = {}
        body = text[interface.end():]
        for declaration in re.finditer(
            r'\b([A-Za-z_$]\w*)\s*\(([^;{}]*)\)\s*(?:throws\s+[^;{}]+)?;', body
        ):
            parameter_text = declaration.group(2).strip()
            parameter_count = (
                0 if not parameter_text
                else len(_split_java_type_list(parameter_text))
            )
            key = f'{declaration.group(1)}/{parameter_count}'
            declared_method_counts[key] = declared_method_counts.get(key, 0) + 1
        repositories.append({
            'owner': _java_package_and_class(text, interface.group(1)),
            'file': str(path),
            'contracts': sorted(set(spring_contracts)),
            'declared_method_counts': declared_method_counts,
        })
    return repositories


def _spring_data_custom_repository_configuration(source_roots):
    custom = []
    for path in _production_java_files(source_roots):
        try:
            text = _mask_java_comments(path.read_text(encoding='utf-8', errors='replace'))
        except OSError:
            continue
        if not re.search(r'@(?:[\w.]+\.)?EnableJpaRepositories\b', text):
            continue
        attributes = sorted(set(re.findall(
            r'\b(repositoryBaseClass|repositoryFactoryBeanClass)\s*=', text
        )))
        if attributes:
            custom.append({'file': str(path), 'attributes': attributes})
    return custom


def run_spring_data_repository_adapter(source_roots, artifact_catalog=None):
    """Resolve Spring Data repository proxies from source contracts and packaged runtime code."""
    repositories = _spring_data_business_repositories(source_roots)
    custom_configuration = _spring_data_custom_repository_configuration(source_roots)
    activation_evidence = _spring_boot_business_activation(source_roots)
    entries = [
        item for item in (artifact_catalog or {}).get('entries') or []
        if str(item.get('coord') or '').strip() == 'org.springframework.data:spring-data-jpa'
        and Path(str(item.get('jar_path') or '')).is_file()
    ]
    edges, nodes, findings, errors = [], [], [], []
    if repositories and not activation_evidence:
        findings.append({
            'reason_code': 'spring_data_activation_unproven',
            'subject': ','.join(item['owner'] for item in repositories),
        })
    if repositories and custom_configuration:
        findings.extend({
            'reason_code': 'spring_data_custom_repository_factory',
            'subject': item['file'],
            'attributes': item['attributes'],
        } for item in custom_configuration)
    if repositories and not entries and not custom_configuration:
        findings.append({
            'reason_code': 'spring_data_runtime_implementation_unresolved',
            'subject': _SIMPLE_JPA_REPOSITORY,
        })
    implementation_methods = []
    if (
        repositories and activation_evidence and len(entries) == 1
        and not custom_configuration
    ):
        entry = entries[0]
        jar_path = str(entry.get('jar_path') or '')
        try:
            completed = subprocess.run(
                ['javap', '-p', '-s', '-classpath', jar_path, _SIMPLE_JPA_REPOSITORY],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30,
            )
            if completed.returncode != 0:
                errors.append(f'{jar_path}:{_SIMPLE_JPA_REPOSITORY}:javap_exit_{completed.returncode}')
            else:
                owner, methods = _parse_javap_methods(completed.stdout)
                if owner != _SIMPLE_JPA_REPOSITORY:
                    errors.append(f'{jar_path}:{_SIMPLE_JPA_REPOSITORY}:owner_mismatch:{owner}')
                else:
                    for method in methods:
                        parameters = _descriptor_parameter_types(method.get('descriptor'))
                        if (
                            parameters is None
                            or not str(method.get('header') or '').startswith('public ')
                            or method.get('member') == _SIMPLE_JPA_REPOSITORY.rsplit('.', 1)[-1]
                        ):
                            continue
                        implementation_methods.append({
                            'member': method['member'],
                            'parameters': parameters,
                            'descriptor': method['descriptor'],
                        })
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f'{jar_path}:{_SIMPLE_JPA_REPOSITORY}:{type(exc).__name__}')

        for repository in repositories:
            for method in implementation_methods:
                target = (
                    f"{_SIMPLE_JPA_REPOSITORY}.{method['member']}"
                    f"({','.join(method['parameters'])})"
                )
                nodes.append({'id': target, 'kind': 'spring_data_repository_proxy_implementation'})
                edges.append({
                    'source': repository['owner'],
                    'target': target,
                    'target_member': method['member'],
                    'target_descriptor': method['descriptor'],
                    'parameter_count': len(method['parameters']),
                    'repository_declared_method_count': repository[
                        'declared_method_counts'
                    ].get(f"{method['member']}/{len(method['parameters'])}", 0),
                    'edge_kind': 'spring_data_repository_proxy_dispatch',
                    'confidence': 'high',
                    'conditions': [],
                    'ambiguity': False,
                    'provenance': {
                        'file': repository['file'],
                        'repository_contracts': repository['contracts'],
                        'coord': entry.get('coord'),
                        'jar': jar_path,
                        'artifact_entry': entry.get('artifact_entry'),
                        'artifact_sha256': entry.get('sha256'),
                        'implementation_class': _SIMPLE_JPA_REPOSITORY,
                        'implementation_descriptor': method['descriptor'],
                        'business_activation': activation_evidence,
                        'authority': 'final_artifact_javap',
                    },
                })
    applicable = bool(repositories)
    unresolved = bool(repositories and (
        not activation_evidence or len(entries) != 1 or custom_configuration
    ))
    return {
        'adapter': 'spring_data_repository_proxy',
        'version': '1',
        'status': 'partial' if applicable and (errors or unresolved) else _status(applicable, errors),
        'nodes': nodes,
        'edges': edges,
        'findings': findings,
        'errors': errors,
        'metrics': {
            'repositories': len(repositories),
            'runtime_implementations': len(entries),
            'implementation_methods': len(implementation_methods),
            'custom_repository_configurations': len(custom_configuration),
            'edges': len(edges),
        },
    }


def _aload_slot(instruction):
    opcode = str(instruction.get('opcode') or '')
    if re.fullmatch(r'aload_[0-3]', opcode):
        return int(opcode[-1])
    if opcode == 'aload':
        match = re.match(r'\s+(\d+)', str(instruction.get('rest') or ''))
        return int(match.group(1)) if match else None
    return None


def _message_listener_adapter_callbacks(jar_path, coord, activation_evidence):
    parsed = []
    errors = []
    try:
        with zipfile.ZipFile(jar_path) as jar, tempfile.TemporaryDirectory(
            prefix='spring-message-listener-adapter-'
        ) as temporary:
            class_names = sorted(
                name for name in jar.namelist()
                if name.endswith('.class') and not name.startswith('META-INF/')
            )
            parsed_entries = set()

            def parse_entry(name):
                if name in parsed_entries:
                    return
                parsed_entries.add(name)
                content = jar.read(name)
                class_file = Path(temporary) / f'class-{len(parsed_entries):06d}.class'
                class_file.write_bytes(content)
                completed = subprocess.run(
                    ['javap', '-c', '-p', '-s', str(class_file)],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=30,
                )
                if completed.returncode != 0:
                    errors.append(f'{jar_path}!/{name}:javap_exit_{completed.returncode}')
                    return
                owner, methods = _parse_javap_methods(completed.stdout)
                parsed.append({'owner': owner, 'entry': name, 'methods': methods})

            for name in class_names:
                if b'MessageListenerAdapter' in jar.read(name):
                    parse_entry(name)

            callback_owners = set()
            for item in parsed:
                for method in item['methods']:
                    instructions = method['instructions']
                    for index, instruction in enumerate(instructions):
                        if (
                            instruction['opcode'] != 'invokespecial'
                            or _MESSAGE_LISTENER_ADAPTER_INIT not in instruction['rest']
                        ):
                            continue
                        window = instructions[max(0, index - 4):index]
                        string_instruction = next((
                            candidate for candidate in reversed(window)
                            if candidate['opcode'] in {'ldc', 'ldc_w'}
                            and re.search(r'//\s+String\s+\S+', candidate['rest'])
                        ), None)
                        aload_instruction = next((
                            candidate for candidate in reversed(window)
                            if _aload_slot(candidate) is not None
                            and (
                                string_instruction is None
                                or candidate['offset'] < string_instruction['offset']
                            )
                        ), None)
                        if string_instruction is None or aload_instruction is None:
                            continue
                        slots = _descriptor_reference_slots(
                            method['descriptor'], ' static ' in f" {method['header']} "
                        )
                        callback_owner = slots.get(_aload_slot(aload_instruction), '')
                        if callback_owner:
                            callback_owners.add(callback_owner)

            class_name_set = set(class_names)
            for callback_owner in sorted(callback_owners):
                callback_entry = callback_owner.replace('.', '/') + '.class'
                if callback_entry in class_name_set:
                    parse_entry(callback_entry)
    except (OSError, zipfile.BadZipFile, subprocess.TimeoutExpired) as exc:
        return [], [f'{jar_path}:{type(exc).__name__}']

    descriptors = {}
    for item in parsed:
        for method in item['methods']:
            descriptors.setdefault((item['owner'], method['member']), set()).add(
                method['descriptor']
            )
    callbacks = []
    seen = set()
    for item in parsed:
        for method in item['methods']:
            instructions = method['instructions']
            for index, instruction in enumerate(instructions):
                if (
                    instruction['opcode'] != 'invokespecial'
                    or _MESSAGE_LISTENER_ADAPTER_INIT not in instruction['rest']
                ):
                    continue
                window = instructions[max(0, index - 4):index]
                string_instruction = next((
                    candidate for candidate in reversed(window)
                    if candidate['opcode'] in {'ldc', 'ldc_w'}
                    and re.search(r'//\s+String\s+\S+', candidate['rest'])
                ), None)
                aload_instruction = next((
                    candidate for candidate in reversed(window)
                    if _aload_slot(candidate) is not None
                    and (
                        string_instruction is None
                        or candidate['offset'] < string_instruction['offset']
                    )
                ), None)
                if string_instruction is None or aload_instruction is None:
                    continue
                callback_name_match = re.search(
                    r'//\s+String\s+(\S+)', string_instruction['rest']
                )
                slots = _descriptor_reference_slots(
                    method['descriptor'], ' static ' in f" {method['header']} "
                )
                callback_owner = slots.get(_aload_slot(aload_instruction), '')
                callback_name = callback_name_match.group(1) if callback_name_match else ''
                callback_descriptors = descriptors.get((callback_owner, callback_name), set())
                if not callback_owner or not callback_name or len(callback_descriptors) != 1:
                    continue
                callback_descriptor = next(iter(callback_descriptors))
                identity = (
                    item['owner'], method['member'], callback_owner,
                    callback_name, callback_descriptor, instruction['offset'],
                )
                if identity in seen:
                    continue
                seen.add(identity)
                callbacks.append({
                    'source': 'framework:spring-amqp-message-listener-adapter',
                    'target': f'{callback_owner}.{callback_name}',
                    'target_descriptor': callback_descriptor,
                    'edge_kind': 'spring_runtime_registered_callback',
                    'confidence': 'high' if activation_evidence else 'medium',
                    'conditions': [] if activation_evidence else ['spring_boot_activation_unproven'],
                    'ambiguity': False,
                    'runtime_activation': 'active' if activation_evidence else 'unproven',
                    'provenance': {
                        'coord': coord,
                        'jar': str(jar_path),
                        'artifact_entry': item['entry'],
                        'line': instruction['offset'],
                        'registration_owner': item['owner'],
                        'registration_member': method['member'],
                        'registration_descriptor': method['descriptor'],
                        'registration_instruction_offset': instruction['offset'],
                        'adapter_owner': (
                            'org.springframework.amqp.rabbit.listener.adapter.MessageListenerAdapter'
                        ),
                        'callback_owner': callback_owner,
                        'callback_member': callback_name,
                        'callback_descriptor': callback_descriptor,
                        'business_activation': activation_evidence,
                        'authority': 'final_artifact_javap_dataflow',
                    },
                })
    return callbacks, errors


def run_runtime_spring_registration_adapter(source_roots, artifact_catalog=None):
    """Read Spring registrations from the exact packaged runtime jars.

    A registration is a confirmed runtime entry only when business code proves that Spring Boot
    starts. Auto-configuration classes remain conditional: registration alone does not prove that
    a particular @Bean method executes.
    """
    activation_evidence = _spring_boot_business_activation(source_roots)
    spring_boot_active = bool(activation_evidence)
    edges, nodes, findings, errors = [], [], [], []
    resource_files = 0
    active_callbacks = 0
    conditional_autoconfigurations = 0
    seen = set()
    for item in (artifact_catalog or {}).get('entries') or []:
        coord = str(item.get('coord') or '').strip()
        jar_path = str(item.get('jar_path') or '').strip()
        if not jar_path or not Path(jar_path).is_file():
            continue
        if coord == '__business__':
            callbacks, callback_errors = _message_listener_adapter_callbacks(
                jar_path, coord, activation_evidence
            )
            errors.extend(callback_errors)
            for edge in callbacks:
                identity = (
                    'message_listener_adapter', edge['target'],
                    edge.get('target_descriptor'), jar_path,
                )
                if identity in seen:
                    continue
                seen.add(identity)
                nodes.append({
                    'id': edge['target'],
                    'kind': 'spring_runtime_registered_callback',
                })
                edges.append(edge)
                if edge['runtime_activation'] == 'active':
                    active_callbacks += 1
            continue
        try:
            with zipfile.ZipFile(jar_path) as jar:
                names = set(jar.namelist())
                factories_name = 'META-INF/spring.factories'
                if factories_name in names:
                    resource_files += 1
                    text = jar.read(factories_name).decode('utf-8', errors='replace')
                    for line_no, registration_type, targets in _logical_properties(text):
                        callback_method = _SPRING_RUNTIME_CALLBACK_METHODS.get(registration_type)
                        for target_class in targets:
                            if callback_method:
                                target = f'{target_class}.{callback_method}'
                                identity = ('callback', registration_type, target, jar_path)
                                if identity in seen:
                                    continue
                                seen.add(identity)
                                nodes.append({'id': target, 'kind': 'spring_runtime_registered_callback'})
                                edges.append({
                                    'source': f'framework:spring-factories:{registration_type}',
                                    'target': target,
                                    'edge_kind': 'spring_runtime_registered_callback',
                                    'confidence': 'high' if spring_boot_active else 'medium',
                                    'conditions': [] if spring_boot_active else ['spring_boot_activation_unproven'],
                                    'ambiguity': False,
                                    'runtime_activation': 'active' if spring_boot_active else 'unproven',
                                    'provenance': {
                                        'coord': coord,
                                        'jar': jar_path,
                                        'resource': factories_name,
                                        'line': line_no,
                                        'registration_type': registration_type,
                                        'business_activation': activation_evidence,
                                    },
                                })
                                if spring_boot_active:
                                    active_callbacks += 1
                            elif registration_type == 'org.springframework.boot.autoconfigure.EnableAutoConfiguration':
                                identity = ('autoconfiguration', target_class, jar_path)
                                if identity in seen:
                                    continue
                                seen.add(identity)
                                nodes.append({'id': target_class, 'kind': 'spring_runtime_autoconfiguration'})
                                edges.append({
                                    'source': 'framework:spring-autoconfiguration',
                                    'target': target_class,
                                    'edge_kind': 'spring_runtime_autoconfiguration_registration',
                                    'confidence': 'medium',
                                    'conditions': ['auto_configuration_conditions_require_runtime_evaluation'],
                                    'ambiguity': False,
                                    'runtime_activation': 'conditional',
                                    'provenance': {
                                        'coord': coord,
                                        'jar': jar_path,
                                        'resource': factories_name,
                                        'line': line_no,
                                        'registration_type': registration_type,
                                        'business_activation': activation_evidence,
                                    },
                                })
                                conditional_autoconfigurations += 1
                imports_name = 'META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports'
                if imports_name in names:
                    resource_files += 1
                    text = jar.read(imports_name).decode('utf-8', errors='replace')
                    for line_no, raw in enumerate(text.splitlines(), 1):
                        target_class = raw.split('#', 1)[0].strip()
                        if not target_class:
                            continue
                        identity = ('autoconfiguration', target_class, jar_path)
                        if identity in seen:
                            continue
                        seen.add(identity)
                        nodes.append({'id': target_class, 'kind': 'spring_runtime_autoconfiguration'})
                        edges.append({
                            'source': 'framework:spring-autoconfiguration',
                            'target': target_class,
                            'edge_kind': 'spring_runtime_autoconfiguration_registration',
                            'confidence': 'medium',
                            'conditions': ['auto_configuration_conditions_require_runtime_evaluation'],
                            'ambiguity': False,
                            'runtime_activation': 'conditional',
                            'provenance': {
                                'coord': coord,
                                'jar': jar_path,
                                'resource': imports_name,
                                'line': line_no,
                                'business_activation': activation_evidence,
                            },
                        })
                        conditional_autoconfigurations += 1
        except (OSError, zipfile.BadZipFile, UnicodeError) as exc:
            errors.append(f'{jar_path}:{type(exc).__name__}')
    if resource_files and not spring_boot_active:
        findings.append({
            'reason_code': 'spring_boot_activation_unproven',
            'subject': 'packaged_spring_registrations',
        })
    applicable = bool(resource_files or activation_evidence)
    return {
        'adapter': 'spring_runtime_artifact',
        'version': '1',
        'status': 'partial' if applicable and (errors or (resource_files and not spring_boot_active)) else _status(applicable, errors),
        'nodes': nodes,
        'edges': edges,
        'findings': findings,
        'errors': errors,
        'metrics': {
            'resource_files': resource_files,
            'business_activation_files': len(activation_evidence),
            'active_callbacks': active_callbacks,
            'conditional_autoconfigurations': conditional_autoconfigurations,
            'edges': len(edges),
        },
    }


def run_framework_adapters(source_roots, output_path='', artifact_catalog=None):
    adapters = [
        run_spi_adapter(source_roots),
        run_spring_adapter(source_roots),
        run_runtime_spring_registration_adapter(source_roots, artifact_catalog=artifact_catalog),
        run_spring_data_repository_adapter(source_roots, artifact_catalog=artifact_catalog),
        run_mybatis_adapter(source_roots),
        run_dynamic_proxy_adapter(source_roots),
        run_declarative_http_client_adapter(source_roots),
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
    if not hasattr(graph, 'reverse_edges') or getattr(graph, 'reverse_edges') is None:
        graph.reverse_edges = {}
    methods_by_qualified = {}
    methods_by_unsigned = {}
    for method in methods:
        qualified = str(getattr(method, 'qualified_key', '') or '')
        if not qualified:
            continue
        methods_by_qualified.setdefault(qualified, []).append(method)
        unsigned = qualified.split('(', 1)[0]
        methods_by_unsigned.setdefault(unsigned, []).append(method)
    entries = {}
    runtime_entries = {}
    activation_linked_symbols = set()
    matched_edges = 0
    unmatched_edges = 0
    proxy_dispatch_edges = 0
    ambiguous_proxy_dispatches = 0
    supported_kinds = {
        'spring_event_listener', 'spring_framework_callback', 'spring_bean_dispatch',
        'spring_runtime_active_entry',
        'java_spi_load_point', 'java_spi_registration', 'dubbo_spi_registration',
        'mybatis_mapper_binding', 'mybatis_annotation_binding',
        'mybatis_type_reference',
        'mybatis_type_handler_binding', 'mybatis_type_handler_registration',
        'mybatis_plugin_registration', 'spring_autoconfiguration_registration',
        'spring_factories_registration', 'spring_runtime_registered_callback',
        'spring_runtime_autoconfiguration_registration',
    }

    def method_signature(method):
        qualified = str(getattr(method, 'qualified_key', '') or '')
        return qualified[qualified.find('('):] if '(' in qualified else ''

    def method_key_parts(value):
        match = re.match(
            r'^(?P<owner>[\w.$]+)\.(?P<member>[\w$<>]+)\((?P<parameters>.*)\)$',
            str(value or '').strip(),
        )
        if not match:
            return None
        parameters = match.group('parameters').strip()
        count = 0 if not parameters else len(parameters.split(','))
        return match.group('owner'), match.group('member'), count

    reverse_edge_snapshot = dict(graph.reverse_edges)
    for adapter in (payload or {}).get('adapters') or []:
        dispatch_edges = [
            edge for edge in adapter.get('edges') or []
            if edge.get('edge_kind') == 'spring_data_repository_proxy_dispatch'
        ]
        grouped = {}
        for edge in dispatch_edges:
            identity = (
                str(edge.get('source') or ''),
                str(edge.get('target_member') or ''),
                int(edge.get('parameter_count') or 0),
            )
            grouped.setdefault(identity, []).append(edge)
        for (repository, member, parameter_count), implementation_edges in grouped.items():
            source_keys = []
            for lookup_key, callers in reverse_edge_snapshot.items():
                parts = method_key_parts(lookup_key)
                if (
                    callers and parts
                    and parts == (repository, member, parameter_count)
                ):
                    source_keys.append(lookup_key)
            declared_method_count = max(
                int(edge.get('repository_declared_method_count') or 0)
                for edge in implementation_edges
            )
            if len(implementation_edges) != 1 or declared_method_count > 1:
                if source_keys or declared_method_count > 1:
                    ambiguous_proxy_dispatches += 1
                continue
            implementation = implementation_edges[0]
            target = str(implementation.get('target') or '').strip()
            if not target:
                continue
            provenance = implementation.get('provenance') or {}
            target_lookup_keys = [target]
            if '(' in target and target.endswith(')'):
                unsigned, signature_body = target.rsplit('(', 1)
                signature = '(' + signature_body
                normalized = normalize_signature_for_lookup(signature)
                compact_normalized = normalized.replace(', ', ',') if normalized else ''
                for alias_signature in (normalized, compact_normalized):
                    if alias_signature:
                        alias = unsigned + alias_signature
                        if alias not in target_lookup_keys:
                            target_lookup_keys.append(alias)
            callers_by_symbol = {}

            def caller_evidence_rank(caller):
                if str(getattr(caller, 'evidence_source', '') or '') == 'current_final_artifact':
                    return 3
                if getattr(caller, 'runtime_analyzer_hit', None):
                    return 2
                if str(getattr(caller, 'evidence_type', '') or '').startswith('bytecode_'):
                    return 1
                return 0

            for source_key in source_keys:
                for caller in reverse_edge_snapshot.get(source_key) or []:
                    caller_symbol = str(getattr(caller, 'caller_symbol_id', '') or '')
                    existing = callers_by_symbol.get(caller_symbol)
                    if existing is None or caller_evidence_rank(caller) > caller_evidence_rank(existing):
                        callers_by_symbol[caller_symbol] = caller
            for caller in callers_by_symbol.values():
                values = dict(vars(caller))
                values.update({
                    'callee_key': target,
                    'callee_simple_key': target.rsplit('.', 1)[-1],
                    'evidence_type': 'spring_data_repository_proxy_dispatch',
                    'confidence': 'high',
                    'file': str(provenance.get('jar') or values.get('file') or ''),
                    'content': (
                        f"Spring Data repository proxy dispatch: {source_keys[0]} -> {target}"
                    ),
                    'framework_registration': True,
                    'framework_source': repository,
                    'framework_target': target,
                    'framework_provenance': dict(provenance),
                    'runtime_activation': 'active',
                })
                synthetic = SimpleNamespace(**values)
                identity = (
                    synthetic.caller_symbol_id,
                    synthetic.callee_key,
                    synthetic.evidence_type,
                )
                attached = False
                for target_lookup_key in target_lookup_keys:
                    bucket = graph.reverse_edges.setdefault(target_lookup_key, [])
                    if any(
                        (
                            getattr(existing, 'caller_symbol_id', ''),
                            getattr(existing, 'callee_key', ''),
                            getattr(existing, 'evidence_type', ''),
                        ) == identity
                        for existing in bucket
                    ):
                        continue
                    bucket.append(synthetic)
                    attached = True
                if attached:
                    proxy_dispatch_edges += 1

    for adapter in (payload or {}).get('adapters') or []:
        for edge in adapter.get('edges') or []:
            if edge.get('edge_kind') not in supported_kinds:
                continue
            target = str(edge.get('target') or '').strip()
            if not target:
                unmatched_edges += 1
                continue
            if edge.get('edge_kind') == 'dubbo_spi_registration':
                # A Dubbo resource registers a provider class, not a concrete
                # method.  Connect only implementations of interface methods
                # already present in the graph; attaching every provider method
                # would manufacture false business entries.
                interface_methods = [
                    method for method in methods
                    if str(getattr(method, 'class_fqcn', '') or '') == str(edge.get('source') or '')
                ]
                candidates = []
                for interface_method in interface_methods:
                    interface_name = str(getattr(interface_method, 'method_name', '') or '')
                    interface_signature = method_signature(interface_method)
                    for method in methods:
                        if str(getattr(method, 'class_fqcn', '') or '') != target:
                            continue
                        if str(getattr(method, 'method_name', '') or '') != interface_name:
                            continue
                        if interface_signature and method_signature(method) != interface_signature:
                            continue
                        candidates.append(method)
                if not candidates:
                    unmatched_edges += 1
                    continue
            else:
                target_unsigned = target.split('(', 1)[0]
                candidates = list(methods_by_qualified.get(target) or [])
                if target_unsigned != target:
                    for method in methods_by_unsigned.get(target_unsigned) or []:
                        if method not in candidates:
                            candidates.append(method)
                else:
                    for method in methods_by_unsigned.get(target) or []:
                        if method not in candidates:
                            candidates.append(method)
            if (
                edge.get('edge_kind') == 'spring_runtime_registered_callback'
                and edge.get('runtime_activation') == 'active'
            ):
                runtime_entries.setdefault(target.split('(', 1)[0], []).append({
                    **edge,
                    'adapter': adapter.get('adapter'),
                    'adapter_version': adapter.get('version'),
                })
            for method in candidates:
                entries.setdefault(method.symbol_id, []).append({
                    **edge,
                    'adapter': adapter.get('adapter'),
                    'adapter_version': adapter.get('version'),
                })
                matched_edges += 1

                if not (
                    edge.get('edge_kind') == 'spring_runtime_registered_callback'
                    and edge.get('runtime_activation') == 'active'
                ):
                    continue
                activations = list((edge.get('provenance') or {}).get('business_activation') or [])
                for activation in activations:
                    activation_name = str((activation or {}).get('business_entry') or '').strip()
                    if not activation_name:
                        continue
                    activation_methods = list(methods_by_qualified.get(activation_name) or [])
                    activation_methods.extend(
                        item for item in methods_by_unsigned.get(activation_name) or []
                        if item not in activation_methods
                    )
                    activation_methods = [
                        item for item in activation_methods
                        if getattr(item, 'owner_type', '') == 'business'
                        and not getattr(item, 'is_test', False)
                    ]
                    if not activation_methods:
                        continue
                    callback_signature = str(getattr(method, 'declared_signature', '') or '').strip()
                    callback_key = (
                        str(getattr(method, 'declared_qualified_key', '') or '').strip()
                        or (
                            f"{getattr(method, 'qualified_key', '')}{callback_signature}"
                            if callback_signature else str(getattr(method, 'qualified_key', '') or '').strip()
                        )
                    )
                    callback_keys = [
                        callback_key,
                        str(getattr(method, 'qualified_key', '') or '').strip(),
                        target,
                    ]
                    for activation_method in activation_methods:
                        synthetic = SimpleNamespace(
                            caller_symbol_id=getattr(activation_method, 'symbol_id', ''),
                            caller_qualified_key=getattr(activation_method, 'qualified_key', ''),
                            callee_key=callback_key or target,
                            callee_simple_key='',
                            evidence_type='spring_runtime_registered_callback',
                            confidence='high',
                            file=str((edge.get('provenance') or {}).get('jar') or ''),
                            line=int((edge.get('provenance') or {}).get('line') or 0),
                            content='Spring Boot 启动后根据当前制品的框架注册触发回调',
                            owner_type='business',
                            owner_coord='BUSINESS',
                            module=getattr(activation_method, 'module', ''),
                            is_test=False,
                            framework_registration=True,
                            framework_source=edge.get('source') or '',
                            framework_target=target,
                            runtime_activation='active',
                        )
                        for lookup_key in dict.fromkeys(key for key in callback_keys if key):
                            bucket = graph.reverse_edges.setdefault(lookup_key, [])
                            identity = (
                                synthetic.caller_symbol_id,
                                synthetic.callee_key,
                                synthetic.evidence_type,
                            )
                            if not any(
                                (
                                    getattr(existing, 'caller_symbol_id', ''),
                                    getattr(existing, 'callee_key', ''),
                                    getattr(existing, 'evidence_type', ''),
                                ) == identity
                                for existing in bucket
                            ):
                                bucket.append(synthetic)
                        activation_linked_symbols.add(method.symbol_id)
    graph.framework_entry_symbols = entries
    graph.framework_runtime_entry_methods = runtime_entries
    graph.framework_activation_linked_symbols = activation_linked_symbols
    graph.framework_edges = [
        edge
        for adapter in (payload or {}).get('adapters') or []
        for edge in adapter.get('edges') or []
    ]
    return {
        'matched_callback_edges': matched_edges,
        'unmatched_callback_edges': unmatched_edges,
        'framework_entry_methods': len(entries),
        'runtime_framework_entry_methods': len(runtime_entries),
        'framework_activation_linked_methods': len(activation_linked_symbols),
        'framework_proxy_dispatch_edges': proxy_dispatch_edges,
        'ambiguous_framework_proxy_dispatches': ambiguous_proxy_dispatches,
    }
