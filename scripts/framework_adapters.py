#!/usr/bin/env python3
"""Independent evidence adapters for Java SPI, Spring, MyBatis and proxy edges."""

from __future__ import annotations

import json
import re
import safe_xml as ET
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Protocol

from enhanced_source_analyzer import analyze_file


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
        r'@(?:[\w.]+\.)?(Scheduled|PostConstruct)(?:\([^)]*\))?'
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
            if ast_authoritative:
                for method in ast_methods:
                    annotations = {str(item).rsplit('.', 1)[-1] for item in method.annotations or []}
                    method_owner = str(getattr(method, 'class_fqcn', '') or owner)
                    method_name = str(getattr(method, 'method_name', '') or '')
                    if method_name and 'EventListener' in annotations:
                        listener_targets.append((f'{method_owner}.{method_name}', '@EventListener'))
                    for annotation in ('Scheduled', 'PostConstruct'):
                        if method_name and annotation in annotations:
                            active_targets.append((f'{method_owner}.{method_name}', annotation))
            else:
                listener_targets.extend(
                    (f'{owner}.{match.group(1)}', '@EventListener')
                    for match in listener_pattern.finditer(text)
                )
                active_targets.extend(
                    (f'{owner}.{match.group(2)}', match.group(1))
                    for match in active_method_pattern.finditer(text)
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
            if xml_active_entries:
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
    unresolved = any(
        finding.get('reason_code') in {
            'spring_conditions_require_runtime_evaluation', 'AMBIGUOUS_FRAMEWORK_DISPATCH',
            'spring_bean_method_unresolved', 'spring_xml_scheduled_task_unresolved',
            'spring_xml_quartz_job_unresolved',
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
                        'request_mapping': request_expr,
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
        if coord == '__business__':
            continue
        jar_path = str(item.get('jar_path') or '').strip()
        if not jar_path or not Path(jar_path).is_file():
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
    for adapter in (payload or {}).get('adapters') or []:
        for edge in adapter.get('edges') or []:
            if edge.get('edge_kind') not in supported_kinds:
                continue
            target = str(edge.get('target') or '').strip()
            if not target:
                unmatched_edges += 1
                continue
            if (
                edge.get('edge_kind') == 'spring_runtime_registered_callback'
                and edge.get('runtime_activation') == 'active'
            ):
                runtime_entries.setdefault(target.split('(', 1)[0], []).append({
                    **edge,
                    'adapter': adapter.get('adapter'),
                    'adapter_version': adapter.get('version'),
                })
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
    }
