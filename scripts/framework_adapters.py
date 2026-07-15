#!/usr/bin/env python3
"""Independent evidence adapters for Java SPI, Spring, MyBatis and proxy edges."""

from __future__ import annotations

import json
import hashlib
import io
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
from step5_evidence_model import (
    CollectedEdge,
    CollectorBatch,
    CoverageRecord,
    EvidenceAuthority,
    EvidenceConcern,
    EvidenceFailure,
    EvidenceProvenance,
    ModuleScope,
    thaw_evidence_value,
)


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


def _framework_edge_authority(edge):
    """Classify the collector's actual evidence without upgrading framework semantics."""
    provenance = dict(edge.get('provenance') or {})
    source = str(edge.get('source') or '')
    path = str(provenance.get('file') or '')
    if edge.get('edge_kind') in {
        'mybatis_mapper_proxy_dispatch',
        'spring_transaction_proxy_dispatch',
        'spring_data_repository_proxy_dispatch',
        'spring_runtime_registered_callback',
        'spring_runtime_autoconfiguration_registration',
    } or provenance.get('authority'):
        return EvidenceAuthority.FRAMEWORK_SEMANTIC
    if (
        '/src/main/resources/' in path.replace('\\', '/')
        or path.endswith(('.xml', '.properties'))
        or source.startswith('framework:')
        or edge.get('edge_kind') in {
            'java_spi_registration', 'dubbo_spi_registration',
            'spring_autoconfiguration_registration', 'spring_factories_registration',
        }
    ):
        return EvidenceAuthority.RESOURCE_CONFIGURATION
    return EvidenceAuthority.SOURCE_AST


def _framework_edge_scope(edge):
    source = str(edge.get('source') or '')
    if source.startswith('framework:'):
        return ModuleScope.EXTERNAL_DEPENDENCY
    return ModuleScope.BUSINESS_CLASSES


def _framework_failure(adapter, error):
    text = str(error or '')
    artifact, separator, detail = text.partition(':')
    if artifact.startswith('/private/var/'):
        artifact = '/var/' + artifact[len('/private/var/'):]
    reason = 'FRAMEWORK_ADAPTER_COLLECTION_FAILED'
    if 'spring_xml:ParseError' in text:
        reason = 'SPRING_XML_PARSE_FAILED'
    elif 'mybatis_xml:ParseError' in text:
        reason = 'MYBATIS_XML_PARSE_FAILED'
    elif 'spring_boot_activation_source:' in text:
        reason = 'SPRING_BOOT_ACTIVATION_SOURCE_READ_FAILED'
    elif 'spring_data_repository_source:' in text:
        reason = 'SPRING_DATA_REPOSITORY_SOURCE_READ_FAILED'
    elif 'spring_data_custom_config_source:' in text:
        reason = 'SPRING_DATA_CUSTOM_CONFIG_SOURCE_READ_FAILED'
    elif 'spring_transaction_mode_source:' in text:
        reason = 'SPRING_TRANSACTION_MODE_SOURCE_READ_FAILED'
    elif 'mybatis_runtime_sha256_mismatch' in text:
        reason = 'MYBATIS_RUNTIME_ARTIFACT_SHA256_MISMATCH'
    return EvidenceFailure(
        stage=adapter,
        reason_code=reason,
        blocking=False,
        artifact=artifact if separator else '',
        detail=detail if separator else text,
    )


def _framework_concern(adapter, finding):
    return EvidenceConcern(
        stage=adapter,
        reason_code=str(finding.get('reason_code') or 'FRAMEWORK_ADAPTER_CONCERN'),
        detail=json.dumps(finding, ensure_ascii=False, sort_keys=True),
        artifact=str(finding.get('file') or ''),
        class_name=str(finding.get('subject') or ''),
    )


def _framework_batch(adapter, version, status, nodes, edges, findings, errors, metrics):
    """Convert legacy parser records once; v1 diagnostics are serializer projections."""
    normalized_edges = []
    for raw_edge in edges:
        ambiguity = bool(raw_edge.get('ambiguity'))
        normalized = {
            **raw_edge,
            'adapter': adapter,
            'adapter_version': version,
            'evidence': dict(raw_edge.get('provenance') or {}),
            'activation_conditions': list(raw_edge.get('conditions') or []),
            'candidate_count': int(raw_edge.get('candidate_count') or (2 if ambiguity else 1)),
            'ambiguity_reason': raw_edge.get('ambiguity_reason') or (
                'multiple candidates' if ambiguity else ''
            ),
        }
        provenance = dict(normalized.get('provenance') or {})
        metadata = {
            key: value for key, value in normalized.items()
            if key not in {'source', 'target', 'edge_kind', 'confidence', 'conditions', 'ambiguity', 'provenance'}
        }
        metadata.update({
            'framework_source': str(normalized.get('source') or ''),
            'framework_target': str(normalized.get('target') or ''),
            'framework_provenance': provenance,
            'legacy_edge': normalized,
        })
        normalized_edges.append(CollectedEdge(
            caller_symbol=str(normalized.get('source') or ''),
            callee_symbol=str(normalized.get('target') or ''),
            edge_kind=str(normalized.get('edge_kind') or ''),
            semantic=True,
            owner_scope=_framework_edge_scope(normalized),
            provenance=EvidenceProvenance(
                authority=_framework_edge_authority(normalized),
                artifact_path=str(provenance.get('jar') or provenance.get('file') or ''),
                artifact_sha256=str(
                    provenance.get('artifact_sha256')
                    or provenance.get('final_artifact_sha256')
                    or ''
                ),
                artifact_entry=str(provenance.get('artifact_entry') or ''),
                class_or_resource_entry=str(provenance.get('resource') or ''),
                parser=str(provenance.get('parser') or 'framework_adapter'),
                evidence_source=_framework_edge_authority(normalized).value,
                line=int(provenance.get('line') or 0),
            ),
            confidence=str(normalized.get('confidence') or 'high'),
            ambiguous=ambiguity,
            activation_conditions=tuple(normalized.get('activation_conditions') or ()),
            metadata=tuple(sorted(metadata.items())),
        ))
    result_metrics = {
        **dict(metrics or {}),
        'edges': len(normalized_edges),
        'ambiguous_edges': sum(edge.ambiguous for edge in normalized_edges),
        'conditional_edges': sum(bool(edge.activation_conditions) for edge in normalized_edges),
        'nodes': len(nodes),
        '_legacy_nodes': tuple(nodes),
        '_legacy_findings': tuple(findings),
        '_legacy_errors': tuple(errors),
    }
    return CollectorBatch(
        collector=adapter,
        version=version,
        edges=tuple(normalized_edges),
        failures=tuple(_framework_failure(adapter, item) for item in errors),
        concerns=tuple(_framework_concern(adapter, item) for item in findings),
        coverage=(CoverageRecord(
            collector=adapter,
            api_identity=adapter,
            status=status,
            applicable=status != 'not_applicable',
        ),),
        metrics=tuple(sorted(result_metrics.items())),
    )


def _serialize_framework_batch(batch):
    metrics = thaw_evidence_value(dict(batch.metrics))
    coverage = next((item for item in batch.coverage if item.collector == batch.collector), None)
    serialized_edges = []
    for edge in batch.edges:
        legacy = thaw_evidence_value(
            dict(edge.metadata).get('legacy_edge') or {}
        )
        if not legacy:
            legacy = {
                'source': edge.caller_symbol,
                'target': edge.callee_symbol,
                'edge_kind': edge.edge_kind,
                'confidence': edge.confidence,
                'conditions': list(edge.activation_conditions),
                'ambiguity': edge.ambiguous,
                'provenance': thaw_evidence_value(
                    dict(edge.metadata).get('framework_provenance') or {}
                ),
            }
        serialized_edges.append(legacy)
    return {
        'adapter': batch.collector,
        'version': batch.version,
        'status': coverage.status if coverage else 'partial',
        'nodes': list(metrics.pop('_legacy_nodes', ())),
        'edges': serialized_edges,
        'findings': list(metrics.pop('_legacy_findings', ())),
        'errors': list(metrics.pop('_legacy_errors', ())),
        'metrics': metrics,
    }


def serialize_framework_batches(batches, output_path=''):
    """Project immutable adapter batches to the legacy v1 diagnostics schema."""
    payload = {
        'schema': 'java-upgrade-analyzer.framework-adapters.v1',
        'adapters': [_serialize_framework_batch(batch) for batch in tuple(batches)],
    }
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return payload


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


def run_spi_adapter(source_roots, artifact_catalog=None):
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
    return _framework_batch(
        'java_spi', '1',
        'partial' if files and (errors or ambiguous) else _status(bool(files), errors),
        nodes, edges, findings, errors,
        {'resource_files': len(files), 'load_points': len(load_points), 'edges': len(edges)},
    )


def _java_package_and_class(text, fallback=''):
    package = re.search(r'\bpackage\s+([\w.]+)\s*;', text)
    clazz = re.search(r'\b(?:class|interface|record|enum)\s+(\w+)', text)
    simple = clazz.group(1) if clazz else fallback
    return f'{package.group(1)}.{simple}' if package and simple else simple


def run_spring_adapter(source_roots, artifact_catalog=None):
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
            if class_match:
                implemented = []
                for raw_interface in class_match.group(1).split(','):
                    simple = re.sub(r'<.*>', '', raw_interface).strip()
                    interface = imports.get(simple, simple)
                    implemented.append((simple, interface))
                    if bean_pattern.search(text):
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
                    callback_interface = simple.rsplit('.', 1)[-1]
                    if callback_interface not in callback_methods:
                        continue
                    allowed = callback_methods[callback_interface]
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
            except ET.ParseError as exc:
                errors.append(f'{path}:spring_xml:{type(exc).__name__}')
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
    return _framework_batch(
        'spring_basic', '1',
        'partial' if applicable and (errors or unresolved) else _status(applicable, errors),
        nodes, edges, findings, errors,
        {'source_files_scanned': scanned, 'xml_files_scanned': xml_files, 'edges': len(edges)},
    )


_MYBATIS_DOCTYPE_RE = re.compile(br'<!DOCTYPE\s+[^>]+>', re.IGNORECASE | re.DOTALL)


def _looks_like_mybatis_xml(path):
    raw = Path(path).read_bytes().lower()
    return b'<mapper' in raw or (
        b'<configuration' in raw
        and any(marker in raw for marker in (b'mybatis', b'<mappers', b'<typealiases'))
    )


def _parse_mybatis_xml(path):
    return _parse_mybatis_xml_bytes(Path(path).read_bytes())


def _parse_mybatis_xml_bytes(raw):
    upper = raw.upper()
    doctype = _MYBATIS_DOCTYPE_RE.search(raw)
    if b'<!ENTITY' in upper or (doctype and b'[' in doctype.group(0)):
        raise ET.ParseError('XML entities and internal DTD subsets are not allowed')
    if doctype:
        declaration = doctype.group(0).lower()
        if not any(marker in declaration for marker in (
            b'mybatis.org/dtd/mybatis-3-mapper.dtd',
            b'mybatis.org/dtd/mybatis-3-config.dtd',
        )):
            raise ET.ParseError('unrecognized external DTD')
        raw = raw[:doctype.start()] + raw[doctype.end():]
    return ET.fromstring(raw)


def run_mybatis_adapter(source_roots, artifact_catalog=None):
    edges, nodes, findings, errors = [], [], [], []
    files = []
    annotation_files = 0
    statement_tags = {'select', 'insert', 'update', 'delete'}
    for root in _resource_roots(source_roots):
        for path in sorted(root.rglob('*.xml')):
            try:
                if not _looks_like_mybatis_xml(path):
                    continue
                mapper = _parse_mybatis_xml(path)
            except ET.ParseError as exc:
                errors.append(f'{path}:mybatis_xml:{type(exc).__name__}')
                continue
            except OSError as exc:
                errors.append(f'{path}:{type(exc).__name__}')
                continue
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
    return _framework_batch(
        'mybatis', '1', _status(bool(files or annotation_files), errors),
        nodes, edges, findings, errors,
        {'xml_files': len(files), 'annotation_files': annotation_files, 'edges': len(edges)},
    )


_MYBATIS_PROXY_RUNTIME_CLASSES = {
    'org/apache/ibatis/binding/MapperProxy.class',
    'org/apache/ibatis/binding/MapperProxy$PlainMethodInvoker.class',
    'org/apache/ibatis/binding/MapperMethod.class',
    'org/apache/ibatis/session/SqlSession.class',
}

_MYBATIS_PROXY_TARGETS = (
    (
        'org.apache.ibatis.binding.MapperProxy.invoke'
        '(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])',
        'proxy_entry',
    ),
    (
        'org.apache.ibatis.binding.MapperMethod.execute'
        '(org.apache.ibatis.session.SqlSession,java.lang.Object[])',
        'mapper_execute',
    ),
)


def _mybatis_xml_statements(source_roots):
    statements = {}
    errors = []
    for root in _resource_roots(source_roots):
        for path in sorted(root.rglob('*.xml')):
            try:
                if not _looks_like_mybatis_xml(path):
                    continue
                mapper = _parse_mybatis_xml(path)
            except (ET.ParseError, OSError) as exc:
                errors.append(f'{path}:mybatis_xml:{type(exc).__name__}')
                continue
            if str(mapper.tag).rsplit('}', 1)[-1] != 'mapper':
                continue
            namespace = str(mapper.attrib.get('namespace') or '').strip()
            if not namespace:
                errors.append(f'{path}:mybatis_mapper_namespace_missing')
                continue
            for child in mapper:
                command = str(child.tag).rsplit('}', 1)[-1]
                member = str(child.attrib.get('id') or '').strip()
                if command in {'select', 'insert', 'update', 'delete'} and member:
                    statements[(namespace, member)] = {
                        'command': command,
                        'file': str(path),
                    }
    return statements, errors


def _mybatis_mapper_contracts(source_roots):
    statements, errors = _mybatis_xml_statements(source_roots)
    annotation_commands = {
        'Select': 'select', 'SelectProvider': 'select',
        'Insert': 'insert', 'InsertProvider': 'insert',
        'Update': 'update', 'UpdateProvider': 'update',
        'Delete': 'delete', 'DeleteProvider': 'delete',
    }
    contracts = []
    unregistered = []
    for path in _production_java_files(source_roots):
        try:
            source_text = _mask_java_comments(
                path.read_text(encoding='utf-8', errors='replace')
            )
        except OSError as exc:
            errors.append(f'{path}:mybatis_proxy_source:{type(exc).__name__}')
            continue
        if 'interface' not in source_text or 'Mapper' not in source_text:
            continue
        exact_mapper_annotation = bool(
            re.search(r'@org\.apache\.ibatis\.annotations\.Mapper\b', source_text)
            or (
                re.search(
                    r'\bimport\s+org\.apache\.ibatis\.annotations\.Mapper\s*;',
                    source_text,
                )
                and re.search(r'@Mapper\b', source_text)
            )
        )
        exact_sql_annotations = set(re.findall(
            r'@org\.apache\.ibatis\.annotations\.(\w+)\b', source_text
        ))
        exact_sql_annotations.update(re.findall(
            r'\bimport\s+org\.apache\.ibatis\.annotations\.(\w+)\s*;',
            source_text,
        ))
        try:
            methods, parser_info = analyze_file(
                str(path),
                {'root': str(path.parent), 'owner_type': 'business', 'owner_coord': 'BUSINESS'},
                prefer_tree_sitter=True,
                return_diagnostics=True,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(f'{path}:mybatis_proxy_ast:{type(exc).__name__}')
            continue
        if parser_info.get('actual_parser') != 'tree_sitter':
            continue
        overloads = {}
        candidates = []
        for method in methods:
            if not getattr(method, 'is_interface', False):
                continue
            owner = str(getattr(method, 'class_fqcn', '') or '')
            member = str(getattr(method, 'method_name', '') or '')
            annotations = {
                str(item).rsplit('.', 1)[-1]
                for item in (getattr(method, 'annotations', None) or [])
            }
            command = next(
                (
                    annotation_commands[item]
                    for item in sorted(annotations)
                    if item in annotation_commands and item in exact_sql_annotations
                ),
                '',
            )
            binding = {'command': command, 'file': str(path)} if command else statements.get((owner, member))
            if not binding:
                continue
            registered = exact_mapper_annotation and 'Mapper' in {
                str(item).rsplit('.', 1)[-1]
                for item in (getattr(method, 'class_annotations', None) or [])
            }
            identity = (owner, member, len(getattr(method, 'param_types', None) or {}))
            overloads[identity] = overloads.get(identity, 0) + 1
            candidates.append((method, binding, registered, identity))
        for method, binding, registered, identity in candidates:
            item = {
                'owner': identity[0],
                'member': identity[1],
                'parameter_count': identity[2],
                'declared_method_count': overloads[identity],
                'parameters': list((getattr(method, 'param_types', None) or {}).values()),
                'return_type': str(getattr(method, 'return_type', '') or ''),
                'command': binding['command'],
                'file': str(path),
                'binding_file': binding['file'],
            }
            if registered:
                contracts.append(item)
            else:
                unregistered.append(item)
    return contracts, unregistered, errors


def _mybatis_runtime_entry(artifact_catalog):
    matches = []
    errors = []
    for entry in (artifact_catalog or {}).get('entries') or []:
        if (
            str(entry.get('evidence_source') or '') != 'current_final_artifact'
            or not re.fullmatch(r'[0-9a-fA-F]{64}', str(entry.get('sha256') or ''))
        ):
            continue
        jar_path = Path(str(entry.get('jar_path') or ''))
        if not jar_path.is_file():
            continue
        try:
            content = jar_path.read_bytes()
            if hashlib.sha256(content).hexdigest() != str(entry.get('sha256') or '').lower():
                errors.append(f'{jar_path}:mybatis_runtime_sha256_mismatch')
                continue
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                names = set(archive.namelist())
        except (OSError, zipfile.BadZipFile) as exc:
            errors.append(f'{jar_path}:mybatis_runtime:{type(exc).__name__}')
            continue
        if _MYBATIS_PROXY_RUNTIME_CLASSES.issubset(names):
            matches.append(entry)
    if len(matches) != 1:
        return None, errors, len(matches)
    return matches[0], errors, 1


def _verified_final_artifact(artifact_catalog):
    path = Path(str((artifact_catalog or {}).get('final_artifact_path') or ''))
    expected = str((artifact_catalog or {}).get('final_artifact_sha256') or '').lower()
    if not path.is_file() or not re.fullmatch(r'[0-9a-f]{64}', expected):
        return None, 'mybatis_final_artifact_unavailable'
    try:
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        return None, f'mybatis_final_artifact:{type(exc).__name__}'
    if actual != expected:
        return None, 'mybatis_final_artifact_sha256_mismatch'
    return path, ''


def _packaged_mybatis_contracts(candidates, artifact_catalog):
    """Validate mapper registration, binding, and activation in one SHA-bound artifact."""
    artifact, artifact_error = _verified_final_artifact(artifact_catalog)
    if not artifact:
        return [], list(candidates), [], [artifact_error]
    packaged = []
    unregistered = []
    activation = []
    errors = []
    try:
        with zipfile.ZipFile(artifact) as outer:
            names = set(outer.namelist())
            class_entries = {
                name: outer.read(name) for name in names
                if name.endswith('.class')
                and name.startswith(('BOOT-INF/classes/', 'WEB-INF/classes/'))
            }
            xml_entries = {
                name: outer.read(name) for name in names
                if name.endswith('.xml')
                and name.startswith(('BOOT-INF/classes/', 'WEB-INF/classes/'))
            }
            for entry in (artifact_catalog or {}).get('entries') or []:
                if not (
                    entry.get('application_owned')
                    and str(entry.get('evidence_source') or '') == 'current_final_artifact'
                ):
                    continue
                nested_entry = str(entry.get('artifact_entry') or '')
                expected_sha = str(entry.get('sha256') or '').lower()
                if nested_entry not in names or not re.fullmatch(r'[0-9a-f]{64}', expected_sha):
                    continue
                nested_blob = outer.read(nested_entry)
                if hashlib.sha256(nested_blob).hexdigest() != expected_sha:
                    errors.append(f'{nested_entry}:mybatis_internal_module_sha256_mismatch')
                    continue
                try:
                    with zipfile.ZipFile(io.BytesIO(nested_blob)) as nested:
                        for name in nested.namelist():
                            qualified = f'{nested_entry}!/{name}'
                            if name.endswith('.class'):
                                class_entries[qualified] = nested.read(name)
                            elif name.endswith('.xml'):
                                xml_entries[qualified] = nested.read(name)
                except zipfile.BadZipFile:
                    errors.append(f'{nested_entry}:mybatis_internal_module_bad_zip')
            xml_statements = {}
            for name, xml_content in sorted(xml_entries.items()):
                try:
                    root = _parse_mybatis_xml_bytes(xml_content)
                except ET.ParseError as exc:
                    errors.append(f'{name}:mybatis_xml:{type(exc).__name__}')
                    continue
                if str(root.tag).rsplit('}', 1)[-1] != 'mapper':
                    continue
                namespace = str(root.attrib.get('namespace') or '').strip()
                for child in root:
                    command = str(child.tag).rsplit('}', 1)[-1]
                    member = str(child.attrib.get('id') or '').strip()
                    if namespace and member and command in {'select', 'insert', 'update', 'delete'}:
                        xml_statements[(namespace, member)] = (command, name)
            for name, content in sorted(class_entries.items()):
                if (
                    b'Lorg/springframework/boot/autoconfigure/SpringBootApplication;' in content
                    or b'Lorg/springframework/boot/autoconfigure/EnableAutoConfiguration;' in content
                ) and b'org/springframework/boot/SpringApplication' in content and b'run' in content:
                    activation.append({
                        'artifact_entry': name,
                        'artifact_sha256': str(artifact_catalog.get('final_artifact_sha256') or ''),
                        'authority': 'current_final_artifact_classfile',
                    })
            final_artifact_sha256 = str(
                (artifact_catalog or {}).get('final_artifact_sha256') or ''
            ).lower()
            for item in candidates:
                class_suffix = item['owner'].replace('.', '/') + '.class'
                class_entry = next(
                    (name for name in class_entries if name.endswith('/' + class_suffix)), ''
                )
                if not class_entry:
                    unregistered.append({**item, '_unproven_reason': 'registration'})
                    continue
                content = class_entries[class_entry]
                registered = b'Lorg/apache/ibatis/annotations/Mapper;' in content
                annotation_markers = {
                    'select': (b'Lorg/apache/ibatis/annotations/Select;', b'Lorg/apache/ibatis/annotations/SelectProvider;'),
                    'insert': (b'Lorg/apache/ibatis/annotations/Insert;', b'Lorg/apache/ibatis/annotations/InsertProvider;'),
                    'update': (b'Lorg/apache/ibatis/annotations/Update;', b'Lorg/apache/ibatis/annotations/UpdateProvider;'),
                    'delete': (b'Lorg/apache/ibatis/annotations/Delete;', b'Lorg/apache/ibatis/annotations/DeleteProvider;'),
                }
                xml_binding = xml_statements.get((item['owner'], item['member']))
                annotation_binding = any(
                    marker in content for marker in annotation_markers.get(item['command'], ())
                ) and item['member'].encode('utf-8') in content
                if not registered:
                    unregistered.append({**item, '_unproven_reason': 'registration'})
                    continue
                if not (annotation_binding or xml_binding):
                    unregistered.append({**item, '_unproven_reason': 'binding'})
                    continue
                verified = dict(item)
                verified['file'] = f'{artifact}!/{class_entry}'
                if xml_binding:
                    verified['command'], binding_entry = xml_binding
                    verified['binding_file'] = f'{artifact}!/{binding_entry}'
                else:
                    binding_entry = class_entry
                    verified['binding_file'] = f'{artifact}!/{class_entry}'
                verified['artifact_entry'] = class_entry
                verified['final_artifact_sha256'] = final_artifact_sha256
                verified['mapper_registration'] = {
                    'artifact_entry': class_entry,
                    'artifact_sha256': final_artifact_sha256,
                    'authority': 'current_final_artifact_classfile',
                }
                verified['binding_evidence'] = {
                    'artifact_entry': binding_entry,
                    'artifact_sha256': final_artifact_sha256,
                    'authority': (
                        'current_final_artifact_resource'
                        if xml_binding else 'current_final_artifact_classfile'
                    ),
                }
                packaged.append(verified)
    except (OSError, zipfile.BadZipFile) as exc:
        errors.append(f'{artifact}:mybatis_final_artifact:{type(exc).__name__}')
        return [], list(candidates), [], errors
    return packaged, unregistered, activation, errors


def _verify_mybatis_runtime_dispatch(entry):
    jar_path = str(entry.get('jar_path') or '')
    classes = (
        'org.apache.ibatis.binding.MapperProxy',
        'org.apache.ibatis.binding.MapperProxy$PlainMethodInvoker',
        'org.apache.ibatis.binding.MapperMethod',
    )
    outputs = {}
    errors = []
    for owner in classes:
        try:
            completed = subprocess.run(
                ['javap', '-c', '-p', '-s', '-classpath', jar_path, owner],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f'{jar_path}:{owner}:{type(exc).__name__}')
            continue
        if completed.returncode != 0:
            errors.append(f'{jar_path}:{owner}:javap_exit_{completed.returncode}')
            continue
        outputs[owner] = completed.stdout
    checks = {
        'proxy_entry_dispatch': (
            'org.apache.ibatis.binding.MapperProxy',
            'InterfaceMethod org/apache/ibatis/binding/MapperProxy$MapperMethodInvoker.invoke:'
            '(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;'
            'Lorg/apache/ibatis/session/SqlSession;)Ljava/lang/Object;',
        ),
        'plain_invoker_dispatch': (
            'org.apache.ibatis.binding.MapperProxy$PlainMethodInvoker',
            'Method org/apache/ibatis/binding/MapperMethod.execute:'
            '(Lorg/apache/ibatis/session/SqlSession;[Ljava/lang/Object;)Ljava/lang/Object;',
        ),
        'select_one_dispatch': (
            'org.apache.ibatis.binding.MapperMethod',
            'InterfaceMethod org/apache/ibatis/session/SqlSession.selectOne:'
            '(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;',
        ),
    }
    verified = {
        name: marker in outputs.get(owner, '')
        for name, (owner, marker) in checks.items()
    }
    return verified, errors


def _mybatis_select_runtime_target(contract):
    if contract.get('command') != 'select':
        return ''
    return_type = str(contract.get('return_type') or '')
    collection_markers = ('[]', 'java.util.List', 'java.util.Collection', 'java.util.Set', 'Cursor')
    if any(marker in return_type for marker in collection_markers):
        return ''
    return (
        'org.apache.ibatis.session.SqlSession.selectOne'
        '(java.lang.String,java.lang.Object)'
    )


def run_mybatis_proxy_adapter(source_roots, artifact_catalog=None):
    """Resolve registered mapper calls through the exact packaged MyBatis proxy runtime."""
    runtime_entry, runtime_errors, runtime_matches = _mybatis_runtime_entry(artifact_catalog)
    if not runtime_entry:
        untrusted_runtime_hint = any(
            'mybatis' in (
                Path(str(entry.get('jar_path') or '')).name
                + str(entry.get('artifact_entry') or '')
            ).lower()
            for entry in (artifact_catalog or {}).get('entries') or []
        )
        findings = ([{
            'reason_code': 'mybatis_runtime_implementation_unresolved',
            'subject': 'org.apache.ibatis.binding.MapperProxy',
            'candidate_count': runtime_matches,
        }] if untrusted_runtime_hint else [])
        return _framework_batch(
            'mybatis_mapper_proxy', '2',
            'partial' if runtime_errors or findings else 'not_applicable',
            [], [], findings, runtime_errors,
            {'registered_mapper_methods': 0, 'unregistered_mapper_methods': 0,
             'runtime_candidates': runtime_matches, 'verified_dispatch_stages': 0,
             'edges': 0},
        )
    source_contracts, source_unregistered, errors = _mybatis_mapper_contracts(source_roots)
    contracts, unregistered, activation_evidence, packaged_errors = _packaged_mybatis_contracts(
        source_contracts + source_unregistered, artifact_catalog
    )
    errors.extend(runtime_errors)
    errors.extend(packaged_errors)
    findings = [{
        'reason_code': (
            'mybatis_mapper_binding_unproven'
            if item.get('_unproven_reason') == 'binding'
            else 'mybatis_mapper_registration_unproven'
        ),
        'subject': f"{item['owner']}.{item['member']}",
        'file': item['file'],
    } for item in unregistered]
    if contracts and not activation_evidence:
        findings.append({
            'reason_code': 'mybatis_runtime_activation_unproven',
            'subject': ','.join(sorted({item['owner'] for item in contracts})),
        })
    if contracts and runtime_matches != 1:
        findings.append({
            'reason_code': 'mybatis_runtime_implementation_unresolved',
            'subject': 'org.apache.ibatis.binding.MapperProxy',
            'candidate_count': runtime_matches,
        })
    dispatch = {}
    if runtime_entry:
        dispatch, dispatch_errors = _verify_mybatis_runtime_dispatch(runtime_entry)
        errors.extend(dispatch_errors)
        missing = sorted(name for name, present in dispatch.items() if not present)
        if missing:
            findings.append({
                'reason_code': 'mybatis_runtime_dispatch_incomplete',
                'subject': ','.join(missing),
            })
    edges = []
    nodes = []
    runtime_complete = bool(dispatch and all(dispatch.values()))
    if contracts and activation_evidence and runtime_entry and runtime_complete:
        for contract in contracts:
            if contract['declared_method_count'] != 1:
                findings.append({
                    'reason_code': 'mybatis_mapper_overload_ambiguous',
                    'subject': f"{contract['owner']}.{contract['member']}/{contract['parameter_count']}",
                })
                continue
            targets = list(_MYBATIS_PROXY_TARGETS)
            select_target = _mybatis_select_runtime_target(contract)
            if select_target:
                targets.append((select_target, 'sql_session_select_one'))
            for target, stage in targets:
                provenance = {
                    'file': contract['file'],
                    'binding_file': contract['binding_file'],
                    'command': contract['command'],
                    'final_artifact_sha256': contract['final_artifact_sha256'],
                    'mapper_registration': contract['mapper_registration'],
                    'binding_evidence': contract['binding_evidence'],
                    'jar': str(runtime_entry.get('jar_path') or ''),
                    'artifact_entry': runtime_entry.get('artifact_entry'),
                    'artifact_sha256': runtime_entry.get('sha256'),
                    'coord': runtime_entry.get('coord'),
                    'business_activation': activation_evidence,
                    'dispatch_stage': stage,
                    'verified_dispatch': dict(dispatch),
                    'physical_target_evidence': {
                        'target': target,
                        'dispatch_stage': {
                            'proxy_entry': 'proxy_entry_dispatch',
                            'mapper_execute': 'plain_invoker_dispatch',
                            'sql_session_select_one': 'select_one_dispatch',
                        }[stage],
                        'verified': bool(dispatch.get({
                            'proxy_entry': 'proxy_entry_dispatch',
                            'mapper_execute': 'plain_invoker_dispatch',
                            'sql_session_select_one': 'select_one_dispatch',
                        }[stage])),
                        'artifact_entry': runtime_entry.get('artifact_entry'),
                        'artifact_sha256': runtime_entry.get('sha256'),
                    },
                    'authority': 'final_artifact_javap',
                }
                edges.append({
                    'source': f"{contract['owner']}.{contract['member']}",
                    'source_owner': contract['owner'],
                    'source_member': contract['member'],
                    'source_parameters': contract['parameters'],
                    'parameter_count': contract['parameter_count'],
                    'target': target,
                    'edge_kind': 'mybatis_mapper_proxy_dispatch',
                    'confidence': 'high',
                    'conditions': [],
                    'ambiguity': False,
                    'provenance': provenance,
                })
                nodes.append({'id': target, 'kind': 'mybatis_proxy_runtime_method'})
    applicable = bool(contracts or unregistered)
    unresolved = bool(applicable and (
        not contracts or not activation_evidence or not runtime_entry or not runtime_complete
    ))
    return _framework_batch(
        'mybatis_mapper_proxy', '2',
        'partial' if applicable and (errors or unresolved) else _status(applicable, errors),
        nodes, edges, findings, errors,
        {
            'registered_mapper_methods': len(contracts),
            'unregistered_mapper_methods': len(unregistered),
            'runtime_candidates': runtime_matches,
            'verified_dispatch_stages': sum(bool(value) for value in dispatch.values()),
            'edges': len(edges),
        },
    )


def run_dynamic_proxy_adapter(source_roots, artifact_catalog=None):
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
    return _framework_batch(
        'dynamic_proxy_basic', '1', status, nodes, edges, findings, errors,
        {
            'source_files_scanned': scanned,
            'proxy_registrations': registrations,
            'edges': len(edges),
        },
    )


def run_declarative_http_client_adapter(source_roots, artifact_catalog=None):
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
    return _framework_batch(
        'declarative_http_client_basic', '1',
        'partial' if applicable and (errors or unresolved) else _status(applicable, errors),
        nodes, edges, findings, errors,
        {
            'source_files_scanned': scanned,
            'clients': len({item['subject'] for item in findings if item.get('reason_code') == 'declarative_http_client_registration'}),
            'edges': len(edges),
        },
    )


_SPRING_RUNTIME_CALLBACK_METHODS = {
    'org.springframework.context.ApplicationListener': 'onApplicationEvent',
    'org.springframework.boot.env.EnvironmentPostProcessor': 'postProcessEnvironment',
    'org.springframework.context.ApplicationContextInitializer': 'initialize',
}


def _spring_boot_business_activation(source_roots):
    evidence = []
    errors = []
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
            except OSError as exc:
                errors.append(
                    f'{path}:spring_boot_activation_source:{type(exc).__name__}'
                )
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
    return evidence, errors


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
    owner_match = re.search(
        r'^(?:(?:public|protected|private|abstract|final|sealed|non-sealed|static)\s+)*'
        r'(?:class|interface|enum|record)\s+([\w.$]+)',
        text,
        re.MULTILINE,
    )
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
_SPRING_TRANSACTION_TARGETS = (
    (
        'spring-tx',
        'org.springframework.transaction.interceptor.TransactionInterceptor',
        'invoke',
        1,
    ),
    (
        'spring-tx',
        'org.springframework.transaction.interceptor.TransactionAspectSupport',
        'invokeWithinTransaction',
        3,
    ),
    (
        'spring-aop',
        'org.springframework.aop.framework.ReflectiveMethodInvocation',
        'proceed',
        0,
    ),
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
    errors = []
    for path in _production_java_files(source_roots):
        try:
            text = _mask_java_comments(path.read_text(encoding='utf-8', errors='replace'))
        except OSError as exc:
            errors.append(
                f'{path}:spring_data_repository_source:{type(exc).__name__}'
            )
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
    return repositories, errors


def _spring_data_custom_repository_configuration(source_roots):
    custom = []
    errors = []
    for path in _production_java_files(source_roots):
        try:
            text = _mask_java_comments(path.read_text(encoding='utf-8', errors='replace'))
        except OSError as exc:
            errors.append(
                f'{path}:spring_data_custom_config_source:{type(exc).__name__}'
            )
            continue
        if not re.search(r'@(?:[\w.]+\.)?EnableJpaRepositories\b', text):
            continue
        attributes = sorted(set(re.findall(
            r'\b(repositoryBaseClass|repositoryFactoryBeanClass)\s*=', text
        )))
        if attributes:
            custom.append({'file': str(path), 'attributes': attributes})
    return custom, errors


def _spring_transactional_business_methods(source_roots):
    methods = []
    errors = []
    for path in _production_java_files(source_roots):
        try:
            text = _mask_java_comments(path.read_text(encoding='utf-8', errors='replace'))
        except OSError as exc:
            errors.append(f'{path}:{type(exc).__name__}')
            continue
        spring_annotation = bool(
            re.search(
                r'\bimport\s+org\.springframework\.transaction\.annotation\.Transactional\s*;',
                text,
            )
            or '@org.springframework.transaction.annotation.Transactional' in text
        )
        if not spring_annotation:
            continue
        try:
            parsed, parser_info = analyze_file(
                str(path),
                {'root': str(path.parent), 'owner_type': 'business', 'owner_coord': 'BUSINESS'},
                prefer_tree_sitter=True,
                return_diagnostics=True,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(f'{path}:transaction_ast:{type(exc).__name__}')
            continue
        if parser_info.get('actual_parser') != 'tree_sitter':
            errors.append(f'{path}:transaction_ast_unavailable')
            continue
        for method in parsed:
            annotations = {
                str(item).rsplit('.', 1)[-1]
                for item in (method.annotations or [])
            }
            class_annotations = {
                str(item).rsplit('.', 1)[-1]
                for item in (method.class_annotations or [])
            }
            if 'Transactional' not in annotations and 'Transactional' not in class_annotations:
                continue
            if 'public' not in (method.modifiers or []):
                continue
            methods.append({
                'owner': str(method.class_fqcn or ''),
                'member': str(method.method_name or ''),
                'parameter_count': len(method.param_types or {}),
                'file': str(path),
                'line': int(method.line or 0),
                'annotation_scope': (
                    'method' if 'Transactional' in annotations else 'class'
                ),
            })
    unique = {}
    for method in methods:
        identity = (
            method['owner'], method['member'], method['parameter_count']
        )
        unique.setdefault(identity, method)
    return list(unique.values()), errors


def _spring_transaction_custom_mode(source_roots):
    findings = []
    errors = []
    for path in _production_java_files(source_roots):
        try:
            text = _mask_java_comments(path.read_text(encoding='utf-8', errors='replace'))
        except OSError as exc:
            errors.append(
                f'{path}:spring_transaction_mode_source:{type(exc).__name__}'
            )
            continue
        if (
            re.search(r'@(?:[\w.]+\.)?EnableTransactionManagement\b', text)
            and re.search(r'\bmode\s*=\s*(?:AdviceMode\s*\.\s*)?ASPECTJ\b', text)
        ):
            findings.append({
                'reason_code': 'spring_transaction_aspectj_mode',
                'subject': str(path),
            })
    return findings, errors


def _packaged_transactional_methods(jar_path, owners):
    verified = {}
    errors = []
    for owner in sorted(set(owners)):
        try:
            completed = subprocess.run(
                ['javap', '-v', '-p', '-classpath', str(jar_path), owner],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f'{jar_path}:{owner}:{type(exc).__name__}')
            continue
        if completed.returncode != 0:
            errors.append(f'{jar_path}:{owner}:javap_exit_{completed.returncode}')
            continue
        parsed_owner, _methods = _parse_javap_methods(completed.stdout)
        if parsed_owner != owner:
            errors.append(f'{jar_path}:{owner}:owner_mismatch:{parsed_owner}')
            continue
        closing = completed.stdout.find('\n}')
        class_tail = completed.stdout[closing + 2:] if closing >= 0 else ''
        class_transactional = (
            'org.springframework.transaction.annotation.Transactional' in class_tail
        )
        matches = list(re.finditer(
            r'^  (?P<header>[^\n]+?\([^\n;]*\))(?: throws [^\n;]+)?;$',
            completed.stdout,
            re.MULTILINE,
        ))
        matches = [
            match for match in matches
            if ':' not in match.group('header').split('(', 1)[0]
        ]
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(completed.stdout)
            block = completed.stdout[match.start():end]
            if '\n}' in block:
                block = block.split('\n}', 1)[0]
            descriptor_match = re.search(r'^\s+descriptor:\s+(\S+)\s*$', block, re.MULTILINE)
            parameters = _descriptor_parameter_types(
                descriptor_match.group(1) if descriptor_match else ''
            )
            if parameters is None:
                continue
            header = match.group('header')
            prefix = header.split('(', 1)[0].strip()
            member = prefix.rsplit(' ', 1)[-1].rsplit('.', 1)[-1]
            method_transactional = (
                'org.springframework.transaction.annotation.Transactional' in block
            )
            if not method_transactional and not (
                class_transactional and header.startswith('public ')
            ):
                continue
            verified[(owner, member, len(parameters))] = {
                'descriptor': descriptor_match.group(1),
                'annotation_scope': 'method' if method_transactional else 'class',
            }
    return verified, errors


def run_spring_transaction_proxy_adapter(source_roots, artifact_catalog=None):
    """Resolve @Transactional business calls through exact packaged Spring AOP methods."""
    transactional_methods, errors = _spring_transactional_business_methods(source_roots)
    activation_evidence, activation_errors = _spring_boot_business_activation(source_roots)
    custom_mode_findings, custom_mode_errors = _spring_transaction_custom_mode(source_roots)
    errors.extend(activation_errors)
    errors.extend(custom_mode_errors)
    findings = list(custom_mode_findings)
    business_entries = [
        item for item in (artifact_catalog or {}).get('entries') or []
        if str(item.get('coord') or '') == '__business__'
        and Path(str(item.get('jar_path') or '')).is_file()
    ]
    verified_methods = []
    if transactional_methods and len(business_entries) == 1:
        business_entry = business_entries[0]
        packaged, packaged_errors = _packaged_transactional_methods(
            business_entry.get('jar_path'),
            [item['owner'] for item in transactional_methods],
        )
        errors.extend(packaged_errors)
        for method in transactional_methods:
            identity = (method['owner'], method['member'], method['parameter_count'])
            packaged_method = packaged.get(identity)
            if not packaged_method:
                findings.append({
                    'reason_code': 'spring_transaction_business_annotation_unverified',
                    'subject': f"{method['owner']}.{method['member']}/{method['parameter_count']}",
                })
                continue
            verified_methods.append({
                **method,
                'business_descriptor': packaged_method['descriptor'],
                'annotation_scope': packaged_method['annotation_scope'],
                'business_artifact': business_entry,
            })
    elif transactional_methods:
        findings.append({
            'reason_code': 'spring_transaction_business_annotation_unverified',
            'subject': '__business__',
            'candidate_count': len(business_entries),
        })
    entries_by_role = {}
    for role in ('spring-tx', 'spring-aop'):
        entries_by_role[role] = [
            item for item in (artifact_catalog or {}).get('entries') or []
            if Path(str(item.get('artifact_entry') or item.get('jar_path') or '')).name.startswith(
                role + '-'
            )
            and Path(str(item.get('jar_path') or '')).is_file()
        ]
    if transactional_methods and not activation_evidence:
        findings.append({
            'reason_code': 'spring_transaction_activation_unproven',
            'subject': ','.join(
                f"{item['owner']}.{item['member']}" for item in transactional_methods
            ),
        })
    for role, entries in entries_by_role.items():
        if transactional_methods and len(entries) != 1:
            findings.append({
                'reason_code': 'spring_transaction_runtime_implementation_unresolved',
                'subject': role,
                'candidate_count': len(entries),
            })

    implementation_targets = []
    can_resolve = bool(
        verified_methods
        and activation_evidence
        and not custom_mode_findings
        and not activation_errors
        and not custom_mode_errors
        and all(len(entries_by_role[role]) == 1 for role in entries_by_role)
    )
    if can_resolve:
        for role, owner, member, parameter_count in _SPRING_TRANSACTION_TARGETS:
            entry = entries_by_role[role][0]
            jar_path = str(entry.get('jar_path') or '')
            try:
                completed = subprocess.run(
                    ['javap', '-p', '-s', '-classpath', jar_path, owner],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=30,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append(f'{jar_path}:{owner}:{type(exc).__name__}')
                continue
            if completed.returncode != 0:
                errors.append(f'{jar_path}:{owner}:javap_exit_{completed.returncode}')
                continue
            parsed_owner, parsed_methods = _parse_javap_methods(completed.stdout)
            candidates = []
            if parsed_owner == owner:
                for parsed in parsed_methods:
                    parameters = _descriptor_parameter_types(parsed.get('descriptor'))
                    if (
                        parsed.get('member') == member
                        and parameters is not None
                        and len(parameters) == parameter_count
                    ):
                        candidates.append((parsed, parameters))
            if len(candidates) != 1:
                errors.append(f'{jar_path}:{owner}.{member}/{parameter_count}:candidate_count_{len(candidates)}')
                continue
            parsed, parameters = candidates[0]
            implementation_targets.append({
                'target': f"{owner}.{member}({','.join(parameters)})",
                'descriptor': parsed['descriptor'],
                'entry': entry,
                'owner': owner,
            })

    edges = []
    nodes = []
    if len(implementation_targets) == len(_SPRING_TRANSACTION_TARGETS):
        for method in verified_methods:
            source = f"{method['owner']}.{method['member']}/{method['parameter_count']}"
            for implementation in implementation_targets:
                entry = implementation['entry']
                nodes.append({
                    'id': implementation['target'],
                    'kind': 'spring_transaction_proxy_implementation',
                })
                edges.append({
                    'source': source,
                    'source_owner': method['owner'],
                    'source_member': method['member'],
                    'parameter_count': method['parameter_count'],
                    'target': implementation['target'],
                    'target_descriptor': implementation['descriptor'],
                    'edge_kind': 'spring_transaction_proxy_dispatch',
                    'confidence': 'high',
                    'conditions': [],
                    'ambiguity': False,
                    'provenance': {
                        'file': method['file'],
                        'line': method['line'],
                        'annotation_scope': method['annotation_scope'],
                        'business_descriptor': method['business_descriptor'],
                        'business_artifact_entry': method['business_artifact'].get('artifact_entry'),
                        'business_artifact_sha256': method['business_artifact'].get('sha256'),
                        'coord': entry.get('coord'),
                        'jar': entry.get('jar_path'),
                        'artifact_entry': entry.get('artifact_entry'),
                        'artifact_sha256': entry.get('sha256'),
                        'implementation_class': implementation['owner'],
                        'implementation_descriptor': implementation['descriptor'],
                        'business_activation': activation_evidence,
                        'authority': 'final_artifact_javap',
                    },
                })
    applicable = bool(transactional_methods or errors)
    unresolved = bool(applicable and (
        findings or errors
        or len(verified_methods) != len(transactional_methods)
        or len(implementation_targets) != len(_SPRING_TRANSACTION_TARGETS)
    ))
    return _framework_batch(
        'spring_transaction_proxy', '1',
        'partial' if unresolved else _status(applicable, errors),
        nodes, edges, findings, errors,
        {
            'transactional_methods': len(transactional_methods),
            'packaged_transactional_methods': len(verified_methods),
            'implementation_methods': len(implementation_targets),
            'edges': len(edges),
        },
    )


def run_spring_data_repository_adapter(source_roots, artifact_catalog=None):
    """Resolve Spring Data repository proxies from source contracts and packaged runtime code."""
    repositories, repository_errors = _spring_data_business_repositories(source_roots)
    custom_configuration, custom_configuration_errors = (
        _spring_data_custom_repository_configuration(source_roots)
    )
    activation_evidence, activation_errors = _spring_boot_business_activation(source_roots)
    entries = [
        item for item in (artifact_catalog or {}).get('entries') or []
        if str(item.get('coord') or '').strip() == 'org.springframework.data:spring-data-jpa'
        and Path(str(item.get('jar_path') or '')).is_file()
    ]
    edges, nodes, findings = [], [], []
    errors = [
        *repository_errors,
        *custom_configuration_errors,
        *activation_errors,
    ]
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
        and not repository_errors
        and not custom_configuration_errors
        and not activation_errors
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
    applicable = bool(repositories or errors)
    unresolved = bool(repositories and (
        not activation_evidence or len(entries) != 1 or custom_configuration
        or repository_errors or custom_configuration_errors or activation_errors
    ))
    return _framework_batch(
        'spring_data_repository_proxy', '1',
        'partial' if applicable and (errors or unresolved) else _status(applicable, errors),
        nodes, edges, findings, errors,
        {
            'repositories': len(repositories),
            'runtime_implementations': len(entries),
            'implementation_methods': len(implementation_methods),
            'custom_repository_configurations': len(custom_configuration),
            'edges': len(edges),
        },
    )


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
    activation_evidence, activation_errors = _spring_boot_business_activation(source_roots)
    trusted_activation_evidence = activation_evidence if not activation_errors else []
    spring_boot_active = bool(trusted_activation_evidence)
    edges, nodes, findings = [], [], []
    errors = list(activation_errors)
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
                jar_path, coord, trusted_activation_evidence
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
                                        'business_activation': trusted_activation_evidence,
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
                                        'business_activation': trusted_activation_evidence,
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
                                'business_activation': trusted_activation_evidence,
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
    applicable = bool(resource_files or activation_evidence or activation_errors)
    return _framework_batch(
        'spring_runtime_artifact', '1',
        'partial' if applicable and (errors or (resource_files and not spring_boot_active)) else _status(applicable, errors),
        nodes, edges, findings, errors,
        {
            'resource_files': resource_files,
            'business_activation_files': len(activation_evidence),
            'active_callbacks': active_callbacks,
            'conditional_autoconfigurations': conditional_autoconfigurations,
            'edges': len(edges),
        },
    )


def run_framework_adapters(source_roots, output_path='', artifact_catalog=None):
    batches = (
        run_spi_adapter(source_roots, artifact_catalog=artifact_catalog),
        run_spring_adapter(source_roots, artifact_catalog=artifact_catalog),
        run_runtime_spring_registration_adapter(source_roots, artifact_catalog=artifact_catalog),
        run_spring_transaction_proxy_adapter(source_roots, artifact_catalog=artifact_catalog),
        run_spring_data_repository_adapter(source_roots, artifact_catalog=artifact_catalog),
        run_mybatis_adapter(source_roots, artifact_catalog=artifact_catalog),
        run_mybatis_proxy_adapter(source_roots, artifact_catalog=artifact_catalog),
        run_dynamic_proxy_adapter(source_roots, artifact_catalog=artifact_catalog),
        run_declarative_http_client_adapter(source_roots, artifact_catalog=artifact_catalog),
    )
    if output_path:
        serialize_framework_batches(batches, output_path)
    return batches
