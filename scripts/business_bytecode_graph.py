#!/usr/bin/env python3
"""Build and merge current business-class bytecode evidence into the source graph."""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import tempfile
import zipfile
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

from compat import run_cmd
from indirect_usage_analyzer import parse_javap_indirect_references
from step5_evidence_ingestion import ingest_collector_batches
from step5_artifact_fact_store import Step5ArtifactFactStore
from step5_evidence_model import (
    CollectedEdge,
    CollectorBatch,
    EvidenceAuthority,
    EvidenceConcern,
    EvidenceFailure,
    EvidenceProvenance,
    ModuleScope,
)


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
METHOD_HEADER_RE = re.compile(
    r'^\s*(?:[\w.$<>\[\],?]+\s+)+([\w$<>]+)\([^;]*\)'
    r'(?:\s+throws\s+[^;]+)?;\s*$'
)
REFLECTION_UTF8_MARKERS = {
    'Class.forName',
    'forName',
    'getMethod',
    'getDeclaredMethod',
    'getField',
    'getDeclaredField',
    'getConstructor',
    'getDeclaredConstructor',
    'MethodHandles',
    'findStatic',
    'findVirtual',
    'findSpecial',
    'findGetter',
    'findSetter',
    'unreflect',
}
BYTECODE_CACHE_SCHEMA = 'java-upgrade-analyzer.bytecode-index.v3'


def _business_javap_workers():
    value = str(os.environ.get('JUA_STEP5_BYTECODE_JAVAP_WORKERS') or '').strip()
    if value:
        try:
            return max(1, min(16, int(value)))
        except ValueError:
            return 4
    return 4


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _cache_line(payload):
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        + '\n'
    ).encode('utf-8')


def _write_business_bytecode_cache(cache_path, artifact_sha256, evidence, metrics):
    cache_file = Path(cache_path)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='wb', dir=cache_file.parent, prefix=cache_file.name + '.',
            suffix='.tmp', delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(_cache_line({
                'kind': 'header',
                'schema': BYTECODE_CACHE_SCHEMA,
                'artifact_sha256': artifact_sha256,
            }))
            digest = hashlib.sha256()
            edge_count = 0
            for edge in evidence:
                line = _cache_line({'kind': 'edge', 'edge': edge})
                handle.write(line)
                digest.update(line)
                edge_count += 1
            handle.write(_cache_line({
                'kind': 'footer',
                'edge_count': edge_count,
                'edges_sha256': digest.hexdigest(),
                'metrics': metrics,
            }))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, cache_file)
    except Exception:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def _validate_business_bytecode_cache(cache_path, artifact_sha256):
    cache_file = Path(cache_path)
    with cache_file.open('rb') as handle:
        header_line = handle.readline()
        header = json.loads(header_line)
        if (
            header.get('kind') != 'header'
            or header.get('schema') != BYTECODE_CACHE_SCHEMA
            or header.get('artifact_sha256') != artifact_sha256
        ):
            raise ValueError('bytecode cache identity mismatch')
        digest = hashlib.sha256()
        edge_count = 0
        footer = None
        for line in handle:
            record = json.loads(line)
            kind = record.get('kind')
            if kind == 'edge' and footer is None:
                edge = record.get('edge')
                if not isinstance(edge, dict) or edge.get('parser') not in {'classfile', 'javap'}:
                    raise ValueError('bytecode cache edge invalid')
                digest.update(line)
                edge_count += 1
                continue
            if kind == 'footer' and footer is None:
                footer = record
                continue
            raise ValueError('bytecode cache record order invalid')
    if footer is None:
        raise ValueError('bytecode cache footer missing')
    if int(footer.get('edge_count', -1)) != edge_count:
        raise ValueError('bytecode cache edge count mismatch')
    if footer.get('edges_sha256') != digest.hexdigest():
        raise ValueError('bytecode cache integrity mismatch')
    metrics = footer.get('metrics')
    if not isinstance(metrics, dict):
        raise ValueError('bytecode cache metrics invalid')
    if metrics.get('failures'):
        raise ValueError('incomplete bytecode scan cache cannot be reused')
    return metrics


def _iter_business_bytecode_cache(cache_path, artifact_sha256):
    """Recheck integrity while streaming so validated evidence cannot be swapped."""
    cache_file = Path(cache_path)
    with cache_file.open('rb') as handle:
        header = json.loads(handle.readline())
        if (
            header.get('schema') != BYTECODE_CACHE_SCHEMA
            or header.get('artifact_sha256') != artifact_sha256
        ):
            raise ValueError('bytecode cache changed after validation')
        digest = hashlib.sha256()
        edge_count = 0
        footer = None
        for line in handle:
            record = json.loads(line)
            if record.get('kind') == 'edge' and footer is None:
                digest.update(line)
                edge_count += 1
                yield record['edge']
            elif record.get('kind') == 'footer' and footer is None:
                footer = record
            else:
                raise ValueError('bytecode cache changed during streaming')
        if (
            footer is None
            or int(footer.get('edge_count', -1)) != edge_count
            or footer.get('edges_sha256') != digest.hexdigest()
        ):
            raise ValueError('bytecode cache changed during streaming')


def _cp_class_name(cp, index):
    item = cp.get(index) or {}
    if item.get('tag') != 7:
        return ''
    return str((cp.get(item.get('name_index')) or {}).get('value') or '')


def _cp_utf8(cp, index):
    return str((cp.get(index) or {}).get('value') or '')


def _cp_name_and_type(cp, index):
    item = cp.get(index) or {}
    if item.get('tag') != 12:
        return '', ''
    return _cp_utf8(cp, item.get('name_index')), _cp_utf8(cp, item.get('descriptor_index'))


def _parse_classfile_constant_pool(data):
    if not data or len(data) < 10 or data[:4] != b'\xca\xfe\xba\xbe':
        return None, 0
    cp_count = struct.unpack_from('>H', data, 8)[0]
    cp = {}
    idx = 10
    cp_index = 1
    while cp_index < cp_count:
        if idx >= len(data):
            return None, 0
        tag = data[idx]
        idx += 1
        if tag == 1:  # Utf8
            if idx + 2 > len(data):
                return None, 0
            length = struct.unpack_from('>H', data, idx)[0]
            idx += 2
            if idx + length > len(data):
                return None, 0
            cp[cp_index] = {
                'tag': tag,
                'value': data[idx:idx + length].decode('utf-8', errors='replace'),
            }
            idx += length
        elif tag == 7:  # Class
            if idx + 2 > len(data):
                return None, 0
            cp[cp_index] = {'tag': tag, 'name_index': struct.unpack_from('>H', data, idx)[0]}
            idx += 2
        elif tag in (9, 10, 11):  # Fieldref / Methodref / InterfaceMethodref
            if idx + 4 > len(data):
                return None, 0
            cp[cp_index] = {
                'tag': tag,
                'class_index': struct.unpack_from('>H', data, idx)[0],
                'name_and_type_index': struct.unpack_from('>H', data, idx + 2)[0],
            }
            idx += 4
        elif tag == 12:  # NameAndType
            if idx + 4 > len(data):
                return None, 0
            cp[cp_index] = {
                'tag': tag,
                'name_index': struct.unpack_from('>H', data, idx)[0],
                'descriptor_index': struct.unpack_from('>H', data, idx + 2)[0],
            }
            idx += 4
        elif tag in (3, 4):  # Integer / Float
            idx += 4
        elif tag in (5, 6):  # Long / Double
            idx += 8
            cp_index += 1
        elif tag == 8:  # String
            idx += 2
        elif tag == 15:  # MethodHandle
            if idx + 3 > len(data):
                return None, 0
            cp[cp_index] = {
                'tag': tag,
                'reference_kind': data[idx],
                'reference_index': struct.unpack_from('>H', data, idx + 1)[0],
            }
            idx += 3
        elif tag == 16:  # MethodType
            if idx + 2 > len(data):
                return None, 0
            cp[cp_index] = {
                'tag': tag,
                'descriptor_index': struct.unpack_from('>H', data, idx)[0],
            }
            idx += 2
        elif tag in (17, 18):  # Dynamic / InvokeDynamic
            if idx + 4 > len(data):
                return None, 0
            cp[cp_index] = {
                'tag': tag,
                'bootstrap_method_attr_index': struct.unpack_from('>H', data, idx)[0],
                'name_and_type_index': struct.unpack_from('>H', data, idx + 2)[0],
            }
            idx += 4
        elif tag in (19, 20):  # Module / Package
            idx += 2
        else:
            return None, 0
        if idx > len(data):
            return None, 0
        cp_index += 1
    return cp, idx


def _skip_attributes(data, idx, count):
    for _ in range(count):
        if idx + 6 > len(data):
            return 0
        length = struct.unpack_from('>I', data, idx + 2)[0]
        idx += 6 + length
        if idx > len(data):
            return 0
    return idx


def _skip_member_table(data, idx):
    if idx + 2 > len(data):
        return 0
    count = struct.unpack_from('>H', data, idx)[0]
    idx += 2
    for _ in range(count):
        if idx + 8 > len(data):
            return 0
        attr_count = struct.unpack_from('>H', data, idx + 6)[0]
        idx = _skip_attributes(data, idx + 8, attr_count)
        if not idx:
            return 0
    return idx


FIXED_OPCODE_LENGTHS = {
    **{op: 1 for op in range(0x00, 0x10)},
    0x10: 2, 0x11: 3, 0x12: 2, 0x13: 3, 0x14: 3,
    **{op: 2 for op in range(0x15, 0x1a)},
    **{op: 1 for op in range(0x1a, 0x36)},
    **{op: 2 for op in range(0x36, 0x3b)},
    **{op: 1 for op in range(0x3b, 0x84)},
    0x84: 3,
    **{op: 1 for op in range(0x85, 0x99)},
    **{op: 3 for op in range(0x99, 0xa8)},
    0xa8: 3, 0xa9: 2,
    **{op: 1 for op in range(0xac, 0xb2)},
    0xb2: 3, 0xb3: 3, 0xb4: 3, 0xb5: 3,
    0xb6: 3, 0xb7: 3, 0xb8: 3, 0xb9: 5, 0xba: 5,
    0xbb: 3, 0xbc: 2, 0xbd: 3, 0xbe: 1, 0xbf: 1, 0xc0: 3, 0xc1: 3,
    0xc2: 1, 0xc3: 1, 0xc5: 4, 0xc6: 3, 0xc7: 3, 0xc8: 5, 0xc9: 5,
}


def _next_instruction_offset(code, offset):
    opcode = code[offset]
    if opcode == 0xaa:  # tableswitch
        pos = offset + 1
        # JVM padding aligns the first operand to a four-byte boundary relative
        # to the beginning of the method's code array, not relative to opcode.
        while pos % 4:
            pos += 1
        if pos + 12 > len(code):
            return -1
        low = struct.unpack_from('>i', code, pos + 4)[0]
        high = struct.unpack_from('>i', code, pos + 8)[0]
        if high < low:
            return -1
        end = pos + 12 + (high - low + 1) * 4
        return end if end <= len(code) else -1
    if opcode == 0xab:  # lookupswitch
        pos = offset + 1
        while pos % 4:
            pos += 1
        if pos + 8 > len(code):
            return -1
        npairs = struct.unpack_from('>i', code, pos + 4)[0]
        if npairs < 0:
            return -1
        end = pos + 8 + npairs * 8
        return end if end <= len(code) else -1
    if opcode == 0xc4:  # wide
        if offset + 1 >= len(code):
            return len(code)
        return offset + (6 if code[offset + 1] == 0x84 else 4)
    return offset + FIXED_OPCODE_LENGTHS.get(opcode, 1)


def _classfile_ref(cp, index):
    ref = cp.get(index) or {}
    tag = ref.get('tag')
    if tag not in (9, 10, 11):
        return '', '', '', tag
    owner = _cp_class_name(cp, ref.get('class_index'))
    name, descriptor = _cp_name_and_type(cp, ref.get('name_and_type_index'))
    return owner, name, descriptor, tag


def parse_classfile_calls(data, class_name):
    """Parse bytecode directly. Return None when javap fallback is required."""
    try:
        cp, idx = _parse_classfile_constant_pool(data)
        if cp is None:
            return None
        utf8_values = {str(item.get('value') or '') for item in cp.values() if item.get('tag') == 1}
        if REFLECTION_UTF8_MARKERS & utf8_values:
            return None
        class_simple = class_name.rsplit('.', 1)[-1]
        edges = []
        pending_invokedynamic = []
        class_refs = {
            _cp_class_name(cp, cp_index).replace('/', '.').replace('$', '.')
            for cp_index, item in cp.items()
            if item.get('tag') == 7
        }
        class_refs.discard(class_name)
        if idx + 8 > len(data):
            return None
        idx += 6  # access_flags, this_class, super_class
        interfaces_count = struct.unpack_from('>H', data, idx)[0]
        idx += 2 + interfaces_count * 2
        idx = _skip_member_table(data, idx)  # fields
        if not idx or idx + 2 > len(data):
            return None
        method_count = struct.unpack_from('>H', data, idx)[0]
        idx += 2
        for _ in range(method_count):
            if idx + 8 > len(data):
                return None
            name = _cp_utf8(cp, struct.unpack_from('>H', data, idx + 2)[0])
            descriptor = _cp_utf8(cp, struct.unpack_from('>H', data, idx + 4)[0])
            attr_count = struct.unpack_from('>H', data, idx + 6)[0]
            idx += 8
            caller_name = class_simple if name == '<init>' else name
            caller_signature = method_descriptor_signature(descriptor)
            for _attr in range(attr_count):
                if idx + 6 > len(data):
                    return None
                attr_name = _cp_utf8(cp, struct.unpack_from('>H', data, idx)[0])
                attr_len = struct.unpack_from('>I', data, idx + 2)[0]
                attr_start = idx + 6
                attr_end = attr_start + attr_len
                if attr_end > len(data):
                    return None
                if attr_name == 'Code':
                    if attr_start + 8 > attr_end:
                        return None
                    code_len = struct.unpack_from('>I', data, attr_start + 4)[0]
                    code_start = attr_start + 8
                    code_end = code_start + code_len
                    if code_end > attr_end:
                        return None
                    code = data[code_start:code_end]
                    offset = 0
                    while offset < len(code):
                        opcode = code[offset]
                        if opcode in (0xb2, 0xb3, 0xb4, 0xb5) and offset + 2 < len(code):
                            cp_idx = struct.unpack_from('>H', code, offset + 1)[0]
                            owner, member, _desc, _tag = _classfile_ref(cp, cp_idx)
                            jvm_owner = owner.replace('/', '.')
                            owner = jvm_owner.replace('$', '.')
                            if owner and member:
                                edges.append({
                                    'caller_owner': class_name,
                                    'caller_name': caller_name,
                                    'caller_signature': caller_signature,
                                    'caller_descriptor': descriptor,
                                    'callee_key': f'{owner}.{member}',
                                    'callee_jvm_owner': jvm_owner,
                                    'callee_descriptor': _desc,
                                    'callee_simple_key': f'field:{member}',
                                    'evidence_type': 'bytecode_field_access',
                                    'line': offset,
                                    'instruction_offset': offset,
                                    'content': f'classfile opcode 0x{opcode:02x}',
                                })
                        elif opcode in (0xb6, 0xb7, 0xb8, 0xb9) and offset + 2 < len(code):
                            cp_idx = struct.unpack_from('>H', code, offset + 1)[0]
                            owner, member, desc, _tag = _classfile_ref(cp, cp_idx)
                            jvm_owner = owner.replace('/', '.')
                            owner = jvm_owner.replace('$', '.')
                            if owner and member:
                                signature = method_descriptor_signature(desc)
                                display_member = owner.rsplit('.', 1)[-1] if member == '<init>' else member
                                edges.append({
                                    'caller_owner': class_name,
                                    'caller_name': caller_name,
                                    'caller_signature': caller_signature,
                                    'caller_descriptor': descriptor,
                                    'callee_key': f'{owner}.{display_member}{signature}',
                                    'callee_jvm_owner': jvm_owner,
                                    'callee_descriptor': desc,
                                    'callee_simple_key': f'method:{display_member}{signature}',
                                    'evidence_type': 'bytecode_constructor_invocation' if member == '<init>' else 'bytecode_method_invocation',
                                    'line': offset,
                                    'instruction_offset': offset,
                                    'content': f'classfile opcode 0x{opcode:02x}',
                                })
                        elif opcode == 0xba and offset + 2 < len(code):
                            cp_idx = struct.unpack_from('>H', code, offset + 1)[0]
                            indy = cp.get(cp_idx) or {}
                            indy_name, indy_desc = _cp_name_and_type(cp, indy.get('name_and_type_index'))
                            signature = method_descriptor_signature(indy_desc)
                            edges.append({
                                'caller_owner': class_name,
                                'caller_name': caller_name,
                                'caller_signature': caller_signature,
                                'caller_descriptor': descriptor,
                                'callee_key': f'invokedynamic:{indy_name}{signature}',
                                'callee_simple_key': f'invokedynamic:{indy_name}',
                                'evidence_type': 'bytecode_invokedynamic',
                                'line': offset,
                                'instruction_offset': offset,
                                'content': 'classfile invokedynamic',
                            })
                            pending_invokedynamic.append({
                                'bootstrap_index': indy.get('bootstrap_method_attr_index'),
                                'caller_owner': class_name,
                                'caller_name': caller_name,
                                'caller_signature': caller_signature,
                                'caller_descriptor': descriptor,
                                'line': offset,
                            })
                        elif opcode in (0xbb, 0xbd, 0xc0, 0xc1) and offset + 2 < len(code):
                            cp_idx = struct.unpack_from('>H', code, offset + 1)[0]
                            owner = _cp_class_name(cp, cp_idx).replace('/', '.').replace('$', '.')
                            if owner:
                                edges.append({
                                    'caller_owner': class_name,
                                    'caller_name': caller_name,
                                    'caller_signature': caller_signature,
                                    'callee_key': owner,
                                    'callee_simple_key': f'class:{owner.rsplit(".", 1)[-1]}',
                                    'evidence_type': 'bytecode_type_reference',
                                    'line': offset,
                                    'instruction_offset': offset,
                                    'content': f'classfile opcode 0x{opcode:02x}',
                                })
                        elif opcode == 0xc5 and offset + 2 < len(code):
                            cp_idx = struct.unpack_from('>H', code, offset + 1)[0]
                            owner = _cp_class_name(cp, cp_idx).replace('/', '.').replace('$', '.')
                            if owner:
                                edges.append({
                                    'caller_owner': class_name,
                                    'caller_name': caller_name,
                                    'caller_signature': caller_signature,
                                    'callee_key': owner,
                                    'callee_simple_key': f'class:{owner.rsplit(".", 1)[-1]}',
                                    'evidence_type': 'bytecode_type_reference',
                                    'line': offset,
                                    'instruction_offset': offset,
                                    'content': 'classfile multianewarray',
                                })
                        next_offset = _next_instruction_offset(code, offset)
                        if next_offset <= offset:
                            return None
                        offset = next_offset
                    # Code_attribute.exception_table entries retain the exact
                    # exception type handled by this method.  A catch type is a
                    # direct binary dependency even when no instruction creates
                    # or casts that exception, so do not leave it as a vague
                    # class-level constant-pool reference.
                    exception_pos = code_end
                    if exception_pos + 2 > attr_end:
                        return None
                    exception_count = struct.unpack_from('>H', data, exception_pos)[0]
                    exception_pos += 2
                    if exception_pos + exception_count * 8 > attr_end:
                        return None
                    for _exception in range(exception_count):
                        _start_pc, _end_pc, handler_pc, catch_type = struct.unpack_from(
                            '>HHHH', data, exception_pos
                        )
                        exception_pos += 8
                        if not catch_type:
                            continue  # finally/catch-all has no API type
                        owner = _cp_class_name(cp, catch_type).replace('/', '.').replace('$', '.')
                        if owner:
                            edges.append({
                                'caller_owner': class_name,
                                'caller_name': caller_name,
                                'caller_signature': caller_signature,
                                'caller_descriptor': descriptor,
                                'callee_key': owner,
                                'callee_simple_key': f'class:{owner.rsplit(".", 1)[-1]}',
                                'evidence_type': 'bytecode_exception_handler_reference',
                                'line': handler_pc,
                                'instruction_offset': handler_pc,
                                'content': 'classfile exception-table catch type',
                            })
                idx = attr_end
        # Resolve lambda/method-reference implementation handles from the
        # class-level BootstrapMethods attribute.  The InvokeDynamic entry stores
        # a zero-based bootstrap table index; LambdaMetafactory arguments include
        # the actual MethodHandle that must become a call-graph edge.
        bootstrap_methods = []
        if idx + 2 > len(data):
            return None
        class_attr_count = struct.unpack_from('>H', data, idx)[0]
        idx += 2
        for _ in range(class_attr_count):
            if idx + 6 > len(data):
                return None
            attr_name = _cp_utf8(cp, struct.unpack_from('>H', data, idx)[0])
            attr_len = struct.unpack_from('>I', data, idx + 2)[0]
            attr_start = idx + 6
            attr_end = attr_start + attr_len
            if attr_end > len(data):
                return None
            if attr_name == 'BootstrapMethods':
                if attr_start + 2 > attr_end:
                    return None
                pos = attr_start
                count = struct.unpack_from('>H', data, pos)[0]
                pos += 2
                for _bootstrap in range(count):
                    if pos + 4 > attr_end:
                        return None
                    method_ref = struct.unpack_from('>H', data, pos)[0]
                    arg_count = struct.unpack_from('>H', data, pos + 2)[0]
                    pos += 4
                    if pos + arg_count * 2 > attr_end:
                        return None
                    arguments = list(struct.unpack_from(f'>{arg_count}H', data, pos)) if arg_count else []
                    pos += arg_count * 2
                    bootstrap_methods.append((method_ref, arguments))
            idx = attr_end

        for pending in pending_invokedynamic:
            bootstrap_index = pending.get('bootstrap_index')
            if not isinstance(bootstrap_index, int) or bootstrap_index >= len(bootstrap_methods):
                return None
            _bootstrap_ref, arguments = bootstrap_methods[bootstrap_index]
            for argument_index in arguments:
                handle = cp.get(argument_index) or {}
                if handle.get('tag') != 15:
                    continue
                owner, member, descriptor, tag = _classfile_ref(
                    cp, handle.get('reference_index')
                )
                if tag not in (10, 11) or not owner or not member:
                    continue
                jvm_owner = owner.replace('/', '.')
                owner = jvm_owner.replace('$', '.')
                signature = method_descriptor_signature(descriptor)
                display_member = owner.rsplit('.', 1)[-1] if member == '<init>' else member
                edges.append({
                    'caller_owner': pending['caller_owner'],
                    'caller_name': pending['caller_name'],
                    'caller_signature': pending['caller_signature'],
                    'caller_descriptor': pending['caller_descriptor'],
                    'callee_key': f'{owner}.{display_member}{signature}',
                    'callee_jvm_owner': jvm_owner,
                    'callee_descriptor': descriptor,
                    'callee_simple_key': f'method:{display_member}{signature}',
                    'evidence_type': (
                        'bytecode_constructor_invocation'
                        if member == '<init>' else 'bytecode_invokedynamic_method_reference'
                    ),
                    'line': pending['line'],
                    'instruction_offset': pending['line'],
                    'content': 'classfile BootstrapMethods method handle',
                })
        existing_type_refs = {
            item['callee_key'] for item in edges
            if item.get('evidence_type') == 'bytecode_type_reference'
        }
        for owner in sorted(item for item in class_refs if item and not item.startswith('[')):
            if owner in existing_type_refs:
                continue
            edges.append({
                'caller_owner': class_name,
                'caller_name': class_simple,
                'caller_signature': '',
                'callee_key': owner,
                'callee_simple_key': f'class:{owner.rsplit(".", 1)[-1]}',
                'evidence_type': 'bytecode_class_reference',
                'line': 0,
                'content': 'classfile constant-pool/signature/annotation reference',
            })
        return edges
    except Exception:
        return None


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
        offset_match = re.match(r'^\s*(\d+):', raw)
        instruction_offset = int(offset_match.group(1)) if offset_match else -1
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
                'instruction_offset': instruction_offset,
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
                'instruction_offset': instruction_offset,
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
                'instruction_offset': instruction_offset,
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
                'instruction_offset': instruction_offset,
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
            'instruction_offset': int(item.get('instruction_offset', -1)),
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


def _logical_application_class_entry(entry):
    for prefix in ('BOOT-INF/classes/', 'WEB-INF/classes/'):
        if entry.startswith(prefix):
            return entry[len(prefix):]
    return entry


def _iter_business_class_bytes(business_jar, fact_store=None):
    if fact_store is not None:
        for entry, data in fact_store.iter_physical_class_bytes('__business__'):
            if (
                entry.startswith('META-INF/')
                or entry.endswith(('module-info.class', 'package-info.class'))
            ):
                continue
            yield entry, data
        return
    with zipfile.ZipFile(business_jar) as archive:
        for entry in sorted(
            name for name in archive.namelist()
            if name.endswith('.class')
            and not name.startswith('META-INF/')
            and not name.endswith(('module-info.class', 'package-info.class'))
        ):
            yield entry, archive.read(entry)


def collect_business_bytecode_edges(
    source_roots, max_classes=10000, artifact_catalog=None, cache_path=None,
    fact_store=None,
):
    evidence = []
    failures = []
    scanned = 0
    fast_path_classes = 0
    javap_fallback_classes = 0
    catalog = artifact_catalog or {}
    business_item = ((catalog.get('by_coord') or {}).get('__business__') or {})
    if not business_item:
        business_item = next((
            item for item in (catalog.get('entries') or ())
            if str((item or {}).get('coord') or '') == '__business__'
        ), {})
    business_jar = str(business_item.get('jar_path') or '').strip()
    cache_key = str(business_item.get('sha256') or '').strip()
    if not business_jar or not os.path.isfile(business_jar):
        failures.append('current_final_artifact_required')
        return [], {
            'classes_scanned': 0,
            'edges_found': 0,
            'classfile_fast_path_classes': 0,
            'javap_fallback_classes': 0,
            'failures': failures,
            'evidence_source': 'unavailable',
            'artifact_sha256': cache_key,
        }
    if not re.fullmatch(r'[0-9a-f]{64}', cache_key):
        failures.append('current_final_artifact_sha_invalid')
        return [], {
            'classes_scanned': 0,
            'edges_found': 0,
            'classfile_fast_path_classes': 0,
            'javap_fallback_classes': 0,
            'failures': failures,
            'evidence_source': 'unavailable',
            'artifact_sha256': cache_key,
        }
    if business_jar and os.path.isfile(business_jar):
        try:
            actual_business_sha256 = _sha256_file(business_jar)
        except OSError as exc:
            failures.append(f'business_artifact_identity_failed:{exc}')
            return [], {
                'classes_scanned': 0,
                'edges_found': 0,
                'classfile_fast_path_classes': 0,
                'javap_fallback_classes': 0,
                'failures': failures,
                'evidence_source': 'unavailable',
                'artifact_sha256': cache_key,
            }
        if (
            actual_business_sha256
            and re.fullmatch(r'[0-9a-f]{64}', cache_key)
            and cache_key != actual_business_sha256
        ):
            failures.append('current_final_artifact_sha_mismatch')
            return [], {
                'classes_scanned': 0,
                'edges_found': 0,
                'classfile_fast_path_classes': 0,
                'javap_fallback_classes': 0,
                'failures': failures,
                'evidence_source': 'unavailable',
                'artifact_sha256': cache_key,
                'actual_artifact_sha256': actual_business_sha256,
            }
    if cache_path and cache_key:
        try:
            cached_metrics = _validate_business_bytecode_cache(cache_path, cache_key)
            cached_edges = list(_iter_business_bytecode_cache(cache_path, cache_key))
        except (OSError, ValueError, TypeError):
            cached_metrics = None
            cached_edges = None
        if cached_metrics is not None:
            try:
                artifact_sha256_after_load = _sha256_file(business_jar)
            except OSError as exc:
                failures.append(f'business_artifact_identity_failed:{exc}')
                return [], {
                    **dict(cached_metrics),
                    'classes_scanned': 0,
                    'edges_found': 0,
                    'failures': failures,
                    'evidence_source': 'unavailable',
                    'artifact_sha256': cache_key,
                    'cache_hit': False,
                }
            if artifact_sha256_after_load != actual_business_sha256:
                failures.append('current_final_artifact_changed_during_scan')
                return [], {
                    **dict(cached_metrics),
                    'classes_scanned': 0,
                    'edges_found': 0,
                    'failures': failures,
                    'evidence_source': 'unavailable',
                    'artifact_sha256': cache_key,
                    'actual_artifact_sha256': artifact_sha256_after_load,
                    'cache_hit': False,
                }
            return cached_edges, {
                **dict(cached_metrics),
                'artifact_sha256': cache_key,
                'cache_hit': True,
            }
    if business_jar and os.path.isfile(business_jar):
        try:
            class_results = []
            def parse_javap_task(task):
                entry = task['entry']
                logical_entry = task['logical_entry']
                class_name = task['class_name']

                def produce_javap(identity=None, _location=None, _profile=None):
                    artifact_path = identity.path if identity is not None else business_jar
                    if identity is not None or logical_entry == entry:
                        return run_cmd(
                            [
                                'javap', '-classpath', artifact_path,
                                '-c', '-s', '-p', '-v', class_name,
                            ],
                            timeout=30,
                        )
                    with zipfile.ZipFile(artifact_path) as archive:
                        nested_data = archive.read(entry)
                    temporary_class = tempfile.NamedTemporaryFile(
                        suffix='.class', delete=False
                    )
                    try:
                        temporary_class.write(nested_data)
                        temporary_class.close()
                        return run_cmd(
                            [
                                'javap', '-c', '-s', '-p', '-v',
                                temporary_class.name,
                            ],
                            timeout=30,
                        )
                    finally:
                        try:
                            os.unlink(temporary_class.name)
                        except OSError:
                            pass

                if fact_store is None:
                    stdout, stderr, rc = produce_javap()
                else:
                    from step5_artifact_fact_store import ClassLocation
                    location = ClassLocation(
                        logical_name=logical_entry,
                        binary_name=class_name,
                        physical_entry=entry,
                        multi_release_version='base',
                    )
                    outcome = fact_store.javap_fact(
                        '__business__', location,
                        'verbose-code-private-signatures-v1', produce_javap,
                        retain=False,
                    )
                    if outcome.status == 'complete':
                        stdout, stderr, rc = outcome.value
                    else:
                        stdout, stderr, rc = '', outcome.reason, 1
                if rc != 0:
                    return (
                        entry, class_name, 'javap', [],
                        f'javap_failed:{class_name}:{(stderr or "")[:80]}',
                    )
                return entry, class_name, 'javap', parse_javap_calls(stdout, class_name), ''

            workers = _business_javap_workers()
            pending_limit = max(1, workers * 2)
            peak_pending = 0
            executor = ThreadPoolExecutor(max_workers=workers) if workers > 1 else None
            pending = {}

            def drain_pending():
                completed, _remaining = wait(
                    tuple(pending), return_when=FIRST_COMPLETED,
                )
                for future in completed:
                    task = pending.pop(future)
                    class_results[task['result_index']] = future.result()

            try:
                for entry, data in _iter_business_class_bytes(business_jar, fact_store):
                    if scanned >= max_classes:
                        failures.append('class_scan_limit_reached')
                        break
                    logical_entry = _logical_application_class_entry(entry)
                    class_name = logical_entry[:-6].replace('/', '.')
                    scanned += 1
                    parsed_edges = parse_classfile_calls(data, class_name)
                    if parsed_edges is not None:
                        fast_path_classes += 1
                        class_results.append(
                            (entry, class_name, 'classfile', parsed_edges, '')
                        )
                        continue

                    javap_fallback_classes += 1
                    class_results.append(None)
                    task = {
                        'result_index': len(class_results) - 1,
                        'entry': entry,
                        'logical_entry': logical_entry,
                        'class_name': class_name,
                    }
                    if executor is None:
                        class_results[task['result_index']] = parse_javap_task(task)
                        peak_pending = max(peak_pending, 1)
                        continue
                    future = executor.submit(parse_javap_task, task)
                    pending[future] = task
                    peak_pending = max(peak_pending, len(pending))
                    if len(pending) >= pending_limit:
                        drain_pending()
                while pending:
                    drain_pending()
            finally:
                if executor is not None:
                    executor.shutdown(wait=True, cancel_futures=True)

            for entry, class_name, parser_kind, parsed_edges, failure in class_results:
                if failure:
                    failures.append(failure)
                    continue
                for item in parsed_edges:
                    item['class_file'] = f'{business_jar}!/{entry}'
                    item['artifact_sha256'] = actual_business_sha256
                    item['evidence_source'] = 'current_final_artifact'
                    item['parser'] = parser_kind
                    evidence.append(item)
            metrics = {
                'classes_scanned': scanned,
                'edges_found': len(evidence),
                'method_edges': sum(item.get('evidence_type') in {
                    'bytecode_method_invocation', 'bytecode_constructor_invocation',
                    'bytecode_invokedynamic_method_reference',
                } for item in evidence),
                'field_edges': sum(item.get('evidence_type') == 'bytecode_field_access' for item in evidence),
                'type_edges': sum(item.get('evidence_type') in {'bytecode_type_reference', 'bytecode_class_reference'} for item in evidence),
                'invokedynamic_edges': sum(item.get('evidence_type') == 'bytecode_invokedynamic' for item in evidence),
                'classfile_fast_path_classes': fast_path_classes,
                'javap_fallback_classes': javap_fallback_classes,
                'javap_peak_pending_tasks': peak_pending,
                'javap_pending_limit': pending_limit,
                'failures': failures,
                'evidence_source': 'current_final_artifact',
                'artifact_sha256': cache_key,
                'cache_write_failed': False,
            }
            try:
                artifact_sha256_after_scan = _sha256_file(business_jar)
            except OSError as exc:
                failures.append(f'business_artifact_identity_failed:{exc}')
                artifact_sha256_after_scan = ''
            if artifact_sha256_after_scan != actual_business_sha256:
                failures.append('current_final_artifact_changed_during_scan')
                metrics['failures'] = failures
                metrics['edges_found'] = 0
                return [], metrics
            if cache_path and cache_key and not failures:
                try:
                    _write_business_bytecode_cache(
                        cache_path, cache_key, evidence, metrics
                    )
                except (OSError, TypeError, ValueError) as exc:
                    metrics['cache_write_failed'] = True
                    metrics['cache_write_error'] = str(exc)
            return evidence, metrics
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            detail = str(exc)
            if (
                'artifact_changed' in detail
                or 'artifact_sha256_mismatch' in detail
            ):
                failures.append('current_final_artifact_changed_during_scan')
            else:
                failures.append(f'business_artifact_scan_failed:{exc}')
            return [], {
                'classes_scanned': scanned,
                'edges_found': 0,
                'classfile_fast_path_classes': fast_path_classes,
                'javap_fallback_classes': javap_fallback_classes,
                'failures': failures,
                'evidence_source': 'unavailable',
                'artifact_sha256': cache_key,
            }
    failures.append('current_final_artifact_required')
    return [], {
        'classes_scanned': 0,
        'edges_found': 0,
        'classfile_fast_path_classes': 0,
        'javap_fallback_classes': 0,
        'failures': failures,
        'evidence_source': 'unavailable',
        'artifact_sha256': cache_key,
    }


def _bytecode_failure(value):
    text = str(value or "")
    if text.startswith("javap_failed:"):
        return EvidenceFailure(
            stage="business-bytecode",
            reason_code="BYTECODE_PARSE_FAILED",
            blocking=True,
            class_name=text.split(":", 2)[1] if text.count(":") >= 2 else "",
            detail=text,
        )
    reason_code = {
        "current_final_artifact_required": "CURRENT_FINAL_ARTIFACT_REQUIRED",
        "class_scan_limit_reached": "BYTECODE_CLASS_SCAN_LIMIT_REACHED",
        "current_final_artifact_sha_invalid": "CURRENT_FINAL_ARTIFACT_SHA_INVALID",
        "current_final_artifact_sha_mismatch": "CURRENT_FINAL_ARTIFACT_SHA_MISMATCH",
        "current_final_artifact_changed_during_scan": "CURRENT_FINAL_ARTIFACT_CHANGED_DURING_SCAN",
    }.get(text, "BYTECODE_COLLECTION_FAILED")
    return EvidenceFailure(
        stage="business-bytecode",
        reason_code=reason_code,
        blocking=True,
        detail=text,
    )


def _valid_sha256(value):
    return bool(re.fullmatch(r"[0-9a-f]{64}", str(value or "")))


def _business_bytecode_batch(
    evidence, metrics, *, strict_final_artifact, release_consumed=False,
):
    metrics = dict(metrics or {})
    string_pool = {}

    def pooled(value):
        text = str(value or "")
        return string_pool.setdefault(text, text)

    failure_values = list(metrics.get("failures") or ())
    typed_failures = []
    concerns = []
    edges = []
    non_executable_class_references = 0
    batch_sha_invalid = (
        strict_final_artifact
        and not _valid_sha256(metrics.get("artifact_sha256"))
    )
    if batch_sha_invalid:
        typed_failures.append(_bytecode_failure("current_final_artifact_sha_invalid"))
    release_list = evidence if release_consumed and isinstance(evidence, list) else None
    for index, item in enumerate(evidence or ()):
        if release_list is not None:
            release_list[index] = None
        if item is None:
            continue
        if item.get("evidence_type") == "bytecode_class_reference":
            # A constant-pool/signature/annotation class entry has no owning
            # bytecode instruction or method.  Keep it as collection telemetry;
            # treating it as a call edge creates synthetic callers and false
            # blocking failures for interfaces and annotation-only classes.
            non_executable_class_references += 1
            continue
        owner = pooled(str(item.get("caller_owner") or "").strip())
        name = pooled(str(item.get("caller_name") or "").strip())
        signature = pooled(item.get("caller_signature"))
        if not owner or not name:
            typed_failures.append(EvidenceFailure(
                stage="business-bytecode",
                reason_code="BYTECODE_CALLER_UNRESOLVED",
                blocking=True,
                detail=f"字节码调用缺少可解析调用方：{owner}.{name}",
                artifact=str(item.get("class_file") or ""),
                class_name=owner,
            ))
            continue
        if batch_sha_invalid:
            continue
        artifact_sha = pooled(item.get("artifact_sha256"))
        class_file = pooled(item.get("class_file"))
        artifact_path, separator, artifact_entry = class_file.partition("!/")
        artifact_path = pooled(artifact_path)
        artifact_entry = pooled(artifact_entry)
        authority = (
            EvidenceAuthority.CURRENT_FINAL_ARTIFACT
            if _valid_sha256(artifact_sha)
            else EvidenceAuthority.SOURCE_AST
        )
        edges.append(CollectedEdge(
            caller_symbol=pooled(f"{owner}.{name}{signature}"),
            callee_symbol=pooled(item.get("callee_key")),
            edge_kind=pooled(item.get("evidence_type") or "bytecode_reference"),
            semantic=False,
            owner_scope=ModuleScope.BUSINESS_CLASSES,
            owner_coord="__business__",
            provenance=EvidenceProvenance(
                authority=authority,
                artifact_path=artifact_path or class_file,
                artifact_sha256=artifact_sha if authority == EvidenceAuthority.CURRENT_FINAL_ARTIFACT else "",
                artifact_entry=artifact_entry if separator else "",
                class_or_resource_entry=artifact_entry if separator else "",
                parser=pooled(item.get("parser") or "classfile"),
                evidence_source=pooled(
                    item.get("evidence_source") or "current_final_artifact"
                ),
                line=int(item.get("line") or 0),
                instruction_offset=int(
                    item["instruction_offset"]
                    if item.get("instruction_offset") is not None else -1
                ),
            ),
            metadata=(
                ("caller_resolution_required", True),
                ("caller_owner", owner),
                ("caller_name", name),
                ("caller_signature", signature),
                ("callee_simple_key", pooled(item.get("callee_simple_key"))),
                ("content", pooled(str(item.get("content") or "")[:100])),
                ("artifact_sha256", artifact_sha),
            ),
        ))
    typed_failures = list(dict.fromkeys((
        *(_bytecode_failure(item) for item in failure_values),
        *typed_failures,
    )))
    if metrics.get("cache_write_failed"):
        concerns.append(EvidenceConcern(
            stage="business-bytecode",
            reason_code="BYTECODE_CACHE_WRITE_FAILED",
            detail=str(metrics.get("cache_write_error") or "bytecode cache write failed"),
        ))
    stable_failure_codes = [failure.reason_code for failure in typed_failures]
    return CollectorBatch(
        collector="business_bytecode",
        version="2",
        edges=tuple(edges),
        failures=tuple(typed_failures),
        concerns=tuple(concerns),
        metrics=tuple(sorted({
            **metrics,
            "failures": stable_failure_codes,
            "collected_edges": len(edges),
            "non_executable_class_references": non_executable_class_references,
            "unresolved_callers": sum(
                failure.reason_code == "BYTECODE_CALLER_UNRESOLVED"
                for failure in typed_failures
            ),
        }.items())),
    )


def collect_business_bytecode_batch(
    source_roots, artifact_catalog, cache_path, *, fact_store=None,
):
    """Collect immutable current-final-artifact bytecode evidence without a graph."""
    if fact_store is None:
        fact_store = Step5ArtifactFactStore.from_catalog(artifact_catalog)
    evidence, metrics = collect_business_bytecode_edges(
        source_roots,
        artifact_catalog=artifact_catalog,
        cache_path=cache_path,
        fact_store=fact_store,
    )
    return _business_bytecode_batch(
        evidence,
        metrics,
        strict_final_artifact=True,
        release_consumed=True,
    )


def merge_business_bytecode_edges(graph, evidence):
    """Compatibility bridge for legacy callers; production uses batch ingestion."""
    batch = _business_bytecode_batch(evidence, {}, strict_final_artifact=False)
    result = ingest_collector_batches(graph, (batch,))
    return {
        "merged_edges": result.merged_edges,
        "skipped_unresolved_callers": dict(result.rejected_by_collector).get(
            "business_bytecode", 0
        ),
    }
