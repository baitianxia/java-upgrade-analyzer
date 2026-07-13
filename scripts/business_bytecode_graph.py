#!/usr/bin/env python3
"""Build and merge current business-class bytecode evidence into the source graph."""

from __future__ import annotations

import os
import json
import re
import struct
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
                            owner = owner.replace('/', '.').replace('$', '.')
                            if owner and member:
                                edges.append({
                                    'caller_owner': class_name,
                                    'caller_name': caller_name,
                                    'caller_signature': caller_signature,
                                    'caller_descriptor': descriptor,
                                    'callee_key': f'{owner}.{member}',
                                    'callee_descriptor': _desc,
                                    'callee_simple_key': f'field:{member}',
                                    'evidence_type': 'bytecode_field_access',
                                    'line': offset,
                                    'content': f'classfile opcode 0x{opcode:02x}',
                                })
                        elif opcode in (0xb6, 0xb7, 0xb8, 0xb9) and offset + 2 < len(code):
                            cp_idx = struct.unpack_from('>H', code, offset + 1)[0]
                            owner, member, desc, _tag = _classfile_ref(cp, cp_idx)
                            owner = owner.replace('/', '.').replace('$', '.')
                            if owner and member:
                                signature = method_descriptor_signature(desc)
                                display_member = owner.rsplit('.', 1)[-1] if member == '<init>' else member
                                edges.append({
                                    'caller_owner': class_name,
                                    'caller_name': caller_name,
                                    'caller_signature': caller_signature,
                                    'caller_descriptor': descriptor,
                                    'callee_key': f'{owner}.{display_member}{signature}',
                                    'callee_descriptor': desc,
                                    'callee_simple_key': f'method:{display_member}{signature}',
                                    'evidence_type': 'bytecode_constructor_invocation' if member == '<init>' else 'bytecode_method_invocation',
                                    'line': offset,
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
                                    'content': 'classfile multianewarray',
                                })
                        next_offset = _next_instruction_offset(code, offset)
                        if next_offset <= offset:
                            return None
                        offset = next_offset
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
                owner = owner.replace('/', '.').replace('$', '.')
                signature = method_descriptor_signature(descriptor)
                display_member = owner.rsplit('.', 1)[-1] if member == '<init>' else member
                edges.append({
                    'caller_owner': pending['caller_owner'],
                    'caller_name': pending['caller_name'],
                    'caller_signature': pending['caller_signature'],
                    'caller_descriptor': pending['caller_descriptor'],
                    'callee_key': f'{owner}.{display_member}{signature}',
                    'callee_descriptor': descriptor,
                    'callee_simple_key': f'method:{display_member}{signature}',
                    'evidence_type': (
                        'bytecode_constructor_invocation'
                        if member == '<init>' else 'bytecode_invokedynamic_method_reference'
                    ),
                    'line': pending['line'],
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


def collect_business_bytecode_edges(source_roots, max_classes=10000, artifact_catalog=None, cache_path=None):
    evidence = []
    failures = []
    scanned = 0
    fast_path_classes = 0
    javap_fallback_classes = 0
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
                    data = zf.read(entry)
                    scanned += 1
                    parsed_edges = parse_classfile_calls(data, class_name)
                    if parsed_edges is None:
                        javap_fallback_classes += 1
                        stdout, stderr, rc = run_cmd(
                            ['javap', '-classpath', business_jar, '-c', '-s', '-p', '-v', class_name],
                            timeout=30,
                        )
                        if rc != 0:
                            failures.append(f'javap_failed:{class_name}:{(stderr or "")[:80]}')
                            continue
                        parsed_edges = parse_javap_calls(stdout, class_name)
                    else:
                        fast_path_classes += 1
                    for item in parsed_edges:
                        item['class_file'] = f'{business_jar}!/{entry}'
                        item['artifact_sha256'] = business_item.get('sha256', '')
                        item['evidence_source'] = 'current_final_artifact'
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
    failures.append('current_final_artifact_required')
    return [], {
        'classes_scanned': 0,
        'edges_found': 0,
        'classfile_fast_path_classes': 0,
        'javap_fallback_classes': 0,
        'failures': failures,
        'evidence_source': 'unavailable',
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
        edge.evidence_source = item.get('evidence_source', '')
        edge.artifact_sha256 = item.get('artifact_sha256', '')
        callee_key = str(edge.callee_key or '')
        edge.callee_fqcn_complete = bool(
            callee_key.startswith('class:')
            or ('.' in callee_key.split('(', 1)[0] and not callee_key.startswith(('method:', 'field:')))
        )
        edge.callee_signature_complete = bool(
            edge.evidence_type not in {
                'bytecode_method_invocation', 'bytecode_constructor_invocation',
                'bytecode_invokedynamic_method_reference',
            }
            or ('(' in callee_key and callee_key.endswith(')'))
        )
        if edge.callee_fqcn_complete and edge.callee_signature_complete:
            edge.callee_resolution_note = '调用目标已解析到全限定名和签名'
        elif not edge.callee_fqcn_complete:
            edge.callee_resolution_note = '缺少调用目标所属类全限定名'
        else:
            edge.callee_resolution_note = '缺少调用目标方法参数签名'
        for key in (edge.callee_key, edge.callee_simple_key):
            bucket = reverse_edges.setdefault(key, [])
            identity = (edge.caller_symbol_id, edge.callee_key, edge.evidence_type)
            if any((old.caller_symbol_id, old.callee_key, old.evidence_type) == identity for old in bucket):
                continue
            bucket.append(edge)
        merged += 1
    return {'merged_edges': merged, 'skipped_unresolved_callers': skipped}
