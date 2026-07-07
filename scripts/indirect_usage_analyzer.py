#!/usr/bin/env python3
"""Target-driven Step5 analyzers for reflection, MethodHandle and resources."""

from __future__ import annotations

import re
import time
from pathlib import Path

from enhanced_source_analyzer import CallEdge
from signature_utils import normalize_signature_for_lookup, split_signature_params


RESOURCE_SUFFIXES = {'.xml', '.properties', '.yml', '.yaml', '.json', '.conf', '.txt'}
REFLECTION_MEMBER_PATTERN = re.compile(r'\.get(?:Declared)?(?:Method|Field|Constructor)\s*\(')
OWNER_SIMPLE_TOKEN_PATTERN_CACHE = {}
SOURCE_INDIRECT_MARKERS = (
    'Class.forName',
    'getMethod',
    'getDeclaredMethod',
    'getField',
    'getDeclaredField',
    'getConstructor',
    'getDeclaredConstructor',
    'MethodHandles',
)
EXPRESSION_MARKERS = ('T(', '#{', '${', '@')


def _descriptor_signature(descriptor):
    primitives = {'B': 'byte', 'C': 'char', 'D': 'double', 'F': 'float', 'I': 'int',
                  'J': 'long', 'S': 'short', 'Z': 'boolean'}
    if not str(descriptor or '').startswith('('):
        return ''
    params, index = [], 1
    while index < len(descriptor) and descriptor[index] != ')':
        arrays = 0
        while descriptor[index:index + 1] == '[':
            arrays += 1
            index += 1
        if descriptor[index:index + 1] == 'L':
            end = descriptor.find(';', index)
            if end < 0:
                return ''
            value = descriptor[index + 1:end].replace('/', '.').replace('$', '.')
            index = end + 1
        else:
            value = primitives.get(descriptor[index:index + 1], '')
            index += 1
        if not value:
            return ''
        params.append(_simple_type(value + '[]' * arrays))
    return '(' + ', '.join(params) + ')'


def parse_javap_indirect_references(text, class_binary_name=''):
    """Recover exact reflection calls from common javac bytecode sequences."""
    header_re = re.compile(
        r'^\s*(?:[\w.$<>\[\],?]+\s+)+([\w$<>.]+)\([^;]*\)'
        r'(?:\s+throws\s+[^;]+)?;\s*$'
    )
    instruction_re = re.compile(r'^\s*(\d+):\s+(.*)$')
    methods = []
    current = None
    class_simple = str(class_binary_name or '').rsplit('.', 1)[-1]
    for raw in (text or '').splitlines():
        header = header_re.match(raw)
        if header:
            name = header.group(1).rsplit('.', 1)[-1]
            current = {'name': '<init>' if name == class_simple else name, 'signature': '', 'instructions': []}
            methods.append(current)
            continue
        if re.match(r'^\s*static\s+\{\};\s*$', raw):
            current = {'name': '<clinit>', 'signature': '', 'instructions': []}
            methods.append(current)
            continue
        if current is None:
            continue
        line = raw.strip()
        if line.startswith('descriptor:'):
            current['signature'] = _descriptor_signature(line.split(':', 1)[1].strip())
            continue
        instruction = instruction_re.match(raw)
        if instruction:
            current['instructions'].append((int(instruction.group(1)), instruction.group(2).strip()))

    result = []
    for method in methods:
        strings = []
        locals_by_slot = {}
        produced = None
        active_class = None
        active_member = None

        def local_slot(instruction, opcode):
            match = re.match(rf'{opcode}(?:_(\d+)|\s+(\d+))\b', instruction)
            if not match:
                return None
            return int(match.group(1) or match.group(2))

        for offset, insn in method['instructions']:
            string_match = re.search(r'\bldc(?:_w)?\b.*//\s+String\s+(.+)$', insn)
            if string_match:
                strings.append((offset, string_match.group(1).strip()))
            load_slot = local_slot(insn, 'aload')
            if load_slot is not None and load_slot in locals_by_slot:
                loaded = locals_by_slot[load_slot]
                produced = loaded
                if loaded.get('kind') == 'class_value':
                    active_class = loaded
                elif loaded.get('kind') in {'method', 'field', 'constructor'}:
                    active_member = loaded
            if re.search(r'//\s+Method\s+java/lang/Class\.forName:', insn):
                if strings:
                    owner_offset, owner = strings[-1]
                    owner = owner.replace('/', '.').replace('$', '.')
                    active_class = {'kind': 'class_value', 'owner': owner, 'offset': owner_offset}
                    produced = active_class
                    result.append({
                        'owner': owner, 'name': '', 'signature': '', 'kind': 'class',
                        'consumer_method': method['name'], 'consumer_signature': method['signature'],
                        'reference_kind': 'reflection_class', 'line': owner_offset,
                    })
                continue
            lookup = re.search(
                r'//\s+Method\s+java/lang/Class\.get(Declared)?(Method|Field|Constructor):', insn
            )
            if lookup and active_class:
                owner = active_class['owner']
                owner_offset = active_class['offset']
                lookup_kind = lookup.group(2)
                recent_strings = [item for item in strings if item[0] > owner_offset and item[0] < offset]
                member = recent_strings[-1][1] if recent_strings and lookup_kind != 'Constructor' else owner.rsplit('.', 1)[-1]
                member_offset = recent_strings[-1][0] if recent_strings else owner_offset
                class_params = []
                expected_param_count = None
                pending_count = None
                for param_offset, param in method['instructions']:
                    if not (member_offset < param_offset < offset):
                        continue
                    count_match = re.search(r'\biconst_(\d)\b', param)
                    if count_match:
                        pending_count = int(count_match.group(1))
                    if re.search(r'\banewarray\b.*//\s+class\s+java/lang/Class', param):
                        expected_param_count = pending_count
                    class_match = re.search(r'\bldc(?:_w)?\b.*//\s+class\s+([A-Za-z0-9_/$]+)', param)
                    if class_match:
                        value = class_match.group(1).replace('/', '.').replace('$', '.')
                        if value != 'java.lang.Class':
                            class_params.append(value)
                active_member = {
                    'owner': owner, 'name': member,
                    'signature': '(' + ', '.join(_simple_type(value) for value in class_params) + ')' if lookup_kind in {'Method', 'Constructor'} else '',
                    'signature_resolved': (
                        lookup_kind not in {'Method', 'Constructor'}
                        or expected_param_count == len(class_params)
                    ),
                    'kind': lookup_kind.lower(), 'offset': offset,
                }
                produced = active_member
                continue
            invocation = re.search(
                r'//\s+Method\s+java/lang/reflect/(Method|Field|Constructor)\.'
                r'(invoke|get|set|newInstance):', insn
            )
            if invocation and active_member:
                expected = invocation.group(1).lower()
                if active_member['kind'] == expected:
                    result.append({
                        **active_member,
                        'consumer_method': method['name'],
                        'consumer_signature': method['signature'],
                        'reference_kind': f'reflection_{active_member["kind"]}',
                        'line': offset,
                    })
                active_member = None
                produced = None
                continue
            store_slot = local_slot(insn, 'astore')
            if store_slot is not None and produced:
                locals_by_slot[store_slot] = dict(produced)
                produced = None
    return result


def _symbol_kind(row):
    kind = str(row.get('symbol_kind') or '').strip().lower()
    return kind if kind in {'class', 'method', 'constructor', 'field'} else ''


def _target(row):
    api_name = str(row.get('api_name') or '').strip()
    kind = _symbol_kind(row)
    if not api_name or not kind:
        return None
    if kind == 'class':
        owner, member = api_name, ''
    elif '.' in api_name:
        owner, member = api_name.rsplit('.', 1)
    else:
        return None
    signature = normalize_signature_for_lookup(str(row.get('api_signature') or '').strip())
    params = tuple(_simple_type(item) for item in split_signature_params(signature)) if signature else ()
    return {
        'row': row, 'kind': kind, 'owner': owner.replace('$', '.'), 'member': member,
        'signature': signature, 'params': params,
        'api_key': _api_key(row),
        'callee_key': api_name + (signature if kind in {'method', 'constructor'} else ''),
    }


def _api_key(row):
    return '|'.join(str(row.get(key) or '').strip() for key in (
        'coord', 'api_name', 'api_signature', 'symbol_kind', 'change_type'
    ))


def _simple_type(value):
    text = str(value or '').strip().replace('$', '.')
    text = re.sub(r'<.*>', '', text).replace('...', '[]')
    return text.rsplit('.', 1)[-1]


def _literal_or_var(token, string_vars):
    value = str(token or '').strip()
    match = re.fullmatch(r'"((?:\\.|[^"\\])*)"', value, re.S)
    if match:
        return bytes(match.group(1), 'utf-8').decode('unicode_escape')
    return string_vars.get(value, '')


def _split_args(raw):
    text = str(raw or '').strip()
    if not text:
        return []
    result = []
    current = []
    depth = 0
    in_string = False
    escape = False
    for ch in text:
        if in_string:
            current.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            current.append(ch)
            continue
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth = max(0, depth - 1)
        if ch == ',' and depth == 0:
            result.append(''.join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = ''.join(current).strip()
    if tail:
        result.append(tail)
    return result


def _class_params(raw):
    raw = str(raw or '').strip()
    if not raw:
        return ()
    result = []
    for part in _split_args(raw):
        token = part.strip()
        match = re.search(r'([A-Za-z_$][\w.$]*(?:\[\])?)\s*\.\s*class\b', token)
        if match:
            result.append(_simple_type(match.group(1)))
            continue
        match = re.search(r'([A-Za-z_$][\w.$]*)\s*\.\s*TYPE\b', token)
        if match:
            result.append(_simple_type(match.group(1)))
            continue
        return None
    return tuple(result)


def _method_type_params(raw):
    parts = _split_args(raw)
    if not parts:
        return ()
    if parts[0].startswith('MethodType.methodType'):
        nested = re.search(r'MethodType\s*\.\s*methodType\s*\((.*)\)\s*$', parts[0], re.S)
        if nested:
            parts = _split_args(nested.group(1))
    if not parts:
        return ()
    # First slot is the return type for MethodType.methodType(...).
    return _class_params(', '.join(parts[1:]))


def _line_for_offset(method, body, offset):
    return int(getattr(method, 'line', 0) or 0) + body[:max(0, offset)].count('\n')


def _resolve_source_owner(value, method):
    text = str(value or '').strip().replace('$', '.')
    if not text or '.' in text:
        return text
    imports = getattr(method, 'imports', {}) or {}
    if text in imports:
        return str(imports[text]).replace('$', '.')
    package_name = str(getattr(method, 'package_name', '') or '').strip()
    return f'{package_name}.{text}' if package_name else text


def _edge_for_target(method, target, evidence_type, body, offset, content):
    member = target['member']
    signature = target['signature'] if target['kind'] in {'method', 'constructor'} else ''
    simple_key = (
        f"class:{target['owner']}" if target['kind'] == 'class'
        else f"{'field' if target['kind'] == 'field' else 'method'}:{member}{signature}"
    )
    return CallEdge(
        caller_symbol_id=method.symbol_id,
        caller_qualified_key=method.qualified_key,
        callee_key=target['callee_key'] if target['kind'] != 'class' else f"class:{target['owner']}",
        callee_simple_key=simple_key,
        evidence_type=evidence_type,
        confidence='high',
        file=method.file,
        line=_line_for_offset(method, body, offset),
        content=str(content or '')[:160],
        owner_type=method.owner_type,
        owner_coord=method.owner_coord,
        module=method.module,
        is_test=method.is_test,
        callee_param_types=list(target['params']),
    )


def _matches_target(target, owner, member='', params=None, kind=None):
    if target['owner'] != str(owner or '').replace('$', '.'):
        return False
    if kind and target['kind'] != kind:
        return False
    if target['kind'] == 'class':
        return True
    if target['member'] != member:
        return False
    if target['kind'] in {'method', 'constructor'} and target['signature']:
        return params is not None and tuple(target['params']) == tuple(params)
    return True


def _expression_matches_target(text, target):
    owner = str(target.get('owner') or '')
    member = str(target.get('member') or '')
    if not owner:
        return False
    if re.search(r'(?:#\{|\$\{)[^}]*T\(\s*' + re.escape(owner) + r'\s*\)', text, re.S):
        if not member:
            return True
        if re.search(
            r'(?:#\{|\$\{)[^}]*T\(\s*' + re.escape(owner) + r'\s*\)\s*\.\s*' + re.escape(member) + r'\b',
            text,
            re.S,
        ):
            return True
    if re.search(r'T\(\s*' + re.escape(owner) + r'\s*\)', text):
        if not member:
            return True
        if re.search(
            r'T\(\s*' + re.escape(owner) + r'\s*\)\s*\.\s*' + re.escape(member) + r'\b',
            text,
        ):
            return True
    if not member:
        return False
    return bool(re.search(r'@' + re.escape(owner) + r'@' + re.escape(member) + r'\b', text))


def _source_candidates(method):
    body = method.get_body_text()
    if not any(marker in body for marker in SOURCE_INDIRECT_MARKERS):
        return body, [], []
    string_vars = {
        match.group(1): match.group(2)
        for match in re.finditer(
            r'\bString\s+([A-Za-z_$]\w*)\s*=\s*"((?:\\.|[^"\\])*)"\s*;', body
        )
    }
    class_vars = {}
    lookup_vars = set()
    handle_vars = {}
    candidates = []
    unresolved = []

    class_expr = r'(?:"(?:\\.|[^"\\])*"|[A-Za-z_$]\w*)'
    for match in re.finditer(
        r'\b(?:MethodHandles\.Lookup|var)\s+([A-Za-z_$]\w*)\s*=\s*MethodHandles\s*\.\s*lookup\s*\(\s*\)',
        body,
    ):
        lookup_vars.add(match.group(1))
    for match in re.finditer(
        rf'\bClass(?:\s*<[^;=]+>)?\s+([A-Za-z_$]\w*)\s*=\s*Class\.forName\s*\(\s*({class_expr})\s*\)',
        body, re.S,
    ):
        owner = _literal_or_var(match.group(2), string_vars)
        if owner:
            class_vars[match.group(1)] = owner.replace('$', '.')
        else:
            unresolved.append({'owner': '', 'member': '', 'reason_code': 'REFLECTION_TARGET_DYNAMIC', 'offset': match.start()})
    for match in re.finditer(
        r'\bClass(?:\s*<[^;=]+>)?\s+([A-Za-z_$]\w*)\s*=\s*([A-Za-z_$][\w.$]*)\s*\.\s*class\b',
        body,
    ):
            class_vars[match.group(1)] = _resolve_source_owner(match.group(2), method)

    method_vars = {}
    member_expr = r'(?:"(?:\\.|[^"\\])*"|[A-Za-z_$]\w*)'
    for match in re.finditer(
        rf'\bMethod\s+([A-Za-z_$]\w*)\s*=\s*([A-Za-z_$]\w*)\s*\.\s*get(Declared)?Method\s*\(\s*({member_expr})\s*(?:,\s*([^;]*?))?\)\s*;',
        body, re.S,
    ):
        owner = class_vars.get(match.group(2), '')
        member = _literal_or_var(match.group(4), string_vars)
        params = _class_params(match.group(5) or '')
        method_vars[match.group(1)] = (owner, member, params, match.start(), match.group(0))
    for var, (owner, member, params, offset, content) in method_vars.items():
        if not re.search(rf'\b{re.escape(var)}\s*\.\s*invoke\s*\(', body[offset:]):
            continue
        if owner and member and params is not None:
            candidates.append(('method', owner, member, params, offset, content, 'reflection_method_invocation'))
        elif owner:
            unresolved.append({'owner': owner, 'member': member, 'reason_code': 'REFLECTION_OVERLOAD_UNRESOLVED', 'offset': offset})

    chain_pattern = re.compile(
        rf'Class\.forName\s*\(\s*({class_expr})\s*\)\s*\.\s*get(Declared)?Method\s*'
        rf'\(\s*({member_expr})\s*(?:,\s*([^)]*?))?\)\s*\.\s*invoke\s*\(', re.S,
    )
    for match in chain_pattern.finditer(body):
        owner = _literal_or_var(match.group(1), string_vars)
        member = _literal_or_var(match.group(3), string_vars)
        params = _class_params(match.group(4) or '')
        if owner and member and params is not None:
            candidates.append(('method', owner, member, params, match.start(), match.group(0), 'reflection_method_invocation'))
        elif owner:
            unresolved.append({'owner': owner, 'member': member, 'reason_code': 'REFLECTION_OVERLOAD_UNRESOLVED', 'offset': match.start()})

    for match in re.finditer(
        r'\bConstructor(?:\s*<[^;=]+>)?\s+([A-Za-z_$]\w*)\s*=\s*([A-Za-z_$]\w*)\s*\.\s*'
        r'get(Declared)?Constructor\s*\(\s*([^;]*?)\)\s*;', body, re.S,
    ):
        owner = class_vars.get(match.group(2), '')
        params = _class_params(match.group(4) or '')
        if not re.search(rf'\b{re.escape(match.group(1))}\s*\.\s*newInstance\s*\(', body[match.start():]):
            continue
        if owner and params is not None:
            candidates.append((
                'constructor', owner, owner.rsplit('.', 1)[-1], params,
                match.start(), match.group(0), 'reflection_constructor_invocation',
            ))
        elif owner:
            unresolved.append({'owner': owner, 'member': owner.rsplit('.', 1)[-1], 'reason_code': 'REFLECTION_OVERLOAD_UNRESOLVED', 'offset': match.start()})

    for match in re.finditer(
        rf'\bField\s+([A-Za-z_$]\w*)\s*=\s*([A-Za-z_$]\w*)\s*\.\s*get(Declared)?Field\s*'
        rf'\(\s*({member_expr})\s*\)\s*;', body, re.S,
    ):
        owner = class_vars.get(match.group(2), '')
        member = _literal_or_var(match.group(4), string_vars)
        if not re.search(rf'\b{re.escape(match.group(1))}\s*\.\s*(?:get|set)\s*\(', body[match.start():]):
            continue
        if owner and member:
            candidates.append(('field', owner, member, (), match.start(), match.group(0), 'reflection_field_access'))
        elif owner:
            unresolved.append({'owner': owner, 'member': member, 'reason_code': 'REFLECTION_TARGET_DYNAMIC', 'offset': match.start()})

    for match in re.finditer(
        rf'Class\.forName\s*\(\s*({class_expr})\s*\)\s*\.\s*get(Declared)?Constructor\s*'
        r'\(\s*([^)]*?)\)\s*\.\s*newInstance\s*\(', body, re.S,
    ):
        owner = _literal_or_var(match.group(1), string_vars)
        params = _class_params(match.group(3) or '')
        if owner and params is not None:
            candidates.append((
                'constructor', owner, owner.rsplit('.', 1)[-1], params,
                match.start(), match.group(0), 'reflection_constructor_invocation',
            ))
        elif owner:
            unresolved.append({'owner': owner, 'member': owner.rsplit('.', 1)[-1], 'reason_code': 'REFLECTION_OVERLOAD_UNRESOLVED', 'offset': match.start()})

    for match in re.finditer(
        rf'Class\.forName\s*\(\s*({class_expr})\s*\)\s*\.\s*get(Declared)?Field\s*'
        rf'\(\s*({member_expr})\s*\)\s*\.\s*(?:get|set)\s*\(', body, re.S,
    ):
        owner = _literal_or_var(match.group(1), string_vars)
        member = _literal_or_var(match.group(3), string_vars)
        if owner and member:
            candidates.append(('field', owner, member, (), match.start(), match.group(0), 'reflection_field_access'))
        elif owner:
            unresolved.append({'owner': owner, 'member': member, 'reason_code': 'REFLECTION_TARGET_DYNAMIC', 'offset': match.start()})

    for match in re.finditer(r'Class\.forName\s*\(\s*(' + class_expr + r')\s*\)', body, re.S):
        owner = _literal_or_var(match.group(1), string_vars)
        if owner:
            candidates.append(('class', owner, '', (), match.start(), match.group(0), 'reflection_class_lookup'))

    lookup_expr = r'(?:MethodHandles\s*\.\s*lookup\s*\(\s*\)|[A-Za-z_$]\w*)'
    for match in re.finditer(
        rf'\b(?:MethodHandle|var)\s+([A-Za-z_$]\w*)\s*=\s*({lookup_expr})\s*'
        r'\.\s*find(Static|Virtual|Special|Constructor)\s*\('
        r'\s*([A-Za-z_$][\w.$]*)\s*\.\s*class\s*,\s*'
        r'(?:"([^"]+)"\s*,\s*)?MethodType\s*\.\s*methodType\s*\(\s*([^;]*?)\)\s*'
        r'(?:,\s*[A-Za-z_$][\w.$]*\s*\.\s*class\s*)?\)\s*;',
        body,
        re.S,
    ):
        lookup_value = match.group(2).strip()
        if lookup_value != 'MethodHandles.lookup()' and lookup_value not in lookup_vars:
            continue
        owner = _resolve_source_owner(match.group(4), method)
        method_kind = match.group(3)
        member = owner.rsplit('.', 1)[-1] if method_kind == 'Constructor' else (match.group(5) or '')
        params = _method_type_params(match.group(6) or '')
        evidence_type = 'method_handle_invocation'
        target_kind = 'constructor' if method_kind == 'Constructor' else 'method'
        handle_vars[match.group(1)] = (
            target_kind, owner, member, params,
            match.start(), match.group(0), evidence_type,
        )
    for match in re.finditer(
        rf'\b(?:MethodHandle|var)\s+([A-Za-z_$]\w*)\s*=\s*({lookup_expr})\s*'
        r'\.\s*find(Static)?(Getter|Setter)\s*\('
        r'\s*([A-Za-z_$][\w.$]*)\s*\.\s*class\s*,\s*"([^"]+)"\s*,\s*([^)]+?)\s*\)\s*;',
        body,
        re.S,
    ):
        lookup_value = match.group(2).strip()
        if lookup_value != 'MethodHandles.lookup()' and lookup_value not in lookup_vars:
            continue
        owner = _resolve_source_owner(match.group(5), method)
        member = match.group(6)
        handle_vars[match.group(1)] = (
            'field', owner, member, (),
            match.start(), match.group(0), 'method_handle_field_access',
        )
    for var, (kind, owner, member, params, offset, content, evidence_type) in handle_vars.items():
        if not re.search(rf'\b{re.escape(var)}\s*\.\s*invoke(?:Exact|WithArguments)?\s*\(', body[offset:]):
            continue
        candidates.append((kind, owner, member, params, offset, content, evidence_type))

    for match in re.finditer(
        r'MethodHandles\s*\.\s*lookup\s*\(\s*\)\s*\.\s*find(Static|Virtual|Special)\s*\('
        r'\s*([A-Za-z_$][\w.$]*)\s*\.\s*class\s*,\s*"([^"]+)"\s*,\s*'
        r'MethodType\s*\.\s*methodType\s*\(\s*[A-Za-z_$][\w.$]*\s*\.\s*class\s*'
        r'(?:,\s*([^)]*?))?\)\s*(?:,\s*[A-Za-z_$][\w.$]*\s*\.\s*class\s*)?\)', body, re.S,
    ):
        params = _class_params(match.group(4) or '')
        tail = body[match.end():]
        if params is not None and re.match(r'\s*\.\s*invoke(?:Exact|WithArguments)?\s*\(', tail):
            candidates.append(('method', _resolve_source_owner(match.group(2), method), match.group(3), params, match.start(), match.group(0), 'method_handle_invocation'))
    for match in re.finditer(
        r'MethodHandles\s*\.\s*lookup\s*\(\s*\)\s*\.\s*findConstructor\s*\('
        r'\s*([A-Za-z_$][\w.$]*)\s*\.\s*class\s*,\s*MethodType\s*\.\s*methodType\s*\(\s*([^)]*?)\)\s*\)',
        body,
        re.S,
    ):
        params = _method_type_params(match.group(2) or '')
        tail = body[match.end():]
        if params is not None and re.match(r'\s*\.\s*invoke(?:Exact|WithArguments)?\s*\(', tail):
            owner = _resolve_source_owner(match.group(1), method)
            candidates.append((
                'constructor', owner, owner.rsplit('.', 1)[-1], params,
                match.start(), match.group(0), 'method_handle_invocation',
            ))
    for match in re.finditer(
        r'MethodHandles\s*\.\s*lookup\s*\(\s*\)\s*\.\s*find(Static)?(Getter|Setter)\s*\('
        r'\s*([A-Za-z_$][\w.$]*)\s*\.\s*class\s*,\s*"([^"]+)"\s*,\s*([^)]+?)\s*\)',
        body,
        re.S,
    ):
        tail = body[match.end():]
        if re.match(r'\s*\.\s*invoke(?:Exact|WithArguments)?\s*\(', tail):
            candidates.append((
                'field',
                _resolve_source_owner(match.group(3), method),
                match.group(4),
                (),
                match.start(),
                match.group(0),
                'method_handle_field_access',
            ))

    return body, candidates, unresolved


def _resource_roots(source_roots):
    seen = set()
    for item in source_roots or []:
        root = Path(str((item or {}).get('root') or item))
        normalized = root.as_posix()
        candidates = []
        for marker in ('/src/main/java', '/src/main/kotlin', '/src/main/groovy'):
            if normalized.endswith(marker):
                candidates.append(Path(normalized[:-len(marker)] + '/src/main/resources'))
        for candidate in candidates:
            if candidate.is_dir() and candidate.resolve() not in seen:
                seen.add(candidate.resolve())
                yield candidate.resolve()


def _owner_simple_token_pattern(owner_simple):
    cached = OWNER_SIMPLE_TOKEN_PATTERN_CACHE.get(owner_simple)
    if cached is None:
        cached = re.compile(r'(?<![\w$])' + re.escape(owner_simple) + r'(?![\w$])')
        OWNER_SIMPLE_TOKEN_PATTERN_CACHE[owner_simple] = cached
    return cached


def _owners_present_in_source_body(body, method, owners, owners_by_simple):
    """Return target owners whose names are plausibly present in one source method body.

    This intentionally preserves the old matching semantics but applies them at owner
    granularity instead of target/API granularity. A removed jar can easily export
    thousands of APIs that belong to a much smaller set of classes, so scanning by
    owner prevents Step5 indirect analysis from degenerating into methods × APIs.
    """
    if not body or not owners:
        return []
    present = set()
    for owner in owners:
        if owner in body or owner.replace('.', '/') in body:
            present.add(owner)
    imports = getattr(method, 'imports', {}) or {}
    if imports:
        for simple, imported in imports.items():
            imported_owner = str(imported or '').replace('$', '.')
            if imported_owner not in owners:
                continue
            if _owner_simple_token_pattern(simple).search(body):
                present.add(imported_owner)
    else:
        for simple, simple_owners in owners_by_simple.items():
            if len(simple_owners) != 1:
                continue
            if _owner_simple_token_pattern(simple).search(body):
                owner = simple_owners[0]
                if owner in body or owner.replace('.', '/') in body:
                    present.add(owner)
    return [owner for owner in owners if owner in present]


def analyze_and_merge_indirect_usages(graph, api_rows, source_roots):
    started_at = time.perf_counter()
    targets = [item for item in (_target(row) for row in api_rows or []) if item]
    by_owner = {}
    for target in targets:
        by_owner.setdefault(target['owner'], []).append(target)
    owners = list(by_owner.keys())
    owners_by_simple = {}
    for owner in owners:
        owners_by_simple.setdefault(owner.rsplit('.', 1)[-1], []).append(owner)
    findings = {target['api_key']: [] for target in targets}
    unresolved_by_api = {target['api_key']: [] for target in targets}
    coverage_by_api = {
        target['api_key']: {
            'reflection_source': 'not_applicable',
            'method_handle_source': 'not_applicable',
            'resource_reference': 'not_applicable',
            'expression_language': 'not_applicable',
            'reflection_bytecode': 'not_applicable',
        }
        for target in targets
    }
    merged_edges = 0
    source_methods = 0
    owner_presence_scans = 0
    source_methods_with_indirect_markers = 0

    for method in (getattr(graph, 'methods_by_id', {}) or {}).values():
        source_methods += 1
        body, candidates, unresolved = _source_candidates(method)
        has_reflection_source = 'Class.forName' in body or bool(REFLECTION_MEMBER_PATTERN.search(body))
        has_method_handle_source = 'MethodHandles' in body
        has_expression_markers = any(marker in body for marker in EXPRESSION_MARKERS)
        present_owners = []
        if has_reflection_source or has_method_handle_source:
            source_methods_with_indirect_markers += 1
        if has_reflection_source or has_method_handle_source or has_expression_markers:
            owner_presence_scans += 1
            present_owners = _owners_present_in_source_body(body, method, owners, owners_by_simple)
        if has_reflection_source or has_method_handle_source:
            for owner in present_owners:
                for target in by_owner.get(owner, []):
                    if has_reflection_source:
                        coverage_by_api[target['api_key']]['reflection_source'] = 'partial'
                    if has_method_handle_source:
                        coverage_by_api[target['api_key']]['method_handle_source'] = 'partial'
        for kind, owner, member, params, offset, content, evidence_type in candidates:
            for target in by_owner.get(owner.replace('$', '.'), []):
                if not _matches_target(target, owner, member, params, kind=kind):
                    continue
                edge = _edge_for_target(method, target, evidence_type, body, offset, content)
                for key in (edge.callee_key, edge.callee_simple_key):
                    bucket = graph.reverse_edges.setdefault(key, [])
                    identity = (edge.caller_symbol_id, edge.callee_key, edge.evidence_type, edge.line)
                    if not any((old.caller_symbol_id, old.callee_key, old.evidence_type, old.line) == identity for old in bucket):
                        bucket.append(edge)
                merged_edges += 1
        for item in unresolved:
            owner = item.get('owner') or ''
            if not owner:
                continue
            for target in by_owner.get(owner.replace('$', '.'), []):
                if item.get('member') and item.get('member') != target['member']:
                    continue
                unresolved_by_api[target['api_key']].append({
                    'evidence_type': 'reflection_unresolved',
                    'reason_code': item.get('reason_code') or 'REFLECTION_TARGET_DYNAMIC',
                    'file': method.file,
                    'line': _line_for_offset(method, body, item.get('offset') or 0),
                    'caller_symbol': method.qualified_key,
                    'owner_coord': method.owner_coord,
                })
        if not has_expression_markers:
            continue
        for owner in present_owners:
            owner_targets = by_owner.get(owner, [])
            for target in owner_targets:
                if not _expression_matches_target(body, target):
                    continue
                findings[target['api_key']].append({
                    'evidence_type': 'expression_target_reference',
                    'reason_code': 'EXPRESSION_TARGET_REFERENCE',
                    'file': method.file,
                    'line': _line_for_offset(method, body, 0),
                    'caller_symbol': method.qualified_key,
                    'owner_coord': method.owner_coord,
                })
                coverage_by_api[target['api_key']]['expression_language'] = 'partial'

    resource_files = 0
    expression_findings = 0
    resource_errors = 0
    resource_roots = list(_resource_roots(source_roots))
    for root in resource_roots:
        for path in root.rglob('*'):
            if not path.is_file() or path.suffix.lower() not in RESOURCE_SUFFIXES:
                continue
            resource_files += 1
            try:
                text = path.read_text(encoding='utf-8', errors='replace')
            except OSError:
                resource_errors += 1
                continue
            for owner, owner_targets in by_owner.items():
                if owner not in text and owner.replace('.', '/') not in text:
                    continue
                for target in owner_targets:
                    member = target['member']
                    expression_matched = _expression_matches_target(text, target)
                    if member and not expression_matched and not re.search(r'(?<![\w$])' + re.escape(member) + r'(?![\w$])', text):
                        continue
                    findings[target['api_key']].append({
                        'evidence_type': 'expression_target_reference' if expression_matched else 'resource_target_reference',
                        'reason_code': 'EXPRESSION_TARGET_REFERENCE' if expression_matched else 'RESOURCE_TARGET_REFERENCE',
                        'file': str(path), 'line': 0,
                        'caller_symbol': f'resource:{path.name}', 'owner_coord': '',
                    })
                    if expression_matched:
                        expression_findings += 1
                        coverage_by_api[target['api_key']]['expression_language'] = 'partial'

    if resource_roots:
        resource_status = 'partial' if resource_errors else 'complete'
        for target in targets:
            coverage_by_api[target['api_key']]['resource_reference'] = resource_status

    for target in targets:
        target_keys = {target['callee_key']}
        if target['kind'] == 'class':
            target_keys.add(f"class:{target['owner']}")
        for key in target_keys:
            for edge in (getattr(graph, 'reverse_edges', {}) or {}).get(key, []):
                if str(getattr(edge, 'evidence_type', '') or '').startswith('bytecode_reflection_'):
                    coverage_by_api[target['api_key']]['reflection_bytecode'] = 'partial'

    def aggregate_status(values, *, empty='not_applicable'):
        statuses = list(values)
        if not statuses:
            return empty
        if 'insufficient' in statuses:
            return 'insufficient'
        if 'partial' in statuses:
            return 'partial'
        if 'complete' in statuses:
            return 'complete'
        return 'not_applicable'

    per_api_coverage = {}
    for target in targets:
        target_matrix = coverage_by_api[target['api_key']]
        status = aggregate_status(target_matrix.values(), empty='complete')
        reason_codes = [
            f'{name}_partial'
            for name, analyzer_status in target_matrix.items()
            if analyzer_status == 'partial'
        ]
        per_api_coverage[target['api_key']] = {
            'status': status,
            'reason_codes': reason_codes,
            'matrix': dict(target_matrix),
        }

    matrix = {}
    for symbol_kind in ('class', 'method', 'constructor', 'field'):
        kind_targets = [target for target in targets if target['kind'] == symbol_kind]
        matrix[symbol_kind] = {
            analyzer: aggregate_status(
                coverage_by_api[target['api_key']][analyzer] for target in kind_targets
            )
            for analyzer in (
                'reflection_source', 'method_handle_source', 'resource_reference',
                'expression_language', 'reflection_bytecode',
            )
        }
    analyzer_statuses = {
        analyzer: aggregate_status(
            coverage_by_api[target['api_key']][analyzer] for target in targets
        )
        for analyzer in (
            'reflection_source', 'method_handle_source', 'resource_reference',
            'expression_language', 'reflection_bytecode',
        )
    }
    overall_status = aggregate_status(
        (item['status'] for item in per_api_coverage.values()),
        empty='complete',
    )
    graph.indirect_usage_findings = findings
    graph.indirect_usage_unresolved = unresolved_by_api
    graph.indirect_analysis_coverage = {
        'status': overall_status,
        'reason_codes': sorted({
            reason
            for item in per_api_coverage.values()
            for reason in item.get('reason_codes') or []
        }),
        'source_methods_scanned': source_methods,
        'resource_files_scanned': resource_files,
        'merged_edges': merged_edges,
        'resource_findings': sum(len(items) for items in findings.values()),
        'expression_findings': expression_findings,
        'unresolved_findings': sum(len(items) for items in unresolved_by_api.values()),
        'elapsed_sec': round(time.perf_counter() - started_at, 3),
        'target_count': len(targets),
        'owner_count': len(owners),
        'potential_legacy_method_target_pairs': source_methods * len(targets),
        'owner_presence_scans': owner_presence_scans,
        'source_methods_with_indirect_markers': source_methods_with_indirect_markers,
        'analyzers': analyzer_statuses,
        'matrix': matrix,
        'by_api': per_api_coverage,
    }
    return dict(graph.indirect_analysis_coverage)


def api_key(row):
    return _api_key(row)
