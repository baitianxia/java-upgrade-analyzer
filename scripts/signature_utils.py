#!/usr/bin/env python3

"""Shared helpers for method signature parsing and normalization."""


def split_signature_params(signature):
    signature = (signature or '').strip()
    if not (signature.startswith('(') and signature.endswith(')')):
        return None
    body = signature[1:-1].strip()
    if not body:
        return []

    params = []
    current = []
    generic_depth = 0
    for ch in body:
        if ch == '<':
            generic_depth += 1
            current.append(ch)
            continue
        if ch == '>':
            if generic_depth <= 0:
                return None
            generic_depth -= 1
            current.append(ch)
            continue
        if ch == ',' and generic_depth == 0:
            param = ''.join(current).strip()
            if not param:
                return None
            params.append(param)
            current = []
            continue
        current.append(ch)

    if generic_depth != 0:
        return None

    last = ''.join(current).strip()
    if not last:
        return None
    params.append(last)
    return params


def normalize_signature_for_lookup(signature):
    signature = (signature or '').strip()
    if not (signature.startswith('(') and signature.endswith(')')):
        return ''
    params = split_signature_params(signature)
    if params is None:
        return ''
    if not params:
        return '()'

    normalized = []
    for param in params:
        type_name = param.strip()
        if not type_name:
            return ''
        type_name = type_name.replace('...', '[]')
        if '<' in type_name:
            type_name = type_name.split('<', 1)[0].strip()
        if '.' in type_name:
            type_name = type_name.rsplit('.', 1)[-1]
        normalized.append(type_name)
    return '(' + ', '.join(normalized) + ')'


def normalize_signature_for_identity(signature):
    """Normalize a signature without discarding qualified type identity."""
    params = split_signature_params((signature or '').strip())
    if params is None:
        return ''
    normalized = []
    for param in params:
        type_name = param.strip().replace('...', '[]').replace('$', '.')
        erased = []
        generic_depth = 0
        for char in type_name:
            if char == '<':
                generic_depth += 1
                continue
            if char == '>':
                generic_depth -= 1
                continue
            if generic_depth == 0 and not char.isspace():
                erased.append(char)
        normalized.append(''.join(erased))
    return '(' + ','.join(normalized) + ')'


def signatures_match_identity(left, right):
    """Match qualified signatures, allowing only missing leading qualification."""
    left_normalized = normalize_signature_for_identity(left)
    right_normalized = normalize_signature_for_identity(right)
    if not left_normalized or not right_normalized:
        return False
    left_params = split_signature_params(left_normalized)
    right_params = split_signature_params(right_normalized)
    if left_params is None or right_params is None or len(left_params) != len(right_params):
        return False
    return all(
        left_param == right_param
        or left_param.endswith('.' + right_param)
        or right_param.endswith('.' + left_param)
        for left_param, right_param in zip(left_params, right_params)
    )


def _canonical_constructor_name(api_name):
    value = str(api_name or '').strip().replace('$', '.')
    if value.endswith('.<init>'):
        return value
    possible_owner, separator, repeated_name = value.rpartition('.')
    owner_simple_name = possible_owner.rpartition('.')[2]
    if separator and repeated_name == owner_simple_name:
        return possible_owner + '.<init>'
    return value + '.<init>' if value else ''


def canonical_api_identity_tuple(row):
    """Return the one API identity shared by analyzer and Oracle producers."""
    row = row or {}
    coord = str(row.get('coord') or '').strip()
    kind = str(row.get('symbol_kind') or '').strip().lower()
    api_name = str(row.get('api_name') or row.get('api') or '').strip()
    api_name = api_name.replace('$', '.')
    if kind == 'constructor':
        api_name = _canonical_constructor_name(api_name)
    raw_signature = str(row.get('api_signature') or '').strip()
    signature = normalize_signature_for_identity(raw_signature)
    if raw_signature and not signature:
        signature = ''.join(raw_signature.replace('$', '.').split())
    change_type = str(row.get('change_type') or '').strip().upper()
    return coord, api_name, signature, kind, change_type


def canonical_api_identity(row):
    return '|'.join(canonical_api_identity_tuple(row))
