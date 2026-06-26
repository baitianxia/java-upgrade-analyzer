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
