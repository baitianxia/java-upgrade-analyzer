#!/usr/bin/env python3
"""Step5 call-chain lookup utility.

Default output is intentionally small: only call-chain text is printed.  The
query index is an internal Step5 artifact so users do not need to rebuild the
source/bytecode graph for every question.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import deque
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from artifact_coordinates import split_artifact_coord
from csv_io import open_csv_read
from pipeline_constants import RUNTIME_DIRNAME, RUNTIME_INDEXES_DIRNAME, STEP5_QUERY_INDEX_FILE
from signature_utils import (
    normalize_signature_for_identity,
    normalize_signature_for_lookup,
    signatures_match_identity,
)


SCHEMA = "java-upgrade-analyzer.s5-query-index.v1"


def _clean(value):
    return str(value or "").strip()


def _method_to_record(method_def):
    return {
        "symbol_id": _clean(getattr(method_def, "symbol_id", "")),
        "qualified_key": _clean(getattr(method_def, "qualified_key", "")),
        "simple_key": _clean(getattr(method_def, "simple_key", "")),
        "class_fqcn": _clean(getattr(method_def, "class_fqcn", "")),
        "method_name": _clean(getattr(method_def, "method_name", "")),
        "declared_signature": _clean(getattr(method_def, "declared_signature", "")),
        "declared_qualified_key": _clean(getattr(method_def, "declared_qualified_key", "")),
        "owner_type": _clean(getattr(method_def, "owner_type", "")),
        "owner_coord": _clean(getattr(method_def, "owner_coord", "")),
        "module": _clean(getattr(method_def, "module", "")),
        "file": _clean(getattr(method_def, "file", "")),
        "line": int(getattr(method_def, "line", 0) or 0),
        "is_test": bool(getattr(method_def, "is_test", False)),
    }


def _edge_to_record(edge):
    return {
        "caller_symbol_id": _clean(getattr(edge, "caller_symbol_id", "")),
        "caller_qualified_key": _clean(getattr(edge, "caller_qualified_key", "")),
        "callee_key": _clean(getattr(edge, "callee_key", "")),
        "callee_simple_key": _clean(getattr(edge, "callee_simple_key", "")),
        "evidence_type": _clean(getattr(edge, "evidence_type", "")),
        "confidence": _clean(getattr(edge, "confidence", "")),
        "file": _clean(getattr(edge, "file", "")),
        "line": int(getattr(edge, "line", 0) or 0),
        "owner_type": _clean(getattr(edge, "owner_type", "")),
        "owner_coord": _clean(getattr(edge, "owner_coord", "")),
        "module": _clean(getattr(edge, "module", "")),
        "is_test": bool(getattr(edge, "is_test", False)),
        "callee_fqcn_complete": bool(getattr(edge, "callee_fqcn_complete", False)),
        "callee_signature_complete": bool(getattr(edge, "callee_signature_complete", False)),
        "callee_resolution_note": _clean(getattr(edge, "callee_resolution_note", "")),
    }


def _target_api_record(api_row):
    row = api_row or {}
    api_name = _clean(row.get("api_name") or row.get("changed_symbol"))
    api_name, embedded_signature = _split_method_and_signature(api_name)
    api_signature = _clean(row.get("api_signature")) or embedded_signature
    return {
        "coord": _clean(row.get("coord") or row.get("target_coord")),
        "api_name": api_name,
        "api_signature": api_signature,
        "symbol_kind": _clean(row.get("symbol_kind")).lower(),
    }


def _target_api_identity(record):
    signature = normalize_signature_for_identity(record.get("api_signature"))
    if not signature:
        signature = "".join(_clean(record.get("api_signature")).split())
    return (
        _clean(record.get("coord")),
        _clean(record.get("api_name")).replace("$", "."),
        signature,
        _clean(record.get("symbol_kind")).lower(),
    )


def _index_target_apis(target_apis):
    records = [
        _target_api_record(item)
        for item in target_apis or []
        if isinstance(item, dict)
    ]
    records = [item for item in records if item.get("coord") and item.get("api_name")]
    unique = {}
    for record in sorted(
        records,
        key=lambda item: (
            _target_api_identity(item),
            item.get("api_signature", ""),
        ),
    ):
        unique.setdefault(_target_api_identity(record), record)
    return sorted(
        unique.values(),
        key=lambda item: (
            item.get("coord", ""),
            item.get("api_name", ""),
            normalize_signature_for_identity(item.get("api_signature", "")),
            item.get("symbol_kind", ""),
        ),
    )


def build_query_index(graph, graph_stats=None, target_apis=None):
    """Build a compact, JSON-safe reverse-call-chain query index from Step5 graph."""
    methods_by_id = getattr(graph, "methods_by_id", {}) or {}
    reverse_edges = getattr(graph, "reverse_edges", {}) or {}
    lookup_keys_by_symbol = getattr(graph, "lookup_keys_by_symbol", {}) or {}
    methods = {
        _clean(symbol_id): _method_to_record(method_def)
        for symbol_id, method_def in sorted(
            methods_by_id.items(), key=lambda item: _clean(item[0])
        )
        if _clean(symbol_id)
    }
    lookup_keys = {}
    for symbol_id, method_def in sorted(
        methods_by_id.items(), key=lambda item: _clean(item[0])
    ):
        keys = []
        for value in lookup_keys_by_symbol.get(symbol_id) or []:
            text = _clean(value)
            if text and text not in keys:
                keys.append(text)
        for value in (
            getattr(method_def, "declared_qualified_key", ""),
            getattr(method_def, "qualified_key", ""),
            (
                f"{getattr(method_def, 'simple_key', '')}{getattr(method_def, 'declared_signature', '')}"
                if getattr(method_def, "declared_signature", "")
                else ""
            ),
            getattr(method_def, "simple_key", ""),
            f"class:{getattr(method_def, 'class_fqcn', '')}" if getattr(method_def, "class_fqcn", "") else "",
        ):
            text = _clean(value)
            if text and text not in keys:
                keys.append(text)
        lookup_keys[_clean(symbol_id)] = keys
    indexed_reverse_edges = {}
    for key, edges in sorted(
        reverse_edges.items(), key=lambda item: _clean(item[0])
    ):
        clean_key = _clean(key)
        if not clean_key:
            continue
        records = [_edge_to_record(edge) for edge in edges or []]
        indexed_reverse_edges[clean_key] = sorted(records, key=_edge_sort_key)
    indexed_target_apis = _index_target_apis(target_apis)
    return {
        "schema": SCHEMA,
        "methods": methods,
        "lookup_keys_by_symbol": lookup_keys,
        "reverse_edges": indexed_reverse_edges,
        # Optional in schema v1 so reports produced by older releases remain
        # readable. New indexes retain the authoritative Step4 -> Step5 target
        # ownership needed by dependency/package scoped queries.
        "target_apis": indexed_target_apis,
        "stats": {
            "methods_indexed": len(methods),
            "reverse_edge_keys": len(indexed_reverse_edges),
            "target_apis_indexed": len(indexed_target_apis),
            **(graph_stats or {}),
        },
    }


def write_query_index(graph, output_path, graph_stats=None, target_apis=None):
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    index = build_query_index(
        graph,
        graph_stats=graph_stats,
        target_apis=target_apis,
    )
    output.write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output


def load_query_index(report_dir_or_file):
    path = Path(report_dir_or_file)
    if path.is_dir():
        path = path / RUNTIME_DIRNAME / RUNTIME_INDEXES_DIRNAME / STEP5_QUERY_INDEX_FILE
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA:
        raise ValueError(f"不支持的查询索引格式：{path}")
    return data, path


def _split_method_and_signature(method):
    text = _clean(method)
    if "(" not in text:
        return text, ""
    prefix, suffix = text.split("(", 1)
    return prefix.strip(), "(" + suffix.strip()


def build_target_keys(method, *, fuzzy=False):
    method_name, signature = _split_method_and_signature(method)
    keys = []
    if not method_name:
        return keys
    if signature:
        for sig in [signature, normalize_signature_for_lookup(signature)]:
            if sig:
                candidate = f"{method_name}{sig}"
                if candidate not in keys:
                    keys.append(candidate)
    # A signed query must never silently fall back to an unsigned owner.method
    # key. That key mixes every overload and can make an exact Object[] query
    # return a String,Object call. Unsigned lookup remains available when the
    # user omitted a signature or explicitly requested fuzzy mode.
    if (not signature or fuzzy) and method_name not in keys:
        keys.append(method_name)
    class_key = f"class:{method_name}"
    if not signature and "." in method_name and class_key not in keys:
        keys.append(class_key)
    if not fuzzy:
        return keys
    simple_name = method_name.rsplit(".", 1)[-1]
    if simple_name and signature:
        for sig in [signature, normalize_signature_for_lookup(signature)]:
            if sig:
                candidate = f"method:{simple_name}{sig}"
                if candidate not in keys:
                    keys.append(candidate)
    simple_key = f"method:{simple_name}" if simple_name else ""
    if simple_key and simple_key not in keys:
        keys.append(simple_key)
    fuzzy_class_key = f"class:{simple_name}" if simple_name and not signature else ""
    if fuzzy_class_key and fuzzy_class_key not in keys:
        keys.append(fuzzy_class_key)
    return keys


def _target_match_prefixes(method):
    method_name, signature = _split_method_and_signature(method)
    prefixes = []
    for key in build_target_keys(method, fuzzy=False):
        if key not in prefixes:
            prefixes.append(key)
    if method_name and not signature:
        prefixes.append(f"{method_name}(")
    return tuple(prefixes)


def _path_ends_with_target(path_text, target_name, target_signature=""):
    normalized_path = _clean(path_text).replace(" -> ", " → ")
    nodes = [item.strip() for item in normalized_path.split(" → ") if item.strip()]
    if not nodes:
        return False
    node_name, node_signature = _split_method_and_signature(nodes[-1])
    wanted_name, embedded_signature = _split_method_and_signature(target_name)
    wanted_signature = _clean(target_signature) or embedded_signature
    if node_name != wanted_name and not node_name.endswith(f":{wanted_name}"):
        return False
    if wanted_signature and node_signature:
        return signatures_match_identity(wanted_signature, node_signature)
    return True


def _resolve_target_keys(index, method, *, fuzzy=False):
    """Resolve exact owner-preserving keys, including every signed overload.

    Reverse-edge indexes normally store ``owner.method(signature)``. A user
    should therefore be able to omit the signature without losing the exact
    owner/package constraint. This expansion deliberately never searches
    ``method:<simple-name>`` unless fuzzy mode was explicitly requested.
    """
    reverse_edges = index.get("reverse_edges") or {}
    method_name, signature = _split_method_and_signature(method)
    exact_keys = [
        key
        for key in build_target_keys(method, fuzzy=False)
        if reverse_edges.get(key)
    ]
    class_key = f"class:{method_name}" if method_name else ""
    if method_name and not signature and not reverse_edges.get(class_key):
        overload_prefix = f"{method_name}("
        overload_keys = []
        for key in sorted(reverse_edges):
            if key.startswith(overload_prefix) and reverse_edges.get(key) and key not in exact_keys:
                overload_keys.append(key)
        # Prefer signed keys so duplicate unsigned aggregate edges do not use
        # up the result limit before distinct overload paths are considered.
        exact_keys = overload_keys + exact_keys

    matched_keys = list(exact_keys)
    # Fuzzy is a fallback, not a union. Once owner-preserving keys exist,
    # adding simple-name keys would contaminate an otherwise exact result.
    if fuzzy and not exact_keys:
        for key in build_target_keys(method, fuzzy=True):
            if reverse_edges.get(key) and key not in matched_keys:
                matched_keys.append(key)
    return exact_keys, matched_keys


def _edge_contains_exact_target(edge, exact_target_keys, target_prefixes, *, fuzzy=False):
    if fuzzy:
        return True
    callee_key = _clean(edge.get("callee_key"))
    if not callee_key:
        return False
    if callee_key in exact_target_keys:
        return True
    return any(prefix.endswith("(") and callee_key.startswith(prefix) for prefix in target_prefixes)


def _is_precise_lookup_key(key):
    """Return True for lookup keys that keep owner/package identity.

    Query expansion must not use simple fallback keys by default.  A precise
    target match followed by ``method:use`` can still jump to an unrelated
    class that happens to have a method named ``use``.  Keep those keys only
    for explicit fuzzy mode.
    """
    text = _clean(key)
    if not text:
        return False
    if text.startswith("method:"):
        return False
    if text.startswith("class:"):
        class_name = text.split(":", 1)[1].strip()
        return "." in class_name
    return "." in text


def _iter_next_lookup_keys(lookup_keys, *, fuzzy=False):
    for key in lookup_keys or []:
        text = _clean(key)
        if not text:
            continue
        if fuzzy or _is_precise_lookup_key(text):
            yield text


def _edge_sort_key(edge):
    confidence_rank = {"high": 0, "medium": 1, "low": 2}.get(edge.get("confidence"), 9)
    owner_rank = 0 if edge.get("owner_type") == "business" else 1
    return (
        confidence_rank,
        owner_rank,
        edge.get("caller_qualified_key", ""),
        edge.get("callee_key", ""),
        edge.get("file", ""),
        int(edge.get("line") or 0),
        edge.get("owner_coord", ""),
        edge.get("module", ""),
    )


def _format_node(method):
    if not method:
        return "?"
    qualified = _clean(method.get("qualified_key"))
    coord = _clean(method.get("owner_coord"))
    owner_type = _clean(method.get("owner_type"))
    if coord and coord != "BUSINESS" and owner_type != "business":
        return f"{coord}:{qualified}"
    return qualified


def _format_path(path_edges, methods, target):
    if not path_edges:
        return _clean(target)
    nodes = []
    for edge in reversed(path_edges):
        method = methods.get(edge.get("caller_symbol_id") or "")
        node = _format_node(method) or edge.get("caller_qualified_key") or edge.get("caller_symbol_id") or "?"
        nodes.append(node)
    nodes.append(path_edges[0].get("callee_key") or _clean(target))
    return " → ".join(nodes)


def _path_parts(path_edges, methods, target):
    text = _format_path(path_edges, methods, target)
    return tuple(part.strip() for part in text.split(" → ") if part.strip())


def _dedupe_and_prefer_longest(paths, methods, target, limit):
    unique = []
    seen = set()
    for path in sorted(paths, key=lambda item: (-len(item), _format_path(item, methods, target))):
        parts = _path_parts(path, methods, target)
        if parts in seen:
            continue
        seen.add(parts)
        unique.append(path)
    filtered = []
    for path in unique:
        parts = _path_parts(path, methods, target)
        if any(len(other) > len(parts) and other[-len(parts):] == parts for other in seen):
            continue
        filtered.append(path)
    return filtered[:limit]


def query_call_chains(index, method, max_depth=5, limit=20, max_visits=50000, *, fuzzy=False):
    if limit <= 0:
        return []
    methods = index.get("methods") or {}
    lookup_keys_by_symbol = index.get("lookup_keys_by_symbol") or {}
    reverse_edges = index.get("reverse_edges") or {}
    exact_target_keys, target_keys = _resolve_target_keys(index, method, fuzzy=fuzzy)
    effective_fuzzy = bool(fuzzy and not exact_target_keys)
    target_prefixes = _target_match_prefixes(method)
    if not target_keys:
        return []
    collection_limit = limit * min(max(len(target_keys), 1), 4)
    queue = deque((key, []) for key in target_keys)
    collected = []
    visited = set()
    visits = 0
    while queue and len(collected) < collection_limit and visits < max_visits:
        current_key, path = queue.popleft()
        visits += 1
        if len(path) >= max_depth:
            continue
        path_callers = tuple(edge.get("caller_symbol_id", "") for edge in path)
        state = (current_key, path_callers)
        if state in visited:
            continue
        visited.add(state)
        for edge in sorted(reverse_edges.get(current_key) or [], key=_edge_sort_key):
            if edge.get("is_test"):
                continue
            caller_id = edge.get("caller_symbol_id") or ""
            if caller_id in path_callers:
                continue
            method_record = methods.get(caller_id)
            if not method_record or method_record.get("is_test"):
                continue
            next_path = path + [edge]
            if method_record.get("owner_type") == "business":
                if next_path and _edge_contains_exact_target(
                    next_path[0],
                    exact_target_keys,
                    target_prefixes,
                    fuzzy=effective_fuzzy,
                ):
                    collected.append(next_path)
                if len(collected) >= collection_limit:
                    break
            if len(next_path) >= max_depth:
                continue
            for next_key in _iter_next_lookup_keys(
                lookup_keys_by_symbol.get(caller_id),
                fuzzy=effective_fuzzy,
            ):
                if reverse_edges.get(next_key):
                    queue.append((next_key, next_path))
    chains = []
    chain_groups = {}
    for path in _dedupe_and_prefer_longest(
        collected,
        methods,
        method,
        collection_limit,
    ):
        _merge_chain(
            chains,
            _format_path(path, methods, method),
            limit=limit,
            groups=chain_groups,
        )
    return chains


def _alerts_path(report_dir_or_file):
    root = Path(report_dir_or_file)
    if root.is_file():
        root = root.parent.parent.parent if root.name == STEP5_QUERY_INDEX_FILE else root.parent
    return root / "evidence" / "call_chain" / "alerts.csv"


def query_alert_chains(report_dir_or_file, method, limit=20):
    """Fallback to Step5 alerts.csv when the graph query index has no chain.

    The query index is built from the source/graph structure.  Runtime packaged
    dependency paths can be present only in alerts.csv, especially for:
      business source -> dependency jar A -> dependency jar B -> changed API
    This fallback keeps the user-facing query useful after Step5 completes.
    """
    alerts_path = _alerts_path(report_dir_or_file)
    if not alerts_path.exists():
        return []

    method_name, signature = _split_method_and_signature(method)
    wanted_signature = normalize_signature_for_lookup(signature) if signature else ""
    chains = []
    seen = set()
    with open_csv_read(alerts_path) as fh:
        for row in csv.DictReader(fh):
            if _clean(row.get("path_status")) and _clean(row.get("path_status")) != "reachable":
                continue
            changed_symbol = _clean(row.get("changed_symbol"))
            row_method_name, embedded_signature = _split_method_and_signature(changed_symbol)
            if row_method_name != method_name:
                continue
            row_signature = normalize_signature_for_lookup(
                _clean(row.get("api_signature")) or embedded_signature
            )
            if wanted_signature and row_signature and row_signature != wanted_signature:
                continue
            path_text = _clean(row.get("path_text")).replace(" -> ", " → ")
            if not path_text:
                continue
            if not _path_ends_with_target(path_text, method_name, wanted_signature):
                continue
            if path_text in seen:
                continue
            seen.add(path_text)
            chains.append(path_text)
            if len(chains) >= limit:
                break
    return chains


def _coord_without_versions(value):
    text = _clean(value).split("（", 1)[0].strip()
    return text.split(" (", 1)[0].strip()


def _coord_ga(coord):
    group_id, artifact_id, _classifier = split_artifact_coord(coord)
    return f"{group_id}:{artifact_id}" if group_id and artifact_id else ""


def _coord_artifact_id(coord):
    _group_id, artifact_id, _classifier = split_artifact_coord(coord)
    return artifact_id


def _resolve_coord_query(query, available_coords):
    wanted = _clean(query)
    coords = sorted({_coord_without_versions(item) for item in available_coords if _coord_without_versions(item)})
    if not wanted:
        return [], "coord_not_found", ["依赖坐标不能为空。"]

    if wanted in coords:
        return [wanted], "coord_exact", []

    candidates = []
    if ":" in wanted:
        _group_id, _artifact_id, classifier = split_artifact_coord(wanted)
        if not classifier:
            candidates = [item for item in coords if _coord_ga(item) == wanted]
    else:
        candidates = [item for item in coords if _coord_artifact_id(item) == wanted]

    if len(candidates) == 1:
        mode = "coord_ga_unique" if ":" in wanted else "coord_artifact_unique"
        return candidates, mode, []
    if len(candidates) > 1:
        return [], "coord_ambiguous", [
            f"依赖标识 {wanted} 对应多个坐标：{', '.join(candidates)}；请使用完整物理制品坐标。"
        ]
    return [], "coord_not_found", [f"本次 Step5 分析范围内没有依赖 {wanted}。"]


def _normalize_package_prefix(value):
    prefix = _clean(value)
    if prefix.endswith(".*"):
        prefix = prefix[:-2]
    return prefix.rstrip(".")


def _api_in_package(api_name, package_prefix):
    name = _split_method_and_signature(api_name)[0].replace("$", ".")
    prefix = _normalize_package_prefix(package_prefix).replace("$", ".")
    return bool(prefix and (name == prefix or name.startswith(prefix + ".")))


def _target_api_query(record):
    api_name = _clean(record.get("api_name"))
    signature = _clean(record.get("api_signature"))
    symbol_kind = _clean(record.get("symbol_kind")).lower()
    if symbol_kind in {"method", "constructor"}:
        # A scoped target denotes one changed API, not a user-requested
        # overload family. Missing method signatures therefore stay
        # unqueryable instead of broadening to every overload.
        return f"{api_name}{signature}" if signature else ""
    if signature and not symbol_kind:
        return f"{api_name}{signature}"
    return api_name


def _chain_identity(chain):
    return "".join(_clean(chain).replace(" -> ", " → ").split())


def _chain_node_identity(node):
    name, signature = _split_method_and_signature(node)
    normalized_signature = normalize_signature_for_identity(signature)
    if signature and not normalized_signature:
        normalized_signature = "".join(signature.split())
    return "".join(name.split()), normalized_signature


def _chains_equivalent(left, right):
    left_nodes = [
        _chain_node_identity(item.strip())
        for item in _clean(left).replace(" -> ", " → ").split(" → ")
        if item.strip()
    ]
    right_nodes = [
        _chain_node_identity(item.strip())
        for item in _clean(right).replace(" -> ", " → ").split(" → ")
        if item.strip()
    ]
    if len(left_nodes) != len(right_nodes):
        return False
    for (left_name, left_signature), (right_name, right_signature) in zip(left_nodes, right_nodes):
        if left_name != right_name:
            return False
        if left_signature and right_signature and left_signature != right_signature:
            return False
    return True


def _chain_precision(chain):
    return sum(
        1
        for item in _clean(chain).replace(" -> ", " → ").split(" → ")
        if _chain_node_identity(item.strip())[1]
    )


def _chain_skeleton(chain):
    return tuple(
        _chain_node_identity(item.strip())[0]
        for item in _clean(chain).replace(" -> ", " → ").split(" → ")
        if item.strip()
    )


def _merge_chain(chains, candidate, limit=None, groups=None):
    candidate_id = _chain_identity(candidate)
    skeleton = _chain_skeleton(candidate)
    candidate_indexes = (
        groups.get(skeleton, []) if groups is not None else range(len(chains))
    )
    for index in candidate_indexes:
        existing = chains[index]
        if _chain_identity(existing) != candidate_id and not _chains_equivalent(existing, candidate):
            continue
        if _chain_precision(candidate) > _chain_precision(existing):
            chains[index] = candidate
        return False
    if limit is None or len(chains) < limit:
        chains.append(candidate)
        if groups is not None:
            groups.setdefault(skeleton, []).append(len(chains) - 1)
        return True
    return False


def _resolve_scope_targets(index, query, query_type):
    targets = [item for item in index.get("target_apis") or [] if isinstance(item, dict)]
    warnings = []
    if query_type == "coord":
        matched_coords, match_mode, warnings = _resolve_coord_query(
            query,
            [item.get("coord") for item in targets],
        )
        matched = [item for item in targets if _clean(item.get("coord")) in matched_coords]
    elif query_type == "package":
        prefix = _normalize_package_prefix(query)
        if not prefix:
            matched = []
            match_mode = "package_not_found"
            warnings = ["包前缀不能为空。"]
        else:
            matched = [item for item in targets if _api_in_package(item.get("api_name"), prefix)]
            match_mode = "package_prefix" if matched else "package_not_found"
            if not matched:
                warnings = [f"本次 Step5 分析范围内没有包前缀 {prefix} 对应的变更 API。"]
        matched_coords = sorted({_clean(item.get("coord")) for item in matched if _clean(item.get("coord"))})
    else:
        raise ValueError(f"unsupported query type: {query_type}")
    return matched, matched_coords, match_mode, warnings


def _alert_scope_rows(report_dir_or_file):
    alerts_path = _alerts_path(report_dir_or_file)
    if not alerts_path.exists():
        return []
    rows = []
    with open_csv_read(alerts_path) as fh:
        for row in csv.DictReader(fh):
            if _clean(row.get("path_status")) and _clean(row.get("path_status")) != "reachable":
                continue
            path_text = _clean(row.get("path_text")).replace(" -> ", " → ")
            if not path_text:
                continue
            normalized = dict(row)
            normalized["path_text"] = path_text
            normalized["coord"] = _coord_without_versions(row.get("target_coord"))
            api_name, embedded_signature = _split_method_and_signature(row.get("changed_symbol"))
            normalized["api_name"] = api_name
            normalized["api_signature"] = _clean(row.get("api_signature")) or embedded_signature
            if not api_name or not _path_ends_with_target(
                path_text,
                api_name,
                normalized["api_signature"],
            ):
                continue
            rows.append(normalized)
    return rows


def query_alert_chains_by_scope(report_dir_or_file, query, query_type, limit=20):
    """Query coord/package scope from alerts for indexes created before scope metadata."""
    rows = _alert_scope_rows(report_dir_or_file)
    warnings = []
    if query_type == "coord":
        matched_coords, match_mode, warnings = _resolve_coord_query(
            query,
            [row.get("coord") for row in rows],
        )
        matched = [row for row in rows if row.get("coord") in matched_coords]
    elif query_type == "package":
        prefix = _normalize_package_prefix(query)
        matched = [row for row in rows if _api_in_package(row.get("api_name"), prefix)]
        matched_coords = sorted({row.get("coord") for row in matched if row.get("coord")})
        match_mode = "package_prefix" if matched else "package_not_found"
        if not prefix:
            warnings = ["包前缀不能为空。"]
        elif not matched:
            warnings = [f"alerts.csv 中没有包前缀 {prefix} 对应的可达调用链。"]
    else:
        raise ValueError(f"unsupported query type: {query_type}")

    matched_targets = {
        (row.get("coord", ""), row.get("api_name", ""), _clean(row.get("api_signature")))
        for row in matched
    }
    all_chains = []
    chain_groups = {}
    for row in matched:
        chain = row.get("path_text", "")
        _merge_chain(all_chains, chain, groups=chain_groups)
    chains = all_chains[:max(0, limit)]
    return {
        "chains": chains,
        "_all_chains": all_chains,
        "matched_coords": matched_coords,
        "matched_target_count": len(matched_targets),
        "match_mode": match_mode,
        "warnings": warnings,
    }


def query_scope_call_chain_result(
    report_dir_or_file,
    query,
    query_type,
    max_depth=5,
    limit=20,
    max_visits=50000,
):
    """Return all reachable changed-API chains for one dependency or package."""
    index, index_path = load_query_index(report_dir_or_file)
    has_scope_metadata = "target_apis" in index
    targets, matched_coords, match_mode, warnings = _resolve_scope_targets(
        index, query, query_type,
    )

    if match_mode == "coord_ambiguous":
        return {
            "query": query,
            "query_type": query_type,
            "chains": [],
            "exact_match": False,
            "match_mode": match_mode,
            "matched_coords": [],
            "matched_target_count": 0,
            "unqueryable_target_count": 0,
            "limit_reached": False,
            "index_path": str(index_path),
            "warnings": warnings,
        }

    chains = []
    chain_groups = {}
    unqueryable_target_count = 0
    for target in targets:
        remaining = limit - len(chains)
        if remaining <= 0:
            break
        target_query = _target_api_query(target)
        if not target_query:
            unqueryable_target_count += 1
            continue
        for chain in query_call_chains(
            index,
            target_query,
            max_depth=max_depth,
            limit=remaining,
            max_visits=max_visits,
        ):
            _merge_chain(chains, chain, limit=limit, groups=chain_groups)
            if len(chains) >= limit:
                break

    # alerts.csv contains packaged-runtime paths that can be absent from the
    # compact source graph. It is also the compatibility path for old v1
    # indexes that predate target_apis.
    alert_result = query_alert_chains_by_scope(
        report_dir_or_file,
        query,
        query_type,
        limit=limit,
    )
    if not has_scope_metadata:
        targets = []
        matched_coords = alert_result["matched_coords"]
        match_mode = f"alerts_{alert_result['match_mode']}"
        warnings = alert_result["warnings"]
    if (targets or not has_scope_metadata) and match_mode != "coord_ambiguous":
        for chain in alert_result["_all_chains"]:
            _merge_chain(chains, chain, limit=limit, groups=chain_groups)

    matched_target_count = (
        len(targets) if has_scope_metadata else alert_result["matched_target_count"]
    )
    limit_reached = bool(limit > 0 and len(chains) >= limit)
    scope_warnings = []
    if unqueryable_target_count:
        scope_warnings.append(
            f"{unqueryable_target_count} 个方法/构造器目标缺少精确签名；"
            "为避免混淆重载，图索引未扩展这些目标。"
        )
    if chains:
        warnings = scope_warnings
        if limit_reached:
            warnings.append(f"结果已达 --limit={limit} 上限，可能还有更多调用链。")
    elif (
        matched_target_count
        and not warnings
        and unqueryable_target_count < matched_target_count
    ):
        warnings = [f"已匹配 {matched_target_count} 个变更 API，但没有找到可达业务调用链。"]
        warnings.extend(scope_warnings)
    elif scope_warnings and not warnings:
        warnings = scope_warnings
    return {
        "query": query,
        "query_type": query_type,
        "chains": chains,
        "exact_match": bool(chains and match_mode != "coord_ambiguous"),
        "match_mode": match_mode,
        "matched_coords": matched_coords,
        "matched_target_count": matched_target_count,
        "unqueryable_target_count": unqueryable_target_count,
        "limit_reached": limit_reached,
        "index_path": str(index_path),
        "warnings": warnings,
    }


def query_call_chain_result(report_dir_or_file, method, max_depth=5, limit=20, max_visits=50000, *, fuzzy=False):
    """Return query chains with trust metadata for CLI and programmatic callers."""
    index, index_path = load_query_index(report_dir_or_file)
    exact_keys, matched_keys = _resolve_target_keys(index, method, fuzzy=fuzzy)
    exact_present = bool(exact_keys)
    warnings = []
    chains = query_call_chains(
        index,
        method,
        max_depth=max_depth,
        limit=limit,
        max_visits=max_visits,
        fuzzy=fuzzy,
    )
    match_mode = "exact" if exact_present else "not_found"
    if not chains:
        alert_chains = query_alert_chains(report_dir_or_file, method, limit=limit)
        if alert_chains:
            chains = alert_chains
            match_mode = "alerts_exact"
    if not chains:
        if not exact_present and matched_keys and not fuzzy:
            warnings.append("未使用简单名候选结果；请使用全限定名精确查询，或显式开启 fuzzy 模式后人工核验。")
        elif not exact_present and fuzzy and matched_keys:
            warnings.append("当前结果来自 fuzzy 简单名匹配，可能包含同名类/方法误匹配，不能作为确定影响结论。")
        else:
            warnings.append("未找到精确匹配的调用链。")
    elif fuzzy and not exact_present:
        match_mode = "fuzzy"
        warnings.append("当前结果来自 fuzzy 简单名匹配，可能包含同名类/方法误匹配，不能作为确定影响结论。")
    return {
        "method": method,
        "chains": chains,
        "exact_match": bool(chains and match_mode in {"exact", "alerts_exact"}),
        "match_mode": match_mode,
        "matched_keys": matched_keys,
        "index_path": str(index_path),
        "warnings": warnings,
    }


def render_call_chains(chains):
    if not chains:
        return "未找到调用链。"
    lines = [f"找到 {len(chains)} 条调用链：", ""]
    for idx, chain in enumerate(chains, 1):
        lines.append(f"{idx}. {chain}")
    return "\n".join(lines)


def render_query_result(result):
    warnings = result.get("warnings") or []
    chains = result.get("chains") or []
    if not chains:
        return "\n".join(warnings) if warnings else "未找到精确匹配的调用链。"
    lines = [render_call_chains(chains)]
    if warnings:
        lines.extend(["", *warnings])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="按方法、依赖坐标或包前缀查询 Step5 调用链索引"
    )
    parser.add_argument("--report-dir", required=True, help="升级报告根目录，或 s5_query_index.json 文件路径")
    query_group = parser.add_mutually_exclusive_group(required=True)
    query_group.add_argument(
        "--method",
        help="方法全限定名，可带签名；省略签名时查询该全限定方法的全部重载",
    )
    query_group.add_argument(
        "--coord",
        help="依赖完整坐标或唯一 artifactId，例如 commons-lang:commons-lang 或 commons-lang",
    )
    query_group.add_argument(
        "--package",
        dest="package_prefix",
        help="Java 包前缀，例如 org.apache.commons.lang",
    )
    parser.add_argument("--max-depth", type=int, default=5)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--max-visits", type=int, default=50000, help=argparse.SUPPRESS)
    parser.add_argument("--fuzzy", action="store_true", help="允许简单名模糊匹配；结果仅供排查，不能作为确定影响结论")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出调用链列表")
    args = parser.parse_args(argv)

    if args.fuzzy and not args.method:
        parser.error("--fuzzy 只能与 --method 一起使用")
    if args.method:
        result = query_call_chain_result(
            args.report_dir,
            args.method,
            max_depth=args.max_depth,
            limit=args.limit,
            max_visits=args.max_visits,
            fuzzy=args.fuzzy,
        )
    else:
        query_type = "coord" if args.coord else "package"
        query = args.coord or args.package_prefix
        result = query_scope_call_chain_result(
            args.report_dir,
            query,
            query_type,
            max_depth=args.max_depth,
            limit=args.limit,
            max_visits=args.max_visits,
        )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(render_query_result(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
