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

from pipeline_constants import RUNTIME_DIRNAME, RUNTIME_INDEXES_DIRNAME, STEP5_QUERY_INDEX_FILE
from csv_io import open_csv_read
from signature_utils import normalize_signature_for_lookup


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


def build_query_index(graph, graph_stats=None):
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
    return {
        "schema": SCHEMA,
        "methods": methods,
        "lookup_keys_by_symbol": lookup_keys,
        "reverse_edges": indexed_reverse_edges,
        "stats": {
            "methods_indexed": len(methods),
            "reverse_edge_keys": len(indexed_reverse_edges),
            **(graph_stats or {}),
        },
    }


def write_query_index(graph, output_path, graph_stats=None):
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    index = build_query_index(graph, graph_stats=graph_stats)
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
    methods = index.get("methods") or {}
    lookup_keys_by_symbol = index.get("lookup_keys_by_symbol") or {}
    reverse_edges = index.get("reverse_edges") or {}
    exact_target_keys = build_target_keys(method, fuzzy=False)
    target_prefixes = _target_match_prefixes(method)
    target_keys = [key for key in build_target_keys(method, fuzzy=fuzzy) if reverse_edges.get(key)]
    if not target_keys:
        return []
    queue = deque((key, []) for key in target_keys)
    collected = []
    visited = set()
    visits = 0
    while queue and len(collected) < limit and visits < max_visits:
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
                    fuzzy=fuzzy,
                ):
                    collected.append(next_path)
                if len(collected) >= limit:
                    break
            if len(next_path) >= max_depth:
                continue
            for next_key in _iter_next_lookup_keys(lookup_keys_by_symbol.get(caller_id), fuzzy=fuzzy):
                if reverse_edges.get(next_key):
                    queue.append((next_key, next_path))
    return [
        _format_path(path, methods, method)
        for path in _dedupe_and_prefer_longest(collected, methods, method, limit)
    ]


def query_alert_chains(report_dir_or_file, method, limit=20):
    """Fallback to Step5 alerts.csv when the graph query index has no chain.

    The query index is built from the source/graph structure.  Runtime packaged
    dependency paths can be present only in alerts.csv, especially for:
      business source -> dependency jar A -> dependency jar B -> changed API
    This fallback keeps the user-facing query useful after Step5 completes.
    """
    root = Path(report_dir_or_file)
    if root.is_file():
        root = root.parent.parent.parent if root.name == STEP5_QUERY_INDEX_FILE else root.parent
    alerts_path = root / "evidence" / "call_chain" / "alerts.csv"
    if not alerts_path.exists():
        return []

    method_name, signature = _split_method_and_signature(method)
    wanted_signature = normalize_signature_for_lookup(signature) if signature else ""
    target_prefixes = _target_match_prefixes(method)
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
            if not any(
                target in path_text or (target.endswith("(") and target[:-1] in path_text)
                for target in target_prefixes
            ):
                continue
            if path_text in seen:
                continue
            seen.add(path_text)
            chains.append(path_text)
            if len(chains) >= limit:
                break
    return chains


def query_call_chain_result(report_dir_or_file, method, max_depth=5, limit=20, max_visits=50000, *, fuzzy=False):
    """Return query chains with trust metadata for CLI and programmatic callers."""
    index, index_path = load_query_index(report_dir_or_file)
    exact_keys = build_target_keys(method, fuzzy=False)
    all_keys = build_target_keys(method, fuzzy=fuzzy)
    reverse_edges = index.get("reverse_edges") or {}
    exact_present = any(reverse_edges.get(key) for key in exact_keys)
    matched_keys = [key for key in all_keys if reverse_edges.get(key)]
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
    parser = argparse.ArgumentParser(description="查询 Step5 调用链索引，默认只返回调用链文本")
    parser.add_argument("--report-dir", required=True, help="升级报告根目录，或 s5_query_index.json 文件路径")
    parser.add_argument("--method", required=True, help="方法全限定名，可带签名，例如 a.b.C.m(String)")
    parser.add_argument("--max-depth", type=int, default=5)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--max-visits", type=int, default=50000, help=argparse.SUPPRESS)
    parser.add_argument("--fuzzy", action="store_true", help="允许简单名模糊匹配；结果仅供排查，不能作为确定影响结论")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出调用链列表")
    args = parser.parse_args(argv)

    result = query_call_chain_result(
        args.report_dir,
        args.method,
        max_depth=args.max_depth,
        limit=args.limit,
        max_visits=args.max_visits,
        fuzzy=args.fuzzy,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(render_query_result(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
