#!/usr/bin/env python3
"""Step5 call-chain lookup utility.

Default output is intentionally small: only call-chain text is printed.  The
query index is an internal Step5 artifact so users do not need to rebuild the
source/bytecode graph for every question.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from pipeline_constants import RUNTIME_DIRNAME, RUNTIME_INDEXES_DIRNAME, STEP5_QUERY_INDEX_FILE
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
    }


def build_query_index(graph, graph_stats=None):
    """Build a compact, JSON-safe reverse-call-chain query index from Step5 graph."""
    methods_by_id = getattr(graph, "methods_by_id", {}) or {}
    reverse_edges = getattr(graph, "reverse_edges", {}) or {}
    lookup_keys_by_symbol = getattr(graph, "lookup_keys_by_symbol", {}) or {}
    methods = {
        _clean(symbol_id): _method_to_record(method_def)
        for symbol_id, method_def in methods_by_id.items()
        if _clean(symbol_id)
    }
    lookup_keys = {}
    for symbol_id, method_def in methods_by_id.items():
        keys = []
        for value in lookup_keys_by_symbol.get(symbol_id) or []:
            text = _clean(value)
            if text and text not in keys:
                keys.append(text)
        for value in (
            getattr(method_def, "qualified_key", ""),
            getattr(method_def, "simple_key", ""),
            f"class:{getattr(method_def, 'class_fqcn', '')}" if getattr(method_def, "class_fqcn", "") else "",
        ):
            text = _clean(value)
            if text and text not in keys:
                keys.append(text)
        lookup_keys[_clean(symbol_id)] = keys
    indexed_reverse_edges = {}
    for key, edges in reverse_edges.items():
        clean_key = _clean(key)
        if not clean_key:
            continue
        indexed_reverse_edges[clean_key] = [_edge_to_record(edge) for edge in edges or []]
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


def build_target_keys(method):
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
    if method_name not in keys:
        keys.append(method_name)
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
    return keys


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


def query_call_chains(index, method, max_depth=5, limit=20, max_visits=50000):
    methods = index.get("methods") or {}
    lookup_keys_by_symbol = index.get("lookup_keys_by_symbol") or {}
    reverse_edges = index.get("reverse_edges") or {}
    target_keys = [key for key in build_target_keys(method) if reverse_edges.get(key)]
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
                collected.append(next_path)
                if len(collected) >= limit:
                    break
            if len(next_path) >= max_depth:
                continue
            for next_key in lookup_keys_by_symbol.get(caller_id) or []:
                if reverse_edges.get(next_key):
                    queue.append((next_key, next_path))
    return [
        _format_path(path, methods, method)
        for path in _dedupe_and_prefer_longest(collected, methods, method, limit)
    ]


def render_call_chains(chains):
    if not chains:
        return "未找到调用链。"
    lines = [f"找到 {len(chains)} 条调用链：", ""]
    for idx, chain in enumerate(chains, 1):
        lines.append(f"{idx}. {chain}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="查询 Step5 调用链索引，默认只返回调用链文本")
    parser.add_argument("--report-dir", required=True, help="升级报告根目录，或 s5_query_index.json 文件路径")
    parser.add_argument("--method", required=True, help="方法全限定名，可带签名，例如 a.b.C.m(String)")
    parser.add_argument("--max-depth", type=int, default=5)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--max-visits", type=int, default=50000, help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help="以 JSON 输出调用链列表")
    args = parser.parse_args(argv)

    index, _path = load_query_index(args.report_dir)
    chains = query_call_chains(
        index,
        args.method,
        max_depth=args.max_depth,
        limit=args.limit,
        max_visits=args.max_visits,
    )
    if args.json:
        print(json.dumps({"method": args.method, "chains": chains}, ensure_ascii=False, indent=2))
    else:
        print(render_call_chains(chains))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
