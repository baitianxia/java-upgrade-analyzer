#!/usr/bin/env python3
"""Stable in-memory graph contract shared by Step5 builders and tracers."""

from dataclasses import dataclass


@dataclass
class SourceGraph:
    methods_by_id: dict
    methods_by_qualified: dict
    methods_by_simple: dict
    reverse_edges: dict
    reverse_edge_count: int
    lookup_keys_by_symbol: dict
    type_metadata: dict
