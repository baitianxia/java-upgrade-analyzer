#!/usr/bin/env python3
"""Deterministic generated topology contracts for binary-first regression."""

from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Iterable

from binary_first_contract import canonical_identity


@dataclass(frozen=True)
class GeneratedTopology:
    seed: int
    node_count: int
    edges: tuple[tuple[int, int], ...]
    changed_nodes: tuple[int, ...]
    entry_nodes: tuple[int, ...]
    identity: str

    def reachable_nodes(self) -> frozenset[int]:
        adjacency: dict[int, set[int]] = {}
        for caller, target in self.edges:
            adjacency.setdefault(caller, set()).add(target)
        reached = set(self.entry_nodes)
        pending = list(self.entry_nodes)
        while pending:
            caller = pending.pop()
            for target in adjacency.get(caller, ()):
                if target not in reached:
                    reached.add(target)
                    pending.append(target)
        return frozenset(reached)


def generate_topology(seed: int, *, node_count: int = 16) -> GeneratedTopology:
    if node_count < 6:
        raise ValueError("generated topology requires at least six nodes")
    rng = random.Random(int(seed))
    # A forward-only graph is deterministic and compileable without recursive
    # initialization. The last node is deliberately isolated so every seed has
    # both a positive and a negative changed target.
    edges = {(0, 1), (1, 2), (2, 3)}
    for caller in range(node_count - 2):
        candidates = list(range(caller + 1, node_count - 1))
        rng.shuffle(candidates)
        for target in candidates[: rng.randint(0, min(3, len(candidates)))]:
            edges.add((caller, target))
    payload = {
        "seed": int(seed),
        "node_count": node_count,
        "edges": sorted([list(item) for item in edges]),
        "changed_nodes": [3, node_count - 1],
        "entry_nodes": [0],
        "generator_policy_version": "binary-generated-dag-v1",
    }
    return GeneratedTopology(
        seed=int(seed),
        node_count=node_count,
        edges=tuple(sorted(edges)),
        changed_nodes=(3, node_count - 1),
        entry_nodes=(0,),
        identity=canonical_identity(
            "binary_generated_topology_identity", payload, schema_version="1"
        ),
    )


def java_sources(
    topology: GeneratedTopology, *, current: bool,
    include_unrelated: bool = False,
) -> dict[str, str]:
    outgoing: dict[int, list[int]] = {}
    for caller, target in topology.edges:
        outgoing.setdefault(caller, []).append(target)
    result = {}
    for node in range(topology.node_count):
        value = node + (
            1000 if current and node in topology.changed_nodes else 0
        )
        terms = [str(value)] + [
            f"N{target:03d}.call()" for target in sorted(outgoing.get(node, ()))
        ]
        result[f"generated/N{node:03d}.java"] = (
            f"package generated; public final class N{node:03d} {{ "
            f"public static int call() {{ return {' + '.join(terms)}; }} }}"
        )
    if include_unrelated:
        result["generated/Unrelated.java"] = (
            "package generated; public final class Unrelated { "
            "public static String value() { return \"unrelated\"; } }"
        )
    return result


def expected_changed_reachability(
    topology: GeneratedTopology,
) -> dict[str, str]:
    reached = topology.reachable_nodes()
    return {
        f"generated/N{node:03d}": (
            "reachable" if node in reached else "not_found_in_static_analysis"
        )
        for node in topology.changed_nodes
    }


def topology_matrix(seeds: Iterable[int]) -> tuple[GeneratedTopology, ...]:
    return tuple(generate_topology(seed) for seed in seeds)


__all__ = [
    "GeneratedTopology", "expected_changed_reachability", "generate_topology",
    "java_sources", "topology_matrix",
]
