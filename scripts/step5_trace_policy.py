#!/usr/bin/env python3
"""Pure, dependency-free path-budget policy for Step5 reverse tracing."""


def calculate_depth_cost(confidence):
    """Map an edge confidence tier to its path-budget cost."""
    if confidence == "high":
        return 1
    if confidence == "medium":
        return 2
    return 5


def update_path_frontier(frontier, *, cost, confidence):
    """Keep only non-dominated ``(cost, confidence)`` states for one symbol."""
    states = list(frontier or [])
    if any(
        old_cost <= cost and old_confidence >= confidence
        for old_cost, old_confidence in states
    ):
        return True, states
    states = [
        (old_cost, old_confidence)
        for old_cost, old_confidence in states
        if not (cost <= old_cost and confidence >= old_confidence)
    ]
    states.append((cost, confidence))
    states.sort(key=lambda item: (item[0], -item[1]))
    return False, states


def should_stop_tracing(
    current_cost,
    max_cost,
    confidence_score,
    critical_node_hit,
    last_edge_confidence="",
):
    """Return a stable stop decision and reason for one path state."""
    if current_cost >= max_cost:
        if last_edge_confidence == "low":
            return True, "LOW_CONFIDENCE_EDGE"
        return True, "DEPTH_LIMIT_REACHED"
    if confidence_score < 0.3:
        return True, "CONFIDENCE_DECAYED"
    if critical_node_hit and critical_node_hit.get("type") == "system_code_touched":
        return True, "SYSTEM_CODE_REACHED"
    if critical_node_hit and critical_node_hit.get("type") == "framework_boundary":
        return True, "FRAMEWORK_BOUNDARY"
    return False, None


def adaptive_exact_high_confidence_cost_limit(
    graph, base_limit, path, provenance_family
):
    """Relax depth only for paths composed entirely of exact high-confidence edges."""
    base_limit = max(1, int(base_limit or 1))
    if provenance_family != "exact" or not path:
        return base_limit
    if any(getattr(edge, "confidence", "") != "high" for edge in path):
        return base_limit
    edge_count = int(getattr(graph, "reverse_edge_count", 0) or 0)
    if edge_count <= 0:
        edge_count = sum(
            len(edges or [])
            for edges in (getattr(graph, "reverse_edges", {}) or {}).values()
        )
    return max(base_limit, min(20, edge_count + 1, base_limit * 3))


def calculate_confidence_decay(current_score, edge_confidence):
    """Apply the stable confidence multiplier for one traversed edge."""
    if edge_confidence == "high":
        return current_score * 0.95
    if edge_confidence == "medium":
        return current_score * 0.8
    return current_score * 0.5
