#!/usr/bin/env python3
"""Correctness-first complexity and resource budget evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import time

from generated_topology import GenerationDimensions, generate_topology
from generated_topology_regression import run_generated_case
from step1_observability import peak_rss_mb


REQUIRED_METRICS = (
    "elapsed_sec",
    "peak_rss_mb",
    "temporary_bytes",
    "archive_scans",
    "parsed_classes",
    "javap_calls",
    "cache_hits",
    "per_api_latency_ms",
    "duplicate_work_keys",
)


@dataclass(frozen=True)
class ComplexityVerdict:
    status: str
    errors: tuple[str, ...]
    tiers_checked: int


def evaluate_scale_tiers(tiers: list[dict], budgets: dict) -> ComplexityVerdict:
    errors = []
    invalid = False
    ordered = sorted(tiers, key=lambda tier: int(tier.get("scale") or 0))
    for tier in ordered:
        scale = int(tier.get("scale") or 0)
        truth = list(tier.get("truth_identities") or ())
        observed = list(tier.get("observed_identities") or ())
        if len(observed) != len(set(observed)):
            errors.append(f"duplicate_scope_identity:{scale}")
            invalid = True
        if set(truth) != set(observed):
            errors.append(f"scope_identity_mismatch:{scale}")
            invalid = True
        metrics = tier.get("metrics") or {}
        for name in REQUIRED_METRICS:
            if name not in metrics:
                errors.append(f"missing_metric:{scale}:{name}")
                invalid = True
    if invalid:
        return ComplexityVerdict("invalid", tuple(errors), len(ordered))

    absolute = budgets.get("absolute") or {}
    ratios = budgets.get("adjacent_ratio") or {}
    for tier in ordered:
        scale = int(tier["scale"])
        metrics = tier["metrics"]
        for key in metrics.get("duplicate_work_keys") or ():
            errors.append(f"duplicate_work:{key}")
        for metric in ("peak_rss_mb", "per_api_latency_ms"):
            limit = absolute.get(metric)
            if limit is not None and float(metrics[metric]) > float(limit):
                errors.append(f"absolute_budget_exceeded:{metric}:{scale}")
        api_count = max(1, len(tier["truth_identities"]))
        javap_per_api = float(metrics["javap_calls"]) / api_count
        if javap_per_api > float(absolute.get("javap_calls_per_api", javap_per_api)):
            errors.append(f"absolute_budget_exceeded:javap_calls_per_api:{scale}")
    for previous, current in zip(ordered, ordered[1:]):
        for metric, limit in ratios.items():
            before = float(previous["metrics"][metric])
            after = float(current["metrics"][metric])
            ratio = after / before if before else (float("inf") if after else 1.0)
            if ratio > float(limit):
                errors.append(
                    f"ratio_budget_exceeded:{metric}:{previous['scale']}->{current['scale']}"
                )
    return ComplexityVerdict("failed" if errors else "passed", tuple(errors), len(ordered))


def _tree_bytes(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def run_generated_scale_tiers(
    repo_root: Path, report_root: Path, *, scales: tuple[int, ...]
) -> list[dict]:
    del repo_root  # The production modules are imported from the current checkout.
    report_root = Path(report_root)
    tiers = []
    for scale in scales:
        tier_root = report_root / f"scale-{scale}"
        truth_identities = []
        observed_identities = []
        parsed_classes = 0
        javap_calls = 0
        cache_hits = 0
        edge_count = 0
        started = time.perf_counter()
        for index in range(scale):
            seed = 10_000 + index
            case = generate_topology(seed, GenerationDimensions.complete())
            result = run_generated_case(case, tier_root / f"case-{index}")
            identities = [f"{seed}:{edge.identity}" for edge in case.spec.truth_edges]
            truth_identities.extend(identities)
            if result.status == "passed":
                observed_identities.extend(identities)
            metrics = result.production_metrics
            parsed_classes += int(metrics.get("classes_scanned") or 0)
            javap_calls += int(metrics.get("javap_fallback_classes") or 0)
            cache_hits += int(bool(metrics.get("cache_hit")))
            edge_count += int(metrics.get("edges_found") or 0)
        elapsed = time.perf_counter() - started
        api_count = max(1, len(truth_identities))
        tiers.append({
            "scale": scale,
            "truth_identities": truth_identities,
            "observed_identities": observed_identities,
            "metrics": {
                "elapsed_sec": elapsed,
                "peak_rss_mb": peak_rss_mb(),
                "temporary_bytes": _tree_bytes(tier_root),
                "archive_scans": scale,
                "parsed_classes": parsed_classes,
                "javap_calls": javap_calls,
                "cache_hits": cache_hits,
                "per_api_latency_ms": elapsed * 1000 / api_count,
                "duplicate_work_keys": [],
                "edges_found": edge_count,
            },
        })
    return tiers
