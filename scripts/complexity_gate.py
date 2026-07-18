#!/usr/bin/env python3
"""Correctness-first complexity and resource budget evaluation."""

from __future__ import annotations

from dataclasses import dataclass


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
