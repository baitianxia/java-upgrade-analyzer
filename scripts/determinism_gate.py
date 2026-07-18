#!/usr/bin/env python3
"""Run semantic analysis under process-level determinism variants."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys

from metamorphic_regression import semantic_digest


@dataclass(frozen=True)
class DeterminismReport:
    status: str
    run_count: int
    first_difference: dict
    reproduction_command: tuple[str, ...]
    runs: tuple[dict, ...]


def _first_difference(left, right, path=""):
    if type(left) is not type(right):
        return {"path": path, "baseline": left, "candidate": right}
    if isinstance(left, dict):
        for key in sorted(set(left) | set(right)):
            child = f"{path}.{key}" if path else key
            if key not in left or key not in right:
                return {"path": child, "baseline": left.get(key), "candidate": right.get(key)}
            difference = _first_difference(left[key], right[key], child)
            if difference:
                return difference
    elif isinstance(left, list):
        if len(left) != len(right):
            return {"path": path, "baseline": len(left), "candidate": len(right)}
        for index, (first, second) in enumerate(zip(left, right)):
            difference = _first_difference(first, second, f"{path}[{index}]")
            if difference:
                return difference
    elif left != right:
        return {"path": path, "baseline": left, "candidate": right}
    return {}


def compare_semantic_runs(runs: list[dict]) -> DeterminismReport:
    if not runs:
        return DeterminismReport("failed", 0, {"path": "runs", "candidate": []}, (), ())
    baseline = runs[0]["ledger"]
    baseline_digest = semantic_digest(baseline)
    for run in runs[1:]:
        if semantic_digest(run["ledger"]) != baseline_digest:
            difference = _first_difference(baseline, run["ledger"])
            return DeterminismReport(
                "failed", len(runs), difference, tuple(run["command"]), tuple(runs)
            )
    return DeterminismReport("passed", len(runs), {}, (), tuple(runs))


def run_generated_determinism_matrix(
    repo_root: Path,
    *,
    seed: int,
    report_root: Path,
    hash_seeds: tuple[int, ...],
    workers: tuple[int, ...],
    cache_modes: tuple[str, ...],
    order_modes: tuple[str, ...],
) -> DeterminismReport:
    repo_root = Path(repo_root)
    report_root = Path(report_root)
    runs = []
    index = 0
    for hash_seed in hash_seeds:
        for worker_count in workers:
            for cache_mode in cache_modes:
                for order_mode in order_modes:
                    index += 1
                    run_root = report_root / f"run-{index:03d}"
                    output = run_root / "result.json"
                    command = [
                        sys.executable,
                        "scripts/generated_topology_regression.py",
                        "--seed", str(seed),
                        "--report-root", str(run_root),
                        "--json-out", str(output),
                        "--workers", str(worker_count),
                        "--cache-mode", cache_mode,
                        "--order-mode", order_mode,
                    ]
                    env = dict(os.environ)
                    env["PYTHONHASHSEED"] = str(hash_seed)
                    completed = subprocess.run(
                        command, cwd=str(repo_root), env=env,
                        capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=60,
                    )
                    if completed.returncode != 0 or not output.is_file():
                        ledger = {"apis": [], "edges": [], "completeness": {"process_error": completed.stderr}, "reason_codes": ["PROCESS_FAILED"]}
                    else:
                        ledger = json.loads(output.read_text(encoding="utf-8"))["semantic_ledger"]
                    runs.append({
                        "variant": {"hash_seed": hash_seed, "workers": worker_count, "cache_mode": cache_mode, "order_mode": order_mode},
                        "command": command,
                        "ledger": ledger,
                    })
    return compare_semantic_runs(runs)
