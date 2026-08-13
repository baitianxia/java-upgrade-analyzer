#!/usr/bin/env python3
"""Focused binary-first accuracy contract runner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from compat import subprocess_platform_kwargs


CATEGORIES = {
    "artifact_facts": ("tests.test_binary_artifact_diff", "tests.test_binary_asm_helper"),
    "runtime_reconciliation": ("tests.test_binary_runtime_reconciler",),
    "decision_projection": ("tests.test_binary_decision_engine", "tests.test_binary_output"),
    "result_truth": ("tests.test_binary_result_truth",),
    "runtime_bytecode_reachability": (
        "tests.test_binary_trace_engine", "tests.test_binary_pipeline",
        "tests.test_binary_generated_regression",
    ),
    "query": ("tests.test_s5_query_call_chain",),
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Binary-first accuracy benchmark")
    parser.add_argument("--category", action="append", default=[])
    parser.add_argument("--profile", choices=("core", "step5", "all"), default="core")
    parser.add_argument("--json-out", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    requested = args.category or (
        [
            "artifact_facts", "runtime_reconciliation", "decision_projection",
            "result_truth",
        ]
        if args.profile == "core"
        else list(CATEGORIES)
    )
    unknown = sorted(set(requested) - set(CATEGORIES))
    if unknown:
        parser.error("unknown categories: " + ", ".join(unknown))
    modules = []
    for category in requested:
        for module in CATEGORIES[category]:
            if module not in modules:
                modules.append(module)
    command = [sys.executable, "-m", "unittest", *modules]
    if args.dry_run:
        print(" ".join(command))
        return 0
    completed = subprocess.run(
        command, check=False, **subprocess_platform_kwargs()
    )
    payload = {
        "schema": "java-upgrade-analyzer.binary-accuracy-benchmark.v1",
        "status": "passed" if completed.returncode == 0 else "failed",
        "categories": requested,
        "modules": modules,
        "returncode": completed.returncode,
    }
    if args.json_out:
        target = Path(args.json_out).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False))
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
