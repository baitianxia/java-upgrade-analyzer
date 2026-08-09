#!/usr/bin/env python3
"""Run the binary-first quality profiles.

The previous gate catalog was coupled to the removed source-first Step4–6
engine.  Profiles now select only current production contracts; release uses
normal unittest discovery so a newly added test cannot silently miss the gate.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys


QUICK_MODULES = (
    "tests.test_binary_first_contract",
    "tests.test_binary_first_model",
    "tests.test_binary_artifact_diff",
    "tests.test_binary_decision_engine",
    "tests.test_binary_runtime_reconciler",
    "tests.test_binary_trace_engine",
    "tests.test_binary_output",
)

STEP5_MODULES = QUICK_MODULES + (
    "tests.test_binary_asm_helper",
    "tests.test_binary_fact_store",
    "tests.test_binary_pipeline",
    "tests.test_binary_snapshot_cache",
    "tests.test_binary_source_overlay",
    "tests.test_s5_query_call_chain",
    "tests.test_run_step_main_state",
    "tests.test_claude_skill_contract",
    "tests.test_user_visible_output_contract",
)


def command_for(profile: str) -> list[str]:
    if profile == "quick":
        return [sys.executable, "-m", "unittest", *QUICK_MODULES]
    if profile == "step5":
        return [sys.executable, "-m", "unittest", *STEP5_MODULES]
    return [sys.executable, "-m", "unittest", "discover", "-s", "tests"]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Binary-first quality gate")
    parser.add_argument("--profile", choices=("quick", "step5", "release"), default="quick")
    parser.add_argument("--json-out", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    command = command_for(args.profile)
    if args.dry_run:
        print(" ".join(command))
        return 0
    started = datetime.now(timezone.utc)
    completed = subprocess.run(command, check=False)
    payload = {
        "schema": "java-upgrade-analyzer.binary-quality-gate.v1",
        "profile": args.profile,
        "status": "passed" if completed.returncode == 0 else "failed",
        "returncode": completed.returncode,
        "command": command,
        "started_at": started.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "engine": "binary_first",
    }
    if args.json_out:
        target = Path(args.json_out).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False))
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
