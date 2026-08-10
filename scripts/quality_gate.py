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
import tempfile

from binary_capability_migration_audit import (
    REGISTRY_PATH as CAPABILITY_MIGRATION_REGISTRY,
    audit_capability_migration,
)


QUICK_MODULES = (
    "tests.test_binary_first_contract",
    "tests.test_binary_first_model",
    "tests.test_binary_artifact_diff",
    "tests.test_binary_decision_engine",
    "tests.test_binary_runtime_reconciler",
    "tests.test_binary_trace_engine",
    "tests.test_binary_output",
    "tests.test_binary_entrypoint_discovery",
    "tests.test_binary_definition_verifier",
    "tests.test_binary_tool_execution",
    "tests.test_binary_capability_migration_audit",
)

STEP5_MODULES = QUICK_MODULES + (
    "tests.test_binary_asm_helper",
    "tests.test_binary_fact_store",
    "tests.test_binary_pipeline",
    "tests.test_binary_snapshot_cache",
    "tests.test_binary_source_overlay",
    "tests.test_binary_runtime_materializer",
    "tests.test_binary_generated_regression",
    "tests.test_binary_test_health_gate",
    "tests.test_binary_real_project_guard",
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


def test_health_command() -> list[str]:
    return [sys.executable, str(Path(__file__).with_name("binary_test_health_gate.py"))]


def real_project_command(
    audit_root: str | Path, *, cache_root: str | Path, jdk_home: str | Path,
) -> list[str]:
    root = Path(audit_root).expanduser().resolve()
    return [
        sys.executable,
        str(Path(__file__).with_name("binary_real_project_guard.py")),
        "--cache-root", str(Path(cache_root).expanduser().resolve()),
        "--output-root", str(root / "real_project"),
        "--jdk-home", str(Path(jdk_home).expanduser().resolve()),
        "--download",
    ]


def performance_command(audit_root: str | Path) -> list[str]:
    root = Path(audit_root).expanduser().resolve()
    return [
        sys.executable,
        str(Path(__file__).with_name("binary_performance_gate.py")),
        "--work-root", str(root / "performance_work"),
        "--output", str(root / "performance_result.json"),
        "--gate", str(PERFORMANCE_GATE_PATH),
    ]


def _jdk_home() -> Path:
    completed = subprocess.run(
        ["java", "-XshowSettings:properties", "-version"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False,
    )
    for line in completed.stderr.splitlines():
        if "java.home" in line and "=" in line:
            candidate = Path(line.split("=", 1)[1].strip()).resolve()
            if candidate.is_dir():
                return candidate
    raise RuntimeError("BINARY_RELEASE_JDK_HOME_UNRESOLVED")


PERFORMANCE_GATE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "binary_first" / "performance_gate.json"
)
REAL_PROJECT_MANIFEST_DIRECTORY = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "binary_first" / "real_projects"
)


def real_project_commands(
    audit_root: str | Path, *, cache_root: str | Path, jdk_home: str | Path,
) -> list[list[str]]:
    commands = []
    for manifest in sorted(REAL_PROJECT_MANIFEST_DIRECTORY.glob("*.json")):
        command = real_project_command(
            Path(audit_root) / manifest.stem,
            cache_root=cache_root,
            jdk_home=jdk_home,
        )
        command.extend(["--manifest", str(manifest)])
        commands.append(command)
    return commands


def capability_migration_status(repository_root: str | Path) -> dict:
    registry = json.loads(
        CAPABILITY_MIGRATION_REGISTRY.read_text(encoding="utf-8")
    )
    return audit_capability_migration(repository_root, registry)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Binary-first quality gate")
    parser.add_argument("--profile", choices=("quick", "step5", "release"), default="quick")
    parser.add_argument("--json-out", default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--audit-root",
        default=str(Path(tempfile.gettempdir()) / "jua-binary-release-gate"),
    )
    parser.add_argument("--real-project-cache", default="")
    parser.add_argument("--jdk-home", default="")
    args = parser.parse_args(argv)
    command = command_for(args.profile)
    audit_root = Path(args.audit_root).expanduser().resolve()
    cache_root = Path(
        args.real_project_cache or (audit_root / "real_project_cache")
    ).expanduser().resolve()
    release_commands = []
    if args.profile == "release":
        try:
            release_jdk_home = Path(args.jdk_home).expanduser().resolve() if args.jdk_home else _jdk_home()
        except (OSError, RuntimeError) as error:
            print(json.dumps({
                "schema": "java-upgrade-analyzer.binary-quality-gate.v2",
                "profile": args.profile,
                "status": "failed",
                "reason_code": "BINARY_RELEASE_JDK_HOME_UNRESOLVED",
                "detail": str(error),
            }, ensure_ascii=False))
            return 2
        release_commands = [test_health_command(), *real_project_commands(
            audit_root, cache_root=cache_root, jdk_home=release_jdk_home,
        ), performance_command(audit_root)]
    if args.dry_run:
        print(" ".join(command))
        for release_command in release_commands:
            print(" ".join(release_command))
        return 0
    started = datetime.now(timezone.utc)
    print(f"[binary-quality-gate] tests: {' '.join(command)}", flush=True)
    completed = subprocess.run(command, check=False)
    health = None
    health_returncode = 0
    real_project = None
    real_project_returncode = 0
    performance = None
    performance_returncode = 0
    if args.profile == "release":
        audit_root.mkdir(parents=True, exist_ok=True)
        print("[binary-quality-gate] test health: branch/mutation/repeat", flush=True)
        health_completed = subprocess.run(
            release_commands[0], check=False, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )
        health_returncode = health_completed.returncode
        try:
            health = json.loads(
                (health_completed.stdout or "").strip().splitlines()[-1]
            )
        except (IndexError, json.JSONDecodeError):
            health = {
                "status": "failed",
                "reason_code": "BINARY_TEST_HEALTH_OUTPUT_INVALID",
                "stderr": (health_completed.stderr or "")[-2000:],
            }
        real_project = []
        for real_command in release_commands[1:-1]:
            manifest = Path(real_command[real_command.index("--manifest") + 1])
            print(
                f"[binary-quality-gate] real project: {manifest.stem}",
                flush=True,
            )
            real_completed = subprocess.run(
                real_command, check=False, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
            )
            real_project_returncode = (
                real_project_returncode or real_completed.returncode
            )
            try:
                real_result = json.loads(
                    (real_completed.stdout or "").strip().splitlines()[-1]
                )
            except (IndexError, json.JSONDecodeError):
                real_result = {
                    "status": "failed",
                    "reason_code": "BINARY_REAL_PROJECT_OUTPUT_INVALID",
                    "manifest": str(manifest),
                    "stderr": (real_completed.stderr or "")[-2000:],
                }
            real_project.append(real_result)
        print("[binary-quality-gate] performance: 400 JAR / 100000 classes", flush=True)
        performance_completed = subprocess.run(
            release_commands[-1], check=False, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )
        performance_returncode = performance_completed.returncode
        performance_path = audit_root / "performance_result.json"
        try:
            performance = json.loads(performance_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            performance = {
                "status": "failed",
                "reason_code": "BINARY_PERFORMANCE_OUTPUT_INVALID",
                "detail": str(error),
                "stderr": (performance_completed.stderr or "")[-2000:],
            }
    migration = capability_migration_status(Path(__file__).resolve().parents[1])
    release_blocked = (
        args.profile == "release"
        and migration.get("release_status") != "passed"
    )
    returncode = (
        completed.returncode
        or health_returncode
        or real_project_returncode
        or performance_returncode
        or (3 if release_blocked else 0)
    )
    payload = {
        "schema": "java-upgrade-analyzer.binary-quality-gate.v2",
        "profile": args.profile,
        "status": "passed" if returncode == 0 else "failed",
        "returncode": returncode,
        "command": command,
        "started_at": started.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "engine": "binary_first",
        "capability_migration": migration,
        "test_health": health,
        "real_project": real_project,
        "performance": performance,
    }
    if args.json_out:
        target = Path(args.json_out).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False))
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
