#!/usr/bin/env python3
"""Materialize SHA-pinned real-project assets from executable manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

from real_project_regression import validate_reproducible_asset_contract


def _source_artifacts(manifest: dict, materialization: dict) -> list[dict]:
    artifacts = list(materialization.get("artifacts") or [])
    if artifacts:
        return artifacts
    return [{
        "revision": manifest.get("git_revision"),
        "artifact_path": materialization.get("artifact_path"),
        "artifact_sha256": manifest.get("artifact_sha256"),
    }]


def build_materialization_plan(manifest: dict, output_root: Path) -> list[dict]:
    materialization = dict(manifest.get("materialization") or {})
    case = str(manifest.get("case") or "unnamed")
    case_root = Path(output_root) / case
    if materialization.get("kind") == "published_artifact":
        url = str(materialization["url"])
        sha256 = str(materialization["sha256"])
        destination = case_root / sha256[:16] / Path(url).name
        return [
            {
                "operation": "download",
                "url": url,
                "destination": str(destination),
            },
            {
                "operation": "verify",
                "path": str(destination),
                "sha1": str(materialization["sha1"]),
                "sha256": sha256,
            },
        ]

    checkout = case_root / ".checkout"
    working_directory = Path(str(materialization["working_directory"]))
    plan = [{
        "operation": "git_clone",
        "argv": [
            "git", "clone", "--no-checkout",
            str(materialization["repository_url"]), str(checkout),
        ],
        "cwd": str(case_root),
    }]
    for artifact in _source_artifacts(manifest, materialization):
        revision = str(artifact["revision"])
        artifact_path = Path(str(artifact["artifact_path"]))
        destination = case_root / revision / artifact_path.name
        plan.extend([
            {
                "operation": "command",
                "argv": ["git", "checkout", "--detach", revision],
                "cwd": str(checkout),
            },
            {
                "operation": "command",
                "argv": list(materialization["command"]),
                "cwd": str(checkout / working_directory),
            },
            {
                "operation": "copy_and_verify",
                "source": str(checkout / working_directory / artifact_path),
                "destination": str(destination),
                "sha256": str(artifact["artifact_sha256"]),
            },
        ])
    return plan


def _digest(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def execute_materialization_plan(plan: list[dict]) -> None:
    for step in plan:
        operation = step["operation"]
        if operation == "git_clone":
            destination = Path(step["argv"][-1])
            if destination.is_dir():
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(step["argv"], cwd=step["cwd"], check=True)
        elif operation == "command":
            subprocess.run(step["argv"], cwd=step["cwd"], check=True)
        elif operation == "download":
            destination = Path(step["destination"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_suffix(destination.suffix + ".part")
            with urllib.request.urlopen(step["url"], timeout=120) as response:
                temporary.write_bytes(response.read())
            temporary.replace(destination)
        elif operation == "copy_and_verify":
            source = Path(step["source"])
            if _digest(source, "sha256") != step["sha256"]:
                raise ValueError(f"artifact SHA-256 mismatch: {source}")
            destination = Path(step["destination"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        elif operation == "verify":
            path = Path(step["path"])
            if _digest(path, "sha1") != step["sha1"]:
                raise ValueError(f"artifact SHA-1 mismatch: {path}")
            if _digest(path, "sha256") != step["sha256"]:
                raise ValueError(f"artifact SHA-256 mismatch: {path}")
        else:
            raise ValueError(f"unsupported materialization operation: {operation}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--plan-only", action="store_true")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        errors = validate_reproducible_asset_contract(manifest)
        if errors:
            print(json.dumps({"status": "invalid", "errors": errors}), file=sys.stderr)
            return 2
        plan = build_materialization_plan(manifest, args.output_root)
        if args.plan_only:
            print(json.dumps(plan, ensure_ascii=False, indent=2))
            return 0
        execute_materialization_plan(plan)
        print(json.dumps({"status": "materialized", "steps": len(plan)}))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
