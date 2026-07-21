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

from real_project_regression import CASES, validate_reproducible_asset_contract


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


def _declared_repository_root(manifest: dict) -> Path:
    checkout_root = Path(str(manifest["checkout_root"]))
    working_directory = Path(str((manifest.get("materialization") or {}).get("working_directory") or "."))
    working_parts = tuple(part for part in working_directory.parts if part not in {"", "."})
    if working_parts and tuple(checkout_root.parts[-len(working_parts):]) == working_parts:
        for _part in working_parts:
            checkout_root = checkout_root.parent
    return checkout_root


def build_declared_materialization_plan(manifest: dict) -> list[dict]:
    """Materialize a guard at the absolute locations consumed by its case contract."""
    materialization = dict(manifest.get("materialization") or {})
    checkout_root = Path(str(manifest["checkout_root"]))
    repository_root = _declared_repository_root(manifest)
    repository_url = str(materialization.get("repository_url") or "")
    if not repository_url:
        repository_url = f"https://github.com/{manifest['repository']}.git"
    plan = [{
        "operation": "git_clone",
        "argv": ["git", "clone", "--no-checkout", repository_url, str(repository_root)],
        "cwd": str(repository_root.parent),
    }]

    if materialization.get("kind") == "published_artifact":
        destination = Path(str(manifest["artifact_path"]))
        if not destination.is_absolute():
            destination = checkout_root / destination
        plan.extend([
            {
                "operation": "command",
                "argv": ["git", "checkout", "--detach", str(manifest["git_revision"])],
                "cwd": str(repository_root),
            },
            {
                "operation": "download",
                "url": str(materialization["url"]),
                "destination": str(destination),
            },
            {
                "operation": "verify",
                "path": str(destination),
                "sha1": str(materialization["sha1"]),
                "sha256": str(materialization["sha256"]),
            },
        ])
        return plan

    working_directory = Path(str(materialization["working_directory"]))
    for artifact in _source_artifacts(manifest, materialization):
        artifact_path = repository_root / working_directory / Path(str(artifact["artifact_path"]))
        plan.extend([
            {
                "operation": "command",
                "argv": ["git", "checkout", "--detach", str(artifact["revision"])],
                "cwd": str(repository_root),
            },
            {
                "operation": "command",
                "argv": list(materialization["command"]),
                "cwd": str(repository_root / working_directory),
            },
            {
                "operation": "verify",
                "path": str(artifact_path),
                "sha256": str(artifact["artifact_sha256"]),
            },
        ])
    return plan


def select_guard_manifests() -> list[Path]:
    return sorted({
        Path(case.fixture_manifest)
        for case in CASES.values()
        if case.case_mode == "guard" and case.fixture_manifest is not None
    })


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
            if step.get("sha1") and _digest(path, "sha1") != step["sha1"]:
                raise ValueError(f"artifact SHA-1 mismatch: {path}")
            if step.get("sha256") and _digest(path, "sha256") != step["sha256"]:
                raise ValueError(f"artifact SHA-256 mismatch: {path}")
        else:
            raise ValueError(f"unsupported materialization operation: {operation}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, nargs="?")
    parser.add_argument("--selector", choices=["guard"])
    parser.add_argument("--output-root", type=Path)
    parser.add_argument(
        "--declared-locations",
        action="store_true",
        help="Materialize at manifest checkout_root/artifact_path locations used by guard cases",
    )
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args(argv)
    if bool(args.manifest) == bool(args.selector):
        parser.error("provide exactly one manifest or --selector")
    if not args.declared_locations and args.output_root is None:
        parser.error("--output-root is required unless --declared-locations is used")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        manifest_paths = select_guard_manifests() if args.selector == "guard" else [args.manifest]
        plan = []
        cases = []
        for manifest_path in manifest_paths:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            errors = validate_reproducible_asset_contract(manifest)
            if errors:
                print(json.dumps({
                    "status": "invalid",
                    "manifest": str(manifest_path),
                    "errors": errors,
                }), file=sys.stderr)
                return 2
            cases.append(str(manifest.get("case") or manifest_path.stem))
            plan.extend(
                build_declared_materialization_plan(manifest)
                if args.declared_locations
                else build_materialization_plan(manifest, args.output_root)
            )
        if args.plan_only:
            print(json.dumps(plan, ensure_ascii=False, indent=2))
            return 0
        execute_materialization_plan(plan)
        print(json.dumps({
            "status": "materialized",
            "cases": cases,
            "steps": len(plan),
        }))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
