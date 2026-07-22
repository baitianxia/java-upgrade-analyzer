#!/usr/bin/env python3
"""Materialize revision-pinned source builds or SHA-pinned published artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import urllib.request
import urllib.error
import zipfile
from pathlib import Path

from compat import resolve_command

from real_project_regression import (
    CASES,
    GUARD_SELECTORS,
    artifact_verification_mode,
    select_case_names,
    validate_reproducible_asset_contract,
)


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
        copy_step = {
            "operation": (
                "copy_and_verify"
                if artifact_verification_mode(manifest) == "sha256"
                else "copy_artifact"
            ),
            "source": str(checkout / working_directory / artifact_path),
            "destination": str(destination),
        }
        if artifact_verification_mode(manifest) == "sha256":
            copy_step["sha256"] = str(artifact["artifact_sha256"])
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
            copy_step,
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
        verify_step = {
            "operation": (
                "verify"
                if artifact_verification_mode(manifest) == "sha256"
                else "verify_artifact"
            ),
            "path": str(artifact_path),
        }
        if artifact_verification_mode(manifest) == "sha256":
            verify_step["sha256"] = str(artifact["artifact_sha256"])
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
            verify_step,
        ])
    return plan


def select_guard_manifests(selector: str = "guard") -> list[Path]:
    return sorted({
        Path(CASES[name].fixture_manifest) for name in select_case_names(selector)
    })


def _digest(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_artifact(path: Path) -> None:
    if not path.is_file():
        raise ValueError(f"artifact missing: {path}")
    try:
        with zipfile.ZipFile(path) as archive:
            if not any(name.endswith(".class") for name in archive.namelist()):
                raise ValueError(f"artifact has no class files: {path}")
    except zipfile.BadZipFile as error:
        raise ValueError(f"artifact is not a valid ZIP: {path}") from error


def _download(url: str, destination: Path) -> None:
    temporary = destination.with_suffix(destination.suffix + ".part")
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            temporary.write_bytes(response.read())
    except urllib.error.URLError:
        curl = shutil.which("curl")
        if not curl:
            raise
        subprocess.run([
            curl, "--fail", "--location", "--silent", "--show-error",
            "--output", str(temporary), url,
        ], check=True)
    temporary.replace(destination)


def execute_materialization_plan(plan: list[dict]) -> list[dict]:
    artifacts = []
    for step in plan:
        operation = step["operation"]
        if operation == "git_clone":
            destination = Path(step["argv"][-1])
            if destination.is_dir():
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(resolve_command(step["argv"]), cwd=step["cwd"], check=True)
        elif operation == "command":
            subprocess.run(resolve_command(step["argv"]), cwd=step["cwd"], check=True)
        elif operation == "download":
            destination = Path(step["destination"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            _download(step["url"], destination)
        elif operation in {"copy_and_verify", "copy_artifact"}:
            source = Path(step["source"])
            _validate_artifact(source)
            if step.get("sha256") and _digest(source, "sha256") != step["sha256"]:
                raise ValueError(f"artifact SHA-256 mismatch: {source}")
            destination = Path(step["destination"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            artifacts.append({
                "path": str(destination),
                "sha256": _digest(destination, "sha256"),
                "verification": "sha256" if step.get("sha256") else "runtime",
            })
        elif operation in {"verify", "verify_artifact"}:
            path = Path(step["path"])
            _validate_artifact(path)
            if step.get("sha1") and _digest(path, "sha1") != step["sha1"]:
                raise ValueError(f"artifact SHA-1 mismatch: {path}")
            if step.get("sha256") and _digest(path, "sha256") != step["sha256"]:
                raise ValueError(f"artifact SHA-256 mismatch: {path}")
            artifacts.append({
                "path": str(path),
                "sha256": _digest(path, "sha256"),
                "verification": "sha256" if step.get("sha256") else "runtime",
            })
        else:
            raise ValueError(f"unsupported materialization operation: {operation}")
    return artifacts


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, nargs="?")
    parser.add_argument("--selector", choices=list(GUARD_SELECTORS))
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
        manifest_paths = select_guard_manifests(args.selector) if args.selector else [args.manifest]
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
        artifacts = execute_materialization_plan(plan)
        print(json.dumps({
            "status": "materialized",
            "cases": cases,
            "steps": len(plan),
            "artifacts": artifacts,
        }))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
