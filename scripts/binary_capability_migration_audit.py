#!/usr/bin/env python3
"""Validate and report legacy-to-binary capability migration coverage."""

from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping


REGISTRY_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "binary_first" / "capability_migration.json"
)


def _baseline_deleted_paths(
    root: Path,
    baseline: str,
    pathspecs: tuple[str, ...],
) -> tuple[set[str], str]:
    """Return paths deleted from the fixed main baseline through the worktree.

    This is deliberately computed from Git instead of trusting the registry's
    own list.  Otherwise deleting a legacy production path and its registry row
    in the same change would make the audit pass.
    """
    try:
        completed = subprocess.run(
            [
                "git", "diff", "--diff-filter=D", "--name-only",
                baseline, "--", *pathspecs,
            ],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as error:
        return set(), f"git_start_failed:{type(error).__name__}"
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "git_diff_failed").strip()
        return set(), detail[:500]
    return {
        line.strip()
        for line in completed.stdout.splitlines()
        if line.strip()
    }, ""


def _load_test(reference: str) -> str:
    parts = str(reference or "").split(".")
    if len(parts) < 4 or parts[0] != "tests":
        return "invalid_test_reference"
    module = ".".join(parts[:2])
    try:
        value: Any = importlib.import_module(module)
        for part in parts[2:]:
            value = getattr(value, part)
    except (ImportError, AttributeError) as error:
        return f"unloadable_test_reference:{type(error).__name__}"
    return "" if callable(value) else "test_reference_not_callable"


def audit_capability_migration(
    repository_root: str | Path,
    registry: Mapping[str, Any],
) -> dict[str, Any]:
    root = Path(repository_root).resolve()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    issues = []
    allowed_statuses = set(registry.get("status_vocabulary") or ())
    baseline = set(
        (registry.get("baseline") or {}).get("legacy_capability_family_ids") or ()
    )
    baseline_config = registry.get("baseline") or {}
    baseline_commit = str(baseline_config.get("merge_base") or "")
    monitored_deleted_production = set(
        baseline_config.get("monitored_deleted_production_paths") or ()
    )
    actual_deleted_production, production_diff_error = _baseline_deleted_paths(
        root, baseline_commit, ("scripts/*.py",)
    )
    if production_diff_error:
        issues.append({
            "reason_code": "CAPABILITY_BASELINE_DIFF_UNAVAILABLE",
            "scope": "production",
            "detail": production_diff_error,
        })
    elif monitored_deleted_production != actual_deleted_production:
        issues.append({
            "reason_code": "CAPABILITY_DELETED_PRODUCTION_PATH_SET_MISMATCH",
            "missing_from_registry": sorted(
                actual_deleted_production - monitored_deleted_production
            ),
            "not_deleted_from_baseline": sorted(
                monitored_deleted_production - actual_deleted_production
            ),
        })

    monitored_deleted_assets = set(
        baseline_config.get("monitored_deleted_test_asset_paths") or ()
    )
    actual_deleted_assets, asset_diff_error = _baseline_deleted_paths(
        root,
        baseline_commit,
        (
            "tests/fixtures/real_projects/*.json",
            "tests/fixtures/topologies/*.json",
            "tests/fixtures/generated_topologies/*.json",
        ),
    )
    if asset_diff_error:
        issues.append({
            "reason_code": "CAPABILITY_BASELINE_DIFF_UNAVAILABLE",
            "scope": "test_assets",
            "detail": asset_diff_error,
        })
    elif monitored_deleted_assets != actual_deleted_assets:
        issues.append({
            "reason_code": "CAPABILITY_DELETED_TEST_ASSET_SET_MISMATCH",
            "missing_from_registry": sorted(
                actual_deleted_assets - monitored_deleted_assets
            ),
            "not_deleted_from_baseline": sorted(
                monitored_deleted_assets - actual_deleted_assets
            ),
        })
    families = list(registry.get("families") or ())
    family_ids = [str(item.get("family_id") or "") for item in families]
    if len(family_ids) != len(set(family_ids)):
        issues.append({"reason_code": "CAPABILITY_FAMILY_DUPLICATE"})
    if set(family_ids) != baseline:
        issues.append({
            "reason_code": "CAPABILITY_BASELINE_SET_MISMATCH",
            "missing": sorted(baseline - set(family_ids)),
            "extra": sorted(set(family_ids) - baseline),
        })

    mechanism_ids = []
    for record_kind, records, identity_key in (
        ("family", families, "family_id"),
        ("mechanism", registry.get("mechanism_inventory") or (), "mechanism_id"),
    ):
        for item in records:
            identity = str(item.get(identity_key) or "")
            if record_kind == "mechanism":
                mechanism_ids.append(identity)
            status = str(item.get("migration_status") or "")
            if not identity:
                issues.append({
                    "reason_code": "CAPABILITY_IDENTITY_MISSING",
                    "record_kind": record_kind,
                })
            if status not in allowed_statuses:
                issues.append({
                    "reason_code": "CAPABILITY_STATUS_INVALID",
                    "identity": identity,
                    "status": status,
                })
            gaps = list(item.get("blocking_gaps") or ())
            if status == "enforced" and gaps:
                issues.append({
                    "reason_code": "ENFORCED_CAPABILITY_HAS_BLOCKING_GAPS",
                    "identity": identity,
                })
            if status in {"partial", "missing"} and not gaps:
                issues.append({
                    "reason_code": "INCOMPLETE_CAPABILITY_GAP_UNDECLARED",
                    "identity": identity,
                })
            production_paths = list(item.get("production_paths") or ())
            for relative in production_paths:
                if not (root / str(relative)).is_file():
                    issues.append({
                        "reason_code": "CAPABILITY_PRODUCTION_PATH_MISSING",
                        "identity": identity,
                        "path": relative,
                    })
            test_fields = (
                ("evidence_tests",) if record_kind == "mechanism"
                else ("positive_tests", "negative_tests", "independent_tests")
            )
            test_count = 0
            for field in test_fields:
                for reference in item.get(field) or ():
                    test_count += 1
                    failure = _load_test(str(reference))
                    if failure:
                        issues.append({
                            "reason_code": "CAPABILITY_TEST_REFERENCE_INVALID",
                            "identity": identity,
                            "field": field,
                            "reference": reference,
                            "detail": failure,
                        })
            if status == "enforced" and test_count == 0:
                issues.append({
                    "reason_code": "ENFORCED_CAPABILITY_TESTS_MISSING",
                    "identity": identity,
                })
    if len(mechanism_ids) != len(set(mechanism_ids)):
        issues.append({"reason_code": "CAPABILITY_MECHANISM_DUPLICATE"})
    expected_mechanisms = set(
        baseline_config.get("monitored_mechanism_ids") or ()
    )
    if set(mechanism_ids) != expected_mechanisms:
        issues.append({
            "reason_code": "CAPABILITY_MECHANISM_SET_MISMATCH",
            "missing": sorted(expected_mechanisms - set(mechanism_ids)),
            "extra": sorted(set(mechanism_ids) - expected_mechanisms),
        })

    incomplete_families = sorted(
        item["family_id"] for item in families
        if item.get("migration_status") != "enforced"
    )
    missing_mechanisms = sorted(
        item["mechanism_id"] for item in registry.get("mechanism_inventory") or ()
        if item.get("migration_status") == "missing"
    )
    incomplete_mechanisms = sorted(
        item["mechanism_id"] for item in registry.get("mechanism_inventory") or ()
        if item.get("migration_status") != "enforced"
    )
    structurally_valid = not issues
    return {
        "schema": "java-upgrade-analyzer.binary-capability-migration-audit.v1",
        "registry_structurally_valid": structurally_valid,
        "release_status": (
            "passed" if structurally_valid and not incomplete_families
            and not missing_mechanisms else "blocked"
        ),
        "baseline_family_count": len(baseline),
        "accounted_family_count": len(set(family_ids)),
        "monitored_deleted_production_path_count": len(
            actual_deleted_production
        ),
        "monitored_deleted_test_asset_count": len(actual_deleted_assets),
        "incomplete_families": incomplete_families,
        "incomplete_mechanisms": incomplete_mechanisms,
        "missing_mechanisms": missing_mechanisms,
        "issue_count": len(issues),
        "issues": issues,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default=str(REGISTRY_PATH))
    parser.add_argument("--repository-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--output", default="")
    parser.add_argument("--require-release-ready", action="store_true")
    args = parser.parse_args(argv)
    registry = json.loads(Path(args.registry).read_text(encoding="utf-8"))
    result = audit_capability_migration(args.repository_root, registry)
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        target = Path(args.output).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    if not result["registry_structurally_valid"]:
        return 2
    if args.require_release_ready and result["release_status"] != "passed":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
