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

from compat import subprocess_platform_kwargs


REGISTRY_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "binary_first" / "capability_migration.json"
)
REQUIRED_FAMILY_IDS = frozenset({
    "artifact_identity_ownership",
    "canonical_evidence_identity",
    "evidence_completeness_visibility",
    "framework_activation_semantics",
    "closed_world_pipeline",
    "reproducible_test_assets",
    "performance_without_scope_loss",
    "test_gate_integrity",
    "module_and_tool_failure_boundaries",
})
REQUIRED_MECHANISM_IDS = frozenset({
    "automatic_runtime_profile_materialization",
    "binary_framework_entrypoints",
    "branch_mutation_flaky_health_gates",
    "declarative_http_client_dispatch",
    "dependency_boot_registration",
    "dependency_source_snapshot_alignment",
    "dubbo_spi_dispatch",
    "dynamic_proxy_dispatch",
    "generated_topology_and_metamorphic_regression",
    "human_report_navigation_and_bounded_detail",
    "human_entrypoint_evidence",
    "implicit_data_contract_dispatch",
    "java_serviceloader_activation",
    "jvm_array_type_resolution",
    "javac_constant_inline_binding",
    "jpa_entity_activation_proof",
    "mybatis_proxy_dispatch",
    "mybatis_runtime_extension_registration",
    "nested_executable_materialization",
    "long_phase_progress_and_recovery",
    "real_project_rotation",
    "whole_dependency_api_enumeration",
    "reflection_and_method_handle_dispatch",
    "source_overlay_language_coverage_visibility",
    "source_overlay_user_choice",
    "dependency_identity_confirmation_workflow",
    "deterministic_immutable_generation",
    "spring_aop_dispatch",
    "spring_bean_wiring_dispatch",
    "spring_component_condition_activation",
    "spring_data_repository_dispatch",
    "spring_message_listener_adapter_registration",
    "spring_security_filter_dispatch",
    "spring_transaction_proxy_dispatch",
    "spring_xml_activation",
    "typed_tool_failure_matrix",
})
REQUIRED_TOPOLOGY_IDS = frozenset({
    "business_direct",
    "same_jar_bridge",
    "cross_jar_bridge",
    "business_to_same_jar_bridge",
    "business_to_cross_jar_bridge",
    "same_coord_multimodule",
    "overloaded_method",
    "constructor",
    "interface_dispatch",
    "virtual_dispatch",
    "static_dispatch",
    "field_access",
    "invokedynamic",
    "reflection",
    "spi",
    "framework_proxy",
    "source_bytecode_agree",
    "source_bytecode_true_conflict",
})


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
            **subprocess_platform_kwargs(new_process_group=True),
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
    declared_baseline = set(
        (registry.get("baseline") or {}).get("legacy_capability_family_ids") or ()
    )
    baseline = set(REQUIRED_FAMILY_IDS)
    baseline_config = registry.get("baseline") or {}
    if declared_baseline != baseline:
        issues.append({
            "reason_code": "CAPABILITY_BASELINE_DECLARATION_MISMATCH",
            "missing": sorted(baseline - declared_baseline),
            "extra": sorted(declared_baseline - baseline),
        })
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

    monitored_deleted_tests = set(
        baseline_config.get("monitored_deleted_test_paths") or ()
    )
    actual_deleted_tests, test_diff_error = _baseline_deleted_paths(
        root, baseline_commit, ("tests/*.py",)
    )
    if test_diff_error:
        issues.append({
            "reason_code": "CAPABILITY_BASELINE_DIFF_UNAVAILABLE",
            "scope": "tests",
            "detail": test_diff_error,
        })
    elif monitored_deleted_tests != actual_deleted_tests:
        issues.append({
            "reason_code": "CAPABILITY_DELETED_TEST_PATH_SET_MISMATCH",
            "missing_from_registry": sorted(
                actual_deleted_tests - monitored_deleted_tests
            ),
            "not_deleted_from_baseline": sorted(
                monitored_deleted_tests - actual_deleted_tests
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
    asset_replacements = list(registry.get("legacy_asset_replacements") or ())
    replacement_asset_paths = [
        str(item.get("legacy_asset_path") or "")
        for item in asset_replacements
    ]
    if len(replacement_asset_paths) != len(set(replacement_asset_paths)):
        issues.append({"reason_code": "CAPABILITY_ASSET_REPLACEMENT_DUPLICATE"})
    if set(replacement_asset_paths) != monitored_deleted_assets:
        issues.append({
            "reason_code": "CAPABILITY_ASSET_REPLACEMENT_SET_MISMATCH",
            "missing": sorted(
                monitored_deleted_assets - set(replacement_asset_paths)
            ),
            "extra": sorted(
                set(replacement_asset_paths) - monitored_deleted_assets
            ),
        })
    for replacement in asset_replacements:
        legacy_path = str(replacement.get("legacy_asset_path") or "")
        tests = list(replacement.get("replacement_tests") or ())
        artifacts = list(replacement.get("replacement_artifacts") or ())
        if not tests or not artifacts:
            issues.append({
                "reason_code": "CAPABILITY_ASSET_REPLACEMENT_EVIDENCE_MISSING",
                "legacy_asset_path": legacy_path,
            })
        for reference in tests:
            failure = _load_test(str(reference))
            if failure:
                issues.append({
                    "reason_code": "CAPABILITY_ASSET_REPLACEMENT_TEST_INVALID",
                    "legacy_asset_path": legacy_path,
                    "reference": reference,
                    "detail": failure,
                })
        for relative in artifacts:
            if not (root / str(relative)).is_file():
                issues.append({
                    "reason_code": "CAPABILITY_ASSET_REPLACEMENT_ARTIFACT_MISSING",
                    "legacy_asset_path": legacy_path,
                    "path": relative,
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
    topology_ids = []
    for record_kind, records, identity_key in (
        ("family", families, "family_id"),
        ("mechanism", registry.get("mechanism_inventory") or (), "mechanism_id"),
        ("topology", registry.get("topology_inventory") or (), "topology_id"),
    ):
        for item in records:
            identity = str(item.get(identity_key) or "")
            if record_kind == "mechanism":
                mechanism_ids.append(identity)
            elif record_kind == "topology":
                topology_ids.append(identity)
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
                ("positive_tests", "negative_tests", "independent_tests")
                if record_kind == "family" else ("evidence_tests",)
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
    declared_mechanisms = set(
        baseline_config.get("monitored_mechanism_ids") or ()
    )
    expected_mechanisms = set(REQUIRED_MECHANISM_IDS)
    if declared_mechanisms != expected_mechanisms:
        issues.append({
            "reason_code": "CAPABILITY_MECHANISM_BASELINE_DECLARATION_MISMATCH",
            "missing": sorted(expected_mechanisms - declared_mechanisms),
            "extra": sorted(declared_mechanisms - expected_mechanisms),
        })
    if set(mechanism_ids) != expected_mechanisms:
        issues.append({
            "reason_code": "CAPABILITY_MECHANISM_SET_MISMATCH",
            "missing": sorted(expected_mechanisms - set(mechanism_ids)),
            "extra": sorted(set(mechanism_ids) - expected_mechanisms),
        })
    if len(topology_ids) != len(set(topology_ids)):
        issues.append({"reason_code": "CAPABILITY_TOPOLOGY_DUPLICATE"})
    declared_topologies = set(
        baseline_config.get("legacy_topology_ids") or ()
    )
    expected_topologies = set(REQUIRED_TOPOLOGY_IDS)
    if declared_topologies != expected_topologies:
        issues.append({
            "reason_code": "CAPABILITY_TOPOLOGY_BASELINE_DECLARATION_MISMATCH",
            "missing": sorted(expected_topologies - declared_topologies),
            "extra": sorted(declared_topologies - expected_topologies),
        })
    if set(topology_ids) != expected_topologies:
        issues.append({
            "reason_code": "CAPABILITY_TOPOLOGY_SET_MISMATCH",
            "missing": sorted(expected_topologies - set(topology_ids)),
            "extra": sorted(set(topology_ids) - expected_topologies),
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
    incomplete_topologies = sorted(
        item["topology_id"] for item in registry.get("topology_inventory") or ()
        if item.get("migration_status") != "enforced"
    )
    structurally_valid = not issues
    return {
        "schema": "java-upgrade-analyzer.binary-capability-migration-audit.v1",
        "registry_structurally_valid": structurally_valid,
        "release_status": (
            "passed" if structurally_valid and not incomplete_families
            and not missing_mechanisms and not incomplete_topologies else "blocked"
        ),
        "baseline_family_count": len(baseline),
        "accounted_family_count": len(set(family_ids)),
        "baseline_topology_count": len(expected_topologies),
        "accounted_topology_count": len(set(topology_ids)),
        "baseline_mechanism_count": len(expected_mechanisms),
        "accounted_mechanism_count": len(set(mechanism_ids)),
        "monitored_deleted_production_path_count": len(
            actual_deleted_production
        ),
        "monitored_deleted_test_path_count": len(actual_deleted_tests),
        "monitored_deleted_test_asset_count": len(actual_deleted_assets),
        "accounted_deleted_test_asset_replacement_count": len(
            set(replacement_asset_paths)
        ),
        "incomplete_families": incomplete_families,
        "incomplete_mechanisms": incomplete_mechanisms,
        "incomplete_topologies": incomplete_topologies,
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
