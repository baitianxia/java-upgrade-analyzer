"""Standard-library harness for public CLI black-box tests.

The harness may create inputs and normalize public outputs.  It must not import
or execute production Python code in-process.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile
from typing import Mapping


IDENTITY_FIELDS = ("owner", "member", "descriptor", "member_kind")
RESULT_FIELDS = (
    "dependency_lineages", "base_dependency_coords", "current_dependency_coords",
    "reachability_status", "static_linkage_status", "impact_conclusion",
    "runtime_verification_status", "exact_path_exists", "possible_path_exists",
    "path_set_complete",
)


class BlackboxContractError(RuntimeError):
    pass


def required_tools() -> dict[str, str]:
    tools = {name: shutil.which(name) or "" for name in ("java", "javac", "javap")}
    missing = sorted(name for name, path in tools.items() if not path)
    if missing:
        raise BlackboxContractError(
            "required OpenJDK tools are missing: " + ", ".join(missing)
        )
    return tools


def _run(command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=180,
    )
    if completed.returncode != 0:
        raise BlackboxContractError(
            f"command_failed:{completed.returncode}:{' '.join(command)}:"
            f"{completed.stderr[-2000:]}"
        )
    return completed


def _jdk_home(java: str) -> Path:
    completed = subprocess.run(
        [java, "-XshowSettings:properties", "-version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
    )
    for line in completed.stderr.splitlines():
        if "java.home" in line and "=" in line:
            candidate = Path(line.split("=", 1)[1].strip()).resolve()
            if candidate.is_dir() and (candidate / "jmods").is_dir():
                return candidate
    raise BlackboxContractError("full target JDK home with jmods was not resolved")


def _compile(
    javac: str, sources: list[Path], destination: Path,
    *, classpath: list[Path] | None = None,
) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    command = [javac, "-g:none", "-encoding", "UTF-8"]
    if classpath:
        command.extend([
            "-classpath", os.pathsep.join(str(path) for path in classpath)
        ])
    command.extend(["-d", str(destination), *map(str, sources)])
    _run(command)


def compile_fixture(case_root: Path, workspace: Path, tools: Mapping[str, str]) -> dict[str, Path]:
    source = case_root / "src"
    base_classes = workspace / "classes" / "base"
    current_classes = workspace / "classes" / "current"
    business_classes = workspace / "classes" / "business"
    oracle_classes = workspace / "classes" / "oracle"
    _compile(
        tools["javac"], sorted((source / "base").rglob("*.java")), base_classes
    )
    _compile(
        tools["javac"], sorted((source / "current").rglob("*.java")),
        current_classes,
    )
    _compile(
        tools["javac"], sorted((source / "business").rglob("*.java")),
        business_classes, classpath=[base_classes],
    )
    _compile(
        tools["javac"], sorted((source / "oracle").rglob("*.java")),
        oracle_classes, classpath=[base_classes, business_classes],
    )
    return {
        "base": base_classes,
        "current": current_classes,
        "business": business_classes,
        "oracle": oracle_classes,
    }


def _package_classes(classes: Path, target: Path, *, variant: str) -> Path:
    class_files = sorted(classes.rglob("*.class"))
    if variant == "repacked":
        class_files.reverse()
        timestamp = (2024, 6, 7, 8, 9, 10)
    else:
        timestamp = (1980, 1, 1, 0, 0, 0)
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w") as archive:
        for class_file in class_files:
            info = zipfile.ZipInfo(
                class_file.relative_to(classes).as_posix(), date_time=timestamp
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, class_file.read_bytes())
    return target


def package_variant(
    compiled: Mapping[str, Path], workspace: Path, *, variant: str,
) -> dict[str, Path]:
    root = workspace / "artifacts" / variant
    return {
        key: _package_classes(classes, root / f"{key}.jar", variant=variant)
        for key, classes in compiled.items()
    }


def _side(
    *, case: Mapping[str, object], artifacts: Mapping[str, Path], version: str,
    jdk_home: Path,
) -> dict[str, object]:
    coordinate = (
        str(case["base_coordinate"])
        if version == "base" else str(case["current_coordinate"])
    )
    runtime_artifacts = [
        {
            "path": str(artifacts["business"]),
            "logical_location": "app/business.jar",
            "loader_realm": "application-loader",
            "path_kind": "business_classes",
            "slot": 0,
            "coord": str(
                case.get("business_coordinate")
                or "blackbox:fixture-app:1.0"
            ),
            "lineage": str(
                case.get("business_lineage") or "blackbox:fixture-app"
            ),
            "runtime_code_source_origin_identity": "blackbox-fixture-app",
        },
        {
            "path": str(artifacts[version]),
            "logical_location": "lib/fixture-lib.jar",
            "loader_realm": "application-loader",
            "path_kind": "classpath",
            "slot": 1,
            "coord": coordinate,
            "lineage": str(case["library_lineage"]),
            "runtime_code_source_origin_identity": "blackbox-fixture-lib",
        },
    ]
    return {
        "jdk_home": str(jdk_home),
        "artifacts": runtime_artifacts,
        "runtime_profile": {
            "container_and_launcher_kind": "java-classpath",
            "loader_topology": {
                "coverage_status": "complete",
                "entrypoint_realms": ["application-loader"],
                "realms": [
                    {
                        "identity": "platform-loader",
                        "kind": "platform",
                        "delegation": "parent_first",
                        "module_mode": "named-platform"
                    },
                    {
                        "identity": "application-loader",
                        "kind": "application",
                        "parent": "platform-loader",
                        "delegation": "parent_first",
                        "module_mode": "unnamed"
                    }
                ]
            },
            "runtime_security_and_package_sealing_policy_identity": (
                "standard-unsealed-unsigned-v1"
            ),
            "active_profile_identities": [],
            "external_config_snapshot_identities": [],
            "agent_transformer_plugin_profile_identities": [],
            "business_entrypoint_profile": {
                "coverage_status": "complete",
                "methods": [
                    {
                        "initiating_loader_realm_identity": "application-loader",
                        **dict(entrypoint),
                    }
                    for entrypoint in case["entrypoints"]
                ],
            },
            "runtime_class_closure_coverage_status": "complete",
            "resource_selection_coverage_status": "complete",
        },
    }


def pipeline_config(
    case: Mapping[str, object], artifacts: Mapping[str, Path], *, java: str,
) -> dict[str, object]:
    home = _jdk_home(java)
    return {
        "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
        "source_usage": {
            "decision": "skip_source",
            "decision_source": "explicit_config",
        },
        "base": _side(
            case=case, artifacts=artifacts, version="base", jdk_home=home
        ),
        "current": _side(
            case=case, artifacts=artifacts, version="current", jdk_home=home
        ),
        "runtime_comparison": {
            "comparison_intent": "same_deployment_profile",
            "profile_correspondence_policy_version": "v1",
            "controlled_profile_fields": ["loader_topology"],
            "declared_upgrade_payload_scope": ["artifact-bytes"],
            "changed_or_unknown_profile_fields": [],
        },
    }


def run_public_pipeline(
    repo_root: Path, case: Mapping[str, object], artifacts: Mapping[str, Path],
    workspace: Path, *, java: str,
) -> tuple[dict[str, object], dict[str, object]]:
    run_root = workspace / "runs" / artifacts["base"].parent.name
    config_path = run_root / "input.json"
    result_path = run_root / "result.json"
    output_root = run_root / "output"
    run_root.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        json.dumps(
            pipeline_config(case, artifacts, java=java),
            ensure_ascii=False, indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    completed = _run([
        sys.executable,
        str(repo_root / str(case["public_entrypoint"])),
        "--config", str(config_path),
        "--output-root", str(output_root),
        "--result-json", str(result_path),
    ], cwd=repo_root)
    stdout_result = json.loads(completed.stdout)
    file_result = json.loads(result_path.read_text(encoding="utf-8"))
    if stdout_result != file_result:
        raise BlackboxContractError("public stdout and --result-json disagree")
    if stdout_result.get("schema") != "java-upgrade-analyzer.binary-pipeline-result.v1":
        raise BlackboxContractError("public pipeline result schema mismatch")
    if stdout_result.get("validation_status") != "passed":
        raise BlackboxContractError(
            f"public pipeline validation failed: {stdout_result.get('validation_status')}"
        )
    generation = Path(str(stdout_result["generation_directory"]))
    formal = json.loads(
        (generation / "binary_formal_results.json").read_text(encoding="utf-8")
    )
    if formal.get("schema") != "java-upgrade-analyzer.binary-formal-results.v1":
        raise BlackboxContractError("formal result schema mismatch")
    return stdout_result, formal


def _expected_identity(row: Mapping[str, object]) -> tuple[str, str, str, str]:
    return tuple(str(row.get(field) or "") for field in IDENTITY_FIELDS)


def _actual_identity(row: Mapping[str, object]) -> tuple[str, str, str, str]:
    return (
        str(row.get("display_owner") or ""),
        str(row.get("display_member") or ""),
        str(row.get("display_descriptor") or ""),
        str(row.get("display_member_kind") or ""),
    )


def semantic_projection(formal: Mapping[str, object]) -> list[dict[str, object]]:
    projected = []
    for row in formal.get("by_api") or []:
        projected.append({
            "owner": str(row.get("display_owner") or ""),
            "member": str(row.get("display_member") or ""),
            "descriptor": str(row.get("display_descriptor") or ""),
            "member_kind": str(row.get("display_member_kind") or ""),
            **{
                field: (
                    sorted(str(value) for value in row.get(field) or [])
                    if field in {
                        "dependency_lineages", "base_dependency_coords",
                        "current_dependency_coords",
                    }
                    else row.get(field)
                )
                for field in RESULT_FIELDS
            },
            "paths": sorted(
                (
                    str(path.get("path_certainty") or ""),
                    str(path.get("path_text") or ""),
                )
                for path in row.get("paths") or []
            ),
        })
    return sorted(projected, key=lambda row: _expected_identity(row))


def expected_projection(truth: Mapping[str, object]) -> list[dict[str, object]]:
    projected = []
    for row in truth.get("expected_results") or []:
        projected.append({
            **{field: str(row.get(field) or "") for field in IDENTITY_FIELDS},
            **{
                field: (
                    sorted(str(value) for value in row.get(field) or [])
                    if field in {
                        "dependency_lineages", "base_dependency_coords",
                        "current_dependency_coords",
                    }
                    else row.get(field)
                )
                for field in RESULT_FIELDS
            },
            "paths": sorted(
                (str(path.get("certainty") or ""), str(path.get("text") or ""))
                for path in row.get("paths") or []
            ),
        })
    return sorted(projected, key=lambda row: _expected_identity(row))


def evaluate_closed_truth(
    formal: Mapping[str, object], truth: Mapping[str, object],
) -> dict[str, object]:
    actual = semantic_projection(formal)
    expected = expected_projection(truth)
    errors = []
    actual_identities = [_expected_identity(row) for row in actual]
    expected_identities = [_expected_identity(row) for row in expected]
    if len(actual_identities) != len(set(actual_identities)):
        errors.append("duplicate_actual_identity")
    if actual_identities != expected_identities:
        errors.append(
            f"closed_identity_set_mismatch:expected={expected_identities}:"
            f"actual={actual_identities}"
        )
    actual_by_identity = {
        _expected_identity(row): row for row in actual
    }
    state_mismatch_count = 0
    path_mismatch_count = 0
    for expected_row in expected:
        identity = _expected_identity(expected_row)
        actual_row = actual_by_identity.get(identity)
        if actual_row is None:
            continue
        expected_state = dict(expected_row)
        actual_state = dict(actual_row)
        expected_paths = expected_state.pop("paths")
        actual_paths = actual_state.pop("paths")
        if actual_state != expected_state:
            state_mismatch_count += 1
            errors.append(
                f"semantic_state_mismatch:{identity}:expected={expected_state}:"
                f"actual={actual_state}"
            )
        if actual_paths != expected_paths:
            path_mismatch_count += 1
            errors.append(
                f"semantic_path_mismatch:{identity}:expected={expected_paths}:"
                f"actual={actual_paths}"
            )
    forbidden_hit_count = 0
    for forbidden in truth.get("forbidden_results") or []:
        identity = _expected_identity(forbidden)
        if identity in actual_by_identity:
            forbidden_hit_count += 1
            errors.append(f"forbidden_result_present:{identity}")
    expected_set = set(expected_identities)
    actual_set = set(actual_identities)
    metrics = {
        "expected_result_count": len(expected_identities),
        "actual_result_count": len(actual_identities),
        "true_positive_count": len(expected_set.intersection(actual_set)),
        "false_positive_count": len(actual_set - expected_set),
        "false_negative_count": len(expected_set - actual_set),
        "state_mismatch_count": state_mismatch_count,
        "path_mismatch_count": path_mismatch_count,
        "forbidden_hit_count": forbidden_hit_count,
    }
    return {
        "schema": "java-upgrade-analyzer.blackbox-evaluation.v1",
        "status": "passed" if not errors else "failed",
        "metrics": metrics,
        "issues": tuple(errors),
    }


def compare_closed_truth(
    formal: Mapping[str, object], truth: Mapping[str, object],
) -> tuple[str, ...]:
    return tuple(evaluate_closed_truth(formal, truth)["issues"])


def compare_truth_with_oracle(
    truth: Mapping[str, object], oracle: Mapping[str, object],
) -> tuple[str, ...]:
    errors = []
    expected_rows = list(truth.get("expected_results") or [])
    expected_member_rows = [
        row for row in expected_rows
        if row.get("member_kind") in {"method", "field"}
    ]
    expected_outcome_rows = [
        row for row in expected_rows
        if row.get("member_kind") in {"provider_topology", "class_definition"}
    ]
    expected_identities = {
        _expected_identity(row) for row in expected_member_rows
    }
    oracle_changed_identities = {
        _expected_identity(row) for row in (
            oracle.get("changed_identities")
            or oracle.get("removed_identities")
            or []
        )
    }
    if expected_identities != oracle_changed_identities:
        errors.append(
            f"oracle_changed_set_mismatch:expected={sorted(expected_identities)}:"
            f"oracle={sorted(oracle_changed_identities)}"
        )
    oracle_reachable = {
        _expected_identity(row)
        for row in (
            oracle.get("reachable_changed_identities")
            or oracle.get("reachable_removed_identities")
            or []
        )
    }
    truth_reachable = {
        _expected_identity(row)
        for row in expected_member_rows
        if row.get("reachability_status") == "reachable"
    }
    if oracle_reachable != truth_reachable:
        errors.append(
            f"oracle_reachability_mismatch:expected={sorted(truth_reachable)}:"
            f"oracle={sorted(oracle_reachable)}"
        )
    oracle_paths = dict(oracle.get("required_paths") or {})
    linkage = dict(oracle.get("linkage") or {})
    behavior = dict(oracle.get("behavior") or {})
    base_identities = {
        _expected_identity(row) for row in oracle.get("base_identities") or []
    }
    current_identities = {
        _expected_identity(row) for row in oracle.get("current_identities") or []
    }
    for row in expected_member_rows:
        identity = _expected_identity(row)
        key = "|".join(identity)
        truth_paths = [str(path.get("text") or "") for path in row.get("paths") or []]
        oracle_path = oracle_paths.get(key)
        if truth_paths != ([oracle_path] if oracle_path else []):
            errors.append(
                f"oracle_path_mismatch:{identity}:expected={truth_paths}:"
                f"oracle={oracle_path}"
            )
        linkage_observation = linkage.get(key)
        behavior_observation = behavior.get(key)
        if linkage_observation:
            if not linkage_observation.get("base_succeeded"):
                errors.append(f"oracle_base_linkage_failed:{identity}")
            if not linkage_observation.get(
                "current_failed_with_expected_linkage_error"
            ):
                errors.append(f"oracle_current_linkage_did_not_fail:{identity}")
            if row.get("static_linkage_status") != "incompatible_if_executed":
                errors.append(f"oracle_linkage_truth_state_mismatch:{identity}")
        elif behavior_observation:
            if not behavior_observation.get("base_succeeded"):
                errors.append(f"oracle_base_behavior_failed:{identity}")
            if not behavior_observation.get("current_succeeded"):
                errors.append(f"oracle_current_behavior_failed:{identity}")
            if not behavior_observation.get("matches_authored_expectation"):
                errors.append(f"oracle_behavior_expectation_mismatch:{identity}")
            if row.get("static_linkage_status") != "compatible_or_not_applicable":
                errors.append(f"oracle_behavior_truth_state_mismatch:{identity}")
        elif row.get("oracle_relation") == "added_member":
            if identity in base_identities or identity not in current_identities:
                errors.append(f"oracle_added_member_presence_mismatch:{identity}")
            if row.get("static_linkage_status") != "compatible_or_not_applicable":
                errors.append(f"oracle_added_member_truth_state_mismatch:{identity}")
        else:
            errors.append(f"oracle_runtime_probe_missing:{identity}")
    expected_outcomes = {
        _expected_identity(row) for row in expected_outcome_rows
    }
    oracle_outcomes = {
        _expected_identity(row)
        for row in oracle.get("runtime_outcome_identities") or []
    }
    if expected_outcomes != oracle_outcomes:
        errors.append(
            f"oracle_runtime_outcome_set_mismatch:"
            f"expected={sorted(expected_outcomes)}:oracle={sorted(oracle_outcomes)}"
        )
    for row in expected_outcome_rows:
        identity = _expected_identity(row)
        if (
            row.get("reachability_status") != "not_found_in_static_analysis"
            or row.get("static_linkage_status") != "undetermined"
            or row.get("impact_conclusion") != "inconclusive"
            or row.get("runtime_verification_status") != "undetermined"
            or row.get("exact_path_exists") is not False
            or row.get("possible_path_exists") is not False
            or row.get("path_set_complete") is not True
            or row.get("paths") != []
        ):
            errors.append(f"oracle_runtime_outcome_truth_state_mismatch:{identity}")
    for row in truth.get("forbidden_results") or []:
        if row.get("oracle_relation") != "unchanged_member":
            continue
        identity = _expected_identity(row)
        if identity not in base_identities or identity not in current_identities:
            errors.append(f"oracle_forbidden_member_not_unchanged:{identity}")
        if identity in oracle_changed_identities:
            errors.append(f"oracle_forbidden_member_is_changed:{identity}")
    return tuple(errors)


def sha256(path: Path) -> str:
    digest = hashlib.sha256(Path(path).read_bytes())
    return digest.hexdigest()


__all__ = [
    "BlackboxContractError", "compare_closed_truth", "compare_truth_with_oracle",
    "compile_fixture", "evaluate_closed_truth", "package_variant", "required_tools",
    "run_public_pipeline", "semantic_projection", "sha256",
]
