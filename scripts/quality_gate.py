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
import sys
import tempfile

from binary_capability_migration_audit import (
    REGISTRY_PATH as CAPABILITY_MIGRATION_REGISTRY,
    audit_capability_migration,
)
from compat import run_managed_subprocess


QUICK_STEP4_ORACLE_REGRESSION_TESTS = (
    "tests.test_final_artifact_edge_oracle.FinalArtifactEdgeOracleTest."
    "test_method_types_and_classes_expand_through_real_bootstrap_pipeline",
    "tests.test_binary_fact_store.BinaryFactStoreTest."
    "test_real_method_type_constants_expand_through_helper_and_store",
    "tests.test_binary_fact_store.BinaryFactStoreTest."
    "test_all_method_handle_reference_kinds_materialize_constraints",
    "tests.test_binary_fact_store.BinaryFactStoreTest."
    "test_member_reference_descriptors_attach_compact_constraint_owners",
    "tests.test_binary_loading_constraints.BinaryLoadingConstraintTest."
    "test_compact_loading_constraint_owner_list_is_canonical_and_fail_closed",
    "tests.test_binary_loading_constraints.BinaryLoadingConstraintTest."
    "test_constraint_universe_is_isolated_to_the_selected_runtime_profile",
    "tests.test_binary_loading_constraints.BinaryLoadingConstraintTest."
    "test_real_jvm_distinguishes_preloaded_and_deferred_conflicts",
    "tests.test_binary_loading_constraints.BinaryLoadingConstraintTest."
    "test_reconciler_keeps_provider_conflicts_deferred_without_load_evidence",
    "tests.test_final_artifact_edge_oracle.FinalArtifactEdgeOracleTest."
    "test_method_named_like_its_class_is_not_rewritten_as_constructor",
    "tests.test_final_artifact_edge_oracle.FinalArtifactEdgeOracleTest."
    "test_real_major48_same_name_method_survives_batched_javap_scan",
    "tests.test_final_artifact_edge_oracle.FinalArtifactEdgeOracleTest."
    "test_real_bootstrap_section_stops_before_later_ref_text",
    "tests.test_final_artifact_edge_oracle.FinalArtifactEdgeOracleTest."
    "test_raw_owner_member_and_descriptor_survive_real_javap",
    "tests.test_final_artifact_edge_oracle.FinalArtifactEdgeOracleTest."
    "test_ldc_method_handles_without_bootstrap_attribute_use_verbose_javap",
    "tests.test_final_artifact_edge_oracle.FinalArtifactEdgeOracleTest."
    "test_real_constant_dynamic_scans_bootstrap_nested_and_field_handles",
)
QUICK_STEP4_VALIDATION_REGRESSION_TESTS = (
    "tests.test_binary_validation_performance_safety."
    "BinaryValidationPerformanceSafetyTest."
    "test_mr_manifest_main_section_and_version_floor_match_all_scanners",
    "tests.test_binary_validation_performance_safety."
    "BinaryValidationPerformanceSafetyTest."
    "test_unbound_sqlite_wal_is_rejected_and_immutable_reader_ignores_it",
    "tests.test_binary_validation_performance_safety."
    "BinaryValidationPerformanceSafetyTest."
    "test_legacy_dynamic_evidence_without_reference_kind_fails_closed",
    "tests.test_binary_validation_performance_safety."
    "BinaryValidationPerformanceSafetyTest."
    "test_dynamic_reference_tag_mutation_fails_closed",
)
QUICK_STEP4_PIPELINE_REGRESSION_TESTS = (
    "tests.test_binary_pipeline.BinaryPipelineTest."
    "test_same_name_method_edges_reach_validated_generation_activation",
    "tests.test_binary_pipeline.BinaryPipelineTest."
    "test_validation_rejects_unbound_sqlite_transient_sidecar",
    "tests.test_binary_pipeline.BinaryPipelineTest."
    "test_step1_materialized_mr_resources_reach_validated_activation",
    "tests.test_binary_pipeline.BinaryPipelineTest."
    "test_static_config_errors_fail_before_jdk_preflight",
    "tests.test_binary_pipeline.BinaryPipelineTest."
    "test_resume_fails_closed_when_implementation_changes_during_validation",
    "tests.test_binary_pipeline.BinaryPipelineTest."
    "test_resume_recovers_validation_written_before_checkpoint_advance",
    "tests.test_binary_pipeline.BinaryPipelineTest."
    "test_resume_revalidates_attachment_after_validator_only_change",
)
QUICK_STEP4_RUN_STEP_REGRESSION_TESTS = (
    "tests.test_run_step_main_state.RunStepMainStateTest."
    "test_step4_gate_or_finalize_failure_rolls_back_all_three_state_layers",
    "tests.test_run_step_main_state.RunStepMainStateTest."
    "test_step4_startup_never_treats_matching_report_as_gate_receipt",
)

QUICK_REPORT_PUBLICATION_REGRESSION_TESTS = (
    "tests.test_gate_step4_candidate",
    "tests.test_binary_pipeline.BinaryPipelineTest."
    "test_end_to_end_generation_is_content_bound_and_immutable",
    "tests.test_step6_report.Step6ReportObjectivityTest."
    "test_coverage_evidence_availability_is_confined_to_report_roots",
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
    "tests.test_binary_result_truth",
    "tests.test_blackbox_harness",
    "tests.blackbox.test_managed_process",
    "tests.test_test_trust_gate",
    "tests.test_test_suite_runner",
    "tests.blackbox.test_public_binary_cli",
    "tests.test_ci_quality_contract",
    "tests.test_platform_contract",
    "tests.test_process_metrics",
    "tests.test_path_runtime_worktree_reliability",
    "tests.test_binary_runtime_materializer",
    "tests.test_step0_workflow",
    *QUICK_STEP4_ORACLE_REGRESSION_TESTS,
    *QUICK_STEP4_VALIDATION_REGRESSION_TESTS,
    *QUICK_STEP4_PIPELINE_REGRESSION_TESTS,
    *QUICK_STEP4_RUN_STEP_REGRESSION_TESTS,
    *QUICK_REPORT_PUBLICATION_REGRESSION_TESTS,
)

# Step5 loads the complete pipeline and run-step modules, so omit their exact
# quick selectors to avoid executing the same regressions twice.
_STEP5_COMPLETE_MODULE_REGRESSIONS = frozenset(
    (*QUICK_STEP4_PIPELINE_REGRESSION_TESTS, *QUICK_STEP4_RUN_STEP_REGRESSION_TESTS)
)
STEP5_MODULES = tuple(
    selector for selector in QUICK_MODULES
    if selector not in _STEP5_COMPLETE_MODULE_REGRESSIONS
) + (
    "tests.test_binary_asm_helper",
    "tests.test_binary_fact_store",
    "tests.test_binary_pipeline",
    "tests.test_binary_snapshot_cache",
    "tests.test_binary_source_overlay",
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
    suite = "all" if profile == "release" else profile
    return [
        sys.executable,
        str(Path(__file__).with_name("test_suite_runner.py")),
        "--suite", suite,
    ]


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


def performance_command(
    audit_root: str | Path, *, evidence_mode: str = "live",
) -> list[str]:
    root = Path(audit_root).expanduser().resolve()
    if evidence_mode == "recorded":
        return [
            sys.executable,
            str(Path(__file__).with_name("binary_performance_gate.py")),
            "--verify-recorded-gate", str(PERFORMANCE_GATE_PATH),
            "--output", str(root / "performance_result.json"),
        ]
    if evidence_mode != "live":
        raise ValueError(f"unsupported performance evidence mode: {evidence_mode}")
    return [
        sys.executable,
        str(Path(__file__).with_name("binary_performance_gate.py")),
        "--work-root", str(root / "performance_work"),
        "--output", str(root / "performance_result.json"),
        "--gate", str(PERFORMANCE_GATE_PATH),
    ]


def _jdk_home() -> Path:
    completed = run_managed_subprocess(
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
    parser.add_argument(
        "--profile",
        choices=(
            "blackbox", "whitebox", "performance",
            "quick", "step5", "release",
        ),
        default="quick",
    )
    parser.add_argument("--json-out", default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--audit-root",
        default=str(Path(tempfile.gettempdir()) / "jua-binary-release-gate"),
    )
    parser.add_argument("--real-project-cache", default="")
    parser.add_argument("--jdk-home", default="")
    parser.add_argument(
        "--release-performance-mode",
        choices=("live", "recorded"),
        default="live",
        help=(
            "live measures only on the gate's matching reference machine; "
            "recorded replays source-bound reference evidence"
        ),
    )
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
        ), performance_command(
            audit_root, evidence_mode=args.release_performance_mode,
        )]
    if args.dry_run:
        print(" ".join(command))
        for release_command in release_commands:
            print(" ".join(release_command))
        return 0
    started = datetime.now(timezone.utc)
    print(f"[binary-quality-gate] tests: {' '.join(command)}", flush=True)
    completed = run_managed_subprocess(command, check=False)
    health = None
    health_returncode = 0
    real_project = None
    real_project_returncode = 0
    performance = None
    performance_returncode = 0
    if args.profile == "release":
        audit_root.mkdir(parents=True, exist_ok=True)
        print("[binary-quality-gate] test health: branch/mutation/repeat", flush=True)
        health_completed = run_managed_subprocess(
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
            real_completed = run_managed_subprocess(
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
        if args.release_performance_mode == "live":
            performance_label = (
                "400 JAR / 100000 classes + full 400 JAR / 100000 class "
                "pipeline on the matching reference machine"
            )
        else:
            performance_label = (
                "source-bound recorded reference evidence replay"
            )
        print(
            f"[binary-quality-gate] performance: {performance_label}",
            flush=True,
        )
        performance_completed = run_managed_subprocess(
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
