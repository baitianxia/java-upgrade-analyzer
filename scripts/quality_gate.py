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
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from binary_capability_migration_audit import (
    REGISTRY_PATH as CAPABILITY_MIGRATION_REGISTRY,
    audit_capability_migration,
)
from compat import run_managed_subprocess


TEST_TIMEOUT_SECONDS_BY_PROFILE = {
    "quick": 3600,
    "step5": 7200,
    "blackbox": 7200,
    "whitebox": 14400,
    "performance": 14400,
    "release": 21600,
}
TEST_HEALTH_TIMEOUT_SECONDS = 3600
REAL_PROJECT_TIMEOUT_SECONDS = 3600
RECORDED_PERFORMANCE_TIMEOUT_SECONDS = 1800
LIVE_PERFORMANCE_TIMEOUT_SECONDS = 21600
JDK_DISCOVERY_TIMEOUT_SECONDS = 30


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


# Product defects that previously escaped must stay on a merge-blocking path.
# The registry audit verifies these exact selectors against independently
# authored truth and prevents a rename/removal from silently weakening CI.
QUICK_ESCAPED_DEFECT_REGRESSION_TESTS = (
    "tests.blackbox.test_public_artifact_safety."
    "PublicArtifactSafetyBlackboxTest."
    "test_duplicate_corrupt_unsupported_and_partial_resource_are_public",
    "tests.blackbox.test_public_failure_contracts."
    "PublicFailureContractsBlackboxTest."
    "test_preflight_failure_never_borrows_stale_progress_phase",
    "tests.blackbox.test_public_failure_contracts."
    "PublicFailureContractsBlackboxTest."
    "test_result_sink_failure_preserves_the_primary_public_failure",
    "tests.blackbox.test_public_checkout_builds."
    "PublicCheckoutBuildBlackboxTest."
    "test_gradle_preflight_reports_root_cause_not_generic_help_footer",
    "tests.blackbox.test_public_cli_surface.PublicCliSurfaceBlackboxTest."
    "test_every_public_command_has_exact_help_and_invalid_option_contract",
    "tests.test_binary_pipeline_input_performance."
    "BinaryPipelineInputPerformanceTest."
    "test_parallel_progress_publishers_use_distinct_atomic_temporary_files",
    "tests.test_binary_artifact_safety.BinaryArtifactSafetyTest."
    "test_snapshot_blocks_duplicate_class_entries_but_allows_maven_metadata",
    "tests.test_binary_artifact_safety.BinaryArtifactSafetyTest."
    "test_spring_xml_uses_xml_semantics_before_line_registration_semantics",
    "tests.test_step3_source_usage.Step3SourceUsageTest."
    "test_business_scan_roots_include_code_and_standard_resources",
    "tests.test_run_step_main_state.RunStepMainStateTest."
    "test_step4_scope_checkpoint_is_skipped_when_no_real_scope_choice_exists",
    "tests.test_step6_report.Step6ReportObjectivityTest."
    "test_two_same_type_change_facts_survive_step6_collection",
    "tests.blackbox.test_public_framework_semantics."
    "PublicFrameworkSemanticsBlackboxTest."
    "test_http_dubbo_and_service_loader_registrations",
    "tests.test_binary_semantic_overlay_boundaries."
    "BinarySemanticOverlayBoundaryTest."
    "test_declarative_clients_support_class_and_method_annotations",
    "tests.blackbox.test_public_framework_semantics."
    "PublicFrameworkSemanticsBlackboxTest."
    "test_web_binding_keeps_removed_field_as_implicit_contract",
    "tests.test_binary_semantic_overlay_boundaries."
    "BinarySemanticOverlayBoundaryTest."
    "test_implicit_data_contract_existing_symbolic_and_direct_boundaries",
    "tests.test_jdk_preflight.JdkPreflightBoundaryTest."
    "test_runtime_metadata_probe_supports_a_real_jdk_without_release_file",
    "tests.blackbox.test_public_runtime_topology."
    "PublicRuntimeTopologyBlackboxTest."
    "test_provider_topology_has_one_public_identity_across_loader_realms",
    "tests.test_final_artifact_edge_oracle_boundaries."
    "FinalArtifactParserBoundaryTest."
    "test_nest_host_attribute_is_not_reparsed_as_a_class_declaration",
    "tests.test_binary_output_boundaries."
    "BinaryOutputPureBoundaryTest."
    "test_aggregate_merges_same_public_provider_identity_across_loader_realms",
    "tests.test_binary_decision_engine_boundaries."
    "DecisionEngineBoundaryTest.test_runtime_outcome_decision_matrix",
    "tests.blackbox.test_public_runtime_topology."
    "PublicRuntimeTopologyBlackboxTest."
    "test_classpath_and_resource_order_match_actual_classloader",
)


QUICK_ALLOWED_SKIP_SELECTORS = (
    "tests.test_platform_contract.PlatformContractTest."
    "test_pythonw_parent_repeatedly_captures_real_git_stdout",
)
STEP5_ALLOWED_SKIP_SELECTORS = (
    *QUICK_ALLOWED_SKIP_SELECTORS,
    "tests.test_binary_real_project_guard.BinaryRealProjectGuardTest."
    "test_pinned_mybatis_final_artifact_exercises_xml_proxy_dispatch",
)


QUICK_MODULES = (
    "tests.test_binary_first_contract",
    "tests.test_binary_first_model",
    "tests.test_binary_artifact_diff",
    "tests.test_binary_decision_engine",
    "tests.test_binary_runtime_reconciler",
    "tests.test_binary_runtime_reconciler_boundaries",
    "tests.test_binary_trace_engine",
    "tests.test_binary_output",
    "tests.test_binary_entrypoint_discovery",
    "tests.test_binary_entrypoint_discovery_boundaries",
    "tests.test_binary_definition_verifier",
    "tests.test_binary_tool_execution",
    "tests.test_binary_capability_migration_audit",
    "tests.test_binary_result_truth",
    "tests.test_blackbox_harness",
    "tests.blackbox.test_managed_process",
    "tests.test_test_trust_gate",
    "tests.test_defect_regression_gate",
    "tests.test_test_suite_runner",
    "tests.test_unittest_evidence_runner",
    "tests.test_quality_gate",
    "tests.test_whitebox_call_coverage",
    "tests.test_git_change_check",
    "tests.test_internal_helper_contracts",
    "tests.test_compat_internal_helpers",
    "tests.test_enhanced_source_analyzer_internal",
    "tests.test_run_step_internal_contracts",
    "tests.test_reporting_internal_contracts",
    "tests.test_stage_internal_contracts",
    "tests.test_platform_edge_internal_contracts",
    "tests.test_validation_oracle_internal_contracts",
    "tests.test_binary_validation_oracle_boundaries",
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
    *QUICK_ESCAPED_DEFECT_REGRESSION_TESTS,
)

# Step5 loads several complete modules, so omit every exact quick selector
# already covered by those modules.  Passing both a module and one of its test
# methods to unittest executes that method twice and inflates execution counts.
_STEP5_COMPLETE_MODULES = (
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


def _covered_by_complete_step5_module(selector: str) -> bool:
    return any(
        selector == module or selector.startswith(module + ".")
        for module in _STEP5_COMPLETE_MODULES
    )


STEP5_MODULES = tuple(
    selector for selector in QUICK_MODULES
    if not _covered_by_complete_step5_module(selector)
) + _STEP5_COMPLETE_MODULES


def command_for(profile: str, *, json_out: str = "") -> list[str]:
    if profile == "quick":
        command = [
            sys.executable,
            str(Path(__file__).with_name("unittest_evidence_runner.py")),
            "--suite-label", profile,
            "--forbid-skips",
        ]
        for selector in QUICK_ALLOWED_SKIP_SELECTORS:
            command.extend(["--allow-skip", selector])
        if json_out:
            command.extend(["--json-out", json_out])
        return [*command, *QUICK_MODULES]
    if profile == "step5":
        command = [
            sys.executable,
            str(Path(__file__).with_name("unittest_evidence_runner.py")),
            "--suite-label", profile,
            "--forbid-skips",
        ]
        for selector in STEP5_ALLOWED_SKIP_SELECTORS:
            command.extend(["--allow-skip", selector])
        if json_out:
            command.extend(["--json-out", json_out])
        return [*command, *STEP5_MODULES]
    suite = "all" if profile == "release" else profile
    command = [
        sys.executable,
        str(Path(__file__).with_name("test_suite_runner.py")),
        "--suite", suite,
    ]
    if json_out:
        command.extend(["--json-out", json_out])
    return command


def load_test_execution_evidence(
    path: str | Path, *, profile: str, returncode: int,
) -> tuple[dict | None, str]:
    target = Path(path)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return None, f"TEST_EXECUTION_EVIDENCE_UNREADABLE:{type(error).__name__}:{error}"
    if not isinstance(payload, dict):
        return None, "TEST_EXECUTION_EVIDENCE_NOT_OBJECT"
    expected_schema = (
        "java-upgrade-analyzer.unittest-execution.v1"
        if profile in {"quick", "step5"}
        else "java-upgrade-analyzer.test-suite-run.v1"
    )
    if payload.get("schema") != expected_schema:
        return payload, "TEST_EXECUTION_EVIDENCE_SCHEMA_INVALID"
    expected_label = "all" if profile == "release" else profile
    actual_label = (
        payload.get("suite_label")
        if profile in {"quick", "step5"} else payload.get("suite")
    )
    if actual_label != expected_label:
        return payload, "TEST_EXECUTION_EVIDENCE_PROFILE_MISMATCH"
    counts = payload.get("counts")
    required_counts = (
        "selected", "unique_selected", "duplicate_selections", "run",
        "failures", "errors", "skipped", "expected_failures",
        "unexpected_successes", "loader_failures",
    )
    if not isinstance(counts, dict) or any(
        not isinstance(counts.get(field), int)
        or isinstance(counts.get(field), bool)
        or counts[field] < 0
        for field in required_counts
    ):
        return payload, "TEST_EXECUTION_EVIDENCE_COUNTS_INVALID"
    if counts["run"] <= 0 or counts["selected"] <= 0:
        return payload, "TEST_EXECUTION_EVIDENCE_EMPTY"
    if (
        counts["unique_selected"] + counts["duplicate_selections"]
        != counts["selected"]
        or counts["run"] != counts["unique_selected"]
    ):
        return payload, "TEST_EXECUTION_EVIDENCE_SELECTION_MISMATCH"
    detail_fields = {
        "duplicate_selections": "duplicate_selections",
        "failures": "failures",
        "errors": "errors",
        "skipped": "skips",
        "expected_failures": "expected_failures",
        "unexpected_successes": "unexpected_successes",
        "loader_failures": "loader_failures",
    }
    if any(
        not isinstance(payload.get(field), list)
        or len(payload[field]) != counts[count]
        for count, field in detail_fields.items()
    ):
        return payload, "TEST_EXECUTION_EVIDENCE_DETAILS_MISMATCH"
    expected_skip_policy = {
        "quick": "allowlisted_only",
        "step5": "allowlisted_only",
        "blackbox": "forbidden",
        "whitebox": "allowlisted_only",
        "performance": "forbidden",
        "release": (
            "blackbox_performance_and_unallowlisted_whitebox_forbidden"
        ),
    }[profile]
    if payload.get("skip_policy") != expected_skip_policy:
        return payload, "TEST_EXECUTION_EVIDENCE_SKIP_POLICY_MISMATCH"
    if profile in {"quick", "step5"}:
        expected_allowed_skips = (
            QUICK_ALLOWED_SKIP_SELECTORS
            if profile == "quick" else STEP5_ALLOWED_SKIP_SELECTORS
        )
        if payload.get("allowed_skip_selectors") != list(
            expected_allowed_skips
        ):
            return payload, "TEST_EXECUTION_EVIDENCE_SKIP_ALLOWLIST_MISMATCH"
    passed = payload.get("status") == "passed"
    if passed != (returncode == 0):
        return payload, "TEST_EXECUTION_EVIDENCE_RETURN_CODE_MISMATCH"
    if passed and any(
        counts[field] for field in (
            "duplicate_selections", "failures", "errors",
            "expected_failures", "unexpected_successes", "loader_failures",
        )
    ):
        return payload, "TEST_EXECUTION_EVIDENCE_OUTCOME_MISMATCH"
    if passed and expected_skip_policy == "forbidden" and counts["skipped"]:
        return payload, "TEST_EXECUTION_EVIDENCE_OUTCOME_MISMATCH"
    return payload, ""


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
    output_path: str | Path | None = None,
) -> list[str]:
    root = Path(audit_root).expanduser().resolve()
    output = (
        Path(output_path).expanduser().resolve()
        if output_path is not None
        else root / "performance_result.json"
    )
    if evidence_mode == "recorded":
        return [
            sys.executable,
            str(Path(__file__).with_name("binary_performance_gate.py")),
            "--verify-recorded-gate", str(PERFORMANCE_GATE_PATH),
            "--output", str(output),
        ]
    if evidence_mode != "live":
        raise ValueError(f"unsupported performance evidence mode: {evidence_mode}")
    return [
        sys.executable,
        str(Path(__file__).with_name("binary_performance_gate.py")),
        "--work-root", str(root / "performance_work"),
        "--output", str(output),
        "--gate", str(PERFORMANCE_GATE_PATH),
    ]


def _jdk_home() -> Path:
    completed = run_managed_subprocess(
        ["java", "-XshowSettings:properties", "-version"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False,
        timeout=JDK_DISCOVERY_TIMEOUT_SECONDS,
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


def _run_bounded_subprocess(command, *, timeout_seconds, **kwargs):
    """Run a release-gate child with a finite tree-killing deadline."""

    try:
        return run_managed_subprocess(
            command,
            timeout=float(timeout_seconds),
            **kwargs,
        ), False
    except subprocess.TimeoutExpired as error:
        def decoded(value):
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            return value

        return subprocess.CompletedProcess(
            command,
            124,
            decoded(getattr(error, "stdout", None)),
            decoded(getattr(error, "stderr", None)),
        ), True


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
    audit_root = Path(args.audit_root).expanduser().resolve()
    test_execution_path = (
        audit_root / f"{args.profile}-test-execution-{os.getpid()}.json"
    )
    performance_path = (
        audit_root / f"performance-result-{os.getpid()}.json"
    )
    command = command_for(args.profile, json_out=str(test_execution_path))
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
            audit_root,
            evidence_mode=args.release_performance_mode,
            output_path=performance_path,
        )]
    if args.dry_run:
        print(" ".join(command))
        for release_command in release_commands:
            print(" ".join(release_command))
        return 0
    try:
        audit_root.mkdir(parents=True, exist_ok=True)
        test_execution_path.unlink(missing_ok=True)
        performance_path.unlink(missing_ok=True)
    except OSError as error:
        payload = {
            "schema": "java-upgrade-analyzer.binary-quality-gate.v2",
            "profile": args.profile,
            "status": "failed",
            "reason_code": "TEST_EXECUTION_EVIDENCE_PREPARE_FAILED",
            "detail": f"{type(error).__name__}: {error}",
        }
        if args.json_out:
            target = Path(args.json_out).resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        print(json.dumps(payload, ensure_ascii=False))
        return 2
    started = datetime.now(timezone.utc)
    subprocess_timeouts = []
    print(f"[binary-quality-gate] tests: {' '.join(command)}", flush=True)
    completed, tests_timed_out = _run_bounded_subprocess(
        command,
        timeout_seconds=TEST_TIMEOUT_SECONDS_BY_PROFILE[args.profile],
        check=False,
    )
    if tests_timed_out:
        subprocess_timeouts.append("tests")
    test_execution, test_execution_error = load_test_execution_evidence(
        test_execution_path,
        profile=args.profile,
        returncode=completed.returncode,
    )
    health = None
    health_returncode = 0
    real_project = None
    real_project_returncode = 0
    performance = None
    performance_returncode = 0
    if args.profile == "release":
        audit_root.mkdir(parents=True, exist_ok=True)
        print("[binary-quality-gate] test health: branch/mutation/repeat", flush=True)
        health_completed, health_timed_out = _run_bounded_subprocess(
            release_commands[0],
            timeout_seconds=TEST_HEALTH_TIMEOUT_SECONDS,
            check=False, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )
        if health_timed_out:
            subprocess_timeouts.append("test_health")
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
            real_completed, real_timed_out = _run_bounded_subprocess(
                real_command,
                timeout_seconds=REAL_PROJECT_TIMEOUT_SECONDS,
                check=False, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
            )
            if real_timed_out:
                subprocess_timeouts.append(f"real_project:{manifest.stem}")
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
        performance_completed, performance_timed_out = _run_bounded_subprocess(
            release_commands[-1],
            timeout_seconds=(
                LIVE_PERFORMANCE_TIMEOUT_SECONDS
                if args.release_performance_mode == "live"
                else RECORDED_PERFORMANCE_TIMEOUT_SECONDS
            ),
            check=False, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )
        if performance_timed_out:
            subprocess_timeouts.append("performance")
        performance_returncode = performance_completed.returncode
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
        or (4 if test_execution_error else 0)
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
        "test_execution": test_execution,
        "test_execution_evidence_error": test_execution_error,
        "started_at": started.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "engine": "binary_first",
        "capability_migration": migration,
        "test_health": health,
        "real_project": real_project,
        "performance": performance,
        "subprocess_timeouts": subprocess_timeouts,
    }
    if args.json_out:
        target = Path(args.json_out).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False))
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
