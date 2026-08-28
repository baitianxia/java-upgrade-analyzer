#!/usr/bin/env python3
"""Source-bound acceptance policy for recorded Step4 performance evidence.

Recorded measurements are observations, never their own specification.  This
module is deliberately part of the performance harness source closure so a
policy change requires new evidence and a new source implementation identity.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from binary_first_contract import canonical_identity


POLICY_SCHEMA = "java-upgrade-analyzer.binary-performance-release-policy.v1"
DATASET_SCHEMA = "binary-performance-scale-400x250-fixed-template-v2"
FULL_PIPELINE_PHASES = (
    "static_preflight",
    "input_and_runtime_profile",
    "artifact_fact_build_and_local_diff",
    "target_independent_runtime_reconciliation",
    "decision_and_projection_freeze",
    "binary_trace",
    "immutable_generation_write",
    "independent_validation",
    "validated_generation_activation",
)
VALIDATED_GENERATION_ACTIVATION_SCOPE = (
    "activate_plus_mode_applicable_candidate_discard_or_recapture_seal_and_"
    "discard_plus_durable_checkpoint_finalization_v1"
)


def _policy_payload() -> dict[str, Any]:
    jar_count = 400
    classes_per_jar = 250
    class_count = jar_count * classes_per_jar
    return {
        "schema": POLICY_SCHEMA,
        "measurement_protocol": {
            "dataset_schema": DATASET_SCHEMA,
            "dataset_identity": (
                "6962cc11f071be24f03a59bc8b24048e1df1838632cc5fbfa"
                "50af7e6f8eaaa5d"
            ),
            "base_template_sha256": (
                "d399daf3228dca8d6a46b829b5b72ca287beb8d68f035386"
                "1121d509b4c91fed"
            ),
            "changed_template_sha256": (
                "d203be05ee7d26c466b189ed7d03b57db122b89ce9af668f"
                "cbcf1fb2f97b53a7"
            ),
            "first_base_artifact_identity": (
                "458117d414064fa591bd29ffd22b4ad05c0ceafcd472d6033"
                "f23f3a43e4d958f"
            ),
            "jar_count": jar_count,
            "class_count": class_count,
            "classes_per_jar": classes_per_jar,
            "large_api_query_count": 10_000,
            "warmup_runs": 1,
            "sample_runs": {
                "cold": 1,
                "warm": 3,
                "legacy": 1,
                "full_pipeline": 1,
                "changed_full_pipeline": 1,
            },
            "p50_method": "nearest-rank",
            "p95_method": "nearest-rank",
            "cold_cleanup_rule": (
                "delete binary snapshot cache and SQLite before run"
            ),
            "warm_cache_rule": (
                "all content+parser cache entries must pass digest validation; "
                "parser_invocations=0"
            ),
            "rss_sample_semantics": {
                "cold_warm_legacy_process_scope": (
                    "one benchmark process lifetime; cumulative high-water "
                    "snapshots include prior fixture preparation, the "
                    "unmeasured warmup, and all measured samples"
                ),
                "component_rule": (
                    "max(self_high_water, completed_children_high_water); "
                    "not a concurrent process-tree sum"
                ),
                "sample_order": [
                    "warmup", "cold", "warm[0]", "warm[1]", "warm[2]",
                    "legacy",
                ],
                "isolated_probe_scope": "one dedicated Python process per probe",
            },
            "legacy_baseline": (
                "javap -c -s -p, all 100000 classes, "
                "batched once per artifact"
            ),
            "full_pipeline_probe": {
                "jar_count": jar_count,
                "class_count": class_count,
                "comparison": "identical-base-current-cold-output",
                "process_isolation": "dedicated_python_process",
                "includes": list(FULL_PIPELINE_PHASES),
                "validated_generation_activation_scope": (
                    VALIDATED_GENERATION_ACTIVATION_SCOPE
                ),
            },
            "changed_full_pipeline_probe": {
                "jar_count": jar_count,
                "class_count": class_count,
                "comparison": "nonidentical-base-current-cold-output",
                "process_isolation": "dedicated_python_process",
                "changed_jar_count": 1,
                "changed_class_count": classes_per_jar,
                "current_artifact_identity": (
                    "d56f3ff0f26020eaadb14464cb30edbd9b18a97504feffbb"
                    "bc6694b525e19d4d"
                ),
                "logical_artifact_derivation_identity": (
                    "8eda832f9cd509a27f67eb968e3b54c56fbeb230d3f943ce"
                    "adab27710a12f39a"
                ),
                "includes": list(FULL_PIPELINE_PHASES),
                "validated_generation_activation_scope": (
                    VALIDATED_GENERATION_ACTIVATION_SCOPE
                ),
            },
        },
        "reference_runtime": {
            "schema": (
                "java-upgrade-analyzer."
                "binary-performance-reference-runtime.v1"
            ),
            "machine_identity": (
                "c405233ee64bf64dfba5d4b5733f82ff2b7b4dcaefd0f4fd"
                "95b8ae596135e69c"
            ),
            "machine": {
                "platform": "macOS-26.5.1-arm64-arm-64bit-Mach-O",
                "machine": "arm64",
                "processor": "arm",
                "logical_cpu_count": 12,
            },
            "python_implementation": "CPython",
            "tool_versions": {
                "python": "3.14.6",
                "java": "openjdk version \"21.0.8\" 2025-07-15",
                "javap": "21.0.8",
                "asm_jar_sha256": (
                    "6f3828a215c920059a5efa2fb55c233d6c54ec5cadca99ce"
                    "1b1bdd10077c7ddd"
                ),
            },
            "jdk_preflight_identity": (
                "22cfe5bc79c4f6b6d69a2db9ab063a8af413ca576dea56e9"
                "02c843a6b1d6c135"
            ),
            "cpu_time_source": (
                "resource.getrusage(self+completed_children)"
            ),
            "peak_rss_source": (
                "resource.getrusage(self+completed_children)"
            ),
        },
        "reference_implementation": {
            "schema": (
                "java-upgrade-analyzer."
                "binary-performance-reference-implementation.v1"
            ),
            # These runtime-sensitive components are captured on the reference
            # host after the measured source is frozen.  The formal replay
            # combines them with the live source identity and the source-bound
            # reference JDK identity to derive the complete runtime identity.
            "pipeline_generation_implementation_identity": (
                "194c8b7c9a3363bf230c65a4fa8bea60fc9d46369fca5226112dbdc4"
                "61ac30ba"
            ),
            "validator_implementation_identity": (
                "ac3fade2b88926b4c290cbf6bfddc8676e25de7797abc029e203fc711"
                "73be485"
            ),
        },
        "thresholds": {
            "cold_end_to_end_seconds": 170.0,
            "warm_end_to_end_p50_seconds": 65.0,
            "warm_end_to_end_p95_seconds": 75.0,
            "full_pipeline_end_to_end_seconds": 400.0,
            "full_pipeline_peak_rss_bytes": 2 * 1024 * 1024 * 1024,
            "full_pipeline_phase_seconds": {
                "static_preflight": 2.0,
                "input_and_runtime_profile": 1.0,
                "artifact_fact_build_and_local_diff": 160.0,
                "target_independent_runtime_reconciliation": 105.0,
                "decision_and_projection_freeze": 3.5,
                "binary_trace": 0.5,
                "immutable_generation_write": 3.5,
                "independent_validation": 140.0,
                "validated_generation_activation": 1.5,
            },
            # dd25c1f's independently recaptured changed 400-JAR pipeline was
            # 266.6166238752194s.  The optimization is releasable only when
            # the same source-bound workload is at least 50% faster.
            "changed_full_pipeline_end_to_end_seconds": 133.308,
            "changed_full_pipeline_peak_rss_bytes": 3 * 1024 * 1024 * 1024,
            "changed_full_pipeline_phase_seconds": {
                "static_preflight": 2.0,
                "input_and_runtime_profile": 1.0,
                "artifact_fact_build_and_local_diff": 170.0,
                "target_independent_runtime_reconciliation": 165.0,
                "decision_and_projection_freeze": 30.0,
                "binary_trace": 1.0,
                "immutable_generation_write": 3.5,
                "independent_validation": 170.0,
                "validated_generation_activation": 1.5,
            },
            "stage_p95_seconds": {
                "inventory": 0.3,
                "parse_and_cache": 110.0,
                "db_write_and_index": 65.0,
                "batch_query_10000": 0.4,
                "report_10000": 0.05,
            },
            "peak_rss_bytes": 3 * 1024 * 1024 * 1024,
            "disk_bytes": 1024 * 1024 * 1024,
            "bytes_per_class": 11_000,
            "bytes_per_edge": 2_700,
            "cold_relative_legacy_ratio": 2.25,
            "warm_relative_legacy_ratio": 1.0,
        },
        "accuracy_invariants": {
            "expected_class_count": class_count,
            "expected_member_count": 300_000,
            "expected_edge_count": 400_000,
            "warmup_expected_class_count": class_count,
            "warmup_expected_parser_invocations": jar_count,
            "warmup_expected_cache_hits": 0,
            "warm_parser_invocations": 0,
            "full_pipeline_expected_class_count": class_count,
            "full_pipeline_expected_parser_invocations": jar_count,
            "full_pipeline_expected_artifact_snapshot_hits": 0,
            "full_pipeline_validation_issue_count": 0,
            "full_pipeline_expected_authoritative_change_fact_count": 0,
            "full_pipeline_expected_formal_api_result_count": 0,
            "full_pipeline_expected_authoritative_member_change_kind_counts": {},
            "full_pipeline_expected_formal_reachability_status_counts": {},
            "full_pipeline_expected_formal_impact_conclusion_counts": {},
            "changed_full_pipeline_expected_class_count": class_count,
            "changed_full_pipeline_expected_parser_invocations": jar_count + 1,
            "changed_full_pipeline_expected_artifact_snapshot_hits": (
                jar_count - 1
            ),
            "changed_full_pipeline_validation_issue_count": 0,
            "changed_full_pipeline_expected_authoritative_change_fact_count": (
                classes_per_jar
            ),
            "changed_full_pipeline_expected_formal_api_result_count": (
                classes_per_jar
            ),
            "changed_full_pipeline_expected_authoritative_member_change_kind_counts": {
                "implementation_changed": classes_per_jar,
            },
            "changed_full_pipeline_expected_formal_reachability_status_counts": {
                "not_found_in_static_analysis": classes_per_jar,
            },
            "changed_full_pipeline_expected_formal_impact_conclusion_counts": {
                "inconclusive": classes_per_jar,
            },
            "cache_digest_validation_required": True,
            "class_or_edge_reduction_allowed": False,
        },
    }


def release_policy() -> dict[str, Any]:
    """Return a defensive copy of the immutable source policy."""

    return deepcopy(_policy_payload())


def release_policy_identity() -> str:
    return canonical_identity(
        "binary_performance_release_policy_identity",
        _policy_payload(),
        schema_version="1",
    )


__all__ = [
    "DATASET_SCHEMA",
    "FULL_PIPELINE_PHASES",
    "POLICY_SCHEMA",
    "VALIDATED_GENERATION_ACTIVATION_SCOPE",
    "release_policy",
    "release_policy_identity",
]
