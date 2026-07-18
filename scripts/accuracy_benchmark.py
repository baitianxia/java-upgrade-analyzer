#!/usr/bin/env python3
"""Run the explicit accuracy benchmark matrix for java-upgrade-analyzer.

This runner intentionally reuses focused regression tests instead of adding a
new assertion layer. Its job is to make the high-risk semantic contracts visible
and repeatable: when Step4/Step5 changes, reviewers can run one command and see
which accuracy dimension is being protected.
"""

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class BenchmarkCategory:
    name: str
    purpose: str
    tests: tuple


@dataclass
class BenchmarkResult:
    name: str
    status: str
    elapsed_sec: float
    returncode: int
    purpose: str
    tests: list


BENCHMARK_CATEGORIES = (
    BenchmarkCategory(
        name="jdeps_floor",
        purpose="jdeps 能发现的跨 JAR 类依赖，Skill 的字节码扫描不得漏掉",
        tests=(
            "tests.test_artifact_bytecode_catalog.ArtifactBytecodeCatalogTest.test_every_reference_found_by_jdeps_is_visible_to_upgrade_scanner",
        ),
    ),
    BenchmarkCategory(
        name="bytecode_symbol_visibility",
        purpose="直接调用、反射、方法引用、多版本 JAR、嵌套 JAR 都能进入目标符号证据池",
        tests=(
            "tests.test_artifact_bytecode_catalog.ArtifactBytecodeCatalogTest.test_reflection_bytecode_is_visible_to_upgrade_scanner",
            "tests.test_artifact_bytecode_catalog.ArtifactBytecodeCatalogTest.test_method_reference_bytecode_is_visible_to_upgrade_scanner",
            "tests.test_artifact_bytecode_catalog.ArtifactBytecodeCatalogTest.test_direct_method_bytecode_uses_constant_pool_fast_path_without_javap",
            "tests.test_artifact_bytecode_catalog.ArtifactBytecodeCatalogTest.test_javap_parser_resolves_lambda_method_handle_target",
            "tests.test_artifact_bytecode_catalog.ArtifactBytecodeCatalogTest.test_multi_release_jar_uses_effective_target_jdk_entry",
            "tests.test_artifact_bytecode_catalog.ArtifactBytecodeCatalogTest.test_catalog_uses_exact_nested_jar_and_business_classes_from_current_artifact",
        ),
    ),
    BenchmarkCategory(
        name="source_owner_and_signature_precision",
        purpose="源码 owner/import/package/static import/signature/重载解析不能因 simple name 或 raw edge 误判",
        tests=(
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_trace_api_respects_import_owner_for_simple_static_field_access",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_trace_api_marks_same_package_simple_static_field_access_as_reachable",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_trace_api_respects_static_import_owner_for_field_access",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_trace_api_does_not_mix_in_raw_edges_from_other_overloads",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_trace_api_still_blocks_raw_edge_when_target_has_multiple_declared_overloads",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_trace_api_uses_builtin_java_assignable_signature_for_target_overload",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_select_compatible_overload_signatures_supports_varargs_target",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_build_graph_infers_chained_string_return_for_url_valueof",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_trace_api_reaches_primitive_array_parameter_without_losing_array_suffix",
        ),
    ),
    BenchmarkCategory(
        name="runtime_bytecode_reachability",
        purpose="删除/升级依赖时，业务字节码与运行时依赖 JAR 的多跳链路必须被发现并正确区分可达/不可达",
        tests=(
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_trace_api_uses_packaged_bytecode_fallback_when_dependency_source_mapping_missing",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_removed_dependency_scans_runtime_consumers_even_when_target_source_mapping_exists",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_packaged_bytecode_keeps_every_consuming_method_for_manual_review",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_packaged_dependency_hit_is_reachable_when_business_bytecode_calls_consumer",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_runtime_dependency_bytecode_graph_connects_business_to_transitive_packaged_hit",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_runtime_dependency_bytecode_graph_connects_three_hop_packaged_hit",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_deleted_commons_lang_many_runtime_jars_reaches_business_via_dependency_chain",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_runtime_dependency_bytecode_graph_does_not_infer_unconnected_packaged_hit",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_runtime_dependency_bytecode_graph_does_not_cross_wrong_overload",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_runtime_dependency_bytecode_graph_connects_business_to_changed_field_hit",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_version_upgrade_scans_runtime_consumers_even_when_target_source_mapping_exists",
        ),
    ),
    BenchmarkCategory(
        name="packaged_scan_resilience",
        purpose="批量 JAR 扫描要复用 javap、保留反射候选，并在单个候选失败时不污染其他 API",
        tests=(
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_batch_packaged_bytecode_scan_reuses_javap_across_apis",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_batch_packaged_bytecode_skips_owner_and_member_string_constants_without_reflection",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_batch_packaged_bytecode_keeps_reflection_string_candidates_for_javap",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_packaged_consumer_scan_continues_after_one_javap_failure",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_packaged_consumer_scan_does_not_report_miss_when_any_candidate_failed",
        ),
    ),
    BenchmarkCategory(
        name="indirect_usage",
        purpose="反射、MethodHandle、表达式语言等间接引用必须进入 Step5，而不是被静默当成未命中",
        tests=(
            "tests.test_indirect_usage_analyzer.IndirectUsageAnalyzerTest.test_exact_reflection_chain_becomes_reachable_step5_edge",
            "tests.test_indirect_usage_analyzer.IndirectUsageAnalyzerTest.test_local_variables_are_correlated_for_reflection",
            "tests.test_indirect_usage_analyzer.IndirectUsageAnalyzerTest.test_dynamic_member_for_known_owner_is_uncertain_not_static_miss",
            "tests.test_indirect_usage_analyzer.IndirectUsageAnalyzerTest.test_static_method_handle_is_merged_when_target_is_exact",
            "tests.test_indirect_usage_analyzer.IndirectUsageAnalyzerTest.test_method_handle_variable_tracks_constructor_and_field_targets",
            "tests.test_indirect_usage_analyzer.IndirectUsageAnalyzerTest.test_reflection_constructor_and_field_are_normalized_to_step4_targets",
            "tests.test_indirect_usage_analyzer.IndirectUsageAnalyzerTest.test_expression_language_reference_is_uncertain_and_recorded_in_coverage",
        ),
    ),
    BenchmarkCategory(
        name="alerts_ledger",
        purpose="alerts.csv 是完整链路台账：保留不同入口、合并等价路径、输出无路径 API、生成拆分文件",
        tests=(
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_alerts_csv_is_complete_path_ledger_with_explicit_consumers",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_alerts_csv_suppresses_only_suffix_paths_covered_by_longer_paths",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_alerts_csv_deduplicates_equivalent_paths_but_keeps_distinct_entries",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_alerts_csv_writes_review_split_files_without_replacing_main_file",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_alerts_review_split_files_are_chunked_and_stale_files_removed",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_alert_row_uses_path_stop_reason_instead_of_api_reason",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_alerts_csv_keeps_api_without_any_path",
        ),
    ),
    BenchmarkCategory(
        name="summary_and_final_report",
        purpose="Step5/S6 汇总结论必须保持四态语义，不把 probable/needs-input 混进无影响",
        tests=(
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_summarize_user_facing_outcome_maps_to_simple_conclusions",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_summarize_user_facing_outcome_treats_behavior_changed_fallback_simple_as_inconclusive",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_summarize_user_facing_outcome_explains_new_step5_precision_reason_codes",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_generate_enhanced_summary_outputs_user_conclusion_counts_without_low_value_text_summary",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_s6_report_matches_by_api_using_signature_and_expands_not_found_items",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_s6_report_starts_with_concrete_impact_overview_from_alerts",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_s6_report_keeps_probable_impact_and_needs_input_out_of_uncovered_section",
            "tests.test_step5_key_matching.Step5KeyMatchingTest.test_s6_report_reads_per_dependency_summary_and_renders_dependency_conclusion_table",
        ),
    ),
)


PROFILE_CATEGORIES = {
    "core": (
        "jdeps_floor",
        "runtime_bytecode_reachability",
        "indirect_usage",
        "alerts_ledger",
    ),
    "step5": (
        "jdeps_floor",
        "bytecode_symbol_visibility",
        "source_owner_and_signature_precision",
        "runtime_bytecode_reachability",
        "packaged_scan_resilience",
        "indirect_usage",
        "alerts_ledger",
        "summary_and_final_report",
    ),
    "all": tuple(category.name for category in BENCHMARK_CATEGORIES),
}


def _category_by_name():
    return {category.name: category for category in BENCHMARK_CATEGORIES}


def build_plan(profile):
    try:
        names = PROFILE_CATEGORIES[profile]
    except KeyError as exc:
        raise ValueError(f"unknown profile: {profile}") from exc
    categories = _category_by_name()
    return [categories[name] for name in names]


def validate_matrix():
    category_names = [category.name for category in BENCHMARK_CATEGORIES]
    if len(category_names) != len(set(category_names)):
        raise ValueError("duplicate benchmark category name")

    all_tests = [test for category in BENCHMARK_CATEGORIES for test in category.tests]
    duplicates = sorted({test for test in all_tests if all_tests.count(test) > 1})
    if duplicates:
        raise ValueError(f"duplicate benchmark test id(s): {duplicates}")

    known = set(category_names)
    for profile, names in PROFILE_CATEGORIES.items():
        missing = sorted(set(names) - known)
        if missing:
            raise ValueError(f"profile {profile} references unknown categories: {missing}")


def _write_json(path, payload):
    if not path:
        return
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _run_category(category, python_exe):
    started = time.perf_counter()
    command = [python_exe, "-m", "unittest", *category.tests]
    print(f"[accuracy-benchmark] START {category.name}: {len(category.tests)} tests", flush=True)
    completed = subprocess.run(command, cwd=str(ROOT))
    elapsed = time.perf_counter() - started
    status = "passed" if completed.returncode == 0 else "failed"
    print(
        f"[accuracy-benchmark] {status.upper()} {category.name} "
        f"elapsed={elapsed:.2f}s rc={completed.returncode}",
        flush=True,
    )
    return BenchmarkResult(
        name=category.name,
        status=status,
        elapsed_sec=round(elapsed, 3),
        returncode=completed.returncode,
        purpose=category.purpose,
        tests=list(category.tests),
    )


def _plan_payload(profile, categories, dry_run):
    return {
        "profile": profile,
        "dry_run": dry_run,
        "categories": [
            {
                "name": category.name,
                "purpose": category.purpose,
                "test_count": len(category.tests),
                "tests": list(category.tests),
            }
            for category in categories
        ],
        "total_tests": sum(len(category.tests) for category in categories),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run explicit java-upgrade-analyzer accuracy benchmarks")
    parser.add_argument("--profile", choices=sorted(PROFILE_CATEGORIES), default="core")
    parser.add_argument(
        "--category",
        choices=sorted(_category_by_name()),
        default="",
        help="Run one benchmark category for platform diagnostics",
    )
    parser.add_argument("--python", default=sys.executable, help="Python executable used by unittest")
    parser.add_argument("--dry-run", action="store_true", help="Print benchmark matrix without executing tests")
    parser.add_argument("--list", action="store_true", help="Alias for --dry-run")
    parser.add_argument("--continue-on-failure", action="store_true", help="Run remaining categories after a failure")
    parser.add_argument("--json-out", default="", help="Write structured benchmark result to JSON")
    args = parser.parse_args(argv)

    validate_matrix()
    categories = (
        [_category_by_name()[args.category]]
        if args.category else build_plan(args.profile)
    )
    selection = f"category:{args.category}" if args.category else args.profile

    if args.dry_run or args.list:
        payload = _plan_payload(selection, categories, dry_run=True)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        _write_json(args.json_out, payload)
        return 0

    started = time.perf_counter()
    results = []
    overall = "passed"
    for category in categories:
        result = _run_category(category, args.python)
        results.append(result)
        if result.status != "passed":
            overall = "failed"
            if not args.continue_on_failure:
                break

    payload = {
        "profile": selection,
        "status": overall,
        "elapsed_sec": round(time.perf_counter() - started, 3),
        "results": [asdict(result) for result in results],
        "skipped_categories": [
            {
                "name": category.name,
                "purpose": category.purpose,
                "tests": list(category.tests),
            }
            for category in categories[len(results):]
        ],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    _write_json(args.json_out, payload)
    return 0 if overall == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
