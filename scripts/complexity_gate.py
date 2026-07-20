#!/usr/bin/env python3
"""Correctness-first complexity and resource budget evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import statistics
import subprocess
import time
import zipfile

from data_contract_analysis import compare_jar_data_contracts
from generated_topology import GenerationDimensions, generate_topology
from generated_topology_regression import run_generated_case
from s1_dep_diff import collect_packaged_deps_from_artifact_path
from step1_observability import peak_rss_mb


REQUIRED_METRICS = (
    "elapsed_sec",
    "peak_rss_mb",
    "temporary_bytes",
    "archive_scans",
    "parsed_classes",
    "javap_calls",
    "cache_hits",
    "per_api_latency_ms",
    "duplicate_work_keys",
)
REQUIRED_STAGE_METRICS = REQUIRED_METRICS
TIMING_TRIALS = 3


@dataclass(frozen=True)
class ComplexityVerdict:
    status: str
    errors: tuple[str, ...]
    tiers_checked: int


def evaluate_scale_tiers(tiers: list[dict], budgets: dict) -> ComplexityVerdict:
    errors = []
    invalid = False
    ordered = sorted(tiers, key=lambda tier: int(tier.get("scale") or 0))
    for tier in ordered:
        scale = int(tier.get("scale") or 0)
        truth = list(tier.get("truth_identities") or ())
        observed = list(tier.get("observed_identities") or ())
        if len(observed) != len(set(observed)):
            errors.append(f"duplicate_scope_identity:{scale}")
            invalid = True
        if set(truth) != set(observed):
            errors.append(f"scope_identity_mismatch:{scale}")
            invalid = True
        metrics = tier.get("metrics") or {}
        for name in REQUIRED_METRICS:
            if name not in metrics:
                errors.append(f"missing_metric:{scale}:{name}")
                invalid = True
        trials = tier.get("trials")
        if trials is not None:
            if (
                not isinstance(trials, list)
                or len(trials) < TIMING_TRIALS
                or len(trials) % 2 == 0
            ):
                errors.append(f"invalid_timing_trial_count:{scale}")
                invalid = True
                continue
            elapsed_samples = []
            for trial_index, trial in enumerate(trials, start=1):
                if not isinstance(trial, dict):
                    errors.append(f"invalid_timing_trial:{scale}:{trial_index}")
                    invalid = True
                    continue
                trial_truth = list(trial.get("truth_identities") or ())
                trial_observed = list(trial.get("observed_identities") or ())
                if len(trial_observed) != len(set(trial_observed)):
                    errors.append(
                        f"trial_duplicate_scope_identity:{scale}:{trial_index}"
                    )
                    invalid = True
                if set(trial_truth) != set(trial_observed):
                    errors.append(
                        f"trial_scope_identity_mismatch:{scale}:{trial_index}"
                    )
                    invalid = True
                if set(trial_truth) != set(truth):
                    errors.append(
                        f"trial_truth_identity_mismatch:{scale}:{trial_index}"
                    )
                    invalid = True
                trial_metrics = trial.get("metrics") or {}
                for name in REQUIRED_METRICS:
                    if name not in trial_metrics:
                        errors.append(
                            f"trial_missing_metric:{scale}:{trial_index}:{name}"
                        )
                        invalid = True
                if "elapsed_sec" in trial_metrics:
                    elapsed_samples.append(float(trial_metrics["elapsed_sec"]))
            if len(elapsed_samples) == len(trials) and "elapsed_sec" in metrics:
                if float(metrics["elapsed_sec"]) != float(
                    statistics.median(elapsed_samples)
                ):
                    errors.append(f"trial_elapsed_median_mismatch:{scale}")
                    invalid = True
    if invalid:
        return ComplexityVerdict("invalid", tuple(errors), len(ordered))

    absolute = budgets.get("absolute") or {}
    ratios = budgets.get("adjacent_ratio") or {}
    for tier in ordered:
        scale = int(tier["scale"])
        metrics = tier["metrics"]
        for key in metrics.get("duplicate_work_keys") or ():
            errors.append(f"duplicate_work:{key}")
        for metric in ("peak_rss_mb", "per_api_latency_ms"):
            limit = absolute.get(metric)
            if limit is not None and float(metrics[metric]) > float(limit):
                errors.append(f"absolute_budget_exceeded:{metric}:{scale}")
        api_count = max(1, len(tier["truth_identities"]))
        javap_per_api = float(metrics["javap_calls"]) / api_count
        if javap_per_api > float(absolute.get("javap_calls_per_api", javap_per_api)):
            errors.append(f"absolute_budget_exceeded:javap_calls_per_api:{scale}")
    for previous, current in zip(ordered, ordered[1:]):
        for metric, limit in ratios.items():
            before = float(previous["metrics"][metric])
            after = float(current["metrics"][metric])
            ratio = after / before if before else (float("inf") if after else 1.0)
            if ratio > float(limit):
                errors.append(
                    f"ratio_budget_exceeded:{metric}:{previous['scale']}->{current['scale']}"
                )
    return ComplexityVerdict("failed" if errors else "passed", tuple(errors), len(ordered))


def evaluate_production_stage_tiers(
    tiers: list[dict], budgets: dict
) -> ComplexityVerdict:
    ordered = sorted(tiers, key=lambda tier: int(tier.get("scale") or 0))
    errors = []
    invalid = False
    for tier in ordered:
        scale = int(tier.get("scale") or 0)
        stages = tier.get("stages") or {}
        for stage_name in ("step1", "step4", "step5"):
            stage = stages.get(stage_name)
            if not isinstance(stage, dict):
                errors.append(f"stage_missing:{stage_name}:{scale}")
                invalid = True
                continue
            truth = list(stage.get("truth_identities") or ())
            observed = list(stage.get("observed_identities") or ())
            if len(observed) != len(set(observed)):
                errors.append(f"stage_duplicate_identity:{stage_name}:{scale}")
                invalid = True
            if set(truth) != set(observed):
                errors.append(f"stage_scope_identity_mismatch:{stage_name}:{scale}")
                invalid = True
            if int(stage.get("scope_count") or 0) != scale:
                errors.append(f"stage_scope_count_mismatch:{stage_name}:{scale}")
                invalid = True
            if "elapsed_sec" not in stage:
                errors.append(f"stage_metric_missing:{stage_name}:{scale}:elapsed_sec")
                invalid = True
            metrics = stage.get("metrics") or {}
            for metric_name in REQUIRED_STAGE_METRICS:
                if metric_name not in metrics:
                    errors.append(
                        f"stage_metric_missing:{stage_name}:{scale}:{metric_name}"
                    )
                    invalid = True
            trials = stage.get("trials")
            if trials is not None:
                if (
                    not isinstance(trials, list)
                    or len(trials) < TIMING_TRIALS
                    or len(trials) % 2 == 0
                ):
                    errors.append(
                        f"stage_invalid_timing_trial_count:{stage_name}:{scale}"
                    )
                    invalid = True
                    continue
                elapsed_samples = []
                for trial_index, trial in enumerate(trials, start=1):
                    if not isinstance(trial, dict):
                        errors.append(
                            f"stage_invalid_timing_trial:{stage_name}:"
                            f"{scale}:{trial_index}"
                        )
                        invalid = True
                        continue
                    trial_truth = list(trial.get("truth_identities") or ())
                    trial_observed = list(
                        trial.get("observed_identities") or ()
                    )
                    if len(trial_observed) != len(set(trial_observed)):
                        errors.append(
                            f"stage_trial_duplicate_identity:{stage_name}:"
                            f"{scale}:{trial_index}"
                        )
                        invalid = True
                    if set(trial_truth) != set(trial_observed):
                        errors.append(
                            f"stage_trial_scope_identity_mismatch:{stage_name}:"
                            f"{scale}:{trial_index}"
                        )
                        invalid = True
                    if set(trial_truth) != set(truth):
                        errors.append(
                            f"stage_trial_truth_identity_mismatch:{stage_name}:"
                            f"{scale}:{trial_index}"
                        )
                        invalid = True
                    trial_metrics = trial.get("metrics") or {}
                    for metric_name in REQUIRED_STAGE_METRICS:
                        if metric_name not in trial_metrics:
                            errors.append(
                                f"stage_trial_metric_missing:{stage_name}:"
                                f"{scale}:{trial_index}:{metric_name}"
                            )
                            invalid = True
                    if "elapsed_sec" in trial_metrics:
                        elapsed_samples.append(
                            float(trial_metrics["elapsed_sec"])
                        )
                if (
                    len(elapsed_samples) == len(trials)
                    and "elapsed_sec" in metrics
                    and float(stage["elapsed_sec"])
                    != float(statistics.median(elapsed_samples))
                ):
                    errors.append(
                        f"stage_trial_elapsed_median_mismatch:"
                        f"{stage_name}:{scale}"
                    )
                    invalid = True
    if invalid:
        return ComplexityVerdict("invalid", tuple(errors), len(ordered))

    absolute = budgets.get("stage_absolute") or {}
    for tier in ordered:
        scale = int(tier["scale"])
        for stage_name in ("step1", "step4", "step5"):
            metrics = tier["stages"][stage_name]["metrics"]
            for key in metrics.get("duplicate_work_keys") or ():
                errors.append(f"stage_duplicate_work:{stage_name}:{key}")
            for metric_name in ("peak_rss_mb", "per_api_latency_ms"):
                limit_value = absolute.get(metric_name)
                if (
                    limit_value is not None
                    and float(metrics[metric_name]) > float(limit_value)
                ):
                    errors.append(
                        f"stage_absolute_budget_exceeded:{stage_name}:"
                        f"{metric_name}:{scale}"
                    )
            javap_per_scope = float(metrics["javap_calls"]) / max(1, scale)
            javap_limit = absolute.get("javap_calls_per_scope")
            if javap_limit is not None and javap_per_scope > float(javap_limit):
                errors.append(
                    f"stage_absolute_budget_exceeded:{stage_name}:"
                    f"javap_calls_per_scope:{scale}"
                )
    limit = float(
        (budgets.get("stage_adjacent_ratio") or {}).get("elapsed_sec") or 3.0
    )
    for previous, current in zip(ordered, ordered[1:]):
        for stage_name in ("step1", "step4", "step5"):
            before = float(previous["stages"][stage_name]["elapsed_sec"])
            after = float(current["stages"][stage_name]["elapsed_sec"])
            ratio = after / before if before else (float("inf") if after else 1.0)
            if ratio > limit:
                errors.append(
                    f"stage_ratio_budget_exceeded:{stage_name}:elapsed_sec:"
                    f"{previous['scale']}->{current['scale']}"
                )
    return ComplexityVerdict(
        "failed" if errors else "passed", tuple(errors), len(ordered)
    )


def _tree_bytes(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def _aggregate_trial_metrics(
    trials: list[dict], *, latency_scope_count: int
) -> dict:
    trial_metrics = [trial["metrics"] for trial in trials]
    elapsed = float(statistics.median(
        float(metrics["elapsed_sec"]) for metrics in trial_metrics
    ))
    duplicate_work_keys = sorted({
        str(key)
        for metrics in trial_metrics
        for key in (metrics.get("duplicate_work_keys") or ())
    })
    aggregated = {
        "elapsed_sec": elapsed,
        "elapsed_samples_sec": [
            float(metrics["elapsed_sec"]) for metrics in trial_metrics
        ],
        "peak_rss_mb": max(
            float(metrics["peak_rss_mb"]) for metrics in trial_metrics
        ),
        "temporary_bytes": max(
            int(metrics["temporary_bytes"]) for metrics in trial_metrics
        ),
        "archive_scans": max(
            int(metrics["archive_scans"]) for metrics in trial_metrics
        ),
        "parsed_classes": max(
            int(metrics["parsed_classes"]) for metrics in trial_metrics
        ),
        "javap_calls": max(
            int(metrics["javap_calls"]) for metrics in trial_metrics
        ),
        "cache_hits": max(
            int(metrics["cache_hits"]) for metrics in trial_metrics
        ),
        "per_api_latency_ms": elapsed * 1000 / max(1, latency_scope_count),
        "duplicate_work_keys": duplicate_work_keys,
    }
    if any("edges_found" in metrics for metrics in trial_metrics):
        aggregated["edges_found"] = max(
            int(metrics.get("edges_found") or 0) for metrics in trial_metrics
        )
    return aggregated


def run_generated_scale_tiers(
    repo_root: Path, report_root: Path, *, scales: tuple[int, ...]
) -> list[dict]:
    del repo_root  # The production modules are imported from the current checkout.
    report_root = Path(report_root)
    trials_by_scale = {scale: [] for scale in scales}
    for trial_index in range(1, TIMING_TRIALS + 1):
        for scale in scales:
            trial_root = (
                report_root / f"scale-{scale}" / f"trial-{trial_index}"
            )
            truth_identities = []
            observed_identities = []
            parsed_classes = 0
            javap_calls = 0
            cache_hits = 0
            edge_count = 0
            started = time.perf_counter()
            for index in range(scale):
                seed = 10_000 + index
                case = generate_topology(seed, GenerationDimensions.complete())
                result = run_generated_case(
                    case, trial_root / f"case-{index}"
                )
                identities = [
                    f"{seed}:{edge.identity}" for edge in case.spec.truth_edges
                ]
                truth_identities.extend(identities)
                if result.status == "passed":
                    observed_identities.extend(identities)
                result_metrics = result.production_metrics
                parsed_classes += int(
                    result_metrics.get("classes_scanned") or 0
                )
                javap_calls += int(
                    result_metrics.get("javap_fallback_classes") or 0
                )
                cache_hits += int(bool(result_metrics.get("cache_hit")))
                edge_count += int(result_metrics.get("edges_found") or 0)
            elapsed = time.perf_counter() - started
            api_count = max(1, len(truth_identities))
            trials_by_scale[scale].append({
                "trial": trial_index,
                "truth_identities": truth_identities,
                "observed_identities": observed_identities,
                "metrics": {
                    "elapsed_sec": elapsed,
                    "peak_rss_mb": peak_rss_mb(),
                    "temporary_bytes": _tree_bytes(trial_root),
                    "archive_scans": scale,
                    "parsed_classes": parsed_classes,
                    "javap_calls": javap_calls,
                    "cache_hits": cache_hits,
                    "per_api_latency_ms": elapsed * 1000 / api_count,
                    "duplicate_work_keys": [],
                    "edges_found": edge_count,
                },
            })
    tiers = []
    for scale in scales:
        trials = trials_by_scale[scale]
        truth_identities = list(trials[0]["truth_identities"])
        tiers.append({
            "scale": scale,
            "truth_identities": truth_identities,
            "observed_identities": list(trials[0]["observed_identities"]),
            "metrics": _aggregate_trial_metrics(
                trials, latency_scope_count=len(truth_identities)
            ),
            "trials": trials,
        })
    return tiers


def _compile_data_contract_pair(root: Path, index: int):
    class_name = f"Data{index}Dto"
    old_source = root / "old-src" / "scale" / f"{class_name}.java"
    new_source = root / "new-src" / "scale" / f"{class_name}.java"
    for source, extra in ((old_source, ""), (new_source, "private int added; public int getAdded() { return added; }")):
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            "package scale; import java.io.Serializable; "
            f"public class {class_name} implements Serializable {{ "
            "private String value; public String getValue() { return value; } "
            f"{extra} }}\n",
            encoding="utf-8",
        )
    jars = []
    for side, source, version in (
        ("old", old_source, "1.0"),
        ("new", new_source, "2.0"),
    ):
        classes = root / f"{side}-classes"
        classes.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            ["javac", "-encoding", "UTF-8", "-d", str(classes), str(source)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"complexity fixture javac failed: {completed.stderr}")
        jar_path = root / f"data-{index}-{version}.jar"
        with zipfile.ZipFile(jar_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for class_file in sorted(classes.rglob("*.class")):
                archive.write(class_file, class_file.relative_to(classes).as_posix())
            archive.writestr(
                f"META-INF/maven/contract/data-{index}/pom.properties",
                f"groupId=contract\nartifactId=data-{index}\nversion={version}\n",
            )
        jars.append(jar_path)
    return jars[0], jars[1], f"scale.{class_name}.added"


def _write_scale_fat_jar(path: Path, nested_jars: list[Path]):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        for jar_path in nested_jars:
            archive.write(jar_path, f"BOOT-INF/lib/{jar_path.name}")


def run_production_stage_scale_tiers(
    repo_root: Path, report_root: Path, *, scales: tuple[int, ...]
) -> list[dict]:
    del repo_root
    report_root = Path(report_root)
    tiers = []
    for scale in scales:
        tier_root = report_root / f"production-scale-{scale}"
        old_jars = []
        new_jars = []
        step4_truth = []
        for index in range(scale):
            old_jar, new_jar, identity = _compile_data_contract_pair(
                tier_root / f"contract-{index}", index
            )
            old_jars.append(old_jar)
            new_jars.append(new_jar)
            step4_truth.append(identity)

        fat_jar = tier_root / "application.jar"
        _write_scale_fat_jar(fat_jar, new_jars)
        step1_truth = [f"contract:data-{index}" for index in range(scale)]
        fixture_bytes = _tree_bytes(tier_root)
        stage_trials = {"step1": [], "step4": [], "step5": []}
        for trial_index in range(1, TIMING_TRIALS + 1):
            started = time.perf_counter()
            packaged, _details = collect_packaged_deps_from_artifact_path(
                fat_jar
            )
            step1_elapsed = time.perf_counter() - started
            step1_observed = sorted(packaged)
            stage_trials["step1"].append({
                "trial": trial_index,
                "truth_identities": list(step1_truth),
                "observed_identities": step1_observed,
                "metrics": {
                    "elapsed_sec": step1_elapsed,
                    "peak_rss_mb": peak_rss_mb(),
                    "temporary_bytes": fixture_bytes,
                    "archive_scans": 1 + scale,
                    "parsed_classes": 0,
                    "javap_calls": 0,
                    "cache_hits": 0,
                    "per_api_latency_ms": (
                        step1_elapsed * 1000 / max(1, scale)
                    ),
                    "duplicate_work_keys": [],
                },
            })

            started = time.perf_counter()
            step4_observed = []
            for index, (old_jar, new_jar) in enumerate(
                zip(old_jars, new_jars)
            ):
                rows = compare_jar_data_contracts(
                    old_jar,
                    new_jar,
                    coord=f"contract:data-{index}",
                    old_version="1.0",
                    new_version="2.0",
                )
                step4_observed.extend(
                    row["api_name"]
                    for row in rows
                    if row.get("change_type") == "DATA_FIELD_ADDED"
                )
            step4_elapsed = time.perf_counter() - started
            stage_trials["step4"].append({
                "trial": trial_index,
                "truth_identities": list(step4_truth),
                "observed_identities": step4_observed,
                "metrics": {
                    "elapsed_sec": step4_elapsed,
                    "peak_rss_mb": peak_rss_mb(),
                    "temporary_bytes": fixture_bytes,
                    "archive_scans": scale * 2,
                    "parsed_classes": scale * 2,
                    "javap_calls": 0,
                    "cache_hits": 0,
                    "per_api_latency_ms": (
                        step4_elapsed * 1000 / max(1, scale)
                    ),
                    "duplicate_work_keys": [],
                },
            })

            step5_root = tier_root / f"trial-{trial_index}" / "step5"
            started = time.perf_counter()
            step5_truth = []
            step5_observed = []
            step5_parsed_classes = 0
            step5_javap_calls = 0
            step5_cache_hits = 0
            step5_edges = 0
            for index in range(scale):
                seed = 20_000 + index
                case = generate_topology(
                    seed, GenerationDimensions.complete()
                )
                result = run_generated_case(
                    case, step5_root / f"case-{index}"
                )
                identities = [
                    f"{seed}:{edge.identity}" for edge in case.spec.truth_edges
                ]
                step5_truth.extend(identities)
                if result.status == "passed":
                    step5_observed.extend(identities)
                result_metrics = result.production_metrics
                step5_parsed_classes += int(
                    result_metrics.get("classes_scanned") or 0
                )
                step5_javap_calls += int(
                    result_metrics.get("javap_fallback_classes") or 0
                )
                step5_cache_hits += int(
                    bool(result_metrics.get("cache_hit"))
                )
                step5_edges += int(result_metrics.get("edges_found") or 0)
            step5_elapsed = time.perf_counter() - started
            stage_trials["step5"].append({
                "trial": trial_index,
                "truth_identities": step5_truth,
                "observed_identities": step5_observed,
                "metrics": {
                    "elapsed_sec": step5_elapsed,
                    "peak_rss_mb": peak_rss_mb(),
                    "temporary_bytes": (
                        fixture_bytes + _tree_bytes(step5_root)
                    ),
                    "archive_scans": scale,
                    "parsed_classes": step5_parsed_classes,
                    "javap_calls": step5_javap_calls,
                    "cache_hits": step5_cache_hits,
                    "per_api_latency_ms": (
                        step5_elapsed * 1000 / max(1, len(step5_truth))
                    ),
                    "duplicate_work_keys": [],
                    "edges_found": step5_edges,
                },
            })

        stages = {}
        for stage_name, trials in stage_trials.items():
            truth_identities = list(trials[0]["truth_identities"])
            observed_identities = list(trials[0]["observed_identities"])
            metrics = _aggregate_trial_metrics(
                trials, latency_scope_count=len(truth_identities)
            )
            if stage_name == "step5":
                identities_per_scope = max(
                    1, len(truth_identities) // max(1, scale)
                )
                scope_count = len(observed_identities) // identities_per_scope
            else:
                scope_count = len(observed_identities)
            stages[stage_name] = {
                "truth_identities": truth_identities,
                "observed_identities": observed_identities,
                "scope_count": scope_count,
                "elapsed_sec": metrics["elapsed_sec"],
                "metrics": metrics,
                "trials": trials,
            }
        stages["step1"]["archive_scans"] = 1 + scale
        stages["step4"]["jar_comparisons"] = scale
        stages["step5"]["topology_runs"] = scale
        tiers.append({"scale": scale, "stages": stages})
    return tiers
