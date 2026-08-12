#!/usr/bin/env python3
"""Reproducible 400-JAR/100k-class binary-first performance measurement.

The scale dataset is generated from one compiled class by length-preserving
constant-pool owner replacement.  Every resulting class is a distinct valid
classfile and every JAR has a stable content identity.  Dataset generation is
outside measured analysis time.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import closing
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import sys
import time
from typing import Any, Iterable
import zipfile

from binary_asm_helper import resolve_asm_jar
from binary_fact_store import BinaryFactStore
from binary_first_contract import canonical_identity
from binary_first_model import ArtifactInstance, RuntimeProfile
from binary_snapshot_cache import cached_snapshot_archive
from compat import subprocess_platform_kwargs
from path_runtime import short_temporary_directory

try:
    import resource as _resource
except ImportError:  # The resource module is unavailable on Windows.
    _resource = None


SCHEMA = "java-upgrade-analyzer.binary-first-performance-result.v1"
DATASET_SCHEMA = "binary-performance-scale-400x250-v1"


class PerformanceGateError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _directory_bytes(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def _rss_bytes() -> int:
    if _resource is None:
        raise PerformanceGateError(
            "peak RSS measurement is unavailable on this platform"
        )
    value = _resource.getrusage(_resource.RUSAGE_SELF).ru_maxrss
    child = _resource.getrusage(_resource.RUSAGE_CHILDREN).ru_maxrss
    multiplier = 1 if sys.platform == "darwin" else 1024
    return int(max(value, child) * multiplier)


def _command_version(command: list[str]) -> str:
    completed = subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8",
        errors="replace", check=False,
        **subprocess_platform_kwargs(),
    )
    text = (completed.stdout or completed.stderr or "").strip().splitlines()
    return text[0] if text else f"exit={completed.returncode}"


def _jdk_home() -> Path:
    completed = subprocess.run(
        ["java", "-XshowSettings:properties", "-version"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False,
        **subprocess_platform_kwargs(),
    )
    for line in completed.stderr.splitlines():
        if "java.home" in line and "=" in line:
            return Path(line.split("=", 1)[1].strip()).resolve()
    raise PerformanceGateError("unable to resolve java.home")


def _java_major(jdk_home: Path) -> int:
    release = (jdk_home / "release").read_text(encoding="utf-8", errors="replace")
    for line in release.splitlines():
        if line.startswith("JAVA_VERSION="):
            version = line.split("=", 1)[1].strip().strip('"')
            return int(version.split(".", 1)[0]) if not version.startswith("1.") else int(version.split(".")[1])
    raise PerformanceGateError("JAVA_VERSION missing")


def _compile_template(
    root: Path, *, return_value: int = 1, label: str = "template"
) -> bytes:
    source = root / label / "p" / "C000000.java"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        "package p; public class C000000 { "
        f"public int value(){{ return {int(return_value)}; }} "
        "public String text(){ return Integer.toString(value()); } }\n",
        encoding="utf-8",
    )
    output = root / f"{label}-classes"
    output.mkdir(exist_ok=True)
    completed = subprocess.run(
        ["javac", "-g:none", "-d", str(output), str(source)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False,
        **subprocess_platform_kwargs(),
    )
    if completed.returncode != 0:
        raise PerformanceGateError(completed.stderr or "javac failed")
    content = (output / "p" / "C000000.class").read_bytes()
    if b"p/C000000" not in content:
        raise PerformanceGateError("template class owner constant missing")
    return content


def build_dataset(root: Path, *, jar_count: int, classes_per_jar: int) -> list[dict[str, Any]]:
    dataset = root / "dataset"
    manifest_path = dataset / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        artifacts = list(manifest.get("artifacts") or ())
        if (
            manifest.get("schema") == DATASET_SCHEMA
            and len(artifacts) == jar_count
            and all(Path(item["path"]).is_file() and _sha256(Path(item["path"])) == item["sha256"] for item in artifacts)
        ):
            return artifacts
    if dataset.exists():
        shutil.rmtree(dataset)
    dataset.mkdir(parents=True)
    template = _compile_template(root)
    artifacts = []
    class_index = 0
    for jar_index in range(jar_count):
        path = dataset / f"artifact-{jar_index:04d}.jar"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
            for _ in range(classes_per_jar):
                owner = f"p/C{class_index:06d}".encode("ascii")
                if len(owner) != len(b"p/C000000"):
                    raise PerformanceGateError("scale dataset class owner length overflow")
                content = template.replace(b"p/C000000", owner)
                info = zipfile.ZipInfo(owner.decode("ascii") + ".class", (2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, content)
                class_index += 1
        artifacts.append({
            "path": str(path.resolve()),
            "sha256": _sha256(path),
            "byte_length": path.stat().st_size,
            "jar_index": jar_index,
            "first_class_index": jar_index * classes_per_jar,
            "class_count": classes_per_jar,
        })
    manifest = {
        "schema": DATASET_SCHEMA,
        "jar_count": jar_count,
        "class_count": class_index,
        "classes_per_jar": classes_per_jar,
        "artifacts": artifacts,
    }
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return artifacts


def build_changed_current_artifacts(
    root: Path,
    artifacts: list[dict[str, Any]],
    *,
    classes_per_jar: int,
) -> list[dict[str, Any]]:
    """Change every method body in one JAR while preserving its class topology."""

    if not artifacts:
        raise PerformanceGateError("changed-side probe requires at least one artifact")
    changed_directory = root / "changed-dataset"
    changed_directory.mkdir(parents=True, exist_ok=True)
    changed_path = changed_directory / "artifact-0000.jar"
    template = _compile_template(
        root, return_value=2, label="changed-template"
    )
    first_class = int(artifacts[0].get("first_class_index") or 0)
    with zipfile.ZipFile(
        changed_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=1,
    ) as archive:
        for class_index in range(first_class, first_class + classes_per_jar):
            owner = f"p/C{class_index:06d}".encode("ascii")
            if len(owner) != len(b"p/C000000"):
                raise PerformanceGateError(
                    "changed-side class owner length overflow"
                )
            content = template.replace(b"p/C000000", owner)
            info = zipfile.ZipInfo(
                owner.decode("ascii") + ".class", (2026, 1, 1, 0, 0, 0)
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    current = [dict(item) for item in artifacts]
    current[0] = {
        **current[0],
        "path": str(changed_path.resolve()),
        "sha256": _sha256(changed_path),
        "byte_length": changed_path.stat().st_size,
    }
    return current


def _runtime_profile(artifacts: list[dict[str, Any]], jdk_major: int) -> RuntimeProfile:
    descriptors = [
        {
            "logical_location": f"lib/artifact-{index:04d}.jar",
            "content_sha256": item["sha256"],
            "path_kind": "classpath",
            "slot": index,
            "loader_realm": "application-loader",
        }
        for index, item in enumerate(artifacts)
    ]
    payload = {
        "target_jvm": {"vendor": "performance-gate", "major": jdk_major},
        "runtime_platform_image_identity": "performance-platform-image",
        "target_os": platform.system(),
        "target_arch": platform.machine(),
        "container_and_launcher_kind": "java-classpath",
        "ordered_runtime_path_entry_descriptors": descriptors,
        "loader_topology": {
            "coverage_status": "complete",
            "entrypoint_realms": ["application-loader"],
            "realms": [
                {"identity": "platform-loader", "kind": "platform", "delegation": "parent_first"},
                {
                    "identity": "application-loader", "kind": "application",
                    "parent": "platform-loader", "delegation": "parent_first",
                    "module_mode": "unnamed",
                },
            ],
        },
        "runtime_code_source_origin_mapping_identity": "performance-origins-v1",
        "runtime_security_and_package_sealing_policy_identity": "standard-unsealed-unsigned-v1",
        "active_profile_identities": ["performance"],
        "external_config_snapshot_identities": [],
        "agent_transformer_plugin_profile_identities": [],
        "business_entrypoint_profile": {"coverage_status": "complete", "methods": []},
        "runtime_class_closure_coverage_status": "complete",
        "resource_selection_coverage_status": "complete",
    }
    payload["field_coverage"] = {key: "known" for key in RuntimeProfile.REQUIRED_FIELDS}
    return RuntimeProfile(payload)


def _instance(profile: RuntimeProfile, artifact: dict[str, Any], index: int) -> ArtifactInstance:
    return ArtifactInstance(
        outer_artifact_sha256=artifact["sha256"],
        container_entry="<artifact>",
        content_sha256=artifact["sha256"],
        runtime_profile_identity=profile.identity,
        path_owner_loader_realm_identity="application-loader",
        runtime_path_kind="classpath",
        runtime_classpath_index=index,
        container_loader_policy_version="flat-parent-first-v1",
        runtime_code_source_origin_identity=f"performance-artifact-{index:04d}",
        coord=f"performance:artifact-{index:04d}:1",
    )


def _inventory(artifacts: Iterable[dict[str, Any]]) -> dict[str, int]:
    entries = 0
    bytes_total = 0
    for artifact in artifacts:
        with zipfile.ZipFile(artifact["path"]) as archive:
            infos = archive.infolist()
            entries += len(infos)
            bytes_total += sum(info.file_size for info in infos)
    return {"entry_count": entries, "uncompressed_bytes": bytes_total}


def _analyze_once(
    artifacts: list[dict[str, Any]], *, root: Path, cache_root: Path,
    asm_jar: Path, warm: bool,
) -> dict[str, Any]:
    if not warm and cache_root.exists():
        shutil.rmtree(cache_root)
    profile = _runtime_profile(artifacts, _java_major(_jdk_home()))
    db = root / ("warm.sqlite" if warm else "cold.sqlite")
    if db.exists():
        db.unlink()
    started = time.perf_counter()
    inventory_started = time.perf_counter()
    inventory = _inventory(artifacts)
    inventory_seconds = time.perf_counter() - inventory_started
    parse_seconds = 0.0
    db_seconds = 0.0
    parser_invocations = 0
    cache_hits = 0
    db_started = time.perf_counter()
    counts = {"entries": 0, "classes": 0, "members": 0, "edges": 0, "resources": 0}
    store = BinaryFactStore(db)
    db_seconds += time.perf_counter() - db_started
    try:
        for index, artifact in enumerate(artifacts):
            instance = _instance(profile, artifact, index)
            parse_started = time.perf_counter()
            outcome = cached_snapshot_archive(
                artifact["path"],
                artifact_instance_identity=instance.identity,
                expected_sha256=artifact["sha256"],
                cache_root=cache_root,
                asm_jar=asm_jar,
                target_jvm_major=int(profile.payload["target_jvm"]["major"]),
            )
            parse_seconds += time.perf_counter() - parse_started
            parser_invocations += outcome.parser_invocation_count
            cache_hits += int(outcome.cache_status == "hit")
            db_started = time.perf_counter()
            added = store.add_artifact_snapshot(instance, outcome.snapshot)
            db_seconds += time.perf_counter() - db_started
            for key, value in added.items():
                counts[key] += value
            del outcome
        db_started = time.perf_counter()
        store.connection.commit()
        db_seconds += time.perf_counter() - db_started
        overlay_started = time.perf_counter()
        # Source is intentionally absent in this scale fixture; exercising the
        # optional overlay must not scan or mutate the binary graph.
        overlay_status = "not_provided"
        overlay_seconds = time.perf_counter() - overlay_started
        query_started = time.perf_counter()
        query_count = 10_000
        connection = store.connection
        for index in range(query_count):
            owner = f"p/C{index % inventory['entry_count']:06d}"
            connection.execute(
                "SELECT member_identity FROM members WHERE class_name=? AND member_name='value' AND descriptor='()I'",
                (owner,),
            ).fetchall()
        query_seconds = time.perf_counter() - query_started
        report_started = time.perf_counter()
        report_payload = {
            "schema": "binary-performance-report-fixture.v1",
            "api_results": [
                {
                    "api": f"p.C{index:06d}.value()I",
                    "reachability_status": "not_found_in_static_analysis",
                    "impact_conclusion": "inconclusive",
                    "runtime_verification_status": "undetermined",
                }
                for index in range(query_count)
            ],
        }
        encoded_report = json.dumps(report_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        report_seconds = time.perf_counter() - report_started
    finally:
        store.close()
    elapsed = time.perf_counter() - started
    return {
        "end_to_end_seconds": elapsed,
        "stage_seconds": {
            "inventory": inventory_seconds,
            "parse_and_cache": parse_seconds,
            "db_write_and_index": db_seconds,
            "overlay": overlay_seconds,
            "batch_query_10000": query_seconds,
            "report_10000": report_seconds,
        },
        "parser_invocations": parser_invocations,
        "cache_hits": cache_hits,
        "counts": counts,
        "inventory": inventory,
        "overlay_status": overlay_status,
        "report_bytes": len(encoded_report),
        "db_bytes": db.stat().st_size,
        "cache_bytes": _directory_bytes(cache_root),
        "peak_rss_bytes": _rss_bytes(),
        "bytes_per_class": (db.stat().st_size + _directory_bytes(cache_root)) / max(counts["classes"], 1),
        "bytes_per_edge": db.stat().st_size / max(counts["edges"], 1),
    }


def _legacy_javap(artifacts: list[dict[str, Any]], classes_per_jar: int) -> dict[str, Any]:
    started = time.perf_counter()
    class_count = 0
    for artifact in artifacts:
        first = int(artifact["first_class_index"])
        names = [f"p.C{index:06d}" for index in range(first, first + classes_per_jar)]
        completed = subprocess.run(
            ["javap", "-c", "-s", "-p", "-classpath", artifact["path"], *names],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            **subprocess_platform_kwargs(),
        )
        if completed.returncode != 0:
            raise PerformanceGateError(
                f"javap failed for {artifact['path']}: {completed.stderr[-500:].decode(errors='replace')}"
            )
        class_count += len(names)
    return {
        "end_to_end_seconds": time.perf_counter() - started,
        "class_count": class_count,
        "peak_rss_bytes": _rss_bytes(),
        "implementation": "legacy-javap-c-s-p-batched-per-artifact",
    }


def _full_pipeline_probe(
    artifacts: list[dict[str, Any]],
    *,
    root: Path,
    asm_jar: Path,
    classes_per_jar: int,
    jar_limit: int | None = None,
    current_artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Measure the full runtime and Oracle phases at the requested scale."""
    from binary_pipeline import run_pipeline

    selected_base = (
        artifacts
        if jar_limit is None
        else artifacts[:min(len(artifacts), jar_limit)]
    )
    all_current = artifacts if current_artifacts is None else current_artifacts
    selected_current = (
        all_current
        if jar_limit is None
        else all_current[:min(len(all_current), jar_limit)]
    )
    if len(selected_base) != len(selected_current):
        raise PerformanceGateError(
            "full pipeline base/current artifact counts must match"
        )
    output_root = root / "full-pipeline-probe"
    if output_root.exists():
        shutil.rmtree(output_root)

    def runtime_artifacts(selected):
        return [
            {
                "path": item["path"],
                "logical_location": f"lib/artifact-{index:04d}.jar",
                "loader_realm": "application-loader",
                "path_kind": "classpath",
                "slot": index,
                "coord": f"performance:artifact-{index:04d}:1",
                "lineage": f"performance:artifact-{index:04d}",
                "runtime_code_source_origin_identity": (
                    f"performance-artifact-{index:04d}"
                ),
            }
            for index, item in enumerate(selected)
        ]
    runtime_profile = {
        "container_and_launcher_kind": "java-classpath",
        "loader_topology": {
            "coverage_status": "complete",
            "entrypoint_realms": ["application-loader"],
            "realms": [
                {
                    "identity": "platform-loader",
                    "kind": "platform",
                    "delegation": "parent_first",
                    "module_mode": "named-platform",
                },
                {
                    "identity": "application-loader",
                    "kind": "application",
                    "parent": "platform-loader",
                    "delegation": "parent_first",
                    "module_mode": "unnamed",
                },
            ],
        },
        "runtime_security_and_package_sealing_policy_identity": (
            "standard-unsealed-unsigned-v1"
        ),
        "active_profile_identities": ["performance"],
        "external_config_snapshot_identities": [],
        "agent_transformer_plugin_profile_identities": [],
        "business_entrypoint_profile": {
            "coverage_status": "complete",
            "methods": [],
        },
        "runtime_class_closure_coverage_status": "complete",
        "resource_selection_coverage_status": "complete",
    }
    jdk_home = str(_jdk_home())
    result = run_pipeline(
        {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "performance_fixture",
            },
            "asm_jar": str(asm_jar),
            "base": {
                "jdk_home": jdk_home,
                "artifacts": runtime_artifacts(selected_base),
                "runtime_profile": runtime_profile,
            },
            "current": {
                "jdk_home": jdk_home,
                "artifacts": runtime_artifacts(selected_current),
                "runtime_profile": runtime_profile,
            },
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        },
        output_root=output_root,
    )
    evidence = _full_pipeline_evidence(result)
    comparison = (
        "identical-base-current-cold-output"
        if [item.get("sha256") for item in selected_base]
        == [item.get("sha256") for item in selected_current]
        else "nonidentical-base-current-cold-output"
    )
    return {
        "status": "passed",
        "comparison": comparison,
        "jar_count": len(selected_base),
        "current_jar_count": len(selected_current),
        "expected_class_count": len(selected_base) * classes_per_jar,
        "end_to_end_seconds": float(result["total_elapsed_seconds"]),
        "phase_seconds": {
            str(item["phase"]): float(item["elapsed_seconds"])
            for item in result["phase_timings"]
        },
        "phase_peak_rss_bytes": {
            str(item["phase"]): int(item.get("peak_rss_bytes") or 0)
            for item in result["phase_timings"]
        },
        "peak_rss_bytes": int(result.get("peak_rss_bytes") or 0),
        "parser_invocations": int(
            result["cache_metrics"]["classfile_parser_invocations"]
        ),
        "artifact_snapshot_hits": int(
            result["cache_metrics"]["artifact_snapshot_hits"]
        ),
        **evidence,
    }


def _full_pipeline_evidence(result: dict[str, Any]) -> dict[str, Any]:
    """Read measured conservation and Oracle values from persisted evidence."""
    generation = Path(result["generation_directory"])
    validation = json.loads(
        Path(result["validation_result_path"]).read_text(encoding="utf-8")
    )
    decisions = json.loads(
        (generation / "binary_decisions.json").read_text(encoding="utf-8")
    )
    formal = json.loads(
        (generation / "binary_formal_results.json").read_text(encoding="utf-8")
    )

    def class_count(side: str) -> int:
        with closing(
            sqlite3.connect(generation / f"{side}_binary_facts.sqlite")
        ) as connection:
            return int(
                connection.execute("SELECT COUNT(*) FROM classes").fetchone()[0]
            )

    base_class_count = class_count("base")
    current_class_count = class_count("current")
    authoritative = list(decisions.get("authoritative_change_facts") or ())
    formal_by_api = list(formal.get("by_api") or ())

    def histogram(values: Iterable[Any]) -> dict[str, int]:
        return dict(sorted(Counter(str(value) for value in values).items()))

    return {
        # Retain the historical aggregate field for gate/result consumers, but
        # also expose both observed sides so conservation cannot be inferred
        # from the configured fixture size.
        "class_count": base_class_count,
        "base_class_count": base_class_count,
        "current_class_count": current_class_count,
        "validation_status": str(validation.get("status") or ""),
        "validation_issue_count": int(validation.get("issue_count") or 0),
        "authoritative_change_fact_count": len(authoritative),
        "authoritative_member_change_kind_counts": histogram(
            (item.get("fact_scope") or {}).get("member_change_kind")
            for item in authoritative
        ),
        "formal_api_result_count": len(formal_by_api),
        "formal_reachability_status_counts": histogram(
            item.get("reachability_status") for item in formal_by_api
        ),
        "formal_impact_conclusion_counts": histogram(
            item.get("impact_conclusion") for item in formal_by_api
        ),
    }


def _p95(values: list[float]) -> float:
    if not values:
        raise PerformanceGateError("p95 requires samples")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def run_benchmark(
    root: Path, *, jar_count: int = 400, classes_per_jar: int = 250,
    warm_samples: int = 3, include_legacy: bool = True,
) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    artifacts = build_dataset(root, jar_count=jar_count, classes_per_jar=classes_per_jar)
    asm_jar = resolve_asm_jar()
    cache_root = root / "cache"
    cold = _analyze_once(
        artifacts, root=root, cache_root=cache_root, asm_jar=asm_jar, warm=False
    )
    warm_runs = [
        _analyze_once(
            artifacts, root=root, cache_root=cache_root, asm_jar=asm_jar, warm=True
        )
        for _ in range(warm_samples)
    ]
    if any(item["parser_invocations"] != 0 for item in warm_runs):
        raise PerformanceGateError("warm cache parser invocation must be zero")
    expected_classes = jar_count * classes_per_jar
    if cold["counts"]["classes"] != expected_classes:
        raise PerformanceGateError(
            f"class conservation failed: {cold['counts']['classes']} != {expected_classes}"
        )
    legacy = _legacy_javap(artifacts, classes_per_jar) if include_legacy else None
    full_pipeline_probe = _full_pipeline_probe(
        artifacts,
        root=root / "identical-full-pipeline",
        asm_jar=asm_jar,
        classes_per_jar=classes_per_jar,
    )
    changed_artifacts = build_changed_current_artifacts(
        root, artifacts, classes_per_jar=classes_per_jar
    )
    changed_full_pipeline_probe = _full_pipeline_probe(
        artifacts,
        current_artifacts=changed_artifacts,
        root=root / "changed-full-pipeline",
        asm_jar=asm_jar,
        classes_per_jar=classes_per_jar,
    )
    dataset_identity = canonical_identity(
        "binary_performance_dataset_identity",
        {
            "schema": DATASET_SCHEMA,
            "artifact_sha256": [item["sha256"] for item in artifacts],
            "classes_per_jar": classes_per_jar,
        },
        schema_version="1",
    )
    warm_p95 = _p95([item["end_to_end_seconds"] for item in warm_runs])
    relative = (
        cold["end_to_end_seconds"] / legacy["end_to_end_seconds"]
        if legacy and legacy["end_to_end_seconds"] else None
    )
    return {
        "schema": SCHEMA,
        "status": "measured",
        "measurement_protocol": {
            "machine_identity": canonical_identity(
                "performance_machine_identity",
                {
                    "platform": platform.platform(),
                    "machine": platform.machine(),
                    "processor": platform.processor(),
                    "logical_cpu_count": os.cpu_count(),
                },
                schema_version="1",
            ),
            "machine": {
                "platform": platform.platform(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "logical_cpu_count": os.cpu_count(),
            },
            "dataset_schema": DATASET_SCHEMA,
            "dataset_identity": dataset_identity,
            "dataset_artifact_identities": [item["sha256"] for item in artifacts],
            "jar_count": jar_count,
            "class_count": expected_classes,
            "classes_per_jar": classes_per_jar,
            "full_pipeline_probe": {
                "jar_count": full_pipeline_probe["jar_count"],
                "class_count": full_pipeline_probe["class_count"],
                "comparison": full_pipeline_probe["comparison"],
                "includes": [
                    "artifact_fact_build_and_local_diff",
                    "target_independent_runtime_reconciliation",
                    "decision_and_projection_freeze",
                    "binary_trace",
                    "immutable_generation_write",
                    "independent_validation",
                    "validated_generation_activation",
                ],
            },
            "changed_full_pipeline_probe": {
                "jar_count": changed_full_pipeline_probe["jar_count"],
                "class_count": changed_full_pipeline_probe["class_count"],
                "comparison": changed_full_pipeline_probe["comparison"],
                "changed_jar_count": 1,
                "changed_class_count": classes_per_jar,
                "current_artifact_identity": changed_artifacts[0]["sha256"],
                "includes": [
                    "artifact_fact_build_and_local_diff",
                    "target_independent_runtime_reconciliation",
                    "decision_and_projection_freeze",
                    "binary_trace",
                    "immutable_generation_write",
                    "independent_validation",
                    "validated_generation_activation",
                ],
            },
            "tool_versions": {
                "python": platform.python_version(),
                "java": _command_version(["java", "-version"]),
                "javap": _command_version(["javap", "-version"]),
                "asm_jar_sha256": _sha256(asm_jar),
            },
            "warmup_runs": 1,
            "sample_runs": {
                "cold": 1,
                "warm": warm_samples,
                "legacy": int(include_legacy),
                "full_pipeline": 1,
                "changed_full_pipeline": 1,
            },
            "p95_method": "nearest-rank",
            "cold_cleanup_rule": "delete binary snapshot cache and SQLite before run",
            "warm_cache_rule": "all content+parser cache entries must pass digest validation; parser_invocations=0",
        },
        "measurements": {
            "cold": cold,
            "warm_runs": warm_runs,
            "warm_end_to_end_p95_seconds": warm_p95,
            "legacy": legacy,
            "full_pipeline_probe": full_pipeline_probe,
            "changed_full_pipeline_probe": changed_full_pipeline_probe,
            "cold_relative_legacy_ratio": relative,
            "peak_rss_bytes": max(
                [
                    cold["peak_rss_bytes"],
                    *[item["peak_rss_bytes"] for item in warm_runs],
                    legacy["peak_rss_bytes"] if legacy else 0,
                    full_pipeline_probe["peak_rss_bytes"],
                    changed_full_pipeline_probe["peak_rss_bytes"],
                ]
            ),
            "disk_bytes": cold["db_bytes"] + cold["cache_bytes"],
        },
    }


def evaluate_gate(result: dict[str, Any], gate: dict[str, Any]) -> dict[str, Any]:
    issues = []
    protocol = result.get("measurement_protocol") or {}
    required_protocol = gate.get("measurement_protocol") or {}
    for field in ("machine_identity", "dataset_identity", "jar_count", "class_count"):
        if protocol.get(field) != required_protocol.get(field):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_PROTOCOL_MISMATCH",
                "field": field,
                "expected": required_protocol.get(field),
                "actual": protocol.get(field),
            })
    required_probe = required_protocol.get("full_pipeline_probe") or {}
    actual_probe_protocol = protocol.get("full_pipeline_probe") or {}
    for field in ("jar_count", "class_count", "comparison", "includes"):
        if (
            field in required_probe
            and actual_probe_protocol.get(field) != required_probe[field]
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_PROTOCOL_MISMATCH",
                "field": f"full_pipeline_probe.{field}",
                "expected": required_probe[field],
                "actual": actual_probe_protocol.get(field),
            })
    required_changed_probe = (
        required_protocol.get("changed_full_pipeline_probe") or {}
    )
    actual_changed_probe_protocol = (
        protocol.get("changed_full_pipeline_probe") or {}
    )
    for field in (
        "jar_count", "class_count", "comparison", "changed_jar_count",
        "changed_class_count", "current_artifact_identity", "includes",
    ):
        if (
            field in required_changed_probe
            and actual_changed_probe_protocol.get(field)
            != required_changed_probe[field]
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_PROTOCOL_MISMATCH",
                "field": f"changed_full_pipeline_probe.{field}",
                "expected": required_changed_probe[field],
                "actual": actual_changed_probe_protocol.get(field),
            })
    measurements = result.get("measurements") or {}
    thresholds = gate.get("thresholds") or {}
    cold = measurements.get("cold") or {}
    warm_runs = list(measurements.get("warm_runs") or ())

    def upper(metric: str, actual: float | int | None, limit: float | int | None):
        if actual is None or limit is None or float(actual) > float(limit):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_THRESHOLD_EXCEEDED",
                "metric": metric, "actual": actual, "limit": limit,
            })

    upper("cold_end_to_end_seconds", cold.get("end_to_end_seconds"), thresholds.get("cold_end_to_end_seconds"))
    upper(
        "warm_end_to_end_p95_seconds",
        measurements.get("warm_end_to_end_p95_seconds"),
        thresholds.get("warm_end_to_end_p95_seconds"),
    )
    upper("peak_rss_bytes", measurements.get("peak_rss_bytes"), thresholds.get("peak_rss_bytes"))
    upper("disk_bytes", measurements.get("disk_bytes"), thresholds.get("disk_bytes"))
    upper("bytes_per_class", cold.get("bytes_per_class"), thresholds.get("bytes_per_class"))
    upper("bytes_per_edge", cold.get("bytes_per_edge"), thresholds.get("bytes_per_edge"))
    upper(
        "cold_relative_legacy_ratio",
        measurements.get("cold_relative_legacy_ratio"),
        thresholds.get("cold_relative_legacy_ratio"),
    )
    legacy_seconds = float(((measurements.get("legacy") or {}).get("end_to_end_seconds") or 0))
    warm_ratio = (
        float(measurements.get("warm_end_to_end_p95_seconds") or 0) / legacy_seconds
        if legacy_seconds else None
    )
    upper("warm_relative_legacy_ratio", warm_ratio, thresholds.get("warm_relative_legacy_ratio"))
    full_pipeline = measurements.get("full_pipeline_probe") or {}
    if "full_pipeline_end_to_end_seconds" in thresholds:
        upper(
            "full_pipeline_end_to_end_seconds",
            full_pipeline.get("end_to_end_seconds"),
            thresholds.get("full_pipeline_end_to_end_seconds"),
        )
    if "full_pipeline_peak_rss_bytes" in thresholds:
        upper(
            "full_pipeline_peak_rss_bytes",
            full_pipeline.get("peak_rss_bytes"),
            thresholds.get("full_pipeline_peak_rss_bytes"),
        )
    for phase, limit in (
        thresholds.get("full_pipeline_phase_seconds") or {}
    ).items():
        upper(
            f"full_pipeline.{phase}",
            (full_pipeline.get("phase_seconds") or {}).get(phase),
            limit,
        )
    changed_full_pipeline = (
        measurements.get("changed_full_pipeline_probe") or {}
    )
    if "changed_full_pipeline_end_to_end_seconds" in thresholds:
        upper(
            "changed_full_pipeline_end_to_end_seconds",
            changed_full_pipeline.get("end_to_end_seconds"),
            thresholds.get("changed_full_pipeline_end_to_end_seconds"),
        )
    if "changed_full_pipeline_peak_rss_bytes" in thresholds:
        upper(
            "changed_full_pipeline_peak_rss_bytes",
            changed_full_pipeline.get("peak_rss_bytes"),
            thresholds.get("changed_full_pipeline_peak_rss_bytes"),
        )
    for phase, limit in (
        thresholds.get("changed_full_pipeline_phase_seconds") or {}
    ).items():
        upper(
            f"changed_full_pipeline.{phase}",
            (changed_full_pipeline.get("phase_seconds") or {}).get(phase),
            limit,
        )
    stage_limits = thresholds.get("stage_p95_seconds") or {}
    upper("cold.inventory", (cold.get("stage_seconds") or {}).get("inventory"), stage_limits.get("inventory"))
    upper("cold.parse_and_cache", (cold.get("stage_seconds") or {}).get("parse_and_cache"), stage_limits.get("parse_and_cache"))
    upper("cold.db_write_and_index", (cold.get("stage_seconds") or {}).get("db_write_and_index"), stage_limits.get("db_write_and_index"))
    upper(
        "warm.batch_query_10000",
        _p95([(item.get("stage_seconds") or {}).get("batch_query_10000", float("inf")) for item in warm_runs]),
        stage_limits.get("batch_query_10000"),
    )
    upper(
        "warm.report_10000",
        _p95([(item.get("stage_seconds") or {}).get("report_10000", float("inf")) for item in warm_runs]),
        stage_limits.get("report_10000"),
    )
    invariants = gate.get("accuracy_invariants") or {}
    expected = invariants.get(
        "expected_class_count", required_protocol.get("class_count")
    )
    counts = cold.get("counts") or {}
    if counts.get("classes") != expected:
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_CLASS_CONSERVATION_FAILED",
            "expected": expected, "actual": counts.get("classes"),
        })
    for count_key, invariant_key in (
        ("members", "expected_member_count"),
        ("edges", "expected_edge_count"),
    ):
        expected_count = invariants.get(invariant_key)
        if expected_count is not None and counts.get(count_key) != expected_count:
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_FACT_CONSERVATION_FAILED",
                "fact_kind": count_key,
                "expected": expected_count,
                "actual": counts.get(count_key),
            })
    expected_warm_parses = int(invariants.get("warm_parser_invocations", 0))
    if any(
        int(item.get("parser_invocations") or 0) != expected_warm_parses
        for item in warm_runs
    ):
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_WARM_PARSE_NOT_ZERO",
        })
    expected_probe_classes = invariants.get("full_pipeline_expected_class_count")
    if expected_probe_classes is not None:
        observed_sides = {
            "base": full_pipeline.get(
                "base_class_count", full_pipeline.get("class_count")
            ),
            "current": full_pipeline.get(
                "current_class_count", full_pipeline.get("class_count")
            ),
        }
        for side, actual_count in observed_sides.items():
            if actual_count != expected_probe_classes:
                issues.append({
                    "reason_code": (
                        "BINARY_PERFORMANCE_FULL_PIPELINE_CLASS_CONSERVATION_FAILED"
                    ),
                    "side": side,
                    "expected": expected_probe_classes,
                    "actual": actual_count,
                })
    expected_validation_issues = invariants.get(
        "full_pipeline_validation_issue_count"
    )
    if (
        expected_validation_issues is not None
        and full_pipeline.get("validation_issue_count")
        != expected_validation_issues
    ):
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_FULL_PIPELINE_VALIDATION_FAILED",
            "expected": expected_validation_issues,
            "actual": full_pipeline.get("validation_issue_count"),
        })
    for result_key, invariant_key in (
        (
            "authoritative_change_fact_count",
            "full_pipeline_expected_authoritative_change_fact_count",
        ),
        ("formal_api_result_count", "full_pipeline_expected_formal_api_result_count"),
    ):
        expected_count = invariants.get(invariant_key)
        if (
            expected_count is not None
            and full_pipeline.get(result_key) != expected_count
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_FULL_PIPELINE_RESULT_MISMATCH",
                "metric": result_key,
                "expected": expected_count,
                "actual": full_pipeline.get(result_key),
            })
    for result_key, invariant_key in (
        (
            "authoritative_member_change_kind_counts",
            "full_pipeline_expected_authoritative_member_change_kind_counts",
        ),
        (
            "formal_reachability_status_counts",
            "full_pipeline_expected_formal_reachability_status_counts",
        ),
        (
            "formal_impact_conclusion_counts",
            "full_pipeline_expected_formal_impact_conclusion_counts",
        ),
    ):
        expected_distribution = invariants.get(invariant_key)
        if (
            expected_distribution is not None
            and full_pipeline.get(result_key) != expected_distribution
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_FULL_PIPELINE_RESULT_MISMATCH",
                "metric": result_key,
                "expected": expected_distribution,
                "actual": full_pipeline.get(result_key),
            })
    expected_changed_classes = invariants.get(
        "changed_full_pipeline_expected_class_count"
    )
    if expected_changed_classes is not None:
        observed_sides = {
            "base": changed_full_pipeline.get(
                "base_class_count", changed_full_pipeline.get("class_count")
            ),
            "current": changed_full_pipeline.get(
                "current_class_count", changed_full_pipeline.get("class_count")
            ),
        }
        for side, actual_count in observed_sides.items():
            if actual_count != expected_changed_classes:
                issues.append({
                    "reason_code": (
                        "BINARY_PERFORMANCE_FULL_PIPELINE_CLASS_CONSERVATION_FAILED"
                    ),
                    "probe": "changed_full_pipeline_probe",
                    "side": side,
                    "expected": expected_changed_classes,
                    "actual": actual_count,
                })
    expected_changed_validation_issues = invariants.get(
        "changed_full_pipeline_validation_issue_count"
    )
    if (
        expected_changed_validation_issues is not None
        and changed_full_pipeline.get("validation_issue_count")
        != expected_changed_validation_issues
    ):
        issues.append({
            "reason_code": "BINARY_PERFORMANCE_FULL_PIPELINE_VALIDATION_FAILED",
            "probe": "changed_full_pipeline_probe",
            "expected": expected_changed_validation_issues,
            "actual": changed_full_pipeline.get("validation_issue_count"),
        })
    for result_key, invariant_key in (
        (
            "authoritative_change_fact_count",
            "changed_full_pipeline_expected_authoritative_change_fact_count",
        ),
        (
            "formal_api_result_count",
            "changed_full_pipeline_expected_formal_api_result_count",
        ),
    ):
        expected_count = invariants.get(invariant_key)
        if (
            expected_count is not None
            and changed_full_pipeline.get(result_key) != expected_count
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_FULL_PIPELINE_RESULT_MISMATCH",
                "probe": "changed_full_pipeline_probe",
                "metric": result_key,
                "expected": expected_count,
                "actual": changed_full_pipeline.get(result_key),
            })
    for result_key, invariant_key in (
        (
            "authoritative_member_change_kind_counts",
            "changed_full_pipeline_expected_authoritative_member_change_kind_counts",
        ),
        (
            "formal_reachability_status_counts",
            "changed_full_pipeline_expected_formal_reachability_status_counts",
        ),
        (
            "formal_impact_conclusion_counts",
            "changed_full_pipeline_expected_formal_impact_conclusion_counts",
        ),
    ):
        expected_distribution = invariants.get(invariant_key)
        if (
            expected_distribution is not None
            and changed_full_pipeline.get(result_key) != expected_distribution
        ):
            issues.append({
                "reason_code": "BINARY_PERFORMANCE_FULL_PIPELINE_RESULT_MISMATCH",
                "probe": "changed_full_pipeline_probe",
                "metric": result_key,
                "expected": expected_distribution,
                "actual": changed_full_pipeline.get(result_key),
            })
    return {
        "schema": "java-upgrade-analyzer.binary-performance-gate-evaluation.v1",
        "status": "passed" if not issues else "failed",
        "issue_count": len(issues),
        "issues": issues,
        "warm_relative_legacy_ratio": warm_ratio,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Measure binary-first scale performance")
    parser.add_argument("--work-root", default="")
    parser.add_argument("--output", required=True)
    parser.add_argument("--jar-count", type=int, default=400)
    parser.add_argument("--classes-per-jar", type=int, default=250)
    parser.add_argument("--warm-samples", type=int, default=3)
    parser.add_argument("--skip-legacy", action="store_true")
    parser.add_argument("--gate", default="")
    args = parser.parse_args(argv)
    if args.jar_count <= 0 or args.classes_per_jar <= 0 or args.warm_samples <= 0:
        parser.error("scale and sample counts must be positive")
    temporary = None
    if args.work_root:
        root = Path(args.work_root).expanduser().resolve()
    else:
        temporary = short_temporary_directory(prefix="binary-performance")
        root = Path(temporary.__enter__())
    try:
        result = run_benchmark(
            root,
            jar_count=args.jar_count,
            classes_per_jar=args.classes_per_jar,
            warm_samples=args.warm_samples,
            include_legacy=not args.skip_legacy,
        )
        evaluation = None
        if args.gate:
            gate = json.loads(Path(args.gate).expanduser().resolve().read_text(encoding="utf-8"))
            evaluation = evaluate_gate(result, gate)
            result["gate_evaluation"] = evaluation
        output = Path(args.output).expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({
            "status": result["status"],
            "dataset_identity": result["measurement_protocol"]["dataset_identity"],
            "cold_seconds": result["measurements"]["cold"]["end_to_end_seconds"],
            "warm_p95_seconds": result["measurements"]["warm_end_to_end_p95_seconds"],
            "legacy_seconds": (result["measurements"]["legacy"] or {}).get("end_to_end_seconds"),
            "full_pipeline_seconds": (
                result["measurements"]["full_pipeline_probe"]
            ).get("end_to_end_seconds"),
            "changed_full_pipeline_seconds": (
                result["measurements"]["changed_full_pipeline_probe"]
            ).get("end_to_end_seconds"),
            "gate_status": (evaluation or {}).get("status"),
        }, sort_keys=True))
        return 0 if not evaluation or evaluation["status"] == "passed" else 1
    finally:
        if temporary is not None:
            temporary.__exit__(None, None, None)


if __name__ == "__main__":
    raise SystemExit(main())
