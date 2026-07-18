#!/usr/bin/env python3
"""Metamorphic transforms and strict semantic report normalization."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json

from generated_topology import GeneratedTopology


TRANSFORM_IDS = (
    "archive_order",
    "dependency_order",
    "module_directory_rename",
    "timestamps",
    "unrelated_classes",
    "worker_counts",
    "bridge_placement",
    "jar_war_layout",
)

VOLATILE_FIELDS = {
    "absolute_path",
    "elapsed",
    "elapsed_ms",
    "elapsed_sec",
    "generated_at",
    "pid",
    "process_id",
    "report_path",
    "timestamp",
}


@dataclass(frozen=True)
class TransformedTopology:
    case: GeneratedTopology
    transform_id: str
    execution_variant: dict


def _canonical(value):
    if isinstance(value, dict):
        return {
            key: _canonical(item)
            for key, item in sorted(value.items())
            if key not in VOLATILE_FIELDS
        }
    if isinstance(value, list):
        normalized = [_canonical(item) for item in value]
        if all(isinstance(item, dict) and "identity" in item for item in normalized):
            return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True))
        return normalized
    if isinstance(value, tuple):
        return _canonical(list(value))
    return value


def semantic_digest(report: dict) -> str:
    retained = {
        "apis": report.get("apis", []),
        "edges": report.get("edges", []),
        "completeness": report.get("completeness", {}),
        "reason_codes": report.get("reason_codes", []),
    }
    encoded = json.dumps(
        _canonical(retained), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def apply_transform(case: GeneratedTopology, transform_id: str) -> TransformedTopology:
    if transform_id not in TRANSFORM_IDS:
        raise ValueError(f"unknown metamorphic transform: {transform_id}")
    spec = case.spec
    variant: dict = {"transform": transform_id}
    if transform_id == "archive_order":
        spec = replace(spec, sources=tuple(reversed(spec.sources)))
        variant["archive_order"] = "reversed"
    elif transform_id == "dependency_order":
        spec = replace(spec, modules=tuple(reversed(spec.modules)))
        variant["dependency_order"] = "reversed"
    elif transform_id == "module_directory_rename":
        spec = replace(
            spec,
            sources=tuple((f"renamed-module/{path}", content) for path, content in spec.sources),
        )
        variant["module_directory"] = "renamed-module"
    elif transform_id == "timestamps":
        variant["zip_timestamp"] = "2001-02-03T04:05:06Z"
    elif transform_id == "unrelated_classes":
        spec = replace(
            spec,
            sources=spec.sources
            + (("generated/Unrelated.java", "package generated; final class Unrelated {}\n"),),
        )
        variant["unrelated_class"] = "generated.Unrelated"
    elif transform_id == "worker_counts":
        variant["workers"] = 4
    elif transform_id == "bridge_placement":
        variant["bridge_module"] = "library"
    elif transform_id == "jar_war_layout":
        spec = replace(
            spec,
            modules=tuple(
                replace(module, packaging="war" if module.name == "application" else module.packaging)
                for module in spec.modules
            ),
        )
        variant["layout"] = "WEB-INF/lib"
    return TransformedTopology(GeneratedTopology(spec), transform_id, variant)
