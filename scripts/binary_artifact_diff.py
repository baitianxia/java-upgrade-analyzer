#!/usr/bin/env python3
"""Artifact-local archive/class/resource comparison backed by pinned ASM facts.

This layer deliberately does not claim runtime effectiveness.  It inventories
physical container entries and produces scope-independent observed deltas for
the later loader/provider/definition reconciliation phase.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
import fnmatch
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping
import zipfile

from artifact_safety import inspect_archive
from binary_asm_helper import BinaryClassInput, BinaryFactRun, extract_class_facts
from binary_first_contract import (
    BinaryFirstContractError,
    canonical_identity,
    observed_delta_identity,
)


SUPPORT_MANIFEST_PATH = Path(__file__).with_name("binary_first_support_manifest.json")
_SUPPORT = json.loads(SUPPORT_MANIFEST_PATH.read_text(encoding="utf-8"))
_ARTIFACT_SUPPORT = _SUPPORT["artifact_diff_support_manifest"]
_SAFETY = _ARTIFACT_SUPPORT["artifact_safety_policy"]
_ATTRIBUTE_POLICY = _ARTIFACT_SUPPORT["classfile_attribute_policy"]
_RESOURCE_POLICY = _ARTIFACT_SUPPORT["resource_policy"]


class BinaryArtifactDiffError(BinaryFirstContractError):
    pass


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


def _mr_class_scope(name: str) -> tuple[str, int]:
    path = PurePosixPath(name)
    parts = path.parts
    if len(parts) >= 4 and parts[:2] == ("META-INF", "versions"):
        try:
            version = int(parts[2])
        except ValueError:
            return name, 0
        return "/".join(parts[3:]), version
    return name, 0


def _classify_resource(name: str) -> str:
    if name.endswith("/"):
        return "directory"
    categories = (
        ("runtime_topology", _RESOURCE_POLICY["runtime_topology"]),
        ("operational_security", _RESOURCE_POLICY["operational_security"]),
        ("distribution_metadata", _RESOURCE_POLICY["distribution_metadata"]),
        ("build_metadata", _RESOURCE_POLICY["build_metadata"]),
        ("runtime_native", _RESOURCE_POLICY["native_extensions"]),
    )
    upper_name = name.upper()
    for category, patterns in categories:
        for pattern in patterns:
            candidate = upper_name if pattern.upper().startswith("META-INF/") else name.lower()
            match_pattern = pattern.upper() if pattern.upper().startswith("META-INF/") else pattern.lower()
            if fnmatch.fnmatchcase(candidate, match_pattern):
                return category
    return "unknown"


def _normalized_resource_digest(name: str, category: str, content: bytes) -> str:
    if category != "runtime_topology":
        return _sha256_bytes(content)
    text = content.decode("utf-8", errors="surrogateescape").replace("\r\n", "\n").replace("\r", "\n")
    if name.startswith("META-INF/services/") or name.startswith("META-INF/spring/"):
        lines = []
        for line in text.splitlines():
            value = line.split("#", 1)[0].strip()
            if value:
                lines.append(value)
        return _identity("ordered_runtime_resource_lines", {"lines": lines})
    # java.util.Properties escaping/duplicate-key semantics are reconciled later;
    # normalize only line endings here and keep the comparison conservative.
    return _sha256_bytes(text.encode("utf-8", errors="surrogateescape"))


def _resource_semantic_facts(name: str, category: str, content: bytes) -> tuple[tuple[str, str], ...]:
    if category not in {"runtime_topology", "distribution_metadata"}:
        return ()
    text = content.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    if name.upper() == "META-INF/MANIFEST.MF":
        unfolded = []
        for line in text.split("\n"):
            if line.startswith(" ") and unfolded:
                unfolded[-1] += line[1:]
            else:
                unfolded.append(line)
        facts = []
        for line in unfolded:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            facts.append((key.strip().lower(), value.strip()))
        return tuple(facts)
    if name.startswith("META-INF/services/") or name.startswith("META-INF/spring/"):
        facts = []
        for line in text.splitlines():
            value = line.split("#", 1)[0].strip()
            if value:
                facts.append(("ordered_entry", value))
        return tuple(facts)
    return ()


@dataclass(frozen=True)
class ArchiveEntryFact:
    physical_entry_identity: str
    name: str
    name_ordinal: int
    archive_ordinal: int
    kind: str
    content_sha256: str
    byte_length: int
    crc32: int
    compression_method: int
    compressed_size: int
    timestamp: tuple[int, int, int, int, int, int]
    external_attributes: int
    extra_sha256: str
    comment_sha256: str
    logical_class_entry: str = ""
    multi_release_version: int = 0
    resource_category: str = ""
    normalized_resource_digest: str = ""
    resource_semantic_facts: tuple[tuple[str, str], ...] = ()

    @property
    def alignment_key(self) -> tuple[str, int]:
        return self.name, self.name_ordinal


@dataclass(frozen=True)
class ArtifactSnapshot:
    artifact_instance_identity: str
    artifact_content_sha256: str
    artifact_byte_length: int
    archive_comment_sha256: str
    entries: tuple[ArchiveEntryFact, ...]
    class_records: tuple[dict[str, Any], ...]
    class_payloads: tuple[tuple[str, bytes], ...]
    safety_reason_codes: tuple[str, ...]
    parse_failure_count: int
    unknown_attribute_scopes: tuple[str, ...]
    unknown_resource_scopes: tuple[str, ...]
    inventory_digest: str
    parser_identity: str
    comparison_coverage_status: str

    @property
    def class_fact_coverage_status(self) -> str:
        """Coverage of class facts, independent of resource semantics.

        An unregistered resource type makes that resource's semantic comparison
        incomplete, but it does not make successfully parsed classfiles
        incomplete.  Keeping those scopes separate prevents one ordinary
        resource from suppressing every method and field change in the JAR.
        """
        incomplete = bool(
            self.safety_reason_codes
            or self.parse_failure_count
            or self.unknown_attribute_scopes
        )
        return "partial" if incomplete else "complete"

    def class_records_by_entry(self) -> dict[str, dict[str, Any]]:
        return {
            str(item.get("class_entry") or ""): item
            for item in self.class_records
        }


def _validate_expected_sha(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise BinaryArtifactDiffError(
            "ARTIFACT_EXPECTED_SHA256_INVALID", "a Step1-bound lowercase SHA-256 is required"
        )
    return normalized


def snapshot_archive(
    path: str | Path,
    *,
    artifact_instance_identity: str,
    expected_sha256: str,
    asm_jar: str | Path | None = None,
) -> ArtifactSnapshot:
    archive_path = Path(path)
    expected_sha256 = _validate_expected_sha(expected_sha256)
    if not archive_path.is_file():
        raise BinaryArtifactDiffError("ARTIFACT_FILE_MISSING", str(archive_path))
    before_sha = _sha256_file(archive_path)
    if before_sha != expected_sha256:
        raise BinaryArtifactDiffError(
            "ARTIFACT_SHA256_MISMATCH",
            f"expected={expected_sha256}; actual={before_sha}",
        )
    safety = inspect_archive(
        archive_path,
        max_entries=int(_SAFETY["max_archive_entries"]),
        max_total_uncompressed_bytes=int(_SAFETY["max_total_uncompressed_bytes"]),
        max_nested_depth=int(_SAFETY["max_nested_depth"]),
        max_nested_archive_bytes=int(_SAFETY["max_nested_archive_bytes"]),
        inspect_nested_archives=False,
        allow_duplicate_maven_metadata=True,
    )
    blocking_safety = tuple(
        reason for reason in safety.reason_codes
        if reason != "ARCHIVE_DUPLICATE_ENTRY"
    )
    if blocking_safety:
        raise BinaryArtifactDiffError(
            "ARTIFACT_SAFETY_POLICY_BLOCKED",
            f"{archive_path}: {', '.join(blocking_safety)}",
        )

    entries = []
    class_inputs = []
    name_counts: Counter[str] = Counter()
    archive_comment_sha = _sha256_bytes(b"")
    try:
        with zipfile.ZipFile(archive_path) as archive:
            archive_comment_sha = _sha256_bytes(archive.comment or b"")
            for archive_ordinal, info in enumerate(archive.infolist()):
                name_ordinal = name_counts[info.filename]
                name_counts[info.filename] += 1
                try:
                    content = b"" if info.is_dir() else archive.read(info)
                except (KeyError, OSError, RuntimeError, zipfile.BadZipFile) as error:
                    raise BinaryArtifactDiffError(
                        "ARTIFACT_ENTRY_READ_FAILED", f"{info.filename}: {error}"
                    ) from error
                content_sha = _sha256_bytes(content)
                physical_identity = _identity(
                    "archive_physical_entry_identity",
                    {
                        "artifact_instance_identity": artifact_instance_identity,
                        "entry_name": info.filename,
                        "name_ordinal": name_ordinal,
                        "archive_ordinal": archive_ordinal,
                        "content_sha256": content_sha,
                    },
                )
                physical_label = f"{info.filename}#occurrence={name_ordinal}"
                logical_class, mr_version = _mr_class_scope(info.filename)
                is_class = not info.is_dir() and info.filename.endswith(".class")
                category = "" if is_class else _classify_resource(info.filename)
                entry = ArchiveEntryFact(
                    physical_entry_identity=physical_identity,
                    name=info.filename,
                    name_ordinal=name_ordinal,
                    archive_ordinal=archive_ordinal,
                    kind="class" if is_class else ("directory" if info.is_dir() else "resource"),
                    content_sha256=content_sha,
                    byte_length=len(content),
                    crc32=int(info.CRC),
                    compression_method=int(info.compress_type),
                    compressed_size=int(info.compress_size),
                    timestamp=tuple(info.date_time),
                    external_attributes=int(info.external_attr),
                    extra_sha256=_sha256_bytes(info.extra or b""),
                    comment_sha256=_sha256_bytes(info.comment or b""),
                    logical_class_entry=logical_class if is_class else "",
                    multi_release_version=mr_version if is_class else 0,
                    resource_category=category,
                    normalized_resource_digest=(
                        _normalized_resource_digest(info.filename, category, content)
                        if not is_class and not info.is_dir() else ""
                    ),
                    resource_semantic_facts=(
                        _resource_semantic_facts(info.filename, category, content)
                        if not is_class and not info.is_dir() else ()
                    ),
                )
                entries.append(entry)
                if is_class:
                    class_inputs.append(BinaryClassInput(
                        artifact_instance_identity,
                        physical_label,
                        content,
                    ))
    except zipfile.BadZipFile as error:
        raise BinaryArtifactDiffError("ARTIFACT_ARCHIVE_INVALID", str(error)) from error

    after_sha = _sha256_file(archive_path)
    if after_sha != before_sha:
        raise BinaryArtifactDiffError(
            "ARTIFACT_CHANGED_DURING_SNAPSHOT", str(archive_path)
        )
    asm_run: BinaryFactRun = extract_class_facts(
        class_inputs,
        asm_jar=asm_jar,
        max_class_bytes=int(_SAFETY["max_class_bytes"]),
        max_frame_bytes=int(_SAFETY["max_protocol_frame_bytes"]),
        max_records=int(_SAFETY["max_fact_records"]),
        timeout_seconds=int(_SAFETY["helper_timeout_seconds"]),
    )

    recognized = set(_ATTRIBUTE_POLICY["recognized_by_typed_facts"])
    definition_sensitive = set(_ATTRIBUTE_POLICY["definition_sensitive_raw"])
    diagnostic = set(_ATTRIBUTE_POLICY["diagnostic_only_raw"])
    known_attributes = recognized | definition_sensitive | diagnostic
    unknown_attribute_scopes = []
    for record in asm_run.records:
        if record.get("frame_type") != "class_fact":
            continue
        for attribute in record.get("attribute_inventory") or ():
            if attribute.get("name") not in known_attributes:
                unknown_attribute_scopes.append(
                    f"{record.get('class_entry')}:{attribute.get('level')}:{attribute.get('name')}"
                )
    unknown_resource_scopes = [
        item.name for item in entries
        if item.kind == "resource" and item.resource_category == "unknown"
    ]
    inventory_payload = {
        "artifact_instance_identity": artifact_instance_identity,
        "artifact_content_sha256": before_sha,
        "archive_comment_sha256": archive_comment_sha,
        "entries": [asdict(item) for item in entries],
        "parser_identity": asm_run.parser_identity,
        "class_input_digest": asm_run.class_input_digest,
        "fact_output_digest": asm_run.fact_output_digest,
        "safety_reason_codes": list(safety.reason_codes),
    }
    incomplete = bool(
        safety.reason_codes
        or asm_run.failure_record_count
        or unknown_attribute_scopes
        or unknown_resource_scopes
    )
    return ArtifactSnapshot(
        artifact_instance_identity=artifact_instance_identity,
        artifact_content_sha256=before_sha,
        artifact_byte_length=archive_path.stat().st_size,
        archive_comment_sha256=archive_comment_sha,
        entries=tuple(entries),
        class_records=asm_run.records,
        class_payloads=tuple(
            (item.class_entry, item.class_bytes) for item in class_inputs
        ),
        safety_reason_codes=tuple(safety.reason_codes),
        parse_failure_count=asm_run.failure_record_count,
        unknown_attribute_scopes=tuple(sorted(set(unknown_attribute_scopes))),
        unknown_resource_scopes=tuple(sorted(set(unknown_resource_scopes))),
        inventory_digest=_identity("binary_artifact_inventory", inventory_payload),
        parser_identity=asm_run.parser_identity,
        comparison_coverage_status="partial" if incomplete else "complete",
    )


def _attribute_digest_map(record: dict[str, Any], names: set[str]) -> dict[tuple, tuple[str, ...]]:
    grouped: dict[tuple, list[str]] = defaultdict(list)
    for attribute in record.get("attribute_inventory") or ():
        if attribute.get("name") in names:
            key = (attribute.get("level"), attribute.get("owner"), attribute.get("name"))
            grouped[key].append(str(attribute.get("sha256") or ""))
    return {key: tuple(values) for key, values in grouped.items()}


def _method_digest_map(record: dict[str, Any]) -> dict[tuple[str, str], str]:
    result = {}
    for method in record.get("methods") or ():
        contract = method.get("contract") or {}
        result[(str(contract.get("name") or ""), str(contract.get("descriptor") or ""))] = str(
            method.get("implementation_digest") or ""
        )
    return result


def _member_fact_map(record: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    result = {}
    for field in record.get("fields") or ():
        key = ("field", str(field.get("name") or ""), str(field.get("descriptor") or ""))
        result[key] = {
            "contract": field,
            "contract_digest": _identity("artifact_local_field_contract", field),
            "implementation_digest": "",
        }
    for method in record.get("methods") or ():
        contract = method.get("contract") or {}
        key = ("method", str(contract.get("name") or ""), str(contract.get("descriptor") or ""))
        result[key] = {
            "contract": contract,
            "contract_digest": _identity("artifact_local_method_contract", contract),
            "implementation_digest": str(method.get("implementation_digest") or ""),
        }
    return result


def _member_deltas(
    old_record: dict[str, Any],
    new_record: dict[str, Any],
    *,
    entry_scope: Mapping[str, Any],
    comparison_or_runtime_scope: Any,
) -> list[dict[str, Any]]:
    old_members = _member_fact_map(old_record)
    new_members = _member_fact_map(new_record)
    deltas = []
    for key in sorted(set(old_members) | set(new_members)):
        old = old_members.get(key)
        new = new_members.get(key)
        if old == new:
            continue
        if old is None:
            change_kind = "added"
        elif new is None:
            change_kind = "removed"
        elif old["contract_digest"] != new["contract_digest"]:
            change_kind = "contract_changed"
        elif old["implementation_digest"] != new["implementation_digest"]:
            change_kind = "implementation_changed"
        else:
            continue
        scope = {
            **dict(entry_scope),
            "member_kind": key[0],
            "member_name": key[1],
            "descriptor": key[2],
        }
        base_fingerprint = (
            _identity("artifact_local_member_fingerprint", old) if old else "ABSENT"
        )
        current_fingerprint = (
            _identity("artifact_local_member_fingerprint", new) if new else "ABSENT"
        )
        deltas.append({
            "member_scope": scope,
            "member_change_kind": change_kind,
            "base_member_fingerprint": base_fingerprint,
            "current_member_fingerprint": current_fingerprint,
            "base_contract": (old or {}).get("contract"),
            "current_contract": (new or {}).get("contract"),
            "observed_delta_identity": observed_delta_identity(
                delta_source_kind="artifact_local",
                comparison_or_runtime_scope=comparison_or_runtime_scope,
                fact_or_mechanism_scope=scope,
                base_fingerprint=base_fingerprint,
                current_fingerprint=current_fingerprint,
            ),
        })
    return deltas


def compare_artifact_snapshots(
    base: ArtifactSnapshot,
    current: ArtifactSnapshot,
    *,
    comparison_or_runtime_scope: Any,
) -> dict[str, Any]:
    base_entries = {item.alignment_key: item for item in base.entries}
    current_entries = {item.alignment_key: item for item in current.entries}
    all_keys = sorted(set(base_entries) | set(current_entries))
    entry_deltas = []
    class_categories = set()
    resource_categories = set()
    coverage_gaps = set(base.safety_reason_codes) | set(current.safety_reason_codes)

    base_records = base.class_records_by_entry()
    current_records = current.class_records_by_entry()
    recognized = set(_ATTRIBUTE_POLICY["recognized_by_typed_facts"])
    definition_sensitive = set(_ATTRIBUTE_POLICY["definition_sensitive_raw"])
    diagnostic = set(_ATTRIBUTE_POLICY["diagnostic_only_raw"])
    known_attributes = recognized | definition_sensitive | diagnostic

    for key in all_keys:
        old = base_entries.get(key)
        new = current_entries.get(key)
        if old and new and old.content_sha256 == new.content_sha256:
            continue
        scope = {
            "entry_name": key[0],
            "name_ordinal": key[1],
            "entry_kind": (new or old).kind,
        }
        old_sha = old.content_sha256 if old else "ABSENT"
        new_sha = new.content_sha256 if new else "ABSENT"
        delta = {
            "entry_scope": scope,
            "base_content_sha256": old_sha,
            "current_content_sha256": new_sha,
            "observed_delta_identity": observed_delta_identity(
                delta_source_kind="artifact_local",
                comparison_or_runtime_scope=comparison_or_runtime_scope,
                fact_or_mechanism_scope=scope,
                base_fingerprint=old_sha,
                current_fingerprint=new_sha,
            ),
        }
        if (old or new).kind == "class":
            if old is None or new is None:
                category = "contract_changed"
            else:
                old_record = base_records.get(f"{old.name}#occurrence={old.name_ordinal}")
                new_record = current_records.get(f"{new.name}#occurrence={new.name_ordinal}")
                if not old_record or not new_record or {
                    old_record.get("frame_type"), new_record.get("frame_type")
                } != {"class_fact"}:
                    category = "incomplete"
                    coverage_gaps.add(f"class_parse:{key[0]}#{key[1]}")
                else:
                    old_unknown = {
                        item.get("name") for item in old_record.get("attribute_inventory") or ()
                        if item.get("name") not in known_attributes
                    }
                    new_unknown = {
                        item.get("name") for item in new_record.get("attribute_inventory") or ()
                        if item.get("name") not in known_attributes
                    }
                    if old_unknown or new_unknown:
                        category = "incomplete"
                        coverage_gaps.add(
                            f"unknown_attributes:{key[0]}:{','.join(sorted(old_unknown | new_unknown))}"
                        )
                    elif old_record.get("class_contract_digest") != new_record.get("class_contract_digest"):
                        category = "contract_changed"
                    elif _method_digest_map(old_record) != _method_digest_map(new_record):
                        category = "implementation_changed"
                    elif _attribute_digest_map(old_record, definition_sensitive) != _attribute_digest_map(new_record, definition_sensitive):
                        category = "runtime_metadata_changed"
                    elif _attribute_digest_map(old_record, diagnostic) != _attribute_digest_map(new_record, diagnostic):
                        category = "runtime_diagnostic_metadata_changed"
                    else:
                        category = "classfile_noise_only"
                    delta["member_deltas"] = _member_deltas(
                        old_record,
                        new_record,
                        entry_scope=scope,
                        comparison_or_runtime_scope=comparison_or_runtime_scope,
                    )
            class_categories.add(category)
            delta["class_change_category"] = category
        elif (old or new).kind == "resource":
            categories = {item.resource_category for item in (old, new) if item}
            if "unknown" in categories:
                category = "unknown"
                coverage_gaps.add(f"unknown_resource:{key[0]}#{key[1]}")
            elif len(categories) == 1:
                category = next(iter(categories))
            else:
                category = "mixed"
            resource_categories.add(category)
            delta["resource_change_category"] = category
            delta["base_normalized_digest"] = old.normalized_resource_digest if old else "ABSENT"
            delta["current_normalized_digest"] = new.normalized_resource_digest if new else "ABSENT"
        else:
            delta["container_change_category"] = "directory_metadata"
        entry_deltas.append(delta)

    if not class_categories:
        class_status = "none"
    elif len(class_categories) == 1:
        class_status = next(iter(class_categories))
    elif class_categories <= {"classfile_noise_only", "runtime_diagnostic_metadata_changed"}:
        class_status = "runtime_diagnostic_metadata_changed"
    elif "incomplete" in class_categories:
        class_status = "incomplete"
    else:
        class_status = "mixed"

    resource_status_map = {
        "build_metadata": "build_metadata_only",
        "distribution_metadata": "distribution_metadata_only",
        "operational_security": "operational_security_changed",
        "runtime_native": "runtime_native_changed",
        "runtime_topology": "runtime_topology_changed",
        "unknown": "unknown",
    }
    mapped_resources = {resource_status_map.get(item, "mixed") for item in resource_categories}
    resource_status = "none" if not mapped_resources else (
        next(iter(mapped_resources)) if len(mapped_resources) == 1 else "mixed"
    )

    payload_sequence_base = [(item.name, item.name_ordinal, item.content_sha256) for item in base.entries]
    payload_sequence_current = [(item.name, item.name_ordinal, item.content_sha256) for item in current.entries]
    full_container_base = [asdict(item) for item in base.entries]
    full_container_current = [asdict(item) for item in current.entries]
    if base.artifact_content_sha256 == current.artifact_content_sha256:
        container_status = "identical"
    elif payload_sequence_base == payload_sequence_current:
        container_status = "packaging_noise_only"
    elif class_status == "none" and resource_status in {
        "distribution_metadata_only", "operational_security_changed"
    }:
        container_status = "runtime_observable_metadata_changed"
    else:
        container_status = "payload_changed"

    comparison_coverage = "partial" if coverage_gaps else "complete"
    result = {
        "schema": "java-upgrade-analyzer.binary-artifact-local-diff.v1",
        "authority": "artifact_local_observation_only",
        "base_artifact_instance_identity": base.artifact_instance_identity,
        "current_artifact_instance_identity": current.artifact_instance_identity,
        "base_inventory_digest": base.inventory_digest,
        "current_inventory_digest": current.inventory_digest,
        "parser_identity": current.parser_identity,
        "container_diff_status": container_status,
        "class_diff_status": class_status,
        "resource_diff_status": resource_status,
        "comparison_coverage_status": comparison_coverage,
        "class_comparison_coverage_status": (
            "partial"
            if any(not gap.startswith("unknown_resource:") for gap in coverage_gaps)
            else "complete"
        ),
        "coverage_gaps": sorted(coverage_gaps),
        "entry_deltas": entry_deltas,
        "entry_delta_count": len(entry_deltas),
        "container_metadata_changed": full_container_base != full_container_current,
        "runtime_effective_diff_summary": "unknown",
        "promotion_status": "candidate" if entry_deltas else "audit_only",
    }
    result["artifact_local_result_identity"] = _identity(
        "artifact_local_diff_result",
        {key: value for key, value in result.items() if key != "artifact_local_result_identity"},
    )
    return result


def compare_archives(
    base_path: str | Path,
    current_path: str | Path,
    *,
    base_artifact_instance_identity: str,
    current_artifact_instance_identity: str,
    base_expected_sha256: str,
    current_expected_sha256: str,
    comparison_or_runtime_scope: Any,
    asm_jar: str | Path | None = None,
) -> tuple[ArtifactSnapshot, ArtifactSnapshot, dict[str, Any]]:
    base = snapshot_archive(
        base_path,
        artifact_instance_identity=base_artifact_instance_identity,
        expected_sha256=base_expected_sha256,
        asm_jar=asm_jar,
    )
    current = snapshot_archive(
        current_path,
        artifact_instance_identity=current_artifact_instance_identity,
        expected_sha256=current_expected_sha256,
        asm_jar=asm_jar,
    )
    return base, current, compare_artifact_snapshots(
        base,
        current,
        comparison_or_runtime_scope=comparison_or_runtime_scope,
    )


__all__ = [
    "ArchiveEntryFact",
    "ArtifactSnapshot",
    "BinaryArtifactDiffError",
    "compare_archives",
    "compare_artifact_snapshots",
    "snapshot_archive",
]
