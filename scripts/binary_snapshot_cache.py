#!/usr/bin/env python3
"""Content-addressed artifact snapshot cache with ArtifactInstance rebinding."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any
import zlib

from binary_artifact_diff import ArchiveEntryFact, ArtifactSnapshot, snapshot_archive
from binary_asm_helper import parser_identity, resolve_asm_jar
from binary_first_contract import BinaryFirstContractError, canonical_identity


CACHE_SCHEMA = "java-upgrade-analyzer.binary-snapshot-cache.v1"
CACHE_POLICY_VERSION = "artifact-content-parser-rebind-v1"


class BinarySnapshotCacheError(BinaryFirstContractError):
    pass


@dataclass(frozen=True)
class SnapshotCacheOutcome:
    snapshot: ArtifactSnapshot
    cache_status: str
    parser_invocation_count: int
    cache_key: str


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _cache_key(content_sha256: str, parser_id: str) -> str:
    return _identity("binary_snapshot_cache_key", {
        "artifact_content_sha256": content_sha256,
        "parser_identity": parser_id,
        "cache_policy_version": CACHE_POLICY_VERSION,
    })


def _template_payload(snapshot: ArtifactSnapshot) -> dict[str, Any]:
    return {
        "artifact_content_sha256": snapshot.artifact_content_sha256,
        "artifact_byte_length": snapshot.artifact_byte_length,
        "archive_comment_sha256": snapshot.archive_comment_sha256,
        "entries": [asdict(item) for item in snapshot.entries],
        "class_records": list(snapshot.class_records),
        "class_payloads": [
            [label, base64.b64encode(content).decode("ascii")]
            for label, content in snapshot.class_payloads
        ],
        "safety_reason_codes": list(snapshot.safety_reason_codes),
        "parse_failure_count": snapshot.parse_failure_count,
        "unknown_attribute_scopes": list(snapshot.unknown_attribute_scopes),
        "unknown_resource_scopes": list(snapshot.unknown_resource_scopes),
        "parser_identity": snapshot.parser_identity,
        "comparison_coverage_status": snapshot.comparison_coverage_status,
    }


def _decode_template(path: Path, expected_key: str) -> dict[str, Any]:
    try:
        envelope = json.loads(zlib.decompress(path.read_bytes()).decode("utf-8"))
    except (OSError, zlib.error, UnicodeError, json.JSONDecodeError) as error:
        raise BinarySnapshotCacheError("BINARY_SNAPSHOT_CACHE_CORRUPT", str(error)) from error
    if envelope.get("schema") != CACHE_SCHEMA or envelope.get("cache_key") != expected_key:
        raise BinarySnapshotCacheError("BINARY_SNAPSHOT_CACHE_IDENTITY_MISMATCH", str(path))
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or hashlib.sha256(_json_bytes(payload)).hexdigest() != envelope.get("payload_sha256"):
        raise BinarySnapshotCacheError("BINARY_SNAPSHOT_CACHE_DIGEST_MISMATCH", str(path))
    return payload


def _write_template(path: Path, cache_key: str, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    envelope = {
        "schema": CACHE_SCHEMA,
        "cache_key": cache_key,
        "cache_policy_version": CACHE_POLICY_VERSION,
        "payload_sha256": hashlib.sha256(_json_bytes(payload)).hexdigest(),
        "payload": payload,
    }
    content = zlib.compress(_json_bytes(envelope), level=6)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".snapshot-cache-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _rebind(payload: dict[str, Any], artifact_instance_identity: str) -> ArtifactSnapshot:
    entries = []
    for raw in payload["entries"]:
        item = dict(raw)
        item["physical_entry_identity"] = _identity(
            "archive_physical_entry_identity",
            {
                "artifact_instance_identity": artifact_instance_identity,
                "entry_name": item["name"],
                "name_ordinal": item["name_ordinal"],
                "archive_ordinal": item["archive_ordinal"],
                "content_sha256": item["content_sha256"],
            },
        )
        item["timestamp"] = tuple(item.get("timestamp") or ())
        item["resource_semantic_facts"] = tuple(
            tuple(value) for value in item.get("resource_semantic_facts") or ()
        )
        entries.append(ArchiveEntryFact(**item))
    records = []
    for raw in payload["class_records"]:
        record = dict(raw)
        record["artifact_instance_identity"] = artifact_instance_identity
        records.append(record)
    inventory_digest = _identity("binary_cached_artifact_inventory", {
        "artifact_instance_identity": artifact_instance_identity,
        "artifact_content_sha256": payload["artifact_content_sha256"],
        "archive_comment_sha256": payload["archive_comment_sha256"],
        "entries": [asdict(item) for item in entries],
        "parser_identity": payload["parser_identity"],
        "cache_policy_version": CACHE_POLICY_VERSION,
    })
    return ArtifactSnapshot(
        artifact_instance_identity=artifact_instance_identity,
        artifact_content_sha256=payload["artifact_content_sha256"],
        artifact_byte_length=int(payload["artifact_byte_length"]),
        archive_comment_sha256=payload["archive_comment_sha256"],
        entries=tuple(entries),
        class_records=tuple(records),
        class_payloads=tuple(
            (label, base64.b64decode(content, validate=True))
            for label, content in payload["class_payloads"]
        ),
        safety_reason_codes=tuple(payload["safety_reason_codes"]),
        parse_failure_count=int(payload["parse_failure_count"]),
        unknown_attribute_scopes=tuple(payload["unknown_attribute_scopes"]),
        unknown_resource_scopes=tuple(payload["unknown_resource_scopes"]),
        inventory_digest=inventory_digest,
        parser_identity=payload["parser_identity"],
        comparison_coverage_status=payload["comparison_coverage_status"],
    )


def cached_snapshot_archive(
    path: str | Path,
    *,
    artifact_instance_identity: str,
    expected_sha256: str,
    cache_root: str | Path,
    asm_jar: str | Path | None = None,
) -> SnapshotCacheOutcome:
    archive = Path(path)
    actual_sha = _sha256_file(archive)
    if actual_sha != expected_sha256:
        raise BinarySnapshotCacheError(
            "BINARY_SNAPSHOT_CACHE_ARTIFACT_SHA_MISMATCH",
            f"expected={expected_sha256}; actual={actual_sha}",
        )
    asm_path = resolve_asm_jar(asm_jar)
    parser_id, _helper_sha = parser_identity(asm_jar=asm_path)
    key = _cache_key(actual_sha, parser_id)
    cache_path = Path(cache_root) / "artifact_snapshots" / parser_id / f"{key}.json.zlib"
    cache_status = "miss"
    parser_invocations = 0
    payload = None
    if cache_path.is_file():
        try:
            payload = _decode_template(cache_path, key)
            if (
                payload.get("artifact_content_sha256") != actual_sha
                or payload.get("parser_identity") != parser_id
            ):
                raise BinarySnapshotCacheError(
                    "BINARY_SNAPSHOT_CACHE_CONTENT_MISMATCH", str(cache_path)
                )
            cache_status = "hit"
        except BinarySnapshotCacheError:
            cache_status = "corrupt_rebuilt"
            payload = None
    if payload is None:
        template = snapshot_archive(
            archive,
            artifact_instance_identity=f"CACHE-TEMPLATE:{key}",
            expected_sha256=actual_sha,
            asm_jar=asm_path,
        )
        parser_invocations = 1
        payload = _template_payload(template)
        _write_template(cache_path, key, payload)
    return SnapshotCacheOutcome(
        snapshot=_rebind(payload, artifact_instance_identity),
        cache_status=cache_status,
        parser_invocation_count=parser_invocations,
        cache_key=key,
    )


__all__ = [
    "BinarySnapshotCacheError",
    "CACHE_POLICY_VERSION",
    "SnapshotCacheOutcome",
    "cached_snapshot_archive",
]
