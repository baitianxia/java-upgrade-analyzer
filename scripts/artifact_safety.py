#!/usr/bin/env python3
"""Bounded, fail-closed validation for JAR/WAR/ZIP analysis inputs."""

from dataclasses import dataclass
from collections import Counter, OrderedDict
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import threading
import zipfile


_DUPLICATE_MAVEN_METADATA_PATTERN = re.compile(
    r"^META-INF/maven/[^/]+/[^/]+/(?:pom\.properties|pom\.xml)$"
)


@dataclass(frozen=True)
class ArchiveSafetyResult:
    safe: bool
    reason_codes: tuple[str, ...]
    entry_count: int
    total_uncompressed_bytes: int
    nested_archives: int
    max_observed_depth: int
    details: tuple[str, ...] = ()


def _unsafe_entry_name(name):
    value = str(name or "")
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    return bool(
        not value
        or "\x00" in value
        or value.startswith(("/", "\\"))
        or re.match(r"^[A-Za-z]:", value)
        or "\\" in value
        or ".." in path.parts
    )


def is_allowed_duplicate_archive_entry(
    name, *, allow_duplicate_maven_metadata=False,
):
    return bool(
        allow_duplicate_maven_metadata
        and _DUPLICATE_MAVEN_METADATA_PATTERN.fullmatch(str(name or ""))
    )


def _inspect_archive_source(
    source,
    *,
    max_entries=100_000,
    max_total_uncompressed_bytes=2 * 1024 * 1024 * 1024,
    max_expansion_ratio=200,
    max_nested_depth=3,
    max_nested_archive_bytes=64 * 1024 * 1024,
    inspect_nested_archives=True,
    allow_duplicate_maven_metadata=False,
):
    reasons = set()
    details = set()
    entry_count = 0
    total_size = 0
    nested_archives = 0
    max_depth = 0

    def inspect(payload, depth, location="<root>"):
        nonlocal entry_count, total_size, nested_archives, max_depth
        max_depth = max(max_depth, depth)
        try:
            archive_source = (
                payload if isinstance(payload, (str, Path)) else io.BytesIO(payload)
            )
            with zipfile.ZipFile(archive_source) as archive:
                infos = archive.infolist()
                names = [item.filename for item in infos]
                entry_count += len(infos)
                if entry_count > max_entries:
                    reasons.add("ARCHIVE_ENTRY_COUNT_EXCEEDED")
                duplicate_names = {
                    name for name, count in Counter(names).items() if count > 1
                }
                blocking_duplicate_names = {
                    name for name in duplicate_names
                    if not is_allowed_duplicate_archive_entry(
                        name,
                        allow_duplicate_maven_metadata=(
                            allow_duplicate_maven_metadata
                        ),
                    )
                }
                if blocking_duplicate_names:
                    reasons.add("ARCHIVE_DUPLICATE_ENTRY")
                    for name in blocking_duplicate_names:
                        details.add(f"ARCHIVE_DUPLICATE_ENTRY:{location}!/{name}")
                for info in infos:
                    entry_rejected = False
                    if _unsafe_entry_name(info.filename):
                        reasons.add("ARCHIVE_ENTRY_PATH_UNSAFE")
                        details.add(f"ARCHIVE_ENTRY_PATH_UNSAFE:{info.filename}")
                        entry_rejected = True
                    total_size += max(int(info.file_size), 0)
                    if total_size > max_total_uncompressed_bytes:
                        reasons.add("ARCHIVE_UNCOMPRESSED_SIZE_EXCEEDED")
                        entry_rejected = True
                    compressed = max(int(info.compress_size), 0)
                    ratio = float("inf") if compressed == 0 and info.file_size else (
                        info.file_size / max(compressed, 1)
                    )
                    if ratio > max_expansion_ratio:
                        reasons.add("ARCHIVE_EXPANSION_RATIO_EXCEEDED")
                        entry_rejected = True
                    if info.is_dir():
                        continue
                    is_nested = info.filename.lower().endswith((".jar", ".war", ".zip"))
                    if is_nested:
                        nested_archives += 1
                    if entry_rejected:
                        continue
                    if is_nested and inspect_nested_archives:
                        if depth >= max_nested_depth:
                            reasons.add("ARCHIVE_NESTED_DEPTH_EXCEEDED")
                            continue
                        if info.file_size > max_nested_archive_bytes:
                            reasons.add("ARCHIVE_NESTED_SIZE_EXCEEDED")
                            continue
                    try:
                        if is_nested and inspect_nested_archives:
                            nested_payload = archive.read(info)
                        else:
                            with archive.open(info) as entry_stream:
                                while entry_stream.read(1024 * 1024):
                                    pass
                    except (OSError, RuntimeError, zipfile.BadZipFile, KeyError):
                        reason = (
                            "ARCHIVE_NESTED_READ_FAILED"
                            if is_nested
                            else "ARCHIVE_ENTRY_READ_FAILED"
                        )
                        reasons.add(reason)
                        details.add(f"{reason}:{info.filename}")
                        continue
                    if is_nested and inspect_nested_archives:
                        inspect(nested_payload, depth + 1, info.filename)
        except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
            reasons.add("ARCHIVE_FORMAT_INVALID")
            details.add(f"ARCHIVE_FORMAT_INVALID:{location}")

    inspect(source, 0)
    reason_codes = tuple(sorted(reasons))
    return ArchiveSafetyResult(
        safe=not reason_codes,
        reason_codes=reason_codes,
        entry_count=entry_count,
        total_uncompressed_bytes=total_size,
        nested_archives=nested_archives,
        max_observed_depth=max_depth,
        details=tuple(sorted(details)),
    )


def inspect_archive_bytes(content, **limits):
    return _inspect_archive_source(bytes(content), **limits)


def inspect_archive(path, **limits):
    archive_path = Path(path)
    if not archive_path.is_file():
        return ArchiveSafetyResult(
            safe=False,
            reason_codes=("ARCHIVE_READ_FAILED",),
            entry_count=0,
            total_uncompressed_bytes=0,
            nested_archives=0,
            max_observed_depth=0,
        )
    return _inspect_archive_source(archive_path, **limits)


def _changed_during_scan_result():
    return ArchiveSafetyResult(
        safe=False,
        reason_codes=("ARCHIVE_CHANGED_DURING_SCAN",),
        entry_count=0,
        total_uncompressed_bytes=0,
        nested_archives=0,
        max_observed_depth=0,
    )


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _cached_archive_inspection(path, expected_sha256, limits):
    key = (path, expected_sha256, limits)
    with _ARCHIVE_CACHE_CONDITION:
        while key in _ARCHIVE_CACHE_IN_FLIGHT:
            _ARCHIVE_CACHE_CONDITION.wait()
        cached = _ARCHIVE_SAFETY_CACHE.get(key)
        if cached is not None:
            _ARCHIVE_SAFETY_CACHE.move_to_end(key)
            return cached
        scan_generation = _ARCHIVE_CACHE_GENERATION
        _ARCHIVE_CACHE_IN_FLIGHT.add(key)
    try:
        archive_path = Path(path)
        result = _inspect_archive_source(archive_path, **dict(limits))
        try:
            actual_sha256 = _sha256_file(archive_path)
        except OSError:
            result = _changed_during_scan_result()
        else:
            if actual_sha256 != expected_sha256:
                result = _changed_during_scan_result()
    except BaseException:
        with _ARCHIVE_CACHE_CONDITION:
            _ARCHIVE_CACHE_IN_FLIGHT.discard(key)
            _ARCHIVE_CACHE_CONDITION.notify_all()
        raise
    with _ARCHIVE_CACHE_CONDITION:
        if scan_generation == _ARCHIVE_CACHE_GENERATION:
            _ARCHIVE_SAFETY_CACHE[key] = result
            _ARCHIVE_SAFETY_CACHE.move_to_end(key)
            while len(_ARCHIVE_SAFETY_CACHE) > _ARCHIVE_CACHE_MAX_SIZE:
                _ARCHIVE_SAFETY_CACHE.popitem(last=False)
        _ARCHIVE_CACHE_IN_FLIGHT.discard(key)
        _ARCHIVE_CACHE_CONDITION.notify_all()
    return result


def clear_archive_safety_cache():
    global _ARCHIVE_CACHE_GENERATION
    with _ARCHIVE_CACHE_CONDITION:
        _ARCHIVE_CACHE_GENERATION += 1
        _ARCHIVE_SAFETY_CACHE.clear()


_ARCHIVE_CACHE_MAX_SIZE = 256
_ARCHIVE_CACHE_GENERATION = 0
_ARCHIVE_SAFETY_CACHE = OrderedDict()
_ARCHIVE_CACHE_IN_FLIGHT = set()
_ARCHIVE_CACHE_CONDITION = threading.Condition()


def require_safe_archive(path, **limits):
    archive_path = Path(path)
    try:
        artifact_sha256 = _sha256_file(archive_path)
    except OSError:
        result = inspect_archive(archive_path, **limits)
    else:
        result = _cached_archive_inspection(
            str(archive_path.resolve()),
            artifact_sha256,
            tuple(sorted(limits.items())),
        )
    if not result.safe:
        evidence = result.details or result.reason_codes
        raise ValueError("artifact_safety_violation:" + ",".join(evidence))
    return result
