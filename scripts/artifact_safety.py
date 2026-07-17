#!/usr/bin/env python3
"""Bounded, fail-closed validation for JAR/WAR/ZIP analysis inputs."""

from dataclasses import dataclass
import io
from pathlib import Path, PurePosixPath
import re
import zipfile


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


def _inspect_archive_source(
    source,
    *,
    max_entries=100_000,
    max_total_uncompressed_bytes=2 * 1024 * 1024 * 1024,
    max_expansion_ratio=200,
    max_nested_depth=3,
    max_nested_archive_bytes=64 * 1024 * 1024,
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
                if len(names) != len(set(names)):
                    reasons.add("ARCHIVE_DUPLICATE_ENTRY")
                    details.add(f"ARCHIVE_DUPLICATE_ENTRY:{location}")
                for info in infos:
                    if _unsafe_entry_name(info.filename):
                        reasons.add("ARCHIVE_ENTRY_PATH_UNSAFE")
                        details.add(f"ARCHIVE_ENTRY_PATH_UNSAFE:{info.filename}")
                    total_size += max(int(info.file_size), 0)
                    if total_size > max_total_uncompressed_bytes:
                        reasons.add("ARCHIVE_UNCOMPRESSED_SIZE_EXCEEDED")
                    compressed = max(int(info.compress_size), 0)
                    ratio = float("inf") if compressed == 0 and info.file_size else (
                        info.file_size / max(compressed, 1)
                    )
                    if ratio > max_expansion_ratio:
                        reasons.add("ARCHIVE_EXPANSION_RATIO_EXCEEDED")
                    if info.is_dir() or not info.filename.lower().endswith((".jar", ".war", ".zip")):
                        continue
                    nested_archives += 1
                    if depth >= max_nested_depth:
                        reasons.add("ARCHIVE_NESTED_DEPTH_EXCEEDED")
                        continue
                    if info.file_size > max_nested_archive_bytes:
                        reasons.add("ARCHIVE_NESTED_SIZE_EXCEEDED")
                        continue
                    try:
                        nested_payload = archive.read(info)
                    except (OSError, RuntimeError, zipfile.BadZipFile, KeyError):
                        reasons.add("ARCHIVE_NESTED_READ_FAILED")
                        details.add(f"ARCHIVE_NESTED_READ_FAILED:{info.filename}")
                        continue
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


def require_safe_archive(path, **limits):
    result = inspect_archive(path, **limits)
    if not result.safe:
        evidence = result.details or result.reason_codes
        raise ValueError("artifact_safety_violation:" + ",".join(evidence))
    return result
